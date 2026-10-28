// Package userdir reads user records from the platform's own Keycloak — the
// realm p3dx-aaa registers users into — via the admin REST API, to list which
// users hold a realm role (job-approval checks). Providers' public keys are
// not read from here; they live in Postgres (internal/repository/postgres/public_keys.go).
package userdir

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
)

// Client talks to the Keycloak admin API with a token cached until shortly
// before it expires: a client_credentials token for clientID/clientSecret
// when those are set, otherwise an admin-cli password-grant token for
// user/password.
type Client struct {
	baseURL, realm, user, password string
	clientID, clientSecret         string
	http                           *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func New(cfg *config.Config) *Client {
	return &Client{
		baseURL:      strings.TrimRight(cfg.UserKeycloakBaseURL, "/"),
		realm:        cfg.UserKeycloakRealm,
		user:         cfg.UserKeycloakAdminUser,
		password:     cfg.UserKeycloakAdminPassword,
		clientID:     cfg.UserKeycloakClientID,
		clientSecret: cfg.UserKeycloakClientSecret,
		http:         &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) usesClientCredentials() bool {
	return c.clientID != "" && c.clientSecret != ""
}

func (c *Client) Configured() bool {
	return c != nil && c.baseURL != "" && c.realm != "" &&
		(c.usesClientCredentials() || (c.user != "" && c.password != ""))
}

func (c *Client) adminToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiresAt.Add(-30*time.Second)) {
		return c.token, nil
	}
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {c.user},
		"password":   {c.password},
	}
	if c.usesClientCredentials() {
		form = url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {c.clientID},
			"client_secret": {c.clientSecret},
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/realms/"+url.PathEscape(c.realm)+"/protocol/openid-connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("keycloak token request returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("decode keycloak token: %w", err)
	}
	c.token = tok.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return c.token, nil
}

// User is one Keycloak user, as the admin API lists it.
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// UsernamesWithRole returns the usernames of every user holding the realm
// role roleName (e.g. "provider", granted when cos_admin approves that role
// request). A role that doesn't exist yields no users, not an error.
func (c *Client) UsernamesWithRole(ctx context.Context, roleName string) ([]string, error) {
	users, err := c.UsersWithRole(ctx, roleName)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, u.Username)
	}
	return out, nil
}

// UsersWithRole returns every user holding the realm role roleName.
func (c *Client) UsersWithRole(ctx context.Context, roleName string) ([]User, error) {
	const pageSize = 500
	var out []User
	for first := 0; ; first += pageSize {
		q := url.Values{"first": {fmt.Sprint(first)}, "max": {fmt.Sprint(pageSize)}}
		var users []User
		found, err := c.adminGet(ctx, "/roles/"+url.PathEscape(roleName)+"/users?"+q.Encode(), &users)
		if err != nil {
			return nil, fmt.Errorf("keycloak role users lookup: %w", err)
		}
		if !found {
			return out, nil
		}
		out = append(out, users...)
		if len(users) < pageSize {
			return out, nil
		}
	}
}

// UserByUsername returns the user with exactly this username, or nil if none.
func (c *Client) UserByUsername(ctx context.Context, username string) (*User, error) {
	q := url.Values{"username": {username}, "exact": {"true"}}
	var users []User
	if _, err := c.adminGet(ctx, "/users?"+q.Encode(), &users); err != nil {
		return nil, fmt.Errorf("keycloak user lookup: %w", err)
	}
	for _, u := range users {
		if strings.EqualFold(u.Username, username) {
			return &u, nil
		}
	}
	return nil, nil
}

// adminGet GETs path under the realm's admin API into out. found is false on 404.
func (c *Client) adminGet(ctx context.Context, path string, out any) (found bool, err error) {
	if !c.Configured() {
		return false, fmt.Errorf("user Keycloak is not configured (USER_KEYCLOAK_BASE_URL/REALM plus CLIENT_ID/SECRET or ADMIN_USER/PASSWORD)")
	}
	token, err := c.adminToken(ctx)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/admin/realms/"+url.PathEscape(c.realm)+path, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("returned %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return false, fmt.Errorf("decode: %w", err)
	}
	return true, nil
}
