// Package userdir reads user records from the platform's own Keycloak — the
// realm p3dx-aaa registers users into — via the admin REST API. Today it only
// serves one thing: a data provider's registered RSA public key, stored by
// p3dx-aaa's keyPair.service.js as the "public_key" user attribute, which
// gov_layer uses to verify TEE contract signatures.
package userdir

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
)

// PublicKeyAttribute is the Keycloak user attribute p3dx-aaa publishes a
// data provider's public key under (see keyPair.service.js).
const PublicKeyAttribute = "public_key"

// ErrUserNotFound / ErrNoPublicKey let callers report a precise reason.
var (
	ErrUserNotFound = errors.New("user not found in Keycloak")
	ErrNoPublicKey  = errors.New("user has no public_key attribute in Keycloak")
)

// Client talks to the Keycloak admin API with an admin-cli password-grant
// token, cached until shortly before it expires.
type Client struct {
	baseURL, realm, user, password string
	http                           *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func New(cfg *config.Config) *Client {
	return &Client{
		baseURL:  strings.TrimRight(cfg.UserKeycloakBaseURL, "/"),
		realm:    cfg.UserKeycloakRealm,
		user:     cfg.UserKeycloakAdminUser,
		password: cfg.UserKeycloakAdminPassword,
		http:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) Configured() bool {
	return c != nil && c.baseURL != "" && c.realm != "" && c.user != "" && c.password != ""
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

// PublicKey returns the PEM public key registered on the Keycloak user with
// exactly this username.
func (c *Client) PublicKey(ctx context.Context, username string) (string, error) {
	if !c.Configured() {
		return "", fmt.Errorf("user Keycloak is not configured (USER_KEYCLOAK_*)")
	}
	token, err := c.adminToken(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{"username": {username}, "exact": {"true"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/admin/realms/"+url.PathEscape(c.realm)+"/users?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak user lookup: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak user lookup returned %d", resp.StatusCode)
	}
	var users []struct {
		Username   string              `json:"username"`
		Attributes map[string][]string `json:"attributes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return "", fmt.Errorf("decode keycloak users: %w", err)
	}
	for _, u := range users {
		if !strings.EqualFold(u.Username, username) {
			continue
		}
		if vals := u.Attributes[PublicKeyAttribute]; len(vals) > 0 && vals[0] != "" {
			return vals[0], nil
		}
		return "", ErrNoPublicKey
	}
	return "", ErrUserNotFound
}
