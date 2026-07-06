// Package keycloak provides the service-account access token used for
// gov_layer -> FL receiver calls, mirroring src/services/keycloak.service.js.
//
// gov_layer authenticates to the unauthenticated control-plane receivers
// (provider_config_receiver.py :8080, output_owner_env_receiver.py :8090) as a
// Keycloak service account via the OAuth2 client-credentials grant, sending the
// access token as `Authorization: Bearer <jwt>`. When Keycloak is not
// configured, callers fall back to the legacy static X-Auth-Token shared secret.
package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
)

// expirySkew refreshes a little before the token actually expires so an
// in-flight request never carries an already-expired token.
const expirySkew = 30 * time.Second

// Client fetches and caches the service-account token.
type Client struct {
	cfg *config.Config

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// New returns a Keycloak token client bound to the given config.
func New(cfg *config.Config) *Client {
	return &Client{cfg: cfg}
}

// Configured reports whether Keycloak service-account auth is set up.
func (c *Client) Configured() bool { return c.cfg.KeycloakConfigured() }

// getServiceToken returns a valid token, fetching/refreshing as needed. Returns
// "" when Keycloak is not configured. Mirrors getServiceToken().
func (c *Client) getServiceToken(ctx context.Context) (string, error) {
	if !c.Configured() {
		return "", nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiresAt.Add(-expirySkew)) {
		return c.token, nil
	}
	tok, ttl, err := c.fetchToken(ctx)
	if err != nil {
		return "", err
	}
	c.token = tok
	c.expiresAt = time.Now().Add(ttl)
	return tok, nil
}

func (c *Client) fetchToken(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.cfg.KeycloakClientID},
		"client_secret": {c.cfg.KeycloakSecret},
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.KeycloakTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.KeycloakTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := string(body)
		if len(detail) > 200 {
			detail = detail[:200]
		}
		return "", 0, fmt.Errorf("Keycloak token request failed: HTTP %d %s", resp.StatusCode, detail)
	}
	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", 0, err
	}
	if data.AccessToken == "" {
		return "", 0, fmt.Errorf("Keycloak token response had no access_token")
	}
	ttl := data.ExpiresIn
	if ttl == 0 {
		ttl = 60
	}
	return data.AccessToken, time.Duration(ttl) * time.Second, nil
}

// AuthHeaders returns request headers with auth attached:
//   - Keycloak configured: Authorization: Bearer <service-account token>
//   - else fallbackToken set: X-Auth-Token: <fallbackToken>
//   - else: base unchanged.
//
// Never fails the caller: if the token fetch errors it logs and returns base, so
// the receiver replies 401 and the per-target result records the failure rather
// than crashing the whole fan-out. Mirrors authHeaders().
func (c *Client) AuthHeaders(ctx context.Context, base map[string]string, fallbackToken string) map[string]string {
	headers := make(map[string]string, len(base)+1)
	for k, v := range base {
		headers[k] = v
	}
	if c.Configured() {
		tok, err := c.getServiceToken(ctx)
		if err != nil {
			log.Printf("[KEYCLOAK] service-account token fetch failed: %v", err)
		} else if tok != "" {
			headers["Authorization"] = "Bearer " + tok
			return headers
		}
	}
	if fallbackToken != "" {
		headers["X-Auth-Token"] = fallbackToken
	}
	return headers
}
