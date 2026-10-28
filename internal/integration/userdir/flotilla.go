package userdir

// Keycloak calls behind the Flotilla FL client-VM credentials
// (internal/transport/httpapi/fl_vm_credentials.go): grants with the confidential
// flotilla-vm client, and the admin calls that list and delete its offline
// sessions.
//
// SECURITY: these requests carry a password or an offline token. Errors here
// hold only status codes and Keycloak's error code, never a request or
// response body.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// TokenResponse is the part of a Keycloak token response the VM flow uses.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// GrantError is a token grant Keycloak refused.
type GrantError struct {
	Status int
	Code   string // Keycloak's "error", e.g. invalid_grant
}

func (e *GrantError) Error() string {
	return fmt.Sprintf("keycloak token grant returned %d (%s)", e.Status, e.Code)
}

// PasswordGrantOffline logs username in with client (clientID, secret) and
// scope offline_access, returning an offline refresh token.
func (c *Client) PasswordGrantOffline(ctx context.Context, clientID, secret, username, password string) (*TokenResponse, error) {
	return c.tokenGrant(ctx, url.Values{
		"grant_type":    {"password"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"username":      {username},
		"password":      {password},
		"scope":         {"openid offline_access"},
	})
}

// RefreshGrant exchanges refreshToken with client (clientID, secret).
func (c *Client) RefreshGrant(ctx context.Context, clientID, secret, refreshToken string) (*TokenResponse, error) {
	return c.tokenGrant(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"refresh_token": {refreshToken},
	})
}

func (c *Client) tokenGrant(ctx context.Context, form url.Values) (*TokenResponse, error) {
	if c.baseURL == "" || c.realm == "" {
		return nil, fmt.Errorf("user Keycloak is not configured (USER_KEYCLOAK_BASE_URL/REALM)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/realms/"+url.PathEscape(c.realm)+"/protocol/openid-connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak token request failed")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var kcErr struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &kcErr)
		return nil, &GrantError{Status: resp.StatusCode, Code: kcErr.Error}
	}
	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("decode keycloak token response")
	}
	return &tok, nil
}

// DeleteOfflineSession revokes an offline session. false: it was already gone.
func (c *Client) DeleteOfflineSession(ctx context.Context, sessionID string) (bool, error) {
	if sessionID == "" {
		return false, nil
	}
	if !c.Configured() {
		return false, fmt.Errorf("user Keycloak admin access is not configured")
	}
	token, err := c.adminToken(ctx)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.baseURL+"/admin/realms/"+url.PathEscape(c.realm)+"/sessions/"+url.PathEscape(sessionID)+"?isOffline=true", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("delete offline session: %w", err)
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("delete offline session returned %d", resp.StatusCode)
}

// OfflineSession is one offline user session held by a client.
type OfflineSession struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// ClientOfflineSessions lists every offline session held by clientID.
func (c *Client) ClientOfflineSessions(ctx context.Context, clientID string) ([]OfflineSession, error) {
	var clients []struct {
		ID string `json:"id"`
	}
	if _, err := c.adminGet(ctx, "/clients?"+url.Values{"clientId": {clientID}}.Encode(), &clients); err != nil {
		return nil, fmt.Errorf("look up client %s: %w", clientID, err)
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("no client %s in realm %s", clientID, c.realm)
	}
	const pageSize = 100
	var out []OfflineSession
	for first := 0; ; first += pageSize {
		q := url.Values{"first": {fmt.Sprint(first)}, "max": {fmt.Sprint(pageSize)}}
		var page []OfflineSession
		if _, err := c.adminGet(ctx, "/clients/"+url.PathEscape(clients[0].ID)+"/offline-sessions?"+q.Encode(), &page); err != nil {
			return nil, fmt.Errorf("list offline sessions: %w", err)
		}
		out = append(out, page...)
		if len(page) < pageSize {
			return out, nil
		}
	}
}
