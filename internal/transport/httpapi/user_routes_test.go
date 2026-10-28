package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
)

// The routes the UI calls directly reject callers without a valid user token,
// or without the role they need, before doing anything else.
func TestUserRoutesAuth(t *testing.T) {
	idp := newStubIdP(t)
	srv := newTestServer(&config.Config{ProviderKeyJWKSURL: idp.jwksURL(), FlotillaVMClientID: "flotilla-vm"})
	h := srv.Handler()

	user := func(rs ...string) string {
		return idp.mint(t, jwt.MapClaims{"preferred_username": "carol", "sub": "u-carol", "realm_access": roles(rs...)})
	}
	vmToken := idp.mint(t, jwt.MapClaims{"azp": "flotilla-vm", "preferred_username": "carol", "sub": "u-carol", "realm_access": roles("consumer", "provider")})

	cases := []struct {
		name, method, path, token string
		want                      int
	}{
		{"inbox without token", http.MethodGet, "/api/v1/me/notifications", "", http.StatusUnauthorized},
		{"inbox with forged token", http.MethodGet, "/api/v1/me/notifications", "not-a-jwt", http.StatusUnauthorized},
		{"inbox with FL VM token", http.MethodGet, "/api/v1/me/notifications", vmToken, http.StatusForbidden},
		{"respond without token", http.MethodPost, "/api/v1/me/notifications/n-1/respond", "", http.StatusUnauthorized},
		{"jobs without token", http.MethodGet, "/governance/me/jobs", "", http.StatusUnauthorized},
		{"sign requests as consumer only", http.MethodGet, "/api/v1/me/sign-requests", user("consumer"), http.StatusForbidden},
		{"session contract without token", http.MethodGet, "/api/v1/contract/s-1", "", http.StatusUnauthorized},
		{"workload catalogue without token", http.MethodGet, "/api/v1/workloads", "", http.StatusUnauthorized},
		{"TEE run without token", http.MethodPost, "/v1/tee/run", "", http.StatusUnauthorized},
		{"TEE run as provider only", http.MethodPost, "/v1/tee/run", user("provider"), http.StatusForbidden},
		{"TEE job as provider only", http.MethodGet, "/v1/tee/jobs/j-1", user("provider"), http.StatusForbidden},
		{"TEE session without token", http.MethodGet, "/v1/tee/sessions/s-1", "", http.StatusUnauthorized},
		{"TEE session as consumer passes auth", http.MethodGet, "/v1/tee/sessions/s-1", user("consumer"), http.StatusNotFound},
		{"FL notify without token", http.MethodPost, "/api/v1/me/fl/notify-providers", "", http.StatusUnauthorized},
		{"FL start with FL VM token", http.MethodPost, "/api/v1/me/fl/start-session", vmToken, http.StatusForbidden},
		{"FL data providers without token", http.MethodGet, "/api/v1/me/fl/data-providers", "", http.StatusUnauthorized},
		{"notification stream without token", http.MethodGet, "/api/v1/me/notifications/stream", "", http.StatusUnauthorized},
		{"projects without token", http.MethodGet, "/api/v1/projects", "", http.StatusUnauthorized},
		{"project without token", http.MethodGet, "/governance/projects/s-1", "", http.StatusUnauthorized},
		{"projects with a user token", http.MethodGet, "/api/v1/projects", user("consumer"), http.StatusUnauthorized},
		// Routes that took the user from the URL or body are gone; the /me
		// routes replace them.
		{"old inbox route", http.MethodGet, "/api/v1/notifications/carol", "", http.StatusNotFound},
		{"old notify route", http.MethodPost, "/api/v1/notifications", "", http.StatusNotFound},
		{"old respond route", http.MethodPost, "/api/v1/notifications/n-1/respond", "", http.StatusNotFound},
		{"old jobs route", http.MethodGet, "/api/v1/jobs/user/u-carol", user("consumer"), http.StatusNotFound},
		{"old session contract route", http.MethodPost, "/api/v1/contracts", "", http.StatusNotFound},
		{"old model download", http.MethodGet, "/api/v1/final-model/download", "", http.StatusNotFound},
		{"old provider message route", http.MethodPost, "/api/v1/send-provider-message", "", http.StatusNotFound},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: %s %s = %d, want %d (body: %s)", c.name, c.method, c.path, rec.Code, c.want, rec.Body.String())
		}
	}
}
