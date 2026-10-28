package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/userdir"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// stubVMStore is an in-memory vmCredentialStore.
type stubVMStore struct {
	recs    map[string]*postgres.VMCredential
	readErr error
}

func (s *stubVMStore) CreateVMCredential(_ context.Context, c postgres.VMCredential) error {
	c.State = postgres.VMCredentialIssued
	s.recs[c.CredentialID] = &c
	return nil
}

func (s *stubVMStore) GetVMCredential(_ context.Context, id string) (*postgres.VMCredential, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	if c, ok := s.recs[id]; ok {
		cp := *c
		return &cp, nil
	}
	return nil, nil
}

func (s *stubVMStore) GetVMCredentialBySession(_ context.Context, sid string) (*postgres.VMCredential, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	for _, c := range s.recs {
		if c.SessionID == sid {
			cp := *c
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *stubVMStore) SetVMCredentialState(_ context.Context, id, state, reason string) (*postgres.VMCredential, error) {
	c, ok := s.recs[id]
	if !ok {
		return nil, nil
	}
	if c.State != state {
		c.State, c.StateReason = state, reason
	}
	cp := *c
	return &cp, nil
}

func (s *stubVMStore) UpdateVMCredentialFingerprint(_ context.Context, id, fp string) error {
	s.recs[id].TokenFingerprint = fp
	return nil
}

// stubVMKeycloak answers refresh grants with tokens for (sid, azp) and
// records deleted sessions.
type stubVMKeycloak struct {
	sid, azp   string
	rotateTo   string
	refreshErr error
	sessions   []userdir.OfflineSession
	deleted    []string
}

func unsignedJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (k *stubVMKeycloak) PasswordGrantOffline(context.Context, string, string, string, string) (*userdir.TokenResponse, error) {
	return nil, errors.New("not used")
}

func (k *stubVMKeycloak) RefreshGrant(_ context.Context, _, _, refresh string) (*userdir.TokenResponse, error) {
	if k.refreshErr != nil {
		return nil, k.refreshErr
	}
	access, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sid": k.sid, "azp": k.azp}).SignedString([]byte("k"))
	next := refresh
	if k.rotateTo != "" {
		next = k.rotateTo
	}
	return &userdir.TokenResponse{AccessToken: access, RefreshToken: next, ExpiresIn: 300}, nil
}

func (k *stubVMKeycloak) DeleteOfflineSession(_ context.Context, sid string) (bool, error) {
	k.deleted = append(k.deleted, sid)
	return true, nil
}

func (k *stubVMKeycloak) ClientOfflineSessions(context.Context, string) ([]userdir.OfflineSession, error) {
	return k.sessions, nil
}

func newVMTestServer(t *testing.T, cfg *config.Config) (*Server, *stubVMStore, *stubVMKeycloak) {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{}
	}
	cfg.FlotillaVMClientID = "flotilla-vm"
	srv := newTestServer(cfg)
	store := &stubVMStore{recs: map[string]*postgres.VMCredential{}}
	kc := &stubVMKeycloak{sid: "sid-1", azp: "flotilla-vm"}
	srv.vmCreds, srv.vmKC = store, kc
	return srv, store, kc
}

func liveRecord(token string) *postgres.VMCredential {
	return &postgres.VMCredential{
		CredentialID: "cred-1", SubmissionID: "sub-1", Username: "alice", UserID: "u-alice",
		SessionID: "sid-1", State: postgres.VMCredentialIssued, TokenFingerprint: tokenFingerprint(token),
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func postVMToken(srv *Server, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/p3dx/fl/vm-token", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestVMTokenRefresh(t *testing.T) {
	const offline = "offline-token-1"
	ok := `{"credential_id":"cred-1","offline_token":"` + offline + `"}`

	cases := []struct {
		name   string
		setup  func(*stubVMStore, *stubVMKeycloak)
		body   string
		want   int
		errStr string
	}{
		{"malformed body", nil, `{"credential_id":`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"missing token", nil, `{"credential_id":"cred-1"}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"unknown credential", nil, `{"credential_id":"nope","offline_token":"x"}`, http.StatusUnauthorized, "UNKNOWN_CREDENTIAL"},
		{"wrong token", nil, `{"credential_id":"cred-1","offline_token":"someone-elses"}`, http.StatusUnauthorized, "INVALID_CREDENTIAL"},
		{"store down", func(s *stubVMStore, _ *stubVMKeycloak) { s.readErr = errors.New("down") }, ok, http.StatusServiceUnavailable, "CREDENTIAL_STORE_UNAVAILABLE"},
		{"refresh refused", func(_ *stubVMStore, k *stubVMKeycloak) { k.refreshErr = errors.New("invalid_grant") }, ok, http.StatusUnauthorized, "REFRESH_FAILED"},
		{"other session", func(_ *stubVMStore, k *stubVMKeycloak) { k.sid = "sid-2" }, ok, http.StatusUnauthorized, "SESSION_MISMATCH"},
		{"other client", func(_ *stubVMStore, k *stubVMKeycloak) { k.azp = "p3dx-auth-ui" }, ok, http.StatusUnauthorized, "SESSION_MISMATCH"},
		{"ok", nil, ok, http.StatusOK, ""},
	}
	for _, c := range cases {
		srv, store, kc := newVMTestServer(t, nil)
		store.recs["cred-1"] = liveRecord(offline)
		if c.setup != nil {
			c.setup(store, kc)
		}
		rec := postVMToken(srv, c.body)
		if rec.Code != c.want || !strings.Contains(rec.Body.String(), c.errStr) {
			t.Errorf("%s: got %d %s, want %d %s", c.name, rec.Code, rec.Body.String(), c.want, c.errStr)
		}
		if strings.Contains(rec.Body.String(), "someone-elses") {
			t.Errorf("%s: response echoes the request body", c.name)
		}
	}
}

func TestVMTokenExpiredRecordIsRevoked(t *testing.T) {
	srv, store, kc := newVMTestServer(t, nil)
	r := liveRecord("tok")
	r.ExpiresAt = time.Now().Add(-time.Minute)
	store.recs["cred-1"] = r

	rec := postVMToken(srv, `{"credential_id":"cred-1","offline_token":"tok"}`)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "CREDENTIAL_EXPIRED") {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	if store.recs["cred-1"].State != postgres.VMCredentialExpired || len(kc.deleted) != 1 || kc.deleted[0] != "sid-1" {
		t.Fatalf("record %q, deleted sessions %v", store.recs["cred-1"].State, kc.deleted)
	}
}

func TestVMTokenRotation(t *testing.T) {
	srv, store, kc := newVMTestServer(t, nil)
	store.recs["cred-1"] = liveRecord("old")
	kc.rotateTo = "new"

	rec := postVMToken(srv, `{"credential_id":"cred-1","offline_token":"old"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"offline_token":"new"`) {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	if rec := postVMToken(srv, `{"credential_id":"cred-1","offline_token":"old"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old token after rotation: got %d, want 401", rec.Code)
	}
}

func TestVMTokenRateLimited(t *testing.T) {
	srv, store, _ := newVMTestServer(t, nil)
	store.recs["cred-1"] = liveRecord("tok")
	for i := 0; i < vmTokenRequestsPerMinute; i++ {
		postVMToken(srv, `{"credential_id":"cred-1","offline_token":"tok"}`)
	}
	if rec := postVMToken(srv, `{"credential_id":"cred-1","offline_token":"tok"}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", rec.Code)
	}
}

func TestVMCredentialDelivered(t *testing.T) {
	idp := newStubIdP(t)
	t.Setenv("KEYCLOAK_JWKS_URL", idp.jwksURL())
	srv, store, _ := newVMTestServer(t, &config.Config{OrchestratorClientID: "p3dx-fl-orchestrator", OrchestratorRole: "fl-orchestrator"})
	store.recs["cred-1"] = liveRecord("tok")
	svc := idp.mint(t, jwt.MapClaims{"azp": "p3dx-fl-orchestrator", "realm_access": roles("fl-orchestrator")})
	user := idp.mint(t, jwt.MapClaims{"azp": "p3dx-auth-ui", "realm_access": roles("provider")})

	call := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/p3dx/internal/fl/vm-credentials/cred-1/delivered", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := call(""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d", rec.Code)
	}
	if rec := call(user); rec.Code != http.StatusForbidden {
		t.Fatalf("user token: got %d", rec.Code)
	}
	if rec := call(svc); rec.Code != http.StatusOK || store.recs["cred-1"].State != postgres.VMCredentialDelivered {
		t.Fatalf("orchestrator: got %d %s, state %q", rec.Code, rec.Body.String(), store.recs["cred-1"].State)
	}
	store.recs["cred-1"].State = postgres.VMCredentialExpired
	if rec := call(svc); rec.Code != http.StatusConflict {
		t.Fatalf("expired: got %d", rec.Code)
	}
}

func TestIssueVMCredentialGuards(t *testing.T) {
	idp := newStubIdP(t)
	provider := idp.mint(t, jwt.MapClaims{"preferred_username": "alice", "sub": "u-alice", "realm_access": roles("provider")})
	consumer := idp.mint(t, jwt.MapClaims{"preferred_username": "carol", "sub": "u-carol", "realm_access": roles("consumer")})

	call := func(cfg *config.Config, token string) *httptest.ResponseRecorder {
		cfg.ProviderKeyJWKSURL = idp.jwksURL()
		srv, _, _ := newVMTestServer(t, cfg)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/me/fl/vm-credentials", strings.NewReader(`{"submission_id":"sub-1","password":"pw"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := call(&config.Config{InternalServiceKey: "k"}, consumer); rec.Code != http.StatusForbidden {
		t.Errorf("consumer: got %d, want 403", rec.Code)
	}
	if rec := call(&config.Config{}, provider); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "INTERNAL_KEY_NOT_CONFIGURED") {
		t.Errorf("no internal key: got %d %s", rec.Code, rec.Body.String())
	}
}

func TestSweepVMOfflineSessions(t *testing.T) {
	srv, store, kc := newVMTestServer(t, nil)
	live := liveRecord("a")
	expired := liveRecord("b")
	expired.CredentialID, expired.SessionID, expired.ExpiresAt = "cred-2", "sid-2", time.Now().Add(-time.Minute)
	store.recs["cred-1"], store.recs["cred-2"] = live, expired
	kc.sessions = []userdir.OfflineSession{{ID: "sid-1"}, {ID: "sid-2"}, {ID: "sid-orphan"}, {ID: ""}}

	sum, err := srv.sweepVMOfflineSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := vmSweepSummary{Sessions: 4, Kept: 1, OrphansDeleted: 1, ExpiredDeleted: 1, Skipped: 1}
	if sum != want {
		t.Fatalf("summary %+v, want %+v", sum, want)
	}
	if strings.Join(kc.deleted, ",") != "sid-2,sid-orphan" {
		t.Fatalf("deleted %v", kc.deleted)
	}
	if store.recs["cred-2"].State != postgres.VMCredentialExpired || store.recs["cred-1"].State != postgres.VMCredentialIssued {
		t.Fatalf("states: cred-1 %q, cred-2 %q", store.recs["cred-1"].State, store.recs["cred-2"].State)
	}
}

func TestRateLimiterWindow(t *testing.T) {
	now := time.Unix(0, 0)
	l := newRateLimiter(2)
	l.now = func() time.Time { return now }
	if !l.allow("a") || !l.allow("a") || l.allow("a") {
		t.Fatal("limit of 2 per minute not enforced")
	}
	if !l.allow("b") {
		t.Fatal("keys share a window")
	}
	now = now.Add(time.Minute)
	if !l.allow("a") {
		t.Fatal("window did not reset")
	}
}
