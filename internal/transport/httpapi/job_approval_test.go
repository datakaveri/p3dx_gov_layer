package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
)

// The job-approval rules are tested in application/jobapproval; these cover
// the HTTP side: reading the caller from their token and the wiring.

// stubAPD serves the infra policy lookup the approval checks call.
func stubAPD(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/policy/by-item/infra-1":
			_, _ = w.Write([]byte(`{"status":"success","data":{"provider_id":"provider-ivan"}}`))
		case "/api/v1/policy/by-item/infra-2":
			_, _ = w.Write([]byte(`{"status":"success","data":{"provider_id":"provider-mallory"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("APD_BASE_URL", srv.URL)
}

const (
	dsHeart   = "11111111-1111-4111-8111-111111111111" // alice's DataBank
	dsMissing = "22222222-2222-4222-8222-222222222222" // not in the catalogue
	dsBob     = "44444444-4444-4444-8444-444444444444"
	dsCarol   = "55555555-5555-4555-8555-555555555555"
)

// stubDXCatalogue serves GET /item?id= and only answers callers sending
// alice's token, the way the DX catalogue refuses a bad token.
func stubDXCatalogue(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer tok-alice" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"type":"urn:dx:controlPlane:invalidToken"}`))
			return
		}
		if id := r.URL.Query().Get("id"); r.URL.Path == "/item" && id == dsHeart {
			_, _ = w.Write([]byte(`{"type":"urn:dx:controlPlane:success","result":[{"id":"` + dsHeart + `","name":"heart","type":["adex:DataBank"],"uploadedBy":"alice@example.com"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"urn:dx:controlPlane:notFound","detail":"doc doesn't exist"}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestDataProviderCallerMatchesParty(t *testing.T) {
	caller := callerFromClaims("t", jwt.MapClaims{"preferred_username": "8adf42ccc9@emailnox.live", "sub": "ABC-123"})
	for _, tc := range []struct {
		party contract.DataProviderParty
		want  bool
	}{
		{contract.DataProviderParty{ID: "provider-8adf42ccc9-emailnox-live"}, true},
		{contract.DataProviderParty{ID: "abc-123", Name: "someone"}, true}, // FL: keycloak id as party id
		{contract.DataProviderParty{ID: "kc-id", Name: "8adf42ccc9@emailnox.live"}, true},
		{contract.DataProviderParty{ID: "provider-bob"}, false},
		{contract.DataProviderParty{}, false},
	} {
		if got := caller.is(tc.party); got != tc.want {
			t.Errorf("is(%+v) = %v, want %v", tc.party, got, tc.want)
		}
	}
}

// The caller handed to the use cases carries everything read off the token.
func TestCallerApprover(t *testing.T) {
	a := callerFromClaims("tok", jwt.MapClaims{"preferred_username": "ivan", "sub": "ivan-sub",
		"realm_access": map[string]any{"roles": []any{"infra_provider"}}}).approver()
	if a.Token != "tok" || a.Username != "ivan" || a.UserID != "ivan-sub" || len(a.Roles) != 1 || !a.Owns("provider-ivan") {
		t.Fatalf("approver = %+v", a)
	}
}

// The service is wired from the server's config: infra approval is required
// unless REQUIRE_INFRA_APPROVAL is off, and the data-provider role defaults
// to the DX "provider" role.
func TestApprovalsWiring(t *testing.T) {
	if a := (&Server{}).approvals(); !a.RequireInfraApproval || a.DataProviderRole != "provider" {
		t.Errorf("no config: %+v", a)
	}
	a := (&Server{cfg: &config.Config{RequireInfraApproval: false, DataProviderRole: "dp"}}).approvals()
	if a.RequireInfraApproval || a.DataProviderRole != "dp" {
		t.Errorf("configured: %+v", a)
	}
}

// With REQUIRE_INFRA_APPROVAL off, a TEE/SMPC contract naming datasets but
// only the placeholder infra is still signed directly; only datasets + real
// infra go through job approval.
func TestJobApprovalRequiredWithoutInfra(t *testing.T) {
	teeNoInfra := &contract.Contract{Technique: "TEE", Parties: contract.Parties{
		DataProviders:  []contract.DataProviderParty{{ID: "provider-a"}},
		InfraProviders: []contract.InfraProviderParty{{Name: "placeholder"}},
	}}
	flNoInfra := &contract.Contract{Technique: "FL", Parties: contract.Parties{
		DataProviders: []contract.DataProviderParty{{ID: "provider-a"}},
	}}
	teeNoData := &contract.Contract{Technique: "TEE", Parties: contract.Parties{
		InfraProviders: []contract.InfraProviderParty{{Name: "placeholder"}},
	}}
	off := &Server{cfg: &config.Config{RequireInfraApproval: false}}
	on := &Server{cfg: &config.Config{RequireInfraApproval: true}}
	for _, tc := range []struct {
		name string
		s    *Server
		c    *contract.Contract
		want bool
	}{
		{"TEE, no infra, infra approval off", off, teeNoInfra, false},
		{"real infra, infra approval off", off, approvalContract(), true},
		{"TEE, no infra, infra approval on", on, teeNoInfra, false},
		{"TEE, no infra, no config", &Server{}, teeNoInfra, false},
		{"FL, infra approval off", off, flNoInfra, false},
		{"TEE, no datasets", off, teeNoData, false},
		{"real infra", on, approvalContract(), true},
	} {
		if got := tc.s.jobApprovalRequired(tc.c); got != tc.want {
			t.Errorf("%s: jobApprovalRequired = %v, want %v", tc.name, got, tc.want)
		}
	}
}
