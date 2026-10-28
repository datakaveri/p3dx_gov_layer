package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/platform/govcrypto"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

const stubIdPKID = "stub-idp-key"

// stubIdP is a fake Keycloak: it serves a JWKS at /certs and mints RS256
// tokens with the matching key.
type stubIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newStubIdP(t *testing.T) *stubIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &stubIdP{key: key}
	idp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kid": stubIdPKID,
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *stubIdP) jwksURL() string { return idp.server.URL + "/certs" }

func (idp *stubIdP) mint(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = stubIdPKID
	s, err := tok.SignedString(idp.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func roles(rs ...string) map[string]any {
	list := make([]any, len(rs))
	for i, r := range rs {
		list[i] = r
	}
	return map[string]any{"roles": list}
}

// stubGatewayStore serves contracts by session/project and records inserts.
type stubGatewayStore struct {
	bySession, byProject map[string]contract.Contract
	inserted             []postgres.GatewayCert
	insertErr            error
}

func (s *stubGatewayStore) raw(c contract.Contract, ok bool) (json.RawMessage, error) {
	if !ok {
		return nil, nil
	}
	return json.Marshal(c)
}

func (s *stubGatewayStore) GetContractBySession(_ context.Context, id string) (json.RawMessage, error) {
	c, ok := s.bySession[id]
	return s.raw(c, ok)
}

func (s *stubGatewayStore) GetContractByProjectID(_ context.Context, id string) (json.RawMessage, error) {
	c, ok := s.byProject[id]
	return s.raw(c, ok)
}

func (s *stubGatewayStore) InsertGatewayCert(_ context.Context, c postgres.GatewayCert) error {
	if s.insertErr != nil {
		return s.insertErr
	}
	s.inserted = append(s.inserted, c)
	return nil
}

type gatewayFixture struct {
	srv     *Server
	idp     *stubIdP
	store   *stubGatewayStore
	alice   *rsa.PrivateKey
	handler http.Handler
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	idp := newStubIdP(t)
	t.Setenv("KEYCLOAK_JWKS_URL", idp.jwksURL())
	srv := newTestServer(&config.Config{
		OrchestratorClientID: "p3dx-fl-orchestrator",
		OrchestratorRole:     "fl-orchestrator",
		FlotillaVMClientID:   "flotilla-vm",
	})
	ca, caPEM, err := govcrypto.LoadOrCreateGovernanceCACert(filepath.Join(t.TempDir(), "ca.pem"), srv.govKey)
	if err != nil {
		t.Fatal(err)
	}
	srv.govCA, srv.govCAPEM = ca, caPEM
	alice, alicePub := newRSAKey(t)
	srv.publicKeys = stubKeys{"alice": alicePub}
	store := &stubGatewayStore{bySession: map[string]contract.Contract{}, byProject: map[string]contract.Contract{}}
	srv.gatewayStore = store
	return &gatewayFixture{srv: srv, idp: idp, store: store, alice: alice, handler: srv.Handler()}
}

// flContract builds a final (v2) FL roster contract for session "sub-1",
// governance-signed and — when signed — signed by its one provider.
func (f *gatewayFixture) flContract(t *testing.T, projectID string, version int, validUntil time.Time, signed bool) contract.Contract {
	t.Helper()
	now := time.Now().UTC()
	c := contract.Contract{
		ProjectID:  projectID,
		ContractID: "contract-" + projectID,
		JobID:      "job-" + projectID,
		Version:    version,
		Technique:  "FL",
		Lifecycle:  contract.Lifecycle{CreatedAt: now, ValidFrom: now, ValidUntil: validUntil},
		Parties: contract.Parties{DataProviders: []contract.DataProviderParty{
			{ID: "kc-uuid-alice", Name: "alice", DatasetName: "a"},
		}},
		SessionInfo: contract.SessionInfo{ID: "sub-1", SessionID: "sub-1"},
	}
	h, err := contract.ComputeHash(c)
	if err != nil {
		t.Fatal(err)
	}
	c.ContractHash = h
	if err := f.srv.governanceSign(&c); err != nil {
		t.Fatal(err)
	}
	if signed {
		sign(&c, 0, "alice", signWith(t, f.alice, c.ContractHash))
	}
	return c
}

func (f *gatewayFixture) orchestratorToken(t *testing.T) string {
	return f.idp.mint(t, jwt.MapClaims{"azp": "p3dx-fl-orchestrator", "realm_access": roles("fl-orchestrator")})
}

func newCSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "gw"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func (f *gatewayFixture) post(t *testing.T, token string, body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway-certs", bytes.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestPostGatewayCertIssues(t *testing.T) {
	f := newGatewayFixture(t)
	validUntil := time.Now().Add(48 * time.Hour).UTC()
	latest := f.flContract(t, "proj-latest", 2, validUntil, true)
	older := f.flContract(t, "proj-older", 2, validUntil.Add(time.Hour), true)
	f.store.bySession["sub-1"] = latest
	f.store.byProject["proj-latest"] = latest
	f.store.byProject["proj-older"] = older

	for _, tc := range []struct {
		name string
		sel  map[string]any
		want contract.Contract
	}{
		{"by submission", map[string]any{"submission_id": "sub-1"}, latest},
		{"by project", map[string]any{"project_id": "proj-older"}, older},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{"csr_pem": newCSR(t), "server_ip": "10.1.2.3"}
			for k, v := range tc.sel {
				body[k] = v
			}
			rec, out := f.post(t, f.orchestratorToken(t), body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			block, _ := pem.Decode([]byte(out["certificate_pem"].(string)))
			if block == nil {
				t.Fatal("no certificate_pem")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			caBlock, _ := pem.Decode([]byte(out["ca_certificate_pem"].(string)))
			ca, err := x509.ParseCertificate(caBlock.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			pool := x509.NewCertPool()
			pool.AddCert(ca)
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "10.1.2.3", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				t.Fatalf("leaf does not verify against the CA: %v", err)
			}
			if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("10.1.2.3")) {
				t.Fatalf("IP SANs = %v", leaf.IPAddresses)
			}
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "urn:p3dx:fl:contract:"+tc.want.ContractID {
				t.Fatalf("URI SANs = %v", leaf.URIs)
			}
			if !leaf.NotAfter.Equal(tc.want.Lifecycle.ValidUntil.Truncate(time.Second)) {
				t.Fatalf("NotAfter %v, want %v", leaf.NotAfter, tc.want.Lifecycle.ValidUntil.Truncate(time.Second))
			}
			if leaf.Subject.CommonName != "flotilla-gateway-"+tc.want.ProjectID {
				t.Fatalf("CN = %q", leaf.Subject.CommonName)
			}
			fp := sha256.Sum256(block.Bytes)
			if out["fingerprint_sha256"] != hex.EncodeToString(fp[:]) || out["serial"] != leaf.SerialNumber.Text(16) {
				t.Fatalf("fingerprint/serial mismatch: %v", out)
			}
			if out["project_id"] != tc.want.ProjectID || out["contract_id"] != tc.want.ContractID || out["submission_id"] != "sub-1" || out["job_id"] != tc.want.JobID {
				t.Fatalf("ids wrong: %v", out)
			}
			parties, _ := out["parties"].([]any)
			if len(parties) != 1 || parties[0].(map[string]any)["name"] != "alice" || parties[0].(map[string]any)["id"] != "kc-uuid-alice" {
				t.Fatalf("parties = %v", out["parties"])
			}
			last := f.store.inserted[len(f.store.inserted)-1]
			if last.Serial != out["serial"] || last.RequestedBy != "p3dx-fl-orchestrator" || last.ServerIP != "10.1.2.3" || last.ProjectID != tc.want.ProjectID {
				t.Fatalf("recorded %+v", last)
			}
		})
	}
}

func TestPostGatewayCertRejects(t *testing.T) {
	f := newGatewayFixture(t)
	future := time.Now().Add(48 * time.Hour)
	f.store.byProject["proj-ok"] = f.flContract(t, "proj-ok", 2, future, true)
	f.store.byProject["proj-unsigned"] = f.flContract(t, "proj-unsigned", 2, future, false)
	f.store.byProject["proj-draft"] = f.flContract(t, "proj-draft", 1, future, true)
	f.store.byProject["proj-expired"] = f.flContract(t, "proj-expired", 2, time.Now().Add(-time.Hour), true)
	csr := newCSR(t)
	ok := f.orchestratorToken(t)

	weakKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, weakKey)
	weakCSR := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: weakDER}))

	cases := []struct {
		name     string
		token    string
		body     map[string]any
		status   int
		errorTag string
	}{
		{"no token", "", map[string]any{"csr_pem": csr, "server_ip": "10.0.0.1", "project_id": "proj-ok"}, 401, "MISSING_AUTH_TOKEN"},
		{"wrong azp", f.idp.mint(t, jwt.MapClaims{"azp": "flotilla-vm", "realm_access": roles("fl-orchestrator")}),
			map[string]any{"csr_pem": csr, "server_ip": "10.0.0.1", "project_id": "proj-ok"}, 403, "FORBIDDEN"},
		{"missing role", f.idp.mint(t, jwt.MapClaims{"azp": "p3dx-fl-orchestrator", "realm_access": roles("other")}),
			map[string]any{"csr_pem": csr, "server_ip": "10.0.0.1", "project_id": "proj-ok"}, 403, "FORBIDDEN"},
		{"both selectors", ok, map[string]any{"csr_pem": csr, "server_ip": "10.0.0.1", "project_id": "proj-ok", "submission_id": "sub-1"}, 400, "MISSING_FIELDS"},
		{"no selector", ok, map[string]any{"csr_pem": csr, "server_ip": "10.0.0.1"}, 400, "MISSING_FIELDS"},
		{"bad csr", ok, map[string]any{"csr_pem": "not a csr", "server_ip": "10.0.0.1", "project_id": "proj-ok"}, 400, "INVALID_CSR"},
		{"weak csr key", ok, map[string]any{"csr_pem": weakCSR, "server_ip": "10.0.0.1", "project_id": "proj-ok"}, 400, "INVALID_CSR"},
		{"bad ip", ok, map[string]any{"csr_pem": csr, "server_ip": "gateway.local", "project_id": "proj-ok"}, 400, "INVALID_IP"},
		{"no contract", ok, map[string]any{"csr_pem": csr, "server_ip": "10.0.0.1", "project_id": "proj-none"}, 404, "CONTRACT_NOT_FOUND"},
		{"unsigned", ok, map[string]any{"csr_pem": csr, "server_ip": "10.0.0.1", "project_id": "proj-unsigned"}, 409, "CONTRACT_NOT_SIGNED"},
		{"v1 draft", ok, map[string]any{"csr_pem": csr, "server_ip": "10.0.0.1", "project_id": "proj-draft"}, 409, "CONTRACT_NOT_SIGNED"},
		{"expired", ok, map[string]any{"csr_pem": csr, "server_ip": "10.0.0.1", "project_id": "proj-expired"}, 410, "CONTRACT_EXPIRED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, out := f.post(t, tc.token, tc.body)
			if rec.Code != tc.status || out["error"] != tc.errorTag {
				t.Fatalf("got %d %v, want %d %s", rec.Code, out, tc.status, tc.errorTag)
			}
		})
	}
	if len(f.store.inserted) != 0 {
		t.Fatalf("rejected requests recorded certificates: %+v", f.store.inserted)
	}
}

func TestPostGatewayCertRecordFailure(t *testing.T) {
	f := newGatewayFixture(t)
	f.store.byProject["proj-ok"] = f.flContract(t, "proj-ok", 2, time.Now().Add(time.Hour), true)
	f.store.insertErr = errors.New("db down")
	rec, out := f.post(t, f.orchestratorToken(t), map[string]any{"csr_pem": newCSR(t), "server_ip": "10.0.0.1", "project_id": "proj-ok"})
	if rec.Code != http.StatusInternalServerError || out["certificate_pem"] != nil {
		t.Fatalf("got %d %v, want 500 without a certificate", rec.Code, out)
	}
}

func TestGetGovernanceCACert(t *testing.T) {
	f := newGatewayFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/governance/ca-cert", nil)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-pem-file" || !bytes.Equal(rec.Body.Bytes(), f.srv.govCAPEM) {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestProviderTokenIdentityRejectsFlotillaVMToken(t *testing.T) {
	idp := newStubIdP(t)
	srv := newTestServer(&config.Config{ProviderKeyJWKSURL: idp.jwksURL(), FlotillaVMClientID: "flotilla-vm"})
	call := func(azp string) *httptest.ResponseRecorder {
		tok := idp.mint(t, jwt.MapClaims{"azp": azp, "preferred_username": "alice", "sub": "u-1", "realm_access": roles("data-provider")})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		if _, ok := srv.providerTokenIdentity(rec, req); ok {
			rec.Code = http.StatusOK
		}
		return rec
	}
	if rec := call("flotilla-vm"); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "VM_TOKEN_NOT_ALLOWED") {
		t.Fatalf("VM token: got %d %s", rec.Code, rec.Body)
	}
	if rec := call("p3dx-ui"); rec.Code != http.StatusOK {
		t.Fatalf("provider token: got %d %s", rec.Code, rec.Body)
	}
}

func TestDevTokenClaimsRejectsFlotillaVMToken(t *testing.T) {
	idp := newStubIdP(t)
	srv := newTestServer(&config.Config{DataProviderJWKSURL: idp.jwksURL(), FlotillaVMClientID: "flotilla-vm"})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+idp.mint(t, jwt.MapClaims{"azp": "flotilla-vm", "preferred_username": "alice"}))
	rec := httptest.NewRecorder()
	if _, _, ok := srv.devTokenClaims(rec, req, "data provider"); ok || rec.Code != http.StatusForbidden {
		t.Fatalf("VM token accepted: %d %s", rec.Code, rec.Body)
	}
}
