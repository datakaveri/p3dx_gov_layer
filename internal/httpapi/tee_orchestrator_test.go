package httpapi

// Tests for the TEE orchestrator API. These exercise the real chi router via
// httptest and never touch Postgres — the /v1/tee routes don't use s.db, so a
// Server with a nil db is sufficient. Routes whose happy path shells out to the
// `az` CLI (provision success, terminate) are deliberately not covered here;
// what is covered is every path that rejects before reaching Azure, plus the
// output proxy against a stub enclave manager.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
)

// newTestServer builds a Server wired for the TEE routes only.
func newTestServer(cfg *config.Config) *Server {
	if cfg == nil {
		cfg = &config.Config{}
	}
	if cfg.TEEEnclavePort == "" {
		cfg.TEEEnclavePort = "4000"
	}
	if cfg.PushTimeout == 0 {
		cfg.PushTimeout = 5 * time.Second
	}
	if cfg.TEEOutputTimeout == 0 {
		cfg.TEEOutputTimeout = 5 * time.Second
	}
	return New(cfg, nil, nil)
}

func validContract() services.TEEContract {
	now := time.Now()
	return services.TEEContract{
		ContractID: "c-1",
		RequestID:  "r-1",
		ConsumerID: "consumer-1",
		ProviderID: "provider-1",
		AppDetails: services.TEEAppDetails{
			ImageID:   "ghcr.io/datakaveri/skald",
			ImageHash: "sha256:deadbeef",
			Version:   "1.0",
		},
		DatasetDetails: services.TEEDatasetDetails{
			ItemID:    "8bdebc63-ccb0-4930-bdbb-60ea9d7f7599",
			AssetName: "patients",
			// Load-bearing: this is relayed to the enclave as the dataset to
			// anonymise, so validation requires it.
			ResourceURL: "https://anondata2.blob.core.windows.net/encrypted-data/patients.csv.enc",
		},
		IssuedAt:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}
}

func TestValidateTEEContract(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		mutate  func(*services.TEEContract)
		wantErr string
	}{
		{name: "valid", mutate: func(*services.TEEContract) {}},
		{
			name:    "missing contractId",
			mutate:  func(c *services.TEEContract) { c.ContractID = "" },
			wantErr: "contractId is required",
		},
		{
			name:    "missing requestId",
			mutate:  func(c *services.TEEContract) { c.RequestID = "" },
			wantErr: "requestId is required",
		},
		{
			name:    "missing imageHash",
			mutate:  func(c *services.TEEContract) { c.AppDetails.ImageHash = "" },
			wantErr: "appDetails.imageHash is required",
		},
		{
			name:    "missing dataset itemId",
			mutate:  func(c *services.TEEContract) { c.DatasetDetails.ItemID = "" },
			wantErr: "datasetDetails.itemId is required",
		},
		{
			name:    "missing dataset resourceUrl",
			mutate:  func(c *services.TEEContract) { c.DatasetDetails.ResourceURL = "" },
			wantErr: "datasetDetails.resourceUrl is required",
		},
		{
			// The guest fetches this URL with its managed identity, so a
			// plaintext scheme would put a bearer token on the wire.
			name:    "non-https dataset URL",
			mutate:  func(c *services.TEEContract) { c.DatasetDetails.ResourceURL = "http://acct.blob.core.windows.net/c/d.enc" },
			wantErr: "must be an absolute https URL",
		},
		{
			name:    "non-URL dataset location",
			mutate:  func(c *services.TEEContract) { c.DatasetDetails.ResourceURL = "just-a-name.csv" },
			wantErr: "must be an absolute https URL",
		},
		{
			// file:// would make the guest read its own disk instead of the
			// contracted dataset.
			name:    "file scheme dataset URL",
			mutate:  func(c *services.TEEContract) { c.DatasetDetails.ResourceURL = "file:///etc/passwd" },
			wantErr: "must be an absolute https URL",
		},
		{
			// A zero expiry is a caller that sent no window at all — distinct
			// from one that sent a window which has since passed.
			name:    "absent expiry",
			mutate:  func(c *services.TEEContract) { c.ExpiresAt = time.Time{} },
			wantErr: "expiresAt is required",
		},
		{
			name:    "expired",
			mutate:  func(c *services.TEEContract) { c.ExpiresAt = now.Add(-time.Hour) },
			wantErr: "contract expired at",
		},
		{
			name:    "not yet valid",
			mutate:  func(c *services.TEEContract) { c.IssuedAt = now.Add(time.Hour) },
			wantErr: "not valid until",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validContract()
			tc.mutate(&c)

			err := services.ValidateTEEContract(&c, now)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid contract, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestValidateTEEContractNil(t *testing.T) {
	if err := services.ValidateTEEContract(nil, time.Now()); err == nil {
		t.Fatal("expected error for nil contract")
	}
}

// A malformed contract must be rejected before any Azure call is attempted.
func TestProvisionRejectsInvalidContract(t *testing.T) {
	srv := newTestServer(&config.Config{TEEAzureRG: "TEE", TEEVMName: "vm-1"})

	body := `{"contractId":"c-1"}` // no requestId, no app/dataset details, no expiry
	req := httptest.NewRequest(http.MethodPost, "/v1/tee/provision", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if resp["error"] != "INVALID_CONTRACT" {
		t.Fatalf("expected error INVALID_CONTRACT, got %v", resp["error"])
	}
}

// With no VM configured, provisioning must fail loudly rather than shelling out
// to `az` with empty arguments.
func TestProvisionRequiresVMConfig(t *testing.T) {
	srv := newTestServer(&config.Config{}) // no TEE_AZURE_RG / TEE_VM_NAME

	c := validContract()
	body, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/tee/provision", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] != "TEE_NOT_CONFIGURED" {
		t.Fatalf("expected error TEE_NOT_CONFIGURED, got %v", resp["error"])
	}
}

func TestUnknownTEEIsNotFound(t *testing.T) {
	srv := newTestServer(nil)

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/v1/tee/nope/output"},
		{http.MethodPost, "/v1/tee/nope/run"},
		{http.MethodPost, "/v1/tee/nope/key-bundle"},
		{http.MethodDelete, "/v1/tee/nope/terminate"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("expected 404, got %d (body: %s)", rec.Code, rec.Body.String())
			}
			var resp map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			if resp["error"] != "UNKNOWN_TEE" {
				t.Fatalf("expected error UNKNOWN_TEE, got %v", resp["error"])
			}
		})
	}
}

// The key-bundle relay must reject rather than silently accept: on this path the
// dataset key comes from Key Vault, so accepting a bundle would look like a key
// had been delivered when nothing consumed it.
func TestKeyBundleNotImplemented(t *testing.T) {
	srv := newTestServer(nil)
	srv.tees.put(&teeInstance{TEEID: "t-1", ContractID: "c-1", EnclaveBase: "http://127.0.0.1:1"})

	req := httptest.NewRequest(http.MethodPost, "/v1/tee/t-1/key-bundle",
		strings.NewReader(`{"requestId":"r-1","encryptedBundle":"AAAA"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] != "KEY_BUNDLE_NOT_SUPPORTED" {
		t.Fatalf("expected error KEY_BUNDLE_NOT_SUPPORTED, got %v", resp["error"])
	}
}

// The output route must pass the enclave's response through unchanged, including
// status code, content type, and the ?file= query — otherwise a CSV download
// arrives as something else.
func TestOutputProxiesEnclaveResponse(t *testing.T) {
	var gotPath, gotQuery string
	enclave := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="out.csv"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PatientID,Age\nabc,30\n"))
	}))
	defer enclave.Close()

	srv := newTestServer(nil)
	srv.tees.put(&teeInstance{TEEID: "t-1", ContractID: "c-1", EnclaveBase: enclave.URL})

	req := httptest.NewRequest(http.MethodGet, "/v1/tee/t-1/output?file=out.csv", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotPath != "/enclave/output" {
		t.Fatalf("expected enclave path /enclave/output, got %q", gotPath)
	}
	if gotQuery != "file=out.csv" {
		t.Fatalf("expected query to be forwarded, got %q", gotQuery)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/csv" {
		t.Fatalf("expected Content-Type text/csv, got %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "out.csv") {
		t.Fatalf("expected Content-Disposition forwarded, got %q", cd)
	}
	if body := rec.Body.String(); !strings.Contains(body, "PatientID,Age") {
		t.Fatalf("expected output body forwarded, got %q", body)
	}
}

// A 404 from the enclave (no output yet) must reach the caller as a 404.
func TestOutputForwardsEnclaveNotFound(t *testing.T) {
	enclave := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"title":"Error: No output"}`))
	}))
	defer enclave.Close()

	srv := newTestServer(nil)
	srv.tees.put(&teeInstance{TEEID: "t-1", EnclaveBase: enclave.URL})

	req := httptest.NewRequest(http.MethodGet, "/v1/tee/t-1/output", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 forwarded, got %d", rec.Code)
	}
}

// An unreachable enclave must produce a clean 502, not a hang or a panic.
func TestOutputUnreachableEnclave(t *testing.T) {
	srv := newTestServer(nil)
	// Port 1 on loopback refuses connections immediately.
	srv.tees.put(&teeInstance{TEEID: "t-1", EnclaveBase: "http://127.0.0.1:1"})

	req := httptest.NewRequest(http.MethodGet, "/v1/tee/t-1/output", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] != "ENCLAVE_UNREACHABLE" {
		t.Fatalf("expected ENCLAVE_UNREACHABLE, got %v", resp["error"])
	}
}

// The run trigger forwards contract/tee ids so the guest can log which contract
// it is executing.
func TestRunPostsIdsToEnclave(t *testing.T) {
	var gotBody, gotPath string
	enclave := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"title":"Success"}`))
	}))
	defer enclave.Close()

	srv := newTestServer(nil)
	srv.tees.put(&teeInstance{TEEID: "t-1", ContractID: "c-1", EnclaveBase: enclave.URL})

	req := httptest.NewRequest(http.MethodPost, "/v1/tee/t-1/run", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if gotPath != "/enclave/run" {
		t.Fatalf("expected /enclave/run, got %q", gotPath)
	}
	if !strings.Contains(gotBody, `"contract_id":"c-1"`) || !strings.Contains(gotBody, `"tee_id":"t-1"`) {
		t.Fatalf("expected contract_id and tee_id in body, got %q", gotBody)
	}
}

// A rejected run (e.g. a run already in progress) must surface as 502 with the
// enclave's own explanation, not a bare success.
func TestRunRejectedByEnclave(t *testing.T) {
	enclave := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"description":"already running"}`))
	}))
	defer enclave.Close()

	srv := newTestServer(nil)
	srv.tees.put(&teeInstance{TEEID: "t-1", EnclaveBase: enclave.URL})

	req := httptest.NewRequest(http.MethodPost, "/v1/tee/t-1/run", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] != "RUN_REJECTED" {
		t.Fatalf("expected RUN_REJECTED, got %v", resp["error"])
	}
	if detail, _ := resp["detail"].(string); !strings.Contains(detail, "already running") {
		t.Fatalf("expected enclave detail forwarded, got %v", resp["detail"])
	}
}

// enclaveBaseURL builds from IP+port, but an explicit base URL wins.
func TestEnclaveBaseURL(t *testing.T) {
	srv := newTestServer(&config.Config{TEEVMIP: "10.0.0.4", TEEEnclavePort: "4000"})
	if got := srv.enclaveBaseURL(); got != "http://10.0.0.4:4000" {
		t.Fatalf("expected http://10.0.0.4:4000, got %q", got)
	}

	srv = newTestServer(&config.Config{
		TEEVMIP:           "10.0.0.4",
		TEEEnclavePort:    "4000",
		TEEEnclaveBaseURL: "https://tee.example.internal",
	})
	if got := srv.enclaveBaseURL(); got != "https://tee.example.internal" {
		t.Fatalf("expected the explicit base URL to win, got %q", got)
	}
}

// ---- attestation gate -------------------------------------------------------

// A run must be refused until the TEE has attested. This is the enforcement
// point: without it, attestation would be decorative.
func TestRunBlockedWithoutAttestation(t *testing.T) {
	srv := newTestServer(&config.Config{TEEAttestationRequired: true, TEEAttestationTTL: time.Hour})
	srv.tees.put(&teeInstance{TEEID: "t-1", EnclaveBase: "http://127.0.0.1:1"})

	req := httptest.NewRequest(http.MethodPost, "/v1/tee/t-1/run", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] != "ATTESTATION_REQUIRED" {
		t.Fatalf("expected ATTESTATION_REQUIRED, got %v", resp["error"])
	}
}

// A verdict older than the TTL must not keep authorising runs — the guest could
// have changed since it was taken.
func TestRunBlockedWhenAttestationStale(t *testing.T) {
	srv := newTestServer(&config.Config{TEEAttestationRequired: true, TEEAttestationTTL: time.Minute})
	srv.tees.put(&teeInstance{
		TEEID:       "t-1",
		EnclaveBase: "http://127.0.0.1:1",
		Attestation: &services.AttestationResult{AttestationType: "sevsnpvm"},
		AttestedAt:  time.Now().Add(-2 * time.Hour),
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/tee/t-1/run", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for a stale verdict, got %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	msg, _ := resp["message"].(string)
	if !strings.Contains(msg, "expired") {
		t.Fatalf("expected the message to say the attestation expired, got %q", msg)
	}
}

// With a fresh verdict the run proceeds and the dataset URL from the contract is
// relayed to the enclave.
func TestRunAllowedWithFreshAttestationRelaysDataset(t *testing.T) {
	var gotBody string
	enclave := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"title":"Success"}`))
	}))
	defer enclave.Close()

	srv := newTestServer(&config.Config{TEEAttestationRequired: true, TEEAttestationTTL: time.Hour})
	srv.tees.put(&teeInstance{
		TEEID:       "t-1",
		ContractID:  "c-1",
		DatasetURL:  "https://acct.blob.core.windows.net/c/data.csv.enc",
		EnclaveBase: enclave.URL,
		Attestation: &services.AttestationResult{AttestationType: "sevsnpvm"},
		AttestedAt:  time.Now(),
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/tee/t-1/run", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(gotBody, `"dataset_url":"https://acct.blob.core.windows.net/c/data.csv.enc"`) {
		t.Fatalf("contract dataset URL was not relayed to the enclave, got %q", gotBody)
	}
}

// The escape hatch must actually work, so local development is possible without
// silently pretending an unattested VM was attested.
func TestRunAllowedWhenAttestationNotRequired(t *testing.T) {
	enclave := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"title":"Success"}`))
	}))
	defer enclave.Close()

	srv := newTestServer(&config.Config{TEEAttestationRequired: false})
	srv.tees.put(&teeInstance{TEEID: "t-1", EnclaveBase: enclave.URL})

	req := httptest.NewRequest(http.MethodPost, "/v1/tee/t-1/run", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 when attestation is not required, got %d", rec.Code)
	}
}

// Attestation cannot even be attempted without a trusted issuer configured.
func TestAttestRefusedWithoutIssuers(t *testing.T) {
	srv := newTestServer(&config.Config{})
	srv.tees.put(&teeInstance{TEEID: "t-1", EnclaveBase: "http://127.0.0.1:1"})

	req := httptest.NewRequest(http.MethodPost, "/v1/tee/t-1/attest", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] != "ATTESTATION_NOT_CONFIGURED" {
		t.Fatalf("expected ATTESTATION_NOT_CONFIGURED, got %v", resp["error"])
	}
}

func TestAttestationFreshness(t *testing.T) {
	inst := &teeInstance{TEEID: "t-1"}
	if inst.attestationFresh(time.Hour, time.Now()) {
		t.Error("an instance with no attestation must never be fresh")
	}
	inst.Attestation = &services.AttestationResult{}
	inst.AttestedAt = time.Now()
	if !inst.attestationFresh(time.Hour, time.Now()) {
		t.Error("a just-verified attestation should be fresh")
	}
	if inst.attestationFresh(time.Minute, time.Now().Add(2*time.Hour)) {
		t.Error("a verdict past its TTL must not be fresh")
	}
}
