package httpapi

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
)

type flOutputFixture struct {
	idp     *stubIdP
	dir     string
	handler http.Handler
}

// rawSubmission has characters the orchestrator sanitises: its file sid is
// "sub-1_x".
const (
	rawSubmission = "sub-1.x"
	fileSID       = "sub-1_x"
)

func newFLOutputFixture(t *testing.T) *flOutputFixture {
	t.Helper()
	idp := newStubIdP(t)
	t.Setenv("KEYCLOAK_JWKS_URL", idp.jwksURL())
	dir := filepath.Join(t.TempDir(), "checkpoint") // created by the upload
	srv := newTestServer(&config.Config{
		OrchestratorClientID: "p3dx-fl-orchestrator",
		OrchestratorRole:     "fl-orchestrator",
		DataProviderJWKSURL:  idp.jwksURL(),
		CheckpointDir:        dir,
		FLOutputMaxBytes:     1 << 20,
	})
	store := &stubGatewayStore{bySession: map[string]contract.Contract{
		rawSubmission: {Parties: contract.Parties{User: contract.UserParty{ID: "owner-sub"}}},
		fileSID:       {Parties: contract.Parties{User: contract.UserParty{ID: "owner-sub"}}},
	}}
	srv.flContracts = store
	return &flOutputFixture{idp: idp, dir: dir, handler: srv.Handler()}
}

func (f *flOutputFixture) orchestrator(t *testing.T) string {
	return f.idp.mint(t, jwt.MapClaims{"azp": "p3dx-fl-orchestrator", "realm_access": roles("fl-orchestrator")})
}

func (f *flOutputFixture) user(t *testing.T, sub string) string {
	return f.idp.mint(t, jwt.MapClaims{"azp": "p3dx-ui", "sub": sub, "preferred_username": sub + "-name"})
}

func (f *flOutputFixture) do(t *testing.T, method, path, token string, body *bytes.Buffer, ctype string) *httptest.ResponseRecorder {
	t.Helper()
	if body == nil {
		body = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, path, body)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func uploadBody(t *testing.T, metrics, round string, model []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("metrics", metrics)
	_ = mw.WriteField("round", round)
	fw, err := mw.CreateFormFile("model", "model.pt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(model)
	_ = mw.Close()
	return &buf, mw.FormDataContentType()
}

const testMetrics = `{
  "global_validation_metrics": {"Val_Accuracy": [0.5, "0.75", 0.9], "val_loss": [1.2, 0.8, "0.4"], "f1": [0.1, 0.2, 0.3]},
  "session_config": {"train": {"num_training_rounds": 10}},
  "start_timestamp": 1, "end_timestamp": "x", "last_checkpoint_round": 3, "rounds_total": null
}`

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad JSON %q: %v", rec.Body.String(), err)
	}
	return m
}

func TestFLOutputUploadRequiresServiceToken(t *testing.T) {
	f := newFLOutputFixture(t)
	body, ct := uploadBody(t, testMetrics, "3", []byte("weights"))
	if rec := f.do(t, http.MethodPost, "/api/v1/fl-output/"+rawSubmission, "", body, ct); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d %s", rec.Code, rec.Body)
	}
	body, ct = uploadBody(t, testMetrics, "3", []byte("weights"))
	if rec := f.do(t, http.MethodPost, "/api/v1/fl-output/"+rawSubmission, f.user(t, "owner-sub"), body, ct); rec.Code != http.StatusForbidden {
		t.Fatalf("user token: got %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(f.dir); !os.IsNotExist(err) {
		t.Fatalf("checkpoint dir created by a refused upload: %v", err)
	}
}

func TestFLOutputRoundTrip(t *testing.T) {
	f := newFLOutputFixture(t)
	owner := f.user(t, "owner-sub")
	base := "/governance/fl-output/" + rawSubmission

	// Before upload: authorised, not_found.
	rec := f.do(t, http.MethodGet, base, owner, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("pre-upload GET: %d %s", rec.Code, rec.Body)
	}
	m := decode(t, rec)
	if m["status"] != "not_found" || m["artifact"] != nil || m["fetched_at"] != nil || m["session_id"] != fileSID {
		t.Fatalf("pre-upload body: %v", m)
	}
	if rec := f.do(t, http.MethodGet, base+"/download", owner, nil, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("pre-upload download: %d", rec.Code)
	}

	model := bytes.Repeat([]byte{0, 1, 2, 3, 0xff}, 1000)
	body, ct := uploadBody(t, testMetrics, "3", model)
	rec = f.do(t, http.MethodPost, base, f.orchestrator(t), body, ct)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body)
	}
	m = decode(t, rec)
	if m["status"] != "stored" || m["session_id"] != fileSID || m["file"] != "model_sub-1_x_round_3.pt" || m["size_bytes"] != float64(len(model)) {
		t.Fatalf("upload body: %v", m)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "output_"+fileSID+".json")); err != nil {
		t.Fatal(err)
	}

	rec = f.do(t, http.MethodGet, base, owner, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", rec.Code, rec.Body)
	}
	var got struct {
		Status string `json:"status"`
		Rounds struct {
			Done  int  `json:"done"`
			Total *int `json:"total"`
		} `json:"rounds"`
		Final    struct{ Accuracy, Loss *float64 } `json:"final"`
		PerRound []flRound                         `json:"per_round"`
		Artifact *struct {
			File       string `json:"file"`
			SizeBytes  int64  `json:"size_bytes"`
			ModifiedAt string `json:"modified_at"`
		} `json:"artifact"`
		FetchedAt *string `json:"fetched_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "ready" || got.Rounds.Done != 3 || got.Rounds.Total == nil || *got.Rounds.Total != 10 {
		t.Fatalf("status/rounds: %s", rec.Body)
	}
	if got.Final.Accuracy == nil || *got.Final.Accuracy != 0.9 || got.Final.Loss == nil || *got.Final.Loss != 0.4 {
		t.Fatalf("final: %s", rec.Body)
	}
	if len(got.PerRound) != 3 || got.PerRound[1].Round != 2 || *got.PerRound[1].Accuracy != 0.75 || *got.PerRound[0].Loss != 1.2 {
		t.Fatalf("per_round: %s", rec.Body)
	}
	if got.Artifact == nil || got.Artifact.File != "model_sub-1_x_round_3.pt" || got.Artifact.SizeBytes != int64(len(model)) || got.FetchedAt == nil {
		t.Fatalf("artifact/fetched_at: %s", rec.Body)
	}

	// Download returns the exact bytes as an attachment.
	rec = f.do(t, http.MethodGet, base+"/download", owner, nil, "")
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), model) {
		t.Fatalf("download: %d len=%d", rec.Code, rec.Body.Len())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, "model_sub-1_x_round_3.pt") {
		t.Fatalf("Content-Disposition: %q", cd)
	}

	// Non-owner and anonymous are refused.
	other := f.user(t, "someone-else")
	for _, p := range []string{base, base + "/download"} {
		if rec := f.do(t, http.MethodGet, p, other, nil, ""); rec.Code != http.StatusForbidden {
			t.Fatalf("non-owner %s: %d %s", p, rec.Code, rec.Body)
		}
		if rec := f.do(t, http.MethodGet, p, "", nil, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous %s: %d", p, rec.Code)
		}
	}
	// Summary is owner-gated too (by file sid).
	if rec := f.do(t, http.MethodGet, "/api/v1/final-model/summary?session_id="+fileSID, other, nil, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("summary non-owner: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, http.MethodGet, "/api/v1/final-model/summary?session_id="+fileSID, "", nil, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("summary anonymous: %d", rec.Code)
	}
}

func TestFLOutputUnknownContractAndBadID(t *testing.T) {
	f := newFLOutputFixture(t)
	owner := f.user(t, "owner-sub")
	if rec := f.do(t, http.MethodGet, "/api/v1/fl-output/no-such-session", owner, nil, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown contract: %d %s", rec.Code, rec.Body)
	}
	long := strings.Repeat("a", flMaxSIDLen+1)
	if rec := f.do(t, http.MethodGet, "/api/v1/fl-output/"+long, owner, nil, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("long id GET: %d", rec.Code)
	}
	body, ct := uploadBody(t, testMetrics, "1", []byte("x"))
	if rec := f.do(t, http.MethodPost, "/api/v1/fl-output/"+long, f.orchestrator(t), body, ct); rec.Code != http.StatusBadRequest {
		t.Fatalf("long id POST: %d", rec.Code)
	}
	if rec := f.do(t, http.MethodGet, "/api/v1/final-model/summary?session_id=..%2Fetc", owner, nil, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("summary bad id: %d", rec.Code)
	}
	if _, ok := flSessionID(""); ok {
		t.Fatal("empty id accepted")
	}
	// Bad round / missing parts.
	body, ct = uploadBody(t, testMetrics, "0", []byte("x"))
	if rec := f.do(t, http.MethodPost, "/api/v1/fl-output/"+rawSubmission, f.orchestrator(t), body, ct); rec.Code != http.StatusBadRequest {
		t.Fatalf("round 0: %d", rec.Code)
	}
	// Oversized upload.
	body, ct = uploadBody(t, testMetrics, "1", make([]byte, 2<<20))
	if rec := f.do(t, http.MethodPost, "/api/v1/fl-output/"+rawSubmission, f.orchestrator(t), body, ct); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: %d %s", rec.Code, rec.Body)
	}
	if entries, _ := os.ReadDir(f.dir); len(entries) != 0 {
		t.Fatalf("leftover files after failed uploads: %v", entries)
	}
}

func TestFLPerRoundNormalisation(t *testing.T) {
	pr := flPerRound(map[string]any{"global_validation_metrics": map[string]any{
		"LOSS":     []any{[]any{1.0, 2.5}, "bad"},
		"accuracy": []any{0.1},
	}})
	if len(pr) != 2 || *pr[0].Accuracy != 0.1 || pr[1].Accuracy != nil || *pr[0].Loss != 2.5 || pr[1].Loss != nil {
		t.Fatalf("%+v", pr)
	}
	if n, ok := flFindRounds(map[string]any{"cfg": map[string]any{"Num_Server_Rounds": "5"}}, 0); !ok || n != 5 {
		t.Fatalf("rounds: %d %v", n, ok)
	}
}
