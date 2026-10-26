package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A missing or out-of-range fl_config is rejected before any DB work, so the
// handler can be exercised on a bare Server.
func TestPostContractFLConfigChecks(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"submission_id":"sub-1"}`, "MISSING_FL_CONFIG"},
		{`{"submission_id":"sub-1","fl_config":{"num_rounds":500,"local_epochs":1,"learning_rate":0.01,"batch_size":32}}`, "num_rounds"},
	} {
		rec := httptest.NewRecorder()
		(&Server{}).postContract(rec, httptest.NewRequest(http.MethodPost, "/contracts", strings.NewReader(tc.body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400; body %s", tc.body, rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("%s: body = %s, want %s", tc.body, rec.Body, tc.want)
		}
	}
}
