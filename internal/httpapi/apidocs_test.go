package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// GET /apis serves the specs page and GET /apis/{doc}.md each embedded doc;
// an unknown doc is 404.
func TestAPIDocsRoutes(t *testing.T) {
	h := newTestServer(nil).Handler()
	cases := []struct {
		path, wantType, wantBody string
		wantCode                 int
	}{
		{"/apis", "text/html", "Governance Layer APIs", http.StatusOK},
		{"/apis/", "text/html", "Governance Layer APIs", http.StatusOK},
		{"/apis/governance-layer.md", "text/markdown", "/provider-keys/{role}", http.StatusOK},
		{"/apis/governance-tee.md", "", "", http.StatusNotFound},
		{"/apis/nope.md", "", "", http.StatusNotFound},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		if rec.Code != c.wantCode {
			t.Errorf("%s: status %d, want %d", c.path, rec.Code, c.wantCode)
			continue
		}
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), c.wantType) {
			t.Errorf("%s: Content-Type %q, want %s", c.path, rec.Header().Get("Content-Type"), c.wantType)
		}
		if !strings.Contains(rec.Body.String(), c.wantBody) {
			t.Errorf("%s: body missing %q", c.path, c.wantBody)
		}
	}
}
