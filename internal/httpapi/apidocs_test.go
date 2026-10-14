package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// GET /apis serves the ReDoc page and GET /apis/spec the OpenAPI spec.
func TestAPIDocsRoutes(t *testing.T) {
	h := newTestServer(nil).Handler()
	cases := []struct {
		path, wantType, wantBody string
		wantCode                 int
	}{
		{"/apis", "text/html", "redoc.standalone.js", http.StatusOK},
		{"/apis/", "text/html", "redoc.standalone.js", http.StatusOK},
		{"/apis/spec", "application/x-yaml", "openapi: 3.0.2", http.StatusOK},
		{"/apis/governance-layer.md", "", "", http.StatusNotFound},
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

// The spec documents exactly the routes registerRoutes mounts, under /api/v1.
func TestAPIDocsSpecCoversRoutes(t *testing.T) {
	spec, err := apiDocsFS.ReadFile("apidocs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	newTestServer(nil).registerRoutes(r)
	n := 0
	_ = chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		n++
		path := strings.TrimSuffix(route, "/")
		if !strings.Contains(string(spec), "\n  /api/v1"+path+":\n") {
			t.Errorf("spec has no path /api/v1%s", path)
		} else if !specHasMethod(string(spec), "/api/v1"+path, strings.ToLower(method)) {
			t.Errorf("spec has no %s /api/v1%s", method, path)
		}
		return nil
	})
	if n == 0 {
		t.Fatal("no routes walked")
	}
}

// specHasMethod reports whether path's block in the spec has a method key.
func specHasMethod(spec, path, method string) bool {
	_, block, _ := strings.Cut(spec, "\n  "+path+":\n")
	if end := strings.Index(block, "\n  /"); end >= 0 {
		block = block[:end]
	}
	return strings.Contains(block, "\n    "+method+":\n") || strings.HasPrefix(block, "    "+method+":\n")
}
