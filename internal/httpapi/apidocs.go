// API specs page (GET /apis): ReDoc rendering the OpenAPI spec in
// apidocs/openapi.yaml, both embedded into the binary. Public, no auth — it
// only describes the routes, it calls none of them.
package httpapi

import (
	"embed"
	"net/http"

	"github.com/go-chi/chi/v5"
)

//go:embed apidocs
var apiDocsFS embed.FS

// registerAPIDocsRoutes mounts the specs page at the root, alongside the TEE
// routes, so it sits at /apis rather than under /api/v1 or /governance.
func (s *Server) registerAPIDocsRoutes(r chi.Router) {
	r.Get("/apis", s.apiDocsPage)
	r.Get("/apis/", s.apiDocsPage)
	r.Get("/apis/spec", s.apiDocsSpec)
}

// GET /apis — the ReDoc page; it loads the spec from GET /apis/spec.
func (s *Server) apiDocsPage(w http.ResponseWriter, r *http.Request) {
	serveAPIDoc(w, "apidocs/index.html", "text/html; charset=utf-8")
}

// GET /apis/spec — the OpenAPI spec as YAML.
func (s *Server) apiDocsSpec(w http.ResponseWriter, r *http.Request) {
	serveAPIDoc(w, "apidocs/openapi.yaml", "application/x-yaml")
}

func serveAPIDoc(w http.ResponseWriter, path, contentType string) {
	body, err := apiDocsFS.ReadFile(path)
	if err != nil {
		http.Error(w, "api docs missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(body)
}
