// API specs page (GET /apis): the endpoint docs in apidocs/, embedded into the
// binary and rendered in the browser. Public, no auth — it only describes the
// routes, it calls none of them.
package httpapi

import (
	"embed"
	"net/http"

	"github.com/go-chi/chi/v5"
)

//go:embed apidocs
var apiDocsFS embed.FS

// apiDocs maps the {doc} in GET /apis/{doc}.md to its file in apidocs/.
var apiDocs = map[string]string{
	"governance-layer": "apidocs/governance-layer.md",
}

// registerAPIDocsRoutes mounts the specs page at the root, alongside the TEE
// routes, so it sits at /apis rather than under /api/v1 or /governance.
func (s *Server) registerAPIDocsRoutes(r chi.Router) {
	r.Get("/apis", s.apiDocsPage)
	r.Get("/apis/", s.apiDocsPage)
	r.Get("/apis/{doc}.md", s.apiDocsMarkdown)
}

// GET /apis — the HTML page; it fetches each doc from GET /apis/{doc}.md.
func (s *Server) apiDocsPage(w http.ResponseWriter, r *http.Request) {
	page, err := apiDocsFS.ReadFile("apidocs/index.html")
	if err != nil {
		http.Error(w, "specs page missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}

// GET /apis/{doc}.md — one endpoint doc as raw markdown.
func (s *Server) apiDocsMarkdown(w http.ResponseWriter, r *http.Request) {
	path, ok := apiDocs[chi.URLParam(r, "doc")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	md, err := apiDocsFS.ReadFile(path)
	if err != nil {
		http.Error(w, "doc missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = w.Write(md)
}
