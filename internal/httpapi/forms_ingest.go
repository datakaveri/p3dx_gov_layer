package httpapi

// This file receives form data pushed by aaa (the store of record for FL
// forms) so FL orchestration and reports have a local copy to read instead
// of pulling from aaa on every request. See db/forms_cache.go.

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// requireFormsPushToken guards the ingest routes with an optional shared
// secret (FORMS_PUSH_TOKEN). Left unset, the check is skipped — matching this
// service's existing internal, network-trust-only endpoints.
func (s *Server) requireFormsPushToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.FormsPushToken == "" {
			next(w, r)
			return
		}
		if r.Header.Get("X-Forms-Push-Token") != s.cfg.FormsPushToken {
			writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "FORBIDDEN"})
			return
		}
		next(w, r)
	}
}

// registerFormsIngestRoutes mounts the push-receiver routes aaa calls after
// every form create/delete. Not part of the /api/v1 or /governance public
// API tree, and not CORS-guarded — this is a server-to-server call from aaa,
// never a browser.
func (s *Server) registerFormsIngestRoutes(r chi.Router) {
	r.Post("/submissions", s.requireFormsPushToken(s.ingestFormSubmission))
	r.Delete("/submissions/{id}", s.requireFormsPushToken(s.ingestFormSubmissionDeleted))
	r.Post("/provider-forms", s.requireFormsPushToken(s.ingestDataProviderForm))
}

// POST /internal/forms/submissions — aaa pushes a submission here right
// after storing it.
func (s *Server) ingestFormSubmission(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Submission db.FormSubmission `json:"submission"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	if body.Submission.ID == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_ID"})
		return
	}
	s.db.IngestFormSubmission(body.Submission, time.Now())
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS"})
}

// DELETE /internal/forms/submissions/{id} — aaa pushes a delete here.
func (s *Server) ingestFormSubmissionDeleted(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.db.RemoveFormSubmission(reqCtx(r), id)
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS"})
}

// POST /internal/forms/provider-forms — aaa pushes a data-provider form here
// right after storing it.
func (s *Server) ingestDataProviderForm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Form db.DataProviderForm `json:"form"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	if body.Form.ID == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_ID"})
		return
	}
	s.db.IngestDataProviderForm(body.Form, time.Now())
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS"})
}
