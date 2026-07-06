// Package httpapi implements the Governance Layer REST API. It reproduces
// src/app.js + src/routes/governance.routes.js: the same endpoints, JSON shapes,
// status codes, CORS behaviour and FL-orchestration semantics, mounted under both
// /api/v1 and /governance.
package httpapi

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/keycloak"
)

// maxBodyBytes mirrors express.json({ limit: "5mb" }).
const maxBodyBytes = 5 * 1024 * 1024

// Server bundles the dependencies shared by every handler.
type Server struct {
	cfg  *config.Config
	db   *db.DB
	kc   *keycloak.Client
	self *selfIPs
	http *http.Client
}

// New builds the Server and kicks off best-effort public-IP discovery (so a
// public IP entered on a form is recognised as "self" — see selfIPs).
func New(cfg *config.Config, database *db.DB, kc *keycloak.Client) *Server {
	s := &Server{
		cfg:  cfg,
		db:   database,
		kc:   kc,
		self: newSelfIPs(cfg.OwnerSelfIPs),
		// No client-level timeout: each outbound call sets its own via context,
		// matching the per-call AbortSignal.timeout(...) values in the Node code.
		http: &http.Client{},
	}
	s.self.discoverPublicIPAsync()
	return s
}

// Handler returns the root http.Handler with CORS + the routes mounted at both
// /api/v1 and /governance.
func (s *Server) Handler() http.Handler {
	root := chi.NewRouter()
	root.Use(s.corsMiddleware)
	root.Route("/api/v1", s.registerRoutes)
	root.Route("/governance", s.registerRoutes)
	return root
}

// registerRoutes wires every endpoint onto the given sub-router. Static segments
// (export, by-submission) precede param routes; chi resolves them correctly.
func (s *Server) registerRoutes(r chi.Router) {
	r.Post("/form-submissions", s.postFormSubmission)
	r.Get("/form-submissions", s.getFormSubmissions)
	r.Get("/form-submissions/export", s.exportFormSubmissions)
	r.Get("/form-submissions/{id}", s.getFormSubmissionByID)
	r.Delete("/form-submissions/{id}", s.deleteFormSubmission)
	r.Get("/form-submissions/{id}/report", s.getSessionReport)

	r.Get("/data-providers", s.getDataProviders)
	r.Post("/send-provider-message", s.sendProviderMessage)

	r.Post("/data-provider-forms", s.postDataProviderForm)
	r.Get("/data-provider-forms", s.getDataProviderForms)

	r.Post("/notifications", s.postNotifications)
	r.Get("/notifications/by-sender/{key}", s.getNotificationsBySender)
	r.Get("/notifications/{key}", s.getNotifications)
	r.Patch("/notifications/{key}/read", s.patchNotificationRead)
	r.Post("/notifications/{key}/respond", s.respondToNotification)

	r.Post("/distribute-config", s.distributeConfig)
	r.Post("/provision-env", s.provisionEnv)
	r.Post("/push-config", s.pushConfig)
	r.Post("/start-fl-session", s.startFLSession)

	r.Get("/client-config/by-submission/{submissionId}", s.clientConfigBySubmission)
	r.Get("/client-config/{username}", s.clientConfigByUsername)
}

// corsMiddleware reproduces the always-allow CORS of app.js: reflect the request
// Origin, advertise GET/POST/OPTIONS + Content-Type/Authorization, and answer
// preflight with 204. A log line is emitted per request, like the Node version.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			log.Println("[CORS] Allowing origin: none")
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			log.Printf("[CORS] Allowing origin: %s", origin)
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// j is a convenience alias for a JSON object literal.
type j = map[string]any

// writeJSON sends v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON reads and decodes a JSON request body (capped at 5MB) into dst.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	return json.NewDecoder(r.Body).Decode(dst)
}

// reqCtx returns the request context for DB/HTTP calls.
func reqCtx(r *http.Request) context.Context { return r.Context() }
