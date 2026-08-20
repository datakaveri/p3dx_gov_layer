// Package httpapi implements the Governance Layer REST API: the routing
// table, CORS, and every handler, mounted under both /api/v1 and /governance.
//
// Files prefixed fl_ are FL-specific (participation notifications). contracts.go
// handles contract management. general_contract.go handles the general pathway
// (POST /contract — pre-built contracts with policy checks). model.go handles
// final model retrieval. server.go itself is shared infra.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/keycloak"
)

// maxBodyBytes mirrors express.json({ limit: "5mb" }).
const maxBodyBytes = 5 * 1024 * 1024

// Server bundles the dependencies shared by every handler.
type Server struct {
	cfg *config.Config
	db  *db.DB
	kc  *keycloak.Client
	http *http.Client
	// tees tracks live TEE instances for the orchestrator API
	// (tee_orchestrator.go).
	tees *teeRegistry
}

// New builds the Server.
func New(cfg *config.Config, database *db.DB, kc *keycloak.Client) *Server {
	return &Server{
		cfg: cfg,
		db:  database,
		kc:  kc,
		// No client-level timeout: each outbound call sets its own via context.
		http: &http.Client{},
		tees: newTEERegistry(),
	}
}

// Handler returns the root http.Handler with CORS + the routes mounted at both
// /api/v1 and /governance.
func (s *Server) Handler() http.Handler {
	root := chi.NewRouter()
	root.Use(s.corsMiddleware)
	root.Route("/api/v1", s.registerRoutes)
	root.Route("/governance", s.registerRoutes)
	// TEE orchestrator API, mounted at the root: APD builds its request URLs as
	// {TEE_ORCHESTRATOR_URL}/v1/tee/... so these must not sit under /api/v1.
	s.registerTEERoutes(root)
	return root
}

// registerRoutes wires every endpoint onto the given sub-router. Static segments
// (export, by-submission) precede param routes; chi resolves them correctly.
func (s *Server) registerRoutes(r chi.Router) {
	r.Get("/data-providers", s.getDataProviders)
	r.Post("/send-provider-message", s.sendProviderMessage)

	// participation-consent notifications (fl_notifications.go)
	r.Post("/notifications", s.postNotifications)
	r.Get("/notifications/by-sender/{key}", s.getNotificationsBySender)
	r.Get("/notifications/{key}", s.getNotifications)
	r.Patch("/notifications/{key}/read", s.patchNotificationRead)
	r.Post("/notifications/{key}/respond", s.respondToNotification)

	// Single contract endpoint for both pathways:
	// Routes to FL, TEE, or SMPC orchestration based on technique field
		r.Post("/contract", s.handleContract)
	r.Get("/contract/{sessionId}", s.getContract)

	// Builds and returns an unsigned contract for display given just a
	// dataset + technique selection (generate_contract.go). Does not sign,
	// store, or deploy — that's still gated on POST /contract above, once
	// the consumer-signing model is resolved.
	r.Post("/generate-contract", s.handleGenerateContract)

	r.Get("/final-models", s.getFinalModels)
	r.Get("/final-model/download", s.getFinalModelDownload)
	r.Get("/final-model/summary", s.getFinalModelSummary)
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

// readBody decodes a JSON request body into dst. An empty body is treated as
// an empty object (matching express.json). A genuine JSON syntax error
// responds 400 INVALID_JSON and returns false.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	err := decodeJSON(w, r, dst)
	if err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "INVALID_JSON", "message": "Invalid JSON in request body",
		})
		return false
	}
	return true
}

// nowISO renders the current UTC time as an ISO-8601 string (matching JS
// new Date().toISOString()).
func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
}
