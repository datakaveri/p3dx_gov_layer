package httpapi

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// readyPingTimeout bounds the database ping behind GET /ready, so a hung
// Postgres fails the probe instead of hanging it.
const readyPingTimeout = 2 * time.Second

// pinger is the database check behind GET /ready — *postgres.DB in
// production; stubbed in tests.
type pinger interface {
	Ping(ctx context.Context) error
}

// registerHealthRoutes mounts the Kubernetes probes at the root. Handler puts
// them outside corsMiddleware so probe traffic doesn't flood the CORS log.
func (s *Server) registerHealthRoutes(r chi.Router) {
	r.Get("/health", s.health)
	r.Get("/ready", s.ready)
}

// GET /health — liveness: the process is up and serving HTTP. It checks no
// dependencies, so a database outage never gets the pod restarted.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, j{"status": "UP"})
}

// GET /ready — readiness: 200 while Postgres answers a ping, 503 otherwise,
// so Kubernetes stops routing traffic here until the database is back.
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.dbPing != nil {
		ctx, cancel := context.WithTimeout(reqCtx(r), readyPingTimeout)
		defer cancel()
		if err := s.dbPing.Ping(ctx); err != nil {
			log.Printf("[READY] Database ping failed: %v", err)
			writeJSON(w, http.StatusServiceUnavailable, j{"status": "DOWN", "database": "DOWN"})
			return
		}
	}
	writeJSON(w, http.StatusOK, j{"status": "UP", "database": "UP"})
}
