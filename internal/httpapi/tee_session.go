package httpapi

// TEE Session API — sequences the individual orchestrator primitives
// (provision -> attest -> run -> poll state -> fetch output) behind one call,
// since nothing else in the platform drives that sequence yet (see
// tee_orchestrator.go's package comment: APD's client only calls provision,
// key-bundle, and terminate). Built for a UI "Run TEE" button: POST
// /v1/tee/sessions kicks the whole sequence off in the background and
// returns immediately with a session id to poll — provisioning alone can
// take minutes (cold CVM boot), so this must not block the request.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
)

type teeSessionStatus string

const (
	teeSessionProvisioning teeSessionStatus = "provisioning"
	teeSessionAttesting    teeSessionStatus = "attesting"
	teeSessionRunning      teeSessionStatus = "running"
	teeSessionComplete     teeSessionStatus = "complete"
	teeSessionFailed       teeSessionStatus = "failed"
	teeSessionTerminated   teeSessionStatus = "terminated"
)

// teeSession tracks one run of the full sequence. In-memory, like teeRegistry
// — a process restart drops in-flight sessions, which is acceptable for the
// same reason teeRegistry accepts it (single-VM demo, not a fleet).
type teeSession struct {
	ID        string
	TEEID     string
	Status    teeSessionStatus
	Error     string
	Output    *teeOutputResult
	CreatedAt time.Time
	UpdatedAt time.Time
}

type teeSessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]*teeSession
}

func newTEESessionRegistry() *teeSessionRegistry {
	return &teeSessionRegistry{sessions: make(map[string]*teeSession)}
}

func (r *teeSessionRegistry) put(s *teeSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s.ID] = s
}

func (r *teeSessionRegistry) get(id string) (*teeSession, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	return s, ok
}

// update mutates the session under lock and stamps UpdatedAt. A no-op if the
// session has since been removed (it never is today, but keeps this safe if
// eviction is added later).
func (r *teeSessionRegistry) update(id string, fn func(*teeSession)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[id]; ok {
		fn(s)
		s.UpdatedAt = time.Now().UTC()
	}
}

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// registerTEESessionRoutes mounts the session API alongside the orchestrator
// primitives in tee_orchestrator.go.
func (s *Server) registerTEESessionRoutes(r chi.Router) {
	r.Route("/v1/tee/sessions", func(r chi.Router) {
		r.Post("/", s.startTEESession)
		r.Route("/{sessionId}", func(r chi.Router) {
			r.Get("/", s.getTEESession)
			r.Get("/output", s.getTEESessionOutput)
			r.Delete("/", s.terminateTEESession)
		})
	})
}

func (s *Server) lookupSession(w http.ResponseWriter, r *http.Request) (*teeSession, bool) {
	id := chi.URLParam(r, "sessionId")
	sess, ok := s.teeSessions.get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, j{
			"status": "FAILED", "error": "UNKNOWN_SESSION", "message": "No such TEE session: " + id,
		})
		return nil, false
	}
	return sess, true
}

// POST /v1/tee/sessions — accepts the same contract shape as
// POST /v1/tee/provision (services.TEEContract) and drives
// provision -> attest -> run -> poll -> output in the background.
func (s *Server) startTEESession(w http.ResponseWriter, r *http.Request) {
	var contract services.TEEContract
	if !s.readBody(w, r, &contract) {
		return
	}

	sessionID := newSessionID()
	now := time.Now().UTC()
	s.teeSessions.put(&teeSession{
		ID: sessionID, Status: teeSessionProvisioning, CreatedAt: now, UpdatedAt: now,
	})

	// Detached from the request context: the sequence outlives this HTTP call
	// by design, so it must not be cancelled when the caller stops waiting.
	go s.runTEESession(context.Background(), sessionID, &contract)

	writeJSON(w, http.StatusAccepted, j{"sessionId": sessionID, "status": string(teeSessionProvisioning)})
}

// runTEESession drives one session end to end, updating its status as it
// goes. Any failure records the step it failed at and stops.
func (s *Server) runTEESession(ctx context.Context, sessionID string, contract *services.TEEContract) {
	inst, _, err := s.doProvisionTEE(ctx, contract)
	if err != nil {
		s.failSession(sessionID, "provision", err)
		return
	}
	s.teeSessions.update(sessionID, func(sess *teeSession) {
		sess.TEEID = inst.TEEID
		sess.Status = teeSessionAttesting
	})

	if _, err := s.doAttestTEE(ctx, inst); err != nil {
		s.failSession(sessionID, "attest", err)
		return
	}
	s.teeSessions.update(sessionID, func(sess *teeSession) { sess.Status = teeSessionRunning })

	if _, err := s.doRunTEE(ctx, inst); err != nil {
		s.failSession(sessionID, "run", err)
		return
	}

	if err := s.waitForCompletion(ctx, inst); err != nil {
		s.failSession(sessionID, "run", err)
		return
	}

	result, err := s.doFetchOutput(ctx, inst, "")
	if err != nil {
		s.failSession(sessionID, "output", err)
		return
	}
	if result.StatusCode < 200 || result.StatusCode >= 300 {
		s.failSession(sessionID, "output", fmt.Errorf("enclave returned HTTP %d fetching output", result.StatusCode))
		return
	}

	s.teeSessions.update(sessionID, func(sess *teeSession) {
		sess.Status = teeSessionComplete
		sess.Output = result
	})
	log.Printf("[TEE] session %s complete (teeId=%s)", sessionID, inst.TEEID)
}

// waitForCompletion polls the enclave's own progress report until it reports
// its final step, or a generous ceiling elapses. The enclave manager is the
// authority on "done" — it isn't guessed from wall-clock time alone.
func (s *Server) waitForCompletion(ctx context.Context, inst *teeInstance) error {
	deadline := time.Now().Add(s.cfg.TEEOutputTimeout * 10)
	for {
		_, state, err := s.doTeeState(ctx, inst, s.cfg.PushTimeout)
		if err == nil && state != nil && state.MaxSteps > 0 && state.Step >= state.MaxSteps {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("anonymisation did not report completion within %s", s.cfg.TEEOutputTimeout*10)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.cfg.TEEPollInterval):
		}
	}
}

func (s *Server) failSession(sessionID, step string, err error) {
	log.Printf("[TEE] session %s failed at %s: %v", sessionID, step, err)
	s.teeSessions.update(sessionID, func(sess *teeSession) {
		sess.Status = teeSessionFailed
		sess.Error = fmt.Sprintf("%s: %v", step, err)
	})
}

// GET /v1/tee/sessions/{sessionId} — current status of a session.
func (s *Server) getTEESession(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.lookupSession(w, r)
	if !ok {
		return
	}

	resp := j{
		"sessionId":  sess.ID,
		"status":     sess.Status,
		"teeId":      sess.TEEID,
		"created_at": sess.CreatedAt,
		"updated_at": sess.UpdatedAt,
	}
	if sess.Error != "" {
		resp["error"] = sess.Error
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /v1/tee/sessions/{sessionId}/output — the anonymised result, once the
// session has completed.
func (s *Server) getTEESessionOutput(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.lookupSession(w, r)
	if !ok {
		return
	}

	switch sess.Status {
	case teeSessionComplete:
		if sess.Output.ContentType != "" {
			w.Header().Set("Content-Type", sess.Output.ContentType)
		}
		if sess.Output.ContentDisposition != "" {
			w.Header().Set("Content-Disposition", sess.Output.ContentDisposition)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sess.Output.Body)
	case teeSessionFailed:
		writeJSON(w, http.StatusUnprocessableEntity, j{
			"status": "FAILED", "error": "SESSION_FAILED", "message": sess.Error,
		})
	default:
		writeJSON(w, http.StatusConflict, j{
			"status": "FAILED", "error": "NOT_READY", "message": "session is still " + string(sess.Status),
		})
	}
}

// DELETE /v1/tee/sessions/{sessionId} — terminate the underlying TEE
// instance (deallocates the VM) and mark the session terminated.
func (s *Server) terminateTEESession(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.lookupSession(w, r)
	if !ok {
		return
	}
	if sess.TEEID == "" {
		writeJSON(w, http.StatusConflict, j{
			"status": "FAILED", "error": "NOT_PROVISIONED", "message": "session has no TEE instance yet",
		})
		return
	}
	inst, ok := s.tees.get(sess.TEEID)
	if !ok {
		writeJSON(w, http.StatusNotFound, j{
			"status": "FAILED", "error": "UNKNOWN_TEE", "message": "underlying TEE instance is gone",
		})
		return
	}

	if err := s.doTerminateTEE(r.Context(), inst); err != nil {
		writeTEEError(w, err)
		return
	}

	s.teeSessions.update(sess.ID, func(sess *teeSession) { sess.Status = teeSessionTerminated })
	writeJSON(w, http.StatusOK, j{"sessionId": sess.ID, "status": string(teeSessionTerminated)})
}
