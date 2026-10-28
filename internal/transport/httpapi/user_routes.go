// User-facing routes for the P3DX UI, which calls gov_layer directly now that
// p3dx-aaa is gone. Every route here needs the user's Keycloak token, and the
// /me routes take the caller's identity from it — never from the URL or body.

package httpapi

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

type userCtxKey struct{}

// consumerRole is the DX realm role of a data consumer (the old P3DX "user").
const consumerRole = "consumer"

// requireUser validates the bearer token (see providerTokenIdentity) and puts
// the caller's identity on the request context for userFrom.
func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.providerTokenIdentity(w, r)
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userCtxKey{}, id)))
	})
}

// requireUserRole is requireUser plus a realm-role check.
func (s *Server) requireUserRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return s.requireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !slices.Contains(userFrom(r).roles, role) {
				writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "INSUFFICIENT_ROLE"})
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

func userFrom(r *http.Request) providerIdentity {
	id, _ := r.Context().Value(userCtxKey{}).(providerIdentity)
	return id
}

// registerUserRoutes mounts the /me routes (under /api/v1 and /governance).
func (s *Server) registerUserRoutes(r chi.Router) {
	r.Route("/me", func(r chi.Router) {
		r.Use(s.requireUser)
		r.Get("/notifications", s.getMyNotifications)
		r.Get("/notifications/stream", s.streamMyNotifications)
		r.Get("/notifications/sent", s.getMySentNotifications)
		r.Post("/notifications/{id}/read", s.markMyNotificationRead)
		r.Post("/notifications/{id}/respond", s.respondToMyNotification)
		r.With(s.requireUserRole(devProviderRole)).Get("/sign-requests", s.getMySignRequests)
		r.Get("/jobs", s.getMyJobs)
		r.Get("/projects", s.getMyProjects)
		// FL session flow (fl_session.go).
		s.registerFLSessionRoutes(r)
	})
}

// GET /me/notifications — the caller's inbox, with its unread count.
func (s *Server) getMyNotifications(w http.ResponseWriter, r *http.Request) {
	rows, ok := s.notificationsFor(w, r, userFrom(r).username)
	if !ok {
		return
	}
	unread := 0
	for _, n := range rows {
		if !n.Read {
			unread++
		}
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "notifications": rows, "unread_count": unread})
}

// GET /me/notifications/sent — what the caller has sent (an FL output owner
// watching each provider's participation response).
func (s *Server) getMySentNotifications(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.GetNotificationsBySender(reqCtx(r), userFrom(r).username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if rows == nil {
		rows = []postgres.Notification{}
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "notifications": rows})
}

// POST /me/notifications/{id}/read — only marks the caller's own notification.
func (s *Server) markMyNotificationRead(w http.ResponseWriter, r *http.Request) {
	updated, err := s.db.MarkNotificationAsRead(reqCtx(r), chi.URLParam(r, "id"), userFrom(r).username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if updated == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND"})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "notification": updated})
}

// POST /me/notifications/{id}/respond — body {response, message}; answers as
// the caller.
func (s *Server) respondToMyNotification(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Response string `json:"response"`
		Message  string `json:"message"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	s.respondAs(w, r, chi.URLParam(r, "id"), userFrom(r).username, body.Response, body.Message)
}

// GET /me/sign-requests — contracts waiting for the calling data provider's
// signature. They are addressed to the provider's provider_id, not their
// username.
func (s *Server) getMySignRequests(w http.ResponseWriter, r *http.Request) {
	rows, ok := s.notificationsFor(w, r, providerIDForUsername(userFrom(r).username))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "requests": currentSignRequests(rows)})
}

// currentSignRequests keeps one CONTRACT_SIGN request per contract: the
// newest one that hasn't been superseded. When a contract changes (consent
// expiry) its old request is superseded and a new one sent; only the new one
// is shown, so a contract is never listed twice. rows are newest first.
func currentSignRequests(rows []postgres.Notification) []postgres.Notification {
	requests := []postgres.Notification{}
	seen := map[string]bool{}
	for _, n := range rows {
		var p struct {
			Type       string `json:"type"`
			ContractID string `json:"contract_id"`
		}
		if json.Unmarshal(n.Payload, &p) != nil || p.Type != "CONTRACT_SIGN" {
			continue
		}
		if n.Response != nil && *n.Response == "superseded" {
			continue
		}
		if p.ContractID != "" {
			if seen[p.ContractID] {
				continue
			}
			seen[p.ContractID] = true
		}
		requests = append(requests, n)
	}
	return requests
}

// GET /me/jobs — every job the caller takes part in.
func (s *Server) getMyJobs(w http.ResponseWriter, r *http.Request) {
	s.listJobsFor(w, r, userFrom(r).userID)
}

// GET /me/projects — the caller's FL projects; the fl-orchestrator operator
// sees every project.
func (s *Server) getMyProjects(w http.ResponseWriter, r *http.Request) {
	id := userFrom(r)
	owner := id.username
	if slices.Contains(id.roles, s.cfg.OrchestratorRole) {
		owner = ""
	}
	projects, err := s.db.ListProjects(reqCtx(r), owner)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "projects": projects})
}

// How often the notification stream checks for new notifications, and sends
// a heartbeat comment to keep proxies from closing an idle connection.
const (
	notificationPollInterval = 4 * time.Second
	notificationHeartbeat    = 15 * time.Second
)

// GET /me/notifications/stream — Server-Sent Events: a
// data: {"type":"notification"} event whenever the caller receives a new
// notification (the client then refetches its inbox). Ones that already
// existed when the stream opened don't fire. Needs the Authorization header,
// so browsers read it with fetch rather than EventSource.
func (s *Server) streamMyNotifications(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "STREAMING_UNSUPPORTED"})
		return
	}
	username := userFrom(r).username
	ids := func() (map[string]bool, error) {
		rows, err := s.db.GetNotificationsForUser(reqCtx(r), username)
		if err != nil {
			return nil, err
		}
		set := make(map[string]bool, len(rows))
		for _, n := range rows {
			set[n.ID] = true
		}
		return set, nil
	}
	known, err := ids()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("\n"))
	flusher.Flush()

	poll := time.NewTicker(notificationPollInterval)
	defer poll.Stop()
	heartbeat := time.NewTicker(notificationHeartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = w.Write([]byte(": heartbeat\n\n"))
		case <-poll.C:
			current, err := ids()
			if err != nil {
				log.Println("[NOTIFY-STREAM] Error polling notifications:", err)
				continue
			}
			hasNew := false
			for id := range current {
				if !known[id] {
					hasNew = true
					break
				}
			}
			known = current
			if !hasNew {
				continue
			}
			_, _ = w.Write([]byte("data: {\"type\":\"notification\"}\n\n"))
		}
		flusher.Flush()
	}
}

func (s *Server) notificationsFor(w http.ResponseWriter, r *http.Request, username string) ([]postgres.Notification, bool) {
	rows, err := s.db.GetNotificationsForUser(reqCtx(r), username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return nil, false
	}
	if rows == nil {
		rows = []postgres.Notification{}
	}
	return rows, true
}
