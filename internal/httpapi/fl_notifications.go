package httpapi

// This file is FL-only: the participation-consent notification loop (an
// output owner asks a selected provider "still willing to join?" and the
// provider accepts/declines).

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// POST /notifications — create notifications for multiple recipients.
func (s *Server) postNotifications(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Recipients []struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"recipients"`
		SenderUsername string          `json:"senderUsername"`
		Message        string          `json:"message"`
		Payload        json.RawMessage `json:"payload"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	if len(body.Recipients) == 0 {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_RECIPIENTS"})
		return
	}
	results := make([]*db.CreatedNotification, 0, len(body.Recipients))
	for _, rcpt := range body.Recipients {
		n, err := s.db.CreateNotification(reqCtx(r), rcpt.ID, rcpt.Username, body.SenderUsername, body.Message, body.Payload)
		if err != nil {
			log.Println("[GOVERNANCE] Error creating notifications:", err)
			writeJSON(w, http.StatusInternalServerError, j{
				"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
			})
			return
		}
		results = append(results, n)
	}
	writeJSON(w, http.StatusCreated, j{"status": "SUCCESS", "created": len(results), "notifications": results})
}

// GET /notifications/{key} — fetch notifications for a username.
func (s *Server) getNotifications(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "key")
	rows, err := s.db.GetNotificationsForUser(reqCtx(r), username)
	if err != nil {
		log.Println("[GOVERNANCE] Error fetching notifications:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if rows == nil {
		rows = []db.Notification{}
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "notifications": rows})
}

// PATCH /notifications/{key}/read — mark a notification read.
func (s *Server) patchNotificationRead(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "key")
	var body struct {
		Username string `json:"username"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	updated, err := s.db.MarkNotificationAsRead(reqCtx(r), id, body.Username)
	if err != nil {
		log.Println("[GOVERNANCE] Error marking notification read:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if updated == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND"})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "notification": updated})
}

// POST /notifications/{key}/respond — a provider answers a participation request
// with accepted/declined plus an optional reason for the owner.
func (s *Server) respondToNotification(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "key")
	var body struct {
		Username string `json:"username"`
		Response string `json:"response"`
		Message  string `json:"message"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	if body.Username == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_USERNAME"})
		return
	}
	if body.Response != "accepted" && body.Response != "declined" {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "INVALID_RESPONSE",
			"message": "response must be 'accepted' or 'declined'",
		})
		return
	}
	updated, err := s.db.RespondToNotification(reqCtx(r), id, body.Username, body.Response, body.Message)
	if err != nil {
		log.Println("[GOVERNANCE] Error recording notification response:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if updated == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND"})
		return
	}
	log.Printf("[GOVERNANCE] %s %s participation request %s", body.Username, body.Response, id)
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "notification": updated})
}

// GET /notifications/by-sender/{key} — notifications a user has sent, so the
// output owner can see each selected provider's participation response.
func (s *Server) getNotificationsBySender(w http.ResponseWriter, r *http.Request) {
	sender := chi.URLParam(r, "key")
	rows, err := s.db.GetNotificationsBySender(reqCtx(r), sender)
	if err != nil {
		log.Println("[GOVERNANCE] Error fetching sent notifications:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if rows == nil {
		rows = []db.Notification{}
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "notifications": rows})
}
