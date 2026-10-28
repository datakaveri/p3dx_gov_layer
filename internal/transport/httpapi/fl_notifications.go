package httpapi

// This file is FL-only: the participation-consent notification loop (an
// output owner asks a selected provider "still willing to join?" and the
// provider accepts/declines).

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// notificationRecipient is one addressee of a notification.
type notificationRecipient struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// createNotifications stores one notification per recipient. For a
// session-scoped payload it skips providers removed from that session (and
// strips them from the payload's rosters); a participation_request also gets
// its round number and, after an earlier decline, the final-warning text.
// Used by the /me/fl routes (fl_session.go).
func (s *Server) createNotifications(r *http.Request, recipients []notificationRecipient, sender, baseMessage string, basePayload json.RawMessage) ([]*postgres.CreatedNotification, []string, error) {
	var meta struct {
		Kind         string `json:"kind"`
		SubmissionID string `json:"submission_id"`
	}
	_ = json.Unmarshal(basePayload, &meta)
	var removed map[string]bool
	if meta.SubmissionID != "" && sessionScopedKinds[meta.Kind] {
		var err error
		if removed, err = s.removedProviderSet(r, meta.SubmissionID); err != nil {
			return nil, nil, fmt.Errorf("load removed providers: %w", err)
		}
	}

	results := make([]*postgres.CreatedNotification, 0, len(recipients))
	skipped := []string{}
	for _, rcpt := range recipients {
		if removed[rcpt.Username] {
			skipped = append(skipped, rcpt.Username)
			continue
		}
		message, payload := baseMessage, basePayload
		if len(removed) > 0 {
			payload = withoutRemovedProviders(payload, removed)
		}
		if meta.Kind == "participation_request" && meta.SubmissionID != "" {
			prior, err := s.db.CountParticipationRequests(reqCtx(r), rcpt.Username, meta.SubmissionID)
			if err != nil {
				return nil, nil, fmt.Errorf("count participation requests: %w", err)
			}
			declines, err := s.db.CountParticipationDeclines(reqCtx(r), rcpt.Username, meta.SubmissionID)
			if err != nil {
				return nil, nil, fmt.Errorf("count participation declines: %w", err)
			}
			round := prior + 1
			final := declines >= 1
			payload = withPayloadFields(payload, map[string]any{"round": round, "final_warning": final})
			if final {
				message += " " + finalWarningText
			}
		}
		n, err := s.db.CreateNotification(reqCtx(r), rcpt.ID, rcpt.Username, sender, message, payload)
		if err != nil {
			return nil, nil, fmt.Errorf("create notification: %w", err)
		}
		results = append(results, n)
	}
	return results, skipped, nil
}

// respondAs records username's accepted/declined answer to notification id,
// for POST /me/notifications/{id}/respond (username from the caller's token).
func (s *Server) respondAs(w http.ResponseWriter, r *http.Request, id, username, response, message string) {
	if response != "accepted" && response != "declined" {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "INVALID_RESPONSE",
			"message": "response must be 'accepted' or 'declined'",
		})
		return
	}
	// A provider removed from a session can't answer its older requests.
	if existing, err := s.db.GetNotificationForRecipient(reqCtx(r), id, username); err == nil && existing != nil {
		var p participationPayload
		_ = json.Unmarshal(existing.Payload, &p)
		if p.SubmissionID != "" && sessionScopedKinds[p.Kind] {
			if removed, err := s.removedProviderSet(r, p.SubmissionID); err == nil && removed[username] {
				writeJSON(w, http.StatusConflict, j{
					"status": "FAILED", "error": "REMOVED_FROM_SESSION",
					"message": "you have been removed from this session",
				})
				return
			}
		}
		// Only the newest willing/not-willing ask for a session can be
		// answered; an older one has been replaced by it.
		if p.SubmissionID != "" && (p.Kind == "participation_request" || p.Kind == "participation_update") {
			if newer, err := s.db.HasNewerParticipationAsk(reqCtx(r), existing, p.SubmissionID); err == nil && newer {
				writeJSON(w, http.StatusConflict, j{
					"status": "FAILED", "error": "SUPERSEDED",
					"message": "a newer participation request has replaced this one — answer the latest one",
				})
				return
			}
		}
	}
	updated, err := s.db.RespondToNotification(reqCtx(r), id, username, response, message)
	if err != nil {
		log.Println("[GOVERNANCE] Error recording notification response:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if updated == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND"})
		return
	}
	log.Printf("[GOVERNANCE] %s %s participation request %s", username, response, id)

	var req participationPayload
	_ = json.Unmarshal(updated.Payload, &req)
	// Declining a second time (this decline included) removes the provider.
	secondDecline := false
	if response == "declined" && req.SubmissionID != "" && (req.Kind == "participation_request" || req.Kind == "participation_update") {
		if n, err := s.db.CountParticipationDeclines(reqCtx(r), username, req.SubmissionID); err == nil {
			secondDecline = n >= 2
		} else {
			log.Println("[GOVERNANCE] Warning: could not count participation declines:", err)
		}
	}
	if secondDecline {
		removedNow, err := s.removeProviderFromSession(r, updated, req, message)
		if err != nil {
			log.Println("[GOVERNANCE] Error removing provider from session:", err)
			writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "notification": updated, "removed_from_session": removedNow})
		return
	}

	// Accepting a participation request is this provider's contract signature.
	// The notification payload carries submission_id (see README's payload
	// shape); non-blocking, same as the other best-effort FL lookups — a
	// missing/malformed submission_id just means no session contract to sign.
	if response == "accepted" {
		var payload struct {
			SubmissionID string `json:"submission_id"`
		}
		if err := json.Unmarshal(updated.Payload, &payload); err == nil && payload.SubmissionID != "" {
			if signed, err := s.db.SignDataProviderParty(reqCtx(r), payload.SubmissionID, username); err != nil {
				log.Println("[GOVERNANCE] Warning: failed to sign contract party:", err)
			} else if signed {
				log.Printf("[GOVERNANCE] %s signed contract for session %s", username, payload.SubmissionID)
			}
		}
	}

	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "notification": updated})
}
