package httpapi

// This file is FL-only: the participation negotiation limit. A data provider
// may decline a participation request for a session once freely; after that,
// every request they get carries a final warning, and declining a second time
// removes them from the session. On removal the output owner and the removed
// provider are notified, and every remaining provider is sent the updated
// list of who is still in (and who is willing) — automatically — which they
// can answer willing / not willing like a request.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

const finalWarningText = "⚠ You declined an earlier request for this session — if you decline again, you will be removed from the session."

// sessionScopedKinds are the FL notification kinds addressed to the
// providers of one session; a removed provider never receives these again.
var sessionScopedKinds = map[string]bool{
	"participation_request": true,
	"participation_update":  true,
	"final_roster":          true,
}

// participationPayload is the subset of a participation notification's
// payload the negotiation logic reads.
type participationPayload struct {
	Kind          string `json:"kind"`
	SubmissionID  string `json:"submission_id"`
	OutputOwnerID string `json:"output_owner_id"`
	Round         int    `json:"round"`
}

// providerRef is one {id, username} entry of a payload's provider lists.
type providerRef struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

func (s *Server) removedProviderSet(r *http.Request, submissionID string) (map[string]bool, error) {
	rows, err := s.db.GetRemovedProviders(reqCtx(r), submissionID)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(rows))
	for _, p := range rows {
		set[p.Username] = true
	}
	return set, nil
}

// withPayloadFields returns payload with fields set (payload must be a JSON
// object; anything else is returned unchanged).
func withPayloadFields(payload json.RawMessage, fields map[string]any) json.RawMessage {
	m := map[string]any{}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &m); err != nil {
			return payload
		}
	}
	for k, v := range fields {
		m[k] = v
	}
	out, err := json.Marshal(m)
	if err != nil {
		return payload
	}
	return out
}

// withoutRemovedProviders drops removed usernames from the payload's
// provider lists, so nobody is shown a provider who's no longer in the session.
func withoutRemovedProviders(payload json.RawMessage, removed map[string]bool) json.RawMessage {
	m := map[string]any{}
	if err := json.Unmarshal(payload, &m); err != nil {
		return payload
	}
	for _, key := range []string{"selected_providers", "requested_providers", "willing_providers"} {
		list, ok := m[key].([]any)
		if !ok {
			continue
		}
		kept := make([]any, 0, len(list))
		for _, item := range list {
			if p, ok := item.(map[string]any); ok {
				if u, _ := p["username"].(string); removed[u] {
					continue
				}
			} else if u, ok := item.(string); ok && removed[u] {
				continue
			}
			kept = append(kept, item)
		}
		m[key] = kept
	}
	out, err := json.Marshal(m)
	if err != nil {
		return payload
	}
	return out
}

// removeProviderFromSession handles a declined round-2+ participation
// request: records the removal, then notifies the output owner, the removed
// provider and every remaining provider (who can answer willing / not
// willing on the updated list). Notification failures are logged,
// not returned — the removal itself is what must stick.
func (s *Server) removeProviderFromSession(r *http.Request, declined *db.Notification, req participationPayload, reason string) (bool, error) {
	ctx := reqCtx(r)
	username := declined.RecipientUsername
	added, err := s.db.RemoveProviderFromSession(ctx, req.SubmissionID, username, reason)
	if err != nil {
		return false, err
	}
	if !added {
		return true, nil
	}
	log.Printf("[GOVERNANCE] %s declined a second time and was removed from session %s", username, req.SubmissionID)

	owner := declined.SenderUsername
	reasonNote := ""
	if reason != "" {
		reasonNote = " Reason: " + reason
	}

	// Remaining providers: each one's latest request for this session.
	removed, err := s.removedProviderSet(r, req.SubmissionID)
	if err != nil {
		log.Println("[GOVERNANCE] Warning: could not load removed providers:", err)
		removed = map[string]bool{username: true}
	}
	latest, err := s.db.GetLatestParticipationRequests(ctx, req.SubmissionID)
	if err != nil {
		log.Println("[GOVERNANCE] Warning: could not load session participants:", err)
	}
	remaining := []providerRef{}
	willing := []providerRef{}
	for _, n := range latest {
		if removed[n.RecipientUsername] {
			continue
		}
		ref := providerRef{ID: n.RecipientID, Username: n.RecipientUsername}
		remaining = append(remaining, ref)
		if n.Response != nil && *n.Response == "accepted" {
			willing = append(willing, ref)
		}
	}

	ownerPayload, _ := json.Marshal(j{
		"kind":                "provider_removed",
		"submission_id":       req.SubmissionID,
		"removed_provider":    username,
		"reason":              reason,
		"remaining_providers": remaining,
		"willing_providers":   willing,
	})
	ownerID := req.OutputOwnerID
	if ownerID == "" {
		ownerID = owner
	}
	if _, err := s.db.CreateNotification(ctx, ownerID, owner, username,
		fmt.Sprintf("%s declined to participate a second time and has been removed from session %s.%s", username, req.SubmissionID, reasonNote),
		ownerPayload); err != nil {
		log.Println("[GOVERNANCE] Warning: owner not notified of removal:", err)
	}

	removedPayload, _ := json.Marshal(j{
		"kind":             "removed_from_session",
		"submission_id":    req.SubmissionID,
		"output_owner_id":  req.OutputOwnerID,
		"removed_provider": username,
	})
	if _, err := s.db.CreateNotification(ctx, declined.RecipientID, username, owner,
		fmt.Sprintf("You declined to participate a second time, so you have been removed from session %s.", req.SubmissionID),
		removedPayload); err != nil {
		log.Println("[GOVERNANCE] Warning: removed provider not notified:", err)
	}

	// The updated list is answerable (willing / not willing). A provider who
	// has already declined once gets the final warning: declining it removes
	// them too.
	msg := fmt.Sprintf("%s has been removed from session %s. Updated list: %d provider(s) remaining, %d willing. Are you still willing to take part?",
		username, req.SubmissionID, len(remaining), len(willing))
	for _, p := range remaining {
		round, err := s.db.CountParticipationRequests(ctx, p.Username, req.SubmissionID)
		if err != nil {
			log.Printf("[GOVERNANCE] Warning: could not count requests for %s: %v", p.Username, err)
		}
		declines, err := s.db.CountParticipationDeclines(ctx, p.Username, req.SubmissionID)
		if err != nil {
			log.Printf("[GOVERNANCE] Warning: could not count declines for %s: %v", p.Username, err)
		}
		final := declines >= 1
		updatePayload, _ := json.Marshal(j{
			"kind":                "participation_update",
			"submission_id":       req.SubmissionID,
			"output_owner_id":     req.OutputOwnerID,
			"removed_provider":    username,
			"requested_providers": remaining,
			"willing_providers":   willing,
			"round":               round,
			"final_warning":       final,
		})
		pmsg := msg
		if final {
			pmsg += " " + finalWarningText
		}
		if _, err := s.db.CreateNotification(ctx, p.ID, p.Username, owner, pmsg, updatePayload); err != nil {
			log.Printf("[GOVERNANCE] Warning: %s not sent the updated list: %v", p.Username, err)
		}
	}
	return true, nil
}

// GET /sessions/{submissionId}/removed-providers — providers removed from an
// FL session for declining to participate a second time.
func (s *Server) getRemovedProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.GetRemovedProviders(reqCtx(r), chi.URLParam(r, "submissionId"))
	if err != nil {
		log.Println("[GOVERNANCE] Error fetching removed providers:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if rows == nil {
		rows = []db.RemovedProvider{}
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "removed_providers": rows})
}
