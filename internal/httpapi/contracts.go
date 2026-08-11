package httpapi

import (
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// POST /contracts — assemble the contract for a session and store it (one row per
// session). Called by the AAA layer both when the owner sends the participation
// request (finalize=false) and when the owner sends the final roster
// (finalize=true). ip/port and the FL config are filled server-side; provider
// user_ids come from Keycloak via the parties list, the owner user_id from
// output_owner_user_id (req.user.sub). project_id is generated once per session.
func (s *Server) postContract(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SubmissionID      string                  `json:"submission_id"`
		OutputOwnerUserID string                  `json:"output_owner_user_id"`
		Parties           []db.ContractPartyInput `json:"parties"`
		Finalize          bool                    `json:"finalize"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	if body.SubmissionID == "" {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "MISSING_SELECTOR", "message": "submission_id is required",
		})
		return
	}

	contract, err := s.db.BuildContract(reqCtx(r), body.SubmissionID, body.OutputOwnerUserID, body.Parties, body.Finalize, "FL")
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, j{
				"status": "FAILED", "error": "NOT_FOUND", "message": "Submission not found",
			})
			return
		}
		log.Println("[GOVERNANCE] Error building contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}

	contractID, err := s.db.StoreContract(reqCtx(r), contract, body.Finalize, "FL")
	if err != nil {
		log.Println("[GOVERNANCE] Error storing contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}

	log.Printf("[GOVERNANCE] ✅ Contract %s ready (session=%s finalized=%t)", contractID, contract.SessionInfo.SessionID, body.Finalize)
	writeJSON(w, http.StatusCreated, j{
		"status": "SUCCESS", "contract_id": contractID, "finalized": body.Finalize, "contract": contract,
	})
}

// GET /contracts/{sessionId} — return the stored contract for a session.
func (s *Server) getContract(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionId")
	raw, err := s.db.GetContractBySession(reqCtx(r), sessionID)
	if err != nil {
		log.Println("[GOVERNANCE] Error retrieving contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}
	if raw == nil {
		writeJSON(w, http.StatusNotFound, j{
			"status": "FAILED", "error": "NOT_FOUND", "message": "No contract for this session",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"SUCCESS","contract":`))
	_, _ = w.Write(raw)
	_, _ = w.Write([]byte(`}`))
}
