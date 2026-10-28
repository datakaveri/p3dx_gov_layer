package httpapi

// Consent withdrawal (DPDP Act 2023 s.6(4); DPDP Rules 2025 Rule 3(c)(i)): a
// data provider who signed a TEE contract can withdraw that consent as
// easily as they gave it. Withdrawing clears their signature on the stored
// contract, so the run gate (requireAllProvidersSigned) refuses any further
// TEE run on it with "consent withdrawn". A run already in progress is not
// stopped here — withdrawal does not affect processing already done.

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// POST /contracts/{contractId}/withdraw-consent — body
// {"notification_id": "<CONTRACT_SIGN notification id>"} (optional). The
// provider is taken from their own Bearer token, as for /sign.
func (s *Server) handleWithdrawConsent(w http.ResponseWriter, r *http.Request) {
	contractID := chi.URLParam(r, "contractId")
	signer, ok := s.providerTokenIdentity(w, r)
	if !ok {
		return
	}
	var body struct {
		NotificationID string `json:"notification_id"`
	}
	if r.ContentLength != 0 && !s.readBody(w, r, &body) {
		return
	}
	providerID := providerIDForUsername(signer.username)

	c, err := s.loadContract(reqCtx(r), contractID)
	if err != nil {
		log.Println("[WITHDRAW] Error loading contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if c == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "CONTRACT_NOT_FOUND"})
		return
	}
	if c.Technique != "TEE" {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "WITHDRAWAL_NOT_SUPPORTED",
			"message": "consent withdrawal is available for TEE contracts only",
		})
		return
	}

	isParty, wasSigned := false, false
	for _, p := range c.Parties.DataProviders {
		if partyProviderID(p) == providerID {
			isParty = true
			wasSigned = wasSigned || p.Signature.Value != ""
		}
	}
	if !isParty {
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "NOT_A_PARTY"})
		return
	}
	if !wasSigned {
		writeJSON(w, http.StatusConflict, j{
			"status": "FAILED", "error": "NOT_SIGNED",
			"message": "you have not given consent on this contract, so there is nothing to withdraw",
		})
		return
	}

	// Clear every party of theirs; keep who withdrew and when. The signature
	// block is outside the hash, so the contract hash is unchanged and the
	// provider can sign it again later to re-consent.
	now := time.Now().UTC()
	for i := range c.Parties.DataProviders {
		p := &c.Parties.DataProviders[i]
		if partyProviderID(*p) == providerID {
			p.Signature.SignedAt = nil
			p.Signature.Algorithm = ""
			p.Signature.SignedHash = ""
			p.Signature.Value = ""
			p.Signature.Signer = signer.username
			p.Signature.WithdrawnAt = &now
		}
	}

	updated, err := json.Marshal(c)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if ok, err := s.db.UpdateContractByContractID(reqCtx(r), contractID, updated); err != nil || !ok {
		log.Println("[WITHDRAW] Error storing contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}

	s.markParticipantStatus(reqCtx(r), c, providerID, signer.userID, signer.username, postgres.ParticipantStatusWithdrawn)

	if body.NotificationID != "" {
		if _, err := s.db.RespondToNotification(reqCtx(r), body.NotificationID, providerID, "withdrawn", "consent withdrawn"); err != nil {
			log.Println("[WITHDRAW] Warning: failed to mark sign request withdrawn:", err)
		}
	}

	log.Printf("[WITHDRAW] %s withdrew consent on %s contract %s", providerID, c.Technique, contractID)
	writeJSON(w, http.StatusOK, j{"status": "withdrawn", "message": "consent withdrawn", "withdrawn_at": now})
}
