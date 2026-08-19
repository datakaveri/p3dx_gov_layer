package httpapi

// This file is FL-only: the mock provider directory and provider messaging.

import (
	"log"
	"net/http"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// GET /data-providers — return the mock provider list.
func (s *Server) getDataProviders(w http.ResponseWriter, r *http.Request) {
	providers := s.db.GetDataProviders(reqCtx(r))
	log.Printf("[GOVERNANCE] Retrieved %d data providers", len(providers))
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "data_providers": providers})
}

// POST /send-provider-message — store a provider notification message.
func (s *Server) sendProviderMessage(w http.ResponseWriter, r *http.Request) {
	var in db.ProviderMessageInput
	if !s.readBody(w, r, &in) {
		return
	}
	if in.ProviderID == "" || in.ProviderEmail == "" {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "MISSING_PROVIDER_INFO",
			"message": "provider_id and provider_email are required",
		})
		return
	}
	messageID, err := s.db.StoreProviderMessage(reqCtx(r), &in)
	if err != nil {
		log.Println("[GOVERNANCE] ❌ Error sending provider message:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": "Failed to send provider message",
		})
		return
	}
	writeJSON(w, http.StatusOK, j{
		"status": "success", "message": "Message sent to provider", "message_id": messageID,
		"data": j{
			"provider_id": in.ProviderID, "provider_name": in.ProviderName,
			"provider_email": in.ProviderEmail, "message": in.Message,
		},
	})
}
