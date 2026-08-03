package httpapi

// This file is FL-only: handlers for the output-owner form (POST
// /form-submissions and friends), the mock provider directory, and the
// data-provider form.

import (
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// POST /form-submissions — store an output-owner form, then persist the combined
// session report (best effort). Mirrors the Node handler exactly.
func (s *Server) postFormSubmission(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Payload *db.FormInput `json:"payload"`
	}
	if !s.readBody(w, r, &body) {
		return
	}

	log.Println("[GOVERNANCE] ============================================")
	log.Println("[GOVERNANCE] Form submission request received")

	if body.Payload == nil {
		log.Println("[GOVERNANCE] ❌ Validation failed: Missing payload")
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "MISSING_PAYLOAD",
			"message": "Request body must contain a payload object",
		})
		return
	}

	p := body.Payload
	var missing []string
	if p.FormID == "" {
		missing = append(missing, "form_id")
	}
	if p.RequestedBy == "" {
		missing = append(missing, "requested_by")
	}
	if p.OutputOwnerID == "" {
		missing = append(missing, "output_owner_id")
	}
	if len(missing) > 0 {
		log.Println("[GOVERNANCE] ❌ Validation failed: Missing fields:", missing)
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "MISSING_REQUIRED_FIELDS",
			"message": "Missing required fields: " + strings.Join(missing, ", "),
		})
		return
	}

	submissionID, err := s.db.StoreFormSubmission(reqCtx(r), p)
	if err != nil {
		log.Println("[GOVERNANCE] ❌ Error processing form submission:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR",
			"message": "Failed to process form submission",
		})
		return
	}
	log.Println("[GOVERNANCE] ✅ Form stored successfully. Submission ID:", submissionID)

	// Best-effort: build + persist the combined session report. A failure here
	// must not lose the form submission (the report endpoint can rebuild later).
	if err := s.persistSessionReport(r, submissionID); err != nil {
		log.Println("[GOVERNANCE] ⚠ Failed to persist session report:", err)
	} else {
		log.Println("[GOVERNANCE] ✅ Session report persisted for submission:", submissionID)
	}
	log.Println("[GOVERNANCE] ============================================")

	writeJSON(w, http.StatusCreated, j{
		"status": "SUCCESS", "message": "Form submission stored successfully",
		"submission_id": submissionID,
	})
}

// GET /form-submissions — list all submissions.
func (s *Server) getFormSubmissions(w http.ResponseWriter, r *http.Request) {
	subs, err := s.db.GetAllFormSubmissions(reqCtx(r))
	if err != nil {
		log.Println("[GOVERNANCE] Error retrieving form submissions:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": "Failed to retrieve form submissions",
		})
		return
	}
	if subs == nil {
		subs = []db.FormSubmission{}
	}
	log.Printf("[GOVERNANCE] Retrieved %d form submissions", len(subs))
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "count": len(subs), "submissions": subs})
}

// GET /form-submissions/export — download all submissions as a JSON file.
func (s *Server) exportFormSubmissions(w http.ResponseWriter, r *http.Request) {
	subs, err := s.db.GetAllFormSubmissions(reqCtx(r))
	if err != nil {
		log.Println("[GOVERNANCE] Error exporting form submissions:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": "Failed to export form submissions",
		})
		return
	}
	if subs == nil {
		subs = []db.FormSubmission{}
	}
	w.Header().Set("Content-Disposition", `attachment; filename="data_provider_forms.json"`)
	writeJSON(w, http.StatusOK, j{
		"exported_at": nowISO(), "count": len(subs), "submissions": subs,
	})
}

// GET /form-submissions/{id} — fetch one submission.
func (s *Server) getFormSubmissionByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sub, err := s.db.GetFormSubmissionByID(reqCtx(r), id)
	if err != nil {
		log.Println("[GOVERNANCE] Error retrieving form submission:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": "Failed to retrieve form submission",
		})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, j{
			"status": "FAILED", "error": "NOT_FOUND", "message": "Form submission not found",
		})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "submission": sub})
}

// DELETE /form-submissions/{id} — delete one submission.
func (s *Server) deleteFormSubmission(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	deleted, err := s.db.DeleteFormSubmission(reqCtx(r), id)
	if err != nil {
		log.Println("[GOVERNANCE] Error deleting form submission:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": "Failed to delete form submission",
		})
		return
	}
	if !deleted {
		writeJSON(w, http.StatusNotFound, j{
			"status": "FAILED", "error": "NOT_FOUND", "message": "Form submission not found",
		})
		return
	}
	log.Printf("[GOVERNANCE] Deleted form submission: %s", id)
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "message": "Form submission deleted successfully"})
}

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

// POST /data-provider-forms — store a data-provider form.
func (s *Server) postDataProviderForm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Payload *db.ProviderFormInput `json:"payload"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	if body.Payload == nil {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_PAYLOAD"})
		return
	}
	id, err := s.db.StoreDataProviderForm(reqCtx(r), body.Payload)
	if err != nil {
		log.Println("[GOVERNANCE] Error storing data provider form:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}
	log.Println("[GOVERNANCE] ✅ Data provider form stored:", id)
	writeJSON(w, http.StatusCreated, j{"status": "SUCCESS", "submission_id": id})
}

// GET /data-provider-forms — list all data-provider forms.
func (s *Server) getDataProviderForms(w http.ResponseWriter, r *http.Request) {
	forms, err := s.db.GetAllDataProviderForms(reqCtx(r))
	if err != nil {
		log.Println("[GOVERNANCE] Error fetching data provider forms:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}
	if forms == nil {
		forms = []db.DataProviderForm{}
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "count": len(forms), "forms": forms})
}
