package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// readBody decodes a JSON request body into dst. An empty body is treated as an
// empty object (matching express.json). A genuine JSON syntax error responds
// 400 INVALID_JSON (matching error.middleware.js) and returns false.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	err := decodeJSON(w, r, dst)
	if err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "INVALID_JSON", "message": "Invalid JSON in request body",
		})
		return false
	}
	return true
}

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
