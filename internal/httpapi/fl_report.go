package httpapi

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// nowISO renders the current UTC time as an ISO-8601 string (matching JS
// new Date().toISOString()).
func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

type reportOwner struct {
	Username         string          `json:"username"`
	RequestedBy      string          `json:"requested_by"`
	IPAddress        *string         `json:"ip_address"`
	Port             *int32          `json:"port"`
	Model            *string         `json:"model"`
	Framework        *string         `json:"framework"`
	NumServerRounds  *int32          `json:"num_server_rounds"`
	FractionEvaluate *db.Real        `json:"fraction_evaluate"`
	LocalEpochs      *int32          `json:"local_epochs"`
	LearningRate     *db.Real        `json:"learning_rate"`
	BatchSize        *int32          `json:"batch_size"`
	Components       json.RawMessage `json:"components"`
}

type reportProvider struct {
	DataOwnerID   *string    `json:"data_owner_id"`
	RAM           *int32     `json:"ram"`
	MemoryMB      *int32     `json:"memory_mb"`
	DataSizeBytes *db.BigInt `json:"data_size_bytes"`
	DataResource  *string    `json:"data_resource_id"`
	IPAddress     *string    `json:"ip_address"`
	Port          *int32     `json:"port"`
}

type combinedReport struct {
	GeneratedAt   string           `json:"generated_at"`
	SubmissionID  string           `json:"submission_id"`
	FormID        string           `json:"form_id"`
	OutputOwner   reportOwner      `json:"output_owner"`
	DataProviders []reportProvider `json:"data_providers"`
}

// buildCombinedReport assembles the output-owner + data-provider report from a
// submission row and the latest form per selected provider. Mirrors
// buildCombinedReport().
func buildCombinedReport(sub *db.FormSubmission, providerForms []db.DataProviderForm) *combinedReport {
	components := sub.Components
	if len(components) == 0 {
		components = json.RawMessage("{}")
	}
	providers := make([]reportProvider, 0, len(providerForms))
	for i := range providerForms {
		f := &providerForms[i]
		providers = append(providers, reportProvider{
			DataOwnerID:   f.DataOwnerID,
			RAM:           f.RAM,
			MemoryMB:      f.MemoryMB,
			DataSizeBytes: f.DataSizeBytes,
			DataResource:  f.DataResource,
			IPAddress:     f.IPAddress,
			Port:          f.Port,
		})
	}
	return &combinedReport{
		GeneratedAt:  nowISO(),
		SubmissionID: sub.ID,
		FormID:       sub.FormID,
		OutputOwner: reportOwner{
			Username:         sub.OutputOwnerID,
			RequestedBy:      sub.RequestedBy,
			IPAddress:        sub.IPAddress,
			Port:             sub.Port,
			Model:            sub.Model,
			Framework:        sub.Framework,
			NumServerRounds:  sub.NumServerRounds,
			FractionEvaluate: sub.FractionEvaluate,
			LocalEpochs:      sub.LocalEpochs,
			LearningRate:     sub.LearningRate,
			BatchSize:        sub.BatchSize,
			Components:       components,
		},
		DataProviders: providers,
	}
}

// selectedUsernames extracts the non-empty provider usernames from a submission's
// selected_providers JSONB.
func selectedUsernames(sub *db.FormSubmission) []string {
	var out []string
	for _, p := range sub.SelectedProviderList() {
		if p.Username != "" {
			out = append(out, p.Username)
		}
	}
	return out
}

// persistSessionReport builds and stores the combined report for a submission.
// Used as the best-effort step of POST /form-submissions.
func (s *Server) persistSessionReport(r *http.Request, submissionID string) error {
	ctx := reqCtx(r)
	sub, err := s.db.GetFormSubmissionByID(ctx, submissionID)
	if err != nil {
		return err
	}
	if sub == nil {
		return fmt.Errorf("submission %s not found", submissionID)
	}
	forms, err := s.db.GetDataProviderFormsByUsernames(ctx, selectedUsernames(sub))
	if err != nil {
		return err
	}
	report := buildCombinedReport(sub, forms)
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = s.db.StoreSessionReport(ctx, submissionID, sub.FormID, sub.OutputOwnerID, raw)
	return err
}

// GET /form-submissions/{id}/report — serve the persisted combined report, or
// rebuild + persist it on the fly for older submissions. Mirrors the Node handler.
func (s *Server) getSessionReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := reqCtx(r)

	report, err := s.db.GetSessionReport(ctx, id)
	if err != nil {
		log.Println("[GOVERNANCE] Error generating report:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}

	if report == nil {
		sub, err := s.db.GetFormSubmissionByID(ctx, id)
		if err != nil {
			log.Println("[GOVERNANCE] Error generating report:", err)
			writeJSON(w, http.StatusInternalServerError, j{
				"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
			})
			return
		}
		if sub == nil {
			writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND"})
			return
		}
		forms, err := s.db.GetDataProviderFormsByUsernames(ctx, selectedUsernames(sub))
		if err != nil {
			log.Println("[GOVERNANCE] Error generating report:", err)
			writeJSON(w, http.StatusInternalServerError, j{
				"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
			})
			return
		}
		raw, _ := json.Marshal(buildCombinedReport(sub, forms))
		report = raw
		// Persist for next time (best effort).
		if _, perr := s.db.StoreSessionReport(ctx, id, sub.FormID, sub.OutputOwnerID, raw); perr != nil {
			log.Println("[GOVERNANCE] ⚠ Failed to persist rebuilt report:", perr)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="fl_session_%s.json"`, id))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(report)
}
