// Enabling a job's TEE run: once every data and infra provider has approved
// and signed a job's contract and PUT /job/{jobId}/status has cross-verified
// it, it is final (putJobStatus, finalizeJob in job_approval.go), and the
// job's consumer enables the TEE run with
// POST /job/{jobId}/tee. Only then may a TEE session be started for that
// contract (requireTEEEnabled, checked by requireSignedContract).
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
)

// POST /job/{jobId}/tee — Authorization: Bearer <the consumer's dev Keycloak
// token>: the user who generated the job's contract. Re-verifies every
// signature on the final contract and marks the job's TEE run enabled. It
// starts nothing: the run itself is POST /v1/tee/sessions with
// governanceContractId = the contract_id.
func (s *Server) enableJobTEE(w http.ResponseWriter, r *http.Request) {
	_, claims, ok := s.devTokenClaims(w, r, "consumer")
	if !ok {
		return
	}
	jobID := chi.URLParam(r, "jobId")
	c, ok := s.loadContractByJob(w, r, jobID)
	if !ok {
		return
	}
	if sub, _ := claims["sub"].(string); sub == "" || !strings.EqualFold(sub, c.Parties.User.ID) {
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "NOT_JOB_CONSUMER",
			"message": "only the user who generated this job's contract can enable its TEE run"})
		return
	}
	if _, err := s.requireAllProvidersSigned(reqCtx(r), c.ContractID); err != nil {
		writeJSON(w, http.StatusConflict, j{"status": "FAILED", "error": "CONTRACT_NOT_SIGNED", "message": teeErrorMessage(err)})
		return
	}
	at, err := s.db.EnableJobTEE(reqCtx(r), jobID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if at == nil {
		writeJSON(w, http.StatusConflict, j{"status": "FAILED", "error": "CONTRACT_NOT_FINAL",
			"message": "the job's contract is not final yet: every data and infra provider must approve it, then PUT /job/" + jobID + "/status must return approved"})
		return
	}
	writeJSON(w, http.StatusOK, j{
		"status":         "SUCCESS",
		"job_id":         jobID,
		"contract_id":    c.ContractID,
		"contract_hash":  c.ContractHash,
		"tee":            "enabled",
		"tee_enabled_at": at,
		"next":           "POST /v1/tee/sessions with governanceContractId = " + c.ContractID,
	})
}

// requireTEEEnabled refuses a TEE run for a job-approval contract (datasets +
// infra) whose consumer hasn't enabled it (POST /job/{jobId}/tee).
func (s *Server) requireTEEEnabled(ctx context.Context, c *contract.Contract) error {
	if !needsJobApproval(c) {
		return nil
	}
	jobID := c.JobID
	if jobID == "" {
		var err error
		if jobID, err = s.db.GetJobIDByContractID(ctx, c.ContractID); err != nil {
			return &teeAPIError{Status: http.StatusInternalServerError, Code: "INTERNAL_ERROR", Message: err.Error()}
		}
	}
	l, err := s.db.GetJobLifecycle(ctx, jobID)
	if err != nil {
		return &teeAPIError{Status: http.StatusInternalServerError, Code: "INTERNAL_ERROR", Message: err.Error()}
	}
	if l.TEEEnabledAt == nil {
		return &teeAPIError{Status: http.StatusForbidden, Code: "TEE_NOT_ENABLED",
			Message: "job " + jobID + "'s TEE run is not enabled: its consumer must call POST /job/" + jobID + "/tee first"}
	}
	return nil
}

// teeErrorMessage is err's message without the code prefix teeAPIError adds.
func teeErrorMessage(err error) string {
	var te *teeAPIError
	if errors.As(err, &te) {
		return te.Message
	}
	return err.Error()
}
