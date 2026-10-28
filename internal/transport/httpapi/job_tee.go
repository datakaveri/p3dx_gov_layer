// Enabling a job's TEE run: once every data and infra provider has approved
// and signed a job's contract and GET /job/{jobId}/status has cross-verified
// it, it is final (getJobStatus, Service.Finalize in application/jobapproval), and the
// job's consumer enables the TEE run with
// POST /job/{jobId}/tee. Only then may a TEE session be started for that
// contract (requireTEEEnabled, checked by requireSignedContract).
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
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
			"message": "the job's contract is not final yet: every data and infra provider must approve it, then GET /job/" + jobID + "/status must return approved"})
		return
	}
	s.markJobParticipants(reqCtx(r), jobID, postgres.ParticipantStatusTEEEnabled)
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
	if !s.jobApprovalRequired(c) {
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

// POST /v1/tee/run — body {"contract_id": "..."}. The UI's Run TEE: builds
// the CreateJob sub-contract from the generated contract (contract.
// NewSubContract) and runs
//
//	grpcurl -plaintext -d '<sub-contract>' $COORDINATOR_ADDR \
//	  kata.coordinator.v1.CoordinatorService/CreateJob
//
// Returns the sub-contract that was sent and grpcurl's output (the Job).
func (s *Server) runTEEJob(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ContractID string `json:"contract_id"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	contractID := strings.TrimSpace(body.ContractID)
	if contractID == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "BAD_REQUEST", "message": "contract_id is required"})
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": "database not available"})
		return
	}

	// Signature gate: the stored contract must still hash to what gov_layer
	// and every data provider signed. A contract edited after signing
	// (PUT /contracts/{id}/workload) fails here and is never run.
	c, err := s.requireAllProvidersSigned(reqCtx(r), contractID)
	if err != nil {
		detail := ""
		stored, _ := s.loadContract(reqCtx(r), contractID)
		if stored != nil {
			got, _ := contract.ComputeHash(*stored)
			detail = " (signed hash " + stored.ContractHash + ", stored content hashes to " + got + ")"
		}
		log.Printf("[TEE-RUN] REJECTED contract %s: %s%s", contractID, teeErrorMessage(err), detail)
		s.recordContractEvent(reqCtx(r), stored, postgres.ContractEventRunRefused, "Run refused: "+teeErrorMessage(err), "governance-layer")
		writeTEEError(w, err)
		return
	}
	// The workload must be the catalogue workload's own image.
	if err := requireWorkloadAllowed(c); err != nil {
		log.Printf("[TEE-RUN] REJECTED contract %s: %s", contractID, teeErrorMessage(err))
		s.recordContractEvent(reqCtx(r), c, postgres.ContractEventRunRefused, "Run refused: "+teeErrorMessage(err), "governance-layer")
		writeTEEError(w, err)
		return
	}
	if s.cfg.CoordinatorAddr == "" {
		writeJSON(w, http.StatusServiceUnavailable, j{"status": "FAILED", "error": "NOT_CONFIGURED", "message": "COORDINATOR_ADDR is not set"})
		return
	}

	sub, missing := contract.NewSubContract(c)
	if len(missing) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, j{
			"status": "FAILED", "error": "CONTRACT_INCOMPLETE",
			"message": "contract is missing " + strings.Join(missing, ", "),
		})
		return
	}
	payload, err := json.Marshal(sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(reqCtx(r), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.GrpcurlBin, "-plaintext", "-d", string(payload),
		s.cfg.CoordinatorAddr, "kata.coordinator.v1.CoordinatorService/CreateJob")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	log.Printf("[TEE-RUN] contract %s: grpcurl -plaintext -d '%s' %s kata.coordinator.v1.CoordinatorService/CreateJob",
		contractID, payload, s.cfg.CoordinatorAddr)
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		log.Printf("[TEE-RUN] contract %s: grpcurl failed: %s", contractID, msg)
		s.recordContractEvent(reqCtx(r), c, postgres.ContractEventRunFailed, "Run could not start: "+msg, "governance-layer")
		writeJSON(w, http.StatusBadGateway, j{"status": "FAILED", "error": "GRPCURL_FAILED", "message": msg, "subContract": sub})
		return
	}
	log.Printf("[TEE-RUN] contract %s: %s", contractID, strings.TrimSpace(stdout.String()))

	resp := j{"status": "SUCCESS", "subContract": sub}
	var job json.RawMessage
	if json.Unmarshal(stdout.Bytes(), &job) == nil {
		resp["job"] = job
	} else {
		resp["output"] = stdout.String()
	}

	// The run is live: the job reads as tee_enabled on the Audit page.
	var created struct {
		JobID string `json:"jobId"`
	}
	_ = json.Unmarshal(stdout.Bytes(), &created)
	if err := s.db.MarkContractTEEEnabled(reqCtx(r), contractID); err != nil {
		log.Printf("[TEE-RUN] Warning: contract %s not marked live: %v", contractID, err)
	}
	if c.JobID != "" {
		s.markJobParticipants(reqCtx(r), c.JobID, postgres.ParticipantStatusTEEEnabled)
	}
	detail := "TEE run started"
	if created.JobID != "" {
		detail += " (coordinator job " + created.JobID + ")"
	}
	s.recordContractEvent(reqCtx(r), c, postgres.ContractEventRunStarted, detail, "governance-layer")
	// Record how the run ends (tee_outcome.go), even if nobody watches it.
	if created.JobID != "" {
		go s.watchTEERun(created.JobID)
	}

	writeJSON(w, http.StatusOK, resp)
}

// Coordinator job IDs look like "job-9f3c4952e83e".
var teeJobIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// GET /v1/tee/jobs/{jobId} — the UI's Run TEE progress, polled every few
// seconds. Runs
//
//	grpcurl -plaintext -d '{"jobId": "<jobId>"}' $COORDINATOR_ADDR \
//	  kata.coordinator.v1.CoordinatorService/GetJob
//
// and returns {"status": "SUCCESS", "job": <grpcurl's output>}.
func (s *Server) getTEEJob(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobId")
	if !teeJobIDPattern.MatchString(jobID) {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "BAD_REQUEST", "message": "invalid jobId"})
		return
	}
	if s.cfg.CoordinatorAddr == "" {
		writeJSON(w, http.StatusServiceUnavailable, j{"status": "FAILED", "error": "NOT_CONFIGURED", "message": "COORDINATOR_ADDR is not set"})
		return
	}
	out, err := s.fetchCoordinatorJob(reqCtx(r), jobID)
	if err != nil {
		log.Printf("[TEE-JOB] %s: grpcurl GetJob failed: %s", jobID, err)
		writeJSON(w, http.StatusBadGateway, j{"status": "FAILED", "error": "GRPCURL_FAILED", "message": err.Error()})
		return
	}

	var job json.RawMessage
	if json.Unmarshal(out, &job) != nil {
		writeJSON(w, http.StatusBadGateway, j{"status": "FAILED", "error": "BAD_COORDINATOR_RESPONSE", "message": strings.TrimSpace(string(out))})
		return
	}
	// Record the outcome now if the job is final (no-op if already recorded).
	s.settleTEERun(reqCtx(r), out)
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "job": job})
}

// GET /v1/tee/jobs/{jobId}/result — the UI's View Result. Fetches the
// result blob the workload wrote (RESULT_READ_URL — DEFAULT_RESULT_URL's
// SAS is write-only) server-side, so the read SAS never reaches the browser.
// Returns {"status": "SUCCESS", "result": <JSON>} or, for a non-JSON blob,
// {"status": "SUCCESS", "output": "<text>"}.
func (s *Server) getTEEJobResult(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobId")
	if !teeJobIDPattern.MatchString(jobID) {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "BAD_REQUEST", "message": "invalid jobId"})
		return
	}
	if s.cfg.ResultReadURL == "" {
		writeJSON(w, http.StatusServiceUnavailable, j{"status": "FAILED", "error": "NOT_CONFIGURED", "message": "RESULT_READ_URL is not set (needs a read SAS for the result blob)"})
		return
	}

	ctx, cancel := context.WithTimeout(reqCtx(r), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.ResultReadURL, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": "invalid RESULT_READ_URL"})
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, j{"status": "FAILED", "error": "RESULT_FETCH_FAILED", "message": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, j{"status": "FAILED", "error": "RESULT_FETCH_FAILED", "message": err.Error()})
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("[TEE-JOB] %s: result fetch returned %d", jobID, resp.StatusCode)
		writeJSON(w, http.StatusBadGateway, j{"status": "FAILED", "error": "RESULT_FETCH_FAILED", "message": "result storage returned status " + strconv.Itoa(resp.StatusCode)})
		return
	}

	var result json.RawMessage
	if json.Unmarshal(body, &result) == nil {
		writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "result": result})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "output": string(body)})
}
