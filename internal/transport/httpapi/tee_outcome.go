package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// How a started TEE run ended. runTEE records run_started once the
// coordinator accepts the job; after that the job runs (or fails, e.g. on
// attestation) inside the enclave, and only the coordinator knows. This
// watches each run until its job is final and records run_succeeded /
// run_execution_failed — with the coordinator's own error text — on the
// contract, so the data provider's Audit page shows the outcome.

const (
	teeWatchInterval = 10 * time.Second
	teeWatchMaxAge   = 6 * time.Hour
	// On startup, resume watching runs started this recently.
	teeWatchResumeWindow = 24 * time.Hour
)

// coordinatorJob is the part of GetJob's response the outcome needs.
type coordinatorJob struct {
	JobID      string `json:"jobId"`
	ContractID string `json:"contractId"`
	State      string `json:"state"`
	Reason     string `json:"reason"`
}

func (j coordinatorJob) terminal() bool {
	switch j.State {
	case "JOB_STATE_SUCCEEDED", "JOB_STATE_FAILED", "JOB_STATE_CANCELLED":
		return true
	}
	return false
}

// fetchCoordinatorJob runs
//
//	grpcurl -plaintext -d '{"jobId": "<jobId>"}' $COORDINATOR_ADDR \
//	  kata.coordinator.v1.CoordinatorService/GetJob
//
// and returns grpcurl's JSON output.
func (s *Server) fetchCoordinatorJob(ctx context.Context, jobID string) ([]byte, error) {
	payload, _ := json.Marshal(map[string]string{"jobId": jobID})
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.GrpcurlBin, "-plaintext", "-d", string(payload),
		s.cfg.CoordinatorAddr, "kata.coordinator.v1.CoordinatorService/GetJob")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	return stdout.Bytes(), nil
}

// settleMu serialises the check-then-record in settleTEERun, so the
// background watcher and the UI's GetJob polling never record one run twice.
var settleMu sync.Mutex

// settleTEERun records the outcome of the coordinator job in raw (GetJob's
// JSON) if it is final and not recorded yet. Returns whether it is final.
func (s *Server) settleTEERun(ctx context.Context, raw []byte) bool {
	var job coordinatorJob
	if json.Unmarshal(raw, &job) != nil || !job.terminal() {
		return false
	}
	if s.db == nil || job.ContractID == "" || job.JobID == "" {
		return true
	}

	settleMu.Lock()
	defer settleMu.Unlock()
	done, err := s.db.HasTEERunOutcome(ctx, job.ContractID, job.JobID)
	if err != nil {
		log.Printf("[TEE-OUTCOME] %s: outcome check failed: %v", job.JobID, err)
		return true
	}
	if done {
		return true
	}
	// The contract row may have been deleted since the run started; its
	// events (and the job_id they belong to) remain, so record against those.
	jobID := ""
	if c, err := s.loadContract(ctx, job.ContractID); err == nil && c != nil {
		jobID = c.JobID
	}
	if jobID == "" {
		if jobID, err = s.db.ContractEventJobID(ctx, job.ContractID); err != nil || jobID == "" {
			log.Printf("[TEE-OUTCOME] %s: no job found for contract %s: %v", job.JobID, job.ContractID, err)
			return true
		}
	}

	ref := " (coordinator job " + job.JobID + ")"
	reason := strings.TrimSpace(job.Reason)
	if reason == "" {
		reason = "no reason given by the coordinator"
	}
	event, detail := postgres.ContractEventRunSucceeded, "TEE run succeeded"+ref
	switch job.State {
	case "JOB_STATE_FAILED":
		event, detail = postgres.ContractEventRunExecutionFailed, "TEE run failed: "+reason+ref
	case "JOB_STATE_CANCELLED":
		event, detail = postgres.ContractEventRunExecutionFailed, "TEE run cancelled: "+reason+ref
	}
	log.Printf("[TEE-OUTCOME] contract %s: %s", job.ContractID, detail)
	if err := s.db.AddContractEvent(ctx, job.ContractID, jobID, event, detail, "governance-layer"); err != nil {
		log.Printf("[TEE-OUTCOME] Warning: contract %s: %s not recorded: %v", job.ContractID, event, err)
	}
	return true
}

// watchTEERun polls coordinator job jobID until it is final (or
// teeWatchMaxAge passes) and records its outcome. Runs in its own goroutine.
func (s *Server) watchTEERun(jobID string) {
	if s.cfg.CoordinatorAddr == "" || !teeJobIDPattern.MatchString(jobID) {
		return
	}
	deadline := time.Now().Add(teeWatchMaxAge)
	for time.Now().Before(deadline) {
		raw, err := s.fetchCoordinatorJob(context.Background(), jobID)
		if err != nil {
			log.Printf("[TEE-OUTCOME] %s: GetJob failed (will retry): %s", jobID, err)
		} else if s.settleTEERun(context.Background(), raw) {
			return
		}
		time.Sleep(teeWatchInterval)
	}
	log.Printf("[TEE-OUTCOME] %s: still not final after %s, stopped watching", jobID, teeWatchMaxAge)
}

// resumeTEERunWatchers restarts watchers for recent runs whose outcome was
// never recorded (e.g. gov_layer restarted while they ran).
func (s *Server) resumeTEERunWatchers() {
	if s.db == nil || s.cfg.CoordinatorAddr == "" {
		return
	}
	runs, err := s.db.ListUnsettledTEERuns(context.Background(), time.Now().Add(-teeWatchResumeWindow))
	if err != nil {
		log.Printf("[TEE-OUTCOME] Warning: could not list unfinished TEE runs: %v", err)
		return
	}
	for _, r := range runs {
		log.Printf("[TEE-OUTCOME] resuming watch of coordinator job %s (contract %s)", r.CoordJobID, r.ContractID)
		go s.watchTEERun(r.CoordJobID)
	}
}
