package db

import (
	"context"
	"time"
)

// Contract event kinds (contract_events.event).
const (
	ContractEventGenerated     = "generated"
	ContractEventSignRequested = "sign_requested"
	ContractEventSigned        = "signed"
	ContractEventEdited        = "edited"
	ContractEventRunStarted    = "run_started"
	ContractEventRunRefused    = "run_refused"
	ContractEventRunFailed     = "run_failed"
	// How a started TEE run ended in the enclave (tee_outcome.go): the
	// coordinator job reached JOB_STATE_SUCCEEDED, or FAILED/CANCELLED —
	// unlike run_failed, which means the run never started.
	ContractEventRunSucceeded       = "run_succeeded"
	ContractEventRunExecutionFailed = "run_execution_failed"
	// ContractEventConsentExpirySet: a data provider set when their consent
	// ends; the contract was re-hashed and re-sent for signature.
	ContractEventConsentExpirySet = "consent_expiry_set"
)

// ContractEvent is one thing that happened to a contract.
type ContractEvent struct {
	ContractID string    `json:"contract_id"`
	JobID      string    `json:"job_id"`
	Event      string    `json:"event"`
	Detail     string    `json:"detail"`
	Actor      string    `json:"actor"`
	At         time.Time `json:"at"`
}

// AddContractEvent appends one event.
func (d *DB) AddContractEvent(ctx context.Context, contractID, jobID, event, detail, actor string) error {
	_, err := d.Pool.Exec(ctx, `INSERT INTO contract_events (contract_id, job_id, event, detail, actor)
		VALUES ($1, $2, $3, $4, $5)`, contractID, jobID, event, detail, actor)
	return err
}

// ListContractEventsForJobs returns each job's events, oldest first, keyed
// by job_id (at most 50 per job).
func (d *DB) ListContractEventsForJobs(ctx context.Context, jobIDs []string) (map[string][]ContractEvent, error) {
	out := map[string][]ContractEvent{}
	if len(jobIDs) == 0 {
		return out, nil
	}
	rows, err := d.Pool.Query(ctx, `SELECT contract_id, job_id, event, detail, actor, created_at FROM (
			SELECT *, row_number() OVER (PARTITION BY job_id ORDER BY created_at DESC, id DESC) AS n
			FROM contract_events WHERE job_id = ANY($1)
		) e WHERE n <= 50 ORDER BY created_at, id`, jobIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e ContractEvent
		if err := rows.Scan(&e.ContractID, &e.JobID, &e.Event, &e.Detail, &e.Actor, &e.At); err != nil {
			return nil, err
		}
		out[e.JobID] = append(out[e.JobID], e)
	}
	return out, rows.Err()
}

// MarkContractTEEEnabled records that contractID's TEE run started (sets
// tee_enabled_at once), so its job reads as live (job_state tee_enabled).
func (d *DB) MarkContractTEEEnabled(ctx context.Context, contractID string) error {
	_, err := d.Pool.Exec(ctx, `UPDATE contracts SET tee_enabled_at = COALESCE(tee_enabled_at, NOW())
		WHERE contract->>'contract_id' = $1`, contractID)
	return err
}

// HasTEERunOutcome reports whether contractID already has a run_succeeded /
// run_execution_failed event for coordinator job coordJobID (its detail
// names the job), so each run's outcome is recorded once.
func (d *DB) HasTEERunOutcome(ctx context.Context, contractID, coordJobID string) (bool, error) {
	var exists bool
	err := d.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM contract_events
		WHERE contract_id = $1 AND event IN ($2, $3) AND strpos(detail, $4) > 0)`,
		contractID, ContractEventRunSucceeded, ContractEventRunExecutionFailed,
		"(coordinator job "+coordJobID+")").Scan(&exists)
	return exists, err
}

// UnsettledTEERun is a TEE run that started but has no recorded outcome.
type UnsettledTEERun struct {
	ContractID string
	CoordJobID string
}

// ListUnsettledTEERuns returns TEE runs started since `since` (run_started
// events naming a coordinator job) with no outcome event for that job yet.
func (d *DB) ListUnsettledTEERuns(ctx context.Context, since time.Time) ([]UnsettledTEERun, error) {
	rows, err := d.Pool.Query(ctx, `SELECT s.contract_id, s.coord_job FROM (
			SELECT contract_id, substring(detail from 'coordinator job ([A-Za-z0-9._-]+)') AS coord_job
			FROM contract_events WHERE event = $1 AND created_at >= $2
		) s
		WHERE s.coord_job IS NOT NULL AND NOT EXISTS (
			SELECT 1 FROM contract_events o
			WHERE o.contract_id = s.contract_id AND o.event IN ($3, $4)
			  AND strpos(o.detail, '(coordinator job ' || s.coord_job || ')') > 0)`,
		ContractEventRunStarted, since, ContractEventRunSucceeded, ContractEventRunExecutionFailed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UnsettledTEERun
	for rows.Next() {
		var u UnsettledTEERun
		if err := rows.Scan(&u.ContractID, &u.CoordJobID); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ContractEventJobID returns the job_id contractID's events were recorded
// under ("" if none) — for recording an event after the contract row itself
// is gone.
func (d *DB) ContractEventJobID(ctx context.Context, contractID string) (string, error) {
	var jobID string
	err := d.Pool.QueryRow(ctx, `SELECT COALESCE((SELECT job_id FROM contract_events
		WHERE contract_id = $1 AND job_id <> '' ORDER BY created_at DESC, id DESC LIMIT 1), '')`,
		contractID).Scan(&jobID)
	return jobID, err
}
