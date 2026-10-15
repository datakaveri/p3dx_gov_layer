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
