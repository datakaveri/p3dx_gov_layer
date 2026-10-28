package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// Audit entry types — which side of a job's approval an entry records.
const (
	AuditTypeDataProvider  = "data-provider"
	AuditTypeInfraProvider = "infra-provider"
)

// Audit entry statuses.
const (
	AuditStatusAccepted = "accepted"
	AuditStatusRejected = "rejected"
)

// AuditEntry is one row of the audit table: the outcome of one job-approval
// check for one provider + item (dataset or infra) on a contract's job_id.
// HasRole/InCatalogue record the two checks behind Status; Reason explains a
// rejection.
type AuditEntry struct {
	ID          int64     `json:"id"`
	JobID       string    `json:"job_id"`
	Type        string    `json:"type"`
	ProviderID  string    `json:"provider_id"`
	Item        string    `json:"item"`
	Status      string    `json:"status"`
	HasRole     bool      `json:"has_role"`
	InCatalogue bool      `json:"in_catalogue"`
	Reason      string    `json:"reason,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
}

// InsertAuditEntries appends entries to the audit table. The table is
// append-only: re-running a job's approval check adds new rows rather than
// overwriting, so the full history is kept and the latest row per
// (job_id, type, provider_id, item) is the current status.
func (d *DB) InsertAuditEntries(ctx context.Context, entries []AuditEntry) error {
	if len(entries) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range entries {
		batch.Queue(`INSERT INTO audit
				(job_id, type, provider_id, item, status, has_role, in_catalogue, reason, checked_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			e.JobID, e.Type, e.ProviderID, e.Item, e.Status, e.HasRole, e.InCatalogue, e.Reason, e.CheckedAt)
	}
	return d.Pool.SendBatch(ctx, batch).Close()
}

// ListAuditByJob returns every audit entry for jobID, oldest first.
func (d *DB) ListAuditByJob(ctx context.Context, jobID string) ([]AuditEntry, error) {
	rows, err := d.Pool.Query(ctx, `SELECT id, job_id, type, provider_id, item, status, has_role, in_catalogue, COALESCE(reason, ''), checked_at
		FROM audit WHERE job_id = $1 ORDER BY checked_at, id`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.JobID, &e.Type, &e.ProviderID, &e.Item, &e.Status, &e.HasRole, &e.InCatalogue, &e.Reason, &e.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetContractByJobID returns the stored contract JSON for jobID, or nil if
// there is none. Backfilled rows carry job_id only in the column, not the
// JSON, so this looks it up by column.
func (d *DB) GetContractByJobID(ctx context.Context, jobID string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := d.Pool.QueryRow(ctx, `SELECT contract FROM contracts WHERE job_id = $1`, jobID).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// MarkSignRequestsSent claims the right to send jobID's sign requests: it
// stamps sign_requests_sent_at and returns true only for the first caller, so
// the requests go out once even if two approval re-checks race.
func (d *DB) MarkSignRequestsSent(ctx context.Context, jobID string) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `UPDATE contracts SET sign_requests_sent_at = CURRENT_TIMESTAMP
		WHERE job_id = $1 AND sign_requests_sent_at IS NULL`, jobID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// MarkJobFinal marks jobID's contract final (finalized, finalized_at) and
// returns true only for the first caller.
func (d *DB) MarkJobFinal(ctx context.Context, jobID string) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `UPDATE contracts SET finalized = true, finalized_at = CURRENT_TIMESTAMP
		WHERE job_id = $1 AND finalized_at IS NULL`, jobID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// JobLifecycle is when a job's contract became final and when its TEE run
// was enabled (nil: not yet).
type JobLifecycle struct {
	FinalizedAt  *time.Time
	TEEEnabledAt *time.Time
}

// GetJobLifecycle reads jobID's JobLifecycle.
func (d *DB) GetJobLifecycle(ctx context.Context, jobID string) (JobLifecycle, error) {
	var l JobLifecycle
	err := d.Pool.QueryRow(ctx, `SELECT finalized_at, tee_enabled_at FROM contracts WHERE job_id = $1`, jobID).
		Scan(&l.FinalizedAt, &l.TEEEnabledAt)
	if err == pgx.ErrNoRows {
		return l, nil
	}
	return l, err
}

// EnableJobTEE stamps tee_enabled_at on jobID's final contract (keeping the
// first stamp) and returns it; nil if the contract isn't final.
func (d *DB) EnableJobTEE(ctx context.Context, jobID string) (*time.Time, error) {
	var at *time.Time
	err := d.Pool.QueryRow(ctx, `UPDATE contracts SET tee_enabled_at = COALESCE(tee_enabled_at, CURRENT_TIMESTAMP)
		WHERE job_id = $1 AND finalized_at IS NOT NULL
		RETURNING tee_enabled_at`, jobID).Scan(&at)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return at, err
}

// GetJobIDByContractID returns the job_id column for the contract with this
// contract_id ("" if none). Backfilled contracts only carry job_id there.
func (d *DB) GetJobIDByContractID(ctx context.Context, contractID string) (string, error) {
	var jobID *string
	err := d.Pool.QueryRow(ctx,
		`SELECT job_id FROM contracts WHERE contract->>'contract_id' = $1 ORDER BY updated_at DESC LIMIT 1`,
		contractID,
	).Scan(&jobID)
	if err == pgx.ErrNoRows || jobID == nil {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return *jobID, nil
}
