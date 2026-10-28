package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Job participant roles.
const (
	ParticipantRoleConsumer      = "consumer"
	ParticipantRoleDataProvider  = "data-provider"
	ParticipantRoleInfraProvider = "infra-provider"
)

// Job participant statuses, in the order a job moves through them. Approved /
// rejected / signed are per participant; final and tee_enabled are set on
// every participant of the job at once.
const (
	ParticipantStatusCreated    = "created"   // consumer: generated the contract
	ParticipantStatusRequested  = "requested" // provider: asked to approve / sign
	ParticipantStatusApproved   = "approved"
	ParticipantStatusRejected   = "rejected"
	ParticipantStatusSigned     = "signed"
	ParticipantStatusFinal      = "final"
	ParticipantStatusTEEEnabled = "tee_enabled"
	ParticipantStatusWithdrawn  = "withdrawn" // provider: withdrew consent after signing (DPDP s.6(4))
)

// JobParticipant is one row of job_participants: one user's part in one job
// (contract) — the consumer, or a data / infra provider and the dataset /
// infra they bring. ParticipantID is how the contract names them (the
// consumer's sub, a provider's "provider-<slug>" id); UserID is their
// Keycloak sub, known for the consumer from the start and for a provider once
// they approve or sign with their own token.
type JobParticipant struct {
	JobID         string    `json:"job_id"`
	ContractID    string    `json:"contract_id"`
	Technique     string    `json:"technique"`
	Role          string    `json:"role"`
	ParticipantID string    `json:"participant_id"`
	UserID        string    `json:"user_id"`
	Username      string    `json:"username"`
	ItemID        string    `json:"item_id"`
	ItemName      string    `json:"item_name"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`

	// From the job's contracts row (nil: not yet).
	FinalizedAt  *time.Time `json:"finalized_at"`
	TEEEnabledAt *time.Time `json:"tee_enabled_at"`
}

// ReplaceJobParticipants stores rows as jobID's participants, replacing any
// it had. Regenerating the same selection overwrites the contracts row with a
// new job_id (StoreGeneratedContract), so participants of jobs no longer in
// contracts are dropped too.
func (d *DB) ReplaceJobParticipants(ctx context.Context, jobID string, rows []JobParticipant) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM job_participants WHERE job_id = $1
		OR job_id NOT IN (SELECT job_id FROM contracts WHERE job_id IS NOT NULL)`, jobID); err != nil {
		return err
	}
	for _, p := range rows {
		if _, err := tx.Exec(ctx, `INSERT INTO job_participants
				(job_id, contract_id, technique, role, participant_id, user_id, username, item_id, item_name, status)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (job_id, role, participant_id, item_id) DO UPDATE SET
				contract_id = EXCLUDED.contract_id,
				technique = EXCLUDED.technique,
				user_id = EXCLUDED.user_id,
				username = EXCLUDED.username,
				item_name = EXCLUDED.item_name,
				status = EXCLUDED.status,
				updated_at = CURRENT_TIMESTAMP`,
			jobID, p.ContractID, p.Technique, p.Role, p.ParticipantID, p.UserID, p.Username, p.ItemID, p.ItemName, p.Status); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// SetJobParticipantStatus sets the status of one participant's item on jobID
// and records their user id / username (kept when blank). Returns whether a
// row matched.
func (d *DB) SetJobParticipantStatus(ctx context.Context, jobID, role, participantID, itemID, status, userID, username string) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `UPDATE job_participants SET
			status = $5,
			user_id = COALESCE(NULLIF($6, ''), user_id),
			username = COALESCE(NULLIF($7, ''), username),
			updated_at = CURRENT_TIMESTAMP
		WHERE job_id = $1 AND role = $2 AND participant_id = $3 AND item_id = $4`,
		jobID, role, participantID, itemID, status, userID, username)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// JobHasRejection reports whether any participant of jobID rejected it.
func (d *DB) JobHasRejection(ctx context.Context, jobID string) (bool, error) {
	var rejected bool
	err := d.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM job_participants WHERE job_id = $1 AND status = $2)`,
		jobID, ParticipantStatusRejected).Scan(&rejected)
	return rejected, err
}

// SetJobStatus sets every participant of jobID to status (final /
// tee_enabled).
func (d *DB) SetJobStatus(ctx context.Context, jobID, status string) error {
	_, err := d.Pool.Exec(ctx, `UPDATE job_participants SET status = $2, updated_at = CURRENT_TIMESTAMP
		WHERE job_id = $1 AND status <> $2`, jobID, status)
	return err
}

// UsernameByUserID returns the username registered with a provider public
// key for this Keycloak user id ("" if none), so a provider can be found by
// their user id before they have approved anything.
func (d *DB) UsernameByUserID(ctx context.Context, userID string) (string, error) {
	var username string
	err := d.Pool.QueryRow(ctx, `SELECT username FROM provider_public_keys WHERE user_id = $1
		ORDER BY updated_at DESC LIMIT 1`, userID).Scan(&username)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return username, err
}

// ListJobParticipantsForUser returns every job_participants row naming one
// of names (matched case-insensitively against participant_id, user_id and
// username), newest job first, with each job's lifecycle timestamps.
func (d *DB) ListJobParticipantsForUser(ctx context.Context, names []string) ([]JobParticipant, error) {
	lower := make([]string, 0, len(names))
	for _, n := range names {
		if n != "" {
			lower = append(lower, strings.ToLower(n))
		}
	}
	rows, err := d.Pool.Query(ctx, `SELECT p.job_id, p.contract_id, p.technique, p.role, p.participant_id,
			p.user_id, p.username, p.item_id, p.item_name, p.status, p.created_at, p.updated_at,
			c.finalized_at, c.tee_enabled_at
		FROM job_participants p
		LEFT JOIN contracts c ON c.job_id = p.job_id
		WHERE lower(p.participant_id) = ANY($1) OR lower(p.user_id) = ANY($1) OR lower(p.username) = ANY($1)
		ORDER BY p.created_at DESC, p.job_id, p.role, p.item_id`, lower)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JobParticipant{}
	for rows.Next() {
		var p JobParticipant
		if err := rows.Scan(&p.JobID, &p.ContractID, &p.Technique, &p.Role, &p.ParticipantID,
			&p.UserID, &p.Username, &p.ItemID, &p.ItemName, &p.Status, &p.CreatedAt, &p.UpdatedAt,
			&p.FinalizedAt, &p.TEEEnabledAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
