package postgres

// Flotilla FL client-VM credential records (internal/transport/httpapi/fl_vm_credentials.go):
// one row per offline token issued to a data provider's FL VM, keyed by
// credential_id and by the token's Keycloak offline session id.

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// VMCredential states.
const (
	VMCredentialIssued    = "issued"
	VMCredentialDelivered = "delivered"
	VMCredentialExpired   = "expired"
)

// VMCredential is one row of fl_vm_credentials.
type VMCredential struct {
	CredentialID     string
	SubmissionID     string
	ContractID       string
	Username         string
	UserID           string
	SessionID        string // Keycloak offline session id (sid)
	State            string
	StateReason      string
	TokenFingerprint string
	IssuedAt         time.Time
	ExpiresAt        time.Time // the session contract's lifecycle.valid_until
}

const vmCredentialCols = `credential_id, submission_id, COALESCE(contract_id, ''), username, user_id, session_id,
	state, COALESCE(state_reason, ''), token_fingerprint, issued_at, expires_at`

func scanVMCredential(row pgx.Row) (*VMCredential, error) {
	var c VMCredential
	err := row.Scan(&c.CredentialID, &c.SubmissionID, &c.ContractID, &c.Username, &c.UserID, &c.SessionID,
		&c.State, &c.StateReason, &c.TokenFingerprint, &c.IssuedAt, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.IssuedAt, c.ExpiresAt = c.IssuedAt.UTC(), c.ExpiresAt.UTC()
	return &c, nil
}

// CreateVMCredential inserts c (state issued).
func (d *DB) CreateVMCredential(ctx context.Context, c VMCredential) error {
	_, err := d.Pool.Exec(ctx, `INSERT INTO fl_vm_credentials
		(credential_id, submission_id, contract_id, username, user_id, session_id, state, token_fingerprint, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		c.CredentialID, c.SubmissionID, c.ContractID, c.Username, c.UserID, c.SessionID, VMCredentialIssued,
		c.TokenFingerprint, c.IssuedAt.UTC(), c.ExpiresAt.UTC())
	return err
}

// GetVMCredential returns the record, or nil if there is none.
func (d *DB) GetVMCredential(ctx context.Context, credentialID string) (*VMCredential, error) {
	return scanVMCredential(d.Pool.QueryRow(ctx, `SELECT `+vmCredentialCols+` FROM fl_vm_credentials WHERE credential_id = $1`, credentialID))
}

// GetVMCredentialBySession returns the record for a Keycloak offline session, or nil.
func (d *DB) GetVMCredentialBySession(ctx context.Context, sessionID string) (*VMCredential, error) {
	return scanVMCredential(d.Pool.QueryRow(ctx, `SELECT `+vmCredentialCols+` FROM fl_vm_credentials WHERE session_id = $1`, sessionID))
}

// SetVMCredentialState moves the record to state (no-op if already there)
// and returns it, or nil if there is no such record.
func (d *DB) SetVMCredentialState(ctx context.Context, credentialID, state, reason string) (*VMCredential, error) {
	return scanVMCredential(d.Pool.QueryRow(ctx, `UPDATE fl_vm_credentials
		SET state = $2,
			state_reason = CASE WHEN state = $2 THEN state_reason ELSE NULLIF($3, '') END,
			state_changed_at = CASE WHEN state = $2 THEN state_changed_at ELSE CURRENT_TIMESTAMP END
		WHERE credential_id = $1
		RETURNING `+vmCredentialCols, credentialID, state, reason))
}

// UpdateVMCredentialFingerprint records a rotated offline token's fingerprint;
// from then on only the new token is accepted.
func (d *DB) UpdateVMCredentialFingerprint(ctx context.Context, credentialID, fingerprint string) error {
	_, err := d.Pool.Exec(ctx, `UPDATE fl_vm_credentials SET token_fingerprint = $2, rotated_at = CURRENT_TIMESTAMP WHERE credential_id = $1`,
		credentialID, fingerprint)
	return err
}
