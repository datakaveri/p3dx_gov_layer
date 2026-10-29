package postgres

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
)

// NewUUID returns a random RFC 4122 version-4 UUID string. Used for contract_id
// (avoids pulling in an external uuid dependency).
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// NewJobID returns a fresh job id ("job-<unixMillis>-<rand9>"). Every contract
// gets its own, minted before its hash is computed so it's part of what's signed.
func NewJobID() string {
	return newID("job", 9)
}

// NewProjectID returns a fresh project id ("proj-<unixMillis>-<rand9>"). Every
// FL roster contract is its own project.
func NewProjectID() string {
	return newID("proj", 9)
}

// DataProviderSignatures returns username -> signed_at for every
// already-signed data-provider party on this session's currently stored
// contract. A provider signs by accepting their participation notification
// (see SignDataProviderParty), which happens against the draft (finalize=false)
// contract; passing these to contractgen.BuildFLRosterContract means the
// signature survives the draft -> final-roster rebuild instead of resetting to
// unsigned.
func (d *DB) DataProviderSignatures(ctx context.Context, sessionID string) map[string]*time.Time {
	raw, err := d.GetContractBySession(ctx, sessionID)
	if err != nil || raw == nil {
		return nil
	}
	var existing contract.Contract
	if err := json.Unmarshal(raw, &existing); err != nil {
		return nil
	}
	signed := make(map[string]*time.Time, len(existing.Parties.DataProviders))
	for _, p := range existing.Parties.DataProviders {
		if p.Signature.SignedAt != nil {
			signed[p.Name] = p.Signature.SignedAt
		}
	}
	return signed
}

// StoreContract upserts a contract keyed by project_id (one contract per
// project; every FL roster contract mints a fresh project_id, so a session
// accumulates a new project per contract build - draft, final, and any
// "Start Again" restart each get their own row).
// finalized marks the final roster contract vs. the initial participation-request
// draft. pathway indicates FL or GENERAL. Returns the contract row id.
func (d *DB) StoreContract(ctx context.Context, c *contract.Contract, finalized bool, pathway string) (string, error) {
	if pathway == "" {
		pathway = "FL"
	}
	// Every contract must carry a job_id. Callers mint it before hashing; this
	// is only a safety net so the column is never left empty.
	if c.JobID == "" {
		c.JobID = NewJobID()
		log.Printf("[DATABASE] Warning: contract %s had no job_id, minted %s after hashing", c.ContractID, c.JobID)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	var id string
	err = d.Pool.QueryRow(ctx, `INSERT INTO contracts
			(id, project_id, session_id, output_owner_id, finalized, pathway, contract, job_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (project_id) DO UPDATE SET
			job_id = EXCLUDED.job_id,
			output_owner_id = EXCLUDED.output_owner_id,
			finalized = contracts.finalized OR EXCLUDED.finalized,
			pathway = EXCLUDED.pathway,
			contract = EXCLUDED.contract,
			updated_at = CURRENT_TIMESTAMP
		RETURNING id`,
		newID("con", 9), c.ProjectID, c.SessionInfo.SessionID, c.Parties.User.ID, finalized, pathway, raw, c.JobID,
	).Scan(&id)
	if err != nil {
		return "", err
	}
	log.Printf("[DATABASE] Contract stored (session=%s project=%s job=%s pathway=%s finalized=%t): %s", c.SessionInfo.SessionID, c.ProjectID, c.JobID, pathway, finalized, id)
	return id, nil
}

// StoreGeneratedContract upserts an unsigned, generated (preview) contract —
// the output of POST /generate-contract, before any signing/submission. It's
// keyed by consumer+dataset+technique (via the synthetic session_id below) so
// regenerating the same selection overwrites the previous draft instead of
// accumulating rows. contractJSON is pre-marshaled by the caller.
func (d *DB) StoreGeneratedContract(ctx context.Context, consumerID, datasetID, technique, contractID, jobID string, contractJSON []byte) (string, error) {
	sessionKey := GeneratedContractSessionKey(consumerID, datasetID, technique)

	var id string
	err := d.Pool.QueryRow(ctx, `INSERT INTO contracts
			(id, project_id, session_id, output_owner_id, finalized, pathway, contract, job_id)
			VALUES ($1, $2, $3, $4, false, 'PREVIEW', $5, $6)
		ON CONFLICT (session_id) WHERE session_id LIKE 'preview:%' DO UPDATE SET
			project_id = EXCLUDED.project_id,
			job_id = EXCLUDED.job_id,
			sign_requests_sent_at = NULL,
			finalized_at = NULL,
			tee_enabled_at = NULL,
			output_owner_id = EXCLUDED.output_owner_id,
			finalized = false,
			pathway = 'PREVIEW',
			contract = EXCLUDED.contract,
			updated_at = CURRENT_TIMESTAMP
		RETURNING id`,
		newID("con", 9), contractID, sessionKey, consumerID, contractJSON, jobID,
	).Scan(&id)
	if err != nil {
		return "", err
	}
	log.Printf("[DATABASE] Generated contract stored (consumer=%s dataset=%s technique=%s): %s", consumerID, datasetID, technique, id)
	return id, nil
}

// SignDataProviderParty marks a data-provider party as signed (signature.signed_at
// = now) on this session's stored contract, matched by username (that's all the
// participation-response flow carries — see httpapi.respondToNotification).
// It's a no-op, returning (false, nil), when there's no stored contract yet, no
// party with that username, or that party already signed. finalize (a later
// roster rebuild for this session) carries the signature forward via
// DataProviderSignatures, so it survives the
// draft -> final-roster transition.

// checks that the contarct is signed by the data providers and if they have signed or not ust updates
func (d *DB) SignDataProviderParty(ctx context.Context, sessionID, username string) (bool, error) {
	var contractRowID string
	var raw json.RawMessage
	err := d.Pool.QueryRow(ctx,
		`SELECT id, contract FROM contracts WHERE session_id = $1 ORDER BY updated_at DESC LIMIT 1`,
		sessionID,
	).Scan(&contractRowID, &raw)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil || raw == nil {
		return false, err
	}
	var c contract.Contract
	if err := json.Unmarshal(raw, &c); err != nil {
		return false, err
	}

	signed := false
	now := time.Now().UTC()
	for i := range c.Parties.DataProviders {
		p := &c.Parties.DataProviders[i]
		if p.Name == username && p.Signature.SignedAt == nil {
			p.Signature.SignedAt = &now
			signed = true
		}
	}
	if !signed {
		return false, nil
	}

	updated, err := json.Marshal(c)
	if err != nil {
		return false, err
	}
	// Target the specific row by id, not by session_id - a session can now have
	// several contract rows (restart history), and only the latest (fetched
	// above) should be signed.
	_, err = d.Pool.Exec(ctx,
		`UPDATE contracts SET contract = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
		updated, contractRowID,
	)
	if err != nil {
		return false, err
	}
	log.Printf("[DATABASE] Signed data-provider party (session=%s username=%s)", sessionID, username)
	return true, nil
}

// GetContractByContractID returns the stored contract whose JSON contract_id
// matches, or (nil, nil) when none exists. Signing addresses contracts by
// contract_id for every technique — for a generated TEE/SMPC contract that's
// also its project_id, but an FL roster contract mints the two separately.
func (d *DB) GetContractByContractID(ctx context.Context, contractID string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := d.Pool.QueryRow(ctx,
		`SELECT contract FROM contracts WHERE contract->>'contract_id' = $1 ORDER BY updated_at DESC LIMIT 1`,
		contractID,
	).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// UpdateContractByContractID overwrites the stored contract JSON for the row
// whose contract_id matches. Returns false when no such row exists.
func (d *DB) UpdateContractByContractID(ctx context.Context, contractID string, raw json.RawMessage) (bool, error) {
	tag, err := d.Pool.Exec(ctx,
		`UPDATE contracts SET contract = $1, updated_at = CURRENT_TIMESTAMP WHERE contract->>'contract_id' = $2`,
		raw, contractID,
	)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// UpdateContractByProjectID overwrites the stored contract JSON for one
// project_id (for a generated TEE contract, project_id is its contract_id —
// see StoreGeneratedContract). Returns false when no such row exists.
func (d *DB) UpdateContractByProjectID(ctx context.Context, projectID string, raw json.RawMessage) (bool, error) {
	tag, err := d.Pool.Exec(ctx,
		`UPDATE contracts SET contract = $1, updated_at = CURRENT_TIMESTAMP WHERE project_id = $2`,
		raw, projectID,
	)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// GetContractBySession returns the most recently updated stored contract for a
// session, or (nil, nil) when none exists. A session can have several contract
// rows (draft, final, and any "Start Again" restarts, each its own project);
// this always returns the current/latest one.
func (d *DB) GetContractBySession(ctx context.Context, sessionID string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := d.Pool.QueryRow(ctx, `SELECT contract FROM contracts WHERE session_id = $1 ORDER BY updated_at DESC LIMIT 1`, sessionID).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// GetContractByProjectID returns the stored contract for one specific
// project, or (nil, nil) when none exists. Unlike GetContractBySession
// (which only ever returns a session's latest contract), this fetches the
// exact contract for a given project_id - needed since a session now
// accumulates several projects (see contractgen.BuildFLRosterContract, which mints a fresh
// project_id on every call) and the UI lets a user view any one of them.
func (d *DB) GetContractByProjectID(ctx context.Context, projectID string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := d.Pool.QueryRow(ctx, `SELECT contract FROM contracts WHERE project_id = $1`, projectID).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// GeneratedContractSessionKey is the session_id StoreGeneratedContract files a
// consumer's generated contract under: one row per consumer, dataset
// selection and technique.
func GeneratedContractSessionKey(consumerID, datasetID, technique string) string {
	return fmt.Sprintf("preview:%s:%s:%s", consumerID, datasetID, technique)
}
