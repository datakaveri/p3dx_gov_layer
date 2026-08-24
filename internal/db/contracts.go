package db

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
)

// The contract is emitted in the canonical contract.Contract shape (see
// internal/contract). Fields the FL flow does not capture are left blank
// (empty string / zero / empty slice) rather than omitted, so the shape is
// always complete.

// ContractPartyInput is one provider passed in from the caller: the Keycloak id
// and username. The dataset fields are left blank — the FL flow doesn't
// capture them (forms live in APD only), so the contract's dataset fields for
// each party stay unpopulated.
type ContractPartyInput struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// NewUUID returns a random RFC 4122 version-4 UUID string. Used for contract_id
// (avoids pulling in an external uuid dependency).
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// existingProjectID returns the project_id already assigned to this session's
// contract, or "" if none exists yet. This keeps project_id stable across the
// initial and final contracts for the same session.
func (d *DB) existingProjectID(ctx context.Context, sessionID string) string {
	var pid string
	err := d.Pool.QueryRow(ctx, `SELECT project_id FROM contracts WHERE session_id = $1`, sessionID).Scan(&pid)
	if err != nil {
		return ""
	}
	return pid
}

// existingContractID returns the contract_id stored inside this session's
// contract JSON, or "" if none exists yet. This keeps contract_id stable across
// the initial and final contracts for the same session.
func (d *DB) existingContractID(ctx context.Context, sessionID string) string {
	var cid string
	err := d.Pool.QueryRow(ctx, `SELECT contract->>'contract_id' FROM contracts WHERE session_id = $1`, sessionID).Scan(&cid)
	if err != nil {
		return ""
	}
	return cid
}

// BuildContract assembles a contract for the given submission session ID and parties.
// Since forms are now stored in APD only, dataset fields from provider forms are
// left blank. It reuses an already-assigned project_id and contract_id for
// the session so only the parties change between the initial and final contracts.
// finalize sets version=2 (the final roster contract) vs. version=1 (the draft).
// pathway indicates whether this is an FL contract (with forms flow) or GENERAL (with policy checks).
func (d *DB) BuildContract(ctx context.Context, submissionID, ownerUserID string, parties []ContractPartyInput, finalize bool, pathway string) (*contract.Contract, error) {
	if pathway == "" {
		pathway = "FL"
	}

	dataProviders := make([]contract.DataProviderParty, 0, len(parties))
	for _, p := range parties {
		dataProviders = append(dataProviders, contract.DataProviderParty{
			ID:          p.ID,
			Name:        p.Username,
			Constraints: contract.Constraints{RestrictedTo: []string{}},
		})
	}

	// The drafting party (the output owner). Use ownerUserID if provided,
	// otherwise fall back to the submission id.
	if ownerUserID == "" {
		ownerUserID = submissionID
	}

	projectID := d.existingProjectID(ctx, submissionID)
	if projectID == "" {
		projectID = newID("proj", 9)
	}
	contractID := d.existingContractID(ctx, submissionID)
	if contractID == "" {
		contractID = NewUUID()
	}
	version := 1
	if finalize {
		version = 2
	}

	now := time.Now().UTC()

	c := &contract.Contract{
		ProjectID:  projectID,
		ContractID: contractID,
		Version:    version,
		Lifecycle: contract.Lifecycle{
			CreatedAt:  now,
			ValidFrom:  now,
			ValidUntil: now.Add(90 * 24 * time.Hour),
		},
		Technique:         "FL",
		ComputeChoice:     "FEDERATED_LEARNING",
		ExecutionPlatform: "AZURE_AMD_SEV",
		Parties: contract.Parties{
			User: contract.UserParty{
				ID:   ownerUserID,
				Name: ownerUserID,
			},
			DataProviders:        dataProviders,
			ApplicationProviders: []contract.ApplicationProviderParty{},
			InfraProviders:       []contract.InfraProviderParty{},
		},
		SessionInfo: contract.SessionInfo{
			ID:        submissionID,
			SessionID: submissionID,
		},
	}

	hash, err := contract.ComputeHash(*c)
	if err != nil {
		return nil, err
	}
	c.ContractHash = hash

	return c, nil
}

// StoreContract upserts a contract keyed by session_id (one contract per session).
// finalized marks the final roster contract vs. the initial participation-request
// draft. pathway indicates FL or GENERAL. Returns the contract row id.
func (d *DB) StoreContract(ctx context.Context, c *contract.Contract, finalized bool, pathway string) (string, error) {
	if pathway == "" {
		pathway = "FL"
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	var id string
	err = d.Pool.QueryRow(ctx, `INSERT INTO contracts
			(id, project_id, session_id, output_owner_id, finalized, pathway, contract)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (session_id) DO UPDATE SET
			output_owner_id = EXCLUDED.output_owner_id,
			finalized = contracts.finalized OR EXCLUDED.finalized,
			pathway = EXCLUDED.pathway,
			contract = EXCLUDED.contract,
			updated_at = CURRENT_TIMESTAMP
		RETURNING id`,
		newID("con", 9), c.ProjectID, c.SessionInfo.SessionID, c.Parties.User.ID, finalized, pathway, raw,
	).Scan(&id)
	if err != nil {
		return "", err
	}
	log.Printf("[DATABASE] Contract stored (session=%s project=%s pathway=%s finalized=%t): %s", c.SessionInfo.SessionID, c.ProjectID, pathway, finalized, id)
	return id, nil
}

// StoreGeneratedContract upserts an unsigned, generated (preview) contract —
// the output of POST /generate-contract, before any signing/submission. It's
// keyed by consumer+dataset+technique (via the synthetic session_id below) so
// regenerating the same selection overwrites the previous draft instead of
// accumulating rows. contractJSON is pre-marshaled by the caller.
func (d *DB) StoreGeneratedContract(ctx context.Context, consumerID, datasetID, technique, contractID string, contractJSON []byte) (string, error) {
	sessionKey := fmt.Sprintf("preview:%s:%s:%s", consumerID, datasetID, technique)

	var id string
	err := d.Pool.QueryRow(ctx, `INSERT INTO contracts
			(id, project_id, session_id, output_owner_id, finalized, pathway, contract)
			VALUES ($1, $2, $3, $4, false, 'PREVIEW', $5)
		ON CONFLICT (session_id) DO UPDATE SET
			project_id = EXCLUDED.project_id,
			output_owner_id = EXCLUDED.output_owner_id,
			finalized = false,
			pathway = 'PREVIEW',
			contract = EXCLUDED.contract,
			updated_at = CURRENT_TIMESTAMP
		RETURNING id`,
		newID("con", 9), contractID, sessionKey, consumerID, contractJSON,
	).Scan(&id)
	if err != nil {
		return "", err
	}
	log.Printf("[DATABASE] Generated contract stored (consumer=%s dataset=%s technique=%s): %s", consumerID, datasetID, technique, id)
	return id, nil
}

// GetContractBySession returns the stored contract for a session, or (nil, nil)
// when none exists.
func (d *DB) GetContractBySession(ctx context.Context, sessionID string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := d.Pool.QueryRow(ctx, `SELECT contract FROM contracts WHERE session_id = $1`, sessionID).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}
