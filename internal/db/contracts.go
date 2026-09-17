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
// and username, plus that provider's dataset info pulled from their APD
// provider-form (dataset_name / dataset_location_url), keyed by data_owner_id
// == username. Left blank when the caller has no form data for this provider.
type ContractPartyInput struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DatasetName string `json:"dataset_name"`
	DataURL     string `json:"data_url"`
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

// existingDataProviderSignatures returns username -> signed_at for every
// already-signed data-provider party on this session's currently stored
// contract. A provider signs by accepting their participation notification
// (see SignDataProviderParty), which happens against the draft (finalize=false)
// contract; carrying that signature forward here means it survives the
// draft -> final-roster rebuild in BuildContract instead of resetting to
// unsigned.
func (d *DB) existingDataProviderSignatures(ctx context.Context, sessionID string) map[string]*time.Time {
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

// BuildContract assembles a contract for the given submission session ID and parties.
// Since forms are now stored in APD only, dataset fields from provider forms are
// left blank. Every call mints a brand-new project_id and contract_id - a
// contract is never reused across calls, so the initial (finalize=false) and
// final-roster (finalize=true) contracts for one session are always two
// distinct projects, and a "Start Again" restart is just another such call.
// finalize sets version=2 (the final roster contract) vs. version=1 (the draft).
// pathway indicates whether this is an FL contract (with forms flow) or GENERAL (with policy checks).
// Prior data-provider signatures are still carried forward from the session's
// most recent contract, since a restart reuses the same accepted roster
// without redoing invite/accept.
func (d *DB) BuildContract(ctx context.Context, submissionID, ownerUserID string, parties []ContractPartyInput, finalize bool, pathway string) (*contract.Contract, error) {
	if pathway == "" {
		pathway = "FL"
	}

	priorSignatures := d.existingDataProviderSignatures(ctx, submissionID)
	dataProviders := make([]contract.DataProviderParty, 0, len(parties))
	for _, p := range parties {
		dp := contract.DataProviderParty{
			ID:          p.ID,
			Name:        p.Username,
			DatasetName: p.DatasetName,
			DataURL:     p.DataURL,
			Constraints: contract.Constraints{RestrictedTo: []string{}},
		}
		if signedAt, ok := priorSignatures[p.Username]; ok {
			dp.Signature.SignedAt = signedAt
		}
		dataProviders = append(dataProviders, dp)
	}

	// The drafting party (the output owner). Use ownerUserID if provided,
	// otherwise fall back to the submission id.
	if ownerUserID == "" {
		ownerUserID = submissionID
	}

	projectID := newID("proj", 9)
	contractID := NewUUID()
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
		Technique:     "FL",
		ComputeChoice: "FEDERATED_LEARNING",
		Parties: contract.Parties{
			User: contract.UserParty{
				ID:        ownerUserID,
				Name:      ownerUserID,
				Signature: contract.Signature{SignedAt: &now},
			},
			DataProviders:        dataProviders,
			DataProviderCount:    len(dataProviders),
			ApplicationProviders: []contract.ApplicationProviderParty{},
			InfraProviders:       []contract.InfraProviderParty{},
			InfraProviderCount:   0,
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

// StoreContract upserts a contract keyed by project_id (one contract per
// project; every BuildContract call mints a fresh project_id, so a session
// accumulates a new project per contract build - draft, final, and any
// "Start Again" restart each get their own row).
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
		ON CONFLICT (project_id) DO UPDATE SET
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
		ON CONFLICT (session_id) WHERE session_id LIKE 'preview:%' DO UPDATE SET
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

// SignDataProviderParty marks a data-provider party as signed (signature.signed_at
// = now) on this session's stored contract, matched by username (that's all the
// participation-response flow carries — see httpapi.respondToNotification).
// It's a no-op, returning (false, nil), when there's no stored contract yet, no
// party with that username, or that party already signed. finalize (a later
// BuildContract call rebuilding the contract for this session) carries the
// signature forward via existingDataProviderSignatures, so it survives the
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
// accumulates several projects (see BuildContract, which mints a fresh
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
