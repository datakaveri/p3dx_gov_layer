package db

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
)

// The contract is emitted in the standard FL contract format. Fields the FL flow
// does not capture are left blank (empty string / zero / empty object) rather
// than omitted, so the shape is always complete. Signatures are left as an empty
// object for now — signing is not implemented yet.

// PartyConstraints carries the accessibility metadata for a party. Blank when the
// FL flow doesn't capture it.
type PartyConstraints struct {
	AccessibilityLevel string   `json:"accessibility_level"`
	RestrictedTo       []string `json:"restricted_to"`
}

// UsageConstraints bounds how a party's output may be used. Blank when unknown.
type UsageConstraints struct {
	MaxRequests  int    `json:"max_requests"`
	MaxBatchSize int    `json:"max_batch_size"`
	ResultFormat string `json:"result_format"`
}

// DataProviderParty is a party_N entry with role DATA_PROVIDER. id is the
// Keycloak user id, name the username. data_resource_id and data_size_bytes come
// from the provider's latest data-provider form; the remaining dataset fields are
// not captured by the FL flow and are left blank.
type DataProviderParty struct {
	ID             string           `json:"id"`
	Role           string           `json:"role"`
	Name           string           `json:"name"`
	DataResourceID string           `json:"data_resource_id"`
	DatasetName    string           `json:"dataset_name"`
	DatasetVersion string           `json:"dataset_version"`
	DataURL        string           `json:"data_url"`
	Format         string           `json:"format"`
	DataSizeBytes  int64            `json:"data_size_bytes"`
	LicenseType    string           `json:"license_type"`
	Constraints    PartyConstraints `json:"constraints"`
}

// DraftingParty is the output owner. In this FL flow there is no separate
// application provider, so the output owner is the sole drafting party. id is the
// Keycloak user id, name the username; ram_usage_mb comes from the owner form.
type DraftingParty struct {
	ID               string           `json:"id"`
	Role             string           `json:"role"`
	Name             string           `json:"name"`
	DatablobURL      string           `json:"datablob_url"`
	RAMUsageMB       int32            `json:"ram_usage_mb"`
	UsageConstraints UsageConstraints `json:"usage_constraints"`
}

// Lifecycle holds the contract validity window (created / valid-from / valid-until).
type Lifecycle struct {
	CreatedAt  string `json:"created_at"`
	ValidFrom  string `json:"valid_from"`
	ValidUntil string `json:"valid_until"`
}

// TrainingConfig is the output-owner FL hyperparameters carried in session_info.
// Absent values serialize as null.
type TrainingConfig struct {
	NumServerRounds  *int32          `json:"num_server_rounds"`
	FractionEvaluate *Real           `json:"fraction_evaluate"`
	LocalEpochs      *int32          `json:"local_epochs"`
	LearningRate     *Real           `json:"learning_rate"`
	BatchSize        *int32          `json:"batch_size"`
	Model            *string         `json:"model"`
	Framework        *string         `json:"framework"`
	Components       json.RawMessage `json:"components"`
}

// SessionInfo describes the form submission the contract was assembled from.
// session_id is the form submission id; form_id is the form template id.
type SessionInfo struct {
	ID             string         `json:"id"`
	FormID         string         `json:"form_id"`
	SessionID      string         `json:"session_id"`
	RequestedBy    string         `json:"requested_by"`
	OutputOwnerID  string         `json:"output_owner_id"`
	Filled         bool           `json:"filled"`
	TrainingConfig TrainingConfig `json:"training_config"`
}

// Contract is the agreement assembled when the output owner selects providers,
// emitted in the standard FL contract format. project_id is generated once per
// session and stays stable; contract_id is likewise reused across the draft and
// final contracts for a session. parties is keyed party_1..party_N: one per data
// provider (role DATA_PROVIDER) followed by the drafting party (the output owner).
type Contract struct {
	ProjectID         string         `json:"project_id"`
	ContractID        string         `json:"contract_id"`
	Version           int            `json:"version"`
	Description       string         `json:"description"`
	Lifecycle         Lifecycle      `json:"lifecycle"`
	ComputeChoice     string         `json:"compute_choice"`
	ExecutionPlatform string         `json:"execution_platform"`
	Parties           map[string]any `json:"parties"`
	SessionInfo       SessionInfo    `json:"session_info"`
	Signatures        map[string]any `json:"signatures"`
}

// ContractPartyInput is one provider passed in from the caller: the Keycloak id
// and username. The dataset fields are filled server-side from the provider's
// latest data-provider form so the contract is always auto-populated.
type ContractPartyInput struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// contractISO formats a timestamp the same way the report code does.
func contractISO(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// newUUID returns a random RFC 4122 version-4 UUID string. Used for contract_id
// (avoids pulling in an external uuid dependency).
func newUUID() string {
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
func (d *DB) BuildContract(ctx context.Context, submissionID, ownerUserID string, parties []ContractPartyInput, finalize bool, pathway string) (*Contract, error) {
	if pathway == "" {
		pathway = "FL"
	}

	// Build parties without form data (forms now live in APD only).
	// party_1..party_N: one DATA_PROVIDER per selected provider.
	partiesMap := make(map[string]any, len(parties)+1)
	idx := 1
	for _, p := range parties {
		dp := DataProviderParty{
			ID:          p.ID,
			Role:        "DATA_PROVIDER",
			Name:        p.Username,
			Constraints: PartyConstraints{RestrictedTo: []string{}},
		}
		partiesMap[fmt.Sprintf("party_%d", idx)] = dp
		idx++
	}

	// Final party: the drafting party (the output owner).
	// Use ownerUserID if provided, otherwise fall back to username.
	if ownerUserID == "" {
		ownerUserID = submissionID
	}
	partiesMap[fmt.Sprintf("party_%d", idx)] = DraftingParty{
		ID:               ownerUserID,
		Role:             "DRAFTING_PARTY",
		Name:             ownerUserID,
		RAMUsageMB:       0,
		UsageConstraints: UsageConstraints{},
	}

	projectID := d.existingProjectID(ctx, submissionID)
	if projectID == "" {
		projectID = newID("proj", 9)
	}
	contractID := d.existingContractID(ctx, submissionID)
	if contractID == "" {
		contractID = newUUID()
	}
	version := 1
	if finalize {
		version = 2
	}

	now := time.Now().UTC()

	return &Contract{
		ProjectID:   projectID,
		ContractID:  contractID,
		Version:     version,
		Description: "",
		Lifecycle: Lifecycle{
			CreatedAt:  contractISO(now),
			ValidFrom:  contractISO(now),
			ValidUntil: contractISO(now.Add(90 * 24 * time.Hour)),
		},
		ComputeChoice:     "FEDERATED_LEARNING",
		ExecutionPlatform: "AZURE_AMD_SEV",
		Parties:           partiesMap,
		SessionInfo: SessionInfo{
			ID:            submissionID,
			FormID:        "",
			SessionID:     submissionID,
			RequestedBy:   "",
			OutputOwnerID: ownerUserID,
			Filled:        true,
			TrainingConfig: TrainingConfig{
				NumServerRounds:  nil,
				FractionEvaluate: nil,
				LocalEpochs:      nil,
				LearningRate:     nil,
				BatchSize:        nil,
				Model:            nil,
				Framework:        nil,
				Components:       json.RawMessage("{}"),
			},
		},
		Signatures: map[string]any{},
	}, nil
}

// StoreContract upserts a contract keyed by session_id (one contract per session).
// finalized marks the final roster contract vs. the initial participation-request
// draft. pathway indicates FL or GENERAL. Returns the contract row id.
func (d *DB) StoreContract(ctx context.Context, c *Contract, finalized bool, pathway string) (string, error) {
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
		newID("con", 9), c.ProjectID, c.SessionInfo.SessionID, c.SessionInfo.OutputOwnerID, finalized, pathway, raw,
	).Scan(&id)
	if err != nil {
		return "", err
	}
	log.Printf("[DATABASE] Contract stored (session=%s project=%s pathway=%s finalized=%t): %s", c.SessionInfo.SessionID, c.ProjectID, pathway, finalized, id)
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
