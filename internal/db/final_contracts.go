package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// FinalContract is a job's final contract: the governance-signed contract,
// stored once every approval, the contract hash and every signature on it
// verified (PUT /job/{jobId}/status). Written once, never updated.
type FinalContract struct {
	JobID        string          `json:"job_id"`
	ContractID   string          `json:"contract_id"`
	ContractHash string          `json:"contract_hash"`
	Contract     json.RawMessage `json:"contract"`
	CreatedAt    time.Time       `json:"created_at"`
}

// CreateFinalContract stores jobID's final contract and returns true only
// for the first caller; a later call leaves the stored one untouched.
func (d *DB) CreateFinalContract(ctx context.Context, jobID, contractID, contractHash string, contractJSON []byte) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `INSERT INTO final_contracts (job_id, contract_id, contract_hash, contract)
		VALUES ($1, $2, $3, $4) ON CONFLICT (job_id) DO NOTHING`, jobID, contractID, contractHash, contractJSON)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// GetFinalContract reads jobID's final contract; nil when it has none.
func (d *DB) GetFinalContract(ctx context.Context, jobID string) (*FinalContract, error) {
	var fc FinalContract
	err := d.Pool.QueryRow(ctx, `SELECT job_id, contract_id, contract_hash, contract, created_at
		FROM final_contracts WHERE job_id = $1`, jobID).
		Scan(&fc.JobID, &fc.ContractID, &fc.ContractHash, &fc.Contract, &fc.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &fc, nil
}
