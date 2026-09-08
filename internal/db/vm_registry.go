package db

// This file is the participant-VM IP registry: terraform/participant-vm
// registers each VM it creates here (keyed by role + participant_name) so a
// data-provider VM can look up the current output-owner's IP for its
// combine_fl broker_host. See internal/httpapi/vm_registry.go for the HTTP
// layer and terraform/participant-vm/templates/configure-broker.sh.tftpl for
// the caller.

import (
	"context"
	"errors"
	"log"

	"github.com/jackc/pgx/v5"
)

// VMRegistryEntry is one row of vm_registry.
type VMRegistryEntry struct {
	Role            string `json:"role"`
	ParticipantName string `json:"participant_name"`
	IPAddress       string `json:"ip_address"`
	UpdatedAt       string `json:"updated_at"`
}

// ErrNoOutputOwner is returned when no "user" role VM has been registered yet.
var ErrNoOutputOwner = errors.New("no output-owner VM registered yet")

// UpsertVMRegistry records or updates the IP for a (role, participant_name) VM.
func (d *DB) UpsertVMRegistry(ctx context.Context, role, participantName, ipAddress string) error {
	_, err := d.Pool.Exec(ctx, `INSERT INTO vm_registry (role, participant_name, ip_address, updated_at)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
		ON CONFLICT (role, participant_name) DO UPDATE
			SET ip_address = EXCLUDED.ip_address, updated_at = CURRENT_TIMESTAMP`,
		role, participantName, ipAddress)
	if err != nil {
		return err
	}
	log.Printf("[DATABASE] vm_registry upserted: role=%s participant=%s ip=%s", role, participantName, ipAddress)
	return nil
}

// GetOutputOwnerVM returns the most recently updated role='user' entry — "the"
// current output-owner VM. ErrNoOutputOwner if none is registered yet.
func (d *DB) GetOutputOwnerVM(ctx context.Context) (*VMRegistryEntry, error) {
	row := d.Pool.QueryRow(ctx, `SELECT role, participant_name, ip_address, updated_at::text
		FROM vm_registry WHERE role = 'user' ORDER BY updated_at DESC LIMIT 1`)
	var e VMRegistryEntry
	if err := row.Scan(&e.Role, &e.ParticipantName, &e.IPAddress, &e.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoOutputOwner
		}
		return nil, err
	}
	return &e, nil
}

// ListDataProviderVMs returns every registered role='data-provider' entry,
// most recently updated first.
func (d *DB) ListDataProviderVMs(ctx context.Context) ([]VMRegistryEntry, error) {
	rows, err := d.Pool.Query(ctx, `SELECT role, participant_name, ip_address, updated_at::text
		FROM vm_registry WHERE role = 'data-provider' ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []VMRegistryEntry{}
	for rows.Next() {
		var e VMRegistryEntry
		if err := rows.Scan(&e.Role, &e.ParticipantName, &e.IPAddress, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
