package postgres

// This file stores providers' contract-signing public keys. The key pair is
// generated in the provider's browser (p3dx-auth-ui api/keyPair.js); only the
// SPKI public key reaches here, via p3dx-aaa -> PUT /provider-keys
// (internal/transport/httpapi/provider_keys.go). The contract-signing flow
// (contract_signing.go) verifies each provider's signature against it.

import (
	"context"
	"errors"
	"log"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ErrNoPublicKey is returned when the user has not registered a public key.
var ErrNoPublicKey = errors.New("user has no registered public key")

// UpsertProviderPublicKey records or replaces username's public key. rotated
// reports whether a previous key was replaced.
func (d *DB) UpsertProviderPublicKey(ctx context.Context, username, userID, role, publicKeyPEM, fingerprint string) (rotated bool, err error) {
	// xmax <> 0 only on the row version an ON CONFLICT ... DO UPDATE wrote.
	err = d.Pool.QueryRow(ctx, `INSERT INTO provider_public_keys
			(username, user_id, role, public_key_pem, fingerprint_sha256, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT (username) DO UPDATE
			SET user_id = EXCLUDED.user_id, role = EXCLUDED.role,
				public_key_pem = EXCLUDED.public_key_pem,
				fingerprint_sha256 = EXCLUDED.fingerprint_sha256,
				updated_at = CURRENT_TIMESTAMP
		RETURNING xmax <> 0`,
		strings.ToLower(username), userID, role, publicKeyPEM, fingerprint).Scan(&rotated)
	if err != nil {
		return false, err
	}
	log.Printf("[DATABASE] provider_public_keys upserted: username=%s role=%s fingerprint=%s rotated=%t",
		username, role, fingerprint, rotated)
	return rotated, nil
}

// ProviderPublicKey returns username's registered PEM public key, or
// ErrNoPublicKey.
func (d *DB) ProviderPublicKey(ctx context.Context, username string) (string, error) {
	var pem string
	err := d.Pool.QueryRow(ctx, `SELECT public_key_pem FROM provider_public_keys WHERE username = $1`,
		strings.ToLower(username)).Scan(&pem)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoPublicKey
	}
	return pem, err
}
