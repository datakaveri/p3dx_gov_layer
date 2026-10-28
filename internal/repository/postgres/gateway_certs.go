package postgres

// This file records every Flotilla gateway TLS certificate the governance CA
// issues (POST /gateway-certs, internal/transport/httpapi/gateway_certs.go): one row
// per certificate serial, tied to the FL contract it was issued for.

import (
	"context"
	"log"
	"time"
)

// GatewayCert is one row of gateway_certs.
type GatewayCert struct {
	Serial            string // hex
	SubmissionID      string
	ProjectID         string
	ContractID        string
	JobID             string
	ServerIP          string
	FingerprintSHA256 string // hex SHA-256 of the certificate DER
	NotAfter          time.Time
	RequestedBy       string // azp of the requesting service token
}

// InsertGatewayCert records an issued gateway certificate.
func (d *DB) InsertGatewayCert(ctx context.Context, c GatewayCert) error {
	_, err := d.Pool.Exec(ctx, `INSERT INTO gateway_certs
		(serial, submission_id, project_id, contract_id, job_id, server_ip, fingerprint_sha256, not_after, requested_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.Serial, c.SubmissionID, c.ProjectID, c.ContractID, c.JobID, c.ServerIP, c.FingerprintSHA256, c.NotAfter.UTC(), c.RequestedBy)
	if err != nil {
		return err
	}
	log.Printf("[DATABASE] gateway_certs recorded: serial=%s submission=%s project=%s ip=%s", c.Serial, c.SubmissionID, c.ProjectID, c.ServerIP)
	return nil
}
