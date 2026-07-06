package db

import (
	"context"
	"encoding/json"
	"log"

	"github.com/jackc/pgx/v5"
)

// StoreSessionReport upserts a combined FL session report on submission_id, so
// re-submitting the same form refreshes the stored report instead of duplicating
// it. Returns the report row id. Mirrors storeSessionReport().
func (d *DB) StoreSessionReport(ctx context.Context, submissionID, formID, outputOwnerID string, report json.RawMessage) (string, error) {
	var existingID string
	err := d.Pool.QueryRow(ctx, `SELECT id FROM session_reports WHERE submission_id = $1`, submissionID).Scan(&existingID)
	switch err {
	case nil:
		_, uerr := d.Pool.Exec(ctx, `UPDATE session_reports
			SET form_id = $2, output_owner_id = $3, report = $4, updated_at = NOW()
			WHERE submission_id = $1`,
			submissionID, nullIfEmpty(formID), nullIfEmpty(outputOwnerID), []byte(report))
		if uerr != nil {
			return "", uerr
		}
		log.Println("[DATABASE] Session report UPDATED:", existingID)
		return existingID, nil
	case pgx.ErrNoRows:
		reportID := newID("rpt", 9)
		_, ierr := d.Pool.Exec(ctx, `INSERT INTO session_reports (id, submission_id, form_id, output_owner_id, report)
			VALUES ($1, $2, $3, $4, $5)`,
			reportID, submissionID, nullIfEmpty(formID), nullIfEmpty(outputOwnerID), []byte(report))
		if ierr != nil {
			return "", ierr
		}
		log.Println("[DATABASE] Session report INSERTED:", reportID)
		return reportID, nil
	default:
		return "", err
	}
}

// GetSessionReport returns the stored report JSON for a submission, or (nil, nil)
// when none exists. Mirrors getSessionReport().
func (d *DB) GetSessionReport(ctx context.Context, submissionID string) (json.RawMessage, error) {
	var report json.RawMessage
	err := d.Pool.QueryRow(ctx, `SELECT report FROM session_reports WHERE submission_id = $1`, submissionID).Scan(&report)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return report, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
