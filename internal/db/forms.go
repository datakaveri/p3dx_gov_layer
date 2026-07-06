package db

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
)

// form_submissions column list (table order + ALTER-added columns), shared by
// every SELECT so pgx.RowToStructByName maps cleanly onto FormSubmission.
const formColumns = `id, form_id, requested_by, output_owner_id,
	num_server_rounds, fraction_evaluate, local_epochs, learning_rate, batch_size,
	model, framework, components, filled, requested_at, filled_at, created_at,
	selected_providers, ip_address, port, ram_usage`

// FormSubmission is one row of form_submissions. JSON tags reproduce the shape
// node-postgres returned to clients (SELECT *); jsonb columns are passed through
// verbatim and nullable scalars serialize as null.
type FormSubmission struct {
	ID                string          `db:"id" json:"id"`
	FormID            string          `db:"form_id" json:"form_id"`
	RequestedBy       string          `db:"requested_by" json:"requested_by"`
	OutputOwnerID     string          `db:"output_owner_id" json:"output_owner_id"`
	NumServerRounds   *int32          `db:"num_server_rounds" json:"num_server_rounds"`
	FractionEvaluate  *Real           `db:"fraction_evaluate" json:"fraction_evaluate"`
	LocalEpochs       *int32          `db:"local_epochs" json:"local_epochs"`
	LearningRate      *Real           `db:"learning_rate" json:"learning_rate"`
	BatchSize         *int32          `db:"batch_size" json:"batch_size"`
	Model             *string         `db:"model" json:"model"`
	Framework         *string         `db:"framework" json:"framework"`
	Components        json.RawMessage `db:"components" json:"components"`
	Filled            *bool           `db:"filled" json:"filled"`
	RequestedAt       *time.Time      `db:"requested_at" json:"requested_at"`
	FilledAt          *time.Time      `db:"filled_at" json:"filled_at"`
	CreatedAt         *time.Time      `db:"created_at" json:"created_at"`
	SelectedProviders json.RawMessage `db:"selected_providers" json:"selected_providers"`
	IPAddress         *string         `db:"ip_address" json:"ip_address"`
	Port              *int32          `db:"port" json:"port"`
	RAMUsage          *int32          `db:"ram_usage" json:"ram_usage"`
}

// FormInput is the inbound payload for storing an output-owner form (the REST
// `payload` object or the gRPC FormSubmission mapped to it). Optional numerics
// are pointers so "absent" and "present" are distinguishable before applying the
// `value || null` coercion.
type FormInput struct {
	FormID            string          `json:"form_id"`
	RequestedBy       string          `json:"requested_by"`
	OutputOwnerID     string          `json:"output_owner_id"`
	NumServerRounds   FlexFloat       `json:"num_server_rounds"`
	FractionEvaluate  FlexFloat       `json:"fraction_evaluate"`
	LocalEpochs       FlexFloat       `json:"local_epochs"`
	LearningRate      FlexFloat       `json:"learning_rate"`
	BatchSize         FlexFloat       `json:"batch_size"`
	Model             *string         `json:"model"`
	Framework         *string         `json:"framework"`
	Components        json.RawMessage `json:"components"`
	SelectedProviders json.RawMessage `json:"selected_providers"`
	IPAddress         *string         `json:"ip_address"`
	Port              FlexFloat       `json:"port"`
	RAMUsage          FlexFloat       `json:"ram_usage"`
	RequestedAt       *string         `json:"requested_at"`
	FilledAt          *string         `json:"filled_at"`
}

// SelectedProvider is one entry of the selected_providers JSONB array.
type SelectedProvider struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// SelectedProviderList parses the selected_providers JSONB into a slice. Invalid
// or empty JSON yields an empty slice (matching JS `submission.selected_providers || []`).
func (f *FormSubmission) SelectedProviderList() []SelectedProvider {
	if len(f.SelectedProviders) == 0 {
		return nil
	}
	var out []SelectedProvider
	if err := json.Unmarshal(f.SelectedProviders, &out); err != nil {
		return nil
	}
	return out
}

// IP returns the owner ip_address or "" when null.
func (f *FormSubmission) IP() string {
	if f.IPAddress == nil {
		return ""
	}
	return *f.IPAddress
}

// StoreFormSubmission upserts on form_id: an existing form_id is UPDATEd in place
// (no duplicate, same id) and a new one is INSERTed with a freshly minted id.
// Returns the submission id. Mirrors storeFormSubmission().
func (d *DB) StoreFormSubmission(ctx context.Context, in *FormInput) (string, error) {
	filledAt := time.Now().UTC()

	var existingID string
	err := d.Pool.QueryRow(ctx, `SELECT id FROM form_submissions WHERE form_id = $1`, in.FormID).Scan(&existingID)
	switch err {
	case nil:
		// UPDATE existing record (no duplicate).
		_, uerr := d.Pool.Exec(ctx, `UPDATE form_submissions SET
				requested_by = $2,
				output_owner_id = $3,
				num_server_rounds = $4,
				fraction_evaluate = $5,
				local_epochs = $6,
				learning_rate = $7,
				batch_size = $8,
				model = $9,
				framework = $10,
				components = $11,
				filled = true,
				filled_at = $12,
				selected_providers = $13,
				ip_address = $14,
				port = $15,
				ram_usage = $16
			WHERE form_id = $1`,
			in.FormID,
			in.RequestedBy,
			in.OutputOwnerID,
			truthyInt(in.NumServerRounds.ptr()),
			truthyFloat(in.FractionEvaluate.ptr()),
			truthyInt(in.LocalEpochs.ptr()),
			truthyFloat(in.LearningRate.ptr()),
			truthyInt(in.BatchSize.ptr()),
			truthyStr(in.Model),
			truthyStr(in.Framework),
			jsonbOr(in.Components, "{}"),
			filledAt,
			jsonbOr(in.SelectedProviders, "[]"),
			truthyStr(in.IPAddress),
			truthyInt(in.Port.ptr()),
			truthyInt(in.RAMUsage.ptr()),
		)
		if uerr != nil {
			return "", uerr
		}
		log.Println("[DATABASE] Form submission UPDATED (no duplicate):", existingID)
		return existingID, nil
	case pgx.ErrNoRows:
		// INSERT new record.
		submissionID := newID("gov", 9)
		requestedAt := parseTimeOr(in.RequestedAt, filledAt)
		_, ierr := d.Pool.Exec(ctx, `INSERT INTO form_submissions (
				id, form_id, requested_by, output_owner_id,
				num_server_rounds, fraction_evaluate, local_epochs,
				learning_rate, batch_size, model, framework,
				components, filled, requested_at, filled_at, selected_providers,
				ip_address, port, ram_usage
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
			submissionID,
			in.FormID,
			in.RequestedBy,
			in.OutputOwnerID,
			truthyInt(in.NumServerRounds.ptr()),
			truthyFloat(in.FractionEvaluate.ptr()),
			truthyInt(in.LocalEpochs.ptr()),
			truthyFloat(in.LearningRate.ptr()),
			truthyInt(in.BatchSize.ptr()),
			truthyStr(in.Model),
			truthyStr(in.Framework),
			jsonbOr(in.Components, "{}"),
			true,
			requestedAt,
			filledAt,
			jsonbOr(in.SelectedProviders, "[]"),
			truthyStr(in.IPAddress),
			truthyInt(in.Port.ptr()),
			truthyInt(in.RAMUsage.ptr()),
		)
		if ierr != nil {
			return "", ierr
		}
		log.Println("[DATABASE] Form submission INSERTED:", submissionID)
		return submissionID, nil
	default:
		return "", err
	}
}

// GetAllFormSubmissions returns every form ordered newest-first.
func (d *DB) GetAllFormSubmissions(ctx context.Context) ([]FormSubmission, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+formColumns+` FROM form_submissions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[FormSubmission])
}

// GetFormSubmissionByID returns one form or (nil, nil) when not found.
func (d *DB) GetFormSubmissionByID(ctx context.Context, id string) (*FormSubmission, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+formColumns+` FROM form_submissions WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	sub, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[FormSubmission])
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sub, nil
}

// DeleteFormSubmission deletes by id and reports whether a row was removed.
func (d *DB) DeleteFormSubmission(ctx context.Context, id string) (bool, error) {
	tag, err := d.Pool.Exec(ctx, `DELETE FROM form_submissions WHERE id = $1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// GetLatestSessionForProvider finds the most recent submission that has an owner
// ip_address set and lists the given provider in selected_providers (JSONB
// containment), or (nil, nil) if none. Mirrors getLatestSessionForProvider().
func (d *DB) GetLatestSessionForProvider(ctx context.Context, username string) (*FormSubmission, error) {
	containment, _ := json.Marshal([]map[string]string{{"username": username}})
	rows, err := d.Pool.Query(ctx, `SELECT `+formColumns+` FROM form_submissions
		WHERE COALESCE(ip_address,'') <> ''
		  AND selected_providers @> $1::jsonb
		ORDER BY created_at DESC
		LIMIT 1`, string(containment))
	if err != nil {
		return nil, err
	}
	sub, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[FormSubmission])
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sub, nil
}

// parseTimeOr parses an optional RFC3339 timestamp string, falling back to def.
func parseTimeOr(s *string, def time.Time) time.Time {
	if s == nil || *s == "" {
		return def
	}
	if t, err := time.Parse(time.RFC3339, *s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339Nano, *s); err == nil {
		return t
	}
	return def
}
