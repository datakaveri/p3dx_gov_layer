package db

// This file is FL-only: the output-owner form (session parameters like model,
// framework, server rounds). aaa is the store of record for the document —
// it pushes each submission here as it's created (see
// httpapi/forms_ingest.go and forms_cache.go) — this file just owns the
// struct shape and the read methods FL orchestration/reports use.

import (
	"context"
	"encoding/json"
	"time"
)

// FormSubmission is one output-owner form. JSON tags match the document aaa
// pushes here verbatim.
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

// IngestFormSubmission stores a submission pushed here by aaa, replacing any
// earlier push for the same id. Called by POST /internal/forms/submissions.
func (d *DB) IngestFormSubmission(sub FormSubmission, receivedAt time.Time) {
	d.forms.putSubmission(sub, receivedAt)
}

// RemoveFormSubmission evicts a submission aaa reports as deleted, and
// reports whether it was present. Called by DELETE /internal/forms/submissions/{id}.
func (d *DB) RemoveFormSubmission(_ context.Context, id string) bool {
	return d.forms.removeSubmission(id)
}

// GetFormSubmissionByID returns one form or nil when not cached.
func (d *DB) GetFormSubmissionByID(_ context.Context, id string) (*FormSubmission, error) {
	return d.forms.getSubmission(id), nil
}

// GetLatestSessionForProvider finds the most recently pushed submission that
// has an owner ip_address set and lists the given provider in
// selected_providers, or nil if none.
func (d *DB) GetLatestSessionForProvider(_ context.Context, username string) (*FormSubmission, error) {
	return d.forms.latestForProvider(username), nil
}
