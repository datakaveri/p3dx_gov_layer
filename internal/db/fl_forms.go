package db

// This file is FL-only: the output-owner form (session parameters like model,
// framework, server rounds). APD is the store of record for the document —
// see apd_client.go — this file owns the struct shape and the coercions that
// match what the old SQL store produced. TEE and SMPC have no equivalent.

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

// FormSubmission is one output-owner form. JSON tags reproduce the shape the
// service has always returned to clients; the form is stored in APD as this exact
// JSON document and reconstructed here on read.
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
// are FlexFloat so "absent" and "present" are distinguishable before applying the
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

// --- FlexFloat -> typed pointer, applying the `value || null` coercion (0/absent
// => nil), matching the SQL-side truthy* helpers the store previously used. ---

func flexInt32(f FlexFloat) *int32 {
	if p := f.ptr(); p != nil && *p != 0 {
		v := int32(*p)
		return &v
	}
	return nil
}

func flexReal(f FlexFloat) *Real {
	if p := f.ptr(); p != nil && *p != 0 {
		v := Real(*p)
		return &v
	}
	return nil
}

func flexBigInt(f FlexFloat) *BigInt {
	if p := f.ptr(); p != nil && *p != 0 {
		v := BigInt(int64(*p))
		return &v
	}
	return nil
}

// strOrNil returns p when it points to a non-empty string, else nil (JS `value || null`).
func strOrNil(p *string) *string {
	if p != nil && *p != "" {
		return p
	}
	return nil
}

// StoreFormSubmission upserts an output-owner form in APD (keyed on form_id: an
// existing form_id is updated in place, a new one gets a freshly minted id).
// Returns the submission id. The form document and the coercions match what the
// SQL store produced.
func (d *DB) StoreFormSubmission(ctx context.Context, in *FormInput) (string, error) {
	now := time.Now().UTC()
	requestedAt := parseTimeOr(in.RequestedAt, now)
	filled := true
	selectedProviders := json.RawMessage(jsonbOr(in.SelectedProviders, "[]"))
	ip := strOrNil(in.IPAddress)

	candidateID := newID("gov", 9)
	sub := FormSubmission{
		ID:                candidateID,
		FormID:            in.FormID,
		RequestedBy:       in.RequestedBy,
		OutputOwnerID:     in.OutputOwnerID,
		NumServerRounds:   flexInt32(in.NumServerRounds),
		FractionEvaluate:  flexReal(in.FractionEvaluate),
		LocalEpochs:       flexInt32(in.LocalEpochs),
		LearningRate:      flexReal(in.LearningRate),
		BatchSize:         flexInt32(in.BatchSize),
		Model:             strOrNil(in.Model),
		Framework:         strOrNil(in.Framework),
		Components:        json.RawMessage(jsonbOr(in.Components, "{}")),
		Filled:            &filled,
		RequestedAt:       &requestedAt,
		FilledAt:          &now,
		SelectedProviders: selectedProviders,
		IPAddress:         ip,
		Port:              flexInt32(in.Port),
		RAMUsage:          flexInt32(in.RAMUsage),
	}

	doc, err := json.Marshal(sub)
	if err != nil {
		return "", err
	}
	id, err := d.apd.upsertSubmission(ctx, candidateID, in.FormID, in.OutputOwnerID, ip != nil, selectedProviders, doc)
	if err != nil {
		return "", err
	}
	log.Println("[DATABASE] Form submission stored in APD:", id)
	return id, nil
}

// GetAllFormSubmissions returns every form ordered newest-first (from APD).
func (d *DB) GetAllFormSubmissions(ctx context.Context) ([]FormSubmission, error) {
	return d.apd.listSubmissions(ctx)
}

// GetFormSubmissionByID returns one form or (nil, nil) when not found (from APD).
func (d *DB) GetFormSubmissionByID(ctx context.Context, id string) (*FormSubmission, error) {
	return d.apd.getSubmission(ctx, id)
}

// DeleteFormSubmission deletes by id and reports whether a row was removed (in APD).
func (d *DB) DeleteFormSubmission(ctx context.Context, id string) (bool, error) {
	return d.apd.deleteSubmission(ctx, id)
}

// GetLatestSessionForProvider finds the most recent submission that has an owner
// ip_address set and lists the given provider in selected_providers, or (nil, nil)
// if none (from APD).
func (d *DB) GetLatestSessionForProvider(ctx context.Context, username string) (*FormSubmission, error) {
	return d.apd.latestSubmissionForProvider(ctx, username)
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
