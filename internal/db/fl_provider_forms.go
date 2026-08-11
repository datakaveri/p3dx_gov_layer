package db

// This file is FL-only: the data-provider form (host/resource details for one
// FL participant). aaa is the store of record; it pushes each form here as
// it's created (see httpapi/forms_ingest.go and forms_cache.go). TEE and SMPC
// have no equivalent.

import (
	"context"
	"time"
)

// DataProviderForm is one data-provider form. JSON tags match the document
// aaa pushes here verbatim.
type DataProviderForm struct {
	ID            string     `db:"id" json:"id"`
	FormID        *string    `db:"form_id" json:"form_id"`
	DataOwnerID   *string    `db:"data_owner_id" json:"data_owner_id"`
	RAM           *int32     `db:"ram" json:"ram"`
	MemoryMB      *int32     `db:"memory_mb" json:"memory_mb"`
	DataSizeBytes *BigInt    `db:"data_size_bytes" json:"data_size_bytes"`
	DataResource  *string    `db:"data_resource_id" json:"data_resource_id"`
	IPAddress     *string    `db:"ip_address" json:"ip_address"`
	Port          *int32     `db:"port" json:"port"`
	Filled        *bool      `db:"filled" json:"filled"`
	FilledAt      *time.Time `db:"filled_at" json:"filled_at"`
	SubmittedBy   *string    `db:"submitted_by" json:"submitted_by"`
	CreatedAt     *time.Time `db:"created_at" json:"created_at"`
	RAMUsage      *int32     `db:"ram_usage" json:"ram_usage"`
}

// IP returns the provider ip_address or "" when null.
func (f *DataProviderForm) IP() string {
	if f.IPAddress == nil {
		return ""
	}
	return *f.IPAddress
}

// PortInt returns the provider port or 0 when null.
func (f *DataProviderForm) PortInt() int {
	if f.Port == nil {
		return 0
	}
	return int(*f.Port)
}

// IngestDataProviderForm stores a provider form pushed here by aaa. Called by
// POST /internal/forms/provider-forms.
func (d *DB) IngestDataProviderForm(form DataProviderForm, receivedAt time.Time) {
	d.forms.putProviderForm(form, receivedAt)
}

// GetDataProviderFormsByUsernames returns the latest pushed form per
// data_owner_id for the given usernames. Empty input yields an empty slice.
func (d *DB) GetDataProviderFormsByUsernames(_ context.Context, usernames []string) ([]DataProviderForm, error) {
	return d.forms.formsByUsernames(usernames), nil
}
