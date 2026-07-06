package db

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
)

const providerFormColumns = `id, form_id, data_owner_id, ram, memory_mb,
	data_size_bytes, data_resource_id, ip_address, port, filled, filled_at,
	submitted_by, created_at, ram_usage`

// DataProviderForm is one row of data_provider_forms.
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

// ProviderFormInput is the inbound data-provider form payload. Numerics accept
// string-or-number to match the loosely-typed values the UI sends. Note: the UI
// sends "RAM" (uppercase) while we read "ram", so ram is null in practice — this
// matches the Node code, which also reads formData.ram.
type ProviderFormInput struct {
	FormID        *string   `json:"form_id"`
	DataOwnerID   *string   `json:"data_owner_id"`
	RAM           FlexFloat `json:"ram"`
	MemoryMB      FlexFloat `json:"memory_mb"`
	DataSizeBytes FlexFloat `json:"data_size_bytes"`
	DataResource  *string   `json:"data_resource_id"`
	IPAddress     *string   `json:"ip_address"`
	Port          FlexFloat `json:"port"`
	RAMUsage      FlexFloat `json:"ram_usage"`
	FilledAt      *string   `json:"filled_at"`
	SubmittedBy   *string   `json:"submitted_by"`
}

// StoreDataProviderForm inserts a data-provider form and returns its id.
// Mirrors storeDataProviderForm().
func (d *DB) StoreDataProviderForm(ctx context.Context, in *ProviderFormInput) (string, error) {
	id := newID("dpf", 9)
	filledAt := parseTimeOr(in.FilledAt, time.Now().UTC())
	_, err := d.Pool.Exec(ctx, `INSERT INTO data_provider_forms
		(id, form_id, data_owner_id, ram, memory_mb, data_size_bytes, data_resource_id, ip_address, port, filled, filled_at, submitted_by, ram_usage)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		id,
		truthyStr(in.FormID),
		truthyStr(in.DataOwnerID),
		truthyInt(in.RAM.ptr()),
		truthyInt(in.MemoryMB.ptr()),
		truthyBigInt(in.DataSizeBytes.ptr()),
		truthyStr(in.DataResource),
		truthyStr(in.IPAddress),
		truthyInt(in.Port.ptr()),
		true,
		filledAt,
		truthyStr(in.SubmittedBy),
		truthyInt(in.RAMUsage.ptr()),
	)
	if err != nil {
		return "", err
	}
	log.Println("[DATABASE] Data provider form stored:", id)
	return id, nil
}

// GetAllDataProviderForms returns every data-provider form, newest-first.
func (d *DB) GetAllDataProviderForms(ctx context.Context) ([]DataProviderForm, error) {
	rows, err := d.Pool.Query(ctx, `SELECT `+providerFormColumns+` FROM data_provider_forms ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[DataProviderForm])
}

// GetDataProviderFormsByUsernames returns the latest form per data_owner_id for
// the given usernames (DISTINCT ON ... ORDER BY created_at DESC). Empty input
// yields an empty slice. Mirrors getDataProviderFormsByUsernames().
func (d *DB) GetDataProviderFormsByUsernames(ctx context.Context, usernames []string) ([]DataProviderForm, error) {
	if len(usernames) == 0 {
		return []DataProviderForm{}, nil
	}
	// usernames is a Go []string -> a single $1 text[] parameter via ANY().
	rows, err := d.Pool.Query(ctx, `SELECT DISTINCT ON (data_owner_id) `+providerFormColumns+`
		FROM data_provider_forms
		WHERE data_owner_id = ANY($1)
		ORDER BY data_owner_id, created_at DESC`, usernames)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[DataProviderForm])
}
