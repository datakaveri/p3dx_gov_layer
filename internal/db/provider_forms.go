package db

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

// DataProviderForm is one data-provider form. It is stored in APD as this exact
// JSON document and reconstructed here on read.
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

// StoreDataProviderForm stores a data-provider form in APD and returns its id.
// The document and coercions match what the SQL store produced.
func (d *DB) StoreDataProviderForm(ctx context.Context, in *ProviderFormInput) (string, error) {
	id := newID("dpf", 9)
	filledAt := parseTimeOr(in.FilledAt, time.Now().UTC())
	filled := true

	form := DataProviderForm{
		ID:            id,
		FormID:        strOrNil(in.FormID),
		DataOwnerID:   strOrNil(in.DataOwnerID),
		RAM:           flexInt32(in.RAM),
		MemoryMB:      flexInt32(in.MemoryMB),
		DataSizeBytes: flexBigInt(in.DataSizeBytes),
		DataResource:  strOrNil(in.DataResource),
		IPAddress:     strOrNil(in.IPAddress),
		Port:          flexInt32(in.Port),
		Filled:        &filled,
		FilledAt:      &filledAt,
		SubmittedBy:   strOrNil(in.SubmittedBy),
		RAMUsage:      flexInt32(in.RAMUsage),
	}

	doc, err := json.Marshal(form)
	if err != nil {
		return "", err
	}
	var formID, dataOwner string
	if form.FormID != nil {
		formID = *form.FormID
	}
	if form.DataOwnerID != nil {
		dataOwner = *form.DataOwnerID
	}
	storedID, err := d.apd.insertProviderForm(ctx, id, formID, dataOwner, doc)
	if err != nil {
		return "", err
	}
	log.Println("[DATABASE] Data provider form stored in APD:", storedID)
	return storedID, nil
}

// GetAllDataProviderForms returns every data-provider form, newest-first (from APD).
func (d *DB) GetAllDataProviderForms(ctx context.Context) ([]DataProviderForm, error) {
	return d.apd.listProviderForms(ctx)
}

// GetDataProviderFormsByUsernames returns the latest form per data_owner_id for
// the given usernames (from APD). Empty input yields an empty slice.
func (d *DB) GetDataProviderFormsByUsernames(ctx context.Context, usernames []string) ([]DataProviderForm, error) {
	return d.apd.providerFormsByUsernames(ctx, usernames)
}
