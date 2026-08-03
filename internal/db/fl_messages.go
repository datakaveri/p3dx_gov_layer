package db

// This file is FL-only: the mock provider directory and the free-text
// messages an output owner sends a provider outside the notification flow.

import (
	"context"
	"log"
	"time"
)

// DataProvider is a registered provider entry (mock list).
type DataProvider struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// GetDataProviders returns the static mock provider list. Mirrors
// getDataProviders() (which returns mock data; the real list is served by the
// AAA backend).
func (d *DB) GetDataProviders(ctx context.Context) []DataProvider {
	return []DataProvider{
		{ID: "provider-1", Name: "Provider A", Email: "provider-a@example.com"},
		{ID: "provider-2", Name: "Provider B", Email: "provider-b@example.com"},
		{ID: "provider-3", Name: "Provider C", Email: "provider-c@example.com"},
	}
}

// ProviderMessageInput is the body of POST /send-provider-message.
type ProviderMessageInput struct {
	ProviderID    string  `json:"provider_id"`
	ProviderEmail string  `json:"provider_email"`
	ProviderName  string  `json:"provider_name"`
	OutputOwnerID string  `json:"output_owner_id"`
	Message       string  `json:"message"`
	Timestamp     *string `json:"timestamp"`
}

// StoreProviderMessage lazily creates provider_messages and inserts one message,
// returning its id. Mirrors storeProviderMessage().
func (d *DB) StoreProviderMessage(ctx context.Context, in *ProviderMessageInput) (string, error) {
	messageID := newID("msg", 9)

	if _, err := d.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS provider_messages (
		id TEXT PRIMARY KEY,
		provider_id TEXT NOT NULL,
		provider_email TEXT NOT NULL,
		provider_name TEXT,
		output_owner_id TEXT NOT NULL,
		message TEXT NOT NULL,
		timestamp TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return "", err
	}

	var ts any
	if in.Timestamp != nil && *in.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339Nano, *in.Timestamp); err == nil {
			ts = t
		} else if t, err := time.Parse(time.RFC3339, *in.Timestamp); err == nil {
			ts = t
		} else {
			ts = *in.Timestamp // let Postgres cast; matches passing the raw value
		}
	}

	_, err := d.Pool.Exec(ctx, `INSERT INTO provider_messages
		(id, provider_id, provider_email, provider_name, output_owner_id, message, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		messageID, in.ProviderID, in.ProviderEmail, in.ProviderName, in.OutputOwnerID, in.Message, ts)
	if err != nil {
		return "", err
	}
	log.Println("[DATABASE] Provider message stored:", messageID)
	return messageID, nil
}
