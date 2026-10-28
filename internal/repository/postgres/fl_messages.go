package postgres

// This file is FL-only: the mock provider directory.

import "context"

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
