package catalogue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
)

// DataBankType is the DX catalogue type of a dataset item.
const DataBankType = "adex:DataBank"

var (
	// ErrCatalogueItemNotFound: the catalogue has no item with that id
	// (or won't show it to the caller).
	ErrCatalogueItemNotFound = errors.New("item not found in DX catalogue")
	// ErrCatalogueTokenRefused: the catalogue rejected the caller's token.
	ErrCatalogueTokenRefused = errors.New("DX catalogue refused the provider's token")
)

// DXCatalogueItem is the part of a DX catalogue item the job approval reads.
type DXCatalogueItem struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Type       []string `json:"type"`
	UploadedBy string   `json:"uploadedBy"`
}

// IsDataBank reports whether the item is a dataset (adex:DataBank).
func (it DXCatalogueItem) IsDataBank() bool {
	return slices.Contains(it.Type, DataBankType)
}

// FetchDXCatalogueItem looks itemID up in the DX catalogue
// (GET {baseURL}/item?id=) as the holder of token. 404 maps to
// ErrCatalogueItemNotFound and 401/403 to ErrCatalogueTokenRefused.
func FetchDXCatalogueItem(ctx context.Context, client *http.Client, baseURL, itemID, token string) (DXCatalogueItem, error) {
	if baseURL == "" {
		return DXCatalogueItem{}, fmt.Errorf("CATALOGUE_BASE_URL not set")
	}
	u := baseURL + "/item?id=" + url.QueryEscape(itemID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return DXCatalogueItem{}, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return DXCatalogueItem{}, fmt.Errorf("DX catalogue request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return DXCatalogueItem{}, ErrCatalogueItemNotFound
	case http.StatusUnauthorized, http.StatusForbidden:
		return DXCatalogueItem{}, ErrCatalogueTokenRefused
	default:
		return DXCatalogueItem{}, fmt.Errorf("DX catalogue returned status %d", resp.StatusCode)
	}

	// result is an array of items, or (on some deployments) a single item.
	var body struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return DXCatalogueItem{}, fmt.Errorf("decode DX catalogue response: %w", err)
	}
	var items []DXCatalogueItem
	if err := json.Unmarshal(body.Result, &items); err != nil {
		var one DXCatalogueItem
		if err := json.Unmarshal(body.Result, &one); err != nil {
			return DXCatalogueItem{}, fmt.Errorf("decode DX catalogue item: %w", err)
		}
		items = []DXCatalogueItem{one}
	}
	if len(items) == 0 || items[0].ID == "" {
		return DXCatalogueItem{}, ErrCatalogueItemNotFound
	}
	return items[0], nil
}
