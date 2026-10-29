package catalogue

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// APDCatalogueItem is one entry of a provider's own APD catalogue — a row of
// "My Datasets" (GET /policy/mine-datasets) or "My Infrastructure"
// (GET /policy/mine).
type APDCatalogueItem struct {
	ItemID string `json:"item_id"`
	Name   string `json:"name"`
}

// ListProviderDatasets returns the datasets providerID has registered in APD.
func ListProviderDatasets(providerID string) ([]APDCatalogueItem, error) {
	return fetchProviderCatalogue("/api/v1/policy/mine-datasets", providerID)
}

// ListProviderInfra returns the infrastructure providerID has registered in
// APD (the provider's slice of InfraCat).
func ListProviderInfra(providerID string) ([]APDCatalogueItem, error) {
	return fetchProviderCatalogue("/api/v1/policy/mine", providerID)
}

func fetchProviderCatalogue(path, providerID string) ([]APDCatalogueItem, error) {
	baseURL := strings.TrimRight(os.Getenv("APD_BASE_URL"), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("APD_BASE_URL not set")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(baseURL + path + "?provider_id=" + url.QueryEscape(providerID))
	if err != nil {
		return nil, fmt.Errorf("fetch APD catalogue: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("APD catalogue endpoint returned status %d", resp.StatusCode)
	}
	var body struct {
		Data []APDCatalogueItem `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode APD catalogue: %w", err)
	}
	return body.Data, nil
}
