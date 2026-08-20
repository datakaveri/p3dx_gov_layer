package services

import (
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// GeneratedContract mirrors the shape p3dx-aaa/contract-gen produces (and
// p3dx-auth-ui already renders): technique, lifecycle, parties, and the
// per-party terms. It additionally carries a top-level Datasets list so a
// generated contract, once signing is resolved, can be submitted as-is to
// POST /contract (handleGeneralContract/handleFLContract read datasets from
// exactly this shape via extractDatasets).
//
// Building this contract is generation only — it is never signed, stored, or
// deployed here. That happens later, once the consumer-signing model is decided.
type GeneratedContract struct {
	ContractID               string                   `json:"contract_id"`
	Version                  int                      `json:"version"`
	Description              string                   `json:"description"`
	Technique                string                   `json:"technique"`
	Datasets                 []GeneratedDatasetRef    `json:"datasets"`
	Lifecycle                GeneratedLifecycle       `json:"lifecycle"`
	ExecutionType            string                   `json:"execution_type"`
	ExecutionPlatform        string                   `json:"execution_platform"`
	Parties                  GeneratedParties         `json:"parties"`
	DataProviderTerms        DataProviderTerms        `json:"data_provider_terms"`
	ApplicationProviderTerms ApplicationProviderTerms `json:"application_provider_terms"`
	ConsumerTerms            ConsumerTerms            `json:"consumer_terms"`
}

type GeneratedDatasetRef struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ProviderID string `json:"provider_id,omitempty"`
}

type GeneratedLifecycle struct {
	CreatedAt  time.Time `json:"created_at"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
}

type GeneratedParty struct {
	ID             string `json:"id,omitempty"`
	Name           string `json:"name"`
	OrganizationID string `json:"organization_id,omitempty"`
	PublicKey      string `json:"public_key"`
}

type GeneratedParties struct {
	DataProvider        GeneratedParty `json:"data_provider"`
	ApplicationProvider GeneratedParty `json:"application_provider"`
	Consumer            GeneratedParty `json:"consumer"`
}

type PartyConstraints struct {
	AccessibilityLevel string `json:"accessibility_level,omitempty"`
}

type UsageConstraints struct {
	MaxRequests  int    `json:"max_requests,omitempty"`
	MaxBatchSize int    `json:"max_batch_size,omitempty"`
	ResultFormat string `json:"result_format,omitempty"`
}

type DataProviderTerms struct {
	DataResourceID string           `json:"data_resource_id"`
	DatasetName    string           `json:"dataset_name"`
	DatasetVersion string           `json:"dataset_version"`
	Format         string           `json:"format"`
	DataSizeBytes  int64            `json:"data_size_bytes"`
	LicenseType    string           `json:"license_type"`
	Constraints    PartyConstraints `json:"constraints,omitempty"`
}

type ApplicationProviderTerms struct {
	AppID       string           `json:"app_id"`
	AppName     string           `json:"app_name"`
	Constraints PartyConstraints `json:"constraints,omitempty"`
	Usage       UsageConstraints `json:"usage_constraints,omitempty"`
}

type ConsumerTerms struct {
	SelectedAppID    string           `json:"selected_app_id"`
	UsageConstraints UsageConstraints `json:"usage_constraints,omitempty"`
	DataRetention    string           `json:"consumer_data_retention_policy,omitempty"`
}

// GenerateContractInput carries what's known when a user has picked a
// dataset and a technique. Fields APD/the catalogue can't supply yet
// (real data URLs/hashes, application provider identity) stay placeholder —
// this mirrors the same limitation contract-gen already had.
type GenerateContractInput struct {
	DatasetID     string
	DatasetName   string
	ApplicationID string
	Technique     string
	ConsumerID    string
	ConsumerName  string
	ProviderName  string // resolved from the provider directory, if a provider was found
	ProviderID    string
	Form          map[string]interface{} // provider form data, if FetchDatasetForm found one
}

// BuildGeneratedContract assembles an unsigned contract for display. It does
// not touch the database and does not call APD itself — callers fetch
// policy/forms first (see FetchPolicyForDataset / FetchDatasetForm) and pass
// whatever they found in via Form.
func BuildGeneratedContract(in GenerateContractInput) GeneratedContract {
	now := time.Now().UTC()

	dataProviderName := in.ProviderName
	if dataProviderName == "" {
		dataProviderName = "Unknown Data Provider"
	}

	terms := DataProviderTerms{
		DataResourceID: in.DatasetID,
		DatasetName:    in.DatasetName,
		DatasetVersion: "v1",
		Format:         "UNKNOWN",
		LicenseType:    "UNKNOWN",
		Constraints:    PartyConstraints{AccessibilityLevel: "PUBLIC"},
	}
	if in.Form != nil {
		if dataSize, ok := in.Form["data_size_bytes"].(float64); ok {
			terms.DataSizeBytes = int64(dataSize)
		}
	}

	appID := in.ApplicationID
	if appID == "" {
		appID = "unselected-application"
	}

	return GeneratedContract{
		ContractID:  db.NewUUID(),
		Version:     1,
		Description: "workload dataset=" + in.DatasetName + " technique=" + in.Technique,
		Technique:   in.Technique,
		Datasets: []GeneratedDatasetRef{
			{ID: in.DatasetID, Name: in.DatasetName, ProviderID: in.ProviderID},
		},
		Lifecycle: GeneratedLifecycle{
			CreatedAt:  now,
			ValidFrom:  now,
			ValidUntil: now.Add(90 * 24 * time.Hour),
		},
		ExecutionType:     "TRAINING",
		ExecutionPlatform: "AZURE_AMD_SEV",
		Parties: GeneratedParties{
			DataProvider:        GeneratedParty{ID: in.ProviderID, Name: dataProviderName},
			ApplicationProvider: GeneratedParty{ID: appID, Name: "Unknown Application Provider"},
			Consumer:            GeneratedParty{ID: in.ConsumerID, Name: in.ConsumerName},
		},
		DataProviderTerms: terms,
		ApplicationProviderTerms: ApplicationProviderTerms{
			AppID:       appID,
			AppName:     appID,
			Constraints: PartyConstraints{AccessibilityLevel: "PUBLIC"},
			Usage:       UsageConstraints{MaxRequests: 10000, MaxBatchSize: 256},
		},
		ConsumerTerms: ConsumerTerms{
			SelectedAppID:    appID,
			UsageConstraints: UsageConstraints{MaxRequests: 10000, MaxBatchSize: 256, ResultFormat: "JSON"},
			DataRetention:    "DELETE_AFTER_EXECUTION",
		},
	}
}
