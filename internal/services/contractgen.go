package services

import (
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// GenerateContractInput carries what's known when a user has picked a
// dataset and a technique. DataURL comes from the APD policy when the
// provider set one (see PolicyForm's "Data URL" field); fields APD/the
// catalogue still can't supply (hashes, application provider identity)
// stay placeholder.
type GenerateContractInput struct {
	DatasetID     string
	DatasetName   string
	ApplicationID string
	Technique     string
	ComputeChoice string // optional override; defaulted per technique when blank
	ConsumerID    string
	ConsumerName  string
	ProviderName  string // resolved from the provider directory, if a provider was found
	ProviderID    string
	Form          map[string]interface{} // provider form data, if FetchDatasetForm found one
	IsPrivate     bool                    // from the APD policy's is_private flag, if one was found
	DataURL       string                  // from the APD policy's data_url field, if one was found

	// Infrastructure Catalogue (InfraCat) selection — SMPC only. InfraID is
	// the caller-selected infra id; the rest are resolved from that infra's
	// APD policy (rules.infrastructure), if FetchInfraPolicy found one.
	InfraID                  string
	InfraName                string
	InfraRegion              string
	InfraAttestationRequired bool
	InfraAttestationService  string
	InfraAttestationPolicyID string
	InfraCPUCores            int
	InfraRAMMB               int
}

// defaultComputeChoice maps a technique to its descriptive compute_choice
// default when the caller doesn't supply one explicitly.
func defaultComputeChoice(technique string) string {
	switch technique {
	case "FL":
		return "FEDERATED_LEARNING"
	case "TEE":
		return "ANONYMIZATION"
	case "SMPC":
		return "SECURE_MULTIPARTY_COMPUTATION"
	default:
		return ""
	}
}

// BuildGeneratedContract assembles an unsigned contract for display, in the
// canonical contract.Contract shape. It does not touch the database and does
// not call APD itself — callers fetch policy/forms first (see
// FetchPolicyForDataset / FetchDatasetForm) and pass whatever they found in
// via Form.
func BuildGeneratedContract(in GenerateContractInput) contract.Contract {
	now := time.Now().UTC()

	dataProviderName := in.ProviderName
	if dataProviderName == "" {
		dataProviderName = "Unknown Data Provider"
	}

	accessibilityLevel := "PUBLIC"
	if in.IsPrivate {
		accessibilityLevel = "PRIVATE"
	}

	dataProvider := contract.DataProviderParty{
		ID:             in.ProviderID,
		Name:           dataProviderName,
		DatasetName:    in.DatasetName,
		DatasetVersion: "v1",
		DataURL:        in.DataURL,
		Constraints:    contract.Constraints{AccessibilityLevel: accessibilityLevel, RestrictedTo: []string{}},
	}
	_ = in.Form // data_size_bytes etc. aren't part of this schema; kept for future use

	applicationProviders := []contract.ApplicationProviderParty{}
	appID := in.ApplicationID
	if appID != "" {
		applicationProviders = append(applicationProviders, contract.ApplicationProviderParty{
			ID:          appID,
			Name:        "Unknown Application Provider",
			AppName:     appID,
			Constraints: contract.Constraints{AccessibilityLevel: "PUBLIC", RestrictedTo: []string{}},
		})
	}

	// A real infra selection (SMPC, via InfraCat) yields a real party built
	// from that infra's APD policy. TEE never sends an InfraID today, and any
	// SMPC caller that predates InfraCat won't either — both fall back to the
	// original placeholder so nothing else breaks.
	infraProviders := []contract.InfraProviderParty{}
	if in.Technique == "TEE" || in.Technique == "SMPC" {
		if in.InfraID != "" {
			infraName := in.InfraName
			if infraName == "" {
				infraName = "Unknown Infrastructure"
			}
			infraProviders = append(infraProviders, contract.InfraProviderParty{
				ID:     in.InfraID,
				Name:   infraName,
				Region: in.InfraRegion,
				Attestation: contract.Attestation{
					Required: in.InfraAttestationRequired,
					Service:  in.InfraAttestationService,
					PolicyID: in.InfraAttestationPolicyID,
				},
				ResourceAllocation: contract.ResourceAllocation{
					CPUCores: in.InfraCPUCores,
					RAMMB:    in.InfraRAMMB,
				},
				Constraints: contract.Constraints{AccessibilityLevel: "PUBLIC", RestrictedTo: []string{}},
			})
		} else {
			infraProviders = append(infraProviders, contract.InfraProviderParty{
				Name:   "Azure Confidential Compute",
				Region: "UNKNOWN",
				Attestation: contract.Attestation{
					Required: true,
					Service:  "MAA",
				},
				Constraints: contract.Constraints{AccessibilityLevel: "PUBLIC", RestrictedTo: []string{}},
			})
		}
	}

	computeChoice := in.ComputeChoice
	if computeChoice == "" {
		computeChoice = defaultComputeChoice(in.Technique)
	}

	c := contract.Contract{
		ContractID: db.NewUUID(),
		Version:    1,
		Lifecycle: contract.Lifecycle{
			CreatedAt:  now,
			ValidFrom:  now,
			ValidUntil: now.Add(90 * 24 * time.Hour),
		},
		Technique:         in.Technique,
		ComputeChoice:     computeChoice,
		ExecutionPlatform: "AZURE_AMD_SEV",
		Parties: contract.Parties{
			User: contract.UserParty{
				ID:   in.ConsumerID,
				Name: in.ConsumerName,
			},
			DataProviders:        []contract.DataProviderParty{dataProvider},
			ApplicationProviders: applicationProviders,
			InfraProviders:       infraProviders,
		},
		SessionInfo: contract.SessionInfo{
			RequestedBy: in.ConsumerID,
		},
	}

	if hash, err := contract.ComputeHash(c); err == nil {
		c.ContractHash = hash
	}

	return c
}
