package services

import (
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// DatasetInput carries what's known about one selected dataset. DataURL comes
// from the APD policy when the provider set one (see PolicyForm's "Data URL"
// field); fields APD/the catalogue still can't supply (hashes) stay
// placeholder.
type DatasetInput struct {
	DatasetID    string
	DatasetName  string
	ProviderName string // resolved from the provider directory, if a provider was found
	ProviderID   string
	IsPrivate    bool   // from the APD policy's is_private flag, if one was found
	DataURL      string // from the APD policy's data_url field, if one was found
}

// InfraInput carries what's known about one selected infrastructure
// (Infrastructure Catalogue selection, SMPC only). InfraID is the
// caller-selected infra id; the rest are resolved from that infra's APD
// policy (rules.infrastructure), if FetchInfraPolicy found one. The 5
// confidential-computing flags are read straight off the policy's
// rules.infrastructure.capacity — InfraPolicyForm.jsx already computed and
// stored them (OR'd across that infra's own node pools/VM instance) at
// registration time, so no classification happens on this side.
type InfraInput struct {
	InfraID                  string
	InfraName                string
	InfraRegion              string
	InfraAttestationRequired bool
	InfraAttestationService  string
	InfraAttestationPolicyID string
	InfraCPUCores            int
	InfraRAMMB               int
	InfraSGXEnabled          bool
	InfraTDXEnabled          bool
	InfraSEVSNPEnabled       bool
	InfraSEVEnabled          bool
	InfraNitroEnclaveEnabled bool
}

// GenerateContractInput carries what's known when a user has picked one or
// more datasets and a technique (and, for SMPC, exactly two infra
// selections).
type GenerateContractInput struct {
	Datasets      []DatasetInput
	ApplicationID string
	Technique     string
	ComputeChoice string // optional override; defaulted per technique when blank
	ConsumerID    string
	ConsumerName  string
	Form          map[string]interface{} // provider form data, if FetchDatasetForm found one

	// Infrastructure Catalogue (InfraCat) selection — SMPC only. Exactly two
	// elements once populated by the caller.
	Infras []InfraInput
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

	dataProviders := make([]contract.DataProviderParty, 0, len(in.Datasets))
	for _, d := range in.Datasets {
		dataProviderName := d.ProviderName
		if dataProviderName == "" {
			dataProviderName = "Unknown Data Provider"
		}
		accessibilityLevel := "PUBLIC"
		if d.IsPrivate {
			accessibilityLevel = "PRIVATE"
		}
		dataProviders = append(dataProviders, contract.DataProviderParty{
			ID:             d.ProviderID,
			Name:           dataProviderName,
			DatasetName:    d.DatasetName,
			DatasetVersion: "v1",
			DataURL:        d.DataURL,
			Constraints:    contract.Constraints{AccessibilityLevel: accessibilityLevel, RestrictedTo: []string{}},
		})
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

	// Real infra selections (SMPC, via InfraCat) yield real parties built
	// from each infra's APD policy. TEE never sends infra selections today,
	// and any SMPC caller that predates InfraCat won't either — both fall
	// back to the original single placeholder so nothing else breaks.
	infraProviders := []contract.InfraProviderParty{}
	if in.Technique == "TEE" || in.Technique == "SMPC" {
		for _, inf := range in.Infras {
			infraName := inf.InfraName
			if infraName == "" {
				infraName = "Unknown Infrastructure"
			}
			infraProviders = append(infraProviders, contract.InfraProviderParty{
				ID:     inf.InfraID,
				Name:   infraName,
				Region: inf.InfraRegion,
				Attestation: contract.Attestation{
					Required: inf.InfraAttestationRequired,
					Service:  inf.InfraAttestationService,
					PolicyID: inf.InfraAttestationPolicyID,
				},
				ResourceAllocation: contract.ResourceAllocation{
					CPUCores:            inf.InfraCPUCores,
					RAMMB:               inf.InfraRAMMB,
					SGXEnabled:          inf.InfraSGXEnabled,
					TDXEnabled:          inf.InfraTDXEnabled,
					SEVSNPEnabled:       inf.InfraSEVSNPEnabled,
					SEVEnabled:          inf.InfraSEVEnabled,
					NitroEnclaveEnabled: inf.InfraNitroEnclaveEnabled,
				},
				Constraints: contract.Constraints{AccessibilityLevel: "PUBLIC", RestrictedTo: []string{}},
			})
		}
		if len(infraProviders) == 0 {
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
		Technique:     in.Technique,
		ComputeChoice: computeChoice,
		Parties: contract.Parties{
			User: contract.UserParty{
				ID:   in.ConsumerID,
				Name: in.ConsumerName,
			},
			DataProviders:        dataProviders,
			DataProviderCount:    len(dataProviders),
			ApplicationProviders: applicationProviders,
			InfraProviders:       infraProviders,
			InfraProviderCount:   len(infraProviders),
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
