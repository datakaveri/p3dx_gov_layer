package contractgen

import (
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/workload"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
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
	// KeyResourcePath is the APD policy's rules.key_resource_path (PolicyForm's
	// "Key Resource Path" field), if the provider set one. Blank falls back to
	// the path NewTrustee derives from the dataset name/id.
	KeyResourcePath string
}

// InfraInput carries what's known about one selected infrastructure
// (Infrastructure Catalogue selection, SMPC only). InfraID is the
// caller-selected infra id; the rest are resolved from that infra's APD
// policy (rules.infrastructure), if apd.FetchInfraPolicy found one. The 5
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
	Purpose       string // consumer's stated purpose of processing (DPDP Rule 3)
	ConsumerID    string
	ConsumerName  string
	Form          map[string]interface{} // provider form data, if apd.FetchDatasetForm found one
	KBSURL        string                 // KBS_URL; each dataset's trustee block, when set
	ResultURL     string                 // DEFAULT_RESULT_URL; the consumer's datablob_url
	CallbackURL   string                 // CONTRACT_CALLBACK_URL; "/<contract_id>" is appended

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
// apd.FetchPolicyForDataset / apd.FetchDatasetForm) and pass whatever they found in
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
			DatasetID:      d.DatasetID,
			DatasetName:    d.DatasetName,
			DatasetVersion: "v1",
			DataURL:        d.DataURL,
			Constraints:    contract.Constraints{AccessibilityLevel: accessibilityLevel, RestrictedTo: []string{}},
			Trustee:        trusteeFor(in.KBSURL, d),
		})
	}
	_ = in.Form // data_size_bytes etc. aren't part of this schema; kept for future use

	applicationProviders := []contract.ApplicationProviderParty{}
	var wl *contract.Workload
	appID := in.ApplicationID
	if appID != "" {
		app := contract.ApplicationProviderParty{
			ID:          appID,
			Name:        "Unknown Application Provider",
			AppName:     appID,
			Constraints: contract.Constraints{AccessibilityLevel: "PUBLIC", RestrictedTo: []string{}},
		}
		if w, ok := workload.KnownWorkloads[appID]; ok {
			app.ContainerImage = w.Image
			wl = &contract.Workload{Image: w.Image, Resources: w.Resources}
		}
		applicationProviders = append(applicationProviders, app)
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
		ContractID: postgres.NewUUID(),
		JobID:      postgres.NewJobID(),
		Version:    1,
		Lifecycle: contract.Lifecycle{
			CreatedAt:  now,
			ValidFrom:  now,
			ValidUntil: now.Add(90 * 24 * time.Hour),
		},
		Technique:     in.Technique,
		ComputeChoice: computeChoice,
		Purpose:       in.Purpose,
		Workload:      wl,
		Parties: contract.Parties{
			User: contract.UserParty{
				ID:          in.ConsumerID,
				Name:        in.ConsumerName,
				DatablobURL: in.ResultURL,
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

	// Known workload (TEE): complete the coordinator's CreateJob shape —
	// workload.env, a contract-level trustee, and callbackUrl.
	if c.Workload != nil {
		env := map[string]string{}
		if len(dataProviders) > 0 && dataProviders[0].DataURL != "" {
			env["DATASET_URL"] = dataProviders[0].DataURL
		}
		if in.ResultURL != "" {
			env["RESULT_URL"] = in.ResultURL
		}
		if len(env) > 0 {
			c.Workload.Env = env
		}
		if len(dataProviders) > 0 && dataProviders[0].Trustee != nil {
			t := dataProviders[0].Trustee
			c.Trustee = &contract.JobTrustee{KBSURL: t.KBSURL, KeyResourcePath: t.KeyResourcePath}
		}
		if in.CallbackURL != "" {
			c.CallbackURL = in.CallbackURL + "/" + c.ContractID
		}
	}

	if hash, err := contract.ComputeHash(c); err == nil {
		c.ContractHash = hash
	}

	return c
}

// trusteeFor builds one dataset's trustee block: the KBS URL is always the
// gov_layer-wide KBS_URL, while the key resource path is the provider's own
// (from its APD policy) when set, else NewTrustee's derived default.
func trusteeFor(kbsURL string, d DatasetInput) *contract.Trustee {
	t := contract.NewTrustee(kbsURL, d.DatasetName, d.DatasetID)
	if t != nil && d.KeyResourcePath != "" {
		t.KeyResourcePath = d.KeyResourcePath
	}
	return t
}
