// Package contractgen builds every contract gov_layer issues: the consumer's
// generate-contract request (FL/TEE/SMPC, BuildGeneratedContract) and an FL
// session's roster contract (BuildFLRosterContract). What a contract carries
// depends on its service (services below): only what that service's UI
// selects (p3dx-auth-ui WorkloadForm.jsx) and what its run reads.
//
//	TEE (Anonymization): datasets + one workload. The contract carries the
//	  workload (image, resources, DATASET_URL/RESULT_URL env), the trustee
//	  (KBS key) of each dataset and of the job, the callback URL and the
//	  consumer's result URL — exactly what CreateJob sends the Kata
//	  coordinator (contract.NewSubContract). No infra or application parties.
//	SMPC: datasets + exactly two infrastructures. The contract carries one
//	  infra party per selection (from its APD policy). No workload.
//	FL: datasets (generate-contract), or the session's provider roster
//	  (BuildFLRosterContract). Data providers only.
package contractgen

import (
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/workload"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// service is what one service's contracts carry beyond the user and data
// providers every contract has.
type service struct {
	computeChoice string // default compute_choice
	workload      bool   // the selected workload and what running it needs (TEE)
	infra         bool   // the selected infrastructures (SMPC)
}

var services = map[string]service{
	"FL":   {computeChoice: "FEDERATED_LEARNING"},
	"TEE":  {computeChoice: "ANONYMIZATION", workload: true},
	"SMPC": {computeChoice: "SECURE_MULTIPARTY_COMPUTATION", infra: true},
}

// defaultValidity is how long a contract is valid when the caller sets no
// validity.
const defaultValidity = 90 * 24 * time.Hour

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
// more datasets and a technique, plus that service's own selection: a
// workload (TEE) or exactly two infrastructures (SMPC).
type GenerateContractInput struct {
	Datasets      []DatasetInput
	ApplicationID string // TEE: the selected workload (workload.KnownWorkloads id)
	Technique     string
	ComputeChoice string // optional override; defaulted per technique when blank
	Purpose       string // consumer's stated purpose of processing (DPDP Rule 3)
	ConsumerID    string
	ConsumerName  string
	Form          map[string]interface{} // provider form data, if apd.FetchDatasetForm found one
	KBSURL        string                 // KBS_URL; TEE: each dataset's trustee block, when set
	ResultURL     string                 // DEFAULT_RESULT_URL; TEE: the consumer's datablob_url
	CallbackURL   string                 // CONTRACT_CALLBACK_URL; TEE: "/<contract_id>" is appended

	// Infrastructure Catalogue (InfraCat) selection — SMPC only. Exactly two
	// elements once populated by the caller.
	Infras []InfraInput
}

// BuildGeneratedContract assembles an unsigned contract for display, in the
// canonical contract.Contract shape, carrying what in.Technique's service
// uses (services). It does not touch the database and does not call APD
// itself — callers fetch policy/forms first (see apd.FetchPolicyForDataset /
// apd.FetchDatasetForm) and pass whatever they found in via Form.
func BuildGeneratedContract(in GenerateContractInput) contract.Contract {
	svc := services[in.Technique]
	c := newContract(in.Technique, 1, defaultValidity)
	if in.ComputeChoice != "" {
		c.ComputeChoice = in.ComputeChoice
	}
	c.Purpose = in.Purpose
	c.Parties.User = contract.UserParty{ID: in.ConsumerID, Name: in.ConsumerName}
	c.SessionInfo = contract.SessionInfo{RequestedBy: in.ConsumerID}

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
		dp := contract.DataProviderParty{
			ID:             d.ProviderID,
			Name:           dataProviderName,
			DatasetID:      d.DatasetID,
			DatasetName:    d.DatasetName,
			DatasetVersion: "v1",
			DataURL:        d.DataURL,
			Constraints:    contract.Constraints{AccessibilityLevel: accessibilityLevel, RestrictedTo: []string{}},
		}
		if svc.workload {
			dp.Trustee = trusteeFor(in.KBSURL, d)
		}
		dataProviders = append(dataProviders, dp)
	}
	_ = in.Form // data_size_bytes etc. aren't part of this schema; kept for future use
	c.Parties.DataProviders = dataProviders
	c.Parties.DataProviderCount = len(dataProviders)

	if svc.workload {
		addWorkload(&c, in)
	}
	if svc.infra {
		c.Parties.InfraProviders = infraParties(in.Infras)
		c.Parties.InfraProviderCount = len(c.Parties.InfraProviders)
	}

	setHash(&c)
	return c
}

// addWorkload adds the selected workload (TEE) and everything the Kata
// coordinator's CreateJob needs to run it: workload.env (DATASET_URL from the
// first dataset, RESULT_URL), the job trustee (the first dataset's), and
// callbackUrl. The consumer's result URL is their datablob_url. A workload
// that isn't in the catalogue adds nothing, so the run reports it missing.
func addWorkload(c *contract.Contract, in GenerateContractInput) {
	c.Parties.User.DatablobURL = in.ResultURL
	w, ok := workload.KnownWorkloads[in.ApplicationID]
	if !ok {
		return
	}
	c.Workload = &contract.Workload{ID: in.ApplicationID, Image: w.Image, Resources: w.Resources}

	env := map[string]string{}
	dataProviders := c.Parties.DataProviders
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

// infraParties builds one infra party per selected infrastructure (SMPC),
// from each infra's APD policy. Never nil, so an SMPC contract always names
// its (possibly empty) infra list.
func infraParties(infras []InfraInput) []contract.InfraProviderParty {
	parties := make([]contract.InfraProviderParty, 0, len(infras))
	for _, inf := range infras {
		infraName := inf.InfraName
		if infraName == "" {
			infraName = "Unknown Infrastructure"
		}
		parties = append(parties, contract.InfraProviderParty{
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
	return parties
}

// FLParty is one provider on an FL session's roster: the Keycloak id and
// username, plus that provider's dataset from their APD provider-form
// (dataset_name / dataset_location_url), blank when they have no form.
type FLParty struct {
	ID          string
	Username    string
	DatasetName string
	DataURL     string
}

// FLRosterInput is an FL session's roster.
type FLRosterInput struct {
	SessionID string
	OwnerID   string // the output owner; the session id when blank
	Parties   []FLParty
	// PriorSignatures is username -> signed_at from the session's current
	// contract (postgres.DataProviderSignatures): a provider who accepted the
	// participation request stays signed when the roster is rebuilt.
	PriorSignatures map[string]*time.Time
	Finalize        bool          // the final roster contract (version 2) vs. the draft (version 1)
	Validity        time.Duration // FL_CONTRACT_VALIDITY; defaultValidity when <= 0
}

// BuildFLRosterContract assembles the FL contract for a session's roster.
// Every call mints a brand-new project_id and contract_id - a contract is
// never reused across calls, so the draft (Finalize false) and final-roster
// (Finalize true) contracts for one session are always two distinct
// projects, and a "Start Again" restart is just another such call. The
// output owner signs on creation.
func BuildFLRosterContract(in FLRosterInput) contract.Contract {
	c := newContract("FL", 1, in.Validity)
	c.ProjectID = postgres.NewProjectID()
	if in.Finalize {
		c.Version = 2
	}

	ownerID := in.OwnerID
	if ownerID == "" {
		ownerID = in.SessionID
	}
	now := c.Lifecycle.CreatedAt
	c.Parties.User = contract.UserParty{
		ID:        ownerID,
		Name:      ownerID,
		Signature: contract.Signature{SignedAt: &now},
	}
	c.SessionInfo = contract.SessionInfo{ID: in.SessionID, SessionID: in.SessionID}

	dataProviders := make([]contract.DataProviderParty, 0, len(in.Parties))
	for _, p := range in.Parties {
		dp := contract.DataProviderParty{
			ID:          p.ID,
			Name:        p.Username,
			DatasetName: p.DatasetName,
			DataURL:     p.DataURL,
			Constraints: contract.Constraints{RestrictedTo: []string{}},
		}
		if signedAt, ok := in.PriorSignatures[p.Username]; ok {
			dp.Signature.SignedAt = signedAt
		}
		dataProviders = append(dataProviders, dp)
	}
	c.Parties.DataProviders = dataProviders
	c.Parties.DataProviderCount = len(dataProviders)

	setHash(&c)
	return c
}

// newContract starts a contract for technique: fresh contract and job ids,
// version, a validity window from now, and the service's compute_choice.
func newContract(technique string, version int, validity time.Duration) contract.Contract {
	if validity <= 0 {
		validity = defaultValidity
	}
	now := time.Now().UTC()
	return contract.Contract{
		ContractID: postgres.NewUUID(),
		JobID:      postgres.NewJobID(),
		Version:    version,
		Lifecycle: contract.Lifecycle{
			CreatedAt:  now,
			ValidFrom:  now,
			ValidUntil: now.Add(validity),
		},
		Technique:     technique,
		ComputeChoice: services[technique].computeChoice,
	}
}

// setHash sets c's contract_hash once c is complete. ComputeHash only fails
// to marshal, which a contract built here can't; c is then left unhashed.
func setHash(c *contract.Contract) {
	if hash, err := contract.ComputeHash(*c); err == nil {
		c.ContractHash = hash
	}
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
