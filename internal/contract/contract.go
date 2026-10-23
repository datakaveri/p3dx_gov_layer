// Package contract defines the single canonical contract JSON schema shared
// across the FL session/roster pathway and the FL/TEE/SMPC generate-contract
// preview pathway. It replaces the two contract shapes that used to live in
// db.Contract and services.GeneratedContract — those diverged over time even
// though they described the same concept, and consumers (p3dx-aaa,
// p3dx-auth-ui) had to special-case both. A third, unrelated shape,
// services.TEEContract, is intentionally not unified here: it is the APD-facing
// TEE provisioning contract, a separate integration with its own lifecycle.
package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Signature carries per-party consent state: nil until the party signs, then
// the time they did. It is a bookkeeping timestamp only — no signature bytes
// or cryptographic verification are attached to it (that remains a separate
// concern; see the top-level signature verification already performed in
// httpapi.handleContract). For the FL pathway, the drafting/output-owner
// party is signed as soon as they submit a contract version (db.BuildContract),
// and each data-provider party is signed when they accept the participation
// notification (db.SignDataProviderParty, called from
// httpapi.respondToNotification).
//
// For every technique (FL final roster, TEE, SMPC), each data-provider party
// additionally signs the contract's ContractHash with their own RSA private
// key (httpapi.handleSignContract), and the verified signature bytes are
// recorded in Value alongside the hash that was signed. Only a verified Value
// counts toward the run gate — SignedAt alone (FL's accept-invite marker) does
// not. The whole block is blanked by ComputeHash, so recording a signature
// never changes the hash being signed.
type Signature struct {
	SignedAt   *time.Time `json:"signed_at"`
	Signer     string     `json:"signer,omitempty"`      // Keycloak username whose public key verifies Value
	Algorithm  string     `json:"algorithm,omitempty"`   // e.g. "RSASSA-PKCS1-v1_5-SHA256"
	SignedHash string     `json:"signed_hash,omitempty"` // the ContractHash string that was signed
	Value      string     `json:"value,omitempty"`       // base64 signature bytes
	// WithdrawnAt is set when the signer withdraws consent
	// (POST /contracts/{id}/withdraw-consent, DPDP Act s.6(4)). Value is
	// cleared at the same time, so the run gate treats the party as unsigned.
	WithdrawnAt *time.Time `json:"withdrawn_at,omitempty"`
}

// Constraints bounds who/what may access a party's contribution.
type Constraints struct {
	AccessibilityLevel string   `json:"accessibility_level"`
	RestrictedTo       []string `json:"restricted_to"`
	// ConsentValidUntil is when a data provider's consent ends, set by that
	// provider before signing (POST /contracts/{id}/consent-expiry). No run
	// starts after it. omitempty keeps older contracts' hashes stable.
	ConsentValidUntil *time.Time `json:"consent_valid_until,omitempty"`
}

// UserParty is the contract's requesting party (the FL output owner, or the
// consumer requesting a TEE/SMPC workload).
type UserParty struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DatablobURL string    `json:"datablob_url"`
	Signature   Signature `json:"signature"`
}

// DataProviderParty is one dataset contributor. DatasetID is the dataset's
// DX catalogue item id (job approval looks it up there); omitempty keeps the
// hash of contracts generated before it was recorded unchanged.
type DataProviderParty struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	DatasetID      string      `json:"dataset_id,omitempty"`
	DatasetName    string      `json:"dataset_name"`
	DatasetVersion string      `json:"dataset_version"`
	DataURL        string      `json:"data_url"`
	Constraints    Constraints `json:"constraints"`
	// Trustee is where the workload fetches this dataset's decryption key.
	// Nil (and omitted, keeping older contracts' hashes unchanged) when no
	// KBS is configured.
	Trustee   *Trustee  `json:"trustee,omitempty"`
	Signature Signature `json:"signature"`
}

// Trustee locates a dataset's decryption key in the Key Broker Service.
type Trustee struct {
	KBSURL          string `json:"kbs_url"`
	KeyResourcePath string `json:"key_resource_path"`
}

// NewTrustee returns the trustee block for one dataset, keyed by
// default/<datasetName>-key/<datasetID> (datasetName when there is no
// id), or nil when kbsURL is empty.
func NewTrustee(kbsURL, datasetName, datasetID string) *Trustee {
	if kbsURL == "" {
		return nil
	}
	resource := datasetID
	if resource == "" {
		resource = datasetName
	}
	return &Trustee{
		KBSURL:          kbsURL,
		KeyResourcePath: "default/" + datasetName + "-key/" + resource,
	}
}

// ApplicationProviderParty is one workload/application contributor.
type ApplicationProviderParty struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	AppName         string      `json:"app_name"`
	ContainerImage  string      `json:"container_image"`
	ContainerDigest string      `json:"container_digest"`
	Constraints     Constraints `json:"constraints"`
	Signature       Signature   `json:"signature"`
}

// Attestation describes the remote-attestation requirement for an infra
// provider's compute environment.
// Workload is what the TEE runs for the selected workload (see
// services.KnownWorkloads): its image and CPU/memory request, as Kubernetes
// quantities (e.g. "250m"/"512Mi").
type Workload struct {
	Image     string            `json:"image"`
	Resources WorkloadResources `json:"resources"`
	// Env is passed to the workload container: DATASET_URL (the first
	// dataset's data_url) and RESULT_URL (the consumer's datablob_url).
	Env map[string]string `json:"env,omitempty"`
}

// JobTrustee is the contract-level trustee the TEE job uses — the first
// dataset's trustee, in the coordinator's camelCase CreateJob shape.
type JobTrustee struct {
	KBSURL          string `json:"kbsUrl"`
	KeyResourcePath string `json:"keyResourcePath"`
}

type WorkloadResources struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

type Attestation struct {
	Required bool   `json:"required"`
	Service  string `json:"service"`
	PolicyID string `json:"policy_id"`
}

// ResourceAllocation is the compute footprint reserved for the workload.
// The 5 confidential-computing flags are computed once at infra-provider
// registration time (InfraPolicyForm.jsx, OR'd across that infra's own node
// pools/VM instance) and stored flat on the policy — this struct's
// population (contractgen.go) just copies them through, no classification
// logic on the Go side.
type ResourceAllocation struct {
	CPUCores            int    `json:"cpu_cores"`
	RAMMB               int    `json:"ram_mb"`
	GPU                 string `json:"gpu"`
	SGXEnabled          bool   `json:"sgx_enabled"`
	TDXEnabled          bool   `json:"tdx_enabled"`
	SEVSNPEnabled       bool   `json:"sev_snp_enabled"`
	SEVEnabled          bool   `json:"sev_enabled"`
	NitroEnclaveEnabled bool   `json:"nitro_enclave_enabled"`
}

// InfraProviderParty is one compute/hosting contributor (e.g. a confidential
// compute region).
type InfraProviderParty struct {
	ID                 string             `json:"id"`
	Name               string             `json:"name"`
	Region             string             `json:"region"`
	Attestation        Attestation        `json:"attestation"`
	ResourceAllocation ResourceAllocation `json:"resource_allocation"`
	Constraints        Constraints        `json:"constraints"`
	Signature          Signature          `json:"signature"`
}

// Parties groups every party to the contract. DataProviders,
// ApplicationProviders, and InfraProviders are always present as arrays
// (possibly empty) rather than omitted, so every pathway (FL, TEE, SMPC)
// produces the same shape. DataProviderCount/InfraProviderCount are plain
// sibling counts (always len(DataProviders)/len(InfraProviders)) rather than
// restructuring either array into an index-keyed object.
type Parties struct {
	User                 UserParty                  `json:"user"`
	DataProviders        []DataProviderParty        `json:"data_providers"`
	DataProviderCount    int                        `json:"data_provider_count"`
	ApplicationProviders []ApplicationProviderParty `json:"application_providers"`
	InfraProviders       []InfraProviderParty       `json:"infra_providers"`
	InfraProviderCount   int                        `json:"infra_provider_count"`
}

// Lifecycle is the contract's validity window.
type Lifecycle struct {
	CreatedAt  time.Time `json:"created_at"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
	// RequestedValidUntil is the end the consumer's contract was generated
	// with, kept once a data provider's consent expiry shortens ValidUntil,
	// so a later expiry change is still bounded by (and can return to) it.
	// omitempty keeps older contracts' hashes stable.
	RequestedValidUntil *time.Time `json:"requested_valid_until,omitempty"`
}

// SessionInfo identifies the request/session the contract was assembled for.
type SessionInfo struct {
	ID          string `json:"id"`
	SessionID   string `json:"session_id"`
	RequestedBy string `json:"requested_by"`
}

// Contract is the canonical agreement shape emitted by both the FL
// session/roster builder and the FL/TEE/SMPC generate-contract preview
// builder.
type Contract struct {
	ProjectID  string `json:"project_id"`
	ContractID string `json:"contract_id"`
	// JobID is unique per contract. omitempty keeps the hash of contracts
	// created before job_id existed unchanged.
	JobID         string    `json:"job_id,omitempty"`
	Version       int       `json:"version"`
	Lifecycle     Lifecycle `json:"lifecycle"`
	Technique     string    `json:"technique"`
	ComputeChoice string    `json:"compute_choice"`
	// Purpose is the consumer's stated purpose for processing, shown to data
	// providers in the DPDP Rule 3 consent notice. It is covered by the
	// contract hash, so a provider's signature binds them to this purpose
	// only. omitempty keeps older contracts' hashes stable.
	Purpose string `json:"purpose,omitempty"`
	// Workload is set when a known workload (e.g. MNIST) was selected.
	// omitempty keeps older contracts' hashes stable.
	Workload *Workload `json:"workload,omitempty"`
	// Trustee and CallbackURL complete the coordinator's CreateJob shape
	// (contractId/workload/trustee/callbackUrl). Set only alongside Workload.
	Trustee      *JobTrustee `json:"trustee,omitempty"`
	CallbackURL  string      `json:"callbackUrl,omitempty"`
	Parties      Parties     `json:"parties"`
	SessionInfo  SessionInfo `json:"session_info"`
	ContractHash string      `json:"contract_hash,omitempty"`
	// GovernanceSignature is gov_layer's own signature over ContractHash
	// (services.GovernanceKey), sent to data providers so they can verify the
	// hash came from gov_layer before signing it. Blanked by ComputeHash like
	// the party signatures.
	GovernanceSignature *Signature `json:"governance_signature,omitempty"`
	// Amendment is gov_layer's signature over the content hash of a contract
	// its consumer edited after it was signed (PUT /contracts/{id}). Its
	// SignedHash is the edited content's hash; ContractHash stays the hash the
	// providers signed, so their signatures keep verifying and the edit needs
	// no re-signing. Blanked by ComputeHash; omitempty keeps older contracts'
	// JSON unchanged.
	Amendment *Signature `json:"amendment,omitempty"`
}

// ComputeHash returns "sha256:<hex>" over the contract's canonical JSON with
// ContractHash itself, and every party's Signature block, blanked out first.
// Blanking the signatures means the hash is computed once, before any party
// signs, and stays stable as signatures accrue afterwards (BuildContract's
// owner self-sign, then each provider's SignDataProviderParty on accept).
func ComputeHash(c Contract) (string, error) {
	c.ContractHash = ""
	c.GovernanceSignature = nil
	c.Amendment = nil
	c = withoutSignatures(c)
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// withoutSignatures returns a copy of c with every party's Signature zeroed.
// c is taken by value, but its slice fields still alias the caller's
// underlying arrays, so each slice is re-allocated before its elements are
// mutated — otherwise blanking signatures here would blank them for the
// caller too.
func withoutSignatures(c Contract) Contract {
	c.Parties.User.Signature = Signature{}

	dataProviders := make([]DataProviderParty, len(c.Parties.DataProviders))
	copy(dataProviders, c.Parties.DataProviders)
	for i := range dataProviders {
		dataProviders[i].Signature = Signature{}
	}
	c.Parties.DataProviders = dataProviders

	appProviders := make([]ApplicationProviderParty, len(c.Parties.ApplicationProviders))
	copy(appProviders, c.Parties.ApplicationProviders)
	for i := range appProviders {
		appProviders[i].Signature = Signature{}
	}
	c.Parties.ApplicationProviders = appProviders

	infraProviders := make([]InfraProviderParty, len(c.Parties.InfraProviders))
	copy(infraProviders, c.Parties.InfraProviders)
	for i := range infraProviders {
		infraProviders[i].Signature = Signature{}
	}
	c.Parties.InfraProviders = infraProviders

	return c
}

// SubContract is the slice of a contract the Kata coordinator runs — the
// body of CoordinatorService/CreateJob ({"contract": {...}}), in its
// camelCase JSON shape.
type SubContract struct {
	Contract SubContractBody `json:"contract"`
}

type SubContractBody struct {
	ContractID  string      `json:"contractId"`
	Workload    *Workload   `json:"workload"`
	Trustee     *JobTrustee `json:"trustee"`
	CallbackURL string      `json:"callbackUrl,omitempty"`
}

// NewSubContract builds the CreateJob sub-contract from c. missing names
// every required field c lacks; when it is non-empty the job must not be
// sent.
func NewSubContract(c *Contract) (sub SubContract, missing []string) {
	if c.ContractID == "" {
		missing = append(missing, "contract_id")
	}
	if c.Workload == nil || c.Workload.Image == "" {
		missing = append(missing, "workload.image")
	}
	if c.Workload == nil || c.Workload.Env["DATASET_URL"] == "" {
		missing = append(missing, "workload.env.DATASET_URL")
	}
	if c.Trustee == nil || c.Trustee.KBSURL == "" || c.Trustee.KeyResourcePath == "" {
		missing = append(missing, "trustee")
	}
	sub.Contract = SubContractBody{
		ContractID:  c.ContractID,
		Workload:    c.Workload,
		Trustee:     c.Trustee,
		CallbackURL: c.CallbackURL,
	}
	return sub, missing
}
