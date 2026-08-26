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
type Signature struct {
	SignedAt *time.Time `json:"signed_at"`
}

// Constraints bounds who/what may access a party's contribution.
type Constraints struct {
	AccessibilityLevel string   `json:"accessibility_level"`
	RestrictedTo       []string `json:"restricted_to"`
}

// UserParty is the contract's requesting party (the FL output owner, or the
// consumer requesting a TEE/SMPC workload).
type UserParty struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DatablobURL string    `json:"datablob_url"`
	Signature   Signature `json:"signature"`
}

// DataProviderParty is one dataset contributor.
type DataProviderParty struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	DatasetName    string      `json:"dataset_name"`
	DatasetVersion string      `json:"dataset_version"`
	DataURL        string      `json:"data_url"`
	Constraints    Constraints `json:"constraints"`
	Signature      Signature   `json:"signature"`
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
type Attestation struct {
	Required bool   `json:"required"`
	Service  string `json:"service"`
	PolicyID string `json:"policy_id"`
}

// ResourceAllocation is the compute footprint reserved for the workload.
type ResourceAllocation struct {
	CPUCores int    `json:"cpu_cores"`
	RAMMB    int    `json:"ram_mb"`
	GPU      string `json:"gpu"`
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
// produces the same shape.
type Parties struct {
	User                 UserParty                  `json:"user"`
	DataProviders        []DataProviderParty        `json:"data_providers"`
	ApplicationProviders []ApplicationProviderParty `json:"application_providers"`
	InfraProviders       []InfraProviderParty       `json:"infra_providers"`
}

// Lifecycle is the contract's validity window.
type Lifecycle struct {
	CreatedAt  time.Time `json:"created_at"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
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
	ProjectID         string      `json:"project_id"`
	ContractID        string      `json:"contract_id"`
	Version           int         `json:"version"`
	Lifecycle         Lifecycle   `json:"lifecycle"`
	Technique         string      `json:"technique"`
	ComputeChoice     string      `json:"compute_choice"`
	ExecutionPlatform string      `json:"execution_platform"`
	Parties           Parties     `json:"parties"`
	SessionInfo       SessionInfo `json:"session_info"`
	ContractHash      string      `json:"contract_hash,omitempty"`
}

// ComputeHash returns "sha256:<hex>" over the contract's canonical JSON with
// ContractHash itself, and every party's Signature block, blanked out first.
// Blanking the signatures means the hash is computed once, before any party
// signs, and stays stable as signatures accrue afterwards (BuildContract's
// owner self-sign, then each provider's SignDataProviderParty on accept).
func ComputeHash(c Contract) (string, error) {
	c.ContractHash = ""
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
