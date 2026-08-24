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

// Signature carries per-party consent state. It is a bookkeeping timestamp
// only — no signature bytes or cryptographic verification are attached to it
// (that remains a separate, still-undesigned concern; see the top-level
// signature verification already performed in httpapi.handleContract).
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
// ContractHash itself blanked out first (a field can't hash itself).
//
// This is a placeholder recipe: it does not yet zero out each party's
// Signature block, so the hash will change as parties sign. Revisit once the
// per-party signing/verification model is designed — at that point the hash
// likely needs to be computed once, before any signing, over a fully
// signature-blanked contract so it stays stable across the sign lifecycle.
func ComputeHash(c Contract) (string, error) {
	c.ContractHash = ""
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
