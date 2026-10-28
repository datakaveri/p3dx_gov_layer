// Package jobapproval holds the job-approval rules and the use cases that
// apply them. Once a contract naming both datasets and infrastructure is
// generated, every provider on it is checked before anyone is asked to sign.
//
// Data providers are checked with their own dev Keycloak token, so each data
// provider on a contract makes the call for their own datasets:
//
//   - the token carries the data-provider realm role (DATA_PROVIDER_ROLE,
//     "provider" in dev), and
//   - each of their datasets exists in the DX catalogue as an adex:DataBank,
//     looked up with that same token.
//
// Infra providers are checked the same way, with their own dev Keycloak
// token — each infra provider on a contract makes the call for their own
// infras:
//
//   - the token carries the infra-provider realm role, and
//   - each of their infras is in their own APD catalogue ("My
//     Infrastructure"); an infra's owner is read off its APD policy.
//
// Each check's outcome is appended to the audit table against the contract's
// job_id. The checks run only when called (re-callable, e.g. after an admin
// granted a missing role).
//
// Approving is also signing: each provider signs the contract hash they were
// sent with the job request with their own private key — generated and kept
// on their machine; only the public key is registered — and sends it with
// the approval call. The signature is stored as submitted; Service.JobStatus
// cross-verifies every provider's hash and signature, and only if all verify
// does it make the contract final and post the APD consumer grants.
//
// This file is the pure rules (no I/O); service.go is the use cases, which
// reach the database, catalogues and APD only through the interfaces it
// declares.
package jobapproval

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/catalogue"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// StatusPending is a side's (or the job's) approval before anyone on it has
// made the call.
const StatusPending = "pending"

// InfraProviderRole is the (DX) realm role an infra's provider must hold.
const InfraProviderRole = "infra_provider"

// NeedsJobApproval reports whether c names at least one dataset and at least
// one real (selected, so id-bearing) infrastructure — the TEE placeholder
// infra has no id and doesn't count.
func NeedsJobApproval(c *contract.Contract) bool {
	if len(c.Parties.DataProviders) == 0 {
		return false
	}
	for _, ip := range c.Parties.InfraProviders {
		if ip.ID != "" {
			return true
		}
	}
	return false
}

// Required reports whether c goes through job approval: it names datasets
// and real infra (NeedsJobApproval). A TEE/SMPC contract with no selected
// infra is sent straight to its data providers to sign (the UI has no
// job-approval screen), whatever REQUIRE_INFRA_APPROVAL is; FL contracts
// never go through it — they're signed on their roster.
func Required(c *contract.Contract) bool {
	// Previously, with REQUIRE_INFRA_APPROVAL off, a TEE/SMPC contract naming
	// datasets but no selected infra went through approval too:
	// return len(c.Parties.DataProviders) > 0 && (c.Technique == "TEE" || c.Technique == "SMPC")
	return NeedsJobApproval(c)
}

// Caller is the data or infra provider making an approval call, read from
// their validated dev Keycloak token.
type Caller struct {
	Token    string          // raw bearer token, forwarded to the DX catalogue
	Username string          // preferred_username, else email: whose registered public key verifies their signature
	UserID   string          // sub: their Keycloak user id
	Names    map[string]bool // provider_ids / usernames / emails / sub that name them on a contract
	Roles    []string        // realm roles
}

// Owns reports whether providerID (an APD policy's provider_id) names the
// caller.
func (c Caller) Owns(providerID string) bool {
	return providerID != "" && (c.Names[providerID] || c.Names[strings.ToLower(providerID)])
}

// Is reports whether dp is one of the caller's datasets.
func (c Caller) Is(dp contract.DataProviderParty) bool {
	return dp.ID != "" && (c.Names[contract.PartyProviderID(dp)] || c.Names[strings.ToLower(dp.ID)])
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// CatalogueItemID is dp's DX catalogue item id. Contracts generated before
// dataset_id was recorded fall back to the dataset name when it is one.
func CatalogueItemID(dp contract.DataProviderParty) string {
	if dp.DatasetID != "" {
		return dp.DatasetID
	}
	if uuidPattern.MatchString(dp.DatasetName) {
		return dp.DatasetName
	}
	return ""
}

// ApprovalItem is the audit "item" for dp: its catalogue id, else its name.
func ApprovalItem(dp contract.DataProviderParty) string {
	if id := CatalogueItemID(dp); id != "" {
		return id
	}
	return dp.DatasetName
}

// AuditKey identifies one provider's item among a job's audit entries.
func AuditKey(providerID, item string) string { return providerID + "\x00" + item }

func catalogueHas(items []catalogue.CatalogueItem, item string) bool {
	for _, it := range items {
		if it.ItemID == item || strings.EqualFold(it.Name, item) {
			return true
		}
	}
	return false
}

// InfraOwner is one selected infra on a contract and its owning provider,
// read off that infra's APD policy (the contract only records the infra id).
type InfraOwner struct {
	InfraID    string
	ProviderID string
	Reason     string // set when the owner couldn't be resolved
}

// OverallStatus is "accepted" only when there is at least one entry and every
// entry is accepted.
func OverallStatus(entries []postgres.AuditEntry) string {
	if len(entries) == 0 {
		return StatusPending
	}
	for _, e := range entries {
		if e.Status != postgres.AuditStatusAccepted {
			return postgres.AuditStatusRejected
		}
	}
	return postgres.AuditStatusAccepted
}

// State is a job's approval standing, derived from its audit history: the
// latest entry per (type, provider_id, item) is current.
type State struct {
	Approval      string                `json:"approval"`
	DataProvider  string                `json:"data_provider"`
	InfraProvider string                `json:"infra_provider"`
	Current       []postgres.AuditEntry `json:"current"`
	History       []postgres.AuditEntry `json:"history"`
	// InfraRequired is false while REQUIRE_INFRA_APPROVAL=false: the job is
	// then approved on its data-provider side alone.
	InfraRequired bool `json:"-"`
}

// Accepted reports whether both sides (or, with infra approval switched off,
// the data-provider side) have been checked and every current entry is
// accepted.
func (st State) Accepted() bool {
	return st.DataProvider == postgres.AuditStatusAccepted &&
		(!st.InfraRequired || st.InfraProvider == postgres.AuditStatusAccepted)
}

// BuildState derives a job's State from its audit history (oldest first).
func BuildState(history []postgres.AuditEntry, infraRequired bool) State {
	latest := map[string]postgres.AuditEntry{}
	order := []string{}
	for _, e := range history {
		key := e.Type + "\x00" + e.ProviderID + "\x00" + e.Item
		if _, seen := latest[key]; !seen {
			order = append(order, key)
		}
		latest[key] = e
	}
	current := make([]postgres.AuditEntry, 0, len(order))
	byType := map[string][]postgres.AuditEntry{}
	for _, k := range order {
		current = append(current, latest[k])
		byType[latest[k].Type] = append(byType[latest[k].Type], latest[k])
	}
	st := State{
		DataProvider:  OverallStatus(byType[postgres.AuditTypeDataProvider]),
		InfraProvider: OverallStatus(byType[postgres.AuditTypeInfraProvider]),
		Current:       current,
		History:       history,
		InfraRequired: infraRequired,
	}
	switch {
	case st.Accepted():
		st.Approval = postgres.AuditStatusAccepted
	case st.DataProvider == postgres.AuditStatusRejected || (st.InfraRequired && st.InfraProvider == postgres.AuditStatusRejected):
		st.Approval = postgres.AuditStatusRejected
	default:
		st.Approval = StatusPending
	}
	return st
}

// checkedKeys is the AuditKey of every current entry of kind in st.
func (st State) checkedKeys(kind string) map[string]bool {
	checked := map[string]bool{}
	for _, e := range st.Current {
		if e.Type == kind {
			checked[AuditKey(e.ProviderID, e.Item)] = true
		}
	}
	return checked
}

// Reasons lists why a job isn't approved yet: every provider/item whose
// current approval isn't accepted, with its reason.
func Reasons(st State) []string {
	reasons := []string{}
	for _, e := range st.Current {
		if e.Status != postgres.AuditStatusAccepted {
			reasons = append(reasons, fmt.Sprintf("%s %s / %s: %s", e.Type, e.ProviderID, e.Item, e.Reason))
		}
	}
	if st.DataProvider == StatusPending {
		reasons = append(reasons, "no data provider has approved yet")
	}
	if st.InfraRequired && st.InfraProvider == StatusPending {
		reasons = append(reasons, "no infra provider has approved yet")
	}
	return reasons
}

// ContractHash is the contract_hash stored with a job's contract at
// POST /generate-contract, cross-checked against a fresh hash of the stored
// contract so an edit made since is refused. Contracts stored before the hash
// was kept with them have none; their fresh hash stands in.
func ContractHash(c *contract.Contract) (string, error) {
	hash, err := contract.ComputeHash(*c)
	if err != nil {
		return "", fmt.Errorf("contract could not be hashed: %w", err)
	}
	if c.ContractHash != "" && c.ContractHash != hash {
		return "", fmt.Errorf("stored contract no longer matches its stored contract_hash %s (now %s)", c.ContractHash, hash)
	}
	return hash, nil
}

// PartySignature is one party's signing state, as reported by
// GET /contracts/{id}/signatures and checked by the run gates.
type PartySignature struct {
	Role        string     `json:"role"` // postgres.AuditTypeDataProvider / postgres.AuditTypeInfraProvider
	ProviderID  string     `json:"provider_id"`
	DatasetName string     `json:"dataset_name,omitempty"`
	InfraID     string     `json:"infra_id,omitempty"`
	Signed      bool       `json:"signed"`
	Valid       bool       `json:"valid"`
	Signer      string     `json:"signer,omitempty"`
	SignedAt    *time.Time `json:"signed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// PartyLabel names p in pending-signature messages: an unsigned infra has no
// signer (so no provider_id) yet.
func PartyLabel(p PartySignature) string {
	if p.InfraID != "" {
		return "infra " + p.InfraID
	}
	return p.ProviderID
}
