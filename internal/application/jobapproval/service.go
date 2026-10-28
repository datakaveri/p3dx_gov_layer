package jobapproval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/apd"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/catalogue"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/platform/govcrypto"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// Repo is the storage the job-approval use cases need — *postgres.DB in
// production; faked in tests.
type Repo interface {
	ListAuditByJob(ctx context.Context, jobID string) ([]postgres.AuditEntry, error)
	InsertAuditEntries(ctx context.Context, entries []postgres.AuditEntry) error
	GetContractByJobID(ctx context.Context, jobID string) (json.RawMessage, error)
	GetJobIDByContractID(ctx context.Context, contractID string) (string, error)
	UpdateContractByContractID(ctx context.Context, contractID string, raw json.RawMessage) (bool, error)
	MarkSignRequestsSent(ctx context.Context, jobID string) (bool, error)
	CreateFinalContract(ctx context.Context, jobID, contractID, contractHash string, contractJSON []byte) (bool, error)
	MarkJobFinal(ctx context.Context, jobID string) (bool, error)
	GetFinalContract(ctx context.Context, jobID string) (*postgres.FinalContract, error)
	SetJobParticipantStatus(ctx context.Context, jobID, role, participantID, itemID, status, userID, username string) (bool, error)
	SetJobStatus(ctx context.Context, jobID, status string) error
}

// Catalogue looks up datasets in the DX catalogue (with the caller's token)
// and a provider's infras in their APD catalogue.
type Catalogue interface {
	Item(ctx context.Context, itemID, token string) (catalogue.DXCatalogueItem, error)
	ProviderInfra(providerID string) ([]catalogue.CatalogueItem, error)
}

// APD reads infra policies and posts consumer grants.
type APD interface {
	InfraPolicy(infraID string) (map[string]any, error)
	PostConsumerGrant(ctx context.Context, g apd.ConsumerGrant) (string, error)
}

// PublicKeys resolves a username to their registered PEM public key.
type PublicKeys interface {
	PublicKey(ctx context.Context, username string) (string, error)
}

// Signatures checks the signatures recorded on a contract against
// gov_layer's key and the providers' registered keys.
type Signatures interface {
	// AmendmentValid reports whether c carries gov_layer's amendment
	// signature over hash (its edited content).
	AmendmentValid(c *contract.Contract, hash string) bool
	// ProviderSignatures checks every provider's signature on c over hash;
	// infraOwnerIDs maps infra id -> the provider_id that must have signed it.
	ProviderSignatures(ctx context.Context, c *contract.Contract, hash string, infraOwnerIDs map[string]string) ([]PartySignature, bool)
	// VerifyContract re-checks c's hash and every signature on it.
	VerifyContract(ctx context.Context, c *contract.Contract) (parties []PartySignature, hashOK, allValid bool)
	// GovernanceSignatureOK reports whether c's governance signature over
	// hash is in order (none is needed on a job-approval contract).
	GovernanceSignatureOK(c *contract.Contract, hash string) bool
}

// Service runs the job-approval use cases.
type Service struct {
	Repo       Repo
	Catalogue  Catalogue
	APD        APD
	Keys       PublicKeys
	Signatures Signatures
	// RequireInfraApproval is REQUIRE_INFRA_APPROVAL: when false a job is
	// approved on its data-provider approval alone.
	RequireInfraApproval bool
	// DataProviderRole is the realm role a dataset's provider must hold
	// (DATA_PROVIDER_ROLE).
	DataProviderRole string
}

// Errors the use cases refuse a call with; anything else is internal.
var (
	ErrJobIDRequired    = errors.New("job_id is required")
	ErrNoContract       = errors.New("No contract for this job_id")
	ErrNoApprovalNeeded = errors.New("contract does not go through job approval (it needs a dataset and an infrastructure, or REQUIRE_INFRA_APPROVAL=false for TEE/SMPC)")
	ErrNotDataProvider  = errors.New("the token's user provides none of this job's datasets")
	ErrNotInfraProvider = errors.New("the token's user owns none of this job's infras")
	ErrMissingSignature = errors.New("contract_hash and signature are required: sign the contract_hash from your job request with your private key")
	ErrNotConsumer      = errors.New("only the user who generated this job's contract can check its status")
)

// SignatureError is a submitted approval signature that doesn't verify.
type SignatureError struct{ Err error }

func (e *SignatureError) Error() string { return e.Err.Error() }
func (e *SignatureError) Unwrap() error { return e.Err }

// Input is an approval call: the job, and the caller's signature over the
// contract hash they were sent.
type Input struct {
	JobID        string
	ContractHash string
	Signature    string
}

// Result is the outcome of an approval call.
type Result struct {
	Kind         string // postgres.AuditTypeDataProvider / postgres.AuditTypeInfraProvider
	JobID        string
	Approval     string // the caller's own result; others' awaiting entries don't count
	State        State
	Entries      []postgres.AuditEntry
	ContractHash string
	Signed       int           // how many of the caller's items carry their submitted signature
	Grants       []GrantResult // data-provider approvals only
}

// GrantResult is one dataset's or infra's consumer grant.
type GrantResult struct {
	ItemType string `json:"item_type"` // "dataset" / "infra"
	ItemID   string `json:"item_id"`
	PolicyID string `json:"policy_id,omitempty"`
	Status   string `json:"status"` // "posted" / "failed"
	Error    string `json:"error,omitempty"`
}

// JobStatus is the governance layer's cross-verification of a job.
type JobStatus struct {
	Approved bool
	Reasons  []string
	// SignaturesChecked is set once the approvals passed and the signatures
	// were verified (Signatures then holds each party's result).
	SignaturesChecked bool
	Signatures        []PartySignature
	ContractHash      string
	Grants            []GrantResult
	Final             bool
	FinalRecord       *postgres.FinalContract
	Pending           []string
}

// State loads jobID's approval state from its audit history.
func (s *Service) State(ctx context.Context, jobID string) (State, error) {
	history, err := s.Repo.ListAuditByJob(ctx, jobID)
	if err != nil {
		return State{}, err
	}
	return BuildState(history, s.RequireInfraApproval), nil
}

// Contract loads and decodes the contract stored for jobID, refusing one that
// doesn't go through job approval.
func (s *Service) Contract(ctx context.Context, jobID string) (*contract.Contract, error) {
	if jobID == "" {
		return nil, ErrJobIDRequired
	}
	raw, err := s.Repo.GetContractByJobID(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, ErrNoContract
	}
	c := &contract.Contract{}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("stored contract is not valid: %w", err)
	}
	if !Required(c) {
		return nil, ErrNoApprovalNeeded
	}
	return c, nil
}

// SigningAllowed reports whether c's providers may be asked to sign / sign
// it: always for a contract that needs no approval, otherwise only once its
// job is accepted. Backfilled contracts carry job_id only in the DB column,
// so it's read from there when the JSON has none.
func (s *Service) SigningAllowed(ctx context.Context, c *contract.Contract) (bool, error) {
	if !Required(c) {
		return true, nil
	}
	jobID := c.JobID
	if jobID == "" {
		var err error
		if jobID, err = s.Repo.GetJobIDByContractID(ctx, c.ContractID); err != nil {
			return false, err
		}
		if jobID == "" {
			return false, nil
		}
	}
	st, err := s.State(ctx, jobID)
	if err != nil {
		return false, err
	}
	return st.Accepted(), nil
}

// MarkSignRequestsSent records that jobID's sign requests went out; first is
// false if they already had.
func (s *Service) MarkSignRequestsSent(ctx context.Context, jobID string) (first bool, err error) {
	return s.Repo.MarkSignRequestsSent(ctx, jobID)
}

// InfraOwners resolves the owner of each selected infra on c from its APD
// policy.
func (s *Service) InfraOwners(c *contract.Contract) []InfraOwner {
	owners := []InfraOwner{}
	for _, ip := range c.Parties.InfraProviders {
		if ip.ID == "" {
			continue
		}
		o := InfraOwner{InfraID: ip.ID}
		policy, err := s.APD.InfraPolicy(ip.ID)
		if err != nil {
			o.Reason = "infra has no known provider: " + err.Error()
		} else if o.ProviderID, _ = policy["provider_id"].(string); o.ProviderID == "" {
			o.Reason = "infra policy has no provider_id"
		}
		owners = append(owners, o)
	}
	return owners
}

// SignedContractHash is ContractHash, except that a consumer edit made after
// the hash was stored (Signatures.AmendmentValid) still yields the stored
// contract_hash — the one the providers sign — so it needs no re-signing.
func (s *Service) SignedContractHash(c *contract.Contract) (string, error) {
	if c.ContractHash != "" {
		if hash, err := contract.ComputeHash(*c); err == nil && hash != c.ContractHash && s.Signatures.AmendmentValid(c, hash) {
			return c.ContractHash, nil
		}
	}
	return ContractHash(c)
}

// VerifySignature checks an approval signature now: the submitted
// contractHash must be the one stored with the job's contract
// (SignedContractHash), and signature over it must verify with the caller's
// registered public key.
func (s *Service) VerifySignature(ctx context.Context, c *contract.Contract, caller Caller, contractHash, signature string) error {
	hash, err := s.SignedContractHash(c)
	if err != nil {
		return err
	}
	if contractHash != hash {
		return fmt.Errorf("contract_hash %s is not this job's contract hash (%s): sign the contract_hash from your JOB_REQUEST", contractHash, hash)
	}
	pub, err := s.Keys.PublicKey(ctx, caller.Username)
	if err != nil {
		return fmt.Errorf("no registered public key for %s (PUT /provider-keys/{role} first): %w", caller.Username, err)
	}
	if err := govcrypto.VerifyContractHashSignature(pub, hash, signature); err != nil {
		return fmt.Errorf("signature does not verify with %s's registered public key: %w", caller.Username, err)
	}
	return nil
}

// ApproveAsDataProvider checks the caller's own datasets on the job's
// contract (dataProviderEntries), verifies their signature (VerifySignature),
// stores it on the accepted ones and posts their APD consumer grants;
// JobStatus cross-verifies it again.
func (s *Service) ApproveAsDataProvider(ctx context.Context, caller Caller, in Input) (*Result, error) {
	c, err := s.Contract(ctx, in.JobID)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(c.Parties.DataProviders, caller.Is) {
		return nil, ErrNotDataProvider
	}
	st, err := s.State(ctx, in.JobID)
	if err != nil {
		return nil, err
	}
	if in.ContractHash == "" || in.Signature == "" {
		return nil, ErrMissingSignature
	}
	entries := s.dataProviderEntries(ctx, in.JobID, c, caller, st.checkedKeys(postgres.AuditTypeDataProvider))

	// "approval" is the caller's own result; the awaiting entries written for
	// other providers don't count against it.
	ownKeys := map[string]bool{}
	for _, dp := range c.Parties.DataProviders {
		if caller.Is(dp) {
			ownKeys[AuditKey(contract.PartyProviderID(dp), ApprovalItem(dp))] = true
		}
	}
	var own []postgres.AuditEntry
	for _, e := range entries {
		if ownKeys[AuditKey(e.ProviderID, e.Item)] {
			own = append(own, e)
		}
	}
	// The signature is verified here, not only at JobStatus: an approval with
	// a bad signature is refused and nothing is recorded.
	if OverallStatus(own) == postgres.AuditStatusAccepted {
		if err := s.VerifySignature(ctx, c, caller, in.ContractHash, in.Signature); err != nil {
			return nil, &SignatureError{err}
		}
	}
	res, err := s.record(ctx, postgres.AuditTypeDataProvider, c, entries, own, caller, in)
	if err != nil {
		return nil, err
	}
	s.markParticipants(ctx, postgres.ParticipantRoleDataProvider, in.JobID, own, caller)
	// Accepted: the consumer may use the dataset — its APD consumer grant is
	// posted now (JobStatus re-posts it; APD updates in place).
	res.Grants = s.postConsumerGrants(ctx, postgres.AuditTypeDataProvider, in.JobID, c, own)
	return res, nil
}

// ApproveAsInfraProvider is ApproveAsDataProvider for the caller's own infras
// (infraProviderEntries); a caller who owns none of them is refused. Their
// signature is stored as submitted and verified at JobStatus.
func (s *Service) ApproveAsInfraProvider(ctx context.Context, caller Caller, in Input) (*Result, error) {
	c, err := s.Contract(ctx, in.JobID)
	if err != nil {
		return nil, err
	}
	owners := s.InfraOwners(c)
	if !slices.ContainsFunc(owners, func(o InfraOwner) bool { return caller.Owns(o.ProviderID) }) {
		return nil, ErrNotInfraProvider
	}
	st, err := s.State(ctx, in.JobID)
	if err != nil {
		return nil, err
	}
	if in.ContractHash == "" || in.Signature == "" {
		return nil, ErrMissingSignature
	}
	entries := s.infraProviderEntries(in.JobID, owners, caller, st.checkedKeys(postgres.AuditTypeInfraProvider))

	// "approval" is the caller's own result, as for data providers.
	var own []postgres.AuditEntry
	for _, e := range entries {
		if caller.Owns(e.ProviderID) {
			own = append(own, e)
		}
	}
	res, err := s.record(ctx, postgres.AuditTypeInfraProvider, c, entries, own, caller, in)
	if err != nil {
		return nil, err
	}
	s.markParticipants(ctx, postgres.ParticipantRoleInfraProvider, in.JobID, own, caller)
	return res, nil
}

// dataProviderEntries checks the caller's datasets on c: the caller's token
// carries the data-provider role, and each dataset is an adex:DataBank in the
// DX catalogue, looked up with that token. Every other provider's dataset
// that has no audit entry yet (checked holds AuditKey of the current ones)
// gets a rejected "awaiting" entry, so the job can't count as accepted until
// each data provider has made the call with their own token.
func (s *Service) dataProviderEntries(ctx context.Context, jobID string, c *contract.Contract, caller Caller, checked map[string]bool) []postgres.AuditEntry {
	now := time.Now().UTC()
	// Local Keycloak users hold "data-provider"; dev ones hold "provider" (or
	// DATA_PROVIDER_ROLE).
	hasRole := slices.Contains(caller.Roles, "data-provider") || slices.Contains(caller.Roles, "provider") ||
		slices.Contains(caller.Roles, s.DataProviderRole)

	entries := []postgres.AuditEntry{}
	for _, dp := range c.Parties.DataProviders {
		e := postgres.AuditEntry{JobID: jobID, Type: postgres.AuditTypeDataProvider, Item: ApprovalItem(dp), CheckedAt: now, Status: postgres.AuditStatusRejected}
		if dp.ID != "" {
			e.ProviderID = contract.PartyProviderID(dp)
		}
		if !caller.Is(dp) {
			if checked[AuditKey(e.ProviderID, e.Item)] {
				continue
			}
			e.Reason = "awaiting this data provider's approval call with their own dev token"
			if dp.ID == "" {
				e.Reason = "dataset has no known provider (no APD policy found)"
			}
			entries = append(entries, e)
			continue
		}

		var reasons []string
		if hasRole {
			e.HasRole = true
		} else {
			reasons = append(reasons, fmt.Sprintf("provider's token does not carry the %s role", s.DataProviderRole))
		}
		itemID := CatalogueItemID(dp)
		if itemID == "" {
			reasons = append(reasons, fmt.Sprintf("contract has no DX catalogue item id for dataset %q", dp.DatasetName))
		} else if item, err := s.Catalogue.Item(ctx, itemID, caller.Token); err != nil {
			switch {
			case errors.Is(err, catalogue.ErrCatalogueItemNotFound):
				reasons = append(reasons, fmt.Sprintf("%s not found in the DX catalogue", itemID))
			case errors.Is(err, catalogue.ErrCatalogueTokenRefused):
				reasons = append(reasons, err.Error())
			default:
				reasons = append(reasons, "DX catalogue lookup failed: "+err.Error())
			}
		} else if !item.IsDataBank() {
			reasons = append(reasons, fmt.Sprintf("%s is not a dataset in the DX catalogue (type %v, want %s)", itemID, item.Type, catalogue.DataBankType))
		} else {
			e.InCatalogue = true
		}
		if e.HasRole && e.InCatalogue {
			e.Status = postgres.AuditStatusAccepted
		}
		e.Reason = strings.Join(reasons, "; ")
		entries = append(entries, e)
	}
	return entries
}

// infraProviderEntries checks the caller's infras among owners: the caller's
// token carries the infra-provider role, and each infra is in their APD
// catalogue. Every other infra that has no audit entry yet (checked holds
// AuditKey of the current ones) gets a rejected "awaiting" entry, so the job
// can't count as accepted until each infra provider has made the call with
// their own token.
func (s *Service) infraProviderEntries(jobID string, owners []InfraOwner, caller Caller, checked map[string]bool) []postgres.AuditEntry {
	now := time.Now().UTC()
	hasRole := slices.Contains(caller.Roles, InfraProviderRole)
	catalogues := map[string][]catalogue.CatalogueItem{}
	catalogueErrs := map[string]error{}

	entries := []postgres.AuditEntry{}
	for _, o := range owners {
		e := postgres.AuditEntry{JobID: jobID, Type: postgres.AuditTypeInfraProvider, ProviderID: o.ProviderID, Item: o.InfraID, CheckedAt: now, Status: postgres.AuditStatusRejected}
		if !caller.Owns(o.ProviderID) {
			if checked[AuditKey(e.ProviderID, e.Item)] {
				continue
			}
			e.Reason = "awaiting this infra provider's approval call with their own dev token"
			if o.Reason != "" {
				e.Reason = o.Reason
			}
			entries = append(entries, e)
			continue
		}

		var reasons []string
		if hasRole {
			e.HasRole = true
		} else {
			reasons = append(reasons, fmt.Sprintf("provider's token does not carry the %s role", InfraProviderRole))
		}
		if _, seen := catalogues[o.ProviderID]; !seen {
			catalogues[o.ProviderID], catalogueErrs[o.ProviderID] = s.Catalogue.ProviderInfra(o.ProviderID)
		}
		switch {
		case catalogueErrs[o.ProviderID] != nil:
			reasons = append(reasons, "catalogue lookup failed: "+catalogueErrs[o.ProviderID].Error())
		case catalogueHas(catalogues[o.ProviderID], o.InfraID):
			e.InCatalogue = true
		default:
			reasons = append(reasons, fmt.Sprintf("%s is not in the provider's catalogue", o.InfraID))
		}
		if e.HasRole && e.InCatalogue {
			e.Status = postgres.AuditStatusAccepted
		}
		e.Reason = strings.Join(reasons, "; ")
		entries = append(entries, e)
	}
	return entries
}

// record stores the caller's submitted signature on their own items
// accepted in own (signApprovedItems), appends entries to the audit table
// and returns the result with the job's new state.
func (s *Service) record(ctx context.Context, kind string, c *contract.Contract, entries, own []postgres.AuditEntry, caller Caller, in Input) (*Result, error) {
	signed, err := s.signApprovedItems(ctx, kind, c, own, caller.Username, in.ContractHash, in.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to store the signature: %w", err)
	}
	if err := s.Repo.InsertAuditEntries(ctx, entries); err != nil {
		return nil, fmt.Errorf("failed to write audit: %w", err)
	}
	st, err := s.State(ctx, in.JobID)
	if err != nil {
		return nil, err
	}
	log.Printf("[JOB-APPROVAL] job=%s type=%s job_approval=%s (%d recorded)", in.JobID, kind, st.Approval, len(entries))
	return &Result{Kind: kind, JobID: in.JobID, Approval: OverallStatus(own), State: st, Entries: entries,
		ContractHash: in.ContractHash, Signed: signed}, nil
}

// signApprovedItems records the caller's submitted (not yet verified)
// signature over hash on each of their parties accepted in own
// (data-provider: datasets, infra-provider: infras) and stores the contract.
// Returns how many parties were signed.
func (s *Service) signApprovedItems(ctx context.Context, kind string, c *contract.Contract, own []postgres.AuditEntry, signer, hash, signature string) (int, error) {
	accepted := map[string]bool{}
	for _, e := range own {
		if e.Status == postgres.AuditStatusAccepted {
			accepted[AuditKey(e.ProviderID, e.Item)] = true
		}
	}
	now := time.Now().UTC()
	sig := contract.Signature{SignedAt: &now, Signer: signer, Algorithm: govcrypto.ContractSignatureAlgorithm, SignedHash: hash, Value: signature}
	signed := 0
	switch kind {
	case postgres.AuditTypeDataProvider:
		for i := range c.Parties.DataProviders {
			dp := &c.Parties.DataProviders[i]
			if dp.ID != "" && accepted[AuditKey(contract.PartyProviderID(*dp), ApprovalItem(*dp))] {
				dp.Signature = sig
				signed++
			}
		}
	case postgres.AuditTypeInfraProvider:
		for i := range c.Parties.InfraProviders {
			ip := &c.Parties.InfraProviders[i]
			for _, e := range own {
				if ip.ID != "" && ip.ID == e.Item && accepted[AuditKey(e.ProviderID, e.Item)] {
					ip.Signature = sig
					signed++
					break
				}
			}
		}
	}
	if signed == 0 {
		return 0, nil
	}
	if err := s.storeContract(ctx, c); err != nil {
		return 0, err
	}
	return signed, nil
}

func (s *Service) storeContract(ctx context.Context, c *contract.Contract) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if ok, err := s.Repo.UpdateContractByContractID(ctx, c.ContractID, raw); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("contract %s not found", c.ContractID)
	}
	return nil
}

// markParticipants records the caller's approval result on each of their
// items in own (role: data-provider / infra-provider).
func (s *Service) markParticipants(ctx context.Context, role, jobID string, own []postgres.AuditEntry, caller Caller) {
	for _, e := range own {
		status := postgres.ParticipantStatusRejected
		if e.Status == postgres.AuditStatusAccepted {
			status = postgres.ParticipantStatusApproved
		}
		if _, err := s.Repo.SetJobParticipantStatus(ctx, jobID, role, e.ProviderID, e.Item, status, caller.UserID, caller.Username); err != nil {
			log.Printf("[JOB-PARTICIPANTS] Warning: job %s: %s %s / %s not marked %s: %v", jobID, role, e.ProviderID, e.Item, status, err)
		}
	}
}

// postConsumerGrants posts an APD consumer grant for each of the calling
// provider's items accepted in own (kind: data-provider -> their datasets,
// infra-provider -> their infras): the job's consumer may use that dataset /
// infra for this job/contract. Each provider's approval posts its own grants,
// independent of the other providers. A failed post doesn't undo the
// approval; it is reported, and calling the approval again retries it (the
// grant's policyId is fixed per job and item, so APD updates it in place).
func (s *Service) postConsumerGrants(ctx context.Context, kind, jobID string, c *contract.Contract, own []postgres.AuditEntry) []GrantResult {
	base := apd.ConsumerGrant{
		JobID:        jobID,
		ContractID:   c.ContractID,
		Consumer:     c.Parties.User.ID,
		ConsumerName: c.Parties.User.Name,
		ExpiresAt:    c.Lifecycle.ValidUntil,
	}
	grants := []apd.ConsumerGrant{}
	for _, e := range own {
		if e.Status != postgres.AuditStatusAccepted || e.ProviderID == "" {
			continue
		}
		g := base
		g.ItemID, g.Provider = e.Item, e.ProviderID
		switch kind {
		case postgres.AuditTypeDataProvider:
			g.ItemType = apd.GrantItemDataset
			for _, dp := range c.Parties.DataProviders {
				if contract.PartyProviderID(dp) == e.ProviderID && ApprovalItem(dp) == e.Item {
					g.ItemName = dp.DatasetName
					// The grant ends when the provider's consent does.
					if u := dp.Constraints.ConsentValidUntil; u != nil && (g.ExpiresAt.IsZero() || u.Before(g.ExpiresAt)) {
						g.ExpiresAt = *u
					}
				}
			}
		case postgres.AuditTypeInfraProvider:
			g.ItemType = apd.GrantItemInfra
			for _, ip := range c.Parties.InfraProviders {
				if ip.ID == e.Item {
					g.ItemName = ip.Name
				}
			}
		default:
			continue
		}
		grants = append(grants, g)
	}

	results := []GrantResult{}
	for _, g := range grants {
		res := GrantResult{ItemType: g.ItemType, ItemID: g.ItemID, Status: "posted"}
		gctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		policyID, err := s.APD.PostConsumerGrant(gctx, g)
		cancel()
		if err != nil {
			log.Printf("[JOB-APPROVAL] job=%s: consumer grant for %s %s not posted: %v", jobID, g.ItemType, g.ItemID, err)
			res.Status, res.Error = "failed", err.Error()
		} else {
			res.PolicyID = policyID
			log.Printf("[JOB-APPROVAL] job=%s: consumer grant %s posted to APD (%s may use %s %s)", jobID, policyID, g.Consumer, g.ItemType, g.ItemID)
		}
		results = append(results, res)
	}
	return results
}

// JobStatus is the governance layer's cross-verification of the job, for
// its consumer only (consumerSub must be the contract's parties.user.id):
//
//  1. every data and infra provider has approved (their role and catalogue
//     checks, recorded with their own token at the approval calls), and
//  2. every provider's submitted contract hash is the hash of gov_layer's copy
//     of the contract and their signature over it verifies with their
//     registered public key (VerifyJobSignatures).
//
// If both hold, the job is approved and only then is its final contract
// created: with its contract_hash (seal) and every provider signature on it
// verified, it is stored in final_contracts (Finalize). No governance
// signature is added. The APD consumer grants for every dataset and infra are
// posted after that. Otherwise the reasons are returned and nothing is
// created. Re-callable: once approved, it re-verifies, returns the same final
// contract and re-posts the grants (APD updates them in place).
func (s *Service) JobStatus(ctx context.Context, jobID, consumerSub string) (*JobStatus, error) {
	c, err := s.Contract(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if consumerSub == "" || !strings.EqualFold(consumerSub, c.Parties.User.ID) {
		return nil, ErrNotConsumer
	}
	st, err := s.State(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if !st.Accepted() {
		return &JobStatus{Reasons: Reasons(st)}, nil
	}
	parties, reasons := s.VerifyJobSignatures(ctx, c)
	if len(reasons) > 0 {
		log.Printf("[JOB-STATUS] job=%s not approved: %s", jobID, strings.Join(reasons, "; "))
		return &JobStatus{Reasons: reasons, SignaturesChecked: true, Signatures: parties}, nil
	}

	// Approvals, hash and signatures all hold: the job is approved. Only now
	// is its final contract created.
	c.JobID = jobID
	if err := s.seal(ctx, c); err != nil {
		return nil, fmt.Errorf("contract hash could not be stored: %w", err)
	}
	final, pending, err := s.Finalize(ctx, jobID, c)
	if err != nil {
		return nil, err
	}
	var finalRecord *postgres.FinalContract
	if final {
		if err := s.Repo.SetJobStatus(ctx, jobID, postgres.ParticipantStatusFinal); err != nil {
			log.Printf("[JOB-PARTICIPANTS] Warning: job %s: participants not marked %s: %v", jobID, postgres.ParticipantStatusFinal, err)
		}
		if finalRecord, err = s.Repo.GetFinalContract(ctx, jobID); err != nil {
			return nil, err
		}
	}

	grants := []GrantResult{}
	for _, kind := range []string{postgres.AuditTypeDataProvider, postgres.AuditTypeInfraProvider} {
		var accepted []postgres.AuditEntry
		for _, e := range st.Current {
			if e.Type == kind {
				accepted = append(accepted, e)
			}
		}
		grants = append(grants, s.postConsumerGrants(ctx, kind, jobID, c, accepted)...)
	}
	return &JobStatus{Approved: true, SignaturesChecked: true, Signatures: parties, ContractHash: c.ContractHash,
		Grants: grants, Final: final, FinalRecord: finalRecord, Pending: pending}, nil
}

// VerifyJobSignatures cross-verifies every provider's submitted signature on
// an approved job's contract: each must be over gov_layer's own hash of the
// contract and verify with the signer's registered public key, and an infra's
// signer must be its owner. Returns each party's result and, if any fails,
// the reasons.
func (s *Service) VerifyJobSignatures(ctx context.Context, c *contract.Contract) ([]PartySignature, []string) {
	hash, err := s.SignedContractHash(c)
	if err != nil {
		return nil, []string{err.Error()}
	}
	owners := map[string]string{}
	for _, o := range s.InfraOwners(c) {
		owners[o.InfraID] = o.ProviderID
	}
	parties, allValid := s.Signatures.ProviderSignatures(ctx, c, hash, owners)
	var reasons []string
	if !allValid {
		for _, p := range parties {
			if !p.Valid {
				reasons = append(reasons, PartyLabel(p)+": "+p.Error)
			}
		}
	}
	return parties, reasons
}

// seal stores the contract_hash on a job's contract whose provider
// signatures all verified — the hash the providers were sent with their job
// requests and signed when approving. A job contract carries no governance
// signature. A no-op once the hash is stored (since /generate-contract
// stores it, only contracts from before then lack it).
func (s *Service) seal(ctx context.Context, c *contract.Contract) error {
	if c.ContractHash != "" {
		return nil
	}
	hash, err := contract.ComputeHash(*c)
	if err != nil {
		return err
	}
	c.ContractHash = hash
	if err := s.storeContract(ctx, c); err != nil {
		return err
	}
	log.Printf("[JOB-APPROVAL] Job %s approved: contract %s hash %s stored", c.JobID, c.ContractID, hash)
	return nil
}

// Finalize makes an approved job's contract final once its hash and every
// signature on it — each data and infra provider's, made when approving —
// verify (Signatures.VerifyContract): it creates the job's final contract
// (final_contracts) and marks the contracts row final. Otherwise it returns
// what's still pending and creates nothing. Idempotent: a final contract,
// once created, is never replaced.
func (s *Service) Finalize(ctx context.Context, jobID string, c *contract.Contract) (bool, []string, error) {
	parties, hashOK, allValid := s.Signatures.VerifyContract(ctx, c)
	if !allValid {
		var pending []string
		if !hashOK {
			pending = append(pending, "contract no longer matches its hash")
		}
		if !s.Signatures.GovernanceSignatureOK(c, c.ContractHash) {
			pending = append(pending, "governance signature missing or invalid")
		}
		for _, p := range parties {
			if !p.Valid {
				pending = append(pending, PartyLabel(p)+": "+p.Error)
			}
		}
		return false, pending, nil
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return false, nil, err
	}
	created, err := s.Repo.CreateFinalContract(ctx, jobID, c.ContractID, c.ContractHash, raw)
	if err != nil {
		return false, nil, fmt.Errorf("final contract could not be stored: %w", err)
	}
	if created {
		log.Printf("[JOB-APPROVAL] Job %s: final contract created (contract %s, hash %s)", jobID, c.ContractID, c.ContractHash)
	}
	first, err := s.Repo.MarkJobFinal(ctx, jobID)
	if err != nil {
		return false, nil, err
	}
	if first {
		log.Printf("[JOB-APPROVAL] Job %s: contract %s is final (all %d provider signatures + governance signature verified)", jobID, c.ContractID, len(parties))
	}
	return true, nil, nil
}
