// Job approvals: once a contract naming both datasets and infrastructure is
// generated, every provider on it is checked before anyone is asked to sign.
//
// Data providers (POST /job/approval/data-provider) are checked with their
// own dev Keycloak token, sent as the Bearer token on that call — so each
// data provider on a contract makes the call for their own datasets:
//
//   - the token carries the data-provider realm role (DATA_PROVIDER_ROLE,
//     "provider" in dev), and
//   - each of their datasets exists in the DX catalogue as an adex:DataBank,
//     looked up (GET {CATALOGUE_BASE_URL}/item?id=) with that same token.
//
// Infra providers (POST /job/approval/infra-provider) are checked the same
// way, with their own dev Keycloak token — each infra provider on a contract
// makes the call for their own infras:
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
// sent with the job request (job_request.go) with their own private key —
// generated and kept on their machine; only the public key is registered
// (PUT /provider-keys/{role}) — and sends it with the approval call:
// {"job_id", "contract_hash", "signature"}. The approval call stores it as
// submitted; the governance layer cross-verifies every provider's hash and
// signature at GET /job/{jobId}/status (getJobStatus), and only if all verify
// does it governance-sign the contract, post the APD consumer grants and make
// the contract final.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
)

// needsJobApproval reports whether c names at least one dataset and at least
// one real (selected, so id-bearing) infrastructure — the TEE placeholder
// infra has no id and doesn't count.
func needsJobApproval(c *contract.Contract) bool {
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

// jobApprovalRequired reports whether c goes through job approval: it names
// datasets and real infra (needsJobApproval), or — with REQUIRE_INFRA_APPROVAL
// off, so a job is approved on its data-provider approval alone — it is a
// TEE/SMPC contract naming datasets but no selected infra (e.g. TEE on the
// placeholder infra). FL contracts never do; they're signed on their roster.
func (s *Server) jobApprovalRequired(c *contract.Contract) bool {
	// Only datasets + real infra go through job approval: a TEE/SMPC contract
	// with no selected infra is sent straight to its data providers to sign
	// (the UI has no job-approval screen), whatever REQUIRE_INFRA_APPROVAL is.
	// if needsJobApproval(c) {
	// 	return true
	// }
	// if s.cfg == nil || s.cfg.RequireInfraApproval {
	// 	return false
	// }
	// return len(c.Parties.DataProviders) > 0 && (c.Technique == "TEE" || c.Technique == "SMPC")
	return needsJobApproval(c)
}

func catalogueHas(items []services.CatalogueItem, item string) bool {
	for _, it := range items {
		if it.ItemID == item || strings.EqualFold(it.Name, item) {
			return true
		}
	}
	return false
}

// providerCaller is the data or infra provider making POST
// /job/approval/{data,infra}-provider, read from their validated dev Keycloak
// token.
type providerCaller struct {
	token    string          // raw bearer token, forwarded to the DX catalogue
	username string          // preferred_username, else email: whose registered public key verifies their signature
	userID   string          // sub: their Keycloak user id
	names    map[string]bool // provider_ids / usernames / emails / sub that name them on a contract
	roles    []string        // realm roles
}

func callerFromClaims(token string, claims jwt.MapClaims) providerCaller {
	c := providerCaller{token: token, names: map[string]bool{}}
	c.username, _ = claims["preferred_username"].(string)
	if c.username == "" {
		c.username, _ = claims["email"].(string)
	}
	for _, k := range []string{"preferred_username", "email"} {
		if v, _ := claims[k].(string); v != "" {
			c.names[providerIDForUsername(v)] = true
			c.names[strings.ToLower(v)] = true
		}
	}
	if sub, _ := claims["sub"].(string); sub != "" {
		c.userID = sub
		c.names[strings.ToLower(sub)] = true
	}
	if ra, ok := claims["realm_access"].(map[string]any); ok {
		if list, ok := ra["roles"].([]any); ok {
			for _, v := range list {
				if r, ok := v.(string); ok {
					c.roles = append(c.roles, r)
				}
			}
		}
	}
	return c
}

// owns reports whether providerID (an APD policy's provider_id) names the
// caller.
func (c providerCaller) owns(providerID string) bool {
	return providerID != "" && (c.names[providerID] || c.names[strings.ToLower(providerID)])
}

// is reports whether dp is one of the caller's datasets.
func (c providerCaller) is(dp contract.DataProviderParty) bool {
	return dp.ID != "" && (c.names[partyProviderID(dp)] || c.names[strings.ToLower(dp.ID)])
}

// devTokenClaims validates the Bearer token on the request against the dev
// Keycloak's JWKS (DATA_PROVIDER_JWKS_URL) and returns it with its claims;
// whose ("data provider", "consumer") is named in the missing-token message.
// On failure it has already written the response.
func (s *Server) devTokenClaims(w http.ResponseWriter, r *http.Request, whose string) (string, jwt.MapClaims, bool) {
	tokenStr, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || tokenStr == "" {
		writeJSON(w, http.StatusUnauthorized, j{"status": "FAILED", "error": "MISSING_AUTH_TOKEN",
			"message": "send the " + whose + "'s dev Keycloak token as the Bearer token"})
		return "", nil, false
	}
	token, err := services.ValidateAccessTokenAt(tokenStr, s.cfg.DataProviderJWKSURL)
	if err != nil || !token.Valid {
		log.Printf("[JOB-APPROVAL] %s token rejected: %v", whose, err)
		writeJSON(w, http.StatusUnauthorized, j{"status": "FAILED", "error": "INVALID_OR_EXPIRED_TOKEN"})
		return "", nil, false
	}
	claims, _ := token.Claims.(jwt.MapClaims)
	if s.rejectFlotillaVMToken(w, claims) {
		return "", nil, false
	}
	return tokenStr, claims, true
}

// approverFromToken reads the provider calling POST
// /job/approval/{data,infra}-provider from their dev Keycloak token; whose
// is named in the missing-token message.
func (s *Server) approverFromToken(w http.ResponseWriter, r *http.Request, whose string) (providerCaller, bool) {
	tokenStr, claims, ok := s.devTokenClaims(w, r, whose)
	if !ok {
		return providerCaller{}, false
	}
	return callerFromClaims(tokenStr, claims), true
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// catalogueItemID is dp's DX catalogue item id. Contracts generated before
// dataset_id was recorded fall back to the dataset name when it is one.
func catalogueItemID(dp contract.DataProviderParty) string {
	if dp.DatasetID != "" {
		return dp.DatasetID
	}
	if uuidPattern.MatchString(dp.DatasetName) {
		return dp.DatasetName
	}
	return ""
}

// approvalItem is the audit "item" for dp: its catalogue id, else its name.
func approvalItem(dp contract.DataProviderParty) string {
	if id := catalogueItemID(dp); id != "" {
		return id
	}
	return dp.DatasetName
}

func (s *Server) lookupCatalogueItem(ctx context.Context, itemID, token string) (services.DXCatalogueItem, error) {
	client, baseURL, timeout := s.http, "", 10*time.Second
	if client == nil {
		client = http.DefaultClient
	}
	if s.cfg != nil {
		baseURL = s.cfg.CatalogueBaseURL
		if s.cfg.CatalogueTimeout > 0 {
			timeout = s.cfg.CatalogueTimeout
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return services.FetchDXCatalogueItem(ctx, client, baseURL, itemID, token)
}

func auditKey(providerID, item string) string { return providerID + "\x00" + item }

// dataProviderApprovals checks the caller's datasets on c: the caller's token
// carries the data-provider role, and each dataset is an adex:DataBank in the
// DX catalogue, looked up with that token. Every other provider's dataset
// that has no audit entry yet (checked holds auditKey of the current ones)
// gets a rejected "awaiting" entry, so the job can't count as accepted until
// each data provider has made the call with their own token.
func (s *Server) dataProviderApprovals(ctx context.Context, jobID string, c *contract.Contract, caller providerCaller, checked map[string]bool) []db.AuditEntry {
	now := time.Now().UTC()
	hasRole := slices.Contains(caller.roles, s.dataProviderRole())

	entries := []db.AuditEntry{}
	for _, dp := range c.Parties.DataProviders {
		e := db.AuditEntry{JobID: jobID, Type: db.AuditTypeDataProvider, Item: approvalItem(dp), CheckedAt: now, Status: db.AuditStatusRejected}
		if dp.ID != "" {
			e.ProviderID = partyProviderID(dp)
		}
		if !caller.is(dp) {
			if checked[auditKey(e.ProviderID, e.Item)] {
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
			reasons = append(reasons, fmt.Sprintf("provider's token does not carry the %s role", s.dataProviderRole()))
		}
		itemID := catalogueItemID(dp)
		if itemID == "" {
			reasons = append(reasons, fmt.Sprintf("contract has no DX catalogue item id for dataset %q", dp.DatasetName))
		} else if item, err := s.lookupCatalogueItem(ctx, itemID, caller.token); err != nil {
			switch {
			case errors.Is(err, services.ErrCatalogueItemNotFound):
				reasons = append(reasons, fmt.Sprintf("%s not found in the DX catalogue", itemID))
			case errors.Is(err, services.ErrCatalogueTokenRefused):
				reasons = append(reasons, err.Error())
			default:
				reasons = append(reasons, "DX catalogue lookup failed: "+err.Error())
			}
		} else if !item.IsDataBank() {
			reasons = append(reasons, fmt.Sprintf("%s is not a dataset in the DX catalogue (type %v, want %s)", itemID, item.Type, services.DataBankType))
		} else {
			e.InCatalogue = true
		}
		if e.HasRole && e.InCatalogue {
			e.Status = db.AuditStatusAccepted
		}
		e.Reason = strings.Join(reasons, "; ")
		entries = append(entries, e)
	}
	return entries
}

// dataProviderRole is the realm role a dataset's provider must hold
// (DATA_PROVIDER_ROLE, "data-provider" by default).
func (s *Server) dataProviderRole() string {
	if s.cfg != nil && s.cfg.DataProviderRole != "" {
		return s.cfg.DataProviderRole
	}
	return "data-provider"
}

// infraProviderRole is the realm role an infra's provider must hold.
const infraProviderRole = "infra-provider"

// infraOwner is one selected infra on a contract and its owning provider,
// read off that infra's APD policy (the contract only records the infra id).
type infraOwner struct {
	infraID    string
	providerID string
	reason     string // set when the owner couldn't be resolved
}

func infraOwners(c *contract.Contract) []infraOwner {
	owners := []infraOwner{}
	for _, ip := range c.Parties.InfraProviders {
		if ip.ID == "" {
			continue
		}
		o := infraOwner{infraID: ip.ID}
		policy, err := services.FetchInfraPolicy(ip.ID)
		if err != nil {
			o.reason = "infra has no known provider: " + err.Error()
		} else if o.providerID, _ = policy["provider_id"].(string); o.providerID == "" {
			o.reason = "infra policy has no provider_id"
		}
		owners = append(owners, o)
	}
	return owners
}

// infraProviderApprovals checks the caller's infras among owners: the
// caller's token carries the infra-provider role, and each infra is in their
// APD catalogue. Every other infra that has no audit entry yet (checked holds
// auditKey of the current ones) gets a rejected "awaiting" entry, so the job
// can't count as accepted until each infra provider has made the call with
// their own token.
func (s *Server) infraProviderApprovals(jobID string, owners []infraOwner, caller providerCaller, checked map[string]bool) []db.AuditEntry {
	now := time.Now().UTC()
	hasRole := slices.Contains(caller.roles, infraProviderRole)
	catalogues := map[string][]services.CatalogueItem{}
	catalogueErrs := map[string]error{}

	entries := []db.AuditEntry{}
	for _, o := range owners {
		e := db.AuditEntry{JobID: jobID, Type: db.AuditTypeInfraProvider, ProviderID: o.providerID, Item: o.infraID, CheckedAt: now, Status: db.AuditStatusRejected}
		if !caller.owns(o.providerID) {
			if checked[auditKey(e.ProviderID, e.Item)] {
				continue
			}
			e.Reason = "awaiting this infra provider's approval call with their own dev token"
			if o.reason != "" {
				e.Reason = o.reason
			}
			entries = append(entries, e)
			continue
		}

		var reasons []string
		if hasRole {
			e.HasRole = true
		} else {
			reasons = append(reasons, fmt.Sprintf("provider's token does not carry the %s role", infraProviderRole))
		}
		if _, seen := catalogues[o.providerID]; !seen {
			catalogues[o.providerID], catalogueErrs[o.providerID] = services.ListProviderInfra(o.providerID)
		}
		switch {
		case catalogueErrs[o.providerID] != nil:
			reasons = append(reasons, "catalogue lookup failed: "+catalogueErrs[o.providerID].Error())
		case catalogueHas(catalogues[o.providerID], o.infraID):
			e.InCatalogue = true
		default:
			reasons = append(reasons, fmt.Sprintf("%s is not in the provider's catalogue", o.infraID))
		}
		if e.HasRole && e.InCatalogue {
			e.Status = db.AuditStatusAccepted
		}
		e.Reason = strings.Join(reasons, "; ")
		entries = append(entries, e)
	}
	return entries
}

// overallStatus is "accepted" only when there is at least one entry and every
// entry is accepted.
func overallStatus(entries []db.AuditEntry) string {
	if len(entries) == 0 {
		return "pending"
	}
	for _, e := range entries {
		if e.Status != db.AuditStatusAccepted {
			return db.AuditStatusRejected
		}
	}
	return db.AuditStatusAccepted
}

// jobApprovalState is a job's approval standing, derived from its audit
// history: the latest entry per (type, provider_id, item) is current.
type jobApprovalState struct {
	Approval      string          `json:"approval"`
	DataProvider  string          `json:"data_provider"`
	InfraProvider string          `json:"infra_provider"`
	Current       []db.AuditEntry `json:"current"`
	History       []db.AuditEntry `json:"history"`
	// infraRequired is false while REQUIRE_INFRA_APPROVAL=false: the job is
	// then approved on its data-provider side alone.
	infraRequired bool
}

// accepted reports whether both sides (or, with infra approval switched off,
// the data-provider side) have been checked and every current entry is
// accepted.
func (st jobApprovalState) accepted() bool {
	return st.DataProvider == db.AuditStatusAccepted &&
		(!st.infraRequired || st.InfraProvider == db.AuditStatusAccepted)
}

func (s *Server) loadJobApprovalState(ctx context.Context, jobID string) (jobApprovalState, error) {
	history, err := s.db.ListAuditByJob(ctx, jobID)
	if err != nil {
		return jobApprovalState{}, err
	}
	latest := map[string]db.AuditEntry{}
	order := []string{}
	for _, e := range history {
		key := e.Type + "\x00" + e.ProviderID + "\x00" + e.Item
		if _, seen := latest[key]; !seen {
			order = append(order, key)
		}
		latest[key] = e
	}
	current := make([]db.AuditEntry, 0, len(order))
	byType := map[string][]db.AuditEntry{}
	for _, k := range order {
		current = append(current, latest[k])
		byType[latest[k].Type] = append(byType[latest[k].Type], latest[k])
	}
	st := jobApprovalState{
		DataProvider:  overallStatus(byType[db.AuditTypeDataProvider]),
		InfraProvider: overallStatus(byType[db.AuditTypeInfraProvider]),
		Current:       current,
		History:       history,
		infraRequired: s.cfg == nil || s.cfg.RequireInfraApproval,
	}
	switch {
	case st.accepted():
		st.Approval = db.AuditStatusAccepted
	case st.DataProvider == db.AuditStatusRejected || (st.infraRequired && st.InfraProvider == db.AuditStatusRejected):
		st.Approval = db.AuditStatusRejected
	default:
		st.Approval = "pending"
	}
	return st, nil
}

// signingAllowed reports whether c's providers may be asked to sign / sign
// it: always for a contract that needs no approval, otherwise only once its
// job is accepted. Backfilled contracts carry job_id only in the DB column,
// so it's read from there when the JSON has none.
func (s *Server) signingAllowed(ctx context.Context, c *contract.Contract) (bool, error) {
	if !s.jobApprovalRequired(c) {
		return true, nil
	}
	jobID := c.JobID
	if jobID == "" {
		var err error
		if jobID, err = s.db.GetJobIDByContractID(ctx, c.ContractID); err != nil {
			return false, err
		}
		if jobID == "" {
			return false, nil
		}
	}
	st, err := s.loadJobApprovalState(ctx, jobID)
	if err != nil {
		return false, err
	}
	return st.accepted(), nil
}

// sendSignRequestsOnce sends c's sign requests unless they already went out
// for this job. Returns how many were sent (0 if already sent).
func (s *Server) sendSignRequestsOnce(ctx context.Context, c contract.Contract, sender string) int {
	if c.JobID != "" {
		first, err := s.db.MarkSignRequestsSent(ctx, c.JobID)
		if err != nil {
			log.Printf("[JOB-APPROVAL] Warning: failed to mark sign requests sent for job %s: %v", c.JobID, err)
			return 0
		}
		if !first {
			return 0
		}
	}
	return s.notifyContractSigners(ctx, c, sender)
}

// loadContractByJob loads and decodes the contract stored for jobID, writing
// the error response itself when it can't.
func (s *Server) loadContractByJob(w http.ResponseWriter, r *http.Request, jobID string) (*contract.Contract, bool) {
	if jobID == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "BAD_REQUEST", "message": "job_id is required"})
		return nil, false
	}
	raw, err := s.db.GetContractByJobID(reqCtx(r), jobID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return nil, false
	}
	if raw == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND", "message": "No contract for this job_id"})
		return nil, false
	}
	c := &contract.Contract{}
	if err := json.Unmarshal(raw, c); err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": "stored contract is not valid: " + err.Error()})
		return nil, false
	}
	if !s.jobApprovalRequired(c) {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "NO_APPROVAL_NEEDED", "message": "contract does not go through job approval (it needs a dataset and an infrastructure, or REQUIRE_INFRA_APPROVAL=false for TEE/SMPC)"})
		return nil, false
	}
	return c, true
}

// approvalBody is the body of the POST /job/approval/* calls: the job, and
// the caller's signature over the contract hash they were sent.
type approvalBody struct {
	JobID        string `json:"job_id"`
	ContractHash string `json:"contract_hash"`
	Signature    string `json:"signature"`
	// Optional, data provider only: copied into their IUDX policies.
	ProviderComment    string `json:"provider_comment,omitempty"`
	FeedbackToConsumer string `json:"feedback_to_consumer,omitempty"`
}

// loadApprovalJob reads the approval body and loads that job's contract,
// writing the error response itself when it can't.
func (s *Server) loadApprovalJob(w http.ResponseWriter, r *http.Request) (approvalBody, *contract.Contract, bool) {
	var body approvalBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "BAD_REQUEST", "message": "Invalid request body"})
		return body, nil, false
	}
	c, ok := s.loadContractByJob(w, r, body.JobID)
	return body, c, ok
}

// requireSubmittedSignature refuses an approval call without the signed
// contract hash; it is stored as submitted and cross-verified at
// GET /job/{jobId}/status. On failure it has already written the response.
func requireSubmittedSignature(w http.ResponseWriter, body approvalBody) bool {
	if body.ContractHash == "" || body.Signature == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_FIELDS",
			"message": "contract_hash and signature are required: sign the contract_hash from your job request with your private key"})
		return false
	}
	return true
}

// signApprovedItems records the caller's submitted (not yet verified)
// signature over hash on each of their parties accepted in own
// (data-provider: datasets, infra-provider: infras) and stores the contract.
// Returns how many parties were signed.
func (s *Server) signApprovedItems(ctx context.Context, kind string, c *contract.Contract, own []db.AuditEntry, signer, hash, signature string) (int, error) {
	accepted := map[string]bool{}
	for _, e := range own {
		if e.Status == db.AuditStatusAccepted {
			accepted[auditKey(e.ProviderID, e.Item)] = true
		}
	}
	now := time.Now().UTC()
	sig := contract.Signature{SignedAt: &now, Signer: signer, Algorithm: services.ContractSignatureAlgorithm, SignedHash: hash, Value: signature}
	signed := 0
	switch kind {
	case db.AuditTypeDataProvider:
		for i := range c.Parties.DataProviders {
			dp := &c.Parties.DataProviders[i]
			if dp.ID != "" && accepted[auditKey(partyProviderID(*dp), approvalItem(*dp))] {
				dp.Signature = sig
				signed++
			}
		}
	case db.AuditTypeInfraProvider:
		for i := range c.Parties.InfraProviders {
			ip := &c.Parties.InfraProviders[i]
			for _, e := range own {
				if ip.ID != "" && ip.ID == e.Item && accepted[auditKey(e.ProviderID, e.Item)] {
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
	raw, err := json.Marshal(c)
	if err != nil {
		return 0, err
	}
	if ok, err := s.db.UpdateContractByContractID(ctx, c.ContractID, raw); err != nil {
		return 0, err
	} else if !ok {
		return 0, fmt.Errorf("contract %s not found", c.ContractID)
	}
	return signed, nil
}

// POST /job/approval/data-provider — Authorization: Bearer <the data
// provider's dev Keycloak token>, body {"job_id", "contract_hash",
// "signature"}. Checks the caller's own datasets on the job's contract (see
// dataProviderApprovals), verifies the signature (verifySubmittedSignature),
// stores it on the accepted ones and posts their APD consumer grants; GET
// /job/{jobId}/status cross-verifies it again.
func (s *Server) handleDataProviderApproval(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.approverFromToken(w, r, "data provider")
	if !ok {
		return
	}
	body, c, ok := s.loadApprovalJob(w, r)
	if !ok {
		return
	}
	jobID := body.JobID
	entries, ok := s.checkCallerDatasets(w, r, jobID, c, caller)
	if !ok || !requireSubmittedSignature(w, body) {
		return
	}

	// "approval" is the caller's own result; the awaiting entries written for
	// other providers don't count against it.
	ownKeys := map[string]bool{}
	for _, dp := range c.Parties.DataProviders {
		if caller.is(dp) {
			ownKeys[auditKey(partyProviderID(dp), approvalItem(dp))] = true
		}
	}
	var own []db.AuditEntry
	for _, e := range entries {
		if ownKeys[auditKey(e.ProviderID, e.Item)] {
			own = append(own, e)
		}
	}
	// The signature is verified here, not only at GET /job/{jobId}/status:
	// an approval with a bad signature is refused and nothing is recorded.
	if overallStatus(own) == db.AuditStatusAccepted {
		if err := s.verifySubmittedSignature(reqCtx(r), c, caller, body); err != nil {
			writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_SIGNATURE", "message": err.Error()})
			return
		}
	}
	resp, ok := s.recordJobApproval(w, r, db.AuditTypeDataProvider, jobID, c, entries, own, caller, body)
	if !ok {
		return
	}
	s.markApprovalParticipants(reqCtx(r), db.ParticipantRoleDataProvider, jobID, own, caller)
	// Accepted: the consumer may use the dataset — its APD consumer grant is
	// posted now (GET /job/{jobId}/status re-posts it; APD updates in place).
	resp["grants"] = s.postConsumerGrants(reqCtx(r), db.AuditTypeDataProvider, jobID, c, own)
	// ...and its IUDX APD policy, with the caller's own token — so only
	// here, not again at GET /job/{jobId}/status (the consumer's token).
	resp["iudx_policies"] = s.postIUDXPolicies(reqCtx(r), jobID, c, own, caller, body)
	writeJSON(w, http.StatusOK, resp)
}

// iudxPolicyResult is one dataset's IUDX APD policy in the approval response.
type iudxPolicyResult struct {
	ItemID   string `json:"item_id"`
	PolicyID string `json:"policy_id,omitempty"`
	Status   string `json:"status"` // "posted" / "failed"
	Error    string `json:"error,omitempty"`
}

// postIUDXPolicies posts an IUDX APD policy (IUDX_APD_POLICY_URL, skipped
// when blank) for each of the caller's accepted datasets, built from the
// stored contract. A failure is reported, never fails the approval.
func (s *Server) postIUDXPolicies(ctx context.Context, jobID string, c *contract.Contract, own []db.AuditEntry, caller providerCaller, body approvalBody) []iudxPolicyResult {
	results := []iudxPolicyResult{}
	if s.cfg == nil || s.cfg.IUDXAPDPolicyURL == "" {
		return results
	}
	client := s.http
	if client == nil {
		client = http.DefaultClient
	}
	for _, e := range own {
		if e.Status != db.AuditStatusAccepted {
			continue
		}
		for _, dp := range c.Parties.DataProviders {
			if partyProviderID(dp) != e.ProviderID || approvalItem(dp) != e.Item {
				continue
			}
			policy := services.BuildIUDXPolicy(services.IUDXPolicyInput{
				Contract:           c,
				JobID:              jobID,
				Dataset:            dp,
				ItemID:             e.Item,
				CallbackURL:        s.cfg.IUDXPolicyCallbackURL,
				ProviderComment:    body.ProviderComment,
				FeedbackToConsumer: body.FeedbackToConsumer,
			})
			res := iudxPolicyResult{ItemID: e.Item, Status: "posted"}
			pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			policyID, err := services.PostIUDXPolicy(pctx, client, s.cfg.IUDXAPDPolicyURL, caller.token, policy)
			cancel()
			if err != nil {
				log.Printf("[JOB-APPROVAL] job=%s: IUDX policy for dataset %s not posted: %v", jobID, e.Item, err)
				res.Status, res.Error = "failed", err.Error()
			} else {
				res.PolicyID = policyID
				log.Printf("[JOB-APPROVAL] job=%s: IUDX policy posted for dataset %s (id=%q)", jobID, e.Item, policyID)
			}
			results = append(results, res)
			break
		}
	}
	return results
}

// jobContractHash is the contract_hash stored with a job's contract at
// POST /generate-contract, cross-checked against a fresh hash of the stored
// contract so an edit made since is refused. Contracts stored before the hash
// was kept with them have none; their fresh hash stands in.
func jobContractHash(c *contract.Contract) (string, error) {
	hash, err := contract.ComputeHash(*c)
	if err != nil {
		return "", fmt.Errorf("contract could not be hashed: %w", err)
	}
	if c.ContractHash != "" && c.ContractHash != hash {
		return "", fmt.Errorf("stored contract no longer matches its stored contract_hash %s (now %s)", c.ContractHash, hash)
	}
	return hash, nil
}

// signedJobContractHash is jobContractHash, except that a consumer edit made
// after the hash was stored (amendmentValid) still yields the stored
// contract_hash — the one the providers sign — so it needs no re-signing.
func (s *Server) signedJobContractHash(c *contract.Contract) (string, error) {
	if c.ContractHash != "" {
		if hash, err := contract.ComputeHash(*c); err == nil && hash != c.ContractHash && s.amendmentValid(c, hash) {
			return c.ContractHash, nil
		}
	}
	return jobContractHash(c)
}

// verifySubmittedSignature checks the caller's approval signature now: the
// submitted contract_hash must be the one stored with the job's contract
// (jobContractHash), and the signature over it must verify with the caller's
// registered public key (PUT /provider-keys/{role}).
func (s *Server) verifySubmittedSignature(ctx context.Context, c *contract.Contract, caller providerCaller, body approvalBody) error {
	hash, err := s.signedJobContractHash(c)
	if err != nil {
		return err
	}
	if body.ContractHash != hash {
		return fmt.Errorf("contract_hash %s is not this job's contract hash (%s): sign the contract_hash from your JOB_REQUEST", body.ContractHash, hash)
	}
	pub, err := s.publicKeys.PublicKey(ctx, caller.username)
	if err != nil {
		return fmt.Errorf("no registered public key for %s (PUT /provider-keys/{role} first): %w", caller.username, err)
	}
	if err := services.VerifyContractHashSignature(pub, hash, body.Signature); err != nil {
		return fmt.Errorf("signature does not verify with %s's registered public key: %w", caller.username, err)
	}
	return nil
}

// grantResult is one dataset's or infra's consumer grant in the approval
// response.
type grantResult struct {
	ItemType string `json:"item_type"` // "dataset" / "infra"
	ItemID   string `json:"item_id"`
	PolicyID string `json:"policy_id,omitempty"`
	Status   string `json:"status"` // "posted" / "failed"
	Error    string `json:"error,omitempty"`
}

// postConsumerGrants posts an APD consumer grant for each of the calling
// provider's items accepted in own (kind: data-provider -> their datasets,
// infra-provider -> their infras): the job's consumer may use that dataset /
// infra for this job/contract. Each provider's approval posts its own grants,
// independent of the other providers. A failed post doesn't undo the
// approval; it is reported, and calling the approval again retries it (the
// grant's policyId is fixed per job and item, so APD updates it in place).
func (s *Server) postConsumerGrants(ctx context.Context, kind, jobID string, c *contract.Contract, own []db.AuditEntry) []grantResult {
	client := s.http
	if client == nil {
		client = http.DefaultClient
	}
	base := services.ConsumerGrant{
		JobID:        jobID,
		ContractID:   c.ContractID,
		Consumer:     c.Parties.User.ID,
		ConsumerName: c.Parties.User.Name,
		ExpiresAt:    c.Lifecycle.ValidUntil,
	}
	grants := []services.ConsumerGrant{}
	for _, e := range own {
		if e.Status != db.AuditStatusAccepted || e.ProviderID == "" {
			continue
		}
		g := base
		g.ItemID, g.Provider = e.Item, e.ProviderID
		switch kind {
		case db.AuditTypeDataProvider:
			g.ItemType = services.GrantItemDataset
			for _, dp := range c.Parties.DataProviders {
				if partyProviderID(dp) == e.ProviderID && approvalItem(dp) == e.Item {
					g.ItemName = dp.DatasetName
					// The grant ends when the provider's consent does.
					if u := dp.Constraints.ConsentValidUntil; u != nil && (g.ExpiresAt.IsZero() || u.Before(g.ExpiresAt)) {
						g.ExpiresAt = *u
					}
				}
			}
		case db.AuditTypeInfraProvider:
			g.ItemType = services.GrantItemInfra
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

	results := []grantResult{}
	for _, g := range grants {
		res := grantResult{ItemType: g.ItemType, ItemID: g.ItemID, Status: "posted"}
		gctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		policyID, err := services.PostConsumerGrant(gctx, client, g)
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

// POST /job/approval/infra-provider — Authorization: Bearer <the infra
// provider's dev Keycloak token>, body {"job_id", "contract_hash",
// "signature"}. As for data providers, for the caller's own infras (see
// infraProviderApprovals); a caller who owns none of them gets 403.
func (s *Server) handleInfraProviderApproval(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.approverFromToken(w, r, "infra provider")
	if !ok {
		return
	}
	body, c, ok := s.loadApprovalJob(w, r)
	if !ok {
		return
	}
	jobID := body.JobID
	owners := infraOwners(c)
	if !slices.ContainsFunc(owners, func(o infraOwner) bool { return caller.owns(o.providerID) }) {
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "NOT_AN_INFRA_PROVIDER_ON_CONTRACT",
			"message": "the token's user owns none of this job's infras"})
		return
	}
	checked, err := s.checkedItems(reqCtx(r), jobID, db.AuditTypeInfraProvider)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if !requireSubmittedSignature(w, body) {
		return
	}
	entries := s.infraProviderApprovals(jobID, owners, caller, checked)

	// "approval" is the caller's own result, as for data providers.
	var own []db.AuditEntry
	for _, e := range entries {
		if caller.owns(e.ProviderID) {
			own = append(own, e)
		}
	}
	if resp, ok := s.recordJobApproval(w, r, db.AuditTypeInfraProvider, jobID, c, entries, own, caller, body); ok {
		s.markApprovalParticipants(reqCtx(r), db.ParticipantRoleInfraProvider, jobID, own, caller)
		writeJSON(w, http.StatusOK, resp)
	}
}

// checkedItems is the auditKey of every current audit entry of kind on jobID.
func (s *Server) checkedItems(ctx context.Context, jobID, kind string) (map[string]bool, error) {
	st, err := s.loadJobApprovalState(ctx, jobID)
	if err != nil {
		return nil, err
	}
	checked := map[string]bool{}
	for _, e := range st.Current {
		if e.Type == kind {
			checked[auditKey(e.ProviderID, e.Item)] = true
		}
	}
	return checked, nil
}

// checkCallerDatasets runs dataProviderApprovals for caller on jobID's
// contract, refusing (403) a caller who provides none of its datasets. On
// failure it has already written the response.
func (s *Server) checkCallerDatasets(w http.ResponseWriter, r *http.Request, jobID string, c *contract.Contract, caller providerCaller) ([]db.AuditEntry, bool) {
	if !slices.ContainsFunc(c.Parties.DataProviders, caller.is) {
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "NOT_A_DATA_PROVIDER_ON_CONTRACT",
			"message": "the token's user provides none of this job's datasets"})
		return nil, false
	}
	checked, err := s.checkedItems(reqCtx(r), jobID, db.AuditTypeDataProvider)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return nil, false
	}
	return s.dataProviderApprovals(reqCtx(r), jobID, c, caller, checked), true
}

// saveJobApproval appends entries to the audit table and returns the job's
// new approval state.
func (s *Server) saveJobApproval(ctx context.Context, kind, jobID string, entries []db.AuditEntry) (jobApprovalState, error) {
	if err := s.db.InsertAuditEntries(ctx, entries); err != nil {
		return jobApprovalState{}, fmt.Errorf("failed to write audit: %w", err)
	}
	st, err := s.loadJobApprovalState(ctx, jobID)
	if err != nil {
		return jobApprovalState{}, err
	}
	log.Printf("[JOB-APPROVAL] job=%s type=%s job_approval=%s (%d recorded)", jobID, kind, st.Approval, len(entries))
	return st, nil
}

// sealContract stores the contract_hash on a job's contract whose provider
// signatures all verified — the hash the providers were sent with their job
// requests and signed when approving. A job contract carries no governance
// signature. A no-op once the hash is stored (since /generate-contract
// stores it, only contracts from before then lack it).
func (s *Server) sealContract(ctx context.Context, c *contract.Contract) error {
	if c.ContractHash != "" {
		return nil
	}
	hash, err := contract.ComputeHash(*c)
	if err != nil {
		return err
	}
	c.ContractHash = hash
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if ok, err := s.db.UpdateContractByContractID(ctx, c.ContractID, raw); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("contract %s not found", c.ContractID)
	}
	log.Printf("[JOB-APPROVAL] Job %s approved: contract %s hash %s stored", c.JobID, c.ContractID, hash)
	return nil
}

// recordJobApproval stores the caller's submitted signature on their own
// items accepted in own (signApprovedItems), records the approval
// (saveJobApproval) and returns the detailed response, whose "approval" is the
// caller's own result, for the caller to write. On failure it has already
// written the error response.
func (s *Server) recordJobApproval(w http.ResponseWriter, r *http.Request, kind, jobID string, c *contract.Contract, entries, own []db.AuditEntry, caller providerCaller, body approvalBody) (j, bool) {
	signed, err := s.signApprovedItems(reqCtx(r), kind, c, own, caller.username, body.ContractHash, body.Signature)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": "failed to store the signature: " + err.Error()})
		return nil, false
	}
	st, err := s.saveJobApproval(reqCtx(r), kind, jobID, entries)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return nil, false
	}
	resp := jobApprovalResponse(kind, jobID, overallStatus(own), st, entries)
	sig := j{"submitted": signed > 0, "contract_hash": body.ContractHash, "items_signed": signed,
		"verified_at": "GET /job/" + jobID + "/status"}
	if kind == db.AuditTypeDataProvider && signed > 0 {
		// verified before recording (handleDataProviderApproval)
		sig["verified"] = true
	}
	resp["signature"] = sig
	return resp, true
}

// finalizeJob makes an approved job's contract final once its hash and every
// signature on it — each data and infra provider's, made when approving —
// verify (verifyContractSignatures): it creates the
// job's final contract (final_contracts) and marks the contracts row final.
// Otherwise it returns what's still pending and creates nothing. Idempotent:
// a final contract, once created, is never replaced.
func (s *Server) finalizeJob(ctx context.Context, jobID string, c *contract.Contract) (bool, []string, error) {
	parties, hashOK, allValid := s.verifyContractSignatures(ctx, c)
	if !allValid {
		var pending []string
		if !hashOK {
			pending = append(pending, "contract no longer matches its hash")
		}
		if !s.governanceSignatureOK(c, c.ContractHash) {
			pending = append(pending, "governance signature missing or invalid")
		}
		for _, p := range parties {
			if !p.Valid {
				pending = append(pending, partyLabel(p)+": "+p.Error)
			}
		}
		return false, pending, nil
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return false, nil, err
	}
	created, err := s.db.CreateFinalContract(ctx, jobID, c.ContractID, c.ContractHash, raw)
	if err != nil {
		return false, nil, fmt.Errorf("final contract could not be stored: %w", err)
	}
	if created {
		log.Printf("[JOB-APPROVAL] Job %s: final contract created (contract %s, hash %s)", jobID, c.ContractID, c.ContractHash)
	}
	first, err := s.db.MarkJobFinal(ctx, jobID)
	if err != nil {
		return false, nil, err
	}
	if first {
		log.Printf("[JOB-APPROVAL] Job %s: contract %s is final (all %d provider signatures + governance signature verified)", jobID, c.ContractID, len(parties))
	}
	return true, nil, nil
}

// jobApprovalResponse is the body of the POST /job/approval/* calls.
func jobApprovalResponse(kind, jobID, approval string, st jobApprovalState, entries []db.AuditEntry) j {
	return j{
		"status":         "SUCCESS",
		"job_id":         jobID,
		"type":           kind,
		"approval":       approval,
		"data_provider":  st.DataProvider,
		"infra_provider": st.InfraProvider,
		"job_approval":   st.Approval,
		"entries":        entries,
	}
}

// GET /job/{jobId}/status — Authorization: Bearer <the consumer's dev
// Keycloak token>: the user who generated the contract (its parties.user.id
// is their token's sub); anyone else gets 403. The governance layer's
// cross-verification of the job:
//
//  1. every data and infra provider has approved (their role and catalogue
//     checks, recorded with their own token at POST /job/approval/*), and
//  2. every provider's submitted contract hash is the hash of gov_layer's copy
//     of the contract and their signature over it verifies with their
//     registered public key (verifyJobSignatures).
//
// If both hold, the job's status is approved and only then is its final
// contract created: with its contract_hash (sealContract) and every provider
// signature on it verified, it is stored in final_contracts (finalizeJob).
// No governance signature is added. The APD consumer grants for every dataset and infra are
// posted after that (postConsumerGrants): {"status": "approved",
// "final_contract": true, "final_contract_record": {...}, ...}. Otherwise
// {"status": "not approved", "reasons": [...]} and nothing is created.
// Re-callable: once approved, it re-verifies, returns the same final
// contract and re-posts the grants (APD updates them in place).
func (s *Server) getJobStatus(w http.ResponseWriter, r *http.Request) {
	_, claims, ok := s.devTokenClaims(w, r, "consumer")
	if !ok {
		return
	}
	jobID := chi.URLParam(r, "jobId")
	c, ok := s.loadContractByJob(w, r, jobID)
	if !ok {
		return
	}
	if sub, _ := claims["sub"].(string); sub == "" || !strings.EqualFold(sub, c.Parties.User.ID) {
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "NOT_JOB_CONSUMER",
			"message": "only the user who generated this job's contract can check its status"})
		return
	}
	ctx := reqCtx(r)
	st, err := s.loadJobApprovalState(ctx, jobID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if !st.accepted() {
		writeJSON(w, http.StatusOK, j{"status": "not approved", "reasons": approvalReasons(st)})
		return
	}
	parties, reasons := s.verifyJobSignatures(ctx, c)
	if len(reasons) > 0 {
		log.Printf("[JOB-STATUS] job=%s not approved: %s", jobID, strings.Join(reasons, "; "))
		writeJSON(w, http.StatusOK, j{"status": "not approved", "reasons": reasons, "signatures": parties})
		return
	}

	// Approvals, hash and signatures all hold: the job is approved. Only now
	// is its final contract created.
	c.JobID = jobID
	if err := s.sealContract(ctx, c); err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": "contract hash could not be stored: " + err.Error()})
		return
	}
	final, pending, err := s.finalizeJob(ctx, jobID, c)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	var finalRecord *db.FinalContract
	if final {
		s.markJobParticipants(ctx, jobID, db.ParticipantStatusFinal)
		if finalRecord, err = s.db.GetFinalContract(ctx, jobID); err != nil {
			writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
			return
		}
	}

	grants := []grantResult{}
	for _, kind := range []string{db.AuditTypeDataProvider, db.AuditTypeInfraProvider} {
		var accepted []db.AuditEntry
		for _, e := range st.Current {
			if e.Type == kind {
				accepted = append(accepted, e)
			}
		}
		grants = append(grants, s.postConsumerGrants(ctx, kind, jobID, c, accepted)...)
	}
	writeJSON(w, http.StatusOK, j{
		"status":                 "approved",
		"contract_hash":          c.ContractHash,
		"signatures":             parties,
		"grants":                 grants,
		"final_contract":         final,
		"final_contract_record":  finalRecord,
		"final_contract_pending": pending,
	})
}

// approvalReasons lists why a job isn't approved yet: every provider/item
// whose current approval isn't accepted, with its reason.
func approvalReasons(st jobApprovalState) []string {
	reasons := []string{}
	for _, e := range st.Current {
		if e.Status != db.AuditStatusAccepted {
			reasons = append(reasons, fmt.Sprintf("%s %s / %s: %s", e.Type, e.ProviderID, e.Item, e.Reason))
		}
	}
	if st.DataProvider == "pending" {
		reasons = append(reasons, "no data provider has approved yet")
	}
	if st.infraRequired && st.InfraProvider == "pending" {
		reasons = append(reasons, "no infra provider has approved yet")
	}
	return reasons
}

// verifyJobSignatures cross-verifies every provider's submitted signature on
// an approved job's contract: each must be over gov_layer's own hash of the
// contract and verify with the signer's registered public key, and an infra's
// signer must be its owner. Returns each party's result and, if any fails,
// the reasons.
func (s *Server) verifyJobSignatures(ctx context.Context, c *contract.Contract) ([]partySignatureStatus, []string) {
	hash, err := s.signedJobContractHash(c)
	if err != nil {
		return nil, []string{err.Error()}
	}
	owners := map[string]string{}
	for _, o := range infraOwners(c) {
		owners[o.infraID] = o.providerID
	}
	parties, allValid := s.providerSignatures(ctx, c, hash, true, owners)
	var reasons []string
	if !allValid {
		for _, p := range parties {
			if !p.Valid {
				reasons = append(reasons, partyLabel(p)+": "+p.Error)
			}
		}
	}
	return parties, reasons
}
