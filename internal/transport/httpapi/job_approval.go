// Job approvals over HTTP. The rules and the use cases live in
// application/jobapproval; this file reads the caller's token and the
// request, calls one use case and writes its result:
//
//   - POST /job/approval/data-provider — Authorization: Bearer <the data
//     provider's dev Keycloak token>, body {"job_id", "contract_hash",
//     "signature"} (Service.ApproveAsDataProvider).
//   - POST /job/approval/infra-provider — the same, for an infra provider's
//     own infras (Service.ApproveAsInfraProvider).
//   - GET /job/{jobId}/status — Authorization: Bearer <the consumer's dev
//     Keycloak token>: the governance layer's cross-verification of the job,
//     which makes its contract final once every approval and signature holds
//     (Service.JobStatus).
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/application/jobapproval"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/apd"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/catalogue"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/keycloak"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// infraOwner is one selected infra on a contract and its owning provider.
type infraOwner = jobapproval.InfraOwner

// infraProviderRole is the (DX) realm role an infra's provider must hold.
const infraProviderRole = jobapproval.InfraProviderRole

// approvals is the job-approval use cases, wired to s's database, catalogues,
// APD and signature checks.
func (s *Server) approvals() *jobapproval.Service {
	return &jobapproval.Service{
		Repo:                 s.db,
		Catalogue:            approvalCatalogue{s},
		APD:                  approvalAPD{s},
		Keys:                 s.publicKeys,
		Signatures:           approvalSignatures{s},
		RequireInfraApproval: s.cfg == nil || s.cfg.RequireInfraApproval,
		DataProviderRole:     s.dataProviderRole(),
	}
}

// jobApprovalRequired reports whether c goes through job approval
// (jobapproval.Required).
func (s *Server) jobApprovalRequired(c *contract.Contract) bool {
	return jobapproval.Required(c)
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

// approver is c as the job-approval use cases see it.
func (c providerCaller) approver() jobapproval.Caller {
	return jobapproval.Caller{Token: c.token, Username: c.username, UserID: c.userID, Names: c.names, Roles: c.roles}
}

// is reports whether dp is one of the caller's datasets.
func (c providerCaller) is(dp contract.DataProviderParty) bool { return c.approver().Is(dp) }

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
	// Dev Keycloak first (Postman), then the Keycloak p3dx-aaa's UI users log
	// in through (PROVIDER_KEY_JWKS_URL), so both kinds of token work.
	var token *jwt.Token
	var err error
	for _, jwksURL := range []string{s.cfg.DataProviderJWKSURL, s.cfg.ProviderKeyJWKSURL} {
		if jwksURL == "" {
			continue
		}
		if token, err = keycloak.ValidateAccessTokenAt(tokenStr, jwksURL); err == nil && token.Valid {
			break
		}
	}
	if err != nil || token == nil || !token.Valid {
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

// dataProviderRole is the realm role a dataset's provider must hold
// (DATA_PROVIDER_ROLE, the DX "provider" role by default).
func (s *Server) dataProviderRole() string {
	if s.cfg != nil && s.cfg.DataProviderRole != "" {
		return s.cfg.DataProviderRole
	}
	return devProviderRole
}

func (s *Server) lookupCatalogueItem(ctx context.Context, itemID, token string) (catalogue.DXCatalogueItem, error) {
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
	return catalogue.FetchDXCatalogueItem(ctx, client, baseURL, itemID, token)
}

// sendSignRequestsOnce sends c's sign requests unless they already went out
// for this job. Returns how many were sent (0 if already sent).
func (s *Server) sendSignRequestsOnce(ctx context.Context, c contract.Contract, sender string) int {
	if c.JobID != "" {
		first, err := s.approvals().MarkSignRequestsSent(ctx, c.JobID)
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

// loadContractByJob loads the contract stored for jobID, writing the error
// response itself when it can't.
func (s *Server) loadContractByJob(w http.ResponseWriter, r *http.Request, jobID string) (*contract.Contract, bool) {
	c, err := s.approvals().Contract(reqCtx(r), jobID)
	if err != nil {
		writeApprovalError(w, err)
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
}

// POST /job/approval/data-provider (Service.ApproveAsDataProvider).
func (s *Server) handleDataProviderApproval(w http.ResponseWriter, r *http.Request) {
	s.handleApproval(w, r, "data provider", s.approvals().ApproveAsDataProvider)
}

// POST /job/approval/infra-provider (Service.ApproveAsInfraProvider).
func (s *Server) handleInfraProviderApproval(w http.ResponseWriter, r *http.Request) {
	s.handleApproval(w, r, "infra provider", s.approvals().ApproveAsInfraProvider)
}

// handleApproval reads the caller's token (whose is named in the
// missing-token message) and the approval body, runs approve and writes its
// result.
func (s *Server) handleApproval(w http.ResponseWriter, r *http.Request, whose string,
	approve func(context.Context, jobapproval.Caller, jobapproval.Input) (*jobapproval.Result, error)) {
	tokenStr, claims, ok := s.devTokenClaims(w, r, whose)
	if !ok {
		return
	}
	var body approvalBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "BAD_REQUEST", "message": "Invalid request body"})
		return
	}
	res, err := approve(reqCtx(r), callerFromClaims(tokenStr, claims).approver(),
		jobapproval.Input{JobID: body.JobID, ContractHash: body.ContractHash, Signature: body.Signature})
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, jobApprovalResponse(res))
}

// jobApprovalResponse is the body of the POST /job/approval/* calls.
func jobApprovalResponse(res *jobapproval.Result) j {
	sig := j{"submitted": res.Signed > 0, "contract_hash": res.ContractHash, "items_signed": res.Signed,
		"verified_at": "GET /job/" + res.JobID + "/status"}
	if res.Kind == postgres.AuditTypeDataProvider && res.Signed > 0 {
		// verified before recording (Service.ApproveAsDataProvider)
		sig["verified"] = true
	}
	resp := j{
		"status":         "SUCCESS",
		"job_id":         res.JobID,
		"type":           res.Kind,
		"approval":       res.Approval,
		"data_provider":  res.State.DataProvider,
		"infra_provider": res.State.InfraProvider,
		"job_approval":   res.State.Approval,
		"entries":        res.Entries,
		"signature":      sig,
	}
	if res.Kind == postgres.AuditTypeDataProvider {
		resp["grants"] = res.Grants
	}
	return resp
}

// GET /job/{jobId}/status (Service.JobStatus). Only the user who generated
// the contract (its parties.user.id is their token's sub) may call it:
// {"status": "approved", "final_contract": true, "final_contract_record":
// {...}, ...} once every approval and signature holds, otherwise
// {"status": "not approved", "reasons": [...]}.
func (s *Server) getJobStatus(w http.ResponseWriter, r *http.Request) {
	_, claims, ok := s.devTokenClaims(w, r, "consumer")
	if !ok {
		return
	}
	sub, _ := claims["sub"].(string)
	st, err := s.approvals().JobStatus(reqCtx(r), chi.URLParam(r, "jobId"), sub)
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	if !st.Approved {
		resp := j{"status": "not approved", "reasons": st.Reasons}
		if st.SignaturesChecked {
			resp["signatures"] = st.Signatures
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	writeJSON(w, http.StatusOK, j{
		"status":                 "approved",
		"contract_hash":          st.ContractHash,
		"signatures":             st.Signatures,
		"grants":                 st.Grants,
		"final_contract":         st.Final,
		"final_contract_record":  st.FinalRecord,
		"final_contract_pending": st.Pending,
	})
}

// writeApprovalError writes the response for an error from a job-approval
// use case: its refusals map to their status and code, anything else is
// internal.
func writeApprovalError(w http.ResponseWriter, err error) {
	status, code := http.StatusInternalServerError, "INTERNAL_ERROR"
	var sigErr *jobapproval.SignatureError
	switch {
	case errors.As(err, &sigErr):
		status, code = http.StatusBadRequest, "INVALID_SIGNATURE"
	case errors.Is(err, jobapproval.ErrJobIDRequired):
		status, code = http.StatusBadRequest, "BAD_REQUEST"
	case errors.Is(err, jobapproval.ErrNoContract):
		status, code = http.StatusNotFound, "NOT_FOUND"
	case errors.Is(err, jobapproval.ErrNoApprovalNeeded):
		status, code = http.StatusBadRequest, "NO_APPROVAL_NEEDED"
	case errors.Is(err, jobapproval.ErrNotDataProvider):
		status, code = http.StatusForbidden, "NOT_A_DATA_PROVIDER_ON_CONTRACT"
	case errors.Is(err, jobapproval.ErrNotInfraProvider):
		status, code = http.StatusForbidden, "NOT_AN_INFRA_PROVIDER_ON_CONTRACT"
	case errors.Is(err, jobapproval.ErrMissingSignature):
		status, code = http.StatusBadRequest, "MISSING_FIELDS"
	case errors.Is(err, jobapproval.ErrNotConsumer):
		status, code = http.StatusForbidden, "NOT_JOB_CONSUMER"
	}
	writeJSON(w, status, j{"status": "FAILED", "error": code, "message": err.Error()})
}

// approvalCatalogue is jobapproval.Catalogue over the DX catalogue
// (CATALOGUE_BASE_URL) and the providers' APD catalogues.
type approvalCatalogue struct{ s *Server }

func (a approvalCatalogue) Item(ctx context.Context, itemID, token string) (catalogue.DXCatalogueItem, error) {
	return a.s.lookupCatalogueItem(ctx, itemID, token)
}

func (approvalCatalogue) ProviderInfra(providerID string) ([]catalogue.APDCatalogueItem, error) {
	return catalogue.ListProviderInfra(providerID)
}

// approvalAPD is jobapproval.APD over p3dx-apd.
type approvalAPD struct{ s *Server }

func (approvalAPD) InfraPolicy(infraID string) (map[string]any, error) {
	return apd.FetchInfraPolicy(infraID)
}

func (a approvalAPD) PostConsumerGrant(ctx context.Context, g apd.ConsumerGrant) (string, error) {
	client := a.s.http
	if client == nil {
		client = http.DefaultClient
	}
	return apd.PostConsumerGrant(ctx, client, g)
}

// approvalSignatures is jobapproval.Signatures over the contract-signing
// checks (contract_signing.go).
type approvalSignatures struct{ s *Server }

func (a approvalSignatures) AmendmentValid(c *contract.Contract, hash string) bool {
	return a.s.amendmentValid(c, hash)
}

func (a approvalSignatures) ProviderSignatures(ctx context.Context, c *contract.Contract, hash string, infraOwnerIDs map[string]string) ([]jobapproval.PartySignature, bool) {
	return a.s.providerSignatures(ctx, c, hash, true, infraOwnerIDs)
}

func (a approvalSignatures) VerifyContract(ctx context.Context, c *contract.Contract) ([]jobapproval.PartySignature, bool, bool) {
	return a.s.verifyContractSignatures(ctx, c)
}

func (a approvalSignatures) GovernanceSignatureOK(c *contract.Contract, hash string) bool {
	return a.s.governanceSignatureOK(c, hash)
}
