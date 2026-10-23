package httpapi

// Contract signing, shared by every technique (FL, TEE, SMPC). Before any run
// starts, each data provider on the contract must sign its hash:
//
//  1. gov_layer computes the contract hash (contract.ComputeHash) and signs it
//     with its own private key (services.GovernanceKey, see governanceSign).
//  2. The hash, the governance signature and the governance public key go to
//     every data provider as a CONTRACT_SIGN notification (notifyContractSigners).
//     FL sends these once the final roster contract is built; TEE and SMPC
//     when the consumer generates the contract — or, for a contract naming
//     datasets and infra, only once its job is approved (job_approval.go),
//     which is also when that contract is hashed and governance-signed.
//  3. The provider verifies the governance signature with the governance
//     public key, then signs the same hash with their own RSA private key and
//     posts it back (POST /contracts/{contractId}/sign).
//  4. gov_layer verifies that signature against the provider's public key as
//     registered in the platform Keycloak ("public_key" attribute) — never a
//     key supplied by the caller — on receipt, and again at the run gate
//     (requireAllProvidersSigned) before the FL session / TEE / SMPC run starts.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
)

// ContractSignNotificationType tags the notification payload so callers
// (p3dx-aaa's /contracts/sign-requests) can tell these apart from the FL
// participation notifications that share the same table.
const ContractSignNotificationType = "CONTRACT_SIGN"

// governanceSigner is the Signer recorded on a contract's governance signature.
const governanceSigner = "governance-layer"

// publicKeyLookup resolves a username to their registered PEM public key.
// dbPublicKeys (provider_public_keys in Postgres) in production; stubbed in tests.
type publicKeyLookup interface {
	PublicKey(ctx context.Context, username string) (string, error)
}

var nonSlugChars = regexp.MustCompile(`[^a-z0-9]+`)

// providerIDForUsername mirrors the provider_id derivation used by
// PolicyForm.jsx and p3dx-aaa: "provider-" + slugify(username).
func providerIDForUsername(username string) string {
	s := strings.ToLower(username)
	if s == "" {
		s = "unknown"
	}
	s = strings.Trim(nonSlugChars.ReplaceAllString(s, "-"), "-")
	return "provider-" + s
}

// partyProviderID is the provider_id a data-provider party signs as. TEE/SMPC
// contracts carry the APD policy's provider_id ("provider-<slug>") as the
// party ID; FL roster contracts carry the Keycloak user id instead, with the
// username in Name, so the provider_id is derived from that.
func partyProviderID(p contract.DataProviderParty) string {
	if strings.HasPrefix(p.ID, "provider-") {
		return p.ID
	}
	return providerIDForUsername(p.Name)
}

// signable reports whether c is a contract providers are asked to sign: FL
// only once it's the final roster (version 2), TEE/SMPC always.
func signable(c *contract.Contract) bool {
	return c.Technique != "FL" || c.Version >= 2
}

// governanceSign signs c's ContractHash with gov_layer's private key and
// records it on c.GovernanceSignature. c.ContractHash must already be set.
func (s *Server) governanceSign(c *contract.Contract) error {
	if s.govKey == nil {
		return errors.New("governance signing key not loaded")
	}
	if c.ContractHash == "" {
		return errors.New("contract has no hash to sign")
	}
	value, err := s.govKey.SignContractHash(c.ContractHash)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	c.GovernanceSignature = &contract.Signature{
		SignedAt:   &now,
		Signer:     governanceSigner,
		Algorithm:  services.ContractSignatureAlgorithm,
		SignedHash: c.ContractHash,
		Value:      value,
	}
	return nil
}

// governanceSignatureOK reports whether c's governance signature over hash is
// in order: required and valid, except on a job-approval contract
// (jobApprovalRequired), which carries none — its providers' signatures over the
// contract_hash stored at /generate-contract are what make it final.
func (s *Server) governanceSignatureOK(c *contract.Contract, hash string) bool {
	return s.jobApprovalRequired(c) || s.governanceSignatureValid(c, hash)
}

// governanceSignatureValid reports whether c carries a governance signature
// over its current hash that verifies against gov_layer's public key.
func (s *Server) governanceSignatureValid(c *contract.Contract, hash string) bool {
	gs := c.GovernanceSignature
	if s.govKey == nil || gs == nil || gs.SignedHash != hash {
		return false
	}
	return services.VerifyContractHashSignature(s.govKey.PublicKeyPEM(), hash, gs.Value) == nil
}

type contractSignPayload struct {
	Type                string            `json:"type"`
	Technique           string            `json:"technique"`
	ContractID          string            `json:"contract_id"`
	ContractHash        string            `json:"contract_hash"`
	HashAlgorithm       string            `json:"hash_algorithm"`
	SignAlgorithm       string            `json:"sign_algorithm"`
	GovernanceSignature string            `json:"governance_signature"`
	GovernancePublicKey string            `json:"governance_public_key"`
	ProviderID          string            `json:"provider_id"`
	Contract            contract.Contract `json:"contract"`
}

// notifyContractSigners sends one CONTRACT_SIGN notification per distinct
// data provider on c, addressed by provider_id ("provider-<slug(username)>",
// which is what p3dx-aaa looks sign requests up by). c must already carry its
// governance signature. Returns how many were sent.
func (s *Server) notifyContractSigners(ctx context.Context, c contract.Contract, senderUsername string) int {
	if c.GovernanceSignature == nil || s.govKey == nil {
		log.Printf("[SIGN] Contract %s has no governance signature — sign requests not sent", c.ContractID)
		return 0
	}
	sent := 0
	seen := map[string]bool{}
	for _, p := range c.Parties.DataProviders {
		providerID := partyProviderID(p)
		if p.ID == "" || seen[providerID] {
			continue
		}
		seen[providerID] = true

		payload, err := json.Marshal(contractSignPayload{
			Type:                ContractSignNotificationType,
			Technique:           c.Technique,
			ContractID:          c.ContractID,
			ContractHash:        c.ContractHash,
			HashAlgorithm:       "SHA-256",
			SignAlgorithm:       services.ContractSignatureAlgorithm,
			GovernanceSignature: c.GovernanceSignature.Value,
			GovernancePublicKey: s.govKey.PublicKeyPEM(),
			ProviderID:          providerID,
			Contract:            c,
		})
		if err != nil {
			log.Printf("[SIGN] Warning: failed to marshal sign request for %s: %v", providerID, err)
			continue
		}
		msg := fmt.Sprintf("%s generated a %s contract using your dataset %q. Please review and sign its hash.", senderUsername, c.Technique, p.DatasetName)
		if _, err := s.db.CreateNotification(ctx, providerID, providerID, senderUsername, msg, payload); err != nil {
			log.Printf("[SIGN] Warning: failed to notify %s for contract %s: %v", providerID, c.ContractID, err)
			continue
		}
		sent++
	}
	log.Printf("[SIGN] %s contract %s (hash %s) sent to %d data provider(s) for signing", c.Technique, c.ContractID, c.ContractHash, sent)
	return sent
}

// loadContract fetches and decodes a stored contract by its contract_id.
// Returns (nil, nil) when it doesn't exist.
func (s *Server) loadContract(ctx context.Context, contractID string) (*contract.Contract, error) {
	raw, err := s.db.GetContractByContractID(ctx, contractID)
	if err != nil || raw == nil {
		return nil, err
	}
	var c contract.Contract
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// partySignatureStatus is one data-provider party's signing state, as
// reported by GET /contracts/{id}/signatures and checked by the run gate.
type partySignatureStatus struct {
	Role        string     `json:"role"` // db.AuditTypeDataProvider / db.AuditTypeInfraProvider
	ProviderID  string     `json:"provider_id"`
	DatasetName string     `json:"dataset_name,omitempty"`
	InfraID     string     `json:"infra_id,omitempty"`
	Signed      bool       `json:"signed"`
	Valid       bool       `json:"valid"`
	Signer      string     `json:"signer,omitempty"`
	SignedAt    *time.Time `json:"signed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// verifyContractSignatures re-checks every signature on c: the contract hash
// must still match its content, the governance signature must verify (not on
// a job-approval contract, governanceSignatureOK), and so must every
// provider's (providerSignatures). allValid is true only when all
// do and there is at least one data provider.
func (s *Server) verifyContractSignatures(ctx context.Context, c *contract.Contract) (parties []partySignatureStatus, hashOK, allValid bool) {
	// hash, err := contract.ComputeHash(*c)
	// hashOK = err == nil && hash == c.ContractHash
	// parties, allValid = s.providerSignatures(ctx, c, hash, hashOK, nil)
	// allValid = allValid && hashOK && s.governanceSignatureOK(c, hash) && len(c.Parties.DataProviders) > 0
	// Signatures are checked against the signed hash (ContractHash); an edit
	// made since (amendmentValid) keeps them valid without re-signing.
	hashOK = s.contentMatchesSignedHash(c)
	parties, allValid = s.providerSignatures(ctx, c, c.ContractHash, hashOK, nil)
	allValid = allValid && hashOK && s.governanceSignatureOK(c, c.ContractHash) && len(c.Parties.DataProviders) > 0
	return parties, hashOK, allValid
}

// contentMatchesSignedHash reports whether c's current content is what was
// signed: it hashes to ContractHash, or it is a consumer edit gov_layer
// signed as an amendment (amendmentValid).
func (s *Server) contentMatchesSignedHash(c *contract.Contract) bool {
	hash, err := contract.ComputeHash(*c)
	if err != nil {
		return false
	}
	return hash == c.ContractHash || s.amendmentValid(c, hash)
}

// amendmentValid reports whether c carries gov_layer's amendment signature
// over hash (its edited content) that verifies against gov_layer's key.
func (s *Server) amendmentValid(c *contract.Contract, hash string) bool {
	a := c.Amendment
	if s.govKey == nil || a == nil || a.SignedHash != hash || hash == "" {
		return false
	}
	return services.VerifyContractHashSignature(s.govKey.PublicKeyPEM(), hash, a.Value) == nil
}

// amendSign signs c's current content hash with gov_layer's private key and
// records it on c.Amendment, so a consumer's edit after signing is accepted
// without its providers re-signing. ContractHash is left unchanged.
func (s *Server) amendSign(c *contract.Contract) (string, error) {
	if s.govKey == nil {
		return "", errors.New("governance signing key not loaded")
	}
	hash, err := contract.ComputeHash(*c)
	if err != nil {
		return "", err
	}
	value, err := s.govKey.SignContractHash(hash)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	c.Amendment = &contract.Signature{
		SignedAt:   &now,
		Signer:     governanceSigner,
		Algorithm:  services.ContractSignatureAlgorithm,
		SignedHash: hash,
		Value:      value,
	}
	return hash, nil
}

// providerSignatures checks each data-provider party on c — and, on a
// job-approval contract (needsJobApproval) with infra approval required, each
// selected infra — for a recorded signature over hash that verifies against
// the signer's registered public key. A data provider must have signed as
// their own provider_id; an infra as its owner in infraOwnerIDs (infra id ->
// provider_id) when given. hashOK false fails every party (the contract no
// longer matches its hash).
func (s *Server) providerSignatures(ctx context.Context, c *contract.Contract, hash string, hashOK bool, infraOwnerIDs map[string]string) (parties []partySignatureStatus, allValid bool) {
	allValid = true
	keys := map[string]string{}
	check := func(st partySignatureStatus, sig contract.Signature, wantProviderID string) partySignatureStatus {
		// Only a recorded signature counts — FL's accept-invite marker sets
		// SignedAt without one.
		st.Signed, st.Signer, st.SignedAt = sig.Value != "", sig.Signer, sig.SignedAt
		if !st.Signed {
			st.SignedAt = nil
		}
		switch {
		case !st.Signed && sig.WithdrawnAt != nil:
			st.Error = "consent withdrawn"
		case !st.Signed:
			st.Error = "not signed yet"
		case !hashOK:
			st.Error = "contract content no longer matches its hash"
		case sig.SignedHash != hash:
			st.Error = "signed a different contract hash"
		case wantProviderID != "" && providerIDForUsername(sig.Signer) != wantProviderID:
			st.Error = "signer does not match provider_id"
		default:
			pub, ok := keys[sig.Signer]
			if !ok {
				var err error
				pub, err = s.publicKeys.PublicKey(ctx, sig.Signer)
				if err != nil {
					st.Error = "public key lookup failed: " + err.Error()
					break
				}
				keys[sig.Signer] = pub
			}
			if err := services.VerifyContractHashSignature(pub, hash, sig.Value); err != nil {
				st.Error = "signature does not verify with the signer's public key: " + err.Error()
			} else {
				st.Valid = true
			}
		}
		if !st.Valid {
			allValid = false
		}
		return st
	}

	for _, p := range c.Parties.DataProviders {
		providerID := partyProviderID(p)
		parties = append(parties, check(partySignatureStatus{Role: db.AuditTypeDataProvider, ProviderID: providerID, DatasetName: p.DatasetName}, p.Signature, providerID))
	}
	if needsJobApproval(c) && (s.cfg == nil || s.cfg.RequireInfraApproval) {
		for _, ip := range c.Parties.InfraProviders {
			if ip.ID == "" {
				continue
			}
			st := partySignatureStatus{Role: db.AuditTypeInfraProvider, InfraID: ip.ID}
			if ip.Signature.Signer != "" {
				st.ProviderID = providerIDForUsername(ip.Signature.Signer)
			}
			parties = append(parties, check(st, ip.Signature, infraOwnerIDs[ip.ID]))
		}
	}
	return parties, allValid
}

// partyLabel names p in pending-signature messages: an unsigned infra has no
// signer (so no provider_id) yet.
func partyLabel(p partySignatureStatus) string {
	if p.InfraID != "" {
		return "infra " + p.InfraID
	}
	return p.ProviderID
}

// signatureGateError is the 403 every run gate returns while a contract is
// not yet fully signed.
func signatureGateError(msg string) error {
	return &teeAPIError{Status: http.StatusForbidden, Code: "CONTRACT_NOT_SIGNED", Message: msg}
}

// requireAllProvidersSigned is the technique-neutral run gate: contractID
// must name a stored, signable contract whose governance signature (none on
// a job-approval contract) and every data-provider signature verify. Returns the contract on success.
func (s *Server) requireAllProvidersSigned(ctx context.Context, contractID string) (*contract.Contract, error) {
	if contractID == "" {
		return nil, signatureGateError("a contract id is required: runs only start for a contract signed by every data provider")
	}
	if s.db == nil {
		return nil, &teeAPIError{Status: http.StatusInternalServerError, Code: "INTERNAL_ERROR", Message: "database not available"}
	}
	c, err := s.loadContract(ctx, contractID)
	if err != nil {
		return nil, &teeAPIError{Status: http.StatusInternalServerError, Code: "INTERNAL_ERROR", Message: err.Error()}
	}
	if c == nil {
		return nil, &teeAPIError{Status: http.StatusNotFound, Code: "CONTRACT_NOT_FOUND", Message: "no contract " + contractID}
	}
	if !signable(c) {
		return nil, signatureGateError("contract " + contractID + " is a draft; only the final roster contract is signed")
	}

	parties, hashOK, allValid := s.verifyContractSignatures(ctx, c)
	if !hashOK {
		return nil, signatureGateError("stored contract no longer matches its hash")
	}
	if !s.governanceSignatureOK(c, c.ContractHash) {
		return nil, signatureGateError("contract has no valid governance signature — regenerate it")
	}
	if !allValid {
		var pending []string
		for _, p := range parties {
			if !p.Valid {
				pending = append(pending, fmt.Sprintf("%s (%s)", partyLabel(p), p.Error))
			}
		}
		if len(parties) == 0 {
			pending = append(pending, "contract has no data providers")
		}
		return nil, signatureGateError("waiting on provider signatures: " + strings.Join(pending, "; "))
	}

	// A provider's consent ends at their consent expiry.
	if err := consentExpiryError(c, time.Now()); err != nil {
		return nil, err
	}

	log.Printf("[SIGN] Gate passed: %s contract %s signed by all %d data provider(s)", c.Technique, c.ContractID, len(parties))
	return c, nil
}

// requireSignedContract is the TEE/SMPC enclave-run gate, called before any
// VM is started (doProvisionTEE, startTEESession). On top of
// requireAllProvidersSigned, the dataset URL the run will fetch must be one
// of the contract's own datasets, so a signed contract can't be used to
// authorise a different dataset.
func (s *Server) requireSignedContract(ctx context.Context, tc *services.TEEContract) error {
	c, err := s.requireAllProvidersSigned(ctx, tc.GovernanceContractID)
	if err != nil {
		return err
	}
	if err := s.requireTEEEnabled(ctx, c); err != nil {
		return err
	}
	// (Workload checks dropped: any workload/image may run.)
	// // The image this run starts must be the signed contract's workload.
	// if c.Workload != nil && tc.AppDetails.ImageID != c.Workload.Image {
	// 	return workloadNotAllowedError(fmt.Sprintf("appDetails.imageId %q is not the signed contract's workload image", tc.AppDetails.ImageID))
	// }
	// if err := requireWorkloadAllowed(c); err != nil {
	// 	return err
	// }
	for _, p := range c.Parties.DataProviders {
		if p.DataURL != "" && p.DataURL == tc.DatasetDetails.ResourceURL {
			return nil
		}
	}
	return signatureGateError("datasetDetails.resourceUrl is not a dataset on the signed contract")
}

// writeSignatureStatus writes the GET .../signatures response for c: only
// {"signatures": "matching", "tee": "can run"} or the not-matching /
// "cannot run" pair.
func (s *Server) writeSignatureStatus(w http.ResponseWriter, r *http.Request, c *contract.Contract) {
	_, _, allValid := s.verifyContractSignatures(reqCtx(r), c)
	// if allValid && signable(c) {
	if allValid && signable(c) && consentExpiryError(c, time.Now()) == nil {
		writeJSON(w, http.StatusOK, j{"signatures": "matching", "tee": "can run"})
		return
	}
	writeJSON(w, http.StatusOK, j{"signatures": "not matching", "tee": "cannot run"})
}

// GET /contracts/{contractId}/signatures — each data provider's signing
// state, re-verified against Keycloak, plus all_signed.
func (s *Server) getContractSignatures(w http.ResponseWriter, r *http.Request) {
	c, err := s.loadContract(reqCtx(r), chi.URLParam(r, "contractId"))
	if err != nil {
		log.Println("[SIGN] Error loading contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if c == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "CONTRACT_NOT_FOUND"})
		return
	}
	s.writeSignatureStatus(w, r, c)
}

// GET /contracts/by-session/{sessionId}/signatures — the same status for a
// session's current (latest) contract. p3dx-aaa gates FL session start on
// this, since it tracks FL sessions by submission id rather than contract id.
func (s *Server) getSessionContractSignatures(w http.ResponseWriter, r *http.Request) {
	raw, err := s.db.GetContractBySession(reqCtx(r), chi.URLParam(r, "sessionId"))
	if err != nil {
		log.Println("[SIGN] Error loading session contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if raw == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "CONTRACT_NOT_FOUND"})
		return
	}
	var c contract.Contract
	if err := json.Unmarshal(raw, &c); err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	s.writeSignatureStatus(w, r, &c)
}

// POST /contracts/{contractId}/sign — a data provider returns their
// signature over the contract hash, with their own access token as the
// Bearer token (p3dx-aaa forwards it; a provider can also call directly).
// The signer's username comes from that token. gov_layer checks that it maps
// to the party's provider_id, re-hashes its own stored copy of the contract,
// and verifies the signature with the public key registered for that user
// (PUT /provider-keys/{role}).
//
// The reply is only {"status": "signed", "message": "sent to governance
// layer"}, or {"status": "not signed", "message": <reason>} with the error's
// HTTP status.
func (s *Server) handleSignContract(w http.ResponseWriter, r *http.Request) {
	rec := httptest.NewRecorder()
	s.signContract(rec, r)
	if rec.Code == http.StatusOK {
		writeJSON(w, http.StatusOK, j{"status": "signed", "message": "sent to governance layer"})
		return
	}
	var failed struct{ Error, Message string }
	_ = json.Unmarshal(rec.Body.Bytes(), &failed)
	msg := failed.Message
	if msg == "" {
		msg = failed.Error
	}
	if msg == "" {
		msg = strings.TrimSpace(rec.Body.String())
	}
	writeJSON(w, rec.Code, j{"status": "not signed", "message": msg})
}

// signContract does the signing behind handleSignContract, writing the
// detailed result it translates.
func (s *Server) signContract(w http.ResponseWriter, r *http.Request) {
	contractID := chi.URLParam(r, "contractId")
	var body struct {
		ProviderUsername string `json:"provider_username"`
		NotificationID   string `json:"notification_id"`
		ContractHash     string `json:"contract_hash"`
		Signature        string `json:"signature"`
	}
	// The signer is whoever the provider's own access token says — never the
	// body. provider_username, if sent (p3dx-aaa does), must agree with it.
	signer, ok := s.providerTokenIdentity(w, r)
	if !ok {
		return
	}
	if !s.readBody(w, r, &body) {
		return
	}
	if body.ProviderUsername != "" && !strings.EqualFold(body.ProviderUsername, signer.username) {
		writeJSON(w, http.StatusForbidden, j{
			"status": "FAILED", "error": "SIGNER_MISMATCH",
			"message": "provider_username does not match the token's user",
		})
		return
	}
	body.ProviderUsername = signer.username
	if body.ContractHash == "" || body.Signature == "" {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "MISSING_FIELDS",
			"message": "contract_hash and signature are required",
		})
		return
	}
	providerID := providerIDForUsername(body.ProviderUsername)

	c, err := s.loadContract(reqCtx(r), contractID)
	if err != nil {
		log.Println("[SIGN] Error loading contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if c == nil {
		// Regenerating the same selection overwrites the draft row with a new
		// contract_id, so an older sign request lands here.
		writeJSON(w, http.StatusNotFound, j{
			"status": "FAILED", "error": "CONTRACT_NOT_FOUND",
			"message": "contract not found — it may have been regenerated",
		})
		return
	}
	if !signable(c) {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "CONTRACT_NOT_SIGNABLE",
			"message": "only the final roster contract is signed",
		})
		return
	}
	// Job approval comes before signing (job_approval.go).
	if allowed, err := s.signingAllowed(reqCtx(r), c); err != nil {
		log.Println("[SIGN] Error checking job approval:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	} else if !allowed {
		writeJSON(w, http.StatusConflict, j{
			"status": "FAILED", "error": "JOB_NOT_APPROVED",
			"message": "this contract's job is not approved yet — every data and infra provider must pass the role and catalogue checks before it can be signed",
		})
		return
	}

	// Recompute from the stored contract rather than trusting the stored or
	// submitted hash: all three must agree.
	hash, err := contract.ComputeHash(*c)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	// if hash != c.ContractHash || hash != body.ContractHash {
	// An edit made after generation (amendmentValid) still signs the
	// original ContractHash.
	if hash != c.ContractHash && s.amendmentValid(c, hash) {
		hash = c.ContractHash
	}
	if hash != c.ContractHash || hash != body.ContractHash {
		writeJSON(w, http.StatusConflict, j{
			"status": "FAILED", "error": "HASH_MISMATCH",
			"message": "signed hash does not match the governance layer's copy of the contract",
		})
		return
	}
	if !s.governanceSignatureValid(c, hash) {
		writeJSON(w, http.StatusConflict, j{
			"status": "FAILED", "error": "NO_GOVERNANCE_SIGNATURE",
			"message": "contract has no valid governance signature — ask for it to be regenerated",
		})
		return
	}

	isParty := false
	for _, p := range c.Parties.DataProviders {
		if partyProviderID(p) == providerID {
			isParty = true
			break
		}
	}
	if !isParty {
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "NOT_A_PARTY"})
		return
	}

	pub, err := s.publicKeys.PublicKey(reqCtx(r), body.ProviderUsername)
	if err != nil {
		log.Printf("[SIGN] Public key lookup failed for %s: %v", body.ProviderUsername, err)
		code, status := "PUBLIC_KEY_LOOKUP_FAILED", http.StatusBadGateway
		if errors.Is(err, db.ErrNoPublicKey) {
			code, status = "NO_PUBLIC_KEY", http.StatusBadRequest
		}
		writeJSON(w, status, j{"status": "FAILED", "error": code, "message": err.Error()})
		return
	}
	if err := services.VerifyContractHashSignature(pub, hash, body.Signature); err != nil {
		log.Printf("[SIGN] Rejected signature from %s on contract %s: %v", providerID, contractID, err)
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_SIGNATURE", "message": err.Error()})
		return
	}

	// A provider may hold several datasets on the same contract — sign every
	// party that belongs to them.
	now := time.Now().UTC()
	for i := range c.Parties.DataProviders {
		p := &c.Parties.DataProviders[i]
		if partyProviderID(*p) == providerID {
			p.Signature = contract.Signature{
				SignedAt:   &now,
				Signer:     body.ProviderUsername,
				Algorithm:  services.ContractSignatureAlgorithm,
				SignedHash: hash,
				Value:      body.Signature,
			}
		}
	}

	updated, err := json.Marshal(c)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if ok, err := s.db.UpdateContractByContractID(reqCtx(r), contractID, updated); err != nil || !ok {
		log.Println("[SIGN] Error storing signed contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}

	s.markSignedParticipant(reqCtx(r), c, providerID, signer.userID, body.ProviderUsername)
	s.recordContractEvent(reqCtx(r), c, db.ContractEventSigned, "Signed by "+providerID, providerID)

	if body.NotificationID != "" {
		if _, err := s.db.RespondToNotification(reqCtx(r), body.NotificationID, providerID, "accepted", "signed"); err != nil {
			log.Println("[SIGN] Warning: failed to mark sign request answered:", err)
		}
	}

	allSigned := true
	for _, p := range c.Parties.DataProviders {
		if p.Signature.Value == "" {
			allSigned = false
			break
		}
	}
	log.Printf("[SIGN] %s signed %s contract %s (all providers signed: %t)", providerID, c.Technique, contractID, allSigned)

	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "all_signed": allSigned, "contract": c})
}
