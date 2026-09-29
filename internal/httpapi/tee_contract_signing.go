package httpapi

// This file is TEE-only: the contract-signing loop. When a consumer generates
// a TEE contract (handleGenerateContract), gov_layer hashes it
// (contract.ComputeHash) and sends the hash plus the contract to every
// participating data provider as a TEE_CONTRACT_SIGN notification. Each
// provider signs that hash with their own RSA private key and posts the
// signature back here. Signatures are always verified against the provider's
// public key as registered in the platform Keycloak ("public_key" attribute),
// never a key supplied by the caller — once on receipt, and again before any
// TEE is provisioned for the contract (requireSignedContract).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/userdir"
)

// TEEContractSignNotificationType tags the notification payload so callers
// (p3dx-aaa's /tee-contracts/sign-requests) can tell these apart from the FL
// participation notifications that share the same table.
const TEEContractSignNotificationType = "TEE_CONTRACT_SIGN"

// publicKeyLookup resolves a Keycloak username to their registered PEM public
// key. *userdir.Client in production; stubbed in tests.
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

type teeContractSignPayload struct {
	Type          string            `json:"type"`
	ContractID    string            `json:"contract_id"`
	ContractHash  string            `json:"contract_hash"`
	HashAlgorithm string            `json:"hash_algorithm"`
	SignAlgorithm string            `json:"sign_algorithm"`
	ProviderID    string            `json:"provider_id"`
	Contract      contract.Contract `json:"contract"`
}

// notifyTEEContractSigners sends one TEE_CONTRACT_SIGN notification per
// distinct data-provider party on c, addressed by provider_id (the APD
// policy's provider_id, "provider-<slug(username)>"). Returns how many were
// sent. Parties with no provider_id (no APD policy found) are skipped.
func (s *Server) notifyTEEContractSigners(ctx context.Context, c contract.Contract, senderUsername string) int {
	sent := 0
	seen := map[string]bool{}
	for _, p := range c.Parties.DataProviders {
		if p.ID == "" || seen[p.ID] {
			continue
		}
		seen[p.ID] = true

		payload, err := json.Marshal(teeContractSignPayload{
			Type:          TEEContractSignNotificationType,
			ContractID:    c.ContractID,
			ContractHash:  c.ContractHash,
			HashAlgorithm: "SHA-256",
			SignAlgorithm: services.ContractSignatureAlgorithm,
			ProviderID:    p.ID,
			Contract:      c,
		})
		if err != nil {
			log.Printf("[TEE-SIGN] Warning: failed to marshal sign request for %s: %v", p.ID, err)
			continue
		}
		msg := fmt.Sprintf("%s generated a TEE contract using your dataset %q. Please review and sign its hash.", senderUsername, p.DatasetName)
		if _, err := s.db.CreateNotification(ctx, p.ID, p.ID, senderUsername, msg, payload); err != nil {
			log.Printf("[TEE-SIGN] Warning: failed to notify %s for contract %s: %v", p.ID, c.ContractID, err)
			continue
		}
		sent++
	}
	log.Printf("[TEE-SIGN] Contract %s (hash %s) sent to %d data provider(s) for signing", c.ContractID, c.ContractHash, sent)
	return sent
}

// loadTEEContract fetches and decodes a stored generated contract by id.
// Returns (nil, nil) when it doesn't exist.
func (s *Server) loadTEEContract(ctx context.Context, contractID string) (*contract.Contract, error) {
	raw, err := s.db.GetContractByProjectID(ctx, contractID)
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
// reported by GET /tee-contracts/{id}/signatures and checked by
// requireSignedContract.
type partySignatureStatus struct {
	ProviderID  string     `json:"provider_id"`
	DatasetName string     `json:"dataset_name"`
	Signed      bool       `json:"signed"`
	Valid       bool       `json:"valid"`
	Signer      string     `json:"signer,omitempty"`
	SignedAt    *time.Time `json:"signed_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// verifyContractSignatures re-checks every data-provider party on c: the
// contract hash must still match its content, and each party's recorded
// signature must verify against the signer's current Keycloak public key.
// allValid is true only when there is at least one party and all are valid.
func (s *Server) verifyContractSignatures(ctx context.Context, c *contract.Contract) (parties []partySignatureStatus, hashOK, allValid bool) {
	hash, err := contract.ComputeHash(*c)
	hashOK = err == nil && hash == c.ContractHash

	keys := map[string]string{}
	allValid = hashOK && len(c.Parties.DataProviders) > 0
	for _, p := range c.Parties.DataProviders {
		st := partySignatureStatus{
			ProviderID:  p.ID,
			DatasetName: p.DatasetName,
			Signed:      p.Signature.SignedAt != nil,
			Signer:      p.Signature.Signer,
			SignedAt:    p.Signature.SignedAt,
		}
		switch {
		case !st.Signed:
			st.Error = "not signed yet"
		case !hashOK:
			st.Error = "contract content no longer matches its hash"
		case p.Signature.SignedHash != hash:
			st.Error = "signature is over a different hash"
		case providerIDForUsername(p.Signature.Signer) != p.ID:
			st.Error = "signer does not match provider_id"
		default:
			pub, ok := keys[p.Signature.Signer]
			if !ok {
				pub, err = s.publicKeys.PublicKey(ctx, p.Signature.Signer)
				if err != nil {
					st.Error = "public key lookup failed: " + err.Error()
					break
				}
				keys[p.Signature.Signer] = pub
			}
			if err := services.VerifyContractHashSignature(pub, hash, p.Signature.Value); err != nil {
				st.Error = err.Error()
			} else {
				st.Valid = true
			}
		}
		if !st.Valid {
			allValid = false
		}
		parties = append(parties, st)
	}
	return parties, hashOK, allValid
}

// requireSignedContract is the TEE run gate, called before any VM is
// started (doProvisionTEE). The run must name a stored, generated TEE
// contract; every data provider on it must hold a valid signature; and the
// dataset URL the run will fetch must be one of the contract's own datasets,
// so a signed contract can't be used to authorise a different dataset.
func (s *Server) requireSignedContract(ctx context.Context, tc *services.TEEContract) error {
	notSigned := func(msg string) error {
		return &teeAPIError{Status: http.StatusForbidden, Code: "CONTRACT_NOT_SIGNED", Message: msg}
	}
	if tc.GovernanceContractID == "" {
		return notSigned("governanceContractId is required: a TEE only runs for a generated contract signed by every data provider")
	}
	if s.db == nil {
		return &teeAPIError{Status: http.StatusInternalServerError, Code: "INTERNAL_ERROR", Message: "database not available"}
	}
	c, err := s.loadTEEContract(ctx, tc.GovernanceContractID)
	if err != nil {
		return &teeAPIError{Status: http.StatusInternalServerError, Code: "INTERNAL_ERROR", Message: err.Error()}
	}
	if c == nil {
		return &teeAPIError{Status: http.StatusNotFound, Code: "CONTRACT_NOT_FOUND", Message: "no generated contract " + tc.GovernanceContractID}
	}
	if c.Technique != "TEE" {
		// Only TEE contracts go through provider signing today, so only
		// they are gated; other techniques pass through unchanged.
		log.Printf("[TEE-SIGN] Gate: contract %s is %s, not TEE — signature check skipped", c.ContractID, c.Technique)
		return nil
	}

	parties, hashOK, allValid := s.verifyContractSignatures(ctx, c)
	if !hashOK {
		return notSigned("stored contract no longer matches its hash")
	}
	if !allValid {
		var pending []string
		for _, p := range parties {
			if !p.Valid {
				pending = append(pending, fmt.Sprintf("%s (%s)", p.ProviderID, p.Error))
			}
		}
		if len(parties) == 0 {
			pending = append(pending, "contract has no data providers")
		}
		return notSigned("waiting on data-provider signatures: " + strings.Join(pending, "; "))
	}

	urlOK := false
	for _, p := range c.Parties.DataProviders {
		if p.DataURL != "" && p.DataURL == tc.DatasetDetails.ResourceURL {
			urlOK = true
			break
		}
	}
	if !urlOK {
		return notSigned("datasetDetails.resourceUrl is not a dataset on the signed contract")
	}

	log.Printf("[TEE-SIGN] Gate passed: contract %s signed by all %d data provider(s)", c.ContractID, len(parties))
	return nil
}

// GET /tee-contracts/{contractId}/signatures — each data provider's signing
// state, re-verified against Keycloak, plus all_signed.
func (s *Server) getTEEContractSignatures(w http.ResponseWriter, r *http.Request) {
	c, err := s.loadTEEContract(reqCtx(r), chi.URLParam(r, "contractId"))
	if err != nil {
		log.Println("[TEE-SIGN] Error loading contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if c == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "CONTRACT_NOT_FOUND"})
		return
	}
	parties, hashOK, allValid := s.verifyContractSignatures(reqCtx(r), c)
	writeJSON(w, http.StatusOK, j{
		"status":        "SUCCESS",
		"contract_id":   c.ContractID,
		"contract_hash": c.ContractHash,
		"technique":     c.Technique,
		"hash_valid":    hashOK,
		"all_signed":    allValid,
		"parties":       parties,
	})
}

// POST /tee-contracts/{contractId}/sign — a data provider returns their
// signature over the contract hash. Called by p3dx-aaa, which authenticates
// the provider and passes their Keycloak username. gov_layer checks that the
// username maps to the party's provider_id, re-hashes its own stored copy of
// the contract, and verifies the signature with the public key Keycloak has
// on record for that user.
func (s *Server) handleSignTEEContract(w http.ResponseWriter, r *http.Request) {
	contractID := chi.URLParam(r, "contractId")
	var body struct {
		ProviderUsername string `json:"provider_username"`
		NotificationID   string `json:"notification_id"`
		ContractHash     string `json:"contract_hash"`
		Signature        string `json:"signature"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	if body.ProviderUsername == "" || body.ContractHash == "" || body.Signature == "" {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "MISSING_FIELDS",
			"message": "provider_username, contract_hash and signature are required",
		})
		return
	}
	providerID := providerIDForUsername(body.ProviderUsername)

	c, err := s.loadTEEContract(reqCtx(r), contractID)
	if err != nil {
		log.Println("[TEE-SIGN] Error loading contract:", err)
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
	if c.Technique != "TEE" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "NOT_A_TEE_CONTRACT"})
		return
	}

	// Recompute from the stored contract rather than trusting the stored or
	// submitted hash: all three must agree.
	hash, err := contract.ComputeHash(*c)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if hash != c.ContractHash || hash != body.ContractHash {
		writeJSON(w, http.StatusConflict, j{
			"status": "FAILED", "error": "HASH_MISMATCH",
			"message": "signed hash does not match the governance layer's copy of the contract",
		})
		return
	}

	isParty := false
	for _, p := range c.Parties.DataProviders {
		if p.ID == providerID {
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
		log.Printf("[TEE-SIGN] Public key lookup failed for %s: %v", body.ProviderUsername, err)
		code, status := "PUBLIC_KEY_LOOKUP_FAILED", http.StatusBadGateway
		if errors.Is(err, userdir.ErrNoPublicKey) || errors.Is(err, userdir.ErrUserNotFound) {
			code, status = "NO_PUBLIC_KEY", http.StatusBadRequest
		}
		writeJSON(w, status, j{"status": "FAILED", "error": code, "message": err.Error()})
		return
	}
	if err := services.VerifyContractHashSignature(pub, hash, body.Signature); err != nil {
		log.Printf("[TEE-SIGN] Rejected signature from %s on contract %s: %v", providerID, contractID, err)
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_SIGNATURE", "message": err.Error()})
		return
	}

	// A provider may hold several datasets on the same contract — sign every
	// party that belongs to them.
	now := time.Now().UTC()
	for i := range c.Parties.DataProviders {
		p := &c.Parties.DataProviders[i]
		if p.ID == providerID {
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
	if ok, err := s.db.UpdateContractByProjectID(reqCtx(r), contractID, updated); err != nil || !ok {
		log.Println("[TEE-SIGN] Error storing signed contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}

	if body.NotificationID != "" {
		if _, err := s.db.RespondToNotification(reqCtx(r), body.NotificationID, providerID, "accepted", "signed"); err != nil {
			log.Println("[TEE-SIGN] Warning: failed to mark sign request answered:", err)
		}
	}

	allSigned := true
	for _, p := range c.Parties.DataProviders {
		if p.Signature.SignedAt == nil {
			allSigned = false
			break
		}
	}
	log.Printf("[TEE-SIGN] %s signed contract %s (all providers signed: %t)", providerID, contractID, allSigned)

	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "all_signed": allSigned, "contract": c})
}
