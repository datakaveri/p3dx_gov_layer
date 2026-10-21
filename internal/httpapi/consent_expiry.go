package httpapi

// Consent expiry: a data provider viewing a TEE/SMPC consent request sets
// when their consent ends, before signing. The expiry is part of the signed
// contract (data_providers[].constraints.consent_valid_until, covered by the
// hash), so setting it re-hashes the contract, re-signs it as governance,
// clears any signatures already given and re-sends every provider a fresh
// sign request. The contract's lifecycle.valid_until becomes the earliest
// consent expiry. The consumer is told (contract event + notification) and
// sees it in their consent request preview (GET /contracts/{id}). No run
// starts once any provider's consent has expired (consentExpiryError).

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
)

// ConsentExpiryNotificationType tags the consumer's notification that a
// provider set their consent expiry.
const ConsentExpiryNotificationType = "CONSENT_EXPIRY_SET"

// parseConsentExpiry accepts RFC 3339 or a date (YYYY-MM-DD, consent then
// lasts to the end of that day, UTC).
func parseConsentExpiry(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), nil
	}
	d, err := time.Parse("2006-01-02", v)
	if err != nil {
		return time.Time{}, fmt.Errorf("valid_until must be a date (YYYY-MM-DD) or an RFC 3339 time")
	}
	return d.Add(24*time.Hour - time.Second).UTC(), nil
}

// POST /contracts/{contractId}/consent-expiry — body {"valid_until": "..."}.
// The provider is taken from their own Bearer token, as for /sign.
func (s *Server) handleSetConsentExpiry(w http.ResponseWriter, r *http.Request) {
	contractID := chi.URLParam(r, "contractId")
	fail := func(status int, code, msg string) {
		writeJSON(w, status, j{"status": "FAILED", "error": code, "message": msg})
	}
	signer, ok := s.providerTokenIdentity(w, r)
	if !ok {
		return
	}
	var body struct {
		ValidUntil string `json:"valid_until"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	until, err := parseConsentExpiry(body.ValidUntil)
	if err != nil {
		fail(http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	providerID := providerIDForUsername(signer.username)

	c, err := s.loadContract(reqCtx(r), contractID)
	if err != nil {
		log.Println("[CONSENT-EXPIRY] Error loading contract:", err)
		fail(http.StatusInternalServerError, "INTERNAL_ERROR", "could not load contract")
		return
	}
	if c == nil {
		fail(http.StatusNotFound, "CONTRACT_NOT_FOUND", "contract not found — it may have been regenerated")
		return
	}
	if c.Technique != "TEE" && c.Technique != "SMPC" {
		fail(http.StatusBadRequest, "NOT_SUPPORTED", "consent expiry can be set on TEE and SMPC consent requests only")
		return
	}
	if s.jobApprovalRequired(c) || c.GovernanceSignature == nil || s.govKey == nil {
		fail(http.StatusConflict, "NOT_SUPPORTED", "this consent request goes through job approval; its consent expiry can't be set here")
		return
	}

	isParty, signed := false, false
	for _, p := range c.Parties.DataProviders {
		if partyProviderID(p) == providerID {
			isParty = true
			signed = signed || p.Signature.Value != ""
		}
	}
	if !isParty {
		fail(http.StatusForbidden, "NOT_A_PARTY", "you are not a data provider on this consent request")
		return
	}
	if signed {
		fail(http.StatusConflict, "ALREADY_SIGNED", "you have already signed this consent request — withdraw consent first to change its expiry")
		return
	}
	now := time.Now().UTC()
	if !until.After(now) {
		fail(http.StatusBadRequest, "BAD_REQUEST", "consent expiry must be in the future")
		return
	}
	// The contract's own end, as generated (ValidUntil may already have been
	// shortened by a consent expiry).
	requestedEnd := c.Lifecycle.ValidUntil
	if c.Lifecycle.RequestedValidUntil != nil {
		requestedEnd = *c.Lifecycle.RequestedValidUntil
	}
	if !requestedEnd.IsZero() && until.After(requestedEnd) {
		fail(http.StatusBadRequest, "BAD_REQUEST", fmt.Sprintf("consent expiry can't be after the contract's own end (%s)", requestedEnd.UTC().Format("2006-01-02 15:04 UTC")))
		return
	}

	// Set it, and clear every signature already given: they covered the old
	// hash. Those providers are asked again with the new one.
	var resigners []string
	for i := range c.Parties.DataProviders {
		p := &c.Parties.DataProviders[i]
		if partyProviderID(*p) == providerID {
			p.Constraints.ConsentValidUntil = &until
		}
		if p.Signature.Value != "" {
			resigners = append(resigners, partyProviderID(*p))
			p.Signature.SignedAt = nil
			p.Signature.Algorithm = ""
			p.Signature.SignedHash = ""
			p.Signature.Value = ""
		}
	}
	// The contract is valid only while every provider's consent lasts:
	// lifecycle.valid_until becomes the earliest consent expiry.
	if c.Lifecycle.RequestedValidUntil == nil && !requestedEnd.IsZero() {
		c.Lifecycle.RequestedValidUntil = &requestedEnd
	}
	c.Lifecycle.ValidUntil = earliestConsentExpiry(c, requestedEnd)

	hash, err := contract.ComputeHash(*c)
	if err != nil {
		fail(http.StatusInternalServerError, "INTERNAL_ERROR", "could not hash contract: "+err.Error())
		return
	}
	c.ContractHash = hash
	if err := s.governanceSign(c); err != nil {
		fail(http.StatusInternalServerError, "INTERNAL_ERROR", "could not governance-sign contract: "+err.Error())
		return
	}
	raw, err := json.Marshal(c)
	if err != nil {
		fail(http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if ok, err := s.db.UpdateContractByContractID(reqCtx(r), contractID, raw); err != nil || !ok {
		log.Println("[CONSENT-EXPIRY] Error storing contract:", err)
		fail(http.StatusInternalServerError, "INTERNAL_ERROR", "could not store contract")
		return
	}

	for _, pid := range resigners {
		s.markParticipantStatus(reqCtx(r), c, pid, "", "", db.ParticipantStatusRequested)
	}
	if _, err := s.db.SupersedeContractSignRequests(reqCtx(r), contractID); err != nil {
		log.Println("[CONSENT-EXPIRY] Warning: old sign requests not superseded:", err)
	}
	sent := s.notifyContractSigners(reqCtx(r), *c, signer.username)

	date := until.Format("2006-01-02 15:04 UTC")
	detail := fmt.Sprintf("%s set consent to expire on %s; the consent request was updated and re-sent for signature", signer.username, date)
	s.recordContractEvent(reqCtx(r), c, db.ContractEventConsentExpirySet, detail, signer.username)
	if c.Parties.User.Name != "" {
		payload, _ := json.Marshal(j{
			"type":                ConsentExpiryNotificationType,
			"contract_id":         c.ContractID,
			"job_id":              c.JobID,
			"provider_id":         providerID,
			"provider_username":   signer.username,
			"consent_valid_until": until,
			"contract_hash":       c.ContractHash,
		})
		if _, err := s.db.CreateNotification(reqCtx(r), c.Parties.User.ID, c.Parties.User.Name, signer.username, detail, payload); err != nil {
			log.Println("[CONSENT-EXPIRY] Warning: consumer not notified:", err)
		}
	}

	log.Printf("[CONSENT-EXPIRY] %s set consent expiry %s on contract %s; new hash %s, %d sign request(s) re-sent", providerID, until.Format(time.RFC3339), contractID, c.ContractHash, sent)
	writeJSON(w, http.StatusOK, j{
		"status":              "SUCCESS",
		"contract_id":         c.ContractID,
		"contract_hash":       c.ContractHash,
		"consent_valid_until": until,
		"sign_requests_sent":  sent,
		"contract":            c,
	})
}

// GET /contracts/{contractId} — the stored contract, for the consumer who
// generated it (their Keycloak token's sub is parties.user.id), so their
// consent request preview picks up later changes such as a provider's
// consent expiry.
func (s *Server) getConsumerContract(w http.ResponseWriter, r *http.Request) {
	tokenStr, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	parsedToken, err := services.ValidateAccessToken(tokenStr)
	if err != nil || !parsedToken.Valid {
		writeJSON(w, http.StatusUnauthorized, j{"status": "FAILED", "error": "UNAUTHORIZED", "message": "invalid Keycloak token"})
		return
	}
	claims, _ := parsedToken.Claims.(jwt.MapClaims)
	sub, _ := claims["sub"].(string)

	c, err := s.loadContract(reqCtx(r), chi.URLParam(r, "contractId"))
	if err != nil {
		log.Println("[CONTRACT] Error loading contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	if c == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "CONTRACT_NOT_FOUND"})
		return
	}
	if sub == "" || !strings.EqualFold(sub, c.Parties.User.ID) {
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "NOT_CONTRACT_OWNER", "message": "only the consumer who generated this contract can read it"})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "contract": c})
}

// earliestConsentExpiry returns the earliest consent expiry any data provider
// set on c, or fallback when that is earlier (or none is set).
func earliestConsentExpiry(c *contract.Contract, fallback time.Time) time.Time {
	out := fallback
	for _, p := range c.Parties.DataProviders {
		if u := p.Constraints.ConsentValidUntil; u != nil && (out.IsZero() || u.Before(out)) {
			out = *u
		}
	}
	return out
}

// consentExpiryError reports the first data provider whose consent on c has
// expired by now, or nil.
func consentExpiryError(c *contract.Contract, now time.Time) error {
	for _, p := range c.Parties.DataProviders {
		if u := p.Constraints.ConsentValidUntil; u != nil && now.After(*u) {
			who := p.Name
			if who == "" {
				who = partyProviderID(p)
			}
			return &teeAPIError{Status: http.StatusForbidden, Code: "CONSENT_EXPIRED",
				Message: fmt.Sprintf("consent from %s for dataset %q expired on %s", who, p.DatasetName, u.UTC().Format("2006-01-02 15:04 UTC"))}
		}
	}
	return nil
}
