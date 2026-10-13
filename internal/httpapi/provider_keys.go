package httpapi

// This file is the provider public-key registry API. A data/infra provider's
// key pair is generated in their browser; p3dx-aaa (keyPair.service.js)
// forwards the SPKI public key here together with the provider's own access
// token, and gov_layer stores it in Postgres (provider_public_keys) for the
// contract-signing flow (contract_signing.go) to verify signatures against.
// The forwarded token — validated against PROVIDER_KEY_JWKS_URL, the Keycloak
// providers log in through — is the only identity source: the username a key
// is stored under always comes from it, never from the request body.

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
)

// providerKeyRoles are the realm roles allowed to register a signing key.
var providerKeyRoles = []string{"data-provider", "infra-provider"}

const minProviderKeyBits = 2048

// dbPublicKeys adapts *db.DB to publicKeyLookup.
type dbPublicKeys struct{ d *db.DB }

func (l dbPublicKeys) PublicKey(ctx context.Context, username string) (string, error) {
	return l.d.ProviderPublicKey(ctx, username)
}

// providerIdentity is a provider read from their validated access token.
type providerIdentity struct {
	username, userID string
	roles            []string
}

// providerTokenIdentity validates the bearer token — issued either by the
// Keycloak p3dx-aaa's users log in through (PROVIDER_KEY_JWKS_URL) or by the
// dev Keycloak (DATA_PROVIDER_JWKS_URL, e.g. a provider calling directly from
// Postman) — and reads the provider from it. On failure it has already
// written the response.
func (s *Server) providerTokenIdentity(w http.ResponseWriter, r *http.Request) (providerIdentity, bool) {
	tokenStr, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || tokenStr == "" {
		writeJSON(w, http.StatusUnauthorized, j{"status": "FAILED", "error": "MISSING_AUTH_TOKEN"})
		return providerIdentity{}, false
	}
	var token *jwt.Token
	var err error
	for _, jwksURL := range []string{s.cfg.ProviderKeyJWKSURL, s.cfg.DataProviderJWKSURL} {
		if jwksURL == "" {
			continue
		}
		if token, err = services.ValidateAccessTokenAt(tokenStr, jwksURL); err == nil && token.Valid {
			break
		}
	}
	if err != nil || token == nil || !token.Valid {
		log.Printf("[PROVIDER-KEYS] Token rejected: %v", err)
		writeJSON(w, http.StatusUnauthorized, j{"status": "FAILED", "error": "INVALID_OR_EXPIRED_TOKEN"})
		return providerIdentity{}, false
	}
	claims, _ := token.Claims.(jwt.MapClaims)
	if s.rejectFlotillaVMToken(w, claims) {
		return providerIdentity{}, false
	}
	var id providerIdentity
	id.username, _ = claims["preferred_username"].(string)
	if id.username == "" {
		// The dev portal's tokens carry the login in email, with no
		// preferred_username.
		id.username, _ = claims["email"].(string)
	}
	id.userID, _ = claims["sub"].(string)
	if id.username == "" || id.userID == "" {
		writeJSON(w, http.StatusUnauthorized, j{"status": "FAILED", "error": "INVALID_TOKEN_CLAIMS"})
		return providerIdentity{}, false
	}
	if ra, ok := claims["realm_access"].(map[string]any); ok {
		if list, ok := ra["roles"].([]any); ok {
			for _, v := range list {
				if s, ok := v.(string); ok {
					id.roles = append(id.roles, s)
				}
			}
		}
	}
	return id, true
}

// providerFromToken validates the bearer token and checks the caller holds
// the {role} path segment — data-provider / infra-provider, or the dev
// Keycloak's DATA_PROVIDER_ROLE ("provider"). On failure it has already
// written the response.
func (s *Server) providerFromToken(w http.ResponseWriter, r *http.Request) (username, userID, role string, ok bool) {
	role = chi.URLParam(r, "role")
	if !slices.Contains(providerKeyRoles, role) && role != s.dataProviderRole() {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "ROLE_NOT_ALLOWED"})
		return "", "", "", false
	}
	id, ok := s.providerTokenIdentity(w, r)
	if !ok {
		return "", "", "", false
	}
	if !slices.Contains(id.roles, role) {
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "INSUFFICIENT_ROLE"})
		return "", "", "", false
	}
	return id.username, id.userID, role, true
}

// PUT /provider-keys/{role} — register (or replace) the caller's public key.
// Body: {"public_key_pem": "-----BEGIN PUBLIC KEY-----..."}.
func (s *Server) putProviderKey(w http.ResponseWriter, r *http.Request) {
	username, userID, role, ok := s.providerFromToken(w, r)
	if !ok {
		return
	}
	var body struct {
		PublicKeyPEM string `json:"public_key_pem"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	normalised, fingerprint, code := normaliseProviderKey(body.PublicKeyPEM)
	if code != "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": code})
		return
	}
	rotated, err := s.db.UpsertProviderPublicKey(reqCtx(r), username, userID, role, normalised, fingerprint)
	if err != nil {
		log.Println("[PROVIDER-KEYS] ❌ Error storing public key:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "fingerprint_sha256": fingerprint, "rotated": rotated})
}

// GET /provider-keys/{role}/status — whether the caller has a key registered.
// The key is per user (shared across providerKeyRoles); {role} only gates on
// the caller holding that role.
func (s *Server) getProviderKeyStatus(w http.ResponseWriter, r *http.Request) {
	username, _, _, ok := s.providerFromToken(w, r)
	if !ok {
		return
	}
	_, err := s.db.ProviderPublicKey(reqCtx(r), username)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "exists": true})
	case errors.Is(err, db.ErrNoPublicKey):
		writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "exists": false})
	default:
		log.Println("[PROVIDER-KEYS] ❌ Error reading public key:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
	}
}

// normaliseProviderKey checks pemStr is an SPKI RSA public key of at least
// minProviderKeyBits — what services.VerifyContractHashSignature expects — and
// returns it re-encoded plus its SHA-256 DER fingerprint, or an error code.
func normaliseProviderKey(pemStr string) (normalised, fingerprint, code string) {
	if strings.TrimSpace(pemStr) == "" {
		return "", "", "MISSING_PUBLIC_KEY"
	}
	if strings.Contains(pemStr, "PRIVATE KEY") {
		return "", "", "PRIVATE_KEY_NOT_ACCEPTED"
	}
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", "", "EXPECTED_SPKI_PEM"
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", "", "INVALID_PUBLIC_KEY"
	}
	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return "", "", "EXPECTED_RSA_KEY"
	}
	if rsaPub.N.BitLen() < minProviderKeyBits {
		return "", "", "KEY_TOO_SHORT"
	}
	sum := sha256.Sum256(block.Bytes)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes})), hex.EncodeToString(sum[:]), ""
}
