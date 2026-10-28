// Flotilla FL client-VM credentials (join gateway), formerly in p3dx-aaa.
//
//	POST /api/v1/me/fl/vm-credentials                     (data provider's token)
//	  The provider re-enters their password; gov_layer does a flotilla-vm
//	  password grant for an OFFLINE token, records its fingerprint and hands
//	  the token straight to p3dx-fl-orchestrator for the VM sidecar. The
//	  browser only gets back {credential_id, expires_at}.
//
//	POST /p3dx/fl/vm-token                                (VM sidecar, no user token)
//	  The only place a VM can turn its offline token into an access token,
//	  until the session contract's lifecycle.valid_until.
//
//	POST /p3dx/internal/fl/vm-credentials/{id}/delivered  (orchestrator service token)
//
// The two /p3dx paths are where the orchestrator and the VMs already call
// (AAA_URL / AAA_PUBLIC_URL), so pointing those at gov_layer is enough.
//
// SECURITY: request bodies here carry a password or an offline token. Never
// log a body, a Keycloak response or a token — only ids, states and codes.

package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/userdir"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

const (
	vmBodyLimit              = 32 << 10
	vmTokenRequestsPerMinute = 30
)

// vmCredentialStore is *postgres.DB in production; stubbed in tests.
type vmCredentialStore interface {
	CreateVMCredential(ctx context.Context, c postgres.VMCredential) error
	GetVMCredential(ctx context.Context, credentialID string) (*postgres.VMCredential, error)
	GetVMCredentialBySession(ctx context.Context, sessionID string) (*postgres.VMCredential, error)
	SetVMCredentialState(ctx context.Context, credentialID, state, reason string) (*postgres.VMCredential, error)
	UpdateVMCredentialFingerprint(ctx context.Context, credentialID, fingerprint string) error
}

// vmKeycloak is *userdir.Client in production; stubbed in tests.
type vmKeycloak interface {
	PasswordGrantOffline(ctx context.Context, clientID, secret, username, password string) (*userdir.TokenResponse, error)
	RefreshGrant(ctx context.Context, clientID, secret, refreshToken string) (*userdir.TokenResponse, error)
	DeleteOfflineSession(ctx context.Context, sessionID string) (bool, error)
	ClientOfflineSessions(ctx context.Context, clientID string) ([]userdir.OfflineSession, error)
}

// registerVMCredentialRoutes mounts the VM-facing and orchestrator-facing
// routes at the server root (see the file comment).
func (s *Server) registerVMCredentialRoutes(r chi.Router) {
	r.Post("/p3dx/fl/vm-token", s.vmToken)
	r.Post("/p3dx/internal/fl/vm-credentials/{id}/delivered", s.vmCredentialDelivered)
}

// tokenFingerprint is the first 16 hex chars of sha256(token) — all that is
// stored of an offline token.
func tokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:16]
}

func fingerprintMatches(token, fingerprint string) bool {
	return subtle.ConstantTimeCompare([]byte(tokenFingerprint(token)), []byte(fingerprint)) == 1
}

// readVMBody decodes a small JSON body. A malformed body is answered with
// 400 without echoing any of it.
func readVMBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, vmBodyLimit)).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_REQUEST", "message": "malformed JSON body"})
		return false
	}
	return true
}

func vmFail(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, j{"status": "FAILED", "error": code})
}

// unverifiedClaims reads a token's claims without checking its signature —
// only for tokens Keycloak just returned to us over TLS.
func unverifiedClaims(token string) jwt.MapClaims {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return nil
	}
	return claims
}

func claimString(c jwt.MapClaims, key string) string {
	v, _ := c[key].(string)
	return v
}

func (s *Server) dropOfflineSession(ctx context.Context, sessionID, where string) {
	if _, err := s.vmKC.DeleteOfflineSession(ctx, sessionID); err != nil {
		log.Printf("[FL-VM] %s: offline session delete failed: %v", where, err)
	}
}

// POST /me/fl/vm-credentials — body {submission_id, password}.
func (s *Server) issueVMCredential(w http.ResponseWriter, r *http.Request) {
	if s.cfg.InternalServiceKey == "" {
		writeJSON(w, http.StatusServiceUnavailable, j{"status": "FAILED", "error": "INTERNAL_KEY_NOT_CONFIGURED",
			"message": "INTERNAL_SERVICE_KEY must be set to hand credentials to the orchestrator"})
		return
	}
	var body struct {
		SubmissionID string `json:"submission_id"`
		Password     string `json:"password"`
	}
	if !readVMBody(w, r, &body) {
		return
	}
	submissionID := strings.TrimSpace(body.SubmissionID)
	if submissionID == "" || body.Password == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_REQUEST", "message": "submission_id and password are required"})
		return
	}
	caller := userFrom(r)
	ctx := reqCtx(r)

	// 1. The session contract: fully signed, FL, the caller a party, not expired.
	raw, err := s.flContracts.GetContractBySession(ctx, submissionID)
	if err != nil {
		log.Println("[FL-VM] vm-credentials: contract lookup failed:", err)
		vmFail(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	var c contract.Contract
	if raw == nil || json.Unmarshal(raw, &c) != nil {
		vmFail(w, http.StatusNotFound, "CONTRACT_NOT_FOUND")
		return
	}
	if !s.contractRunnable(ctx, &c) {
		writeJSON(w, http.StatusConflict, j{"status": "FAILED", "error": "CONTRACT_NOT_SIGNED", "message": "the session contract is not fully signed"})
		return
	}
	if c.Technique != "FL" {
		vmFail(w, http.StatusConflict, "NOT_AN_FL_CONTRACT")
		return
	}
	isParty := false
	for _, p := range c.Parties.DataProviders {
		if p.ID != "" && p.ID == caller.userID {
			isParty = true
			break
		}
	}
	if !isParty {
		vmFail(w, http.StatusForbidden, "NOT_A_CONTRACT_PARTY")
		return
	}
	validUntil := c.Lifecycle.ValidUntil
	if validUntil.IsZero() {
		writeJSON(w, http.StatusConflict, j{"status": "FAILED", "error": "CONTRACT_NO_VALIDITY", "message": "contract has no lifecycle.valid_until"})
		return
	}
	if !time.Now().Before(validUntil) {
		vmFail(w, http.StatusGone, "CONTRACT_EXPIRED")
		return
	}

	// 2. Offline token — the username comes from the verified token, never the body.
	tok, err := s.vmKC.PasswordGrantOffline(ctx, s.cfg.FlotillaVMClientID, s.cfg.FlotillaVMClientSecret, caller.username, body.Password)
	if err != nil {
		var ge *userdir.GrantError
		if errors.As(err, &ge) && (ge.Status == http.StatusBadRequest || ge.Status == http.StatusUnauthorized) {
			vmFail(w, http.StatusUnauthorized, "INVALID_CREDENTIALS")
			return
		}
		log.Println("[FL-VM] vm-credentials: keycloak login failed:", err)
		vmFail(w, http.StatusBadGateway, "KEYCLOAK_ERROR")
		return
	}
	access, refresh := unverifiedClaims(tok.AccessToken), unverifiedClaims(tok.RefreshToken)
	sessionID := claimString(access, "sid")
	if sessionID == "" {
		sessionID = claimString(refresh, "sid")
	}
	if access == nil || claimString(access, "sub") != caller.userID {
		s.dropOfflineSession(ctx, sessionID, "vm-credentials")
		vmFail(w, http.StatusForbidden, "SUBJECT_MISMATCH")
		return
	}
	if refresh == nil || claimString(refresh, "typ") != "Offline" || sessionID == "" {
		s.dropOfflineSession(ctx, sessionID, "vm-credentials")
		log.Printf("[FL-VM] vm-credentials: Keycloak did not return an offline token (typ=%q)", claimString(refresh, "typ"))
		vmFail(w, http.StatusBadGateway, "NOT_OFFLINE_TOKEN")
		return
	}

	// 3. Record (fingerprint only).
	rec := postgres.VMCredential{
		CredentialID:     postgres.NewUUID(),
		SubmissionID:     submissionID,
		ContractID:       c.ContractID,
		Username:         caller.username,
		UserID:           caller.userID,
		SessionID:        sessionID,
		TokenFingerprint: tokenFingerprint(tok.RefreshToken),
		IssuedAt:         time.Now().UTC(),
		ExpiresAt:        validUntil.UTC(),
	}
	if err := s.vmCreds.CreateVMCredential(ctx, rec); err != nil {
		log.Println("[FL-VM] vm-credentials: record store failed:", err)
		s.dropOfflineSession(ctx, sessionID, "vm-credentials")
		vmFail(w, http.StatusServiceUnavailable, "CREDENTIAL_STORE_UNAVAILABLE")
		return
	}
	expiresAt := rec.ExpiresAt.Format(time.RFC3339)

	// 4. Hand off to the orchestrator.
	if err := s.handOffVMCredential(ctx, rec, tok.RefreshToken, expiresAt); err != nil {
		log.Printf("[FL-VM] vm-credentials: handoff failed for %s (session %s): %v", rec.CredentialID, submissionID, err)
		s.dropOfflineSession(ctx, sessionID, "vm-credentials")
		if _, err := s.vmCreds.SetVMCredentialState(ctx, rec.CredentialID, postgres.VMCredentialExpired, "HANDOFF_FAILED"); err != nil {
			log.Println("[FL-VM] vm-credentials: could not mark record expired:", err)
		}
		writeJSON(w, http.StatusBadGateway, j{"status": "FAILED", "error": "HANDOFF_FAILED", "message": "could not deliver the credential to the orchestrator"})
		return
	}
	log.Printf("[FL-VM] vm-credentials: %s issued to %s for session %s (fingerprint %s, until %s)",
		rec.CredentialID, rec.Username, submissionID, rec.TokenFingerprint, expiresAt)
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "credential_id": rec.CredentialID, "expires_at": expiresAt})
}

func (s *Server) handOffVMCredential(ctx context.Context, rec postgres.VMCredential, offlineToken, expiresAt string) error {
	base := strings.TrimRight(s.cfg.OrchestratorServiceURL, "/")
	if base == "" {
		return errors.New("ORCHESTRATOR_SERVICE_URL not set")
	}
	payload, _ := json.Marshal(j{
		"credential_id": rec.CredentialID, "submission_id": rec.SubmissionID, "contract_id": rec.ContractID,
		"username": rec.Username, "user_id": rec.UserID, "offline_token": offlineToken, "expires_at": expiresAt,
	})
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/p3dx/internal/vm-credentials", bytes.NewReader(payload))
	if err != nil {
		return errors.New("build handoff request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", s.cfg.InternalServiceKey)
	resp, err := s.http.Do(req)
	if err != nil {
		return errors.New("orchestrator unreachable")
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("orchestrator returned " + resp.Status)
	}
	return nil
}

// POST /p3dx/fl/vm-token — body {credential_id, offline_token}.
func (s *Server) vmToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CredentialID string `json:"credential_id"`
		OfflineToken string `json:"offline_token"`
	}
	if !readVMBody(w, r, &body) {
		return
	}
	id := strings.TrimSpace(body.CredentialID)
	if id == "" || body.OfflineToken == "" || len(id) > 128 {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_REQUEST", "message": "credential_id and offline_token are required"})
		return
	}
	if !s.vmRate.allow(id) {
		vmFail(w, http.StatusTooManyRequests, "RATE_LIMITED")
		return
	}
	ctx := reqCtx(r)
	rec, err := s.vmCreds.GetVMCredential(ctx, id)
	if err != nil {
		log.Println("[FL-VM] vm-token: record read failed:", err)
		vmFail(w, http.StatusServiceUnavailable, "CREDENTIAL_STORE_UNAVAILABLE")
		return
	}
	if rec == nil {
		vmFail(w, http.StatusUnauthorized, "UNKNOWN_CREDENTIAL")
		return
	}
	if !fingerprintMatches(body.OfflineToken, rec.TokenFingerprint) {
		log.Printf("[FL-VM] vm-token: fingerprint mismatch for %s", id)
		vmFail(w, http.StatusUnauthorized, "INVALID_CREDENTIAL")
		return
	}
	if rec.State == postgres.VMCredentialExpired || !time.Now().Before(rec.ExpiresAt) {
		if rec.State != postgres.VMCredentialExpired {
			s.dropOfflineSession(ctx, rec.SessionID, "vm-token")
			if _, err := s.vmCreds.SetVMCredentialState(ctx, id, postgres.VMCredentialExpired, "CONTRACT_EXPIRED"); err != nil {
				log.Println("[FL-VM] vm-token: could not mark record expired:", err)
			}
		}
		vmFail(w, http.StatusUnauthorized, "CREDENTIAL_EXPIRED")
		return
	}
	tok, err := s.vmKC.RefreshGrant(ctx, s.cfg.FlotillaVMClientID, s.cfg.FlotillaVMClientSecret, body.OfflineToken)
	if err != nil {
		log.Printf("[FL-VM] vm-token: refresh failed for %s: %v", id, err)
		vmFail(w, http.StatusUnauthorized, "REFRESH_FAILED")
		return
	}
	access := unverifiedClaims(tok.AccessToken)
	if access == nil || claimString(access, "sid") == "" || claimString(access, "sid") != rec.SessionID ||
		claimString(access, "azp") != s.cfg.FlotillaVMClientID {
		log.Printf("[FL-VM] vm-token: session mismatch for %s", id)
		vmFail(w, http.StatusUnauthorized, "SESSION_MISMATCH")
		return
	}
	resp := j{
		"status":               "SUCCESS",
		"access_token":         tok.AccessToken,
		"expires_in":           tok.ExpiresIn,
		"contract_valid_until": rec.ExpiresAt.Format(time.RFC3339),
	}
	if tok.RefreshToken != "" && tok.RefreshToken != body.OfflineToken {
		// Keycloak rotated the token; from now on only the new one is accepted.
		// If that can't be recorded, hand out nothing — the old token still
		// works in Keycloak, so the VM simply retries.
		if err := s.vmCreds.UpdateVMCredentialFingerprint(ctx, id, tokenFingerprint(tok.RefreshToken)); err != nil {
			log.Println("[FL-VM] vm-token: fingerprint update failed:", err)
			vmFail(w, http.StatusServiceUnavailable, "CREDENTIAL_STORE_UNAVAILABLE")
			return
		}
		resp["offline_token"] = tok.RefreshToken
	}
	log.Printf("[FL-VM] vm-token: access token issued for %s (session %s, rotated=%t)", id, rec.SubmissionID, resp["offline_token"] != nil)
	writeJSON(w, http.StatusOK, resp)
}

// POST /p3dx/internal/fl/vm-credentials/{id}/delivered — the orchestrator
// confirms the VM has its credential.
func (s *Server) vmCredentialDelivered(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireServiceToken(w, r, s.cfg.OrchestratorClientID, s.cfg.OrchestratorRole); !ok {
		return
	}
	ctx := reqCtx(r)
	rec, err := s.vmCreds.GetVMCredential(ctx, chi.URLParam(r, "id"))
	if err != nil {
		log.Println("[FL-VM] delivered: record read failed:", err)
		vmFail(w, http.StatusServiceUnavailable, "CREDENTIAL_STORE_UNAVAILABLE")
		return
	}
	if rec == nil {
		vmFail(w, http.StatusNotFound, "UNKNOWN_CREDENTIAL")
		return
	}
	if rec.State == postgres.VMCredentialExpired {
		vmFail(w, http.StatusConflict, "CREDENTIAL_EXPIRED")
		return
	}
	updated, err := s.vmCreds.SetVMCredentialState(ctx, rec.CredentialID, postgres.VMCredentialDelivered, "")
	if err != nil || updated == nil {
		log.Println("[FL-VM] delivered: state update failed:", err)
		vmFail(w, http.StatusServiceUnavailable, "CREDENTIAL_STORE_UNAVAILABLE")
		return
	}
	log.Printf("[FL-VM] %s delivered (session %s)", updated.CredentialID, updated.SubmissionID)
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "credential_id": updated.CredentialID, "state": updated.State})
}

// vmSweepSummary counts one sweep's outcomes.
type vmSweepSummary struct {
	Sessions, Kept, OrphansDeleted, ExpiredDeleted, Skipped, Errors int
}

// sweepVMOfflineSessions deletes every flotilla-vm offline session without a
// live credential behind it: orphans (no record) and sessions whose record is
// expired or past expires_at; those records are marked expired. A session
// whose record can't be read is left alone this round.
func (s *Server) sweepVMOfflineSessions(ctx context.Context) (vmSweepSummary, error) {
	var sum vmSweepSummary
	sessions, err := s.vmKC.ClientOfflineSessions(ctx, s.cfg.FlotillaVMClientID)
	if err != nil {
		return sum, err
	}
	sum.Sessions = len(sessions)
	now := time.Now()
	for _, sess := range sessions {
		if sess.ID == "" {
			sum.Skipped++
			continue
		}
		rec, err := s.vmCreds.GetVMCredentialBySession(ctx, sess.ID)
		if err != nil {
			sum.Skipped++
			sum.Errors++
			continue
		}
		if rec != nil && rec.State != postgres.VMCredentialExpired && now.Before(rec.ExpiresAt) {
			sum.Kept++
			continue
		}
		if _, err := s.vmKC.DeleteOfflineSession(ctx, sess.ID); err != nil {
			sum.Errors++
			continue
		}
		if rec == nil {
			sum.OrphansDeleted++
			continue
		}
		sum.ExpiredDeleted++
		if rec.State != postgres.VMCredentialExpired {
			if _, err := s.vmCreds.SetVMCredentialState(ctx, rec.CredentialID, postgres.VMCredentialExpired, "CONTRACT_EXPIRED"); err != nil {
				sum.Errors++
			}
		}
	}
	return sum, nil
}

// runVMSessionSweeper sweeps every FLVMSweepInterval; 0 disables it.
func (s *Server) runVMSessionSweeper() {
	interval := s.cfg.FLVMSweepInterval
	if interval <= 0 {
		log.Println("[FL-VM] sweeper disabled (FL_VM_SWEEP_INTERVAL_MS=0)")
		return
	}
	log.Printf("[FL-VM] sweeper started (every %s)", interval)
	for range time.Tick(interval) {
		ctx, cancel := context.WithTimeout(context.Background(), interval)
		sum, err := s.sweepVMOfflineSessions(ctx)
		cancel()
		if err != nil {
			log.Println("[FL-VM] sweep failed:", err)
			continue
		}
		log.Printf("[FL-VM] sweep: sessions=%d kept=%d orphans_deleted=%d expired_deleted=%d skipped=%d errors=%d",
			sum.Sessions, sum.Kept, sum.OrphansDeleted, sum.ExpiredDeleted, sum.Skipped, sum.Errors)
	}
}

// rateLimiter allows `limit` calls per key per fixed one-minute window.
type rateLimiter struct {
	limit int
	now   func() time.Time

	mu   sync.Mutex
	hits map[string]*rateWindow
}

type rateWindow struct {
	start time.Time
	count int
}

func newRateLimiter(limit int) *rateLimiter {
	return &rateLimiter{limit: limit, now: time.Now, hits: map[string]*rateWindow{}}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	if len(l.hits) > 10000 {
		for k, v := range l.hits {
			if t.Sub(v.start) >= time.Minute {
				delete(l.hits, k)
			}
		}
	}
	e := l.hits[key]
	if e == nil || t.Sub(e.start) >= time.Minute {
		l.hits[key] = &rateWindow{start: t, count: 1}
		return true
	}
	e.count++
	return e.count <= l.limit
}
