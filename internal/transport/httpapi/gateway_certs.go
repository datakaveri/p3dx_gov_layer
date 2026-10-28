package httpapi

// Flotilla join gateway certificates. Each FL session runs a gateway that FL
// clients connect to over TLS; its server certificate is issued here, by the
// governance CA (govcrypto.LoadOrCreateGovernanceCACert), and only for a
// session whose final roster contract every data provider has signed. The
// certificate names the gateway's IP, carries the contract id as a URI SAN,
// and expires with the contract (Lifecycle.ValidUntil), so a client that
// trusts the governance CA knows the gateway it reached belongs to a live,
// fully signed FL contract.
//
//	POST /gateway-certs      — FL orchestrator service token only
//	GET  /governance/ca-cert — the CA certificate (PEM), unauthenticated

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/platform/govcrypto"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// gatewayCertStore is what POST /gateway-certs needs from Postgres: *postgres.DB
// in production; stubbed in tests.
type gatewayCertStore interface {
	GetContractBySession(ctx context.Context, sessionID string) (json.RawMessage, error)
	GetContractByProjectID(ctx context.Context, projectID string) (json.RawMessage, error)
	InsertGatewayCert(ctx context.Context, c postgres.GatewayCert) error
}

// gatewayCertBackdate covers clock skew between gov_layer and FL clients.
const gatewayCertBackdate = 5 * time.Minute

// errInvalidCSR marks a CSR that parses but is not acceptable.
var errInvalidCSR = errors.New("invalid CSR")

// parseGatewayCSR decodes a PEM CERTIFICATE REQUEST, checks its
// self-signature, and requires an RSA ≥2048 or ECDSA P-256 public key.
func parseGatewayCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csr_pem is not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < minProviderKeyBits {
			return nil, errors.New("RSA key must be at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return nil, errors.New("ECDSA key must be on P-256")
		}
	default:
		return nil, errors.New("key must be RSA or ECDSA P-256")
	}
	return csr, nil
}

// gatewayContractURI is the URI SAN naming the contract a gateway
// certificate was issued for.
func gatewayContractURI(contractID string) *url.URL {
	return &url.URL{Scheme: "urn", Opaque: "p3dx:fl:contract:" + contractID}
}

// issueGatewayCert signs a gateway server certificate for csr's key, valid
// at ip, for contract c, from now until the contract's ValidUntil. Returns
// the certificate DER and its serial.
func (s *Server) issueGatewayCert(c *contract.Contract, csr *x509.CertificateRequest, ip net.IP, now time.Time) ([]byte, *big.Int, error) {
	if s.govKey == nil || s.govCA == nil {
		return nil, nil, errors.New("governance CA not loaded")
	}
	serial, err := govcrypto.RandomSerial()
	if err != nil {
		return nil, nil, err
	}
	keyUsage := x509.KeyUsageDigitalSignature
	if _, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "flotilla-gateway-" + c.ProjectID},
		IPAddresses:           []net.IP{ip},
		URIs:                  []*url.URL{gatewayContractURI(c.ContractID)},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		NotBefore:             now.Add(-gatewayCertBackdate),
		NotAfter:              c.Lifecycle.ValidUntil,
		AuthorityKeyId:        s.govCA.SubjectKeyId,
	}
	der, err := s.govKey.SignCertificate(tmpl, s.govCA, csr.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return der, serial, nil
}

// POST /gateway-certs — issue a Flotilla gateway TLS certificate.
// Body: {"csr_pem", "server_ip", and exactly one of "submission_id" (the
// session's latest contract) or "project_id" (that exact contract)}. The
// contract must be a final FL roster contract, fully signed, not expired.
func (s *Server) postGatewayCert(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireServiceToken(w, r, s.cfg.OrchestratorClientID, s.cfg.OrchestratorRole)
	if !ok {
		return
	}
	var body struct {
		CSRPEM       string `json:"csr_pem"`
		ServerIP     string `json:"server_ip"`
		SubmissionID string `json:"submission_id"`
		ProjectID    string `json:"project_id"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	body.SubmissionID = strings.TrimSpace(body.SubmissionID)
	body.ProjectID = strings.TrimSpace(body.ProjectID)
	if body.CSRPEM == "" || body.ServerIP == "" || (body.SubmissionID == "") == (body.ProjectID == "") {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_FIELDS",
			"message": "csr_pem, server_ip and exactly one of submission_id / project_id are required"})
		return
	}
	csr, err := parseGatewayCSR(body.CSRPEM)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_CSR", "message": err.Error()})
		return
	}
	ip := net.ParseIP(strings.TrimSpace(body.ServerIP))
	if ip == nil {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_IP",
			"message": "server_ip is not an IP address"})
		return
	}

	ctx := reqCtx(r)
	var raw json.RawMessage
	if body.ProjectID != "" {
		raw, err = s.gatewayStore.GetContractByProjectID(ctx, body.ProjectID)
	} else {
		raw, err = s.gatewayStore.GetContractBySession(ctx, body.SubmissionID)
	}
	if err != nil {
		log.Println("[GATEWAY-CERTS] Error loading contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if raw == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "CONTRACT_NOT_FOUND",
			"message": "No contract found for this submission_id / project_id"})
		return
	}
	var c contract.Contract
	if err := json.Unmarshal(raw, &c); err != nil {
		log.Println("[GATEWAY-CERTS] Error decoding contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if c.Technique != "FL" || !signable(&c) {
		writeJSON(w, http.StatusConflict, j{"status": "FAILED", "error": "CONTRACT_NOT_SIGNED",
			"message": "contract is not a final FL roster contract"})
		return
	}
	if _, _, allValid := s.verifyContractSignatures(ctx, &c); !allValid {
		writeJSON(w, http.StatusConflict, j{"status": "FAILED", "error": "CONTRACT_NOT_SIGNED",
			"message": "contract is not signed by the governance layer and every data provider"})
		return
	}
	now := time.Now()
	if !now.Before(c.Lifecycle.ValidUntil) {
		writeJSON(w, http.StatusGone, j{"status": "FAILED", "error": "CONTRACT_EXPIRED",
			"message": "contract expired at " + c.Lifecycle.ValidUntil.UTC().Format(time.RFC3339)})
		return
	}

	der, serial, err := s.issueGatewayCert(&c, csr, ip, now)
	if err != nil {
		log.Println("[GATEWAY-CERTS] Error issuing certificate:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Println("[GATEWAY-CERTS] Error parsing issued certificate:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	fp := sha256.Sum256(der)
	serialHex := serial.Text(16)
	fingerprint := hex.EncodeToString(fp[:])
	requestedBy, _ := claims["azp"].(string)

	// Record before returning: a certificate that isn't on record is never
	// handed out.
	if err := s.gatewayStore.InsertGatewayCert(ctx, postgres.GatewayCert{
		Serial:            serialHex,
		SubmissionID:      c.SessionInfo.SessionID,
		ProjectID:         c.ProjectID,
		ContractID:        c.ContractID,
		JobID:             c.JobID,
		ServerIP:          ip.String(),
		FingerprintSHA256: fingerprint,
		NotAfter:          cert.NotAfter,
		RequestedBy:       requestedBy,
	}); err != nil {
		log.Println("[GATEWAY-CERTS] Error recording certificate:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR",
			"message": "could not record the issued certificate"})
		return
	}
	log.Printf("[GATEWAY-CERTS] Issued serial %s for project %s (contract %s) at %s, expires %s",
		serialHex, c.ProjectID, c.ContractID, ip, cert.NotAfter.UTC().Format(time.RFC3339))

	parties := make([]j, 0, len(c.Parties.DataProviders))
	for _, p := range c.Parties.DataProviders {
		parties = append(parties, j{"id": p.ID, "name": p.Name})
	}
	writeJSON(w, http.StatusOK, j{
		"status":             "SUCCESS",
		"serial":             serialHex,
		"certificate_pem":    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"ca_certificate_pem": string(s.govCAPEM),
		"fingerprint_sha256": fingerprint,
		"not_after":          cert.NotAfter.UTC().Format(time.RFC3339),
		"contract_id":        c.ContractID,
		"project_id":         c.ProjectID,
		"job_id":             c.JobID,
		"submission_id":      c.SessionInfo.SessionID,
		"valid_until":        c.Lifecycle.ValidUntil.UTC().Format(time.RFC3339),
		"parties":            parties,
	})
}

// GET /governance/ca-cert — the governance CA certificate, PEM. Public: FL
// clients pin it to trust gateway certificates.
func (s *Server) getGovernanceCACert(w http.ResponseWriter, r *http.Request) {
	if len(s.govCAPEM) == 0 {
		writeJSON(w, http.StatusServiceUnavailable, j{"status": "FAILED", "error": "CA_NOT_LOADED"})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.govCAPEM)
}
