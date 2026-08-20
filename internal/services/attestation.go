package services

// Verification of Microsoft Azure Attestation (MAA) tokens for SEV-SNP
// confidential VMs.
//
// The guest runs Azure's AttestationClient, which talks to the AMD PSP, has the
// hardware sign a report, and exchanges it at an MAA endpoint for a signed JWT.
// MAA has already done the AMD certificate-chain work (ARK -> ASK -> VCEK) and
// the report-signature check; what reaches us is MAA's *assertion* about the
// guest, so verifying it means verifying MAA's signature and then reading the
// claims MAA vouched for.
//
// That is a different trust model from p3dx-apd's internal/service/attestation.go,
// which parses the raw 1184-byte SNP report and checks the AMD chain itself. That
// path trusts only AMD; this one also trusts MAA. We use MAA because it is what
// the guest tooling already produces (AttestationClient -o token), and because
// Azure does not hand a CVM guest the raw VCEK chain by default. The cost is one
// extra trusted party, which is why the issuer allowlist below matters: it is the
// only thing pinning *which* MAA we believe.
//
// What a passing verification does and does not establish is documented on
// VerifyMAAToken.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AttestationPolicy is what a token is checked against.
type AttestationPolicy struct {
	// AllowedIssuers is the set of MAA endpoints whose assertions we accept,
	// e.g. "https://sharedeus2.eus2.attest.azure.net". This is the trust anchor:
	// without it an attacker could present a well-formed token signed by an
	// attestation service they control. Empty means no token can verify.
	AllowedIssuers []string

	// Nonce is the value this orchestrator generated for this attestation. The
	// token must carry it, which is what makes the token fresh rather than a
	// replay of an earlier genuine one. Required.
	Nonce string

	// ExpectedLaunchMeasurement, when set, pins the guest's SEV-SNP launch
	// measurement (hex SHA-384) — the boot state of the VM. Leaving it empty
	// accepts any measurement, which still proves "a genuine non-debuggable
	// SEV-SNP CVM" but not "the VM image we expect".
	ExpectedLaunchMeasurement string

	// Leeway absorbs clock skew when checking exp/nbf.
	Leeway time.Duration
}

// AttestationResult is the useful content of a verified token.
type AttestationResult struct {
	Issuer            string    `json:"issuer"`
	VMID              string    `json:"vm_id"`
	AttestationType   string    `json:"attestation_type"`
	ComplianceStatus  string    `json:"compliance_status"`
	LaunchMeasurement string    `json:"launch_measurement"`
	ChipFamily        string    `json:"chip_family"`
	GuestSVN          int       `json:"guest_svn"`
	BootloaderSVN     int       `json:"bootloader_svn"`
	SecureBoot        bool      `json:"secure_boot"`
	Debuggable        bool      `json:"debuggable"`
	MeasurementPinned bool      `json:"measurement_pinned"`
	NonceVerified     bool      `json:"nonce_verified"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	VerifiedAt        time.Time `json:"verified_at"`
}

// maaClaims mirrors the subset of an MAA CVM token we read.
type maaClaims struct {
	jwt.RegisteredClaims

	SecureBoot bool   `json:"secureboot"`
	VMID       string `json:"x-ms-azurevm-vmid"`

	// Where AttestationClient's -n value surfaces, base64-encoded.
	Runtime struct {
		ClientPayload struct {
			Nonce string `json:"nonce"`
		} `json:"client-payload"`
	} `json:"x-ms-runtime"`

	// The hardware-rooted part of the token.
	IsolationTEE struct {
		AttestationType   string `json:"x-ms-attestation-type"`
		ComplianceStatus  string `json:"x-ms-compliance-status"`
		LaunchMeasurement string `json:"x-ms-sevsnpvm-launchmeasurement"`
		ChipFamily        string `json:"x-ms-sevsnpvm-chip-family"`
		GuestSVN          int    `json:"x-ms-sevsnpvm-guestsvn"`
		BootloaderSVN     int    `json:"x-ms-sevsnpvm-bootloader-svn"`
		IsDebuggable      bool   `json:"x-ms-sevsnpvm-is-debuggable"`
	} `json:"x-ms-isolation-tee"`
}

// VerifyMAAToken verifies an MAA attestation token against policy.
//
// A nil error establishes that, at the moment the token was minted:
//   - an MAA instance on the allowlist signed this assertion;
//   - the guest is a genuine AMD SEV-SNP confidential VM
//     (x-ms-attestation-type "sevsnpvm", Azure-compliant);
//   - the guest is NOT debuggable, so its memory cannot be inspected by the host;
//   - the token is fresh — it carries the nonce we just generated;
//   - if a measurement was pinned, the VM booted the expected image.
//
// It does NOT establish which *container* ran inside the guest. The SEV-SNP
// launch measurement covers guest firmware/kernel/initrd, not a docker image
// pulled later at runtime, so a contract's appDetails.imageHash (a container
// digest) is a different quantity and cannot be compared against it. Binding the
// workload itself needs the guest to measure the image into a PCR that MAA
// attests, or the image digest carried in report_data/host_data.
func VerifyMAAToken(ctx context.Context, client *http.Client, tokenStr string, policy AttestationPolicy) (*AttestationResult, error) {
	if strings.TrimSpace(tokenStr) == "" {
		return nil, fmt.Errorf("attestation token is empty")
	}
	if policy.Nonce == "" {
		return nil, fmt.Errorf("policy.Nonce is required: without it a replayed token would verify")
	}
	if len(policy.AllowedIssuers) == 0 {
		return nil, fmt.Errorf("policy.AllowedIssuers is empty: no attestation service is trusted")
	}

	// Read the issuer without trusting the signature yet, purely to decide which
	// JWKS to fetch — and refuse anything not on the allowlist BEFORE making
	// that request. Deriving the JWKS URL from the validated issuer (never from
	// the token's own `jku` header) is what stops a forged token from pointing
	// us at an attacker-controlled key set.
	var unverified maaClaims
	if _, _, err := jwt.NewParser().ParseUnverified(tokenStr, &unverified); err != nil {
		return nil, fmt.Errorf("malformed attestation token: %w", err)
	}
	issuer := strings.TrimRight(unverified.Issuer, "/")
	if !issuerAllowed(issuer, policy.AllowedIssuers) {
		return nil, fmt.Errorf("attestation issuer %q is not in the allowed set %v", issuer, policy.AllowedIssuers)
	}

	keys, err := fetchJWKS(ctx, client, issuer+"/certs")
	if err != nil {
		return nil, fmt.Errorf("fetch MAA signing keys: %w", err)
	}

	var claims maaClaims
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithLeeway(policy.Leeway),
		jwt.WithIssuer(issuer),
	)
	token, err := parser.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("no MAA signing key for kid %q", kid)
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("attestation token signature/claims invalid: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("attestation token is not valid")
	}

	// Freshness. The claim holds base64(nonce-we-sent); compare in constant time
	// so the check cannot be probed byte by byte.
	rawNonce, err := base64.StdEncoding.DecodeString(claims.Runtime.ClientPayload.Nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce claim is not valid base64: %w", err)
	}
	if subtle.ConstantTimeCompare(rawNonce, []byte(policy.Nonce)) != 1 {
		return nil, fmt.Errorf("nonce mismatch: token does not answer this attestation challenge (possible replay)")
	}

	iso := claims.IsolationTEE

	// Genuine SEV-SNP, not some other (or absent) isolation technology.
	if iso.AttestationType != "sevsnpvm" {
		return nil, fmt.Errorf("not an SEV-SNP guest: x-ms-attestation-type is %q, want \"sevsnpvm\"", iso.AttestationType)
	}
	if iso.ComplianceStatus != "azure-compliant-cvm" {
		return nil, fmt.Errorf("guest is not an Azure-compliant CVM: compliance status %q", iso.ComplianceStatus)
	}

	// A debuggable guest can have its memory read by the host, which defeats the
	// entire point of running the workload in a TEE.
	if iso.IsDebuggable {
		return nil, fmt.Errorf("guest is debuggable: TEE memory protection cannot be relied on")
	}

	measurementPinned := false
	if policy.ExpectedLaunchMeasurement != "" {
		got := strings.ToLower(iso.LaunchMeasurement)
		want := strings.ToLower(policy.ExpectedLaunchMeasurement)
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			return nil, fmt.Errorf("launch measurement mismatch:\n  got : %s\n  want: %s", got, want)
		}
		measurementPinned = true
	}

	result := &AttestationResult{
		Issuer:            issuer,
		VMID:              claims.VMID,
		AttestationType:   iso.AttestationType,
		ComplianceStatus:  iso.ComplianceStatus,
		LaunchMeasurement: strings.ToLower(iso.LaunchMeasurement),
		ChipFamily:        iso.ChipFamily,
		GuestSVN:          iso.GuestSVN,
		BootloaderSVN:     iso.BootloaderSVN,
		SecureBoot:        claims.SecureBoot,
		Debuggable:        iso.IsDebuggable,
		MeasurementPinned: measurementPinned,
		NonceVerified:     true,
		VerifiedAt:        time.Now().UTC(),
	}
	if claims.IssuedAt != nil {
		result.IssuedAt = claims.IssuedAt.Time.UTC()
	}
	if claims.ExpiresAt != nil {
		result.ExpiresAt = claims.ExpiresAt.Time.UTC()
	}
	return result, nil
}

// nonceBytes is the challenge size. 32 bytes makes collision or prediction
// infeasible, and stays inside the length the guest's AttestationClient accepts.
const nonceBytes = 32

// NewAttestationNonce returns a fresh random challenge, base64-encoded.
//
// The orchestrator must generate this — never the guest. A guest-chosen nonce
// would let a compromised VM replay a token captured while it was still honest.
func NewAttestationNonce() (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate attestation nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// issuerAllowed reports whether issuer is on the allowlist (exact match after
// trimming a trailing slash).
func issuerAllowed(issuer string, allowed []string) bool {
	if issuer == "" {
		return false
	}
	for _, a := range allowed {
		if issuer == strings.TrimRight(strings.TrimSpace(a), "/") {
			return true
		}
	}
	return false
}

// jwksResponse is the JWKS document MAA serves at {issuer}/certs.
type jwksResponse struct {
	Keys []struct {
		Kid string   `json:"kid"`
		Kty string   `json:"kty"`
		N   string   `json:"n"`
		E   string   `json:"e"`
		X5c []string `json:"x5c"`
	} `json:"keys"`
}

// maxJWKSBytes caps the JWKS body so a hostile or broken endpoint cannot make us
// read unboundedly.
const maxJWKSBytes = 1 << 20

// fetchJWKS retrieves MAA's signing keys, keyed by kid. MAA publishes them as
// x5c certificate chains; the n/e form is handled too since the JWK spec allows
// either.
func fetchJWKS(ctx context.Context, client *http.Client, url string) (map[string]*rsa.PublicKey, error) {
	if client == nil {
		client = http.DefaultClient
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
	}

	var doc jwksResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "" && k.Kty != "RSA" {
			continue
		}
		pub, err := jwkToRSA(k.X5c, k.N, k.E)
		if err != nil {
			// Skip unusable entries rather than failing the whole set: MAA may
			// publish keys of kinds we don't handle alongside the one we need.
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no usable RSA signing keys at %s", url)
	}
	return keys, nil
}

// jwkToRSA builds an RSA public key from an x5c chain (preferred, as MAA uses
// it) or from raw n/e parameters.
func jwkToRSA(x5c []string, nB64, eB64 string) (*rsa.PublicKey, error) {
	if len(x5c) > 0 {
		der, err := base64.StdEncoding.DecodeString(x5c[0])
		if err != nil {
			return nil, fmt.Errorf("decode x5c: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse x5c cert: %w", err)
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("x5c key is not RSA")
		}
		return pub, nil
	}

	if nB64 == "" || eB64 == "" {
		return nil, fmt.Errorf("JWK has neither x5c nor n/e")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(nB64, "="))
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(eB64, "="))
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}
