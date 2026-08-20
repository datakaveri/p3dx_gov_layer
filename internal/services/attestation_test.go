package services

// Tests for MAA attestation-token verification.
//
// These mint tokens with a locally generated RSA key and serve the matching
// JWKS from an httptest server standing in for MAA, so the signature path, the
// nonce binding and every claim check are exercised for real rather than
// stubbed. The claim shape mirrors an actual token observed from
// sharedeus2.eus2.attest.azure.net on an SEV-SNP DC2as_v5 guest.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testKID = "test-maa-key"

// realLaunchMeasurement is the measurement observed on the demo CVM.
const realLaunchMeasurement = "5b0ce64ad1c1f6375dbda5f760b98526ca1bcf91b8195091afc28e7b024251d68fe32e05af34048d6607678cd23283ff"

// stubMAA is a fake attestation service: it serves a JWKS at /certs and signs
// tokens with the same key.
type stubMAA struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	issuer string
}

func newStubMAA(t *testing.T) *stubMAA {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}

	m := &stubMAA{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		// MAA publishes x5c chains, so mirror that: a self-signed cert
		// carrying the public key.
		der, err := x509.CreateCertificate(rand.Reader, certTemplate(), certTemplate(), &key.PublicKey, key)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kid": testKID,
				"kty": "RSA",
				"x5c": []string{base64.StdEncoding.EncodeToString(der)},
			}},
		})
	})

	m.server = httptest.NewServer(mux)
	m.issuer = m.server.URL
	t.Cleanup(m.server.Close)
	return m
}

// tokenOpts controls what the stub signs, so each test can bend one thing.
type tokenOpts struct {
	issuer          string
	nonce           string // raw nonce; encoded into the claim as base64
	attestationType string
	compliance      string
	debuggable      bool
	measurement     string
	expiresIn       time.Duration
	kid             string
	omitNonce       bool
}

func (m *stubMAA) mint(t *testing.T, o tokenOpts) string {
	t.Helper()

	if o.issuer == "" {
		o.issuer = m.issuer
	}
	if o.attestationType == "" {
		o.attestationType = "sevsnpvm"
	}
	if o.compliance == "" {
		o.compliance = "azure-compliant-cvm"
	}
	if o.measurement == "" {
		o.measurement = realLaunchMeasurement
	}
	if o.expiresIn == 0 {
		o.expiresIn = time.Hour
	}
	if o.kid == "" {
		o.kid = testKID
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":               o.issuer,
		"iat":               now.Unix(),
		"nbf":               now.Add(-time.Minute).Unix(),
		"exp":               now.Add(o.expiresIn).Unix(),
		"secureboot":        true,
		"x-ms-azurevm-vmid": "A2E6C98D-6C28-4180-AE99-204DF9D92BAF",
		"x-ms-isolation-tee": map[string]any{
			"x-ms-attestation-type":           o.attestationType,
			"x-ms-compliance-status":          o.compliance,
			"x-ms-sevsnpvm-is-debuggable":     o.debuggable,
			"x-ms-sevsnpvm-launchmeasurement": o.measurement,
			"x-ms-sevsnpvm-chip-family":       "Milan",
			"x-ms-sevsnpvm-guestsvn":          12,
			"x-ms-sevsnpvm-bootloader-svn":    4,
		},
	}
	if !o.omitNonce {
		claims["x-ms-runtime"] = map[string]any{
			"client-payload": map[string]any{
				"nonce": base64.StdEncoding.EncodeToString([]byte(o.nonce)),
			},
		}
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = o.kid
	signed, err := tok.SignedString(m.key)
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return signed
}

func TestNewAttestationNonce(t *testing.T) {
	a, err := NewAttestationNonce()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAttestationNonce()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two nonces were identical — challenges must be unpredictable")
	}
	raw, err := base64.StdEncoding.DecodeString(a)
	if err != nil {
		t.Fatalf("nonce is not base64: %v", err)
	}
	if len(raw) != nonceBytes {
		t.Fatalf("expected %d random bytes, got %d", nonceBytes, len(raw))
	}
}

// The happy path: a genuine-shaped token from the trusted issuer, carrying our
// nonce, with the measurement pinned.
func TestVerifyMAATokenAccepts(t *testing.T) {
	maa := newStubMAA(t)
	nonce := "Zm9vYmFyLW5vbmNlLXZhbHVlLTAxMjM0NTY3ODk="
	tok := maa.mint(t, tokenOpts{nonce: nonce})

	res, err := VerifyMAAToken(context.Background(), maa.server.Client(), tok, AttestationPolicy{
		AllowedIssuers:            []string{maa.issuer},
		Nonce:                     nonce,
		ExpectedLaunchMeasurement: realLaunchMeasurement,
	})
	if err != nil {
		t.Fatalf("expected token to verify, got: %v", err)
	}
	if !res.NonceVerified {
		t.Error("NonceVerified should be true")
	}
	if !res.MeasurementPinned {
		t.Error("MeasurementPinned should be true when a measurement was supplied")
	}
	if res.AttestationType != "sevsnpvm" {
		t.Errorf("attestation type = %q", res.AttestationType)
	}
	if res.Debuggable {
		t.Error("Debuggable should be false")
	}
	if res.Issuer != maa.issuer {
		t.Errorf("issuer = %q, want %q", res.Issuer, maa.issuer)
	}
}

// Measurement is optional; without it the token still verifies but is marked
// unpinned so a caller can tell the difference.
func TestVerifyMAATokenUnpinnedMeasurement(t *testing.T) {
	maa := newStubMAA(t)
	nonce := "bm9uY2UtdW5wcmlubmVkLTAxMjM0NTY3ODk="
	tok := maa.mint(t, tokenOpts{nonce: nonce})

	res, err := VerifyMAAToken(context.Background(), maa.server.Client(), tok, AttestationPolicy{
		AllowedIssuers: []string{maa.issuer},
		Nonce:          nonce,
	})
	if err != nil {
		t.Fatalf("expected verification to succeed: %v", err)
	}
	if res.MeasurementPinned {
		t.Error("MeasurementPinned should be false when no measurement was pinned")
	}
}

func TestVerifyMAATokenRejects(t *testing.T) {
	maa := newStubMAA(t)
	nonce := "Y2hhbGxlbmdlLW5vbmNlLXZhbHVlLTAxMjM0NTY3"

	tests := []struct {
		name    string
		token   func() string
		policy  func(*AttestationPolicy)
		wantErr string
	}{
		{
			// The security case that matters most: a genuine token captured
			// earlier must not authorise a later run.
			name:    "replayed token (nonce mismatch)",
			token:   func() string { return maa.mint(t, tokenOpts{nonce: "an-older-nonce"}) },
			wantErr: "nonce mismatch",
		},
		{
			// A token signed by an attestation service we do not trust.
			name: "untrusted issuer",
			token: func() string {
				other := newStubMAA(t)
				return other.mint(t, tokenOpts{nonce: nonce})
			},
			wantErr: "not in the allowed set",
		},
		{
			name:    "not an SEV-SNP guest",
			token:   func() string { return maa.mint(t, tokenOpts{nonce: nonce, attestationType: "tpm"}) },
			wantErr: "not an SEV-SNP guest",
		},
		{
			name:    "non-compliant CVM",
			token:   func() string { return maa.mint(t, tokenOpts{nonce: nonce, compliance: "unknown"}) },
			wantErr: "not an Azure-compliant CVM",
		},
		{
			// A debuggable guest's memory is readable by the host, defeating
			// the point of the TEE.
			name:    "debuggable guest",
			token:   func() string { return maa.mint(t, tokenOpts{nonce: nonce, debuggable: true}) },
			wantErr: "debuggable",
		},
		{
			name: "measurement mismatch",
			token: func() string {
				return maa.mint(t, tokenOpts{nonce: nonce, measurement: strings.Repeat("ab", 48)})
			},
			policy:  func(p *AttestationPolicy) { p.ExpectedLaunchMeasurement = realLaunchMeasurement },
			wantErr: "launch measurement mismatch",
		},
		{
			name:    "expired token",
			token:   func() string { return maa.mint(t, tokenOpts{nonce: nonce, expiresIn: -time.Hour}) },
			wantErr: "invalid",
		},
		{
			name:    "unknown signing key",
			token:   func() string { return maa.mint(t, tokenOpts{nonce: nonce, kid: "who-is-this"}) },
			wantErr: "invalid",
		},
		{
			name:    "no nonce claim at all",
			token:   func() string { return maa.mint(t, tokenOpts{omitNonce: true}) },
			wantErr: "nonce mismatch",
		},
		{
			name:    "empty token",
			token:   func() string { return "" },
			wantErr: "empty",
		},
		{
			name:    "garbage token",
			token:   func() string { return "not.a.jwt" },
			wantErr: "malformed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := AttestationPolicy{
				AllowedIssuers: []string{maa.issuer},
				Nonce:          nonce,
			}
			if tc.policy != nil {
				tc.policy(&policy)
			}
			_, err := VerifyMAAToken(context.Background(), maa.server.Client(), tc.token(), policy)
			if err == nil {
				t.Fatalf("expected rejection containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

// Missing policy inputs must fail closed rather than skip the check.
func TestVerifyMAATokenRequiresPolicy(t *testing.T) {
	maa := newStubMAA(t)
	tok := maa.mint(t, tokenOpts{nonce: "abc"})

	if _, err := VerifyMAAToken(context.Background(), maa.server.Client(), tok, AttestationPolicy{
		AllowedIssuers: []string{maa.issuer},
	}); err == nil || !strings.Contains(err.Error(), "Nonce is required") {
		t.Fatalf("expected a missing-nonce refusal, got %v", err)
	}

	if _, err := VerifyMAAToken(context.Background(), maa.server.Client(), tok, AttestationPolicy{
		Nonce: "abc",
	}); err == nil || !strings.Contains(err.Error(), "no attestation service is trusted") {
		t.Fatalf("expected an empty-allowlist refusal, got %v", err)
	}
}

// An untrusted issuer must be refused without the verifier ever contacting it,
// so a forged token cannot be used to make us fetch from an attacker's server.
func TestVerifyMAATokenDoesNotFetchUntrustedIssuer(t *testing.T) {
	hit := false
	rogue := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(200)
	}))
	defer rogue.Close()

	maa := newStubMAA(t)
	tok := maa.mint(t, tokenOpts{issuer: rogue.URL, nonce: "abc"})

	_, err := VerifyMAAToken(context.Background(), maa.server.Client(), tok, AttestationPolicy{
		AllowedIssuers: []string{maa.issuer}, // rogue.URL deliberately absent
		Nonce:          "abc",
	})
	if err == nil {
		t.Fatal("expected rejection of untrusted issuer")
	}
	if hit {
		t.Fatal("verifier contacted the untrusted issuer — allowlist must be checked before any fetch")
	}
}

func TestIssuerAllowed(t *testing.T) {
	allowed := []string{"https://a.attest.azure.net", " https://b.attest.azure.net/ "}
	for _, in := range []string{"https://a.attest.azure.net", "https://b.attest.azure.net"} {
		if !issuerAllowed(in, allowed) {
			t.Errorf("%q should be allowed (whitespace/trailing slash must be tolerated)", in)
		}
	}
	for _, in := range []string{"", "https://evil.example", "https://a.attest.azure.net.evil.example"} {
		if issuerAllowed(in, allowed) {
			t.Errorf("%q must not be allowed", in)
		}
	}
}

// certTemplate is a minimal self-signed template for the stub JWKS's x5c entry.
func certTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "stub-maa"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}
