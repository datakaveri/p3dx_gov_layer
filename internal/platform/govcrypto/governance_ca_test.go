package govcrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestGovernanceKey(t *testing.T) *GovernanceKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k, err := NewGovernanceKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestGovernanceCACertCreatedAndReloaded(t *testing.T) {
	k := newTestGovernanceKey(t)
	path := filepath.Join(t.TempDir(), "keys", "governance_ca.pem")

	ca, caPEM, err := LoadOrCreateGovernanceCACert(path, k)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.MaxPathLen != 0 || !ca.MaxPathLenZero {
		t.Fatalf("CA constraints wrong: IsCA=%t BCV=%t MaxPathLen=%d Zero=%t", ca.IsCA, ca.BasicConstraintsValid, ca.MaxPathLen, ca.MaxPathLenZero)
	}
	if ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("CA key usage = %v", ca.KeyUsage)
	}
	if ca.Subject.CommonName != "P3DX Governance CA" || len(ca.SubjectKeyId) == 0 {
		t.Fatalf("CA subject/SKID wrong: %v %x", ca.Subject, ca.SubjectKeyId)
	}
	if !k.Public().Equal(ca.PublicKey) {
		t.Fatal("CA public key is not the governance key")
	}
	if err := ca.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("CA is not self-signed: %v", err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(onDisk, caPEM) {
		t.Fatalf("CA PEM not written: %v", err)
	}

	again, againPEM, err := LoadOrCreateGovernanceCACert(path, k)
	if err != nil {
		t.Fatal(err)
	}
	if again.SerialNumber.Cmp(ca.SerialNumber) != 0 || !bytes.Equal(againPEM, caPEM) {
		t.Fatal("existing CA certificate was not reused")
	}
}

func TestGovernanceCACertRegeneratedOnKeyChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "governance_ca.pem")
	old, _, err := LoadOrCreateGovernanceCACert(path, newTestGovernanceKey(t))
	if err != nil {
		t.Fatal(err)
	}
	k := newTestGovernanceKey(t)
	ca, _, err := LoadOrCreateGovernanceCACert(path, k)
	if err != nil {
		t.Fatal(err)
	}
	if ca.SerialNumber.Cmp(old.SerialNumber) == 0 || !k.Public().Equal(ca.PublicKey) {
		t.Fatal("CA certificate not regenerated for the new key")
	}
}

func TestSignCertificateLeafVerifiesAgainstCA(t *testing.T) {
	k := newTestGovernanceKey(t)
	ca, _, err := LoadOrCreateGovernanceCACert(filepath.Join(t.TempDir(), "ca.pem"), k)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := RandomSerial()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	der, err := k.SignCertificate(&x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "leaf"},
		IPAddresses:  []net.IP{net.ParseIP("10.0.0.5")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
	}, ca, &leafKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "10.0.0.5"}); err != nil {
		t.Fatalf("leaf does not verify against the CA: %v", err)
	}
	if !bytes.Equal(leaf.AuthorityKeyId, ca.SubjectKeyId) {
		t.Fatal("leaf AuthorityKeyId does not match CA SubjectKeyId")
	}
}
