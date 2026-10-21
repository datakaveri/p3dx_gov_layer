package services

// The governance key (governance_key.go) is also gov_layer's certificate
// authority for the Flotilla join gateway: each FL session's gateway gets a
// TLS server certificate signed by it (httpapi/gateway_certs.go), and FL
// clients trust exactly this CA certificate. The CA certificate is self-signed
// with the governance key, generated on first start and persisted next to the
// key; if the key is ever replaced the old certificate no longer matches and
// is regenerated.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// governanceCAValidity is how long a freshly generated CA certificate lasts.
const governanceCAValidity = 5 * 365 * 24 * time.Hour

// Public returns the governance public key.
func (k *GovernanceKey) Public() *rsa.PublicKey { return &k.priv.PublicKey }

// SignCertificate issues template (signed by parent, for public key pub) with
// the governance private key and returns the certificate DER — a thin
// x509.CreateCertificate wrapper so the private key never leaves this type.
func (k *GovernanceKey) SignCertificate(template, parent *x509.Certificate, pub any) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, template, parent, pub, k.priv)
}

// RandomSerial returns a random positive 128-bit certificate serial number.
func RandomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

// LoadOrCreateGovernanceCACert reads the PEM CA certificate at path and
// returns it when its public key is the governance key's. Otherwise —
// missing, unparseable, or issued for a different key — it generates a new
// self-signed CA certificate with k and writes it there (0644). Returns the
// certificate and its PEM.
func LoadOrCreateGovernanceCACert(path string, k *GovernanceKey) (*x509.Certificate, []byte, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
			cert, perr := x509.ParseCertificate(block.Bytes)
			if perr == nil && k.Public().Equal(cert.PublicKey) {
				return cert, pem.EncodeToMemory(block), nil
			}
		}
		log.Printf("[WARN] Governance CA certificate %s does not match the governance key; regenerating it", path)
	case errors.Is(err, fs.ErrNotExist):
	default:
		return nil, nil, fmt.Errorf("read governance CA certificate %s: %w", path, err)
	}

	cert, certPEM, err := newGovernanceCACert(k, time.Now())
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, fmt.Errorf("create governance CA certificate dir: %w", err)
	}
	if err := os.WriteFile(path, certPEM, 0o644); err != nil {
		return nil, nil, fmt.Errorf("write governance CA certificate %s: %w", path, err)
	}
	return cert, certPEM, nil
}

// newGovernanceCACert builds the self-signed CA certificate for k. It may
// only sign leaf certificates (MaxPathLen 0).
func newGovernanceCACert(k *GovernanceKey, now time.Time) (*x509.Certificate, []byte, error) {
	serial, err := RandomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA serial: %w", err)
	}
	skid, err := SubjectKeyID(k.Public())
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "P3DX Governance CA", Organization: []string{"P3DX"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(governanceCAValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          skid,
	}
	der, err := k.SignCertificate(tmpl, tmpl, k.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("create governance CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// SubjectKeyID is the RFC 5280 method-1 key identifier of pub: the SHA-1 of
// its subjectPublicKey bit string.
func SubjectKeyID(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return sum[:], nil
}
