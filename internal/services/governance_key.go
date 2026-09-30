package services

// The governance layer's own contract-signing key pair. Before a contract is
// sent to its data providers, gov_layer signs the contract hash with this
// private key (the "encrypt the hash with the governance private key" step)
// and ships the signature plus the public key with the sign request. Each
// provider verifies that signature with the governance public key — proving
// the hash really came from gov_layer and wasn't altered in transit — before
// signing the same hash with their own private key.
//
// The key is generated on first start and persisted, so sign requests that
// are already out stay verifiable across restarts.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// GovernanceKey is gov_layer's RSA-2048 contract-signing key pair.
type GovernanceKey struct {
	priv         *rsa.PrivateKey
	publicKeyPEM string
}

// LoadOrCreateGovernanceKey reads the PKCS#8 PEM private key at path, or
// generates a new RSA-2048 key and writes it there (0600) when none exists.
func LoadOrCreateGovernanceKey(path string) (*GovernanceKey, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("governance key %s is not valid PEM", path)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse governance key %s: %w", path, err)
		}
		priv, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("governance key %s is not an RSA key", path)
		}
		return newGovernanceKey(priv)
	case errors.Is(err, fs.ErrNotExist):
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate governance key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create governance key dir: %w", err)
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, fmt.Errorf("write governance key %s: %w", path, err)
		}
		return newGovernanceKey(priv)
	default:
		return nil, fmt.Errorf("read governance key %s: %w", path, err)
	}
}

// NewGovernanceKey wraps an existing private key (tests use this to avoid
// touching disk).
func NewGovernanceKey(priv *rsa.PrivateKey) (*GovernanceKey, error) {
	return newGovernanceKey(priv)
}

func newGovernanceKey(priv *rsa.PrivateKey) (*GovernanceKey, error) {
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &GovernanceKey{
		priv:         priv,
		publicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}, nil
}

// PublicKeyPEM is the SPKI ("PUBLIC KEY") PEM data providers verify the
// governance signature with — the format WebCrypto's importKey("spki") takes.
func (k *GovernanceKey) PublicKeyPEM() string { return k.publicKeyPEM }

// SignContractHash signs the UTF-8 bytes of contractHash with the governance
// private key using ContractSignatureAlgorithm — the same scheme providers
// sign with, so VerifyContractHashSignature(k.PublicKeyPEM(), ...) checks it.
// Returns the signature base64-encoded.
func (k *GovernanceKey) SignContractHash(contractHash string) (string, error) {
	digest := sha256.Sum256([]byte(contractHash))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
