package services

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func testKeyPair(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func signHash(t *testing.T, priv *rsa.PrivateKey, hash string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(hash))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestVerifyContractHashSignature(t *testing.T) {
	priv, pubPEM := testKeyPair(t)
	_, otherPubPEM := testKeyPair(t)
	hash := "sha256:abc123"
	sig := signHash(t, priv, hash)

	if err := VerifyContractHashSignature(pubPEM, hash, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifyContractHashSignature(pubPEM, "sha256:tampered", sig); err == nil {
		t.Fatal("signature over a different hash was accepted")
	}
	if err := VerifyContractHashSignature(otherPubPEM, hash, sig); err == nil {
		t.Fatal("signature verified against the wrong public key")
	}
	if err := VerifyContractHashSignature("not pem", hash, sig); err == nil {
		t.Fatal("invalid PEM was accepted")
	}
	if err := VerifyContractHashSignature(pubPEM, hash, "!!notbase64"); err == nil {
		t.Fatal("invalid base64 was accepted")
	}
}
