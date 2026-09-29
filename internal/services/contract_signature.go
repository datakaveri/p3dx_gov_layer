package services

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// ContractSignatureAlgorithm is the only scheme data providers sign a TEE
// contract hash with: RSASSA-PKCS1-v1_5 over SHA-256. It matches the RSA-2048
// key pair p3dx-aaa provisions per data provider (keyPair.service.js) and what
// the browser's WebCrypto produces with {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"}.
const ContractSignatureAlgorithm = "RSASSA-PKCS1-v1_5-SHA256"

// VerifyContractHashSignature checks that signatureB64 is a valid signature,
// by the private half of publicKeyPEM, over the UTF-8 bytes of contractHash
// (the "sha256:<hex>" string from contract.ComputeHash). WebCrypto can't sign
// a pre-computed digest, so the provider signs the hash string itself — which
// RSASSA then SHA-256s once more before signing; the same digest is rebuilt
// here.
func VerifyContractHashSignature(publicKeyPEM, contractHash, signatureB64 string) error {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return fmt.Errorf("public key is not valid PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not an RSA key")
	}

	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("signature is not valid base64: %w", err)
	}

	digest := sha256.Sum256([]byte(contractHash))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return fmt.Errorf("signature does not match contract hash")
	}
	return nil
}
