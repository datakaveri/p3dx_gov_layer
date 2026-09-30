package httpapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/userdir"
)

type stubKeys map[string]string

func (k stubKeys) PublicKey(_ context.Context, username string) (string, error) {
	if pub, ok := k[username]; ok {
		return pub, nil
	}
	return "", userdir.ErrUserNotFound
}

func newRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func signWith(t *testing.T, priv *rsa.PrivateKey, hash string) string {
	t.Helper()
	d := sha256.Sum256([]byte(hash))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// twoProviderContract builds a hashed TEE contract that srv has
// governance-signed, ready for its two providers to sign.
func twoProviderContract(t *testing.T, srv *Server) contract.Contract {
	t.Helper()
	c := contract.Contract{
		ContractID: "c-1",
		Technique:  "TEE",
		Parties: contract.Parties{DataProviders: []contract.DataProviderParty{
			{ID: "provider-alice", DatasetName: "a", DataURL: "https://x/a"},
			{ID: "provider-bob", DatasetName: "b", DataURL: "https://x/b"},
		}},
	}
	h, err := contract.ComputeHash(c)
	if err != nil {
		t.Fatal(err)
	}
	c.ContractHash = h
	if err := srv.governanceSign(&c); err != nil {
		t.Fatal(err)
	}
	return c
}

func sign(c *contract.Contract, i int, signer, value string) {
	now := time.Now()
	c.Parties.DataProviders[i].Signature = contract.Signature{
		SignedAt: &now, Signer: signer, SignedHash: c.ContractHash, Value: value,
		Algorithm: services.ContractSignatureAlgorithm,
	}
}

func TestProviderIDForUsername(t *testing.T) {
	cases := map[string]string{"alice": "provider-alice", "Bob.Smith": "provider-bob-smith", "-x_y-": "provider-x-y"}
	for in, want := range cases {
		if got := providerIDForUsername(in); got != want {
			t.Errorf("providerIDForUsername(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerifyContractSignatures(t *testing.T) {
	alice, alicePub := newRSAKey(t)
	bob, bobPub := newRSAKey(t)
	srv := newTestServer(nil)
	srv.publicKeys = stubKeys{"alice": alicePub, "bob": bobPub}
	ctx := context.Background()

	c := twoProviderContract(t, srv)
	sign(&c, 0, "alice", signWith(t, alice, c.ContractHash))
	if _, _, all := srv.verifyContractSignatures(ctx, &c); all {
		t.Fatal("all_signed with bob still unsigned")
	}

	sign(&c, 1, "bob", signWith(t, bob, c.ContractHash))
	if parties, hashOK, all := srv.verifyContractSignatures(ctx, &c); !hashOK || !all {
		t.Fatalf("expected all valid, got hashOK=%t parties=%+v", hashOK, parties)
	}

	// bob's signature made with alice's key must fail against bob's Keycloak key.
	forged := c
	forged.Parties.DataProviders = append([]contract.DataProviderParty(nil), c.Parties.DataProviders...)
	sign(&forged, 1, "bob", signWith(t, alice, c.ContractHash))
	if _, _, all := srv.verifyContractSignatures(ctx, &forged); all {
		t.Fatal("signature by the wrong key was accepted")
	}

	// A signer whose username doesn't map to the party's provider_id.
	swapped := c
	swapped.Parties.DataProviders = append([]contract.DataProviderParty(nil), c.Parties.DataProviders...)
	sign(&swapped, 1, "alice", signWith(t, alice, c.ContractHash))
	if _, _, all := srv.verifyContractSignatures(ctx, &swapped); all {
		t.Fatal("alice signing bob's party was accepted")
	}

	// Without a valid governance signature the contract never passes.
	noGov := c
	noGov.GovernanceSignature = nil
	if _, _, all := srv.verifyContractSignatures(ctx, &noGov); all {
		t.Fatal("contract without a governance signature passed verification")
	}
	otherGov := newTestServer(nil) // a different governance key
	otherGov.publicKeys = srv.publicKeys
	if _, _, all := otherGov.verifyContractSignatures(ctx, &c); all {
		t.Fatal("governance signature from another key was accepted")
	}

	// Tampering with the contract after signing breaks the hash.
	tampered := c
	tampered.Parties.DataProviders = append([]contract.DataProviderParty(nil), c.Parties.DataProviders...)
	tampered.Parties.DataProviders[0].DataURL = "https://evil/a"
	if _, hashOK, all := srv.verifyContractSignatures(ctx, &tampered); hashOK || all {
		t.Fatal("tampered contract passed verification")
	}
}

// The governance signature is over the hash and doesn't change it, so
// signing never invalidates the hash being signed.
func TestGovernanceSignatureLeavesHashStable(t *testing.T) {
	srv := newTestServer(nil)
	c := twoProviderContract(t, srv)
	h, err := contract.ComputeHash(c)
	if err != nil {
		t.Fatal(err)
	}
	if h != c.ContractHash {
		t.Fatalf("hash changed after governance signing: %s != %s", h, c.ContractHash)
	}
	if err := services.VerifyContractHashSignature(srv.govKey.PublicKeyPEM(), c.ContractHash, c.GovernanceSignature.Value); err != nil {
		t.Fatalf("governance signature doesn't verify with the governance public key: %v", err)
	}
}

// FL roster contracts carry the Keycloak user id as the party ID and the
// username in Name; they're only signable once finalized (version 2), and
// the accept-invite SignedAt marker alone doesn't count as a signature.
func TestFLContractSigning(t *testing.T) {
	alice, alicePub := newRSAKey(t)
	srv := newTestServer(nil)
	srv.publicKeys = stubKeys{"alice": alicePub}
	ctx := context.Background()

	now := time.Now()
	c := contract.Contract{
		ContractID: "fl-1",
		Technique:  "FL",
		Version:    1,
		Parties: contract.Parties{DataProviders: []contract.DataProviderParty{
			{ID: "5f0c-keycloak-uuid", Name: "alice", Signature: contract.Signature{SignedAt: &now}},
		}},
	}
	if signable(&c) {
		t.Fatal("draft FL contract reported signable")
	}
	c.Version = 2
	if !signable(&c) {
		t.Fatal("final roster FL contract not signable")
	}
	if got := partyProviderID(c.Parties.DataProviders[0]); got != "provider-alice" {
		t.Fatalf("partyProviderID = %q, want provider-alice", got)
	}

	h, _ := contract.ComputeHash(c)
	c.ContractHash = h
	if err := srv.governanceSign(&c); err != nil {
		t.Fatal(err)
	}
	if parties, _, all := srv.verifyContractSignatures(ctx, &c); all || parties[0].Signed {
		t.Fatal("accept-invite marker counted as a signature")
	}

	sign(&c, 0, "alice", signWith(t, alice, c.ContractHash))
	if parties, hashOK, all := srv.verifyContractSignatures(ctx, &c); !hashOK || !all {
		t.Fatalf("expected FL contract fully signed, got parties=%+v", parties)
	}
}

// With the gate on, a TEE/SMPC run that doesn't name a signed contract never
// reaches VM provisioning.
func TestProvisionBlockedWithoutSignedContract(t *testing.T) {
	srv := newTestServer(&config.Config{TEEAzureRG: "TEE", TEEVMName: "vm-1", RequireSignedContract: true})

	body, _ := json.Marshal(validContract()) // no governanceContractId
	for _, path := range []string{"/v1/tee/provision", "/v1/tee/sessions"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: expected 403, got %d (body: %s)", path, rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["error"] != "CONTRACT_NOT_SIGNED" {
			t.Fatalf("%s: expected CONTRACT_NOT_SIGNED, got %v", path, resp["error"])
		}
	}
}
