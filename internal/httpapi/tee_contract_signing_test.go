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

func twoProviderContract(t *testing.T) contract.Contract {
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

	c := twoProviderContract(t)
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

	// Tampering with the contract after signing breaks the hash.
	tampered := c
	tampered.Parties.DataProviders = append([]contract.DataProviderParty(nil), c.Parties.DataProviders...)
	tampered.Parties.DataProviders[0].DataURL = "https://evil/a"
	if _, hashOK, all := srv.verifyContractSignatures(ctx, &tampered); hashOK || all {
		t.Fatal("tampered contract passed verification")
	}
}

// With the gate on, a TEE run that doesn't name a signed contract never
// reaches VM provisioning.
func TestProvisionBlockedWithoutSignedContract(t *testing.T) {
	srv := newTestServer(&config.Config{TEEAzureRG: "TEE", TEEVMName: "vm-1", TEERequireSignedContract: true})

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
