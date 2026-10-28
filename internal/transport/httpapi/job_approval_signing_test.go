package httpapi

import (
	"context"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/application/contractgen"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/application/jobapproval"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

func approvalContract() *contract.Contract {
	return &contract.Contract{JobID: "job-1", ContractID: "contract-1", Technique: "SMPC", Parties: contract.Parties{
		DataProviders:  []contract.DataProviderParty{{ID: "provider-alice", DatasetID: dsHeart, DatasetName: "heart"}},
		InfraProviders: []contract.InfraProviderParty{{ID: "infra-1", Name: "Pune DC"}},
	}}
}

// GET /job/{jobId}/status cross-verifies every provider's submitted
// signature: over gov_layer's own hash of the contract, verifying with the
// signer's registered public key, and an infra signed by its owner.
func TestVerifyJobSignatures(t *testing.T) {
	stubAPD(t) // infra-1 is provider-ivan's
	alice, alicePub := newRSAKey(t)
	ivan, ivanPub := newRSAKey(t)
	srv := newTestServer(&config.Config{RequireInfraApproval: true})
	srv.publicKeys = stubKeys{"alice@example.com": alicePub, "ivan": ivanPub}

	base := approvalContract()
	base.Parties.DataProviders[0].ID = "provider-alice-example-com"
	hash, err := contract.ComputeHash(*base)
	if err != nil {
		t.Fatal(err)
	}
	sig := func(signer, signedHash, value string) contract.Signature {
		return contract.Signature{Signer: signer, SignedHash: signedHash, Value: value}
	}
	for _, tc := range []struct {
		name        string
		data, infra contract.Signature
		wantReasons []string
	}{
		{"all valid", sig("alice@example.com", hash, signWith(t, alice, hash)), sig("ivan", hash, signWith(t, ivan, hash)), nil},
		{"infra not signed yet", sig("alice@example.com", hash, signWith(t, alice, hash)), contract.Signature{},
			[]string{"infra infra-1: not signed yet"}},
		{"other hash submitted", sig("alice@example.com", "sha256:00", signWith(t, alice, "sha256:00")), sig("ivan", hash, signWith(t, ivan, hash)),
			[]string{"provider-alice-example-com: signed a different contract hash"}},
		{"signed with another key", sig("alice@example.com", hash, signWith(t, ivan, hash)), sig("ivan", hash, signWith(t, ivan, hash)),
			[]string{"provider-alice-example-com: signature does not verify"}},
		{"infra signed by someone else", sig("alice@example.com", hash, signWith(t, alice, hash)), sig("alice@example.com", hash, signWith(t, alice, hash)),
			[]string{"infra infra-1: signer does not match provider_id"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := approvalContract()
			c.Parties.DataProviders[0].ID = "provider-alice-example-com"
			c.Parties.DataProviders[0].Signature = tc.data
			c.Parties.InfraProviders[0].Signature = tc.infra
			parties, reasons := srv.approvals().VerifyJobSignatures(context.Background(), c)
			if len(parties) != 2 {
				t.Fatalf("parties = %+v, want data + infra", parties)
			}
			if len(reasons) != len(tc.wantReasons) {
				t.Fatalf("reasons = %q, want %q", reasons, tc.wantReasons)
			}
			for i, want := range tc.wantReasons {
				if !strings.HasPrefix(reasons[i], want) {
					t.Errorf("reason %d = %q, want prefix %q", i, reasons[i], want)
				}
			}
		})
	}
}

// On a job-approval contract the infra provider's signature (made when
// approving) is required alongside the data providers', and no governance
// signature is.
func TestVerifyContractSignaturesWithInfra(t *testing.T) {
	alice, alicePub := newRSAKey(t)
	ivan, ivanPub := newRSAKey(t)
	srv := newTestServer(&config.Config{RequireInfraApproval: true})
	srv.publicKeys = stubKeys{"alice": alicePub, "ivan": ivanPub}
	ctx := context.Background()

	c := approvalContract()
	hash, _ := contract.ComputeHash(*c)
	c.ContractHash = hash
	sig := func(signer string, value string) contract.Signature {
		return contract.Signature{Signer: signer, SignedHash: hash, Value: value}
	}
	c.Parties.DataProviders[0].Signature = sig("alice", signWith(t, alice, hash))

	parties, _, all := srv.verifyContractSignatures(ctx, c)
	if all || len(parties) != 2 || parties[1].Role != postgres.AuditTypeInfraProvider || parties[1].InfraID != "infra-1" || parties[1].Signed {
		t.Fatalf("infra unsigned: all=%v parties=%+v", all, parties)
	}

	c.Parties.InfraProviders[0].Signature = sig("ivan", signWith(t, alice, hash)) // wrong key
	if _, _, all := srv.verifyContractSignatures(ctx, c); all {
		t.Fatal("infra signature made with another key was accepted")
	}

	c.Parties.InfraProviders[0].Signature = sig("ivan", signWith(t, ivan, hash))
	parties, _, all = srv.verifyContractSignatures(ctx, c)
	if !all || parties[1].ProviderID != "provider-ivan" || !parties[1].Valid {
		t.Fatalf("all signed: all=%v parties=%+v", all, parties)
	}

	// With REQUIRE_INFRA_APPROVAL=false the infra doesn't sign.
	srv.cfg.RequireInfraApproval = false
	c.Parties.InfraProviders[0].Signature = contract.Signature{}
	if parties, _, all := srv.verifyContractSignatures(ctx, c); !all || len(parties) != 1 {
		t.Fatalf("infra approval off: all=%v parties=%+v", all, parties)
	}
}

// An approved job whose signatures don't all verify yet isn't made final;
// Finalize says what's pending (and never touches the DB). A missing
// governance signature isn't among it: job contracts carry none.
func TestFinalizeJobPending(t *testing.T) {
	alice, alicePub := newRSAKey(t)
	srv := newTestServer(&config.Config{RequireInfraApproval: true})
	srv.publicKeys = stubKeys{"alice": alicePub}

	c := approvalContract()
	hash, _ := contract.ComputeHash(*c)
	c.ContractHash = hash
	c.Parties.DataProviders[0].Signature = contract.Signature{Signer: "alice", SignedHash: hash, Value: signWith(t, alice, hash)}

	// Infra unsigned; no governance signature, and none needed.
	final, pending, err := srv.approvals().Finalize(context.Background(), "job-1", c)
	if err != nil || final {
		t.Fatalf("final=%v err=%v, want not final", final, err)
	}
	if len(pending) != 1 || pending[0] != "infra infra-1: not signed yet" {
		t.Errorf("pending = %q, want only the infra signature", pending)
	}
}

// Contracts outside the job-approval flow (no real infra) don't need the
// TEE to be enabled.
func TestRequireTEEEnabledSkipsNonJobContracts(t *testing.T) {
	c := &contract.Contract{Parties: contract.Parties{
		DataProviders:  []contract.DataProviderParty{{ID: "provider-alice"}},
		InfraProviders: []contract.InfraProviderParty{{Name: "Azure Confidential Compute"}},
	}}
	if err := (&Server{}).requireTEEEnabled(context.Background(), c); err != nil {
		t.Fatalf("err = %v, want nil for a non-job contract", err)
	}
}

// POST /job/approval/data-provider verifies the submitted signature at once:
// over gov_layer's own hash of the stored contract, with the caller's
// registered public key.
func TestVerifySubmittedSignature(t *testing.T) {
	alice, alicePub := newRSAKey(t)
	other, _ := newRSAKey(t)
	srv := newTestServer(&config.Config{})
	srv.publicKeys = stubKeys{"alice@example.com": alicePub}

	c := approvalContract()
	hash, err := contract.ComputeHash(*c)
	if err != nil {
		t.Fatal(err)
	}
	caller := jobapproval.Caller{Username: "alice@example.com"}
	stranger := jobapproval.Caller{Username: "mallory@example.com"}
	for _, tc := range []struct {
		name    string
		caller  jobapproval.Caller
		body    approvalBody
		wantErr string
	}{
		{"valid", caller, approvalBody{ContractHash: hash, Signature: signWith(t, alice, hash)}, ""},
		{"other hash", caller, approvalBody{ContractHash: "sha256:00", Signature: signWith(t, alice, "sha256:00")}, "is not this job's contract hash"},
		{"wrong key", caller, approvalBody{ContractHash: hash, Signature: signWith(t, other, hash)}, "does not verify"},
		{"no registered key", stranger, approvalBody{ContractHash: hash, Signature: signWith(t, alice, hash)}, "no registered public key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := srv.approvals().VerifySignature(context.Background(), c, tc.caller, tc.body.ContractHash, tc.body.Signature)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("err = %v, want nil", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// A job's contract carries the contract_hash stored at /generate-contract;
// verification uses it, and refuses a contract edited since.
func TestJobContractHash(t *testing.T) {
	c := approvalContract()
	fresh, err := contract.ComputeHash(*c)
	if err != nil {
		t.Fatal(err)
	}

	// Stored before the hash was kept with the contract: the fresh hash.
	if got, err := jobapproval.ContractHash(c); err != nil || got != fresh {
		t.Fatalf("no stored hash: got %q, %v; want %q", got, err, fresh)
	}

	c.ContractHash = fresh
	if got, err := jobapproval.ContractHash(c); err != nil || got != fresh {
		t.Fatalf("stored hash: got %q, %v; want %q", got, err, fresh)
	}

	// Signatures don't count towards the hash.
	c.Parties.DataProviders[0].Signature = contract.Signature{Signer: "alice@example.com", SignedHash: fresh, Value: "sig"}
	if got, err := jobapproval.ContractHash(c); err != nil || got != fresh {
		t.Fatalf("after signing: got %q, %v; want %q", got, err, fresh)
	}

	// The stored contract edited after its hash was stored.
	c.Parties.DataProviders[0].DataURL = "https://elsewhere"
	if _, err := jobapproval.ContractHash(c); err == nil || !strings.Contains(err.Error(), "no longer matches its stored contract_hash") {
		t.Fatalf("edited contract: err = %v, want a mismatch", err)
	}
	srv := newTestServer(&config.Config{})
	if err := srv.approvals().VerifySignature(context.Background(), c, jobapproval.Caller{Username: "alice@example.com"}, fresh, ""); err == nil {
		t.Fatal("VerifySignature accepted an edited contract")
	}
	if _, reasons := srv.approvals().VerifyJobSignatures(context.Background(), c); len(reasons) != 1 || !strings.Contains(reasons[0], "no longer matches") {
		t.Fatalf("VerifyJobSignatures reasons = %q, want the mismatch", reasons)
	}
}

// Without an APD policy, a TEE/SMPC dataset's provider is its DX catalogue
// owner (uploadedBy).
func TestCatalogueOwnerAsProvider(t *testing.T) {
	srv := newTestServer(&config.Config{CatalogueBaseURL: stubDXCatalogue(t)})

	var in contractgen.DatasetInput
	srv.catalogueOwnerAsProvider(context.Background(), dsHeart, "tok-alice", &in)
	if in.ProviderID != "provider-alice-example-com" || in.ProviderName != "alice@example.com" {
		t.Fatalf("provider = %q / %q, want provider-alice-example-com / alice@example.com", in.ProviderID, in.ProviderName)
	}
	alice := callerFromClaims("tok-alice", jwt.MapClaims{"preferred_username": "alice@example.com"})
	if !alice.is(contract.DataProviderParty{ID: in.ProviderID, Name: in.ProviderName}) {
		t.Error("the catalogue owner is not recognised as the dataset's provider")
	}

	in = contractgen.DatasetInput{}
	srv.catalogueOwnerAsProvider(context.Background(), dsMissing, "tok-alice", &in)
	if in.ProviderID != "" {
		t.Errorf("unknown dataset: provider = %q, want none", in.ProviderID)
	}
}
