package httpapi

import (
	"context"
	"strings"
	"testing"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

func approvalContract() *contract.Contract {
	return &contract.Contract{JobID: "job-1", ContractID: "contract-1", Technique: "SMPC", Parties: contract.Parties{
		DataProviders:  []contract.DataProviderParty{{ID: "provider-alice", DatasetID: dsHeart, DatasetName: "heart"}},
		InfraProviders: []contract.InfraProviderParty{{ID: "infra-1", Name: "Pune DC"}},
	}}
}

// PUT /job/{jobId}/status cross-verifies every provider's submitted
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
			parties, reasons := srv.verifyJobSignatures(context.Background(), c)
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

func TestApprovalReasons(t *testing.T) {
	st := jobApprovalState{DataProvider: db.AuditStatusAccepted, InfraProvider: "pending", infraRequired: true, Current: []db.AuditEntry{
		{Type: db.AuditTypeDataProvider, ProviderID: "provider-alice", Item: dsHeart, Status: db.AuditStatusAccepted},
		{Type: db.AuditTypeDataProvider, ProviderID: "provider-bob", Item: dsBob, Status: db.AuditStatusRejected, Reason: "awaiting"},
	}}
	got := approvalReasons(st)
	want := []string{"data-provider provider-bob / " + dsBob + ": awaiting", "no infra provider has approved yet"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("reasons = %q, want %q", got, want)
	}
}

// On a job-approval contract the infra provider's signature (made when
// approving) is required alongside the data providers'.
func TestVerifyContractSignaturesWithInfra(t *testing.T) {
	alice, alicePub := newRSAKey(t)
	ivan, ivanPub := newRSAKey(t)
	srv := newTestServer(&config.Config{RequireInfraApproval: true})
	srv.publicKeys = stubKeys{"alice": alicePub, "ivan": ivanPub}
	ctx := context.Background()

	c := approvalContract()
	hash, _ := contract.ComputeHash(*c)
	c.ContractHash = hash
	if err := srv.governanceSign(c); err != nil {
		t.Fatal(err)
	}
	sig := func(signer string, value string) contract.Signature {
		return contract.Signature{Signer: signer, SignedHash: hash, Value: value}
	}
	c.Parties.DataProviders[0].Signature = sig("alice", signWith(t, alice, hash))

	parties, _, all := srv.verifyContractSignatures(ctx, c)
	if all || len(parties) != 2 || parties[1].Role != db.AuditTypeInfraProvider || parties[1].InfraID != "infra-1" || parties[1].Signed {
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
// finalizeJob says what's pending (and never touches the DB).
func TestFinalizeJobPending(t *testing.T) {
	alice, alicePub := newRSAKey(t)
	srv := newTestServer(&config.Config{RequireInfraApproval: true})
	srv.publicKeys = stubKeys{"alice": alicePub}

	c := approvalContract()
	hash, _ := contract.ComputeHash(*c)
	c.Parties.DataProviders[0].Signature = contract.Signature{Signer: "alice", SignedHash: hash, Value: signWith(t, alice, hash)}

	// Not governance-signed yet, infra unsigned.
	final, pending, err := srv.finalizeJob(context.Background(), "job-1", c)
	if err != nil || final {
		t.Fatalf("final=%v err=%v, want not final", final, err)
	}
	want := map[string]bool{"governance signature missing or invalid": false, "infra infra-1: not signed yet": false}
	for _, p := range pending {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for p, seen := range want {
		if !seen {
			t.Errorf("pending = %q, missing %q", pending, p)
		}
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
