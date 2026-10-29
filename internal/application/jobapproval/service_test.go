package jobapproval

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/apd"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/catalogue"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// These run the approval use cases against fakes: no HTTP server, no
// database.

func approvalContract() *contract.Contract {
	return &contract.Contract{JobID: "job-1", ContractID: "contract-1", Technique: "SMPC", Parties: contract.Parties{
		User:           contract.UserParty{ID: "consumer-sub", Name: "Carl"},
		DataProviders:  []contract.DataProviderParty{{ID: "provider-alice-example-com", DatasetID: dsHeart, DatasetName: "heart"}},
		InfraProviders: []contract.InfraProviderParty{{ID: "infra-1", Name: "Pune DC"}},
	}}
}

type testEnv struct {
	svc  *Service
	repo *fakeRepo
	apd  *fakeAPD
	sigs *fakeSignatures
}

func newTestEnv(t *testing.T, c *contract.Contract, keys fakeKeys) testEnv {
	t.Helper()
	env := testEnv{
		repo: newFakeRepo("job-1", c),
		apd:  &fakeAPD{owners: map[string]string{"infra-1": "provider-ivan", "infra-2": "provider-mallory"}},
		sigs: &fakeSignatures{},
	}
	env.svc = &Service{
		Repo:                 env.repo,
		Catalogue:            fakeCatalogue{infra: map[string][]catalogue.APDCatalogueItem{"provider-ivan": {{ItemID: "infra-1", Name: "Pune DC"}}}},
		APD:                  env.apd,
		Keys:                 keys,
		Signatures:           env.sigs,
		RequireInfraApproval: true,
		DataProviderRole:     "provider",
	}
	return env
}

var (
	alice = Caller{Token: "tok-alice", Username: "alice@example.com", UserID: "alice-sub",
		Names: map[string]bool{"provider-alice-example-com": true, "alice@example.com": true}, Roles: []string{"offline_access", "provider"}}
	ivan = Caller{Token: "tok-ivan", Username: "ivan", UserID: "ivan-sub",
		Names: map[string]bool{"provider-ivan": true, "ivan": true}, Roles: []string{InfraProviderRole}}
	mallory = Caller{Username: "mallory", Names: map[string]bool{"provider-mallory": true}, Roles: []string{InfraProviderRole}}
)

func signedInput(t *testing.T, c *contract.Contract) (Input, Input, fakeKeys) {
	t.Helper()
	hash, err := contract.ComputeHash(*c)
	if err != nil {
		t.Fatal(err)
	}
	alicePriv, alicePub := newRSAKey(t)
	ivanPriv, ivanPub := newRSAKey(t)
	return Input{JobID: "job-1", ContractHash: hash, Signature: signWith(t, alicePriv, hash)},
		Input{JobID: "job-1", ContractHash: hash, Signature: signWith(t, ivanPriv, hash)},
		fakeKeys{"alice@example.com": alicePub, "ivan": ivanPub}
}

func TestApproveAsDataProvider(t *testing.T) {
	c := approvalContract()
	aliceIn, _, keys := signedInput(t, c)
	env := newTestEnv(t, c, keys)

	res, err := env.svc.ApproveAsDataProvider(context.Background(), alice, aliceIn)
	if err != nil {
		t.Fatal(err)
	}
	if res.Approval != postgres.AuditStatusAccepted || res.Signed != 1 || res.State.DataProvider != postgres.AuditStatusAccepted ||
		res.State.Approval != StatusPending { // the infra provider hasn't approved yet
		t.Fatalf("result = %+v", res)
	}
	checkEntries(t, env.repo.audit, []wantEntry{{postgres.AuditStatusAccepted, true, true}})
	if len(env.repo.updated) != 1 || env.repo.updated[0].Parties.DataProviders[0].Signature.Value != aliceIn.Signature {
		t.Errorf("signature not stored on the contract: %+v", env.repo.updated)
	}
	if len(env.repo.marked) != 1 || env.repo.marked[0] != "data-provider provider-alice-example-com "+dsHeart+" approved" {
		t.Errorf("participants marked = %q", env.repo.marked)
	}
	if len(res.Grants) != 1 || res.Grants[0].Status != "posted" || len(env.apd.posted) != 1 || env.apd.posted[0].ItemType != apd.GrantItemDataset {
		t.Errorf("grants = %+v, posted %+v", res.Grants, env.apd.posted)
	}
}

// Every refusal leaves nothing recorded.
func TestApproveAsDataProviderRefused(t *testing.T) {
	c := approvalContract()
	aliceIn, ivanIn, keys := signedInput(t, c)
	noData := approvalContract()
	noData.Parties.InfraProviders = nil

	for _, tc := range []struct {
		name   string
		caller Caller
		in     Input
		want   error
	}{
		{"no job id", alice, Input{}, ErrJobIDRequired},
		{"unknown job", alice, Input{JobID: "job-x"}, ErrNoContract},
		{"not a data provider", ivan, aliceIn, ErrNotDataProvider},
		{"no signature", alice, Input{JobID: "job-1", ContractHash: aliceIn.ContractHash}, ErrMissingSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, c, keys)
			if _, err := env.svc.ApproveAsDataProvider(context.Background(), tc.caller, tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if len(env.repo.audit)+len(env.repo.updated)+len(env.repo.marked)+len(env.apd.posted) != 0 {
				t.Error("a refused call recorded something")
			}
		})
	}

	t.Run("signed with another key", func(t *testing.T) {
		env := newTestEnv(t, c, keys)
		bad := aliceIn
		bad.Signature = ivanIn.Signature
		var sigErr *SignatureError
		if _, err := env.svc.ApproveAsDataProvider(context.Background(), alice, bad); !errors.As(err, &sigErr) {
			t.Fatalf("err = %v, want a SignatureError", err)
		}
		if len(env.repo.audit)+len(env.repo.updated) != 0 {
			t.Error("an approval with a bad signature was recorded")
		}
	})

	t.Run("no job approval needed", func(t *testing.T) {
		env := newTestEnv(t, noData, keys)
		if _, err := env.svc.ApproveAsDataProvider(context.Background(), alice, aliceIn); !errors.Is(err, ErrNoApprovalNeeded) {
			t.Fatalf("err = %v, want ErrNoApprovalNeeded", err)
		}
	})
}

func TestApproveAsInfraProvider(t *testing.T) {
	c := approvalContract()
	_, ivanIn, keys := signedInput(t, c)
	env := newTestEnv(t, c, keys)

	if _, err := env.svc.ApproveAsInfraProvider(context.Background(), mallory, ivanIn); !errors.Is(err, ErrNotInfraProvider) {
		t.Fatalf("mallory: err = %v, want ErrNotInfraProvider", err)
	}
	res, err := env.svc.ApproveAsInfraProvider(context.Background(), ivan, ivanIn)
	if err != nil {
		t.Fatal(err)
	}
	if res.Approval != postgres.AuditStatusAccepted || res.Signed != 1 || res.Grants != nil {
		t.Fatalf("result = %+v", res)
	}
	if len(env.repo.marked) != 1 || env.repo.marked[0] != "infra-provider provider-ivan infra-1 approved" {
		t.Errorf("participants marked = %q", env.repo.marked)
	}
}

// The consumer's status call: not approved until both sides approved and
// every signature verifies; then the contract is final and grants posted.
func TestJobStatus(t *testing.T) {
	c := approvalContract()
	aliceIn, ivanIn, keys := signedInput(t, c)
	env := newTestEnv(t, c, keys)
	ctx := context.Background()

	if _, err := env.svc.JobStatus(ctx, "job-1", "someone-else"); !errors.Is(err, ErrNotConsumer) {
		t.Fatalf("err = %v, want ErrNotConsumer", err)
	}
	st, err := env.svc.JobStatus(ctx, "job-1", "CONSUMER-SUB")
	if err != nil || st.Approved || len(st.Reasons) != 2 || st.SignaturesChecked {
		t.Fatalf("before approvals: %+v, %v", st, err)
	}

	if _, err := env.svc.ApproveAsDataProvider(ctx, alice, aliceIn); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.ApproveAsInfraProvider(ctx, ivan, ivanIn); err != nil {
		t.Fatal(err)
	}

	env.sigs.invalid = []PartySignature{{Role: postgres.AuditTypeInfraProvider, InfraID: "infra-1", Error: "not signed yet"}}
	if st, err = env.svc.JobStatus(ctx, "job-1", "consumer-sub"); err != nil || st.Approved || !st.SignaturesChecked ||
		len(st.Reasons) != 1 || st.Reasons[0] != "infra infra-1: not signed yet" {
		t.Fatalf("bad signature: %+v, %v", st, err)
	}

	env.sigs.invalid = nil
	env.apd.posted = nil
	st, err = env.svc.JobStatus(ctx, "job-1", "consumer-sub")
	if err != nil || !st.Approved || !st.Final || st.FinalRecord == nil || st.ContractHash == "" {
		t.Fatalf("approved: %+v, %v", st, err)
	}
	if len(st.Grants) != 2 || len(env.apd.posted) != 2 {
		t.Errorf("grants = %+v, want the dataset's and the infra's", st.Grants)
	}
}

func TestInfraProviderEntries(t *testing.T) {
	c := &contract.Contract{JobID: "job-1", Parties: contract.Parties{
		DataProviders: []contract.DataProviderParty{{ID: "provider-alice", DatasetName: "Heart Data"}},
		InfraProviders: []contract.InfraProviderParty{
			{ID: "infra-1"},                      // ivan's
			{ID: "infra-2"},                      // mallory's
			{Name: "Azure Confidential Compute"}, // placeholder, skipped
		},
	}}
	svc := newTestEnv(t, c, nil).svc
	owners := svc.InfraOwners(c)
	if len(owners) != 2 || owners[0].ProviderID != "provider-ivan" || owners[1].ProviderID != "provider-mallory" {
		t.Fatalf("owners = %+v", owners)
	}

	// ivan approves his own infra; mallory's is left awaiting her own call.
	entries := svc.infraProviderEntries(c.JobID, owners, ivan, map[string]bool{})
	checkEntries(t, entries, []wantEntry{
		{postgres.AuditStatusAccepted, true, true},
		{postgres.AuditStatusRejected, false, false},
	})
	if got := OverallStatus(entries); got != postgres.AuditStatusRejected {
		t.Errorf("overall = %q, want rejected (mallory still awaiting)", got)
	}

	// Once mallory's infra has an entry of her own, ivan's call leaves it alone.
	entries = svc.infraProviderEntries(c.JobID, owners, ivan, map[string]bool{AuditKey("provider-mallory", "infra-2"): true})
	checkEntries(t, entries, []wantEntry{{postgres.AuditStatusAccepted, true, true}})

	// Without the infra-provider role in his token, ivan's infra is rejected.
	noRole := ivan
	noRole.Roles = nil
	entries = svc.infraProviderEntries(c.JobID, owners[:1], noRole, map[string]bool{})
	checkEntries(t, entries, []wantEntry{{postgres.AuditStatusRejected, false, true}})

	// mallory owns infra-2, but it isn't in her APD catalogue.
	entries = svc.infraProviderEntries(c.JobID, owners[1:], mallory, map[string]bool{})
	checkEntries(t, entries, []wantEntry{{postgres.AuditStatusRejected, true, false}})
}

func TestDataProviderEntries(t *testing.T) {
	c := &contract.Contract{JobID: "job-1", Parties: contract.Parties{
		DataProviders: []contract.DataProviderParty{
			{ID: "provider-alice-example-com", DatasetID: dsHeart},   // role + DataBank
			{ID: "provider-alice-example-com", DatasetID: dsMissing}, // not in catalogue
			{ID: "provider-alice-example-com", DatasetID: dsApp},     // not a DataBank
			{ID: "provider-alice-example-com", DatasetName: dsHeart}, // older contract: uuid name
			{ID: "provider-alice-example-com", DatasetName: "Lungs"}, // no catalogue id at all
			{ID: "provider-bob", DatasetID: dsBob},                   // someone else: awaiting
			{ID: "provider-carol", DatasetID: dsCarol},               // someone else, already checked
			{DatasetName: "Orphan"},                                  // no provider at all
		},
	}}
	svc := newTestEnv(t, c, nil).svc
	checked := map[string]bool{AuditKey("provider-carol", dsCarol): true}

	got := svc.dataProviderEntries(context.Background(), c.JobID, c, alice, checked)
	checkEntries(t, got, []wantEntry{
		{postgres.AuditStatusAccepted, true, true},
		{postgres.AuditStatusRejected, true, false},
		{postgres.AuditStatusRejected, true, false},
		{postgres.AuditStatusAccepted, true, true},
		{postgres.AuditStatusRejected, true, false},
		{postgres.AuditStatusRejected, false, false}, // bob: awaiting
		{postgres.AuditStatusRejected, false, false}, // orphan
	})
	if got[5].ProviderID != "provider-bob" || got[5].Item != dsBob {
		t.Errorf("awaiting entry = %+v, want provider-bob/%s", got[5], dsBob)
	}

	// Same provider without the role, and with a token the catalogue refuses.
	noRole := Caller{Token: "tok-other", Names: alice.Names}
	got = svc.dataProviderEntries(context.Background(), c.JobID, &contract.Contract{Parties: contract.Parties{
		DataProviders: c.Parties.DataProviders[:1],
	}}, noRole, nil)
	if len(got) != 1 || got[0].HasRole || got[0].InCatalogue || got[0].Status != postgres.AuditStatusRejected {
		t.Fatalf("no-role caller = %+v, want rejected without role or catalogue", got)
	}
}

func TestPostConsumerGrants(t *testing.T) {
	until := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	consentEnds := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	c := &contract.Contract{ContractID: "contract-1", Lifecycle: contract.Lifecycle{ValidUntil: until}, Parties: contract.Parties{
		User: contract.UserParty{ID: "consumer-sub", Name: "Carl"},
		DataProviders: []contract.DataProviderParty{
			{ID: "provider-alice-example-com", DatasetID: dsHeart, DatasetName: "heart",
				Constraints: contract.Constraints{ConsentValidUntil: &consentEnds}},
			{ID: "provider-alice-example-com", DatasetID: dsMissing},
		},
		InfraProviders: []contract.InfraProviderParty{{ID: "infra-1", Name: "Pune DC"}, {ID: "infra-2"}},
	}}
	env := newTestEnv(t, c, nil)
	env.apd.fail = map[string]bool{dsMissing: true}

	// The data provider's approval posts grants for their own accepted
	// datasets only — nothing for infras, nothing for a rejected dataset.
	dataOwn := []postgres.AuditEntry{
		{ProviderID: "provider-alice-example-com", Item: dsHeart, Status: postgres.AuditStatusAccepted},
		{ProviderID: "provider-alice-example-com", Item: dsApp, Status: postgres.AuditStatusRejected},
		{ProviderID: "provider-alice-example-com", Item: dsMissing, Status: postgres.AuditStatusAccepted},
	}
	got := env.svc.postConsumerGrants(context.Background(), postgres.AuditTypeDataProvider, "job-1", c, dataOwn)
	if len(got) != 2 || len(env.apd.posted) != 2 {
		t.Fatalf("data grants = %+v, posted %d, want 2 each", got, len(env.apd.posted))
	}
	if got[0] != (GrantResult{ItemType: "dataset", ItemID: dsHeart, PolicyID: "grant-job-1-" + dsHeart, Status: "posted"}) {
		t.Errorf("data grant 0 = %+v", got[0])
	}
	if got[1].Status != "failed" || got[1].Error != "db down" {
		t.Errorf("data grant 1 = %+v, want failed with APD's message", got[1])
	}
	want := apd.ConsumerGrant{JobID: "job-1", ContractID: "contract-1", Consumer: "consumer-sub", ConsumerName: "Carl",
		ItemType: apd.GrantItemDataset, ItemID: dsHeart, ItemName: "heart", Provider: "provider-alice-example-com",
		ExpiresAt: consentEnds} // ends with the provider's consent, before the contract does
	if env.apd.posted[0] != want {
		t.Errorf("grant posted = %+v, want %+v", env.apd.posted[0], want)
	}

	// The infra provider's approval posts grants for their own infras only.
	infraOwn := []postgres.AuditEntry{
		{ProviderID: "provider-ivan", Item: "infra-1", Status: postgres.AuditStatusAccepted},
		{ProviderID: "provider-ivan", Item: "infra-2", Status: postgres.AuditStatusRejected},
	}
	got = env.svc.postConsumerGrants(context.Background(), postgres.AuditTypeInfraProvider, "job-1", c, infraOwn)
	if len(got) != 1 || len(env.apd.posted) != 3 {
		t.Fatalf("infra grants = %+v, posted %d total, want 1 more", got, len(env.apd.posted))
	}
	if g := env.apd.posted[2]; g.ItemType != apd.GrantItemInfra || g.ItemName != "Pune DC" || g.ExpiresAt != until {
		t.Errorf("infra grant = %+v", g)
	}
}
