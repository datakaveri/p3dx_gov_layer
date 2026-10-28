package jobapproval

import (
	"strings"
	"testing"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

func TestNeedsJobApproval(t *testing.T) {
	dataOnly := &contract.Contract{Parties: contract.Parties{
		DataProviders:  []contract.DataProviderParty{{ID: "provider-a"}},
		InfraProviders: []contract.InfraProviderParty{{Name: "placeholder"}},
	}}
	if NeedsJobApproval(dataOnly) {
		t.Error("placeholder infra (no id) should not trigger approval")
	}
	infraOnly := &contract.Contract{Parties: contract.Parties{
		InfraProviders: []contract.InfraProviderParty{{ID: "infra-1"}},
	}}
	if NeedsJobApproval(infraOnly) {
		t.Error("contract with no datasets should not trigger approval")
	}
	if !NeedsJobApproval(approvalContract()) {
		t.Error("contract with datasets + infra should need approval")
	}
}

func TestJobAcceptedWithoutInfraApproval(t *testing.T) {
	for _, tc := range []struct {
		data, infra   string
		infraRequired bool
		want          bool
	}{
		{postgres.AuditStatusAccepted, postgres.AuditStatusAccepted, true, true},
		{postgres.AuditStatusAccepted, StatusPending, true, false},
		{postgres.AuditStatusAccepted, StatusPending, false, true},                 // REQUIRE_INFRA_APPROVAL=false
		{postgres.AuditStatusAccepted, postgres.AuditStatusRejected, false, true},  // infra ignored
		{postgres.AuditStatusRejected, postgres.AuditStatusAccepted, false, false}, // data provider still required
		{StatusPending, StatusPending, false, false},
	} {
		st := State{DataProvider: tc.data, InfraProvider: tc.infra, InfraRequired: tc.infraRequired}
		if got := st.Accepted(); got != tc.want {
			t.Errorf("Accepted(data=%s infra=%s infraRequired=%v) = %v, want %v", tc.data, tc.infra, tc.infraRequired, got, tc.want)
		}
	}
}

// The latest entry per provider and item is current: a re-run that passes
// replaces an earlier rejection.
func TestBuildState(t *testing.T) {
	dp := func(provider, item, status string) postgres.AuditEntry {
		return postgres.AuditEntry{Type: postgres.AuditTypeDataProvider, ProviderID: provider, Item: item, Status: status}
	}
	infra := postgres.AuditEntry{Type: postgres.AuditTypeInfraProvider, ProviderID: "provider-ivan", Item: "infra-1", Status: postgres.AuditStatusAccepted}
	history := []postgres.AuditEntry{
		dp("provider-alice", dsHeart, postgres.AuditStatusRejected),
		dp("provider-bob", dsBob, postgres.AuditStatusAccepted),
		dp("provider-alice", dsHeart, postgres.AuditStatusAccepted),
	}

	st := BuildState(history, true)
	if len(st.Current) != 2 || st.DataProvider != postgres.AuditStatusAccepted || st.InfraProvider != StatusPending || st.Approval != StatusPending {
		t.Fatalf("no infra yet: %+v", st)
	}
	if st = BuildState(append(history, infra), true); st.Approval != postgres.AuditStatusAccepted {
		t.Fatalf("all accepted: approval = %s", st.Approval)
	}
	if st = BuildState(history[:2], true); st.Approval != postgres.AuditStatusRejected {
		t.Fatalf("alice still rejected: approval = %s", st.Approval)
	}
	if st = BuildState(history, false); st.Approval != postgres.AuditStatusAccepted {
		t.Fatalf("infra approval off: approval = %s", st.Approval)
	}
}

func TestReasons(t *testing.T) {
	st := State{DataProvider: postgres.AuditStatusAccepted, InfraProvider: StatusPending, InfraRequired: true, Current: []postgres.AuditEntry{
		{Type: postgres.AuditTypeDataProvider, ProviderID: "provider-alice", Item: dsHeart, Status: postgres.AuditStatusAccepted},
		{Type: postgres.AuditTypeDataProvider, ProviderID: "provider-bob", Item: dsBob, Status: postgres.AuditStatusRejected, Reason: "awaiting"},
	}}
	got := Reasons(st)
	want := []string{"data-provider provider-bob / " + dsBob + ": awaiting", "no infra provider has approved yet"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("reasons = %q, want %q", got, want)
	}
}

func TestCallerMatchesParty(t *testing.T) {
	caller := Caller{Names: map[string]bool{"provider-alice-example-com": true, "abc-123": true}}
	for _, tc := range []struct {
		party contract.DataProviderParty
		want  bool
	}{
		{contract.DataProviderParty{ID: "provider-alice-example-com"}, true},
		{contract.DataProviderParty{ID: "ABC-123", Name: "someone"}, true},
		{contract.DataProviderParty{ID: "kc-id", Name: "alice@example.com"}, true},
		{contract.DataProviderParty{ID: "provider-bob"}, false},
		{contract.DataProviderParty{}, false},
	} {
		if got := caller.Is(tc.party); got != tc.want {
			t.Errorf("Is(%+v) = %v, want %v", tc.party, got, tc.want)
		}
	}
	if !caller.Owns("Provider-Alice-Example-Com") || caller.Owns("") {
		t.Error("Owns should match case-insensitively and never match an empty id")
	}
}

func TestApprovalItem(t *testing.T) {
	for _, tc := range []struct {
		dp   contract.DataProviderParty
		want string
	}{
		{contract.DataProviderParty{DatasetID: dsHeart, DatasetName: "heart"}, dsHeart},
		{contract.DataProviderParty{DatasetName: dsHeart}, dsHeart}, // older contract: uuid name
		{contract.DataProviderParty{DatasetName: "Lungs"}, "Lungs"},
	} {
		if got := ApprovalItem(tc.dp); got != tc.want {
			t.Errorf("ApprovalItem(%+v) = %q, want %q", tc.dp, got, tc.want)
		}
	}
	if CatalogueItemID(contract.DataProviderParty{DatasetName: "Lungs"}) != "" {
		t.Error("a non-uuid dataset name is not a catalogue id")
	}
}

// A job's contract carries the contract_hash stored at /generate-contract;
// verification uses it, and refuses a contract edited since.
func TestContractHash(t *testing.T) {
	c := approvalContract()
	fresh, err := contract.ComputeHash(*c)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ContractHash(c); err != nil || got != fresh {
		t.Fatalf("no stored hash: got %q, %v; want %q", got, err, fresh)
	}
	c.ContractHash = fresh
	c.Parties.DataProviders[0].Signature = contract.Signature{Signer: "alice@example.com", SignedHash: fresh, Value: "sig"}
	if got, err := ContractHash(c); err != nil || got != fresh {
		t.Fatalf("signatures don't count towards the hash: got %q, %v; want %q", got, err, fresh)
	}
	c.Parties.DataProviders[0].DataURL = "https://elsewhere"
	if _, err := ContractHash(c); err == nil || !strings.Contains(err.Error(), "no longer matches its stored contract_hash") {
		t.Fatalf("edited contract: err = %v, want a mismatch", err)
	}
}
