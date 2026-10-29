package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewTrustee(t *testing.T) {
	if got := NewTrustee("", "mnist-dataset", "dataset1"); got != nil {
		t.Fatalf("NewTrustee with no KBS URL = %+v, want nil", got)
	}

	got := NewTrustee("http://172.17.0.8:30081", "mnist-dataset", "dataset1")
	want := Trustee{KBSURL: "http://172.17.0.8:30081", KeyResourcePath: "default/mnist-dataset-key/dataset1"}
	if got == nil || *got != want {
		t.Fatalf("NewTrustee = %+v, want %+v", got, want)
	}

	// No dataset id: the name stands in for it.
	got = NewTrustee("http://kbs", "mnist-dataset", "")
	if got.KeyResourcePath != "default/mnist-dataset-key/mnist-dataset" {
		t.Fatalf("KeyResourcePath = %q", got.KeyResourcePath)
	}
}

func TestTrusteeInHash(t *testing.T) {
	c := Contract{ContractID: "c1", Parties: Parties{DataProviders: []DataProviderParty{{ID: "p1", DatasetName: "d"}}}}
	without, err := ComputeHash(c)
	if err != nil {
		t.Fatal(err)
	}

	// A nil trustee is omitted from the JSON, so older contracts hash the same.
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), "trustee") {
		t.Fatalf("nil trustee serialised: %s", raw)
	}

	c.Parties.DataProviders[0].Trustee = NewTrustee("http://kbs", "d", "id1")
	with, err := ComputeHash(c)
	if err != nil {
		t.Fatal(err)
	}
	if with == without {
		t.Fatal("trustee did not change the contract hash")
	}

	c.Parties.DataProviders[0].Trustee.KeyResourcePath = "default/other-key/id1"
	if changed, _ := ComputeHash(c); changed == with {
		t.Fatal("changing key_resource_path did not change the contract hash")
	}
}

func TestPartiesOmitUnusedLists(t *testing.T) {
	// A service with no infra/application parties leaves them out.
	raw, _ := json.Marshal(Parties{DataProviders: []DataProviderParty{}})
	for _, key := range []string{"application_providers", "infra_providers", "infra_provider_count"} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("nil list serialised %s: %s", key, raw)
		}
	}

	// Contracts stored before that wrote [] / 0; they must re-marshal (and so
	// hash) exactly as stored.
	stored := `{"user":{"id":"","name":"","datablob_url":"","signature":{"signed_at":null}},"data_providers":[],"data_provider_count":0,"application_providers":[],"infra_providers":[],"infra_provider_count":0}`
	var p Parties
	if err := json.Unmarshal([]byte(stored), &p); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(p)
	if string(again) != stored {
		t.Fatalf("stored parties re-marshalled as\n%s\nwant\n%s", again, stored)
	}
}

func TestSubContractOmitsWorkloadID(t *testing.T) {
	c := Contract{
		ContractID: "c1",
		Workload:   &Workload{ID: "credits-evaluation", Image: "img", Env: map[string]string{"DATASET_URL": "u"}},
		Trustee:    &JobTrustee{KBSURL: "http://kbs", KeyResourcePath: "default/k/1"},
	}
	sub, missing := NewSubContract(&c)
	if len(missing) > 0 {
		t.Fatalf("missing = %v", missing)
	}
	if sub.Contract.Workload.ID != "" {
		t.Fatalf("sub-contract workload id = %q, want none (CreateJob has no such field)", sub.Contract.Workload.ID)
	}
	if c.Workload.ID != "credits-evaluation" {
		t.Fatal("NewSubContract changed the contract's own workload")
	}
}
