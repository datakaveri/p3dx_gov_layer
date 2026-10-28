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
