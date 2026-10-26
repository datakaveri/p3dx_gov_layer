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

// fl_config is covered by the contract hash: setting it, or changing a
// field, changes the hash.
func TestFLConfigInHash(t *testing.T) {
	c := Contract{ContractID: "c1", Technique: "FL", Parties: Parties{DataProviders: []DataProviderParty{{ID: "p1", DatasetName: "d"}}}}
	without, err := ComputeHash(c)
	if err != nil {
		t.Fatal(err)
	}

	c.FLConfig = &FLRunConfig{NumRounds: 10, LocalEpochs: 1, LearningRate: 0.01, BatchSize: 32}
	with, err := ComputeHash(c)
	if err != nil {
		t.Fatal(err)
	}
	if with == without {
		t.Fatal("fl_config did not change the contract hash")
	}
	c.FLConfig.NumRounds = 11
	if changed, _ := ComputeHash(c); changed == with {
		t.Fatal("changing num_rounds did not change the contract hash")
	}
}

func TestFLRunConfigValidate(t *testing.T) {
	ok := FLRunConfig{NumRounds: 10, LocalEpochs: 1, LearningRate: 0.01, BatchSize: 32}
	cases := []struct {
		name    string
		mut     func(*FLRunConfig)
		wantErr string
	}{
		{"valid", func(*FLRunConfig) {}, ""},
		{"upper bounds", func(c *FLRunConfig) { c.NumRounds, c.LocalEpochs, c.LearningRate, c.BatchSize = 100, 5, 1, 1024 }, ""},
		{"lower bounds", func(c *FLRunConfig) { c.NumRounds, c.LocalEpochs, c.LearningRate, c.BatchSize = 1, 1, 0.0001, 1 }, ""},
		{"rounds zero", func(c *FLRunConfig) { c.NumRounds = 0 }, "num_rounds"},
		{"rounds 101", func(c *FLRunConfig) { c.NumRounds = 101 }, "num_rounds"},
		{"epochs zero", func(c *FLRunConfig) { c.LocalEpochs = 0 }, "local_epochs"},
		{"epochs 6", func(c *FLRunConfig) { c.LocalEpochs = 6 }, "local_epochs"},
		{"lr zero", func(c *FLRunConfig) { c.LearningRate = 0 }, "learning_rate"},
		{"lr negative", func(c *FLRunConfig) { c.LearningRate = -0.1 }, "learning_rate"},
		{"lr above 1", func(c *FLRunConfig) { c.LearningRate = 1.5 }, "learning_rate"},
		{"batch zero", func(c *FLRunConfig) { c.BatchSize = 0 }, "batch_size"},
		{"batch 1025", func(c *FLRunConfig) { c.BatchSize = 1025 }, "batch_size"},
	}
	for _, tc := range cases {
		c := ok
		tc.mut(&c)
		err := c.Validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: got %v, want error naming %s", tc.name, err, tc.wantErr)
		}
	}
}
