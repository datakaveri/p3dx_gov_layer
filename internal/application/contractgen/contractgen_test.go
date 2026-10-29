package contractgen

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
)

func dataset() DatasetInput {
	return DatasetInput{DatasetID: "ds1", DatasetName: "mnist", ProviderID: "p1", ProviderName: "prov", DataURL: "https://data"}
}

// contractJSON is c as JSON, for presence checks.
func contractJSON(t *testing.T, c contract.Contract) string {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func assertAbsent(t *testing.T, raw string, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if strings.Contains(raw, `"`+k+`"`) {
			t.Errorf("contract has %q, which its service doesn't use: %s", k, raw)
		}
	}
}

func TestTEEContract(t *testing.T) {
	c := BuildGeneratedContract(GenerateContractInput{
		Datasets:      []DatasetInput{dataset()},
		ApplicationID: "credits-evaluation",
		Technique:     "TEE",
		ConsumerID:    "u1",
		KBSURL:        "http://kbs",
		ResultURL:     "https://result",
		CallbackURL:   "http://cb",
		Infras:        []InfraInput{{InfraID: "i1"}}, // not a TEE selection: ignored
	})
	if c.ComputeChoice != "ANONYMIZATION" || c.ContractHash == "" {
		t.Fatalf("compute_choice %q hash %q", c.ComputeChoice, c.ContractHash)
	}
	if c.Workload == nil || c.Workload.ID != "credits-evaluation" || c.Workload.Image == "" {
		t.Fatalf("workload = %+v", c.Workload)
	}
	if c.Workload.Env["DATASET_URL"] != "https://data" || c.Workload.Env["RESULT_URL"] != "https://result" {
		t.Fatalf("workload env = %v", c.Workload.Env)
	}
	if c.Trustee == nil || c.Parties.DataProviders[0].Trustee == nil {
		t.Fatal("TEE contract has no trustee")
	}
	if c.CallbackURL != "http://cb/"+c.ContractID || c.Parties.User.DatablobURL != "https://result" {
		t.Fatalf("callback %q datablob %q", c.CallbackURL, c.Parties.User.DatablobURL)
	}
	if _, missing := contract.NewSubContract(&c); len(missing) > 0 {
		t.Fatalf("TEE contract can't run, missing %v", missing)
	}
	assertAbsent(t, contractJSON(t, c), "application_providers", "infra_providers", "infra_provider_count")
}

func TestSMPCContract(t *testing.T) {
	c := BuildGeneratedContract(GenerateContractInput{
		Datasets:      []DatasetInput{dataset()},
		ApplicationID: "unselected-application", // the UI's default when nothing is picked
		Technique:     "SMPC",
		KBSURL:        "http://kbs",
		ResultURL:     "https://result",
		CallbackURL:   "http://cb",
		Infras:        []InfraInput{{InfraID: "i1", InfraName: "A"}, {InfraID: "i2"}},
	})
	if c.ComputeChoice != "SECURE_MULTIPARTY_COMPUTATION" {
		t.Fatalf("compute_choice %q", c.ComputeChoice)
	}
	ip := c.Parties.InfraProviders
	if len(ip) != 2 || c.Parties.InfraProviderCount != 2 || ip[0].ID != "i1" || ip[1].Name != "Unknown Infrastructure" {
		t.Fatalf("infra providers = %+v", ip)
	}
	if c.Parties.User.DatablobURL != "" {
		t.Fatalf("datablob_url = %q", c.Parties.User.DatablobURL)
	}
	assertAbsent(t, contractJSON(t, c), "application_providers", "workload", "trustee", "callbackUrl")
}

func TestFLContract(t *testing.T) {
	c := BuildGeneratedContract(GenerateContractInput{
		Datasets:      []DatasetInput{dataset()},
		ApplicationID: "unselected-application",
		Technique:     "FL",
		KBSURL:        "http://kbs",
		ResultURL:     "https://result",
	})
	if c.ComputeChoice != "FEDERATED_LEARNING" {
		t.Fatalf("compute_choice %q", c.ComputeChoice)
	}
	assertAbsent(t, contractJSON(t, c), "application_providers", "infra_providers", "infra_provider_count", "workload", "trustee", "callbackUrl")
}

func TestFLRosterContract(t *testing.T) {
	signed := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	c := BuildFLRosterContract(FLRosterInput{
		SessionID:       "s1",
		Parties:         []FLParty{{ID: "a", Username: "alice", DatasetName: "d1"}, {ID: "b", Username: "bob"}},
		PriorSignatures: map[string]*time.Time{"alice": &signed},
		Finalize:        true,
	})
	if c.Technique != "FL" || c.Version != 2 || c.ProjectID == "" || c.ContractHash == "" {
		t.Fatalf("technique %q version %d project %q hash %q", c.Technique, c.Version, c.ProjectID, c.ContractHash)
	}
	if c.Parties.User.ID != "s1" || c.Parties.User.Signature.SignedAt == nil {
		t.Fatalf("owner = %+v (want the session id, signed)", c.Parties.User)
	}
	dps := c.Parties.DataProviders
	if len(dps) != 2 || c.Parties.DataProviderCount != 2 || dps[0].Signature.SignedAt == nil || dps[1].Signature.SignedAt != nil {
		t.Fatalf("data providers = %+v", dps)
	}
	if got := c.Lifecycle.ValidUntil.Sub(c.Lifecycle.ValidFrom); got != defaultValidity {
		t.Fatalf("validity = %v", got)
	}
	assertAbsent(t, contractJSON(t, c), "application_providers", "infra_providers", "infra_provider_count", "workload", "trustee")
}
