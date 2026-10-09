package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

func TestJobRequests(t *testing.T) {
	c := contract.Contract{JobID: "job-1", ContractID: "contract-1", Technique: "SMPC", Parties: contract.Parties{
		User: contract.UserParty{ID: "consumer-sub", Name: "Carl"},
		DataProviders: []contract.DataProviderParty{
			{ID: "provider-alice", DatasetID: dsHeart, DatasetName: "heart"},
			{ID: "provider-alice", DatasetID: dsBob, DatasetName: "lungs"}, // same provider: one request
			{ID: "provider-bob", DatasetID: dsCarol, DatasetName: "eyes"},
			{DatasetName: "Orphan"}, // no provider: no request
		},
		InfraProviders: []contract.InfraProviderParty{{ID: "infra-1", Name: "Pune DC"}, {ID: "infra-2"}, {ID: "infra-3"}},
	}}
	owners := []infraOwner{
		{infraID: "infra-1", providerID: "provider-ivan"},
		{infraID: "infra-2", providerID: "provider-ivan"},
		{infraID: "infra-3", reason: "infra has no known provider"},
	}

	got := jobRequests(c, "sha256:abc", owners, "carl@example.com")
	want := []struct {
		provider, role string
		items          []string
	}{
		{"provider-alice", db.AuditTypeDataProvider, []string{dsHeart, dsBob}},
		{"provider-bob", db.AuditTypeDataProvider, []string{dsCarol}},
		{"provider-ivan", db.AuditTypeInfraProvider, []string{"infra-1", "infra-2"}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d requests, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.providerID != w.provider || g.payload.Role != w.role || g.payload.ApproveWith != "POST /job/approval/"+w.role {
			t.Errorf("request %d = %s/%s/%s, want %s/%s", i, g.providerID, g.payload.Role, g.payload.ApproveWith, w.provider, w.role)
		}
		var ids []string
		for _, it := range g.payload.Items {
			ids = append(ids, it.ID)
		}
		if strings.Join(ids, ",") != strings.Join(w.items, ",") {
			t.Errorf("request %d items = %v, want %v", i, ids, w.items)
		}
		p := g.payload
		if p.Type != JobRequestNotificationType || p.JobID != "job-1" || p.ContractID != "contract-1" || p.Technique != "SMPC" || p.Consumer != (jobRequestConsumer{"consumer-sub", "Carl"}) ||
			p.ContractHash != "sha256:abc" || p.HashAlgorithm != "SHA-256" || p.Contract.ContractID != "contract-1" {
			t.Errorf("request %d payload = %+v", i, p)
		}
	}
	if m := got[0].message; m != `carl@example.com requests to use your datasets "heart", "lungs" for the SMPC job job-1. Please approve or reject it.` {
		t.Errorf("data provider message = %q", m)
	}
	if m := got[2].message; !strings.Contains(m, `infrastructures "Pune DC", "infra-2"`) {
		t.Errorf("infra provider message = %q, want infra names (id when unnamed)", m)
	}
}

// The hash sent with a job request must be the one sealContract signs after
// approval: computed from the stored contract, ignoring hash/signature fields.
func TestStoredContractHashMatchesSeal(t *testing.T) {
	c := contract.Contract{JobID: "job-1", ContractID: "contract-1", Technique: "SMPC",
		Lifecycle: contract.Lifecycle{CreatedAt: time.Now(), ValidUntil: time.Now().Add(720 * time.Hour)},
		Parties:   contract.Parties{DataProviders: []contract.DataProviderParty{{ID: "provider-alice", DatasetID: dsHeart}}}}
	stored, hash, err := storedContractHash(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c)
	var loaded contract.Contract
	_ = json.Unmarshal(raw, &loaded)
	loaded.ContractHash = "something else" // sealContract hashes before setting it
	want, _ := contract.ComputeHash(loaded)
	if hash != want || !strings.HasPrefix(hash, "sha256:") {
		t.Errorf("hash = %q, want %q (what sealContract computes)", hash, want)
	}
	if stored.ContractID != "contract-1" {
		t.Errorf("stored contract = %+v", stored)
	}
}
