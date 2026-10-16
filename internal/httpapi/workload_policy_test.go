package httpapi

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
)

func TestRequireWorkloadAllowed(t *testing.T) {
	policies := map[string]map[string]interface{}{
		"ds-mnist": {"rules": map[string]interface{}{"allowed_workloads": []interface{}{map[string]interface{}{"id": "credits-evaluation"}}}},
		"ds-reg":   {"rules": map[string]interface{}{"allowed_workloads": []interface{}{"market-offer-generation"}}},
		"ds-any":   {"rules": map[string]interface{}{}},
	}
	orig := fetchDatasetPolicy
	defer func() { fetchDatasetPolicy = orig }()
	fetchDatasetPolicy = func(id string) (map[string]interface{}, error) {
		if p, ok := policies[id]; ok {
			return p, nil
		}
		if id == "ds-apd-down" {
			return nil, errors.New("connection refused")
		}
		return nil, fmt.Errorf("%w for item %q", services.ErrPolicyNotFound, id)
	}

	tee := func(workload, image string, datasets ...string) *contract.Contract {
		c := &contract.Contract{ContractID: "c1", Technique: "TEE", Workload: &contract.Workload{Image: image}}
		c.Parties.ApplicationProviders = []contract.ApplicationProviderParty{{ID: workload}}
		for _, d := range datasets {
			c.Parties.DataProviders = append(c.Parties.DataProviders, contract.DataProviderParty{DatasetID: d})
		}
		return c
	}
	mnist := services.KnownWorkloads["credits-evaluation"].Image

	cases := []struct {
		name    string
		check   func(*contract.Contract) error
		c       *contract.Contract
		wantErr string
	}{
		// Run gate: disabled — any workload runs on any dataset.
		{"allowed", requireWorkloadAllowed, tee("credits-evaluation", mnist, "ds-mnist"), ""},
		// {"other workload's dataset", requireWorkloadAllowed, tee("credits-evaluation", mnist, "ds-mnist", "ds-reg"), "Workload not matching"},
		{"other workload's dataset", requireWorkloadAllowed, tee("credits-evaluation", mnist, "ds-mnist", "ds-reg"), ""},
		{"no workloads picked", requireWorkloadAllowed, tee("credits-evaluation", mnist, "ds-any"), ""},
		{"no policy", requireWorkloadAllowed, tee("credits-evaluation", mnist, "ds-missing"), ""},
		// {"APD down", requireWorkloadAllowed, tee("credits-evaluation", mnist, "ds-apd-down"), "no data-provider policy"},
		// {"image swapped", requireWorkloadAllowed, tee("credits-evaluation", "docker.io/evil:1", "ds-mnist"), "not workload"},
		// {"unknown workload", requireWorkloadAllowed, tee("other", mnist, "ds-mnist"), "known workload"},
		{"APD down", requireWorkloadAllowed, tee("credits-evaluation", mnist, "ds-apd-down"), ""},
		{"image swapped", requireWorkloadAllowed, tee("credits-evaluation", "docker.io/evil:1", "ds-mnist"), ""},
		{"unknown workload", requireWorkloadAllowed, tee("other", mnist, "ds-mnist"), ""},
		{"no workload", requireWorkloadAllowed, &contract.Contract{Technique: "TEE"}, ""},
		{"FL not gated", requireWorkloadAllowed, &contract.Contract{Technique: "FL"}, ""},
		// Per-dataset check on its own.
		{"dataset: allowed", requireDatasetWorkloads, tee("credits-evaluation", mnist, "ds-mnist"), ""},
		{"dataset: other workload's", requireDatasetWorkloads, tee("credits-evaluation", mnist, "ds-mnist", "ds-reg"), "Workload not matching: dataset ds-reg allows Market Offer Generation, but you selected Credits Evaluation"},
		{"dataset: names no workload", requireDatasetWorkloads, tee("credits-evaluation", mnist, "ds-any"), ""},
		{"dataset: no policy", requireDatasetWorkloads, tee("credits-evaluation", mnist, "ds-missing"), ""},
		{"dataset: no id", requireDatasetWorkloads, tee("credits-evaluation", mnist, ""), "no dataset id"},
	}
	for _, c := range cases {
		err := c.check(c.c)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(teeErrorMessage(err), c.wantErr)):
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.wantErr)
		}
	}
}
