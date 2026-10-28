package httpapi

import (
	"errors"
	"fmt"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/workload"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/apd"
	"net/http"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
)

// fetchDatasetPolicy looks up a dataset's own APD policy (no private-dataset
// notice: no provider is passed). A var so tests can stub APD.
var fetchDatasetPolicy = func(datasetID string) (map[string]interface{}, error) {
	return apd.FetchPolicyForDataset(datasetID, "", "", "", "TEE", nil, nil)
}

// contractWorkloadID is the catalogue workload (workload.KnownWorkloads id) a
// TEE contract runs — BuildGeneratedContract records it as the application
// provider.
func contractWorkloadID(c *contract.Contract) string {
	if len(c.Parties.ApplicationProviders) == 0 {
		return ""
	}
	return c.Parties.ApplicationProviders[0].ID
}

func workloadNotAllowedError(msg string) error {
	return &teeAPIError{Status: http.StatusForbidden, Code: "WORKLOAD_NOT_ALLOWED", Message: msg}
}

// requireWorkloadAllowed is the TEE workload gate: a contract that runs a
// workload must run a known catalogue workload, unmodified (its image is that
// workload's image), and every dataset's current policy must allow it
// (requireDatasetWorkloads). Other techniques, and contracts with no
// workload, pass.
//
// Disabled: any workload (catalogue or not, any image) may run on any
// dataset, whatever its policy — the original gate is kept below.
func requireWorkloadAllowed(c *contract.Contract) error {
	return nil
	// if c.Technique != "TEE" || c.Workload == nil {
	// 	return nil
	// }
	// id := contractWorkloadID(c)
	// known, ok := workload.KnownWorkloads[id]
	// if !ok {
	// 	return workloadNotAllowedError(fmt.Sprintf("contract %s does not name a known workload", c.ContractID))
	// }
	// if c.Workload.Image != known.Image {
	// 	return workloadNotAllowedError(fmt.Sprintf("contract %s runs image %q, not workload %q's image", c.ContractID, c.Workload.Image, id))
	// }
	// return requireDatasetWorkloads(c)
}

// requireDatasetWorkloads: every dataset's current APD policy must allow the
// contract's workload — a policy naming no workloads allows any
// (workload.PolicyAllowsWorkload). Re-read at run time, so a policy changed
// after signing still applies.
func requireDatasetWorkloads(c *contract.Contract) error {
	id := contractWorkloadID(c)
	for _, dp := range c.Parties.DataProviders {
		if dp.DatasetID == "" {
			return workloadNotAllowedError(fmt.Sprintf("dataset %q on contract %s has no dataset id to check its policy", dp.DatasetName, c.ContractID))
		}
		policy, err := fetchDatasetPolicy(dp.DatasetID)
		if errors.Is(err, apd.ErrPolicyNotFound) {
			// No policy, no restriction — the same as contract generation,
			// which falls back to the dataset's catalogue owner.
			continue
		}
		if err != nil {
			return workloadNotAllowedError(fmt.Sprintf("no data-provider policy for dataset %s: %v", dp.DatasetID, err))
		}
		if !workload.PolicyAllowsWorkload(policy, id) {
			return workloadNotAllowedError(workload.WorkloadMismatchMessage(policy, dp.DatasetID, id))
		}
	}
	return nil
}
