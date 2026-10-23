package services

import (
	"fmt"
	"sort"
	"strings"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
)

// KnownWorkload is one workload a consumer can pick in WorkloadForm.jsx's
// TEE "Workload" tab, keyed by the id sent as applicationId. Its image and
// resources are fixed here, server-side, rather than taken from the client.
type KnownWorkload struct {
	Name      string
	Image     string
	Resources contract.WorkloadResources
	// Purposes are the dataset purposes (PolicyForm.jsx's Purpose dropdown:
	// research/clinical/benchmarking/internal) this workload is offered for —
	// a data provider picks a dataset's workloads from its purpose's list.
	Purposes []string
}

// KnownWorkloads must stay in step with WorkloadForm.jsx's TEE_WORKLOADS.
var KnownWorkloads = map[string]KnownWorkload{
	// "mnist": {
	// 	Name:      "MNIST",
	"credits-evaluation": {
		Name: "Credits Evaluation",
		// Image:     "docker.io/rohithvaidya/mnist-vault-workload:1.8",
		Image:     "docker.io/rohithvaidya/mnist-vault-workload@sha256:e155df758090022a9ca9d1ff6574bf7e5c3d1975c7e14f5d62f4a11054bbddd8",
		Resources: contract.WorkloadResources{CPU: "250m", Memory: "512Mi"},
		Purposes:  []string{"research", "benchmarking", "internal"},
	},
	// "regression": {
	// 	Name:      "Regression",
	"market-offer-generation": {
		Name:      "Market Offer Generation",
		Image:     "docker.io/rohithvaidya/logreg-workload@sha256:5ad1cbf6079130b3f1ae527246ebf629ca435b919ed1ca9e39c9b7e780df5525",
		Resources: contract.WorkloadResources{CPU: "250m", Memory: "512Mi"},
		Purposes:  []string{"research", "clinical", "benchmarking"},
	},
	// Placeholder workload for testing the TEE flow (e.g. edit -> run
	// refused) without the MNIST image — removed for now.
	// "dummy": {
	// 	Name:      "Dummy",
	// 	Image:     "docker.io/library/busybox:1.36",
	// 	Resources: contract.WorkloadResources{CPU: "100m", Memory: "128Mi"},
	// },
}

// WorkloadInfo is one KnownWorkloads entry as listed by GET /workloads.
type WorkloadInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Image  string `json:"image"`
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
	// Purposes: the dataset purposes this workload is offered for.
	Purposes []string `json:"purposes"`
}

// ListKnownWorkloads returns every KnownWorkloads entry, sorted by id — the
// catalogue the UI's workload picker and contract edit dropdown show.
func ListKnownWorkloads() []WorkloadInfo {
	out := make([]WorkloadInfo, 0, len(KnownWorkloads))
	for id, w := range KnownWorkloads {
		purposes := w.Purposes
		if purposes == nil {
			purposes = []string{}
		}
		out = append(out, WorkloadInfo{ID: id, Name: w.Name, Image: w.Image, CPU: w.Resources.CPU, Memory: w.Resources.Memory, Purposes: purposes})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// PolicyAllowsWorkload reports whether a dataset's APD policy permits the
// given workload id, per rules.allowed_workloads (PolicyForm.jsx's "Allowed
// workloads" picker: a list of {id, name}; bare id strings are accepted too).
// A policy with no list, or an empty one, restricts nothing.
func PolicyAllowsWorkload(policy map[string]interface{}, workloadID string) bool {
	rules, _ := policy["rules"].(map[string]interface{})
	allowed, _ := rules["allowed_workloads"].([]interface{})
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		id, _ := a.(string)
		if m, ok := a.(map[string]interface{}); ok {
			id, _ = m["id"].(string)
		}
		if id != "" && id == workloadID {
			return true
		}
	}
	return false
}

// WorkloadMismatchMessage is the error shown when a consumer picks workloadID
// for a dataset whose policy doesn't allow it: names what the policy does
// allow (rules.allowed_workloads), by display name.
func WorkloadMismatchMessage(policy map[string]interface{}, datasetID, workloadID string) string {
	rules, _ := policy["rules"].(map[string]interface{})
	allowed, _ := rules["allowed_workloads"].([]interface{})
	var names []string
	for _, a := range allowed {
		id, _ := a.(string)
		if m, ok := a.(map[string]interface{}); ok {
			id, _ = m["id"].(string)
		}
		if id != "" {
			names = append(names, workloadName(id))
		}
	}
	allows := "no workload"
	if len(names) > 0 {
		allows = strings.Join(names, ", ")
	}
	selected := "no workload"
	if workloadID != "" {
		selected = workloadName(workloadID)
	}
	return fmt.Sprintf("Workload not matching: dataset %s allows %s, but you selected %s. The TEE cannot run with this workload.", datasetID, allows, selected)
}

func workloadName(id string) string {
	if w, ok := KnownWorkloads[id]; ok && w.Name != "" {
		return w.Name
	}
	return id
}
