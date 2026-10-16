package services

import (
	"sort"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
)

// KnownWorkload is one workload a consumer can pick in WorkloadForm.jsx's
// TEE "Workload" tab, keyed by the id sent as applicationId. Its image and
// resources are fixed here, server-side, rather than taken from the client.
type KnownWorkload struct {
	Name      string
	Image     string
	Resources contract.WorkloadResources
}

// KnownWorkloads must stay in step with WorkloadForm.jsx's TEE_WORKLOADS.
var KnownWorkloads = map[string]KnownWorkload{
	"mnist": {
		Name:      "MNIST",
		// Image:     "docker.io/rohithvaidya/mnist-vault-workload:1.8",
		Image:     "docker.io/rohithvaidya/mnist-vault-workload@sha256:e155df758090022a9ca9d1ff6574bf7e5c3d1975c7e14f5d62f4a11054bbddd8",
		Resources: contract.WorkloadResources{CPU: "250m", Memory: "512Mi"},
	},
	"regression": {
		Name:      "Regression",
		Image:     "docker.io/rohithvaidya/logreg-workload@sha256:5ad1cbf6079130b3f1ae527246ebf629ca435b919ed1ca9e39c9b7e780df5525",
		Resources: contract.WorkloadResources{CPU: "250m", Memory: "512Mi"},
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
}

// ListKnownWorkloads returns every KnownWorkloads entry, sorted by id — the
// catalogue the UI's workload picker and contract edit dropdown show.
func ListKnownWorkloads() []WorkloadInfo {
	out := make([]WorkloadInfo, 0, len(KnownWorkloads))
	for id, w := range KnownWorkloads {
		out = append(out, WorkloadInfo{ID: id, Name: w.Name, Image: w.Image, CPU: w.Resources.CPU, Memory: w.Resources.Memory})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
