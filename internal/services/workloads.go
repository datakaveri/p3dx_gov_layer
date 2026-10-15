package services

import "github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"

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
		Image:     "docker.io/rohithvaidya/mnist-vault-workload:1.8",
		Resources: contract.WorkloadResources{CPU: "250m", Memory: "512Mi"},
	},
}
