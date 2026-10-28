package httpapi

import (
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/workload"
	"net/http"
)

// GET /workloads — every workload a TEE contract can run
// (workload.KnownWorkloads): id, name, image, cpu, memory, purposes.
func (s *Server) listWorkloads(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "workloads": workload.ListKnownWorkloads()})
}
