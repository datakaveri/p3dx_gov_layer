package httpapi

import (
	"net/http"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
)

// GET /workloads — every workload a TEE contract can run
// (services.KnownWorkloads): id, name, image, cpu, memory.
func (s *Server) listWorkloads(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "workloads": services.ListKnownWorkloads()})
}
