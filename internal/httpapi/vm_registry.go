package httpapi

// This file is the participant-VM IP registry API: terraform/participant-vm
// calls POST /vm-registry right after creating a VM (both roles), and a
// data-provider VM's provisioning calls GET /vm-registry/output-owner to find
// where to point combine_fl's client_config.yaml broker_host. Protected by an
// optional shared secret (X-VM-Registry-Token / VM_REGISTRY_TOKEN), the same
// "empty disables the check" convention as FORMS_PUSH_TOKEN elsewhere in this
// service.

import (
	"errors"
	"log"
	"net/http"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// requireVMRegistryToken checks X-VM-Registry-Token against cfg.VMRegistryToken.
// An unset VM_REGISTRY_TOKEN disables the check entirely (local dev default).
func (s *Server) requireVMRegistryToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.VMRegistryToken != "" && r.Header.Get("X-VM-Registry-Token") != s.cfg.VMRegistryToken {
			writeJSON(w, http.StatusUnauthorized, j{
				"status": "FAILED", "error": "UNAUTHORIZED", "message": "invalid or missing X-VM-Registry-Token",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

type vmRegistryInput struct {
	Role            string `json:"role"`
	ParticipantName string `json:"participant_name"`
	IPAddress       string `json:"ip_address"`
}

// POST /vm-registry — register/update a participant VM's IP.
func (s *Server) postVMRegistry(w http.ResponseWriter, r *http.Request) {
	var in vmRegistryInput
	if !s.readBody(w, r, &in) {
		return
	}
	if in.Role != "data-provider" && in.Role != "user" {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "INVALID_ROLE", "message": `role must be "data-provider" or "user"`,
		})
		return
	}
	if in.ParticipantName == "" || in.IPAddress == "" {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "MISSING_FIELDS", "message": "participant_name and ip_address are required",
		})
		return
	}
	if err := s.db.UpsertVMRegistry(reqCtx(r), in.Role, in.ParticipantName, in.IPAddress); err != nil {
		log.Println("[GOVERNANCE] ❌ Error upserting vm_registry:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": "Failed to store VM registration",
		})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS"})
}

// GET /vm-registry/output-owner — the most recently registered output-owner VM.
func (s *Server) getOutputOwnerVM(w http.ResponseWriter, r *http.Request) {
	entry, err := s.db.GetOutputOwnerVM(reqCtx(r))
	if err != nil {
		if errors.Is(err, db.ErrNoOutputOwner) {
			writeJSON(w, http.StatusNotFound, j{
				"status": "FAILED", "error": "NOT_FOUND", "message": "no output-owner VM registered yet",
			})
			return
		}
		log.Println("[GOVERNANCE] ❌ Error fetching output-owner VM:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": "Failed to fetch output-owner VM",
		})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "vm": entry})
}

// GET /vm-registry/data-providers — every registered data-provider VM.
func (s *Server) getDataProviderVMs(w http.ResponseWriter, r *http.Request) {
	entries, err := s.db.ListDataProviderVMs(reqCtx(r))
	if err != nil {
		log.Println("[GOVERNANCE] ❌ Error listing data-provider VMs:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": "Failed to list data-provider VMs",
		})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "vms": entries})
}
