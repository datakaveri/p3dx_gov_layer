package httpapi

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// buildSessionContract assembles, stores and (when finalize) governance-signs
// the FL session contract for submissionID as its own project (one row per
// contract, never reused; a new project_id every call), records the project,
// and on finalize sends each data provider a sign request. An unknown
// submission fails with pgx.ErrNoRows. Called by the /me/fl routes.
func (s *Server) buildSessionContract(ctx context.Context, submissionID, outputOwnerUserID string, parties []postgres.ContractPartyInput, finalize bool) (string, *contract.Contract, int, error) {
	c, err := s.db.BuildContract(ctx, submissionID, outputOwnerUserID, parties, finalize, "FL", s.cfg.KBSURL, s.cfg.FLContractValidity)
	if err != nil {
		return "", nil, 0, err
	}

	if finalize {
		if err := s.governanceSign(c); err != nil {
			return "", nil, 0, fmt.Errorf("governance-sign contract: %w", err)
		}
	}

	contractID, err := s.db.StoreContract(ctx, c, finalize, "FL")
	if err != nil {
		return "", nil, 0, fmt.Errorf("store contract: %w", err)
	}

	usernames := make([]string, 0, len(parties))
	for _, p := range parties {
		usernames = append(usernames, p.Username)
	}
	if err := s.db.UpsertProject(ctx, c.ProjectID, c.SessionInfo.SessionID, c.Parties.User.ID, usernames); err != nil {
		log.Println("[GOVERNANCE] Error recording project participants:", err)
	}

	signRequestsSent := 0
	if finalize {
		signRequestsSent = s.notifyContractSigners(ctx, *c, contractRequester(*c))
	}

	log.Printf("[GOVERNANCE] ✅ Contract %s ready (session=%s finalized=%t)", contractID, c.SessionInfo.SessionID, finalize)
	return contractID, c, signRequestsSent, nil
}

// GET /contracts/{sessionId} — return the stored contract for a session.
func (s *Server) getContract(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionId")
	raw, err := s.db.GetContractBySession(reqCtx(r), sessionID)
	if err != nil {
		log.Println("[GOVERNANCE] Error retrieving contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}
	if raw == nil {
		writeJSON(w, http.StatusNotFound, j{
			"status": "FAILED", "error": "NOT_FOUND", "message": "No contract for this session",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"SUCCESS","contract":`))
	_, _ = w.Write(raw)
	_, _ = w.Write([]byte(`}`))
}

// GET /contracts/by-project/{projectId} — return the stored contract for one
// specific project (not just a session's latest one - see
// GetContractByProjectID). Used by the owner's Projects page to view the
// exact contract behind any one project card.
func (s *Server) getContractByProject(w http.ResponseWriter, r *http.Request) {
	projectID := chi.URLParam(r, "projectId")
	raw, err := s.db.GetContractByProjectID(reqCtx(r), projectID)
	if err != nil {
		log.Println("[GOVERNANCE] Error retrieving contract by project:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}
	if raw == nil {
		writeJSON(w, http.StatusNotFound, j{
			"status": "FAILED", "error": "NOT_FOUND", "message": "No contract for this project",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"SUCCESS","contract":`))
	_, _ = w.Write(raw)
	_, _ = w.Write([]byte(`}`))
}

// GET /projects/{sessionId} — return only the project_id recorded for a
// session (not the participant roster - that stays internal to governance).
// FL orchestrator service token only.
func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireServiceToken(w, r, s.cfg.OrchestratorClientID, s.cfg.OrchestratorRole); !ok {
		return
	}
	sessionID := chi.URLParam(r, "sessionId")
	projectID, err := s.db.GetProjectIDBySession(reqCtx(r), sessionID)
	if err != nil {
		log.Println("[GOVERNANCE] Error retrieving project:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}
	if projectID == "" {
		writeJSON(w, http.StatusNotFound, j{
			"status": "FAILED", "error": "NOT_FOUND", "message": "No project for this session",
		})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "project_id": projectID})
}

// GET /projects?owner={username} — list projects. With owner set, only that
// owner's projects (the output-owner's own "Projects" view); omitted, every
// project. FL orchestrator service token only; an owner's own view is
// GET /me/projects.
func (s *Server) getProjects(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireServiceToken(w, r, s.cfg.OrchestratorClientID, s.cfg.OrchestratorRole); !ok {
		return
	}
	owner := r.URL.Query().Get("owner")
	projects, err := s.db.ListProjects(reqCtx(r), owner)
	if err != nil {
		log.Println("[GOVERNANCE] Error listing projects:", err)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "projects": projects})
}
