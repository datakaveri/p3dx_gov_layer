// FL session flow for the P3DX UI (formerly p3dx-aaa's /notify-* and /gov/*
// routes): the output owner requests data providers, confirms the final
// roster (which builds the session contract), and starts, queues or restarts
// the session; providers report their Azure sign-in. Every route sits under
// /me (user_routes.go), so the sender is always the token's user.

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/apd"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/application/contractgen"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
)

// flOrchestratorUsername is the Keycloak user that operates FL sessions; a
// queued session is sent to it as an fl_session_pending notification.
const flOrchestratorUsername = "fl-orchestrator"

func (s *Server) registerFLSessionRoutes(r chi.Router) {
	r.Route("/fl", func(r chi.Router) {
		r.Get("/data-providers", s.getFLDataProviders)
		r.Post("/notify-providers", s.notifyProviders)
		r.Post("/notify-roster", s.notifyRoster)
		r.Post("/queue-session", s.queueFLSession)
		r.Post("/start-session", s.startFLSession)
		r.Post("/restart-session", s.restartFLSession)
		r.Post("/restart-session/queue", s.queueRestartedFLSession)
		r.Post("/azure-signin", s.notifyAzureSignIn)
		r.With(s.requireUserRole(s.dataProviderRole())).Post("/vm-credentials", s.issueVMCredential)
	})
}

// rosterEntry is one provider as the UI sends it. Only id and username are
// read; the whole object goes into the notification payload unchanged.
type rosterEntry map[string]any

func (p rosterEntry) id() string       { v, _ := p["id"].(string); return v }
func (p rosterEntry) username() string { v, _ := p["username"].(string); return v }

func withoutRemoved(roster []rosterEntry, removed map[string]bool) []rosterEntry {
	out := []rosterEntry{}
	for _, p := range roster {
		if p != nil && !removed[p.username()] {
			out = append(out, p)
		}
	}
	return out
}

func recipientsOf(roster []rosterEntry) []notificationRecipient {
	out := []notificationRecipient{}
	for _, p := range roster {
		if p.id() != "" && p.username() != "" {
			out = append(out, notificationRecipient{ID: p.id(), Username: p.username()})
		}
	}
	return out
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// GET /me/fl/data-providers — every user holding the data-provider realm role,
// with the RAM they declared on their latest FL provider form (APD).
func (s *Server) getFLDataProviders(w http.ResponseWriter, r *http.Request) {
	users, err := s.users.UsersWithRole(reqCtx(r), s.dataProviderRole())
	if err != nil {
		log.Println("[FL] Error listing data providers:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	forms, err := apd.LatestProviderFormByOwner()
	if err != nil {
		log.Println("[FL] Warning: could not load provider forms from APD:", err)
	}
	providers := make([]j, 0, len(users))
	for _, u := range users {
		var ram any
		if f, ok := forms[u.Username]; ok {
			ram = f["ram_usage"]
		}
		providers = append(providers, j{"id": u.ID, "username": u.Username, "email": u.Email, "ram_usage": ram})
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "data_providers": providers})
}

// POST /me/fl/notify-providers — the output owner asks the requested providers
// (else the selected ones) to participate. Providers removed from the session
// are skipped.
func (s *Server) notifyProviders(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Selected     []rosterEntry `json:"selected_providers"`
		Requested    []rosterEntry `json:"requested_providers"`
		Willing      []rosterEntry `json:"willing_providers"`
		OutputOwner  string        `json:"output_owner_id"`
		SubmissionID string        `json:"submission_id"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	requested := body.Requested
	if len(requested) == 0 {
		requested = body.Selected
	}
	if len(requested) == 0 {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_REQUESTED_PROVIDERS"})
		return
	}
	removed, ok := s.sessionRemovedProviders(w, r, body.SubmissionID)
	if !ok {
		return
	}
	sender := userFrom(r).username
	remaining := withoutRemoved(requested, removed)
	recipients := recipientsOf(remaining)
	if len(recipients) == 0 {
		code := "ALL_REQUESTED_PROVIDERS_REMOVED"
		if len(remaining) > 0 {
			code = "REQUESTED_PROVIDERS_MISSING_ID_OR_USERNAME"
		}
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": code})
		return
	}
	selected := withoutRemoved(body.Selected, removed)
	willing := withoutRemoved(body.Willing, removed)

	message := fmt.Sprintf("%s requested %d data provider(s)", sender, len(remaining))
	if body.SubmissionID != "" {
		message += " for session " + body.SubmissionID
	} else {
		message += " for a federated learning session"
	}
	if len(selected) > 0 {
		message += fmt.Sprintf(" — %d selected by the owner", len(selected))
	}
	message += fmt.Sprintf(" — %d confirmed willing so far.", len(willing))

	created, skipped, err := s.createNotifications(r, recipients, sender, message, mustJSON(j{
		"kind":                "participation_request",
		"submission_id":       body.SubmissionID,
		"output_owner_id":     firstNonEmpty(body.OutputOwner, sender),
		"selected_providers":  selected,
		"requested_providers": remaining,
		"willing_providers":   willing,
	}))
	if err != nil {
		log.Println("[FL] Error sending participation requests:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	for _, p := range requested {
		if removed[p.username()] && !slices.Contains(skipped, p.username()) {
			skipped = append(skipped, p.username())
		}
	}
	writeJSON(w, http.StatusCreated, j{"status": "SUCCESS", "created": len(created), "skipped_removed": skipped})
}

// POST /me/fl/notify-roster — the output owner confirms the final roster: the
// willing providers are told, and the session contract is built and sent out
// for signing.
func (s *Server) notifyRoster(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Selected     []rosterEntry `json:"selected_providers"`
		Willing      []rosterEntry `json:"willing_providers"`
		OutputOwner  string        `json:"output_owner_id"`
		SubmissionID string        `json:"submission_id"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	removed, ok := s.sessionRemovedProviders(w, r, body.SubmissionID)
	if !ok {
		return
	}
	willing := withoutRemoved(body.Willing, removed)
	if len(willing) == 0 {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_WILLING_PROVIDERS"})
		return
	}
	recipients := recipientsOf(willing)
	if len(recipients) == 0 {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "WILLING_PROVIDERS_MISSING_ID_OR_USERNAME"})
		return
	}
	sender := userFrom(r).username
	owner := firstNonEmpty(body.OutputOwner, sender)
	names := make([]string, len(recipients))
	for i, p := range recipients {
		names[i] = p.Username
	}
	message := sender + " confirmed the final roster"
	if body.SubmissionID != "" {
		message += " for session " + body.SubmissionID
	} else {
		message += " for this federated learning session"
	}
	message += " — participating: " + strings.Join(names, ", ") + "."

	created, _, err := s.createNotifications(r, recipients, sender, message, mustJSON(j{
		"kind":               "final_roster",
		"submission_id":      body.SubmissionID,
		"output_owner_id":    owner,
		"selected_providers": withoutRemoved(body.Selected, removed),
		"willing_providers":  willing,
	}))
	if err != nil {
		log.Println("[FL] Error sending final roster:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	resp := j{"status": "SUCCESS", "created": len(created)}
	if body.SubmissionID != "" {
		contractID, c, err := s.buildRosterContract(reqCtx(r), body.SubmissionID, owner, recipients)
		if err != nil {
			log.Println("[FL] Error building session contract:", err)
			resp["contract_error"] = err.Error()
		} else {
			resp["contract_id"], resp["contract"] = contractID, c
		}
	}
	writeJSON(w, http.StatusCreated, resp)
}

// POST /me/fl/queue-session — once every provider has signed, hand the
// session to the FL orchestrator operator.
func (s *Server) queueFLSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SubmissionID string        `json:"submission_id"`
		Providers    []rosterEntry `json:"participating_providers"`
		VMName       string        `json:"vm_name"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	if body.SubmissionID == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_SUBMISSION_ID"})
		return
	}
	if len(body.Providers) == 0 {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_PARTICIPATING_PROVIDERS"})
		return
	}
	if !s.requireSignedSession(w, r, body.SubmissionID) {
		return
	}
	if err := s.queueForOrchestrator(r, body.SubmissionID, body.Providers, body.VMName); err != nil {
		log.Println("[FL] Error queueing session:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS"})
}

// POST /me/fl/start-session — tell the participating providers to join (Azure
// sign-in) and report the expected count to the orchestrator. The
// fl-orchestrator operator may start a session on an owner's behalf
// (output_owner_username); anyone else starts it as themselves.
func (s *Server) startFLSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SubmissionID string        `json:"submission_id"`
		Providers    []rosterEntry `json:"participating_providers"`
		OutputOwner  string        `json:"output_owner_username"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	if body.SubmissionID == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_SUBMISSION_ID"})
		return
	}
	recipients := recipientsOf(body.Providers)
	if len(recipients) == 0 {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_PARTICIPATING_PROVIDERS"})
		return
	}
	if !s.requireSignedSession(w, r, body.SubmissionID) {
		return
	}
	caller := userFrom(r)
	sender := caller.username
	if body.OutputOwner != "" && slices.Contains(caller.roles, s.cfg.OrchestratorRole) {
		sender = body.OutputOwner
	}
	created, _, err := s.createNotifications(r, recipients, sender,
		fmt.Sprintf("%s started the FL session for submission %s — sign in with your Azure account to join.", sender, body.SubmissionID),
		mustJSON(j{"kind": "fl_session_start", "submission_id": body.SubmissionID, "output_owner_id": sender}))
	if err != nil {
		log.Println("[FL] Error notifying session start:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	go s.registerExpectedProviders(body.SubmissionID, len(recipients))
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "notified": len(created)})
}

// POST /me/fl/restart-session — "Start Again" with the same roster: a new
// session contract goes out for signing and the providers are told.
func (s *Server) restartFLSession(w http.ResponseWriter, r *http.Request) {
	submissionID, recipients, ok := s.readRestartBody(w, r)
	if !ok {
		return
	}
	caller := userFrom(r)
	resp := j{"status": "SUCCESS", "awaiting_signatures": true}
	if _, _, err := s.buildRosterContract(reqCtx(r), submissionID, caller.userID, recipients); err != nil {
		log.Println("[FL] Error building restart contract:", err)
		resp["awaiting_signatures"], resp["contract_error"] = false, err.Error()
	}
	if _, _, err := s.createNotifications(r, recipients, caller.username,
		fmt.Sprintf("%s is starting the FL session for submission %s again with the same roster — please sign the new contract.", caller.username, submissionID),
		mustJSON(j{"kind": "fl_session_restart", "submission_id": submissionID, "output_owner_username": caller.username})); err != nil {
		log.Println("[FL] Error notifying restart:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /me/fl/restart-session/queue — queue a restarted session once its new
// contract is fully signed.
func (s *Server) queueRestartedFLSession(w http.ResponseWriter, r *http.Request) {
	submissionID, recipients, ok := s.readRestartBody(w, r)
	if !ok {
		return
	}
	if !s.requireSignedSession(w, r, submissionID) {
		return
	}
	providers := make([]rosterEntry, len(recipients))
	for i, p := range recipients {
		providers[i] = rosterEntry{"id": p.ID, "username": p.Username}
	}
	if err := s.queueForOrchestrator(r, submissionID, providers, ""); err != nil {
		log.Println("[FL] Error queueing restarted session:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS"})
}

// POST /me/fl/azure-signin — a provider tells the session's owner they signed
// in with Azure.
func (s *Server) notifyAzureSignIn(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Owner        string `json:"owner_username"`
		SubmissionID string `json:"submission_id"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	if body.Owner == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_OWNER_USERNAME"})
		return
	}
	owner, err := s.users.UserByUsername(reqCtx(r), body.Owner)
	if err != nil || owner == nil {
		log.Println("[FL] Error looking up session owner:", err)
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "OWNER_NOT_FOUND"})
		return
	}
	provider := userFrom(r).username
	message := provider + " signed in with Azure"
	if body.SubmissionID != "" {
		message += " for submission " + body.SubmissionID
	}
	created, _, err := s.createNotifications(r, []notificationRecipient{{ID: owner.ID, Username: owner.Username}}, provider, message+".",
		mustJSON(j{"kind": "azure_signin", "submission_id": body.SubmissionID, "provider_username": provider}))
	if err != nil {
		log.Println("[FL] Error notifying Azure sign-in:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "notified": len(created)})
}

// readRestartBody reads {submission_id, provider_usernames} and resolves the
// usernames to Keycloak users; unknown ones are dropped.
func (s *Server) readRestartBody(w http.ResponseWriter, r *http.Request) (string, []notificationRecipient, bool) {
	var body struct {
		SubmissionID string   `json:"submission_id"`
		Usernames    []string `json:"provider_usernames"`
	}
	if !s.readBody(w, r, &body) {
		return "", nil, false
	}
	if body.SubmissionID == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_SUBMISSION_ID"})
		return "", nil, false
	}
	var recipients []notificationRecipient
	asked := 0
	for _, name := range body.Usernames {
		if name == "" {
			continue
		}
		asked++
		u, err := s.users.UserByUsername(reqCtx(r), name)
		if err != nil || u == nil {
			log.Printf("[FL] Provider %q not found in Keycloak: %v", name, err)
			continue
		}
		recipients = append(recipients, notificationRecipient{ID: u.ID, Username: u.Username})
	}
	if asked == 0 {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_PARTICIPATING_PROVIDERS"})
		return "", nil, false
	}
	if len(recipients) == 0 {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "PROVIDERS_NOT_FOUND"})
		return "", nil, false
	}
	return body.SubmissionID, recipients, true
}

// sessionRemovedProviders loads the providers removed from submissionID (none
// when it is empty). On failure it has already written the response.
func (s *Server) sessionRemovedProviders(w http.ResponseWriter, r *http.Request, submissionID string) (map[string]bool, bool) {
	if submissionID == "" {
		return map[string]bool{}, true
	}
	removed, err := s.removedProviderSet(r, submissionID)
	if err != nil {
		log.Println("[FL] Error loading removed providers:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return nil, false
	}
	return removed, true
}

// buildRosterContract builds and sends out the finalized session contract for
// the given providers, each with the dataset from their latest APD form.
func (s *Server) buildRosterContract(ctx context.Context, submissionID, ownerUserID string, providers []notificationRecipient) (string, *contract.Contract, error) {
	forms, err := apd.LatestProviderFormByOwner()
	if err != nil {
		return "", nil, fmt.Errorf("load provider forms: %w", err)
	}
	parties := make([]contractgen.FLParty, len(providers))
	for i, p := range providers {
		form := forms[p.Username]
		name, _ := form["dataset_name"].(string)
		url, _ := form["dataset_location_url"].(string)
		parties[i] = contractgen.FLParty{ID: p.ID, Username: p.Username, DatasetName: name, DataURL: url}
	}
	contractID, c, _, err := s.buildSessionContract(ctx, submissionID, ownerUserID, parties, true)
	return contractID, c, err
}

// requireSignedSession refuses (403 CONTRACT_NOT_SIGNED) unless the session's
// contract is fully signed and runnable.
func (s *Server) requireSignedSession(w http.ResponseWriter, r *http.Request, submissionID string) bool {
	raw, err := s.db.GetContractBySession(reqCtx(r), submissionID)
	if err != nil {
		log.Println("[FL] Error loading session contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return false
	}
	if raw == nil {
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "CONTRACT_NOT_SIGNED", "message": "No final roster contract for this session yet."})
		return false
	}
	var c contract.Contract
	if err := json.Unmarshal(raw, &c); err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return false
	}
	if !s.contractRunnable(reqCtx(r), &c) {
		writeJSON(w, http.StatusForbidden, j{
			"status": "FAILED", "error": "CONTRACT_NOT_SIGNED",
			"message":    "Data-provider signatures are not matching yet — every data provider must sign the final roster contract.",
			"signatures": j{"signatures": "not matching", "tee": "cannot run"},
		})
		return false
	}
	return true
}

// queueForOrchestrator sends the fl-orchestrator operator an
// fl_session_pending notification for the session.
func (s *Server) queueForOrchestrator(r *http.Request, submissionID string, providers []rosterEntry, vmName string) error {
	orch, err := s.users.UserByUsername(reqCtx(r), flOrchestratorUsername)
	if err != nil {
		return fmt.Errorf("look up %s user: %w", flOrchestratorUsername, err)
	}
	if orch == nil {
		return fmt.Errorf("no %s user in Keycloak", flOrchestratorUsername)
	}
	projectID, err := s.db.GetProjectIDBySession(reqCtx(r), submissionID)
	if err != nil {
		log.Println("[FL] Warning: could not look up project:", err)
	}
	owner := userFrom(r).username
	_, _, err = s.createNotifications(r, []notificationRecipient{{ID: orch.ID, Username: orch.Username}}, owner,
		fmt.Sprintf("%s requested to start the FL session for submission %s.", owner, submissionID),
		mustJSON(j{
			"kind":                    "fl_session_pending",
			"submission_id":           submissionID,
			"participating_providers": providers,
			"vm_name":                 vmName,
			"output_owner_username":   owner,
			"project_id":              nilIfEmpty(projectID),
		}))
	return err
}

// registerExpectedProviders tells p3dx-fl-orchestrator how many providers to
// wait for. Best effort: failures are only logged.
func (s *Server) registerExpectedProviders(submissionID string, count int) {
	base := strings.TrimRight(s.cfg.OrchestratorServiceURL, "/")
	if base == "" {
		log.Println("[FL] ORCHESTRATOR_SERVICE_URL not set; not registering expected providers")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/p3dx/internal/register-expected-providers",
		bytes.NewReader(mustJSON(j{"submissionId": submissionID, "count": count})))
	if err != nil {
		log.Println("[FL] Error building register-expected-providers request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", s.cfg.InternalServiceKey)
	resp, err := s.http.Do(req)
	if err != nil {
		log.Println("[FL] register-expected-providers failed:", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("[FL] register-expected-providers returned %d", resp.StatusCode)
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
