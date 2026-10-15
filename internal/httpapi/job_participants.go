// Job participants: who takes part in each job (contract) and how far along
// they are, kept in the job_participants table (internal/db/job_participants.go)
// so GET /jobs/user/{userId} can list every contract a user is on, and
// GET /jobs/consumer/{userId} / GET /jobs/provider/{userId} the ones they
// created / are requested on as a data provider.
//
// Rows are written as the job moves, always best-effort (a failed write is
// logged and never fails the step itself):
//
//   - POST /generate-contract: the consumer ("created") and every data /
//     infra provider on the contract ("requested"). FL is left out — its
//     sessions are tracked in projects.
//   - POST /job/approval/{data,infra}-provider: the caller's items
//     "approved" / "rejected", with their user id from their token.
//   - POST /contracts/{contractId}/sign: the signer's datasets "signed".
//   - PUT /job/{jobId}/status (once final) and POST /job/{jobId}/tee: every
//     participant "final" / "tee_enabled".
package httpapi

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// jobParticipantRows is c's participants as first stored: the consumer
// (consumerUsername from their token) and each data and infra provider —
// an infra's provider is its owner in owners (looked up in APD).
func jobParticipantRows(c *contract.Contract, consumerUsername string, owners []infraOwner) []db.JobParticipant {
	base := db.JobParticipant{JobID: c.JobID, ContractID: c.ContractID, Technique: c.Technique}
	rows := []db.JobParticipant{}

	consumer := base
	consumer.Role = db.ParticipantRoleConsumer
	consumer.ParticipantID = c.Parties.User.ID
	consumer.UserID = c.Parties.User.ID
	consumer.Username = consumerUsername
	consumer.Status = db.ParticipantStatusCreated
	rows = append(rows, consumer)

	for _, dp := range c.Parties.DataProviders {
		p := base
		p.Role = db.ParticipantRoleDataProvider
		if dp.ID != "" {
			p.ParticipantID = partyProviderID(dp)
		}
		p.ItemID = approvalItem(dp)
		p.ItemName = dp.DatasetName
		p.Status = db.ParticipantStatusRequested
		rows = append(rows, p)
	}

	names := map[string]string{}
	for _, ip := range c.Parties.InfraProviders {
		names[ip.ID] = ip.Name
	}
	for _, o := range owners {
		p := base
		p.Role = db.ParticipantRoleInfraProvider
		p.ParticipantID = o.providerID
		p.ItemID = o.infraID
		p.ItemName = names[o.infraID]
		p.Status = db.ParticipantStatusRequested
		rows = append(rows, p)
	}
	return rows
}

// recordJobParticipants stores c's participants (jobParticipantRows) right
// after /generate-contract stored c.
func (s *Server) recordJobParticipants(ctx context.Context, c *contract.Contract, consumerUsername string) {
	if c.JobID == "" || c.Technique == "FL" {
		return
	}
	var owners []infraOwner
	if needsJobApproval(c) {
		owners = infraOwners(c)
	}
	rows := jobParticipantRows(c, consumerUsername, owners)
	if err := s.db.ReplaceJobParticipants(ctx, c.JobID, rows); err != nil {
		log.Printf("[JOB-PARTICIPANTS] Warning: job %s: participants not stored: %v", c.JobID, err)
		return
	}
	log.Printf("[JOB-PARTICIPANTS] Job %s: %d participant(s) stored", c.JobID, len(rows))
}

// markApprovalParticipants records the caller's approval result on each of
// their items in own (kind: data-provider / infra-provider).
func (s *Server) markApprovalParticipants(ctx context.Context, kind, jobID string, own []db.AuditEntry, caller providerCaller) {
	for _, e := range own {
		status := db.ParticipantStatusRejected
		if e.Status == db.AuditStatusAccepted {
			status = db.ParticipantStatusApproved
		}
		if _, err := s.db.SetJobParticipantStatus(ctx, jobID, kind, e.ProviderID, e.Item, status, caller.userID, caller.username); err != nil {
			log.Printf("[JOB-PARTICIPANTS] Warning: job %s: %s %s / %s not marked %s: %v", jobID, kind, e.ProviderID, e.Item, status, err)
		}
	}
}

// markSignedParticipant records providerID's datasets on c as signed.
func (s *Server) markSignedParticipant(ctx context.Context, c *contract.Contract, providerID, userID, username string) {
	s.markParticipantStatus(ctx, c, providerID, userID, username, db.ParticipantStatusSigned)
}

// markParticipantStatus sets providerID's data-provider rows on c's job to
// status (signed, or withdrawn on consent withdrawal).
func (s *Server) markParticipantStatus(ctx context.Context, c *contract.Contract, providerID, userID, username, status string) {
	jobID := c.JobID
	if jobID == "" {
		var err error
		if jobID, err = s.db.GetJobIDByContractID(ctx, c.ContractID); err != nil || jobID == "" {
			return
		}
	}
	for _, dp := range c.Parties.DataProviders {
		if partyProviderID(dp) != providerID {
			continue
		}
		if _, err := s.db.SetJobParticipantStatus(ctx, jobID, db.ParticipantRoleDataProvider, providerID, approvalItem(dp), status, userID, username); err != nil {
			log.Printf("[JOB-PARTICIPANTS] Warning: job %s: %s not marked %s: %v", jobID, providerID, status, err)
		}
	}
}

// markJobParticipants sets every participant of jobID to status.
func (s *Server) markJobParticipants(ctx context.Context, jobID, status string) {
	if err := s.db.SetJobStatus(ctx, jobID, status); err != nil {
		log.Printf("[JOB-PARTICIPANTS] Warning: job %s: participants not marked %s: %v", jobID, status, err)
	}
}

// userJobPart is one of a user's parts in a job in the GET /jobs/user
// response.
type userJobPart struct {
	Role          string    `json:"role"`
	ParticipantID string    `json:"participant_id"`
	UserID        string    `json:"user_id"`
	Username      string    `json:"username"`
	ItemID        string    `json:"item_id,omitempty"`
	ItemName      string    `json:"item_name,omitempty"`
	Status        string    `json:"status"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// userJob is one job (contract) a user is on in the GET /jobs/user response.
type userJob struct {
	JobID         string        `json:"job_id"`
	ContractID    string        `json:"contract_id"`
	Technique     string        `json:"technique"`
	JobState      string        `json:"job_state"` // in_progress / final / tee_enabled
	CreatedAt     time.Time     `json:"created_at"`
	FinalizedAt   *time.Time    `json:"finalized_at"`
	TEEEnabledAt  *time.Time    `json:"tee_enabled_at"`
	Participation []userJobPart `json:"participation"`
	// What happened to the contract, oldest first (contract_events.go), its
	// latest entry, and who generated it.
	Events    []db.ContractEvent `json:"events"`
	LastEvent *db.ContractEvent  `json:"last_event"`
	Consumer  string             `json:"consumer"`
}

// groupUserJobs folds a user's job_participants rows (newest job first) into
// one entry per job, keeping that order.
func groupUserJobs(rows []db.JobParticipant) []userJob {
	jobs := []userJob{}
	index := map[string]int{}
	for _, p := range rows {
		i, seen := index[p.JobID]
		if !seen {
			state := "in_progress"
			switch {
			case p.TEEEnabledAt != nil:
				state = "tee_enabled"
			case p.FinalizedAt != nil:
				state = "final"
			}
			jobs = append(jobs, userJob{
				JobID: p.JobID, ContractID: p.ContractID, Technique: p.Technique, JobState: state,
				CreatedAt: p.CreatedAt, FinalizedAt: p.FinalizedAt, TEEEnabledAt: p.TEEEnabledAt,
				Participation: []userJobPart{},
			})
			i = len(jobs) - 1
			index[p.JobID] = i
		}
		jobs[i].Participation = append(jobs[i].Participation, userJobPart{
			Role: p.Role, ParticipantID: p.ParticipantID, UserID: p.UserID, Username: p.Username,
			ItemID: p.ItemID, ItemName: p.ItemName, Status: p.Status, UpdatedAt: p.UpdatedAt,
		})
	}
	return jobs
}

// userJobNames is every name userID may appear under in job_participants: the
// id itself (a Keycloak sub, username, email or provider id), its provider id,
// and — for a provider's sub — the username their public key is registered
// under and its provider id.
func (s *Server) userJobNames(ctx context.Context, userID string) ([]string, error) {
	names := []string{userID}
	if !strings.HasPrefix(strings.ToLower(userID), "provider-") {
		names = append(names, providerIDForUsername(userID))
	}
	username, err := s.db.UsernameByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if username != "" {
		names = append(names, username, providerIDForUsername(username))
	}
	return names, nil
}

// GET /jobs/user/{userId} — Authorization: Bearer <a dev Keycloak token>.
// Every job (contract) the user takes part in — as its consumer or as a data /
// infra provider — newest first, with their status on each. userId is their
// Keycloak user id (sub); a username, email or provider id also works.
func (s *Server) getUserJobs(w http.ResponseWriter, r *http.Request) {
	s.listUserJobs(w, r, func(db.JobParticipant) bool { return true })
}

// GET /jobs/consumer/{userId} — Authorization: Bearer <a dev Keycloak token>.
// The jobs (contracts) the user created, as their consumer, newest first.
func (s *Server) getConsumerJobs(w http.ResponseWriter, r *http.Request) {
	s.listUserJobs(w, r, isConsumerPart)
}

// GET /jobs/provider/{userId} — Authorization: Bearer <a dev Keycloak token>.
// The jobs (contracts) the user is requested on as a data provider and has not
// yet approved or rejected, newest first.
func (s *Server) getProviderJobs(w http.ResponseWriter, r *http.Request) {
	s.listUserJobs(w, r, isRequestedDataProviderPart)
}

func isConsumerPart(p db.JobParticipant) bool {
	return p.Role == db.ParticipantRoleConsumer
}

func isRequestedDataProviderPart(p db.JobParticipant) bool {
	return p.Role == db.ParticipantRoleDataProvider && p.Status == db.ParticipantStatusRequested
}

// filterJobParticipants is the rows keep accepts, in order.
func filterJobParticipants(rows []db.JobParticipant, keep func(db.JobParticipant) bool) []db.JobParticipant {
	out := []db.JobParticipant{}
	for _, p := range rows {
		if keep(p) {
			out = append(out, p)
		}
	}
	return out
}

// listUserJobs writes the jobs of the userId path param's job_participants
// rows that keep accepts, grouped by job (groupUserJobs).
func (s *Server) listUserJobs(w http.ResponseWriter, r *http.Request, keep func(db.JobParticipant) bool) {
	if _, _, ok := s.devTokenClaims(w, r, "user"); !ok {
		return
	}
	userID := strings.TrimSpace(chi.URLParam(r, "userId"))
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "BAD_REQUEST", "message": "userId is required"})
		return
	}
	ctx := reqCtx(r)
	names, err := s.userJobNames(ctx, userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	rows, err := s.db.ListJobParticipantsForUser(ctx, names)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	jobs := groupUserJobs(filterJobParticipants(rows, keep))
	s.attachContractEvents(ctx, jobs)
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "user_id": userID, "count": len(jobs), "jobs": jobs})
}

// GET /job/{jobId}/contract/{contractId} — Authorization: Bearer <a dev
// Keycloak token>. The job's stored contract and its contract_hash (the hash
// stored at POST /generate-contract, re-checked against a fresh hash of the
// stored contract — jobContractHash). Only the job's consumer or one of its
// data / infra providers may read it: 403 NOT_JOB_PARTICIPANT otherwise, 404
// if contractId is not this job's contract.
func (s *Server) getJobContract(w http.ResponseWriter, r *http.Request) {
	tokenStr, claims, ok := s.devTokenClaims(w, r, "user")
	if !ok {
		return
	}
	jobID := strings.TrimSpace(chi.URLParam(r, "jobId"))
	contractID := strings.TrimSpace(chi.URLParam(r, "contractId"))
	c, ok := s.loadContractByJob(w, r, jobID)
	if !ok {
		return
	}
	if contractID == "" || c.ContractID != contractID {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND",
			"message": "contract_id " + contractID + " is not this job's contract"})
		return
	}
	ctx := reqCtx(r)
	allowed, err := s.isJobParticipant(ctx, c, callerFromClaims(tokenStr, claims))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if !allowed {
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "NOT_JOB_PARTICIPANT",
			"message": "only this job's consumer or its data / infra providers can read its contract"})
		return
	}
	hash, err := jobContractHash(c)
	if err != nil {
		writeJSON(w, http.StatusConflict, j{"status": "FAILED", "error": "CONTRACT_HASH_MISMATCH", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "job_id": jobID, "contract_id": c.ContractID,
		"contract_hash": hash, "contract": c})
}

// isJobParticipant reports whether caller is c's consumer, one of its data
// providers, or anyone job_participants lists on c's job (which also covers
// its infra providers).
func (s *Server) isJobParticipant(ctx context.Context, c *contract.Contract, caller providerCaller) (bool, error) {
	if caller.userID != "" && strings.EqualFold(caller.userID, c.Parties.User.ID) {
		return true, nil
	}
	for _, dp := range c.Parties.DataProviders {
		if caller.is(dp) {
			return true, nil
		}
	}
	if caller.userID == "" {
		return false, nil
	}
	names, err := s.userJobNames(ctx, caller.userID)
	if err != nil {
		return false, err
	}
	rows, err := s.db.ListJobParticipantsForUser(ctx, names)
	if err != nil {
		return false, err
	}
	for _, p := range rows {
		if p.JobID == c.JobID {
			return true, nil
		}
	}
	return false, nil
}

// attachContractEvents fills each job's Events, LastEvent and Consumer from
// contract_events. Best-effort: on error the jobs are returned without them.
func (s *Server) attachContractEvents(ctx context.Context, jobs []userJob) {
	ids := make([]string, 0, len(jobs))
	for _, jb := range jobs {
		ids = append(ids, jb.JobID)
	}
	byJob, err := s.db.ListContractEventsForJobs(ctx, ids)
	if err != nil {
		log.Printf("[JOB-PARTICIPANTS] Warning: contract events not loaded: %v", err)
	}
	for i := range jobs {
		evs := byJob[jobs[i].JobID]
		if evs == nil {
			evs = []db.ContractEvent{}
		}
		jobs[i].Events = evs
		if n := len(evs); n > 0 {
			jobs[i].LastEvent = &evs[n-1]
		}
		for _, e := range evs {
			if e.Event == db.ContractEventGenerated {
				jobs[i].Consumer = e.Actor
				break
			}
		}
	}
}
