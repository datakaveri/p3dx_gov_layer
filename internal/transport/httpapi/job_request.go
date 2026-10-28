// Job requests: when a consumer generates a contract that needs job approval
// (datasets + infra, see job_approval.go), each data and infra provider on it
// is sent a JOB_REQUEST notification asking them to approve or reject the
// job with POST /job/approval/{data,infra}-provider. It carries the contract
// and its hash — the contract_hash stored with it, which each provider signs
// when approving and every approval is cross-verified against.
package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/application/jobapproval"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// JobRequestNotificationType is payload.type of a job request notification.
const JobRequestNotificationType = "JOB_REQUEST"

type jobRequestConsumer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type jobRequestItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// jobRequestPayload is the payload of a JOB_REQUEST notification.
type jobRequestPayload struct {
	Type        string             `json:"type"`
	Role        string             `json:"role"` // postgres.AuditTypeDataProvider / postgres.AuditTypeInfraProvider
	JobID       string             `json:"job_id"`
	ContractID  string             `json:"contract_id"`
	Technique   string             `json:"technique"`
	Consumer    jobRequestConsumer `json:"consumer"`
	Items       []jobRequestItem   `json:"items"`
	ApproveWith string             `json:"approve_with"`
	// ContractHash is the contract's hash (contract.ComputeHash).
	ContractHash  string            `json:"contract_hash"`
	HashAlgorithm string            `json:"hash_algorithm"`
	Contract      contract.Contract `json:"contract"`
}

// jobRequest is one provider's JOB_REQUEST notification.
type jobRequest struct {
	providerID string
	message    string
	payload    jobRequestPayload
}

// jobRequests builds one request per distinct data provider (their datasets
// on c) and per distinct infra provider (their infras on c, owners as
// resolved by Service.InfraOwners). Datasets / infras with no known provider get none.
func jobRequests(c contract.Contract, hash string, owners []infraOwner, sender string) []jobRequest {
	base := jobRequestPayload{
		Type:          JobRequestNotificationType,
		JobID:         c.JobID,
		ContractID:    c.ContractID,
		Technique:     c.Technique,
		Consumer:      jobRequestConsumer{ID: c.Parties.User.ID, Name: c.Parties.User.Name},
		ContractHash:  hash,
		HashAlgorithm: "SHA-256",
		Contract:      c,
	}
	reqs := []jobRequest{}
	index := map[string]int{} // role + provider_id -> reqs index
	add := func(role, providerID string, item jobRequestItem) {
		key := role + "\x00" + providerID
		i, seen := index[key]
		if !seen {
			p := base
			p.Role = role
			p.ApproveWith = "POST /job/approval/" + role
			reqs = append(reqs, jobRequest{providerID: providerID, payload: p})
			i = len(reqs) - 1
			index[key] = i
		}
		reqs[i].payload.Items = append(reqs[i].payload.Items, item)
	}
	for _, dp := range c.Parties.DataProviders {
		if dp.ID != "" {
			add(postgres.AuditTypeDataProvider, partyProviderID(dp), jobRequestItem{ID: jobapproval.ApprovalItem(dp), Name: dp.DatasetName})
		}
	}
	infraNames := map[string]string{}
	for _, ip := range c.Parties.InfraProviders {
		infraNames[ip.ID] = ip.Name
	}
	for _, o := range owners {
		if o.ProviderID != "" {
			add(postgres.AuditTypeInfraProvider, o.ProviderID, jobRequestItem{ID: o.InfraID, Name: infraNames[o.InfraID]})
		}
	}

	for i := range reqs {
		p := reqs[i].payload
		what, noun := make([]string, 0, len(p.Items)), "dataset"
		if p.Role == postgres.AuditTypeInfraProvider {
			noun = "infrastructure"
		}
		for _, it := range p.Items {
			name := it.Name
			if name == "" {
				name = it.ID
			}
			what = append(what, fmt.Sprintf("%q", name))
		}
		if len(what) > 1 {
			noun += "s"
		}
		reqs[i].message = fmt.Sprintf("%s requests to use your %s %s for the %s job %s. Please approve or reject it.",
			sender, noun, strings.Join(what, ", "), p.Technique, p.JobID)
	}
	return reqs
}

// storedContractHash is c's hash as computed from its stored (JSON
// round-tripped) form — the form the job-approval seal later loads and hashes.
func storedContractHash(c contract.Contract) (contract.Contract, string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return c, "", err
	}
	var stored contract.Contract
	if err := json.Unmarshal(raw, &stored); err != nil {
		return c, "", err
	}
	hash, err := contract.ComputeHash(stored)
	return stored, hash, err
}

// notifyJobRequest sends c's job requests (jobRequests) as notifications
// addressed by provider_id. Returns how many were sent.
func (s *Server) notifyJobRequest(ctx context.Context, c contract.Contract, sender string) int {
	c, hash, err := storedContractHash(c)
	if err != nil {
		log.Printf("[JOB-REQUEST] Warning: job %s: contract could not be hashed, providers not notified: %v", c.JobID, err)
		return 0
	}
	sent := 0
	for _, req := range jobRequests(c, hash, s.approvals().InfraOwners(&c), sender) {
		payload, err := json.Marshal(req.payload)
		if err != nil {
			log.Printf("[JOB-REQUEST] Warning: failed to marshal job request for %s: %v", req.providerID, err)
			continue
		}
		if _, err := s.db.CreateNotification(ctx, req.providerID, req.providerID, sender, req.message, payload); err != nil {
			log.Printf("[JOB-REQUEST] Warning: failed to notify %s of job %s: %v", req.providerID, c.JobID, err)
			continue
		}
		sent++
	}
	log.Printf("[JOB-REQUEST] Job %s: %d provider(s) asked to approve", c.JobID, sent)
	return sent
}
