package httpapi

// A consumer may not generate a second contract for the same datasets and
// technique while their previous one is still waiting for the providers:
// regenerating would overwrite it (same preview row), mint a new contract and
// job, and send the providers a fresh round of approval / sign requests.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// pendingGeneratedContract returns the consumer's stored contract for this
// selection if it is still waiting for approval, else nil.
func (s *Server) pendingGeneratedContract(ctx context.Context, consumerID, datasetKey, technique string) (*contract.Contract, error) {
	raw, err := s.db.GetContractBySession(ctx, postgres.GeneratedContractSessionKey(consumerID, datasetKey, technique))
	if err != nil || raw == nil {
		return nil, err
	}
	var c contract.Contract
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("decode stored contract: %w", err)
	}
	rejected := false
	if c.JobID != "" {
		if rejected, err = s.db.JobHasRejection(ctx, c.JobID); err != nil {
			return nil, err
		}
	}
	if !contractAwaitingApproval(&c, time.Now(), rejected, s.contractRunnable(ctx, &c)) {
		return nil, nil
	}
	return &c, nil
}

// contractAwaitingApproval: a TEE/SMPC contract that is not fully signed yet,
// and that no provider has rejected or withdrawn from, and that hasn't
// expired. FL drafts send no requests, so they never block.
func contractAwaitingApproval(c *contract.Contract, now time.Time, rejected, runnable bool) bool {
	if c == nil || c.Technique == "FL" || rejected || runnable {
		return false
	}
	if vu := c.Lifecycle.ValidUntil; !vu.IsZero() && !now.Before(vu) {
		return false
	}
	for _, p := range c.Parties.DataProviders {
		if p.Signature.WithdrawnAt != nil {
			return false
		}
	}
	return consentExpiryError(c, now) == nil
}
