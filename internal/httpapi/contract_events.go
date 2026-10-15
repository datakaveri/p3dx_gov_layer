package httpapi

import (
	"context"
	"log"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
)

// recordContractEvent appends one event to c's history (contract_events) for
// the data provider's Audit page. Best-effort: a failure is only logged.
func (s *Server) recordContractEvent(ctx context.Context, c *contract.Contract, event, detail, actor string) {
	if s.db == nil || c == nil || c.ContractID == "" {
		return
	}
	if err := s.db.AddContractEvent(ctx, c.ContractID, c.JobID, event, detail, actor); err != nil {
		log.Printf("[CONTRACT-EVENT] Warning: contract %s: %s not recorded: %v", c.ContractID, event, err)
	}
}
