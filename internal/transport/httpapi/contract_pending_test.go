package httpapi

import (
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

func TestContractAwaitingApproval(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	pending := func() *contract.Contract {
		return &contract.Contract{
			Technique: "TEE",
			Lifecycle: contract.Lifecycle{ValidUntil: future},
			Parties: contract.Parties{DataProviders: []contract.DataProviderParty{
				{ID: "u-alice", Name: "alice"},
			}},
		}
	}

	withdrawn := pending()
	withdrawn.Parties.DataProviders[0].Signature.WithdrawnAt = &past
	expired := pending()
	expired.Lifecycle.ValidUntil = past
	consentExpired := pending()
	consentExpired.Parties.DataProviders[0].Constraints.ConsentValidUntil = &past
	fl := pending()
	fl.Technique = "FL"
	smpc := pending()
	smpc.Technique = "SMPC"

	cases := []struct {
		name               string
		c                  *contract.Contract
		rejected, runnable bool
		want               bool
	}{
		{"no stored contract", nil, false, false, false},
		{"waiting for providers", pending(), false, false, true},
		{"SMPC waiting for providers", smpc, false, false, true},
		{"fully signed", pending(), false, true, false},
		{"rejected by a provider", pending(), true, false, false},
		{"consent withdrawn", withdrawn, false, false, false},
		{"contract expired", expired, false, false, false},
		{"consent expired", consentExpired, false, false, false},
		{"FL draft", fl, false, false, false},
	}
	for _, c := range cases {
		if got := contractAwaitingApproval(c.c, now, c.rejected, c.runnable); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestContractRequester(t *testing.T) {
	c := contract.Contract{}
	c.Parties.User.ID, c.Parties.User.Name = "u-carol", "carol"
	if got := contractRequester(c); got != "carol" {
		t.Errorf("got %q, want carol", got)
	}
	c.Parties.User.Name = ""
	if got := contractRequester(c); got != "u-carol" {
		t.Errorf("without a name: got %q, want u-carol", got)
	}
}

func TestCurrentSignRequests(t *testing.T) {
	str := func(s string) *string { return &s }
	sign := func(id, contractID string, response *string) postgres.Notification {
		return postgres.Notification{ID: id, Response: response,
			Payload: []byte(`{"type":"CONTRACT_SIGN","contract_id":"` + contractID + `"}`)}
	}
	rows := []postgres.Notification{ // newest first, as the DB returns them
		sign("n4", "c-1", str("accepted")),
		{ID: "n3", Payload: []byte(`{"type":"CONSENT_EXPIRY_SET","contract_id":"c-1"}`)},
		sign("n2", "c-1", str("superseded")),
		sign("n1", "c-2", nil),
		sign("n0", "c-2", nil), // older duplicate for the same contract
	}
	got := currentSignRequests(rows)
	ids := []string{}
	for _, n := range got {
		ids = append(ids, n.ID)
	}
	if len(ids) != 2 || ids[0] != "n4" || ids[1] != "n1" {
		t.Fatalf("got %v, want [n4 n1]", ids)
	}
}
