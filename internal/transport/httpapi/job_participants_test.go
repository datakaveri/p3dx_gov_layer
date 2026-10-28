package httpapi

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

func TestJobParticipantRows(t *testing.T) {
	c := &contract.Contract{
		JobID: "job-1", ContractID: "con-1", Technique: "TEE",
		Parties: contract.Parties{
			User: contract.UserParty{ID: "sub-consumer", Name: "consumer"},
			DataProviders: []contract.DataProviderParty{
				{ID: "provider-alice", Name: "alice", DatasetID: "ds-1", DatasetName: "Dataset One"},
			},
			InfraProviders: []contract.InfraProviderParty{{ID: "infra-1", Name: "Infra One"}},
		},
	}
	rows := jobParticipantRows(c, "consumer", []infraOwner{{InfraID: "infra-1", ProviderID: "provider-bob"}})
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3: %+v", len(rows), rows)
	}

	consumer, dp, ip := rows[0], rows[1], rows[2]
	if consumer.Role != postgres.ParticipantRoleConsumer || consumer.UserID != "sub-consumer" || consumer.Username != "consumer" || consumer.Status != postgres.ParticipantStatusCreated {
		t.Errorf("consumer row = %+v", consumer)
	}
	if dp.Role != postgres.ParticipantRoleDataProvider || dp.ParticipantID != "provider-alice" || dp.ItemID != "ds-1" || dp.ItemName != "Dataset One" || dp.Status != postgres.ParticipantStatusRequested {
		t.Errorf("data provider row = %+v", dp)
	}
	if ip.Role != postgres.ParticipantRoleInfraProvider || ip.ParticipantID != "provider-bob" || ip.ItemID != "infra-1" || ip.ItemName != "Infra One" {
		t.Errorf("infra provider row = %+v", ip)
	}
	for _, r := range rows {
		if r.JobID != "job-1" || r.ContractID != "con-1" || r.Technique != "TEE" {
			t.Errorf("row not tied to the job: %+v", r)
		}
	}
}

func TestGroupUserJobs(t *testing.T) {
	final := time.Now()
	rows := []postgres.JobParticipant{
		{JobID: "job-2", ContractID: "con-2", Role: postgres.ParticipantRoleConsumer, Status: postgres.ParticipantStatusCreated},
		{JobID: "job-1", ContractID: "con-1", Role: postgres.ParticipantRoleDataProvider, ItemID: "ds-1", Status: postgres.ParticipantStatusFinal, FinalizedAt: &final},
		{JobID: "job-1", ContractID: "con-1", Role: postgres.ParticipantRoleDataProvider, ItemID: "ds-2", Status: postgres.ParticipantStatusFinal, FinalizedAt: &final},
	}
	jobs := groupUserJobs(rows)
	if len(jobs) != 2 {
		t.Fatalf("got %d jobs, want 2", len(jobs))
	}
	if jobs[0].JobID != "job-2" || jobs[0].JobState != "in_progress" || len(jobs[0].Participation) != 1 {
		t.Errorf("jobs[0] = %+v", jobs[0])
	}
	if jobs[1].JobID != "job-1" || jobs[1].JobState != "final" || len(jobs[1].Participation) != 2 {
		t.Errorf("jobs[1] = %+v", jobs[1])
	}
}

func TestOwnTokenNames(t *testing.T) {
	caller := callerFromClaims("tok", jwt.MapClaims{
		"sub": "48fa1de2-43f5-4274-92a7-0b9917c2e597", "preferred_username": "dataprovider-private", "email": "data@gmail.com",
	})
	has := func(names []string, want string) bool {
		for _, n := range names {
			if n == want {
				return true
			}
		}
		return false
	}
	for _, id := range []string{"48fa1de2-43f5-4274-92a7-0b9917c2e597", "DataProvider-Private", "data@gmail.com"} {
		names := ownTokenNames(id, caller)
		if !has(names, "provider-dataprovider-private") {
			t.Errorf("ownTokenNames(%q) = %v, want it to include provider-dataprovider-private", id, names)
		}
		// A requested row (no user id / username yet) now matches.
		row := postgres.JobParticipant{Role: postgres.ParticipantRoleDataProvider, ParticipantID: "provider-dataprovider-private", Status: postgres.ParticipantStatusRequested}
		if !has(names, strings.ToLower(row.ParticipantID)) {
			t.Errorf("requested row not matched for %q", id)
		}
	}
	if names := ownTokenNames("someone-else", caller); names != nil {
		t.Errorf("ownTokenNames(someone-else) = %v, want nil", names)
	}
}
