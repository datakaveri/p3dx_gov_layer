package httpapi

import (
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
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
	rows := jobParticipantRows(c, "consumer", []infraOwner{{infraID: "infra-1", providerID: "provider-bob"}})
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3: %+v", len(rows), rows)
	}

	consumer, dp, ip := rows[0], rows[1], rows[2]
	if consumer.Role != db.ParticipantRoleConsumer || consumer.UserID != "sub-consumer" || consumer.Username != "consumer" || consumer.Status != db.ParticipantStatusCreated {
		t.Errorf("consumer row = %+v", consumer)
	}
	if dp.Role != db.ParticipantRoleDataProvider || dp.ParticipantID != "provider-alice" || dp.ItemID != "ds-1" || dp.ItemName != "Dataset One" || dp.Status != db.ParticipantStatusRequested {
		t.Errorf("data provider row = %+v", dp)
	}
	if ip.Role != db.ParticipantRoleInfraProvider || ip.ParticipantID != "provider-bob" || ip.ItemID != "infra-1" || ip.ItemName != "Infra One" {
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
	rows := []db.JobParticipant{
		{JobID: "job-2", ContractID: "con-2", Role: db.ParticipantRoleConsumer, Status: db.ParticipantStatusCreated},
		{JobID: "job-1", ContractID: "con-1", Role: db.ParticipantRoleDataProvider, ItemID: "ds-1", Status: db.ParticipantStatusFinal, FinalizedAt: &final},
		{JobID: "job-1", ContractID: "con-1", Role: db.ParticipantRoleDataProvider, ItemID: "ds-2", Status: db.ParticipantStatusFinal, FinalizedAt: &final},
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

func TestFilterJobParticipants(t *testing.T) {
	rows := []db.JobParticipant{
		{JobID: "job-3", Role: db.ParticipantRoleConsumer, Status: db.ParticipantStatusCreated},
		{JobID: "job-2", Role: db.ParticipantRoleDataProvider, ItemID: "ds-1", Status: db.ParticipantStatusRequested},
		{JobID: "job-2", Role: db.ParticipantRoleDataProvider, ItemID: "ds-2", Status: db.ParticipantStatusApproved},
		{JobID: "job-1", Role: db.ParticipantRoleInfraProvider, ItemID: "infra-1", Status: db.ParticipantStatusRequested},
	}
	consumer := filterJobParticipants(rows, isConsumerPart)
	if len(consumer) != 1 || consumer[0].JobID != "job-3" {
		t.Errorf("consumer rows = %+v", consumer)
	}
	provider := filterJobParticipants(rows, isRequestedDataProviderPart)
	if len(provider) != 1 || provider[0].JobID != "job-2" || provider[0].ItemID != "ds-1" {
		t.Errorf("provider rows = %+v", provider)
	}
}
