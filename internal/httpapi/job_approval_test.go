package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// stubAPD serves the two provider-catalogue endpoints and the infra policy
// lookup the approval checks call.
func stubAPD(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		pid := r.URL.Query().Get("provider_id")
		switch {
		case r.URL.Path == "/api/v1/policy/mine-datasets" && pid == "provider-alice":
			_, _ = w.Write([]byte(`{"status":"success","data":[{"item_id":"ds-1","name":"Heart Data"}]}`))
		case r.URL.Path == "/api/v1/policy/mine" && pid == "provider-ivan":
			_, _ = w.Write([]byte(`{"status":"success","data":[{"item_id":"infra-1","name":"Pune DC"}]}`))
		case r.URL.Path == "/api/v1/policy/mine-datasets" || r.URL.Path == "/api/v1/policy/mine":
			_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
		case r.URL.Path == "/api/v1/policy/by-item/infra-1":
			_, _ = w.Write([]byte(`{"status":"success","data":{"provider_id":"provider-ivan"}}`))
		case r.URL.Path == "/api/v1/policy/by-item/infra-2":
			_, _ = w.Write([]byte(`{"status":"success","data":{"provider_id":"provider-mallory"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("APD_BASE_URL", srv.URL)
}

func TestInfraProviderApprovals(t *testing.T) {
	stubAPD(t)
	s := &Server{}
	c := &contract.Contract{JobID: "job-1", Parties: contract.Parties{
		DataProviders: []contract.DataProviderParty{{ID: "provider-alice", DatasetName: "Heart Data"}},
		InfraProviders: []contract.InfraProviderParty{
			{ID: "infra-1"},                      // ivan's
			{ID: "infra-2"},                      // mallory's
			{Name: "Azure Confidential Compute"}, // placeholder, skipped
		},
	}}
	if !needsJobApproval(c) {
		t.Fatal("contract with datasets + infra should need approval")
	}
	owners := infraOwners(c)
	if len(owners) != 2 || owners[0].providerID != "provider-ivan" || owners[1].providerID != "provider-mallory" {
		t.Fatalf("owners = %+v", owners)
	}

	ivan := callerFromClaims("tok", jwt.MapClaims{"preferred_username": "ivan", "sub": "ivan-sub",
		"realm_access": map[string]any{"roles": []any{"infra-provider"}}})

	// ivan approves his own infra; mallory's is left awaiting her own call.
	entries := s.infraProviderApprovals(c.JobID, owners, ivan, map[string]bool{})
	checkEntries(t, entries, []wantEntry{
		{db.AuditStatusAccepted, true, true},
		{db.AuditStatusRejected, false, false},
	})
	if got := overallStatus(entries); got != db.AuditStatusRejected {
		t.Errorf("overall = %q, want rejected (mallory still awaiting)", got)
	}

	// Once mallory's infra has an entry of her own, ivan's call leaves it alone.
	entries = s.infraProviderApprovals(c.JobID, owners, ivan, map[string]bool{auditKey("provider-mallory", "infra-2"): true})
	checkEntries(t, entries, []wantEntry{{db.AuditStatusAccepted, true, true}})

	// Without the infra-provider role in his token, ivan's infra is rejected.
	noRole := callerFromClaims("tok", jwt.MapClaims{"preferred_username": "ivan"})
	entries = s.infraProviderApprovals(c.JobID, owners[:1], noRole, map[string]bool{})
	checkEntries(t, entries, []wantEntry{{db.AuditStatusRejected, false, true}})

	// mallory owns infra-2, but it isn't in her APD catalogue.
	mallory := callerFromClaims("tok", jwt.MapClaims{"preferred_username": "mallory",
		"realm_access": map[string]any{"roles": []any{"infra-provider"}}})
	entries = s.infraProviderApprovals(c.JobID, owners[1:], mallory, map[string]bool{})
	checkEntries(t, entries, []wantEntry{{db.AuditStatusRejected, true, false}})
}

type wantEntry struct {
	status          string
	role, catalogue bool
}

func checkEntries(t *testing.T, got []db.AuditEntry, wants []wantEntry) {
	t.Helper()
	if len(got) != len(wants) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(wants), got)
	}
	for i, w := range wants {
		g := got[i]
		if g.Status != w.status || g.HasRole != w.role || g.InCatalogue != w.catalogue || g.JobID != "job-1" {
			t.Errorf("entry %d (%s/%s) = %+v, want %+v", i, g.ProviderID, g.Item, g, w)
		}
		if g.Status == db.AuditStatusRejected && g.Reason == "" {
			t.Errorf("entry %d rejected without a reason", i)
		}
	}
}

const (
	dsHeart   = "11111111-1111-4111-8111-111111111111" // alice's DataBank
	dsMissing = "22222222-2222-4222-8222-222222222222" // not in the catalogue
	dsApp     = "33333333-3333-4333-8333-333333333333" // an app, not a dataset
	dsBob     = "44444444-4444-4444-8444-444444444444"
	dsCarol   = "55555555-5555-4555-8555-555555555555"
)

// stubDXCatalogue serves GET /item?id= and only answers callers sending
// alice's token, the way the DX catalogue refuses a bad token.
func stubDXCatalogue(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer tok-alice" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"type":"urn:dx:controlPlane:invalidToken"}`))
			return
		}
		switch id := r.URL.Query().Get("id"); {
		case r.URL.Path == "/item" && id == dsHeart:
			_, _ = w.Write([]byte(`{"type":"urn:dx:controlPlane:success","result":[{"id":"` + dsHeart + `","name":"heart","type":["adex:DataBank"],"uploadedBy":"alice@example.com"}]}`))
		case r.URL.Path == "/item" && id == dsApp:
			_, _ = w.Write([]byte(`{"type":"urn:dx:controlPlane:success","result":[{"id":"` + dsApp + `","name":"app","type":["adex:Apps"]}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"type":"urn:dx:controlPlane:notFound","detail":"doc doesn't exist"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestDataProviderApprovals(t *testing.T) {
	s := &Server{cfg: &config.Config{CatalogueBaseURL: stubDXCatalogue(t), DataProviderRole: "provider"}}
	c := &contract.Contract{JobID: "job-1", Parties: contract.Parties{
		DataProviders: []contract.DataProviderParty{
			{ID: "provider-alice-example-com", DatasetID: dsHeart},   // role + DataBank
			{ID: "provider-alice-example-com", DatasetID: dsMissing}, // not in catalogue
			{ID: "provider-alice-example-com", DatasetID: dsApp},     // not a DataBank
			{ID: "provider-alice-example-com", DatasetName: dsHeart}, // older contract: uuid name
			{ID: "provider-alice-example-com", DatasetName: "Lungs"}, // no catalogue id at all
			{ID: "provider-bob", DatasetID: dsBob},                   // someone else: awaiting
			{ID: "provider-carol", DatasetID: dsCarol},               // someone else, already checked
			{DatasetName: "Orphan"},                                  // no provider at all
		},
	}}
	alice := callerFromClaims("tok-alice", jwt.MapClaims{
		"preferred_username": "alice@example.com",
		"realm_access":       map[string]any{"roles": []any{"offline_access", "provider"}},
	})
	checked := map[string]bool{auditKey("provider-carol", dsCarol): true}

	got := s.dataProviderApprovals(context.Background(), c.JobID, c, alice, checked)
	checkEntries(t, got, []wantEntry{
		{db.AuditStatusAccepted, true, true},
		{db.AuditStatusRejected, true, false},
		{db.AuditStatusRejected, true, false},
		{db.AuditStatusAccepted, true, true},
		{db.AuditStatusRejected, true, false},
		{db.AuditStatusRejected, false, false}, // bob: awaiting
		{db.AuditStatusRejected, false, false}, // orphan
	})
	if got[5].ProviderID != "provider-bob" || got[5].Item != dsBob {
		t.Errorf("awaiting entry = %+v, want provider-bob/%s", got[5], dsBob)
	}

	// Same provider without the role, and with a token the catalogue refuses.
	noRole := callerFromClaims("tok-other", jwt.MapClaims{"email": "Alice@Example.com"})
	got = s.dataProviderApprovals(context.Background(), c.JobID, &contract.Contract{Parties: contract.Parties{
		DataProviders: c.Parties.DataProviders[:1],
	}}, noRole, nil)
	if len(got) != 1 || got[0].HasRole || got[0].InCatalogue || got[0].Status != db.AuditStatusRejected {
		t.Fatalf("no-role caller = %+v, want rejected without role or catalogue", got)
	}
}

func TestDataProviderCallerMatchesParty(t *testing.T) {
	caller := callerFromClaims("t", jwt.MapClaims{"preferred_username": "8adf42ccc9@emailnox.live", "sub": "ABC-123"})
	for _, tc := range []struct {
		party contract.DataProviderParty
		want  bool
	}{
		{contract.DataProviderParty{ID: "provider-8adf42ccc9-emailnox-live"}, true},
		{contract.DataProviderParty{ID: "abc-123", Name: "someone"}, true}, // FL: keycloak id as party id
		{contract.DataProviderParty{ID: "kc-id", Name: "8adf42ccc9@emailnox.live"}, true},
		{contract.DataProviderParty{ID: "provider-bob"}, false},
		{contract.DataProviderParty{}, false},
	} {
		if got := caller.is(tc.party); got != tc.want {
			t.Errorf("is(%+v) = %v, want %v", tc.party, got, tc.want)
		}
	}
}

func TestNeedsJobApproval(t *testing.T) {
	dataOnly := &contract.Contract{Parties: contract.Parties{
		DataProviders:  []contract.DataProviderParty{{ID: "provider-a"}},
		InfraProviders: []contract.InfraProviderParty{{Name: "placeholder"}},
	}}
	if needsJobApproval(dataOnly) {
		t.Error("placeholder infra (no id) should not trigger approval")
	}
	infraOnly := &contract.Contract{Parties: contract.Parties{
		InfraProviders: []contract.InfraProviderParty{{ID: "infra-1"}},
	}}
	if needsJobApproval(infraOnly) {
		t.Error("contract with no datasets should not trigger approval")
	}
}

func TestJobAcceptedWithoutInfraApproval(t *testing.T) {
	for _, tc := range []struct {
		data, infra   string
		infraRequired bool
		want          bool
	}{
		{db.AuditStatusAccepted, db.AuditStatusAccepted, true, true},
		{db.AuditStatusAccepted, "pending", true, false},
		{db.AuditStatusAccepted, "pending", false, true},               // REQUIRE_INFRA_APPROVAL=false
		{db.AuditStatusAccepted, db.AuditStatusRejected, false, true},  // infra ignored
		{db.AuditStatusRejected, db.AuditStatusAccepted, false, false}, // data provider still required
		{"pending", "pending", false, false},
	} {
		st := jobApprovalState{DataProvider: tc.data, InfraProvider: tc.infra, infraRequired: tc.infraRequired}
		if got := st.accepted(); got != tc.want {
			t.Errorf("accepted(data=%s infra=%s infraRequired=%v) = %v, want %v", tc.data, tc.infra, tc.infraRequired, got, tc.want)
		}
	}
}

func TestPostConsumerGrants(t *testing.T) {
	var posted []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/policy" {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		posted = append(posted, body)
		if body["itemId"] == dsMissing {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"status":"error","message":"db down"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("APD_BASE_URL", srv.URL)

	until := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &contract.Contract{ContractID: "contract-1", Lifecycle: contract.Lifecycle{ValidUntil: until}, Parties: contract.Parties{
		User: contract.UserParty{ID: "consumer-sub", Name: "Carl"},
		DataProviders: []contract.DataProviderParty{
			{ID: "provider-alice-example-com", DatasetID: dsHeart, DatasetName: "heart"},
			{ID: "provider-alice-example-com", DatasetID: dsMissing},
		},
		InfraProviders: []contract.InfraProviderParty{{ID: "infra-1", Name: "Pune DC"}, {ID: "infra-2"}},
	}}
	s := &Server{}

	// The data provider's approval posts grants for their own accepted
	// datasets only — nothing for infras, nothing for a rejected dataset.
	dataOwn := []db.AuditEntry{
		{ProviderID: "provider-alice-example-com", Item: dsHeart, Status: db.AuditStatusAccepted},
		{ProviderID: "provider-alice-example-com", Item: dsApp, Status: db.AuditStatusRejected},
		{ProviderID: "provider-alice-example-com", Item: dsMissing, Status: db.AuditStatusAccepted},
	}
	got := s.postConsumerGrants(context.Background(), db.AuditTypeDataProvider, "job-1", c, dataOwn)
	if len(got) != 2 || len(posted) != 2 {
		t.Fatalf("data grants = %+v, posted %d, want 2 each", got, len(posted))
	}
	if got[0] != (grantResult{ItemType: "dataset", ItemID: dsHeart, PolicyID: "grant-job-1-" + dsHeart, Status: "posted"}) {
		t.Errorf("data grant 0 = %+v", got[0])
	}
	if got[1].Status != "failed" || !strings.Contains(got[1].Error, "db down") {
		t.Errorf("data grant 1 = %+v, want failed with APD's message", got[1])
	}

	// The infra provider's approval posts grants for their own infras only.
	infraOwn := []db.AuditEntry{
		{ProviderID: "provider-ivan", Item: "infra-1", Status: db.AuditStatusAccepted},
		{ProviderID: "provider-ivan", Item: "infra-2", Status: db.AuditStatusRejected},
	}
	got = s.postConsumerGrants(context.Background(), db.AuditTypeInfraProvider, "job-1", c, infraOwn)
	if len(got) != 1 || len(posted) != 3 {
		t.Fatalf("infra grants = %+v, posted %d total, want 1 more", got, len(posted))
	}
	if got[0] != (grantResult{ItemType: "infra", ItemID: "infra-1", PolicyID: "grant-job-1-infra-1", Status: "posted"}) {
		t.Errorf("infra grant = %+v", got[0])
	}

	check := func(b map[string]any, top, rules map[string]any) {
		t.Helper()
		r, _ := b["rules"].(map[string]any)
		for k, want := range top {
			if b[k] != want {
				t.Errorf("%v: body[%s] = %v, want %v", b["policyId"], k, b[k], want)
			}
		}
		for k, want := range rules {
			if r[k] != want {
				t.Errorf("%v: rules[%s] = %v, want %v", b["policyId"], k, r[k], want)
			}
		}
	}
	check(posted[0],
		map[string]any{"itemId": dsHeart, "provider_id": "provider-alice-example-com", "dataset_id": dsHeart, "expiresAt": "2027-01-01T00:00:00Z"},
		map[string]any{"policy_type": "consumer-grant", "item_type": "dataset", "job_id": "job-1", "contract_id": "contract-1", "consumer": "consumer-sub", "data_provider": "provider-alice-example-com", "dataset_name": "heart"})
	check(posted[2],
		map[string]any{"itemId": "infra-1", "provider_id": "provider-ivan", "dataset_id": nil},
		map[string]any{"policy_type": "consumer-grant", "item_type": "infra", "job_id": "job-1", "contract_id": "contract-1", "consumer": "consumer-sub", "infra_provider": "provider-ivan", "infra_id": "infra-1", "infra_name": "Pune DC"})
}
