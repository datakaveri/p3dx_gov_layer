package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

func TestPostIUDXPolicies(t *testing.T) {
	var posted []map[string]any
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/apd/v2/policy" {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		posted = append(posted, body)
		auth = append(auth, r.Header.Get("Authorization"))
		req, _ := body["request"].(map[string]any)
		if req["itemId"] == dsMissing {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"type":"urn:dx:as:Forbidden","title":"Forbidden","detail":"not the item owner"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"type":"urn:dx:as:Success","results":[{"id":"pol-1"}]}`))
	}))
	t.Cleanup(srv.Close)

	until := time.Date(2027, 1, 1, 6, 18, 0, 0, time.UTC)
	c := &contract.Contract{ContractID: "contract-1", ContractHash: "sha256:abc", Lifecycle: contract.Lifecycle{ValidUntil: until}, Parties: contract.Parties{
		User: contract.UserParty{ID: "consumer-sub", Name: "Carl"},
		DataProviders: []contract.DataProviderParty{
			{ID: "provider-alice-example-com", DatasetID: dsHeart, DatasetName: "mnist-dataset", DataURL: "https://blob/mnist.tar.enc",
				Trustee: contract.NewTrustee("http://kbs:30081", "mnist-dataset", dsHeart)},
			{ID: "provider-alice-example-com", DatasetID: dsMissing},
		},
		ApplicationProviders: []contract.ApplicationProviderParty{{ContainerImage: "docker.io/x/mnist:1.4"}},
		InfraProviders:       []contract.InfraProviderParty{{ID: "infra-1", ResourceAllocation: contract.ResourceAllocation{CPUCores: 2, RAMMB: 512}}},
	}}
	s := &Server{cfg: &config.Config{IUDXAPDPolicyURL: srv.URL + "/apd/v2/policy", IUDXPolicyCallbackURL: "http://sink/callbacks/"}}
	caller := providerCaller{token: "alice-token"}
	own := []db.AuditEntry{
		{ProviderID: "provider-alice-example-com", Item: dsHeart, Status: db.AuditStatusAccepted},
		{ProviderID: "provider-alice-example-com", Item: dsApp, Status: db.AuditStatusRejected},
		{ProviderID: "provider-alice-example-com", Item: dsMissing, Status: db.AuditStatusAccepted},
	}
	body := approvalBody{ProviderComment: "for MNIST", FeedbackToConsumer: "test only"}

	got := s.postIUDXPolicies(context.Background(), "job-1", c, own, caller, body)
	if len(got) != 2 || len(posted) != 2 {
		t.Fatalf("results = %+v, posted %d, want 2 each (rejected dataset skipped)", got, len(posted))
	}
	if got[0] != (iudxPolicyResult{ItemID: dsHeart, PolicyID: "pol-1", Status: "posted"}) {
		t.Errorf("result 0 = %+v", got[0])
	}
	if got[1].Status != "failed" || !strings.Contains(got[1].Error, "not the item owner") {
		t.Errorf("result 1 = %+v, want failed with IUDX's detail", got[1])
	}
	if auth[0] != "Bearer alice-token" {
		t.Errorf("Authorization = %q, want the caller's token", auth[0])
	}

	raw, _ := json.Marshal(posted[0])
	var p struct {
		Request struct {
			PolicyType, ItemID, ItemType, ExpiryTime, ProviderComment, FeedbackToConsumer string
			Constraints                                                                   struct {
				Subjects struct {
					AllowedUserIds []string
					AllowedRoles   []string
				}
				Access   []struct{ AccessType, Expiry string }
				Workload struct {
					Image     string
					Resources struct{ CPU, Memory string }
					Env       struct {
						DatasetURL string `json:"DATASET_URL"`
					}
				}
				Trustee     struct{ KBSURL, KeyResourcePath string }
				CallbackURL string
			}
			AdditionalInfo struct{ Name, JobID, ContractID, ContractHash string }
		}
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	r := p.Request
	if r.PolicyType != "GROUP" || r.ItemID != dsHeart || r.ItemType != "DATABANK" || r.ExpiryTime != "2027-01-01T06:18:00" {
		t.Errorf("top-level = %+v", r)
	}
	if r.ProviderComment != "for MNIST" || r.FeedbackToConsumer != "test only" {
		t.Errorf("comments = %q / %q", r.ProviderComment, r.FeedbackToConsumer)
	}
	k := r.Constraints
	if len(k.Subjects.AllowedUserIds) != 1 || k.Subjects.AllowedUserIds[0] != "consumer-sub" || k.Subjects.AllowedRoles[0] != "consumer" {
		t.Errorf("subjects = %+v", k.Subjects)
	}
	if len(k.Access) != 3 || k.Access[0].AccessType != "api" || k.Access[2].Expiry != "2027-01-01T06:18:00" {
		t.Errorf("access = %+v", k.Access)
	}
	if k.Workload.Image != "docker.io/x/mnist:1.4" || k.Workload.Resources.CPU != "2000m" || k.Workload.Resources.Memory != "512Mi" || k.Workload.Env.DatasetURL != "https://blob/mnist.tar.enc" {
		t.Errorf("workload = %+v", k.Workload)
	}
	if k.Trustee.KBSURL != "http://kbs:30081" || k.Trustee.KeyResourcePath != "default/mnist-dataset-key/"+dsHeart {
		t.Errorf("trustee = %+v", k.Trustee)
	}
	if k.CallbackURL != "http://sink/callbacks/job-1" {
		t.Errorf("callbackUrl = %q", k.CallbackURL)
	}
	if a := r.AdditionalInfo; a.Name != "mnist-dataset" || a.JobID != "job-1" || a.ContractID != "contract-1" || a.ContractHash != "sha256:abc" {
		t.Errorf("additionalInfo = %+v", a)
	}

	// No IUDX_APD_POLICY_URL: nothing is posted.
	s.cfg.IUDXAPDPolicyURL = ""
	if got := s.postIUDXPolicies(context.Background(), "job-1", c, own, caller, body); len(got) != 0 || len(posted) != 2 {
		t.Errorf("with no URL: results %+v, posted %d", got, len(posted))
	}
}
