package apd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// PostConsumerGrant's body: the dataset and infra grant shapes APD stores,
// and APD's message on a failed post.
func TestPostConsumerGrant(t *testing.T) {
	var posted []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/policy" {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		posted = append(posted, body)
		if body["itemId"] == "ds-down" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"status":"error","message":"db down"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("APD_BASE_URL", srv.URL)

	base := ConsumerGrant{JobID: "job-1", ContractID: "contract-1", Consumer: "consumer-sub", ConsumerName: "Carl"}
	dataset := base
	dataset.ItemType, dataset.ItemID, dataset.ItemName, dataset.Provider = GrantItemDataset, "ds-1", "heart", "provider-alice"
	dataset.ExpiresAt = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	infra := base
	infra.ItemType, infra.ItemID, infra.ItemName, infra.Provider = GrantItemInfra, "infra-1", "Pune DC", "provider-ivan"
	down := dataset
	down.ItemID = "ds-down"

	ctx := context.Background()
	if id, err := PostConsumerGrant(ctx, http.DefaultClient, dataset); err != nil || id != "grant-job-1-ds-1" {
		t.Fatalf("dataset grant: %q, %v", id, err)
	}
	if _, err := PostConsumerGrant(ctx, http.DefaultClient, infra); err != nil {
		t.Fatalf("infra grant: %v", err)
	}
	if _, err := PostConsumerGrant(ctx, http.DefaultClient, down); err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("failed grant: err = %v, want APD's message", err)
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
		map[string]any{"itemId": "ds-1", "provider_id": "provider-alice", "dataset_id": "ds-1", "expiresAt": "2027-01-01T00:00:00Z"},
		map[string]any{"policy_type": "consumer-grant", "item_type": "dataset", "job_id": "job-1", "contract_id": "contract-1", "consumer": "consumer-sub", "data_provider": "provider-alice", "dataset_name": "heart"})
	check(posted[1],
		map[string]any{"itemId": "infra-1", "provider_id": "provider-ivan", "dataset_id": nil},
		map[string]any{"policy_type": "consumer-grant", "item_type": "infra", "job_id": "job-1", "contract_id": "contract-1", "consumer": "consumer-sub", "infra_provider": "provider-ivan", "infra_id": "infra-1", "infra_name": "Pune DC"})
}
