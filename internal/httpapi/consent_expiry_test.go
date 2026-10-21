package httpapi

import (
	"strings"
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
)

func TestParseConsentExpiry(t *testing.T) {
	d, err := parseConsentExpiry("2026-11-30")
	if err != nil || d.Format(time.RFC3339) != "2026-11-30T23:59:59Z" {
		t.Errorf("date: got %v, %v; want end of 2026-11-30 UTC", d, err)
	}
	r, err := parseConsentExpiry("2026-11-30T10:00:00+05:30")
	if err != nil || r.Format(time.RFC3339) != "2026-11-30T04:30:00Z" {
		t.Errorf("rfc3339: got %v, %v", r, err)
	}
	if _, err := parseConsentExpiry("30/11/2026"); err == nil {
		t.Error("bad format accepted")
	}
}

func TestConsentExpiryError(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	c := &contract.Contract{Parties: contract.Parties{DataProviders: []contract.DataProviderParty{
		{ID: "provider-alice", Name: "alice", DatasetName: "a"},
		{ID: "provider-bob", Name: "bob", DatasetName: "b", Constraints: contract.Constraints{ConsentValidUntil: &future}},
	}}}
	if err := consentExpiryError(c, now); err != nil {
		t.Errorf("unexpired: %v", err)
	}
	c.Parties.DataProviders[0].Constraints.ConsentValidUntil = &past
	err := consentExpiryError(c, now)
	if err == nil || !strings.Contains(teeErrorMessage(err), "consent from alice") {
		t.Errorf("expired: got %v", err)
	}
}

// Setting a consent expiry changes the contract hash (it is part of what
// providers sign); leaving it unset keeps older contracts' hashes stable.
func TestConsentExpiryCoveredByHash(t *testing.T) {
	c := contract.Contract{ContractID: "c-1", Technique: "TEE", Parties: contract.Parties{
		DataProviders: []contract.DataProviderParty{{ID: "provider-alice"}}}}
	before, _ := contract.ComputeHash(c)
	raw, _ := contract.ComputeHash(c)
	if before != raw {
		t.Fatal("hash not deterministic")
	}
	u := time.Date(2026, 11, 30, 23, 59, 59, 0, time.UTC)
	c.Parties.DataProviders[0].Constraints.ConsentValidUntil = &u
	after, _ := contract.ComputeHash(c)
	if after == before {
		t.Error("consent expiry not covered by the contract hash")
	}
}

func TestEarliestConsentExpiry(t *testing.T) {
	end := time.Date(2027, 1, 14, 10, 0, 0, 0, time.UTC)
	a := time.Date(2026, 12, 1, 9, 30, 0, 0, time.UTC)
	b := time.Date(2026, 11, 20, 18, 0, 0, 0, time.UTC)
	c := &contract.Contract{Parties: contract.Parties{DataProviders: []contract.DataProviderParty{{}, {}}}}
	if got := earliestConsentExpiry(c, end); !got.Equal(end) {
		t.Errorf("none set: got %v, want contract end", got)
	}
	c.Parties.DataProviders[0].Constraints.ConsentValidUntil = &a
	if got := earliestConsentExpiry(c, end); !got.Equal(a) {
		t.Errorf("one set: got %v, want %v", got, a)
	}
	c.Parties.DataProviders[1].Constraints.ConsentValidUntil = &b
	if got := earliestConsentExpiry(c, end); !got.Equal(b) {
		t.Errorf("two set: got %v, want earliest %v", got, b)
	}
}
