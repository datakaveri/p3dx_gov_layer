package jobapproval

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/apd"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/catalogue"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

const (
	dsHeart   = "11111111-1111-4111-8111-111111111111" // alice's DataBank
	dsMissing = "22222222-2222-4222-8222-222222222222" // not in the catalogue
	dsApp     = "33333333-3333-4333-8333-333333333333" // an app, not a dataset
	dsBob     = "44444444-4444-4444-8444-444444444444"
	dsCarol   = "55555555-5555-4555-8555-555555555555"
)

// fakeRepo is an in-memory Repo.
type fakeRepo struct {
	contracts map[string]*contract.Contract // by job id
	audit     []postgres.AuditEntry
	updated   []*contract.Contract // every contract stored
	marked    []string             // "role provider item status"
	final     map[string]bool
	err       error // returned by every call when set
}

func newFakeRepo(jobID string, c *contract.Contract) *fakeRepo {
	return &fakeRepo{contracts: map[string]*contract.Contract{jobID: c}, final: map[string]bool{}}
}

func (r *fakeRepo) ListAuditByJob(_ context.Context, jobID string) ([]postgres.AuditEntry, error) {
	var out []postgres.AuditEntry
	for _, e := range r.audit {
		if e.JobID == jobID {
			out = append(out, e)
		}
	}
	return out, r.err
}

func (r *fakeRepo) InsertAuditEntries(_ context.Context, entries []postgres.AuditEntry) error {
	r.audit = append(r.audit, entries...)
	return r.err
}

func (r *fakeRepo) GetContractByJobID(_ context.Context, jobID string) (json.RawMessage, error) {
	c, ok := r.contracts[jobID]
	if !ok || r.err != nil {
		return nil, r.err
	}
	return json.Marshal(c)
}

func (r *fakeRepo) GetJobIDByContractID(_ context.Context, contractID string) (string, error) {
	for jobID, c := range r.contracts {
		if c.ContractID == contractID {
			return jobID, r.err
		}
	}
	return "", r.err
}

func (r *fakeRepo) UpdateContractByContractID(_ context.Context, _ string, raw json.RawMessage) (bool, error) {
	var c contract.Contract
	if err := json.Unmarshal(raw, &c); err != nil {
		return false, err
	}
	r.updated = append(r.updated, &c)
	return true, r.err
}

func (r *fakeRepo) MarkSignRequestsSent(context.Context, string) (bool, error) { return true, r.err }

func (r *fakeRepo) CreateFinalContract(_ context.Context, jobID, _, _ string, _ []byte) (bool, error) {
	created := !r.final[jobID]
	r.final[jobID] = true
	return created, r.err
}

func (r *fakeRepo) MarkJobFinal(context.Context, string) (bool, error) { return true, r.err }

func (r *fakeRepo) GetFinalContract(_ context.Context, jobID string) (*postgres.FinalContract, error) {
	return &postgres.FinalContract{JobID: jobID}, r.err
}

func (r *fakeRepo) SetJobParticipantStatus(_ context.Context, _, role, participantID, itemID, status, _, _ string) (bool, error) {
	r.marked = append(r.marked, role+" "+participantID+" "+itemID+" "+status)
	return true, r.err
}

func (r *fakeRepo) SetJobStatus(context.Context, string, string) error { return r.err }

// fakeCatalogue answers DX lookups only for alice's token, the way the DX
// catalogue refuses a bad token.
type fakeCatalogue struct {
	infra map[string][]catalogue.APDCatalogueItem // provider id -> their APD infras
}

func (fakeCatalogue) Item(_ context.Context, itemID, token string) (catalogue.DXCatalogueItem, error) {
	if token != "tok-alice" {
		return catalogue.DXCatalogueItem{}, catalogue.ErrCatalogueTokenRefused
	}
	switch itemID {
	case dsHeart:
		return catalogue.DXCatalogueItem{ID: dsHeart, Type: []string{catalogue.DataBankType}}, nil
	case dsApp:
		return catalogue.DXCatalogueItem{ID: dsApp, Type: []string{"adex:Apps"}}, nil
	}
	return catalogue.DXCatalogueItem{}, catalogue.ErrCatalogueItemNotFound
}

func (f fakeCatalogue) ProviderInfra(providerID string) ([]catalogue.APDCatalogueItem, error) {
	return f.infra[providerID], nil
}

// fakeAPD resolves infra owners from a map and records the grants posted.
type fakeAPD struct {
	owners map[string]string // infra id -> provider id
	posted []apd.ConsumerGrant
	fail   map[string]bool // item ids whose grant post fails
}

func (a *fakeAPD) InfraPolicy(infraID string) (map[string]any, error) {
	if p, ok := a.owners[infraID]; ok {
		return map[string]any{"provider_id": p}, nil
	}
	return nil, errors.New("no policy")
}

func (a *fakeAPD) PostConsumerGrant(_ context.Context, g apd.ConsumerGrant) (string, error) {
	a.posted = append(a.posted, g)
	if a.fail[g.ItemID] {
		return "", errors.New("db down")
	}
	return "grant-" + g.JobID + "-" + g.ItemID, nil
}

type fakeKeys map[string]string

func (k fakeKeys) PublicKey(_ context.Context, username string) (string, error) {
	if pub, ok := k[username]; ok {
		return pub, nil
	}
	return "", errors.New("not registered")
}

// fakeSignatures reports every signature valid unless invalid is set.
type fakeSignatures struct{ invalid []PartySignature }

func (fakeSignatures) AmendmentValid(*contract.Contract, string) bool { return false }

func (f fakeSignatures) ProviderSignatures(context.Context, *contract.Contract, string, map[string]string) ([]PartySignature, bool) {
	return f.invalid, len(f.invalid) == 0
}

func (f fakeSignatures) VerifyContract(context.Context, *contract.Contract) ([]PartySignature, bool, bool) {
	return f.invalid, true, len(f.invalid) == 0
}

func (fakeSignatures) GovernanceSignatureOK(*contract.Contract, string) bool { return true }

func newRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func signWith(t *testing.T, priv *rsa.PrivateKey, hash string) string {
	t.Helper()
	d := sha256.Sum256([]byte(hash))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

type wantEntry struct {
	status          string
	role, catalogue bool
}

func checkEntries(t *testing.T, got []postgres.AuditEntry, wants []wantEntry) {
	t.Helper()
	if len(got) != len(wants) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(wants), got)
	}
	for i, w := range wants {
		g := got[i]
		if g.Status != w.status || g.HasRole != w.role || g.InCatalogue != w.catalogue || g.JobID != "job-1" {
			t.Errorf("entry %d (%s/%s) = %+v, want %+v", i, g.ProviderID, g.Item, g, w)
		}
		if g.Status == postgres.AuditStatusRejected && g.Reason == "" {
			t.Errorf("entry %d rejected without a reason", i)
		}
	}
}
