package services

// The contract the TEE orchestrator receives on POST /v1/tee/provision.
//
// This mirrors p3dx-apd's domain.Contract field-for-field (see
// p3dx-apd/internal/domain/models.go), since APD is the caller — its
// TEEService.ProvisionTEE marshals exactly this shape. It is redeclared here
// rather than imported because APD is a separate Go module; the JSON tags are
// the actual contract between the two services, so they must stay in step.
//
// Note this is a THIRD contract shape in the platform, distinct from
// gov_layer's own services.GeneratedContract (technique/datasets/parties) and
// from the older compute_choice/party_N form. Converging them is open work;
// this file deliberately serves only the APD-facing orchestrator API.

import (
	"fmt"
	"net/url"
	"time"
)

// TEEContract is the signed instruction to run a workload in a TEE.
type TEEContract struct {
	ContractID string `json:"contractId"`
	RequestID  string `json:"requestId"`

	ConsumerID string `json:"consumerId"`
	ProviderID string `json:"providerId"`

	AppDetails     TEEAppDetails     `json:"appDetails"`
	DatasetDetails TEEDatasetDetails `json:"datasetDetails"`
	AccessConfig   TEEAccessConfig   `json:"accessConfig"`

	// The TEE encrypts its result to this key.
	ConsumerPublicKey string `json:"consumerPublicKey"`

	// Where the TEE posts its attestation report.
	APDCallbackURL string `json:"apdCallbackUrl"`

	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`

	// APD's ECDSA P-256 signature over the contract with this field cleared.
	Signature string `json:"signature"`
}

type TEEAppDetails struct {
	ImageID     string            `json:"imageId"`
	ImageHash   string            `json:"imageHash"` // expected SEV-SNP measurement
	Version     string            `json:"version"`
	EntryPoint  string            `json:"entryPoint"`
	Environment map[string]string `json:"environment,omitempty"`
}

type TEEDatasetDetails struct {
	ItemID      string `json:"itemId"`
	AssetName   string `json:"assetName"`
	AssetType   string `json:"assetType"`
	ResourceURL string `json:"resourceUrl"`
}

type TEEAccessConfig struct {
	Type string `json:"type"`
}

// ValidateTEEContract checks the contract is structurally usable and currently
// valid.
//
// It deliberately does NOT verify Signature. APD signs with ECDSA P-256 and
// this orchestrator has no configured trust anchor for APD's key yet; the whole
// platform's signing model is still open (p3dx-aaa defers signed submission for
// the same reason). Accepting an unverified signature means a caller who can
// reach this endpoint can run a workload — acceptable only because the
// orchestrator API is internal-network-only, and it is why the API must not be
// exposed publicly before signature verification lands.
func ValidateTEEContract(c *TEEContract, now time.Time) error {
	if c == nil {
		return fmt.Errorf("contract is nil")
	}
	if c.ContractID == "" {
		return fmt.Errorf("contractId is required")
	}
	if c.RequestID == "" {
		return fmt.Errorf("requestId is required")
	}

	// The image measurement is what an attesting TEE would have to match. It is
	// required even though this path does not check it, so a contract that
	// could never be attested is rejected up front rather than silently run.
	if c.AppDetails.ImageID == "" {
		return fmt.Errorf("appDetails.imageId is required")
	}
	if c.AppDetails.ImageHash == "" {
		return fmt.Errorf("appDetails.imageHash is required (expected TEE measurement)")
	}

	if c.DatasetDetails.ItemID == "" {
		return fmt.Errorf("datasetDetails.itemId is required")
	}

	// resourceUrl is relayed to the enclave, which fetches it using the CVM's
	// managed identity. Require https so that identity's bearer token is never
	// put on a plaintext connection, and reject other schemes outright rather
	// than letting the guest resolve something unexpected (file://, or a URL
	// aimed at IMDS itself).
	if c.DatasetDetails.ResourceURL == "" {
		return fmt.Errorf("datasetDetails.resourceUrl is required")
	}
	u, err := url.Parse(c.DatasetDetails.ResourceURL)
	if err != nil {
		return fmt.Errorf("datasetDetails.resourceUrl is not a valid URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("datasetDetails.resourceUrl must be an absolute https URL, got %q",
			c.DatasetDetails.ResourceURL)
	}

	// Lifecycle: a zero ExpiresAt means the caller sent no window at all, which
	// is different from an expired one — report it as such.
	if c.ExpiresAt.IsZero() {
		return fmt.Errorf("expiresAt is required")
	}
	if now.After(c.ExpiresAt) {
		return fmt.Errorf("contract expired at %s", c.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if !c.IssuedAt.IsZero() && now.Before(c.IssuedAt) {
		return fmt.Errorf("contract is not valid until %s", c.IssuedAt.UTC().Format(time.RFC3339))
	}

	return nil
}
