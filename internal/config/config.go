// Package config loads all runtime configuration for the Governance Layer from
// environment variables (and the service's own .env, loaded with override
// semantics — see LoadEnv). Every value mirrors a constant from the original
// Node implementation (src/server.js + src/routes/governance.routes.js +
// src/services/keycloak.service.js) so behaviour is identical.
package config

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config holds every tunable used by the service. Field comments name the
// environment variable each value comes from and its default.
type Config struct {
	// --- server ---
	RESTPort string // PORT (default 8083)
	NodeEnv  string // NODE_ENV (default "development")
	CORSRaw  string // CORS_ORIGINS (raw, for the startup log line)

	// --- database ---
	DBHost     string // DB_HOST (default localhost)
	DBPort     string // DB_PORT (default 5432)
	DBName     string // DB_NAME (default p3dx_governance)
	DBUser     string // DB_USER (default postgres)
	DBPassword string // DB_PASSWORD (default postgres)

	// --- keycloak service-account auth ---
	KeycloakTokenURL string
	KeycloakClientID string
	KeycloakSecret   string
	KeycloakTimeout  time.Duration // KEYCLOAK_TOKEN_TIMEOUT_MS (default 8000)
	PushAuthToken    string        // PUSH_AUTH_TOKEN (legacy X-Auth-Token fallback)

	// --- distribute-config (shell-out) ---
	DistributeScript string // DISTRIBUTE_SCRIPT

	// --- provider env provisioning ---
	ProviderProvisionPath string        // PROVIDER_PROVISION_PATH (default /provision-env)
	ProvisionTimeout      time.Duration // PROVISION_TIMEOUT_MS (default 600000)
	ProvisionEnvPath      string        // PROVISION_ENV_PATH (default "")
	ProvisionRequirements string        // PROVISION_REQUIREMENTS (client requirements.txt)

	// --- client config template + HTTP push ---
	ClientConfigTemplate string        // CLIENT_CONFIG_TEMPLATE
	ProviderReceiverPath string        // PROVIDER_RECEIVER_PATH (default /update-config)
	PushTimeout          time.Duration // PUSH_TIMEOUT_MS (default 15000)

	// --- start-fl-session ---
	FedmlSrc                      string        // FEDML_SRC
	FedmlVenvPy                   string        // FEDML_VENV_PY
	OwnerReceiverProvisionPath    string        // OWNER_RECEIVER_PROVISION_PATH (default /provision-env)
	OwnerReceiverStartServerPath  string        // OWNER_RECEIVER_START_SERVER_PATH (default /start-server)
	OwnerReceiverStartSessionPath string        // OWNER_RECEIVER_START_SESSION_PATH (default /start-session)
	OwnerEnvReceiverFallback      string        // derived from OWNER_ENV_RECEIVER_URL (default http://localhost:8090)
	OwnerRequirements             string        // OWNER_REQUIREMENTS (server requirements.txt)
	FLSessionConfig               string        // FL_SESSION_CONFIG
	FLServerEndpoint              string        // FL_SERVER_ENDPOINT (default localhost:12345)
	CheckpointDir                 string        // CHECKPOINT_DIR (default FEDML_SRC/checkpoint) — where flo_server writes per-round global models
	FLLogDir                      string        // FL_LOG_DIR
	ProviderStartClientPath       string        // PROVIDER_START_CLIENT_PATH (default /start-client)
	FLClientDelay                 time.Duration // FL_CLIENT_DELAY_MS (default 5000)
	FLSessionDelay                time.Duration // FL_SESSION_DELAY_MS (default 30000)

	// --- self-IP detection ---
	OwnerSelfIPs string // OWNER_SELF_IPS (CSV)

	// --- forms ingest (aaa pushes form data here; see httpapi/forms_ingest.go) ---
	FormsPushToken string // FORMS_PUSH_TOKEN — shared secret aaa sends on pushes; empty disables the check

	// --- participant-VM IP registry (httpapi/vm_registry.go) ---
	VMRegistryToken string // VM_REGISTRY_TOKEN — shared secret terraform/participant-vm sends on vm-registry calls; empty disables the check

	// --- provider public keys (httpapi/provider_keys.go) ---
	ProviderKeyJWKSURL string // PROVIDER_KEY_JWKS_URL — JWKS of the Keycloak providers log in through; validates the token p3dx-aaa forwards on /provider-keys

	// --- TEE orchestrator (httpapi/tee_orchestrator.go) ---
	// The confidential VM is pre-provisioned; the orchestrator starts and stops
	// it rather than creating it. TEEEnclaveBaseURL overrides the URL built from
	// TEEVMIP + TEEEnclavePort, for when the manager sits behind a proxy.
	TEEAzureRG        string        // TEE_AZURE_RG
	TEEVMName         string        // TEE_VM_NAME
	TEEVMIP           string        // TEE_VM_IP
	TEEEnclavePort    string        // TEE_ENCLAVE_PORT (default 4000)
	TEEEnclaveBaseURL string        // TEE_ENCLAVE_BASE_URL (overrides IP+port)
	TEEStartTimeout   time.Duration // TEE_START_TIMEOUT_MS (default 300000) — cold CVM boot is slow
	TEEPollInterval   time.Duration // TEE_POLL_INTERVAL_MS (default 5000)
	TEEOutputTimeout  time.Duration // TEE_OUTPUT_TIMEOUT_MS (default 60000) — output may be large

	// --- Run TEE (httpapi/job_tee.go runTEEJob) ---
	// Runs `grpcurl -plaintext -d <sub-contract> COORDINATOR_ADDR
	// kata.coordinator.v1.CoordinatorService/CreateJob`.
	GrpcurlBin      string // GRPCURL_BIN (default "grpcurl")
	CoordinatorAddr string // COORDINATOR_ADDR (host:port; empty = Run TEE disabled)

	// --- TEE attestation (services/attestation.go) ---
	// TEEAttestationRequired defaults to TRUE: a run is refused unless the TEE
	// has produced a verified attestation. Set TEE_ATTESTATION_REQUIRED=false
	// only for local development — it turns the TEE into an ordinary VM as far
	// as any trust claim goes.
	TEEAttestationRequired bool          // TEE_ATTESTATION_REQUIRED (default true)
	TEEMAAIssuers          []string      // TEE_MAA_ISSUERS (CSV) — trusted attestation endpoints
	TEEExpectedMeasurement string        // TEE_EXPECTED_LAUNCH_MEASUREMENT (hex SHA-384; empty = unpinned)
	TEEAttestationTTL      time.Duration // TEE_ATTESTATION_TTL_MS (default 900000) — how long a verdict authorises runs
	TEEAttestTimeout       time.Duration // TEE_ATTEST_TIMEOUT_MS (default 180000) — attestation is slow
	TEEClockLeeway         time.Duration // TEE_CLOCK_LEEWAY_MS (default 60000)

	// RequireSignedContract defaults to TRUE: no FL session, TEE or SMPC run
	// starts unless every data provider has signed its contract's hash, each
	// signature verified against that provider's Keycloak public key
	// (contract_signing.go). The older TEE_REQUIRE_SIGNED_CONTRACT name is
	// still read when REQUIRE_SIGNED_CONTRACT is unset.
	RequireSignedContract bool // REQUIRE_SIGNED_CONTRACT (default true)

	// GovSigningKeyPath is where gov_layer's own contract-signing RSA key pair
	// lives (PKCS#8 PEM). Generated on first start if missing.
	GovSigningKeyPath string // GOV_SIGNING_KEY_PATH (default keys/governance_signing_key.pem)

	// --- Flotilla join gateway (httpapi/gateway_certs.go) ---
	// The governance key above doubles as a CA: its self-signed certificate
	// lives at GovCACertPath (generated on first start, or regenerated when it
	// no longer matches the key) and signs each FL session gateway's TLS
	// certificate. Only the FL orchestrator's service account (client
	// OrchestratorClientID holding realm role OrchestratorRole) may request
	// one. Tokens minted for the Flotilla VMs (azp FlotillaVMClientID) are
	// refused by every provider-token endpoint.
	GovCACertPath        string // GOV_CA_CERT_PATH (default ./keys/governance_ca.pem)
	OrchestratorClientID string // ORCHESTRATOR_CLIENT_ID (default p3dx-fl-orchestrator)
	OrchestratorRole     string // ORCHESTRATOR_ROLE (default fl-orchestrator)
	FlotillaVMClientID   string // FLOTILLA_VM_CLIENT_ID (default flotilla-vm)

	// FLContractValidity is how long an FL roster contract is valid from the
	// moment it is built (Lifecycle.ValidUntil); gateway certificates expire
	// with it.
	FLContractValidity time.Duration // FL_CONTRACT_VALIDITY (Go duration, default 2160h = 90 days)

	// --- user directory (the platform's own Keycloak, where p3dx-aaa keeps
	// users and each data provider's "public_key" attribute). Distinct from
	// the KEYCLOAK_* service account above, which targets the FL receivers'
	// Keycloak. Admin credentials mirror p3dx-aaa's KEYCLOAK_ADMIN_*.
	UserKeycloakBaseURL       string // USER_KEYCLOAK_BASE_URL (default http://localhost:8080)
	UserKeycloakRealm         string // USER_KEYCLOAK_REALM (default "master")
	UserKeycloakAdminUser     string // USER_KEYCLOAK_ADMIN_USER
	UserKeycloakAdminPassword string // USER_KEYCLOAK_ADMIN_PASSWORD
	// Service-account alternative to the admin user (client_credentials
	// grant), used instead of it when both are set — e.g. against the dev
	// Keycloak. The client's service account needs realm-management's
	// view-users role.
	UserKeycloakClientID     string // USER_KEYCLOAK_CLIENT_ID
	UserKeycloakClientSecret string // USER_KEYCLOAK_CLIENT_SECRET
	// Realm role the job-approval data-provider check looks for. The dev
	// Keycloak calls it "provider".
	DataProviderRole string // DATA_PROVIDER_ROLE (default "data-provider")

	// --- DX catalogue (job-approval data-provider check, job_approval.go) ---
	// POST /job/approval/data-provider carries the data provider's own dev
	// Keycloak token; it is validated against DataProviderJWKSURL and then
	// used to look each of their datasets up in the DX catalogue.
	CatalogueBaseURL    string        // CATALOGUE_BASE_URL (default https://v2.dev.iudx.io/controlplane/iudx/v2/cat)
	CatalogueTimeout    time.Duration // CATALOGUE_TIMEOUT_MS (default 10000)
	DataProviderJWKSURL string        // DATA_PROVIDER_JWKS_URL (default: USER_KEYCLOAK_BASE_URL/REALM's certs)

	// RequireInfraApproval: a job is approved only once both its data-provider
	// and infra-provider approvals are accepted. Set REQUIRE_INFRA_APPROVAL=false
	// to approve on the data-provider side alone (temporary, while infra
	// providers aren't set up in dev).
	RequireInfraApproval bool // REQUIRE_INFRA_APPROVAL (default true)

	// KBSURL is the Key Broker Service each data provider's contract
	// "trustee" block points at (contract.NewTrustee). Blank omits the block.
	KBSURL string // KBS_URL

	// DefaultResultURL is where the TEE workload writes its result — the
	// default for every generated contract's parties.user.datablob_url
	// (relayed to the workload as RESULT_URL). Blank leaves it empty.
	DefaultResultURL string // DEFAULT_RESULT_URL

	// ResultReadURL is a read-capable URL (e.g. an Azure SAS with sp=r) for
	// the same result blob — DEFAULT_RESULT_URL's SAS is write-only — fetched
	// server-side by GET /v1/tee/jobs/{jobId}/result. Blank disables it.
	ResultReadURL string // RESULT_READ_URL

	// ContractCallbackURL is the base of a TEE contract's callbackUrl;
	// "/<contract_id>" is appended. Blank leaves callbackUrl out.
	ContractCallbackURL string // CONTRACT_CALLBACK_URL

	// --- IUDX APD policy, posted per accepted dataset at
	// POST /job/approval/data-provider with the data provider's own token.
	// Blank IUDXAPDPolicyURL skips it.
	IUDXAPDPolicyURL      string // IUDX_APD_POLICY_URL
	IUDXPolicyCallbackURL string // IUDX_POLICY_CALLBACK_URL; "/<job_id>" is appended

	// --- ad-hoc VM provisioning (httpapi/vm_provision.go) ---
	// Unlike the TEE flow above, this creates a brand-new VM per request
	// rather than starting a pre-provisioned one.
	VMAzureRG       string        // VM_AZURE_RG — resource group new VMs are created into
	VMAzureLocation string        // VM_AZURE_LOCATION (default "eastus")
	VMImage         string        // VM_IMAGE (default "Ubuntu2204")
	VMSize          string        // VM_SIZE (default "Standard_B2s")
	VMAdminUser     string        // VM_ADMIN_USER (default "azureuser")
	VMCreateTimeout time.Duration // VM_CREATE_TIMEOUT_MS (default 300000)
}

// LoadEnv loads the service's own .env with OVERRIDE semantics, matching the
// Node load-env.js (dotenv.config({ override: true })). godotenv.Overload
// overwrites any variables already present in the shell so this service's .env
// always wins — without it, generic vars like DB_USER/DB_PASSWORD exported for a
// sibling service would hijack this service's database connection. A missing
// .env is non-fatal (env may be set entirely by the launcher).
func LoadEnv() {
	_ = godotenv.Overload(".env")
}

// Load reads the configuration from the environment. Paths default relative to
// the repository root (the parent of the working directory, which is
// p3dx_gov_layer/ when launched by start.sh), reproducing the Node defaults that
// were resolved relative to src/routes (../../../X == repoRoot/X).
func Load() *Config {
	repoRoot := repoRoot()

	c := &Config{
		RESTPort: getEnv("PORT", "8083"),
		NodeEnv:  os.Getenv("NODE_ENV"),
		CORSRaw:  os.Getenv("CORS_ORIGINS"),

		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBName:     getEnv("DB_NAME", "p3dx_governance"),
		DBUser:     getEnv("DB_USER", "postgres"),
		DBPassword: getEnv("DB_PASSWORD", "postgres"),

		KeycloakTokenURL: keycloakTokenURL(),
		KeycloakClientID: os.Getenv("KEYCLOAK_CLIENT_ID"),
		KeycloakSecret:   os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		KeycloakTimeout:  getEnvMS("KEYCLOAK_TOKEN_TIMEOUT_MS", 8000),
		PushAuthToken:    os.Getenv("PUSH_AUTH_TOKEN"),

		DistributeScript: getEnv("DISTRIBUTE_SCRIPT", filepath.Join(repoRoot, "send_output_owner_config.sh")),

		ProviderProvisionPath: getEnv("PROVIDER_PROVISION_PATH", "/provision-env"),
		ProvisionTimeout:      getEnvMS("PROVISION_TIMEOUT_MS", 600000),
		ProvisionEnvPath:      os.Getenv("PROVISION_ENV_PATH"),
		ProvisionRequirements: getEnv("PROVISION_REQUIREMENTS", filepath.Join(repoRoot, "fedml-ng-release-v1.0/src/client/requirements.txt")),

		ClientConfigTemplate: getEnv("CLIENT_CONFIG_TEMPLATE", filepath.Join(repoRoot, "fedml-ng-release-v1.0/src/config/client_config.yaml")),
		ProviderReceiverPath: getEnv("PROVIDER_RECEIVER_PATH", "/update-config"),
		PushTimeout:          getEnvMS("PUSH_TIMEOUT_MS", 15000),

		FedmlSrc:                      getEnv("FEDML_SRC", filepath.Join(repoRoot, "fedml-ng-release-v1.0/src")),
		FedmlVenvPy:                   getEnv("FEDML_VENV_PY", filepath.Join(repoRoot, "venv/bin/python")),
		OwnerReceiverProvisionPath:    getEnv("OWNER_RECEIVER_PROVISION_PATH", "/provision-env"),
		OwnerReceiverStartServerPath:  getEnv("OWNER_RECEIVER_START_SERVER_PATH", "/start-server"),
		OwnerReceiverStartSessionPath: getEnv("OWNER_RECEIVER_START_SESSION_PATH", "/start-session"),
		OwnerEnvReceiverFallback:      ownerEnvReceiverFallback(),
		OwnerRequirements:             getEnv("OWNER_REQUIREMENTS", filepath.Join(repoRoot, "fedml-ng-release-v1.0/src/server/requirements.txt")),
		FLSessionConfig:               getEnv("FL_SESSION_CONFIG", "../config/flotilla_quicksetup_config.yaml"),
		FLServerEndpoint:              getEnv("FL_SERVER_ENDPOINT", "localhost:12345"),
		CheckpointDir:                 getEnv("CHECKPOINT_DIR", filepath.Join(repoRoot, "fedml-ng-release-v1.0/src/checkpoint")),
		FLLogDir:                      getEnv("FL_LOG_DIR", filepath.Join(repoRoot, "logs")),
		ProviderStartClientPath:       getEnv("PROVIDER_START_CLIENT_PATH", "/start-client"),
		FLClientDelay:                 getEnvMS("FL_CLIENT_DELAY_MS", 5000),
		FLSessionDelay:                getEnvMS("FL_SESSION_DELAY_MS", 30000),

		OwnerSelfIPs: os.Getenv("OWNER_SELF_IPS"),

		FormsPushToken: os.Getenv("FORMS_PUSH_TOKEN"),

		VMRegistryToken: os.Getenv("VM_REGISTRY_TOKEN"),

		ProviderKeyJWKSURL: getEnv("PROVIDER_KEY_JWKS_URL", "http://localhost:8080/realms/master/protocol/openid-connect/certs"),

		TEEAzureRG:        os.Getenv("TEE_AZURE_RG"),
		TEEVMName:         os.Getenv("TEE_VM_NAME"),
		TEEVMIP:           os.Getenv("TEE_VM_IP"),
		TEEEnclavePort:    getEnv("TEE_ENCLAVE_PORT", "4000"),
		TEEEnclaveBaseURL: os.Getenv("TEE_ENCLAVE_BASE_URL"),
		TEEStartTimeout:   getEnvMS("TEE_START_TIMEOUT_MS", 300000),
		TEEPollInterval:   getEnvMS("TEE_POLL_INTERVAL_MS", 5000),
		TEEOutputTimeout:  getEnvMS("TEE_OUTPUT_TIMEOUT_MS", 60000),

		GrpcurlBin:      getEnv("GRPCURL_BIN", "grpcurl"),
		CoordinatorAddr: os.Getenv("COORDINATOR_ADDR"),

		TEEAttestationRequired: getEnvBool("TEE_ATTESTATION_REQUIRED", true),
		TEEMAAIssuers:          getEnvCSV("TEE_MAA_ISSUERS"),
		TEEExpectedMeasurement: os.Getenv("TEE_EXPECTED_LAUNCH_MEASUREMENT"),
		TEEAttestationTTL:      getEnvMS("TEE_ATTESTATION_TTL_MS", 900000),
		TEEAttestTimeout:       getEnvMS("TEE_ATTEST_TIMEOUT_MS", 180000),
		TEEClockLeeway:         getEnvMS("TEE_CLOCK_LEEWAY_MS", 60000),

		RequireSignedContract: getEnvBool("REQUIRE_SIGNED_CONTRACT", getEnvBool("TEE_REQUIRE_SIGNED_CONTRACT", true)),
		GovSigningKeyPath:     getEnv("GOV_SIGNING_KEY_PATH", "keys/governance_signing_key.pem"),

		GovCACertPath:        getEnv("GOV_CA_CERT_PATH", "./keys/governance_ca.pem"),
		OrchestratorClientID: getEnv("ORCHESTRATOR_CLIENT_ID", "p3dx-fl-orchestrator"),
		OrchestratorRole:     getEnv("ORCHESTRATOR_ROLE", "fl-orchestrator"),
		FlotillaVMClientID:   getEnv("FLOTILLA_VM_CLIENT_ID", "flotilla-vm"),
		FLContractValidity:   getEnvDuration("FL_CONTRACT_VALIDITY", DefaultFLContractValidity),

		UserKeycloakBaseURL:       getEnv("USER_KEYCLOAK_BASE_URL", "http://localhost:8080"),
		UserKeycloakRealm:         getEnv("USER_KEYCLOAK_REALM", "master"),
		UserKeycloakAdminUser:     os.Getenv("USER_KEYCLOAK_ADMIN_USER"),
		UserKeycloakAdminPassword: os.Getenv("USER_KEYCLOAK_ADMIN_PASSWORD"),
		UserKeycloakClientID:      os.Getenv("USER_KEYCLOAK_CLIENT_ID"),
		UserKeycloakClientSecret:  os.Getenv("USER_KEYCLOAK_CLIENT_SECRET"),
		DataProviderRole:          getEnv("DATA_PROVIDER_ROLE", "data-provider"),

		CatalogueBaseURL: strings.TrimRight(getEnv("CATALOGUE_BASE_URL", "https://v2.dev.iudx.io/controlplane/iudx/v2/cat"), "/"),
		CatalogueTimeout: getEnvMS("CATALOGUE_TIMEOUT_MS", 10000),

		RequireInfraApproval: getEnvBool("REQUIRE_INFRA_APPROVAL", true),

		KBSURL: strings.TrimRight(os.Getenv("KBS_URL"), "/"),

		DefaultResultURL: strings.TrimSpace(os.Getenv("DEFAULT_RESULT_URL")),
		ResultReadURL:    strings.TrimSpace(os.Getenv("RESULT_READ_URL")),

		ContractCallbackURL: strings.TrimRight(strings.TrimSpace(os.Getenv("CONTRACT_CALLBACK_URL")), "/"),

		IUDXAPDPolicyURL:      os.Getenv("IUDX_APD_POLICY_URL"),
		IUDXPolicyCallbackURL: os.Getenv("IUDX_POLICY_CALLBACK_URL"),
	}
	c.DataProviderJWKSURL = getEnv("DATA_PROVIDER_JWKS_URL",
		strings.TrimRight(c.UserKeycloakBaseURL, "/")+"/realms/"+c.UserKeycloakRealm+"/protocol/openid-connect/certs")
	return c
}

// getEnvBool reads a boolean env var. Anything unparseable falls back rather
// than silently reading as false — for security switches, a typo must not
// quietly disable the check.
func getEnvBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// DefaultFLContractValidity is FL_CONTRACT_VALIDITY's default: 90 days.
const DefaultFLContractValidity = 90 * 24 * time.Hour

// getEnvDuration reads a Go duration string ("2160h", "30m"). An unparseable
// or non-positive value falls back to the default, with a log line so the
// typo doesn't go unnoticed.
func getEnvDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("[CONFIG] %s=%q is not a positive duration; using default %s", key, v, fallback)
		return fallback
	}
	return d
}

// getEnvCSV splits a comma-separated env var, trimming blanks.
func getEnvCSV(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// KeycloakConfigured mirrors keycloak.service.js keycloakConfigured().
func (c *Config) KeycloakConfigured() bool {
	return c.KeycloakTokenURL != "" && c.KeycloakClientID != "" && c.KeycloakSecret != ""
}

// repoRoot returns the parent of the working directory. start.sh launches the
// service from p3dx_gov_layer/, so the parent is the repository root.
func repoRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ".."
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		abs = cwd
	}
	return filepath.Dir(abs)
}

// keycloakTokenURL reproduces the TOKEN_URL derivation in keycloak.service.js:
// KEYCLOAK_TOKEN_URL wins; otherwise it is built from KEYCLOAK_BASE_URL + realm.
func keycloakTokenURL() string {
	if v := os.Getenv("KEYCLOAK_TOKEN_URL"); v != "" {
		return v
	}
	base := os.Getenv("KEYCLOAK_BASE_URL")
	realm := os.Getenv("KEYCLOAK_REALM")
	if base != "" && realm != "" {
		base = strings.TrimRight(base, "/")
		return base + "/realms/" + realm + "/protocol/openid-connect/token"
	}
	return ""
}

// ownerEnvReceiverFallback reproduces OWNER_ENV_RECEIVER_FALLBACK: take
// OWNER_ENV_RECEIVER_URL (default http://localhost:8090), strip a trailing
// /provision-env and any trailing slash.
func ownerEnvReceiverFallback() string {
	u := os.Getenv("OWNER_ENV_RECEIVER_URL")
	if u == "" {
		u = "http://localhost:8090"
	}
	u = trimProvisionSuffix(u)
	u = strings.TrimRight(u, "/")
	return u
}

func trimProvisionSuffix(u string) string {
	for _, suf := range []string{"/provision-env/", "/provision-env"} {
		if strings.HasSuffix(u, suf) {
			return u[:len(u)-len(suf)]
		}
	}
	return u
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getEnvMS reads an integer count of milliseconds and returns a Duration.
func getEnvMS(key string, fallbackMS int) time.Duration {
	ms := fallbackMS
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			ms = n
		}
	}
	return time.Duration(ms) * time.Millisecond
}
