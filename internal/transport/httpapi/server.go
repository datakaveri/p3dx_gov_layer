// Package httpapi implements the Governance Layer REST API: the routing
// table, CORS, and every handler, mounted under both /api/v1 and /governance.
//
// Files prefixed fl_ are FL-specific (participation notifications). contracts.go
// handles contract management. general_contract.go handles the general pathway
// (POST /contract — pre-built contracts with policy checks). model.go handles
// final model retrieval. server.go itself is shared infra.
package httpapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/platform/govcrypto"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/keycloak"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/userdir"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// maxBodyBytes mirrors express.json({ limit: "5mb" }).
const maxBodyBytes = 5 * 1024 * 1024

// Server bundles the dependencies shared by every handler.
type Server struct {
	cfg  *config.Config
	db   *postgres.DB
	kc   *keycloak.Client
	http *http.Client
	// tees tracks live TEE instances for the orchestrator API
	// (tee_orchestrator.go).
	tees *teeRegistry
	// teeSessions tracks the provision->attest->run->output sequences started
	// by POST /v1/tee/sessions (tee_session.go).
	teeSessions *teeSessionRegistry
	// publicKeys resolves a provider's registered public key from Postgres
	// (provider_public_keys), to verify contract signatures (contract_signing.go).
	publicKeys publicKeyLookup
	// govKey is gov_layer's own key pair; it signs each contract hash before
	// the hash goes out to data providers (contract_signing.go).
	govKey *govcrypto.GovernanceKey
	// govCA is govKey's self-signed CA certificate (and govCAPEM its PEM);
	// it signs Flotilla gateway TLS certificates (gateway_certs.go).
	govCA    *x509.Certificate
	govCAPEM []byte
	// gatewayStore loads FL contracts and records issued gateway
	// certificates — *postgres.DB in production; stubbed in tests.
	gatewayStore gatewayCertStore
	// flContracts loads a session's contract to gate FL output reads to its
	// output owner (fl_output.go) — *postgres.DB in production; stubbed in tests.
	flContracts flContractStore
	// users looks up users and their realm roles in the platform Keycloak
	// (USER_KEYCLOAK_*), for the FL session routes (fl_session.go).
	users *userdir.Client
	// vmCreds / vmKC back the FL client-VM credentials (fl_vm_credentials.go):
	// *postgres.DB and users in production; stubbed in tests. vmRate limits
	// POST /p3dx/fl/vm-token per credential.
	vmCreds vmCredentialStore
	vmKC    vmKeycloak
	vmRate  *rateLimiter
}

// New builds the Server.
func New(cfg *config.Config, database *postgres.DB, kc *keycloak.Client, govKey *govcrypto.GovernanceKey, govCA *x509.Certificate, govCAPEM []byte) *Server {
	s := &Server{
		cfg: cfg,
		db:  database,
		kc:  kc,
		// No client-level timeout: each outbound call sets its own via context.
		http:         &http.Client{},
		tees:         newTEERegistry(),
		teeSessions:  newTEESessionRegistry(),
		publicKeys:   dbPublicKeys{database},
		govKey:       govKey,
		govCA:        govCA,
		govCAPEM:     govCAPEM,
		gatewayStore: database,
		flContracts:  database,
		users:        userdir.New(cfg),
		vmCreds:      database,
		vmRate:       newRateLimiter(vmTokenRequestsPerMinute),
	}
	s.vmKC = s.users
	// Pick up TEE runs whose outcome wasn't recorded before a restart.
	go s.resumeTEERunWatchers()
	go s.runVMSessionSweeper()
	return s
}

// Handler returns the root http.Handler with CORS + the routes mounted at both
// /api/v1 and /governance.
func (s *Server) Handler() http.Handler {
	root := chi.NewRouter()
	root.Use(s.corsMiddleware)
	root.Route("/api/v1", s.registerRoutes)
	root.Route("/governance", s.registerRoutes)
	// TEE orchestrator API, mounted at the root: APD builds its request URLs as
	// {TEE_ORCHESTRATOR_URL}/v1/tee/... so these must not sit under /api/v1.
	s.registerTEERoutes(root)
	s.registerTEESessionRoutes(root)
	// API specs page (apidocs.go), also at the root: GET /apis.
	s.registerAPIDocsRoutes(root)
	// FL client-VM token refresh + orchestrator delivery callback, at the
	// /p3dx paths the VMs and orchestrator already call (fl_vm_credentials.go).
	s.registerVMCredentialRoutes(root)
	return root
}

// registerRoutes wires every endpoint onto the given sub-router. Static segments
// (export, by-submission) precede param routes; chi resolves them correctly.
// helps to hit url to the respective handler
func (s *Server) registerRoutes(r chi.Router) {
	// User-facing /me routes for the P3DX UI (user_routes.go), including
	// the caller's notifications, jobs and projects.
	s.registerUserRoutes(r)

	// provider contract-signing public keys (provider_keys.go)
	r.Put("/provider-keys/{role}", s.putProviderKey)
	r.Get("/provider-keys/{role}/status", s.getProviderKeyStatus)

	// FL participation negotiation: providers removed for a 2nd decline (fl_negotiation.go)
	r.With(s.requireUser).Get("/sessions/{submissionId}/removed-providers", s.getRemovedProviders)

	// Single contract endpoint for both pathways:
	// Routes to FL, TEE, or SMPC orchestration based on technique field
	r.Post("/contract", s.handleContract)
	r.With(s.requireUser).Get("/contract/{sessionId}", s.getContract)

	r.With(s.requireUser).Get("/contracts/by-project/{projectId}", s.getContractByProject)

	// Project record (projects.go): the project_id + participants tracked
	// against a session once the final roster contract is stored. Only the
	// id is exposed here - see getProject. Both take the FL orchestrator's
	// service token; users read their own via GET /me/projects.
	r.Get("/projects/{sessionId}", s.getProject)
	r.Get("/projects", s.getProjects)

	// Builds and returns an unsigned contract for display given just a
	// dataset + technique selection (generate_contract.go). Does not sign,
	// store, or deploy — that's still gated on POST /contract above, once
	// the consumer-signing model is resolved.
	//generate_contract.go
	r.Post("/generate-contract", s.handleGenerateContract)

	// Contract signing for every technique (contract_signing.go): a data
	// provider posts their RSA signature over a contract's hash; the
	// signatures routes report who has signed (FL looks it up by session).
	r.Post("/contracts/{contractId}/sign", s.handleSignContract)
	r.Post("/contracts/{contractId}/withdraw-consent", s.handleWithdrawConsent)
	r.Post("/contracts/{contractId}/consent-expiry", s.handleSetConsentExpiry)
	r.Get("/contracts/{contractId}", s.getConsumerContract)
	r.With(s.requireUser).Get("/contracts/{contractId}/signatures", s.getContractSignatures)
	// Consumer edit of a TEE contract, in place and unsigned
	// (contract_edit.go) — the run gate then refuses it.
	r.Put("/contracts/{contractId}", s.editContract)
	// Workload catalogue (workloads_catalog.go) for the UI's pickers.
	r.With(s.requireUser).Get("/workloads", s.listWorkloads)
	r.With(s.requireUser).Get("/contracts/by-session/{sessionId}/signatures", s.getSessionContractSignatures)

	// Job approvals (job_approval.go): role + catalogue checks for every
	// data/infra provider on a contract's job_id, recorded in the audit table.
	r.Post("/job/approval/data-provider", s.handleDataProviderApproval)
	r.Post("/job/approval/infra-provider", s.handleInfraProviderApproval)
	// r.Put("/job/{jobId}/status", s.putJobStatus)
	r.Get("/job/{jobId}/status", s.getJobStatus)

	// Flotilla join gateway (gateway_certs.go): the FL orchestrator's service
	// account requests a TLS server certificate for an FL session's gateway,
	// signed by the governance CA; FL clients fetch the CA certificate
	// (unauthenticated) to trust it.
	r.Post("/gateway-certs", s.postGatewayCert)
	r.Get("/governance/ca-cert", s.getGovernanceCACert)
	r.Post("/job/{jobId}/tee", s.enableJobTEE)
	// The job's contract + its contract_hash (job_participants.go).
	r.Get("/job/{jobId}/contract/{contractId}", s.getJobContract)
	// A user's own jobs are GET /me/jobs (user_routes.go).
	//for the model.go; downloads go through GET /fl-output/{submissionId}/download
	r.Get("/final-model/summary", s.getFinalModelSummary)
	// FL session output (fl_output.go): the orchestrator uploads the final
	// model + metrics; the session's output owner reads / downloads them.
	r.Post("/fl-output/{submissionId}", s.postFLOutput)
	r.Get("/fl-output/{submissionId}", s.getFLOutput)
	r.Get("/fl-output/{submissionId}/download", s.getFLOutputDownload)

	// Participant-VM IP registry (vm_registry.go), called by
	// terraform/participant-vm right after it creates each VM. Guarded by an
	// optional shared secret — see requireVMRegistryToken.
	r.Group(func(r chi.Router) {
		r.Use(s.requireVMRegistryToken)
		r.Post("/vm-registry", s.postVMRegistry)
		r.Get("/vm-registry/output-owner", s.getOutputOwnerVM)
		r.Get("/vm-registry/data-providers", s.getDataProviderVMs)
	})
}

// corsMiddleware reproduces the always-allow CORS of app.js: reflect the request
// Origin, advertise the methods the UI uses + Content-Type/Authorization, and answer
// preflight with 204. A log line is emitted per request, like the Node version.
// thsi is teh place where a request hit the server
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			log.Println("[CORS] Allowing origin: none")
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			log.Printf("[CORS] Allowing origin: %s", origin)
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		}
		// PUT/PATCH/DELETE: the UI registers keys, edits contracts and ends
		// TEE sessions directly now that p3dx-aaa is gone.
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// j is a convenience alias for a JSON object literal.
type j = map[string]any

// writeJSON sends v as JSON with the given status code.
// this will send the final json to client  with the status code
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON reads and decodes a JSON request body (capped at 5MB) into dst.
// this will reject the json
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	return json.NewDecoder(r.Body).Decode(dst)
}

// reqCtx returns the request context for DB/HTTP calls.
func reqCtx(r *http.Request) context.Context { return r.Context() }

// readBody decodes a JSON request body into dst. An empty body is treated as
// an empty object (matching express.json). A genuine JSON syntax error
// responds 400 INVALID_JSON and returns false.
// tihs will prase the incoming json file
func (s *Server) readBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	err := decodeJSON(w, r, dst)
	if err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "INVALID_JSON", "message": "Invalid JSON in request body",
		})
		return false
	}
	return true
}

// nowISO renders the current UTC time as an ISO-8601 string (matching JS
// new Date().toISOString()).
func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
}
