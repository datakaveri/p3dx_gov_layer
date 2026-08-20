package httpapi

// TEE Orchestrator API.
//
// These routes implement the orchestrator interface p3dx-apd is already coded
// against (see p3dx-apd/internal/service/tee.go, which builds request URLs as
// {TEE_ORCHESTRATOR_URL}/v1/tee/...). They are mounted at the server root
// rather than under /api/v1 or /governance for exactly that reason.
//
// Provisioning maps onto starting a pre-provisioned SEV-SNP confidential VM and
// waiting for its enclave manager; terminating maps onto deallocating it. The
// run/output routes are orchestrator-local additions APD does not call — they
// drive and collect the anonymisation demo.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
)

// teeInstance is one provisioned TEE: the contract it was provisioned for and
// the VM serving it.
type teeInstance struct {
	TEEID      string
	ContractID string
	RequestID  string
	// DatasetURL comes from the contract's datasetDetails.resourceUrl and is
	// relayed to the enclave at run time. The enclave does not know it
	// otherwise — the dataset location is a property of the contract, not of
	// the image.
	DatasetURL    string
	VM            services.AzureVM
	EnclaveBase   string
	ProvisionedAt time.Time

	// Attestation is the verified verdict for this instance, nil until
	// /attest succeeds. A run is gated on this being present and unexpired.
	Attestation *services.AttestationResult
	AttestedAt  time.Time
}

// attestationFresh reports whether this instance's verdict still authorises a
// run. Verdicts expire so a long-lived VM cannot ride indefinitely on a single
// attestation taken when it booted — the guest could have changed since.
func (t *teeInstance) attestationFresh(ttl time.Duration, now time.Time) bool {
	if t.Attestation == nil || t.AttestedAt.IsZero() {
		return false
	}
	return now.Sub(t.AttestedAt) <= ttl
}

// teeRegistry tracks live TEE instances.
//
// In-memory on purpose: this demo drives a single pre-provisioned VM, so the
// mapping is at most one entry and does not need to survive a restart. A real
// orchestrator managing a fleet needs this in Postgres alongside the VM's
// lifecycle state — at which point teeId also stops being derivable from a
// single VM's identity.
type teeRegistry struct {
	mu        sync.Mutex
	instances map[string]*teeInstance
}

func newTEERegistry() *teeRegistry {
	return &teeRegistry{instances: make(map[string]*teeInstance)}
}

func (r *teeRegistry) put(t *teeInstance) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.instances[t.TEEID] = t
}

func (r *teeRegistry) get(teeID string) (*teeInstance, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.instances[teeID]
	return t, ok
}

func (r *teeRegistry) delete(teeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.instances, teeID)
}

// contextWithTimeout derives a bounded context from the request.
func contextWithTimeout(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), timeout)
}

// postReceiver POSTs body to url with headers and a per-call timeout, returning
// (status, bodyText, err). The FL orchestration code carried an identical
// helper before it was removed; this is the only caller now.
func (s *Server) postReceiver(ctx context.Context, url string, headers map[string]string, body []byte, timeout time.Duration) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := s.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

// registerTEERoutes mounts the orchestrator API at the root.
func (s *Server) registerTEERoutes(r chi.Router) {
	r.Route("/v1/tee", func(r chi.Router) {
		r.Post("/provision", s.provisionTEE)

		r.Route("/{teeId}", func(r chi.Router) {
			r.Get("/state", s.teeState)
			r.Post("/attest", s.attestTEE)
			r.Post("/run", s.runTEE)
			r.Get("/output", s.teeOutput)
			r.Delete("/terminate", s.terminateTEE)
			r.Post("/key-bundle", s.teeKeyBundle)
		})
	})
}

// teeVM is the configured confidential VM backing every TEE in this demo.
func (s *Server) teeVM() services.AzureVM {
	return services.AzureVM{
		ResourceGroup: s.cfg.TEEAzureRG,
		Name:          s.cfg.TEEVMName,
	}
}

// enclaveBaseURL is the enclave manager root on the configured VM.
func (s *Server) enclaveBaseURL() string {
	if s.cfg.TEEEnclaveBaseURL != "" {
		return s.cfg.TEEEnclaveBaseURL
	}
	return fmt.Sprintf("http://%s:%s", s.cfg.TEEVMIP, s.cfg.TEEEnclavePort)
}

// lookupTEE resolves {teeId} or writes a 404 and returns false.
func (s *Server) lookupTEE(w http.ResponseWriter, r *http.Request) (*teeInstance, bool) {
	teeID := chi.URLParam(r, "teeId")
	inst, ok := s.tees.get(teeID)
	if !ok {
		writeJSON(w, http.StatusNotFound, j{
			"status": "FAILED", "error": "UNKNOWN_TEE",
			"message": "No such TEE instance: " + teeID,
		})
		return nil, false
	}
	return inst, true
}

// POST /v1/tee/provision — start the confidential VM for a contract.
//
// Response shape is {"teeId": ...} because that is what APD's client decodes.
func (s *Server) provisionTEE(w http.ResponseWriter, r *http.Request) {
	var contract services.TEEContract
	if !s.readBody(w, r, &contract) {
		return
	}

	if err := services.ValidateTEEContract(&contract, time.Now()); err != nil {
		writeJSON(w, http.StatusBadRequest, j{
			"status": "FAILED", "error": "INVALID_CONTRACT", "message": err.Error(),
		})
		return
	}

	if s.cfg.TEEAzureRG == "" || s.cfg.TEEVMName == "" {
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "TEE_NOT_CONFIGURED",
			"message": "TEE_AZURE_RG and TEE_VM_NAME must be set",
		})
		return
	}

	vm := s.teeVM()
	ctx := r.Context()

	log.Printf("[TEE] provision: contract=%s request=%s vm=%s/%s",
		contract.ContractID, contract.RequestID, vm.ResourceGroup, vm.Name)

	if err := services.StartVM(ctx, vm); err != nil {
		writeJSON(w, http.StatusBadGateway, j{
			"status": "FAILED", "error": "VM_START_FAILED", "message": err.Error(),
		})
		return
	}

	base := s.enclaveBaseURL()
	state, err := services.WaitForEnclaveManager(ctx, s.http, base,
		s.cfg.TEEStartTimeout, s.cfg.TEEPollInterval)
	if err != nil {
		// The VM is up but its manager never answered. Leave it running: tearing
		// it down here would destroy the evidence needed to debug the guest.
		writeJSON(w, http.StatusBadGateway, j{
			"status": "FAILED", "error": "ENCLAVE_NOT_READY", "message": err.Error(),
			"detail": "VM started but the enclave manager did not become reachable; VM left running for diagnosis",
		})
		return
	}

	// teeId is the contract's request id where APD supplied one, so the two
	// systems agree on the identifier without extra bookkeeping.
	teeID := contract.RequestID
	if teeID == "" {
		teeID = contract.ContractID
	}

	inst := &teeInstance{
		TEEID:         teeID,
		ContractID:    contract.ContractID,
		RequestID:     contract.RequestID,
		DatasetURL:    contract.DatasetDetails.ResourceURL,
		VM:            vm,
		EnclaveBase:   base,
		ProvisionedAt: time.Now().UTC(),
	}
	s.tees.put(inst)

	log.Printf("[TEE] provisioned teeId=%s enclave=%s (state: step %d/%d %q)",
		teeID, base, state.Step, state.MaxSteps, state.Title)

	writeJSON(w, http.StatusOK, j{
		"teeId":       teeID,
		"status":      "PROVISIONED",
		"contract_id": contract.ContractID,
		"enclave":     base,
		"state":       state,
	})
}

// GET /v1/tee/{teeId}/state — Azure power state plus the enclave's own progress.
func (s *Server) teeState(w http.ResponseWriter, r *http.Request) {
	inst, ok := s.lookupTEE(w, r)
	if !ok {
		return
	}

	power, err := services.VMPowerState(r.Context(), inst.VM)
	if err != nil {
		power = "unknown"
		log.Printf("[TEE] state: power lookup failed for %s: %v", inst.TEEID, err)
	}

	resp := j{
		"teeId":       inst.TEEID,
		"contract_id": inst.ContractID,
		"vm":          inst.VM.Name,
		"power_state": power,
	}

	// A short probe: the caller wants a status snapshot, not a wait.
	ctx, cancel := contextWithTimeout(r, s.cfg.PushTimeout)
	defer cancel()
	if state, err := services.FetchEnclaveState(ctx, s.http, inst.EnclaveBase); err == nil {
		resp["enclave_state"] = state
	} else {
		resp["enclave_state"] = nil
		resp["enclave_error"] = err.Error()
	}

	writeJSON(w, http.StatusOK, resp)
}

// POST /v1/tee/{teeId}/attest — challenge the TEE and verify its attestation.
//
// The orchestrator generates the nonce, so the token that comes back cannot be a
// replay of an earlier genuine attestation. On success the verdict is recorded
// against the instance and authorises runs until it expires.
func (s *Server) attestTEE(w http.ResponseWriter, r *http.Request) {
	inst, ok := s.lookupTEE(w, r)
	if !ok {
		return
	}

	if len(s.cfg.TEEMAAIssuers) == 0 {
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "ATTESTATION_NOT_CONFIGURED",
			"message": "TEE_MAA_ISSUERS is empty, so no attestation service is trusted and no token can be verified",
		})
		return
	}

	nonce, err := services.NewAttestationNonce()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}

	body, err := json.Marshal(map[string]string{"nonce": nonce})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}

	log.Printf("[TEE] attest: challenging teeId=%s", inst.TEEID)
	status, text, err := s.postReceiver(r.Context(), inst.EnclaveBase+"/enclave/attest",
		map[string]string{"Content-Type": "application/json"}, body, s.cfg.TEEAttestTimeout)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, j{
			"status": "FAILED", "error": "ENCLAVE_UNREACHABLE",
			"message": fmt.Sprintf("enclave manager at %s unreachable: %v", inst.EnclaveBase, err),
		})
		return
	}
	if status < 200 || status >= 300 {
		writeJSON(w, http.StatusBadGateway, j{
			"status": "FAILED", "error": "ATTESTATION_FAILED",
			"message": fmt.Sprintf("enclave could not produce an attestation token (HTTP %d)", status),
			"detail":  clip(text, 500),
		})
		return
	}

	var enclaveResp struct {
		JWT string `json:"jwt"`
	}
	if err := json.Unmarshal([]byte(text), &enclaveResp); err != nil || enclaveResp.JWT == "" {
		writeJSON(w, http.StatusBadGateway, j{
			"status": "FAILED", "error": "ATTESTATION_MALFORMED",
			"message": "enclave response did not contain a token", "detail": clip(text, 300),
		})
		return
	}

	result, err := services.VerifyMAAToken(r.Context(), s.http, enclaveResp.JWT, services.AttestationPolicy{
		AllowedIssuers:            s.cfg.TEEMAAIssuers,
		Nonce:                     nonce,
		ExpectedLaunchMeasurement: s.cfg.TEEExpectedMeasurement,
		Leeway:                    s.cfg.TEEClockLeeway,
	})
	if err != nil {
		// Verification failure is the interesting security event: the guest is
		// reachable but could not prove it is the TEE we expect.
		log.Printf("[TEE] attest REJECTED teeId=%s: %v", inst.TEEID, err)
		writeJSON(w, http.StatusForbidden, j{
			"status": "FAILED", "error": "ATTESTATION_REJECTED", "message": err.Error(),
		})
		return
	}

	inst.Attestation = result
	inst.AttestedAt = time.Now().UTC()
	s.tees.put(inst)

	log.Printf("[TEE] attest OK teeId=%s type=%s compliance=%s debuggable=%t measurement=%s pinned=%t",
		inst.TEEID, result.AttestationType, result.ComplianceStatus,
		result.Debuggable, result.LaunchMeasurement, result.MeasurementPinned)

	writeJSON(w, http.StatusOK, j{
		"teeId":       inst.TEEID,
		"status":      "ATTESTED",
		"attestation": result,
		"valid_until": inst.AttestedAt.Add(s.cfg.TEEAttestationTTL),
	})
}

// POST /v1/tee/{teeId}/run — trigger the in-TEE anonymisation.
//
// Orchestrator-local: APD's client does not call this. It exists because the
// demo has no attestation/key-bundle phase to trigger the run implicitly.
func (s *Server) runTEE(w http.ResponseWriter, r *http.Request) {
	inst, ok := s.lookupTEE(w, r)
	if !ok {
		return
	}

	// Gate: no compute without a fresh, verified attestation. This is the point
	// of enforcement — the guest has to have proved it is a genuine,
	// non-debuggable SEV-SNP CVM before we hand it a workload.
	if s.cfg.TEEAttestationRequired && !inst.attestationFresh(s.cfg.TEEAttestationTTL, time.Now()) {
		reason := "this TEE has not been attested; POST /v1/tee/{teeId}/attest first"
		if inst.Attestation != nil {
			reason = fmt.Sprintf("attestation expired (verified at %s, TTL %s); re-attest before running",
				inst.AttestedAt.Format(time.RFC3339), s.cfg.TEEAttestationTTL)
		}
		log.Printf("[TEE] run BLOCKED teeId=%s: %s", inst.TEEID, reason)
		writeJSON(w, http.StatusConflict, j{
			"status": "FAILED", "error": "ATTESTATION_REQUIRED", "message": reason,
		})
		return
	}

	// The dataset location travels contract -> orchestrator -> enclave, so the
	// enclave anonymises what the contract named rather than something baked
	// into its image.
	body, err := json.Marshal(map[string]string{
		"contract_id": inst.ContractID,
		"tee_id":      inst.TEEID,
		"dataset_url": inst.DatasetURL,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}
	headers := map[string]string{"Content-Type": "application/json"}

	status, text, err := s.postReceiver(r.Context(), inst.EnclaveBase+"/enclave/run",
		headers, body, s.cfg.PushTimeout)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, j{
			"status": "FAILED", "error": "ENCLAVE_UNREACHABLE",
			"message": fmt.Sprintf("enclave manager at %s unreachable: %v", inst.EnclaveBase, err),
		})
		return
	}
	if status < 200 || status >= 300 {
		writeJSON(w, http.StatusBadGateway, j{
			"status": "FAILED", "error": "RUN_REJECTED",
			"message": fmt.Sprintf("enclave manager returned HTTP %d", status),
			"detail":  clip(text, 500),
		})
		return
	}

	log.Printf("[TEE] run started teeId=%s contract=%s", inst.TEEID, inst.ContractID)
	writeJSON(w, http.StatusAccepted, j{
		"teeId": inst.TEEID, "status": "RUNNING", "detail": clip(text, 500),
	})
}

// GET /v1/tee/{teeId}/output — proxy the anonymised output to the caller.
//
// Streams the enclave's response through unchanged (including its status code
// and content type) so a ?file= download stays a download.
func (s *Server) teeOutput(w http.ResponseWriter, r *http.Request) {
	inst, ok := s.lookupTEE(w, r)
	if !ok {
		return
	}

	url := inst.EnclaveBase + "/enclave/output"
	if q := r.URL.RawQuery; q != "" {
		url += "?" + q
	}

	ctx, cancel := contextWithTimeout(r, s.cfg.TEEOutputTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}

	resp, err := s.http.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, j{
			"status": "FAILED", "error": "ENCLAVE_UNREACHABLE",
			"message": fmt.Sprintf("enclave manager at %s unreachable: %v", inst.EnclaveBase, err),
		})
		return
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		w.Header().Set("Content-Disposition", cd)
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		// Headers are already sent; all that's left is to record it.
		log.Printf("[TEE] output: copy failed for %s: %v", inst.TEEID, err)
	}
}

// DELETE /v1/tee/{teeId}/terminate — deallocate the VM and forget the instance.
func (s *Server) terminateTEE(w http.ResponseWriter, r *http.Request) {
	inst, ok := s.lookupTEE(w, r)
	if !ok {
		return
	}

	if err := services.StopVM(r.Context(), inst.VM); err != nil {
		// Keep the registry entry: the VM may still be running, so the caller
		// needs to be able to retry the teardown.
		writeJSON(w, http.StatusBadGateway, j{
			"status": "FAILED", "error": "VM_STOP_FAILED", "message": err.Error(),
		})
		return
	}

	s.tees.delete(inst.TEEID)
	log.Printf("[TEE] terminated teeId=%s vm=%s", inst.TEEID, inst.VM.Name)
	writeJSON(w, http.StatusOK, j{"teeId": inst.TEEID, "status": "TERMINATED"})
}

// POST /v1/tee/{teeId}/key-bundle — not implemented on this path.
//
// APD forwards a provider's encrypted key bundle here so the TEE can unwrap the
// dataset key. The anonymisation demo has no use for it: the dataset key lives
// in Key Vault and the CVM's managed identity fetches it directly over IMDS, so
// no key ever needs relaying. Fail loudly with 501 rather than accepting and
// discarding a bundle, which would look like the key had been delivered.
func (s *Server) teeKeyBundle(w http.ResponseWriter, r *http.Request) {
	inst, ok := s.lookupTEE(w, r)
	if !ok {
		return
	}

	log.Printf("[TEE] key-bundle rejected for teeId=%s: MI-backed dataset", inst.TEEID)
	writeJSON(w, http.StatusNotImplemented, j{
		"status": "FAILED", "error": "KEY_BUNDLE_NOT_SUPPORTED",
		"message": "This TEE fetches its dataset key from Key Vault via managed identity; " +
			"no key bundle is accepted. Relaying is not implemented on this path.",
	})
}
