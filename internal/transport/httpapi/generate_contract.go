package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/application/contractgen"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/apd"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/keycloak"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

type datasetSelection struct {
	DatasetID   string `json:"dataset_id"`
	DatasetName string `json:"dataset_name"`
}

type generateContractRequest struct {
	Datasets      []datasetSelection `json:"datasets"`
	ApplicationID string             `json:"application_id"`
	Technique     string             `json:"technique"`
	ProviderID    string             `json:"provider_id"`
	ComputeChoice string             `json:"compute_choice"` // optional; defaulted per technique when blank
	InfraIDs      []string           `json:"infra_ids"`      // InfraCat selection; SMPC only, exactly 2 required
	Purpose       string             `json:"purpose"`        // stated purpose of processing; required for TEE (DPDP Rule 3)
}

// maxPurposeLen caps the free-text purpose carried into the contract.
const maxPurposeLen = 1000

var validTechniques = map[string]bool{"FL": true, "TEE": true, "SMPC": true}

// handleGenerateContract builds and returns an unsigned contract for display,
// given a dataset + technique selection (and, for SMPC, exactly two infra
// selections). It fetches the real policy (TEE/SMPC) or provider form (FL)
// from APD so the preview reflects real data where APD has it, but it does
// not sign, store, or deploy anything — that step is deferred until the
// consumer-signing model is decided.
func (s *Server) handleGenerateContract(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenStr := ""
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		tokenStr = authHeader[7:]
	}
	parsedToken, err := keycloak.ValidateAccessToken(tokenStr)
	if err != nil || !parsedToken.Valid {
		http.Error(w, "Invalid Keycloak token", http.StatusUnauthorized)
		return
	}
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	var req generateContractRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Datasets) == 0 {
		http.Error(w, "at least one dataset is required", http.StatusBadRequest)
		return
	}
	if !validTechniques[req.Technique] {
		http.Error(w, "technique must be one of FL, TEE, SMPC", http.StatusBadRequest)
		return
	}
	// InfraCat: SMPC requires exactly two infra selections. Enforced here as a
	// second line of defense alongside the UI's own cap/requirement in
	// WorkloadForm.jsx and the p3dx-aaa route's check.
	if req.Technique == "SMPC" && len(req.InfraIDs) != 2 {
		http.Error(w, "exactly 2 infra_ids are required for SMPC", http.StatusBadRequest)
		return
	}
	// DPDP Rule 3(b)(ii): the consent notice providers sign must state the
	// specific purpose. Optional for now (the UI no longer asks for it);
	// re-enable the TEE requirement below to enforce it again.
	req.Purpose = strings.TrimSpace(req.Purpose)
	// if req.Technique == "TEE" && req.Purpose == "" {
	// 	http.Error(w, "purpose is required for TEE", http.StatusBadRequest)
	// 	return
	// }
	if len(req.Purpose) > maxPurposeLen {
		http.Error(w, "purpose must be at most 1000 characters", http.StatusBadRequest)
		return
	}
	// One open request per selection: refuse while this consumer's previous
	// contract for the same datasets and technique still awaits approval
	// (contract_pending.go).
	consumerID, _ := claims["sub"].(string)
	pendingKeyIDs := make([]string, 0, len(req.Datasets))
	for _, d := range req.Datasets {
		pendingKeyIDs = append(pendingKeyIDs, d.DatasetID)
	}
	sort.Strings(pendingKeyIDs)
	if pending, err := s.pendingGeneratedContract(r.Context(), consumerID, strings.Join(pendingKeyIDs, "+"), req.Technique); err != nil {
		log.Printf("[GENERATE] Error checking for a pending contract: %v", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR"})
		return
	} else if pending != nil {
		writeJSON(w, http.StatusConflict, j{
			"status":      "FAILED",
			"error":       "CONTRACT_PENDING",
			"message":     "A contract for these datasets is already waiting for the providers' approval. Wait for it to be approved, rejected or to expire before requesting again.",
			"contract_id": pending.ContractID,
			"job_id":      pending.JobID,
			"contract":    pending,
		})
		return
	}

	lookupProvider := func(providerID string) apd.ProviderContact {
		for _, p := range s.db.GetDataProviders(r.Context()) {
			if p.ID == providerID {
				return apd.ProviderContact{Email: p.Email, Name: p.Name}
			}
		}
		return apd.ProviderContact{}
	}

	// Fetch APD policy for every selected dataset, every technique (FL
	// included) — this is the same lookup used at authorization time
	// (apd.AuthorizeContractAgainstAPD), kept in parity here so the
	// private-dataset notice fires and the policy's existence is validated
	// regardless of pathway. Never gates the preview: a failed lookup just
	// leaves that dataset's fields at their zero-value default.
	datasetIDs := make([]string, 0, len(req.Datasets))
	datasetInputs := make([]contractgen.DatasetInput, 0, len(req.Datasets))
	for _, d := range req.Datasets {
		datasetName := d.DatasetName
		if datasetName == "" {
			datasetName = d.DatasetID
		}
		datasetIDs = append(datasetIDs, d.DatasetID)

		in := contractgen.DatasetInput{DatasetID: d.DatasetID, DatasetName: datasetName}
		policy, err := apd.FetchPolicyForDataset(d.DatasetID, "", req.ProviderID, datasetName, req.Technique, claims, lookupProvider)
		if err != nil {
			log.Printf("[GENERATE] Warning: no policy found in APD for dataset %s: %v", d.DatasetID, err)
			// (Workload restriction dropped: a TEE dataset without a policy
			// falls back to its catalogue owner again, like SMPC.)
			// if req.Technique == "TEE" {
			// 	http.Error(w, fmt.Sprintf("dataset %s has no data-provider policy naming the workloads it may be used for", d.DatasetID), http.StatusForbidden)
			// 	return
			// }
			if req.Technique != "FL" {
				// TEE/SMPC without an APD policy: the dataset's DX catalogue
				// owner (uploadedBy) is its provider, so the job request still
				// reaches them and their approval call recognises them.
				s.catalogueOwnerAsProvider(r.Context(), d.DatasetID, tokenStr, &in)
			}
		} else {
			// TEE: the dataset's provider may limit which workloads can run
			// on it (PolicyForm.jsx's "Allowed workloads"). Unlike the rest
			// of this lookup, this one does gate the preview.
			// TEE: if the provider picked workloads for this dataset (PolicyForm's
			// "Workloads for this purpose"), only those may run on it; none
			// picked means any workload.
			// (Workload matching dropped: any workload may be picked for
			// any dataset, whatever its policy's allowed workloads.)
			// if req.Technique == "TEE" && !workload.PolicyAllowsWorkload(policy, req.ApplicationID) {
			// 	// http.Error(w, fmt.Sprintf("workload %q is not allowed by the data provider's policy for dataset %s", req.ApplicationID, d.DatasetID), http.StatusForbidden)
			// 	http.Error(w, workload.WorkloadMismatchMessage(policy, d.DatasetID, req.ApplicationID), http.StatusForbidden)
			// 	return
			// }
			in.IsPrivate = apd.IsPrivateDataset(policy)
			if url, ok := policy["data_url"].(string); ok {
				in.DataURL = url
			}
			if rules, ok := policy["rules"].(map[string]interface{}); ok {
				if path, ok := rules["key_resource_path"].(string); ok {
					in.KeyResourcePath = strings.TrimSpace(path)
				}
			}
			if req.ProviderID != "" {
				in.ProviderID = req.ProviderID
				in.ProviderName = lookupProvider(req.ProviderID).Name
			} else if req.Technique != "FL" {
				// TEE/SMPC: the dataset's own APD policy names its provider —
				// that provider_id is who gets sent the contract to sign below.
				// (FL is signed later, on its final roster contract.)
				in.ProviderID, _ = policy["provider_id"].(string)
				in.ProviderName, _ = policy["provider_email"].(string)
				if in.ProviderName == "" {
					in.ProviderName = in.ProviderID
				}
			}
		}
		datasetInputs = append(datasetInputs, in)
	}

	var form map[string]interface{}
	if req.Technique == "FL" {
		// FL forms are keyed by dataset name today (single-dataset pathway
		// upstream of this handler) — use the first selected dataset's name,
		// matching this handler's pre-existing FL behavior.
		datasetName := datasetInputs[0].DatasetName
		f, err := apd.FetchDatasetForm(datasetName)
		if err != nil {
			log.Printf("[GENERATE] Warning: no provider form found in APD for dataset %s: %v", datasetName, err)
		} else {
			form = f
		}
	}

	// InfraCat (SMPC only): resolve each selected infrastructure's APD policy
	// into the contract's InfraProviderParty fields. Never gates the preview —
	// same graceful-degradation style as the dataset policy fetch above (an
	// unresolved name becomes "Unknown Infrastructure"). The 5
	// confidential-compute flags are read directly as booleans —
	// InfraPolicyForm.jsx computes and stores them at registration time (OR'd
	// across that infra's own node pools/VM instance), so no tech-string
	// classification happens here.
	var infraInputs []contractgen.InfraInput
	if req.Technique == "SMPC" {
		for _, infraID := range req.InfraIDs {
			in := contractgen.InfraInput{InfraID: infraID}
			infraPolicy, err := apd.FetchInfraPolicy(infraID)
			if err != nil {
				log.Printf("[GENERATE] Warning: no infra policy found in APD for infra %s: %v", infraID, err)
				infraInputs = append(infraInputs, in)
				continue
			}
			rules, ok := infraPolicy["rules"].(map[string]interface{})
			if !ok {
				infraInputs = append(infraInputs, in)
				continue
			}
			infra, ok := rules["infrastructure"].(map[string]interface{})
			if !ok {
				infraInputs = append(infraInputs, in)
				continue
			}
			in.InfraName, _ = infra["name"].(string)
			in.InfraRegion, _ = infra["region"].(string)
			if attestation, ok := infra["attestation"].(map[string]interface{}); ok {
				in.InfraAttestationRequired, _ = attestation["required"].(bool)
				in.InfraAttestationService, _ = attestation["service"].(string)
				in.InfraAttestationPolicyID, _ = attestation["policy_id"].(string)
			}
			if capacity, ok := infra["capacity"].(map[string]interface{}); ok {
				if v, ok := capacity["cpu_cores"].(float64); ok { // JSON numbers decode as float64
					in.InfraCPUCores = int(v)
				}
				if v, ok := capacity["ram_mb"].(float64); ok {
					in.InfraRAMMB = int(v)
				}
				in.InfraSGXEnabled, _ = capacity["sgx_enabled"].(bool)
				in.InfraTDXEnabled, _ = capacity["tdx_enabled"].(bool)
				in.InfraSEVSNPEnabled, _ = capacity["sev_snp_enabled"].(bool)
				in.InfraSEVEnabled, _ = capacity["sev_enabled"].(bool)
				in.InfraNitroEnclaveEnabled, _ = capacity["nitro_enclave_enabled"].(bool)
			}
			infraInputs = append(infraInputs, in)
		}
	}

	contract := contractgen.BuildGeneratedContract(contractgen.GenerateContractInput{
		Datasets:      datasetInputs,
		ApplicationID: req.ApplicationID,
		Technique:     req.Technique,
		ComputeChoice: req.ComputeChoice,
		Purpose:       req.Purpose,
		ConsumerID:    consumerID,
		ConsumerName:  apd.ConsumerDisplayName(claims),
		Form:          form,
		KBSURL:        s.cfg.KBSURL,
		ResultURL:     s.cfg.DefaultResultURL,
		CallbackURL:   s.cfg.ContractCallbackURL,

		Infras: infraInputs,
	})

	// A contract naming both datasets and infra needs job approval first. It
	// is stored with its contract_hash — the hash its JOB_REQUESTs carry
	// (storedContractHash), its providers sign when approving and the
	// approvals are cross-verified against (jobapproval.ContractHash). It is never
	// governance-signed.
	needsApproval := s.jobApprovalRequired(&contract)
	if needsApproval {
		contract.ContractHash = ""
		if _, hash, err := storedContractHash(contract); err == nil {
			contract.ContractHash = hash
		} else {
			log.Printf("[GENERATE] Warning: job %s: contract could not be hashed: %v", contract.JobID, err)
		}
	} else if req.Technique != "FL" && contract.ContractHash != "" {
		// Other TEE/SMPC contracts: gov_layer signs the hash with its own key
		// before storing, so the stored copy carries the governance signature
		// providers verify. Best-effort — without it the sign requests just
		// aren't sent, and the run gate stays closed.
		if err := s.governanceSign(&contract); err != nil {
			log.Printf("[GENERATE] Warning: failed to governance-sign contract %s: %v", contract.ContractID, err)
		}
	}

	// Dedup/session key for StoreGeneratedContract: joins every selected
	// dataset ID (sorted, so selection order doesn't matter) so regenerating
	// the same N-dataset selection overwrites the same draft row instead of
	// accumulating one row per generation.
	sortedDatasetIDs := append([]string(nil), datasetIDs...)
	sort.Strings(sortedDatasetIDs)
	datasetKey := strings.Join(sortedDatasetIDs, "+")

	stored := false
	if contractJSON, err := json.Marshal(contract); err == nil {
		if _, dbErr := s.db.StoreGeneratedContract(r.Context(), consumerID, datasetKey, req.Technique, contract.ContractID, contract.JobID, contractJSON); dbErr != nil {
			log.Printf("[GOVERNANCE] Warning: Failed to store generated contract in DB: %v", dbErr)
		} else {
			stored = true
		}
	} else {
		log.Printf("[GOVERNANCE] Warning: Failed to marshal generated contract for storage: %v", err)
	}

	log.Printf("[GENERATE] Contract generated (unsigned): datasets=%s technique=%s hash=%s", datasetKey, req.Technique, contract.ContractHash)

	// TEE/SMPC: send the hash + governance signature + contract to each
	// participating data provider to sign (contract_signing.go). Only once
	// stored — signing verifies against the stored copy, so an unstored
	// contract could never be signed. FL sends its sign requests from
	// postContract once the final roster contract exists instead.
	//
	// Job approval comes first: a contract naming both datasets and infra
	// is hashed, governance-signed and sent out only once
	// POST /job/approval/data-provider and /job/approval/infra-provider have
	// both accepted its job_id (job_approval.go).
	sender, _ := claims["preferred_username"].(string)
	if sender == "" {
		sender = consumerID
	}

	// Who takes part in the job, for GET /me/jobs
	// (job_participants.go).
	if stored {
		s.recordJobParticipants(r.Context(), &contract, sender)
		s.recordContractEvent(r.Context(), &contract, postgres.ContractEventGenerated,
			fmt.Sprintf("%s consent request generated by %s", req.Technique, sender), sender)
	}

	// A job that needs approval: ask each of its data and infra providers to
	// approve or reject it (job_request.go).
	providersNotified := 0
	if needsApproval && stored {
		providersNotified = s.notifyJobRequest(r.Context(), contract, sender)
	}

	signRequestsSent := 0
	signing := "not_applicable"
	switch {
	case req.Technique == "FL" || !stored:
	case needsApproval:
		signing = "on_hold_pending_approval"
		log.Printf("[GENERATE] Job %s: contract hashed and stored; its providers sign the hash when approving", contract.JobID)
	case contract.GovernanceSignature != nil:
		signRequestsSent = s.sendSignRequestsOnce(r.Context(), contract, sender)
		signing = "requested"
		if signRequestsSent > 0 {
			s.recordContractEvent(r.Context(), &contract, postgres.ContractEventSignRequested,
				fmt.Sprintf("Signature requested from %d data provider(s)", signRequestsSent), "governance-layer")
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":             "success",
		"contract":           contract,
		"sign_requests_sent": signRequestsSent,
		"signing":            signing,
		"approval_required":  needsApproval,
		"providers_notified": providersNotified,
	})
}

// catalogueOwnerAsProvider sets in's provider to the DX catalogue item's
// owner (uploadedBy, a username/email) when APD has no policy naming one, so
// a TEE/SMPC dataset's provider is still known: provider_id
// "provider-<slug(uploadedBy)>", name uploadedBy. A failed lookup leaves in
// unchanged (the dataset then has no known provider, as before).
func (s *Server) catalogueOwnerAsProvider(ctx context.Context, datasetID, token string, in *contractgen.DatasetInput) {
	item, err := s.lookupCatalogueItem(ctx, datasetID, token)
	if err != nil {
		log.Printf("[GENERATE] Warning: dataset %s: DX catalogue lookup failed, provider unknown: %v", datasetID, err)
		return
	}
	if item.UploadedBy == "" {
		log.Printf("[GENERATE] Warning: dataset %s: DX catalogue item has no uploadedBy, provider unknown", datasetID)
		return
	}
	in.ProviderID = providerIDForUsername(item.UploadedBy)
	in.ProviderName = item.UploadedBy
	log.Printf("[GENERATE] Dataset %s: no APD policy, provider %s taken from its DX catalogue owner", datasetID, in.ProviderID)
}
