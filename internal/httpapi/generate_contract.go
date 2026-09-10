package httpapi

import (
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
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
}

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
	parsedToken, err := services.ValidateAccessToken(tokenStr)
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

	lookupProvider := func(providerID string) services.ProviderContact {
		for _, p := range s.db.GetDataProviders(r.Context()) {
			if p.ID == providerID {
				return services.ProviderContact{Email: p.Email, Name: p.Name}
			}
		}
		return services.ProviderContact{}
	}

	// Fetch APD policy for every selected dataset, every technique (FL
	// included) — this is the same lookup used at authorization time
	// (services.AuthorizeContractAgainstAPD), kept in parity here so the
	// private-dataset notice fires and the policy's existence is validated
	// regardless of pathway. Never gates the preview: a failed lookup just
	// leaves that dataset's fields at their zero-value default.
	datasetIDs := make([]string, 0, len(req.Datasets))
	datasetInputs := make([]services.DatasetInput, 0, len(req.Datasets))
	for _, d := range req.Datasets {
		datasetName := d.DatasetName
		if datasetName == "" {
			datasetName = d.DatasetID
		}
		datasetIDs = append(datasetIDs, d.DatasetID)

		in := services.DatasetInput{DatasetID: d.DatasetID, DatasetName: datasetName}
		policy, err := services.FetchPolicyForDataset(d.DatasetID, "", req.ProviderID, datasetName, req.Technique, claims, lookupProvider)
		if err != nil {
			log.Printf("[GENERATE] Warning: no policy found in APD for dataset %s: %v", d.DatasetID, err)
		} else {
			in.IsPrivate = services.IsPrivateDataset(policy)
			if url, ok := policy["data_url"].(string); ok {
				in.DataURL = url
			}
			if req.ProviderID != "" {
				in.ProviderID = req.ProviderID
				in.ProviderName = lookupProvider(req.ProviderID).Name
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
		f, err := services.FetchDatasetForm(datasetName)
		if err != nil {
			log.Printf("[GENERATE] Warning: no provider form found in APD for dataset %s: %v", datasetName, err)
		} else {
			form = f
		}
	}

	// InfraCat: resolve each selected infrastructure's APD policy into the
	// contract's InfraProviderParty fields. SMPC only, and never gates the
	// preview — same graceful-degradation style as the dataset policy fetch
	// above (BuildGeneratedContract falls back to "Unknown Infrastructure" if
	// a lookup or shape doesn't resolve a name). The 5 confidential-compute
	// flags are read directly as booleans — InfraPolicyForm.jsx computes and
	// stores them at registration time (OR'd across that infra's own node
	// pools/VM instance), so no tech-string classification happens here.
	var infraInputs []services.InfraInput
	if req.Technique == "SMPC" {
		for _, infraID := range req.InfraIDs {
			in := services.InfraInput{InfraID: infraID}
			infraPolicy, err := services.FetchInfraPolicy(infraID)
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

	consumerID, _ := claims["sub"].(string)
	contract := services.BuildGeneratedContract(services.GenerateContractInput{
		Datasets:      datasetInputs,
		ApplicationID: req.ApplicationID,
		Technique:     req.Technique,
		ComputeChoice: req.ComputeChoice,
		ConsumerID:    consumerID,
		ConsumerName:  services.ConsumerDisplayName(claims),
		Form:          form,

		Infras: infraInputs,
	})

	// Dedup/session key for StoreGeneratedContract: joins every selected
	// dataset ID (sorted, so selection order doesn't matter) so regenerating
	// the same N-dataset selection overwrites the same draft row instead of
	// accumulating one row per generation.
	sortedDatasetIDs := append([]string(nil), datasetIDs...)
	sort.Strings(sortedDatasetIDs)
	datasetKey := strings.Join(sortedDatasetIDs, "+")

	if contractJSON, err := json.Marshal(contract); err == nil {
		if _, dbErr := s.db.StoreGeneratedContract(r.Context(), consumerID, datasetKey, req.Technique, contract.ContractID, contractJSON); dbErr != nil {
			log.Printf("[GOVERNANCE] Warning: Failed to store generated contract in DB: %v", dbErr)
		}
	} else {
		log.Printf("[GOVERNANCE] Warning: Failed to marshal generated contract for storage: %v", err)
	}

	log.Printf("[GENERATE] Contract generated (unsigned): datasets=%s technique=%s", datasetKey, req.Technique)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"contract": contract,
	})
}
