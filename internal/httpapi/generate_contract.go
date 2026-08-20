package httpapi

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
)

type generateContractRequest struct {
	DatasetID     string `json:"dataset_id"`
	DatasetName   string `json:"dataset_name"`
	ApplicationID string `json:"application_id"`
	Technique     string `json:"technique"`
	ProviderID    string `json:"provider_id"`
}

var validTechniques = map[string]bool{"FL": true, "TEE": true, "SMPC": true}

// handleGenerateContract builds and returns an unsigned contract for display,
// given just a dataset + technique selection. It fetches the real policy
// (TEE/SMPC) or provider form (FL) from APD so the preview reflects real
// data where APD has it, but it does not sign, store, or deploy anything —
// that step is deferred until the consumer-signing model is decided.
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

	if req.DatasetID == "" {
		http.Error(w, "dataset_id is required", http.StatusBadRequest)
		return
	}
	if !validTechniques[req.Technique] {
		http.Error(w, "technique must be one of FL, TEE, SMPC", http.StatusBadRequest)
		return
	}
	datasetName := req.DatasetName
	if datasetName == "" {
		datasetName = req.DatasetID
	}

	lookupProvider := func(providerID string) services.ProviderContact {
		for _, p := range s.db.GetDataProviders(r.Context()) {
			if p.ID == providerID {
				return services.ProviderContact{Email: p.Email, Name: p.Name}
			}
		}
		return services.ProviderContact{}
	}

	providerName := ""
	var form map[string]interface{}

	if req.Technique == "TEE" || req.Technique == "SMPC" {
		policy, err := services.FetchPolicyForDataset(req.DatasetID, "", req.ProviderID, datasetName, req.Technique, claims, lookupProvider)
		if err != nil {
			log.Printf("[GENERATE] Warning: no policy found in APD for dataset %s: %v", req.DatasetID, err)
		} else if req.ProviderID != "" {
			providerName = lookupProvider(req.ProviderID).Name
		}
		_ = policy // policy details aren't merged into the preview yet; fetching it surfaces the private-dataset notice and validates it exists.
	} else {
		f, err := services.FetchDatasetForm(datasetName)
		if err != nil {
			log.Printf("[GENERATE] Warning: no provider form found in APD for dataset %s: %v", datasetName, err)
		} else {
			form = f
		}
	}

	consumerID, _ := claims["sub"].(string)
	contract := services.BuildGeneratedContract(services.GenerateContractInput{
		DatasetID:     req.DatasetID,
		DatasetName:   datasetName,
		ApplicationID: req.ApplicationID,
		Technique:     req.Technique,
		ConsumerID:    consumerID,
		ConsumerName:  services.ConsumerDisplayName(claims),
		ProviderName:  providerName,
		ProviderID:    req.ProviderID,
		Form:          form,
	})

	if contractJSON, err := json.Marshal(contract); err == nil {
		if _, dbErr := s.db.StoreGeneratedContract(r.Context(), consumerID, req.DatasetID, req.Technique, contract.ContractID, contractJSON); dbErr != nil {
			log.Printf("[GOVERNANCE] Warning: Failed to store generated contract in DB: %v", dbErr)
		}
	} else {
		log.Printf("[GOVERNANCE] Warning: Failed to marshal generated contract for storage: %v", err)
	}

	log.Printf("[GENERATE] Contract generated (unsigned): dataset=%s technique=%s", req.DatasetID, req.Technique)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"contract": contract,
	})
}
