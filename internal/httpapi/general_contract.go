package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
)

type ContractRequest struct {
	AccessToken string                 `json:"access_token"`
	Token       string                 `json:"token"`
	Contract    map[string]interface{} `json:"contract"`
	Signature   string                 `json:"signature"` // hex-encoded user signature of the contract
}

func (s *Server) handleContract(w http.ResponseWriter, r *http.Request) {
	var req ContractRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 1. Validate Keycloak token
	tokenStr := req.AccessToken
	if tokenStr == "" {
		tokenStr = req.Token
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

	// 2. Marshal contract (bytes that were signed)
	contractBytes, err := json.Marshal(req.Contract)
	if err != nil {
		http.Error(w, "Invalid contract", http.StatusBadRequest)
		return
	}

	// 3. Verify the user's signature on the contract
	userSig, err := hex.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "Invalid signature encoding", http.StatusBadRequest)
		return
	}
	userPub, err := services.RSAPublicKeyFromToken(parsedToken)
	if err != nil {
		http.Error(w, "Token missing bound public key", http.StatusUnauthorized)
		return
	}
	if err := services.Verify(contractBytes, userSig, userPub); err != nil {
		http.Error(w, "Contract signature verification failed", http.StatusUnauthorized)
		return
	}

	// 4. Extract technique from contract to determine pathway
	technique := stringValue(req.Contract, "technique")
	if technique == "" {
		http.Error(w, "Contract missing technique field", http.StatusBadRequest)
		return
	}

	// 5. Route to appropriate handler based on technique
	switch technique {
	case "FL":
		s.handleFLContract(w, r, req, claims, contractBytes)
	case "TEE", "SMPC":
		s.handleGeneralContract(w, r, req, claims, contractBytes)
	default:
		http.Error(w, "Unsupported technique: "+technique, http.StatusBadRequest)
	}
}

// handleFLContract processes FL pathway contracts
// Fetches forms from APD for each dataset and orchestrates FL session
func (s *Server) handleFLContract(w http.ResponseWriter, r *http.Request, req ContractRequest, claims jwt.MapClaims, contractBytes []byte) {
	// Extract datasets from contract
	datasets := extractDatasets(req.Contract)
	if len(datasets) == 0 {
		http.Error(w, "Contract missing datasets", http.StatusBadRequest)
		return
	}

	// Fetch forms from APD for each dataset (APD keys provider forms by name)
	forms := make(map[string]interface{})
	for _, dataset := range datasets {
		form, err := services.FetchDatasetForm(dataset.Name)
		if err != nil {
			log.Printf("[FL] Warning: Failed to fetch form for dataset %s: %v", dataset.ID, err)
			// Non-blocking: continue with available forms
			continue
		}
		forms[dataset.ID] = form
	}

	log.Printf("[FL] Contract received with %d datasets, fetched %d forms from APD", len(datasets), len(forms))

	// Store contract in database with FL pathway
	contract := &db.Contract{}
	if err := json.Unmarshal(contractBytes, contract); err == nil {
		_, dbErr := s.db.StoreContract(context.Background(), contract, true, "FL")
		if dbErr != nil {
			log.Printf("[GOVERNANCE] Warning: Failed to store FL contract in DB: %v", dbErr)
		}
	}

	// Return success — FL orchestration triggered by separate endpoints
	resp := map[string]interface{}{
		"status":   "success",
		"pathway":  "FL",
		"datasets": len(datasets),
		"forms":    len(forms),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(resp)
}

// handleGeneralContract processes General pathway (TEE/SMPC) contracts
// Fetches policies from APD for each dataset, authorizes, and deploys
func (s *Server) handleGeneralContract(w http.ResponseWriter, r *http.Request, req ContractRequest, claims jwt.MapClaims, contractBytes []byte) {
	// Extract datasets from contract
	datasets := extractDatasets(req.Contract)
	if len(datasets) == 0 {
		http.Error(w, "Contract missing datasets", http.StatusBadRequest)
		return
	}

	// Fetch and authorize policies from APD for each dataset
	lookupProvider := func(providerID string) services.ProviderContact {
		for _, p := range s.db.GetDataProviders(r.Context()) {
			if p.ID == providerID {
				return services.ProviderContact{Email: p.Email, Name: p.Name}
			}
		}
		return services.ProviderContact{}
	}

	for _, dataset := range datasets {
		allowed, err := services.AuthorizeContractAgainstAPD(req.Contract, claims, dataset.ID, dataset.Name, lookupProvider)
		if err != nil {
			http.Error(w, "Policy authorization failed for dataset "+dataset.ID+": "+err.Error(), http.StatusInternalServerError)
			return
		}
		if !allowed {
			http.Error(w, "User not authorized by provider policy for dataset "+dataset.ID, http.StatusForbidden)
			return
		}
	}

	log.Printf("[GENERAL] Contract authorized against %d dataset policies", len(datasets))

	// Load orchestrator private key
	priv, err := services.LoadPrivateKey(os.Getenv("ORCH_PRIVATE_KEY"))
	if err != nil {
		http.Error(w, "Failed to load orchestrator private key", http.StatusInternalServerError)
		return
	}

	// Secure store
	storeKey := []byte(os.Getenv("STORE_KEY"))
	storePath := os.Getenv("STORE_PATH")

	contractID, err := services.SecureStore(req.Contract, storeKey, storePath)
	if err != nil {
		http.Error(w, "Storage failed", http.StatusInternalServerError)
		return
	}

	// Store contract in database with GENERAL pathway
	contract := &db.Contract{}
	if err := json.Unmarshal(contractBytes, contract); err == nil {
		_, dbErr := s.db.StoreContract(context.Background(), contract, true, "GENERAL")
		if dbErr != nil {
			log.Printf("[GOVERNANCE] Warning: Failed to store GENERAL contract in DB: %v", dbErr)
		}
	}

	// Sign contract with orchestrator key
	orchSig, err := services.Sign(contractBytes, priv)
	if err != nil {
		http.Error(w, "Contract signing failed", http.StatusInternalServerError)
		return
	}

	// Deploy to enclave (TEE) or SMPC network
	technique := stringValue(req.Contract, "technique")
	deployReq := services.DeployRequest{
		Contract:     services.Contract(req.Contract),
		Signature:    req.Signature,
		TopSignature: hex.EncodeToString(orchSig),
	}

	if err := services.DeployEnclave(r.Context(), s.enclaveBaseURL(), deployReq); err != nil {
		http.Error(w, "Deployment failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[%s] Contract deployed successfully", technique)

	resp := map[string]string{
		"status":         "success",
		"pathway":        "GENERAL",
		"technique":      technique,
		"orch_signature": hex.EncodeToString(orchSig),
		"contract_id":    contractID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// stringValue extracts a string value from a map, trying multiple field names
func stringValue(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// DatasetRef is a dataset entry extracted from a contract's datasets list.
type DatasetRef struct {
	ID   string
	Name string
}

// extractDatasets extracts dataset id/name pairs from contract
func extractDatasets(contract map[string]interface{}) []DatasetRef {
	var datasets []DatasetRef

	// Try multiple possible field names for datasets
	if ds, ok := contract["datasets"].([]interface{}); ok {
		for _, d := range ds {
			if dMap, ok := d.(map[string]interface{}); ok {
				if id, ok := dMap["id"].(string); ok {
					name, _ := dMap["name"].(string)
					datasets = append(datasets, DatasetRef{ID: id, Name: name})
				}
			}
		}
	}

	if len(datasets) == 0 {
		if ds, ok := contract["data_providers"].([]interface{}); ok {
			for _, d := range ds {
				if dMap, ok := d.(map[string]interface{}); ok {
					if id, ok := dMap["id"].(string); ok {
						name, _ := dMap["name"].(string)
						datasets = append(datasets, DatasetRef{ID: id, Name: name})
					}
				}
			}
		}
	}

	return datasets
}
