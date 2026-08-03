package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Contract is the payload sent to the enclave deploy API.
type Contract map[string]interface{}

type DeployRequest struct {
	Contract     Contract `json:"contract"`
	Signature    string   `json:"signature"`
	TopSignature string   `json:"topSignature"`
}

// DeployEnclave POSTs the contract and signatures to the enclave service.
func DeployEnclave(req DeployRequest) error {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return err
	}

	client := &http.Client{}

	request, err := http.NewRequest(
		"POST",
		"http://localhost:8080/deployEnclave",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return err
	}

	request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("deployment failed with status %d", resp.StatusCode)
	}

	return nil
}
