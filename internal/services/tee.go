package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Contract is the payload sent to the enclave deploy API.
type Contract map[string]interface{}

type DeployRequest struct {
	Contract     Contract `json:"contract"`
	Signature    string   `json:"signature"`
	TopSignature string   `json:"topSignature"`
}

// deployEnclaveTimeout bounds the call so a wedged enclave host cannot hang the
// request handler indefinitely.
const deployEnclaveTimeout = 30 * time.Second

// DeployEnclave POSTs the contract and signatures to the enclave service.
//
// baseURL is the enclave host root, e.g. http://20.0.0.1:4000. It used to be
// hardcoded to http://localhost:8080, which was wrong twice over: the enclave
// manager listens on :4000 and exposes /enclave/deploy (not /deployEnclave), and
// :8080 is p3dx-apd's own default port, so the two collided on a single host.
func DeployEnclave(ctx context.Context, baseURL string, req DeployRequest) error {
	if baseURL == "" {
		return fmt.Errorf("enclave base URL is not configured")
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, deployEnclaveTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		baseURL+"/enclave/deploy",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return err
	}

	request.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("deployment failed with status %d", resp.StatusCode)
	}

	return nil
}
