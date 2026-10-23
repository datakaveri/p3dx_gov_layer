package services

// Azure CVM lifecycle for the TEE orchestrator. The confidential VM is
// long-lived and pre-provisioned (cloned from a known-good SEV-SNP guest disk);
// "provisioning" a TEE therefore means starting that VM and waiting for its
// enclave manager to answer, and "terminating" means deallocating it. Nothing
// here creates or destroys Azure resources.
//
// These call the `az` CLI rather than the Azure SDK for Go. That is a
// deliberate demo-scoped choice: it needs no service-principal plumbing and
// inherits whatever identity the operator is already logged in as. The
// hardening step is a service principal (or the gov_layer host's own managed
// identity) driving armcompute through the SDK — at which point only this file
// changes.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// AzureVM identifies the confidential VM backing the TEE.
type AzureVM struct {
	ResourceGroup string
	Name          string
}

// azRun executes an `az` subcommand and returns stdout. Stderr is folded into
// the error since az writes diagnostics there.
func azRun(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "az", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return nil, fmt.Errorf("az %s: %s", strings.Join(args, " "), detail)
	}
	return out, nil
}

// StartVM starts (or resumes a deallocated) confidential VM. It is idempotent:
// starting an already-running VM succeeds.
func StartVM(ctx context.Context, vm AzureVM) error {
	log.Printf("[TEE] starting VM %s/%s", vm.ResourceGroup, vm.Name)
	_, err := azRun(ctx, "vm", "start", "-g", vm.ResourceGroup, "-n", vm.Name, "-o", "none")
	return err
}

// StopVM deallocates the VM so it stops billing compute. Deallocate rather than
// stop: a merely stopped CVM still incurs charges.
func StopVM(ctx context.Context, vm AzureVM) error {
	log.Printf("[TEE] deallocating VM %s/%s", vm.ResourceGroup, vm.Name)
	_, err := azRun(ctx, "vm", "deallocate", "-g", vm.ResourceGroup, "-n", vm.Name, "-o", "none")
	return err
}

// VMPowerState returns the Azure power state, e.g. "PowerState/running" reduced
// to "running". Returns "unknown" when Azure reports no power-state code.
func VMPowerState(ctx context.Context, vm AzureVM) (string, error) {
	out, err := azRun(ctx, "vm", "get-instance-view",
		"-g", vm.ResourceGroup, "-n", vm.Name,
		"--query", "instanceView.statuses[].code", "-o", "json")
	if err != nil {
		return "", err
	}

	var codes []string
	if err := json.Unmarshal(out, &codes); err != nil {
		return "", fmt.Errorf("parse instance view: %w", err)
	}
	for _, c := range codes {
		if rest, ok := cutPrefix(c, "PowerState/"); ok {
			return rest, nil
		}
	}
	return "unknown", nil
}

// cutPrefix reports whether s starts with prefix and returns the remainder.
func cutPrefix(s, prefix string) (string, bool) {
	if strings.HasPrefix(s, prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

// EnclaveState is the enclave manager's progress report (GET /enclave/state).
type EnclaveState struct {
	Step        int    `json:"step"`
	MaxSteps    int    `json:"maxSteps"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// FetchEnclaveState reads the enclave manager's current state. baseURL is the
// manager root, e.g. http://20.0.0.1:4000.
func FetchEnclaveState(ctx context.Context, client *http.Client, baseURL string) (*EnclaveState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/enclave/state", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enclave manager returned HTTP %d", resp.StatusCode)
	}

	var st EnclaveState
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, fmt.Errorf("decode enclave state: %w", err)
	}
	return &st, nil
}

// WaitForEnclaveManager polls GET /enclave/state until it answers or the budget
// expires. A freshly started CVM needs roughly a minute before gunicorn is up,
// so callers should allow generously more than that.
func WaitForEnclaveManager(ctx context.Context, client *http.Client, baseURL string, timeout, interval time.Duration) (*EnclaveState, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var lastErr error
	for {
		// Bound each probe well under the poll interval so a hanging connect
		// cannot stall the loop.
		probeCtx, probeCancel := context.WithTimeout(ctx, interval)
		st, err := FetchEnclaveState(probeCtx, client, baseURL)
		probeCancel()
		if err == nil {
			return st, nil
		}
		lastErr = err

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("enclave manager at %s not ready within %s (last error: %v)", baseURL, timeout, lastErr)
		case <-time.After(interval):
		}
	}
}
