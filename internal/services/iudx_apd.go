package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
)

// iudxTimeLayout is the IUDX APD's expiry format (no zone, UTC).
const iudxTimeLayout = "2006-01-02T15:04:05"

// IUDXPolicyInput is one accepted dataset's policy for the IUDX APD
// (POST /apd/v2/policy), built from the job's stored contract.
type IUDXPolicyInput struct {
	Contract           *contract.Contract
	JobID              string
	Dataset            contract.DataProviderParty
	ItemID             string // the dataset's DX catalogue (DataBank) id
	CallbackURL        string // IUDX_POLICY_CALLBACK_URL; "/<job_id>" is appended
	ProviderComment    string
	FeedbackToConsumer string
}

// BuildIUDXPolicy returns the {"request": {...}} body for in: the consumer
// (parties.user) may use the dataset until the contract's valid_until, and
// constraints carry the workload, trustee and callback the TEE run needs.
func BuildIUDXPolicy(in IUDXPolicyInput) map[string]any {
	c, dp := in.Contract, in.Dataset
	expiry := c.Lifecycle.ValidUntil.UTC().Format(iudxTimeLayout)

	access := []map[string]any{}
	for _, t := range []string{"api", "file", "sub"} {
		access = append(access, map[string]any{"accessType": t, "expiry": expiry})
	}
	constraints := map[string]any{
		"subjects": map[string]any{
			"allowedUserIds": []string{c.Parties.User.ID},
			"allowedRoles":   []string{"consumer"},
		},
		"access": access,
	}

	workload := map[string]any{}
	if len(c.Parties.ApplicationProviders) > 0 && c.Parties.ApplicationProviders[0].ContainerImage != "" {
		workload["image"] = c.Parties.ApplicationProviders[0].ContainerImage
	}
	// The contract's own workload (known workloads, e.g. MNIST) wins over the
	// application provider's image and the infra's resource allocation.
	if c.Workload != nil {
		if c.Workload.Image != "" {
			workload["image"] = c.Workload.Image
		}
		r := c.Workload.Resources
		res := map[string]any{}
		if r.CPU != "" {
			res["cpu"] = r.CPU
		}
		if r.Memory != "" {
			res["memory"] = r.Memory
		}
		if len(res) > 0 {
			workload["resources"] = res
		}
	}
	for _, ip := range c.Parties.InfraProviders {
		if _, set := workload["resources"]; set {
			break
		}
		ra := ip.ResourceAllocation
		if ra.CPUCores > 0 || ra.RAMMB > 0 {
			res := map[string]any{}
			if ra.CPUCores > 0 {
				res["cpu"] = strconv.Itoa(ra.CPUCores*1000) + "m"
			}
			if ra.RAMMB > 0 {
				res["memory"] = strconv.Itoa(ra.RAMMB) + "Mi"
			}
			workload["resources"] = res
			break
		}
	}
	env := map[string]any{}
	if dp.DataURL != "" {
		env["DATASET_URL"] = dp.DataURL
	}
	if c.Parties.User.DatablobURL != "" {
		env["RESULT_URL"] = c.Parties.User.DatablobURL
	}
	if len(env) > 0 {
		workload["env"] = env
	}
	if len(workload) > 0 {
		constraints["workload"] = workload
	}
	if dp.Trustee != nil {
		constraints["trustee"] = map[string]any{
			"kbsUrl":          dp.Trustee.KBSURL,
			"keyResourcePath": dp.Trustee.KeyResourcePath,
		}
	}
	if in.CallbackURL != "" {
		constraints["callbackUrl"] = strings.TrimRight(in.CallbackURL, "/") + "/" + in.JobID
	}

	// Job contracts stored before their contract_hash was kept with them
	// have none; the hash providers signed is computed from them instead.
	hash := c.ContractHash
	if hash == "" {
		hash, _ = contract.ComputeHash(*c)
	}

	request := map[string]any{
		"policyType":  "GROUP",
		"itemId":      in.ItemID,
		"itemType":    "DATABANK",
		"expiryTime":  expiry,
		"constraints": constraints,
		"additionalInfo": map[string]any{
			"name":         dp.DatasetName,
			"jobId":        in.JobID,
			"contractId":   c.ContractID,
			"contractHash": hash,
		},
	}
	if in.ProviderComment != "" {
		request["providerComment"] = in.ProviderComment
	}
	if in.FeedbackToConsumer != "" {
		request["feedbackToConsumer"] = in.FeedbackToConsumer
	}
	return map[string]any{"request": request}
}

// PostIUDXPolicy posts body to the IUDX APD policy endpoint as the holder of
// token (the data provider's dev Keycloak token) and returns the policy id
// from the response, if it carries one.
func PostIUDXPolicy(ctx context.Context, client *http.Client, policyURL, token string, body map[string]any) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, policyURL, bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("build IUDX policy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("IUDX policy request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Title  string `json:"title"`
			Detail string `json:"detail"`
		}
		msg := strings.TrimSpace(string(respBody))
		if json.Unmarshal(respBody, &e) == nil && (e.Title != "" || e.Detail != "") {
			msg = strings.TrimSpace(e.Title + " " + e.Detail)
		}
		return "", fmt.Errorf("IUDX APD refused the policy (%d): %s", resp.StatusCode, msg)
	}
	var ok struct {
		ID      string `json:"id"`
		Results []struct {
			ID       string `json:"id"`
			PolicyID string `json:"policyId"`
		} `json:"results"`
	}
	_ = json.Unmarshal(respBody, &ok)
	if ok.ID != "" {
		return ok.ID, nil
	}
	if len(ok.Results) > 0 {
		if ok.Results[0].ID != "" {
			return ok.Results[0].ID, nil
		}
		return ok.Results[0].PolicyID, nil
	}
	return "", nil
}
