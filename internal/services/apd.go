package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ProviderContact is a data provider's notification contact info, looked up
// by provider ID from the caller's provider directory (see db.GetDataProviders).
type ProviderContact struct {
	Email string
	Name  string
}

// ProviderLookup resolves a provider ID to its notification contact info.
// A nil/zero-value return means no contact info was found.
type ProviderLookup func(providerID string) ProviderContact

// AuthorizeContractAgainstAPD fetches the data provider policy from APD for a specific dataset
// and evaluates whether the caller claims satisfy that policy.
// If the policy marks the dataset private, sends an FYI notice to the data
// provider — this never gates authorization, which is decided purely by policy rules.
func AuthorizeContractAgainstAPD(contract map[string]interface{}, claims jwt.MapClaims, datasetID, datasetName string, lookupProvider ProviderLookup) (bool, error) {
	providerID, policyID, action := extractProviderContext(contract, datasetID)
	technique := stringValue(contract, "technique")

	policy, err := FetchPolicyForDataset(datasetID, policyID, providerID, datasetName, technique, claims, lookupProvider)
	if err != nil {
		return false, err
	}

	return evaluatePolicy(policy, claims, action), nil
}

// FetchPolicyForDataset fetches the APD policy for a dataset and, if it's
// marked private, fires the FYI notice to the data provider — shared by both
// authorization time (AuthorizeContractAgainstAPD) and contract-generation
// time (handleGenerateContract), so the notice fires exactly once either way
// depending on which path the caller uses. Never gates/blocks the caller.
func FetchPolicyForDataset(datasetID, policyID, providerID, datasetName, technique string, claims jwt.MapClaims, lookupProvider ProviderLookup) (map[string]interface{}, error) {
	policy, err := fetchProviderPolicy(datasetID, policyID)
	if err != nil {
		return nil, err
	}

	if isPrivateDataset(policy) && lookupProvider != nil && providerID != "" {
		contact := lookupProvider(providerID)
		if contact.Email != "" {
			consumer := ConsumerDisplayName(claims)
			if err := sendPrivateDatasetNotice(contact.Email, contact.Name, consumer, datasetName, technique); err != nil {
				fmt.Printf("[APD] Warning: Failed to send private dataset notice to %s: %v\n", contact.Email, err)
			}
		}
	}

	return policy, nil
}

// FetchDatasetForm fetches the data-provider forms submitted for a dataset from APD (FL
// pathway). APD keys provider forms by dataset name, not dataset ID.
func FetchDatasetForm(datasetName string) (map[string]interface{}, error) {
	baseURL := strings.TrimRight(os.Getenv("APD_BASE_URL"), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("APD_BASE_URL not set")
	}
	if datasetName == "" {
		return nil, fmt.Errorf("dataset name required to fetch APD provider forms")
	}

	u := baseURL + "/api/v1/forms/provider-forms?dataset_name=" + url.QueryEscape(datasetName)

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build APD forms request: %w", err)
	}
	if token := strings.TrimSpace(os.Getenv("APD_FORMS_TOKEN")); token != "" {
		req.Header.Set("X-Forms-Push-Token", token)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch APD provider forms: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("APD provider-forms endpoint returned status %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("decode APD provider forms: %w", err)
	}

	forms, _ := response["data"].([]interface{})
	if len(forms) == 0 {
		return nil, fmt.Errorf("no provider forms found in APD for dataset %q", datasetName)
	}

	// The endpoint already filters by dataset_name server-side; return the
	// most recent (first, per ORDER BY created_at DESC) matching form.
	form, ok := forms[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected provider form shape for dataset %q", datasetName)
	}
	return form, nil
}

func fetchProviderPolicy(itemID, policyID string) (map[string]interface{}, error) {
	baseURL := strings.TrimRight(os.Getenv("APD_BASE_URL"), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("APD_BASE_URL not set")
	}

	paths := buildPolicyPaths(itemID, policyID)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no APD policy path candidates")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, p := range paths {
		u := baseURL + p
		resp, err := client.Get(u)
		if err != nil {
			return nil, fmt.Errorf("fetch APD policy: %w", err)
		}

		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("APD policy endpoint returned status %d", resp.StatusCode)
		}

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode APD policy: %w", err)
		}
		data, ok := response["data"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("APD policy response missing data field")
		}
		return data, nil
	}

	return nil, fmt.Errorf("no policy found in APD for item %q", itemID)
}

func isPrivateDataset(policy map[string]interface{}) bool {
	// Check common field names for privacy designation
	if isPrivate, ok := policy["is_private"].(bool); ok {
		return isPrivate
	}
	if isPrivate, ok := policy["private"].(bool); ok {
		return isPrivate
	}
	if isPrivate, ok := policy["visibility"].(string); ok {
		return isPrivate == "private"
	}
	return false
}

// sendPrivateDatasetNotice sends the data provider a plain FYI notice that a
// consumer is using their private dataset. This is informational only — it
// never blocks or gates the authorization decision.
func sendPrivateDatasetNotice(recipientEmail, providerName, consumerName, datasetName, technique string) error {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	senderEmail := os.Getenv("SENDER_EMAIL")
	senderPassword := os.Getenv("SENDER_PASSWORD")

	if smtpHost == "" || smtpPort == "" || senderEmail == "" {
		return fmt.Errorf("SMTP configuration not set")
	}

	if providerName == "" {
		providerName = "there"
	}
	if consumerName == "" {
		consumerName = "A user"
	}
	if datasetName == "" {
		datasetName = "(unnamed dataset)"
	}

	subject := fmt.Sprintf("%s is using your dataset %s", consumerName, datasetName)

	body := fmt.Sprintf(`Hello %s,

%s is using your dataset "%s" via the governance layer (technique: %s).

This is an informational notice only — no action is required.

Best regards,
P3DX Governance Layer`,
		providerName, consumerName, datasetName, technique)

	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		senderEmail, recipientEmail, subject, body)

	addr := smtpHost + ":" + smtpPort
	auth := smtp.PlainAuth("", senderEmail, senderPassword, smtpHost)

	err := smtp.SendMail(addr, auth, senderEmail, []string{recipientEmail}, []byte(message))
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}

	return nil
}

// ConsumerDisplayName picks a human-readable name for the requesting user
// from their Keycloak claims, falling back through preferred_username, name,
// email, and finally sub.
func ConsumerDisplayName(claims jwt.MapClaims) string {
	for _, key := range []string{"preferred_username", "name", "email", "sub"} {
		if v, ok := claims[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// buildPolicyPaths returns the candidate APD policy paths to try, in order:
// a direct policyID lookup first (when the contract's dataset entry carries
// one), then by-item(itemID) — itemID is the dataset/catalogue item ID,
// which is exactly APD's Policy.ItemID.
func buildPolicyPaths(itemID, policyID string) []string {
	template := strings.TrimSpace(os.Getenv("APD_POLICY_PATH_TEMPLATE"))
	if template != "" {
		path := strings.ReplaceAll(template, "{item_id}", itemID)
		path = strings.ReplaceAll(path, "{policy_id}", policyID)
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return []string{path}
	}

	paths := make([]string, 0, 2)
	if policyID != "" {
		paths = append(paths, "/api/v1/policy/"+policyID)
	}
	if itemID != "" {
		paths = append(paths, "/api/v1/policy/by-item/"+itemID)
	}
	return paths
}

func extractProviderContext(contract map[string]interface{}, datasetID string) (providerID, policyID, action string) {
	// First try to find provider info for the specific dataset
	if datasets, ok := contract["datasets"].([]interface{}); ok {
		for _, d := range datasets {
			if dMap, ok := d.(map[string]interface{}); ok {
				if id, ok := dMap["id"].(string); ok && id == datasetID {
					// Found matching dataset, extract provider info
					if pid, ok := dMap["provider_id"].(string); ok && pid != "" {
						providerID = pid
					}
					if pid, ok := dMap["policy_id"].(string); ok && pid != "" {
						policyID = pid
					}
					break
				}
			}
		}
	}

	// Fallback to contract-level fields if not found in datasets
	if providerID == "" {
		providerID = stringValue(contract, "data_provider_id", "provider_id")
	}
	if policyID == "" {
		policyID = stringValue(contract, "policy_id", "data_provider_policy_id")
	}
	action = stringValue(contract, "action", "operation", "purpose")

	nested := []string{"data_provider", "dataProvider", "provider"}
	for _, k := range nested {
		raw, ok := contract[k]
		if !ok {
			continue
		}
		obj, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if providerID == "" {
			providerID = stringValue(obj, "id", "provider_id", "data_provider_id")
		}
		if policyID == "" {
			policyID = stringValue(obj, "policy_id", "id_policy")
		}
		if action == "" {
			action = stringValue(obj, "action", "operation", "purpose")
		}
	}

	return providerID, policyID, action
}

func evaluatePolicy(policy map[string]interface{}, claims jwt.MapClaims, action string) bool {
	ids := userIDsFromClaims(claims)
	roles := rolesFromClaims(claims)
	scopes := scopesFromClaims(claims)

	// APD stores authorization rules under a nested "rules" key.
	rules := policy
	if r, ok := policy["rules"].(map[string]interface{}); ok {
		rules = r
	}

	allowedUsers := stringSet(
		valuesByPath(rules, "allowed_users"),
		valuesByPath(rules, "users"),
		valuesByPath(rules, "access.allowed_users"),
		valuesByPath(rules, "subjects"),
	)
	allowedRoles := stringSet(
		valuesByPath(rules, "allowed_roles"),
		valuesByPath(rules, "roles"),
		valuesByPath(rules, "access.allowed_roles"),
	)
	requiredRoles := stringSet(
		valuesByPath(rules, "required_roles"),
		valuesByPath(rules, "access.required_roles"),
	)
	allowedScopes := stringSet(
		valuesByPath(rules, "allowed_scopes"),
		valuesByPath(rules, "scopes"),
		valuesByPath(rules, "access.allowed_scopes"),
	)
	requiredScopes := stringSet(
		valuesByPath(rules, "required_scopes"),
		valuesByPath(rules, "access.required_scopes"),
	)
	allowedActions := stringSet(
		valuesByPath(rules, "allowed_actions"),
		valuesByPath(rules, "actions"),
		valuesByPath(rules, "access.allowed_actions"),
	)

	if len(allowedActions) > 0 && action != "" && !has(allowedActions, action) {
		return false
	}
	if len(allowedUsers) > 0 && !intersects(ids, allowedUsers) {
		return false
	}
	if len(allowedRoles) > 0 && !intersects(roles, allowedRoles) {
		return false
	}
	if len(requiredRoles) > 0 && !containsAll(roles, requiredRoles) {
		return false
	}
	if len(allowedScopes) > 0 && !intersects(scopes, allowedScopes) {
		return false
	}
	if len(requiredScopes) > 0 && !containsAll(scopes, requiredScopes) {
		return false
	}

	return len(allowedUsers)+len(allowedRoles)+len(requiredRoles)+len(allowedScopes)+len(requiredScopes)+len(allowedActions) > 0
}

func userIDsFromClaims(claims jwt.MapClaims) map[string]struct{} {
	return stringSet(
		rawToStrings(claims["sub"]),
		rawToStrings(claims["preferred_username"]),
		rawToStrings(claims["email"]),
		rawToStrings(claims["username"]),
	)
}

func rolesFromClaims(claims jwt.MapClaims) map[string]struct{} {
	roles := stringSet(rawToStrings(claims["roles"]))

	if realm, ok := claims["realm_access"].(map[string]interface{}); ok {
		for _, r := range rawToStrings(realm["roles"]) {
			roles[r] = struct{}{}
		}
	}
	if ra, ok := claims["resource_access"].(map[string]interface{}); ok {
		for _, v := range ra {
			if app, ok := v.(map[string]interface{}); ok {
				for _, r := range rawToStrings(app["roles"]) {
					roles[r] = struct{}{}
				}
			}
		}
	}

	return roles
}

func scopesFromClaims(claims jwt.MapClaims) map[string]struct{} {
	scopes := stringSet(rawToStrings(claims["scp"]))
	for _, s := range rawToStrings(claims["scope"]) {
		for _, split := range strings.Fields(s) {
			scopes[split] = struct{}{}
		}
	}
	return scopes
}

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

func valuesByPath(m map[string]interface{}, path string) []string {
	parts := strings.Split(path, ".")
	var cur interface{} = m
	for _, p := range parts {
		obj, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur, ok = obj[p]
		if !ok {
			return nil
		}
	}
	return rawToStrings(cur)
}

func rawToStrings(v interface{}) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, i := range t {
			if s, ok := i.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(t))
		for _, s := range t {
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func stringSet(groups ...[]string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, g := range groups {
		for _, s := range g {
			if s == "" {
				continue
			}
			set[s] = struct{}{}
		}
	}
	return set
}

func has(set map[string]struct{}, v string) bool {
	_, ok := set[v]
	return ok
}

func intersects(a, b map[string]struct{}) bool {
	for k := range a {
		if has(b, k) {
			return true
		}
	}
	return false
}

func containsAll(have, need map[string]struct{}) bool {
	for k := range need {
		if !has(have, k) {
			return false
		}
	}
	return true
}
