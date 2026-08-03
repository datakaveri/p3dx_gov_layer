package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthorizeContractAgainstAPD fetches the data provider policy from APD
// and evaluates whether the caller claims satisfy that policy.
func AuthorizeContractAgainstAPD(contract map[string]interface{}, claims jwt.MapClaims) (bool, error) {
	providerID, policyID, action := extractProviderContext(contract)
	if providerID == "" {
		return false, fmt.Errorf("contract missing data provider details")
	}

	policy, err := fetchProviderPolicy(providerID, policyID)
	if err != nil {
		return false, err
	}

	return evaluatePolicy(policy, claims, action), nil
}

func fetchProviderPolicy(providerID, policyID string) (map[string]interface{}, error) {
	baseURL := strings.TrimRight(os.Getenv("APD_BASE_URL"), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("APD_BASE_URL not set")
	}

	paths := buildPolicyPaths(providerID, policyID)
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

	return nil, fmt.Errorf("no policy found in APD for provider %q", providerID)
}

func buildPolicyPaths(providerID, policyID string) []string {
	template := strings.TrimSpace(os.Getenv("APD_POLICY_PATH_TEMPLATE"))
	if template != "" {
		path := strings.ReplaceAll(template, "{provider_id}", providerID)
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
	if providerID != "" {
		paths = append(paths, "/api/v1/policy/item/"+providerID)
	}
	return paths
}

func extractProviderContext(contract map[string]interface{}) (providerID, policyID, action string) {
	providerID = stringValue(contract, "data_provider_id", "provider_id")
	policyID = stringValue(contract, "policy_id", "data_provider_policy_id")
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
