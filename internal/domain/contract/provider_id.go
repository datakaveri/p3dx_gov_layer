package contract

import (
	"regexp"
	"strings"
)

var nonSlugChars = regexp.MustCompile(`[^a-z0-9]+`)

// ProviderIDForUsername mirrors the provider_id derivation used by
// PolicyForm.jsx and p3dx-aaa: "provider-" + slugify(username).
func ProviderIDForUsername(username string) string {
	s := strings.ToLower(username)
	if s == "" {
		s = "unknown"
	}
	s = strings.Trim(nonSlugChars.ReplaceAllString(s, "-"), "-")
	return "provider-" + s
}

// PartyProviderID is the provider_id a data-provider party signs as. TEE/SMPC
// contracts carry the APD policy's provider_id ("provider-<slug>") as the
// party ID; FL roster contracts carry the Keycloak user id instead, with the
// username in Name, so the provider_id is derived from that.
func PartyProviderID(p DataProviderParty) string {
	if strings.HasPrefix(p.ID, "provider-") {
		return p.ID
	}
	return ProviderIDForUsername(p.Name)
}
