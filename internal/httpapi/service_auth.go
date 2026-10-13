package httpapi

// Service-account authentication: endpoints only another P3DX service may
// call (e.g. POST /gateway-certs, called by the FL orchestrator) take a
// client-credentials token from the services' Keycloak (KEYCLOAK_JWKS_URL),
// minted for one specific client (azp) holding one realm role. Also the
// containment rule for Flotilla VM tokens: a token minted for the VMs'
// client is never accepted where a provider's own token is expected.

import (
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/services"
)

// requireServiceToken validates the Bearer token against the services'
// Keycloak and checks it was issued to client azp and carries realm role
// role. On failure it has already written the response.
func (s *Server) requireServiceToken(w http.ResponseWriter, r *http.Request, azp, role string) (jwt.MapClaims, bool) {
	tokenStr, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || tokenStr == "" {
		writeJSON(w, http.StatusUnauthorized, j{"status": "FAILED", "error": "MISSING_AUTH_TOKEN"})
		return nil, false
	}
	token, err := services.ValidateAccessToken(tokenStr)
	if err != nil || token == nil || !token.Valid {
		log.Printf("[SERVICE-AUTH] Token rejected: %v", err)
		writeJSON(w, http.StatusUnauthorized, j{"status": "FAILED", "error": "INVALID_OR_EXPIRED_TOKEN"})
		return nil, false
	}
	claims, _ := token.Claims.(jwt.MapClaims)
	if got, _ := claims["azp"].(string); azp == "" || got != azp {
		log.Printf("[SERVICE-AUTH] Token for client %q refused (want %q)", got, azp)
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "FORBIDDEN",
			"message": "token was not issued to the " + azp + " client"})
		return nil, false
	}
	if role == "" || !slices.Contains(realmRoles(claims), role) {
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "FORBIDDEN",
			"message": "token lacks the " + role + " realm role"})
		return nil, false
	}
	return claims, true
}

// realmRoles reads realm_access.roles from a Keycloak token's claims.
func realmRoles(claims jwt.MapClaims) []string {
	var roles []string
	if ra, ok := claims["realm_access"].(map[string]any); ok {
		if list, ok := ra["roles"].([]any); ok {
			for _, v := range list {
				if r, ok := v.(string); ok {
					roles = append(roles, r)
				}
			}
		}
	}
	return roles
}

// rejectFlotillaVMToken refuses a validated token minted for the Flotilla
// VMs' client (FLOTILLA_VM_CLIENT_ID): those tokens only let a VM reach its
// own session and must never pass as a provider's. Returns true (and has
// written 403) when the token is one.
func (s *Server) rejectFlotillaVMToken(w http.ResponseWriter, claims jwt.MapClaims) bool {
	if s.cfg == nil || s.cfg.FlotillaVMClientID == "" {
		return false
	}
	if azp, _ := claims["azp"].(string); azp != s.cfg.FlotillaVMClientID {
		return false
	}
	log.Printf("[SERVICE-AUTH] Flotilla VM token (azp %q) refused on a provider endpoint", s.cfg.FlotillaVMClientID)
	writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "VM_TOKEN_NOT_ALLOWED"})
	return true
}
