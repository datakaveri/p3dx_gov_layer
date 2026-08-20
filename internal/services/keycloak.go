package services

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// JWKS is the JSON Web Key Set returned by Keycloak.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is a single JSON Web Key (RSA).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// FetchKeycloakJWKS fetches the JWKS from KEYCLOAK_JWKS_URL (or, if unset,
// derives the standard path from KEYCLOAK_BASE_URL + KEYCLOAK_REALM) and
// returns RSA public keys. Keys are indexed by kid; if kid is empty, the
// first key is used.
func FetchKeycloakJWKS() (map[string]*rsa.PublicKey, error) {
	jwksURL := os.Getenv("KEYCLOAK_JWKS_URL")
	if jwksURL == "" {
		base := strings.TrimRight(os.Getenv("KEYCLOAK_BASE_URL"), "/")
		realm := os.Getenv("KEYCLOAK_REALM")
		if base == "" || realm == "" {
			return nil, fmt.Errorf("KEYCLOAK_JWKS_URL not set (and KEYCLOAK_BASE_URL/KEYCLOAK_REALM not set to derive it)")
		}
		jwksURL = base + "/realms/" + realm + "/protocol/openid-connect/certs"
	}
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS returned status %d", resp.StatusCode)
	}
	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" || jwk.N == "" || jwk.E == "" {
			continue
		}
		pub, err := jwkToRSAPublicKey(jwk)
		if err != nil {
			continue
		}
		kid := jwk.Kid
		if kid == "" {
			kid = "default"
		}
		keys[kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no RSA keys in JWKS")
	}
	return keys, nil
}

func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e == 0 {
		e = 65537
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// ValidateAccessToken verifies a Keycloak JWT (e.g. access_token or id_token)
// using the realm JWKS from KEYCLOAK_JWKS_URL.
func ValidateAccessToken(tokenStr string) (*jwt.Token, error) {
	if tokenStr == "" {
		return nil, fmt.Errorf("empty token")
	}

	keysByKID, err := FetchKeycloakJWKS()
	if err != nil {
		return nil, err
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	return parser.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			// Some setups omit kid; try "default" if present.
			if pub, ok := keysByKID["default"]; ok {
				return pub, nil
			}
			return nil, fmt.Errorf("token header missing kid")
		}
		pub, ok := keysByKID[kid]
		if !ok {
			return nil, fmt.Errorf("kid %q not found in Keycloak JWKS", kid)
		}
		return pub, nil
	})
}

func RSAPublicKeyFromToken(t *jwt.Token) (*rsa.PublicKey, error) {
	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected token claims type")
	}

	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("token missing cnf claim")
	}
	jwkRaw, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("token cnf claim missing jwk")
	}

	kty, _ := jwkRaw["kty"].(string)
	n, _ := jwkRaw["n"].(string)
	e, _ := jwkRaw["e"].(string)
	if kty != "RSA" || n == "" || e == "" {
		return nil, fmt.Errorf("token cnf.jwk is not a valid RSA key")
	}

	return jwkToRSAPublicKey(JWK{Kty: kty, N: n, E: e})
}
