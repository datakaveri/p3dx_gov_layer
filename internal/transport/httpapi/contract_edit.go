package httpapi

import (
	"encoding/json"
	"fmt"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/workload"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/integration/keycloak"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/repository/postgres"
)

// editContractRequest is the body of PUT /contracts/{contractId}. Every field
// is optional (nil = leave unchanged). Only these fields can be edited — the
// contract id, hash, signatures, technique and party identities never come
// from the client.
type editContractRequest struct {
	Lifecycle *struct {
		ValidFrom  *string `json:"valid_from"`  // RFC 3339
		ValidUntil *string `json:"valid_until"` // RFC 3339
	} `json:"lifecycle"`
	User *struct {
		Name *string `json:"name"`
	} `json:"user"`
	// DataProviders is positional: entry i edits parties.data_providers[i].
	DataProviders []struct {
		DatasetName     *string `json:"dataset_name"`
		DatasetVersion  *string `json:"dataset_version"`
		DataURL         *string `json:"data_url"`
		KeyResourcePath *string `json:"key_resource_path"`
	} `json:"data_providers"`
	Workload *struct {
		// ID switches to another workload.KnownWorkloads entry (its image,
		// resources and application party); Image/CPU/Memory, if also
		// sent, then override that entry's values.
		ID     *string `json:"id"`
		Image  *string `json:"image"`
		CPU    *string `json:"cpu"`
		Memory *string `json:"memory"`
	} `json:"workload"`
}

// PUT /contracts/{contractId} — the consumer who generated a TEE contract
// edits it in place, under the same contract_id, without its data providers
// re-signing. ContractHash stays the hash they signed; gov_layer signs the
// edited content's hash as an amendment (amendSign), which the run gate
// (requireAllProvidersSigned) accepts in its place. A change made any other
// way (e.g. directly in the DB) carries no valid amendment and is refused.
func (s *Server) editContract(w http.ResponseWriter, r *http.Request) {
	contractID := chi.URLParam(r, "contractId")
	fail := func(status int, code, msg string) {
		writeJSON(w, status, j{"status": "FAILED", "error": code, "message": msg})
	}

	tokenStr, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	parsedToken, err := keycloak.ValidateAccessToken(tokenStr)
	if err != nil || !parsedToken.Valid {
		fail(http.StatusUnauthorized, "UNAUTHORIZED", "invalid Keycloak token")
		return
	}
	claims, _ := parsedToken.Claims.(jwt.MapClaims)
	sub, _ := claims["sub"].(string)

	var body editContractRequest
	if !s.readBody(w, r, &body) {
		return
	}
	if s.db == nil {
		fail(http.StatusInternalServerError, "INTERNAL_ERROR", "database not available")
		return
	}

	c, err := s.loadContract(reqCtx(r), contractID)
	if err != nil {
		fail(http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if c == nil {
		fail(http.StatusNotFound, "CONTRACT_NOT_FOUND", "no contract "+contractID)
		return
	}
	if sub == "" || !strings.EqualFold(sub, c.Parties.User.ID) {
		fail(http.StatusForbidden, "NOT_CONTRACT_OWNER", "only the consumer who generated this contract can edit it")
		return
	}
	if c.Technique != "TEE" {
		fail(http.StatusBadRequest, "EDIT_NOT_SUPPORTED", "only TEE contracts can be edited")
		return
	}
	if len(body.DataProviders) > len(c.Parties.DataProviders) {
		fail(http.StatusBadRequest, "BAD_REQUEST", fmt.Sprintf("contract has %d data provider(s), got %d", len(c.Parties.DataProviders), len(body.DataProviders)))
		return
	}

	var changes []string
	setStr := func(label string, dst *string, v *string) {
		if v == nil {
			return
		}
		nv := strings.TrimSpace(*v)
		if nv != *dst {
			changes = append(changes, fmt.Sprintf("%s %q -> %q", label, *dst, nv))
			*dst = nv
		}
	}
	setTime := func(label string, dst *time.Time, v *string) bool {
		if v == nil || strings.TrimSpace(*v) == "" {
			return true
		}
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(*v))
		if err != nil {
			fail(http.StatusBadRequest, "BAD_REQUEST", label+" must be an RFC 3339 time")
			return false
		}
		t = t.UTC()
		if !t.Equal(*dst) {
			changes = append(changes, fmt.Sprintf("%s %s -> %s", label, dst.Format(time.RFC3339), t.Format(time.RFC3339)))
			*dst = t
		}
		return true
	}

	if l := body.Lifecycle; l != nil {
		if !setTime("lifecycle.valid_from", &c.Lifecycle.ValidFrom, l.ValidFrom) ||
			!setTime("lifecycle.valid_until", &c.Lifecycle.ValidUntil, l.ValidUntil) {
			return
		}
		if c.Lifecycle.ValidUntil.Before(c.Lifecycle.ValidFrom) {
			fail(http.StatusBadRequest, "BAD_REQUEST", "valid_until must not be before valid_from")
			return
		}
	}
	if u := body.User; u != nil {
		setStr("user.name", &c.Parties.User.Name, u.Name)
	}
	for i, e := range body.DataProviders {
		dp := &c.Parties.DataProviders[i]
		p := fmt.Sprintf("data_providers[%d].", i)
		setStr(p+"dataset_name", &dp.DatasetName, e.DatasetName)
		setStr(p+"dataset_version", &dp.DatasetVersion, e.DatasetVersion)
		setStr(p+"data_url", &dp.DataURL, e.DataURL)
		if e.KeyResourcePath != nil {
			if dp.Trustee == nil {
				dp.Trustee = &contract.Trustee{}
			}
			setStr(p+"key_resource_path", &dp.Trustee.KeyResourcePath, e.KeyResourcePath)
		}
	}
	if wl := body.Workload; wl != nil {
		if c.Workload == nil {
			fail(http.StatusBadRequest, "BAD_REQUEST", "contract has no workload")
			return
		}
		if wl.ID != nil && strings.TrimSpace(*wl.ID) != "" {
			id := strings.TrimSpace(*wl.ID)
			known, ok := workload.KnownWorkloads[id]
			// if !ok {
			// 	fail(http.StatusBadRequest, "UNKNOWN_WORKLOAD", "no workload "+id)
			// 	return
			// }
			// A workload outside the catalogue needs its image sent with it.
			if !ok && (wl.Image == nil || strings.TrimSpace(*wl.Image) == "") {
				fail(http.StatusBadRequest, "UNKNOWN_WORKLOAD", "no workload "+id+" in the catalogue — send workload.image with it")
				return
			}
			prev := ""
			if len(c.Parties.ApplicationProviders) > 0 {
				prev = c.Parties.ApplicationProviders[0].ID
			}
			if id != prev {
				changes = append(changes, fmt.Sprintf("workload %q -> %q", prev, id))
				if ok {
					c.Workload.Image = known.Image
					c.Workload.Resources = known.Resources
				}
				if len(c.Parties.ApplicationProviders) > 0 {
					ap := &c.Parties.ApplicationProviders[0]
					ap.ID, ap.AppName, ap.ContainerImage = id, id, c.Workload.Image
				}
			}
		}
		setStr("workload.image", &c.Workload.Image, wl.Image)
		setStr("workload.cpu", &c.Workload.Resources.CPU, wl.CPU)
		setStr("workload.memory", &c.Workload.Resources.Memory, wl.Memory)
		// Keep the application party's image in step with an image override.
		if len(c.Parties.ApplicationProviders) > 0 {
			c.Parties.ApplicationProviders[0].ContainerImage = c.Workload.Image
		}
		// (Workload checks dropped: any workload/image may be chosen.)
		// // The (possibly new) workload must be a known catalogue workload,
		// // run with that workload's own image.
		// if err := requireWorkloadAllowed(c); err != nil {
		// 	fail(http.StatusForbidden, "WORKLOAD_NOT_ALLOWED", teeErrorMessage(err))
		// 	return
		// }
	}

	// Keep what the run actually uses (workload env, job trustee — both
	// derived from the first dataset at generation) in step with the edit.
	if len(c.Parties.DataProviders) > 0 {
		first := c.Parties.DataProviders[0]
		if c.Workload != nil && c.Workload.Env != nil {
			if _, ok := c.Workload.Env["DATASET_URL"]; ok {
				c.Workload.Env["DATASET_URL"] = first.DataURL
			}
		}
		if c.Trustee != nil && first.Trustee != nil {
			c.Trustee.KeyResourcePath = first.Trustee.KeyResourcePath
		}
	}

	if len(changes) == 0 {
		fail(http.StatusBadRequest, "NO_CHANGES", "nothing was changed")
		return
	}

	// gov_layer accepts the edit: it signs the new content hash as an
	// amendment, so the providers' signatures over ContractHash still hold.
	newHash, err := s.amendSign(c)
	if err != nil {
		fail(http.StatusInternalServerError, "INTERNAL_ERROR", "edit could not be signed: "+err.Error())
		return
	}

	raw, err := json.Marshal(c)
	if err != nil {
		fail(http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if ok, err := s.db.UpdateContractByContractID(reqCtx(r), contractID, raw); err != nil || !ok {
		msg := "contract row not updated"
		if err != nil {
			msg = err.Error()
		}
		fail(http.StatusInternalServerError, "INTERNAL_ERROR", msg)
		return
	}

	// newHash, _ := contract.ComputeHash(*c)
	log.Printf("[CONTRACT-EDIT] contract %s edited by consumer %s: %s; signed hash %s, content now hashes to %s — amendment signed by gov_layer, provider signatures still valid",
		contractID, sub, strings.Join(changes, ", "), c.ContractHash, newHash)
	editor, _ := claims["preferred_username"].(string)
	if editor == "" {
		editor = sub
	}
	detail := "Changed after signing: " + strings.Join(changes, ", ")
	// if newHash != c.ContractHash {
	// 	detail += " — signatures no longer match"
	// }
	detail += " — accepted by the governance layer, no re-signing needed"
	s.recordContractEvent(reqCtx(r), c, postgres.ContractEventEdited, detail, editor)

	writeJSON(w, http.StatusOK, j{
		"status":       "SUCCESS",
		"contract":     c,
		"changes":      changes,
		"signed_hash":  c.ContractHash,
		"content_hash": newHash,
		"hash_matches": newHash == c.ContractHash,
		"amended":      true,
		// "message":      "contract updated; it no longer matches what its data providers signed, so it cannot be run",
		"message": "contract updated; no re-signing needed — it can be run with the new details",
	})
}
