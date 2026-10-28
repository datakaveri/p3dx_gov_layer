package httpapi

// FL session output (the final global model + its training metrics), pushed
// here by the FL orchestrator once a session finishes and read back by the
// session's output owner:
//
//	POST /fl-output/{submissionId}           orchestrator service token; multipart upload
//	GET  /fl-output/{submissionId}           owner; status + per-round metrics + artifact
//	GET  /fl-output/{submissionId}/download  owner; the highest-round model file
//
// {submissionId} is the raw FL submission id (= contracts.session_id); files
// on disk use the sanitised sid (non [a-zA-Z0-9_-] replaced with "_", as the
// orchestrator does): model_<sid>_round_<N>.pt and output_<sid>.json in
// CheckpointDir.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/domain/contract"
)

// flContractStore loads a session's latest contract: *db.DB in production;
// stubbed in tests.
type flContractStore interface {
	GetContractBySession(ctx context.Context, sessionID string) (json.RawMessage, error)
}

// flNonAlnum mirrors the orchestrator's sanitiser for file-level session ids.
var flNonAlnum = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// flMaxSIDLen keeps model_<sid>_round_<N>.pt within filesystem name limits.
const flMaxSIDLen = 200

// flTextPartMax caps the metrics / round text parts of an upload.
const flTextPartMax = 16 << 20

// flSessionID turns a raw submission id into the file-level sid.
func flSessionID(raw string) (string, bool) {
	sid := flNonAlnum.ReplaceAllString(raw, "_")
	if len(sid) > flMaxSIDLen || !safeID.MatchString(sid) {
		return "", false
	}
	return sid, true
}

func flOutputJSONName(sid string) string { return "output_" + sid + ".json" }

// flSessionModel returns the highest-round model file for sid, or nil.
func (s *Server) flSessionModel(sid string) (*finalModel, error) {
	entries, err := os.ReadDir(s.cfg.CheckpointDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var best *finalModel
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := modelFileRe.FindStringSubmatch(e.Name())
		if m == nil || m[1] != sid {
			continue
		}
		round, _ := strconv.Atoi(m[2])
		if best != nil && best.Round >= round {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		best = &finalModel{
			SessionID:  sid,
			Round:      round,
			File:       e.Name(),
			SizeBytes:  info.Size(),
			ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
			modTime:    info.ModTime().UnixNano(),
		}
	}
	return best, nil
}

// requireSessionOwner authenticates the caller (dev Keycloak token) and
// checks they own the contract for sessionID: the contract's user party (the
// FL output owner) must be the token's sub (or its username / email). On
// failure it has already written the response.
func (s *Server) requireSessionOwner(w http.ResponseWriter, r *http.Request, sessionID string) bool {
	_, claims, ok := s.devTokenClaims(w, r, "output owner")
	if !ok {
		return false
	}
	return s.checkSessionOwner(w, r, claims, sessionID)
}

// checkSessionOwner is requireSessionOwner for an already-validated token.
func (s *Server) checkSessionOwner(w http.ResponseWriter, r *http.Request, claims jwt.MapClaims, sessionID string) bool {
	raw, err := s.flContracts.GetContractBySession(reqCtx(r), sessionID)
	if err != nil {
		log.Println("[FL-OUTPUT] Error loading contract:", err)
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return false
	}
	if raw == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "CONTRACT_NOT_FOUND",
			"message": "No contract found for this session"})
		return false
	}
	var c contract.Contract
	if err := json.Unmarshal(raw, &c); err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR",
			"message": "stored contract is not valid: " + err.Error()})
		return false
	}
	if !isContractOwner(claims, c) {
		writeJSON(w, http.StatusForbidden, j{"status": "FAILED", "error": "NOT_OUTPUT_OWNER",
			"message": "only this session's output owner can read its output"})
		return false
	}
	return true
}

func isContractOwner(claims jwt.MapClaims, c contract.Contract) bool {
	owner := strings.TrimSpace(c.Parties.User.ID)
	if owner == "" {
		return false
	}
	for _, k := range []string{"sub", "preferred_username", "email"} {
		if v, _ := claims[k].(string); v != "" && strings.EqualFold(v, owner) {
			return true
		}
	}
	return false
}

// writeFileAtomic writes src to dir/name through a temp file + rename.
func writeFileAtomic(dir, name string, src io.Reader) (int64, error) {
	tmp, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(tmp, src)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(dir, name))
	}
	if err != nil {
		os.Remove(tmp.Name())
		return 0, err
	}
	return n, nil
}

// POST /fl-output/{submissionId} — the FL orchestrator stores a finished
// session's output. multipart/form-data: "metrics" (JSON object), "round"
// (int >= 1) and "model" (file; streamed to disk).
func (s *Server) postFLOutput(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireServiceToken(w, r, s.cfg.OrchestratorClientID, s.cfg.OrchestratorRole); !ok {
		return
	}
	sid, ok := flSessionID(chi.URLParam(r, "submissionId"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_SESSION_ID"})
		return
	}
	maxBytes := s.cfg.FLOutputMaxBytes
	if maxBytes <= 0 {
		maxBytes = 2 << 30
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_MULTIPART", "message": err.Error()})
		return
	}
	dir := s.cfg.CheckpointDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	uploadErr := func(err error) {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeJSON(w, http.StatusRequestEntityTooLarge, j{"status": "FAILED", "error": "TOO_LARGE",
				"message": fmt.Sprintf("upload exceeds %d bytes", maxBytes)})
			return
		}
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_MULTIPART", "message": err.Error()})
	}

	var (
		metrics   map[string]any
		round     int
		modelTmp  string
		modelSize int64
	)
	defer func() {
		if modelTmp != "" {
			os.Remove(modelTmp)
		}
	}()
	for {
		part, perr := mr.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			uploadErr(perr)
			return
		}
		switch part.FormName() {
		case "metrics":
			b, rerr := io.ReadAll(io.LimitReader(part, flTextPartMax))
			if rerr != nil {
				uploadErr(rerr)
				return
			}
			if err := json.Unmarshal(b, &metrics); err != nil || metrics == nil {
				writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_METRICS",
					"message": "metrics must be a JSON object"})
				return
			}
		case "round":
			b, rerr := io.ReadAll(io.LimitReader(part, 64))
			if rerr != nil {
				uploadErr(rerr)
				return
			}
			n, cerr := strconv.Atoi(strings.TrimSpace(string(b)))
			if cerr != nil || n < 1 {
				writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_ROUND",
					"message": "round must be an integer >= 1"})
				return
			}
			round = n
		case "model":
			if modelTmp != "" {
				writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "DUPLICATE_MODEL"})
				return
			}
			tmp, terr := os.CreateTemp(dir, ".model_"+sid+".*.tmp")
			if terr != nil {
				writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": terr.Error()})
				return
			}
			modelTmp = tmp.Name()
			n, cerr := io.Copy(tmp, part)
			if closeErr := tmp.Close(); cerr == nil {
				cerr = closeErr
			}
			if cerr != nil {
				uploadErr(cerr)
				return
			}
			modelSize = n
		default:
			// Drain unknown parts.
			if _, derr := io.Copy(io.Discard, part); derr != nil {
				uploadErr(derr)
				return
			}
		}
		part.Close()
	}
	if metrics == nil || round < 1 || modelTmp == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_FIELDS",
			"message": "metrics, round and model parts are required"})
		return
	}

	modelName := fmt.Sprintf("model_%s_round_%d.pt", sid, round)
	if err := os.Rename(modelTmp, filepath.Join(dir, modelName)); err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	modelTmp = ""

	metrics["fetched_at"] = time.Now().UTC().Format(time.RFC3339)
	out, err := json.Marshal(metrics)
	if err == nil {
		_, err = writeFileAtomic(dir, flOutputJSONName(sid), strings.NewReader(string(out)))
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	log.Printf("[FL-OUTPUT] stored %s (%d bytes) + %s", modelName, modelSize, flOutputJSONName(sid))
	writeJSON(w, http.StatusCreated, j{"status": "stored", "session_id": sid, "file": modelName, "size_bytes": modelSize})
}

// flRound is one round's normalised validation metrics.
type flRound struct {
	Round    int      `json:"round"`
	Accuracy *float64 `json:"accuracy"`
	Loss     *float64 `json:"loss"`
}

// flNumber reads a metric value leniently: a number, a numeric string, or a
// [round, value] pair (value taken).
func flNumber(v any) *float64 {
	switch t := v.(type) {
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return nil
		}
		return &t
	case json.Number:
		if f, err := t.Float64(); err == nil {
			return flNumber(f)
		}
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(t), 64); err == nil {
			return flNumber(f)
		}
	case []any:
		if len(t) == 2 {
			return flNumber(t[1])
		}
	case map[string]any:
		for _, k := range []string{"value", "v"} {
			if x, ok := t[k]; ok {
				return flNumber(x)
			}
		}
	}
	return nil
}

func flSeries(v any) []*float64 {
	list, ok := v.([]any)
	if !ok {
		if n := flNumber(v); n != nil {
			return []*float64{n}
		}
		return nil
	}
	out := make([]*float64, len(list))
	for i, x := range list {
		out[i] = flNumber(x)
	}
	return out
}

// flPerRound normalises global_validation_metrics: the first key (sorted)
// containing "acc" is accuracy, the first containing "loss" is loss.
func flPerRound(metrics map[string]any) []flRound {
	gvm, _ := metrics["global_validation_metrics"].(map[string]any)
	keys := make([]string, 0, len(gvm))
	for k := range gvm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var acc, loss []*float64
	accSet, lossSet := false, false
	for _, k := range keys {
		lk := strings.ToLower(k)
		if !accSet && strings.Contains(lk, "acc") {
			acc, accSet = flSeries(gvm[k]), true
		} else if !lossSet && strings.Contains(lk, "loss") {
			loss, lossSet = flSeries(gvm[k]), true
		}
	}
	n := max(len(acc), len(loss))
	out := make([]flRound, n)
	for i := range n {
		out[i].Round = i + 1
		if i < len(acc) {
			out[i].Accuracy = acc[i]
		}
		if i < len(loss) {
			out[i].Loss = loss[i]
		}
	}
	return out
}

// flInt reads a positive integer leniently.
func flInt(v any) (int, bool) {
	if f := flNumber(v); f != nil && *f >= 1 && *f == math.Trunc(*f) {
		return int(*f), true
	}
	return 0, false
}

var flRoundKeys = []string{"num_training_rounds", "num_server_rounds", "num_rounds", "total_rounds", "rounds", "training_rounds", "server_rounds"}

// flFindRounds looks through session_config (up to a few levels deep) for a
// round-count key, in flRoundKeys priority order.
func flFindRounds(v any, depth int) (int, bool) {
	m, ok := v.(map[string]any)
	if !ok || depth > 3 {
		return 0, false
	}
	lower := make(map[string]any, len(m))
	for k, x := range m {
		lower[strings.ToLower(k)] = x
	}
	for _, k := range flRoundKeys {
		if x, ok := lower[k]; ok {
			if n, ok := flInt(x); ok {
				return n, true
			}
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if n, ok := flFindRounds(m[k], depth+1); ok {
			return n, true
		}
	}
	return 0, false
}

// GET /fl-output/{submissionId} — the session's output for its owner.
func (s *Server) getFLOutput(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "submissionId")
	sid, ok := flSessionID(raw)
	if !ok {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_SESSION_ID"})
		return
	}
	if !s.requireSessionOwner(w, r, raw) {
		return
	}

	var metrics map[string]any
	if b, err := os.ReadFile(filepath.Join(s.cfg.CheckpointDir, flOutputJSONName(sid))); err == nil {
		if jerr := json.Unmarshal(b, &metrics); jerr != nil {
			log.Printf("[FL-OUTPUT] %s is not valid JSON: %v", flOutputJSONName(sid), jerr)
			metrics = nil
		}
	} else if !os.IsNotExist(err) {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	model, err := s.flSessionModel(sid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}

	perRound := []flRound{}
	final := j{"accuracy": nil, "loss": nil}
	var total, fetchedAt any
	if metrics != nil {
		perRound = flPerRound(metrics)
		for _, pr := range perRound {
			if pr.Accuracy != nil {
				final["accuracy"] = *pr.Accuracy
			}
			if pr.Loss != nil {
				final["loss"] = *pr.Loss
			}
		}
		if n, ok := flInt(metrics["rounds_total"]); ok {
			total = n
		} else if n, ok := flFindRounds(metrics["session_config"], 0); ok {
			total = n
		}
		if fa, ok := metrics["fetched_at"].(string); ok && fa != "" {
			fetchedAt = fa
		}
	}
	done := len(perRound)
	var artifact any
	if model != nil {
		done = max(done, model.Round)
		artifact = j{"file": model.File, "size_bytes": model.SizeBytes, "modified_at": model.ModifiedAt}
	}
	status := "not_found"
	if metrics != nil && model != nil {
		status = "ready"
	}
	writeJSON(w, http.StatusOK, j{
		"status":     status,
		"session_id": sid,
		"rounds":     j{"done": done, "total": total},
		"final":      final,
		"per_round":  perRound,
		"artifact":   artifact,
		"fetched_at": fetchedAt,
	})
}

// GET /fl-output/{submissionId}/download — the highest-round model file.
func (s *Server) getFLOutputDownload(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "submissionId")
	sid, ok := flSessionID(raw)
	if !ok {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_SESSION_ID"})
		return
	}
	if !s.requireSessionOwner(w, r, raw) {
		return
	}
	model, err := s.flSessionModel(sid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if model == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NO_MODEL", "message": "No model stored for this session yet."})
		return
	}
	f, err := os.Open(filepath.Join(s.cfg.CheckpointDir, model.File))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "READ_ERROR", "message": err.Error()})
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "READ_ERROR", "message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, model.File))
	http.ServeContent(w, r, model.File, info.ModTime(), f)
}
