package httpapi

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"
)

// inspectModelPy is the torch-free .pt reader, embedded so the binary is
// self-contained. It's written to a temp file and run via python3 to produce a
// readable JSON summary of a checkpoint.
//
//go:embed inspect_model.py
var inspectModelPy string

// modelFileRe matches the per-round global-model checkpoints flo_server writes:
//
//	model_<session_id>_round_<N>.pt   (or .weights for non-pytorch backends)
var modelFileRe = regexp.MustCompile(`^model_(.+)_round_(\d+)\.(pt|weights)$`)

// safeID matches ids safe to interpolate into a filename (alphanumeric, dash,
// underscore) — mirrors the ids newID produces in the db package.
var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// clip truncates s to at most n bytes without splitting a multi-byte rune,
// used to cap error messages before they're embedded in a JSON response.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// finalModel describes the final (highest-round) global model for one FL session.
type finalModel struct {
	SessionID  string `json:"session_id"`
	Round      int    `json:"round"`
	File       string `json:"file"`
	SizeBytes  int64  `json:"size_bytes"`
	ModifiedAt string `json:"modified_at"`
	modTime    int64  // for sorting; not serialized
}

// listFinalModels scans the checkpoint dir and returns, per session, the model
// with the highest round number (the final model), newest session first.
func (s *Server) listFinalModels() ([]finalModel, error) {
	entries, err := os.ReadDir(s.cfg.CheckpointDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []finalModel{}, nil
		}
		return nil, err
	}
	best := map[string]finalModel{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := modelFileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		session := m[1]
		round, _ := strconv.Atoi(m[2])
		cur, ok := best[session]
		if ok && cur.Round >= round {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		best[session] = finalModel{
			SessionID:  session,
			Round:      round,
			File:       e.Name(),
			SizeBytes:  info.Size(),
			ModifiedAt: info.ModTime().UTC().Format("2006-01-02T15:04:05.000Z07:00"),
			modTime:    info.ModTime().UnixNano(),
		}
	}
	out := make([]finalModel, 0, len(best))
	for _, v := range best {
		out = append(out, v)
	}
	// Newest session (by the final model's mtime) first.
	sort.Slice(out, func(i, j int) bool { return out[i].modTime > out[j].modTime })
	return out, nil
}

// GET /final-models — list each session's final (highest-round) model, newest
// first, plus `latest` (the most recently written one) for convenience.
func (s *Server) getFinalModels(w http.ResponseWriter, r *http.Request) {
	models, err := s.listFinalModels()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error(),
		})
		return
	}
	var latest any
	if len(models) > 0 {
		latest = models[0]
	}
	writeJSON(w, http.StatusOK, j{
		"status": "SUCCESS", "count": len(models), "models": models, "latest": latest,
	})
}

// resolveModelFile picks the checkpoint file to serve from validated query params.
// session_id defaults to the newest session; round defaults to that session's
// highest (final) round. Returns (absPath, filename, ok); on failure it has
// already written the error response.
func (s *Server) resolveModelFile(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	models, err := s.listFinalModels()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return "", "", false
	}
	if len(models) == 0 {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NO_MODEL", "message": "No global model checkpoints found yet."})
		return "", "", false
	}

	session := r.URL.Query().Get("session_id")
	if session == "" {
		session = models[0].SessionID // newest
	} else if !safeID.MatchString(session) {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_SESSION_ID"})
		return "", "", false
	}

	// Default round = the session's final (highest) round.
	var fm *finalModel
	for i := range models {
		if models[i].SessionID == session {
			fm = &models[i]
			break
		}
	}
	if fm == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NO_MODEL", "message": "No model for that session."})
		return "", "", false
	}

	filename := fm.File
	if rs := r.URL.Query().Get("round"); rs != "" {
		round, cerr := strconv.Atoi(rs)
		if cerr != nil || round < 0 {
			writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_ROUND"})
			return "", "", false
		}
		// Build the specific round filename; both extensions are possible.
		filename = ""
		for _, ext := range []string{"pt", "weights"} {
			cand := fmt.Sprintf("model_%s_round_%d.%s", session, round, ext)
			if _, statErr := os.Stat(filepath.Join(s.cfg.CheckpointDir, cand)); statErr == nil {
				filename = cand
				break
			}
		}
		if filename == "" {
			writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NO_MODEL", "message": "No model for that session/round."})
			return "", "", false
		}
	}

	// Defence in depth: the resolved path must stay inside CheckpointDir.
	abs := filepath.Join(s.cfg.CheckpointDir, filename)
	dirAbs, _ := filepath.Abs(s.cfg.CheckpointDir)
	fileAbs, _ := filepath.Abs(abs)
	if filepath.Dir(fileAbs) != dirAbs || !modelFileRe.MatchString(filepath.Base(fileAbs)) {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_PATH"})
		return "", "", false
	}
	return abs, filename, true
}

// GET /final-model/download?session_id=&round= — stream a global model .pt.
// Defaults to the newest session's final round.
func (s *Server) getFinalModelDownload(w http.ResponseWriter, r *http.Request) {
	abs, filename, ok := s.resolveModelFile(w, r)
	if !ok {
		return
	}
	f, err := os.Open(abs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "READ_ERROR", "message": err.Error()})
		return
	}
	defer f.Close()
	info, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
	if info != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	}
	http.ServeContent(w, r, filename, info.ModTime(), f)
}

// GET /final-model/summary?session_id=&round= — a human-readable JSON view of a
// model checkpoint (layers, shapes, dtypes, total params, sample weights). Parses
// the .pt torch-free via the embedded python script, so a .pt (opaque binary) is
// legible in the UI without downloading it.
func (s *Server) getFinalModelSummary(w http.ResponseWriter, r *http.Request) {
	abs, filename, ok := s.resolveModelFile(w, r)
	if !ok {
		return
	}

	// Write the embedded inspector to a temp file and run it with python3.
	tmp, err := os.CreateTemp("", "inspect_model_*.py")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(inspectModelPy); err != nil {
		tmp.Close()
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	tmp.Close()

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "python3", tmp.Name(), abs).Output()
	if err != nil {
		msg := err.Error()
		if ee, okc := err.(*exec.ExitError); okc && len(ee.Stderr) > 0 {
			msg = string(ee.Stderr)
		}
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "PARSE_FAILED", "message": clip(msg, 500),
		})
		return
	}
	if !json.Valid(out) {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "PARSE_FAILED", "message": "inspector returned invalid JSON"})
		return
	}

	m := modelFileRe.FindStringSubmatch(filename)
	round := 0
	session := ""
	if m != nil {
		session = m[1]
		round, _ = strconv.Atoi(m[2])
	}
	writeJSON(w, http.StatusOK, j{
		"status": "SUCCESS", "session_id": session, "round": round, "file": filename,
		"summary": json.RawMessage(out),
	})
}
