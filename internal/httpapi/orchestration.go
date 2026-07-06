package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// safeID restricts submission/form ids that get embedded in a shell-out.
var safeID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Section-aware client_config.yaml editors (mirror renderClientConfig()).
var (
	sectionRe  = regexp.MustCompile(`^( {2})([A-Za-z_]+):\s*(#.*)?$`)
	hostKVRe   = regexp.MustCompile(`^(\s*host:\s+)(\S+)(\s*(?:#.*)?)$`)
	brokerKVRe = regexp.MustCompile(`^(\s*broker_host:\s+)(\S+)(\s*(?:#.*)?)$`)
)

// targetResult is one per-provider fan-out outcome (ip/port are nullable to match
// the Node skipped-target shape).
type targetResult struct {
	Username string `json:"username"`
	IP       any    `json:"ip"`
	Port     any    `json:"port"`
	URL      string `json:"url,omitempty"`
	Status   string `json:"status"`
	HTTP     int    `json:"http,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// fanResult is the aggregate of a provider fan-out.
type fanResult struct {
	Status  string         `json:"status"`
	Error   string         `json:"error,omitempty"`
	Message string         `json:"message,omitempty"`
	Summary map[string]int `json:"summary"`
	Results []targetResult `json:"results"`
}

// receiverResp captures the fields gov_layer reads from a receiver's JSON reply.
type receiverResp struct {
	Status                string `json:"status"`
	Stage                 string `json:"stage"`
	EnvPath               string `json:"env_path"`
	RequirementsInstalled bool   `json:"requirements_installed"`
	Detail                string `json:"detail"`
	Message               string `json:"message"`
	Pid                   any    `json:"pid"`
	Log                   string `json:"log"`
}

// ownerResult is the outcome of an owner-receiver call.
type ownerResult struct {
	OK        bool
	URL       string
	EnvPath   string
	Installed bool
	Pid       any
	Log       string
	Stage     string
	Detail    string
}

// ---- low-level HTTP + helpers -------------------------------------------------

// postReceiver POSTs body to url with headers and a per-call timeout, returning
// (status, bodyText, err).
func (s *Server) postReceiver(ctx context.Context, url string, headers map[string]string, body []byte, timeout time.Duration) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func readFileOrEmpty(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// ownerBaseURL is the owner receiver base URL from their form (ip:port), with a
// self IP rewritten to loopback; falls back to OWNER_ENV_RECEIVER_FALLBACK when
// the form carries no ip/port. Mirrors ownerBaseUrl().
func (s *Server) ownerBaseURL(sub *db.FormSubmission) string {
	ip := sub.IP()
	if ip != "" && sub.Port != nil && *sub.Port != 0 {
		return fmt.Sprintf("http://%s:%d", s.self.reachableHost(ip), *sub.Port)
	}
	return s.cfg.OwnerEnvReceiverFallback
}

// renderClientConfig writes ownerIp into comm_config.grpc_discovery.host and
// comm_config.mqtt_discovery.broker_host, preserving every other line. Mirrors
// renderClientConfig().
func renderClientConfig(src, ownerIP string) string {
	lines := strings.Split(src, "\n")
	section := ""
	for i, line := range lines {
		if m := sectionRe.FindStringSubmatch(line); m != nil {
			section = m[2]
			continue
		}
		switch section {
		case "grpc_discovery":
			if kv := hostKVRe.FindStringSubmatch(line); kv != nil {
				lines[i] = kv[1] + ownerIP + kv[3]
			}
		case "mqtt_discovery":
			if kv := brokerKVRe.FindStringSubmatch(line); kv != nil {
				lines[i] = kv[1] + ownerIP + kv[3]
			}
		}
	}
	return strings.Join(lines, "\n")
}

// sendRenderedConfig serves client_config.yaml rendered for a submission, or 409
// when the owner has no IP. Mirrors sendRenderedConfig().
func (s *Server) sendRenderedConfig(w http.ResponseWriter, sub *db.FormSubmission) {
	ownerIP := sub.IP()
	if ownerIP == "" {
		writeJSON(w, http.StatusConflict, j{
			"status": "FAILED", "error": "NO_OWNER_IP",
			"message": "The output owner has not set an IP address for this session yet.",
		})
		return
	}
	template, err := os.ReadFile(s.cfg.ClientConfigTemplate)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "TEMPLATE_NOT_FOUND", "message": err.Error(),
		})
		return
	}
	yaml := renderClientConfig(string(template), ownerIP)
	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="client_config.yaml"`)
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, yaml)
}

// providerTargets maps each selected username to its latest provider form.
func (s *Server) providerTargets(ctx context.Context, selected []string) (map[string]*db.DataProviderForm, error) {
	forms, err := s.db.GetDataProviderFormsByUsernames(ctx, selected)
	if err != nil {
		return nil, err
	}
	byUser := make(map[string]*db.DataProviderForm, len(forms))
	for i := range forms {
		f := &forms[i]
		if f.DataOwnerID != nil {
			byUser[*f.DataOwnerID] = f
		}
	}
	return byUser, nil
}

// fanOut runs fn for each selected username in parallel, preserving order.
func fanOut(selected []string, fn func(username string) targetResult) []targetResult {
	results := make([]targetResult, len(selected))
	var wg sync.WaitGroup
	for i, u := range selected {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			results[i] = fn(u)
		}(i, u)
	}
	wg.Wait()
	return results
}

func tally(results []targetResult, okStatus string) (ok, failed, skipped int) {
	for _, r := range results {
		switch r.Status {
		case okStatus:
			ok++
		case "failed":
			failed++
		case "skipped":
			skipped++
		}
	}
	return
}

func aggregateStatus(ok, failed int) string {
	switch {
	case ok > 0 && failed == 0:
		return "SUCCESS"
	case ok > 0:
		return "PARTIAL"
	default:
		return "FAILED"
	}
}

// ---- provider env provisioning ------------------------------------------------

// provisionProviders provisions a venv (+requirements) on each selected provider
// by POSTing to its receiver's /provision-env. Mirrors provisionProviders().
func (s *Server) provisionProviders(ctx context.Context, selected []string) (*fanResult, error) {
	requirements := readFileOrEmpty(s.cfg.ProvisionRequirements)
	reqNote := "none (empty venv)"
	if requirements != "" {
		reqNote = s.cfg.ProvisionRequirements
	}
	envNote := "receiver default (./venv)"
	if s.cfg.ProvisionEnvPath != "" {
		envNote = s.cfg.ProvisionEnvPath
	}
	log.Printf("[GOVERNANCE] provision: env=%s requirements=%s providers=%d", envNote, reqNote, len(selected))

	payload := map[string]any{"requirements": requirements}
	if s.cfg.ProvisionEnvPath != "" {
		payload["env_path"] = s.cfg.ProvisionEnvPath
	}
	body, _ := json.Marshal(payload)
	headers := s.kc.AuthHeaders(ctx, map[string]string{"Content-Type": "application/json"}, s.cfg.PushAuthToken)

	byUser, err := s.providerTargets(ctx, selected)
	if err != nil {
		return nil, err
	}

	results := fanOut(selected, func(username string) targetResult {
		f := byUser[username]
		if f == nil || f.IP() == "" || f.PortInt() == 0 {
			return targetResult{Username: username, IP: nullableIP(f), Port: nullablePort(f), Status: "skipped", Reason: "no registered ip/port"}
		}
		url := fmt.Sprintf("http://%s:%d%s", s.self.reachableHost(f.IP()), f.PortInt(), s.cfg.ProviderProvisionPath)
		status, detail, perr := s.postReceiver(ctx, url, headers, body, s.cfg.ProvisionTimeout)
		if perr != nil {
			return targetResult{Username: username, IP: f.IP(), Port: f.PortInt(), URL: url, Status: "failed", Reason: perr.Error()}
		}
		st := "failed"
		if status >= 200 && status < 300 {
			st = "ok"
		}
		return targetResult{Username: username, IP: f.IP(), Port: f.PortInt(), URL: url, Status: st, HTTP: status, Detail: clip(detail, 300)}
	})

	ok, failed, skipped := tally(results, "ok")
	return &fanResult{Status: aggregateStatus(ok, failed), Summary: map[string]int{"ok": ok, "failed": failed, "skipped": skipped}, Results: results}, nil
}

// ---- client config push -------------------------------------------------------

// renderAndPushClientConfig renders client_config.yaml with the owner IP and
// POSTs it to each selected provider's receiver. Mirrors renderAndPushClientConfig().
func (s *Server) renderAndPushClientConfig(ctx context.Context, sub *db.FormSubmission) *fanResult {
	empty := map[string]int{"sent": 0, "failed": 0, "skipped": 0}
	ownerIP := sub.IP()
	if ownerIP == "" {
		return &fanResult{Status: "FAILED", Error: "NO_OWNER_IP",
			Message: "The output owner has not set an IP address for this session yet.",
			Summary: empty, Results: []targetResult{}}
	}
	selected := selectedUsernames(sub)
	if len(selected) == 0 {
		return &fanResult{Status: "FAILED", Error: "NO_PROVIDERS",
			Message: "This session has no selected providers.", Summary: empty, Results: []targetResult{}}
	}
	template, err := os.ReadFile(s.cfg.ClientConfigTemplate)
	if err != nil {
		return &fanResult{Status: "FAILED", Error: "TEMPLATE_NOT_FOUND", Message: err.Error(), Summary: empty, Results: []targetResult{}}
	}
	yaml := []byte(renderClientConfig(string(template), ownerIP))

	byUser, err := s.providerTargets(ctx, selected)
	if err != nil {
		return &fanResult{Status: "FAILED", Error: "INTERNAL_ERROR", Message: err.Error(), Summary: empty, Results: []targetResult{}}
	}
	headers := s.kc.AuthHeaders(ctx, map[string]string{"Content-Type": "application/x-yaml"}, s.cfg.PushAuthToken)

	results := fanOut(selected, func(username string) targetResult {
		f := byUser[username]
		if f == nil || f.IP() == "" || f.PortInt() == 0 {
			return targetResult{Username: username, IP: nullableIP(f), Port: nullablePort(f), Status: "skipped", Reason: "no registered ip/port"}
		}
		url := fmt.Sprintf("http://%s:%d%s", s.self.reachableHost(f.IP()), f.PortInt(), s.cfg.ProviderReceiverPath)
		status, detail, perr := s.postReceiver(ctx, url, headers, yaml, s.cfg.PushTimeout)
		if perr != nil {
			return targetResult{Username: username, IP: f.IP(), Port: f.PortInt(), URL: url, Status: "failed", Reason: perr.Error()}
		}
		st := "failed"
		if status >= 200 && status < 300 {
			st = "sent"
		}
		return targetResult{Username: username, IP: f.IP(), Port: f.PortInt(), URL: url, Status: st, HTTP: status, Detail: clip(detail, 200)}
	})

	sent, failed, skipped := tally(results, "sent")
	return &fanResult{Status: aggregateStatus(sent, failed), Summary: map[string]int{"sent": sent, "failed": failed, "skipped": skipped}, Results: results}
}

func nullableIP(f *db.DataProviderForm) any {
	if f == nil || f.IP() == "" {
		return nil
	}
	return f.IP()
}

func nullablePort(f *db.DataProviderForm) any {
	if f == nil || f.PortInt() == 0 {
		return nil
	}
	return f.PortInt()
}

// ---- owner receiver calls -----------------------------------------------------

func (s *Server) ownerAuthHeaders(ctx context.Context) map[string]string {
	return s.kc.AuthHeaders(ctx, map[string]string{"Content-Type": "application/json"}, s.cfg.PushAuthToken)
}

func decodeReceiver(body string) receiverResp {
	var r receiverResp
	_ = json.Unmarshal([]byte(body), &r)
	return r
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// provisionOwnerEnv builds the owner FL env via its receiver's /provision-env.
// Mirrors provisionOwnerEnv().
func (s *Server) provisionOwnerEnv(ctx context.Context, sub *db.FormSubmission) ownerResult {
	url := s.ownerBaseURL(sub) + s.cfg.OwnerReceiverProvisionPath
	requirements := readFileOrEmpty(s.cfg.OwnerRequirements)
	body, _ := json.Marshal(map[string]any{"requirements": requirements})
	status, text, err := s.postReceiver(ctx, url, s.ownerAuthHeaders(ctx), body, s.cfg.ProvisionTimeout)
	if err != nil {
		return ownerResult{OK: false, URL: url, Stage: "receiver",
			Detail: fmt.Sprintf("output-owner env receiver unreachable at %s: %s", url, err.Error())}
	}
	data := decodeReceiver(text)
	if status < 200 || status >= 300 || data.Status != "provisioned" || data.EnvPath == "" {
		return ownerResult{OK: false, URL: url, Stage: firstNonEmpty(data.Stage, "receiver"),
			Detail: firstNonEmpty(data.Detail, data.Message, fmt.Sprintf("HTTP %d", status))}
	}
	return ownerResult{OK: true, URL: url, EnvPath: data.EnvPath, Installed: data.RequirementsInstalled}
}

// startOwnerServer launches flo_server.py on the owner via /start-server.
// Mirrors startOwnerServer().
func (s *Server) startOwnerServer(ctx context.Context, sub *db.FormSubmission) ownerResult {
	url := s.ownerBaseURL(sub) + s.cfg.OwnerReceiverStartServerPath
	status, text, err := s.postReceiver(ctx, url, s.ownerAuthHeaders(ctx), []byte("{}"), s.cfg.PushTimeout)
	if err != nil {
		return ownerResult{OK: false, URL: url,
			Detail: fmt.Sprintf("output-owner server receiver unreachable at %s: %s", url, err.Error())}
	}
	data := decodeReceiver(text)
	if status < 200 || status >= 300 || data.Status != "started" {
		return ownerResult{OK: false, URL: url, Detail: firstNonEmpty(data.Detail, data.Message, fmt.Sprintf("HTTP %d", status))}
	}
	return ownerResult{OK: true, URL: url, Pid: data.Pid, Log: data.Log}
}

// startOwnerSession runs flo_session.py on the owner via /start-session.
// Mirrors startOwnerSession().
func (s *Server) startOwnerSession(ctx context.Context, sub *db.FormSubmission) ownerResult {
	url := s.ownerBaseURL(sub) + s.cfg.OwnerReceiverStartSessionPath
	body, _ := json.Marshal(map[string]any{"config": s.cfg.FLSessionConfig, "server_endpoint": s.cfg.FLServerEndpoint})
	status, text, err := s.postReceiver(ctx, url, s.ownerAuthHeaders(ctx), body, s.cfg.PushTimeout)
	if err != nil {
		return ownerResult{OK: false, URL: url,
			Detail: fmt.Sprintf("output-owner session receiver unreachable at %s: %s", url, err.Error())}
	}
	data := decodeReceiver(text)
	if status < 200 || status >= 300 || data.Status != "started" {
		return ownerResult{OK: false, URL: url, Detail: firstNonEmpty(data.Detail, data.Message, fmt.Sprintf("HTTP %d", status))}
	}
	return ownerResult{OK: true, URL: url, Pid: data.Pid, Log: data.Log}
}

// ---- handlers -----------------------------------------------------------------

// readSubmissionID decodes { submission_id } and validates it against safeID.
// Returns (id, ok); on validation failure it has already written the response.
func (s *Server) readSubmissionID(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body struct {
		SubmissionID string `json:"submission_id"`
	}
	if !s.readBody(w, r, &body) {
		return "", false
	}
	if body.SubmissionID == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_SELECTOR", "message": "submission_id is required"})
		return "", false
	}
	if !safeID.MatchString(body.SubmissionID) {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_SUBMISSION_ID"})
		return "", false
	}
	return body.SubmissionID, true
}

// POST /provision-env — standalone provider provisioning.
func (s *Server) provisionEnv(w http.ResponseWriter, r *http.Request) {
	submissionID, ok := s.readSubmissionID(w, r)
	if !ok {
		return
	}
	ctx := context.Background()
	sub, err := s.db.GetFormSubmissionByID(ctx, submissionID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND", "message": "Submission not found"})
		return
	}
	selected := selectedUsernames(sub)
	if len(selected) == 0 {
		writeJSON(w, http.StatusOK, j{
			"status": "FAILED", "error": "NO_PROVIDERS",
			"message": "This session has no selected providers.",
			"summary": j{"ok": 0, "failed": 0, "skipped": 0}, "results": []any{},
		})
		return
	}
	result, err := s.provisionProviders(ctx, selected)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	log.Printf("[GOVERNANCE] provision-env %s: ok=%d failed=%d skipped=%d", submissionID, result.Summary["ok"], result.Summary["failed"], result.Summary["skipped"])
	writeJSON(w, http.StatusOK, result)
}

// POST /push-config — HTTP push of client_config.yaml to each provider.
func (s *Server) pushConfig(w http.ResponseWriter, r *http.Request) {
	submissionID, ok := s.readSubmissionID(w, r)
	if !ok {
		return
	}
	ctx := context.Background()
	sub, err := s.db.GetFormSubmissionByID(ctx, submissionID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND", "message": "Submission not found"})
		return
	}
	res := s.renderAndPushClientConfig(ctx, sub)
	code := http.StatusOK
	switch res.Error {
	case "NO_OWNER_IP":
		code = http.StatusConflict
	case "TEMPLATE_NOT_FOUND", "INTERNAL_ERROR":
		code = http.StatusInternalServerError
	}
	log.Printf("[GOVERNANCE] push-config %s: sent=%d failed=%d skipped=%d", submissionID, res.Summary["sent"], res.Summary["failed"], res.Summary["skipped"])
	writeJSON(w, code, res)
}

// POST /start-fl-session — bring up owner, provision providers, push config,
// start clients, then start the session. Mirrors start-fl-session.
func (s *Server) startFLSession(w http.ResponseWriter, r *http.Request) {
	submissionID, ok := s.readSubmissionID(w, r)
	if !ok {
		return
	}
	ctx := context.Background()
	sub, err := s.db.GetFormSubmissionByID(ctx, submissionID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND", "message": "Submission not found"})
		return
	}

	ownerURL := s.ownerBaseURL(sub)
	log.Printf("[GOVERNANCE] start-fl-session %s: output owner at %s", submissionID, ownerURL)

	// 1) OWNER ENV.
	ownerEnv := s.provisionOwnerEnv(ctx, sub)
	if !ownerEnv.OK {
		writeJSON(w, http.StatusBadGateway, j{
			"status": "FAILED", "error": "OWNER_ENV_FAILED", "stage": ownerEnv.Stage,
			"message": fmt.Sprintf("Output-owner env provisioning failed at %s (%s)", ownerEnv.Stage, ownerEnv.URL),
			"detail":  ownerEnv.Detail,
		})
		return
	}
	log.Printf("[GOVERNANCE] start-fl-session %s: owner env %s (requirements installed: %t)", submissionID, ownerEnv.EnvPath, ownerEnv.Installed)

	// 2) FLO_SERVER.
	server := s.startOwnerServer(ctx, sub)
	if !server.OK {
		writeJSON(w, http.StatusBadGateway, j{
			"status": "FAILED", "error": "SERVER_LAUNCH_FAILED",
			"message": fmt.Sprintf("Could not start flo_server.py on the output owner (%s)", server.URL),
			"detail":  server.Detail,
		})
		return
	}
	log.Printf("[GOVERNANCE] start-fl-session %s: flo_server pid=%v log=%s @ %s", submissionID, server.Pid, server.Log, ownerURL)

	// 3) PROVIDER ENV.
	selected := selectedUsernames(sub)
	provision, err := s.provisionProviders(ctx, selected)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	log.Printf("[GOVERNANCE] start-fl-session %s: provision ok=%d failed=%d skipped=%d", submissionID, provision.Summary["ok"], provision.Summary["failed"], provision.Summary["skipped"])

	// 3.5) PUSH CONFIG.
	pushConfig := s.renderAndPushClientConfig(ctx, sub)
	log.Printf("[GOVERNANCE] start-fl-session %s: push-config sent=%d failed=%d skipped=%d", submissionID, pushConfig.Summary["sent"], pushConfig.Summary["failed"], pushConfig.Summary["skipped"])

	// 4) START CLIENTS (after a short warmup so the server is accepting connections).
	time.Sleep(s.cfg.FLClientDelay)
	byUser, err := s.providerTargets(ctx, selected)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	headers := s.kc.AuthHeaders(ctx, map[string]string{"Content-Type": "application/json"}, s.cfg.PushAuthToken)
	clientResults := fanOut(selected, func(username string) targetResult {
		f := byUser[username]
		if f == nil || f.IP() == "" || f.PortInt() == 0 {
			return targetResult{Username: username, IP: nullableIP(f), Port: nullablePort(f), Status: "skipped", Reason: "no registered ip/port"}
		}
		url := fmt.Sprintf("http://%s:%d%s", s.self.reachableHost(f.IP()), f.PortInt(), s.cfg.ProviderStartClientPath)
		status, detail, perr := s.postReceiver(ctx, url, headers, []byte("{}"), s.cfg.PushTimeout)
		if perr != nil {
			return targetResult{Username: username, IP: f.IP(), Port: f.PortInt(), URL: url, Status: "failed", Reason: perr.Error()}
		}
		st := "failed"
		if status >= 200 && status < 300 {
			st = "started"
		}
		return targetResult{Username: username, IP: f.IP(), Port: f.PortInt(), URL: url, Status: st, HTTP: status, Detail: clip(detail, 200)}
	})
	cstarted, cfailed, cskipped := tally(clientResults, "started")
	log.Printf("[GOVERNANCE] start-fl-session %s: clients started=%d failed=%d skipped=%d", submissionID, cstarted, cfailed, cskipped)

	// 5) START SESSION (after clients register).
	log.Printf("[GOVERNANCE] start-fl-session %s: waiting %dms for clients to register before flo_session.py", submissionID, s.cfg.FLSessionDelay.Milliseconds())
	time.Sleep(s.cfg.FLSessionDelay)
	session := s.startOwnerSession(ctx, sub)
	waitedMS := s.cfg.FLSessionDelay.Milliseconds()

	var sessionObj j
	if session.OK {
		sessionObj = j{"status": "started", "pid": session.Pid, "log": session.Log, "server_endpoint": s.cfg.FLServerEndpoint, "waited_ms": waitedMS}
	} else {
		sessionObj = j{"status": "failed", "detail": session.Detail, "waited_ms": waitedMS}
	}

	writeJSON(w, http.StatusOK, j{
		"status":      "SUCCESS",
		"owner":       j{"url": ownerURL, "env_path": ownerEnv.EnvPath, "requirements_installed": ownerEnv.Installed},
		"server":      j{"pid": server.Pid, "log": server.Log, "url": server.URL},
		"provision":   j{"summary": provision.Summary, "results": provision.Results},
		"push_config": j{"status": pushConfig.Status, "summary": pushConfig.Summary, "results": pushConfig.Results},
		"clients":     j{"summary": j{"started": cstarted, "failed": cfailed, "skipped": cskipped}, "results": clientResults},
		"session":     sessionObj,
	})
}

// POST /distribute-config — render + scp client_config.yaml to providers via the
// send_output_owner_config.sh script. Mirrors distribute-config.
func (s *Server) distributeConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SubmissionID string `json:"submission_id"`
		FormID       string `json:"form_id"`
		AllProviders bool   `json:"all_providers"`
	}
	if !s.readBody(w, r, &body) {
		return
	}
	if body.SubmissionID == "" && body.FormID == "" {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "MISSING_SELECTOR", "message": "submission_id or form_id is required"})
		return
	}
	if body.SubmissionID != "" && !safeID.MatchString(body.SubmissionID) {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_SUBMISSION_ID"})
		return
	}
	if body.FormID != "" && !safeID.MatchString(body.FormID) {
		writeJSON(w, http.StatusBadRequest, j{"status": "FAILED", "error": "INVALID_FORM_ID"})
		return
	}

	args := []string{s.cfg.DistributeScript}
	if body.SubmissionID != "" {
		args = append(args, "--submission-id", body.SubmissionID)
	} else {
		args = append(args, "--form-id", body.FormID)
	}
	if body.AllProviders {
		args = append(args, "--all-providers")
	}
	log.Printf("[GOVERNANCE] distribute-config: bash %s", strings.Join(args, " "))

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", args...)
	out, runErr := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))

	// Final line: "Done. ok=N fail=M skipped(...)=K   configs in: ..."
	summaryRe := regexp.MustCompile(`ok=(\d+)\s+fail=(\d+)\s+skipped[^=]*=(\d+)`)
	m := summaryRe.FindStringSubmatch(output)
	var summary j
	if m != nil {
		summary = j{"sent": atoi(m[1]), "failed": atoi(m[2]), "skipped": atoi(m[3])}
	}

	// Non-zero exit is still useful as long as we parsed a summary; only a hard
	// error with no summary at all is a 500.
	if runErr != nil && summary == nil {
		log.Println("[GOVERNANCE] distribute-config failed:", runErr)
		writeJSON(w, http.StatusInternalServerError, j{
			"status": "FAILED", "error": "DISTRIBUTE_ERROR", "message": runErr.Error(), "output": output,
		})
		return
	}

	status := "PARTIAL"
	if summary != nil && summary["failed"] == 0 {
		status = "SUCCESS"
	}
	resp := j{"status": status, "summary": summary, "output": output}
	writeJSON(w, http.StatusOK, resp)
}

// GET /client-config/by-submission/{submissionId}
func (s *Server) clientConfigBySubmission(w http.ResponseWriter, r *http.Request) {
	sub, err := s.db.GetFormSubmissionByID(reqCtx(r), chi.URLParam(r, "submissionId"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, j{"status": "FAILED", "error": "NOT_FOUND", "message": "Submission not found"})
		return
	}
	s.sendRenderedConfig(w, sub)
}

// GET /client-config/{username}[?submission_id=...]
func (s *Server) clientConfigByUsername(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	submissionID := r.URL.Query().Get("submission_id")
	ctx := reqCtx(r)

	var sub *db.FormSubmission
	var err error
	if submissionID != "" {
		sub, err = s.db.GetFormSubmissionByID(ctx, submissionID)
	} else {
		sub, err = s.db.GetLatestSessionForProvider(ctx, username)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, j{
			"status": "FAILED", "error": "NO_SESSION",
			"message": "No FL session with an owner IP has selected this provider yet.",
		})
		return
	}
	selectedHere := false
	for _, p := range sub.SelectedProviderList() {
		if p.Username == username {
			selectedHere = true
			break
		}
	}
	if !selectedHere {
		writeJSON(w, http.StatusForbidden, j{
			"status": "FAILED", "error": "NOT_SELECTED",
			"message": "This provider is not part of the requested session.",
		})
		return
	}
	s.sendRenderedConfig(w, sub)
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
