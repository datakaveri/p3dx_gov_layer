package db

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// apdClient talks to the APD service, which is the store of record for the FL
// forms (output-owner submissions and data-provider forms). The gov layer owns
// the form struct shapes and ships/receives them as the opaque `doc` field, so
// the DB form methods keep their signatures and callers are unchanged.
type apdClient struct {
	baseURL string
	http    *http.Client
}

func newAPDClient(baseURL string) *apdClient {
	return &apdClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// do performs an HTTP request against the APD and returns the status + raw body.
func (a *apdClient) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}

// upsertSubmission stores (upsert on form_id) an output-owner form; returns the id.
func (a *apdClient) upsertSubmission(ctx context.Context, id, formID, outputOwnerID string, hasOwnerIP bool, selectedProviders, doc json.RawMessage) (string, error) {
	reqBody := map[string]any{
		"id":                 id,
		"form_id":            formID,
		"output_owner_id":    outputOwnerID,
		"has_owner_ip":       hasOwnerIP,
		"selected_providers": selectedProviders,
		"doc":                doc,
	}
	code, data, err := a.do(ctx, http.MethodPost, "/internal/gov-forms/submissions", reqBody)
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("apd upsertSubmission: status %d: %s", code, data)
	}
	var r struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return "", err
	}
	return r.ID, nil
}

// listSubmissions returns every output-owner form, newest first.
func (a *apdClient) listSubmissions(ctx context.Context) ([]FormSubmission, error) {
	code, data, err := a.do(ctx, http.MethodGet, "/internal/gov-forms/submissions", nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("apd listSubmissions: status %d: %s", code, data)
	}
	var r struct {
		Submissions []FormSubmission `json:"submissions"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return r.Submissions, nil
}

// getSubmission returns one output-owner form, or (nil, nil) when not found.
func (a *apdClient) getSubmission(ctx context.Context, id string) (*FormSubmission, error) {
	code, data, err := a.do(ctx, http.MethodGet, "/internal/gov-forms/submissions/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, nil
	}
	if code >= 300 {
		return nil, fmt.Errorf("apd getSubmission: status %d: %s", code, data)
	}
	var r struct {
		Submission *FormSubmission `json:"submission"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return r.Submission, nil
}

// deleteSubmission deletes one output-owner form and reports whether it existed.
func (a *apdClient) deleteSubmission(ctx context.Context, id string) (bool, error) {
	code, data, err := a.do(ctx, http.MethodDelete, "/internal/gov-forms/submissions/"+url.PathEscape(id), nil)
	if err != nil {
		return false, err
	}
	if code >= 300 {
		return false, fmt.Errorf("apd deleteSubmission: status %d: %s", code, data)
	}
	var r struct {
		Deleted bool `json:"deleted"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return false, err
	}
	return r.Deleted, nil
}

// latestSubmissionForProvider returns the newest submission with an owner ip that
// lists the given provider, or (nil, nil) when none.
func (a *apdClient) latestSubmissionForProvider(ctx context.Context, username string) (*FormSubmission, error) {
	code, data, err := a.do(ctx, http.MethodGet, "/internal/gov-forms/submissions/latest-for-provider/"+url.PathEscape(username), nil)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, nil
	}
	if code >= 300 {
		return nil, fmt.Errorf("apd latestSubmissionForProvider: status %d: %s", code, data)
	}
	var r struct {
		Submission *FormSubmission `json:"submission"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return r.Submission, nil
}

// insertProviderForm stores a data-provider form; returns the id.
func (a *apdClient) insertProviderForm(ctx context.Context, id, formID, dataOwnerID string, doc json.RawMessage) (string, error) {
	reqBody := map[string]any{
		"id":            id,
		"form_id":       formID,
		"data_owner_id": dataOwnerID,
		"doc":           doc,
	}
	code, data, err := a.do(ctx, http.MethodPost, "/internal/gov-forms/provider-forms", reqBody)
	if err != nil {
		return "", err
	}
	if code >= 300 {
		return "", fmt.Errorf("apd insertProviderForm: status %d: %s", code, data)
	}
	var r struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return "", err
	}
	return r.ID, nil
}

// listProviderForms returns every data-provider form, newest first.
func (a *apdClient) listProviderForms(ctx context.Context) ([]DataProviderForm, error) {
	code, data, err := a.do(ctx, http.MethodGet, "/internal/gov-forms/provider-forms/all", nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("apd listProviderForms: status %d: %s", code, data)
	}
	var r struct {
		Forms []DataProviderForm `json:"forms"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return r.Forms, nil
}

// providerFormsByUsernames returns the latest data-provider form per username.
func (a *apdClient) providerFormsByUsernames(ctx context.Context, usernames []string) ([]DataProviderForm, error) {
	if len(usernames) == 0 {
		return []DataProviderForm{}, nil
	}
	q := url.Values{}
	q.Set("usernames", strings.Join(usernames, ","))
	code, data, err := a.do(ctx, http.MethodGet, "/internal/gov-forms/provider-forms?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if code >= 300 {
		return nil, fmt.Errorf("apd providerFormsByUsernames: status %d: %s", code, data)
	}
	var r struct {
		Forms []DataProviderForm `json:"forms"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return r.Forms, nil
}
