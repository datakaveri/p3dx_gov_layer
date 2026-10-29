package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubPinger struct{ err error }

func (p stubPinger) Ping(context.Context) error { return p.err }

// GET /health is always 200; GET /ready follows the database ping.
func TestHealthRoutes(t *testing.T) {
	cases := []struct {
		name, path string
		ping       pinger
		wantCode   int
	}{
		{"health, db down", "/health", stubPinger{errors.New("down")}, http.StatusOK},
		{"ready, db up", "/ready", stubPinger{}, http.StatusOK},
		{"ready, db down", "/ready", stubPinger{errors.New("down")}, http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		s := newTestServer(nil)
		s.dbPing = c.ping
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		if rec.Code != c.wantCode {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.wantCode)
		}
		// Probes are mounted outside corsMiddleware.
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s: probe went through CORS", c.name)
		}
	}
}

// Mounting the probes in front of the API must not hide the existing routes.
func TestHealthRoutesKeepAPIRoutes(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer(nil).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/apis/spec", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/apis/spec: status %d, want 200", rec.Code)
	}
}
