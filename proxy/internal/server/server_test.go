package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

func TestMethodGuard_AllowsExpectedMethod(t *testing.T) {
	called := false
	handler := methodGuard(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Fatal("expected wrapped handler to be called")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func TestMethodGuard_RejectsUnexpectedMethod(t *testing.T) {
	called := false
	handler := methodGuard(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodPost, "/api/data", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if called {
		t.Fatal("expected wrapped handler not to be called")
	}
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestJSONMiddleware_AcceptsApplicationJSONWithCharset(t *testing.T) {
	called := false
	handler := jsonMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/subscribe", nil)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Fatal("expected wrapped handler to be called")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func TestJSONMiddleware_RejectsNonJSONContentType(t *testing.T) {
	called := false
	handler := jsonMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodPost, "/api/subscribe", nil)
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	handler(rr, req)

	if called {
		t.Fatal("expected wrapped handler not to be called")
	}
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", rr.Code)
	}
}

func TestBuildMux_DoesNotExposeLegacyMachineDataRoute(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	mgr, err := push.New(dir, "admin@test.local", store)
	if err != nil {
		t.Fatalf("push: %v", err)
	}

	srv := New(&config.Config{HTTPPort: 3000, IngestTCPPort: 9000}, mgr, store, false)
	req := httptest.NewRequest(http.MethodPost, "/api/machine-data", nil)
	rr := httptest.NewRecorder()
	srv.buildMux().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for removed route, got %d", rr.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body) != 1 {
		t.Fatalf("expected single-field error response, got %#v", body)
	}
	if body["error"] != "not found" {
		t.Fatalf("expected not found error, got %#v", body)
	}
}

func TestIsLocalNetwork(t *testing.T) {
	cases := []struct {
		addr  string
		local bool
	}{
		{"::1", true},
		{"[::1]:5000", true},
		{"fc00::1", true},
		{"[fe80::1]:80", true},
		{"2001:db8::1", false},
	}
	for _, tc := range cases {
		got := isLocalNetwork(tc.addr)
		if got != tc.local {
			t.Errorf("isLocalNetwork(%q) = %v, want %v", tc.addr, got, tc.local)
		}
	}
}

func TestLocalNetworkOnly_AllowsLocalIP(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := localNetworkOnly(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.RemoteAddr = "[fc00::1]:54321"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("expected inner handler to be called for local IP")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestLocalNetworkOnly_BlocksPublicIP(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	handler := localNetworkOnly(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.RemoteAddr = "[2001:db8::1]:54321"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Fatal("expected inner handler not to be called for public IP")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}
