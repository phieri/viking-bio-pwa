package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/server"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

func newTestHandlers(t *testing.T, cfg *config.Config) *server.Handlers {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	mgr, err := push.New(dir, "admin@test.local", store)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if cfg == nil {
		cfg = &config.Config{}
	}
	return server.NewHandlers(cfg, mgr)
}

func postJSON(t *testing.T, h http.HandlerFunc, body any, headers map[string]string) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr.Result()
}

func getReq(t *testing.T, h http.HandlerFunc) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr.Result()
}

func decodeJSON(t *testing.T, r *http.Response) map[string]any {
	t.Helper()
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode JSON: %v (body: %s)", err, body)
	}
	return m
}

func TestGetVapidKey_ProxySource(t *testing.T) {
	h := newTestHandlers(t, nil)
	resp := getReq(t, h.HandleGetVapidKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["source"] != "proxy" {
		t.Errorf("expected source=proxy, got %v", m["source"])
	}
	if m["key"] == "" || m["key"] == nil {
		t.Error("expected non-empty key")
	}
}

func TestSubscribe_Valid(t *testing.T) {
	h := newTestHandlers(t, nil)
	body := map[string]any{
		"endpoint": "https://example.com/push/test",
		"p256dh":   "p256dhkey",
		"auth":     "authkey",
		"prefs":    map[string]bool{"flame": true, "error": false, "clean": false},
	}
	resp := postJSON(t, h.HandleSubscribe, body, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", m["status"])
	}
}

func TestMachineData_ValidAuth(t *testing.T) {
	cfg := &config.Config{WebhookAuthToken: "secret123"}
	h := newTestHandlers(t, cfg)
	body := map[string]any{
		"flame": true,
		"fan":   50.0,
		"temp":  75.0,
		"err":   0.0,
		"valid": true,
	}
	resp := postJSON(t, h.HandleMachineData, body, map[string]string{
		"X-Hook-Auth": "secret123",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", m["status"])
	}
	if m["vapid_public_key"] == "" || m["vapid_public_key"] == nil {
		t.Error("expected non-empty vapid_public_key in machine data response")
	}
}

func TestMachineData_WrongToken(t *testing.T) {
	cfg := &config.Config{WebhookAuthToken: "secret123"}
	h := newTestHandlers(t, cfg)
	body := map[string]any{
		"flame": false,
		"fan":   0.0,
		"temp":  20.0,
		"err":   0.0,
		"valid": true,
	}
	resp := postJSON(t, h.HandleMachineData, body, map[string]string{
		"X-Hook-Auth": "wrongtoken",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestMachineData_InvalidBody(t *testing.T) {
	h := newTestHandlers(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"flame":true}`)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleMachineData(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestPicoForward_MockEndpoint(t *testing.T) {
	received := make(chan []byte, 1)
	mockPico := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- body
		if r.Header.Get("X-Hook-Auth") != "mytoken" {
			t.Errorf("expected X-Hook-Auth=mytoken, got %q", r.Header.Get("X-Hook-Auth"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockPico.Close()

	cfg := &config.Config{
		PicoBaseURL:          mockPico.URL,
		PicoForwardTimeoutMs: 2000,
		WebhookAuthToken:     "mytoken",
	}
	h := newTestHandlers(t, cfg)

	body := map[string]any{
		"endpoint": "https://example.com/push/fwd",
		"p256dh":   "key",
		"auth":     "auth",
		"prefs":    map[string]bool{"flame": true},
	}
	resp := postJSON(t, h.HandleSubscribe, body, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	select {
	case data := <-received:
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("mock pico: bad JSON: %v", err)
		}
		if m["endpoint"] != "https://example.com/push/fwd" {
			t.Errorf("forwarded wrong endpoint: %v", m["endpoint"])
		}
	case <-time.After(3 * time.Second):
		t.Error("timed out waiting for pico forward")
	}
}

func FuzzHandleMachineData(f *testing.F) {
	f.Add(`{"flame":true,"fan":50,"temp":75,"err":0,"valid":true}`)
	f.Add(`{"flame":false}`)
	f.Add(`not-json`)

	f.Fuzz(func(t *testing.T, body string) {
		h := newTestHandlers(t, nil)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.HandleMachineData(rr, req)
		if rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest {
			t.Fatalf("unexpected status code %d for body %q", rr.Code, body)
		}
	})
}

func FuzzHandleSubscribe(f *testing.F) {
	f.Add(`{"endpoint":"https://example.com","p256dh":"key","auth":"auth","prefs":{"flame":true}}`)
	f.Add(`{"endpoint":""}`)
	f.Add(`oops`)

	f.Fuzz(func(t *testing.T, body string) {
		h := newTestHandlers(t, nil)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.HandleSubscribe(rr, req)
		if rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest {
			t.Fatalf("unexpected status code %d for body %q", rr.Code, body)
		}
	})
}
