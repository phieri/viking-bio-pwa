package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/server"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

func newTestHandlers(t *testing.T) *server.Handlers {
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
	return server.NewHandlers(mgr)
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
	h := newTestHandlers(t)
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

func TestGetData_ReturnsStateSnapshot(t *testing.T) {
	h := newTestHandlers(t)
	h.state.Flame = true
	h.state.Fan = 55
	h.state.Temp = 74
	h.state.Err = 3
	h.state.Valid = true
	h.state.FlameSecs = 456

	resp := getReq(t, h.HandleGetData)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["flame"] != true || m["fan"] != 55.0 || m["temp"] != 74.0 ||
		m["err"] != 3.0 || m["valid"] != true || m["flame_secs"] != 456.0 {
		t.Fatalf("unexpected response body: %#v", m)
	}
}

func TestSubscribe_Valid(t *testing.T) {
	h := newTestHandlers(t)
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

func FuzzHandleSubscribe(f *testing.F) {
	f.Add(`{"endpoint":"https://example.com","p256dh":"key","auth":"auth","prefs":{"flame":true}}`)
	f.Add(`{"endpoint":""}`)
	f.Add(`oops`)

	f.Fuzz(func(t *testing.T, body string) {
		h := newTestHandlers(t)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.HandleSubscribe(rr, req)
		if rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest {
			t.Fatalf("unexpected status code %d for body %q", rr.Code, body)
		}
	})
}
