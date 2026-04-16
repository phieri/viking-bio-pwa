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
	"github.com/phieri/viking-bio-pwa/proxy/internal/uptime"
)

func newTestHandlers(t *testing.T, uptimeAuthToken string) *server.Handlers {
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
	uptimeStore := uptime.NewStore(dir)
	return server.NewHandlers(mgr, uptimeStore, uptimeAuthToken)
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
	h := newTestHandlers(t, "")
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
	h := newTestHandlers(t, "")
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
		h := newTestHandlers(t, "")
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.HandleSubscribe(rr, req)
		if rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest {
			t.Fatalf("unexpected status code %d for body %q", rr.Code, body)
		}
	})
}

// --- Uptime handler tests ---------------------------------------------------

func TestPostUptimeBuckets_ValidBatch(t *testing.T) {
	h := newTestHandlers(t, "")
	body := map[string]any{
		"device_id": "pico-1",
		"source":    "pico",
		"buckets": []map[string]any{
			{"start": "2024-01-15T10:00:00Z", "duration_seconds": 300, "seconds_on": 200, "bucket_id": "b1"},
		},
	}
	resp := postJSON(t, h.HandlePostUptimeBuckets, body, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", m["status"])
	}
	if m["accepted"] != float64(1) {
		t.Errorf("expected accepted=1, got %v", m["accepted"])
	}
}

func TestPostUptimeBuckets_ValidDailySummary(t *testing.T) {
	h := newTestHandlers(t, "")
	body := map[string]any{
		"device_id":    "pico-1",
		"date":         "2024-01-15",
		"seconds_on":   7200,
		"sample_count": 24,
		"source":       "pwa",
	}
	resp := postJSON(t, h.HandlePostUptimeBuckets, body, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if m["accepted"] != float64(1) {
		t.Errorf("expected accepted=1, got %v", m["accepted"])
	}
}

func TestPostUptimeBuckets_MissingDeviceID(t *testing.T) {
	h := newTestHandlers(t, "")
	body := map[string]any{
		"buckets": []map[string]any{
			{"start": "2024-01-15T10:00:00Z", "duration_seconds": 300, "seconds_on": 200},
		},
	}
	resp := postJSON(t, h.HandlePostUptimeBuckets, body, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestPostUptimeBuckets_RequiresAuth(t *testing.T) {
	h := newTestHandlers(t, "secret")
	body := map[string]any{
		"device_id":  "pico-1",
		"date":       "2024-01-15",
		"seconds_on": 3600,
	}
	// No token → 401
	resp := postJSON(t, h.HandlePostUptimeBuckets, body, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	// Wrong token → 401
	resp = postJSON(t, h.HandlePostUptimeBuckets, body, map[string]string{
		"Authorization": "Bearer wrongtoken",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong token, got %d", resp.StatusCode)
	}
	// Correct token → 200
	resp = postJSON(t, h.HandlePostUptimeBuckets, body, map[string]string{
		"Authorization": "Bearer secret",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with correct token, got %d", resp.StatusCode)
	}
}

func TestGetUptimeDaily_RequiresDeviceID(t *testing.T) {
	h := newTestHandlers(t, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/uptime/daily", nil)
	rr := httptest.NewRecorder()
	h.HandleGetUptimeDaily(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestGetUptimeDaily_ReturnsEmptyForUnknownDevice(t *testing.T) {
	h := newTestHandlers(t, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/uptime/daily?device_id=unknown", nil)
	rr := httptest.NewRecorder()
	h.HandleGetUptimeDaily(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&out)
	sums, ok := out["summaries"].([]any)
	if !ok || len(sums) != 0 {
		t.Errorf("expected empty summaries array, got %v", out["summaries"])
	}
}

func TestPostThenGetUptimeDaily(t *testing.T) {
	h := newTestHandlers(t, "")
	// Post a daily summary
	postBody := map[string]any{
		"device_id":  "dev-42",
		"date":       "2024-06-15",
		"seconds_on": 14400,
		"source":     "pwa",
		"summary_id": "s1",
	}
	resp := postJSON(t, h.HandlePostUptimeBuckets, postBody, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post: expected 200, got %d", resp.StatusCode)
	}
	// Get it back
	req := httptest.NewRequest(http.MethodGet, "/api/v1/uptime/daily?device_id=dev-42", nil)
	rr := httptest.NewRecorder()
	h.HandleGetUptimeDaily(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", rr.Code)
	}
	var out struct {
		DeviceID  string `json:"device_id"`
		Summaries []struct {
			SecondsOn int    `json:"seconds_on"`
			Date      string `json:"date"`
		} `json:"summaries"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(out.Summaries))
	}
	if out.Summaries[0].SecondsOn != 14400 {
		t.Errorf("expected seconds_on=14400, got %d", out.Summaries[0].SecondsOn)
	}
}

func FuzzHandlePostUptimeBuckets(f *testing.F) {
	f.Add(`{"device_id":"pico","buckets":[{"start":"2024-01-01T00:00:00Z","duration_seconds":60,"seconds_on":30}]}`)
	f.Add(`{"device_id":"d","date":"2024-01-01","seconds_on":3600}`)
	f.Add(`{}`)
	f.Add(`not-json`)

	f.Fuzz(func(t *testing.T, body string) {
		h := newTestHandlers(t, "")
		req := httptest.NewRequest(http.MethodPost, "/api/v1/uptime/buckets", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.HandlePostUptimeBuckets(rr, req)
		if rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest && rr.Code != http.StatusInternalServerError {
			t.Fatalf("unexpected status %d for body %q", rr.Code, body)
		}
	})
}
