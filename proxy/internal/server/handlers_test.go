package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/phieri/viking-bio-pwa/proxy/internal/server"
)

func newTestHandlers(t *testing.T) *server.Handlers {
	t.Helper()
	return server.NewHandlers(nil)
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

func TestGetDataReturnsStateSnapshot(t *testing.T) {
	h := newTestHandlers(t)
	resp := getReq(t, h.HandleGetData)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	m := decodeJSON(t, resp)
	if _, ok := m["flame"]; !ok {
		t.Fatalf("expected state snapshot JSON, got %#v", m)
	}
}
