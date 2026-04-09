package ddns

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewReturnsNilWithoutCredentials(t *testing.T) {
	t.Parallel()

	if New("", "token") != nil {
		t.Fatal("expected nil client when subdomain is empty")
	}
	if New("subdomain", "") != nil {
		t.Fatal("expected nil client when token is empty")
	}
}

func TestUpdateUsesConfiguredHTTPClientAndAPIURL(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("domains"); got != "burner" {
			t.Fatalf("unexpected domains query: %q", got)
		}
		if got := r.URL.Query().Get("token"); got != "secret" {
			t.Fatalf("unexpected token query: %q", got)
		}
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := New("burner", "secret")
	client.apiURL = server.URL
	client.httpClient = server.Client()

	if err := client.update(); err != nil {
		t.Fatalf("update: %v", err)
	}
}

func TestStartPerformsImmediateUpdateAndStopStops(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := New("burner", "secret")
	client.apiURL = server.URL
	client.httpClient = server.Client()

	var hits atomic.Int32
	done := make(chan struct{}, 1)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("OK"))
		select {
		case done <- struct{}{}:
		default:
		}
	})

	client.Start()
	defer client.Stop()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial DDNS update")
	}

	client.Stop()
	count := hits.Load()
	time.Sleep(100 * time.Millisecond)
	if hits.Load() != count {
		t.Fatal("expected DDNS updates to stop after Stop")
	}
}
