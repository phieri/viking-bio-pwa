package push

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

func TestNotifyByTypeLimitsConcurrentSends(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	mgr, err := New(dir, "test@example.com", store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mgr.notifySem = make(chan struct{}, 2)

	for i := 0; i < 4; i++ {
		if !mgr.AddSubscription(
			"https://example.com/"+time.Now().Add(time.Duration(i)*time.Second).String(),
			"key",
			"auth",
			storage.Prefs{Flame: true},
		) {
			t.Fatalf("expected subscription %d to be added", i)
		}
	}

	var active atomic.Int32
	var maxActive atomic.Int32
	var mu sync.Mutex
	mgr.sendNotification = func([]byte, *webpush.Subscription, *webpush.Options) (*http.Response, error) {
		current := active.Add(1)
		mu.Lock()
		if current > maxActive.Load() {
			maxActive.Store(current)
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		active.Add(-1)
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.NotifyByType("flame", "title", "body")
		}()
	}
	wg.Wait()

	if got := maxActive.Load(); got > 2 {
		t.Fatalf("expected at most 2 concurrent sends, got %d", got)
	}
}
