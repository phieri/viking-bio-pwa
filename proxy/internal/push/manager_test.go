package push_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

func TestVAPIDKeyGeneration(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	mgr, err := push.New(dir, "test@example.com", store)
	if err != nil {
		t.Fatalf("push.New: %v", err)
	}
	key := mgr.GetVapidPublicKey()
	if key == "" {
		t.Error("expected non-empty VAPID public key")
	}

	// Reload from disk – same key
	mgr2, err := push.New(dir, "test@example.com", store)
	if err != nil {
		t.Fatalf("push.New reload: %v", err)
	}
	if mgr2.GetVapidPublicKey() != key {
		t.Errorf("reloaded key differs: %q vs %q", mgr2.GetVapidPublicKey(), key)
	}
}

func TestSubscriptionAddRemove(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	mgr, err := push.New(dir, "test@example.com", store)
	if err != nil {
		t.Fatalf("push.New: %v", err)
	}

	if mgr.GetSubscriptionCount() != 0 {
		t.Errorf("expected 0 subscriptions, got %d", mgr.GetSubscriptionCount())
	}

	prefs := storage.Prefs{Flame: true, Error: true, Clean: false}
	ok, err := mgr.AddSubscription("https://example.com/push/1", "key1", "auth1", prefs)
	if err != nil {
		t.Fatalf("AddSubscription returned error: %v", err)
	}
	if !ok {
		t.Error("AddSubscription returned false unexpectedly")
	}
	if mgr.GetSubscriptionCount() != 1 {
		t.Errorf("expected 1 subscription, got %d", mgr.GetSubscriptionCount())
	}

	mgr.RemoveSubscription("https://example.com/push/1")
	if mgr.GetSubscriptionCount() != 0 {
		t.Errorf("expected 0 subscriptions after remove, got %d", mgr.GetSubscriptionCount())
	}
}

func TestSubscriptionRejectsInvalidEndpoint(t *testing.T) {
	tests := []string{
		"http://127.0.0.1/push/1",
		"https://192.168.0.10/push/1",
		"https://device.local/push/1",
	}

	for _, endpoint := range tests {
		t.Run(endpoint, func(t *testing.T) {
			dir := t.TempDir()
			store, err := storage.NewStore(dir)
			if err != nil {
				t.Fatalf("storage: %v", err)
			}
			mgr, err := push.New(dir, "test@example.com", store)
			if err != nil {
				t.Fatalf("push.New: %v", err)
			}

			ok, err := mgr.AddSubscription(endpoint, "k", "a", storage.Prefs{})
			if !errors.Is(err, push.ErrInvalidSubscriptionEndpoint) {
				t.Fatalf("expected invalid endpoint error, got %v", err)
			}
			if ok {
				t.Error("expected invalid endpoint to be rejected")
			}
		})
	}
}

func TestSubscriptionCapacity(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	mgr, err := push.New(dir, "test@example.com", store)
	if err != nil {
		t.Fatalf("push.New: %v", err)
	}

	prefs := storage.Prefs{Flame: true}
	for i := 0; i < storage.MaxSubscriptions; i++ {
		ep := fmt.Sprintf("https://example.com/push/%d", i)
		ok, err := mgr.AddSubscription(ep, "k", "a", prefs)
		if err != nil {
			t.Fatalf("expected AddSubscription to succeed at index %d: %v", i, err)
		}
		if !ok {
			t.Fatalf("expected AddSubscription to succeed at index %d", i)
		}
	}
	// One more should fail
	ok, err := mgr.AddSubscription("https://example.com/push/overflow", "k", "a", prefs)
	if err != nil {
		t.Fatalf("expected AddSubscription capacity check to return no error: %v", err)
	}
	if ok {
		t.Error("expected AddSubscription to return false when full")
	}
}
