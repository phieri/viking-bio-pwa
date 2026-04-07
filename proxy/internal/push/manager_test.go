package push_test

import (
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
	ok := mgr.AddSubscription("https://example.com/push/1", "key1", "auth1", prefs)
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
		if !mgr.AddSubscription(ep, "k", "a", prefs) {
			t.Fatalf("expected AddSubscription to succeed at index %d", i)
		}
	}
	// One more should fail
	if mgr.AddSubscription("https://example.com/push/overflow", "k", "a", prefs) {
		t.Error("expected AddSubscription to return false when full")
	}
}
