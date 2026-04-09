package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
)

func testSubscription(endpoint string) Subscription {
	return Subscription{
		Endpoint: endpoint,
		P256DH:   "p256dh",
		Auth:     "auth",
		Prefs: Prefs{
			Flame: true,
			Error: true,
		},
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func TestStoreAddUpdateRemoveAndCount(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	sub := testSubscription("https://example.com/1")
	if !store.Add(sub) {
		t.Fatal("expected first add to succeed")
	}
	if store.Count() != 1 {
		t.Fatalf("expected count 1, got %d", store.Count())
	}

	updated := sub
	updated.Auth = "updated"
	if !store.Add(updated) {
		t.Fatal("expected update to succeed")
	}

	all := store.All()
	if len(all) != 1 || all[0].Auth != "updated" {
		t.Fatalf("expected single updated subscription, got %+v", all)
	}

	store.Remove(sub.Endpoint)
	if store.Count() != 0 {
		t.Fatalf("expected count 0 after remove, got %d", store.Count())
	}
}

func TestStoreLoadsPersistedSubscriptions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if !store.Add(testSubscription("https://example.com/persisted")) {
		t.Fatal("expected add to succeed")
	}

	reloaded, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore reload: %v", err)
	}
	all := reloaded.All()
	if len(all) != 1 || all[0].Endpoint != "https://example.com/persisted" {
		t.Fatalf("unexpected reloaded subscriptions: %+v", all)
	}
}

func TestStoreCapacityLimit(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	for i := 0; i < MaxSubscriptions; i++ {
		if !store.Add(testSubscription(fmt.Sprintf("https://example.com/%d", i))) {
			t.Fatalf("expected add %d to succeed", i)
		}
	}
	if store.Add(testSubscription("https://example.com/overflow")) {
		t.Fatal("expected overflow add to fail")
	}
}

func TestStoreRemoveAll(t *testing.T) {
	t.Parallel()

	store := newTestStore(t)
	endpoints := []string{
		"https://example.com/1",
		"https://example.com/2",
		"https://example.com/3",
	}
	for _, endpoint := range endpoints {
		if !store.Add(testSubscription(endpoint)) {
			t.Fatalf("expected add for %s to succeed", endpoint)
		}
	}

	store.RemoveAll(endpoints[:2])
	all := store.All()
	if len(all) != 1 || all[0].Endpoint != endpoints[2] {
		t.Fatalf("unexpected subscriptions after RemoveAll: %+v", all)
	}
}

func TestStoreConcurrentWritesKeepJSONValid(t *testing.T) {
	store := newTestStore(t)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			endpoint := fmt.Sprintf("https://example.com/%d", i)
			store.Add(testSubscription(endpoint))
			if i%2 == 0 {
				store.Remove(endpoint)
			}
		}()
	}
	wg.Wait()

	data, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var subs []Subscription
	if err := json.Unmarshal(data, &subs); err != nil {
		t.Fatalf("expected persisted JSON to remain valid, got %v", err)
	}
}
