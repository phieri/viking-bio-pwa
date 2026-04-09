package storage

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const MaxSubscriptions = 32

// Prefs holds per-subscriber notification preferences.
type Prefs struct {
	Flame bool `json:"flame"`
	Error bool `json:"error"`
	Clean bool `json:"clean"`
}

// Subscription is a single Web Push subscription record.
type Subscription struct {
	Endpoint string `json:"endpoint"`
	P256DH   string `json:"p256dh"`
	Auth     string `json:"auth"`
	Prefs    Prefs  `json:"prefs"`
}

// Store persists subscriptions to a JSON file with thread-safe access.
type Store struct {
	mu   sync.RWMutex
	path string
	subs []Subscription
}

// NewStore creates a Store backed by the given file path.
// The data directory is created if it does not exist.
func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dataDir, "subscriptions.json")}
	s.load()
	return s, nil
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Printf("storage: failed to read %s: %v", s.path, err)
		return
	}
	var subs []Subscription
	if err := json.Unmarshal(data, &subs); err != nil {
		log.Printf("storage: failed to parse subscriptions: %v", err)
		return
	}
	s.subs = subs
	log.Printf("storage: loaded %d subscription(s)", len(s.subs))
}

func (s *Store) save() {
	data, err := json.MarshalIndent(s.subs, "", "  ")
	if err != nil {
		log.Printf("storage: failed to marshal subscriptions: %v", err)
		return
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, "subscriptions-*.json")
	if err != nil {
		log.Printf("storage: failed to create temp file: %v", err)
		return
	}
	tmpName := tmp.Name()
	defer func() {
		if err := os.Remove(tmpName); err != nil && !os.IsNotExist(err) {
			log.Printf("storage: failed to remove temp file %s: %v", tmpName, err)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		log.Printf("storage: failed to write temp subscriptions: %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		log.Printf("storage: failed to close temp subscriptions: %v", err)
		return
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		log.Printf("storage: failed to chmod temp subscriptions: %v", err)
		return
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		log.Printf("storage: failed to write subscriptions: %v", err)
	}
}

// Add inserts or updates a subscription. Returns false if at capacity.
func (s *Store) Add(sub Subscription) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.subs {
		if existing.Endpoint == sub.Endpoint {
			s.subs[i] = sub
			s.save()
			return true
		}
	}
	if len(s.subs) >= MaxSubscriptions {
		log.Println("storage: subscription list full")
		return false
	}
	s.subs = append(s.subs, sub)
	s.save()
	log.Printf("storage: added subscription (total: %d)", len(s.subs))
	return true
}

// Remove deletes the subscription with the given endpoint.
func (s *Store) Remove(endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.subs)
	filtered := s.subs[:0]
	for _, sub := range s.subs {
		if sub.Endpoint != endpoint {
			filtered = append(filtered, sub)
		}
	}
	s.subs = filtered
	if len(s.subs) < before {
		s.save()
		log.Printf("storage: removed subscription (total: %d)", len(s.subs))
	}
}

// RemoveAll removes all subscriptions with the given endpoints.
func (s *Store) RemoveAll(endpoints []string) {
	if len(endpoints) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	set := make(map[string]struct{}, len(endpoints))
	for _, ep := range endpoints {
		set[ep] = struct{}{}
	}
	filtered := s.subs[:0]
	for _, sub := range s.subs {
		if _, found := set[sub.Endpoint]; !found {
			filtered = append(filtered, sub)
		}
	}
	removed := len(s.subs) - len(filtered)
	s.subs = filtered
	if removed > 0 {
		s.save()
		log.Printf("storage: removed %d expired subscription(s)", removed)
	}
}

// All returns a snapshot of all subscriptions.
func (s *Store) All() []Subscription {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Subscription, len(s.subs))
	copy(out, s.subs)
	return out
}

// Count returns the number of subscriptions.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subs)
}
