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
	mu           sync.RWMutex
	dataDir      string
	path         string
	devicesPath  string
	fallbackPath string
	subs         []Subscription
	devices      map[string]DeviceRecord
}

// NewStore creates a Store backed by the given file path.
// The data directory is created if it does not exist.
func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(dataDir, "viking-bio.conf")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		conf := `# Viking Bio Proxy configuration
# Copy or edit this file, then restart the proxy.
# Lines starting with '#' are comments. Uncommented lines set a value.
# Environment variables always take precedence over values in this file.

# Port for the HTTP/HTTPS dashboard server (default: 3000)
# HTTP_PORT=3000

# Port for framed telemetry ingest from the Pico bridge (default: 9000)
# INGEST_TCP_PORT=9000

# Set to 1/true to require TLS on the ingest listener.
# Requires TLS_CERT_PATH and TLS_KEY_PATH.
# INGEST_TCP_TLS=0

# Webhook authentication token – the Pico bridge must send this in X-Hook-Auth.
# Set to a strong random string in production; leave empty to disable auth.
# MACHINE_WEBHOOK_AUTH_TOKEN=

# ---------------------------------------------------------------------------
# Automatic HTTPS via DuckDNS + Let's Encrypt (recommended for production)
# ---------------------------------------------------------------------------
# DDNS_SUBDOMAIN=my-viking-bio
# DDNS_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# ACME_EMAIL=admin@example.com
# ACME_STAGING=1

# ---------------------------------------------------------------------------
# Manual HTTPS with a user-supplied certificate (alternative to DDNS above)
# ---------------------------------------------------------------------------
# TLS_CERT_PATH=/etc/ssl/certs/server.crt
# TLS_KEY_PATH=/etc/ssl/private/server.key

# ---------------------------------------------------------------------------
# Data directory (VAPID keys, subscriptions, ACME cache)
# ---------------------------------------------------------------------------
# Device provisioning stores per-device secrets in devices.json here.
# DATA_DIR=/var/lib/viking-bio-proxy
`
		// Writing the config template is best-effort: a failure (e.g. read-only
		// filesystem) should not prevent the proxy from starting up.
		if err := os.WriteFile(cfgPath, []byte(conf), 0o644); err != nil {
			log.Printf("storage: failed to write %s: %v", cfgPath, err)
		}
	}
	s := &Store{
		dataDir:      dataDir,
		path:         filepath.Join(dataDir, "subscriptions.json"),
		devicesPath:  filepath.Join(dataDir, "devices.json"),
		fallbackPath: filepath.Join(dataDir, "ingest-fallback.log"),
		devices:      make(map[string]DeviceRecord),
	}
	s.load()
	s.loadDevices()
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
	if err := writeAtomicJSON(s.path, s.subs, 0o644); err != nil {
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
