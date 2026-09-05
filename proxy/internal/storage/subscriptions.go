package storage

import (
	"log"
	"os"
	"path/filepath"
	"sync"
)

// Store persists runtime state for provisioned devices and ingest fallback logs.
type Store struct {
	mu           sync.RWMutex
	dataDir      string
	devicesPath  string
	fallbackPath string
	devices      map[string]DeviceRecord
}

// NewStore creates a Store backed by the given data directory.
// The directory is created if it does not exist.
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

# Optional manual HTTPS for the dashboard.
# TLS_CERT_PATH=/etc/ssl/certs/server.crt
# TLS_KEY_PATH=/etc/ssl/private/server.key

# Webhook notification target for burner alerts.
# WEBHOOK_URL=https://example.com/webhook

# Device provisioning stores per-device secrets in devices.json here.
# DATA_DIR=/var/lib/viking-bio-proxy
`
		if err := os.WriteFile(cfgPath, []byte(conf), 0o644); err != nil {
			log.Printf("storage: failed to write %s: %v", cfgPath, err)
		}
	}
	s := &Store{
		dataDir:      dataDir,
		devicesPath:  filepath.Join(dataDir, "devices.json"),
		fallbackPath: filepath.Join(dataDir, "ingest-fallback.log"),
		devices:      make(map[string]DeviceRecord),
	}
	s.loadDevices()
	return s, nil
}
