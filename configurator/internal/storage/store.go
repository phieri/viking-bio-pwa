/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package storage

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/phieri/viking-bio-pwa/configurator/internal/config"
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
// The directory is created if it does not exist. A default viking-bio.conf is
// created only when the file is absent; an existing file is never reset.
func NewStore(dataDir string) (*Store, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		dataDir = config.DefaultDataDir()
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(dataDir, "viking-bio.conf")
	if err := ensureConfigTemplate(cfgPath); err != nil {
		return nil, err
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

func ensureConfigTemplate(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if info.Mode().IsRegular() && info.Size() > 0 {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	conf := `# Viking Bio Configurator configuration
# Copy or edit this file, then restart the configurator.
# Lines starting with '#' are comments. Uncommented lines set a value.
# Environment variables always take precedence over values in this file.

# Port for framed telemetry ingest from the Pico bridge (default: 9000)
# INGEST_TCP_PORT=9000

# Set to 1/true to require TLS on the ingest listener.
# Requires TLS_CERT_PATH and TLS_KEY_PATH.
# INGEST_TCP_TLS=0

# Optional manual TLS for the ingest listener.
# TLS_CERT_PATH=/etc/ssl/certs/server.crt
# TLS_KEY_PATH=/etc/ssl/private/server.key

# Device provisioning stores per-device secrets in devices.json here.
# DATA_DIR=/var/lib/viking-bio-configurator
`
	return os.WriteFile(path, []byte(conf), 0o644)
}
