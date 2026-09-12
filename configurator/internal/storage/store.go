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
// The directory is created if it does not exist.
func NewStore(dataDir string) (*Store, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		dataDir = config.DefaultDataDir()
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
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
