/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Config holds all runtime configuration parsed from environment variables.
type Config struct {
	IngestTCPPort  int
	IngestTCPTLS   bool
	TLSCertPath    string
	TLSKeyPath     string
	MDNSName       string
	MDNSDisable    bool
	PicoSerialPort string
	DataDir        string
}

func parsePort(name, val string, def int) (int, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return def, nil
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%s must be a port number (1-65535), got %q", name, val)
	}
	return n, nil
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func parseBool(val string) bool {
	switch strings.TrimSpace(strings.ToLower(val)) {
	case "1", "true", "t", "yes", "y", "on", "enabled":
		return true
	default:
		return false
	}
}

// DefaultDataDir returns the data directory path using DATA_DIR env var, falling
// back to ~/.viking-bio-bridge on Linux or <exe_dir>/data otherwise (using
// ./data when the binary lives under /tmp).
func DefaultDataDir() string {
	if dir := strings.TrimSpace(os.Getenv("DATA_DIR")); dir != "" {
		return dir
	}
	if runtime.GOOS == "linux" {
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			return filepath.Join(home, ".viking-bio-bridge")
		}
	}
	base := exeDir()
	if runtime.GOOS != "windows" && strings.HasPrefix(base, "/tmp") {
		base = "."
	}
	return filepath.Join(base, "data")
}

// exeDir returns the directory containing the running executable.
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	ingestTCPPort, err := parsePort("INGEST_TCP_PORT", strings.TrimSpace(os.Getenv("INGEST_TCP_PORT")), 9000)
	if err != nil {
		return nil, err
	}
	dataDir := strings.TrimSpace(DefaultDataDir())
	if dataDir == "" {
		dataDir = "."
	}

	mdnsName := firstNonEmptyEnv("MDNS_NAME")
	if mdnsName == "" {
		mdnsName = "Viking Bio Configurator"
	}

	return &Config{
		IngestTCPPort:  ingestTCPPort,
		IngestTCPTLS:   parseBool(os.Getenv("INGEST_TCP_TLS")),
		TLSCertPath:    strings.TrimSpace(os.Getenv("TLS_CERT_PATH")),
		TLSKeyPath:     strings.TrimSpace(os.Getenv("TLS_KEY_PATH")),
		MDNSName:       mdnsName,
		MDNSDisable:    parseBool(os.Getenv("MDNS_DISABLE")),
		PicoSerialPort: strings.TrimSpace(os.Getenv("PICO_SERIAL_PORT")),
		DataDir:        dataDir,
	}, nil
}
