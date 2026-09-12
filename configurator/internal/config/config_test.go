/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package config

import (
	"path/filepath"
	"runtime"
	"testing"
)

var configEnvKeys = []string{
	"INGEST_TCP_PORT",
	"INGEST_TCP_TLS",
	"TLS_CERT_PATH",
	"TLS_KEY_PATH",
	"MDNS_NAME",
	"MDNS_DISABLE",
	"PICO_SERIAL_PORT",
	"DATA_DIR",
}

func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range configEnvKeys {
		t.Setenv(key, "")
	}
}

func TestParsePort(t *testing.T) {
	t.Parallel()

	port, err := parsePort("INGEST_TCP_PORT", "", 9000)
	if err != nil || port != 9000 {
		t.Fatalf("expected default port 9000, got %d, err=%v", port, err)
	}

	port, err = parsePort("INGEST_TCP_PORT", "443", 9000)
	if err != nil || port != 443 {
		t.Fatalf("expected parsed port 443, got %d, err=%v", port, err)
	}

	if _, err := parsePort("INGEST_TCP_PORT", "0", 9000); err == nil {
		t.Fatal("expected invalid low port to fail")
	}
	if _, err := parsePort("INGEST_TCP_PORT", "70000", 9000); err == nil {
		t.Fatal("expected invalid high port to fail")
	}
	if _, err := parsePort("INGEST_TCP_PORT", "nope", 9000); err == nil {
		t.Fatal("expected non-numeric port to fail")
	}
}

func TestParseBool(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"1", "true", "TRUE", "TrUe", "yes", "YES", "on", "enabled"} {
		if !parseBool(input) {
			t.Fatalf("expected %q to parse as true", input)
		}
	}
	for _, input := range []string{"", "0", "false", "FALSE", "no", "off", "disabled"} {
		if parseBool(input) {
			t.Fatalf("expected %q to parse as false", input)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	clearConfigEnv(t)
	if runtime.GOOS == "linux" {
		t.Setenv("HOME", "/home/tester")
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	expectedDataDir := filepath.Join("/home/tester", ".viking-bio-bridge")
	if runtime.GOOS != "linux" {
		base := exeDir()
		if runtime.GOOS != "windows" && len(base) >= len("/tmp") && base[:len("/tmp")] == "/tmp" {
			base = "."
		}
		expectedDataDir = filepath.Join(base, "data")
	}

	if cfg.IngestTCPPort != 9000 {
		t.Fatalf("expected default ingest TCP port 9000, got %d", cfg.IngestTCPPort)
	}
	if cfg.IngestTCPTLS {
		t.Fatal("expected ingest TCP TLS to default to false")
	}
	if cfg.DataDir != expectedDataDir {
		t.Fatalf("unexpected default data dir: %q", cfg.DataDir)
	}
	if cfg.MDNSName != "Viking Bio Configurator" {
		t.Fatalf("unexpected default MDNS name: %q", cfg.MDNSName)
	}
}

func TestLoadOverrides(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("INGEST_TCP_PORT", "9443")
	t.Setenv("INGEST_TCP_TLS", "true")
	t.Setenv("TLS_CERT_PATH", "/cert.pem")
	t.Setenv("TLS_KEY_PATH", "/key.pem")
	t.Setenv("MDNS_NAME", "Custom Name")
	t.Setenv("MDNS_DISABLE", "1")
	t.Setenv("PICO_SERIAL_PORT", "/dev/ttyACM0")
	t.Setenv("DATA_DIR", "/data")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.IngestTCPPort != 9443 {
		t.Fatalf("unexpected numeric overrides: %+v", cfg)
	}
	if cfg.DataDir != "/data" || cfg.TLSCertPath != "/cert.pem" || cfg.TLSKeyPath != "/key.pem" {
		t.Fatalf("unexpected string overrides: %+v", cfg)
	}
	if cfg.MDNSName != "Custom Name" {
		t.Fatalf("unexpected MDNS overrides: %+v", cfg)
	}
	if !cfg.IngestTCPTLS || !cfg.MDNSDisable {
		t.Fatalf("expected boolean overrides to be true: %+v", cfg)
	}
}

func TestLoadTrimsWhitespace(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("INGEST_TCP_PORT", " 9443 ")
	t.Setenv("MDNS_NAME", "  Custom Name  ")
	t.Setenv("TLS_CERT_PATH", "  /cert.pem  ")
	t.Setenv("TLS_KEY_PATH", "  /key.pem  ")
	t.Setenv("PICO_SERIAL_PORT", "  /dev/ttyACM0  ")
	t.Setenv("DATA_DIR", "  /data  ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.IngestTCPPort != 9443 {
		t.Fatalf("expected trimmed port value to be parsed, got %d", cfg.IngestTCPPort)
	}
	if cfg.DataDir != "/data" || cfg.TLSCertPath != "/cert.pem" || cfg.TLSKeyPath != "/key.pem" || cfg.PicoSerialPort != "/dev/ttyACM0" {
		t.Fatalf("expected trimmed path values, got %+v", cfg)
	}
	if cfg.MDNSName != "Custom Name" {
		t.Fatalf("expected trimmed MDNS name, got %q", cfg.MDNSName)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("INGEST_TCP_PORT", "0")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid INGEST_TCP_PORT to fail")
	}
}
