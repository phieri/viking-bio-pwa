package config

import (
	"path/filepath"
	"runtime"
	"testing"
)

var configEnvKeys = []string{
	"HTTP_PORT",
	"MACHINE_WEBHOOK_AUTH_TOKEN",
	"TLS_CERT_PATH",
	"TLS_KEY_PATH",
	"ACME_EMAIL",
	"ACME_STAGING",
	"ACME_CERT_DIR",
	"ACME_HTTP_PORT",
	"DDNS_SUBDOMAIN",
	"DDNS_TOKEN",
	"VAPID_CONTACT_EMAIL",
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

	port, err := parsePort("HTTP_PORT", "", 3000)
	if err != nil || port != 3000 {
		t.Fatalf("expected default port 3000, got %d, err=%v", port, err)
	}

	port, err = parsePort("HTTP_PORT", "443", 3000)
	if err != nil || port != 443 {
		t.Fatalf("expected parsed port 443, got %d, err=%v", port, err)
	}

	if _, err := parsePort("HTTP_PORT", "0", 3000); err == nil {
		t.Fatal("expected invalid low port to fail")
	}
	if _, err := parsePort("HTTP_PORT", "70000", 3000); err == nil {
		t.Fatal("expected invalid high port to fail")
	}
	if _, err := parsePort("HTTP_PORT", "nope", 3000); err == nil {
		t.Fatal("expected non-numeric port to fail")
	}
}

func TestParseBool(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"1", "true", "TRUE", "TrUe"} {
		if !parseBool(input) {
			t.Fatalf("expected %q to parse as true", input)
		}
	}
	for _, input := range []string{"", "0", "false", "yes"} {
		if parseBool(input) {
			t.Fatalf("expected %q to parse as false", input)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	clearConfigEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	base := exeDir()
	if runtime.GOOS != "windows" && len(base) >= len("/tmp") && base[:len("/tmp")] == "/tmp" {
		base = "."
	}

	if cfg.HTTPPort != 3000 {
		t.Fatalf("expected default HTTP port 3000, got %d", cfg.HTTPPort)
	}
	if cfg.ACMEHTTPPort != 80 {
		t.Fatalf("expected default ACME HTTP port 80, got %d", cfg.ACMEHTTPPort)
	}
	if cfg.DataDir != filepath.Join(base, "data") {
		t.Fatalf("unexpected default data dir: %q", cfg.DataDir)
	}
	if cfg.ACMECertDir != cfg.DataDir {
		t.Fatalf("expected ACME cert dir to default to data dir, got %q vs %q", cfg.ACMECertDir, cfg.DataDir)
	}
	if cfg.VAPIDContactEmail != "admin@viking-bio.local" {
		t.Fatalf("unexpected default VAPID email: %q", cfg.VAPIDContactEmail)
	}
	if cfg.MDNSName != "Viking Bio" {
		t.Fatalf("unexpected default MDNS name: %q", cfg.MDNSName)
	}
}

func TestLoadOverrides(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("HTTP_PORT", "3001")
	t.Setenv("MACHINE_WEBHOOK_AUTH_TOKEN", "secret")
	t.Setenv("TLS_CERT_PATH", "/cert.pem")
	t.Setenv("TLS_KEY_PATH", "/key.pem")
	t.Setenv("ACME_EMAIL", "acme@example.com")
	t.Setenv("ACME_STAGING", "true")
	t.Setenv("ACME_CERT_DIR", "/certs")
	t.Setenv("ACME_HTTP_PORT", "8080")
	t.Setenv("DDNS_SUBDOMAIN", "burner")
	t.Setenv("DDNS_TOKEN", "token")
	t.Setenv("VAPID_CONTACT_EMAIL", "push@example.com")
	t.Setenv("MDNS_NAME", "Custom Name")
	t.Setenv("MDNS_DISABLE", "1")
	t.Setenv("PICO_SERIAL_PORT", "/dev/ttyACM0")
	t.Setenv("DATA_DIR", "/data")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.HTTPPort != 3001 || cfg.ACMEHTTPPort != 8080 {
		t.Fatalf("unexpected numeric overrides: %+v", cfg)
	}
	if cfg.DataDir != "/data" || cfg.ACMECertDir != "/certs" {
		t.Fatalf("unexpected string overrides: %+v", cfg)
	}
	if !cfg.ACMEStaging || !cfg.MDNSDisable {
		t.Fatalf("expected boolean overrides to be true: %+v", cfg)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("HTTP_PORT", "0")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid HTTP_PORT to fail")
	}
}
