package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/phieri/viking-bio-pwa/configurator/internal/storage"
)

func TestLoadDotEnvDoesNotOverwriteExistingValues(t *testing.T) {
	t.Setenv("TEST_KEY", "existing-value")

	cfgPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(cfgPath, []byte("TEST_KEY=from-file\nOTHER_KEY=from-file\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	loadDotEnv(cfgPath)

	if got := os.Getenv("TEST_KEY"); got != "existing-value" {
		t.Fatalf("existing env var should not be overwritten, got %q", got)
	}
	if got := os.Getenv("OTHER_KEY"); got != "from-file" {
		t.Fatalf("new env var should be loaded, got %q", got)
	}
}

func TestNewStoreCreatesDefaultConfigWhenMissing(t *testing.T) {
	dir := t.TempDir()

	if _, err := storage.NewStore(dir); err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	cfgPath := filepath.Join(dir, "viking-bio.conf")
	content, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read created config: %v", err)
	}
	if len(content) == 0 || !contains(content, "INGEST_TCP_PORT") {
		t.Fatalf("created config should contain the default template, got %q", string(content))
	}
}

func TestNewStorePreservesExistingConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "viking-bio.conf")
	want := "INGEST_TCP_PORT=9123\n"
	if err := os.WriteFile(cfgPath, []byte(want), 0o600); err != nil {
		t.Fatalf("write existing config: %v", err)
	}
	if _, err := storage.NewStore(dir); err != nil {
		t.Fatalf("NewStore on existing config: %v", err)
	}
	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config after NewStore: %v", err)
	}
	if string(got) != want {
		t.Fatalf("existing config should be preserved, got %q", string(got))
	}
}

func contains(b []byte, want string) bool {
	return bytes.Contains(b, []byte(want))
}
