/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewStoreUsesConfiguredDefaultDir(t *testing.T) {
	t.Setenv("DATA_DIR", filepath.Join(t.TempDir(), "custom-data"))

	store, err := NewStore("   ")
	if err != nil {
		t.Fatalf("NewStore returned error: %v", err)
	}
	if store == nil {
		t.Fatal("NewStore returned nil store")
	}
	if store.dataDir == "" {
		t.Fatal("expected default dir to be set")
	}
	if _, err := os.Stat(store.dataDir); err != nil {
		t.Fatalf("default data dir was not created: %v", err)
	}
}

func TestNewStoreHandlesEmptyDevicesFile(t *testing.T) {
	for _, fixture := range []string{"", "null"} {
		t.Run("content="+fixture, func(t *testing.T) {
			dir := t.TempDir()
			devicesPath := filepath.Join(dir, "devices.json")
			if err := os.WriteFile(devicesPath, []byte(fixture), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			store, err := NewStore(dir)
			if err != nil {
				t.Fatalf("NewStore: %v", err)
			}
			if store == nil {
				t.Fatal("NewStore returned nil store")
			}
			if store.devices == nil {
				t.Fatal("expected devices map to be initialized")
			}
			if err := store.ProvisionDevice("pico-1234", "super-secret"); err != nil {
				t.Fatalf("ProvisionDevice: %v", err)
			}
			if record, ok := store.Device("pico-1234"); !ok || record.Key != "super-secret" {
				t.Fatalf("unexpected device record: %+v, ok=%v", record, ok)
			}
		})
	}
}
