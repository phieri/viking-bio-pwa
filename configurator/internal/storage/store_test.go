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
