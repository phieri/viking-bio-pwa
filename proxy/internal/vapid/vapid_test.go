package vapid

import "testing"

func TestLoadOrGenerate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	first, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerate first call: %v", err)
	}
	if first.Public == "" || first.Private == "" {
		t.Fatal("expected generated key pair")
	}

	second, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerate second call: %v", err)
	}
	if second != first {
		t.Fatalf("expected key pair reload, got %#v want %#v", second, first)
	}
}
