package version

import (
	"strings"
	"testing"
)

func TestDefaultVersionUsesExplicitVersion(t *testing.T) {
	t.Setenv("APP_VERSION", "1.2.3")
	t.Setenv("VERSION", "")
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("GITHUB_RUN_NUMBER", "")

	if got := DefaultVersion(); got != "1.2.3" {
		t.Fatalf("DefaultVersion() = %q, want %q", got, "1.2.3")
	}
}

func TestDefaultVersionUsesGitHubBuildMetadata(t *testing.T) {
	t.Setenv("APP_VERSION", "")
	t.Setenv("VERSION", "")
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("GITHUB_RUN_NUMBER", "42")

	got := DefaultVersion()
	if !strings.HasPrefix(got, "0.0.0-") {
		t.Fatalf("DefaultVersion() = %q, want a zero-version build tag", got)
	}
	if !strings.HasSuffix(got, ".42") {
		t.Fatalf("DefaultVersion() = %q, want the GitHub Actions run number appended", got)
	}
}

func TestDefaultVersionFallsBackToDateStamp(t *testing.T) {
	t.Setenv("APP_VERSION", "")
	t.Setenv("VERSION", "")
	t.Setenv("GITHUB_REF_NAME", "")
	t.Setenv("GITHUB_RUN_NUMBER", "")

	got := DefaultVersion()
	if !strings.HasPrefix(got, "dev-") {
		t.Fatalf("DefaultVersion() = %q, want a dev date stamp", got)
	}
}
