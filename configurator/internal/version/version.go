package version

import (
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	Version string
	Commit  string
	Date    string
)

func init() {
	if Version == "" {
		Version = DefaultVersion()
	}
	if Commit == "" {
		Commit = strings.TrimSpace(os.Getenv("GITHUB_SHA"))
	}
	if Date == "" {
		Date = defaultDate()
	}
}

func defaultDate() string {
	if startedAt := strings.TrimSpace(os.Getenv("GITHUB_RUN_STARTED_AT")); startedAt != "" {
		if ts, err := time.Parse(time.RFC3339, startedAt); err == nil {
			return ts.UTC().Format("2006-01-02")
		}
		return startedAt
	}
	return time.Now().UTC().Format("2006-01-02")
}

func DefaultVersion() string {
	if v := strings.TrimSpace(os.Getenv("APP_VERSION")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("VERSION")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("GITHUB_REF_NAME")); v != "" && strings.HasPrefix(v, "v") {
		return v
	}
	if runNumber := strings.TrimSpace(os.Getenv("GITHUB_RUN_NUMBER")); runNumber != "" {
		return fmt.Sprintf("0.0.0-%s.%s", time.Now().UTC().Format("20060102"), runNumber)
	}
	return fmt.Sprintf("dev-%s", time.Now().UTC().Format("20060102"))
}

func String() string {
	if Version == "" {
		return DefaultVersion()
	}
	return Version
}

func FullString() string {
	version := String()
	suffixes := make([]string, 0, 2)
	if Commit != "" {
		suffixes = append(suffixes, "commit "+Commit[:min(len(Commit), 7)])
	}
	if Date != "" {
		suffixes = append(suffixes, "date "+Date)
	}
	if len(suffixes) == 0 {
		return version
	}
	return fmt.Sprintf("%s (%s)", version, strings.Join(suffixes, ", "))
}
