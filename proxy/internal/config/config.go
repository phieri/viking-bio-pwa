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
	HTTPPort          int
	IngestTCPPort     int
	IngestTCPTLS      bool
	WebhookAuthToken  string
	TLSCertPath       string
	TLSKeyPath        string
	ACMEEmail         string
	ACMEStaging       bool
	ACMECertDir       string
	ACMEHTTPPort      int
	DDNSSubdomain     string
	DDNSToken         string
	VAPIDContactEmail string
	MDNSName          string
	MDNSDisable       bool
	PicoSerialPort    string
	DataDir           string
}

func parsePort(name, val string, def int) (int, error) {
	if val == "" {
		return def, nil
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%s must be a port number (1-65535), got %q", name, val)
	}
	return n, nil
}

func parseBool(val string) bool {
	return val == "1" || strings.ToLower(val) == "true"
}

// DefaultDataDir returns the data directory path using DATA_DIR env var, falling
// back to ~/.viking-bio-bridge on Linux or <exe_dir>/data otherwise (using
// ./data when the binary lives under /tmp).
func DefaultDataDir() string {
	if dir := os.Getenv("DATA_DIR"); dir != "" {
		return dir
	}
	if runtime.GOOS == "linux" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
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
	httpPort, err := parsePort("HTTP_PORT", os.Getenv("HTTP_PORT"), 3000)
	if err != nil {
		return nil, err
	}
	ingestTCPPort, err := parsePort("INGEST_TCP_PORT", os.Getenv("INGEST_TCP_PORT"), 9000)
	if err != nil {
		return nil, err
	}
	acmeHTTPPort, err := parsePort("ACME_HTTP_PORT", os.Getenv("ACME_HTTP_PORT"), 80)
	if err != nil {
		return nil, err
	}

	dataDir := DefaultDataDir()

	acmeCertDir := os.Getenv("ACME_CERT_DIR")
	if acmeCertDir == "" {
		acmeCertDir = dataDir
	}

	vapidContact := os.Getenv("VAPID_CONTACT_EMAIL")
	if vapidContact == "" {
		vapidContact = "admin@viking-bio.local"
	}
	mdnsName := os.Getenv("MDNS_NAME")
	if mdnsName == "" {
		mdnsName = "Viking Bio"
	}

	return &Config{
		HTTPPort:          httpPort,
		IngestTCPPort:     ingestTCPPort,
		IngestTCPTLS:      parseBool(os.Getenv("INGEST_TCP_TLS")),
		WebhookAuthToken:  os.Getenv("MACHINE_WEBHOOK_AUTH_TOKEN"),
		TLSCertPath:       os.Getenv("TLS_CERT_PATH"),
		TLSKeyPath:        os.Getenv("TLS_KEY_PATH"),
		ACMEEmail:         os.Getenv("ACME_EMAIL"),
		ACMEStaging:       parseBool(os.Getenv("ACME_STAGING")),
		ACMECertDir:       acmeCertDir,
		ACMEHTTPPort:      acmeHTTPPort,
		DDNSSubdomain:     os.Getenv("DDNS_SUBDOMAIN"),
		DDNSToken:         os.Getenv("DDNS_TOKEN"),
		VAPIDContactEmail: vapidContact,
		MDNSName:          mdnsName,
		MDNSDisable:       parseBool(os.Getenv("MDNS_DISABLE")),
		PicoSerialPort:    os.Getenv("PICO_SERIAL_PORT"),
		DataDir:           dataDir,
	}, nil
}
