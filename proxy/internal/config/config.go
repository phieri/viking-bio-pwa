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
	HTTPPort             int
	WebhookAuthToken     string
	TLSCertPath          string
	TLSKeyPath           string
	PicoBaseURL          string
	PicoForwardTimeoutMs int
	PicoVapidPublicKey   string
	ACMEEmail            string
	ACMEStaging          bool
	ACMECertDir          string
	ACMEHTTPPort         int
	DDNSSubdomain        string
	DDNSToken            string
	VAPIDContactEmail    string
	MDNSName             string
	MDNSDisable          bool
	PicoSerialPort       string
	DataDir              string
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

func requireHTTPURL(val, name string) (string, error) {
	if val == "" {
		return "", nil
	}
	val = strings.TrimSpace(val)
	if !strings.HasPrefix(val, "http://") && !strings.HasPrefix(val, "https://") {
		return "", fmt.Errorf("%s must use http:// or https://, got %q", name, val)
	}
	return val, nil
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
	acmeHTTPPort, err := parsePort("ACME_HTTP_PORT", os.Getenv("ACME_HTTP_PORT"), 80)
	if err != nil {
		return nil, err
	}

	picoBaseURL, err := requireHTTPURL(os.Getenv("PICO_BASE_URL"), "PICO_BASE_URL")
	if err != nil {
		return nil, err
	}

	picoTimeoutMs := 5000
	if v := os.Getenv("PICO_FORWARD_TIMEOUT_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("PICO_FORWARD_TIMEOUT_MS must be a positive integer, got %q", v)
		}
		picoTimeoutMs = n
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		base := exeDir()
		if runtime.GOOS != "windows" && strings.HasPrefix(base, "/tmp") {
			base = "."
		}
		dataDir = filepath.Join(base, "data")
	}

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
		HTTPPort:             httpPort,
		WebhookAuthToken:     os.Getenv("MACHINE_WEBHOOK_AUTH_TOKEN"),
		TLSCertPath:          os.Getenv("TLS_CERT_PATH"),
		TLSKeyPath:           os.Getenv("TLS_KEY_PATH"),
		PicoBaseURL:          picoBaseURL,
		PicoForwardTimeoutMs: picoTimeoutMs,
		PicoVapidPublicKey:   os.Getenv("PICO_VAPID_PUBLIC_KEY"),
		ACMEEmail:            os.Getenv("ACME_EMAIL"),
		ACMEStaging:          parseBool(os.Getenv("ACME_STAGING")),
		ACMECertDir:          acmeCertDir,
		ACMEHTTPPort:         acmeHTTPPort,
		DDNSSubdomain:        os.Getenv("DDNS_SUBDOMAIN"),
		DDNSToken:            os.Getenv("DDNS_TOKEN"),
		VAPIDContactEmail:    vapidContact,
		MDNSName:             mdnsName,
		MDNSDisable:          parseBool(os.Getenv("MDNS_DISABLE")),
		PicoSerialPort:       os.Getenv("PICO_SERIAL_PORT"),
		DataDir:              dataDir,
	}, nil
}
