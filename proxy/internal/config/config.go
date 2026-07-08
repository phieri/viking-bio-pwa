package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration parsed from environment variables.
type Config struct {
	HTTPPort          int
	IngestTCPPort     int
	IngestTCPTLS      bool
	TLSCertPath       string
	TLSKeyPath        string
	ACMEDomain        string
	ACMEChallenge     string
	ACMEDNSProvider   string
	ACMEEmail         string
	ACMEStaging       bool
	ACMECertDir       string
	ACMEHTTPPort      int
	VAPIDContactEmail string
	MDNSName          string
	MDNSDisable       bool
	PicoSerialPort    string
	DataDir           string

	CleaningReminderWeekday time.Weekday
	CleaningReminderHour    int
	CleaningReminderMinute  int

	// Energy price card
	EnergyCardEnabled      bool
	BurnerFixedCostSEKYear float64 // annual fixed costs for burner (service, amortization)
	BurnerCostSEKPerKWh    float64 // direct pellet energy cost per kWh of heat
	AnnualHeatingKWh       float64 // estimated annual heating kWh (to amortize fixed costs)

	// Telemetry history endpoint
	TelemetryHistoryEnabled bool
}

const (
	ACMEChallengeHTTP01       = "http-01"
	ACMEChallengeDNS01        = "dns-01"
	ACMEDNSProviderCloudflare = "cloudflare"
)

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

func parseFloat(name, val string, def float64) (float64, error) {
	if val == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number, got %q", name, val)
	}
	return f, nil
}

func DefaultReminderSchedule() (time.Weekday, int, int) {
	return time.Saturday, 7, 0
}

func parseWeekday(name, val string, def time.Weekday) (time.Weekday, error) {
	if val == "" {
		return def, nil
	}
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "sunday", "sun", "0":
		return time.Sunday, nil
	case "monday", "mon", "1":
		return time.Monday, nil
	case "tuesday", "tue", "tues", "2":
		return time.Tuesday, nil
	case "wednesday", "wed", "3":
		return time.Wednesday, nil
	case "thursday", "thu", "4":
		return time.Thursday, nil
	case "friday", "fri", "5":
		return time.Friday, nil
	case "saturday", "sat", "6":
		return time.Saturday, nil
	default:
		return 0, fmt.Errorf("%s must be a weekday name (for example Monday), got %q", name, val)
	}
}

func parseReminderTime(name, val string, defHour, defMinute int) (int, int, error) {
	if val == "" {
		return defHour, defMinute, nil
	}
	parts := strings.Split(strings.TrimSpace(val), ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("%s must be in HH:MM format, got %q", name, val)
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil || hour < 0 || hour > 23 {
		return 0, 0, fmt.Errorf("%s must have an hour between 0 and 23, got %q", name, val)
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil || minute < 0 || minute > 59 {
		return 0, 0, fmt.Errorf("%s must have minutes between 0 and 59, got %q", name, val)
	}
	return hour, minute, nil
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
	acmeDomain := strings.TrimSpace(os.Getenv("ACME_DOMAIN"))
	acmeChallenge := strings.ToLower(strings.TrimSpace(os.Getenv("ACME_CHALLENGE")))
	if acmeChallenge == "" {
		acmeChallenge = ACMEChallengeHTTP01
	}
	acmeDNSProvider := strings.ToLower(strings.TrimSpace(os.Getenv("ACME_DNS_PROVIDER")))
	if acmeDomain == "" {
		if os.Getenv("ACME_CHALLENGE") != "" || os.Getenv("ACME_DNS_PROVIDER") != "" {
			return nil, fmt.Errorf("ACME_DOMAIN must be set when ACME_CHALLENGE or ACME_DNS_PROVIDER is configured")
		}
	} else {
		switch acmeChallenge {
		case ACMEChallengeHTTP01, ACMEChallengeDNS01:
		default:
			return nil, fmt.Errorf("ACME_CHALLENGE must be %q or %q, got %q", ACMEChallengeHTTP01, ACMEChallengeDNS01, acmeChallenge)
		}
		if acmeChallenge == ACMEChallengeDNS01 && acmeDNSProvider == "" {
			return nil, fmt.Errorf("ACME_DNS_PROVIDER must be set when ACME_CHALLENGE=%s", ACMEChallengeDNS01)
		}
		if acmeChallenge == ACMEChallengeHTTP01 && acmeDNSProvider != "" {
			return nil, fmt.Errorf("ACME_DNS_PROVIDER is only used with ACME_CHALLENGE=%s", ACMEChallengeDNS01)
		}
	}

	vapidContact := os.Getenv("VAPID_CONTACT_EMAIL")
	if vapidContact == "" {
		vapidContact = "admin@viking-bio.local"
	}
	mdnsName := os.Getenv("MDNS_NAME")
	if mdnsName == "" {
		mdnsName = "Viking Bio"
	}

	defaultWeekday, defaultHour, defaultMinute := DefaultReminderSchedule()
	cleaningReminderWeekday, err := parseWeekday("CLEANING_REMINDER_WEEKDAY", os.Getenv("CLEANING_REMINDER_WEEKDAY"), defaultWeekday)
	if err != nil {
		return nil, err
	}
	cleaningReminderHour, cleaningReminderMinute, err := parseReminderTime("CLEANING_REMINDER_TIME", os.Getenv("CLEANING_REMINDER_TIME"), defaultHour, defaultMinute)
	if err != nil {
		return nil, err
	}

	burnerFixed, err := parseFloat("BURNER_FIXED_COST_SEK_YEAR", os.Getenv("BURNER_FIXED_COST_SEK_YEAR"), 0)
	if err != nil {
		return nil, err
	}
	burnerKWh, err := parseFloat("BURNER_COST_SEK_KWH", os.Getenv("BURNER_COST_SEK_KWH"), 0)
	if err != nil {
		return nil, err
	}
	annualKWh, err := parseFloat("ANNUAL_HEATING_KWH", os.Getenv("ANNUAL_HEATING_KWH"), 20000)
	if err != nil {
		return nil, err
	}

	return &Config{
		HTTPPort:          httpPort,
		IngestTCPPort:     ingestTCPPort,
		IngestTCPTLS:      parseBool(os.Getenv("INGEST_TCP_TLS")),
		TLSCertPath:       os.Getenv("TLS_CERT_PATH"),
		TLSKeyPath:        os.Getenv("TLS_KEY_PATH"),
		ACMEDomain:        acmeDomain,
		ACMEChallenge:     acmeChallenge,
		ACMEDNSProvider:   acmeDNSProvider,
		ACMEEmail:         os.Getenv("ACME_EMAIL"),
		ACMEStaging:       parseBool(os.Getenv("ACME_STAGING")),
		ACMECertDir:       acmeCertDir,
		ACMEHTTPPort:      acmeHTTPPort,
		VAPIDContactEmail: vapidContact,
		MDNSName:          mdnsName,
		MDNSDisable:       parseBool(os.Getenv("MDNS_DISABLE")),
		PicoSerialPort:    os.Getenv("PICO_SERIAL_PORT"),
		DataDir:           dataDir,

		CleaningReminderWeekday: cleaningReminderWeekday,
		CleaningReminderHour:    cleaningReminderHour,
		CleaningReminderMinute:  cleaningReminderMinute,

		EnergyCardEnabled:       parseBool(os.Getenv("ENERGY_CARD_ENABLED")),
		BurnerFixedCostSEKYear:  burnerFixed,
		BurnerCostSEKPerKWh:     burnerKWh,
		AnnualHeatingKWh:        annualKWh,
		TelemetryHistoryEnabled: parseBool(os.Getenv("TELEMETRY_HISTORY_ENABLED")),
	}, nil
}
