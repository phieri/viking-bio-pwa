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

	// Energy comparison card
	EnergyCardEnabled      bool
	BurnerFixedCostSEKYear float64 // annual fixed costs for burner (service, amortization)
	BurnerCostSEKPerKWh    float64 // direct pellet energy cost per kWh of heat
	ElecGridFeeSEKPerKWh   float64 // electricity grid fee per kWh
	ElecTaxSEKPerKWh       float64 // electricity tax per kWh
	ElecFixedCostSEKYear   float64 // annual fixed electricity subscription fee
	ElecPriceRegion        string  // spot price region: SE1, SE2, SE3, SE4
	AnnualHeatingKWh       float64 // estimated annual heating kWh (to amortize fixed costs)
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

	burnerFixed, err := parseFloat("BURNER_FIXED_COST_SEK_YEAR", os.Getenv("BURNER_FIXED_COST_SEK_YEAR"), 0)
	if err != nil {
		return nil, err
	}
	burnerKWh, err := parseFloat("BURNER_COST_SEK_KWH", os.Getenv("BURNER_COST_SEK_KWH"), 0)
	if err != nil {
		return nil, err
	}
	elecGrid, err := parseFloat("ELEC_GRID_FEE_SEK_KWH", os.Getenv("ELEC_GRID_FEE_SEK_KWH"), 0)
	if err != nil {
		return nil, err
	}
	elecTax, err := parseFloat("ELEC_TAX_SEK_KWH", os.Getenv("ELEC_TAX_SEK_KWH"), 0)
	if err != nil {
		return nil, err
	}
	elecFixed, err := parseFloat("ELEC_FIXED_COST_SEK_YEAR", os.Getenv("ELEC_FIXED_COST_SEK_YEAR"), 0)
	if err != nil {
		return nil, err
	}
	annualKWh, err := parseFloat("ANNUAL_HEATING_KWH", os.Getenv("ANNUAL_HEATING_KWH"), 20000)
	if err != nil {
		return nil, err
	}
	elecRegion := os.Getenv("ELEC_PRICE_REGION")
	if elecRegion == "" {
		elecRegion = "SE3"
	}

	return &Config{
		HTTPPort:          httpPort,
		IngestTCPPort:     ingestTCPPort,
		IngestTCPTLS:      parseBool(os.Getenv("INGEST_TCP_TLS")),
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

		EnergyCardEnabled:      parseBool(os.Getenv("ENERGY_CARD_ENABLED")),
		BurnerFixedCostSEKYear: burnerFixed,
		BurnerCostSEKPerKWh:    burnerKWh,
		ElecGridFeeSEKPerKWh:   elecGrid,
		ElecTaxSEKPerKWh:       elecTax,
		ElecFixedCostSEKYear:   elecFixed,
		ElecPriceRegion:        elecRegion,
		AnnualHeatingKWh:       annualKWh,
	}, nil
}
