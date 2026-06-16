package cert

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
)

// Manager wraps automatic Let's Encrypt certificate management.
type Manager struct {
	tlsConfig   *tls.Config
	httpHandler http.Handler
	manage      func(context.Context) error
}

// NewManager creates a Manager for the given domain and challenge type.
func NewManager(domain, email, certDir string, staging bool, challenge, dnsProvider string) (*Manager, error) {
	switch challenge {
	case config.ACMEChallengeHTTP01:
		return newHTTP01Manager(domain, email, certDir, staging), nil
	case config.ACMEChallengeDNS01:
		return newDNS01Manager(domain, email, certDir, staging, dnsProvider)
	default:
		return nil, fmt.Errorf("unsupported ACME challenge %q", challenge)
	}
}

func newHTTP01Manager(domain, email, certDir string, staging bool) *Manager {
	client := &acme.Client{DirectoryURL: acme.LetsEncryptURL}
	if staging {
		client.DirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}

	autocertManager := &autocert.Manager{
		Cache:      autocert.DirCache(certDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Email:      email,
		Client:     client,
	}
	return &Manager{
		tlsConfig:   autocertManager.TLSConfig(),
		httpHandler: autocertManager.HTTPHandler(nil),
	}
}

func newDNS01Manager(domain, email, certDir string, staging bool, dnsProvider string) (*Manager, error) {
	solver, err := newDNS01Solver(dnsProvider)
	if err != nil {
		return nil, err
	}

	cm := certmagic.New(certmagic.NewCache(certmagic.CacheOptions{}), certmagic.Config{
		Storage: &certmagic.FileStorage{Path: certDir},
	})
	issuer := certmagic.NewACMEIssuer(cm, certmagic.ACMEIssuer{
		CA:                      certmagic.LetsEncryptProductionCA,
		Email:                   email,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		DNS01Solver:             solver,
	})
	if staging {
		issuer.CA = certmagic.LetsEncryptStagingCA
	}
	cm.Issuers = []certmagic.Issuer{issuer}
	return &Manager{
		tlsConfig: cm.TLSConfig(),
		manage: func(ctx context.Context) error {
			return cm.ManageSync(ctx, []string{domain})
		},
	}, nil
}

func newDNS01Solver(dnsProvider string) (*certmagic.DNS01Solver, error) {
	switch strings.ToLower(strings.TrimSpace(dnsProvider)) {
	case config.ACMEDNSProviderCloudflare:
		apiToken := strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN"))
		if apiToken == "" {
			return nil, fmt.Errorf("CLOUDFLARE_API_TOKEN must be set when ACME_DNS_PROVIDER=%s", config.ACMEDNSProviderCloudflare)
		}
		provider := &cloudflare.Provider{APIToken: apiToken}
		if zoneToken := strings.TrimSpace(os.Getenv("CLOUDFLARE_ZONE_TOKEN")); zoneToken != "" {
			provider.ZoneToken = zoneToken
		}
		return &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: provider,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported ACME_DNS_PROVIDER %q", dnsProvider)
	}
}

// Manage starts background certificate maintenance when required.
func (m *Manager) Manage(ctx context.Context) error {
	if m.manage == nil {
		return nil
	}
	return m.manage(ctx)
}

// TLSConfig returns the TLS config used by the HTTPS server.
func (m *Manager) TLSConfig() *tls.Config {
	return m.tlsConfig
}

// HTTPHandler returns the HTTP-01 challenge handler when HTTP-01 is in use.
func (m *Manager) HTTPHandler() http.Handler {
	return m.httpHandler
}

// UsesHTTPChallenge reports whether the manager requires a challenge HTTP server.
func (m *Manager) UsesHTTPChallenge() bool {
	return m.httpHandler != nil
}
