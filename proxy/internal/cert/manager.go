package cert

import (
	"crypto/tls"
	"net/http"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Manager wraps an autocert.Manager for automatic Let's Encrypt certificates.
type Manager struct {
	m *autocert.Manager
}

// NewManager creates a Manager for the given domain.
// If staging is true, the Let's Encrypt staging environment is used.
func NewManager(domain, email, certDir string, staging bool) (*Manager, error) {
	client := &acme.Client{DirectoryURL: acme.LetsEncryptURL}
	if staging {
		client.DirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}

	m := &autocert.Manager{
		Cache:      autocert.DirCache(certDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Email:      email,
		Client:     client,
	}
	return &Manager{m: m}, nil
}

// TLSConfig returns a *tls.Config that uses the autocert.Manager for certificate
// retrieval and automatic renewal.
func (m *Manager) TLSConfig() *tls.Config {
	return m.m.TLSConfig()
}

// HTTPHandler returns the HTTP-01 challenge handler for port 80.
// Mount this on a plain HTTP server at the ACME_HTTP_PORT.
func (m *Manager) HTTPHandler() http.Handler {
	return m.m.HTTPHandler(nil)
}
