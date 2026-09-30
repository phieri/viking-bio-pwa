package provisioning

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/phieri/viking-bio-pwa/configurator/internal/serial"
)

const webhookURLSavedConfirmation = "notifications: webhook URL saved – reboot to apply"

type webhookProvisioningBridge interface {
	GetStatus() (serial.StatusResult, error)
	ProvisionWebhookCA([]byte) error
	SendConfirmedCommand(string, string) error
}

type webhookCADiscoverer func(string) ([]byte, error)

func configureWebhook(bridge webhookProvisioningBridge, rawURL string, discoverCA webhookCADiscoverer) (bool, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return false, fmt.Errorf("webhook URL must start with http:// or https://")
	}
	if len(rawURL) > 512 || strings.ContainsAny(rawURL, "\r\n") {
		return false, fmt.Errorf("webhook URL is invalid or too long")
	}

	usedExistingCA := false
	if strings.HasPrefix(rawURL, "https://") {
		ca, err := discoverCA(rawURL)
		if err != nil {
			status, statusErr := bridge.GetStatus()
			if statusErr != nil || !strings.EqualFold(strings.TrimSpace(status.WebhookCA), "(set)") {
				return false, fmt.Errorf("could not automatically verify the HTTPS webhook; manually provision its CA certificate first: %w", err)
			}
			usedExistingCA = true
		} else if err := bridge.ProvisionWebhookCA(ca); err != nil {
			return false, fmt.Errorf("provision webhook CA: %w", err)
		}
	}

	if err := bridge.SendConfirmedCommand("WEBHOOK="+rawURL, webhookURLSavedConfirmation); err != nil {
		return false, err
	}
	return usedExistingCA, nil
}

func discoverWebhookCA(rawURL string) ([]byte, error) {
	return discoverWebhookCAWithRoots(rawURL, nil)
}

func discoverWebhookCAWithRoots(rawURL string, roots *x509.CertPool) ([]byte, error) {
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("invalid HTTPS webhook URL")
	}
	if target.Scheme != "https" || target.Opaque != "" || target.Hostname() == "" ||
		target.Fragment != "" || strings.Contains(rawURL, "#") ||
		strings.HasSuffix(target.Host, ":") || (target.Path == "" && target.RawQuery != "") {
		return nil, fmt.Errorf("HTTPS webhook URL must have a valid DNS hostname")
	}

	host := target.Hostname()
	if net.ParseIP(host) != nil || !validWebhookDNSHostname(host) {
		return nil, fmt.Errorf("HTTPS webhook URL must use a valid DNS hostname")
	}

	port := target.Port()
	if port == "" {
		port = "443"
	} else if portNumber, err := strconv.Atoi(port); err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("HTTPS webhook URL has an invalid port")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{
			ServerName: host,
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		},
	}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("connect to and verify HTTPS webhook: %w", err)
	}
	defer connection.Close()

	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("HTTPS webhook connection did not negotiate TLS")
	}
	chains := tlsConnection.ConnectionState().VerifiedChains
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		ca, err := serial.ParseWebhookCA(chain[len(chain)-1].Raw)
		if err == nil {
			return ca, nil
		}
	}
	return nil, fmt.Errorf("verified HTTPS certificate chain has no compatible CA certificate")
}

func validWebhookDNSHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	hasLetter := false
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			char := label[i]
			letter := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
			digit := char >= '0' && char <= '9'
			if !letter && !digit && char != '-' {
				return false
			}
			hasLetter = hasLetter || letter
		}
	}
	return hasLetter
}
