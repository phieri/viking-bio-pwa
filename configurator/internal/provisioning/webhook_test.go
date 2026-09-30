package provisioning

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/phieri/viking-bio-pwa/configurator/internal/serial"
)

type fakeWebhookBridge struct {
	status     serial.StatusResult
	statusErr  error
	caErr      error
	commandErr error
	calls      []string
	ca         []byte
	command    string
}

func (b *fakeWebhookBridge) GetStatus() (serial.StatusResult, error) {
	b.calls = append(b.calls, "status")
	return b.status, b.statusErr
}

func (b *fakeWebhookBridge) ProvisionWebhookCA(ca []byte) error {
	b.calls = append(b.calls, "ca")
	b.ca = append([]byte(nil), ca...)
	return b.caErr
}

func (b *fakeWebhookBridge) SendConfirmedCommand(command, _ string) error {
	b.calls = append(b.calls, "webhook")
	b.command = command
	return b.commandErr
}

func TestDiscoverWebhookCASelectsVerifiedRoot(t *testing.T) {
	serverURL, roots, caDER := startWebhookTLSServer(t)

	got, err := discoverWebhookCAWithRoots(serverURL, roots)
	if err != nil {
		t.Fatalf("discoverWebhookCAWithRoots() error = %v", err)
	}
	if string(got) != string(caDER) {
		t.Fatal("discovered CA does not match the verified server root")
	}
}

func TestDiscoverWebhookCARejectsUntrustedAndInvalidTargets(t *testing.T) {
	serverURL, _, _ := startWebhookTLSServer(t)
	if _, err := discoverWebhookCAWithRoots(serverURL, x509.NewCertPool()); err == nil {
		t.Fatal("expected untrusted webhook certificate to be rejected")
	}

	for _, target := range []string{
		"http://hooks.example.com/",
		"https://127.0.0.1/",
		"https://-invalid.example/",
		"https://hooks.example.com#fragment",
		"https://hooks.example.com?token=secret",
	} {
		if _, err := discoverWebhookCAWithRoots(target, nil); err == nil {
			t.Errorf("discoverWebhookCAWithRoots(%q) unexpectedly succeeded", target)
		}
	}
}

func TestConfigureWebhookAutomaticallyProvisionsCABeforeURL(t *testing.T) {
	ca := []byte("verified-root")
	bridge := &fakeWebhookBridge{}
	discover := func(gotURL string) ([]byte, error) {
		if gotURL != "https://hooks.example.com/notify" {
			t.Fatalf("CA discovery URL = %q", gotURL)
		}
		return ca, nil
	}

	usedExistingCA, err := configureWebhook(bridge, "https://hooks.example.com/notify", discover)
	if err != nil {
		t.Fatalf("configureWebhook() error = %v", err)
	}
	if usedExistingCA {
		t.Fatal("expected automatically discovered CA to be used")
	}
	if strings.Join(bridge.calls, ",") != "ca,webhook" {
		t.Fatalf("command order = %v, want CA before webhook URL", bridge.calls)
	}
	if string(bridge.ca) != string(ca) {
		t.Fatalf("provisioned CA = %q, want %q", bridge.ca, ca)
	}
	if bridge.command != "WEBHOOK=https://hooks.example.com/notify" {
		t.Fatalf("webhook command = %q", bridge.command)
	}
}

func TestConfigureWebhookRequiresCAUnlessManuallyProvisioned(t *testing.T) {
	discoveryErr := errors.New("untrusted server")
	discover := func(string) ([]byte, error) { return nil, discoveryErr }

	bridge := &fakeWebhookBridge{}
	if _, err := configureWebhook(bridge, "https://hooks.example.com/notify", discover); err == nil {
		t.Fatal("expected missing CA to prevent setting HTTPS webhook")
	}
	if strings.Join(bridge.calls, ",") != "status" {
		t.Fatalf("commands after failed discovery = %v", bridge.calls)
	}

	bridge = &fakeWebhookBridge{status: serial.StatusResult{WebhookCA: "(set)"}}
	usedExistingCA, err := configureWebhook(bridge, "https://hooks.example.com/notify", discover)
	if err != nil {
		t.Fatalf("configureWebhook() with existing manual CA error = %v", err)
	}
	if !usedExistingCA {
		t.Fatal("expected existing manually provisioned CA to be used")
	}
	if strings.Join(bridge.calls, ",") != "status,webhook" {
		t.Fatalf("commands with manual CA = %v", bridge.calls)
	}
}

func TestConfigureWebhookDoesNotDiscoverCAForHTTP(t *testing.T) {
	bridge := &fakeWebhookBridge{}
	discover := func(string) ([]byte, error) {
		t.Fatal("HTTP webhook should not trigger CA discovery")
		return nil, nil
	}

	if _, err := configureWebhook(bridge, "http://hooks.example.com/notify", discover); err != nil {
		t.Fatalf("configureWebhook() error = %v", err)
	}
	if strings.Join(bridge.calls, ",") != "webhook" {
		t.Fatalf("commands for HTTP webhook = %v", bridge.calls)
	}
}

func TestConfigureWebhookStopsWhenCAProvisioningFails(t *testing.T) {
	bridge := &fakeWebhookBridge{caErr: errors.New("USB transfer failed")}
	discover := func(string) ([]byte, error) { return []byte("verified-root"), nil }

	if _, err := configureWebhook(bridge, "https://hooks.example.com/notify", discover); err == nil {
		t.Fatal("expected CA transfer failure")
	}
	if strings.Join(bridge.calls, ",") != "ca" {
		t.Fatalf("commands after failed CA transfer = %v", bridge.calls)
	}
}

func startWebhookTLSServer(t *testing.T) (string, *x509.CertPool, []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test webhook root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCert := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{serverCert}})
	go func() {
		_ = server.Serve(tlsListener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
	})

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return fmt.Sprintf("https://localhost:%s/", port), roots, caDER
}

func TestValidWebhookDNSHostname(t *testing.T) {
	t.Parallel()

	for _, hostname := range []string{"hooks.example.com", "localhost", "hooks-1.example2.com"} {
		if !validWebhookDNSHostname(hostname) {
			t.Errorf("validWebhookDNSHostname(%q) = false", hostname)
		}
	}
	for _, hostname := range []string{"", "127.0.0.1", "hooks..example.com", "-hooks.example.com", "hooks_.example.com", "hooks.example.com."} {
		if validWebhookDNSHostname(hostname) {
			t.Errorf("validWebhookDNSHostname(%q) = true", hostname)
		}
	}
}
