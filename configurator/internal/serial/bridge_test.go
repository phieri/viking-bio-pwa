/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package serial

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseWebhookCA(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour),
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})} {
		got, err := ParseWebhookCA(input)
		if err != nil || string(got) != string(cert) {
			t.Fatalf("ParseWebhookCA(valid) = %x, %v", got, err)
		}
	}
	for _, input := range [][]byte{nil, []byte("not a certificate"), make([]byte, maxWebhookCACertBytes+1),
		append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), []byte("extra")...)} {
		if _, err := ParseWebhookCA(input); err == nil {
			t.Fatalf("ParseWebhookCA should reject invalid input of length %d", len(input))
		}
	}
}

func TestConfirmedResponse(t *testing.T) {
	t.Parallel()
	confirmation := "telemetry: device key saved – reboot to apply"
	for _, tc := range []struct {
		name  string
		lines []string
		want  bool
	}{
		{"success", []string{"noise", "  " + confirmation}, true},
		{"failure", []string{"telemetry: ERROR saving device key"}, false},
		{"no reply", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := confirmedResponse(tc.lines, confirmation); got != tc.want {
				t.Fatalf("confirmedResponse() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestParseStatusHandlesRuntimeFields(t *testing.T) {
	t.Parallel()

	bridge := New("/dev/null")
	status := bridge.ParseStatus([]string{
		"wifi: connected",
		"  IPv6[0]: fd00::1234",
		"  country: SE",
		"  firmware: v1.2.3",
		"  server:  fd00::1:9000",
		"  device:  pico-1234",
		"  device key: (set)",
		"  webhook: not set",
		"  webhook CA: (set)",
		"  telemetry: active",
	})

	if !status.Connected {
		t.Fatal("expected connected status")
	}
	if len(status.Addresses) != 1 || status.Addresses[0] != "fd00::1234" {
		t.Fatalf("unexpected addresses: %#v", status.Addresses)
	}
	if status.Country != "SE" {
		t.Fatalf("expected country SE, got %q", status.Country)
	}
	if status.Server != "fd00::1" || status.Port != 9000 {
		t.Fatalf("expected server fd00::1:9000, got %q:%d", status.Server, status.Port)
	}
	if status.DeviceID != "pico-1234" {
		t.Fatalf("expected device ID pico-1234, got %q", status.DeviceID)
	}
	if status.FirmwareVersion != "v1.2.3" {
		t.Fatalf("expected firmware version v1.2.3, got %q", status.FirmwareVersion)
	}
	if status.DeviceKey != "(set)" {
		t.Fatalf("expected device key marker, got %q", status.DeviceKey)
	}
	if status.Webhook != "not set" {
		t.Fatalf("expected webhook marker, got %q", status.Webhook)
	}
	if status.WebhookCA != "(set)" {
		t.Fatalf("expected webhook CA marker, got %q", status.WebhookCA)
	}
	if status.Telemetry != "active" {
		t.Fatalf("expected telemetry active, got %q", status.Telemetry)
	}
}

func TestParseStatusIgnoresUnconfiguredServer(t *testing.T) {
	t.Parallel()

	status := New("/dev/null").ParseStatus([]string{
		"wifi: disconnected",
		"  server:  not configured",
	})

	if status.Server != "" || status.Port != 0 {
		t.Fatalf("expected empty server, got %q:%d", status.Server, status.Port)
	}
}

func TestSelectAutoPortEmptyList(t *testing.T) {
	t.Parallel()

	port, err := selectAutoPort(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if port != "" {
		t.Fatalf("expected empty port name, got %q", port)
	}
}

func TestSelectAutoPortUsesSingleAttachedPort(t *testing.T) {
	t.Parallel()

	port, err := selectAutoPort([]string{"/dev/ttyACM0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if port != "/dev/ttyACM0" {
		t.Fatalf("expected /dev/ttyACM0, got %q", port)
	}
}

func TestSelectAutoPortRejectsMultiplePorts(t *testing.T) {
	t.Parallel()

	_, err := selectAutoPort([]string{"/dev/ttyACM0", "/dev/ttyUSB0"})
	if err == nil {
		t.Fatal("expected error for multiple attached serial ports")
	}
}
