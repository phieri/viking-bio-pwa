package serial

import "testing"

func TestParseStatusHandlesRuntimeFields(t *testing.T) {
	t.Parallel()

	bridge := New("/dev/null")
	status := bridge.ParseStatus([]string{
		"wifi: connected",
		"  IPv6[0]: fd00::1234",
		"  country: SE",
		"  server:  fd00::1:9000",
		"  device:  pico-1234",
		"  device key: (set)",
		"  webhook: not set",
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
	if status.DeviceKey != "(set)" {
		t.Fatalf("expected device key marker, got %q", status.DeviceKey)
	}
	if status.Webhook != "not set" {
		t.Fatalf("expected webhook marker, got %q", status.Webhook)
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
