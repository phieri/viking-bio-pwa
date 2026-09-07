package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/phieri/viking-bio-pwa/configurator/internal/config"
	ingestcodec "github.com/phieri/viking-bio-pwa/configurator/internal/ingest"
	"github.com/phieri/viking-bio-pwa/configurator/internal/storage"
)

func newIngestTestServer(t *testing.T) (*tcpIngestServer, *storage.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	handler := NewHandlers(&config.Config{IngestTCPPort: 9000})
	return newTCPIngestServer(&config.Config{IngestTCPPort: 9000}, store, handler), store
}

func signPayload(t *testing.T, secret string, payload ingestcodec.Payload) ingestcodec.Payload {
	t.Helper()
	canonical, err := ingestcodec.CanonicalTelemetryString(payload)
	if err != nil {
		t.Fatalf("CanonicalTelemetryString: %v", err)
	}
	sum := hmacSHA256([]byte(secret), []byte(canonical))
	payload.Sig = base64.StdEncoding.EncodeToString(sum)
	return payload
}

func hmacSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

func TestVerifyTelemetrySignature(t *testing.T) {
	t.Parallel()

	payload := ingestcodec.Payload{
		Device: "pico-1234",
		Seq:    1,
		TS:     time.Now().Unix(),
		Data: ingestcodec.TelemetryData{
			Flame: true,
			Fan:   42,
			Temp:  73,
			Err:   0,
			Valid: true,
		},
	}
	payload = signPayload(t, "super-secret", payload)

	if err := ingestcodec.VerifySignature("super-secret", payload); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}

	payload.Seq++
	if err := ingestcodec.VerifySignature("super-secret", payload); err == nil {
		t.Fatal("expected signature verification to fail after payload mutation")
	}
}

func TestIsAllowedRemoteAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		remote string
		want   bool
	}{
		{name: "ipv6 loopback", remote: "[::1]:12345", want: true},
		{name: "ipv6 ula", remote: "[fc00::1234]:12345", want: true},
		{name: "ipv6 link local", remote: "[fe80::1234%lo0]:12345", want: true},
		{name: "ipv4 loopback", remote: "127.0.0.1:12345", want: true},
		{name: "ipv4 private 10", remote: "10.0.0.2:12345", want: true},
		{name: "ipv4 private 172", remote: "172.16.0.2:12345", want: true},
		{name: "ipv4 private 192", remote: "192.168.1.2:12345", want: true},
		{name: "ipv4 link local", remote: "169.254.1.1:12345", want: true},
		{name: "public ipv4", remote: "8.8.8.8:12345", want: false},
		{name: "public ipv6", remote: "[2001:4860:4860::8888]:12345", want: false},
		{name: "private ipv6", remote: "[fd00::1]:12345", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAllowedRemoteAddr(tc.remote); got != tc.want {
				t.Fatalf("isAllowedRemoteAddr(%q) = %v, want %v", tc.remote, got, tc.want)
			}
		})
	}
}

func TestProcessPayloadRejectsReplay(t *testing.T) {
	t.Parallel()

	ingest, store := newIngestTestServer(t)
	if err := store.ProvisionDevice("pico-1234", "super-secret"); err != nil {
		t.Fatalf("ProvisionDevice: %v", err)
	}

	first := signPayload(t, "super-secret", ingestcodec.Payload{
		Device: "pico-1234",
		Seq:    1,
		TS:     time.Now().Unix(),
		Data:   ingestcodec.TelemetryData{Valid: true},
	})
	if err := ingest.processPayload(first, "[::1]:12345", time.Now()); err != nil {
		t.Fatalf("first processPayload: %v", err)
	}

	replay := signPayload(t, "super-secret", ingestcodec.Payload{
		Device: "pico-1234",
		Seq:    1,
		TS:     time.Now().Add(time.Second).Unix(),
		Data:   ingestcodec.TelemetryData{Valid: true},
	})
	if err := ingest.processPayload(replay, "[::1]:12345", time.Now()); err == nil {
		t.Fatal("expected replayed sequence to be rejected")
	}
}
