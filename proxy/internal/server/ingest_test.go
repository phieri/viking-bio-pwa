package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

func newIngestTestServer(t *testing.T) (*tcpIngestServer, *storage.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	mgr, err := push.New(dir, "admin@test.local", store)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	handler := NewHandlers(mgr, nil, "")
	return newTCPIngestServer(&config.Config{IngestTCPPort: 9000}, store, handler), store
}

func signPayload(t *testing.T, secret string, payload ingestPayload) ingestPayload {
	t.Helper()
	canonical, err := canonicalTelemetryString(payload)
	if err != nil {
		t.Fatalf("canonicalTelemetryString: %v", err)
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

	payload := ingestPayload{
		Device: "pico-1234",
		Seq:    1,
		TS:     time.Now().Unix(),
		Data: telemetryData{
			Flame: true,
			Fan:   42,
			Temp:  73,
			Err:   0,
			Valid: true,
		},
	}
	payload = signPayload(t, "super-secret", payload)

	if err := verifyTelemetrySignature("super-secret", payload); err != nil {
		t.Fatalf("verifyTelemetrySignature: %v", err)
	}

	payload.Seq++
	if err := verifyTelemetrySignature("super-secret", payload); err == nil {
		t.Fatal("expected signature verification to fail after payload mutation")
	}
}

func TestProcessPayloadRejectsReplay(t *testing.T) {
	t.Parallel()

	ingest, store := newIngestTestServer(t)
	if err := store.ProvisionDevice("pico-1234", "super-secret"); err != nil {
		t.Fatalf("ProvisionDevice: %v", err)
	}

	first := signPayload(t, "super-secret", ingestPayload{
		Device: "pico-1234",
		Seq:    1,
		TS:     time.Now().Unix(),
		Data:   telemetryData{Valid: true},
	})
	if err := ingest.processPayload(first, "[::1]:12345", time.Now()); err != nil {
		t.Fatalf("first processPayload: %v", err)
	}

	replay := signPayload(t, "super-secret", ingestPayload{
		Device: "pico-1234",
		Seq:    1,
		TS:     time.Now().Add(time.Second).Unix(),
		Data:   telemetryData{Valid: true},
	})
	if err := ingest.processPayload(replay, "[::1]:12345", time.Now()); err == nil {
		t.Fatal("expected replayed sequence to be rejected")
	}
}
