package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	ingestcodec "github.com/phieri/viking-bio-pwa/proxy/internal/ingest"
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
	handler := NewHandlers(mgr)
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
