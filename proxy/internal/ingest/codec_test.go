package ingest

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

func signPayload(t *testing.T, secret string, payload Payload) Payload {
	t.Helper()
	canonical, err := CanonicalTelemetryString(payload)
	if err != nil {
		t.Fatalf("CanonicalTelemetryString: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonical))
	payload.Sig = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return payload
}

func TestReadFrame(t *testing.T) {
	t.Parallel()

	payload := Payload{
		Device: "pico-1234",
		Seq:    1,
		TS:     time.Now().Unix(),
		Sig:    "signature",
		Data:   TelemetryData{Valid: true},
	}
	frame, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(frame))); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}
	if _, err := buf.Write(frame); err != nil {
		t.Fatalf("buf.Write: %v", err)
	}

	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Device != payload.Device || got.Seq != payload.Seq || got.Sig != payload.Sig {
		t.Fatalf("unexpected payload: %#v", got)
	}
}

func TestVerifySignature(t *testing.T) {
	t.Parallel()

	payload := signPayload(t, "super-secret", Payload{
		Device: "pico-1234",
		Seq:    1,
		TS:     time.Now().Unix(),
		Data:   TelemetryData{Valid: true},
	})

	if err := VerifySignature("super-secret", payload); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}

	if err := VerifySignature("wrong-secret", payload); err == nil {
		t.Fatal("expected signature verification to fail")
	}
}
