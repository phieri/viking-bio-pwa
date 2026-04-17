package ingest

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const maxFrameSize = 4096

type TelemetryData struct {
	Flame bool    `json:"flame"`
	Fan   float64 `json:"fan"`
	Temp  float64 `json:"temp"`
	Err   float64 `json:"err"`
	Valid bool    `json:"valid"`
}

type Payload struct {
	Device string        `json:"device"`
	Seq    uint64        `json:"seq"`
	TS     int64         `json:"ts"`
	Data   TelemetryData `json:"data"`
	Sig    string        `json:"sig"`
}

func ReadFrame(r io.Reader) (Payload, error) {
	var frameLenBuf [4]byte
	if _, err := io.ReadFull(r, frameLenBuf[:]); err != nil {
		return Payload{}, err
	}
	frameLen := binary.BigEndian.Uint32(frameLenBuf[:])
	if frameLen == 0 || frameLen > maxFrameSize {
		return Payload{}, fmt.Errorf("invalid frame size %d", frameLen)
	}
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(r, frame); err != nil {
		return Payload{}, err
	}
	var payload Payload
	if err := json.Unmarshal(frame, &payload); err != nil {
		return Payload{}, fmt.Errorf("decode frame JSON: %w", err)
	}
	if payload.Device == "" || payload.Sig == "" || payload.TS == 0 {
		return Payload{}, fmt.Errorf("missing required payload fields")
	}
	return payload, nil
}

func CanonicalTelemetryString(payload Payload) (string, error) {
	dataJSON, err := json.Marshal(payload.Data)
	if err != nil {
		return "", fmt.Errorf("marshal telemetry data: %w", err)
	}
	return fmt.Sprintf("%s\n%d\n%d\n%s", payload.Device, payload.Seq, payload.TS, dataJSON), nil
}

func VerifySignature(secret string, payload Payload) error {
	canonical, err := CanonicalTelemetryString(payload)
	if err != nil {
		return err
	}
	provided, err := base64.StdEncoding.DecodeString(payload.Sig)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(canonical)); err != nil {
		return fmt.Errorf("hash canonical payload: %w", err)
	}
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(expected, provided) != 1 {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
