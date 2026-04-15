package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

const (
	ingestQueueSize         = 64
	ingestMaxFrameSize      = 4096
	ingestFailureWindow     = time.Minute
	ingestBlacklistDuration = 5 * time.Minute
	ingestFailureThreshold  = 5
	ingestReadTimeout       = 2 * time.Minute
)

type telemetryData struct {
	Flame bool    `json:"flame"`
	Fan   float64 `json:"fan"`
	Temp  float64 `json:"temp"`
	Err   float64 `json:"err"`
	Valid bool    `json:"valid"`
}

func (d telemetryData) machineDataBody() machineDataBody {
	flame := d.Flame
	fan := d.Fan
	temp := d.Temp
	errCode := d.Err
	valid := d.Valid
	return machineDataBody{
		Flame: &flame,
		Fan:   &fan,
		Temp:  &temp,
		Err:   &errCode,
		Valid: &valid,
	}
}

type ingestPayload struct {
	Device string        `json:"device"`
	Seq    uint64        `json:"seq"`
	TS     int64         `json:"ts"`
	Data   telemetryData `json:"data"`
	Sig    string        `json:"sig"`
}

type telemetryEnvelope struct {
	Payload    ingestPayload
	RemoteAddr string
	ReceivedAt time.Time
}

type telemetryPipeline struct {
	handler *Handlers
	queue   chan telemetryEnvelope
}

func newTelemetryPipeline(handler *Handlers) *telemetryPipeline {
	p := &telemetryPipeline{
		handler: handler,
		queue:   make(chan telemetryEnvelope, ingestQueueSize),
	}
	go p.run()
	return p
}

func (p *telemetryPipeline) run() {
	for env := range p.queue {
		p.handler.processMachineData(env.Payload.Data.machineDataBody(), "ingest", env.ReceivedAt)
	}
}

func (p *telemetryPipeline) enqueue(env telemetryEnvelope) bool {
	select {
	case p.queue <- env:
		return true
	default:
		return false
	}
}

type failureState struct {
	count        int
	lastFailure  time.Time
	blockedUntil time.Time
}

type failureTracker struct {
	mu      sync.Mutex
	entries map[string]failureState
}

func newFailureTracker() *failureTracker {
	return &failureTracker{entries: make(map[string]failureState)}
}

func (t *failureTracker) blocked(remote string, now time.Time) bool {
	host := remoteHost(remote)
	t.mu.Lock()
	defer t.mu.Unlock()
	state, ok := t.entries[host]
	if !ok {
		return false
	}
	if now.After(state.blockedUntil) {
		state.blockedUntil = time.Time{}
		state.count = 0
		t.entries[host] = state
		return false
	}
	return !state.blockedUntil.IsZero()
}

func (t *failureTracker) recordFailure(remote string, now time.Time) bool {
	host := remoteHost(remote)
	t.mu.Lock()
	defer t.mu.Unlock()
	state := t.entries[host]
	if now.Sub(state.lastFailure) > ingestFailureWindow {
		state.count = 0
	}
	state.count++
	state.lastFailure = now
	if state.count >= ingestFailureThreshold {
		state.blockedUntil = now.Add(ingestBlacklistDuration)
	}
	t.entries[host] = state
	return !state.blockedUntil.IsZero()
}

func (t *failureTracker) clear(remote string) {
	host := remoteHost(remote)
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, host)
}

func remoteHost(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

type tcpIngestServer struct {
	cfg      *config.Config
	store    *storage.Store
	pipeline *telemetryPipeline
	failures *failureTracker
}

func newTCPIngestServer(cfg *config.Config, store *storage.Store, handler *Handlers) *tcpIngestServer {
	return &tcpIngestServer{
		cfg:      cfg,
		store:    store,
		pipeline: newTelemetryPipeline(handler),
		failures: newFailureTracker(),
	}
}

func (s *tcpIngestServer) Start(ctx context.Context) error {
	addr := fmt.Sprintf("[::]:%d", s.cfg.IngestTCPPort)
	ln, err := listen(addr)
	if err != nil {
		return fmt.Errorf("ingest listen: %w", err)
	}
	if s.cfg.IngestTCPTLS {
		if s.cfg.TLSCertPath == "" || s.cfg.TLSKeyPath == "" {
			_ = ln.Close()
			return fmt.Errorf("ingest TLS requires TLS_CERT_PATH and TLS_KEY_PATH")
		}
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertPath, s.cfg.TLSKeyPath)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("load ingest TLS cert/key: %w", err)
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
		log.Printf("ingest: listening with TLS on %s", addr)
	} else {
		log.Printf("ingest: listening on %s", addr)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Printf("ingest: temporary accept error: %v", err)
				continue
			}
			return fmt.Errorf("accept ingest connection: %w", err)
		}
		go s.handleConn(conn)
	}
}

func (s *tcpIngestServer) handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	now := time.Now()
	if s.failures.blocked(remote, now) {
		log.Printf("ingest: dropping blacklisted client %s", remote)
		return
	}
	log.Printf("ingest: accepted connection from %s", remote)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(ingestReadTimeout)); err != nil {
			log.Printf("ingest: set deadline failed for %s: %v", remote, err)
			return
		}
		payload, err := readIngestFrame(conn)
		if err != nil {
			if err == io.EOF {
				return
			}
			if isConnectionClose(err) {
				return
			}
			blocked := s.failures.recordFailure(remote, time.Now())
			log.Printf("ingest: rejected frame from %s: %v", remote, err)
			if blocked {
				log.Printf("ingest: blacklisted %s after repeated failures", remoteHost(remote))
			}
			return
		}
		if err := s.processPayload(payload, remote, time.Now()); err != nil {
			blocked := s.failures.recordFailure(remote, time.Now())
			log.Printf("ingest: rejected payload from %s: %v", remote, err)
			if blocked {
				log.Printf("ingest: blacklisted %s after repeated failures", remoteHost(remote))
			}
			return
		}
		s.failures.clear(remote)
	}
}

func isConnectionClose(err error) bool {
	return err == io.EOF || err == net.ErrClosed
}

func readIngestFrame(r io.Reader) (ingestPayload, error) {
	var frameLenBuf [4]byte
	if _, err := io.ReadFull(r, frameLenBuf[:]); err != nil {
		return ingestPayload{}, err
	}
	frameLen := binary.BigEndian.Uint32(frameLenBuf[:])
	if frameLen == 0 || frameLen > ingestMaxFrameSize {
		return ingestPayload{}, fmt.Errorf("invalid frame size %d", frameLen)
	}
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(r, frame); err != nil {
		return ingestPayload{}, err
	}
	var payload ingestPayload
	if err := json.Unmarshal(frame, &payload); err != nil {
		return ingestPayload{}, fmt.Errorf("decode frame JSON: %w", err)
	}
	if payload.Device == "" || payload.Sig == "" || payload.TS == 0 {
		return ingestPayload{}, fmt.Errorf("missing required payload fields")
	}
	return payload, nil
}

func canonicalTelemetryString(payload ingestPayload) (string, error) {
	dataJSON, err := json.Marshal(payload.Data)
	if err != nil {
		return "", fmt.Errorf("marshal telemetry data: %w", err)
	}
	return fmt.Sprintf("%s\n%d\n%d\n%s", payload.Device, payload.Seq, payload.TS, dataJSON), nil
}

func verifyTelemetrySignature(secret string, payload ingestPayload) error {
	canonical, err := canonicalTelemetryString(payload)
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

func (s *tcpIngestServer) processPayload(payload ingestPayload, remote string, receivedAt time.Time) error {
	record, ok := s.store.Device(payload.Device)
	if !ok {
		return fmt.Errorf("unknown device %q", payload.Device)
	}
	if err := verifyTelemetrySignature(record.Key, payload); err != nil {
		return err
	}
	if err := s.store.AcceptSequence(payload.Device, payload.Seq); err != nil {
		return err
	}
	env := telemetryEnvelope{
		Payload:    payload,
		RemoteAddr: remote,
		ReceivedAt: receivedAt,
	}
	if s.pipeline.enqueue(env) {
		return nil
	}
	fallbackRecord := map[string]any{
		"received_at": receivedAt.UTC().Format(time.RFC3339Nano),
		"remote_addr": remote,
		"payload":     payload,
		"reason":      "ingest queue full",
	}
	if err := s.store.AppendIngestFallback(fallbackRecord); err != nil {
		log.Printf("ingest: failed to append fallback record: %v", err)
	} else {
		log.Printf("ingest: queued overflow fallback for device=%s seq=%d", payload.Device, payload.Seq)
	}
	return nil
}
