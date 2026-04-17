package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	ingestcodec "github.com/phieri/viking-bio-pwa/proxy/internal/ingest"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

const (
	ingestQueueSize         = 64
	ingestFailureWindow     = time.Minute
	ingestBlacklistDuration = 5 * time.Minute
	ingestFailureThreshold  = 5
	ingestReadTimeout       = 2 * time.Minute
)

func machineDataFromTelemetry(d ingestcodec.TelemetryData) machineDataBody {
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

type telemetryEnvelope struct {
	Payload    ingestcodec.Payload
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
		p.handler.processMachineData(machineDataFromTelemetry(env.Payload.Data), "ingest", env.ReceivedAt)
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
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				log.Printf("ingest: timeout on accept: %v", err)
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
		payload, err := ingestcodec.ReadFrame(conn)
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

func (s *tcpIngestServer) processPayload(payload ingestcodec.Payload, remote string, receivedAt time.Time) error {
	record, ok := s.store.Device(payload.Device)
	if !ok {
		return fmt.Errorf("unknown device %q", payload.Device)
	}
	if err := ingestcodec.VerifySignature(record.Key, payload); err != nil {
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
