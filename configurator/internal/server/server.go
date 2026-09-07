package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/phieri/viking-bio-pwa/configurator/internal/config"
	"github.com/phieri/viking-bio-pwa/configurator/internal/storage"
)

// Server wraps the runtime state and the ingest listener.
type Server struct {
	cfg       *config.Config
	handler   *Handlers
	ingestSrv *tcpIngestServer
}

func (s *Server) Handlers() *Handlers {
	if s == nil {
		return nil
	}
	return s.handler
}

func (s *Server) State() *State {
	if s == nil || s.handler == nil {
		return nil
	}
	return s.handler.State()
}

func New(cfg *config.Config, store *storage.Store) *Server {
	h := NewHandlers(cfg)
	return &Server{
		cfg:       cfg,
		handler:   h,
		ingestSrv: newTCPIngestServer(cfg, store, h),
	}
}

func (s *Server) Start(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("server is nil")
	}
	if s.ingestSrv == nil {
		return fmt.Errorf("ingest server is not configured")
	}
	go func() {
		if err := s.ingestSrv.Start(ctx); err != nil && ctx.Err() == nil {
			log.Printf("ingest: %v", err)
		}
	}()

	<-ctx.Done()
	return nil
}

func listen(addr string) (net.Listener, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, fmt.Errorf("listen address is empty")
	}
	ln, err := net.Listen("tcp6", addr)
	if err == nil {
		return ln, nil
	}
	ln, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return ln, nil
}
