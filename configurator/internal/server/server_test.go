/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package server

import (
	"context"
	"testing"
	"time"

	"github.com/phieri/viking-bio-pwa/configurator/internal/config"
	"github.com/phieri/viking-bio-pwa/configurator/internal/storage"
)

func TestServerStartStopsWhenContextCancels(t *testing.T) {
	t.Parallel()

	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	srv := New(&config.Config{IngestTCPPort: 0}, store)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}
