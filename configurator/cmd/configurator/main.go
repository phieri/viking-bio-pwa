/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package main

import (
	"bufio"
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/phieri/viking-bio-pwa/configurator/internal/config"
	"github.com/phieri/viking-bio-pwa/configurator/internal/mdns"
	"github.com/phieri/viking-bio-pwa/configurator/internal/provisioning"
	"github.com/phieri/viking-bio-pwa/configurator/internal/server"
	"github.com/phieri/viking-bio-pwa/configurator/internal/storage"
)

func main() {
	// Load .env file if present (best-effort)
	loadDotEnv(".env")
	// Also load config from the data directory when present. A default viking-bio.conf is
	// created only when the file is missing; existing settings are never overwritten. Values
	// already set (e.g. from .env or the environment) are not overridden.
	loadDotEnv(filepath.Join(config.DefaultDataDir(), "viking-bio.conf"))

	runServer()
}

// loadDotEnv reads a simple KEY=VALUE file and sets environment variables.
// Skips lines starting with '#' and empty lines. Does not override existing vars.
func loadDotEnv(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			continue
		}
		// Remove surrounding quotes.
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, value)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("config: failed to parse %s: %v", path, err)
	}
}

func runServer() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	store, err := storage.NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}

	// mDNS advertiser
	var mdnsAdv mdns.Advertiser
	if !cfg.MDNSDisable {
		mdnsAdv.Start(cfg.IngestTCPPort, cfg.MDNSName)
		defer mdnsAdv.Stop()
	} else {
		log.Println("mdns: disabled (MDNS_DISABLE is set)")
	}

	// Create server
	srv := server.New(cfg, store)

	// No dashboard is served anymore; keep the server headless and rely on the
	// Fyne configurator for local operational status.

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("%s received, shutting down", sig)
		cancel()
	}()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		if err := srv.Start(ctx); err != nil && ctx.Err() == nil {
			log.Printf("server: %v", err)
			cancel()
		}
	}()

	if provisioning.ShouldLaunchLocalUI(cfg.PicoSerialPort) {
		if err := provisioning.RunLocalUI(cfg.PicoSerialPort, store, srv.State()); err != nil {
			log.Printf("provisioning: %v", err)
		}
		cancel()
	}

	<-ctx.Done()
	<-serverDone
	log.Println("Viking Bio Configurator stopped.")
}
