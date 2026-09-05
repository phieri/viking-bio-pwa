package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/phieri/viking-bio-pwa/configurator/internal/config"
	"github.com/phieri/viking-bio-pwa/configurator/internal/mdns"
	"github.com/phieri/viking-bio-pwa/configurator/internal/server"
	"github.com/phieri/viking-bio-pwa/configurator/internal/storage"
)

const version = "1.0.0"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Viking Bio Configurator v%s\n\nUsage: %s [options]\n\nOptions:\n", version, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("viking-bio-configurator v%s\n", version)
		return
	}

	// Load .env file if present (best-effort)
	loadDotEnv(".env")
	// Also load config from the data directory (created on first run by storage.NewStore).
	// This lets operators configure the configurator by editing <data-dir>/viking-bio.conf
	// without needing a .env file next to the binary. Values already set (e.g. from .env or
	// the environment) are not overridden.
	loadDotEnv(filepath.Join(config.DefaultDataDir(), "viking-bio.conf"))

	runServer()
}

// loadDotEnv reads a simple KEY=VALUE file and sets environment variables.
// Skips lines starting with '#' and empty lines. Does not override existing vars.
func loadDotEnv(path string) {
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
		// Remove surrounding quotes
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, value)
		}
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
		mdnsAdv.Start(cfg.HTTPPort, cfg.MDNSName)
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

	if err := srv.Start(ctx); err != nil {
		log.Printf("server: %v", err)
	}
	log.Println("Viking Bio Configurator stopped.")
}
