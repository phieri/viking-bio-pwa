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
	"runtime"
	"strings"
	"syscall"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	"github.com/phieri/viking-bio-pwa/proxy/internal/configure"
	"github.com/phieri/viking-bio-pwa/proxy/internal/mdns"
	"github.com/phieri/viking-bio-pwa/proxy/internal/serial"
	"github.com/phieri/viking-bio-pwa/proxy/internal/server"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

const version = "1.0.0"

func main() {
	var (
		showVersion = flag.Bool("version", false, "print version and exit")
		doConfig    = flag.Bool("configure", false, "run device configurator (GUI when display available, TUI otherwise)")
		serialPort  = flag.String("port", "", "serial port for --configure (e.g. /dev/ttyACM0)")
		notifyOnly  = flag.Bool("notify-only", false, "run in notification-only mode: no dashboard, local network connections only")
	)
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
	// This lets operators configure the proxy by editing <data-dir>/viking-bio.conf without
	// needing a .env file next to the binary. Values already set (e.g. from .env or the
	// environment) are not overridden.
	loadDotEnv(filepath.Join(config.DefaultDataDir(), "viking-bio.conf"))

	if *doConfig {
		runConfigurator(*serialPort)
		return
	}

	runServer(*notifyOnly)
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

func runServer(notifyOnly bool) {
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
	srv := server.New(cfg, store, notifyOnly)

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

func runConfigurator(portArg string) {
	cfg, _ := config.Load()
	portName := portArg
	dataDir := config.DefaultDataDir()
	if portName == "" && cfg != nil {
		portName = cfg.PicoSerialPort
	}
	if cfg != nil && cfg.DataDir != "" {
		dataDir = cfg.DataDir
	}

	bridge := serial.New(portName)
	store, err := storage.NewStore(dataDir)
	if err != nil {
		fmt.Printf("Failed to open storage: %v\n", err)
		return
	}

	if portName == "" {
		// List ports and ask the user
		ports, err := bridge.ListPorts()
		if err != nil || len(ports) == 0 {
			fmt.Println("No serial ports found. Specify one with --port /dev/ttyACM0")
			return
		}
		fmt.Println("Available serial ports:")
		for i, p := range ports {
			fmt.Printf("  %d. %s\n", i+1, p.Name)
		}
		fmt.Print("Select port number: ")
		var n int
		if _, err := fmt.Scan(&n); err != nil || n < 1 || n > len(ports) {
			fmt.Println("Invalid selection.")
			return
		}
		portName = ports[n-1].Name
		bridge = serial.New(portName)
	}

	if err := bridge.Connect(); err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer bridge.Disconnect()

	if guiAvailable() {
		configure.RunGUI(bridge, store)
	} else {
		tui := configure.NewTUI(bridge, store)
		tui.Run()
	}
}

// guiAvailable returns true when a graphical display is likely available.
// On Linux/BSD it checks the DISPLAY (X11) and WAYLAND_DISPLAY environment
// variables. On Windows and macOS a display is assumed to always be present.
// Setting NO_GUI=1 forces the TUI regardless of platform.
func guiAvailable() bool {
	if os.Getenv("NO_GUI") != "" {
		return false
	}
	switch runtime.GOOS {
	case "windows", "darwin":
		return true
	default:
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	}
}
