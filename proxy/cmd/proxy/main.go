package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	"github.com/phieri/viking-bio-pwa/proxy/internal/configure"
	"github.com/phieri/viking-bio-pwa/proxy/internal/ddns"
	"github.com/phieri/viking-bio-pwa/proxy/internal/mdns"
	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/serial"
	"github.com/phieri/viking-bio-pwa/proxy/internal/server"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

const version = "1.0.0"

func main() {
	var (
		showVersion   = flag.Bool("version", false, "print version and exit")
		doConfig      = flag.Bool("configure", false, "run device configurator TUI")
		serialPort    = flag.String("port", "", "serial port for --configure (e.g. /dev/ttyACM0)")
		noOpenBrowser = flag.Bool("no-open-browser", false, "do not open the browser automatically on startup")
		notifyTest    = flag.Bool("notify-test", false, "send a test push notification to all subscribers and exit")
		notifyOnly    = flag.Bool("notify-only", false, "run in notification-only mode: no dashboard, no Let's Encrypt/DuckDNS, local network connections only")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Viking Bio Proxy v%s\n\nUsage: %s [options]\n\nOptions:\n", version, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("viking-bio-proxy v%s\n", version)
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

	if *notifyTest {
		runNotifyTest()
		return
	}

	runServer(*noOpenBrowser, *notifyOnly)
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

func runServer(noOpenBrowser bool, notifyOnly bool) {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	store, err := storage.NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}

	pushMgr, err := push.New(cfg.DataDir, cfg.VAPIDContactEmail, store)
	if err != nil {
		log.Fatalf("push: %v", err)
	}

	// mDNS advertiser
	var mdnsAdv mdns.Advertiser
	if !cfg.MDNSDisable {
		mdnsAdv.Start(cfg.HTTPPort, cfg.MDNSName)
		defer mdnsAdv.Stop()
	} else {
		log.Println("mdns: disabled (MDNS_DISABLE is set)")
	}

	// DDNS client – skipped in notify-only mode
	if !notifyOnly {
		ddnsClient := ddns.New(cfg.DDNSSubdomain, cfg.DDNSToken)
		if ddnsClient != nil {
			ddnsClient.Start()
			defer ddnsClient.Stop()
		}
	}

	// Create server
	srv := server.New(cfg, pushMgr, store, notifyOnly)

	// Open the browser automatically unless disabled by flag or CI environment.
	if !noOpenBrowser && !notifyOnly && os.Getenv("CI") == "" {
		srv.OnReady = func(url string) {
			log.Printf("browser: opening %s", url)
			openBrowser(url)
		}
	}

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
	log.Println("Viking Bio Proxy stopped.")
}

func runNotifyTest() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	store, err := storage.NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}

	pushMgr, err := push.New(cfg.DataDir, cfg.VAPIDContactEmail, store)
	if err != nil {
		log.Fatalf("push: %v", err)
	}

	count := pushMgr.GetSubscriptionCount()
	if count == 0 {
		fmt.Println("No subscribers to notify.")
		return
	}
	fmt.Printf("Sending test notification to %d subscriber(s)...\n", count)
	pushMgr.SendTest()
	fmt.Println("Done.")
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

	tui := configure.NewTUI(bridge, store)
	tui.Run()
}

// openBrowser opens the given URL in the system default browser.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("browser: could not open %s: %v", url, err)
		return
	}
	// Reap the child process to avoid zombies.
	go func() { _ = cmd.Wait() }()
}
