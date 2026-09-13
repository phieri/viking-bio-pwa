/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package provisioning

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/phieri/viking-bio-pwa/configurator/internal/serial"
	"github.com/phieri/viking-bio-pwa/configurator/internal/server"
	"github.com/phieri/viking-bio-pwa/configurator/internal/storage"
)

func displayAvailable() bool {
	switch runtime.GOOS {
	case "windows", "darwin":
		return true
	default:
		return strings.TrimSpace(os.Getenv("DISPLAY")) != "" ||
			strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != ""
	}
}

func interactiveSession() bool {
	stdin, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	stdout, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (stdin.Mode()&os.ModeCharDevice) != 0 && (stdout.Mode()&os.ModeCharDevice) != 0
}

func resolvePort(explicit string) (string, error) {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		return explicit, nil
	}

	ports, err := serial.New("").ListPorts()
	if err != nil {
		return "", fmt.Errorf("list serial ports: %w", err)
	}
	if len(ports) == 0 {
		return "", fmt.Errorf("no Pico serial port found")
	}
	if len(ports) == 1 {
		return ports[0].Name, nil
	}

	names := make([]string, 0, len(ports))
	for _, port := range ports {
		names = append(names, port.Name)
	}
	sort.Strings(names)
	return "", fmt.Errorf("multiple serial ports found (%s); set PICO_SERIAL_PORT",
		strings.Join(names, ", "))
}

func ShouldLaunchLocalUI(explicitPort string) bool {
	if strings.TrimSpace(explicitPort) != "" {
		return true
	}
	if !displayAvailable() && !interactiveSession() {
		return false
	}

	// The local configurator may be started purely to inspect runtime/network state,
	// even when no Pico is currently connected over USB. In that case, the GUI/TUI
	// still opens in offline mode instead of exiting early.
	return true
}

func waitForConnection(ctx context.Context, connect func() error, portName string, pollInterval time.Duration, onConnected func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	if pollInterval <= 0 {
		pollInterval = 100 * time.Millisecond
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if err := connect(); err == nil {
				if onConnected != nil {
					onConnected()
				}
				return
			}
			if portName != "" {
				log.Printf("serial: waiting for configured port %s to become available", portName)
			}
			timer := time.NewTimer(pollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

var ErrPortWatchActive = fmt.Errorf("provisioning: waiting for configured serial port")

func startPortMonitor(ctx context.Context, cancel func(), bridge *serial.Bridge, store *storage.Store, telemetryState ...*server.State) {
	waitForConnection(ctx, func() error {
		return bridge.Connect()
	}, bridge.PortName(), 2*time.Second, func() {
		if displayAvailable() {
			RunGUI(bridge, store, telemetryState...)
			bridge.Disconnect()
			if cancel != nil {
				cancel()
			}
			return
		}
		if interactiveSession() {
			NewTUI(bridge, store, telemetryState...).Run()
			bridge.Disconnect()
			if cancel != nil {
				cancel()
			}
			return
		}
		if cancel != nil {
			cancel()
		}
	})
}

func RunLocalUI(ctx context.Context, cancel func(), explicitPort string, store *storage.Store, telemetryState ...*server.State) error {
	if ctx == nil {
		ctx = context.Background()
	}
	port, err := resolvePort(explicitPort)
	if err != nil {
		if strings.TrimSpace(explicitPort) == "" && (displayAvailable() || interactiveSession()) {
			bridge := serial.New("")
			if displayAvailable() {
				RunGUI(bridge, store, telemetryState...)
				return nil
			}
			NewTUI(bridge, store, telemetryState...).Run()
			return nil
		}
		return err
	}

	bridge := serial.New(port)
	if err := bridge.Connect(); err != nil {
		if strings.TrimSpace(explicitPort) != "" {
			log.Printf("provisioning: configured port %s is unavailable; waiting for it to appear", port)
			startPortMonitor(ctx, cancel, bridge, store, telemetryState...)
			return ErrPortWatchActive
		}
		return err
	}
	defer bridge.Disconnect()

	if displayAvailable() {
		RunGUI(bridge, store, telemetryState...)
		return nil
	}

	if interactiveSession() {
		NewTUI(bridge, store, telemetryState...).Run()
		return nil
	}
	return nil
}
