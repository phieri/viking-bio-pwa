/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package provisioning

import (
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

func waitForConnection(connect func() error, portName string, pollInterval time.Duration, onConnected func()) {
	go func() {
		for {
			if err := connect(); err == nil {
				if onConnected != nil {
					onConnected()
				}
				return
			}
			if portName != "" {
				log.Printf("serial: waiting for configured port %s to become available", portName)
			}
			if pollInterval > 0 {
				time.Sleep(pollInterval)
			}
		}
	}()
}

func startPortMonitor(bridge *serial.Bridge, store *storage.Store, telemetryState ...*server.State) {
	waitForConnection(func() error {
		return bridge.Connect()
	}, bridge.PortName(), 2*time.Second, func() {
		if displayAvailable() {
			RunGUI(bridge, store, telemetryState...)
			return
		}
		if interactiveSession() {
			NewTUI(bridge, store, telemetryState...).Run()
			return
		}
	})
}

func RunLocalUI(explicitPort string, store *storage.Store, telemetryState ...*server.State) error {
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
			startPortMonitor(bridge, store, telemetryState...)
			return nil
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
