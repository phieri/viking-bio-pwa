package configure

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/phieri/viking-bio-pwa/configurator/internal/serial"
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

	ports, err := serial.New("").ListPorts()
	return err == nil && len(ports) == 1
}

func RunLocalUI(explicitPort string, store *storage.Store) error {
	port, err := resolvePort(explicitPort)
	if err != nil {
		return err
	}

	bridge := serial.New(port)
	if err := bridge.Connect(); err != nil {
		return err
	}
	defer bridge.Disconnect()

	if displayAvailable() {
		RunGUI(bridge, store)
		return nil
	}

	NewTUI(bridge, store).Run()
	return nil
}
