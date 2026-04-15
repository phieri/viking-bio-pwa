package serial

import (
	"bytes"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	goserial "go.bug.st/serial"
)

const (
	baudRate         = 115200
	silenceTimeout   = 500 * time.Millisecond
	defaultTimeoutMs = 4000
)

// PortInfo describes a serial port.
type PortInfo struct {
	Name string
}

// StatusResult holds parsed output from the Pico STATUS command.
type StatusResult struct {
	Connected bool
	Addresses []string
	Country   string
	DeviceID  string
	Server    string
	Port      int
	Telemetry string
	DeviceKey string
	Webhook   string
	Token     string
}

// Bridge communicates with the Pico W over USB serial.
type Bridge struct {
	portName string
	port     goserial.Port
}

// New creates a Bridge for the given serial port.
func New(portName string) *Bridge {
	return &Bridge{portName: portName}
}

// Connect opens the serial port.
func (b *Bridge) Connect() error {
	mode := &goserial.Mode{BaudRate: baudRate}
	p, err := goserial.Open(b.portName, mode)
	if err != nil {
		return fmt.Errorf("serial: open %s: %w", b.portName, err)
	}
	b.port = p
	log.Printf("serial: connected to %s", b.portName)
	return nil
}

// Disconnect closes the serial port.
func (b *Bridge) Disconnect() {
	if b.port != nil {
		_ = b.port.Close()
		b.port = nil
		log.Println("serial: disconnected")
	}
}

// SendCommand sends a command and collects lines until silence or total timeout.
// timeoutMs[0] overrides the default 4000 ms total timeout.
func (b *Bridge) SendCommand(cmd string, timeoutMs ...int) ([]string, error) {
	if b.port == nil {
		return nil, fmt.Errorf("serial: not connected")
	}

	totalMs := defaultTimeoutMs
	if len(timeoutMs) > 0 && timeoutMs[0] > 0 {
		totalMs = timeoutMs[0]
	}

	// Send command
	if _, err := fmt.Fprintf(b.port, "%s\n", cmd); err != nil {
		return nil, fmt.Errorf("serial: write: %w", err)
	}

	// Set a short per-read timeout so we can detect silence
	if err := b.port.SetReadTimeout(silenceTimeout); err != nil {
		return nil, fmt.Errorf("serial: set read timeout: %w", err)
	}

	var lines []string
	buf := make([]byte, 4096)
	var partial []byte
	deadline := time.Now().Add(time.Duration(totalMs) * time.Millisecond)

	for time.Now().Before(deadline) {
		n, err := b.port.Read(buf)
		if n > 0 {
			partial = append(partial, buf[:n]...)
			// Extract complete lines
			for {
				idx := bytes.IndexByte(partial, '\n')
				if idx < 0 {
					break
				}
				line := strings.TrimRight(string(partial[:idx]), "\r")
				if line != "" {
					lines = append(lines, line)
				}
				partial = partial[idx+1:]
			}
		}
		if err != nil {
			// Read timeout means silence – if we have any lines, we're done
			if len(lines) > 0 {
				break
			}
			// No lines yet; keep waiting until total deadline
		}
	}
	return lines, nil
}

// GetStatus sends the STATUS command and parses the result.
func (b *Bridge) GetStatus() (StatusResult, error) {
	lines, err := b.SendCommand("STATUS")
	if err != nil {
		return StatusResult{}, err
	}
	return b.ParseStatus(lines), nil
}

// ParseStatus parses the multi-line output of the STATUS command.
func (b *Bridge) ParseStatus(lines []string) StatusResult {
	var r StatusResult
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "connected") && !strings.Contains(lower, "disconnected") {
			r.Connected = true
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		switch key {
		case "addr", "address":
			r.Addresses = append(r.Addresses, value)
		case "country":
			r.Country = value
		case "device":
			r.DeviceID = value
		case "server":
			if idx := strings.LastIndex(value, ":"); idx > 0 {
				r.Server = strings.TrimSpace(value[:idx])
				n, err := strconv.Atoi(strings.TrimSpace(value[idx+1:]))
				if err != nil {
					log.Printf("serial: parse server port value: %v", err)
				} else {
					r.Port = n
				}
			} else {
				r.Server = value
			}
		case "port":
			n, err := strconv.Atoi(value)
			if err != nil {
				log.Printf("serial: parse Port value: %v", err)
			} else {
				r.Port = n
			}
		case "telemetry":
			r.Telemetry = value
		case "device key":
			r.DeviceKey = value
		case "webhook", "hook":
			r.Webhook = value
		case "token":
			r.Token = value
		}
	}
	return r
}

// ListPorts returns available serial ports.
func (b *Bridge) ListPorts() ([]PortInfo, error) {
	ports, err := goserial.GetPortsList()
	if err != nil {
		return nil, err
	}
	out := make([]PortInfo, len(ports))
	for i, p := range ports {
		out[i] = PortInfo{Name: p}
	}
	return out, nil
}
