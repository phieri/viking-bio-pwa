/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package serial

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	Connected       bool
	Addresses       []string
	Country         string
	DeviceID        string
	FirmwareVersion string
	Server          string
	Port            int
	Telemetry       string
	DeviceKey       string
	Webhook         string
	WebhookCA       string
}

// Bridge communicates with the Pico W over USB serial.
type Bridge struct {
	mu       sync.Mutex
	portName string
	port     goserial.Port
}

// New creates a Bridge for the given serial port.
func New(portName string) *Bridge {
	return &Bridge{portName: portName}
}

// PortName returns the configured serial port name.
func (b *Bridge) PortName() string {
	if b == nil {
		return ""
	}
	return b.portName
}

func selectAutoPort(portNames []string) (string, error) {
	clean := make([]string, 0, len(portNames))
	for _, p := range portNames {
		p = strings.TrimSpace(p)
		if p != "" {
			clean = append(clean, p)
		}
	}
	if len(clean) == 0 {
		return "", nil
	}
	if len(clean) == 1 {
		return clean[0], nil
	}
	sorted := append([]string(nil), clean...)
	sort.Strings(sorted)
	return "", fmt.Errorf("multiple serial ports found (%s); set PICO_SERIAL_PORT", strings.Join(sorted, ", "))
}

// EnsureConnected opens the configured serial port if it has not already been opened,
// or automatically selects a single attached port when the device is connected after
// the UI has already started running.
func (b *Bridge) EnsureConnected() error {
	if b.port != nil {
		return nil
	}

	portName := strings.TrimSpace(b.portName)
	if portName == "" {
		ports, err := goserial.GetPortsList()
		if err != nil {
			return fmt.Errorf("serial: list ports: %w", err)
		}
		selected, err := selectAutoPort(ports)
		if err != nil {
			return fmt.Errorf("serial: auto-detect: %w", err)
		}
		if selected == "" {
			return fmt.Errorf("serial: no port available")
		}
		portName = selected
	}

	if err := b.connectPort(portName); err != nil {
		return err
	}
	return nil
}

func (b *Bridge) connectPort(portName string) error {
	portName = strings.TrimSpace(portName)
	if portName == "" {
		return fmt.Errorf("serial: missing port name")
	}
	mode := &goserial.Mode{BaudRate: baudRate}
	p, err := goserial.Open(portName, mode)
	if err != nil {
		return fmt.Errorf("serial: open %s: %w", portName, err)
	}
	b.portName = portName
	b.port = p
	log.Printf("serial: connected to %s", portName)
	return nil
}

// Connect opens the serial port.
func (b *Bridge) Connect() error {
	return b.connectPort(b.portName)
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
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.port == nil {
		if err := b.EnsureConnected(); err != nil {
			return nil, err
		}
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

// SendConfirmedCommand requires the Pico's success response, not just a successful USB write.
func (b *Bridge) SendConfirmedCommand(cmd, confirmation string) error {
	lines, err := b.SendCommand(cmd)
	if err != nil {
		return err
	}
	if confirmedResponse(lines, confirmation) {
		return nil
	}
	return fmt.Errorf("serial: Pico did not confirm command")
}

const maxWebhookCACertBytes = 4096
const webhookCAChunkBytes = 64

// ParseWebhookCA accepts one PEM or DER CA certificate and returns its DER encoding.
func ParseWebhookCA(contents []byte) ([]byte, error) {
	if block, rest := pem.Decode(contents); block != nil {
		if block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("webhook CA must contain exactly one certificate")
		}
		contents = block.Bytes
	}
	if len(contents) == 0 || len(contents) > maxWebhookCACertBytes {
		return nil, fmt.Errorf("webhook CA certificate must be 1–%d DER bytes", maxWebhookCACertBytes)
	}
	cert, err := x509.ParseCertificate(contents)
	if err != nil || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("webhook CA must be a valid certificate authority with certificate-signing usage")
	}
	return contents, nil
}

// ProvisionWebhookCA transfers a CA certificate to the Pico over USB in bounded chunks.
func (b *Bridge) ProvisionWebhookCA(contents []byte) error {
	der, err := ParseWebhookCA(contents)
	if err != nil {
		return err
	}
	if err := b.SendConfirmedCommand(fmt.Sprintf("CABEGIN=%d", len(der)), "tls: CA transfer started"); err != nil {
		return err
	}
	for offset := 0; offset < len(der); offset += webhookCAChunkBytes {
		end := offset + webhookCAChunkBytes
		if end > len(der) {
			end = len(der)
		}
		if err := b.SendConfirmedCommand("CACHUNK="+hex.EncodeToString(der[offset:end]), "tls: CA chunk received"); err != nil {
			return err
		}
	}
	return b.SendConfirmedCommand("CACOMMIT", "tls: CA certificate saved – reboot to apply")
}

func (b *Bridge) ClearWebhookCA() error {
	return b.SendConfirmedCommand("CACLEAR", "tls: CA certificate cleared – reboot to apply")
}

func confirmedResponse(lines []string, confirmation string) bool {
	for _, line := range lines {
		if strings.TrimSpace(line) == confirmation {
			return true
		}
	}
	return false
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
		case "ipv6[0]", "ipv6[1]", "ipv6[2]", "ipv6[3]":
			r.Addresses = append(r.Addresses, value)
		case "country":
			r.Country = value
		case "device":
			r.DeviceID = value
		case "firmware", "version":
			r.FirmwareVersion = value
		case "server":
			if strings.EqualFold(value, "not configured") {
				r.Server = ""
				r.Port = 0
				break
			}
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
		case "webhook":
			r.Webhook = value
		case "webhook ca":
			r.WebhookCA = value
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
