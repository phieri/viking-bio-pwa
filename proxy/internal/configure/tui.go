package configure

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/phieri/viking-bio-pwa/proxy/internal/serial"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

const (
	colorReset  = "\033[0m"
	colorCyan   = "\033[36m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorBold   = "\033[1m"
)

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func color(s, c string) string {
	if !isTTY() {
		return s
	}
	return c + s + colorReset
}

// TUI provides the interactive device configurator menu.
type TUI struct {
	bridge  *serial.Bridge
	store   *storage.Store
	scanner *bufio.Scanner
}

// NewTUI creates a TUI attached to the given bridge.
func NewTUI(bridge *serial.Bridge, store *storage.Store) *TUI {
	return &TUI{
		bridge:  bridge,
		store:   store,
		scanner: bufio.NewScanner(os.Stdin),
	}
}

func (t *TUI) readLine(prompt string) string {
	fmt.Print(prompt)
	if t.scanner.Scan() {
		return strings.TrimSpace(t.scanner.Text())
	}
	return ""
}

func (t *TUI) printHeader() {
	fmt.Println()
	fmt.Println(color("╔══════════════════════════════════════╗", colorCyan))
	fmt.Println(color("║  Viking Bio – Device Configurator    ║", colorCyan))
	fmt.Println(color("╚══════════════════════════════════════╝", colorCyan))
	fmt.Println()
}

func (t *TUI) printMenu() {
	fmt.Println(color("  1.", colorYellow) + " Show device status")
	fmt.Println(color("  2.", colorYellow) + " Configure WiFi (SSID + password)")
	fmt.Println(color("  3.", colorYellow) + " Set Wi-Fi country code")
	fmt.Println(color("  4.", colorYellow) + " Set proxy server address & port")
	fmt.Println(color("  5.", colorYellow) + " Provision telemetry device key")
	fmt.Println(color("  6.", colorYellow) + " Clear all credentials")
	fmt.Println(color("  0.", colorRed) + " Exit")
	fmt.Println()
}

func (t *TUI) sendAndPrint(cmd string) {
	fmt.Printf("→ %s\n", color(cmd, colorCyan))
	lines, err := t.bridge.SendCommand(cmd)
	if err != nil {
		fmt.Println(color("Error: "+err.Error(), colorRed))
		return
	}
	for _, l := range lines {
		fmt.Println("  " + l)
	}
}

// sendSilent sends a command without echoing it to stdout (for sensitive values).
func (t *TUI) sendSilent(cmd string) {
	lines, err := t.bridge.SendCommand(cmd)
	if err != nil {
		fmt.Println(color("Error: "+err.Error(), colorRed))
		return
	}
	for _, l := range lines {
		fmt.Println("  " + l)
	}
}

func (t *TUI) showStatus() {
	status, err := t.bridge.GetStatus()
	if err != nil {
		fmt.Println(color("Error reading status: "+err.Error(), colorRed))
		return
	}
	fmt.Println()
	fmt.Println(color("Device Status:", colorBold))
	if status.Connected {
		fmt.Println("  WiFi:     " + color("connected", colorGreen))
	} else {
		fmt.Println("  WiFi:     " + color("not connected", colorRed))
	}
	for _, addr := range status.Addresses {
		fmt.Println("  Address:  " + addr)
	}
	if status.Country != "" {
		fmt.Println("  Country:  " + status.Country)
	}
	if status.DeviceID != "" {
		fmt.Println("  Device:   " + status.DeviceID)
	}
	if status.Server != "" {
		fmt.Printf("  Server:   %s:%d\n", status.Server, status.Port)
	}
	if status.Telemetry != "" {
		fmt.Println("  Telemetry: " + status.Telemetry)
	}
	if status.DeviceKey != "" {
		fmt.Println("  DeviceKey: " + status.DeviceKey)
	}
	if status.Token != "" {
		fmt.Println("  Token:    " + status.Token)
	}
	fmt.Println()
}

func (t *TUI) configureWiFi() {
	ssid := t.readLine("SSID: ")
	if ssid == "" {
		fmt.Println(color("Cancelled.", colorYellow))
		return
	}
	password := t.readLine("Password: ")
	t.sendAndPrint("SSID=" + ssid)
	t.sendSilent("PASS=" + password) // password not echoed to stdout
	fmt.Println(color("Credentials saved. Device will reboot.", colorGreen))
}

func (t *TUI) setCountry() {
	cc := t.readLine("Country code (e.g. SE, US): ")
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 {
		fmt.Println(color("Invalid country code (must be 2 letters).", colorRed))
		return
	}
	t.sendAndPrint("COUNTRY=" + cc)
}

func (t *TUI) setServer() {
	addr := t.readLine("Server IP/hostname: ")
	if addr == "" {
		fmt.Println(color("Cancelled.", colorYellow))
		return
	}
	port := t.readLine("Server port [9000]: ")
	if port == "" {
		port = "9000"
	}
	t.sendAndPrint("SERVER=" + addr)
	t.sendAndPrint("PORT=" + port)
}

func randomDeviceKey() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func (t *TUI) provisionDeviceKey() {
	status, err := t.bridge.GetStatus()
	if err != nil {
		fmt.Println(color("Error reading status: "+err.Error(), colorRed))
		return
	}
	if status.DeviceID == "" {
		fmt.Println(color("Device ID missing from STATUS output.", colorRed))
		return
	}
	key, err := randomDeviceKey()
	if err != nil {
		fmt.Println(color("Error generating device key: "+err.Error(), colorRed))
		return
	}
	if err := t.store.ProvisionDevice(status.DeviceID, key); err != nil {
		fmt.Println(color("Error storing device key: "+err.Error(), colorRed))
		return
	}
	t.sendAndPrint("DEVICEKEY=" + key)
	fmt.Println(color("Telemetry key provisioned for "+status.DeviceID+".", colorGreen))
}

func (t *TUI) clearCredentials() {
	confirm := t.readLine("Type YES to confirm clearing all credentials: ")
	if confirm != "YES" {
		fmt.Println(color("Cancelled.", colorYellow))
		return
	}
	t.sendAndPrint("CLEAR")
	fmt.Println(color("Credentials cleared. Device will reboot.", colorGreen))
}

// Run starts the interactive TUI loop.
func (t *TUI) Run() {
	t.printHeader()
	for {
		t.printMenu()
		choice := t.readLine(color("Choice: ", colorBold))
		switch choice {
		case "1":
			t.showStatus()
		case "2":
			t.configureWiFi()
		case "3":
			t.setCountry()
		case "4":
			t.setServer()
		case "5":
			t.provisionDeviceKey()
		case "6":
			t.clearCredentials()
		case "0", "q", "quit", "exit":
			fmt.Println(color("Bye!", colorCyan))
			return
		default:
			fmt.Println(color("Unknown option.", colorYellow))
		}
		fmt.Println()
	}
}
