/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package provisioning

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/phieri/viking-bio-pwa/configurator/internal/i18n"
	"github.com/phieri/viking-bio-pwa/configurator/internal/serial"
	"github.com/phieri/viking-bio-pwa/configurator/internal/server"
	"github.com/phieri/viking-bio-pwa/configurator/internal/storage"
	appversion "github.com/phieri/viking-bio-pwa/configurator/internal/version"
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
	bridge         *serial.Bridge
	store          *storage.Store
	scanner        *bufio.Scanner
	telemetryState *server.State
	locale         string
}

func (t *TUI) text(key string) string {
	return i18n.Lookup(t.locale, key)
}

// NewTUI creates a TUI attached to the given bridge.
func NewTUI(bridge *serial.Bridge, store *storage.Store, telemetryState ...*server.State) *TUI {
	var state *server.State
	if len(telemetryState) > 0 {
		state = telemetryState[0]
	}
	return &TUI{
		bridge:         bridge,
		store:          store,
		scanner:        bufio.NewScanner(os.Stdin),
		telemetryState: state,
		locale:         i18n.ResolveLocale(os.Getenv("LANG")),
	}
}

func (t *TUI) readLine(prompt string) string {
	fmt.Print(prompt)
	if t.scanner.Scan() {
		return strings.TrimSpace(t.scanner.Text())
	}
	return ""
}

func formatHeaderLine(content string) string {
	const width = 34
	runes := []rune(content)
	if len(runes) > width {
		content = string([]rune(content)[:width-1]) + "…"
		runes = []rune(content)
	}
	return color("║ "+content+strings.Repeat(" ", width-len(runes))+" ║", colorCyan)
}

func (t *TUI) printHeader() {
	fmt.Println()
	fmt.Println(color("╔"+strings.Repeat("═", 36)+"╗", colorCyan))
	fmt.Println(formatHeaderLine(t.text("app.title")))
	fmt.Println(formatHeaderLine(fmt.Sprintf(t.text("app.version"), appversion.String())))
	fmt.Println(color("╚"+strings.Repeat("═", 36)+"╝", colorCyan))
	fmt.Println()
}

func (t *TUI) printMenu() {
	fmt.Println(color("  1.", colorYellow) + " " + t.text("menu.show_status"))
	fmt.Println(color("  2.", colorYellow) + " " + t.text("menu.configure_wifi"))
	fmt.Println(color("  3.", colorYellow) + " " + t.text("menu.set_country"))
	fmt.Println(color("  4.", colorYellow) + " " + t.text("menu.set_server"))
	fmt.Println(color("  5.", colorYellow) + " " + t.text("menu.set_webhook"))
	fmt.Println(color("  6.", colorYellow) + " " + t.text("menu.provision_key"))
	fmt.Println(color("  7.", colorYellow) + " " + t.text("menu.clear_credentials"))
	fmt.Println(color("  8.", colorYellow) + " " + t.text("menu.show_telemetry"))
	fmt.Println(color("  0.", colorRed) + " " + t.text("menu.exit"))
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
	fmt.Println(color(t.text("status.device"), colorBold))
	if status.Connected {
		fmt.Println("  WiFi:     " + color(t.text("status.connected"), colorGreen))
	} else {
		fmt.Println("  WiFi:     " + color(t.text("status.disconnected"), colorRed))
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
	if status.FirmwareVersion != "" {
		fmt.Println("  Firmware: " + status.FirmwareVersion)
	}
	if status.Server != "" {
		fmt.Printf("  Server:   %s:%d\n", status.Server, status.Port)
	}
	if status.Telemetry != "" {
		fmt.Println("  Telemetry: " + status.Telemetry)
	}
	if status.DeviceKey != "" {
		fmt.Println("  DeviceKey: " + maskSensitiveConfiguredValue(status.DeviceKey))
	}
	if status.Webhook != "" {
		fmt.Println("  Webhook:  " + normaliseConfiguredValue(status.Webhook))
	}
	fmt.Println()
}

func (t *TUI) showTelemetry() {
	if t.telemetryState == nil {
		fmt.Println(color(t.text("telemetry.unavailable"), colorYellow))
		return
	}
	fmt.Println()
	fmt.Println(color(t.text("telemetry.title"), colorBold))
	snapshot := t.telemetryState.Snapshot()
	if snapshot.UpdatedAt == 0 {
		fmt.Println(color("  "+t.text("status.waiting"), colorYellow))
		fmt.Println()
		return
	}
	fmt.Printf("  Flame: %t\n", snapshot.Flame)
	fmt.Printf("  Fan: %.1f\n", snapshot.Fan)
	fmt.Printf("  Temp: %.1f°C\n", snapshot.Temp)
	fmt.Printf("  Err: %.0f\n", snapshot.Err)
	fmt.Printf("  Valid: %t\n", snapshot.Valid)
	fmt.Printf("  Flame seconds: %d\n", snapshot.FlameSecs)
	fmt.Printf("  Updated: %s\n", time.UnixMilli(snapshot.UpdatedAt).Format(time.RFC3339))
	fmt.Println()
}

func (t *TUI) configureWiFi() {
	ssid := t.readLine(t.text("form.ssid") + ": ")
	if ssid == "" {
		fmt.Println(color(t.text("action.cancelled"), colorYellow))
		return
	}
	password := t.readLine(t.text("form.password") + ": ")
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
	addr := t.readLine(t.text("form.server_address") + ": ")
	if addr == "" {
		fmt.Println(color(t.text("action.cancelled"), colorYellow))
		return
	}
	port := t.readLine(t.text("form.port") + " [9000]: ")
	if port == "" {
		port = "9000"
	}
	t.sendAndPrint("SERVER=" + addr)
	t.sendAndPrint("PORT=" + port)
}

func (t *TUI) setWebhook() {
	url := t.readLine(t.text("form.webhook_url") + " (http:// or https://): ")
	if url == "" {
		fmt.Println(color(t.text("action.cancelled"), colorYellow))
		return
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fmt.Println(color("Webhook URL must start with http:// or https://.", colorRed))
		return
	}
	t.sendAndPrint("WEBHOOK=" + url)
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
		fmt.Println(color(t.text("action.cancelled"), colorYellow))
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
		choice := t.readLine(color(t.text("menu.choice"), colorBold))
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
			t.setWebhook()
		case "6":
			t.provisionDeviceKey()
		case "7":
			t.clearCredentials()
		case "8":
			t.showTelemetry()
		case "0", "q", "quit", "exit":
			fmt.Println(color("Bye!", colorCyan))
			return
		default:
			fmt.Println(color("Unknown option.", colorYellow))
		}
		fmt.Println()
	}
}
