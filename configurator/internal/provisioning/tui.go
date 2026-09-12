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
	localizer      provisioningLocalizer
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
		localizer:      newProvisioningLocalizer(),
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
	fmt.Println(formatHeaderLine(t.localizer.Text("app.title")))
	fmt.Println(formatHeaderLine(t.localizer.Text("app.version", appversion.String())))
	fmt.Println(color("╚"+strings.Repeat("═", 36)+"╝", colorCyan))
	fmt.Println()
}

func formatBoxLine(content string, width int) string {
	if len([]rune(content)) > width {
		content = string([]rune(content)[:width-1]) + "…"
	}
	return content + strings.Repeat(" ", width-len([]rune(content)))
}

func (t *TUI) printLogBox(title string, lines []string) {
	if len(lines) == 0 {
		return
	}
	const width = 62
	newlineLines := make([]string, 0, len(lines))
	for _, line := range lines {
		for _, part := range strings.Split(line, "\n") {
			newlineLines = append(newlineLines, strings.TrimRight(part, "\r"))
		}
	}
	fmt.Println()
	fmt.Println(color("╔"+strings.Repeat("═", width)+"╗", colorCyan))
	if title != "" {
		titleLine := " " + title + " "
		if len([]rune(titleLine)) > width-2 {
			titleLine = string([]rune(titleLine)[:width-3]) + "…"
		}
		fmt.Println(color("║"+formatBoxLine(titleLine, width-2)+"║", colorCyan))
		fmt.Println(color("╠"+strings.Repeat("═", width)+"╣", colorCyan))
	} else {
		fmt.Println(color("╠"+strings.Repeat("═", width)+"╣", colorCyan))
	}
	for _, line := range newlineLines {
		fmt.Println(color("║", colorCyan) + " " + formatBoxLine(line, width-4) + " " + color("║", colorCyan))
	}
	fmt.Println(color("╚"+strings.Repeat("═", width)+"╝", colorCyan))
	fmt.Println()
}

func (t *TUI) printMenu() {
	fmt.Println(color("  1.", colorYellow) + " " + t.localizer.Text("menu.option1"))
	fmt.Println(color("  2.", colorYellow) + " " + t.localizer.Text("menu.option2"))
	fmt.Println(color("  3.", colorYellow) + " " + t.localizer.Text("menu.option3"))
	fmt.Println(color("  4.", colorYellow) + " " + t.localizer.Text("menu.option4"))
	fmt.Println(color("  5.", colorYellow) + " " + t.localizer.Text("menu.option5"))
	fmt.Println(color("  6.", colorYellow) + " " + t.localizer.Text("menu.option6"))
	fmt.Println(color("  7.", colorYellow) + " " + t.localizer.Text("menu.option7"))
	fmt.Println(color("  8.", colorYellow) + " " + t.localizer.Text("menu.option8"))
	fmt.Println(color("  0.", colorRed) + " " + t.localizer.Text("menu.option0"))
	fmt.Println()
}

func (t *TUI) sendAndPrint(cmd string) {
	lines := []string{"→ " + cmd}
	resp, err := t.bridge.SendCommand(cmd)
	if err != nil {
		lines = append(lines, "Error: "+err.Error())
		t.printLogBox("command log", lines)
		return
	}
	for _, l := range resp {
		lines = append(lines, l)
	}
	t.printLogBox("command log", lines)
}

// sendSilent sends a command without echoing it to stdout (for sensitive values).
func (t *TUI) sendSilent(cmd string) {
	lines := []string{"(hidden)"}
	resp, err := t.bridge.SendCommand(cmd)
	if err != nil {
		lines = append(lines, "Error: "+err.Error())
		t.printLogBox("command log", lines)
		return
	}
	for _, l := range resp {
		lines = append(lines, l)
	}
	t.printLogBox("command log", lines)
}

func formatDeviceStatus(localizer provisioningLocalizer, status *serial.StatusResult, prefix string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s%-10s ", prefix, localizer.Text("field.wifi")+":"))
	if status.Connected {
		sb.WriteString(localizer.Text("status.wifi.connected") + "\n")
	} else {
		sb.WriteString(localizer.Text("status.wifi.disconnected") + "\n")
	}
	for _, addr := range status.Addresses {
		sb.WriteString(fmt.Sprintf("%s%-10s %s\n", prefix, localizer.Text("field.address")+":", addr))
	}
	if status.Country != "" {
		sb.WriteString(fmt.Sprintf("%s%-10s %s\n", prefix, localizer.Text("field.country")+":", localizer.regionLabel(status.Country)))
	}
	if status.DeviceID != "" {
		sb.WriteString(fmt.Sprintf("%s%-10s %s\n", prefix, localizer.Text("field.device")+":", status.DeviceID))
	}
	if status.FirmwareVersion != "" {
		sb.WriteString(fmt.Sprintf("%s%-10s %s\n", prefix, localizer.Text("field.firmware")+":", status.FirmwareVersion))
	}
	if status.Server != "" {
		sb.WriteString(fmt.Sprintf("%s%-10s %s:%d\n", prefix, localizer.Text("field.server")+":", status.Server, status.Port))
	}
	if status.Telemetry != "" {
		sb.WriteString(fmt.Sprintf("%s%-10s %s\n", prefix, localizer.Text("field.telemetry")+":", status.Telemetry))
	}
	if status.DeviceKey != "" {
		sb.WriteString(fmt.Sprintf("%s%-10s %s\n", prefix, localizer.Text("field.device_key")+":", maskSensitiveConfiguredValue(status.DeviceKey)))
	}
	if status.Webhook != "" {
		sb.WriteString(fmt.Sprintf("%s%-10s %s\n", prefix, localizer.Text("field.webhook")+":", normaliseConfiguredValue(status.Webhook)))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func formatTelemetrySnapshot(localizer provisioningLocalizer, flame bool, fan, temp, errValue float64, valid bool, flameSecs int64, updatedAt int64) string {
	return fmt.Sprintf(
		"%s: %t\n%s: %.1f\n%s: %.1f°C\n%s: %.0f\n%s: %t\n%s: %d\n%s: %s",
		localizer.Text("field.flame"),
		flame,
		localizer.Text("field.fan"),
		fan,
		localizer.Text("field.temp"),
		temp,
		localizer.Text("field.err"),
		errValue,
		localizer.Text("field.valid"),
		valid,
		localizer.Text("field.flame_seconds"),
		flameSecs,
		localizer.Text("status.last_contact"),
		time.UnixMilli(updatedAt).Format(time.RFC3339),
	)
}

func (t *TUI) showStatus() {
	status, err := t.bridge.GetStatus()
	if err != nil {
		t.printLogBox("status", []string{t.localizer.Text("error.reading_status", err.Error())})
		return
	}
	t.printLogBox("status", []string{
		t.localizer.Text("tui.device_status"),
		formatDeviceStatus(t.localizer, &status, "  "),
	})
}

func (t *TUI) showTelemetry() {
	if t.telemetryState == nil {
		t.printLogBox("telemetry", []string{t.localizer.Text("status.live_telemetry_unavailable")})
		return
	}
	snapshot := t.telemetryState.Snapshot()
	if snapshot.UpdatedAt == 0 {
		t.printLogBox("telemetry", []string{t.localizer.Text("status.live_telemetry_empty")})
		return
	}
	t.printLogBox("telemetry", []string{
		t.localizer.Text("tui.live_telemetry"),
		strings.ReplaceAll(formatTelemetrySnapshot(
			t.localizer,
			snapshot.Flame,
			snapshot.Fan,
			snapshot.Temp,
			snapshot.Err,
			snapshot.Valid,
			snapshot.FlameSecs,
			snapshot.UpdatedAt,
		), "\n", "\n  "),
	})
}

func (t *TUI) configureWiFi() {
	ssid := t.readLine(t.localizer.Text("form.ssid") + ": ")
	if ssid == "" {
		t.printLogBox("status", []string{t.localizer.Text("tui.cancelled")})
		return
	}
	password := t.readLine(t.localizer.Text("form.password") + ": ")
	t.sendAndPrint("SSID=" + ssid)
	t.sendSilent("PASS=" + password)
	t.printLogBox("status", []string{t.localizer.Text("tui.credentials_saved")})
}

func (t *TUI) setCountry() {
	cc := t.readLine(t.localizer.Text("tui.country_prompt"))
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 {
		t.printLogBox("status", []string{t.localizer.Text("tui.invalid_country")})
		return
	}
	t.sendAndPrint("COUNTRY=" + cc)
}

func (t *TUI) setServer() {
	addr := t.readLine(t.localizer.Text("tui.server_prompt"))
	if addr == "" {
		t.printLogBox("status", []string{t.localizer.Text("tui.cancelled")})
		return
	}
	port := t.readLine(t.localizer.Text("tui.server_port_prompt"))
	if port == "" {
		port = "9000"
	}
	t.sendAndPrint("SERVER=" + addr)
	t.sendAndPrint("PORT=" + port)
}

func (t *TUI) setWebhook() {
	url := t.readLine(t.localizer.Text("tui.webhook_prompt"))
	if url == "" {
		t.printLogBox("status", []string{t.localizer.Text("tui.cancelled")})
		return
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		t.printLogBox("status", []string{t.localizer.Text("tui.invalid_webhook")})
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
		t.printLogBox("status", []string{t.localizer.Text("error.reading_status", err.Error())})
		return
	}
	if status.DeviceID == "" {
		t.printLogBox("status", []string{t.localizer.Text("error.device_id_missing")})
		return
	}
	key, err := randomDeviceKey()
	if err != nil {
		t.printLogBox("status", []string{t.localizer.Text("error.generating_key", err.Error())})
		return
	}
	if err := t.store.ProvisionDevice(status.DeviceID, key); err != nil {
		t.printLogBox("status", []string{t.localizer.Text("error.storing_key", err.Error())})
		return
	}
	t.sendAndPrint("DEVICEKEY=" + key)
	t.printLogBox("status", []string{t.localizer.Text("tui.telemetry_provisioned", status.DeviceID)})
}

func (t *TUI) clearCredentials() {
	confirm := t.readLine(t.localizer.Text("tui.clear_confirm"))
	if confirm != "YES" {
		t.printLogBox("status", []string{t.localizer.Text("tui.cancelled")})
		return
	}
	t.sendAndPrint("CLEAR")
	t.printLogBox("status", []string{t.localizer.Text("tui.credentials_cleared")})
}

// Run starts the interactive TUI loop.
func (t *TUI) Run() {
	t.printHeader()
	for {
		t.printMenu()
		choice := t.readLine(color(t.localizer.Text("menu.choice"), colorBold))
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
			t.printLogBox("status", []string{t.localizer.Text("tui.bye")})
			return
		default:
			t.printLogBox("status", []string{t.localizer.Text("error.unknown_option")})
		}
	}
}
