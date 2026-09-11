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

func formatTelemetrySnapshot(localizer provisioningLocalizer, snapshot server.Snapshot) string {
    return fmt.Sprintf(
        "%s: %t\n%s: %.1f\n%s: %.1f°C\n%s: %.0f\n%s: %t\n%s: %d\n%s: %s",
        localizer.Text("field.flame"),
        snapshot.Flame,
        localizer.Text("field.fan"),
        snapshot.Fan,
        localizer.Text("field.temp"),
        snapshot.Temp,
        localizer.Text("field.err"),
        snapshot.Err,
        localizer.Text("field.valid"),
        snapshot.Valid,
        localizer.Text("field.flame_seconds"),
        snapshot.FlameSecs,
        localizer.Text("status.last_contact"),
        time.UnixMilli(snapshot.UpdatedAt).Format(time.RFC3339),
    )
}

func (t *TUI) showStatus() {
    status, err := t.bridge.GetStatus()
    if err != nil {
        fmt.Println(color(t.localizer.Text("error.reading_status", err.Error()), colorRed))
        return
    }
    fmt.Println()
    fmt.Println(color(t.localizer.Text("tui.device_status"), colorBold))
    fmt.Println(formatDeviceStatus(t.localizer, status, "  "))
    fmt.Println()
}

func (t *TUI) showTelemetry() {
    if t.telemetryState == nil {
        fmt.Println(color(t.localizer.Text("status.live_telemetry_unavailable"), colorYellow))
        return
    }
    fmt.Println()
    fmt.Println(color(t.localizer.Text("tui.live_telemetry"), colorBold))
    snapshot := t.telemetryState.Snapshot()
    if snapshot.UpdatedAt == 0 {
        fmt.Println(color(t.localizer.Text("status.live_telemetry_empty"), colorYellow))
        fmt.Println()
        return
    }
    fmt.Println("  " + strings.ReplaceAll(formatTelemetrySnapshot(t.localizer, snapshot), "\n", "\n  "))
    fmt.Println()
}

func (t *TUI) configureWiFi() {
    ssid := t.readLine(t.localizer.Text("form.ssid") + ": ")
    if ssid == "" {
        fmt.Println(color(t.localizer.Text("tui.cancelled"), colorYellow))
        return
    }
    password := t.readLine(t.localizer.Text("form.password") + ": ")
    t.sendAndPrint("SSID=" + ssid)
    t.sendSilent("PASS=" + password)
    fmt.Println(color(t.localizer.Text("tui.credentials_saved"), colorGreen))
}

func (t *TUI) setCountry() {
    cc := t.readLine(t.localizer.Text("tui.country_prompt"))
    cc = strings.ToUpper(strings.TrimSpace(cc))
    if len(cc) != 2 {
        fmt.Println(color(t.localizer.Text("tui.invalid_country"), colorRed))
        return
    }
    t.sendAndPrint("COUNTRY=" + cc)
}

func (t *TUI) setServer() {
    addr := t.readLine(t.localizer.Text("tui.server_prompt"))
    if addr == "" {
        fmt.Println(color(t.localizer.Text("tui.cancelled"), colorYellow))
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
        fmt.Println(color(t.localizer.Text("tui.cancelled"), colorYellow))
        return
    }
    if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
        fmt.Println(color(t.localizer.Text("tui.invalid_webhook"), colorRed))
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
        fmt.Println(color(t.localizer.Text("error.reading_status", err.Error()), colorRed))
        return
    }
    if status.DeviceID == "" {
        fmt.Println(color(t.localizer.Text("error.device_id_missing"), colorRed))
        return
    }
    key, err := randomDeviceKey()
    if err != nil {
        fmt.Println(color(t.localizer.Text("error.generating_key", err.Error()), colorRed))
        return
    }
    if err := t.store.ProvisionDevice(status.DeviceID, key); err != nil {
        fmt.Println(color(t.localizer.Text("error.storing_key", err.Error()), colorRed))
        return
    }
    t.sendAndPrint("DEVICEKEY=" + key)
    fmt.Println(color(t.localizer.Text("tui.telemetry_provisioned", status.DeviceID), colorGreen))
}

func (t *TUI) clearCredentials() {
    confirm := t.readLine(t.localizer.Text("tui.clear_confirm"))
    if confirm != "YES" {
        fmt.Println(color(t.localizer.Text("tui.cancelled"), colorYellow))
        return
    }
    t.sendAndPrint("CLEAR")
    fmt.Println(color(t.localizer.Text("tui.credentials_cleared"), colorGreen))
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
            fmt.Println(color(t.localizer.Text("tui.bye"), colorCyan))
            return
        default:
            fmt.Println(color(t.localizer.Text("error.unknown_option"), colorYellow))
        }
        fmt.Println()
    }
}
