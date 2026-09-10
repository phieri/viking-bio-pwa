//go:build cgo

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package provisioning

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/phieri/viking-bio-pwa/configurator/internal/serial"
	"github.com/phieri/viking-bio-pwa/configurator/internal/server"
	"github.com/phieri/viking-bio-pwa/configurator/internal/storage"
	appversion "github.com/phieri/viking-bio-pwa/configurator/internal/version"
)

var supportedWiFiRegions = []string{
	"Worldwide (XX)",
	"Australia (AU)",
	"Austria (AT)",
	"Belgium (BE)",
	"Brazil (BR)",
	"Canada (CA)",
	"Chile (CL)",
	"China (CN)",
	"Colombia (CO)",
	"Czech Republic (CZ)",
	"Denmark (DK)",
	"Estonia (EE)",
	"Finland (FI)",
	"France (FR)",
	"Germany (DE)",
	"Greece (GR)",
	"Hong Kong (HK)",
	"Hungary (HU)",
	"Iceland (IS)",
	"India (IN)",
	"Israel (IL)",
	"Italy (IT)",
	"Japan (JP)",
	"Kenya (KE)",
	"Latvia (LV)",
	"Liechtenstein (LI)",
	"Lithuania (LT)",
	"Luxembourg (LU)",
	"Malaysia (MY)",
	"Malta (MT)",
	"Mexico (MX)",
	"Netherlands (NL)",
	"New Zealand (NZ)",
	"Nigeria (NG)",
	"Norway (NO)",
	"Peru (PE)",
	"Philippines (PH)",
	"Poland (PL)",
	"Portugal (PT)",
	"Singapore (SG)",
	"Slovakia (SK)",
	"Slovenia (SI)",
	"South Africa (ZA)",
	"South Korea (KR)",
	"Spain (ES)",
	"Sweden (SE)",
	"Switzerland (CH)",
	"Taiwan (TW)",
	"Thailand (TH)",
	"Turkey (TR)",
	"United Kingdom (GB)",
	"United States (US)",
}

func wifiCountryCodeFromSelection(selection string) string {
	if selection == "" {
		return "XX"
	}
	start := strings.LastIndex(selection, " (")
	end := strings.LastIndex(selection, ")")
	if start >= 0 && end > start+2 {
		return strings.ToUpper(selection[start+2 : end])
	}
	return strings.ToUpper(selection)
}

func wifiRegionLabel(countryCode string) string {
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if countryCode == "" {
		return "Worldwide (XX)"
	}
	for _, option := range supportedWiFiRegions {
		if wifiCountryCodeFromSelection(option) == countryCode {
			return option
		}
	}
	return "Worldwide (XX)"
}

// RunGUI starts the Fyne-based device configurator GUI and blocks until the
// window is closed. It must be called from the main goroutine (or a goroutine
// that has been locked to the OS thread with runtime.LockOSThread).
func RunGUI(bridge *serial.Bridge, store *storage.Store, telemetryState ...*server.State) {
	// Fyne requires the main OS thread on some platforms.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	a := fyneapp.New()
	var openWindows atomic.Int32
	openWindows.Store(2)
	provisioningWindow := a.NewWindow("Viking Bio – Provisioning over USB")
	provisioningWindow.Resize(fyne.NewSize(680, 480))

	titleLabel := widget.NewLabelWithStyle("Viking Bio – Device Configurator",
		fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	versionLabel := widget.NewLabelWithStyle("Configurator: "+appversion.String(),
		fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	statusLabel := widget.NewLabel("Loading device status...")
	statusLabel.Wrapping = fyne.TextWrapWord
	statusLabel.TextStyle = fyne.TextStyle{Monospace: true}
	offlineMode := bridge == nil || strings.TrimSpace(bridge.PortName()) == ""

	var refreshInFlight atomic.Bool
	refreshStatus := func() {
		if !refreshInFlight.CompareAndSwap(false, true) {
			return
		}
		defer refreshInFlight.Store(false)

		status, err := bridge.GetStatus()
		if err != nil {
			if offlineMode {
				statusLabel.SetText("Status unavailable: no Pico serial port is connected.\nConnect a device over USB or set PICO_SERIAL_PORT to enable live configuration.\nThe configurator is running in offline/network mode.")
				return
			}
			statusLabel.SetText("Status unavailable: " + err.Error())
			return
		}
		var sb strings.Builder
		sb.WriteString("WiFi:      ")
		if status.Connected {
			sb.WriteString("connected\n")
		} else {
			sb.WriteString("not connected\n")
		}
		for _, addr := range status.Addresses {
			sb.WriteString("Address:   " + addr + "\n")
		}
		if status.Country != "" {
			sb.WriteString("Country:   " + status.Country + "\n")
		}
		if status.DeviceID != "" {
			sb.WriteString("Device:    " + status.DeviceID + "\n")
		}
		if status.FirmwareVersion != "" {
			sb.WriteString("Firmware:  " + status.FirmwareVersion + "\n")
		}
		if status.Server != "" {
			sb.WriteString(fmt.Sprintf("Server:    %s:%d\n", status.Server, status.Port))
		}
		if status.Telemetry != "" {
			sb.WriteString("Telemetry: " + status.Telemetry + "\n")
		}
		if status.DeviceKey != "" {
			sb.WriteString("DeviceKey: " + maskSensitiveConfiguredValue(status.DeviceKey) + "\n")
		}
		if status.Webhook != "" {
			sb.WriteString("Webhook:   " + normaliseConfiguredValue(status.Webhook) + "\n")
		}
		statusLabel.SetText(strings.TrimRight(sb.String(), "\n"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	provisioningWindow.SetOnClosed(func() {
		cancel()
		if openWindows.Add(-1) == 0 {
			a.Quit()
		}
	})
	go refreshStatus()
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refreshStatus()
			}
		}
	}()

	// Log area for command output – Fyne widget calls are goroutine-safe.
	logEntry := widget.NewMultiLineEntry()
	logEntry.SetMinRowsVisible(10)
	logEntry.Wrapping = fyne.TextWrapWord
	logEntry.Disable() // read-only feel; user cannot type
	logScroll := container.NewScroll(logEntry)
	logScroll.SetMinSize(fyne.NewSize(640, 200))

	appendLog := func(text string) {
		old := logEntry.Text
		if old != "" {
			old += "\n"
		}
		logEntry.SetText(old + text)
		logScroll.ScrollToBottom()
	}

	// ── Show device status ────────────────────────────────────────────────
	btnStatus := widget.NewButton("Show device status", func() {
		appendLog("→ STATUS")
		go func() {
			status, err := bridge.GetStatus()
			if err != nil {
				appendLog("Error: " + err.Error())
				dialog.ShowError(err, provisioningWindow)
				return
			}
			var sb strings.Builder
			if status.Connected {
				sb.WriteString("  WiFi:      connected\n")
			} else {
				sb.WriteString("  WiFi:      not connected\n")
			}
			for _, addr := range status.Addresses {
				sb.WriteString("  Address:   " + addr + "\n")
			}
			if status.Country != "" {
				sb.WriteString("  Country:   " + status.Country + "\n")
			}
			if status.DeviceID != "" {
				sb.WriteString("  Device:    " + status.DeviceID + "\n")
			}
			if status.FirmwareVersion != "" {
				sb.WriteString("  Firmware:  " + status.FirmwareVersion + "\n")
			}
			if status.Server != "" {
				sb.WriteString(fmt.Sprintf("  Server:    %s:%d\n", status.Server, status.Port))
			}
			if status.Telemetry != "" {
				sb.WriteString("  Telemetry: " + status.Telemetry + "\n")
			}
			if status.DeviceKey != "" {
				sb.WriteString("  DeviceKey: " + maskSensitiveConfiguredValue(status.DeviceKey) + "\n")
			}
			if status.Webhook != "" {
				sb.WriteString("  Webhook:   " + normaliseConfiguredValue(status.Webhook) + "\n")
			}
			appendLog(strings.TrimRight(sb.String(), "\n"))
		}()
	})

	// ── Configure WiFi ───────────────────────────────────────────────────
	btnWiFi := widget.NewButton("Configure WiFi", func() {
		ssidEntry := widget.NewEntry()
		ssidEntry.SetPlaceHolder("MyNetwork")
		passEntry := widget.NewPasswordEntry()
		passEntry.SetPlaceHolder("password")

		form := &widget.Form{
			Items: []*widget.FormItem{
				{Text: "SSID", Widget: ssidEntry},
				{Text: "Password", Widget: passEntry},
			},
		}
		d := dialog.NewCustomConfirm("Configure WiFi", "Save", "Cancel", form, func(confirmed bool) {
			if !confirmed {
				return
			}
			ssid := strings.TrimSpace(ssidEntry.Text)
			if ssid == "" {
				dialog.ShowError(fmt.Errorf("SSID must not be empty"), provisioningWindow)
				return
			}
			go func() {
				appendLog("→ SSID=" + ssid)
				lines, err := bridge.SendCommand("SSID=" + ssid)
				if err != nil {
					appendLog("Error: " + err.Error())
					dialog.ShowError(err, provisioningWindow)
					return
				}
				for _, l := range lines {
					appendLog("  " + l)
				}
				appendLog("→ PASS=***")
				lines, err = bridge.SendCommand("PASS=" + passEntry.Text)
				if err != nil {
					appendLog("Error: " + err.Error())
					dialog.ShowError(err, provisioningWindow)
					return
				}
				for _, l := range lines {
					appendLog("  " + l)
				}
				dialog.ShowInformation("WiFi configured", "Credentials saved. Device will reboot.", provisioningWindow)
			}()
		}, provisioningWindow)
		d.Show()
	})

	// ── Set country code ─────────────────────────────────────────────────
	btnCountry := widget.NewButton("Set country code", func() {
		regionSelect := widget.NewSelect(supportedWiFiRegions, nil)
		regionSelect.SetSelected("Worldwide (XX)")
		if bridge != nil {
			if status, err := bridge.GetStatus(); err == nil {
				regionSelect.SetSelected(wifiRegionLabel(status.Country))
			}
		}

		form := &widget.Form{
			Items: []*widget.FormItem{{Text: "Wi-Fi region", Widget: regionSelect}},
		}
		d := dialog.NewCustomConfirm("Set Wi-Fi country code", "Set", "Cancel", form, func(confirmed bool) {
			if !confirmed {
				return
			}
			cc := wifiCountryCodeFromSelection(regionSelect.Selected)
			go func() {
				appendLog("→ COUNTRY=" + cc)
				lines, err := bridge.SendCommand("COUNTRY=" + cc)
				if err != nil {
					appendLog("Error: " + err.Error())
					dialog.ShowError(err, provisioningWindow)
					return
				}
				for _, l := range lines {
					appendLog("  " + l)
				}
			}()
		}, provisioningWindow)
		d.Show()
	})

	// ── Set server address & port ─────────────────────────────────────────
	btnServer := widget.NewButton("Set server address & port", func() {
		addrEntry := widget.NewEntry()
		addrEntry.SetPlaceHolder("192.168.1.10 or fd00::1")
		portEntry := widget.NewEntry()
		portEntry.SetText("9000")

		form := widget.NewForm(
			widget.NewFormItem("Server IP/hostname", addrEntry),
			widget.NewFormItem("Port", portEntry),
		)
		d := dialog.NewCustomConfirm("Set server", "Set", "Cancel", form, func(confirmed bool) {
			if !confirmed {
				return
			}
			addr := strings.TrimSpace(addrEntry.Text)
			if addr == "" {
				dialog.ShowError(fmt.Errorf("server address must not be empty"), provisioningWindow)
				return
			}
			port := strings.TrimSpace(portEntry.Text)
			if port == "" {
				port = "9000"
			}
			go func() {
				appendLog("→ SERVER=" + addr)
				lines, err := bridge.SendCommand("SERVER=" + addr)
				if err != nil {
					appendLog("Error: " + err.Error())
					dialog.ShowError(err, provisioningWindow)
					return
				}
				for _, l := range lines {
					appendLog("  " + l)
				}
				appendLog("→ PORT=" + port)
				lines, err = bridge.SendCommand("PORT=" + port)
				if err != nil {
					appendLog("Error: " + err.Error())
					dialog.ShowError(err, provisioningWindow)
					return
				}
				for _, l := range lines {
					appendLog("  " + l)
				}
			}()
		}, provisioningWindow)
		d.Show()
	})

	// ── Set webhook URL ──────────────────────────────────────────────────
	btnWebhook := widget.NewButton("Set webhook URL", func() {
		urlEntry := widget.NewEntry()
		urlEntry.SetPlaceHolder("https://hooks.example.com/secret")

		form := widget.NewForm(widget.NewFormItem("Webhook URL", urlEntry))
		d := dialog.NewCustomConfirm("Set webhook URL", "Set", "Cancel", form, func(confirmed bool) {
			if !confirmed {
				return
			}
			url := strings.TrimSpace(urlEntry.Text)
			if url == "" || (!strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://")) {
				dialog.ShowError(fmt.Errorf("webhook URL must start with http:// or https://"), provisioningWindow)
				return
			}
			go func() {
				appendLog("→ WEBHOOK=" + url)
				lines, err := bridge.SendCommand("WEBHOOK=" + url)
				if err != nil {
					appendLog("Error: " + err.Error())
					dialog.ShowError(err, provisioningWindow)
					return
				}
				for _, l := range lines {
					appendLog("  " + l)
				}
			}()
		}, provisioningWindow)
		d.Show()
	})

	// ── Provision telemetry device key ──────────────────────────────────
	btnProvision := widget.NewButton("Provision telemetry device key", func() {
		go func() {
			appendLog("→ STATUS (reading device ID)")
			status, err := bridge.GetStatus()
			if err != nil {
				appendLog("Error: " + err.Error())
				dialog.ShowError(err, provisioningWindow)
				return
			}
			if status.DeviceID == "" {
				msg := fmt.Errorf("device ID missing from STATUS output")
				appendLog("Error: " + msg.Error())
				dialog.ShowError(msg, provisioningWindow)
				return
			}
			key, err := randomDeviceKey()
			if err != nil {
				appendLog("Error generating key: " + err.Error())
				dialog.ShowError(err, provisioningWindow)
				return
			}
			if err := store.ProvisionDevice(status.DeviceID, key); err != nil {
				appendLog("Error storing key: " + err.Error())
				dialog.ShowError(err, provisioningWindow)
				return
			}
			appendLog("→ DEVICEKEY=*** (sending to device)")
			lines, err := bridge.SendCommand("DEVICEKEY=" + key)
			if err != nil {
				appendLog("Error: " + err.Error())
				dialog.ShowError(err, provisioningWindow)
				return
			}
			for _, l := range lines {
				appendLog("  " + l)
			}
			msg := "Telemetry key provisioned for " + status.DeviceID + "."
			appendLog(msg)
			dialog.ShowInformation("Provisioned", msg, provisioningWindow)
		}()
	})

	// ── Clear all credentials ────────────────────────────────────────────
	btnClear := widget.NewButton("Clear all credentials", func() {
		dialog.ShowConfirm("Clear credentials",
			"This will erase all stored credentials and reboot the device.\nAre you sure?",
			func(confirmed bool) {
				if !confirmed {
					return
				}
				go func() {
					appendLog("→ CLEAR")
					lines, err := bridge.SendCommand("CLEAR")
					if err != nil {
						appendLog("Error: " + err.Error())
						dialog.ShowError(err, provisioningWindow)
						return
					}
					for _, l := range lines {
						appendLog("  " + l)
					}
					appendLog("Credentials cleared. Device will reboot.")
					dialog.ShowInformation("Done", "Credentials cleared. Device will reboot.", provisioningWindow)
				}()
			}, provisioningWindow)
	})

	// ── Close ────────────────────────────────────────────────────────────
	btnClose := widget.NewButton("Close", func() {
		provisioningWindow.Close()
	})

	// Layout
	buttons := container.New(layout.NewGridLayout(2),
		btnStatus,
		btnWiFi,
		btnCountry,
		btnServer,
		btnWebhook,
		btnProvision,
		btnClear,
	)

	content := container.NewBorder(
		container.NewVBox(titleLabel, versionLabel),
		container.NewHBox(layout.NewSpacer(), btnClose),
		nil,
		nil,
		container.NewVBox(buttons, widget.NewSeparator(), logScroll),
	)
	provisioningWindow.SetContent(content)

	monitorWindow := a.NewWindow("Viking Bio – Network Telemetry")
	monitorWindow.Resize(fyne.NewSize(420, 320))
	telemetryStateValue := (*server.State)(nil)
	if len(telemetryState) > 0 {
		telemetryStateValue = telemetryState[0]
	}
	telemetryTitle := widget.NewLabelWithStyle("Network telemetry", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	telemetryStatus := widget.NewLabel("Waiting for telemetry...")
	telemetryStatus.Wrapping = fyne.TextWrapWord
	telemetryStatus.TextStyle = fyne.TextStyle{Monospace: true}
	var lastErrorNotification float64
	var lastErrorNotificationSet bool
	telemetryRefresh := func() {
		if telemetryStateValue == nil {
			telemetryStatus.SetText("Waiting for telemetry...\nThe server is not connected to a live telemetry stream.")
			return
		}
		snapshot := telemetryStateValue.Snapshot()
		if snapshot.UpdatedAt == 0 {
			telemetryStatus.SetText("Waiting for telemetry...\nNo data has been received yet.")
			return
		}
		if snapshot.Err != 0 {
			if !lastErrorNotificationSet || lastErrorNotification != snapshot.Err {
				a.SendNotification(fyne.NewNotification(
					"Viking Bio – burner error",
					fmt.Sprintf("New burner error code: %.0f", snapshot.Err),
				))
				lastErrorNotification = snapshot.Err
				lastErrorNotificationSet = true
			}
		} else {
			lastErrorNotification = 0
			lastErrorNotificationSet = false
		}
		telemetryStatus.SetText(strings.TrimRight(fmt.Sprintf(
			"Flame: %t\nFan: %.1f\nTemp: %.1f°C\nErr: %.0f\nValid: %t\nFlame seconds: %d\nUpdated: %s",
			snapshot.Flame,
			snapshot.Fan,
			snapshot.Temp,
			snapshot.Err,
			snapshot.Valid,
			snapshot.FlameSecs,
			time.UnixMilli(snapshot.UpdatedAt).Format(time.RFC3339),
		), "\n"))
	}
	telemetryCtx, telemetryCancel := context.WithCancel(context.Background())
	monitorWindow.SetOnClosed(func() {
		telemetryCancel()
		if openWindows.Add(-1) == 0 {
			a.Quit()
		}
	})
	if telemetryStateValue != nil {
		updates := telemetryStateValue.Updates()
		go func() {
			for {
				select {
				case <-telemetryCtx.Done():
					return
				case <-updates:
					telemetryRefresh()
				}
			}
		}()
	}
	telemetryRefresh()
	monitorWindow.SetContent(container.NewBorder(
		telemetryTitle,
		nil,
		nil,
		nil,
		container.NewVBox(
			widget.NewLabel("Live burner telemetry"),
			telemetryStatus,
		),
	))
	provisioningWindow.Show()
	monitorWindow.Show()
	a.Run()
}
