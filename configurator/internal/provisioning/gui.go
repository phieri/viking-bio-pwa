//go:build cgo

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package provisioning

import (
	"context"
	"errors"
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

var supportedWiFiRegionCodes = []string{
	"XX", "AU", "AT", "BE", "BR", "CA", "CL", "CN", "CO", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HK", "HU", "IS", "IN", "IL", "IT", "JP", "KE", "LV", "LI", "LT", "LU", "MY", "MT", "MX", "NL", "NZ", "NG", "NO", "PE", "PH", "PL", "PT", "SG", "SK", "SI", "ZA", "KR", "ES", "SE", "CH", "TW", "TH", "TR", "GB", "US",
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

func wifiRegionLabel(localizer provisioningLocalizer, countryCode string) string {
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if countryCode == "" {
		return localizer.regionLabel("XX")
	}
	for _, code := range supportedWiFiRegionCodes {
		if code == countryCode {
			return localizer.regionLabel(code)
		}
	}
	return localizer.regionLabel("XX")
}

func wifiRegionOptions(localizer provisioningLocalizer) []string {
	options := make([]string, 0, len(supportedWiFiRegionCodes))
	for _, code := range supportedWiFiRegionCodes {
		options = append(options, localizer.regionLabel(code))
	}
	return options
}

func localizedError(localizer provisioningLocalizer, key string, args ...any) error {
	return errors.New(localizer.Text(key, args...))
}

// RunGUI starts the Fyne-based device configurator GUI and blocks until the
// window is closed. It must be called from the main goroutine (or a goroutine
// that has been locked to the OS thread with runtime.LockOSThread).
func RunGUI(bridge *serial.Bridge, store *storage.Store, telemetryState ...*server.State) {
	// Fyne requires the main OS thread on some platforms.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	a := fyneapp.New()
	localizer := newProvisioningLocalizer()
	var openWindows atomic.Int32
	openWindows.Store(2)
	provisioningWindow := a.NewWindow(localizer.Text("app.window.provisioning"))
	provisioningWindow.Resize(fyne.NewSize(680, 480))

	titleLabel := widget.NewLabelWithStyle(localizer.Text("app.title"),
		fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	versionLabel := widget.NewLabelWithStyle(localizer.Text("app.version", appversion.String()),
		fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	languageLabel := widget.NewLabelWithStyle(localizer.Text("app.language")+": "+localizer.LanguageName(localizer.Language()),
		fyne.TextAlignCenter, fyne.TextStyle{})

	statusLabel := widget.NewLabel(localizer.Text("status.loading"))
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
				statusLabel.SetText(localizer.Text("status.unavailable.offline"))
				return
			}
			statusLabel.SetText(localizer.Text("status.unavailable.error", err.Error()))
			return
		}
		statusLabel.SetText(formatDeviceStatus(localizer, &status, ""))
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
	btnStatus := widget.NewButton(localizer.Text("button.show_status"), func() {
		appendLog("→ STATUS")
		go func() {
			status, err := bridge.GetStatus()
			if err != nil {
				appendLog("Error: " + err.Error())
				dialog.ShowError(err, provisioningWindow)
				return
			}
			appendLog(formatDeviceStatus(localizer, &status, "  "))
		}()
	})

	// ── Configure WiFi ───────────────────────────────────────────────────
	btnWiFi := widget.NewButton(localizer.Text("button.configure_wifi"), func() {
		ssidEntry := widget.NewEntry()
		ssidEntry.SetPlaceHolder(localizer.Text("placeholder.ssid"))
		passEntry := widget.NewPasswordEntry()
		passEntry.SetPlaceHolder(localizer.Text("placeholder.password"))

		form := &widget.Form{
			Items: []*widget.FormItem{
				{Text: localizer.Text("form.ssid"), Widget: ssidEntry},
				{Text: localizer.Text("form.password"), Widget: passEntry},
			},
		}
		d := dialog.NewCustomConfirm(localizer.Text("dialog.wifi.title"), localizer.Text("dialog.save"), localizer.Text("dialog.cancel"), form, func(confirmed bool) {
			if !confirmed {
				return
			}
			ssid := strings.TrimSpace(ssidEntry.Text)
			if ssid == "" {
				dialog.ShowError(localizedError(localizer, "error.blank_ssid"), provisioningWindow)
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
				dialog.ShowInformation(localizer.Text("dialog.wifi.saved_title"), localizer.Text("dialog.wifi.saved_body"), provisioningWindow)
			}()
		}, provisioningWindow)
		d.Show()
	})

	// ── Set country code ─────────────────────────────────────────────────
	btnCountry := widget.NewButton(localizer.Text("button.set_country"), func() {
		regionSelect := widget.NewSelect(wifiRegionOptions(localizer), nil)
		regionSelect.SetSelected(localizer.regionLabel("XX"))
		if bridge != nil {
			if status, err := bridge.GetStatus(); err == nil {
				regionSelect.SetSelected(wifiRegionLabel(localizer, status.Country))
			}
		}

		form := &widget.Form{
			Items: []*widget.FormItem{{Text: localizer.Text("form.region"), Widget: regionSelect}},
		}
		d := dialog.NewCustomConfirm(localizer.Text("dialog.country.title"), localizer.Text("dialog.set"), localizer.Text("dialog.cancel"), form, func(confirmed bool) {
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
	btnServer := widget.NewButton(localizer.Text("button.set_server"), func() {
		addrEntry := widget.NewEntry()
		addrEntry.SetPlaceHolder(localizer.Text("placeholder.server"))
		portEntry := widget.NewEntry()
		portEntry.SetText("9000")

		form := widget.NewForm(
			widget.NewFormItem(localizer.Text("form.server"), addrEntry),
			widget.NewFormItem(localizer.Text("form.port"), portEntry),
		)
		d := dialog.NewCustomConfirm(localizer.Text("dialog.server.title"), localizer.Text("dialog.set"), localizer.Text("dialog.cancel"), form, func(confirmed bool) {
			if !confirmed {
				return
			}
			addr := strings.TrimSpace(addrEntry.Text)
			if addr == "" {
				dialog.ShowError(localizedError(localizer, "error.blank_server"), provisioningWindow)
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
	btnWebhook := widget.NewButton(localizer.Text("button.set_webhook"), func() {
		urlEntry := widget.NewEntry()
		urlEntry.SetPlaceHolder(localizer.Text("placeholder.webhook"))

		form := widget.NewForm(widget.NewFormItem(localizer.Text("form.webhook"), urlEntry))
		d := dialog.NewCustomConfirm(localizer.Text("dialog.webhook.title"), localizer.Text("dialog.set"), localizer.Text("dialog.cancel"), form, func(confirmed bool) {
			if !confirmed {
				return
			}
			url := strings.TrimSpace(urlEntry.Text)
			if url == "" || (!strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://")) {
				dialog.ShowError(localizedError(localizer, "error.invalid_webhook"), provisioningWindow)
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
	btnProvision := widget.NewButton(localizer.Text("button.provision_key"), func() {
		go func() {
			appendLog("→ STATUS (reading device ID)")
			status, err := bridge.GetStatus()
			if err != nil {
				appendLog("Error: " + err.Error())
				dialog.ShowError(err, provisioningWindow)
				return
			}
			if status.DeviceID == "" {
				msg := localizedError(localizer, "error.device_id_missing")
				appendLog("Error: " + msg.Error())
				dialog.ShowError(msg, provisioningWindow)
				return
			}
			key, err := randomDeviceKey()
			if err != nil {
				appendLog(localizer.Text("error.generating_key", err.Error()))
				dialog.ShowError(err, provisioningWindow)
				return
			}
			if err := store.ProvisionDevice(status.DeviceID, key); err != nil {
				appendLog(localizer.Text("error.storing_key", err.Error()))
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
			msg := localizer.Text("tui.telemetry_provisioned", status.DeviceID)
			appendLog(msg)
			dialog.ShowInformation(localizer.Text("dialog.provisioned"), msg, provisioningWindow)
		}()
	})

	// ── Clear all credentials ────────────────────────────────────────────
	btnClear := widget.NewButton(localizer.Text("button.clear_credentials"), func() {
		dialog.ShowConfirm(localizer.Text("dialog.clear.title"),
			localizer.Text("dialog.clear.body"),
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
					appendLog(localizer.Text("tui.credentials_cleared"))
					dialog.ShowInformation(localizer.Text("dialog.done"), localizer.Text("tui.credentials_cleared"), provisioningWindow)
				}()
			}, provisioningWindow)
	})

	// ── Close ────────────────────────────────────────────────────────────
	btnClose := widget.NewButton(localizer.Text("button.close"), func() {
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
		container.NewVBox(titleLabel, versionLabel, languageLabel),
		container.NewHBox(layout.NewSpacer(), btnClose),
		nil,
		nil,
		container.NewVBox(buttons, widget.NewSeparator(), logScroll),
	)
	provisioningWindow.SetContent(content)

	monitorWindow := a.NewWindow(localizer.Text("app.window.telemetry"))
	monitorWindow.Resize(fyne.NewSize(420, 320))
	telemetryStateValue := (*server.State)(nil)
	if len(telemetryState) > 0 {
		telemetryStateValue = telemetryState[0]
	}
	telemetryTitle := widget.NewLabelWithStyle(localizer.Text("telemetry.title"), fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	telemetryStatus := widget.NewLabel(localizer.Text("status.telemetry.waiting"))
	telemetryStatus.Wrapping = fyne.TextWrapWord
	telemetryStatus.TextStyle = fyne.TextStyle{Monospace: true}
	var lastErrorNotification float64
	var lastErrorNotificationSet bool
	telemetryRefresh := func() {
		if telemetryStateValue == nil {
			telemetryStatus.SetText(localizer.Text("status.telemetry.unavailable"))
			return
		}
		snapshot := telemetryStateValue.Snapshot()
		if snapshot.UpdatedAt == 0 {
			telemetryStatus.SetText(localizer.Text("status.telemetry.empty"))
			return
		}
		if snapshot.Err != 0 {
			if !lastErrorNotificationSet || lastErrorNotification != snapshot.Err {
				a.SendNotification(fyne.NewNotification(
					localizer.Text("telemetry.error.notification_title"),
					localizer.Text("telemetry.error.notification_body", snapshot.Err),
				))
				lastErrorNotification = snapshot.Err
				lastErrorNotificationSet = true
			}
		} else {
			lastErrorNotification = 0
			lastErrorNotificationSet = false
		}
		telemetryStatus.SetText(formatTelemetrySnapshot(
			localizer,
			snapshot.Flame,
			snapshot.Fan,
			snapshot.Temp,
			snapshot.Err,
			snapshot.Valid,
			snapshot.FlameSecs,
			snapshot.UpdatedAt,
		))
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
			widget.NewLabel(localizer.Text("telemetry.label")),
			telemetryStatus,
		),
	))
	provisioningWindow.Show()
	monitorWindow.Show()
	a.Run()
}
