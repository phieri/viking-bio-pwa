package configure

import (
	"fmt"
	"runtime"
	"strings"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/phieri/viking-bio-pwa/proxy/internal/serial"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

// RunGUI starts the Fyne-based device configurator GUI and blocks until the
// window is closed. It must be called from the main goroutine (or a goroutine
// that has been locked to the OS thread with runtime.LockOSThread).
func RunGUI(bridge *serial.Bridge, store *storage.Store) {
	// Fyne requires the main OS thread on some platforms.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	a := fyneapp.New()
	w := a.NewWindow("Viking Bio – Device Configurator")
	w.Resize(fyne.NewSize(680, 480))

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
				dialog.ShowError(err, w)
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
			if status.Server != "" {
				sb.WriteString(fmt.Sprintf("  Server:    %s:%d\n", status.Server, status.Port))
			}
			if status.Telemetry != "" {
				sb.WriteString("  Telemetry: " + status.Telemetry + "\n")
			}
			if status.DeviceKey != "" {
				sb.WriteString("  DeviceKey: " + status.DeviceKey + "\n")
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
				dialog.ShowError(fmt.Errorf("SSID must not be empty"), w)
				return
			}
			go func() {
				appendLog("→ SSID=" + ssid)
				lines, err := bridge.SendCommand("SSID=" + ssid)
				if err != nil {
					appendLog("Error: " + err.Error())
					dialog.ShowError(err, w)
					return
				}
				for _, l := range lines {
					appendLog("  " + l)
				}
				appendLog("→ PASS=***")
				lines, err = bridge.SendCommand("PASS=" + passEntry.Text)
				if err != nil {
					appendLog("Error: " + err.Error())
					dialog.ShowError(err, w)
					return
				}
				for _, l := range lines {
					appendLog("  " + l)
				}
				dialog.ShowInformation("WiFi configured", "Credentials saved. Device will reboot.", w)
			}()
		}, w)
		d.Show()
	})

	// ── Set country code ─────────────────────────────────────────────────
	btnCountry := widget.NewButton("Set country code", func() {
		// Offer a simple choice: Sweden (SE) or worldwide (XX).
		// XX is the Pico SDK worldwide/permissive regulatory region.
		regionSelect := widget.NewSelect(
			[]string{"Sweden (SE)", "Worldwide (XX)"},
			nil,
		)
		regionSelect.SetSelected("Sweden (SE)")

		form := &widget.Form{
			Items: []*widget.FormItem{
				{Text: "Wi-Fi region", Widget: regionSelect},
			},
		}
		d := dialog.NewCustomConfirm("Set Wi-Fi country code", "Set", "Cancel", form, func(confirmed bool) {
			if !confirmed {
				return
			}
			var cc string
			switch regionSelect.Selected {
			case "Worldwide (XX)":
				cc = "XX"
			default:
				cc = "SE"
			}
			go func() {
				appendLog("→ COUNTRY=" + cc)
				lines, err := bridge.SendCommand("COUNTRY=" + cc)
				if err != nil {
					appendLog("Error: " + err.Error())
					dialog.ShowError(err, w)
					return
				}
				for _, l := range lines {
					appendLog("  " + l)
				}
			}()
		}, w)
		d.Show()
	})

	// ── Set proxy server & port ──────────────────────────────────────────
	btnServer := widget.NewButton("Set proxy server & port", func() {
		addrEntry := widget.NewEntry()
		addrEntry.SetPlaceHolder("192.168.1.10 or fd00::1")
		portEntry := widget.NewEntry()
		portEntry.SetText("9000")

		form := &widget.Form{
			Items: []*widget.FormItem{
				{Text: "Server IP/hostname", Widget: addrEntry},
				{Text: "Port", Widget: portEntry},
			},
		}
		d := dialog.NewCustomConfirm("Set proxy server", "Set", "Cancel", form, func(confirmed bool) {
			if !confirmed {
				return
			}
			addr := strings.TrimSpace(addrEntry.Text)
			if addr == "" {
				dialog.ShowError(fmt.Errorf("server address must not be empty"), w)
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
					dialog.ShowError(err, w)
					return
				}
				for _, l := range lines {
					appendLog("  " + l)
				}
				appendLog("→ PORT=" + port)
				lines, err = bridge.SendCommand("PORT=" + port)
				if err != nil {
					appendLog("Error: " + err.Error())
					dialog.ShowError(err, w)
					return
				}
				for _, l := range lines {
					appendLog("  " + l)
				}
			}()
		}, w)
		d.Show()
	})

	// ── Provision telemetry device key ──────────────────────────────────
	btnProvision := widget.NewButton("Provision telemetry device key", func() {
		go func() {
			appendLog("→ STATUS (reading device ID)")
			status, err := bridge.GetStatus()
			if err != nil {
				appendLog("Error: " + err.Error())
				dialog.ShowError(err, w)
				return
			}
			if status.DeviceID == "" {
				msg := fmt.Errorf("device ID missing from STATUS output")
				appendLog("Error: " + msg.Error())
				dialog.ShowError(msg, w)
				return
			}
			key, err := randomDeviceKey()
			if err != nil {
				appendLog("Error generating key: " + err.Error())
				dialog.ShowError(err, w)
				return
			}
			if err := store.ProvisionDevice(status.DeviceID, key); err != nil {
				appendLog("Error storing key: " + err.Error())
				dialog.ShowError(err, w)
				return
			}
			appendLog("→ DEVICEKEY=*** (sending to device)")
			lines, err := bridge.SendCommand("DEVICEKEY=" + key)
			if err != nil {
				appendLog("Error: " + err.Error())
				dialog.ShowError(err, w)
				return
			}
			for _, l := range lines {
				appendLog("  " + l)
			}
			msg := "Telemetry key provisioned for " + status.DeviceID + "."
			appendLog(msg)
			dialog.ShowInformation("Provisioned", msg, w)
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
						dialog.ShowError(err, w)
						return
					}
					for _, l := range lines {
						appendLog("  " + l)
					}
					appendLog("Credentials cleared. Device will reboot.")
					dialog.ShowInformation("Done", "Credentials cleared. Device will reboot.", w)
				}()
			}, w)
	})

	// ── Close ────────────────────────────────────────────────────────────
	btnClose := widget.NewButton("Close", func() {
		w.Close()
	})

	// Layout
	buttons := container.New(layout.NewGridLayout(2),
		btnStatus,
		btnWiFi,
		btnCountry,
		btnServer,
		btnProvision,
		btnClear,
	)

	content := container.NewBorder(
		widget.NewLabelWithStyle("Viking Bio – Device Configurator",
			fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		container.NewHBox(layout.NewSpacer(), btnClose),
		nil,
		nil,
		container.NewVBox(buttons, widget.NewSeparator(), logScroll),
	)

	w.SetContent(content)
	w.ShowAndRun()
}
