//go:build !cgo

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package provisioning

import (
	"github.com/phieri/viking-bio-pwa/configurator/internal/serial"
	"github.com/phieri/viking-bio-pwa/configurator/internal/server"
	"github.com/phieri/viking-bio-pwa/configurator/internal/storage"
)

// RunGUI is not available in this build (CGo is disabled). Falls back to the TUI.
func RunGUI(bridge *serial.Bridge, store *storage.Store, telemetryState ...*server.State) {
	tui := NewTUI(bridge, store, telemetryState...)
	tui.Run()
}
