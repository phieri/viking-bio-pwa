//go:build !cgo

package configure

import (
	"github.com/phieri/viking-bio-pwa/proxy/internal/serial"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

// RunGUI is not available in this build (CGo is disabled). Falls back to the TUI.
func RunGUI(bridge *serial.Bridge, store *storage.Store) {
	tui := NewTUI(bridge, store)
	tui.Run()
}
