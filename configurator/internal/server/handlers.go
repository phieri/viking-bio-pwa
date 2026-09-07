package server

import (
	"log"
	"time"

	"github.com/phieri/viking-bio-pwa/configurator/internal/config"
)

// Handlers bundles the runtime state used by the ingest pipeline.
type Handlers struct {
	state  *State
	config *config.Config
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(cfg *config.Config) *Handlers {
	return &Handlers{
		state:  &State{},
		config: cfg,
	}
}

func (h *Handlers) updateBurnerState(body machineDataBody, now time.Time) machineDataUpdateResult {
	return h.state.applyMachineData(body, now)
}

func (h *Handlers) processMachineData(body machineDataBody, source string, now time.Time) {
	result := h.updateBurnerState(body, now)
	log.Printf("%s: data received (flame=%v, temp=%.1f°C, err=%.0f)", source, result.flame, result.temp, result.err)
}
