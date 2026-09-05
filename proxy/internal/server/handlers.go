package server

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
)

// Handlers bundles all HTTP handler dependencies.
type Handlers struct {
	state  *State
	config *config.Config
}

// NewHandlers creates a new Handlers instance. cfg may be nil to disable the
// energy price card (used in tests).
func NewHandlers(cfg *config.Config) *Handlers {
	state := &State{}
	state.setReminderSchedule(cfg)
	return &Handlers{
		state:  state,
		config: cfg,
	}
}

const maxJSONBodySize = 64 << 10

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty request body"})
			return false
		}
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
			return false
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	// Ensure no trailing data follows the first JSON object.
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body must contain exactly one JSON object"})
		return false
	}
	return true
}

type endpointJSONBody interface {
	endpoint() string
}

func decodeJSONBodyWithEndpoint(w http.ResponseWriter, r *http.Request, dst endpointJSONBody) bool {
	if !decodeJSONBody(w, r, dst) {
		return false
	}
	if dst.endpoint() == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return false
	}
	return true
}

// HandleGetData serves GET /api/data.
func (h *Handlers) HandleGetData(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.state.snapshot())
}

// HandleGetMetrics serves GET /api/metrics.
func (h *Handlers) metricsEnabled() bool {
	return h.config != nil && h.config.TelemetryHistoryEnabled
}

func (h *Handlers) energyCardEnabled() bool {
	return h.config != nil && h.config.EnergyCardEnabled
}

func (h *Handlers) HandleGetMetrics(w http.ResponseWriter, r *http.Request) {
	if !h.metricsEnabled() {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "metrics history disabled"})
		return
	}
	writeJSON(w, http.StatusOK, h.state.telemetryHistoryWindow())
}

func (h *Handlers) updateBurnerState(body machineDataBody, now time.Time) machineDataUpdateResult {
	return h.state.applyMachineData(body, now)
}

func (h *Handlers) triggerNotifications(result machineDataUpdateResult) {
	// The bridge owns outbound webhook delivery. The proxy only ingests telemetry
	// and maintains the local state used by the configurator UI.
	_ = notificationsForMachineData(result)
}

func (h *Handlers) processMachineData(body machineDataBody, source string, now time.Time) {
	result := h.updateBurnerState(body, now)
	if h.metricsEnabled() {
		h.state.appendTelemetrySample(now, result.snapshot)
	}
	log.Printf("%s: data received (flame=%v, temp=%.1f°C, err=%.0f)", source, result.flame, result.temp, result.err)
	h.triggerNotifications(result)
}

// energyPriceResponse is the JSON payload for GET /api/energy-price.
type energyPriceResponse struct {
	Enabled           bool    `json:"enabled"`
	BurnerSEKPerKWh   float64 `json:"burner_sek_kwh"`
	FixedSEKPerKWh    float64 `json:"fixed_sek_kwh"`
	VariableSEKPerKWh float64 `json:"variable_sek_kwh"`
}

func burnerPricePerKWh(cfg *config.Config) (variableCost, fixedCost, totalCost float64) {
	annualKWh := cfg.AnnualHeatingKWh
	if annualKWh <= 0 {
		annualKWh = 20000
	}

	variableCost = cfg.BurnerCostSEKPerKWh
	fixedCost = cfg.BurnerFixedCostSEKYear / annualKWh
	totalCost = variableCost + fixedCost

	return variableCost, fixedCost, totalCost
}

// HandleGetEnergyPrice serves GET /api/energy-price.
// It returns the burner's current configured cost per kWh.
func (h *Handlers) HandleGetEnergyPrice(w http.ResponseWriter, r *http.Request) {
	if !h.energyCardEnabled() {
		writeJSON(w, http.StatusOK, energyPriceResponse{Enabled: false})
		return
	}

	variableCost, fixedCost, totalCost := burnerPricePerKWh(h.config)

	writeJSON(w, http.StatusOK, energyPriceResponse{
		Enabled:           true,
		BurnerSEKPerKWh:   totalCost,
		FixedSEKPerKWh:    fixedCost,
		VariableSEKPerKWh: variableCost,
	})
}
