package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
)

// Handlers bundles all HTTP handler dependencies.
type Handlers struct {
	state        *State
	notifyByType func(string, string, string)
	config       *config.Config
}

// NewHandlers creates a new Handlers instance. cfg may be nil to disable the
// energy price card (used in tests).
func NewHandlers(cfg *config.Config) *Handlers {
	state := &State{}
	state.setReminderSchedule(cfg)
	h := &Handlers{
		state:  state,
		config: cfg,
	}
	if cfg != nil && cfg.WebhookURL != "" {
		h.notifyByType = func(typ, title, body string) {
			if err := SendWebhookNotification(cfg.WebhookURL, typ, title, body, time.Now()); err != nil {
				log.Printf("server: webhook notification failed for %s: %v", typ, err)
			}
		}
	} else {
		h.notifyByType = func(typ, title, body string) {
			log.Printf("server: webhook URL not configured; skipping %s notification %q", typ, title)
		}
	}
	return h
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

type webhookPayload struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Timestamp int64  `json:"timestamp"`
}

// SendWebhookNotification posts a notification payload to a configured webhook URL.
func SendWebhookNotification(webhookURL, typ, title, body string, sentAt time.Time) error {
	if webhookURL == "" {
		return nil
	}
	payload, err := json.Marshal(webhookPayload{
		Type:      typ,
		Title:     title,
		Body:      body,
		Timestamp: sentAt.UTC().UnixMilli(),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned %s: %s", resp.Status, strings.TrimSpace(string(bodyBytes)))
	}
	return nil
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
	for _, notification := range notificationsForMachineData(result) {
		go h.notifyByType(notification.typ, notification.title, notification.body)
	}
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
