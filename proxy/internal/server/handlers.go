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
	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

// Handlers bundles all HTTP handler dependencies.
type Handlers struct {
	state        *State
	pushMgr      *push.Manager
	notifyByType func(string, string, string)
	energyCfg    *config.Config
	telemetryCfg *config.Config
}

// NewHandlers creates a new Handlers instance. cfg may be nil to disable the
// energy price card (used in tests).
func NewHandlers(pushMgr *push.Manager, cfg *config.Config) *Handlers {
	state := &State{}
	state.setReminderSchedule(cfg)
	return &Handlers{
		state:        state,
		pushMgr:      pushMgr,
		notifyByType: pushMgr.NotifyByType,
		energyCfg:    cfg,
		telemetryCfg: cfg,
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

// HandleGetData serves GET /api/data.
func (h *Handlers) HandleGetData(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.state.snapshot())
}

// HandleGetTelemetry serves GET /api/telemetry.
func (h *Handlers) HandleGetTelemetry(w http.ResponseWriter, r *http.Request) {
	if h.telemetryCfg == nil || !h.telemetryCfg.TelemetryHistoryEnabled {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "telemetry history disabled"})
		return
	}
	writeJSON(w, http.StatusOK, h.state.telemetryHistoryWindow(time.Now()))
}

// HandleGetVapidKey serves GET /api/vapid-public-key.
func (h *Handlers) HandleGetVapidKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"key":    h.pushMgr.GetVapidPublicKey(),
		"source": "proxy",
	})
}

// HandleGetSubscribers serves GET /api/subscribers.
func (h *Handlers) HandleGetSubscribers(w http.ResponseWriter, r *http.Request) {
	subs := h.pushMgr.GetSubscriptions()
	items := make([]map[string]string, 0, len(subs))
	for _, sub := range subs {
		items = append(items, map[string]string{"endpoint": sub.Endpoint})
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(items), "subscribers": items})
}

// HandleSendTestPush serves POST /api/test-push.
func (h *Handlers) HandleSendTestPush(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Endpoint string `json:"endpoint"`
		Priority string `json:"priority"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.Endpoint == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	priority := body.Priority
	if priority == "" {
		priority = "normal"
	}
	if err := h.pushMgr.SendTestToSubscriber(body.Endpoint, priority); err != nil {
		if errors.Is(err, push.ErrSubscriptionNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "subscriber not found"})
			return
		}
		if errors.Is(err, push.ErrInvalidSubscriptionEndpoint) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid subscription endpoint"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to send test push"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
	if h.telemetryCfg != nil && h.telemetryCfg.TelemetryHistoryEnabled {
		h.state.appendTelemetrySample(now, h.state.snapshot())
	}
	log.Printf("%s: data received (flame=%v, temp=%.1f°C, err=%.0f)", source, result.flame, result.temp, result.err)
	h.triggerNotifications(result)
}

// HandleSubscribe serves POST /api/subscribe.
func (h *Handlers) HandleSubscribe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Endpoint string        `json:"endpoint"`
		P256DH   string        `json:"p256dh"`
		Auth     string        `json:"auth"`
		Prefs    storage.Prefs `json:"prefs"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.Endpoint == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}

	ok, err := h.pushMgr.AddSubscription(body.Endpoint, body.P256DH, body.Auth, body.Prefs)
	if err != nil {
		if errors.Is(err, push.ErrInvalidSubscriptionEndpoint) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid subscription endpoint"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to add subscription"})
		return
	}
	status := "ok"
	if !ok {
		status = "full"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}

// HandleUnsubscribe serves POST /api/unsubscribe.
func (h *Handlers) HandleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Endpoint string `json:"endpoint"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.Endpoint == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	h.pushMgr.RemoveSubscription(body.Endpoint)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
	if h.energyCfg == nil || !h.energyCfg.EnergyCardEnabled {
		writeJSON(w, http.StatusOK, energyPriceResponse{Enabled: false})
		return
	}

	variableCost, fixedCost, totalCost := burnerPricePerKWh(h.energyCfg)

	writeJSON(w, http.StatusOK, energyPriceResponse{
		Enabled:           true,
		BurnerSEKPerKWh:   totalCost,
		FixedSEKPerKWh:    fixedCost,
		VariableSEKPerKWh: variableCost,
	})
}
