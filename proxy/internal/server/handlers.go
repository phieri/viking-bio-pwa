package server

import (
	"encoding/json"
	"log"
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
}

// NewHandlers creates a new Handlers instance. cfg may be nil to disable the
// energy price card (used in tests).
func NewHandlers(pushMgr *push.Manager, cfg *config.Config) *Handlers {
	return &Handlers{
		state:        &State{},
		pushMgr:      pushMgr,
		notifyByType: pushMgr.NotifyByType,
		energyCfg:    cfg,
	}
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// HandleGetData serves GET /api/data.
func (h *Handlers) HandleGetData(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.state.snapshot())
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
	writeJSON(w, http.StatusOK, map[string]int{"count": h.pushMgr.GetSubscriptionCount()})
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Endpoint == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}

	ok := h.pushMgr.AddSubscription(body.Endpoint, body.P256DH, body.Auth, body.Prefs)
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Endpoint == "" {
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
