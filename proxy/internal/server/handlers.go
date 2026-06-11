package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	"github.com/phieri/viking-bio-pwa/proxy/internal/elspot"
	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

// spotPriceFetcher abstracts the elprisetjustnu spot price lookup.
type spotPriceFetcher interface {
	CurrentHourSEKPerKWh(region string, now time.Time) (float64, error)
}

// Handlers bundles all HTTP handler dependencies.
type Handlers struct {
	state        *State
	pushMgr      *push.Manager
	notifyByType func(string, string, string)
	energyCfg    *config.Config
	spotFetcher  spotPriceFetcher
}

// NewHandlers creates a new Handlers instance. cfg may be nil to disable the
// energy price card (used in tests).
func NewHandlers(pushMgr *push.Manager, cfg *config.Config) *Handlers {
	h := &Handlers{
		state:        &State{},
		pushMgr:      pushMgr,
		notifyByType: pushMgr.NotifyByType,
		energyCfg:    cfg,
	}
	if cfg != nil && cfg.EnergyCardEnabled {
		h.spotFetcher = elspot.NewFetcher()
	}
	return h
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
	Enabled         bool    `json:"enabled"`
	SpotSEKPerKWh   float64 `json:"spot_sek_kwh,omitempty"`
	ElecTotalSEKPerKWh float64 `json:"elec_total_sek_kwh,omitempty"`
	BurnerTotalSEKPerKWh float64 `json:"burner_total_sek_kwh,omitempty"`
	DiffSEKPerKWh   float64 `json:"diff_sek_kwh,omitempty"`
	Error           string  `json:"error,omitempty"`
}

// HandleGetEnergyPrice serves GET /api/energy-price.
// It computes the current difference in cost per kWh between electrical and
// burner heating. A positive diff means the burner is cheaper (saving money).
func (h *Handlers) HandleGetEnergyPrice(w http.ResponseWriter, r *http.Request) {
	if h.energyCfg == nil || !h.energyCfg.EnergyCardEnabled {
		writeJSON(w, http.StatusOK, energyPriceResponse{Enabled: false})
		return
	}

	cfg := h.energyCfg
	annualKWh := cfg.AnnualHeatingKWh
	if annualKWh <= 0 {
		annualKWh = 20000
	}

	spot, err := h.spotFetcher.CurrentHourSEKPerKWh(cfg.ElecPriceRegion, time.Now())
	if err != nil {
		log.Printf("energy-price: spot fetch failed: %v", err)
		writeJSON(w, http.StatusOK, energyPriceResponse{
			Enabled: true,
			Error:   "Kunde inte hämta spotpris",
		})
		return
	}

	elecTotal := spot + cfg.ElecGridFeeSEKPerKWh + cfg.ElecTaxSEKPerKWh +
		cfg.ElecFixedCostSEKYear/annualKWh
	burnerTotal := cfg.BurnerCostSEKPerKWh +
		cfg.BurnerFixedCostSEKYear/annualKWh

	writeJSON(w, http.StatusOK, energyPriceResponse{
		Enabled:              true,
		SpotSEKPerKWh:        spot,
		ElecTotalSEKPerKWh:   elecTotal,
		BurnerTotalSEKPerKWh: burnerTotal,
		DiffSEKPerKWh:        elecTotal - burnerTotal,
	})
}
