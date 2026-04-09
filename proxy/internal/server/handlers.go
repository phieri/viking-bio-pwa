package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

// State holds the shared burner telemetry state.
type State struct {
	mu            sync.RWMutex
	Flame         bool    `json:"flame"`
	Fan           float64 `json:"fan"`
	Temp          float64 `json:"temp"`
	Err           float64 `json:"err"`
	Valid         bool    `json:"valid"`
	FlameSecs     int64   `json:"flame_secs"`
	UpdatedAt     int64   `json:"updated_at"`
	lastFlameTime int64   // ms; zero means flame was off last update
	errorNotified bool
}

// Handlers bundles all HTTP handler dependencies.
type Handlers struct {
	cfg          *config.Config
	state        *State
	pushMgr      *push.Manager
	notifyByType func(string, string, string)
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(cfg *config.Config, pushMgr *push.Manager) *Handlers {
	return &Handlers{
		cfg:          cfg,
		state:        &State{},
		pushMgr:      pushMgr,
		notifyByType: pushMgr.NotifyByType,
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
	h.state.mu.RLock()
	out := struct {
		Flame     bool    `json:"flame"`
		Fan       float64 `json:"fan"`
		Temp      float64 `json:"temp"`
		Err       float64 `json:"err"`
		Valid     bool    `json:"valid"`
		FlameSecs int64   `json:"flame_secs"`
	}{
		Flame:     h.state.Flame,
		Fan:       h.state.Fan,
		Temp:      h.state.Temp,
		Err:       h.state.Err,
		Valid:     h.state.Valid,
		FlameSecs: h.state.FlameSecs,
	}
	h.state.mu.RUnlock()
	writeJSON(w, http.StatusOK, out)
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

// machineDataBody is the expected JSON body for POST /api/machine-data.
type machineDataBody struct {
	Flame *bool    `json:"flame"`
	Fan   *float64 `json:"fan"`
	Temp  *float64 `json:"temp"`
	Err   *float64 `json:"err"`
	Valid *bool    `json:"valid"`
}

type machineDataUpdateResult struct {
	flameChanged bool
	newErr       bool
	flame        bool
	temp         float64
	err          float64
}

func (h *Handlers) authenticateWebhook(r *http.Request) bool {
	if token := h.cfg.WebhookAuthToken; token != "" {
		provided := r.Header.Get("X-Hook-Auth")
		return subtle.ConstantTimeCompare([]byte(token), []byte(provided)) == 1
	}
	return true
}

func decodeMachineData(r io.Reader) (machineDataBody, error) {
	var body machineDataBody
	if err := json.NewDecoder(r).Decode(&body); err != nil {
		return machineDataBody{}, err
	}
	if body.Flame == nil || body.Fan == nil || body.Temp == nil || body.Err == nil || body.Valid == nil {
		return machineDataBody{}, fmt.Errorf("missing required field")
	}
	return body, nil
}

func (h *Handlers) updateBurnerState(body machineDataBody, now time.Time) machineDataUpdateResult {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	prevFlame := h.state.Flame
	prevErr := h.state.Err

	h.state.Flame = *body.Flame
	h.state.Fan = *body.Fan
	h.state.Temp = *body.Temp
	h.state.Err = *body.Err
	h.state.Valid = *body.Valid

	nowMillis := now.UnixMilli()
	h.state.UpdatedAt = nowMillis
	if h.state.Flame {
		if h.state.lastFlameTime == 0 {
			h.state.lastFlameTime = nowMillis
		}
		elapsed := nowMillis - h.state.lastFlameTime
		h.state.FlameSecs += elapsed / 1000
		h.state.lastFlameTime = nowMillis - (elapsed % 1000)
	} else {
		h.state.lastFlameTime = 0
	}

	result := machineDataUpdateResult{
		flameChanged: h.state.Flame != prevFlame,
		newErr:       h.state.Err != 0 && h.state.Err != prevErr && !h.state.errorNotified,
		flame:        h.state.Flame,
		temp:         h.state.Temp,
		err:          h.state.Err,
	}
	if result.newErr {
		h.state.errorNotified = true
	}
	if h.state.Err == 0 {
		h.state.errorNotified = false
	}

	return result
}

func (h *Handlers) triggerNotifications(result machineDataUpdateResult) {
	if result.flameChanged {
		title := "Viking Bio: Låga släckt"
		body := "Pannan har slocknat"
		if result.flame {
			title = "Viking Bio: Låga tänd"
			body = fmt.Sprintf("Pannan tänd – %.0f °C", result.temp)
		}
		go h.notifyByType("flame", title, body)
	}
	if result.newErr {
		go h.notifyByType("error", "Viking Bio: Fel",
			fmt.Sprintf("Felkod %.0f detekterad", result.err))
	}
}

// HandleMachineData serves POST /api/machine-data.
func (h *Handlers) HandleMachineData(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateWebhook(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	body, err := decodeMachineData(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}

	result := h.updateBurnerState(body, time.Now())

	log.Printf("webhook: data received (flame=%v, temp=%.1f°C, err=%.0f)", result.flame, result.temp, result.err)

	h.triggerNotifications(result)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "ok",
		"server_time":      time.Now().Unix(),
		"vapid_public_key": h.pushMgr.GetVapidPublicKey(),
	})
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
	// Forward to Pico (best-effort)
	go h.picoForward("/api/subscribe", map[string]any{
		"endpoint": body.Endpoint,
		"p256dh":   body.P256DH,
		"auth":     body.Auth,
		"prefs":    body.Prefs,
	})
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
	go h.picoForward("/api/unsubscribe", map[string]string{"endpoint": body.Endpoint})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// picoForward forwards a JSON body to the Pico W at the given path.
func (h *Handlers) picoForward(path string, body any) {
	if h.cfg.PicoBaseURL == "" {
		return
	}
	fullURL := h.cfg.PicoBaseURL + path
	payload, err := json.Marshal(body)
	if err != nil {
		log.Printf("pico-forward: marshal error: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(h.cfg.PicoForwardTimeoutMs)*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("pico-forward: create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if h.cfg.WebhookAuthToken != "" {
		req.Header.Set("X-Hook-Auth", h.cfg.WebhookAuthToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("pico-forward: %s error: %v", path, err)
		return
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		log.Printf("pico-forward: drain response for %s: %v", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("pico-forward: %s → HTTP %d", path, resp.StatusCode)
	}
}
