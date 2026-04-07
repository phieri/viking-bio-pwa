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
	cfg     *config.Config
	state   *State
	pushMgr *push.Manager
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(cfg *config.Config, pushMgr *push.Manager) *Handlers {
	return &Handlers{
		cfg:     cfg,
		state:   &State{},
		pushMgr: pushMgr,
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

// HandleMachineData serves POST /api/machine-data.
func (h *Handlers) HandleMachineData(w http.ResponseWriter, r *http.Request) {
	// Token validation (constant-time)
	if token := h.cfg.WebhookAuthToken; token != "" {
		provided := r.Header.Get("X-Hook-Auth")
		if subtle.ConstantTimeCompare([]byte(token), []byte(provided)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
	}

	var body machineDataBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
		body.Flame == nil || body.Fan == nil || body.Temp == nil ||
		body.Err == nil || body.Valid == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}

	h.state.mu.Lock()
	prevFlame := h.state.Flame
	prevErr := h.state.Err

	h.state.Flame = *body.Flame
	h.state.Fan = *body.Fan
	h.state.Temp = *body.Temp
	h.state.Err = *body.Err
	h.state.Valid = *body.Valid

	// Accumulate flame-on seconds (tracked in ms for accuracy)
	now := time.Now().UnixMilli()
	h.state.UpdatedAt = now
	if h.state.Flame {
		if h.state.lastFlameTime == 0 {
			h.state.lastFlameTime = now
		}
		elapsed := now - h.state.lastFlameTime
		h.state.FlameSecs += elapsed / 1000
		h.state.lastFlameTime = now - (elapsed % 1000) // carry sub-second remainder
	} else {
		h.state.lastFlameTime = 0
	}

	flameChanged := h.state.Flame != prevFlame
	newErr := h.state.Err != 0 && h.state.Err != prevErr && !h.state.errorNotified
	errCleared := h.state.Err == 0
	curFlame := h.state.Flame
	curTemp := h.state.Temp
	curErr := h.state.Err

	if newErr {
		h.state.errorNotified = true
	}
	if errCleared {
		h.state.errorNotified = false
	}
	h.state.mu.Unlock()

	log.Printf("webhook: data received (flame=%v, temp=%.1f°C, err=%.0f)", curFlame, curTemp, curErr)

	// Push notifications (non-blocking, best-effort)
	if flameChanged {
		var title, body string
		if curFlame {
			title = "Viking Bio: Låga tänd"
			body = fmt.Sprintf("Pannan tänd \u2013 %.0f\u00a0°C", curTemp)
		} else {
			title = "Viking Bio: Låga släckt"
			body = "Pannan har slocknat"
		}
		go h.pushMgr.NotifyByType("flame", title, body)
	}
	if newErr {
		go h.pushMgr.NotifyByType("error", "Viking Bio: Fel",
			fmt.Sprintf("Felkod %.0f detekterad", curErr))
	}

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
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("pico-forward: %s → HTTP %d", path, resp.StatusCode)
	}
}
