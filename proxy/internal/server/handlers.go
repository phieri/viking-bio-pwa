package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
	"github.com/phieri/viking-bio-pwa/proxy/internal/uptime"
)

// State holds the shared burner telemetry state.
type State struct {
	mu                       sync.RWMutex
	Flame                    bool    `json:"flame"`
	Fan                      float64 `json:"fan"`
	Temp                     float64 `json:"temp"`
	Err                      float64 `json:"err"`
	Valid                    bool    `json:"valid"`
	FlameSecs                int64   `json:"flame_secs"`
	UpdatedAt                int64   `json:"updated_at"`
	lastFlameTime            int64   // ms; zero means flame was off last update
	errorNotified            bool
	lastCleanReminderDay     int64
	lastCleanReminderSeconds int64
}

// Handlers bundles all HTTP handler dependencies.
type Handlers struct {
	cfg          *config.Config
	state        *State
	pushMgr      *push.Manager
	notifyByType func(string, string, string)
	uptimeStore  *uptime.Store
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(cfg *config.Config, pushMgr *push.Manager, uptimeStore *uptime.Store) *Handlers {
	return &Handlers{
		cfg:          cfg,
		state:        &State{},
		pushMgr:      pushMgr,
		notifyByType: pushMgr.NotifyByType,
		uptimeStore:  uptimeStore,
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
	cleanDue     bool
	flame        bool
	temp         float64
	err          float64
	cleanBody    string
}

func formatFlameSeconds(secs int64) string {
	hours := secs / 3600
	minutes := (secs % 3600) / 60
	switch {
	case hours == 0:
		return fmt.Sprintf("%d min", minutes)
	case minutes == 0:
		return fmt.Sprintf("%d h", hours)
	default:
		return fmt.Sprintf("%d h %d min", hours, minutes)
	}
}

func isCleaningReminderWindow(now time.Time) bool {
	now = now.UTC()
	month := now.Month()
	inSeason := month == time.November ||
		month == time.December ||
		month == time.January ||
		month == time.February ||
		month == time.March
	if !inSeason {
		return false
	}
	return now.Weekday() == time.Saturday && now.Hour() == 7 && now.Minute() < 30
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
	nowMillis := now.UnixMilli()

	if prevFlame && h.state.lastFlameTime != 0 {
		elapsed := nowMillis - h.state.lastFlameTime
		if elapsed > 0 {
			h.state.FlameSecs += elapsed / 1000
			h.state.lastFlameTime = nowMillis - (elapsed % 1000)
		}
	}

	h.state.Flame = *body.Flame
	h.state.Fan = *body.Fan
	h.state.Temp = *body.Temp
	h.state.Err = *body.Err
	h.state.Valid = *body.Valid

	h.state.UpdatedAt = nowMillis
	if h.state.Flame {
		if !prevFlame {
			h.state.lastFlameTime = nowMillis
		}
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
	if isCleaningReminderWindow(now) {
		today := now.UTC().Unix() / 86400
		if h.state.lastCleanReminderDay == 0 || today-h.state.lastCleanReminderDay >= 7 {
			flameSecsSinceReminder := h.state.FlameSecs - h.state.lastCleanReminderSeconds
			if flameSecsSinceReminder < 0 {
				flameSecsSinceReminder = 0
			}
			result.cleanDue = true
			result.cleanBody = fmt.Sprintf(
				"Clean the burner. Flame-on since last reminder: %s.",
				formatFlameSeconds(flameSecsSinceReminder),
			)
			h.state.lastCleanReminderDay = today
			h.state.lastCleanReminderSeconds = h.state.FlameSecs
		}
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
	if result.cleanDue {
		go h.notifyByType("clean", "Viking Bio: Cleaning Reminder", result.cleanBody)
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

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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

// authenticateUptime checks the Bearer token in the Authorization header
// against cfg.UptimeAuthToken. When no token is configured all requests pass.
func (h *Handlers) authenticateUptime(r *http.Request) bool {
	token := h.cfg.UptimeAuthToken
	if token == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	provided := strings.TrimPrefix(auth, "Bearer ")
	return subtle.ConstantTimeCompare([]byte(token), []byte(provided)) == 1
}

// uptimeBucketsBody is the union body for POST /api/v1/uptime/buckets.
// The handler detects the shape by the presence of the "date" field (daily
// summary) vs the "buckets" array (bucket batch).
type uptimeBucketsBody struct {
	DeviceID   string          `json:"device_id"`
	// Bucket-batch fields
	Buckets    []uptime.Bucket `json:"buckets"`
	Source     string          `json:"source"`
	BatchID    string          `json:"batch_id"`
	SequenceID string          `json:"sequence_id"`
	// Daily-summary fields
	Date        string `json:"date"`
	SecondsOn   int    `json:"seconds_on"`
	SampleCount int    `json:"sample_count"`
	SummaryID   string `json:"summary_id"`
}

// HandlePostUptimeBuckets serves POST /api/v1/uptime/buckets.
// It accepts two payload shapes:
//   - bucket batch: device_id + buckets array
//   - daily summary: device_id + date + seconds_on
func (h *Handlers) HandlePostUptimeBuckets(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateUptime(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if h.uptimeStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "uptime store unavailable"})
		return
	}

	var body uptimeBucketsBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if body.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id is required"})
		return
	}

	// Daily summary shape: date field is present.
	if body.Date != "" {
		sum := uptime.DailySummary{
			DeviceID:    body.DeviceID,
			Date:        body.Date,
			SecondsOn:   body.SecondsOn,
			SampleCount: body.SampleCount,
			Source:      body.Source,
			SummaryID:   body.SummaryID,
		}
		if err := h.uptimeStore.UpsertDailySummary(sum); err != nil {
			log.Printf("uptime: upsert daily summary: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "accepted": 1})
		return
	}

	// Bucket batch shape.
	batch := uptime.BucketBatch{
		DeviceID:   body.DeviceID,
		Buckets:    body.Buckets,
		Source:     body.Source,
		BatchID:    body.BatchID,
		SequenceID: body.SequenceID,
	}
	n, err := h.uptimeStore.AppendBuckets(batch)
	if err != nil {
		log.Printf("uptime: append buckets: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	log.Printf("uptime: accepted %d bucket(s) from device %s", n, body.DeviceID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "accepted": n})
}

// HandleGetUptimeDaily serves GET /api/v1/uptime/daily.
// Query parameters: device_id (required), from (YYYY-MM-DD, optional),
// to (YYYY-MM-DD, optional).
func (h *Handlers) HandleGetUptimeDaily(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateUptime(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if h.uptimeStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "uptime store unavailable"})
		return
	}

	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id is required"})
		return
	}
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")

	summaries, err := h.uptimeStore.GetDailySummaries(deviceID, from, to)
	if err != nil {
		log.Printf("uptime: get daily summaries: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if summaries == nil {
		summaries = []uptime.DailySummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_id": deviceID, "summaries": summaries})
}
