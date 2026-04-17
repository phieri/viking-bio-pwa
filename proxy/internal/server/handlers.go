package server

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
	"github.com/phieri/viking-bio-pwa/proxy/internal/uptime"
)

var safeDeviceID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
// Handlers bundles all HTTP handler dependencies.
type Handlers struct {
	state           *State
	pushMgr         *push.Manager
	notifyByType    func(string, string, string)
	uptimeStore     *uptime.Store
	uptimeAuthToken string
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(pushMgr *push.Manager, uptimeStore *uptime.Store, uptimeAuthToken string) *Handlers {
	return &Handlers{
		state:           &State{},
		pushMgr:         pushMgr,
		notifyByType:    pushMgr.NotifyByType,
		uptimeStore:     uptimeStore,
		uptimeAuthToken: uptimeAuthToken,
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

// authenticateUptime checks the Bearer token in the Authorization header
// against the configured uptimeAuthToken. When no token is configured all requests pass.
func (h *Handlers) authenticateUptime(r *http.Request) bool {
	token := h.uptimeAuthToken
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
	DeviceID string `json:"device_id"`
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
	if !safeDeviceID.MatchString(body.DeviceID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device_id"})
		return
	}

	// Daily summary shape: date field is present.
	if body.Date != "" {
		if _, err := time.Parse("2006-01-02", body.Date); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "date must be YYYY-MM-DD"})
			return
		}
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
