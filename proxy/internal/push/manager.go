package push

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
	"github.com/phieri/viking-bio-pwa/proxy/internal/vapid"
)

// Manager handles VAPID key lifecycle and Web Push notification delivery.
type Manager struct {
	vapidPub         string
	vapidPriv        string
	contact          string
	store            *storage.Store
	sendNotification func([]byte, *webpush.Subscription, *webpush.Options) (*http.Response, error)
	notifySem        chan struct{}
}

var ErrSubscriptionNotFound = errors.New("subscription not found")

const (
	testNotificationTitle = "Viking Bio: Test"
	testNotificationBody  = "Testnotifiering från Viking Bio Proxy"
)

// New creates a Manager, loading or generating VAPID keys in dataDir.
func New(dataDir, contactEmail string, store *storage.Store) (*Manager, error) {
	keys, err := vapid.LoadOrGenerate(dataDir)
	if err != nil {
		return nil, fmt.Errorf("push: %w", err)
	}

	contact := fmt.Sprintf("mailto:%s", contactEmail)
	return &Manager{
		vapidPub:         keys.Public,
		vapidPriv:        keys.Private,
		contact:          contact,
		store:            store,
		sendNotification: webpush.SendNotification,
		notifySem:        make(chan struct{}, 4),
	}, nil
}

// GetVapidPublicKey returns the server-side VAPID public key.
func (m *Manager) GetVapidPublicKey() string {
	return m.vapidPub
}

// GetSubscriptionCount returns the number of active subscriptions.
func (m *Manager) GetSubscriptionCount() int {
	return m.store.Count()
}

// GetSubscriptions returns a snapshot of the active subscriptions.
func (m *Manager) GetSubscriptions() []storage.Subscription {
	return m.store.All()
}

// AddSubscription adds or updates a subscription. Returns false if at capacity.
func (m *Manager) AddSubscription(endpoint, p256dh, auth string, prefs storage.Prefs) bool {
	return m.store.Add(storage.Subscription{
		Endpoint: endpoint,
		P256DH:   p256dh,
		Auth:     auth,
		Prefs:    prefs,
	})
}

// RemoveSubscription removes a subscription by endpoint URL.
func (m *Manager) RemoveSubscription(endpoint string) {
	m.store.Remove(endpoint)
}

type notifyPayload struct {
	Title    string `json:"title"`
	Body     string `json:"body"`
	Icon     string `json:"icon"`
	Type     string `json:"type"`
	Priority string `json:"priority"`
	TS       int64  `json:"ts"`
}

func (m *Manager) buildPayload(title, body, typ, priority string) ([]byte, error) {
	return json.Marshal(notifyPayload{
		Title:    title,
		Body:     body,
		Icon:     "/icon-192.png",
		Type:     typ,
		Priority: priority,
		TS:       time.Now().UnixMilli(),
	})
}

func (m *Manager) subscriptionFor(sub storage.Subscription) *webpush.Subscription {
	return &webpush.Subscription{
		Endpoint: sub.Endpoint,
		Keys: webpush.Keys{
			P256dh: sub.P256DH,
			Auth:   sub.Auth,
		},
	}
}

func notificationPreferenceSelector(typ string) (func(storage.Prefs) bool, bool) {
	switch typ {
	case "flame":
		return func(prefs storage.Prefs) bool { return prefs.Flame }, true
	case "error":
		return func(prefs storage.Prefs) bool { return prefs.Error }, true
	case "clean":
		return func(prefs storage.Prefs) bool { return prefs.Clean }, true
	default:
		return nil, false
	}
}

func (m *Manager) sendOptions() *webpush.Options {
	return &webpush.Options{
		VAPIDPublicKey:  m.vapidPub,
		VAPIDPrivateKey: m.vapidPriv,
		Subscriber:      m.contact,
		TTL:             30,
	}
}

func (m *Manager) sendPayload(payload []byte, subs []storage.Subscription, shouldSend func(storage.Subscription) bool, onSuccess func(storage.Subscription, int)) {
	var expired []string
	for _, sub := range subs {
		if shouldSend != nil && !shouldSend(sub) {
			continue
		}

		m.notifySem <- struct{}{}
		resp, err := m.sendNotification(payload, m.subscriptionFor(sub), m.sendOptions())
		<-m.notifySem
		if err != nil {
			log.Printf("push: send error for %s: %v", sub.Endpoint, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotFound {
			expired = append(expired, sub.Endpoint)
			continue
		}
		if onSuccess != nil {
			onSuccess(sub, resp.StatusCode)
		}
	}
	if len(expired) > 0 {
		m.store.RemoveAll(expired)
	}
}

// normalizePriority maps UI priorities to the Web Push urgency values used in
// the payload and defaults invalid values to "low" for safety.
func normalizePriority(priority string) string {
	switch priority {
	case "very-low", "low":
		return "low"
	case "normal", "high":
		return priority
	default:
		return "low"
	}
}

// SendTestToSubscriber sends a test push notification to the selected subscriber.
func (m *Manager) SendTestToSubscriber(endpoint, priority string) error {
	if sub, ok := m.store.GetByEndpoint(endpoint); ok {
		payload, err := m.buildPayload(testNotificationTitle, testNotificationBody, "test", normalizePriority(priority))
		if err != nil {
			return fmt.Errorf("push: marshal payload: %w", err)
		}
		m.sendPayload(payload, []storage.Subscription{sub}, nil, func(sentSub storage.Subscription, statusCode int) {
			log.Printf("push: test notification sent to %s (%d)", sentSub.Endpoint, statusCode)
		})
		return nil
	}
	return ErrSubscriptionNotFound
}

// SendTest sends a test push notification to all subscribers, ignoring per-type preferences.
func (m *Manager) SendTest() {
	subs := m.store.All()
	payload, err := m.buildPayload("Viking Bio: Test", "Testnotis från Viking Bio Proxy", "test", "low")
	if err != nil {
		log.Printf("push: marshal payload: %v", err)
		return
	}
	m.sendPayload(payload, subs, nil, func(sub storage.Subscription, statusCode int) {
		log.Printf("push: test notification sent to %s (%d)", sub.Endpoint, statusCode)
	})
}

// NotifyByType sends a push notification to all subscribers opted in to the given type.
func (m *Manager) NotifyByType(typ, title, body string) {
	subs := m.store.All()
	enabledForType, ok := notificationPreferenceSelector(typ)
	if !ok {
		log.Printf("push: unsupported notification type %q (valid: flame, error, clean)", typ)
		return
	}
	priority := "low"
	if typ == "error" {
		priority = "high"
	}
	payload, err := m.buildPayload(title, body, typ, priority)
	if err != nil {
		log.Printf("push: marshal payload: %v", err)
		return
	}
	m.sendPayload(payload, subs, func(sub storage.Subscription) bool {
		return enabledForType(sub.Prefs)
	}, nil)
}
