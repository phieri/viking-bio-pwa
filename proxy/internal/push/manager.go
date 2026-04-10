package push

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
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

// New creates a Manager, loading or generating VAPID keys in dataDir.
func New(dataDir, contactEmail string, store *storage.Store) (*Manager, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("push: mkdir %s: %w", dataDir, err)
	}

	pubPath := filepath.Join(dataDir, "server-vapid.pub")
	privPath := filepath.Join(dataDir, "server-vapid.priv")

	var pub, priv string
	pubBytes, pubErr := os.ReadFile(pubPath)
	privBytes, privErr := os.ReadFile(privPath)

	if pubErr == nil && privErr == nil {
		pub = string(pubBytes)
		priv = string(privBytes)
		log.Println("push: loaded VAPID keys from disk")
	} else {
		var err error
		// GenerateVAPIDKeys returns (privateKey, publicKey, error)
		priv, pub, err = webpush.GenerateVAPIDKeys()
		if err != nil {
			return nil, fmt.Errorf("push: generate VAPID keys: %w", err)
		}
		if err := os.WriteFile(pubPath, []byte(pub), 0o644); err != nil {
			return nil, fmt.Errorf("push: write public key: %w", err)
		}
		if err := os.WriteFile(privPath, []byte(priv), 0o600); err != nil {
			return nil, fmt.Errorf("push: write private key: %w", err)
		}
		log.Println("push: generated new VAPID keys")
	}

	contact := fmt.Sprintf("mailto:%s", contactEmail)
	return &Manager{
		vapidPub:         pub,
		vapidPriv:        priv,
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

// SendTest sends a test push notification to all subscribers, ignoring per-type preferences.
func (m *Manager) SendTest() {
	subs := m.store.All()
	payload, err := json.Marshal(notifyPayload{
		Title:    "Viking Bio: Test",
		Body:     "Testnotis från Viking Bio Proxy",
		Icon:     "/icon-192.png",
		Type:     "test",
		Priority: "low",
		TS:       time.Now().UnixMilli(),
	})
	if err != nil {
		log.Printf("push: marshal payload: %v", err)
		return
	}

	var expired []string
	for _, sub := range subs {
		m.notifySem <- struct{}{}
		resp, err := m.sendNotification(payload, &webpush.Subscription{
			Endpoint: sub.Endpoint,
			Keys: webpush.Keys{
				P256dh: sub.P256DH,
				Auth:   sub.Auth,
			},
		}, &webpush.Options{
			VAPIDPublicKey:  m.vapidPub,
			VAPIDPrivateKey: m.vapidPriv,
			Subscriber:      m.contact,
			TTL:             30,
		})
		<-m.notifySem
		if err != nil {
			log.Printf("push: send error for %s: %v", sub.Endpoint, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 410 || resp.StatusCode == 404 {
			expired = append(expired, sub.Endpoint)
		} else {
			log.Printf("push: test notification sent to %s (%d)", sub.Endpoint, resp.StatusCode)
		}
	}
	if len(expired) > 0 {
		m.store.RemoveAll(expired)
	}
}

// NotifyByType sends a push notification to all subscribers opted in to the given type.
func (m *Manager) NotifyByType(typ, title, body string) {
	subs := m.store.All()
	priority := "low"
	if typ == "error" {
		priority = "high"
	}
	payload, err := json.Marshal(notifyPayload{
		Title:    title,
		Body:     body,
		Icon:     "/icon-192.png",
		Type:     typ,
		Priority: priority,
		TS:       time.Now().UnixMilli(),
	})
	if err != nil {
		log.Printf("push: marshal payload: %v", err)
		return
	}

	var expired []string
	for _, sub := range subs {
		var enabled bool
		switch typ {
		case "flame":
			enabled = sub.Prefs.Flame
		case "error":
			enabled = sub.Prefs.Error
		case "clean":
			enabled = sub.Prefs.Clean
		}
		if !enabled {
			continue
		}

		m.notifySem <- struct{}{}
		resp, err := m.sendNotification(payload, &webpush.Subscription{
			Endpoint: sub.Endpoint,
			Keys: webpush.Keys{
				P256dh: sub.P256DH,
				Auth:   sub.Auth,
			},
		}, &webpush.Options{
			VAPIDPublicKey:  m.vapidPub,
			VAPIDPrivateKey: m.vapidPriv,
			Subscriber:      m.contact,
			TTL:             30,
		})
		<-m.notifySem
		if err != nil {
			log.Printf("push: send error for %s: %v", sub.Endpoint, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 410 || resp.StatusCode == 404 {
			expired = append(expired, sub.Endpoint)
		}
	}
	if len(expired) > 0 {
		m.store.RemoveAll(expired)
	}
}
