package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
	"github.com/phieri/viking-bio-pwa/proxy/internal/uptime"
)

func newInternalTestHandlers(t *testing.T, cfg *config.Config) *Handlers {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	mgr, err := push.New(dir, "admin@test.local", store)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if cfg == nil {
		cfg = &config.Config{}
	}
	uptimeStore := uptime.NewStore(dir)
	return NewHandlers(cfg, mgr, uptimeStore)
}

func testBoolPtr(v bool) *bool { return &v }

func testFloat64Ptr(v float64) *float64 { return &v }

func TestAuthenticateWebhook(t *testing.T) {
	t.Parallel()

	h := newInternalTestHandlers(t, &config.Config{WebhookAuthToken: "secret"})
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-Hook-Auth", "secret")
	if !h.authenticateWebhook(req) {
		t.Fatal("expected matching webhook token to authenticate")
	}

	req.Header.Set("X-Hook-Auth", "wrong")
	if h.authenticateWebhook(req) {
		t.Fatal("expected wrong webhook token to fail")
	}

	h = newInternalTestHandlers(t, &config.Config{})
	if !h.authenticateWebhook(req) {
		t.Fatal("expected empty webhook token config to allow request")
	}
}

func TestDecodeMachineData(t *testing.T) {
	t.Parallel()

	body, err := decodeMachineData(strings.NewReader(`{"flame":true,"fan":1,"temp":2,"err":0,"valid":true}`))
	if err != nil {
		t.Fatalf("decodeMachineData: %v", err)
	}
	if body.Flame == nil || !*body.Flame {
		t.Fatal("expected decoded flame=true")
	}

	if _, err := decodeMachineData(strings.NewReader(`{"flame":true}`)); err == nil {
		t.Fatal("expected missing fields to fail")
	}
}

func TestUpdateBurnerStateTracksFlameSecondsAndErrors(t *testing.T) {
	t.Parallel()

	h := newInternalTestHandlers(t, nil)
	start := time.Unix(1, 0)
	first := h.updateBurnerState(machineDataBody{
		Flame: testBoolPtr(true),
		Fan:   testFloat64Ptr(20),
		Temp:  testFloat64Ptr(70),
		Err:   testFloat64Ptr(0),
		Valid: testBoolPtr(true),
	}, start)
	if !first.flameChanged || first.newErr {
		t.Fatalf("unexpected first update result: %+v", first)
	}

	second := h.updateBurnerState(machineDataBody{
		Flame: testBoolPtr(true),
		Fan:   testFloat64Ptr(20),
		Temp:  testFloat64Ptr(71),
		Err:   testFloat64Ptr(5),
		Valid: testBoolPtr(true),
	}, start.Add(1500*time.Millisecond))
	if second.flameChanged || !second.newErr {
		t.Fatalf("unexpected second update result: %+v", second)
	}
	if got := h.state.FlameSecs; got != 1 {
		t.Fatalf("expected FlameSecs=1, got %d", got)
	}

	h.updateBurnerState(machineDataBody{
		Flame: testBoolPtr(false),
		Fan:   testFloat64Ptr(0),
		Temp:  testFloat64Ptr(30),
		Err:   testFloat64Ptr(0),
		Valid: testBoolPtr(true),
	}, start.Add(2*time.Second))
	if got := h.state.FlameSecs; got != 2 {
		t.Fatalf("expected FlameSecs=2 after flame turns off, got %d", got)
	}
	if h.state.errorNotified {
		t.Fatal("expected errorNotified to reset when error clears")
	}
}

func TestUpdateBurnerStateSchedulesCleaningReminder(t *testing.T) {
	t.Parallel()

	h := newInternalTestHandlers(t, nil)
	reminderTime := time.Date(2026, time.January, 3, 7, 10, 0, 0, time.UTC)

	result := h.updateBurnerState(machineDataBody{
		Flame: testBoolPtr(true),
		Fan:   testFloat64Ptr(20),
		Temp:  testFloat64Ptr(70),
		Err:   testFloat64Ptr(0),
		Valid: testBoolPtr(true),
	}, reminderTime)
	if !result.cleanDue {
		t.Fatal("expected cleaning reminder to be due during Saturday morning heating season window")
	}
	if result.cleanBody == "" {
		t.Fatal("expected cleaning reminder body to be populated")
	}

	second := h.updateBurnerState(machineDataBody{
		Flame: testBoolPtr(true),
		Fan:   testFloat64Ptr(20),
		Temp:  testFloat64Ptr(71),
		Err:   testFloat64Ptr(0),
		Valid: testBoolPtr(true),
	}, reminderTime.Add(10*time.Minute))
	if second.cleanDue {
		t.Fatal("expected reminder to be debounced within the same week")
	}
}

func TestTriggerNotifications(t *testing.T) {
	h := newInternalTestHandlers(t, nil)

	type call struct {
		typ   string
		title string
		body  string
	}
	calls := make(chan call, 2)
	h.notifyByType = func(typ, title, body string) {
		calls <- call{typ: typ, title: title, body: body}
	}

	h.triggerNotifications(machineDataUpdateResult{
		flameChanged: true,
		newErr:       true,
		flame:        true,
		temp:         73,
		err:          12,
	})

	got := []call{<-calls, <-calls}
	if len(got) != 2 {
		t.Fatalf("expected 2 notifications, got %d", len(got))
	}
}
