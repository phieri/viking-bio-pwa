package server

import (
	"strings"
	"testing"
	"time"

	"github.com/phieri/viking-bio-pwa/configurator/internal/config"
)

func newInternalTestHandlers(t *testing.T) *Handlers {
	t.Helper()
	return newInternalTestHandlersWithConfig(t, nil)
}

func newInternalTestHandlersWithConfig(t *testing.T, cfg *config.Config) *Handlers {
	t.Helper()
	return NewHandlers(cfg)
}

func testBoolPtr(v bool) *bool { return &v }

func testFloat64Ptr(v float64) *float64 { return &v }

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

	h := newInternalTestHandlers(t)
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

func TestStateSnapshot(t *testing.T) {
	t.Parallel()

	state := &State{
		Flame:     true,
		Fan:       50,
		Temp:      78,
		Err:       2,
		Valid:     true,
		FlameSecs: 123,
		UpdatedAt: 999,
	}

	got := state.snapshot()
	if got.Flame != state.Flame || got.Fan != state.Fan || got.Temp != state.Temp ||
		got.Err != state.Err || got.Valid != state.Valid || got.FlameSecs != state.FlameSecs {
		t.Fatalf("snapshot() = %#v, state = %#v", got, state)
	}
}
