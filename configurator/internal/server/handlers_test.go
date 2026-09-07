package server

import (
	"testing"
	"time"
)

func TestProcessMachineDataUpdatesStateSnapshot(t *testing.T) {
	h := NewHandlers(nil)
	now := time.Unix(123, 0)
	flame := true
	fan := 55.0
	temp := 72.0
	err := 3.0
	valid := true

	h.processMachineData(machineDataBody{
		Flame: &flame,
		Fan:   &fan,
		Temp:  &temp,
		Err:   &err,
		Valid: &valid,
	}, "test", now)

	state := h.state.snapshot()
	if !state.Flame {
		t.Fatal("expected flame to be true")
	}
	if state.Temp != 72 {
		t.Fatalf("expected temp 72, got %v", state.Temp)
	}
	if state.Err != 3 {
		t.Fatalf("expected err 3, got %v", state.Err)
	}
}
