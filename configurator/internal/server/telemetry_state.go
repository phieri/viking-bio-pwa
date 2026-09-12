/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package server

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
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
	updates       chan struct{}
}

func NewState() *State {
	return &State{updates: make(chan struct{}, 1)}
}

func (s *State) Updates() chan struct{} {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updates == nil {
		s.updates = make(chan struct{}, 1)
	}
	return s.updates
}

func (s *State) notifyUpdate() {
	if s == nil {
		return
	}

	ch := s.Updates()
	if ch == nil {
		return
	}

	select {
	case ch <- struct{}{}:
	default:
	}
}

type machineDataSnapshot struct {
	Flame     bool    `json:"flame"`
	Fan       float64 `json:"fan"`
	Temp      float64 `json:"temp"`
	Err       float64 `json:"err"`
	Valid     bool    `json:"valid"`
	FlameSecs int64   `json:"flame_secs"`
	UpdatedAt int64   `json:"updated_at"`
}

func newMachineDataSnapshot(flame bool, fan, temp, err float64, valid bool, flameSecs, updatedAt int64) machineDataSnapshot {
	return machineDataSnapshot{
		Flame:     flame,
		Fan:       fan,
		Temp:      temp,
		Err:       err,
		Valid:     valid,
		FlameSecs: flameSecs,
		UpdatedAt: updatedAt,
	}
}

// machineDataBody is the shared telemetry payload shape used by ingest and state updates.
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
	snapshot     machineDataSnapshot
}

func (s *State) Snapshot() machineDataSnapshot {
	return s.snapshot()
}

func (s *State) snapshot() machineDataSnapshot {
	if s == nil {
		return newMachineDataSnapshot(false, 0, 0, 0, false, 0, 0)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return newMachineDataSnapshot(s.Flame, s.Fan, s.Temp, s.Err, s.Valid, s.FlameSecs, s.UpdatedAt)
}

func decodeMachineData(r io.Reader) (machineDataBody, error) {
	if r == nil {
		return machineDataBody{}, fmt.Errorf("nil reader")
	}
	var body machineDataBody
	if err := json.NewDecoder(r).Decode(&body); err != nil {
		return machineDataBody{}, err
	}
	if body.Flame == nil || body.Fan == nil || body.Temp == nil || body.Err == nil || body.Valid == nil {
		return machineDataBody{}, fmt.Errorf("missing required field")
	}
	return body, nil
}

func (s *State) applyMachineData(body machineDataBody, now time.Time) machineDataUpdateResult {
	if s == nil {
		return machineDataUpdateResult{}
	}
	if body.Flame == nil || body.Fan == nil || body.Temp == nil || body.Err == nil || body.Valid == nil {
		snapshot := s.snapshot()
		return machineDataUpdateResult{
			snapshot: snapshot,
			flame:    snapshot.Flame,
			temp:     snapshot.Temp,
			err:      snapshot.Err,
		}
	}

	s.mu.Lock()
	prevFlame := s.Flame
	prevErr := s.Err
	nowMillis := now.UnixMilli()

	if prevFlame && s.lastFlameTime != 0 {
		elapsed := nowMillis - s.lastFlameTime
		if elapsed > 0 {
			s.FlameSecs += elapsed / 1000
			s.lastFlameTime = nowMillis - (elapsed % 1000)
		}
	}

	s.Flame = *body.Flame
	s.Fan = *body.Fan
	s.Temp = *body.Temp
	s.Err = *body.Err
	s.Valid = *body.Valid
	s.UpdatedAt = nowMillis

	if s.Flame {
		if !prevFlame {
			s.lastFlameTime = nowMillis
		}
	} else {
		s.lastFlameTime = 0
	}

	result := machineDataUpdateResult{
		flameChanged: s.Flame != prevFlame,
		newErr:       s.Err != 0 && s.Err != prevErr && !s.errorNotified,
		flame:        s.Flame,
		temp:         s.Temp,
		err:          s.Err,
		snapshot:     newMachineDataSnapshot(s.Flame, s.Fan, s.Temp, s.Err, s.Valid, s.FlameSecs, s.UpdatedAt),
	}
	if result.newErr {
		s.errorNotified = true
	}
	if s.Err == 0 {
		s.errorNotified = false
	}
	s.mu.Unlock()
	s.notifyUpdate()
	return result
}
