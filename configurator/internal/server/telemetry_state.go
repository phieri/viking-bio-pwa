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
}

type machineDataSnapshot struct {
	Flame     bool    `json:"flame"`
	Fan       float64 `json:"fan"`
	Temp      float64 `json:"temp"`
	Err       float64 `json:"err"`
	Valid     bool    `json:"valid"`
	FlameSecs int64   `json:"flame_secs"`
}

func newMachineDataSnapshot(flame bool, fan, temp, err float64, valid bool, flameSecs int64) machineDataSnapshot {
	return machineDataSnapshot{
		Flame:     flame,
		Fan:       fan,
		Temp:      temp,
		Err:       err,
		Valid:     valid,
		FlameSecs: flameSecs,
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

func (s *State) snapshot() machineDataSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return newMachineDataSnapshot(s.Flame, s.Fan, s.Temp, s.Err, s.Valid, s.FlameSecs)
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

func (s *State) applyMachineData(body machineDataBody, now time.Time) machineDataUpdateResult {
	s.mu.Lock()
	defer s.mu.Unlock()

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
		snapshot:     newMachineDataSnapshot(s.Flame, s.Fan, s.Temp, s.Err, s.Valid, s.FlameSecs),
	}
	if result.newErr {
		s.errorNotified = true
	}
	if s.Err == 0 {
		s.errorNotified = false
	}

	return result
}
