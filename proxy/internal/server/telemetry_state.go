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

type machineDataSnapshot struct {
	Flame     bool    `json:"flame"`
	Fan       float64 `json:"fan"`
	Temp      float64 `json:"temp"`
	Err       float64 `json:"err"`
	Valid     bool    `json:"valid"`
	FlameSecs int64   `json:"flame_secs"`
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
	cleanDue     bool
	flame        bool
	temp         float64
	err          float64
	cleanBody    string
}

func (s *State) snapshot() machineDataSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return machineDataSnapshot{
		Flame:     s.Flame,
		Fan:       s.Fan,
		Temp:      s.Temp,
		Err:       s.Err,
		Valid:     s.Valid,
		FlameSecs: s.FlameSecs,
	}
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
	}
	if result.newErr {
		s.errorNotified = true
	}
	if s.Err == 0 {
		s.errorNotified = false
	}
	if isCleaningReminderWindow(now) {
		today := now.UTC().Unix() / 86400
		if s.lastCleanReminderDay == 0 || today-s.lastCleanReminderDay >= 7 {
			flameSecsSinceReminder := s.FlameSecs - s.lastCleanReminderSeconds
			if flameSecsSinceReminder < 0 {
				flameSecsSinceReminder = 0
			}
			result.cleanDue = true
			result.cleanBody = fmt.Sprintf(
				"Clean the burner. Flame-on since last reminder: %s.",
				formatFlameSeconds(flameSecsSinceReminder),
			)
			s.lastCleanReminderDay = today
			s.lastCleanReminderSeconds = s.FlameSecs
		}
	}

	return result
}
