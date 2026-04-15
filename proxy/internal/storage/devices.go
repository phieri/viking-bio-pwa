package storage

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// DeviceRecord stores the per-device ingest secret and replay state.
type DeviceRecord struct {
	Key       string `json:"key"`
	LastSeq   uint64 `json:"last_seq"`
	UpdatedAt int64  `json:"updated_at"`
}

func (s *Store) loadDevices() {
	data, err := os.ReadFile(s.devicesPath)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Printf("storage: failed to read %s: %v", s.devicesPath, err)
		return
	}
	var devices map[string]DeviceRecord
	if err := json.Unmarshal(data, &devices); err != nil {
		log.Printf("storage: failed to parse devices: %v", err)
		return
	}
	s.devices = devices
	log.Printf("storage: loaded %d provisioned device(s)", len(s.devices))
}

func (s *Store) saveDevicesLocked() error {
	if err := writeAtomicJSON(s.devicesPath, s.devices, 0o600); err != nil {
		return err
	}
	return nil
}

// ProvisionDevice inserts or replaces the secret for a device and resets replay state.
func (s *Store) ProvisionDevice(device, key string) error {
	if device == "" || key == "" {
		return fmt.Errorf("device and key are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[device] = DeviceRecord{
		Key:       key,
		LastSeq:   0,
		UpdatedAt: time.Now().Unix(),
	}
	if err := s.saveDevicesLocked(); err != nil {
		return fmt.Errorf("save devices: %w", err)
	}
	log.Printf("storage: provisioned device %s", device)
	return nil
}

// Device returns the stored device record, if any.
func (s *Store) Device(device string) (DeviceRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.devices[device]
	return record, ok
}

// AcceptSequence atomically verifies anti-replay ordering and persists the new sequence.
func (s *Store) AcceptSequence(device string, seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.devices[device]
	if !ok {
		return fmt.Errorf("unknown device")
	}
	if seq <= record.LastSeq {
		return fmt.Errorf("replayed or out-of-order sequence")
	}
	record.LastSeq = seq
	record.UpdatedAt = time.Now().Unix()
	s.devices[device] = record
	if err := s.saveDevicesLocked(); err != nil {
		return fmt.Errorf("save devices: %w", err)
	}
	return nil
}

// AppendIngestFallback stores a JSONL record when the ingest queue overflows.
func (s *Store) AppendIngestFallback(record any) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal fallback record: %w", err)
	}
	line := append(data, '\n')
	f, err := os.OpenFile(s.fallbackPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open fallback log: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("write fallback log: %w", err)
	}
	return nil
}
