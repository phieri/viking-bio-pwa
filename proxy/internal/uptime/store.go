// Package uptime provides file-backed storage for device uptime buckets and
// daily summaries. Data is stored as append-only JSONL files (buckets) and
// atomic JSON files (daily summaries) under <DATA_DIR>/uptime/.
//
// Directory layout:
//
//	<DATA_DIR>/uptime/
//	  buckets/<device_id>/<YYYY-MM-DD>.jsonl   – raw bucket entries (append-only)
//	  daily/<device_id>/<YYYY-MM-DD>.json       – aggregated daily summaries (atomic write)
//	  seen-batches/<device_id>.txt              – seen batch_ids (one per line)
package uptime

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Bucket is a single uptime measurement window.
type Bucket struct {
	Start           string `json:"start"`                 // ISO8601 timestamp of window start
	DurationSeconds int    `json:"duration_seconds"`      // total length of window in seconds
	SecondsOn       int    `json:"seconds_on"`            // burner-on time within window
	BucketID        string `json:"bucket_id,omitempty"`   // optional client-assigned dedup ID
	ReceivedAt      string `json:"received_at,omitempty"` // server-assigned receive timestamp
}

// BucketBatch is the "bucket batch" variant of POST /api/v1/uptime/buckets.
type BucketBatch struct {
	DeviceID   string   `json:"device_id"`
	Buckets    []Bucket `json:"buckets"`
	Source     string   `json:"source"`             // "pico" | "pwa"
	BatchID    string   `json:"batch_id,omitempty"` // optional batch-level dedup ID
	SequenceID string   `json:"sequence_id,omitempty"`
}

// DailySummary is an aggregated uptime summary for one calendar day per device.
type DailySummary struct {
	DeviceID    string `json:"device_id"`
	Date        string `json:"date"` // YYYY-MM-DD
	SecondsOn   int    `json:"seconds_on"`
	SampleCount int    `json:"sample_count,omitempty"`
	Source      string `json:"source,omitempty"`
	SummaryID   string `json:"summary_id,omitempty"` // optional client-assigned dedup ID
	UpdatedAt   string `json:"updated_at,omitempty"` // RFC3339
}

// Store manages uptime data on disk. All exported methods are safe for
// concurrent use from multiple goroutines.
type Store struct {
	mu      sync.Mutex
	dataDir string
}

// NewStore returns a Store that persists data under dataDir.
func NewStore(dataDir string) *Store {
	return &Store{dataDir: dataDir}
}

// sanitizeID converts an arbitrary string into a file-system-safe path component.
// Only alphanumerics, hyphens, underscores and dots are kept; all other
// characters are replaced with underscore. This prevents path traversal.
func sanitizeID(id string) string {
	if id == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range id {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// isValidDate returns true if s is a syntactically valid YYYY-MM-DD date
// string (digit positions and hyphen separators only, no path separators).
func isValidDate(s string) bool {
	if len(s) != 10 {
		return false
	}
	for i, r := range s {
		if i == 4 || i == 7 {
			if r != '-' {
				return false
			}
		} else if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// dateFromISO8601 extracts and validates the YYYY-MM-DD portion of an ISO8601
// timestamp. Falls back to today (UTC) when the string is absent or does not
// yield a valid date, preventing path-traversal via crafted start values.
func dateFromISO8601(s string) string {
	if len(s) >= 10 {
		candidate := s[:10]
		if isValidDate(candidate) {
			return candidate
		}
	}
	return time.Now().UTC().Format("2006-01-02")
}

func (s *Store) bucketsPath(deviceID, date string) string {
	// Defense-in-depth: bucket files are keyed by YYYY-MM-DD only.
	// Keep path construction safe even if callers pass unchecked input.
	if !isValidDate(date) {
		date = "invalid-date"
	}
	return filepath.Join(s.dataDir, "uptime", "buckets", sanitizeID(deviceID), date+".jsonl")
}

func (s *Store) dailyPath(deviceID, date string) string {
	// Defense-in-depth: daily summaries are keyed by YYYY-MM-DD only.
	// Callers already validate, but keep path construction safe even if called directly.
	if !isValidDate(date) {
		date = "invalid-date"
	}
	return filepath.Join(s.dataDir, "uptime", "daily", sanitizeID(deviceID), date+".json")
}

func ensureWithinBase(baseDir, targetPath string) error {
	if filepath.IsAbs(targetPath) {
		// Absolute target paths are only allowed after canonical containment checks.
		// Keep behavior strict to avoid path-injection surprises.
	}
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("resolve base dir: %w", err)
	}
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("resolve target path: %w", err)
	}
	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return fmt.Errorf("compute relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("invalid path outside allowed directory")
	}
	return nil
}

func (s *Store) seenBatchesPath(deviceID string) string {
	return filepath.Join(s.dataDir, "uptime", "seen-batches", sanitizeID(deviceID)+".txt")
}

// AppendBuckets deduplicates and persists buckets from a BucketBatch, then
// updates the relevant daily summary file(s). Returns the number of new
// buckets written; returns 0 without error when the batch_id was already seen.
func (s *Store) AppendBuckets(batch BucketBatch) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if batch.DeviceID == "" {
		return 0, fmt.Errorf("device_id is required")
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Batch-level deduplication via batch_id.
	if batch.BatchID != "" && s.hasSeenBatch(batch.DeviceID, batch.BatchID) {
		return 0, nil
	}

	// Group incoming buckets by calendar date.
	type dateGroup struct{ buckets []Bucket }
	byDate := make(map[string]*dateGroup)
	for i := range batch.Buckets {
		b := batch.Buckets[i]
		date := dateFromISO8601(b.Start)
		if !isValidDate(date) {
			return 0, fmt.Errorf("invalid bucket date")
		}
		b.ReceivedAt = now
		if byDate[date] == nil {
			byDate[date] = &dateGroup{}
		}
		byDate[date].buckets = append(byDate[date].buckets, b)
	}

	total := 0
	for date, g := range byDate {
		newBuckets, err := s.appendDayBuckets(batch.DeviceID, date, g.buckets)
		if err != nil {
			return total, err
		}
		total += len(newBuckets)
		if len(newBuckets) > 0 {
			if err := s.aggregateToDailySummary(batch.DeviceID, date, newBuckets, batch.Source); err != nil {
				log.Printf("uptime: aggregate daily summary %s/%s: %v", batch.DeviceID, date, err)
			}
		}
	}

	if batch.BatchID != "" {
		s.recordSeenBatch(batch.DeviceID, batch.BatchID)
	}
	return total, nil
}

// appendDayBuckets deduplicates buckets against the existing JSONL file for
// (deviceID, date) and appends the new ones. Returns only the newly written
// buckets.
func (s *Store) appendDayBuckets(deviceID, date string, buckets []Bucket) ([]Bucket, error) {
	existingIDs, err := s.loadBucketIDs(deviceID, date)
	if err != nil {
		return nil, err
	}

	var newBuckets []Bucket
	for _, b := range buckets {
		if b.BucketID != "" && existingIDs[b.BucketID] {
			continue // already recorded
		}
		newBuckets = append(newBuckets, b)
		if b.BucketID != "" {
			existingIDs[b.BucketID] = true
		}
	}
	if len(newBuckets) == 0 {
		return nil, nil
	}

	path := s.bucketsPath(deviceID, date)
	baseDir := filepath.Join(s.dataDir, "uptime", "buckets")
	if err := ensureWithinBase(baseDir, path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, b := range newBuckets {
		if err := enc.Encode(b); err != nil {
			return newBuckets, err
		}
	}
	return newBuckets, nil
}

// aggregateToDailySummary reads the existing daily summary (if any), adds the
// contribution of newBuckets, and writes the result atomically.
func (s *Store) aggregateToDailySummary(deviceID, date string, newBuckets []Bucket, source string) error {
	path := s.dailyPath(deviceID, date)
	dir := filepath.Dir(path)

	var sum DailySummary
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &sum)
	}
	if sum.DeviceID == "" {
		sum.DeviceID = deviceID
		sum.Date = date
	}
	if source != "" {
		sum.Source = source
	}
	for _, b := range newBuckets {
		sum.SecondsOn += b.SecondsOn
		sum.SampleCount++
	}
	sum.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return atomicWriteJSON(dir, path, sum)
}

// UpsertDailySummary stores or replaces a DailySummary directly (the "daily
// summary" POST shape). If summary_id matches the one already stored for that
// device+date it is a no-op (idempotent).
func (s *Store) UpsertDailySummary(sum DailySummary) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sum.DeviceID == "" {
		return fmt.Errorf("device_id is required")
	}
	if !isValidDate(sum.Date) {
		return fmt.Errorf("date must be a valid YYYY-MM-DD string, got %q", sum.Date)
	}

	path := s.dailyPath(sum.DeviceID, sum.Date)
	if err := ensureWithinBase(filepath.Join(s.dataDir, "uptime", "daily"), path); err != nil {
		return err
	}
	dir := filepath.Dir(path)

	// summary_id deduplication: no-op if same ID already stored.
	if sum.SummaryID != "" {
		if data, err := os.ReadFile(path); err == nil {
			var existing DailySummary
			if json.Unmarshal(data, &existing) == nil && existing.SummaryID == sum.SummaryID {
				return nil
			}
		}
	}

	if sum.UpdatedAt == "" {
		sum.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	return atomicWriteJSON(dir, path, sum)
}

// GetDailySummaries returns all stored daily summaries for deviceID whose date
// falls within [from, to] (both inclusive, YYYY-MM-DD strings). An empty
// string means unbounded on that side. The slice is nil when no data exists.
func (s *Store) GetDailySummaries(deviceID, from, to string) ([]DailySummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate date bounds when provided.
	if from != "" && !isValidDate(from) {
		return nil, fmt.Errorf("from must be a valid YYYY-MM-DD string, got %q", from)
	}
	if to != "" && !isValidDate(to) {
		return nil, fmt.Errorf("to must be a valid YYYY-MM-DD string, got %q", to)
	}

	dir := filepath.Join(s.dataDir, "uptime", "daily", sanitizeID(deviceID))
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var results []DailySummary
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		date := strings.TrimSuffix(e.Name(), ".json")
		// Only process files with valid date names to guard against stray files.
		if !isValidDate(date) {
			continue
		}
		if from != "" && date < from {
			continue
		}
		if to != "" && date > to {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			log.Printf("uptime: read daily summary %s: %v", e.Name(), err)
			continue
		}
		var sum DailySummary
		if err := json.Unmarshal(data, &sum); err != nil {
			log.Printf("uptime: parse daily summary %s: %v", e.Name(), err)
			continue
		}
		results = append(results, sum)
	}
	return results, nil
}

// loadBucketIDs reads the bucket JSONL file for (deviceID, date) and returns
// the set of bucket_ids already stored there.
func (s *Store) loadBucketIDs(deviceID, date string) (map[string]bool, error) {
	// Defense-in-depth at the sink: refuse unexpected date path components.
	if !isValidDate(date) {
		return make(map[string]bool), nil
	}
	path := s.bucketsPath(deviceID, date)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return make(map[string]bool), nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var b Bucket
		if err := json.Unmarshal(scanner.Bytes(), &b); err == nil && b.BucketID != "" {
			seen[b.BucketID] = true
		}
	}
	return seen, scanner.Err()
}

// hasSeenBatch reports whether batchID appears in the device's seen-batches file.
func (s *Store) hasSeenBatch(deviceID, batchID string) bool {
	f, err := os.Open(s.seenBatchesPath(deviceID))
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if scanner.Text() == batchID {
			return true
		}
	}
	return false
}

// recordSeenBatch appends batchID to the device's seen-batches file.
func (s *Store) recordSeenBatch(deviceID, batchID string) {
	path := s.seenBatchesPath(deviceID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("uptime: mkdir seen-batches: %v", err)
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("uptime: open seen-batches for %s: %v", deviceID, err)
		return
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, batchID); err != nil {
		log.Printf("uptime: record batch id for %s: %v", deviceID, err)
	}
}

// atomicWriteJSON marshals v as indented JSON and writes it to path via a
// temporary file in the same directory (rename is atomic on POSIX).
func atomicWriteJSON(dir, path string, v any) error {
	// Validate the directory target before creating it.
	if err := ensureWithinBase(filepath.Dir(path), dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := ensureWithinBase(dir, path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".uptime-tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if removeErr := os.Remove(tmpName); removeErr != nil && !os.IsNotExist(removeErr) {
			log.Printf("uptime: remove temp %s: %v", tmpName, removeErr)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		log.Printf("uptime: chmod %s: %v", tmpName, err)
	}
	return os.Rename(tmpName, path)
}
