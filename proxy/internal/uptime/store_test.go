package uptime_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/phieri/viking-bio-pwa/proxy/internal/uptime"
)

func newStore(t *testing.T) *uptime.Store {
	t.Helper()
	return uptime.NewStore(t.TempDir())
}

// --- AppendBuckets ----------------------------------------------------------

func TestAppendBuckets_BasicWrite(t *testing.T) {
	s := newStore(t)
	batch := uptime.BucketBatch{
		DeviceID: "pico-1",
		Source:   "pico",
		Buckets: []uptime.Bucket{
			{Start: "2024-01-15T10:00:00Z", DurationSeconds: 300, SecondsOn: 200, BucketID: "b1"},
			{Start: "2024-01-15T10:05:00Z", DurationSeconds: 300, SecondsOn: 150, BucketID: "b2"},
		},
	}
	n, err := s.AppendBuckets(batch)
	if err != nil {
		t.Fatalf("AppendBuckets: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 buckets written, got %d", n)
	}
}

func TestAppendBuckets_RequiresDeviceID(t *testing.T) {
	s := newStore(t)
	_, err := s.AppendBuckets(uptime.BucketBatch{
		Buckets: []uptime.Bucket{
			{Start: "2024-01-15T10:00:00Z", DurationSeconds: 60, SecondsOn: 30},
		},
	})
	if err == nil {
		t.Fatal("expected error for empty device_id")
	}
}

func TestAppendBuckets_BucketIDDedup(t *testing.T) {
	s := newStore(t)
	batch := uptime.BucketBatch{
		DeviceID: "pico-1",
		Source:   "pico",
		Buckets: []uptime.Bucket{
			{Start: "2024-01-15T10:00:00Z", DurationSeconds: 300, SecondsOn: 200, BucketID: "dup"},
		},
	}
	n, err := s.AppendBuckets(batch)
	if err != nil || n != 1 {
		t.Fatalf("first write: n=%d err=%v", n, err)
	}
	// Send same bucket again.
	n, err = s.AppendBuckets(batch)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 new buckets on duplicate, got %d", n)
	}
}

func TestAppendBuckets_BatchIDDedup(t *testing.T) {
	s := newStore(t)
	batch := uptime.BucketBatch{
		DeviceID: "pico-1",
		BatchID:  "batch-42",
		Source:   "pico",
		Buckets: []uptime.Bucket{
			{Start: "2024-01-15T10:00:00Z", DurationSeconds: 300, SecondsOn: 200},
		},
	}
	n, err := s.AppendBuckets(batch)
	if err != nil || n != 1 {
		t.Fatalf("first batch: n=%d err=%v", n, err)
	}
	n, err = s.AppendBuckets(batch)
	if err != nil {
		t.Fatalf("second batch: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 on duplicate batch_id, got %d", n)
	}
}

func TestAppendBuckets_NoBucketIDNeverDedup(t *testing.T) {
	s := newStore(t)
	batch := uptime.BucketBatch{
		DeviceID: "pico-1",
		Source:   "pico",
		Buckets: []uptime.Bucket{
			// No BucketID → always appended (client is responsible for dedup via batch_id)
			{Start: "2024-01-15T10:00:00Z", DurationSeconds: 300, SecondsOn: 100},
		},
	}
	n1, _ := s.AppendBuckets(batch)
	n2, _ := s.AppendBuckets(batch)
	if n1 != 1 || n2 != 1 {
		t.Fatalf("expected 1 each time without BucketID, got %d, %d", n1, n2)
	}
}

func TestAppendBuckets_UpdatesDailySummary(t *testing.T) {
	dir := t.TempDir()
	s := uptime.NewStore(dir)

	batch := uptime.BucketBatch{
		DeviceID: "pico-1",
		Source:   "pico",
		Buckets: []uptime.Bucket{
			{Start: "2024-03-20T08:00:00Z", DurationSeconds: 3600, SecondsOn: 3000, BucketID: "x1"},
			{Start: "2024-03-20T09:00:00Z", DurationSeconds: 3600, SecondsOn: 2400, BucketID: "x2"},
		},
	}
	if _, err := s.AppendBuckets(batch); err != nil {
		t.Fatal(err)
	}

	summaries, err := s.GetDailySummaries("pico-1", "2024-03-20", "2024-03-20")
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 daily summary, got %d", len(summaries))
	}
	if summaries[0].SecondsOn != 5400 {
		t.Errorf("expected seconds_on=5400, got %d", summaries[0].SecondsOn)
	}
	if summaries[0].SampleCount != 2 {
		t.Errorf("expected sample_count=2, got %d", summaries[0].SampleCount)
	}
}

func TestAppendBuckets_AccumulatesAcrossRequests(t *testing.T) {
	s := newStore(t)
	b1 := uptime.BucketBatch{
		DeviceID: "pico-2",
		BatchID:  "b1",
		Source:   "pico",
		Buckets:  []uptime.Bucket{{Start: "2024-04-01T00:00:00Z", DurationSeconds: 600, SecondsOn: 500, BucketID: "a"}},
	}
	b2 := uptime.BucketBatch{
		DeviceID: "pico-2",
		BatchID:  "b2",
		Source:   "pico",
		Buckets:  []uptime.Bucket{{Start: "2024-04-01T00:10:00Z", DurationSeconds: 600, SecondsOn: 300, BucketID: "c"}},
	}
	if _, err := s.AppendBuckets(b1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendBuckets(b2); err != nil {
		t.Fatal(err)
	}
	sums, _ := s.GetDailySummaries("pico-2", "", "")
	if len(sums) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(sums))
	}
	if sums[0].SecondsOn != 800 {
		t.Errorf("expected cumulative seconds_on=800, got %d", sums[0].SecondsOn)
	}
}

func TestAppendBuckets_JSONLFileExists(t *testing.T) {
	dir := t.TempDir()
	s := uptime.NewStore(dir)
	batch := uptime.BucketBatch{
		DeviceID: "dev",
		Source:   "pico",
		Buckets: []uptime.Bucket{
			{Start: "2024-05-10T12:00:00Z", DurationSeconds: 60, SecondsOn: 40, BucketID: "j1"},
		},
	}
	if _, err := s.AppendBuckets(batch); err != nil {
		t.Fatal(err)
	}
	// JSONL file should exist and contain valid JSON on first line.
	jsonlPath := filepath.Join(dir, "uptime", "buckets", "dev", "2024-05-10.jsonl")
	data, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("JSONL file not found: %v", err)
	}
	var b uptime.Bucket
	if err := json.Unmarshal(data[:len(data)-1], &b); err != nil {
		t.Fatalf("JSONL line is not valid JSON: %v", err)
	}
	if b.BucketID != "j1" {
		t.Errorf("expected BucketID=j1, got %q", b.BucketID)
	}
}

// --- UpsertDailySummary -----------------------------------------------------

func TestUpsertDailySummary_Basic(t *testing.T) {
	s := newStore(t)
	sum := uptime.DailySummary{
		DeviceID:    "pwa-client",
		Date:        "2024-06-01",
		SecondsOn:   7200,
		SampleCount: 12,
		Source:      "pwa",
		SummaryID:   "sum-1",
	}
	if err := s.UpsertDailySummary(sum); err != nil {
		t.Fatalf("UpsertDailySummary: %v", err)
	}
	results, err := s.GetDailySummaries("pwa-client", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(results))
	}
	if results[0].SecondsOn != 7200 {
		t.Errorf("expected seconds_on=7200, got %d", results[0].SecondsOn)
	}
}

func TestUpsertDailySummary_SummaryIDDedup(t *testing.T) {
	s := newStore(t)
	sum := uptime.DailySummary{
		DeviceID:  "d1",
		Date:      "2024-07-01",
		SecondsOn: 3600,
		SummaryID: "s-dedup",
	}
	if err := s.UpsertDailySummary(sum); err != nil {
		t.Fatal(err)
	}
	// Second upsert with same summary_id but different seconds_on.
	sum.SecondsOn = 9999
	if err := s.UpsertDailySummary(sum); err != nil {
		t.Fatal(err)
	}
	results, _ := s.GetDailySummaries("d1", "", "")
	if results[0].SecondsOn != 3600 {
		t.Errorf("dedup failed: seconds_on changed to %d", results[0].SecondsOn)
	}
}

func TestUpsertDailySummary_RequiresDeviceID(t *testing.T) {
	s := newStore(t)
	err := s.UpsertDailySummary(uptime.DailySummary{Date: "2024-01-01", SecondsOn: 100})
	if err == nil {
		t.Fatal("expected error for missing device_id")
	}
}

func TestUpsertDailySummary_RequiresDate(t *testing.T) {
	s := newStore(t)
	err := s.UpsertDailySummary(uptime.DailySummary{DeviceID: "d1", SecondsOn: 100})
	if err == nil {
		t.Fatal("expected error for missing date")
	}
}

func TestUpsertDailySummary_RejectsInvalidDate(t *testing.T) {
	s := newStore(t)
	// Path-traversal attempt
	err := s.UpsertDailySummary(uptime.DailySummary{DeviceID: "d1", Date: "../../../../etc", SecondsOn: 100})
	if err == nil {
		t.Fatal("expected error for invalid date")
	}
	// Wrong format
	err = s.UpsertDailySummary(uptime.DailySummary{DeviceID: "d1", Date: "2024/01/01", SecondsOn: 100})
	if err == nil {
		t.Fatal("expected error for slash-separated date")
	}
}

// --- GetDailySummaries -------------------------------------------------------

func TestGetDailySummaries_EmptyWhenNoData(t *testing.T) {
	s := newStore(t)
	results, err := s.GetDailySummaries("nobody", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatalf("expected nil slice for missing device, got %v", results)
	}
}

func TestGetDailySummaries_RejectsInvalidDateBounds(t *testing.T) {
	s := newStore(t)
	_, err := s.GetDailySummaries("d", "not-a-date", "")
	if err == nil {
		t.Fatal("expected error for invalid from date")
	}
	_, err = s.GetDailySummaries("d", "", "2024/99/99")
	if err == nil {
		t.Fatal("expected error for invalid to date")
	}
}

func TestGetDailySummaries_DateRangeFilter(t *testing.T) {
	s := newStore(t)
	for _, date := range []string{"2024-01-01", "2024-01-15", "2024-01-31"} {
		_ = s.UpsertDailySummary(uptime.DailySummary{
			DeviceID:  "d",
			Date:      date,
			SecondsOn: 100,
		})
	}
	// from + to
	results, _ := s.GetDailySummaries("d", "2024-01-10", "2024-01-20")
	if len(results) != 1 || results[0].Date != "2024-01-15" {
		t.Errorf("range filter failed: %+v", results)
	}
	// only from
	results, _ = s.GetDailySummaries("d", "2024-01-15", "")
	if len(results) != 2 {
		t.Errorf("from-only filter failed: got %d", len(results))
	}
	// only to
	results, _ = s.GetDailySummaries("d", "", "2024-01-15")
	if len(results) != 2 {
		t.Errorf("to-only filter failed: got %d", len(results))
	}
}

// --- sanitizeID (via device_id usage) ----------------------------------------

func TestSanitizeID_SpecialCharsReplaced(t *testing.T) {
	dir := t.TempDir()
	s := uptime.NewStore(dir)
	// A device_id with slashes and spaces should not create extra path segments.
	sum := uptime.DailySummary{
		DeviceID:  "device/with spaces",
		Date:      "2024-08-01",
		SecondsOn: 42,
	}
	if err := s.UpsertDailySummary(sum); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results, _ := s.GetDailySummaries("device/with spaces", "", "")
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}
