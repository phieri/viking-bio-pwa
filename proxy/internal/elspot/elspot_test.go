package elspot

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCurrentHourSEKPerKWh_HappyPath(t *testing.T) {
	t.Parallel()

	// 2026-06-11T14:00:00+02:00 → hour 14 local
	now, _ := time.Parse(time.RFC3339, "2026-06-11T14:30:00+02:00")
	entries := []hourlyPrice{
		{Date: "2026-06-11T13:00:00+02:00", SEKPerKWh: 0.50},
		{Date: "2026-06-11T14:00:00+02:00", SEKPerKWh: 0.65},
		{Date: "2026-06-11T15:00:00+02:00", SEKPerKWh: 0.70},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer srv.Close()

	f := &Fetcher{httpGet: func(_ string) (*http.Response, error) {
		return http.Get(srv.URL + "/prices.json")
	}}

	got, err := f.CurrentHourSEKPerKWh("SE3", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 0.65 {
		t.Errorf("expected 0.65, got %v", got)
	}
}

func TestCurrentHourSEKPerKWh_CachesResult(t *testing.T) {
	t.Parallel()

	now, _ := time.Parse(time.RFC3339, "2026-06-11T10:00:00+02:00")
	entries := []hourlyPrice{
		{Date: "2026-06-11T10:00:00+02:00", SEKPerKWh: 0.42},
	}

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer srv.Close()

	f := &Fetcher{httpGet: func(url string) (*http.Response, error) {
		return http.Get(srv.URL + "/prices.json")
	}}

	for i := 0; i < 3; i++ {
		if _, err := f.CurrentHourSEKPerKWh("SE3", now); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if callCount != 1 {
		t.Errorf("expected 1 HTTP call due to caching, got %d", callCount)
	}
}

func TestCurrentHourSEKPerKWh_RefetchesOnDateChange(t *testing.T) {
	t.Parallel()

	day1, _ := time.Parse(time.RFC3339, "2026-06-11T10:00:00+02:00")
	day2, _ := time.Parse(time.RFC3339, "2026-06-12T10:00:00+02:00")

	makeEntries := func(day string) []hourlyPrice {
		return []hourlyPrice{{Date: day + "T10:00:00+02:00", SEKPerKWh: 0.99}}
	}

	callCount := 0
	f := &Fetcher{httpGet: func(url string) (*http.Response, error) {
		callCount++
		var entries []hourlyPrice
		if callCount == 1 {
			entries = makeEntries("2026-06-11")
		} else {
			entries = makeEntries("2026-06-12")
		}
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rec).Encode(entries)
		return rec.Result(), nil
	}}

	if _, err := f.CurrentHourSEKPerKWh("SE3", day1); err != nil {
		t.Fatalf("day1: %v", err)
	}
	if _, err := f.CurrentHourSEKPerKWh("SE3", day2); err != nil {
		t.Fatalf("day2: %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 fetches (one per day), got %d", callCount)
	}
}

func TestCurrentHourSEKPerKWh_MissingHour(t *testing.T) {
	t.Parallel()

	now, _ := time.Parse(time.RFC3339, "2026-06-11T23:00:00+02:00")
	// Only hour 10 in response
	entries := []hourlyPrice{{Date: "2026-06-11T10:00:00+02:00", SEKPerKWh: 0.30}}

	f := &Fetcher{httpGet: func(url string) (*http.Response, error) {
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rec).Encode(entries)
		return rec.Result(), nil
	}}

	if _, err := f.CurrentHourSEKPerKWh("SE3", now); err == nil {
		t.Fatal("expected error for missing hour, got nil")
	}
}

func TestCurrentHourSEKPerKWh_ServerError(t *testing.T) {
	t.Parallel()

	now, _ := time.Parse(time.RFC3339, "2026-06-11T10:00:00+02:00")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	f := &Fetcher{httpGet: func(url string) (*http.Response, error) {
		return http.Get(srv.URL)
	}}

	if _, err := f.CurrentHourSEKPerKWh("SE3", now); err == nil {
		t.Fatal("expected error for non-200 response, got nil")
	}
}
