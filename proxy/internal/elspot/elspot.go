// Package elspot fetches hourly spot electricity prices from elprisetjustnu.se.
package elspot

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const baseURL = "https://www.elprisetjustnu.se/api/v1/prices"

// hourlyPrice is one entry in the elprisetjustnu API response.
type hourlyPrice struct {
	Date      string  `json:"time_start"`
	SEKPerKWh float64 `json:"SEK_per_kWh"`
}

// cached holds a fetched day's prices plus metadata for cache invalidation.
type cached struct {
	date      string // date key in "YYYY/MM-DD" format (e.g. "2026/06-11") matching the API URL path
	region    string
	prices    []hourlyPrice
	fetchedAt time.Time
}

// Fetcher fetches and caches spot electricity prices.
// It keeps the prices for the current calendar day in memory and re-fetches
// when the date or region changes. A zero-value Fetcher is ready to use.
type Fetcher struct {
	mu      sync.Mutex
	cache   *cached
	httpGet func(url string) (*http.Response, error)
}

// NewFetcher creates a Fetcher using the default HTTP client.
func NewFetcher() *Fetcher {
	return &Fetcher{httpGet: http.Get}
}

// CurrentHourSEKPerKWh returns the spot price in SEK/kWh for the current
// clock hour in the given price region (e.g. "SE3"). Results are cached for
// the duration of the current calendar day; a fresh fetch is made whenever
// the date or region changes.
func (f *Fetcher) CurrentHourSEKPerKWh(region string, now time.Time) (float64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	date := now.Format("2006/01-02")
	if f.cache == nil || f.cache.date != date || f.cache.region != region {
		prices, err := f.fetchDay(date, region)
		if err != nil {
			return 0, err
		}
		f.cache = &cached{date: date, region: region, prices: prices, fetchedAt: now}
	}

	return priceForHour(f.cache.prices, now)
}

// fetchDay fetches all hourly prices for the given date and region.
func (f *Fetcher) fetchDay(date, region string) ([]hourlyPrice, error) {
	url := fmt.Sprintf("%s/%s_%s.json", baseURL, date, region)
	resp, err := f.httpGet(url)
	if err != nil {
		return nil, fmt.Errorf("elspot: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("elspot: unexpected status %d for %s", resp.StatusCode, url)
	}
	var prices []hourlyPrice
	if err := json.NewDecoder(resp.Body).Decode(&prices); err != nil {
		return nil, fmt.Errorf("elspot: decode response: %w", err)
	}
	if len(prices) == 0 {
		return nil, fmt.Errorf("elspot: empty price list for %s %s", date, region)
	}
	return prices, nil
}

// priceForHour returns the SEK/kWh price for the current clock hour from a
// slice of hourly prices. The API returns entries with time_start in ISO 8601
// format; we match by comparing the hour in the same timezone as now.
func priceForHour(prices []hourlyPrice, now time.Time) (float64, error) {
	targetHour := now.Hour()
	loc := now.Location()
	for _, p := range prices {
		t, err := time.Parse(time.RFC3339, p.Date)
		if err != nil {
			continue
		}
		if t.In(loc).Hour() == targetHour {
			return p.SEKPerKWh, nil
		}
	}
	return 0, fmt.Errorf("elspot: no price entry found for hour %d", targetHour)
}
