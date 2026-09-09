/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

//go:build cgo

package provisioning

import "testing"

func TestWifiCountryCodeFromSelection(t *testing.T) {
	cases := map[string]string{
		"Worldwide (XX)":     "XX",
		"Sweden (SE)":        "SE",
		"South Korea (KR)":   "KR",
		"United States (US)": "US",
	}
	for selection, want := range cases {
		if got := wifiCountryCodeFromSelection(selection); got != want {
			t.Fatalf("%q => %q, want %q", selection, got, want)
		}
	}
}

func TestSupportedWiFiRegionsIncludeSDKCodes(t *testing.T) {
	want := []string{"XX", "AU", "AT", "BE", "BR", "CA", "CL", "CN", "CO", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HK", "HU", "IS", "IN", "IL", "IT", "JP", "KE", "LV", "LI", "LT", "LU", "MY", "MT", "MX", "NL", "NZ", "NG", "NO", "PE", "PH", "PL", "PT", "SG", "SK", "SI", "ZA", "KR", "ES", "SE", "CH", "TW", "TH", "TR", "GB", "US"}
	seen := map[string]bool{}
	for _, option := range supportedWiFiRegions {
		seen[wifiCountryCodeFromSelection(option)] = true
	}
	for _, code := range want {
		if !seen[code] {
			t.Fatalf("missing supported Wi-Fi region %q", code)
		}
	}
}
