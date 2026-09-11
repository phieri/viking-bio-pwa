//go:build cgo

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

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
	for _, code := range supportedWiFiRegionCodes {
		seen[code] = true
	}
	for _, code := range want {
		if !seen[code] {
			t.Fatalf("missing supported Wi-Fi region %q", code)
		}
	}
}

func TestNormalizeProvisioningLanguage(t *testing.T) {
	cases := map[string]string{
		"sv_SE.UTF-8": "sv",
		"nb-NO":       "no",
		"nn_NO":       "no",
		"fi_FI":       "fi",
		"da-DK":       "da",
		"is_IS":       "is",
		"en_GB":       "en",
		"":            "",
	}
	for input, want := range cases {
		if got := normalizeProvisioningLanguage(input); got != want {
			t.Fatalf("%q => %q, want %q", input, got, want)
		}
	}
}
