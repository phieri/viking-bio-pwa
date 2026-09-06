package configure

import "strings"

func normaliseConfiguredValue(value string) string {
	value = strings.TrimSpace(value)
	switch strings.ToLower(value) {
	case "(set)", "set", "configured":
		return "configured"
	case "not set", "not configured":
		return "not set"
	default:
		return value
	}
}

func maskSensitiveConfiguredValue(value string) string {
	value = normaliseConfiguredValue(value)
	if value == "" || value == "configured" || value == "not set" {
		return value
	}
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}
	return strings.Repeat("*", len(value)-4) + value[len(value)-4:]
}
