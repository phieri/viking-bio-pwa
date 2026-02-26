#ifndef WIFI_CONFIG_H
#define WIFI_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// WiFi credential limits (IEEE 802.11: SSID ≤ 32 bytes, WPA2 passphrase ≤ 63 bytes)
#define WIFI_SSID_MAX_LEN 32
#define WIFI_PASS_MAX_LEN 63

// WiFi country code length (2-letter ISO 3166-1 alpha-2)
#define WIFI_COUNTRY_LEN 2

/**
 * Initialize the WiFi config module (resets in-memory state).
 * Call once at startup before any load/save operations.
 */
void wifi_config_init(void);

/**
 * Load WiFi credentials from encrypted storage (LittleFS).
 * @param ssid     Output buffer for SSID (at least WIFI_SSID_MAX_LEN+1 bytes)
 * @param ssid_len Size of ssid buffer
 * @param password Output buffer for password (at least WIFI_PASS_MAX_LEN+1 bytes)
 * @param pass_len Size of password buffer
 * @return true if valid credentials were loaded, false otherwise
 */
bool wifi_config_load(char *ssid, size_t ssid_len, char *password, size_t pass_len);

/**
 * Encrypt and save WiFi credentials to storage (LittleFS).
 * Credentials are encrypted with AES-128-GCM using a key derived from
 * the device's unique board ID.
 * @param ssid     WiFi SSID (must not be NULL or empty)
 * @param password WiFi password (may be NULL or empty for open networks)
 * @return true on success, false on error
 */
bool wifi_config_save(const char *ssid, const char *password);

/**
 * Erase stored WiFi credentials from storage.
 */
void wifi_config_clear(void);

/**
 * Check whether valid credentials are currently loaded in memory.
 * @return true if credentials are available
 */
bool wifi_config_is_valid(void);

/**
 * Load the WiFi country code from storage (LittleFS).
 * @param country  Output buffer (at least 3 bytes for 2-letter code + null)
 * @param len      Size of output buffer
 * @return true if a country code was loaded, false otherwise (defaults to "XX")
 */
bool wifi_config_load_country(char *country, size_t len);

/**
 * Save the WiFi country code to storage (LittleFS).
 * @param country  2-letter ISO 3166-1 country code (e.g. "SE", "US", "GB")
 * @return true on success, false on error
 */
bool wifi_config_save_country(const char *country);

/**
 * Convert a 2-letter country code string to CYW43 country code format.
 * @param country  2-letter country code (e.g. "SE")
 * @return CYW43 country code value for use with cyw43_arch_init_with_country()
 */
uint32_t wifi_config_country_to_cyw43(const char *country);

#endif // WIFI_CONFIG_H
