#ifndef WIFI_CONFIG_H
#define WIFI_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// WiFi credential limits (IEEE 802.11: SSID ≤ 32 bytes, WPA2 passphrase ≤ 63 bytes)
#define WIFI_SSID_MAX_LEN 32
#define WIFI_PASS_MAX_LEN 63

/**
 * Initialize the WiFi config module (resets in-memory state).
 * Call once at startup before any load/save operations.
 */
void wifi_config_init(void);

/**
 * Load WiFi credentials from encrypted flash storage.
 * @param ssid     Output buffer for SSID (at least WIFI_SSID_MAX_LEN+1 bytes)
 * @param ssid_len Size of ssid buffer
 * @param password Output buffer for password (at least WIFI_PASS_MAX_LEN+1 bytes)
 * @param pass_len Size of password buffer
 * @return true if valid credentials were loaded, false otherwise
 */
bool wifi_config_load(char *ssid, size_t ssid_len, char *password, size_t pass_len);

/**
 * Encrypt and save WiFi credentials to flash.
 * Credentials are encrypted with AES-128-CBC using a key derived from
 * the device's unique board ID.
 * @param ssid     WiFi SSID (must not be NULL or empty)
 * @param password WiFi password (may be NULL or empty for open networks)
 * @return true on success, false on error
 */
bool wifi_config_save(const char *ssid, const char *password);

/**
 * Erase stored WiFi credentials from flash.
 */
void wifi_config_clear(void);

/**
 * Check whether valid credentials are currently loaded in memory.
 * @return true if credentials are available
 */
bool wifi_config_is_valid(void);

#endif // WIFI_CONFIG_H
