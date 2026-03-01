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

// Proxy server IP address max length (IPv6 max string + null)
#define WIFI_SERVER_IP_MAX_LEN 46

// Default proxy server port
#define WIFI_SERVER_PORT_DEFAULT 9000

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

/**
 * Load the proxy server IP address and port from storage (LittleFS).
 * @param ip      Output buffer for IP string (at least WIFI_SERVER_IP_MAX_LEN+1 bytes)
 * @param ip_len  Size of ip buffer
 * @param port    Output for port number
 * @return true if server config was loaded, false otherwise
 */
bool wifi_config_load_server(char *ip, size_t ip_len, uint16_t *port);

/**
 * Save the proxy server IP address and port to storage (LittleFS).
 * @param ip    Server IP address string
 * @param port  Server TCP port
 * @return true on success, false on error
 */
bool wifi_config_save_server(const char *ip, uint16_t port);

// Webhook auth token max length
#define WIFI_HOOK_TOKEN_MAX_LEN 64

/**
 * Load the webhook auth token from storage (LittleFS).
 * @param token  Output buffer (at least WIFI_HOOK_TOKEN_MAX_LEN+1 bytes)
 * @param len    Size of output buffer
 * @return true if a token was loaded, false otherwise
 */
bool wifi_config_load_hook_token(char *token, size_t len);

/**
 * Save the webhook auth token to storage (LittleFS).
 * @param token  Auth token string (max WIFI_HOOK_TOKEN_MAX_LEN chars)
 * @return true on success, false on error
 */
bool wifi_config_save_hook_token(const char *token);

#endif // WIFI_CONFIG_H
