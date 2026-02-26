#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "wifi_config.h"
#include "lfs_hal.h"

// LittleFS file paths
#define WIFI_CONFIG_FILE   "/wifi.dat"
#define WIFI_COUNTRY_FILE  "/country.dat"

#define WIFI_CONFIG_MAGIC 0x57494649U  // "WIFI"

// AES-128 block size is 16 bytes.  Plaintext: ssid(33) + pass(64) = 97 bytes.
// Round up to next multiple of 16: 7 * 16 = 112 bytes.
#define WIFI_PLAINTEXT_PADDED 112

// AES-128-GCM parameters
#define WIFI_GCM_NONCE_LEN 12
#define WIFI_GCM_TAG_LEN   16

// Storage layout:
//   magic(4) + nonce(12) + tag(16) + ciphertext(112) = 144 bytes
#define WIFI_STORED_SIZE (4 + WIFI_GCM_NONCE_LEN + WIFI_GCM_TAG_LEN + WIFI_PLAINTEXT_PADDED)

// In-memory cached credentials
static char s_ssid[WIFI_SSID_MAX_LEN + 1];
static char s_pass[WIFI_PASS_MAX_LEN + 1];
static bool s_valid = false;

// Derive a 16-byte AES-128 key from the device's unique board ID.
// Uses SHA-256(board_id || fixed_salt) and takes the first 16 bytes.
static bool derive_key(uint8_t key[16]) {
	pico_unique_board_id_t uid;
	pico_get_unique_board_id(&uid);

	// 8-byte board ID concatenated with a fixed 16-byte salt
	uint8_t material[PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 16];
	memcpy(material, uid.id, PICO_UNIQUE_BOARD_ID_SIZE_BYTES);
	memcpy(material + PICO_UNIQUE_BOARD_ID_SIZE_BYTES, "VIKINGBIO_WIFIKEY", 16);

	uint8_t hash[32];
	if (mbedtls_sha256(material, sizeof(material), hash, 0) != 0) return false;
	memcpy(key, hash, 16);
	return true;
}

void wifi_config_init(void) {
	memset(s_ssid, 0, sizeof(s_ssid));
	memset(s_pass, 0, sizeof(s_pass));
	s_valid = false;
}

bool wifi_config_load(char *ssid, size_t ssid_len, char *password, size_t pass_len) {
	if (!ssid || !password || ssid_len == 0 || pass_len == 0) return false;

	uint8_t stored[WIFI_STORED_SIZE];
	int n = lfs_hal_read_file(WIFI_CONFIG_FILE, stored, sizeof(stored));
	if (n < (int)sizeof(stored)) return false;

	// Check magic
	uint32_t magic;
	memcpy(&magic, stored, sizeof(magic));
	if (magic != WIFI_CONFIG_MAGIC) return false;

	const uint8_t *nonce      = stored + 4;
	const uint8_t *tag        = stored + 4 + WIFI_GCM_NONCE_LEN;
	const uint8_t *ciphertext = stored + 4 + WIFI_GCM_NONCE_LEN + WIFI_GCM_TAG_LEN;

	// Derive decryption key
	uint8_t key[16];
	if (!derive_key(key)) return false;

	// Decrypt and authenticate using AES-128-GCM.
	// Additional data (AD) = magic value, binding the tag to this layout.
	uint8_t ad[4];
	memcpy(ad, &magic, sizeof(ad));

	uint8_t plaintext[WIFI_PLAINTEXT_PADDED];

	mbedtls_gcm_context gcm;
	mbedtls_gcm_init(&gcm);
	bool ok = (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128) == 0) &&
	          (mbedtls_gcm_auth_decrypt(&gcm, WIFI_PLAINTEXT_PADDED,
	                                     nonce, WIFI_GCM_NONCE_LEN,
	                                     ad, sizeof(ad),
	                                     tag, WIFI_GCM_TAG_LEN,
	                                     ciphertext, plaintext) == 0);
	mbedtls_gcm_free(&gcm);
	if (!ok) return false;

	// Plaintext layout: ssid[WIFI_SSID_MAX_LEN+1] || pass[WIFI_PASS_MAX_LEN+1]
	const char *pt_ssid = (const char *)plaintext;
	const char *pt_pass = (const char *)(plaintext + WIFI_SSID_MAX_LEN + 1);

	// Enforce null-termination within their respective fields
	if (pt_ssid[WIFI_SSID_MAX_LEN] != '\0' || pt_ssid[0] == '\0') return false;
	if (pt_pass[WIFI_PASS_MAX_LEN] != '\0') return false;

	snprintf(ssid, ssid_len, "%.*s", WIFI_SSID_MAX_LEN, pt_ssid);
	snprintf(password, pass_len, "%.*s", WIFI_PASS_MAX_LEN, pt_pass);

	// Update cache
	snprintf(s_ssid, sizeof(s_ssid), "%.*s", WIFI_SSID_MAX_LEN, pt_ssid);
	snprintf(s_pass, sizeof(s_pass), "%.*s", WIFI_PASS_MAX_LEN, pt_pass);
	s_valid = true;
	return true;
}

bool wifi_config_save(const char *ssid, const char *password) {
	if (!ssid || ssid[0] == '\0') return false;
	if (strlen(ssid) > WIFI_SSID_MAX_LEN) return false;
	if (password && strlen(password) > WIFI_PASS_MAX_LEN) return false;

	// Build zero-padded plaintext: ssid[33] || pass[64]
	uint8_t plaintext[WIFI_PLAINTEXT_PADDED];
	memset(plaintext, 0, sizeof(plaintext));
	snprintf((char *)plaintext, WIFI_SSID_MAX_LEN + 1, "%s", ssid);
	if (password) {
		snprintf((char *)(plaintext + WIFI_SSID_MAX_LEN + 1),
		         WIFI_PASS_MAX_LEN + 1, "%s", password);
	}

	// Generate GCM nonce: 8 bytes from timestamp + 4 bytes from board ID
	uint8_t nonce[WIFI_GCM_NONCE_LEN];
	uint64_t t = time_us_64();
	pico_unique_board_id_t uid;
	pico_get_unique_board_id(&uid);
	memcpy(nonce, &t, 8);
	memcpy(nonce + 8, uid.id, 4);

	// Derive encryption key
	uint8_t key[16];
	if (!derive_key(key)) return false;

	// Encrypt + authenticate using AES-128-GCM
	uint8_t ciphertext[WIFI_PLAINTEXT_PADDED];
	uint8_t tag[WIFI_GCM_TAG_LEN];
	uint32_t magic = WIFI_CONFIG_MAGIC;
	uint8_t ad[4];
	memcpy(ad, &magic, sizeof(ad));

	mbedtls_gcm_context gcm;
	mbedtls_gcm_init(&gcm);
	bool ok = (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128) == 0) &&
	          (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, WIFI_PLAINTEXT_PADDED,
	                                      nonce, WIFI_GCM_NONCE_LEN,
	                                      ad, sizeof(ad),
	                                      plaintext, ciphertext,
	                                      WIFI_GCM_TAG_LEN, tag) == 0);
	mbedtls_gcm_free(&gcm);
	if (!ok) return false;

	// Build storage buffer: magic + nonce + tag + ciphertext
	uint8_t stored[WIFI_STORED_SIZE];
	size_t off = 0;
	memcpy(stored + off, &magic, 4);                off += 4;
	memcpy(stored + off, nonce, sizeof(nonce));      off += sizeof(nonce);
	memcpy(stored + off, tag, sizeof(tag));           off += sizeof(tag);
	memcpy(stored + off, ciphertext, sizeof(ciphertext));

	if (!lfs_hal_write_file(WIFI_CONFIG_FILE, stored, sizeof(stored))) {
		printf("wifi_config: ERROR writing to LittleFS\n");
		return false;
	}

	// Update cache
	snprintf(s_ssid, sizeof(s_ssid), "%s", ssid);
	snprintf(s_pass, sizeof(s_pass), "%s", password ? password : "");
	s_valid = true;

	printf("wifi_config: credentials saved (AES-128-GCM, LittleFS)\n");
	return true;
}

void wifi_config_clear(void) {
	lfs_hal_delete_file(WIFI_CONFIG_FILE);

	memset(s_ssid, 0, sizeof(s_ssid));
	memset(s_pass, 0, sizeof(s_pass));
	s_valid = false;
	printf("wifi_config: credentials cleared\n");
}

bool wifi_config_is_valid(void) {
	return s_valid;
}

bool wifi_config_load_country(char *country, size_t len) {
	if (!country || len < 3) return false;

	char buf[WIFI_COUNTRY_LEN];
	int n = lfs_hal_read_file(WIFI_COUNTRY_FILE, buf, sizeof(buf));
	if (n != WIFI_COUNTRY_LEN) return false;

	// Validate: must be two uppercase ASCII letters
	if (!isupper((unsigned char)buf[0]) || !isupper((unsigned char)buf[1])) return false;

	country[0] = buf[0];
	country[1] = buf[1];
	country[2] = '\0';
	return true;
}

bool wifi_config_save_country(const char *country) {
	if (!country || strlen(country) != WIFI_COUNTRY_LEN) return false;
	if (!isupper((unsigned char)country[0]) || !isupper((unsigned char)country[1])) return false;

	if (!lfs_hal_write_file(WIFI_COUNTRY_FILE, country, WIFI_COUNTRY_LEN)) {
		printf("wifi_config: ERROR saving country code\n");
		return false;
	}
	printf("wifi_config: country set to %c%c\n", country[0], country[1]);
	return true;
}

uint32_t wifi_config_country_to_cyw43(const char *country) {
	if (!country || strlen(country) < WIFI_COUNTRY_LEN) {
		// Default: worldwide
		return ((uint32_t)'X') | ((uint32_t)'X' << 8);
	}
	return ((uint32_t)(unsigned char)country[0]) |
	       ((uint32_t)(unsigned char)country[1] << 8);
}
