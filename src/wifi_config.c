#include <string.h>
#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "wifi_config.h"

// Use the second-to-last flash sector (last sector is used by push_manager for VAPID keys)
#define WIFI_CONFIG_FLASH_OFFSET (PICO_FLASH_SIZE_BYTES - 2 * FLASH_SECTOR_SIZE)
#define WIFI_CONFIG_MAGIC 0x57494649U  // "WIFI"

// AES-128 block size is 16 bytes.  Plaintext: ssid(33) + pass(64) = 97 bytes.
// Round up to next multiple of 16: 7 * 16 = 112 bytes.
#define WIFI_PLAINTEXT_PADDED 112

// AES-128-GCM parameters
#define WIFI_GCM_NONCE_LEN 12
#define WIFI_GCM_TAG_LEN   16

// Flash page layout (must equal FLASH_PAGE_SIZE = 256 bytes):
//   magic(4) + nonce(12) + tag(16) + ciphertext(112) + reserved(112) = 256
#define WIFI_RESERVED_SIZE \
    (FLASH_PAGE_SIZE - 4 - WIFI_GCM_NONCE_LEN - WIFI_GCM_TAG_LEN - WIFI_PLAINTEXT_PADDED)

typedef struct {
	uint32_t magic;
	uint8_t  nonce[WIFI_GCM_NONCE_LEN];
	uint8_t  tag[WIFI_GCM_TAG_LEN];
	uint8_t  ciphertext[WIFI_PLAINTEXT_PADDED];
	uint8_t  reserved[WIFI_RESERVED_SIZE];
} __attribute__((packed)) wifi_flash_page_t;

_Static_assert(sizeof(wifi_flash_page_t) == FLASH_PAGE_SIZE,
               "wifi_flash_page_t must be exactly FLASH_PAGE_SIZE bytes");

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

	const wifi_flash_page_t *stored =
		(const wifi_flash_page_t *)(XIP_BASE + WIFI_CONFIG_FLASH_OFFSET);

	if (stored->magic != WIFI_CONFIG_MAGIC) return false;

	// Derive decryption key
	uint8_t key[16];
	if (!derive_key(key)) return false;

	// Decrypt and authenticate using AES-128-GCM.
	// Additional data (AD) = magic value, binding the tag to this flash layout.
	uint8_t ad[4];
	memcpy(ad, &stored->magic, sizeof(ad));

	uint8_t plaintext[WIFI_PLAINTEXT_PADDED];

	mbedtls_gcm_context gcm;
	mbedtls_gcm_init(&gcm);
	bool ok = (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128) == 0) &&
	          (mbedtls_gcm_auth_decrypt(&gcm, WIFI_PLAINTEXT_PADDED,
	                                     stored->nonce, WIFI_GCM_NONCE_LEN,
	                                     ad, sizeof(ad),
	                                     stored->tag, WIFI_GCM_TAG_LEN,
	                                     stored->ciphertext, plaintext) == 0);
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
	// Ensures uniqueness per-device and per-save.
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

	// Build 256-byte flash page
	uint8_t buf[FLASH_PAGE_SIZE];
	memset(buf, 0xFF, sizeof(buf));

	wifi_flash_page_t *page = (wifi_flash_page_t *)buf;
	page->magic = WIFI_CONFIG_MAGIC;
	memcpy(page->nonce, nonce, sizeof(nonce));
	memcpy(page->tag, tag, sizeof(tag));
	memcpy(page->ciphertext, ciphertext, sizeof(ciphertext));

	// Write to flash (interrupts must be disabled during flash operations)
	uint32_t ints = save_and_disable_interrupts();
	flash_range_erase(WIFI_CONFIG_FLASH_OFFSET, FLASH_SECTOR_SIZE);
	flash_range_program(WIFI_CONFIG_FLASH_OFFSET, buf, FLASH_PAGE_SIZE);
	restore_interrupts(ints);

	// Update cache
	snprintf(s_ssid, sizeof(s_ssid), "%s", ssid);
	snprintf(s_pass, sizeof(s_pass), "%s", password ? password : "");
	s_valid = true;

	printf("wifi_config: credentials saved to flash (AES-128-GCM)\n");
	return true;
}

void wifi_config_clear(void) {
	uint8_t buf[FLASH_PAGE_SIZE];
	memset(buf, 0xFF, sizeof(buf));

	uint32_t ints = save_and_disable_interrupts();
	flash_range_erase(WIFI_CONFIG_FLASH_OFFSET, FLASH_SECTOR_SIZE);
	flash_range_program(WIFI_CONFIG_FLASH_OFFSET, buf, FLASH_PAGE_SIZE);
	restore_interrupts(ints);

	memset(s_ssid, 0, sizeof(s_ssid));
	memset(s_pass, 0, sizeof(s_pass));
	s_valid = false;
	printf("wifi_config: credentials cleared\n");
}

bool wifi_config_is_valid(void) {
	return s_valid;
}

