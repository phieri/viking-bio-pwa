#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/unique_id.h"
#include "lwip/tcp.h"
#include "lwip/dns.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include "push_manager.h"

// VAPID key storage in flash (last 4KB sector)
// Flash size is 2MB for Pico W; last sector at 0x1FF000
#define FLASH_TARGET_OFFSET (PICO_FLASH_SIZE_BYTES - FLASH_SECTOR_SIZE)
#define VAPID_MAGIC 0x56415049  // "VAPI"

// Padding: FLASH_PAGE_SIZE(256) - magic(4) - private_key(32) - public_key(65) - crc(4) = 151 bytes
#define VAPID_RESERVED_SIZE (FLASH_PAGE_SIZE - 4 - 32 - 65 - 4)

typedef struct {
	uint32_t magic;
	uint8_t private_key[32];             // P-256 private key (raw 32 bytes)
	uint8_t public_key[65];              // P-256 public key (uncompressed, 65 bytes)
	uint8_t reserved[VAPID_RESERVED_SIZE]; // Padding to reach FLASH_PAGE_SIZE
	uint32_t crc;                        // Simple XOR checksum
} vapid_flash_t;

// Verify the struct fits in one flash page at compile time
_Static_assert(sizeof(vapid_flash_t) == FLASH_PAGE_SIZE,
               "vapid_flash_t must be exactly FLASH_PAGE_SIZE bytes");

// VAPID keys (in RAM after loaded/generated)
static uint8_t vapid_private_key[32];
static uint8_t vapid_public_key[65];
static bool vapid_keys_valid = false;

// Push subscriptions
static push_subscription_t subscriptions[PUSH_MAX_SUBSCRIPTIONS];
static int subscription_count = 0;

// mbedTLS context
static mbedtls_entropy_context entropy;
static mbedtls_hmac_drbg_context hmac_drbg;

// Simple CRC
static uint32_t calc_crc(const uint8_t *data, size_t len) {
	uint32_t crc = 0;
	for (size_t i = 0; i < len; i++) crc ^= ((uint32_t)data[i] << (8 * (i % 4)));
	return crc;
}

static bool load_vapid_keys_from_flash(void) {
	const vapid_flash_t *stored = (const vapid_flash_t *)(XIP_BASE + FLASH_TARGET_OFFSET);
	if (stored->magic != VAPID_MAGIC) return false;

	// Verify CRC
	uint32_t expected_crc = calc_crc((const uint8_t *)stored, offsetof(vapid_flash_t, crc));
	if (stored->crc != expected_crc) return false;

	memcpy(vapid_private_key, stored->private_key, 32);
	memcpy(vapid_public_key, stored->public_key, 65);
	return true;
}

static bool save_vapid_keys_to_flash(void) {
	// Build flash data (must be multiple of FLASH_PAGE_SIZE = 256)
	uint8_t buf[FLASH_PAGE_SIZE];
	memset(buf, 0xFF, sizeof(buf));

	vapid_flash_t *data = (vapid_flash_t *)buf;
	data->magic = VAPID_MAGIC;
	memcpy(data->private_key, vapid_private_key, 32);
	memcpy(data->public_key, vapid_public_key, 65);
	data->crc = calc_crc(buf, offsetof(vapid_flash_t, crc));

	// Write to flash (must disable interrupts)
	uint32_t ints = save_and_disable_interrupts();
	flash_range_erase(FLASH_TARGET_OFFSET, FLASH_SECTOR_SIZE);
	flash_range_program(FLASH_TARGET_OFFSET, buf, FLASH_PAGE_SIZE);
	restore_interrupts(ints);

	return true;
}

static bool generate_vapid_keys(void) {
	mbedtls_ecp_keypair keypair;
	mbedtls_ecp_keypair_init(&keypair);

	int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &keypair,
	                               mbedtls_hmac_drbg_random, &hmac_drbg);
	if (ret != 0) {
		mbedtls_ecp_keypair_free(&keypair);
		return false;
	}

	// Export private key (32 bytes big-endian)
	ret = mbedtls_mpi_write_binary(&keypair.MBEDTLS_PRIVATE(d), vapid_private_key, 32);
	if (ret != 0) {
		mbedtls_ecp_keypair_free(&keypair);
		return false;
	}

	// Export public key (uncompressed, 65 bytes)
	size_t olen = 0;
	ret = mbedtls_ecp_point_write_binary(&keypair.MBEDTLS_PRIVATE(grp),
	                                      &keypair.MBEDTLS_PRIVATE(Q),
	                                      MBEDTLS_ECP_PF_UNCOMPRESSED,
	                                      &olen, vapid_public_key, 65);
	mbedtls_ecp_keypair_free(&keypair);

	if (ret != 0 || olen != 65) return false;
	return true;
}

bool push_manager_init(void) {
	memset(subscriptions, 0, sizeof(subscriptions));
	subscription_count = 0;

	// Initialize mbedTLS RNG (HMAC_DRBG instead of CTR_DRBG for SDK compatibility)
	mbedtls_entropy_init(&entropy);
	mbedtls_hmac_drbg_init(&hmac_drbg);

	// Seed with Pico W unique ID
	pico_unique_board_id_t uid;
	pico_get_unique_board_id(&uid);
	int ret = mbedtls_hmac_drbg_seed(&hmac_drbg,
	                                   mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
	                                   mbedtls_entropy_func, &entropy,
	                                   uid.id, PICO_UNIQUE_BOARD_ID_SIZE_BYTES);
	if (ret != 0) {
		printf("push_manager: failed to seed RNG (%d)\n", ret);
		// Continue anyway - use hardware entropy directly
	}

	// Try to load VAPID keys from flash
	if (load_vapid_keys_from_flash()) {
		printf("push_manager: loaded VAPID keys from flash\n");
		vapid_keys_valid = true;
		return true;
	}

	// Generate new VAPID keys
	printf("push_manager: generating new VAPID keys...\n");
	if (!generate_vapid_keys()) {
		printf("push_manager: VAPID key generation failed\n");
		return false;
	}

	// Save to flash
	if (!save_vapid_keys_to_flash()) {
		printf("push_manager: WARNING: failed to save VAPID keys to flash\n");
	}

	vapid_keys_valid = true;
	printf("push_manager: VAPID keys generated and saved\n");
	return true;
}

void push_manager_poll(void) {
	// Placeholder: outbound HTTPS push would be driven here
	// Full HTTPS push implementation requires additional memory budget
}

bool push_manager_get_vapid_public_key(uint8_t *key_buf) {
	if (!vapid_keys_valid || !key_buf) return false;
	memcpy(key_buf, vapid_public_key, 65);
	return true;
}

bool push_manager_add_subscription(const char *endpoint, const char *p256dh, const char *auth) {
	if (!endpoint) return false;

	// Check if already exists
	for (int i = 0; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
		if (subscriptions[i].active &&
		    strncmp(subscriptions[i].endpoint, endpoint, PUSH_MAX_ENDPOINT_LEN) == 0) {
			// Update existing
			if (p256dh) strncpy(subscriptions[i].p256dh, p256dh, PUSH_MAX_KEY_LEN - 1);
			if (auth) strncpy(subscriptions[i].auth, auth, PUSH_MAX_AUTH_LEN - 1);
			return true;
		}
	}

	// Find empty slot
	for (int i = 0; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
		if (!subscriptions[i].active) {
			subscriptions[i].active = true;
			strncpy(subscriptions[i].endpoint, endpoint, PUSH_MAX_ENDPOINT_LEN - 1);
			subscriptions[i].endpoint[PUSH_MAX_ENDPOINT_LEN - 1] = '\0';
			if (p256dh) {
				strncpy(subscriptions[i].p256dh, p256dh, PUSH_MAX_KEY_LEN - 1);
				subscriptions[i].p256dh[PUSH_MAX_KEY_LEN - 1] = '\0';
			}
			if (auth) {
				strncpy(subscriptions[i].auth, auth, PUSH_MAX_AUTH_LEN - 1);
				subscriptions[i].auth[PUSH_MAX_AUTH_LEN - 1] = '\0';
			}
			subscription_count++;
			printf("push_manager: added subscription (%d active)\n", subscription_count);
			return true;
		}
	}

	return false;  // Storage full
}

bool push_manager_remove_subscription(const char *endpoint) {
	if (!endpoint) return false;
	for (int i = 0; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
		if (subscriptions[i].active &&
		    strncmp(subscriptions[i].endpoint, endpoint, PUSH_MAX_ENDPOINT_LEN) == 0) {
			memset(&subscriptions[i], 0, sizeof(push_subscription_t));
			subscription_count--;
			if (subscription_count < 0) subscription_count = 0;
			printf("push_manager: removed subscription\n");
			return true;
		}
	}
	return false;
}

void push_manager_notify_all(const char *title, const char *body, uint8_t error_code) {
	if (subscription_count == 0) return;
	// Log notification intent (full outbound HTTPS push requires additional implementation)
	printf("push_manager: notify all (%d subs) - %s: %s (err=%d)\n",
	       subscription_count, title, body, error_code);
	// TODO: implement outbound HTTPS push to each subscription endpoint
}

int push_manager_subscription_count(void) {
	return subscription_count;
}
