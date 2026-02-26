#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "pico/stdlib.h"
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
#include "lfs_hal.h"

// VAPID key storage in LittleFS
#define VAPID_FILE   "/vapid.dat"
#define VAPID_MAGIC  0x56415049  // "VAPI"

// Storage layout: magic(4) + private_key(32) + public_key(65) + crc(4) = 105 bytes
#define VAPID_STORED_SIZE (4 + 32 + 65 + 4)

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

static bool load_vapid_keys(void) {
	uint8_t buf[VAPID_STORED_SIZE];
	int n = lfs_hal_read_file(VAPID_FILE, buf, sizeof(buf));
	if (n < (int)sizeof(buf)) return false;

	// Check magic
	uint32_t magic;
	memcpy(&magic, buf, sizeof(magic));
	if (magic != VAPID_MAGIC) return false;

	// Verify CRC (covers magic + private + public = 101 bytes)
	uint32_t stored_crc;
	memcpy(&stored_crc, buf + 4 + 32 + 65, sizeof(stored_crc));
	uint32_t expected_crc = calc_crc(buf, 4 + 32 + 65);
	if (stored_crc != expected_crc) return false;

	memcpy(vapid_private_key, buf + 4, 32);
	memcpy(vapid_public_key, buf + 4 + 32, 65);
	return true;
}

static bool save_vapid_keys(void) {
	uint8_t buf[VAPID_STORED_SIZE];
	uint32_t magic = VAPID_MAGIC;

	memcpy(buf, &magic, 4);
	memcpy(buf + 4, vapid_private_key, 32);
	memcpy(buf + 4 + 32, vapid_public_key, 65);

	uint32_t crc = calc_crc(buf, 4 + 32 + 65);
	memcpy(buf + 4 + 32 + 65, &crc, 4);

	return lfs_hal_write_file(VAPID_FILE, buf, sizeof(buf));
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

	// Try to load VAPID keys from LittleFS
	if (load_vapid_keys()) {
		printf("push_manager: loaded VAPID keys from storage\n");
		vapid_keys_valid = true;
		return true;
	}

	// Generate new VAPID keys
	printf("push_manager: generating new VAPID keys...\n");
	if (!generate_vapid_keys()) {
		printf("push_manager: VAPID key generation failed\n");
		return false;
	}

	// Save to LittleFS
	if (!save_vapid_keys()) {
		printf("push_manager: WARNING: failed to save VAPID keys\n");
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
