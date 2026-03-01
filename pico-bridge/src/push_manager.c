#include <string.h>
#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"
#include "push_manager.h"
#include "lfs_hal.h"

// LittleFS file for VAPID key pair
#define VAPID_FILE "/vapid.dat"

// Storage layout: magic(4) + private_key(32) + public_key(65) + crc32(4) = 105 bytes
#define VAPID_MAGIC   0x56415049U  // "VAPI"
#define VAPID_PRIVLEN 32
#define VAPID_PUBLEN  65
#define VAPID_STORED  (4 + VAPID_PRIVLEN + VAPID_PUBLEN + 4)

// In-memory key pair
static uint8_t s_private_key[VAPID_PRIVLEN];
static uint8_t s_public_key[VAPID_PUBLEN];   // Uncompressed P-256 point (0x04 || X || Y)
static bool    s_keys_valid = false;

// In-RAM subscriptions
static push_subscription_t s_subs[PUSH_MAX_SUBSCRIPTIONS];

// ---------------------------------------------------------------------------
// CRC-32 (ISO 3309) helper
// ---------------------------------------------------------------------------

static uint32_t crc32(const uint8_t *data, size_t len) {
	uint32_t crc = 0xFFFFFFFFU;
	for (size_t i = 0; i < len; i++) {
		crc ^= data[i];
		for (int j = 0; j < 8; j++)
			crc = (crc >> 1) ^ (0xEDB88320U & -(crc & 1));
	}
	return ~crc;
}

// ---------------------------------------------------------------------------
// VAPID key persistence
// ---------------------------------------------------------------------------

static bool load_vapid_keys(void) {
	uint8_t buf[VAPID_STORED];
	int n = lfs_hal_read_file(VAPID_FILE, buf, sizeof(buf));
	if (n != (int)sizeof(buf)) return false;

	uint32_t magic;
	memcpy(&magic, buf, 4);
	if (magic != VAPID_MAGIC) return false;

	uint32_t stored_crc;
	memcpy(&stored_crc, buf + 4 + VAPID_PRIVLEN + VAPID_PUBLEN, 4);
	uint32_t computed_crc = crc32(buf, 4 + VAPID_PRIVLEN + VAPID_PUBLEN);
	if (stored_crc != computed_crc) return false;

	memcpy(s_private_key, buf + 4, VAPID_PRIVLEN);
	memcpy(s_public_key,  buf + 4 + VAPID_PRIVLEN, VAPID_PUBLEN);
	return true;
}

static bool save_vapid_keys(void) {
	uint8_t buf[VAPID_STORED];
	uint32_t magic = VAPID_MAGIC;
	memcpy(buf, &magic, 4);
	memcpy(buf + 4, s_private_key, VAPID_PRIVLEN);
	memcpy(buf + 4 + VAPID_PRIVLEN, s_public_key, VAPID_PUBLEN);
	uint32_t crc = crc32(buf, 4 + VAPID_PRIVLEN + VAPID_PUBLEN);
	memcpy(buf + 4 + VAPID_PRIVLEN + VAPID_PUBLEN, &crc, 4);
	return lfs_hal_write_file(VAPID_FILE, buf, sizeof(buf));
}

// ---------------------------------------------------------------------------
// VAPID key generation
// ---------------------------------------------------------------------------

static bool generate_vapid_keys(void) {
	int ret;
	mbedtls_ecp_group  grp;
	mbedtls_mpi        d;      // private key
	mbedtls_ecp_point  Q;      // public key
	mbedtls_entropy_context    entropy;
	mbedtls_ctr_drbg_context   ctr_drbg;

	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_ecp_point_init(&Q);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	// Seed using the board's unique ID as personalisation string
	pico_unique_board_id_t uid;
	pico_get_unique_board_id(&uid);

	bool ok = false;
	do {
		ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		                             uid.id, sizeof(uid.id));
		if (ret != 0) { printf("push_manager: ctr_drbg_seed failed (%d)\n", ret); break; }

		ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
		if (ret != 0) { printf("push_manager: ecp_group_load failed (%d)\n", ret); break; }

		ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q,
		                              mbedtls_ctr_drbg_random, &ctr_drbg);
		if (ret != 0) { printf("push_manager: ecp_gen_keypair failed (%d)\n", ret); break; }

		// Export private key as big-endian 32 bytes
		ret = mbedtls_mpi_write_binary(&d, s_private_key, VAPID_PRIVLEN);
		if (ret != 0) { printf("push_manager: mpi_write_binary failed (%d)\n", ret); break; }

		// Export public key as uncompressed point: 0x04 || X(32) || Y(32)
		size_t olen = 0;
		ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
		                                     &olen, s_public_key, VAPID_PUBLEN);
		if (ret != 0 || olen != VAPID_PUBLEN) {
			printf("push_manager: ecp_point_write_binary failed (%d)\n", ret);
			break;
		}

		ok = true;
	} while (0);

	mbedtls_ecp_group_free(&grp);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_point_free(&Q);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	return ok;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool push_manager_init(void) {
	memset(s_subs, 0, sizeof(s_subs));

	if (load_vapid_keys()) {
		printf("push_manager: loaded VAPID keys from flash\n");
		s_keys_valid = true;
		return true;
	}

	printf("push_manager: generating new VAPID key pair (P-256)...\n");
	if (!generate_vapid_keys()) return false;

	if (!save_vapid_keys()) {
		printf("push_manager: WARNING – could not persist VAPID keys\n");
	}

	s_keys_valid = true;
	printf("push_manager: VAPID keys generated and stored\n");
	return true;
}

bool push_manager_get_vapid_public_key(char *out_buf, size_t buf_len) {
	if (!s_keys_valid || !out_buf || buf_len == 0) return false;

	size_t olen = 0;
	// Base64url-encode the uncompressed public key point
	int ret = mbedtls_base64_encode((unsigned char *)out_buf, buf_len, &olen,
	                                 s_public_key, VAPID_PUBLEN);
	if (ret != 0) return false;
	out_buf[olen] = '\0';

	// Convert base64 to base64url ('+' → '-', '/' → '_', remove '=')
	size_t write = 0;
	for (size_t i = 0; i < olen; i++) {
		char c = out_buf[i];
		if      (c == '+') out_buf[write++] = '-';
		else if (c == '/') out_buf[write++] = '_';
		else if (c == '=') continue;  // strip padding
		else                out_buf[write++] = c;
	}
	out_buf[write] = '\0';
	return true;
}

bool push_manager_add_subscription(const char *endpoint, const char *p256dh,
                                   const char *auth, const bool prefs[PUSH_NOTIFY_TYPE_COUNT]) {
	if (!endpoint || endpoint[0] == '\0') return false;

	// Update existing
	for (int i = 0; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
		if (s_subs[i].active &&
		    strncmp(s_subs[i].endpoint, endpoint, PUSH_ENDPOINT_MAX_LEN) == 0) {
			if (p256dh) snprintf(s_subs[i].p256dh, sizeof(s_subs[i].p256dh), "%s", p256dh);
			if (auth)   snprintf(s_subs[i].auth,   sizeof(s_subs[i].auth),   "%s", auth);
			if (prefs) {
				for (int t = 0; t < PUSH_NOTIFY_TYPE_COUNT; t++)
					s_subs[i].prefs[t] = prefs[t];
			}
			printf("push_manager: updated subscription (total: %d)\n",
			       push_manager_subscription_count());
			return true;
		}
	}

	// Add new
	for (int i = 0; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
		if (!s_subs[i].active) {
			s_subs[i].active = true;
			snprintf(s_subs[i].endpoint, sizeof(s_subs[i].endpoint), "%s", endpoint);
			snprintf(s_subs[i].p256dh,   sizeof(s_subs[i].p256dh),   "%s", p256dh ? p256dh : "");
			snprintf(s_subs[i].auth,     sizeof(s_subs[i].auth),     "%s", auth   ? auth   : "");
			if (prefs) {
				for (int t = 0; t < PUSH_NOTIFY_TYPE_COUNT; t++)
					s_subs[i].prefs[t] = prefs[t];
			}
			printf("push_manager: added subscription (total: %d)\n",
			       push_manager_subscription_count());
			return true;
		}
	}

	printf("push_manager: subscription capacity reached (%d)\n", PUSH_MAX_SUBSCRIPTIONS);
	return false;
}

void push_manager_remove_subscription(const char *endpoint) {
	if (!endpoint) return;
	for (int i = 0; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
		if (s_subs[i].active &&
		    strncmp(s_subs[i].endpoint, endpoint, PUSH_ENDPOINT_MAX_LEN) == 0) {
			memset(&s_subs[i], 0, sizeof(s_subs[i]));
			printf("push_manager: removed subscription (total: %d)\n",
			       push_manager_subscription_count());
			return;
		}
	}
}

int push_manager_subscription_count(void) {
	int n = 0;
	for (int i = 0; i < PUSH_MAX_SUBSCRIPTIONS; i++)
		if (s_subs[i].active) n++;
	return n;
}

void push_manager_notify_all(push_notify_type_t type, const char *title, const char *body) {
	int count = 0;
	for (int i = 0; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
		if (s_subs[i].active && s_subs[i].prefs[type]) count++;
	}

	printf("push_manager: notify type=%d title='%s' body='%s' (%d recipient(s))\n",
	       (int)type, title ? title : "", body ? body : "", count);

	// TODO: Send actual Web Push notifications via outbound HTTPS.
	// This requires:
	//   1. VAPID JWT generation (ECDSA-P256 signing of base64url(header).base64url(payload))
	//   2. RFC 8291 message encryption (ECDH-P256 key agreement, HKDF, AES-128-GCM)
	//   3. TLS client (pico_lwip_mbedtls) for HTTPS POST to each subscription endpoint
	// Enable MBEDTLS_ECDSA_C, MBEDTLS_HKDF_C and pico_lwip_mbedtls when implementing.
}
