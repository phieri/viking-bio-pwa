#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "pico/time.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"
#include "mbedtls/ssl.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/dns.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "push_manager.h"
#include "http_client.h"
#include "lfs_hal.h"

// LittleFS file for VAPID key pair
#define VAPID_FILE "/vapid.dat"

// LittleFS file for persisted push subscriptions
#define SUBS_FILE  "/subs.dat"

// Storage layout: magic(4) + private_key(32) + public_key(65) + crc32(4) = 105 bytes
#define VAPID_MAGIC   0x56415049U  // "VAPI"
#define VAPID_PRIVLEN 32
#define VAPID_PUBLEN  65
#define VAPID_STORED  (4 + VAPID_PRIVLEN + VAPID_PUBLEN + 4)

// Subscriptions storage layout (fixed-size flat record array):
//   magic(4) + N×slot + crc32(4)
// Each slot: active(1) + endpoint(513) + p256dh(97) + auth(33) + prefs(3) = 647 bytes
#define SUBS_MAGIC     0x53554253U  // "SUBS"
#define SUBS_SLOT_SIZE (1 + (PUSH_ENDPOINT_MAX_LEN + 1) + (PUSH_P256DH_MAX_LEN + 1) + \
                        (PUSH_AUTH_MAX_LEN + 1) + PUSH_NOTIFY_TYPE_COUNT)
#define SUBS_STORED    (4 + SUBS_SLOT_SIZE * PUSH_MAX_SUBSCRIPTIONS + 4)

// In-memory key pair
static uint8_t s_private_key[VAPID_PRIVLEN];
static uint8_t s_public_key[VAPID_PUBLEN];   // Uncompressed P-256 point (0x04 || X || Y)
static bool    s_keys_valid = false;

// In-memory subscription cache (loaded from /subs.dat on init, persisted on change)
static push_subscription_t s_subs[PUSH_MAX_SUBSCRIPTIONS];

// ---------------------------------------------------------------------------
// Push delivery state machine
// ---------------------------------------------------------------------------

// Maximum length of host portion of a push endpoint URL
#define PUSH_HOST_MAX_LEN     255
// Maximum length of path portion of a push endpoint URL
#define PUSH_PATH_MAX_LEN     255
// Maximum length of the notification JSON payload
#define PUSH_PAYLOAD_MAX_LEN  255
// Encrypted body: salt(16)+rs(4)+idlen(1)+as_pub(65)+ciphertext+tag(16)
#define PUSH_ENCRYPTED_MAX_LEN  (86 + PUSH_PAYLOAD_MAX_LEN + 17)
// VAPID JWT maximum length
#define PUSH_VAPID_JWT_MAX_LEN  512
// HTTP response buffer (just need the status line)
#define PUSH_RESPONSE_MAX_LEN   64
// TLS delivery timeout (ms)
#define PUSH_DELIVERY_TIMEOUT_MS  15000

typedef enum {
	PUSH_STATE_IDLE = 0,
	PUSH_STATE_RESOLVING,
	PUSH_STATE_CONNECTING,
	PUSH_STATE_SENDING,
	PUSH_STATE_READING,
} push_state_t;

typedef struct {
	push_state_t        state;
	int                 sub_idx;
	struct altcp_pcb   *pcb;
	ip_addr_t           server_addr;
	absolute_time_t     timeout;
	char                host[PUSH_HOST_MAX_LEN + 1];
	uint16_t            port;
	// HTTP request buffer: headers (text) + encrypted body (binary)
	uint8_t             http_req[704 + PUSH_ENCRYPTED_MAX_LEN];
	size_t              http_req_len;
	char                response[PUSH_RESPONSE_MAX_LEN];
	size_t              response_len;
	// VAPID JWT (built per-subscriber, stored here to avoid stack pressure)
	char                vapid_jwt[PUSH_VAPID_JWT_MAX_LEN];
	// Current notification being delivered
	push_notify_type_t  type;
	char                title[64];
	char                body[128];
} push_ctx_t;

typedef struct {
	bool                valid;
	push_notify_type_t  type;
	char                title[64];
	char                body[128];
} push_pending_t;

static push_ctx_t     s_ctx;
static push_pending_t s_pending;
static struct altcp_tls_config *s_tls_config = NULL;

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
// Subscription persistence
// ---------------------------------------------------------------------------

static void save_subscriptions(void) {
	uint8_t buf[SUBS_STORED];
	memset(buf, 0, sizeof(buf));

	uint32_t magic = SUBS_MAGIC;
	memcpy(buf, &magic, 4);

	uint8_t *p = buf + 4;
	for (int i = 0; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
		p[0] = s_subs[i].active ? 1 : 0;
		p++;
		memcpy(p, s_subs[i].endpoint, PUSH_ENDPOINT_MAX_LEN + 1); p += PUSH_ENDPOINT_MAX_LEN + 1;
		memcpy(p, s_subs[i].p256dh,   PUSH_P256DH_MAX_LEN + 1);   p += PUSH_P256DH_MAX_LEN + 1;
		memcpy(p, s_subs[i].auth,     PUSH_AUTH_MAX_LEN + 1);     p += PUSH_AUTH_MAX_LEN + 1;
		for (int t = 0; t < PUSH_NOTIFY_TYPE_COUNT; t++)
			*p++ = s_subs[i].prefs[t] ? 1 : 0;
	}

	uint32_t crc = crc32(buf, 4 + SUBS_SLOT_SIZE * PUSH_MAX_SUBSCRIPTIONS);
	memcpy(buf + 4 + SUBS_SLOT_SIZE * PUSH_MAX_SUBSCRIPTIONS, &crc, 4);

	if (!lfs_hal_write_file(SUBS_FILE, buf, sizeof(buf))) {
		printf("push_manager: WARNING – could not persist subscriptions\n");
	}
}

static void load_subscriptions(void) {
	uint8_t buf[SUBS_STORED];
	int n = lfs_hal_read_file(SUBS_FILE, buf, sizeof(buf));
	if (n != (int)sizeof(buf)) return;

	uint32_t magic;
	memcpy(&magic, buf, 4);
	if (magic != SUBS_MAGIC) return;

	uint32_t stored_crc;
	memcpy(&stored_crc, buf + 4 + SUBS_SLOT_SIZE * PUSH_MAX_SUBSCRIPTIONS, 4);
	if (crc32(buf, 4 + SUBS_SLOT_SIZE * PUSH_MAX_SUBSCRIPTIONS) != stored_crc) return;

	const uint8_t *p = buf + 4;
	int loaded = 0;
	for (int i = 0; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
		s_subs[i].active = (p[0] == 1);
		p++;
		memcpy(s_subs[i].endpoint, p, PUSH_ENDPOINT_MAX_LEN + 1); p += PUSH_ENDPOINT_MAX_LEN + 1;
		memcpy(s_subs[i].p256dh,   p, PUSH_P256DH_MAX_LEN + 1);   p += PUSH_P256DH_MAX_LEN + 1;
		memcpy(s_subs[i].auth,     p, PUSH_AUTH_MAX_LEN + 1);     p += PUSH_AUTH_MAX_LEN + 1;
		for (int t = 0; t < PUSH_NOTIFY_TYPE_COUNT; t++)
			s_subs[i].prefs[t] = (*p++ == 1);
		// Enforce null-termination to guard against corrupted strings
		s_subs[i].endpoint[PUSH_ENDPOINT_MAX_LEN] = '\0';
		s_subs[i].p256dh[PUSH_P256DH_MAX_LEN]     = '\0';
		s_subs[i].auth[PUSH_AUTH_MAX_LEN]          = '\0';
		if (s_subs[i].active) loaded++;
	}
	printf("push_manager: loaded %d subscription(s) from flash\n", loaded);
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
// Delivery helper: base64url encode/decode
// ---------------------------------------------------------------------------

// Base64url-encode src into dst (NUL-terminated). Returns output length or -1.
static int b64url_encode(const uint8_t *src, size_t src_len, char *dst, size_t dst_cap) {
	size_t olen = 0;
	if (mbedtls_base64_encode((unsigned char *)dst, dst_cap, &olen, src, src_len) != 0)
		return -1;
	// Convert to base64url in-place and strip padding
	size_t w = 0;
	for (size_t i = 0; i < olen; i++) {
		char c = dst[i];
		if      (c == '+') dst[w++] = '-';
		else if (c == '/') dst[w++] = '_';
		else if (c == '=') continue;
		else               dst[w++] = c;
	}
	dst[w] = '\0';
	return (int)w;
}

// Base64url-decode src into dst. Returns decoded length or -1.
#define B64URL_DECODE_INPUT_MAX 260

static int b64url_decode(const char *src, uint8_t *dst, size_t dst_cap) {
	size_t src_len = strlen(src);
	if (src_len >= B64URL_DECODE_INPUT_MAX) return -1;
	char b64[264];
	size_t i;
	for (i = 0; i < src_len; i++) {
		char c = src[i];
		if      (c == '-') b64[i] = '+';
		else if (c == '_') b64[i] = '/';
		else               b64[i] = c;
	}
	// Add standard base64 padding
	size_t pad = (4 - (i % 4)) % 4;
	for (size_t j = 0; j < pad; j++) b64[i++] = '=';
	b64[i] = '\0';
	size_t olen = 0;
	if (mbedtls_base64_decode(dst, dst_cap, &olen, (const unsigned char *)b64, i) != 0)
		return -1;
	return (int)olen;
}

// ---------------------------------------------------------------------------
// Delivery helper: URL parsing
// ---------------------------------------------------------------------------

// Parse https://[host]:port/path into components.
static bool parse_push_url(const char *url,
                            char *host, size_t host_cap,
                            uint16_t *port,
                            char *path, size_t path_cap) {
	if (strncmp(url, "https://", 8) != 0) return false;
	const char *p = url + 8;
	*port = 443;

	if (*p == '[') {
		// IPv6 literal: [::1] or [::1]:443
		p++;
		const char *end = strchr(p, ']');
		if (!end) return false;
		size_t len = (size_t)(end - p);
		if (len == 0 || len >= host_cap) return false;
		memcpy(host, p, len);
		host[len] = '\0';
		p = end + 1;
	} else {
		const char *end = p;
		while (*end && *end != ':' && *end != '/') end++;
		size_t len = (size_t)(end - p);
		if (len == 0 || len >= host_cap) return false;
		memcpy(host, p, len);
		host[len] = '\0';
		p = end;
	}

	if (*p == ':') {
		p++;
		char *ep;
		long pv = strtol(p, &ep, 10);
		if (ep != p && pv > 0 && pv <= 65535) *port = (uint16_t)pv;
		while (*p && *p != '/') p++;
	}

	if (*p == '/') {
		size_t plen = strlen(p);
		if (plen >= path_cap) return false;
		memcpy(path, p, plen + 1);
	} else {
		if (path_cap < 2) return false;
		path[0] = '/';
		path[1] = '\0';
	}
	return host[0] != '\0';
}

// Extract https://host:port origin from a push endpoint URL.
static bool extract_origin(const char *url, char *origin, size_t origin_cap) {
	if (strncmp(url, "https://", 8) != 0) return false;
	const char *p = url + 8;
	const char *auth_end;
	if (*p == '[') {
		const char *br = strchr(p, ']');
		if (!br) return false;
		auth_end = br + 1;
		if (*auth_end == ':') {
			auth_end++;
			while (*auth_end && *auth_end != '/') auth_end++;
		}
	} else {
		auth_end = p;
		while (*auth_end && *auth_end != '/') auth_end++;
	}
	size_t total = 8 + (size_t)(auth_end - p);
	if (total >= origin_cap) return false;
	snprintf(origin, origin_cap, "https://%.*s", (int)(auth_end - p), p);
	return true;
}

// ---------------------------------------------------------------------------
// Delivery helper: VAPID JWT (RFC 8292, ES256)
// ---------------------------------------------------------------------------

static bool build_vapid_jwt(const char *audience, char *out_buf, size_t out_cap) {
	if (!s_keys_valid) return false;

	// Header: {"typ":"JWT","alg":"ES256"}
	static const char hdr_json[] = "{\"typ\":\"JWT\",\"alg\":\"ES256\"}";
	char hdr_b64[48];
	if (b64url_encode((const uint8_t *)hdr_json, sizeof(hdr_json) - 1,
	                  hdr_b64, sizeof(hdr_b64)) < 0) return false;

	// Payload: use http_client_get_epoch_time() (proxy-synced or BUILD_UNIX_TIME fallback)
	uint32_t now = http_client_get_epoch_time();
	// Require a plausible timestamp (after 2001); fall back to BUILD_UNIX_TIME
	if (now < 1000000000UL) now = BUILD_UNIX_TIME;
	uint32_t exp = now + VAPID_JWT_EXPIRY_SECS;
	char pay_json[256];
	int pjlen = snprintf(pay_json, sizeof(pay_json),
	                     "{\"aud\":\"%s\",\"exp\":%lu,"
	                     "\"sub\":\"mailto:push@viking-bio.local\"}",
	                     audience, (unsigned long)exp);
	if (pjlen <= 0 || pjlen >= (int)sizeof(pay_json)) return false;

	char pay_b64[256];
	if (b64url_encode((const uint8_t *)pay_json, (size_t)pjlen,
	                  pay_b64, sizeof(pay_b64)) < 0) return false;

	// header.payload to sign
	char hp[400];
	int hp_len = snprintf(hp, sizeof(hp), "%s.%s", hdr_b64, pay_b64);
	if (hp_len <= 0 || hp_len >= (int)sizeof(hp)) return false;

	// SHA-256 hash of header.payload
	uint8_t hash[32];
	mbedtls_sha256((const unsigned char *)hp, (size_t)hp_len, hash, 0);

	// ECDSA-P256 sign
	mbedtls_ecp_group grp;
	mbedtls_mpi d, r, s;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	bool ok = false;
	do {
		if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		                           NULL, 0) != 0) break;
		if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0) break;
		if (mbedtls_mpi_read_binary(&d, s_private_key, VAPID_PRIVLEN) != 0) break;
		if (mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, sizeof(hash),
		                        mbedtls_ctr_drbg_random, &ctr_drbg) != 0) break;

		// Raw R||S signature (64 bytes, big-endian 32+32)
		uint8_t sig[64];
		if (mbedtls_mpi_write_binary(&r, sig,      32) != 0) break;
		if (mbedtls_mpi_write_binary(&s, sig + 32, 32) != 0) break;

		char sig_b64[96];
		if (b64url_encode(sig, 64, sig_b64, sizeof(sig_b64)) < 0) break;

		int jlen = snprintf(out_buf, out_cap, "%s.%s", hp, sig_b64);
		if (jlen <= 0 || jlen >= (int)out_cap) break;
		ok = true;
	} while (0);

	mbedtls_ecp_group_free(&grp);
	mbedtls_mpi_free(&d);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	return ok;
}

// ---------------------------------------------------------------------------
// Delivery helper: RFC 8291 message encryption (aes128gcm)
// ---------------------------------------------------------------------------

// Encrypt plaintext for a push subscriber.
// Returns number of bytes written to out_buf (header + ciphertext), or -1 on error.
static int push_encrypt(const char *p256dh_b64, const char *auth_b64,
                         const char *plaintext,
                         uint8_t *out_buf, size_t out_cap) {
	// Decode subscription keys
	uint8_t ua_pub[65];
	if (b64url_decode(p256dh_b64, ua_pub, sizeof(ua_pub)) != 65) return -1;

	uint8_t auth_secret[16];
	if (b64url_decode(auth_b64, auth_secret, sizeof(auth_secret)) != 16) return -1;

	// Generate ephemeral sender key pair
	uint8_t as_pub[65];
	size_t as_pub_olen = 0;
	uint8_t ecdh_secret[32];

	mbedtls_ecp_group  grp;
	mbedtls_mpi        as_d;
	mbedtls_ecp_point  as_Q, ua_Q;
	mbedtls_mpi        shared_x;
	mbedtls_entropy_context  entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&as_d);
	mbedtls_ecp_point_init(&as_Q);
	mbedtls_ecp_point_init(&ua_Q);
	mbedtls_mpi_init(&shared_x);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	bool ok = false;
	int ret;
	do {
		ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
		if (ret != 0) break;

		ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
		if (ret != 0) break;

		ret = mbedtls_ecp_gen_keypair(&grp, &as_d, &as_Q,
		                               mbedtls_ctr_drbg_random, &ctr_drbg);
		if (ret != 0) break;

		ret = mbedtls_ecp_point_write_binary(&grp, &as_Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
		                                      &as_pub_olen, as_pub, sizeof(as_pub));
		if (ret != 0 || as_pub_olen != 65) break;

		ret = mbedtls_ecp_point_read_binary(&grp, &ua_Q, ua_pub, 65);
		if (ret != 0) break;

		// ECDH shared secret (X coordinate of as_d * ua_Q)
		ret = mbedtls_ecdh_compute_shared(&grp, &shared_x, &ua_Q, &as_d,
		                                   mbedtls_ctr_drbg_random, &ctr_drbg);
		if (ret != 0) break;

		ret = mbedtls_mpi_write_binary(&shared_x, ecdh_secret, 32);
		if (ret != 0) break;
		ok = true;
	} while (0);

	mbedtls_ecp_group_free(&grp);
	mbedtls_mpi_free(&as_d);
	mbedtls_ecp_point_free(&as_Q);
	mbedtls_ecp_point_free(&ua_Q);
	mbedtls_mpi_free(&shared_x);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	if (!ok) return -1;

	// HKDF key derivation (RFC 8291 Section 3.4)
	const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!sha256) return -1;

	// PRK_key = HKDF-Extract(salt=auth_secret, IKM=ecdh_secret)
	uint8_t prk_key[32];
	if (mbedtls_hkdf_extract(sha256, auth_secret, 16,
	                          ecdh_secret, 32, prk_key) != 0) return -1;

	// key_info = "WebPush: info\0" (14 bytes) || ua_pub(65) || as_pub(65)
	uint8_t key_info[144];
	memcpy(key_info, "WebPush: info\x00", 14);
	memcpy(key_info + 14,  ua_pub, 65);
	memcpy(key_info + 79,  as_pub, 65);

	// IKM = HKDF-Expand(PRK_key, key_info, 32)
	uint8_t ikm[32];
	if (mbedtls_hkdf_expand(sha256, prk_key, 32,
	                         key_info, sizeof(key_info), ikm, 32) != 0) return -1;

	// Random 16-byte salt for content encryption
	uint8_t salt[16];
	{
		mbedtls_entropy_context  e2;
		mbedtls_ctr_drbg_context d2;
		mbedtls_entropy_init(&e2);
		mbedtls_ctr_drbg_init(&d2);
		ret = mbedtls_ctr_drbg_seed(&d2, mbedtls_entropy_func, &e2, NULL, 0);
		if (ret == 0) ret = mbedtls_ctr_drbg_random(&d2, salt, 16);
		mbedtls_entropy_free(&e2);
		mbedtls_ctr_drbg_free(&d2);
		if (ret != 0) return -1;
	}

	// PRK = HKDF-Extract(salt=salt, IKM=ikm)
	uint8_t prk[32];
	if (mbedtls_hkdf_extract(sha256, salt, 16, ikm, 32, prk) != 0) return -1;

	// CEK = HKDF-Expand(PRK, "Content-Encoding: aes128gcm\0", 16)
	uint8_t cek[16];
	static const uint8_t cek_info[] = "Content-Encoding: aes128gcm\x00"; // 28 bytes
	if (mbedtls_hkdf_expand(sha256, prk, 32, cek_info, 28, cek, 16) != 0) return -1;

	// NONCE = HKDF-Expand(PRK, "Content-Encoding: nonce\0", 12)
	uint8_t nonce[12];
	static const uint8_t nonce_info[] = "Content-Encoding: nonce\x00"; // 24 bytes
	if (mbedtls_hkdf_expand(sha256, prk, 32, nonce_info, 24, nonce, 12) != 0) return -1;

	// Pad plaintext: append 0x02 delimiter (RFC 8291)
	size_t pt_len = strlen(plaintext);
	if (pt_len >= PUSH_PAYLOAD_MAX_LEN) return -1;
	uint8_t padded[PUSH_PAYLOAD_MAX_LEN + 1];
	memcpy(padded, plaintext, pt_len);
	padded[pt_len] = 0x02;
	size_t padded_len = pt_len + 1;

	// Output header: salt(16) + rs_be32(4) + idlen(1) + as_pub(65)
	size_t total = 16 + 4 + 1 + 65 + padded_len + 16;
	if (total > out_cap) return -1;

	uint8_t *p = out_buf;

	memcpy(p, salt, 16); p += 16;

	uint32_t rs = PUSH_RS_FIELD;
	p[0] = (uint8_t)(rs >> 24); p[1] = (uint8_t)(rs >> 16);
	p[2] = (uint8_t)(rs >> 8);  p[3] = (uint8_t) rs;
	p += 4;

	*p++ = 65; // idlen = length of as_pub

	memcpy(p, as_pub, 65); p += 65;

	// AES-128-GCM encrypt: writes ciphertext to p, tag to tag[]
	uint8_t tag[16];
	mbedtls_gcm_context gcm;
	mbedtls_gcm_init(&gcm);
	ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, cek, 128);
	if (ret == 0) {
		ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
		                                 padded_len, nonce, 12,
		                                 NULL, 0,
		                                 padded, p, 16, tag);
	}
	mbedtls_gcm_free(&gcm);
	if (ret != 0) return -1;

	p += padded_len;
	memcpy(p, tag, 16);

	return (int)total;
}

// ---------------------------------------------------------------------------
// Delivery state machine – forward declarations
// ---------------------------------------------------------------------------

static void push_advance_to_next_sub(void);
static void push_start_delivery_for_sub(int sub_idx);

// ---------------------------------------------------------------------------
// Delivery state machine – altcp_tls callbacks
// ---------------------------------------------------------------------------

static void push_tls_abort(void) {
	if (s_ctx.pcb != NULL) {
		altcp_recv(s_ctx.pcb, NULL);
		altcp_err(s_ctx.pcb, NULL);
		altcp_abort(s_ctx.pcb);
		s_ctx.pcb = NULL;
	}
}

static void push_tls_err_cb(void *arg, err_t err) {
	(void)arg;
	printf("push_manager: TLS error %d for sub %d\n", (int)err, s_ctx.sub_idx);
	s_ctx.pcb = NULL; // PCB already freed by lwIP before err_cb fires
	push_advance_to_next_sub();
}

static err_t push_tls_recv_cb(void *arg, struct altcp_pcb *conn,
                               struct pbuf *p, err_t err) {
	(void)arg; (void)err;

	if (p == NULL) {
		// Server closed connection – parse HTTP status and clean up
		s_ctx.response[s_ctx.response_len] = '\0';
		int http_code = 0;
		const char *sp = strchr(s_ctx.response, ' ');
		if (sp) http_code = atoi(sp + 1);

		if (http_code >= 200 && http_code < 300) {
			printf("push_manager: push OK (%d) sub %d\n", http_code, s_ctx.sub_idx);
		} else if (http_code == 404 || http_code == 410) {
			printf("push_manager: subscription expired (%d) – removing sub %d\n",
			       http_code, s_ctx.sub_idx);
			push_manager_remove_subscription(s_subs[s_ctx.sub_idx].endpoint);
		} else {
			printf("push_manager: push returned %d for sub %d\n",
			       http_code, s_ctx.sub_idx);
		}

		// Close our side of the connection
		altcp_recv(conn, NULL);
		altcp_err(conn, NULL);
		altcp_close(conn);
		s_ctx.pcb = NULL;
		push_advance_to_next_sub();
		return ERR_OK;
	}

	// Accumulate response (just need the status line)
	if (s_ctx.response_len < sizeof(s_ctx.response) - 1) {
		size_t copy = p->tot_len;
		if (copy > sizeof(s_ctx.response) - 1 - s_ctx.response_len)
			copy = sizeof(s_ctx.response) - 1 - s_ctx.response_len;
		pbuf_copy_partial(p, s_ctx.response + s_ctx.response_len, (u16_t)copy, 0);
		s_ctx.response_len += copy;
	}

	altcp_recved(conn, p->tot_len);
	pbuf_free(p);
	return ERR_OK;
}

static err_t push_tls_connected_cb(void *arg, struct altcp_pcb *conn, err_t err) {
	(void)arg;

	if (err != ERR_OK || conn == NULL) {
		printf("push_manager: TLS connect failed (%d) sub %d\n",
		       (int)err, s_ctx.sub_idx);
		push_tls_abort();
		push_advance_to_next_sub();
		return err;
	}

	printf("push_manager: TLS connected to %s – sending push\n", s_ctx.host);
	s_ctx.state = PUSH_STATE_SENDING;
	s_ctx.timeout = make_timeout_time_ms(PUSH_DELIVERY_TIMEOUT_MS);
	s_ctx.response_len = 0;

	if (s_ctx.http_req_len > 0 && s_ctx.http_req_len <= 0xFFFFU) {
		err_t e = altcp_write(conn, s_ctx.http_req, (u16_t)s_ctx.http_req_len,
		                       TCP_WRITE_FLAG_COPY);
		if (e == ERR_OK) {
			altcp_output(conn);
			s_ctx.state = PUSH_STATE_READING;
		} else {
			printf("push_manager: altcp_write failed (%d)\n", (int)e);
			push_tls_abort();
			push_advance_to_next_sub();
		}
	} else {
		push_tls_abort();
		push_advance_to_next_sub();
	}
	return ERR_OK;
}

static void push_dns_found_cb(const char *name, const ip_addr_t *addr, void *arg) {
	(void)name; (void)arg;

	// Ignore stale DNS results if we've already timed out and moved on
	if (s_ctx.state != PUSH_STATE_RESOLVING) return;

	if (addr == NULL) {
		printf("push_manager: DNS lookup failed for %s\n", s_ctx.host);
		push_advance_to_next_sub();
		return;
	}
	s_ctx.server_addr = *addr;

	// Create TLS config lazily (lwIP must be fully initialised first)
	if (s_tls_config == NULL) {
		s_tls_config = altcp_tls_create_config_client(NULL, 0);
		if (s_tls_config == NULL) {
			printf("push_manager: TLS config creation failed\n");
			push_advance_to_next_sub();
			return;
		}
	}

	// Open a TLS connection
	s_ctx.pcb = altcp_tls_new(s_tls_config, IP_GET_TYPE(&s_ctx.server_addr));
	if (s_ctx.pcb == NULL) {
		printf("push_manager: altcp_tls_new failed\n");
		push_advance_to_next_sub();
		return;
	}

	altcp_arg(s_ctx.pcb, NULL);
	altcp_err(s_ctx.pcb, push_tls_err_cb);
	altcp_recv(s_ctx.pcb, push_tls_recv_cb);

	// Set SNI hostname so the push service can route the TLS handshake correctly
	mbedtls_ssl_context *ssl =
	    (mbedtls_ssl_context *)altcp_tls_context(s_ctx.pcb);
	if (ssl != NULL)
		mbedtls_ssl_set_hostname(ssl, s_ctx.host);

	s_ctx.state = PUSH_STATE_CONNECTING;
	s_ctx.timeout = make_timeout_time_ms(PUSH_DELIVERY_TIMEOUT_MS);

	err_t e = altcp_connect(s_ctx.pcb, &s_ctx.server_addr, s_ctx.port,
	                         push_tls_connected_cb);
	if (e != ERR_OK) {
		printf("push_manager: altcp_connect failed (%d)\n", (int)e);
		altcp_abort(s_ctx.pcb);
		s_ctx.pcb = NULL;
		push_advance_to_next_sub();
	}
}

// ---------------------------------------------------------------------------
// Delivery state machine – per-subscriber delivery setup
// ---------------------------------------------------------------------------

static void push_advance_to_next_sub(void) {
	// Defensive: ensure no dangling PCB
	if (s_ctx.pcb != NULL) {
		altcp_recv(s_ctx.pcb, NULL);
		altcp_err(s_ctx.pcb, NULL);
		altcp_abort(s_ctx.pcb);
		s_ctx.pcb = NULL;
	}

	// Find next eligible subscriber after the current one
	for (int i = s_ctx.sub_idx + 1; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
		if (s_subs[i].active && s_subs[i].prefs[s_ctx.type]) {
			push_start_delivery_for_sub(i);
			return;
		}
	}

	// All subscribers handled
	s_ctx.state = PUSH_STATE_IDLE;
	s_ctx.sub_idx = -1;
	printf("push_manager: all deliveries complete\n");
}

static void push_start_delivery_for_sub(int sub_idx) {
	const push_subscription_t *sub = &s_subs[sub_idx];
	s_ctx.sub_idx = sub_idx;

	char path[PUSH_PATH_MAX_LEN + 1];
	if (!parse_push_url(sub->endpoint,
	                     s_ctx.host, sizeof(s_ctx.host),
	                     &s_ctx.port,
	                     path, sizeof(path))) {
		printf("push_manager: bad endpoint URL for sub %d\n", sub_idx);
		push_advance_to_next_sub();
		return;
	}

	char audience[128];
	if (!extract_origin(sub->endpoint, audience, sizeof(audience))) {
		printf("push_manager: cannot extract origin for sub %d\n", sub_idx);
		push_advance_to_next_sub();
		return;
	}

	// Build notification JSON payload (matches the format the service worker expects)
	const char *type_str;
	switch (s_ctx.type) {
		case PUSH_NOTIFY_FLAME: type_str = "flame"; break;
		case PUSH_NOTIFY_ERROR: type_str = "error"; break;
		case PUSH_NOTIFY_CLEAN: type_str = "clean"; break;
		default:                type_str = "status"; break;
	}
	const char *priority = (s_ctx.type == PUSH_NOTIFY_ERROR) ? "high" : "low";

	char payload[PUSH_PAYLOAD_MAX_LEN + 1];
	int plen = snprintf(payload, sizeof(payload),
	                    "{\"title\":\"%s\",\"body\":\"%s\","
	                    "\"icon\":\"/icon.png\","
	                    "\"type\":\"%s\",\"priority\":\"%s\"}",
	                    s_ctx.title, s_ctx.body, type_str, priority);
	if (plen <= 0 || plen >= (int)sizeof(payload)) {
		printf("push_manager: payload overflow for sub %d\n", sub_idx);
		push_advance_to_next_sub();
		return;
	}

	// RFC 8291: encrypt the payload
	uint8_t encrypted[PUSH_ENCRYPTED_MAX_LEN];
	int enc_len = push_encrypt(sub->p256dh, sub->auth, payload,
	                            encrypted, sizeof(encrypted));
	if (enc_len < 0) {
		printf("push_manager: encryption failed for sub %d\n", sub_idx);
		push_advance_to_next_sub();
		return;
	}

	// VAPID JWT (stored in s_ctx to avoid large stack frame)
	if (!build_vapid_jwt(audience, s_ctx.vapid_jwt, sizeof(s_ctx.vapid_jwt))) {
		printf("push_manager: JWT build failed for sub %d\n", sub_idx);
		push_advance_to_next_sub();
		return;
	}

	// VAPID public key
	char vapid_pub[96];
	if (!push_manager_get_vapid_public_key(vapid_pub, sizeof(vapid_pub))) {
		printf("push_manager: cannot get VAPID public key\n");
		push_advance_to_next_sub();
		return;
	}

	// Build HTTP POST headers directly into s_ctx.http_req, then append binary body
	int hdr_len = snprintf((char *)s_ctx.http_req, sizeof(s_ctx.http_req),
	                        "POST %s HTTP/1.1\r\n"
	                        "Host: %s\r\n"
	                        "Content-Type: application/octet-stream\r\n"
	                        "Content-Encoding: aes128gcm\r\n"
	                        "Authorization: vapid t=%s,k=%s\r\n"
	                        "TTL: 0\r\n"
	                        "Content-Length: %d\r\n"
	                        "Connection: close\r\n"
	                        "\r\n",
	                        path, s_ctx.host,
	                        s_ctx.vapid_jwt, vapid_pub,
	                        enc_len);
	if (hdr_len <= 0 || (size_t)hdr_len + (size_t)enc_len > sizeof(s_ctx.http_req)) {
		printf("push_manager: HTTP request overflow for sub %d\n", sub_idx);
		push_advance_to_next_sub();
		return;
	}
	memcpy(s_ctx.http_req + hdr_len, encrypted, (size_t)enc_len);
	s_ctx.http_req_len = (size_t)hdr_len + (size_t)enc_len;

	printf("push_manager: delivering to sub %d host=%s\n", sub_idx, s_ctx.host);

	// Resolve hostname (or connect directly if already a numeric IP)
	s_ctx.state = PUSH_STATE_RESOLVING;
	s_ctx.timeout = make_timeout_time_ms(PUSH_DELIVERY_TIMEOUT_MS);
	if (ipaddr_aton(s_ctx.host, &s_ctx.server_addr)) {
		// Direct IP – skip DNS; call dns callback path manually
		push_dns_found_cb(NULL, &s_ctx.server_addr, NULL);
	} else {
		err_t e = dns_gethostbyname(s_ctx.host, &s_ctx.server_addr,
		                             push_dns_found_cb, NULL);
		if (e == ERR_OK) {
			push_dns_found_cb(NULL, &s_ctx.server_addr, NULL);
		} else if (e != ERR_INPROGRESS) {
			printf("push_manager: DNS error %d for %s\n", (int)e, s_ctx.host);
			push_advance_to_next_sub();
		}
	}
}

// ---------------------------------------------------------------------------
// Internal helper: start delivering a queued notification
// ---------------------------------------------------------------------------

static void push_notify_start(push_notify_type_t type,
                               const char *title, const char *body) {
	s_ctx.type = type;
	snprintf(s_ctx.title, sizeof(s_ctx.title), "%s", title ? title : "");
	snprintf(s_ctx.body,  sizeof(s_ctx.body),  "%s", body  ? body  : "");
	s_ctx.sub_idx = -1;

	// Find first eligible subscriber
	for (int i = 0; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
		if (s_subs[i].active && s_subs[i].prefs[type]) {
			push_start_delivery_for_sub(i);
			return;
		}
	}
	s_ctx.state = PUSH_STATE_IDLE;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool push_manager_init(void) {
	memset(s_subs, 0, sizeof(s_subs));
	memset(&s_ctx, 0, sizeof(s_ctx));
	memset(&s_pending, 0, sizeof(s_pending));

	if (load_vapid_keys()) {
		printf("push_manager: loaded VAPID keys from flash\n");
		s_keys_valid = true;
	} else {
		printf("push_manager: generating new VAPID key pair (P-256)...\n");
		if (!generate_vapid_keys()) return false;

		if (!save_vapid_keys()) {
			printf("push_manager: WARNING – could not persist VAPID keys\n");
		}

		s_keys_valid = true;
		printf("push_manager: VAPID keys generated and stored\n");
	}

	// s_tls_config is created lazily on first use in push_dns_found_cb() to
	// ensure lwIP has been fully initialised by cyw43_arch_init_with_country()
	// before any altcp_tls allocation takes place.

	load_subscriptions();
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
			save_subscriptions();
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
			save_subscriptions();
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
			save_subscriptions();
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

	if (count == 0) return;

	if (s_ctx.state == PUSH_STATE_IDLE) {
		push_notify_start(type, title, body);
	} else {
		// Queue as pending (overwrite any unstarted previous notification)
		s_pending.valid = true;
		s_pending.type  = type;
		snprintf(s_pending.title, sizeof(s_pending.title), "%s", title ? title : "");
		snprintf(s_pending.body,  sizeof(s_pending.body),  "%s", body  ? body  : "");
	}
}

void push_manager_poll(void) {
	// Timeout check for in-progress deliveries
	if (s_ctx.state != PUSH_STATE_IDLE &&
	    time_reached(s_ctx.timeout)) {
		printf("push_manager: timeout for sub %d\n", s_ctx.sub_idx);
		push_tls_abort();
		push_advance_to_next_sub();
		return;
	}

	// Start a pending notification once the current delivery is complete
	if (s_ctx.state == PUSH_STATE_IDLE && s_pending.valid) {
		s_pending.valid = false;
		push_notify_start(s_pending.type, s_pending.title, s_pending.body);
	}
}
