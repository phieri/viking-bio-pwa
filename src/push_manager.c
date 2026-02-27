#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "pico/rand.h"
#include "lwip/tcp.h"
#include "lwip/dns.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
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

// VAPID subject claim – identifies the application server
#define VAPID_SUB "mailto:admin@viking-bio.local"

// JWT expiry window in seconds (1 hour; RFC 8292 requires ≤ 24 h)
#define VAPID_JWT_EXPIRY_SECS 3600U

// aes128gcm record-size field (RFC 8188 §2; single-record push)
#define PUSH_RS_FIELD 4096U

// altcp poll interval (units of 500 ms each; 20 × 500 ms = 10 s total)
#define PUSH_POLL_TIMEOUT_INTERVALS 20

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

/* Entropy source callback for mbedTLS using pico_rand (unconditionally) */
static int pico_entropy_source(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;
    /* pico_rand_get_bytes fills the buffer with len bytes */
    pico_rand_get_bytes(output, len);
    *olen = len;
    return 0;
}

static void pico_register_entropy(mbedtls_entropy_context *entropy) {
    mbedtls_entropy_add_source(entropy,
                               pico_entropy_source,
                               NULL,
                               sizeof(uint32_t),
                               MBEDTLS_ENTROPY_SOURCE_STRONG);
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

// ============================================================
// Base64url helpers
// ============================================================

// base64url alphabet (no padding)
static const char b64url_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Encode binary data as base64url (unpadded).
// Returns number of characters written (excluding NUL terminator).
static size_t base64url_encode(const uint8_t *data, size_t len,
                                char *out, size_t out_size) {
	size_t out_len = 0;
	size_t i;
	for (i = 0; i + 2 < len; i += 3) {
		if (out_len + 4 >= out_size) break;
		out[out_len++] = b64url_chars[(data[i] >> 2) & 0x3F];
		out[out_len++] = b64url_chars[((data[i] & 0x3) << 4) | ((data[i+1] >> 4) & 0xF)];
		out[out_len++] = b64url_chars[((data[i+1] & 0xF) << 2) | ((data[i+2] >> 6) & 0x3)];
		out[out_len++] = b64url_chars[data[i+2] & 0x3F];
	}
	if (i < len && out_len + 3 < out_size) {
		if (len - i == 1) {
			out[out_len++] = b64url_chars[(data[i] >> 2) & 0x3F];
			out[out_len++] = b64url_chars[(data[i] & 0x3) << 4];
		} else {
			out[out_len++] = b64url_chars[(data[i] >> 2) & 0x3F];
			out[out_len++] = b64url_chars[((data[i] & 0x3) << 4) | ((data[i+1] >> 4) & 0xF)];
			out[out_len++] = b64url_chars[(data[i+1] & 0xF) << 2];
		}
	}
	if (out_len < out_size) out[out_len] = '\0';
	return out_len;
}

// Decode base64url string (with or without padding) to binary.
// Returns number of decoded bytes, or -1 on error.
// Buffer tmp must accommodate worst-case padded base64: ceil(in_len/3)*4 + 1.
// The constant 260 covers the maximum in_len accepted (255) padded to 256 + NUL.
static int base64url_decode(const char *in, size_t in_len,
                             uint8_t *out, size_t out_size) {
	// Convert base64url alphabet to standard base64
	char tmp[260];
	if (in_len >= sizeof(tmp) - 4) return -1;
	size_t i;
	for (i = 0; i < in_len; i++) {
		tmp[i] = (in[i] == '-') ? '+' : (in[i] == '_') ? '/' : in[i];
	}
	// Add '=' padding to next multiple of 4
	while (i % 4 != 0) tmp[i++] = '=';
	tmp[i] = '\0';

	size_t olen = 0;
	if (mbedtls_base64_decode(out, out_size, &olen,
	                           (const uint8_t *)tmp, i) != 0) return -1;
	return (int)olen;
}

// ============================================================
// URL parsing
// ============================================================

// Parse an HTTPS push endpoint URL into host, path, and port.
// Returns true on success.
static bool parse_push_url(const char *url,
                            char *host, size_t host_size,
                            char *path, size_t path_size,
                            uint16_t *port) {
	if (strncmp(url, "https://", 8) != 0) return false;
	const char *p = url + 8;

	const char *slash = strchr(p, '/');
	const char *colon = strchr(p, ':');
	const char *host_end;

	*port = 443;
	if (colon && (!slash || colon < slash)) {
		// Explicit port: https://hostname:port/path
		host_end = colon;
		char *end_ptr = NULL;
		unsigned long port_val = strtoul(colon + 1, &end_ptr, 10);
		if (end_ptr == colon + 1 || port_val == 0 || port_val > 65535U) return false;
		*port = (uint16_t)port_val;
		if (!slash) slash = strchr(colon + 1, '/');
	} else {
		host_end = slash ? slash : (p + strlen(p));
	}

	size_t hlen = (size_t)(host_end - p);
	if (hlen == 0 || hlen >= host_size) return false;
	memcpy(host, p, hlen);
	host[hlen] = '\0';

	if (slash) {
		strncpy(path, slash, path_size - 1);
		path[path_size - 1] = '\0';
	} else {
		strncpy(path, "/", path_size - 1);
		path[path_size - 1] = '\0';
	}
	return true;
}

// ============================================================
// VAPID JWT (RFC 8292)
// ============================================================

// Build a VAPID JWT for the given push service origin (audience).
// The token is signed with the VAPID private key using ECDSA-P256 / SHA-256.
// jwt_out must be at least 512 bytes.
// Returns true on success.
static bool make_vapid_jwt(const char *audience, char *jwt_out, size_t jwt_out_size) {
	if (!vapid_keys_valid) return false;

	// --- Header (base64url) ---
	const char header_json[] = "{\"typ\":\"JWT\",\"alg\":\"ES256\"}";
	char b64_header[48] = {0};
	base64url_encode((const uint8_t *)header_json, strlen(header_json),
	                 b64_header, sizeof(b64_header));

	// --- Payload (base64url) ---
	// exp = approximate Unix time + 1 hour (BUILD_UNIX_TIME anchors the epoch)
	uint32_t exp_time = (uint32_t)(BUILD_UNIX_TIME +
	                               (uint32_t)(time_us_64() / 1000000ULL) +
	                               VAPID_JWT_EXPIRY_SECS);
	char payload_json[200];
	snprintf(payload_json, sizeof(payload_json),
	         "{\"aud\":\"%s\",\"exp\":%u,\"sub\":\"" VAPID_SUB "\"}",
	         audience, (unsigned)exp_time);
	char b64_payload[300] = {0};
	base64url_encode((const uint8_t *)payload_json, strlen(payload_json),
	                 b64_payload, sizeof(b64_payload));

	// --- Signing input: header.payload ---
	char signing_input[400];
	int si_len = snprintf(signing_input, sizeof(signing_input),
	                      "%s.%s", b64_header, b64_payload);
	if (si_len <= 0 || si_len >= (int)sizeof(signing_input)) return false;

	// --- SHA-256 digest of signing input ---
	uint8_t hash[32];
	if (mbedtls_sha256((const uint8_t *)signing_input, (size_t)si_len, hash, 0) != 0)
		return false;

	// --- ECDSA-P256 signature ---
	mbedtls_ecp_keypair kp;
	mbedtls_ecp_keypair_init(&kp);
	int ret = mbedtls_ecp_group_load(&kp.MBEDTLS_PRIVATE(grp),
	                                  MBEDTLS_ECP_DP_SECP256R1);
	if (ret != 0) { mbedtls_ecp_keypair_free(&kp); return false; }
	ret = mbedtls_mpi_read_binary(&kp.MBEDTLS_PRIVATE(d), vapid_private_key, 32);
	if (ret != 0) { mbedtls_ecp_keypair_free(&kp); return false; }

	mbedtls_mpi r, s;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	ret = mbedtls_ecdsa_sign(&kp.MBEDTLS_PRIVATE(grp), &r, &s,
	                          &kp.MBEDTLS_PRIVATE(d), hash, 32,
	                          mbedtls_hmac_drbg_random, &hmac_drbg);
	mbedtls_ecp_keypair_free(&kp);
	if (ret != 0) { mbedtls_mpi_free(&r); mbedtls_mpi_free(&s); return false; }

	// Raw signature: r (32 bytes) || s (32 bytes)
	uint8_t sig[64];
	mbedtls_mpi_write_binary(&r, sig,      32);
	mbedtls_mpi_write_binary(&s, sig + 32, 32);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);

	char b64_sig[96] = {0};
	base64url_encode(sig, 64, b64_sig, sizeof(b64_sig));

	// --- Assemble JWT: header.payload.signature ---
	int n = snprintf(jwt_out, jwt_out_size, "%s.%s", signing_input, b64_sig);
	return n > 0 && n < (int)jwt_out_size;
}

// ============================================================
// Web Push payload encryption (RFC 8291, aes128gcm)
// ============================================================

// Encrypt plaintext for delivery to a Web Push subscriber.
//   plaintext        – JSON notification content (max 255 bytes)
//   plaintext_len    – byte length of plaintext (must be <= 255)
//   p256dh_b64       – subscriber's P-256 public key (base64url, uncompressed 65 B)
//   auth_b64         – subscriber's auth secret (base64url, 16 B)
//   out              – output buffer for the aes128gcm-encoded body
//   out_size         – capacity of out (needs >= plaintext_len + 39)
// Returns encoded byte count, or 0 on failure.
static size_t encrypt_push_payload(const uint8_t *plaintext, size_t plaintext_len,
                                    const char *p256dh_b64, const char *auth_b64,
                                    uint8_t *out, size_t out_size) {
	// Minimum output size check: 16 (salt) + 4 (rs) + 1 (idlen) + record + 16 (tag)
	// The internal record buffer is 256 bytes, so plaintext must be <= 255 bytes.
	if (plaintext_len > 255 || out_size < plaintext_len + 38) return 0;

	// --- Decode subscriber keys ---
	uint8_t receiver_key[65];
	int r_len = base64url_decode(p256dh_b64, strlen(p256dh_b64),
	                              receiver_key, sizeof(receiver_key));
	if (r_len != 65) return 0;

	uint8_t auth_secret[16];
	int a_len = base64url_decode(auth_b64, strlen(auth_b64),
	                              auth_secret, sizeof(auth_secret));
	if (a_len != 16) return 0;

	// --- Generate ephemeral P-256 key pair ---
	mbedtls_ecp_keypair ua_key;
	mbedtls_ecp_keypair_init(&ua_key);
	int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &ua_key,
	                               mbedtls_hmac_drbg_random, &hmac_drbg);
	if (ret != 0) { mbedtls_ecp_keypair_free(&ua_key); return 0; }

	// Export ephemeral public key (uncompressed, 65 bytes)
	uint8_t ua_public[65];
	size_t olen = 0;
	ret = mbedtls_ecp_point_write_binary(&ua_key.MBEDTLS_PRIVATE(grp),
	                                      &ua_key.MBEDTLS_PRIVATE(Q),
	                                      MBEDTLS_ECP_PF_UNCOMPRESSED,
	                                      &olen, ua_public, 65);
	if (ret != 0 || olen != 65) { mbedtls_ecp_keypair_free(&ua_key); return 0; }

	// --- ECDH shared secret ---
	mbedtls_ecp_group grp;
	mbedtls_ecp_point receiver_Q;
	mbedtls_mpi z;
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&receiver_Q);
	mbedtls_mpi_init(&z);

	ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
	if (ret != 0) goto cleanup_ecdh;
	ret = mbedtls_ecp_point_read_binary(&grp, &receiver_Q, receiver_key, 65);
	if (ret != 0) goto cleanup_ecdh;
	ret = mbedtls_ecdh_compute_shared(&grp, &z,
	                                   &receiver_Q, &ua_key.MBEDTLS_PRIVATE(d),
	                                   mbedtls_hmac_drbg_random, &hmac_drbg);
	if (ret != 0) goto cleanup_ecdh;

	{
		uint8_t ecdh_secret[32];
		mbedtls_mpi_write_binary(&z, ecdh_secret, 32);
		mbedtls_mpi_free(&z);
		mbedtls_ecp_point_free(&receiver_Q);
		mbedtls_ecp_group_free(&grp);
		mbedtls_ecp_keypair_free(&ua_key);

		// --- RFC 8291 key derivation ---
		const mbedtls_md_info_t *md =
			mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

		// PRK_key = HKDF-Extract(auth_secret, ecdh_secret)
		uint8_t prk_key[32];
		mbedtls_hkdf_extract(md, auth_secret, 16, ecdh_secret, 32, prk_key);

		// auth_info = "WebPush: info\0" || receiver_key (65) || ua_public (65) = 144 bytes
		uint8_t auth_info[144];
		memcpy(auth_info, "WebPush: info", 13);
		auth_info[13] = 0x00;
		memcpy(auth_info + 14, receiver_key, 65);
		memcpy(auth_info + 79, ua_public, 65);

		// IKM = HKDF-Expand(PRK_key, auth_info, 32)
		uint8_t ikm[32];
		mbedtls_hkdf_expand(md, prk_key, 32, auth_info, 144, ikm, 32);

		// Random salt (16 bytes)
		uint8_t salt[16];
		mbedtls_hmac_drbg_random(&hmac_drbg, salt, 16);

		// PRK = HKDF-Extract(salt, IKM)
		uint8_t prk[32];
		mbedtls_hkdf_extract(md, salt, 16, ikm, 32, prk);

		// CEK = first 16 bytes of HKDF-Expand(PRK, "Content-Encoding: aes128gcm\0")
		// The trailing \x00 is the explicit null byte required by RFC 8188.
		const uint8_t cek_label[] = "Content-Encoding: aes128gcm\x00";
		uint8_t cek[32];
		mbedtls_hkdf_expand(md, prk, 32,
		                     cek_label, sizeof(cek_label) - 1, cek, 32);

		// nonce = first 12 bytes of HKDF-Expand(PRK, "Content-Encoding: nonce\0")
		const uint8_t nonce_label[] = "Content-Encoding: nonce\x00";
		uint8_t nonce_full[32];
		mbedtls_hkdf_expand(md, prk, 32,
		                     nonce_label, sizeof(nonce_label) - 1, nonce_full, 32);

		// --- Encrypt with AES-128-GCM ---
		// Plaintext record = plaintext || 0x02 (final-record delimiter per RFC 8188)
		size_t rec_len = plaintext_len + 1;
		uint8_t record[256];
		if (rec_len > sizeof(record)) return 0;
		memcpy(record, plaintext, plaintext_len);
		record[plaintext_len] = 0x02;

		mbedtls_gcm_context gcm;
		mbedtls_gcm_init(&gcm);
		ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, cek, 128);
		if (ret != 0) { mbedtls_gcm_free(&gcm); return 0; }

		// Output layout: salt(16) + rs(4) + idlen(1) + ciphertext(rec_len) + tag(16)
		uint8_t tag[16];
		ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, rec_len,
		                                 nonce_full, 12,
		                                 NULL, 0,
		                                 record, out + 21,
		                                 16, tag);
		mbedtls_gcm_free(&gcm);
		if (ret != 0) return 0;

		// Write aes128gcm header
		memcpy(out, salt, 16);
		uint32_t rs = PUSH_RS_FIELD;
		out[16] = (uint8_t)(rs >> 24);
		out[17] = (uint8_t)(rs >> 16);
		out[18] = (uint8_t)(rs >>  8);
		out[19] = (uint8_t)(rs      );
		out[20] = 0;  // idlen = 0 (no explicit key ID)
		memcpy(out + 21 + rec_len, tag, 16);

		return 21 + rec_len + 16;
	}

cleanup_ecdh:
	mbedtls_mpi_free(&z);
	mbedtls_ecp_point_free(&receiver_Q);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ecp_keypair_free(&ua_key);
	return 0;
}

// ============================================================
// Async HTTPS push state machine
// ============================================================

typedef enum {
	PUSH_IDLE = 0,
	PUSH_DNS,
	PUSH_CONNECTING,
	PUSH_SENDING,
	PUSH_RECEIVING,
	PUSH_DONE,
	PUSH_ERROR,
} push_state_t;

// Pending notification (single-slot queue)
typedef struct {
	bool pending;
	char title[64];
	char body[128];
	uint8_t error_code;
} push_notify_t;

// Per-attempt send context
typedef struct {
	push_state_t state;
	int sub_idx;                     // subscription being processed
	struct altcp_pcb *pcb;
	struct altcp_tls_config *tls_cfg;
	ip_addr_t addr;
	char hostname[128];
	char path[PUSH_MAX_ENDPOINT_LEN];
	uint16_t port;
	uint8_t req_buf[1024];           // HTTP request headers
	size_t req_len;
	uint8_t payload[300];            // aes128gcm-encrypted body
	size_t payload_len;
} push_ctx_t;

static push_notify_t s_notify;
static push_ctx_t    s_push;

// Forward declarations for callbacks
static err_t push_connected_cb(void *arg, struct altcp_pcb *pcb, err_t err);
static err_t push_recv_cb(void *arg, struct altcp_pcb *pcb,
                           struct pbuf *p, err_t err);
static err_t push_sent_cb(void *arg, struct altcp_pcb *pcb, u16_t len);
static void  push_err_cb(void *arg, err_t err);
static err_t push_poll_cb(void *arg, struct altcp_pcb *pcb);

// DNS resolution callback
static void push_dns_cb(const char *name, const ip_addr_t *ipaddr, void *arg) {
	(void)name; (void)arg;
	if (ipaddr == NULL || s_push.state != PUSH_DNS) {
		printf("push_manager: DNS failed for %s\n", s_push.hostname);
		s_push.state = PUSH_ERROR;
		return;
	}

	s_push.addr = *ipaddr;

	// Create TLS client config (NULL cert = no server-certificate verification)
	s_push.tls_cfg = altcp_tls_create_config_client(NULL, 0);
	if (!s_push.tls_cfg) {
		printf("push_manager: TLS config alloc failed\n");
		s_push.state = PUSH_ERROR;
		return;
	}

	// Create AltCP TLS PCB – use ANY so DNS result (IPv4 or IPv6) is accepted
	s_push.pcb = altcp_tls_new(s_push.tls_cfg, IPADDR_TYPE_ANY);
	if (!s_push.pcb) {
		printf("push_manager: altcp_tls_new failed\n");
		s_push.state = PUSH_ERROR;
		return;
	}

	altcp_recv(s_push.pcb, push_recv_cb);
	altcp_sent(s_push.pcb, push_sent_cb);
	altcp_err(s_push.pcb, push_err_cb);
	altcp_poll(s_push.pcb, push_poll_cb, PUSH_POLL_TIMEOUT_INTERVALS);

	err_t err = altcp_connect(s_push.pcb, &s_push.addr, s_push.port,
	                           push_connected_cb);
	if (err != ERR_OK) {
		printf("push_manager: connect failed (%d)\n", err);
		altcp_abort(s_push.pcb);
		s_push.pcb = NULL;
		s_push.state = PUSH_ERROR;
		return;
	}

	s_push.state = PUSH_CONNECTING;
	printf("push_manager: connecting to %s:%u\n", s_push.hostname, s_push.port);
}

// TLS handshake + TCP connect complete
static err_t push_connected_cb(void *arg, struct altcp_pcb *pcb, err_t err) {
	(void)arg;
	if (err != ERR_OK || s_push.state != PUSH_CONNECTING) {
		printf("push_manager: connected_cb error %d\n", err);
		s_push.state = PUSH_ERROR;
		return ERR_OK;
	}

	// Send HTTP headers
	err_t werr = altcp_write(pcb, s_push.req_buf, (u16_t)s_push.req_len,
	                          TCP_WRITE_FLAG_COPY);
	if (werr != ERR_OK) {
		printf("push_manager: write headers failed (%d)\n", werr);
		s_push.state = PUSH_ERROR;
		return ERR_OK;
	}

	// Send encrypted payload
	if (s_push.payload_len > 0) {
		werr = altcp_write(pcb, s_push.payload, (u16_t)s_push.payload_len,
		                   TCP_WRITE_FLAG_COPY);
		if (werr != ERR_OK) {
			printf("push_manager: write payload failed (%d)\n", werr);
			s_push.state = PUSH_ERROR;
			return ERR_OK;
		}
	}

	altcp_output(pcb);
	s_push.state = PUSH_SENDING;
	return ERR_OK;
}

// Data received from push service (HTTP response)
static err_t push_recv_cb(void *arg, struct altcp_pcb *pcb,
                           struct pbuf *p, err_t err) {
	(void)arg;
	if (err != ERR_OK) {
		if (p) pbuf_free(p);
		s_push.state = PUSH_ERROR;
		return ERR_OK;
	}

	if (p == NULL) {
		// Server closed the connection
		if (s_push.state == PUSH_RECEIVING || s_push.state == PUSH_SENDING) {
			printf("push_manager: notification delivered (sub %d)\n",
			       s_push.sub_idx);
		}
		s_push.state = PUSH_DONE;
		altcp_close(pcb);
		s_push.pcb = NULL;
		return ERR_OK;
	}

	// Log first 12 bytes of HTTP response status line
	if (s_push.state == PUSH_SENDING || s_push.state == PUSH_RECEIVING) {
		s_push.state = PUSH_RECEIVING;
		if (p->tot_len >= 12) {
			char resp[16] = {0};
			pbuf_copy_partial(p, resp, 12, 0);
			printf("push_manager: sub %d response: %.12s\n",
			       s_push.sub_idx, resp);
		}
	}

	u16_t tot = p->tot_len;
	pbuf_free(p);
	altcp_recved(pcb, tot);
	return ERR_OK;
}

// Data acknowledged by push service
static err_t push_sent_cb(void *arg, struct altcp_pcb *pcb, u16_t len) {
	(void)arg; (void)pcb; (void)len;
	if (s_push.state == PUSH_SENDING) {
		s_push.state = PUSH_RECEIVING;
	}
	return ERR_OK;
}

// Connection error (PCB already freed by lwIP)
static void push_err_cb(void *arg, err_t err) {
	(void)arg;
	printf("push_manager: connection error %d\n", err);
	s_push.pcb = NULL;
	s_push.state = PUSH_ERROR;
}

// Poll callback used as an inactivity timeout
static err_t push_poll_cb(void *arg, struct altcp_pcb *pcb) {
	(void)arg;
	if (s_push.state != PUSH_DONE && s_push.state != PUSH_IDLE) {
		printf("push_manager: timeout\n");
		s_push.state = PUSH_ERROR;
		altcp_abort(pcb);
		s_push.pcb = NULL;
	}
	return ERR_OK;
}

// Build and start a push send for the given subscription index.
// On sync failure sets s_push.state = PUSH_ERROR; on async start sets PUSH_DNS.
static void start_push_for_sub(int sub_idx) {
	push_subscription_t *sub = &subscriptions[sub_idx];
	s_push.sub_idx    = sub_idx;
	s_push.pcb        = NULL;
	s_push.tls_cfg    = NULL;

	// Parse endpoint URL
	if (!parse_push_url(sub->endpoint,
	                    s_push.hostname, sizeof(s_push.hostname),
	                    s_push.path,     sizeof(s_push.path),
	                    &s_push.port)) {
		printf("push_manager: invalid endpoint: %s\n", sub->endpoint);
		s_push.state = PUSH_ERROR;
		return;
	}

	// Build JSON notification payload
	char json[256];
	int json_len = snprintf(json, sizeof(json),
	    "{\"title\":\"%s\",\"body\":\"%s\",\"icon\":\"/icon.png\"}",
	    s_notify.title, s_notify.body);
	if (json_len <= 0 || json_len >= (int)sizeof(json)) {
		s_push.state = PUSH_ERROR;
		return;
	}

	// Encrypt payload when subscription keys are present
	if (sub->p256dh[0] != '\0' && sub->auth[0] != '\0') {
		s_push.payload_len = encrypt_push_payload(
		    (const uint8_t *)json, (size_t)json_len,
		    sub->p256dh, sub->auth,
		    s_push.payload, sizeof(s_push.payload));
		if (s_push.payload_len == 0) {
			printf("push_manager: encryption failed (sub %d)\n", sub_idx);
			s_push.state = PUSH_ERROR;
			return;
		}
	} else {
		s_push.payload_len = 0;
	}

	// Build VAPID JWT (audience = https://hostname)
	char audience[160];
	snprintf(audience, sizeof(audience), "https://%s", s_push.hostname);
	char jwt[512];
	if (!make_vapid_jwt(audience, jwt, sizeof(jwt))) {
		printf("push_manager: JWT generation failed\n");
		s_push.state = PUSH_ERROR;
		return;
	}

	// VAPID public key as base64url
	char vapid_pub_b64[96] = {0};
	base64url_encode(vapid_public_key, 65, vapid_pub_b64, sizeof(vapid_pub_b64));

	// Assemble HTTP POST request headers
	int hlen = snprintf((char *)s_push.req_buf, sizeof(s_push.req_buf),
	    "POST %s HTTP/1.1\r\n"
	    "Host: %s\r\n"
	    "Authorization: vapid t=%s,k=%s\r\n"
	    "Content-Type: application/octet-stream\r\n"
	    "Content-Encoding: aes128gcm\r\n"
	    "TTL: 60\r\n"
	    "Content-Length: %u\r\n"
	    "Connection: close\r\n"
	    "\r\n",
	    s_push.path,
	    s_push.hostname,
	    jwt, vapid_pub_b64,
	    (unsigned)s_push.payload_len);
	if (hlen <= 0 || hlen >= (int)sizeof(s_push.req_buf)) {
		printf("push_manager: request buffer overflow\n");
		s_push.state = PUSH_ERROR;
		return;
	}
	s_push.req_len = (size_t)hlen;

	// Kick off async DNS resolution
	s_push.state = PUSH_DNS;
	ip_addr_t addr;
	err_t dns_err = dns_gethostbyname(s_push.hostname, &addr,
	                                   push_dns_cb, NULL);
	if (dns_err == ERR_OK) {
		// Cached result – invoke callback synchronously
		push_dns_cb(s_push.hostname, &addr, NULL);
	} else if (dns_err != ERR_INPROGRESS) {
		printf("push_manager: DNS error %d for %s\n",
		       dns_err, s_push.hostname);
		s_push.state = PUSH_ERROR;
	}
	// ERR_INPROGRESS: callback fires later from lwIP stack
}

// ============================================================
// Public API
// ============================================================

bool push_manager_init(void) {
	memset(subscriptions, 0, sizeof(subscriptions));
	memset(&s_notify, 0, sizeof(s_notify));
	memset(&s_push,   0, sizeof(s_push));
	subscription_count = 0;
	s_push.state = PUSH_IDLE;

	// Initialize mbedTLS RNG (HMAC_DRBG instead of CTR_DRBG for SDK compatibility)
	mbedtls_entropy_init(&entropy);
	mbedtls_hmac_drbg_init(&hmac_drbg);

	/* Register Pico hardware entropy source (ROSC) */
	pico_rand_init();
    pico_register_entropy(&entropy);

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
	switch (s_push.state) {

	case PUSH_IDLE:
		// Start processing when there is a pending notification
		if (!s_notify.pending || subscription_count == 0) return;
		for (int i = 0; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
			if (subscriptions[i].active) {
				start_push_for_sub(i);
				return;
			}
		}
		// No active subscriptions (subscription_count was stale)
		s_notify.pending = false;
		break;

	case PUSH_DNS:
	case PUSH_CONNECTING:
	case PUSH_SENDING:
	case PUSH_RECEIVING:
		// These transitions are driven entirely by lwIP callbacks
		break;

	case PUSH_DONE:
	case PUSH_ERROR: {
		// Clean up the current connection (callbacks may have already done this)
		if (s_push.pcb) {
			if (s_push.state == PUSH_DONE) altcp_close(s_push.pcb);
			else                           altcp_abort(s_push.pcb);
			s_push.pcb = NULL;
		}
		if (s_push.tls_cfg) {
			altcp_tls_free_config(s_push.tls_cfg);
			s_push.tls_cfg = NULL;
		}

		// Advance to the next active subscription
		for (int i = s_push.sub_idx + 1; i < PUSH_MAX_SUBSCRIPTIONS; i++) {
			if (subscriptions[i].active) {
				start_push_for_sub(i);
				return;
			}
		}
		// All subscriptions processed
		s_notify.pending = false;
		s_push.state = PUSH_IDLE;
		printf("push_manager: all notifications processed\n");
		break;
	}

	default:
		break;
	}
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
	if (!vapid_keys_valid) {
		printf("push_manager: VAPID keys not ready\n");
		return;
	}

	printf("push_manager: queuing notification (%d subs) – %s: %s (err=%d)\n",
	       subscription_count, title, body, error_code);

	// Store in single-slot queue (overwrites any previously pending notification)
	s_notify.pending    = true;
	s_notify.error_code = error_code;
	strncpy(s_notify.title, title ? title : "", sizeof(s_notify.title) - 1);
	s_notify.title[sizeof(s_notify.title) - 1] = '\0';
	strncpy(s_notify.body, body ? body : "", sizeof(s_notify.body) - 1);
	s_notify.body[sizeof(s_notify.body) - 1] = '\0';
}

int push_manager_subscription_count(void) {
	return subscription_count;
}

