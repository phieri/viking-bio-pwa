/**
 * @file mbedtls_config.h
 * @brief mbedTLS configuration for Viking Bio PWA firmware (Pico W)
 *
 * Minimal mbedTLS configuration enabling ECP (P-256) for VAPID key generation
 * and SHA-256/HKDF for Web Push payload encryption.
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// Allow access to private struct members (required for ECP operations in mbedTLS 3.x)
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

// System support
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_FREE_MACRO     free
#define MBEDTLS_PLATFORM_CALLOC_MACRO   calloc

// No platform entropy (RP2040 uses hardware RNG directly)
#define MBEDTLS_NO_PLATFORM_ENTROPY

// Core crypto modules
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_GCM_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PKCS5_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C

// Cipher modes
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR

// ECP curve for VAPID (P-256 / secp256r1)
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED

// Key exchange
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED

// SSL/TLS client support (for outbound HTTPS push notifications)
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C

// Reduce TLS I/O buffer sizes to conserve RAM on RP2040 (264 KB total)
#define MBEDTLS_SSL_IN_CONTENT_LEN  4096
#define MBEDTLS_SSL_OUT_CONTENT_LEN 2048

#endif /* MBEDTLS_CONFIG_H */
