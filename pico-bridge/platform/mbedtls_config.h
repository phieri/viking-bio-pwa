/**
 * @file mbedtls_config.h
 * @brief mbedTLS configuration for Viking Bio Bridge firmware (Pico W)
 *
 * Enables:
 *   - AES-128-GCM + SHA-256 for WiFi credential encryption
 *   - ECC P-256 (ECDH + ECDSA + CTR-DRBG + Entropy) for VAPID key generation/signing
 *   - HKDF for RFC 8291 Web Push message encryption key derivation
 *   - TLS 1.2 client (ECDHE-ECDSA, ECDHE-RSA) for HTTPS push delivery via altcp_tls
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// Allow access to private struct members (required in mbedTLS 3.x)
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

// System support
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_FREE_MACRO     free
#define MBEDTLS_PLATFORM_CALLOC_MACRO   calloc

// Enable time support (Pico SDK provides mbedtls_time())
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_PLATFORM_MS_TIME_ALT

// No platform entropy (RP2040 uses hardware RNG directly via CTR-DRBG)
#define MBEDTLS_NO_PLATFORM_ENTROPY

// Core crypto modules needed for WiFi credential encryption
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_GCM_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C

// SHA-1 (required for X.509 certificate parsing of legacy hash fields)
#define MBEDTLS_SHA1_C

// Big-number arithmetic (required by ECC and RSA)
#define MBEDTLS_BIGNUM_C

// ECC P-256 for VAPID key generation, signing, and ECDHE key exchange
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECDH_C

// ECDSA for VAPID JWT signing (ES256) and ECDHE-ECDSA TLS key exchange
#define MBEDTLS_ECDSA_C

// Deterministic RNG seeded from hardware entropy (required for key generation)
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

// Base64 encoding for VAPID public key export and JWT building
#define MBEDTLS_BASE64_C

// HKDF for RFC 8291 Web Push message encryption key derivation
#define MBEDTLS_HKDF_C

// ASN.1 encoding/parsing (required by ECDSA and X.509)
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C

// OID lookup (required by X.509 and public key abstraction)
#define MBEDTLS_OID_C

// Public key abstraction (required by TLS and X.509)
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C

// RSA (needed for ECDHE-RSA cipher suites used by most push services)
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15

// X.509 certificate parsing (needed to parse server cert during TLS handshake)
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

// TLS 1.2 protocol stack for HTTPS push delivery via pico_lwip_mbedtls
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2

// Supported key exchange methods (ECDHE-ECDSA for P-256 servers, ECDHE-RSA for RSA servers)
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED

// Server Name Indication (SNI) for HTTPS connections to push services
#define MBEDTLS_SSL_SERVER_NAME_INDICATION

// TLS I/O buffer sizes (reduced from default 16 KB to save RAM on the Pico W)
// 8 KB input is sufficient for the server certificate during TLS handshake;
// 2 KB output is sufficient for ClientHello and the push HTTP POST request.
#define MBEDTLS_SSL_IN_CONTENT_LEN  8192
#define MBEDTLS_SSL_OUT_CONTENT_LEN 2048

#endif /* MBEDTLS_CONFIG_H */
