/**
 * @file mbedtls_config.h
 * @brief Minimal mbedTLS configuration for Viking Bio Bridge firmware (Pico W)
 *
 * Enables:
 *   - AES-128-GCM + SHA-256 for WiFi credential encryption
 *   - ECC P-256 (ECDH + CTR-DRBG + Entropy) for VAPID key generation
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

// Big-number arithmetic (required by ECC)
#define MBEDTLS_BIGNUM_C

// ECC P-256 for VAPID key generation and signing
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECDH_C

// Deterministic RNG seeded from hardware entropy (required for key generation)
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

// Base64 encoding for VAPID public key export
#define MBEDTLS_BASE64_C

#endif /* MBEDTLS_CONFIG_H */
