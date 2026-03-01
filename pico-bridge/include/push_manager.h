#ifndef PUSH_MANAGER_H
#define PUSH_MANAGER_H

#include <stdbool.h>
#include <stddef.h>

// Maximum number of push subscriptions (persisted in LittleFS flash)
#define PUSH_MAX_SUBSCRIPTIONS 4

// Maximum length of a push endpoint URL
#define PUSH_ENDPOINT_MAX_LEN  512

// Maximum length of a base64url-encoded p256dh key (65 bytes → ~88 chars)
#define PUSH_P256DH_MAX_LEN    96

// Maximum length of a base64url-encoded auth secret (16 bytes → ~24 chars)
#define PUSH_AUTH_MAX_LEN      32

// VAPID JWT validity period in seconds
#define VAPID_JWT_EXPIRY_SECS  43200  // 12 hours

/**
 * Notification type for per-subscription preference filtering.
 */
typedef enum {
	PUSH_NOTIFY_FLAME = 0,
	PUSH_NOTIFY_ERROR,
	PUSH_NOTIFY_CLEAN,
	PUSH_NOTIFY_TYPE_COUNT,
} push_notify_type_t;

/**
 * A single browser push subscription (cached in RAM, persisted to LittleFS flash).
 */
typedef struct {
	bool   active;
	char   endpoint[PUSH_ENDPOINT_MAX_LEN + 1];
	char   p256dh[PUSH_P256DH_MAX_LEN + 1];
	char   auth[PUSH_AUTH_MAX_LEN + 1];
	bool   prefs[PUSH_NOTIFY_TYPE_COUNT];
} push_subscription_t;

/**
 * Initialise the push manager.
 * Loads or generates VAPID EC P-256 key pair from flash.
 * Must be called once at startup after lfs_hal_init().
 * @return true on success
 */
bool push_manager_init(void);

/**
 * Return the VAPID public key as an uncompressed point (65 bytes), base64url-
 * encoded into out_buf (must be at least 90 bytes).
 * @param out_buf  Output buffer
 * @param buf_len  Size of output buffer
 * @return true on success
 */
bool push_manager_get_vapid_public_key(char *out_buf, size_t buf_len);

/**
 * Add or update a push subscription.
 * The subscription is written to LittleFS flash immediately so it survives reboots.
 * @param endpoint  Push endpoint URL
 * @param p256dh    Browser's ECDH public key (base64url)
 * @param auth      Auth secret (base64url)
 * @param prefs     Notification type preferences (indexed by push_notify_type_t)
 * @return true if added/updated, false if at capacity
 */
bool push_manager_add_subscription(const char *endpoint, const char *p256dh,
                                   const char *auth, const bool prefs[PUSH_NOTIFY_TYPE_COUNT]);

/**
 * Remove a push subscription by endpoint URL.
 * The change is written to LittleFS flash immediately.
 * @param endpoint  Push endpoint URL to remove
 */
void push_manager_remove_subscription(const char *endpoint);

/**
 * Return the number of active push subscriptions.
 */
int push_manager_subscription_count(void);

/**
 * Send a push notification to all subscribers that opted in to the given type.
 *
 * @param type   Notification type (used to filter by subscriber preferences)
 * @param title  Notification title
 * @param body   Notification body
 *
 * NOTE: Outbound HTTPS delivery is a TODO.  This function currently logs the
 * notification only.  TLS client support (pico_lwip_mbedtls) and RFC 8291
 * message encryption must be added to enable actual delivery.
 */
void push_manager_notify_all(push_notify_type_t type, const char *title, const char *body);

#endif // PUSH_MANAGER_H
