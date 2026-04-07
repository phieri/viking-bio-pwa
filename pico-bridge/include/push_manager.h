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
 * Loads the proxy VAPID public key from flash if previously stored.
 * Must be called once at startup after lfs_hal_init().
 * @return true on success
 */
bool push_manager_init(void);

/**
 * Return the proxy VAPID public key as a base64url-encoded string into out_buf.
 * The key is fetched from the proxy and stored locally; returns an empty string
 * until the first successful webhook response is received.
 * @param out_buf  Output buffer (must be at least 92 bytes)
 * @param buf_len  Size of output buffer
 * @return true if a key is available (non-empty), false otherwise
 */
bool push_manager_get_vapid_public_key(char *out_buf, size_t buf_len);

/**
 * Store the proxy VAPID public key received from the webhook response.
 * Persists the key to LittleFS flash so it survives reboots.
 * @param key  Base64url-encoded VAPID public key (NUL-terminated)
 */
void push_manager_set_proxy_vapid_key(const char *key);

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
 * The notification is delivered asynchronously: call push_manager_poll() from
 * the main loop to drive the HTTPS delivery state machine.
 *
 * @param type   Notification type (used to filter by subscriber preferences)
 * @param title  Notification title
 * @param body   Notification body
 */
void push_manager_notify_all(push_notify_type_t type, const char *title, const char *body);

/**
 * Poll the push notification delivery state machine.
 * Must be called regularly from the main loop (e.g. on every EVENT_BROADCAST).
 * Drives asynchronous HTTPS delivery, handles timeouts, and starts any pending
 * notification once the current delivery is complete.
 */
void push_manager_poll(void);

/**
 * Update the cleaning reminder scheduler.
 * Must be called regularly from the main loop (e.g. on every EVENT_BROADCAST).
 * Accumulates flame-on time and sends a cleaning reminder push notification on
 * Saturday mornings (07:00–07:30) during the heating season (November–March).
 * Requires proxy time-sync (http_client_get_epoch_time() ≥ 1e9).
 *
 * @param flame_on  true if the burner flame is currently detected
 */
void push_manager_tick_scheduler(bool flame_on);

#endif // PUSH_MANAGER_H
