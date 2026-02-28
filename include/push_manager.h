#ifndef PUSH_MANAGER_H
#define PUSH_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Maximum number of stored push subscriptions
#define PUSH_MAX_SUBSCRIPTIONS 4

// Maximum URL length for push endpoint
#define PUSH_MAX_ENDPOINT_LEN 256

// Maximum key length (base64url-encoded P-256 key: 88 bytes)
#define PUSH_MAX_KEY_LEN 88

// Maximum auth secret length (base64url-encoded 16 bytes: 24 bytes)
#define PUSH_MAX_AUTH_LEN 24

// Push subscription structure
typedef struct {
	bool active;
	char endpoint[PUSH_MAX_ENDPOINT_LEN];
	char p256dh[PUSH_MAX_KEY_LEN];  // Browser's P-256 public key (base64url)
	char auth[PUSH_MAX_AUTH_LEN];   // Auth secret (base64url)
    // Preferences: which notification types this subscriber wants
    bool pref_flame;
    bool pref_error;
    bool pref_clean;
} push_subscription_t;

/**
 * Initialize the push manager
 * Generates or loads VAPID keys from flash
 * @return true on success, false on failure
 */
bool push_manager_init(void);

/**
 * Poll the push manager (call from main loop)
 * Handles pending outbound HTTPS requests
 */
void push_manager_poll(void);

/**
 * Get the VAPID public key in uncompressed X9.62 format (65 bytes)
 * @param key_buf Output buffer (must be at least 65 bytes)
 * @return true on success
 */
bool push_manager_get_vapid_public_key(uint8_t *key_buf);

/**
 * Add a push subscription
 * @param endpoint Push endpoint URL
 * @param p256dh Browser P-256 public key (base64url)
 * @param auth Auth secret (base64url)
 * @return true if added successfully, false if storage full
 */
bool push_manager_add_subscription(const char *endpoint, const char *p256dh, const char *auth,
								   bool pref_flame, bool pref_error, bool pref_clean);

/**
 * Remove a push subscription by endpoint
 * @param endpoint Push endpoint URL to remove
 * @return true if found and removed
 */
bool push_manager_remove_subscription(const char *endpoint);

/**
 * Send a push notification to all subscribers
 * @param title Notification title
 * @param body Notification body
 * @param error_code Error code (0 for info, non-zero for error)
 */
void push_manager_notify_all(const char *title, const char *body, uint8_t error_code);
/**
 * Queue a notification with an explicit type (0:onoff,1:error,2:clean)
 */
void push_manager_notify_type(const char *title, const char *body, uint8_t type, uint8_t error_code);

/**
 * Get number of active subscriptions
 * @return Number of active subscriptions
 */
int push_manager_subscription_count(void);

#endif // PUSH_MANAGER_H
