#include <string.h>
#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/time.h"
#include "push_manager.h"
#include "http_client.h"
#include "lfs_hal.h"

// LittleFS file for persisted proxy VAPID public key (base64url string)
#define VAPID_PUB_FILE "/vapid_pub.dat"

// Maximum base64url length of a P-256 uncompressed public key (65 bytes → 88 chars)
#define VAPID_PUB_MAX_LEN 88

// LittleFS file for persisted push subscriptions
#define SUBS_FILE  "/subs.dat"

// Subscriptions storage layout (fixed-size flat record array):
//   magic(4) + N×slot + crc32(4)
// Each slot: active(1) + endpoint(513) + p256dh(97) + auth(33) + prefs(3) = 647 bytes
#define SUBS_MAGIC     0x53554253U  // "SUBS"
#define SUBS_SLOT_SIZE (1 + (PUSH_ENDPOINT_MAX_LEN + 1) + (PUSH_P256DH_MAX_LEN + 1) + \
                        (PUSH_AUTH_MAX_LEN + 1) + PUSH_NOTIFY_TYPE_COUNT)
#define SUBS_STORED    (4 + SUBS_SLOT_SIZE * PUSH_MAX_SUBSCRIPTIONS + 4)

// Proxy VAPID public key (base64url-encoded, fetched from the proxy on first webhook response)
static char s_proxy_vapid_pub[VAPID_PUB_MAX_LEN + 1];

// In-memory subscription cache (loaded from /subs.dat on init, persisted on change)
static push_subscription_t s_subs[PUSH_MAX_SUBSCRIPTIONS];

// ---------------------------------------------------------------------------
// Push delivery state machine
// ---------------------------------------------------------------------------

typedef enum {
	PUSH_STATE_IDLE = 0,
} push_state_t;

typedef struct {
	push_state_t        state;
	int                 sub_idx;
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

// ---------------------------------------------------------------------------
// Cleaning reminder scheduler state
// ---------------------------------------------------------------------------

// Accumulated flame-on seconds since the last cleaning reminder was sent
static uint32_t s_flame_secs_since_reminder = 0;
// Boot-relative seconds when flame tracking was last updated; 0 = not tracking
static uint32_t s_last_flame_boot_s = 0;
// Unix-epoch day (epoch/86400) when the last reminder was sent; 0 = never
static uint32_t s_last_reminder_epoch_day = 0;

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
// Delivery state machine – per-subscriber delivery setup
// ---------------------------------------------------------------------------

static void push_advance_to_next_sub(void);
static void push_start_delivery_for_sub(int sub_idx);

static void push_advance_to_next_sub(void) {
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
	s_ctx.sub_idx = sub_idx;

	// VAPID JWT signing requires the private key, which is managed exclusively
	// by the proxy. Direct push delivery from the bridge is not supported.
	// Subscriptions are delivered by the proxy when it receives webhook data.
	printf("push_manager: direct push delivery not supported (VAPID private key is proxy-only)\n");
	push_advance_to_next_sub();
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
	memset(s_proxy_vapid_pub, 0, sizeof(s_proxy_vapid_pub));

	// Load the proxy VAPID public key if previously stored in flash.
	// The key will be refreshed on the next successful webhook response.
	char buf[VAPID_PUB_MAX_LEN + 2];
	int n = lfs_hal_read_file(VAPID_PUB_FILE, buf, sizeof(buf) - 1);
	if (n > 0 && n <= VAPID_PUB_MAX_LEN) {
		buf[n] = '\0';
		// Validate: key should be non-empty base64url characters
		bool valid = true;
		for (int i = 0; i < n; i++) {
			char c = buf[i];
			if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			      (c >= '0' && c <= '9') || c == '-' || c == '_')) {
				valid = false;
				break;
			}
		}
		if (valid) {
			memcpy(s_proxy_vapid_pub, buf, (size_t)n + 1);
			printf("push_manager: loaded proxy VAPID public key from flash\n");
		}
	}

	load_subscriptions();
	return true;
}

bool push_manager_get_vapid_public_key(char *out_buf, size_t buf_len) {
	if (!out_buf || buf_len == 0) return false;
	size_t key_len = strlen(s_proxy_vapid_pub);
	if (key_len == 0 || key_len >= buf_len) return false;
	memcpy(out_buf, s_proxy_vapid_pub, key_len + 1);
	return true;
}

void push_manager_set_proxy_vapid_key(const char *key) {
	if (!key || key[0] == '\0') return;
	size_t key_len = strlen(key);
	if (key_len > VAPID_PUB_MAX_LEN) {
		printf("push_manager: proxy VAPID key too long (%u > %d)\n",
		       (unsigned)key_len, VAPID_PUB_MAX_LEN);
		return;
	}
	if (strcmp(s_proxy_vapid_pub, key) == 0) return;  // already up to date
	memcpy(s_proxy_vapid_pub, key, key_len + 1);
	if (!lfs_hal_write_file(VAPID_PUB_FILE, key, key_len)) {
		printf("push_manager: WARNING – could not persist proxy VAPID key\n");
	} else {
		printf("push_manager: proxy VAPID public key updated and stored\n");
	}
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
	// Start a pending notification once the current delivery is complete
	if (s_ctx.state == PUSH_STATE_IDLE && s_pending.valid) {
		s_pending.valid = false;
		push_notify_start(s_pending.type, s_pending.title, s_pending.body);
	}
}

// ---------------------------------------------------------------------------
// Cleaning reminder scheduler
// ---------------------------------------------------------------------------

/**
 * Decompose a Unix epoch timestamp into calendar fields.
 *
 * @param epoch   Seconds since 1970-01-01 00:00:00 UTC
 * @param month   Output: 0=Jan .. 11=Dec
 * @param dow     Output: 0=Sun .. 6=Sat
 * @param hour    Output: 0-23
 * @param min     Output: 0-59
 *
 * Uses Howard Hinnant's civil_from_days algorithm for the month/year part.
 */
static void epoch_to_fields(uint32_t epoch,
                             int *month, int *dow, int *hour, int *min)
{
	*hour = (int)((epoch % 86400UL) / 3600UL);
	*min  = (int)((epoch % 3600UL)  / 60UL);
	/* 1970-01-01 was a Thursday = day 4 in Sun=0 scheme */
	*dow = (int)((epoch / 86400UL + 4UL) % 7UL);

	/*
	 * Month from epoch days using the civil calendar (March-based era):
	 *   mp=0→Mar, mp=1→Apr, …, mp=9→Dec, mp=10→Jan, mp=11→Feb
	 * Final mapping: mp<10 → mp+2 (Mar–Dec), mp>=10 → mp-10 (Jan–Feb)
	 *
	 * 719468 is the number of days from the civil epoch (0000-03-01)
	 * to the Unix epoch (1970-01-01).  The era length is 146097 days
	 * (400 Gregorian years); the 146096 in the yoe term is intentional
	 * – it fires the 400-year leap correction only on the last day of
	 * each era (day 146096).  See: Howard Hinnant, "date_algorithms.html".
	 */
	uint32_t z   = epoch / 86400UL + 719468UL;
	uint32_t era = z / 146097UL;
	uint32_t doe = z - era * 146097UL;
	uint32_t yoe = (doe - doe / 1460UL + doe / 36524UL - doe / 146096UL) / 365UL;
	uint32_t doy = doe - (365UL * yoe + yoe / 4UL - yoe / 100UL);
	uint32_t mp  = (5UL * doy + 2UL) / 153UL;
	*month = (int)(mp < 10UL ? mp + 2UL : mp - 10UL);
}

/**
 * Format a flame-on duration as a short ASCII string,
 * e.g. "3 h 25 min" or "45 min" or "2 h".
 */
static void format_flame_secs(uint32_t secs, char *buf, size_t buf_len)
{
	unsigned h = (unsigned)(secs / 3600U);
	unsigned m = (unsigned)((secs % 3600U) / 60U);
	if (h == 0) {
		snprintf(buf, buf_len, "%u min", m);
	} else if (m == 0) {
		snprintf(buf, buf_len, "%u h", h);
	} else {
		snprintf(buf, buf_len, "%u h %u min", h, m);
	}
}

void push_manager_tick_scheduler(bool flame_on)
{
	uint32_t now_boot_s =
		(uint32_t)(to_us_since_boot(get_absolute_time()) / 1000000ULL);

	/* Accumulate flame-on time since the previous tick */
	if (flame_on && s_last_flame_boot_s != 0) {
		s_flame_secs_since_reminder += now_boot_s - s_last_flame_boot_s;
	}
	s_last_flame_boot_s = flame_on ? now_boot_s : 0;

	/* Epoch must be proxy-synced before we can check the calendar */
	uint32_t epoch = http_client_get_epoch_time();
	if (epoch < 1000000000UL) return;

	int month, dow, hour, min;
	epoch_to_fields(epoch, &month, &dow, &hour, &min);

	/* Heating season: November (10), December (11), January (0), February (1), March (2) */
	bool in_season = (month == 10 || month == 11 ||
	                  month == 0  || month == 1  || month == 2);
	/* Saturday 07:00–07:29 */
	bool is_sat_morning = (dow == 6 && hour == 7 && min < 30);

	if (!in_season || !is_sat_morning) return;

	/* Send at most once per week (debounce within the 30-minute window) */
	uint32_t today = epoch / 86400UL;
	if (s_last_reminder_epoch_day != 0 &&
	    today - s_last_reminder_epoch_day < 7) return;

	/* Build and send the notification */
	char time_str[32];
	format_flame_secs(s_flame_secs_since_reminder, time_str, sizeof(time_str));
	char body[128];
	snprintf(body, sizeof(body),
	         "Clean the burner. Flame-on since last reminder: %s.", time_str);

	printf("push_manager: sending cleaning reminder (flame-on: %s)\n", time_str);
	push_manager_notify_all(PUSH_NOTIFY_CLEAN,
	                        "Viking Bio: Cleaning Reminder", body);

	/* Reset accumulator and record this week as done */
	s_flame_secs_since_reminder = 0;
	s_last_flame_boot_s = flame_on ? now_boot_s : 0;
	s_last_reminder_epoch_day = today;
}
