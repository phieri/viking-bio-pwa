#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "pico/stdlib.h"
#include "lwip/apps/httpd.h"
#include "lwip/apps/fs.h"
#include "lwip/pbuf.h"
#include "http_server.h"
#include "push_manager.h"
#include "wifi_config.h"
#include "version.h"
#include "web_content.h"
#include "flame_counter.h"

// --- Cached data for API responses ---
static viking_bio_data_t s_cached_data = {0};

// Dynamic response buffers (allocated per-connection in fs_open_custom)
static char s_data_json[160];
static char s_vapid_json[128];
static char s_country_json[32];
static char s_subs_json[32];

// POST response buffers
static const char s_ok_json[]    = "{\"status\":\"ok\"}";
static const char s_full_json[]  = "{\"status\":\"full\"}";
static const char s_error_json[] = "{\"error\":\"bad request\"}";

// --- Base64url encoding ---
static const char b64url_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t base64url_encode(const uint8_t *data, size_t len, char *out, size_t out_size) {
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

/**
 * Extract a JSON string value for the given key from a JSON object string.
 */
static bool json_extract_string(const char *json, const char *key,
                                 char *out, size_t out_size) {
	if (!json || !key || !out || out_size == 0) return false;
	out[0] = '\0';

	char search[64];
	snprintf(search, sizeof(search), "\"%s\":", key);
	const char *p = strstr(json, search);
	if (!p) return false;

	p += strlen(search);
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
	if (*p != '"') return false;
	p++;

	const char *end = strchr(p, '"');
	if (!end) return false;

	size_t val_len = (size_t)(end - p);
	if (val_len >= out_size) return false;

	memcpy(out, p, val_len);
	out[val_len] = '\0';
	return true;
}

static bool json_extract_bool(const char *json, const char *key, bool *out) {
	if (!json || !key || !out) return false;
	char search[64];
	snprintf(search, sizeof(search), "\"%s\":", key);
	const char *p = strstr(json, search);
	if (!p) return false;
	p += strlen(search);
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
	if (strncmp(p, "true", 4) == 0) { *out = true; return true; }
	if (strncmp(p, "false", 5) == 0) { *out = false; return true; }
	return false;
}

// --- Update cached data for the /api/data JSON response ---
static void update_data_json(void) {
	snprintf(s_data_json, sizeof(s_data_json),
	         "{\"flame\":%s,\"fan\":%d,\"temp\":%d,\"err\":%d,\"valid\":%s,\"flame_secs\":%u}",
	         s_cached_data.flame_detected ? "true" : "false",
	         s_cached_data.fan_speed,
	         s_cached_data.temperature,
	         s_cached_data.error_code,
	         s_cached_data.valid ? "true" : "false",
	         flame_counter_get_seconds());
}

static void update_vapid_json(void) {
	char key_b64[96] = {0};
	uint8_t key_raw[65];
	if (push_manager_get_vapid_public_key(key_raw)) {
		base64url_encode(key_raw, 65, key_b64, sizeof(key_b64));
	}
	snprintf(s_vapid_json, sizeof(s_vapid_json), "{\"key\":\"%s\"}", key_b64);
}

static void update_subs_json(void) {
	int c = push_manager_subscription_count();
	snprintf(s_subs_json, sizeof(s_subs_json), "{\"count\":%d}", c);
}

static void update_country_json(void) {
	char cc[3] = "XX";
	wifi_config_load_country(cc, sizeof(cc));
	snprintf(s_country_json, sizeof(s_country_json), "{\"country\":\"%s\"}", cc);
}

// --- CGI handlers ---

static const char *cgi_data_handler(int iIndex, int iNumParams,
                                     char *pcParam[], char *pcValue[]) {
	(void)iIndex; (void)iNumParams; (void)pcParam; (void)pcValue;
	update_data_json();
	return "/api_data.json";
}

static const char *cgi_vapid_handler(int iIndex, int iNumParams,
                                      char *pcParam[], char *pcValue[]) {
	(void)iIndex; (void)iNumParams; (void)pcParam; (void)pcValue;
	update_vapid_json();
	return "/api_vapid.json";
}

static const char *cgi_country_handler(int iIndex, int iNumParams,
                                        char *pcParam[], char *pcValue[]) {
	(void)iIndex; (void)iNumParams; (void)pcParam; (void)pcValue;
	update_country_json();
	return "/api_country.json";
}

static const char *cgi_subs_handler(int iIndex, int iNumParams,
									 char *pcParam[], char *pcValue[]) {
	(void)iIndex; (void)iNumParams; (void)pcParam; (void)pcValue;
	update_subs_json();
	return "/api_subs.json";
}

static const tCGI s_cgi_handlers[] = {
	{"/api/data",            cgi_data_handler},
	{"/api/vapid-public-key", cgi_vapid_handler},
	{"/api/country",         cgi_country_handler},
	{"/api/subscribers",     cgi_subs_handler},
};

// --- Custom filesystem (serves embedded web content + dynamic JSON) ---

// Helper: allocate a copy of a static buffer for a per-connection dynamic response
static int fs_open_dynamic(struct fs_file *file, const char *src, size_t src_size) {
	size_t len = strlen(src);
	char *buf = (char *)malloc(len + 1);
	if (!buf) return 0;
	memcpy(buf, src, len + 1);
	file->data = buf;
	file->len = (int)len;
	file->state = buf;
	(void)src_size;
	return 1;
}

int fs_open_custom(struct fs_file *file, const char *name) {
	memset(file, 0, sizeof(struct fs_file));

	// Static web content
	if (strcmp(name, "/index.html") == 0 || strcmp(name, "/") == 0 ||
	    strcmp(name, "/index.shtml") == 0) {
		file->data = INDEX_HTML;
		file->len = (int)strlen(INDEX_HTML);
		return 1;
	}
	if (strcmp(name, "/sw.js") == 0) {
		file->data = SW_JS;
		file->len = (int)strlen(SW_JS);
		return 1;
	}
	if (strcmp(name, "/manifest.json") == 0) {
		file->data = MANIFEST_JSON;
		file->len = (int)strlen(MANIFEST_JSON);
		return 1;
	}
	if (strcmp(name, "/style.css") == 0) {
		file->data = STYLE_CSS;
		file->len = (int)strlen(STYLE_CSS);
		return 1;
	}
	if (strcmp(name, "/app.js") == 0) {
		file->data = APP_JS;
		file->len = (int)strlen(APP_JS);
		return 1;
	}

	// Dynamic JSON responses (served after CGI handler updates the buffer)
	if (strcmp(name, "/api_data.json") == 0)
		return fs_open_dynamic(file, s_data_json, sizeof(s_data_json));
	if (strcmp(name, "/api_vapid.json") == 0)
		return fs_open_dynamic(file, s_vapid_json, sizeof(s_vapid_json));
	if (strcmp(name, "/api_country.json") == 0)
		return fs_open_dynamic(file, s_country_json, sizeof(s_country_json));
	if (strcmp(name, "/api_subs.json") == 0)
		return fs_open_dynamic(file, s_subs_json, sizeof(s_subs_json));

	// POST response files
	if (strcmp(name, "/api_ok.json") == 0) {
		file->data = s_ok_json;
		file->len = (int)strlen(s_ok_json);
		return 1;
	}
	if (strcmp(name, "/api_full.json") == 0) {
		file->data = s_full_json;
		file->len = (int)strlen(s_full_json);
		return 1;
	}
	if (strcmp(name, "/api_error.json") == 0) {
		file->data = s_error_json;
		file->len = (int)strlen(s_error_json);
		return 1;
	}

	return 0;  // Not found
}

void fs_close_custom(struct fs_file *file) {
	if (file && file->state) {
		free(file->state);
		file->state = NULL;
	}
}

#if LWIP_HTTPD_DYNAMIC_FILE_READ
int fs_read_custom(struct fs_file *file, char *buffer, int count) {
	(void)file; (void)buffer; (void)count;
	return FS_READ_EOF;
}
#endif

// --- POST handler state ---
#define MAX_POST_CONNS 4
#define POST_BODY_MAX  512

typedef struct {
	void *connection;
	char uri[32];
	char body[POST_BODY_MAX];
	size_t body_len;
	bool active;
} post_state_t;

static post_state_t s_post_states[MAX_POST_CONNS];

static post_state_t *find_post_state(void *connection) {
	for (int i = 0; i < MAX_POST_CONNS; i++) {
		if (s_post_states[i].active && s_post_states[i].connection == connection)
			return &s_post_states[i];
	}
	return NULL;
}

static post_state_t *alloc_post_state(void *connection) {
	for (int i = 0; i < MAX_POST_CONNS; i++) {
		if (!s_post_states[i].active) {
			memset(&s_post_states[i], 0, sizeof(post_state_t));
			s_post_states[i].connection = connection;
			s_post_states[i].active = true;
			return &s_post_states[i];
		}
	}
	return NULL;
}

err_t httpd_post_begin(void *connection, const char *uri,
                       const char *http_request, u16_t http_request_len,
                       int content_len, char *response_uri,
                       u16_t response_uri_len, u8_t *post_auto_wnd) {
	(void)http_request; (void)http_request_len; (void)content_len;
	(void)response_uri; (void)response_uri_len;

	if (strcmp(uri, "/api/subscribe") == 0 ||
	    strcmp(uri, "/api/unsubscribe") == 0) {
		post_state_t *state = alloc_post_state(connection);
		if (!state) return ERR_MEM;
		snprintf(state->uri, sizeof(state->uri), "%s", uri);
		*post_auto_wnd = 1;
		return ERR_OK;
	}

	return ERR_VAL;
}

err_t httpd_post_receive_data(void *connection, struct pbuf *p) {
	post_state_t *state = find_post_state(connection);
	if (!state) {
		pbuf_free(p);
		return ERR_VAL;
	}

	size_t to_copy = p->tot_len;
	if (state->body_len + to_copy >= POST_BODY_MAX - 1) {
		to_copy = POST_BODY_MAX - 1 - state->body_len;
	}
	if (to_copy > 0) {
		pbuf_copy_partial(p, state->body + state->body_len, (u16_t)to_copy, 0);
		state->body_len += to_copy;
		state->body[state->body_len] = '\0';
	}

	pbuf_free(p);
	return ERR_OK;
}

void httpd_post_finished(void *connection, char *response_uri, u16_t response_uri_len) {
	post_state_t *state = find_post_state(connection);
	if (!state) {
		snprintf(response_uri, response_uri_len, "/api_error.json");
		return;
	}

	if (strcmp(state->uri, "/api/subscribe") == 0) {
		char endpoint[PUSH_MAX_ENDPOINT_LEN] = {0};
		char p256dh[PUSH_MAX_KEY_LEN] = {0};
		char auth[PUSH_MAX_AUTH_LEN] = {0};

		json_extract_string(state->body, "endpoint", endpoint, sizeof(endpoint));
		json_extract_string(state->body, "p256dh", p256dh, sizeof(p256dh));
		json_extract_string(state->body, "auth", auth, sizeof(auth));

		// Preferences (optional)
		bool pref_flame = false, pref_error = false, pref_clean = false;
		json_extract_bool(state->body, "flame", &pref_flame);
		json_extract_bool(state->body, "error", &pref_error);
		json_extract_bool(state->body, "clean", &pref_clean);

		if (endpoint[0]) {
			bool ok = push_manager_add_subscription(endpoint, p256dh, auth, pref_flame, pref_error, pref_clean);
			snprintf(response_uri, response_uri_len,
			         ok ? "/api_ok.json" : "/api_full.json");
		} else {
			snprintf(response_uri, response_uri_len, "/api_error.json");
		}

	} else if (strcmp(state->uri, "/api/unsubscribe") == 0) {
		char endpoint[PUSH_MAX_ENDPOINT_LEN] = {0};
		json_extract_string(state->body, "endpoint", endpoint, sizeof(endpoint));
		if (endpoint[0]) {
			push_manager_remove_subscription(endpoint);
		}
		snprintf(response_uri, response_uri_len, "/api_ok.json");

	} else {
		snprintf(response_uri, response_uri_len, "/api_error.json");
	}

	state->active = false;
}

// --- Public API ---

bool http_server_init(void) {
	// Initialize the VAPID JSON once at startup
	update_vapid_json();
	update_data_json();
	update_country_json();

	// Clear POST states
	memset(s_post_states, 0, sizeof(s_post_states));

	// Register CGI handlers
	http_set_cgi_handlers(s_cgi_handlers,
	                       sizeof(s_cgi_handlers) / sizeof(s_cgi_handlers[0]));

	// Start the lwIP httpd server
	httpd_init();
	printf("HTTP server listening on port %d (lwIP httpd)\n", HTTP_SERVER_PORT);
	return true;
}

void http_server_update_data(const viking_bio_data_t *data) {
	if (!data) return;
	memcpy(&s_cached_data, data, sizeof(s_cached_data));
}

size_t http_server_get_vapid_public_key(char *buf, size_t buf_size) {
	uint8_t key_raw[65];
	if (!push_manager_get_vapid_public_key(key_raw)) return 0;
	return base64url_encode(key_raw, 65, buf, buf_size);
}
