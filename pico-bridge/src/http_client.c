#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "pico/time.h"
#include "lwip/tcp.h"
#include "lwip/ip_addr.h"
#include "lwip/dns.h"
#include "http_client.h"
#include "wifi_config.h"

typedef enum {
	HTTP_STATE_IDLE,
	HTTP_STATE_RESOLVING,
	HTTP_STATE_CONNECTING,
	HTTP_STATE_SENDING,
	HTTP_STATE_READING,
	HTTP_STATE_RETRY_WAIT,
} http_state_t;

// Webhook path (fixed)
#define WEBHOOK_PATH "/api/machine-data"

// Auth token max length matches WIFI_HOOK_TOKEN_MAX_LEN
#define HTTP_AUTH_TOKEN_MAX 64

// Maximum request size: headers + JSON body
#define HTTP_REQUEST_MAX 512

// Response buffer (large enough for the status line + JSON body with server_time)
#define HTTP_RESPONSE_MAX 256

static struct tcp_pcb *s_pcb = NULL;
static http_state_t s_state = HTTP_STATE_IDLE;

static char s_host[WIFI_SERVER_IP_MAX_LEN + 1];
static uint16_t s_port;
static char s_auth_token[HTTP_AUTH_TOKEN_MAX + 1];

static ip_addr_t s_server_addr;
static absolute_time_t s_timeout;
static absolute_time_t s_retry_time;

// Pending request buffer (latest data to send)
static char s_request[HTTP_REQUEST_MAX];
static size_t s_request_len = 0;
static bool s_has_pending = false;

// Response accumulation
static char s_response[HTTP_RESPONSE_MAX];
static size_t s_response_len = 0;

// Epoch time tracking: offset from seconds-since-boot to Unix epoch.
// Initialised to BUILD_UNIX_TIME at compile time as an approximation;
// updated to the exact value whenever the proxy responds with server_time.
static int64_t s_epoch_offset = BUILD_UNIX_TIME;

// Minimum plausible Unix epoch value (September 9, 2001 01:46:40 UTC)
#define MIN_VALID_EPOCH_SECS 1000000000UL

// Forward declarations
static void do_connect(void);
static void abort_and_retry(void);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Returns true when host is a bare IPv6 address (contains ':' but no '[').
 * Used to wrap it in brackets for the HTTP Host header.
 */
static bool is_bare_ipv6(const char *host) {
	return (strchr(host, ':') != NULL) && (host[0] != '[');
}

/**
 * Build the HTTP POST request into s_request.
 * @param body  JSON body string
 * @return length of the request, or 0 on overflow
 */
static size_t build_request(const char *body) {
	// Wrap bare IPv6 addresses in brackets for the Host header.
	// Buffer: "[" + addr(max 46) + "]:" + port(max 5 digits) + null = 55 bytes; +8 for safety.
	// Note: IPv6 zone IDs (e.g. fe80::1%eth0) are not supported by ipaddr_aton; users
	// should configure link-local addresses without zone IDs (routing via the default interface).
	char host_header[WIFI_SERVER_IP_MAX_LEN + 8];
	if (is_bare_ipv6(s_host)) {
		snprintf(host_header, sizeof(host_header), "[%s]:%u", s_host, (unsigned)s_port);
	} else {
		snprintf(host_header, sizeof(host_header), "%s:%u", s_host, (unsigned)s_port);
	}

	size_t body_len = strlen(body);

	int len;
	if (s_auth_token[0] != '\0') {
		len = snprintf(s_request, sizeof(s_request),
			"POST " WEBHOOK_PATH " HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Content-Type: application/json\r\n"
			"X-Hook-Auth: %s\r\n"
			"Content-Length: %u\r\n"
			"Connection: close\r\n"
			"\r\n"
			"%s",
			host_header, s_auth_token, (unsigned)body_len, body);
	} else {
		len = snprintf(s_request, sizeof(s_request),
			"POST " WEBHOOK_PATH " HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Content-Type: application/json\r\n"
			"Content-Length: %u\r\n"
			"Connection: close\r\n"
			"\r\n"
			"%s",
			host_header, (unsigned)body_len, body);
	}

	if (len <= 0 || len >= (int)sizeof(s_request)) return 0;
	return (size_t)len;
}

// ---------------------------------------------------------------------------
// lwIP callbacks
// ---------------------------------------------------------------------------

static err_t tcp_connected_cb(void *arg, struct tcp_pcb *pcb, err_t err) {
	(void)arg;
	if (err != ERR_OK || pcb == NULL) {
		abort_and_retry();
		return err;
	}

	s_state = HTTP_STATE_SENDING;
	s_timeout = make_timeout_time_ms(HTTP_CLIENT_TIMEOUT_MS);
	printf("http_client: connected to %s:%d – sending request\n", s_host, s_port);

	if (s_request_len > 0) {
		err_t e = tcp_write(s_pcb, s_request, (u16_t)s_request_len, TCP_WRITE_FLAG_COPY);
		if (e == ERR_OK) {
			tcp_output(s_pcb);
			s_state = HTTP_STATE_READING;
		} else {
			printf("http_client: tcp_write failed (%d)\n", (int)e);
			abort_and_retry();
		}
	} else {
		abort_and_retry();
	}
	return ERR_OK;
}

static err_t tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
	(void)arg; (void)err;
	if (p == NULL) {
		// Server closed connection – parse status line and optional server_time
		s_response[s_response_len] = '\0';
		if (s_response_len > 0) {
			// Extract status code from "HTTP/1.x NNN ..."
			const char *sp = strchr(s_response, ' ');
			if (sp) {
				int code = atoi(sp + 1);
				if (code >= 200 && code < 300) {
					printf("http_client: POST OK (%d)\n", code);
				} else {
					printf("http_client: POST returned %d\n", code);
				}
			}
			// Extract server_time from JSON body for system-time synchronisation
			const char *st = strstr(s_response, "\"server_time\":");
			if (st) {
				st += 14;
				while (*st == ' ') st++;
				char *end_ptr;
				unsigned long server_time = strtoul(st, &end_ptr, 10);
				if (end_ptr != st && server_time >= MIN_VALID_EPOCH_SECS) {
					uint32_t elapsed_s = (uint32_t)(to_us_since_boot(get_absolute_time()) / 1000000ULL);
					s_epoch_offset = (int64_t)server_time - (int64_t)elapsed_s;
					printf("http_client: time synced (server_time=%lu)\n",
					       server_time);
				}
			}
		}
		s_pcb = NULL;
		s_state = HTTP_STATE_IDLE;
		s_has_pending = false;
		return ERR_OK;
	}

	// Accumulate up to s_response capacity (just need the status line)
	if (s_response_len < sizeof(s_response) - 1) {
		size_t copy = p->tot_len;
		if (copy > sizeof(s_response) - 1 - s_response_len)
			copy = sizeof(s_response) - 1 - s_response_len;
		pbuf_copy_partial(p, s_response + s_response_len, (u16_t)copy, 0);
		s_response_len += copy;
	}

	tcp_recved(pcb, p->tot_len);
	pbuf_free(p);
	return ERR_OK;
}

static void tcp_err_cb(void *arg, err_t err) {
	(void)arg; (void)err;
	printf("http_client: TCP error %d – retrying\n", (int)err);
	s_pcb = NULL;
	s_state = HTTP_STATE_RETRY_WAIT;
	s_retry_time = make_timeout_time_ms(HTTP_CLIENT_RETRY_MS);
}

static void dns_found_cb(const char *name, const ip_addr_t *addr, void *arg) {
	(void)name; (void)arg;
	if (addr == NULL) {
		printf("http_client: DNS lookup failed\n");
		s_state = HTTP_STATE_RETRY_WAIT;
		s_retry_time = make_timeout_time_ms(HTTP_CLIENT_RETRY_MS);
		return;
	}
	s_server_addr = *addr;
	do_connect();
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static void abort_and_retry(void) {
	if (s_pcb != NULL) {
		tcp_abort(s_pcb);
		s_pcb = NULL;
	}
	s_state = HTTP_STATE_RETRY_WAIT;
	s_retry_time = make_timeout_time_ms(HTTP_CLIENT_RETRY_MS);
}

static void do_connect(void) {
	s_pcb = tcp_new_ip_type(IP_GET_TYPE(&s_server_addr));
	if (s_pcb == NULL) {
		printf("http_client: tcp_new failed\n");
		s_state = HTTP_STATE_RETRY_WAIT;
		s_retry_time = make_timeout_time_ms(HTTP_CLIENT_RETRY_MS);
		return;
	}
	tcp_err(s_pcb, tcp_err_cb);
	tcp_recv(s_pcb, tcp_recv_cb);
	s_state = HTTP_STATE_CONNECTING;
	s_timeout = make_timeout_time_ms(HTTP_CLIENT_TIMEOUT_MS);
	err_t err = tcp_connect(s_pcb, &s_server_addr, s_port, tcp_connected_cb);
	if (err != ERR_OK) {
		printf("http_client: tcp_connect failed (%d)\n", (int)err);
		tcp_close(s_pcb);
		s_pcb = NULL;
		s_state = HTTP_STATE_RETRY_WAIT;
		s_retry_time = make_timeout_time_ms(HTTP_CLIENT_RETRY_MS);
	}
}

static void start_connect(void) {
	s_response_len = 0;
	// Try to parse as numeric IP first
	if (ipaddr_aton(s_host, &s_server_addr)) {
		do_connect();
		return;
	}
	// Fall back to DNS
	s_state = HTTP_STATE_RESOLVING;
	err_t err = dns_gethostbyname(s_host, &s_server_addr, dns_found_cb, NULL);
	if (err == ERR_OK) {
		do_connect();
	} else if (err != ERR_INPROGRESS) {
		printf("http_client: DNS error %d\n", (int)err);
		s_state = HTTP_STATE_RETRY_WAIT;
		s_retry_time = make_timeout_time_ms(HTTP_CLIENT_RETRY_MS);
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void http_client_init(const char *host, uint16_t port, const char *auth_token) {
	snprintf(s_host, sizeof(s_host), "%s", host ? host : "");
	s_port = port;
	snprintf(s_auth_token, sizeof(s_auth_token), "%s", auth_token ? auth_token : "");
	s_state = HTTP_STATE_IDLE;
	s_has_pending = false;
	s_request_len = 0;
	s_pcb = NULL;
	memset(&s_server_addr, 0, sizeof(s_server_addr));
}

void http_client_send_data(const viking_bio_data_t *data) {
	if (data == NULL) return;

	// Build JSON body
	char body[128];
	int blen = snprintf(body, sizeof(body),
		"{\"flame\":%s,\"fan\":%d,\"temp\":%d,\"err\":%d,\"valid\":%s}",
		data->flame_detected ? "true" : "false",
		data->fan_speed,
		data->temperature,
		data->error_code,
		data->valid ? "true" : "false");
	if (blen <= 0 || blen >= (int)sizeof(body)) return;

	// Build full HTTP request
	size_t rlen = build_request(body);
	if (rlen == 0) {
		printf("http_client: request buffer overflow\n");
		return;
	}

	s_request_len = rlen;
	s_has_pending = true;

	// If idle, start a new connection immediately
	if (s_state == HTTP_STATE_IDLE && s_host[0] != '\0' && s_port != 0) {
		printf("http_client: connecting to %s:%d\n", s_host, s_port);
		start_connect();
	}
}

void http_client_poll(void) {
	// Check for connection/response timeout
	if ((s_state == HTTP_STATE_CONNECTING || s_state == HTTP_STATE_READING ||
	     s_state == HTTP_STATE_SENDING) && time_reached(s_timeout)) {
		printf("http_client: timeout – retrying\n");
		abort_and_retry();
	}

	// Retry after backoff
	if (s_state == HTTP_STATE_RETRY_WAIT && time_reached(s_retry_time)) {
		s_state = HTTP_STATE_IDLE;
		// Re-send pending data if any
		if (s_has_pending && s_host[0] != '\0' && s_port != 0) {
			printf("http_client: retrying POST to %s:%d\n", s_host, s_port);
			start_connect();
		}
	}
}

bool http_client_is_active(void) {
	return s_state != HTTP_STATE_IDLE && s_state != HTTP_STATE_RETRY_WAIT;
}

uint32_t http_client_get_epoch_time(void) {
	uint32_t elapsed_s = (uint32_t)(to_us_since_boot(get_absolute_time()) / 1000000ULL);
	return (uint32_t)(s_epoch_offset + (int64_t)elapsed_s);
}
