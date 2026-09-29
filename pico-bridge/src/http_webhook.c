/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pico/cyw43_arch.h"
#include "pico/time.h"
#include "pico/stdlib.h"
#include "lwip/dns.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"
#include "mbedtls/ssl.h"

#include "http_webhook.h"
#include "http_webhook_hostname.h"
#include "http_webhook_response.h"
#include "lfs_hal.h"
#include "wifi_config.h"

#define WEBHOOK_RETRY_MS 30000
#define WEBHOOK_TIMEOUT_MS 10000
#define WEBHOOK_QUEUE_LEN 4
#define WEBHOOK_JSON_MAX 384
#define WEBHOOK_BODY_MAX 512
#define WEBHOOK_HEARTBEAT_INTERVAL_MS (24ULL * 60ULL * 60ULL * 1000ULL)

typedef enum {
	WEBHOOK_STATE_IDLE,
	WEBHOOK_STATE_RESOLVING,
	WEBHOOK_STATE_CONNECTING,
	WEBHOOK_STATE_WAIT_RESPONSE,
	WEBHOOK_STATE_RETRY_WAIT,
} http_webhook_state_t;

static struct altcp_pcb *s_pcb = NULL;
static struct altcp_tls_config *s_tls_config = NULL;
static uint8_t s_ca[WIFI_WEBHOOK_CA_MAX_LEN + 1];
static size_t s_ca_len = 0;
static http_webhook_state_t s_state = WEBHOOK_STATE_IDLE;
static bool s_lwip_ready = false;

static void send_http_request(void);
static void webhook_err_cb(void *arg, err_t err);
static bool build_payload(const vikingbio_data_t *data, const char *type, const char *detail,
						  char *out, size_t out_len);

static char s_host[WIFI_SERVER_IP_MAX_LEN + 1];
static char s_path[128];
static char s_auth_token[129];
static uint16_t s_port = 80;
static bool s_https = false;
static webhook_response_t s_response;

static ip_addr_t s_server_addr;
static uintptr_t s_dns_generation = 0;
static absolute_time_t s_timeout;
static absolute_time_t s_retry_time;

static char s_queue[WEBHOOK_QUEUE_LEN][WEBHOOK_BODY_MAX];
static size_t s_queue_head = 0;
static size_t s_queue_count = 0;
static uint64_t s_last_heartbeat_ms = 0;
static uint64_t s_flame_on_ms_since_last_heartbeat = 0;
static uint64_t s_last_flame_transition_ms = 0;
static bool s_last_flame_state_known = false;
static bool s_last_flame_state = false;

static bool queue_push(const char *json);

static bool read_wifi_rssi(int *rssi_dbm) {
	if (rssi_dbm == NULL) {
		return false;
	}
	*rssi_dbm = INT_MIN;
	if (s_lwip_ready) cyw43_arch_lwip_begin();
	bool link_up = netif_default != NULL && netif_is_up(netif_default) &&
				   netif_is_link_up(netif_default);
	if (s_lwip_ready) cyw43_arch_lwip_end();
	if (!link_up) {
		return false;
	}

	int rssi = cyw43_wifi_get_rssi(&cyw43_state, 0);
	if (rssi >= 0) {
		return false;
	}
	*rssi_dbm = rssi;
	return true;
}

static void record_heartbeat_sent(void) {
	uint64_t now_ms = to_ms_since_boot(get_absolute_time());
	s_last_heartbeat_ms = now_ms;
	s_last_flame_transition_ms = now_ms;
	s_flame_on_ms_since_last_heartbeat = 0ULL;
}

static bool should_send_heartbeat(void) {
	if (s_host[0] == '\0') {
		return false;
	}
	uint64_t now_ms = to_ms_since_boot(get_absolute_time());
	return now_ms - s_last_heartbeat_ms >= WEBHOOK_HEARTBEAT_INTERVAL_MS;
}

static void update_flame_activity(bool flame_on, uint64_t now_ms) {
	if (!s_last_flame_state_known) {
		s_last_flame_state = flame_on;
		s_last_flame_state_known = true;
		s_last_flame_transition_ms = now_ms;
		return;
	}

	if (s_last_flame_state != flame_on) {
		if (s_last_flame_state) {
			s_flame_on_ms_since_last_heartbeat += now_ms - s_last_flame_transition_ms;
		}
		s_last_flame_state = flame_on;
		s_last_flame_transition_ms = now_ms;
	}
}

static void commit_heartbeat_summary(uint64_t now_ms, bool flame_on) {
	if (!s_last_flame_state_known) {
		s_last_flame_state = flame_on;
		s_last_flame_state_known = true;
		s_last_flame_transition_ms = now_ms;
		if (flame_on && s_last_heartbeat_ms > 0ULL) {
			s_flame_on_ms_since_last_heartbeat = now_ms - s_last_heartbeat_ms;
		} else {
			s_flame_on_ms_since_last_heartbeat = 0ULL;
		}
		return;
	}

	if (s_last_flame_state) {
		s_flame_on_ms_since_last_heartbeat += now_ms - s_last_flame_transition_ms;
	}
	s_last_flame_transition_ms = now_ms;
	s_last_flame_state = flame_on;
}

static bool queue_heartbeat(void) {
	vikingbio_data_t snapshot = {0};
	vikingbio_get_current_data(&snapshot);
	uint64_t now_ms = to_ms_since_boot(get_absolute_time());
	commit_heartbeat_summary(now_ms, snapshot.flame_detected);
	char payload[WEBHOOK_BODY_MAX];
	if (!build_payload(&snapshot, "heartbeat", "alive", payload, sizeof(payload))) {
		printf("webhook: failed to build heartbeat payload\n");
		return false;
	}
	cyw43_arch_lwip_begin();
	bool queued = queue_push(payload);
	cyw43_arch_lwip_end();
	if (!queued) {
		printf("webhook: failed to queue heartbeat payload\n");
		return false;
	}
	record_heartbeat_sent();
	return true;
}

static void abort_connection(void) {
	if (s_pcb != NULL) {
		struct altcp_pcb *pcb = s_pcb;
		s_pcb = NULL;
		altcp_err(pcb, NULL);
		altcp_abort(pcb);
	}
	if (s_tls_config) {
		altcp_tls_free_config(s_tls_config);
		s_tls_config = NULL;
	}
}

static void clear_queue(void) {
	s_queue_head = 0;
	s_queue_count = 0;
}

static bool queue_push(const char *json) {
	if (json == NULL || json[0] == '\0') {
		return false;
	}
	if (s_queue_count >= WEBHOOK_QUEUE_LEN) {
		printf("webhook: queue full, dropping new alert\n");
		return false;
	}

	size_t slot = (s_queue_head + s_queue_count) % WEBHOOK_QUEUE_LEN;
	snprintf(s_queue[slot], sizeof(s_queue[slot]), "%s", json);
	s_queue_count++;
	return true;
}

static const char *queue_peek(void) {
	if (s_queue_count == 0) {
		return NULL;
	}
	return s_queue[s_queue_head];
}

static void queue_pop(void) {
	if (s_queue_count == 0) {
		return;
	}
	s_queue[s_queue_head][0] = '\0';
	s_queue_head = (s_queue_head + 1) % WEBHOOK_QUEUE_LEN;
	s_queue_count--;
}

static void set_retry_wait(void) {
	s_dns_generation++;
	abort_connection();
	s_state = WEBHOOK_STATE_RETRY_WAIT;
	s_retry_time = make_timeout_time_ms(WEBHOOK_RETRY_MS);
}

static bool http_status_retryable(int status) {
	return status == 408 || status == 425 || status == 429 || status >= 500;
}

static err_t webhook_connected_cb(void *arg, struct altcp_pcb *pcb, err_t err) {
	(void)arg;
	if (err != ERR_OK || pcb == NULL) {
		printf("webhook: connect failed (%d)\n", (int)err);
		set_retry_wait();
		return ERR_ABRT;
	}
	if (s_https) {
		mbedtls_ssl_context *ssl = altcp_tls_context(pcb);
		if (!ssl || !mbedtls_ssl_get_peer_cert(ssl) ||
			mbedtls_ssl_get_verify_result(ssl) != 0) {
			printf("webhook: TLS peer verification failed\n");
			set_retry_wait();
			return ERR_ABRT;
		}
	}

	s_state = WEBHOOK_STATE_WAIT_RESPONSE;
	s_timeout = make_timeout_time_ms(WEBHOOK_TIMEOUT_MS);
	memset(&s_response, 0, sizeof(s_response));
	send_http_request();
	return s_pcb == NULL ? ERR_ABRT : ERR_OK;
}

static err_t webhook_recv_cb(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err) {
	(void)arg;
	if (err != ERR_OK) {
		if (p != NULL) pbuf_free(p);
		set_retry_wait();
		return ERR_ABRT;
	}
	if (p == NULL) {
		printf("webhook: connection closed before HTTP response\n");
		set_retry_wait();
		return ERR_ABRT;
	}
	bool valid = true;
	for (struct pbuf *part = p; part != NULL && s_response.status == 0 && valid; part = part->next) {
		const char *bytes = part->payload;
		for (u16_t i = 0; i < part->len && s_response.status == 0; ++i) {
			valid = webhook_response_feed(&s_response, bytes[i]);
			if (!valid) break;
		}
	}
	altcp_recved(pcb, p->tot_len);
	pbuf_free(p);
	if (!valid) {
		printf("webhook: invalid or oversized HTTP response\n");
		set_retry_wait();
		return ERR_ABRT;
	}
	if (s_response.status != 0) {
		int status = s_response.status;
		if (status >= 200 && status < 300) {
			queue_pop();
			printf("webhook: delivered (HTTP %d)\n", status);
			abort_connection();
			s_state = WEBHOOK_STATE_IDLE;
		} else if (http_status_retryable(status)) {
			printf("webhook: HTTP %d, retrying\n", status);
			set_retry_wait();
		} else {
			queue_pop();
			printf("webhook: discarded (HTTP %d)\n", status);
			abort_connection();
			s_state = WEBHOOK_STATE_IDLE;
		}
		return ERR_ABRT;
	}
	s_timeout = make_timeout_time_ms(WEBHOOK_TIMEOUT_MS);
	return ERR_OK;
}

static void webhook_err_cb(void *arg, err_t err) {
	(void)arg;
	printf("webhook: TCP error %d\n", (int)err);
	s_pcb = NULL;
	/* lwIP may still close/free the TLS PCB after invoking this callback. */
	s_dns_generation++;
	s_state = WEBHOOK_STATE_RETRY_WAIT;
	s_retry_time = make_timeout_time_ms(WEBHOOK_RETRY_MS);
}

static bool open_connection(void) {
	if (s_https) {
		if (!s_ca_len) return false;
		s_tls_config = altcp_tls_create_config_client(s_ca, s_ca_len);
		if (!s_tls_config) return false;
		s_pcb = altcp_tls_new(s_tls_config, IP_GET_TYPE(&s_server_addr));
		if (s_pcb) {
			mbedtls_ssl_context *ssl = altcp_tls_context(s_pcb);
			if (!ssl || mbedtls_ssl_set_hostname(ssl, s_host) != 0) {
				abort_connection();
				return false;
			}
		}
	} else {
		s_pcb = altcp_tcp_new_ip_type(IP_GET_TYPE(&s_server_addr));
	}
	if (!s_pcb) {
		abort_connection();
		return false;
	}
	altcp_err(s_pcb, webhook_err_cb);
	altcp_recv(s_pcb, webhook_recv_cb);
	s_state = WEBHOOK_STATE_CONNECTING;
	s_timeout = make_timeout_time_ms(WEBHOOK_TIMEOUT_MS);
	err_t err = altcp_connect(s_pcb, &s_server_addr, s_port, webhook_connected_cb);
	if (err != ERR_OK) {
		printf("webhook: connect failed (%d)\n", (int)err);
		set_retry_wait();
	}
	return true;
}

static void webhook_dns_found_cb(const char *name, const ip_addr_t *addr, void *arg) {
	(void)name;
	if (s_state != WEBHOOK_STATE_RESOLVING || (uintptr_t)arg != s_dns_generation) return;
	if (addr == NULL) {
		printf("webhook: DNS lookup failed for %s\n", s_host);
		set_retry_wait();
		return;
	}
	if (addr != &s_server_addr) s_server_addr = *addr;
	if (s_pcb != NULL) {
		return;
	}

	if (!open_connection()) set_retry_wait();
}

static bool parse_url(const char *url) {
	if (url == NULL || url[0] == '\0' || strlen(url) > WIFI_WEBHOOK_URL_MAX_LEN) {
		return false;
	}

	for (const char *p = url; *p != '\0'; ++p) {
		if ((unsigned char)*p <= ' ' || (unsigned char)*p == 127 || *p == '#') return false;
	}

	s_host[0] = '\0';
	s_path[0] = '/';
	s_path[1] = '\0';
	s_auth_token[0] = '\0';
	s_port = 80;
	s_https = false;

	const char *cursor = url;
	if (strncmp(cursor, "https://", 8) == 0) {
		s_port = 443;
		s_https = true;
		cursor += 8;
	} else if (strncmp(cursor, "http://", 7) == 0) {
		s_port = 80;
		cursor += 7;
	} else {
		return false;
	}

	const char *path_start = strchr(cursor, '/');
	const char *authority_end = path_start ? path_start : cursor + strlen(cursor);
	const char *at_sign = NULL;
	for (const char *p = cursor; p < authority_end; p++) {
		if (*p == '@') {
			at_sign = p;
		}
	}
	if (at_sign != NULL) {
		size_t token_len = (size_t)(at_sign - cursor);
		if (token_len == 0 || token_len >= sizeof(s_auth_token)) {
			return false;
		}
		memcpy(s_auth_token, cursor, token_len);
		s_auth_token[token_len] = '\0';
		cursor = at_sign + 1;
		path_start = strchr(cursor, '/');
		authority_end = path_start ? path_start : cursor + strlen(cursor);
	}
	const char *host_end = authority_end;
	if (cursor[0] == '[') {
		const char *end_bracket = strchr(cursor, ']');
		if (end_bracket == NULL || end_bracket > host_end) {
			return false;
		}
		size_t host_len = (size_t)(end_bracket - cursor - 1);
		if (host_len == 0 || host_len >= sizeof(s_host)) {
			return false;
		}
		memcpy(s_host, cursor + 1, host_len);
		s_host[host_len] = '\0';
		if (end_bracket + 1 < host_end && *(end_bracket + 1) != ':') return false;
		if (end_bracket + 1 < host_end) {
			const char *port_start = end_bracket + 2;
			char *end = NULL;
			unsigned long value = strtoul(port_start, &end, 10);
			if (end != host_end || value == 0 || value > 65535UL) return false;
			s_port = (uint16_t)value;
		}
	} else {
		const char *colon = NULL;
		for (const char *p = cursor; p < host_end; p++) {
			if (*p == ':') {
				colon = p;
				break;
			}
		}
		if (colon != NULL) {
			size_t host_len = (size_t)(colon - cursor);
			if (host_len == 0 || host_len >= sizeof(s_host)) {
				return false;
			}
			memcpy(s_host, cursor, host_len);
			s_host[host_len] = '\0';
			char *end = NULL;
			unsigned long value = strtoul(colon + 1, &end, 10);
			if (end != host_end || value == 0 || value > 65535UL) return false;
			s_port = (uint16_t)value;
		} else {
			size_t host_len = (size_t)(host_end - cursor);
			if (host_len == 0 || host_len >= sizeof(s_host)) {
				return false;
			}
			memcpy(s_host, cursor, host_len);
			s_host[host_len] = '\0';
		}
	}

	if (path_start != NULL) {
		size_t path_len = (size_t)(strlen(path_start));
		if (path_len >= sizeof(s_path)) return false;
		memcpy(s_path, path_start, path_len);
		s_path[path_len] = '\0';
	} else {
		s_path[0] = '/';
		s_path[1] = '\0';
	}

	if (strchr(s_host, '@') != NULL || strchr(s_host, '[') != NULL ||
		strchr(s_host, ']') != NULL || strchr(s_host, '?') != NULL) return false;
	if (s_https) {
		ip_addr_t literal;
		if (ipaddr_aton(s_host, &literal)) return false;
		if (!webhook_dns_hostname_valid(s_host)) return false;
	}
	return s_host[0] != '\0';
}

bool http_webhook_valid_https_url(const char *url) {
	if (!url || strncmp(url, "https://", 8) != 0) return false;
	if (s_lwip_ready) cyw43_arch_lwip_begin();
	char old_host[sizeof(s_host)], old_path[sizeof(s_path)], old_token[sizeof(s_auth_token)];
	memcpy(old_host, s_host, sizeof(old_host));
	memcpy(old_path, s_path, sizeof(old_path));
	memcpy(old_token, s_auth_token, sizeof(old_token));
	uint16_t old_port = s_port;
	bool old_https = s_https;
	bool valid = parse_url(url);
	memcpy(s_host, old_host, sizeof(s_host));
	memcpy(s_path, old_path, sizeof(s_path));
	memcpy(s_auth_token, old_token, sizeof(s_auth_token));
	s_port = old_port;
	s_https = old_https;
	if (s_lwip_ready) cyw43_arch_lwip_end();
	return valid;
}

static bool build_payload(const vikingbio_data_t *data, const char *type, const char *detail,
						  char *out, size_t out_len) {
	if (data == NULL || type == NULL || out == NULL || out_len < 64) {
		return false;
	}

	char device[WIFI_DEVICE_ID_MAX_LEN + 1] = {0};
	char detail_text[32] = {0};
	const char *detail_value = detail ? detail : "";
	if (detail_value[0] != '\0' && strlen(detail_value) < sizeof(detail_text)) {
		snprintf(detail_text, sizeof(detail_text), "%s", detail_value);
	}

	if (!wifi_config_get_device_id(device, sizeof(device))) {
		snprintf(device, sizeof(device), "unknown");
	}

	if (strcmp(type, "heartbeat") == 0) {
		int rssi = INT_MIN;
		bool have_rssi = read_wifi_rssi(&rssi);
		bool lfs_healthy = lfs_hal_is_healthy();
		uint64_t now_ms = to_ms_since_boot(get_absolute_time());
		uint64_t window_ms = (s_last_heartbeat_ms > 0ULL) ? (now_ms - s_last_heartbeat_ms) : WEBHOOK_HEARTBEAT_INTERVAL_MS;
		if (window_ms == 0ULL) {
			window_ms = WEBHOOK_HEARTBEAT_INTERVAL_MS;
		}
		int written;
		const char *rssi_value = have_rssi ? "" : "null";
		char rssi_buf[32];
		if (have_rssi) {
			snprintf(rssi_buf, sizeof(rssi_buf), "%d", rssi);
			rssi_value = rssi_buf;
		}
		written = snprintf(out, out_len,
				"{\"device\":\"%s\",\"type\":\"%s\",\"detail\":\"%s\",\"rssi\":%s,\"lfs_ok\":%s,\"flame_on_ms\":%llu,\"window_ms\":%llu}",
				device, type, detail_text, rssi_value,
				lfs_healthy ? "true" : "false",
				(unsigned long long)s_flame_on_ms_since_last_heartbeat,
				(unsigned long long)window_ms);
		return written > 0 && written < (int)out_len;
	}

	int written = snprintf(out, out_len,
				"{\"device\":\"%s\",\"type\":\"%s\",\"detail\":\"%s\",\"flame\":%s,\"fan\":%u,\"temp\":%u,\"err\":%u,\"valid\":%s}",
				device, type, detail_text,
				data->flame_detected ? "true" : "false",
				(unsigned)data->fan_speed,
				(unsigned)data->temperature,
				(unsigned)data->error_code,
				data->valid ? "true" : "false");
	return written > 0 && written < (int)out_len;
}

static void do_connect(void) {
	if (s_pcb != NULL || s_host[0] == '\0') {
		return;
	}

	if (s_https && !s_ca_len) {
		printf("webhook: HTTPS requires a valid CA certificate\n");
		s_state = WEBHOOK_STATE_RETRY_WAIT;
		s_retry_time = make_timeout_time_ms(WEBHOOK_RETRY_MS);
		return;
	}
	memset(&s_server_addr, 0, sizeof(s_server_addr));
	if (ipaddr_aton(s_host, &s_server_addr)) {
		/* ipaddr_aton accepts both IPv4 and IPv6 literals in lwIP builds that support IPv6. */
	} else {
		s_state = WEBHOOK_STATE_RESOLVING;
		s_timeout = make_timeout_time_ms(WEBHOOK_TIMEOUT_MS);
		s_dns_generation++;
		void *dns_arg = (void *)s_dns_generation;
		err_t err = dns_gethostbyname(s_host, &s_server_addr, webhook_dns_found_cb, dns_arg);
		if (err == ERR_OK) {
			webhook_dns_found_cb(s_host, &s_server_addr, dns_arg);
		} else if (err != ERR_INPROGRESS) {
			printf("webhook: DNS error %d\n", (int)err);
			set_retry_wait();
		}
		return;
	}

	if (!open_connection()) set_retry_wait();
}

static void start_connection(void) {
	if (s_pcb != NULL || s_queue_count == 0 || s_host[0] == '\0') {
		return;
	}
	do_connect();
}

static void send_http_request(void) {
	const char *pending_json = queue_peek();
	if (s_pcb == NULL || pending_json == NULL || pending_json[0] == '\0') {
		return;
	}

	char request[WEBHOOK_BODY_MAX + 512];
	char host_header[sizeof(s_host) + 10];
	int host_len = snprintf(host_header, sizeof(host_header),
							strchr(s_host, ':') ? "[%s]" : "%s", s_host);
	if (host_len < 0 || (size_t)host_len >= sizeof(host_header)) {
		set_retry_wait();
		return;
	}
	if (s_port != 80 && s_port != 443) {
		int port_len = snprintf(host_header + host_len, sizeof(host_header) - (size_t)host_len,
							 ":%u", (unsigned)s_port);
		if (port_len < 0 || (size_t)port_len >= sizeof(host_header) - (size_t)host_len) {
			set_retry_wait();
			return;
		}
	}
	size_t body_len = strlen(pending_json);
	int len;
	if (s_auth_token[0] != '\0') {
		len = snprintf(request, sizeof(request),
				"POST %s HTTP/1.1\r\n"
				"Host: %s\r\n"
				"X-Webhook-Token: %s\r\n"
				"Content-Type: application/json\r\n"
				"Content-Length: %zu\r\n"
				"Connection: close\r\n"
				"\r\n"
				"%s",
				s_path, host_header, s_auth_token, body_len, pending_json);
	} else {
		len = snprintf(request, sizeof(request),
				"POST %s HTTP/1.1\r\n"
				"Host: %s\r\n"
				"Content-Type: application/json\r\n"
				"Content-Length: %zu\r\n"
				"Connection: close\r\n"
				"\r\n"
				"%s",
				s_path, host_header, body_len, pending_json);
	}
	if (len <= 0 || (size_t)len >= sizeof(request)) {
		printf("webhook: request too large\n");
		set_retry_wait();
		return;
	}

	err_t err = altcp_write(s_pcb, request, (u16_t)len, TCP_WRITE_FLAG_COPY);
	if (err == ERR_OK) {
		err = altcp_output(s_pcb);
		if (err == ERR_OK) {
			printf("webhook: awaiting HTTP response from %s\n", s_host);
			return;
		}
	}
	if (err != ERR_OK) {
		printf("webhook: request send failed (%d)\n", (int)err);
		set_retry_wait();
		return;
	}
}

void http_webhook_init(void) {
	char url[WIFI_WEBHOOK_URL_MAX_LEN + 1] = {0};
	s_host[0] = '\0';
	s_path[0] = '/';
	s_path[1] = '\0';
	s_auth_token[0] = '\0';
	s_last_heartbeat_ms = to_ms_since_boot(get_absolute_time());
	s_flame_on_ms_since_last_heartbeat = 0ULL;
	s_last_flame_transition_ms = s_last_heartbeat_ms;
	s_last_flame_state_known = false;
	s_last_flame_state = false;
	s_state = WEBHOOK_STATE_IDLE;
	s_pcb = NULL;
	s_tls_config = NULL;
	s_ca_len = 0;
	wifi_config_load_webhook_ca(s_ca, sizeof(s_ca), &s_ca_len);
	clear_queue();
	if (!wifi_config_load_webhook_url(url, sizeof(url))) {
		return;
	}
	http_webhook_set_url(url);
}

void http_webhook_set_url(const char *url) {
	if (url == NULL) {
		return;
	}
	if (s_lwip_ready) cyw43_arch_lwip_begin();
	char old_host[sizeof(s_host)], old_path[sizeof(s_path)], old_token[sizeof(s_auth_token)];
	memcpy(old_host, s_host, sizeof(old_host));
	memcpy(old_path, s_path, sizeof(old_path));
	memcpy(old_token, s_auth_token, sizeof(old_token));
	uint16_t old_port = s_port;
	bool old_https = s_https;
	if (!parse_url(url)) {
		memcpy(s_host, old_host, sizeof(s_host));
		memcpy(s_path, old_path, sizeof(s_path));
		memcpy(s_auth_token, old_token, sizeof(s_auth_token));
		s_port = old_port;
		s_https = old_https;
		printf("webhook: invalid URL\n");
		if (s_lwip_ready) cyw43_arch_lwip_end();
		return;
	}
	clear_queue();
	s_dns_generation++;
	abort_connection();
	s_last_heartbeat_ms = to_ms_since_boot(get_absolute_time());
	s_flame_on_ms_since_last_heartbeat = 0ULL;
	s_last_flame_transition_ms = s_last_heartbeat_ms;
	s_last_flame_state_known = false;
	s_last_flame_state = false;
	s_state = WEBHOOK_STATE_IDLE;
	printf("webhook: configured %s\n", s_host);
	if (s_https && !s_ca_len) printf("webhook: HTTPS requires a valid CA certificate\n");
	if (s_lwip_ready) cyw43_arch_lwip_end();
}

bool http_webhook_is_configured(void) {
	return s_host[0] != '\0';
}

void http_webhook_send_alert(const vikingbio_data_t *data, const char *type, const char *detail) {
	if (data == NULL || type == NULL || s_host[0] == '\0') {
		return;
	}
	if (strcmp(type, "flame") == 0) {
		update_flame_activity(data->flame_detected, to_ms_since_boot(get_absolute_time()));
	}
	char payload[WEBHOOK_BODY_MAX];
	if (!build_payload(data, type, detail, payload, sizeof(payload))) {
		printf("webhook: failed to build alert payload\n");
		return;
	}
	if (s_lwip_ready) cyw43_arch_lwip_begin();
	bool queued = queue_push(payload);
	if (s_lwip_ready) cyw43_arch_lwip_end();
	if (!queued) {
		printf("webhook: failed to queue alert payload\n");
		return;
	}
}

void http_webhook_poll(void) {
	s_lwip_ready = true;
	cyw43_arch_lwip_begin();
	if (s_pcb == NULL && s_tls_config != NULL) {
		altcp_tls_free_config(s_tls_config);
		s_tls_config = NULL;
	}
	if (s_state == WEBHOOK_STATE_RETRY_WAIT && time_reached(s_retry_time)) {
		s_state = WEBHOOK_STATE_IDLE;
	}

	if (s_state == WEBHOOK_STATE_IDLE && s_queue_count == 0 && s_host[0] != '\0' &&
		should_send_heartbeat()) {
		cyw43_arch_lwip_end();
		/* RSSI queries can block on CYW43 events; do not run them under the lwIP lock. */
		queue_heartbeat();
		return;
	}

	if (s_state == WEBHOOK_STATE_IDLE && s_queue_count > 0 && s_host[0] != '\0') {
		start_connection();
		cyw43_arch_lwip_end();
		return;
	}

	if ((s_state == WEBHOOK_STATE_RESOLVING || s_state == WEBHOOK_STATE_CONNECTING ||
		 s_state == WEBHOOK_STATE_WAIT_RESPONSE) && time_reached(s_timeout)) {
		printf("webhook: timeout waiting for response\n");
		set_retry_wait();
		cyw43_arch_lwip_end();
		return;
	}
	cyw43_arch_lwip_end();
}
