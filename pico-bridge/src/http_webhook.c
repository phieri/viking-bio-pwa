#include <stdio.h>
#include <string.h>

#include "pico/time.h"
#include "pico/stdlib.h"
#include "lwip/dns.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"

#include "http_webhook.h"
#include "wifi_config.h"

#define WEBHOOK_RETRY_MS 30000
#define WEBHOOK_TIMEOUT_MS 10000
#define WEBHOOK_QUEUE_LEN 4
#define WEBHOOK_JSON_MAX 384
#define WEBHOOK_BODY_MAX 512

typedef enum {
	WEBHOOK_STATE_IDLE,
	WEBHOOK_STATE_RESOLVING,
	WEBHOOK_STATE_CONNECTING,
	WEBHOOK_STATE_CONNECTED,
	WEBHOOK_STATE_RETRY_WAIT,
} http_webhook_state_t;

static struct tcp_pcb *s_pcb = NULL;
static http_webhook_state_t s_state = WEBHOOK_STATE_IDLE;

static char s_url[WIFI_WEBHOOK_URL_MAX_LEN + 1];
static char s_host[WIFI_SERVER_IP_MAX_LEN + 1];
static char s_path[128];
static char s_auth_token[129];
static uint16_t s_port = 80;

static ip_addr_t s_server_addr;
static absolute_time_t s_timeout;
static absolute_time_t s_retry_time;

static char s_queue[WEBHOOK_QUEUE_LEN][WEBHOOK_BODY_MAX];
static size_t s_queue_head = 0;
static size_t s_queue_count = 0;

static void abort_connection(void) {
	if (s_pcb != NULL) {
		tcp_abort(s_pcb);
		s_pcb = NULL;
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
		printf("webhook: queue full, dropping oldest alert\n");
		s_queue_head = (s_queue_head + 1) % WEBHOOK_QUEUE_LEN;
		s_queue_count--;
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
	abort_connection();
	s_state = WEBHOOK_STATE_RETRY_WAIT;
	s_retry_time = make_timeout_time_ms(WEBHOOK_RETRY_MS);
}

static err_t webhook_connected_cb(void *arg, struct tcp_pcb *pcb, err_t err) {
	(void)arg;
	if (err != ERR_OK || pcb == NULL) {
		printf("webhook: connect failed (%d)\n", (int)err);
		set_retry_wait();
		return err;
	}

	s_state = WEBHOOK_STATE_CONNECTED;
	s_timeout = make_timeout_time_ms(WEBHOOK_TIMEOUT_MS);
	send_http_request();
	return ERR_OK;
}

static err_t webhook_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
	(void)arg;
	(void)err;
	if (p == NULL) {
		printf("webhook: server closed connection\n");
		s_pcb = NULL;
		s_state = WEBHOOK_STATE_IDLE;
		return ERR_OK;
	}

	tcp_recved(pcb, p->tot_len);
	pbuf_free(p);
	abort_connection();
	s_state = WEBHOOK_STATE_IDLE;
	return ERR_OK;
}

static void webhook_err_cb(void *arg, err_t err) {
	(void)arg;
	printf("webhook: TCP error %d\n", (int)err);
	s_pcb = NULL;
	s_state = WEBHOOK_STATE_RETRY_WAIT;
	s_retry_time = make_timeout_time_ms(WEBHOOK_RETRY_MS);
}

static void webhook_dns_found_cb(const char *name, const ip_addr_t *addr, void *arg) {
	(void)name;
	(void)arg;
	if (addr == NULL) {
		printf("webhook: DNS lookup failed for %s\n", s_host);
		set_retry_wait();
		return;
	}
	memcpy(&s_server_addr, addr, sizeof(s_server_addr));
	if (s_pcb != NULL) {
		return;
	}

	s_pcb = tcp_new_ip_type(IP_GET_TYPE(&s_server_addr));
	if (s_pcb == NULL) {
		set_retry_wait();
		return;
	}
	tcp_err(s_pcb, webhook_err_cb);
	tcp_recv(s_pcb, webhook_recv_cb);
	s_state = WEBHOOK_STATE_CONNECTING;
	s_timeout = make_timeout_time_ms(WEBHOOK_TIMEOUT_MS);
	err_t err = tcp_connect(s_pcb, &s_server_addr, s_port, webhook_connected_cb);
	if (err != ERR_OK) {
		printf("webhook: tcp_connect failed (%d)\n", (int)err);
		set_retry_wait();
	}
}

static bool parse_url(const char *url) {
	if (url == NULL || url[0] == '\0') {
		return false;
	}

	s_url[0] = '\0';
	s_host[0] = '\0';
	s_path[0] = '/';
	s_path[1] = '\0';
	s_auth_token[0] = '\0';
	s_port = 80;

	const char *cursor = url;
	if (strncmp(cursor, "https://", 8) == 0) {
		s_port = 443;
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
		if (end_bracket + 1 < host_end && *(end_bracket + 1) == ':') {
			const char *port_start = end_bracket + 2;
			char *end = NULL;
			unsigned long value = strtoul(port_start, &end, 10);
			if (end != NULL && end == host_end && value > 0 && value <= 65535UL) {
				s_port = (uint16_t)value;
			}
		}
	} else {
		const char *colon = NULL;
		for (const char *p = cursor; p < host_end; p++) {
			if (*p == ':') {
				colon = p;
				break;
			}
		}
		if (colon != NULL && strchr(cursor, ':') != strrchr(cursor, ':')) {
			size_t host_len = (size_t)(host_end - cursor);
			if (host_len == 0 || host_len >= sizeof(s_host)) {
				return false;
			}
			memcpy(s_host, cursor, host_len);
			s_host[host_len] = '\0';
		} else if (colon != NULL) {
			size_t host_len = (size_t)(colon - cursor);
			if (host_len == 0 || host_len >= sizeof(s_host)) {
				return false;
			}
			memcpy(s_host, cursor, host_len);
			s_host[host_len] = '\0';
			char *end = NULL;
			unsigned long value = strtoul(colon + 1, &end, 10);
			if (end != NULL && end == host_end && value > 0 && value <= 65535UL) {
				s_port = (uint16_t)value;
			}
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
		if (path_len >= sizeof(s_path)) {
			path_len = sizeof(s_path) - 1;
		}
		memcpy(s_path, path_start, path_len);
		s_path[path_len] = '\0';
	} else {
		s_path[0] = '/';
		s_path[1] = '\0';
	}

	snprintf(s_url, sizeof(s_url), "%s", url);
	return s_host[0] != '\0';
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

	memset(&s_server_addr, 0, sizeof(s_server_addr));
	if (ipaddr_aton(s_host, &s_server_addr)) {
		/* ipaddr_aton accepts both IPv4 and IPv6 literals in lwIP builds that support IPv6. */
	} else {
		s_state = WEBHOOK_STATE_RESOLVING;
		s_timeout = make_timeout_time_ms(WEBHOOK_TIMEOUT_MS);
		err_t err = dns_gethostbyname(s_host, &s_server_addr, webhook_dns_found_cb, NULL);
		if (err == ERR_OK) {
			do_connect();
		} else if (err != ERR_INPROGRESS) {
			printf("webhook: DNS error %d\n", (int)err);
			set_retry_wait();
		}
		return;
	}

	s_pcb = tcp_new_ip_type(IP_GET_TYPE(&s_server_addr));
	if (s_pcb == NULL) {
		printf("webhook: tcp_new failed\n");
		set_retry_wait();
		return;
	}
	tcp_err(s_pcb, webhook_err_cb);
	tcp_recv(s_pcb, webhook_recv_cb);
	s_state = WEBHOOK_STATE_CONNECTING;
	s_timeout = make_timeout_time_ms(WEBHOOK_TIMEOUT_MS);
	err_t err = tcp_connect(s_pcb, &s_server_addr, s_port, webhook_connected_cb);
	if (err != ERR_OK) {
		printf("webhook: tcp_connect failed (%d)\n", (int)err);
		set_retry_wait();
	}
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

	char request[WEBHOOK_BODY_MAX + 256];
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
				s_path, s_host, s_auth_token, body_len, pending_json);
	} else {
		len = snprintf(request, sizeof(request),
				"POST %s HTTP/1.1\r\n"
				"Host: %s\r\n"
				"Content-Type: application/json\r\n"
				"Content-Length: %zu\r\n"
				"Connection: close\r\n"
				"\r\n"
				"%s",
				s_path, s_host, body_len, pending_json);
	}
	if (len <= 0 || (size_t)len >= sizeof(request)) {
		printf("webhook: request too large\n");
		queue_pop();
		set_retry_wait();
		return;
	}

	err_t err = tcp_write(s_pcb, request, (u16_t)len, TCP_WRITE_FLAG_COPY);
	if (err == ERR_OK) {
		tcp_output(s_pcb);
		printf("webhook: sent alert payload to %s\n", s_url);
		queue_pop();
		abort_connection();
		s_state = WEBHOOK_STATE_IDLE;
		return;
	}
	printf("webhook: tcp_write failed (%d)\n", (int)err);
	set_retry_wait();
}

void http_webhook_init(void) {
	char url[WIFI_WEBHOOK_URL_MAX_LEN + 1] = {0};
	s_url[0] = '\0';
	s_host[0] = '\0';
	s_path[0] = '/';
	s_path[1] = '\0';
	s_auth_token[0] = '\0';
	s_state = WEBHOOK_STATE_IDLE;
	abort_connection();
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
	if (!parse_url(url)) {
		printf("webhook: invalid URL '%s'\n", url);
		return;
	}
	clear_queue();
	abort_connection();
	s_state = WEBHOOK_STATE_IDLE;
	printf("webhook: configured %s\n", s_url);
}

bool http_webhook_is_configured(void) {
	return s_host[0] != '\0';
}

void http_webhook_send_alert(const vikingbio_data_t *data, const char *type, const char *detail) {
	if (data == NULL || type == NULL || s_host[0] == '\0') {
		return;
	}
	char payload[WEBHOOK_BODY_MAX];
	if (!build_payload(data, type, detail, payload, sizeof(payload))) {
		printf("webhook: failed to build alert payload\n");
		return;
	}
	if (!queue_push(payload)) {
		printf("webhook: failed to queue alert payload\n");
		return;
	}
	if (s_state == WEBHOOK_STATE_IDLE) {
		start_connection();
	}
}

void http_webhook_poll(void) {
	if (s_state == WEBHOOK_STATE_RETRY_WAIT && time_reached(s_retry_time)) {
		s_state = WEBHOOK_STATE_IDLE;
	}

	if (s_state == WEBHOOK_STATE_IDLE && s_queue_count > 0 && s_host[0] != '\0') {
		start_connection();
		return;
	}

	if (s_state == WEBHOOK_STATE_CONNECTING && s_pcb != NULL && time_reached(s_timeout)) {
		printf("webhook: timeout waiting for connection\n");
		set_retry_wait();
		return;
	}

	if (s_state == WEBHOOK_STATE_CONNECTED && s_pcb != NULL && s_queue_count > 0) {
		send_http_request();
	}
}
