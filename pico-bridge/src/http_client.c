#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "pico/time.h"
#include "pico/stdlib.h"
#include "lwip/dns.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"

#include "http_client.h"
#include "wifi_config.h"

typedef enum {
	HTTP_STATE_IDLE,
	HTTP_STATE_RESOLVING,
	HTTP_STATE_CONNECTING,
	HTTP_STATE_CONNECTED,
	HTTP_STATE_RETRY_WAIT,
} http_state_t;

#define TELEMETRY_QUEUE_LEN 8
#define TELEMETRY_PAYLOAD_MAX 384
#define TELEMETRY_FRAME_MAX (4 + TELEMETRY_PAYLOAD_MAX)
#define TELEMETRY_DATA_JSON_MAX 128
#define TELEMETRY_CANONICAL_MAX 256
#define TELEMETRY_SIGNATURE_MAX 48

typedef struct {
	uint8_t bytes[TELEMETRY_FRAME_MAX];
	size_t len;
} telemetry_frame_t;

static struct tcp_pcb *s_pcb = NULL;
static http_state_t s_state = HTTP_STATE_IDLE;

static char s_host[WIFI_SERVER_IP_MAX_LEN + 1];
static uint16_t s_port = 0;
static char s_device_key[WIFI_DEVICE_KEY_MAX_LEN + 1];
static char s_device_id[WIFI_DEVICE_ID_MAX_LEN + 1];
static uint32_t s_boot_counter = 0;
static uint32_t s_message_counter = 0;

static ip_addr_t s_server_addr;
static absolute_time_t s_timeout;
static absolute_time_t s_retry_time;

static telemetry_frame_t s_queue[TELEMETRY_QUEUE_LEN];
static size_t s_queue_head = 0;
static size_t s_queue_count = 0;

static void start_connect(void);
static void do_connect(void);
static void abort_and_retry(void);
static void flush_queue(void);

static bool queue_push(const uint8_t *data, size_t len) {
	if (len == 0 || len > TELEMETRY_FRAME_MAX) {
		return false;
	}
	if (s_queue_count >= TELEMETRY_QUEUE_LEN) {
		size_t overwrite = s_queue_head;
		s_queue_head = (s_queue_head + 1) % TELEMETRY_QUEUE_LEN;
		s_queue_count--;
		printf("http_client: telemetry queue full, dropping oldest frame (%u bytes)\n",
			   (unsigned)s_queue[overwrite].len);
	}
	size_t slot = (s_queue_head + s_queue_count) % TELEMETRY_QUEUE_LEN;
	memcpy(s_queue[slot].bytes, data, len);
	s_queue[slot].len = len;
	s_queue_count++;
	return true;
}

static telemetry_frame_t *queue_peek(void) {
	if (s_queue_count == 0) {
		return NULL;
	}
	return &s_queue[s_queue_head];
}

static void queue_pop(void) {
	if (s_queue_count == 0) {
		return;
	}
	s_queue_head = (s_queue_head + 1) % TELEMETRY_QUEUE_LEN;
	s_queue_count--;
}

static bool build_data_json(const viking_bio_data_t *data, char *out, size_t out_len) {
	int written = snprintf(out, out_len,
						   "{\"flame\":%s,\"fan\":%d,\"temp\":%d,\"err\":%d,\"valid\":%s}",
						   data->flame_detected ? "true" : "false", data->fan_speed,
						   data->temperature, data->error_code,
						   data->valid ? "true" : "false");
	return written > 0 && written < (int)out_len;
}

static uint64_t next_sequence(void) {
	s_message_counter++;
	return ((uint64_t)s_boot_counter << 32) | s_message_counter;
}

static bool build_signature(const char *device_key, const char *canonical,
							char *out, size_t out_len) {
	unsigned char mac[32];
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (md == NULL) {
		return false;
	}
	if (mbedtls_md_hmac(md, (const unsigned char *)device_key, strlen(device_key),
						(const unsigned char *)canonical, strlen(canonical), mac) != 0) {
		return false;
	}
	size_t olen = 0;
	if (mbedtls_base64_encode((unsigned char *)out, out_len, &olen, mac, sizeof(mac)) != 0) {
		return false;
	}
	if (olen >= out_len) {
		return false;
	}
	out[olen] = '\0';
	return true;
}

static bool build_frame(const viking_bio_data_t *data, uint8_t *frame, size_t *frame_len) {
	char data_json[TELEMETRY_DATA_JSON_MAX];
	char canonical[TELEMETRY_CANONICAL_MAX];
	char signature[TELEMETRY_SIGNATURE_MAX];
	char payload[TELEMETRY_PAYLOAD_MAX];
	uint64_t seq = next_sequence();
	uint64_t ts = to_ms_since_boot(get_absolute_time());

	if (!build_data_json(data, data_json, sizeof(data_json))) {
		return false;
	}

	int canonical_len = snprintf(canonical, sizeof(canonical), "%s\n%llu\n%llu\n%s", s_device_id,
								 (unsigned long long)seq, (unsigned long long)ts, data_json);
	if (canonical_len <= 0 || canonical_len >= (int)sizeof(canonical)) {
		return false;
	}

	if (!build_signature(s_device_key, canonical, signature, sizeof(signature))) {
		return false;
	}

	int payload_len = snprintf(payload, sizeof(payload),
							  "{\"device\":\"%s\",\"seq\":%llu,\"ts\":%llu,\"data\":%s,\"sig\":\"%s\"}",
							  s_device_id, (unsigned long long)seq, (unsigned long long)ts,
							  data_json, signature);
	if (payload_len <= 0 || payload_len >= (int)sizeof(payload)) {
		return false;
	}

	frame[0] = (uint8_t)(((uint32_t)payload_len >> 24) & 0xff);
	frame[1] = (uint8_t)(((uint32_t)payload_len >> 16) & 0xff);
	frame[2] = (uint8_t)(((uint32_t)payload_len >> 8) & 0xff);
	frame[3] = (uint8_t)((uint32_t)payload_len & 0xff);
	memcpy(frame + 4, payload, (size_t)payload_len);
	*frame_len = (size_t)payload_len + 4;
	return true;
}

static err_t tcp_connected_cb(void *arg, struct tcp_pcb *pcb, err_t err) {
	(void)arg;
	if (err != ERR_OK || pcb == NULL) {
		abort_and_retry();
		return err;
	}

	s_state = HTTP_STATE_CONNECTED;
	s_timeout = make_timeout_time_ms(HTTP_CLIENT_TIMEOUT_MS);
	printf("http_client: connected to %s:%d\n", s_host, s_port);
	return ERR_OK;
}

static err_t tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
	(void)arg;
	(void)err;
	if (p == NULL) {
		printf("http_client: server closed connection\n");
		s_pcb = NULL;
		s_state = HTTP_STATE_RETRY_WAIT;
		s_retry_time = make_timeout_time_ms(HTTP_CLIENT_RETRY_MS);
		return ERR_OK;
	}

	tcp_recved(pcb, p->tot_len);
	pbuf_free(p);
	s_timeout = make_timeout_time_ms(HTTP_CLIENT_TIMEOUT_MS);
	return ERR_OK;
}

static void tcp_err_cb(void *arg, err_t err) {
	(void)arg;
	printf("http_client: TCP error %d – reconnecting\n", (int)err);
	s_pcb = NULL;
	s_state = HTTP_STATE_RETRY_WAIT;
	s_retry_time = make_timeout_time_ms(HTTP_CLIENT_RETRY_MS);
}

static void dns_found_cb(const char *name, const ip_addr_t *addr, void *arg) {
	(void)name;
	(void)arg;
	if (addr == NULL) {
		printf("http_client: DNS lookup failed\n");
		s_state = HTTP_STATE_RETRY_WAIT;
		s_retry_time = make_timeout_time_ms(HTTP_CLIENT_RETRY_MS);
		return;
	}
	s_server_addr = *addr;
	do_connect();
}

static void abort_connection(void) {
	if (s_pcb != NULL) {
		tcp_abort(s_pcb);
		s_pcb = NULL;
	}
}

static void abort_and_retry(void) {
	abort_connection();
	s_state = HTTP_STATE_RETRY_WAIT;
	s_retry_time = make_timeout_time_ms(HTTP_CLIENT_RETRY_MS);
}

static void flush_queue(void) {
	while (s_state == HTTP_STATE_CONNECTED && s_pcb != NULL && s_queue_count > 0) {
		telemetry_frame_t *frame = queue_peek();
		if (frame == NULL) {
			return;
		}
		err_t err = tcp_write(s_pcb, frame->bytes, (u16_t)frame->len, TCP_WRITE_FLAG_COPY);
		if (err == ERR_OK) {
			tcp_output(s_pcb);
			printf("http_client: sent telemetry frame (%u bytes)\n", (unsigned)frame->len);
			queue_pop();
			s_timeout = make_timeout_time_ms(HTTP_CLIENT_TIMEOUT_MS);
			continue;
		}
		if (err == ERR_MEM) {
			return;
		}
		printf("http_client: tcp_write failed (%d)\n", (int)err);
		abort_and_retry();
		return;
	}
}

static void do_connect(void) {
	if (s_pcb != NULL || s_host[0] == '\0' || s_port == 0) {
		return;
	}

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
		abort_and_retry();
	}
}

static void start_connect(void) {
	if (s_pcb != NULL || s_host[0] == '\0' || s_port == 0) {
		return;
	}

	if (ipaddr_aton(s_host, &s_server_addr)) {
		do_connect();
		return;
	}

	s_state = HTTP_STATE_RESOLVING;
	s_timeout = make_timeout_time_ms(HTTP_CLIENT_TIMEOUT_MS);
	err_t err = dns_gethostbyname(s_host, &s_server_addr, dns_found_cb, NULL);
	if (err == ERR_OK) {
		do_connect();
	} else if (err != ERR_INPROGRESS) {
		printf("http_client: DNS error %d\n", (int)err);
		s_state = HTTP_STATE_RETRY_WAIT;
		s_retry_time = make_timeout_time_ms(HTTP_CLIENT_RETRY_MS);
	}
}

void http_client_init(const char *host, uint16_t port, const char *device_key) {
	snprintf(s_host, sizeof(s_host), "%s", host ? host : "");
	s_port = port;
	snprintf(s_device_key, sizeof(s_device_key), "%s", device_key ? device_key : "");
	s_queue_head = 0;
	s_queue_count = 0;
	s_state = HTTP_STATE_IDLE;
	abort_connection();
	memset(&s_server_addr, 0, sizeof(s_server_addr));

	if (s_device_id[0] == '\0' &&
		!wifi_config_get_device_id(s_device_id, sizeof(s_device_id))) {
		s_device_id[0] = '\0';
	}
	if (s_boot_counter == 0) {
		s_message_counter = 0;
		if (!wifi_config_reserve_boot_counter(&s_boot_counter)) {
			s_boot_counter = (uint32_t)(time_us_64() & 0xffffffffu);
		}
	}

	if (s_host[0] != '\0' && s_device_key[0] != '\0') {
		printf("http_client: ready for device %s -> %s:%d (boot counter %lu)\n", s_device_id,
			   s_host, s_port, (unsigned long)s_boot_counter);
	} else if (s_device_key[0] == '\0') {
		printf("http_client: telemetry key missing – provision DEVICEKEY via USB\n");
	}
}

void http_client_send_data(const viking_bio_data_t *data) {
	uint8_t frame[TELEMETRY_FRAME_MAX];
	size_t frame_len = 0;

	if (data == NULL || s_host[0] == '\0' || s_port == 0 || s_device_key[0] == '\0' ||
		s_device_id[0] == '\0') {
		return;
	}

	if (!build_frame(data, frame, &frame_len)) {
		printf("http_client: failed to build telemetry frame\n");
		return;
	}
	if (!queue_push(frame, frame_len)) {
		printf("http_client: failed to queue telemetry frame\n");
		return;
	}

}

void http_client_poll(void) {
	if ((s_state == HTTP_STATE_RESOLVING || s_state == HTTP_STATE_CONNECTING ||
		 (s_state == HTTP_STATE_CONNECTED && s_queue_count > 0)) &&
		time_reached(s_timeout)) {
		printf("http_client: timeout – reconnecting\n");
		abort_and_retry();
	}

	if (s_state == HTTP_STATE_RETRY_WAIT && time_reached(s_retry_time)) {
		s_state = HTTP_STATE_IDLE;
	}

	if (s_queue_count == 0 || s_host[0] == '\0' || s_port == 0 || s_device_key[0] == '\0') {
		return;
	}

	if (s_state == HTTP_STATE_IDLE) {
		start_connect();
		return;
	}
	if (s_state == HTTP_STATE_CONNECTED) {
		flush_queue();
	}
}

bool http_client_is_active(void) {
	return s_state == HTTP_STATE_RESOLVING || s_state == HTTP_STATE_CONNECTING ||
		   s_state == HTTP_STATE_CONNECTED;
}
