#include <string.h>
#include <stdio.h>
#include "pico/stdlib.h"
#include "lwip/tcp.h"
#include "lwip/ip_addr.h"
#include "lwip/dns.h"
#include "tcp_client.h"
#include "wifi_config.h"

typedef enum {
	TCP_STATE_DISCONNECTED,
	TCP_STATE_RESOLVING,
	TCP_STATE_CONNECTING,
	TCP_STATE_CONNECTED,
} tcp_state_t;

static struct tcp_pcb *s_pcb = NULL;
static tcp_state_t s_state = TCP_STATE_DISCONNECTED;
static char s_server_ip[WIFI_SERVER_IP_MAX_LEN + 1];
static uint16_t s_server_port;
static absolute_time_t s_reconnect_time;
static ip_addr_t s_server_addr;

// Pending send buffer (one JSON message)
static char s_pending[256];
static bool s_has_pending = false;

// Forward declarations
static void do_connect(void);

static err_t tcp_connected_cb(void *arg, struct tcp_pcb *pcb, err_t err) {
	(void)arg;
	if (err != ERR_OK || pcb == NULL) {
		s_state = TCP_STATE_DISCONNECTED;
		s_reconnect_time = make_timeout_time_ms(TCP_CLIENT_RECONNECT_MS);
		return err;
	}
	s_state = TCP_STATE_CONNECTED;
	printf("tcp_client: connected to %s:%d\n", s_server_ip, s_server_port);

	// Flush any pending data
	if (s_has_pending) {
		size_t len = strlen(s_pending);
		err_t e = tcp_write(s_pcb, s_pending, (u16_t)len, TCP_WRITE_FLAG_COPY);
		if (e == ERR_OK) {
			tcp_output(s_pcb);
			s_has_pending = false;
		}
	}
	return ERR_OK;
}

static err_t tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
	(void)arg; (void)err;
	if (p == NULL) {
		// Connection closed by remote
		s_state = TCP_STATE_DISCONNECTED;
		s_pcb = NULL;
		s_reconnect_time = make_timeout_time_ms(TCP_CLIENT_RECONNECT_MS);
		return ERR_OK;
	}
	// Acknowledge and discard any data from server
	tcp_recved(pcb, p->tot_len);
	pbuf_free(p);
	return ERR_OK;
}

static void tcp_err_cb(void *arg, err_t err) {
	(void)arg; (void)err;
	printf("tcp_client: connection error %d – reconnecting\n", (int)err);
	s_pcb = NULL;
	s_state = TCP_STATE_DISCONNECTED;
	s_reconnect_time = make_timeout_time_ms(TCP_CLIENT_RECONNECT_MS);
}

static void dns_found_cb(const char *name, const ip_addr_t *addr, void *arg) {
	(void)name; (void)arg;
	if (addr == NULL) {
		printf("tcp_client: DNS lookup failed\n");
		s_state = TCP_STATE_DISCONNECTED;
		s_reconnect_time = make_timeout_time_ms(TCP_CLIENT_RECONNECT_MS);
		return;
	}
	s_server_addr = *addr;
	do_connect();
}

static void do_connect(void) {
	s_pcb = tcp_new_ip_type(IP_GET_TYPE(&s_server_addr));
	if (s_pcb == NULL) {
		printf("tcp_client: tcp_new failed\n");
		s_state = TCP_STATE_DISCONNECTED;
		s_reconnect_time = make_timeout_time_ms(TCP_CLIENT_RECONNECT_MS);
		return;
	}
	tcp_err(s_pcb, tcp_err_cb);
	tcp_recv(s_pcb, tcp_recv_cb);
	s_state = TCP_STATE_CONNECTING;
	err_t err = tcp_connect(s_pcb, &s_server_addr, s_server_port, tcp_connected_cb);
	if (err != ERR_OK) {
		printf("tcp_client: tcp_connect failed (%d)\n", (int)err);
		tcp_close(s_pcb);
		s_pcb = NULL;
		s_state = TCP_STATE_DISCONNECTED;
		s_reconnect_time = make_timeout_time_ms(TCP_CLIENT_RECONNECT_MS);
	}
}

static void start_connect(void) {
	// Try to parse as numeric IP first
	if (ipaddr_aton(s_server_ip, &s_server_addr)) {
		do_connect();
		return;
	}
	// Fall back to DNS
	s_state = TCP_STATE_RESOLVING;
	err_t err = dns_gethostbyname(s_server_ip, &s_server_addr, dns_found_cb, NULL);
	if (err == ERR_OK) {
		// Already resolved
		do_connect();
	} else if (err != ERR_INPROGRESS) {
		printf("tcp_client: DNS error %d\n", (int)err);
		s_state = TCP_STATE_DISCONNECTED;
		s_reconnect_time = make_timeout_time_ms(TCP_CLIENT_RECONNECT_MS);
	}
}

void tcp_client_init(const char *server_ip, uint16_t port) {
	snprintf(s_server_ip, sizeof(s_server_ip), "%s", server_ip);
	s_server_port = port;
	s_state = TCP_STATE_DISCONNECTED;
	s_reconnect_time = get_absolute_time();  // Connect immediately
	s_has_pending = false;
	s_pcb = NULL;
	memset(&s_server_addr, 0, sizeof(s_server_addr));
}

void tcp_client_send_data(const viking_bio_data_t *data) {
	if (data == NULL) return;

	int len = snprintf(s_pending, sizeof(s_pending),
	                   "{\"flame\":%s,\"fan\":%d,\"temp\":%d,\"err\":%d,\"valid\":%s}\n",
	                   data->flame_detected ? "true" : "false",
	                   data->fan_speed,
	                   data->temperature,
	                   data->error_code,
	                   data->valid ? "true" : "false");
	if (len <= 0 || len >= (int)sizeof(s_pending)) return;

	if (s_state == TCP_STATE_CONNECTED && s_pcb != NULL) {
		err_t err = tcp_write(s_pcb, s_pending, (u16_t)len, TCP_WRITE_FLAG_COPY);
		if (err == ERR_OK) {
			tcp_output(s_pcb);
			s_has_pending = false;
			return;
		}
		// Write failed – abort connection and reconnect
		printf("tcp_client: write failed (%d)\n", (int)err);
		tcp_abort(s_pcb);
		s_pcb = NULL;
		s_state = TCP_STATE_DISCONNECTED;
		s_reconnect_time = make_timeout_time_ms(TCP_CLIENT_RECONNECT_MS);
	}
	// Queue for next connection
	s_has_pending = true;
}

void tcp_client_poll(void) {
	if (s_state == TCP_STATE_DISCONNECTED && time_reached(s_reconnect_time)) {
		if (s_server_ip[0] != '\0' && s_server_port != 0) {
			printf("tcp_client: connecting to %s:%d\n", s_server_ip, s_server_port);
			start_connect();
		}
	}
}

bool tcp_client_is_connected(void) {
	return s_state == TCP_STATE_CONNECTED;
}
