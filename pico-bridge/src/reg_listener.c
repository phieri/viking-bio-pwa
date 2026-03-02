#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "pico/stdlib.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/ip6_addr.h"
#include "reg_listener.h"
#include "wifi_config.h"

#define REG_KEYWORD     "VIKINGBIO"
#define REG_MAX_PACKET  256

// ---------------------------------------------------------------------------
// Token comparison (constant-time to avoid timing oracles)
// ---------------------------------------------------------------------------

static bool tokens_equal(const char *a, size_t alen, const char *b, size_t blen) {
	if (alen != blen) return false;
	uint8_t diff = 0;
	for (size_t i = 0; i < alen; i++) {
		diff |= (uint8_t)((unsigned char)a[i] ^ (unsigned char)b[i]);
	}
	return (diff == 0);
}

// ---------------------------------------------------------------------------
// UDP receive callback
// ---------------------------------------------------------------------------

static void reg_recv_cb(void *arg, struct udp_pcb *pcb,
                        struct pbuf *p,
                        const ip_addr_t *addr, u16_t port) {
	(void)arg; (void)pcb; (void)addr; (void)port;

	if (!p) return;

	if (p->tot_len >= REG_MAX_PACKET) {
		pbuf_free(p);
		return;
	}

	// Copy packet to a local null-terminated buffer
	char buf[REG_MAX_PACKET];
	uint16_t len = p->tot_len;
	pbuf_copy_partial(p, buf, len, 0);
	pbuf_free(p);
	buf[len] = '\0';

	// Strip trailing whitespace (CR/LF/space)
	while (len > 0 && isspace((unsigned char)buf[len - 1])) {
		buf[--len] = '\0';
	}

	// Parse: "VIKINGBIO <token> <ipv6addr> <port>"
	char *saveptr;
	char *keyword = strtok_r(buf, " ", &saveptr);
	char *token   = strtok_r(NULL, " ", &saveptr);
	char *ipstr   = strtok_r(NULL, " ", &saveptr);
	char *portstr = strtok_r(NULL, " ", &saveptr);

	if (!keyword || !token || !ipstr || !portstr) return;
	if (strcmp(keyword, REG_KEYWORD) != 0) return;

	// Validate port using strtol to detect non-numeric and out-of-range input
	char *endptr;
	long new_port = strtol(portstr, &endptr, 10);
	if (endptr == portstr || *endptr != '\0' || new_port <= 0 || new_port > 65535) {
		printf("reg_listener: invalid port in announcement\n");
		return;
	}

	// Load and compare stored token
	char stored[WIFI_HOOK_TOKEN_MAX_LEN + 1];
	if (!wifi_config_load_hook_token(stored, sizeof(stored))) {
		printf("reg_listener: no token configured – ignoring announcement\n");
		return;
	}

	if (!tokens_equal(stored, strlen(stored), token, strlen(token))) {
		printf("reg_listener: token mismatch – ignoring announcement\n");
		return;
	}

	// Save new proxy server config
	if (wifi_config_save_server(ipstr, (uint16_t)new_port)) {
		printf("reg_listener: proxy registered: %s:%d\n", ipstr, new_port);
	} else {
		printf("reg_listener: failed to save proxy config\n");
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool reg_listener_start(void) {
	struct udp_pcb *pcb = udp_new();
	if (!pcb) {
		printf("reg_listener: udp_new() failed\n");
		return false;
	}

	// Bind to any IPv6 address on the registration port
	err_t err = udp_bind(pcb, IP6_ADDR_ANY, REG_LISTENER_PORT);
	if (err != ERR_OK) {
		printf("reg_listener: udp_bind() failed (%d)\n", (int)err);
		udp_remove(pcb);
		return false;
	}

	udp_recv(pcb, reg_recv_cb, NULL);
	printf("reg_listener: listening on UDP port %d\n", REG_LISTENER_PORT);
	return true;
}
