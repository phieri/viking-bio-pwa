#include "ntp.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#if defined(PICO_BOARD)
#include "pico/time.h"
#define SLEEP_MS(ms) sleep_ms(ms)
#else
#define SLEEP_MS(ms) usleep((ms) * 1000)
#endif
#include <errno.h>

/* lwIP APIs (DNS + UDP pbuf/pcb) - IPv6-capable */
#include <lwip/dns.h>
#include <lwip/udp.h>
#include <lwip/pbuf.h>
#include <lwip/ip_addr.h>
#include <lwip/inet.h>
#include <lwip/err.h>

// NTP time starts on 1900, Unix time on 1970
#define NTP_TIMESTAMP_DELTA 2208988800UL

// Timeout in milliseconds for NTP response
#define NTP_RECV_TIMEOUT_MS 3000

static void print_time_now(const char *prefix) {
    time_t t = time(NULL);
    struct tm *ptm = gmtime(&t);
    if (ptm) {
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", ptm);
        printf("%s %s\n", prefix, buf);
    } else {
        printf("%s (time unavailable)\n", prefix);
    }
}

typedef struct {
    volatile int resolved;
    ip_addr_t addr;
} dns_ctx_t;

typedef struct {
    volatile int got;
    uint8_t buf[512];
    int len;
} resp_t;

static void ntp_dns_cb(const char *name, const ip_addr_t *ipaddr, void *arg) {
    (void)name;
    if (ipaddr == NULL || arg == NULL) return;
    dns_ctx_t *ctx = (dns_ctx_t *)arg;
    ctx->addr = *ipaddr;
    ctx->resolved = 1;
}

static void ntp_udp_recv_cb(void *arg, struct udp_pcb *upcb, struct pbuf *p,
                           const ip_addr_t *addr, u16_t port) {
    (void)upcb; (void)addr; (void)port;
    resp_t *r = (resp_t *)arg;
    if (!p || !r) return;
    int copy_len = p->tot_len > (int)sizeof(r->buf) ? (int)sizeof(r->buf) : p->tot_len;
    pbuf_copy_partial(p, r->buf, copy_len, 0);
    r->len = copy_len;
    r->got = 1;
    pbuf_free(p);
}

bool ntp_sync_time_for_country(const char *country) {
    const char *server = "pool.ntp.org";
    if (country && strcmp(country, "SE") == 0) {
        server = "ntp.se";
    }

    printf("NTP: querying server=%s\n", server);

    /* Resolve hostname via lwIP DNS (ip_addr_t supports v6 when enabled).
       We'll perform a short synchronous wait for the callback. */
    dns_ctx_t dns_ctx = { .resolved = 0 };

    ip_addr_t tmp_addr;
    err_t derr = dns_gethostbyname(server, &tmp_addr, ntp_dns_cb, &dns_ctx);
    if (derr == ERR_OK) {
        dns_ctx.addr = tmp_addr;
        dns_ctx.resolved = 1;
    } else if (derr != ERR_INPROGRESS) {
        printf("NTP: DNS lookup failed for %s (err=%d)\n", server, derr);
        return false;
    } else {
        int waited = 0;
        while (!dns_ctx.resolved && waited < NTP_RECV_TIMEOUT_MS) {
            SLEEP_MS(50);
            waited += 50;
        }
        if (!dns_ctx.resolved) {
            printf("NTP: DNS resolution timeout for %s\n", server);
            return false;
        }
    }

    /* Prepare UDP PCB (request IPv6-capable PCB when available) */
    struct udp_pcb *pcb = NULL;
#if LWIP_UDP
#if LWIP_IPV6 && defined(udp_new_ip_type)
    pcb = udp_new_ip_type(IPADDR_TYPE_V6);
#else
    pcb = udp_new();
#endif
#endif
    if (!pcb) {
        printf("NTP: failed to allocate UDP pcb\n");
        return false;
    }

    /* Response capture */
    resp_t resp = { .got = 0, .len = 0 };

    /* Register UDP receive callback with resp as arg */
    udp_recv(pcb, ntp_udp_recv_cb, &resp);

    /* Connect to remote (works for v4 or v6 ip_addr_t) */
    err_t err = udp_connect(pcb, &dns_ctx.addr, 123);
    if (err != ERR_OK) {
        printf("NTP: udp_connect failed (%d)\n", err);
        udp_remove(pcb);
        return false;
    }

    /* Prepare and send NTP request (48 bytes, client mode) */
    uint8_t packet[48] = {0};
    packet[0] = 0x1B; /* LI = 0, VN = 3 (or 4), Mode = 3 (client) */

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, sizeof(packet), PBUF_RAM);
    if (!p) {
        printf("NTP: pbuf_alloc failed\n");
        udp_remove(pcb);
        return false;
    }
    memcpy(p->payload, packet, sizeof(packet));
    err = udp_send(pcb, p);
    pbuf_free(p);
    if (err != ERR_OK) {
        printf("NTP: udp_send failed (%d)\n", err);
        udp_remove(pcb);
        return false;
    }

    /* Wait for response (up to timeout) */
    int waited = 0;
    while (!resp.got && waited < NTP_RECV_TIMEOUT_MS) {
        SLEEP_MS(50);
        waited += 50;
    }

    if (!resp.got) {
        printf("NTP: no response from %s\n", server);
        udp_remove(pcb);
        return false;
    }

    if (resp.len < 48) {
        printf("NTP: short response (%d bytes)\n", resp.len);
        udp_remove(pcb);
        return false;
    }

    /* Transmit timestamp starts at byte 40 (big-endian seconds) */
    uint32_t secs_net = 0;
    secs_net |= ((uint32_t)resp.buf[40]) << 24;
    secs_net |= ((uint32_t)resp.buf[41]) << 16;
    secs_net |= ((uint32_t)resp.buf[42]) << 8;
    secs_net |= ((uint32_t)resp.buf[43]) << 0;
    uint32_t sec = ntohl(secs_net);
    if (sec == 0) {
        printf("NTP: invalid timestamp from %s\n", server);
        udp_remove(pcb);
        return false;
    }

    time_t unix_time = (time_t)(sec - NTP_TIMESTAMP_DELTA);
    struct timeval tv_set = { .tv_sec = unix_time, .tv_usec = 0 };
    if (settimeofday(&tv_set, NULL) != 0) {
        printf("NTP: settimeofday failed: %d (%s)\n", errno, strerror(errno));
        udp_remove(pcb);
        return false;
    }

    printf("NTP: time set from %s\n", server);
    print_time_now("Current time:");

    udp_remove(pcb);
    return true;
}
