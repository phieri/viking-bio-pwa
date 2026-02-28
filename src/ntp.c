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

#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <lwip/inet.h>
// We'll implement a small SNTP query here instead of relying on
// lwIP's sntp app (avoids linker issues when the app isn't linked).

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

bool ntp_sync_time_for_country(const char *country) {
    const char *server = "pool.ntp.org";
    if (country && strcmp(country, "SE") == 0) {
        server = "ntp.se";
    }

    printf("NTP: querying server=%s\n", server);

    struct addrinfo hints;
    struct addrinfo *res = NULL, *rp = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC; /* allow IPv4 or IPv6 */

    int err = getaddrinfo(server, "123", &hints, &res);
    if (err != 0 || res == NULL) {
        printf("NTP: DNS lookup failed for %s: %s\n", server, gai_strerror(err));
        return false;
    }

    int sock = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        /* set recv timeout */
        struct timeval tv;
        tv.tv_sec = NTP_RECV_TIMEOUT_MS / 1000;
        tv.tv_usec = (NTP_RECV_TIMEOUT_MS % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        /* prepare NTP request (48 bytes, mode 3, version 4) */
        uint8_t packet[48] = {0};
        packet[0] = 0x1B; /* LI = 0, VN = 3 (or 4), Mode = 3 (client) */

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            ssize_t w = send(sock, packet, sizeof(packet), 0);
            if (w == sizeof(packet)) {
                uint8_t buf[512];
                ssize_t r = recv(sock, buf, sizeof(buf), 0);
                if (r >= 48) {
                    /* Transmit timestamp starts at byte 40 (big-endian seconds) */
                    uint32_t secs_net = 0;
                    secs_net |= ((uint32_t)buf[40]) << 24;
                    secs_net |= ((uint32_t)buf[41]) << 16;
                    secs_net |= ((uint32_t)buf[42]) << 8;
                    secs_net |= ((uint32_t)buf[43]) << 0;
                    uint32_t sec = ntohl(secs_net);
                    if (sec != 0) {
                        time_t unix_time = (time_t)(sec - NTP_TIMESTAMP_DELTA);
                        struct timeval tv_set = { .tv_sec = unix_time, .tv_usec = 0 };
                        if (settimeofday(&tv_set, NULL) != 0) {
                            printf("NTP: settimeofday failed: %d (%s)\n", errno, strerror(errno));
                            close(sock);
                            freeaddrinfo(res);
                            return false;
                        }
                        printf("NTP: time set from %s\n", server);
                        print_time_now("Current time:");
                        close(sock);
                        freeaddrinfo(res);
                        return true;
                    }
                }
            }
        }
        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    printf("NTP: failed to get time from %s\n", server);
    return false;
}
