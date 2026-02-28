#include "ntp.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

// NTP time starts on 1900, Unix time on 1970
#define NTP_TIMESTAMP_DELTA 2208988800UL

// Timeout in milliseconds for NTP response
#define NTP_RECV_TIMEOUT_MS 3000

static void print_time_now(const char *prefix) {
    time_t t = time(NULL);
    struct tm tm;
    if (gmtime_r(&t, &tm)) {
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm);
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

    printf("NTP: resolving %s\n", server);

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    char port[] = "123";
    int rc = getaddrinfo(server, port, &hints, &res);
    if (rc != 0 || res == NULL) {
        printf("NTP: getaddrinfo failed: %s\n", gai_strerror(rc));
        return false;
    }

    int sock = -1;
    struct addrinfo *rp;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;

        // Set recv timeout
        struct timeval tv;
        tv.tv_sec = NTP_RECV_TIMEOUT_MS / 1000;
        tv.tv_usec = (NTP_RECV_TIMEOUT_MS % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Prepare NTP request (48 bytes)
        uint8_t packet[48] = {0};
        packet[0] = 0x1B; // LI = 0, VN = 3, Mode = 3 (client)

        ssize_t sent = sendto(sock, packet, sizeof(packet), 0,
                              rp->ai_addr, rp->ai_addrlen);
        if (sent != sizeof(packet)) {
            close(sock);
            sock = -1;
            continue;
        }

        // Receive response
        uint8_t recvbuf[48];
        ssize_t recvd = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
        if (recvd < 48) {
            close(sock);
            sock = -1;
            continue;
        }

        // Transmit Timestamp starts at byte 40 (index 40..47)
        uint32_t sec = (recvbuf[40] << 24) | (recvbuf[41] << 16) | (recvbuf[42] << 8) | (recvbuf[43]);
        uint32_t frac = (recvbuf[44] << 24) | (recvbuf[45] << 16) | (recvbuf[46] << 8) | (recvbuf[47]);

        time_t unix_time = (time_t)(sec - NTP_TIMESTAMP_DELTA);
        long usec = (long)((uint64_t)frac * 1000000ULL >> 32);

        struct timeval tv_set = { .tv_sec = unix_time, .tv_usec = usec };
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

    if (res) freeaddrinfo(res);
    printf("NTP: failed to contact server %s\n", server);
    return false;
}
