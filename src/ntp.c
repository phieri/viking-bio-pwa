#include "ntp.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <lwip/inet.h>
#include <lwip/apps/sntp.h>

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

    printf("NTP: using lwIP SNTP, server=%s\n", server);

    /* Configure SNTP server and start SNTP client */
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, server);
    sntp_init();

    /* Poll for a result until timeout */
    int waited_ms = 0;
    uint32_t sec = 0;
    while (waited_ms < NTP_RECV_TIMEOUT_MS) {
        sec = sntp_get_current_timestamp();
        if (sec != 0) break;
        usleep(100 * 1000); /* 100 ms */
        waited_ms += 100;
    }

    if (sec == 0) {
        printf("NTP: SNTP failed to get time within %d ms\n", NTP_RECV_TIMEOUT_MS);
        sntp_stop();
        return false;
    }

    /* sec is seconds since 1900 per NTP; convert to unix epoch */
    time_t unix_time = (time_t)(sec - NTP_TIMESTAMP_DELTA);
    struct timeval tv_set = { .tv_sec = unix_time, .tv_usec = 0 };
    if (settimeofday(&tv_set, NULL) != 0) {
        printf("NTP: settimeofday failed: %d (%s)\n", errno, strerror(errno));
        sntp_stop();
        return false;
    }

    printf("NTP: time set from %s\n", server);
    print_time_now("Current time:");

    sntp_stop();
    return true;
}
