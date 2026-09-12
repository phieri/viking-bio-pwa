/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

#ifndef DNS_SD_BROWSER_H
#define DNS_SD_BROWSER_H

#include <stdbool.h>
#include <stdint.h>

/**
 * Callback invoked when a _viking-bio._tcp service is discovered via mDNS.
 * @param ip6addr  Configurator IPv6 address as a string (bare, no brackets)
 * @param port     Configurator ingest TCP port
 */
typedef void (*dns_sd_found_cb_t)(const char *ip6addr, uint16_t port);

/**
 * Start the passive mDNS service listener.
 *
 * Joins the ff02::fb IPv6 multicast group and binds a UDP socket to the mDNS
 * port (5353).  The Pico does not send any DNS queries; it only listens for
 * unsolicited mDNS service announcements sent by the configurator (bonjour)
 * to the multicast group.  When a complete record set (PTR + SRV + AAAA) for
 * _viking-bio._tcp is received, @p cb is invoked with the configurator address
 * and port.
 *
 * The listener is only useful while the Pico does not have a live TCP session to
 * the configurator; active telemetry sessions are allowed to proceed without
 * listening for repeated mDNS traffic.
 *
 * Must be called after WiFi is connected.
 *
 * @param cb  Discovery callback (called from the lwIP poll context)
 * @return true on success
 */
bool dns_sd_browser_start(dns_sd_found_cb_t cb);

/**
 * Stop the passive mDNS listener.
 */
void dns_sd_browser_stop(void);

#endif // DNS_SD_BROWSER_H
