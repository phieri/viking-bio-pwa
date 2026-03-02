#ifndef DNS_SD_BROWSER_H
#define DNS_SD_BROWSER_H

#include <stdbool.h>
#include <stdint.h>

/**
 * Callback invoked when a _viking-bio._tcp service is discovered via mDNS.
 * @param ip6addr  Proxy IPv6 address as a string (bare, no brackets)
 * @param port     Proxy HTTP port
 */
typedef void (*dns_sd_found_cb_t)(const char *ip6addr, uint16_t port);

/**
 * Start the passive mDNS service listener.
 *
 * Joins the ff02::fb IPv6 multicast group and binds a UDP socket to the mDNS
 * port (5353).  The Pico does not send any DNS queries; it only listens for
 * unsolicited mDNS service announcements sent by the proxy (bonjour) to the
 * multicast group.  When a complete record set (PTR + SRV + AAAA) for
 * _viking-bio._tcp is received, @p cb is invoked with the proxy address and
 * port.
 *
 * Note: because the Pico does not query, discovery depends on the proxy
 * sending a spontaneous announcement.  This happens automatically when the
 * proxy (re-)starts.  If the proxy was already running before the Pico
 * connected, restart the proxy to trigger a fresh announcement.
 *
 * Must be called after WiFi is connected.
 *
 * @param cb  Discovery callback (called from the lwIP poll context)
 * @return true on success
 */
bool dns_sd_browser_start(dns_sd_found_cb_t cb);

#endif // DNS_SD_BROWSER_H
