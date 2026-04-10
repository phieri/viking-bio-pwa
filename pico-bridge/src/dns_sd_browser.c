#include <string.h>
#include <strings.h>
#include <stdio.h>
#include "pico/stdlib.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/mld6.h"
#include "lwip/netif.h"
#include "dns_sd_browser.h"

/*
 * Passive mDNS service listener for _viking-bio._tcp.
 *
 * The Pico joins the ff02::fb IPv6 multicast group and listens on UDP port
 * 5353 for unsolicited mDNS announcements sent by the proxy (bonjour).  No
 * DNS queries are sent by the Pico; discovery is entirely passive.
 *
 * A complete DNS-SD record set consists of:
 *   PTR  _viking-bio._tcp.local  → <instance>._viking-bio._tcp.local
 *   SRV  <instance>...           → priority weight port <hostname>
 *   AAAA <hostname>              → 16-byte IPv6 address
 *
 * The callback is invoked once the SRV port and AAAA address are extracted
 * from the same mDNS packet.
 */

#define MDNS_PORT 5353
#define MDNS_MCAST_ADDR "ff02::fb"

/* DNS record types */
#define DNS_TYPE_PTR 12
#define DNS_TYPE_SRV 33
#define DNS_TYPE_AAAA 28

/* Service type label expected in SRV/PTR names */
#define SERVICE_LABEL "_viking-bio._tcp"

/* Maximum DNS records scanned in a single response */
#define DNS_MAX_SCAN_RECORDS 16

/* Maximum AAAA candidates collected per target in pass 2 */
#define DNS_MAX_AAAA_CANDIDATES 4

/* Receive buffer: mDNS packets are at most 9000 bytes; 512 is enough here */
#define MDNS_BUF_SIZE 512

static struct udp_pcb *s_pcb = NULL;
static dns_sd_found_cb_t s_found_cb = NULL;

/* ---------------------------------------------------------------------------
 * DNS name helpers
 * ------------------------------------------------------------------------- */

/*
 * Decode a DNS name from wire format into a dotted-label string.
 * Handles pointer compression (labels with 0xC0 prefix).
 *
 * Returns the offset *after* the name in the original packet (i.e. where the
 * next field starts), or -1 on error.  When the name starts with a pointer,
 * the returned offset is still just after the 2-byte pointer — not after the
 * data the pointer points to.
 */
static int dns_decode_name(const uint8_t *pkt, int pkt_len, int offset, char *out, int out_size) {
	int out_pos = 0;
	int end_offset = -1;
	int steps = 0; /* guard against infinite pointer loops */

	while (steps++ < 64 && offset < pkt_len) {
		uint8_t b = pkt[offset];

		if (b == 0) {
			if (end_offset == -1)
				end_offset = offset + 1;
			break;
		}

		if ((b & 0xC0) == 0xC0) {
			/* Compression pointer */
			if (offset + 2 > pkt_len)
				return -1;
			if (end_offset == -1)
				end_offset = offset + 2;
			offset = ((b & 0x3F) << 8) | pkt[offset + 1];
			continue;
		}

		/* Regular label */
		int label_len = (int)b;
		offset++;
		if (offset + label_len > pkt_len)
			return -1;

		if (out_pos > 0) {
			if (out_pos + 1 >= out_size)
				return -1;
			out[out_pos++] = '.';
		}
		if (out_pos + label_len >= out_size)
			return -1;
		memcpy(out + out_pos, pkt + offset, (size_t)label_len);
		out_pos += label_len;
		offset += label_len;
	}

	if (out_pos < out_size)
		out[out_pos] = '\0';
	return end_offset;
}

/*
 * Skip over a DNS name in wire format.
 * Returns the offset after the name, or -1 on error.
 */
static int dns_skip_name(const uint8_t *pkt, int pkt_len, int offset) {
	int steps = 0;
	while (steps++ < 64 && offset < pkt_len) {
		uint8_t b = pkt[offset];
		if (b == 0)
			return offset + 1;
		if ((b & 0xC0) == 0xC0)
			return (offset + 2 <= pkt_len) ? offset + 2 : -1;
		offset += 1 + (int)b;
	}
	return -1;
}

/* ---------------------------------------------------------------------------
 * IPv6 address helper
 * ------------------------------------------------------------------------- */

/*
 * Convert 16 network-order bytes from a DNS AAAA rdata field into a lwIP
 * ip6_addr_t and format it as a string using ip6addr_ntoa.
 *
 * lwIP stores ip6_addr_t::addr[4] in host byte order (each uint32_t is the
 * big-endian word value converted to host order).  The raw DNS bytes are in
 * network byte order, so each 4-byte chunk must be converted with ntohl.
 */
static void format_aaaa(const uint8_t *bytes, char *out, size_t out_size) {
	ip6_addr_t a;
	for (int i = 0; i < 4; i++) {
		const uint8_t *p = bytes + i * 4;
		uint32_t w = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
					 (uint32_t)p[3];
		a.addr[i] = lwip_ntohl(w);
	}
	ip6_addr_set_zone(&a, 0);
	snprintf(out, out_size, "%s", ip6addr_ntoa(&a));
}

/* ---------------------------------------------------------------------------
 * DNS response parser
 * ------------------------------------------------------------------------- */

/*
 * Parse a received mDNS packet and invoke s_found_cb if it contains a
 * complete _viking-bio._tcp record set (PTR + SRV + AAAA).
 *
 * Two-pass scan:
 *   Pass 1 – find a SRV record whose name contains "_viking-bio._tcp";
 *             extract port and target hostname.
 *   Pass 2 – collect all AAAA records for that target hostname, then select
 *             an address by this policy:
 *               a) prefer link-local (fe80::/10)
 *               b) else prefer ULA (fc00::/7, covers fc00:: and fd00::)
 *               c) ignore packets where only global addresses were found
 *             Only invoke the callback when a local-only address was selected.
 */
static void parse_mdns_packet(const uint8_t *data, int len) {
	if (len < 12)
		return;

	uint16_t flags = ((uint16_t)data[2] << 8) | data[3];
	uint16_t qdcount = ((uint16_t)data[4] << 8) | data[5];
	uint16_t ancount = ((uint16_t)data[6] << 8) | data[7];
	uint16_t arcount = ((uint16_t)data[10] << 8) | data[11];

	/* Must be a DNS response (QR bit set) */
	if (!(flags & 0x8000))
		return;

	int offset = 12;

	/* Skip question section */
	for (int i = 0; i < (int)qdcount; i++) {
		offset = dns_skip_name(data, len, offset);
		if (offset < 0 || offset + 4 > len)
			return;
		offset += 4; /* type + class */
	}

	/* Records start here; answers + additional (skip authority) */
	int records_start = offset;
	int total = (int)ancount + (int)arcount;
	if (total > DNS_MAX_SCAN_RECORDS)
		total = DNS_MAX_SCAN_RECORDS;

	/* Pass 1: find the SRV record for a _viking-bio._tcp instance */
	uint16_t srv_port = 0;
	char srv_target[64] = {0};

	int scan = records_start;
	for (int i = 0; i < total && scan >= 0 && scan < len; i++) {
		char name[64];
		int after_name = dns_decode_name(data, len, scan, name, sizeof(name));
		if (after_name < 0 || after_name + 10 > len)
			return;

		uint16_t rtype = ((uint16_t)data[after_name + 0] << 8) | data[after_name + 1];
		uint16_t rdlen = ((uint16_t)data[after_name + 8] << 8) | data[after_name + 9];
		int rdata_start = after_name + 10;
		if (rdata_start + rdlen > len)
			return;

		if (rtype == DNS_TYPE_SRV && rdlen >= 7 && strstr(name, SERVICE_LABEL) != NULL) {
			uint16_t port = ((uint16_t)data[rdata_start + 4] << 8) | data[rdata_start + 5];
			char target[64];
			if (dns_decode_name(data, len, rdata_start + 6, target, sizeof(target)) >= 0) {
				srv_port = port;
				snprintf(srv_target, sizeof(srv_target), "%s", target);
			}
		}

		scan = rdata_start + rdlen;
	}

	if (!srv_port || !srv_target[0])
		return;

	/* Pass 2: collect all AAAA records for the SRV target.
	 * Store up to DNS_MAX_AAAA_CANDIDATES raw 16-byte addresses (network order). */
	uint8_t candidates[DNS_MAX_AAAA_CANDIDATES][16];
	int ncandidates = 0;

	scan = records_start;
	for (int i = 0; i < total && scan >= 0 && scan < len; i++) {
		char name[64];
		int after_name = dns_decode_name(data, len, scan, name, sizeof(name));
		if (after_name < 0 || after_name + 10 > len)
			return;

		uint16_t rtype = ((uint16_t)data[after_name + 0] << 8) | data[after_name + 1];
		uint16_t rdlen = ((uint16_t)data[after_name + 8] << 8) | data[after_name + 9];
		int rdata_start = after_name + 10;
		if (rdata_start + rdlen > len)
			return;

		if (rtype == DNS_TYPE_AAAA && rdlen == 16) {
			/* Strip trailing dot and compare names (case-insensitive) */
			char srv_bare[64], rec_bare[64];
			snprintf(srv_bare, sizeof(srv_bare), "%s", srv_target);
			snprintf(rec_bare, sizeof(rec_bare), "%s", name);
			size_t slen = strlen(srv_bare);
			size_t rlen2 = strlen(rec_bare);
			if (slen > 0 && srv_bare[slen - 1] == '.')
				srv_bare[slen - 1] = '\0';
			if (rlen2 > 0 && rec_bare[rlen2 - 1] == '.')
				rec_bare[rlen2 - 1] = '\0';

			if (strcasecmp(srv_bare, rec_bare) == 0 && ncandidates < DNS_MAX_AAAA_CANDIDATES) {
				memcpy(candidates[ncandidates], data + rdata_start, 16);
				ncandidates++;
			}
		}

		scan = rdata_start + rdlen;
	}

	if (ncandidates == 0)
		return;

	/* Select address by local-only policy:
	 *   a) Link-local (fe80::/10): first byte 0xfe, second byte top 2 bits = 10
	 *   b) ULA (fc00::/7): first byte top 7 bits = 1111110 (covers fc00:: and fd00::)
	 *   c) Global addresses are ignored; do not call the callback.
	 */
	const uint8_t *selected = NULL;
	const char *kind = NULL;

	/* First preference: link-local (fe80::/10) */
	for (int i = 0; i < ncandidates && !selected; i++) {
		const uint8_t *b = candidates[i];
		if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) {
			selected = b;
			kind = "link-local";
		}
	}

	/* Second preference: ULA (fc00::/7) */
	for (int i = 0; i < ncandidates && !selected; i++) {
		const uint8_t *b = candidates[i];
		if ((b[0] & 0xfe) == 0xfc) {
			selected = b;
			kind = "ULA";
		}
	}

	if (!selected) {
		printf("dns_sd: ignoring packet – %d AAAA record(s) found but none are link-local or ULA\n",
			   ncandidates);
		return;
	}

	char ip_str[40];
	format_aaaa(selected, ip_str, sizeof(ip_str));
	printf("dns_sd: selected %s address %s:%d\n", kind, ip_str, (int)srv_port);
	if (s_found_cb) {
		s_found_cb(ip_str, srv_port);
	}
}

/* ---------------------------------------------------------------------------
 * UDP receive callback
 * ------------------------------------------------------------------------- */

static void mdns_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr,
						 u16_t port) {
	(void)arg;
	(void)pcb;
	(void)addr;
	(void)port;
	if (!p)
		return;

	uint8_t buf[MDNS_BUF_SIZE];
	uint16_t pkt_len = p->tot_len > sizeof(buf) ? (uint16_t)sizeof(buf) : p->tot_len;
	pbuf_copy_partial(p, buf, pkt_len, 0);
	pbuf_free(p);

	parse_mdns_packet(buf, (int)pkt_len);
}

/* ---------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

bool dns_sd_browser_start(dns_sd_found_cb_t cb) {
	s_found_cb = cb;

	s_pcb = udp_new();
	if (!s_pcb) {
		printf("dns_sd: udp_new() failed\n");
		return false;
	}

	/* Bind to the mDNS port on any IPv6 address */
	err_t err = udp_bind(s_pcb, IP6_ADDR_ANY, MDNS_PORT);
	if (err != ERR_OK) {
		printf("dns_sd: udp_bind(%d) failed (%d)\n", MDNS_PORT, (int)err);
		udp_remove(s_pcb);
		s_pcb = NULL;
		return false;
	}

	/* Join the mDNS IPv6 multicast group so the NIC accepts these packets */
	ip_addr_t mcast_ip;
	ipaddr_aton(MDNS_MCAST_ADDR, &mcast_ip);
	err_t mld_err = mld6_joingroup_netif(netif_default, ip_2_ip6(&mcast_ip));
	if (mld_err != ERR_OK) {
		printf("dns_sd: mld6_joingroup() failed (%d) – may not receive announcements\n",
			   (int)mld_err);
	}

	udp_recv(s_pcb, mdns_recv_cb, NULL);

	printf("dns_sd: passive listener started (port %d, group %s)\n", MDNS_PORT, MDNS_MCAST_ADDR);
	return true;
}
