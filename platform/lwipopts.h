#ifndef LWIPOPTS_H
#define LWIPOPTS_H

// Use single-threaded (no OS) mode
#define NO_SYS 1
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define MEM_LIBC_MALLOC 0

// IPv6 only (IPv4 disabled)
#define LWIP_IPV4 0
#define LWIP_IPV6 1
#define LWIP_IPV6_AUTOCONFIG 1      // Stateless Address Autoconfiguration (SLAAC)
#define LWIP_IPV6_ND 1              // Neighbor Discovery Protocol
#define LWIP_ND6_RDNSS 1            // Enable RDNSS support (Recursive DNS via RA)
#define LWIP_IPV6_RDNSS 1           // Alternate macro used in some lwIP versions
#define ND6_RDNSS_MAX_SERVERS 2     // Max RDNSS entries to accept from RA
#define LWIP_ND6_RDNSS_MAX_SERVERS 2
#define LWIP_IPV6_MLD 1             // Multicast Listener Discovery (required for mDNS)
#define LWIP_IPV6_NUM_ADDRESSES 3   // Max IPv6 addresses per interface

// Protocol support
#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_DNS 1
#define LWIP_AUTOIP 0
#define LWIP_IGMP 0
#define LWIP_ICMP 1
#define LWIP_RAW 0

// mDNS / DNS-SD
#define LWIP_MDNS_RESPONDER 1
#define MDNS_MAX_SERVICES 2

// AltCP (needed for TLS)
#define LWIP_ALTCP 1
#define LWIP_ALTCP_TLS 1
#define LWIP_ALTCP_TLS_MBEDTLS 1

#define MEM_ALIGNMENT 4
// Memory configuration (increased for IPv6 headers and mDNS)
#define MEM_SIZE (32 * 1024)

// TCP
#define TCP_MSS 1460
#define TCP_SND_BUF (4 * TCP_MSS)
#define TCP_SND_QUEUELEN ((2 * TCP_SND_BUF) / TCP_MSS)
#define TCP_WND (4 * TCP_MSS)
#define MEMP_NUM_TCP_PCB 8
#define MEMP_NUM_TCP_PCB_LISTEN 2
#define MEMP_NUM_TCP_SEG ((2 * TCP_SND_BUF) / TCP_MSS)

// Pbufs (increased for IPv6 headers)
#define MEMP_NUM_PBUF 24
#define PBUF_POOL_SIZE 32

// UDP
#define MEMP_NUM_UDP_PCB 6

// DNS
#define DNS_MAX_SERVERS 2
#define DNS_TABLE_SIZE 4

// Timers (increased from 4 to 8 to accommodate mDNS responder)
#define MEMP_NUM_SYS_TIMEOUT 8

// ARP (unused with IPv6 only, kept harmless)
#define ARP_TABLE_SIZE 4
#define ARP_QUEUEING 1
#define ETHARP_SUPPORT_STATIC_ENTRIES 0

// Netif client data (mDNS responder needs 1 slot)
#define LWIP_NUM_NETIF_CLIENT_DATA 1

// Keep-alive for persistent SSE connections
#define LWIP_TCP_KEEPALIVE 1

// HTTP server (lwIP httpd)
#define LWIP_HTTPD_CGI              1
#define LWIP_HTTPD_CGI_SSI          0
#define LWIP_HTTPD_SSI              0
#define LWIP_HTTPD_SUPPORT_POST     1
#define LWIP_HTTPD_CUSTOM_FILES     1
#define LWIP_HTTPD_DYNAMIC_HEADERS  1
#define LWIP_HTTPD_FILE_STATE       1
#define HTTPD_USE_CUSTOM_FSDATA     1
#define HTTPD_SERVER_PORT           80
#define LWIP_HTTPD_SUPPORT_V09      0
#define LWIP_HTTPD_SUPPORT_11_KEEPALIVE 0
#define LWIP_HTTPD_MAX_REQUEST_URI_LEN  128
#define LWIP_HTTPD_POST_MAX_RESPONSE_URI_LEN 64

// Checksums (use hardware acceleration where available)
#define LWIP_CHKSUM_ALGORITHM 3

// Timers
#define LWIP_TIMERS 1

// Performance
#define LWIP_STATS 0
#define LWIP_STATS_DISPLAY 0
#define LWIP_DEBUG 0

// Loopback interface
#define LWIP_HAVE_LOOPIF 0
#define LWIP_NETIF_LOOPBACK 0

// Multicast
#define LWIP_MULTICAST_TX_OPTIONS 0

// SNMP
#define LWIP_SNMP 0

// API
#define LWIP_CALLBACK_API 1


#define ETHARP_DEBUG                LWIP_DBG_OFF
#define NETIF_DEBUG                 LWIP_DBG_OFF
#define PBUF_DEBUG                  LWIP_DBG_OFF
#define API_LIB_DEBUG               LWIP_DBG_OFF
#define API_MSG_DEBUG               LWIP_DBG_OFF
#define SOCKETS_DEBUG               LWIP_DBG_OFF
#define ICMP_DEBUG                  LWIP_DBG_OFF
#define INET_DEBUG                  LWIP_DBG_OFF
#define IP_DEBUG                    LWIP_DBG_OFF
#define IP_REASS_DEBUG              LWIP_DBG_OFF
#define RAW_DEBUG                   LWIP_DBG_OFF
#define MEM_DEBUG                   LWIP_DBG_OFF
#define MEMP_DEBUG                  LWIP_DBG_OFF
#define SYS_DEBUG                   LWIP_DBG_OFF
#define TCP_DEBUG                   LWIP_DBG_OFF
#define TCP_INPUT_DEBUG             LWIP_DBG_OFF
#define TCP_OUTPUT_DEBUG            LWIP_DBG_OFF
#define TCP_RTO_DEBUG               LWIP_DBG_OFF
#define TCP_CWND_DEBUG              LWIP_DBG_OFF
#define TCP_WND_DEBUG               LWIP_DBG_OFF
#define TCP_FR_DEBUG                LWIP_DBG_OFF
#define TCP_QLEN_DEBUG              LWIP_DBG_OFF
#define TCP_RST_DEBUG               LWIP_DBG_OFF
#define UDP_DEBUG                   LWIP_DBG_OFF
#define TCPIP_DEBUG                 LWIP_DBG_OFF
#define PPP_DEBUG                   LWIP_DBG_OFF
#define SLIP_DEBUG                  LWIP_DBG_OFF
#define DHCP_DEBUG                  LWIP_DBG_OFF

#endif // LWIPOPTS_H
