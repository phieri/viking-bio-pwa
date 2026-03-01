#ifndef LWIPOPTS_H
#define LWIPOPTS_H

// Use single-threaded (no OS) mode
#define NO_SYS 1
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define MEM_LIBC_MALLOC 0

// IPv6 only (no IPv4 – Pico W CYW43 arch uses IPv6-only lwIP configuration)
#define LWIP_IPV4 0
#define LWIP_IPV6 1
#define LWIP_IPV6_AUTOCONFIG 1
#define LWIP_IPV6_ND 1
#define LWIP_IPV6_MLD 1
#define LWIP_IPV6_NUM_ADDRESSES 3

// Protocol support
#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_DNS 1
#define LWIP_AUTOIP 0
#define LWIP_IGMP 0
#define LWIP_ICMP 1
#define LWIP_RAW 0

// mDNS (for device hostname advertisement)
#define LWIP_MDNS_RESPONDER 1
#define MDNS_MAX_SERVICES 1

#define MEM_ALIGNMENT 4
#define MEM_SIZE (16 * 1024)

// TCP
#define TCP_MSS 1460
#define TCP_SND_BUF (4 * TCP_MSS)
#define TCP_SND_QUEUELEN ((2 * TCP_SND_BUF) / TCP_MSS)
#define TCP_WND (4 * TCP_MSS)
#define MEMP_NUM_TCP_PCB 4
#define MEMP_NUM_TCP_PCB_LISTEN 1
#define MEMP_NUM_TCP_SEG ((2 * TCP_SND_BUF) / TCP_MSS)

// Pbufs
#define MEMP_NUM_PBUF 12
#define PBUF_POOL_SIZE 16

// UDP
#define MEMP_NUM_UDP_PCB 4

// DNS
#define DNS_MAX_SERVERS 2
#define DNS_TABLE_SIZE 4

// Timers
// Base lwIP timers (TCP + DNS + IPv6 ND/REASS/MLD) use ~5 slots.
// The mDNS responder allocates additional sys_timeout slots at runtime
// during the probe/announce sequence. 14 is a safe value for this config.
#define MEMP_NUM_SYS_TIMEOUT 14

// ARP
#define ARP_TABLE_SIZE 4
#define ARP_QUEUEING 1
#define ETHARP_SUPPORT_STATIC_ENTRIES 0

// Netif client data (mDNS responder needs 1 slot)
#define LWIP_NUM_NETIF_CLIENT_DATA 1

// Keep-alive for TCP connection to proxy
#define LWIP_TCP_KEEPALIVE 1

// Checksums
#define LWIP_CHKSUM_ALGORITHM 3

// Timers
#define LWIP_TIMERS 1

// Performance
#define LWIP_STATS 0
#define LWIP_STATS_DISPLAY 0
#define LWIP_DEBUG 0

// Loopback
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
