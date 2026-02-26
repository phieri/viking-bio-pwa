#ifndef LWIPOPTS_H
#define LWIPOPTS_H

// Use single-threaded (no OS) mode
#define NO_SYS 1
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define MEM_LIBC_MALLOC 0

// IPv4 support
#define LWIP_IPV4 1
#define LWIP_IPV6 0

// Protocol support
#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_DNS 1
#define LWIP_DHCP 1
#define LWIP_AUTOIP 0
#define LWIP_IGMP 0
#define LWIP_ICMP 1
#define LWIP_RAW 0

// AltCP (needed for TLS)
#define LWIP_ALTCP 1
#define LWIP_ALTCP_TLS 1
#define LWIP_ALTCP_TLS_MBEDTLS 1

// Memory configuration
#define MEM_SIZE (24 * 1024)

// TCP
#define TCP_MSS 1460
#define TCP_SND_BUF (8 * TCP_MSS)
#define TCP_SND_QUEUELEN ((4 * TCP_SND_BUF) / TCP_MSS)
#define TCP_WND (8 * TCP_MSS)
#define MEMP_NUM_TCP_PCB 8
#define MEMP_NUM_TCP_PCB_LISTEN 2
#define MEMP_NUM_TCP_SEG 16

// Pbufs
#define MEMP_NUM_PBUF 24
#define PBUF_POOL_SIZE 24

// UDP
#define MEMP_NUM_UDP_PCB 4

// DNS
#define DNS_MAX_SERVERS 2
#define DNS_TABLE_SIZE 4

// ARP
#define ARP_TABLE_SIZE 4
#define ARP_QUEUEING 1
#define ETHARP_SUPPORT_STATIC_ENTRIES 0

// Keep-alive for persistent SSE connections
#define LWIP_TCP_KEEPALIVE 1

// Checksums (use hardware acceleration where available)
#define LWIP_CHKSUM_ALGORITHM 3

// Netif client data (1 slot minimum)
#define LWIP_NUM_NETIF_CLIENT_DATA 1

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

#endif // LWIPOPTS_H
