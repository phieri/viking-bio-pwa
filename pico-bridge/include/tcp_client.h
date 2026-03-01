#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include "viking_bio_protocol.h"

// Default proxy server port
#define TCP_CLIENT_DEFAULT_PORT 9000

// Reconnect delay after connection failure (ms)
#define TCP_CLIENT_RECONNECT_MS 5000

/**
 * Initialize the TCP client.
 * @param server_ip  Proxy server IP address string (IPv4 or IPv6)
 * @param port       Proxy server TCP port
 */
void tcp_client_init(const char *server_ip, uint16_t port);

/**
 * Send burner data to the proxy server as a JSON message.
 * If not connected, queues the data and sends on reconnection.
 * @param data  Pointer to current burner data
 */
void tcp_client_send_data(const viking_bio_data_t *data);

/**
 * Poll the TCP client state machine.
 * Must be called repeatedly from the main loop.
 */
void tcp_client_poll(void);

/**
 * Check whether the TCP client is currently connected.
 * @return true if connected
 */
bool tcp_client_is_connected(void);

#endif // TCP_CLIENT_H
