/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include "vikingbio.h"

// Retry delay after a connection failure (ms)
#define TCP_CLIENT_RETRY_MS 5000

// Timeout waiting for a TCP connection or ingest activity (ms)
#define TCP_CLIENT_TIMEOUT_MS 10000

/**
 * Initialize the persistent telemetry client.
 * @param host       Configurator server hostname or IP (IPv4 or bare IPv6 without brackets)
 * @param port       Configurator ingest TCP port
 * @param device_key Provisioned device key (may be NULL or empty when not provisioned yet)
 */
void tcp_client_init(const char *host, uint16_t port, const char *device_key);

/**
 * Queue burner data for delivery over the persistent telemetry connection.
 * @param data  Pointer to current burner data
 */
void tcp_client_send_data(const vikingbio_data_t *data);

/**
 * Poll the TCP telemetry client state machine.
 * Must be called repeatedly from the main loop.
 */
void tcp_client_poll(void);

/**
 * Check whether the TCP telemetry client is currently connected or connecting.
 * @return true if the persistent ingest connection is active
 */
[[nodiscard]] bool tcp_client_is_active(void);

#endif // TCP_CLIENT_H
