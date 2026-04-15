#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include "viking_bio_protocol.h"

// Retry delay after a connection failure (ms)
#define HTTP_CLIENT_RETRY_MS 5000

// Timeout waiting for a TCP connection or ingest activity (ms)
#define HTTP_CLIENT_TIMEOUT_MS 10000

/**
 * Initialize the persistent telemetry client.
 * @param host       Proxy server hostname or IP (IPv4 or bare IPv6 without brackets)
 * @param port       Proxy ingest TCP port
 * @param device_key Provisioned device key (may be NULL or empty when not provisioned yet)
 */
void http_client_init(const char *host, uint16_t port, const char *device_key);

/**
 * Queue burner data for delivery over the persistent telemetry connection.
 * @param data  Pointer to current burner data
 */
void http_client_send_data(const viking_bio_data_t *data);

/**
 * Poll the HTTP client state machine.
 * Must be called repeatedly from the main loop.
 */
void http_client_poll(void);

/**
 * Check whether the HTTP client currently has an active request in-flight.
 * @return true if connecting or waiting for a response
 */
bool http_client_is_active(void);

#endif // HTTP_CLIENT_H
