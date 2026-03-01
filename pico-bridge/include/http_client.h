#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include "viking_bio_protocol.h"

// Retry delay after a connection or HTTP failure (ms)
#define HTTP_CLIENT_RETRY_MS 5000

// Timeout waiting for a TCP connection or HTTP response (ms)
#define HTTP_CLIENT_TIMEOUT_MS 10000

/**
 * Initialize the HTTP webhook client.
 * @param host       Proxy server hostname or IP (IPv4 or bare IPv6 without brackets)
 * @param port       Proxy server port
 * @param auth_token X-Hook-Auth token (may be NULL or empty to omit the header)
 */
void http_client_init(const char *host, uint16_t port, const char *auth_token);

/**
 * Queue burner data for delivery to the proxy webhook endpoint.
 * If a request is already in-flight the queued data is replaced with the
 * latest value so the proxy always receives the most recent telemetry.
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

/**
 * Return the best estimate of the current Unix epoch time (seconds).
 * Initialised to BUILD_UNIX_TIME at startup; updated whenever the proxy
 * responds with a "server_time" field in the webhook acknowledgement.
 * @return Approximate Unix epoch seconds (0 if completely uninitialised)
 */
uint32_t http_client_get_epoch_time(void);

#endif // HTTP_CLIENT_H
