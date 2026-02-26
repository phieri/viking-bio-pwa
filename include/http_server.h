#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <stdint.h>
#include <stdbool.h>
#include "viking_bio_protocol.h"

// HTTP server port
#define HTTP_SERVER_PORT 80

// Maximum number of simultaneous SSE connections
#define HTTP_MAX_SSE_CONNECTIONS 4

/**
 * Initialize the HTTP server
 * Call after WiFi is connected
 * @return true on success, false on failure
 */
bool http_server_init(void);

/**
 * Poll the HTTP server (call from main loop)
 * Processes pending connections and sends SSE data
 */
void http_server_poll(void);

/**
 * Broadcast Viking Bio data to all active SSE connections
 * Call whenever new data is available or periodically for keep-alive
 * @param data Pointer to current Viking Bio data
 */
void http_server_broadcast_data(const viking_bio_data_t *data);

/**
 * Get the VAPID public key in base64url format
 * @param buf Output buffer
 * @param buf_size Size of output buffer (needs at least 88 bytes for uncompressed P-256 key)
 * @return Length of key string written, 0 on error
 */
size_t http_server_get_vapid_public_key(char *buf, size_t buf_size);

#endif // HTTP_SERVER_H
