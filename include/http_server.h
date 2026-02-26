#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <stdint.h>
#include <stdbool.h>
#include "viking_bio_protocol.h"

// HTTP server port (configured via HTTPD_SERVER_PORT in lwipopts.h)
#define HTTP_SERVER_PORT 80

/**
 * Initialize the HTTP server (lwIP httpd with CGI/POST handlers).
 * Call after WiFi is connected.
 * @return true on success, false on failure
 */
bool http_server_init(void);

/**
 * Update cached Viking Bio data for API responses.
 * Call whenever new data is available from the serial protocol.
 * @param data Pointer to current Viking Bio data
 */
void http_server_update_data(const viking_bio_data_t *data);

/**
 * Get the VAPID public key in base64url format.
 * @param buf Output buffer
 * @param buf_size Size of output buffer (needs at least 88 bytes for uncompressed P-256 key)
 * @return Length of key string written, 0 on error
 */
size_t http_server_get_vapid_public_key(char *buf, size_t buf_size);

#endif // HTTP_SERVER_H
