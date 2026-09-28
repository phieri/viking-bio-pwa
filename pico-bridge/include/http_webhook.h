/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

#ifndef HTTP_WEBHOOK_H
#define HTTP_WEBHOOK_H

#include <stdbool.h>

#include "vikingbio.h"

/**
 * Initialize the outbound webhook client using the saved WEBHOOK= URL from storage.
 */
void http_webhook_init(void);

/**
 * Override the configured webhook URL for the next request cycle.
 * @param url Absolute HTTP(S) webhook URL. HTTPS delivery is currently disabled
 *            rather than falling back to unencrypted TCP: this firmware does not
 *            provision CA trust anchors or a trusted wall clock for verification.
 */
void http_webhook_set_url(const char *url);

/**
 * Whether a valid webhook URL is currently configured.
 */
bool http_webhook_is_configured(void);

/**
 * Queue an outbound webhook alert payload. The payload is delivered asynchronously,
 * and the current TCP telemetry stream remains untouched.
 * @param data  Burner data snapshot used for the alert payload.
 * @param type  Alert category (for example "flame" or "error").
 * @param detail Optional short detail string.
 */
void http_webhook_send_alert(const vikingbio_data_t *data, const char *type, const char *detail);

/**
 * Poll the outbound webhook client state machine. Must be called repeatedly from the
 * main loop while Wi-Fi is up, outside the CYW43 lwIP lock (which this function
 * acquires internally).
 */
void http_webhook_poll(void);

#endif // HTTP_WEBHOOK_H
