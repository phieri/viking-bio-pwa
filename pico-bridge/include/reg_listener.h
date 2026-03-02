#ifndef REG_LISTENER_H
#define REG_LISTENER_H

#include <stdbool.h>

// UDP port on which the Pico listens for proxy registration announcements
#define REG_LISTENER_PORT 41234

/**
 * Start the UDP registration listener.
 *
 * Binds a UDP socket to REG_LISTENER_PORT on any IPv6 address and waits for
 * proxy announcement packets of the form:
 *   "VIKINGBIO <token> <ipv6addr> <port>"
 *
 * When a packet with a matching token (loaded from LittleFS via
 * wifi_config_load_hook_token) is received, the proxy address and port are
 * saved using wifi_config_save_server().
 *
 * Must be called after WiFi is connected and LittleFS is initialised.
 * @return true on success, false if the UDP socket could not be created/bound
 */
bool reg_listener_start(void);

#endif // REG_LISTENER_H
