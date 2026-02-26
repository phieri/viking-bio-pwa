#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "hardware/uart.h"
#include "hardware/gpio.h"
#include "hardware/watchdog.h"
#include "hardware/timer.h"
#include "serial_handler.h"
#include "viking_bio_protocol.h"
#include "http_server.h"
#include "push_manager.h"
#include "version.h"

// Event flags (modified from interrupt context)
volatile uint32_t event_flags = 0;

#define EVENT_SERIAL_DATA   (1 << 0)
#define EVENT_TIMEOUT_CHECK (1 << 2)
#define EVENT_BROADCAST     (1 << 4)  // Periodic SSE broadcast

// Broadcast interval: 2 seconds
#define BROADCAST_INTERVAL_MS 2000

bool periodic_timer_callback(struct repeating_timer *t) {
	(void)t;
	event_flags |= EVENT_TIMEOUT_CHECK | EVENT_BROADCAST;
	__sev();
	return true;
}

static bool wifi_connect(void) {
	printf("Connecting to WiFi SSID: %s\n", WIFI_SSID);

	if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD,
	                                        CYW43_AUTH_WPA2_AES_PSK, 30000) != 0) {
		printf("WiFi connection failed\n");
		return false;
	}

	printf("WiFi connected!\n");
	printf("IP address: %s\n", ip4addr_ntoa(netif_ip4_addr(netif_default)));
	return true;
}

int main(void) {
	stdio_init_all();
	sleep_ms(3000);

	printf("\n");
	version_print_info();
	printf("Viking Bio PWA starting...\n");

	// Initialize protocol parser
	printf("Initializing Viking Bio protocol parser...\n");
	viking_bio_init();

	// Initialize serial handler
	printf("Initializing serial handler...\n");
	serial_handler_init();

	// Initialize CYW43 / WiFi
	printf("Initializing WiFi...\n");
	if (cyw43_arch_init()) {
		printf("FATAL: cyw43_arch_init() failed\n");
		return 1;
	}
	cyw43_arch_enable_sta_mode();

	// Initialize push manager (VAPID keys)
	printf("Initializing push manager...\n");
	push_manager_init();

	// Connect to WiFi
	if (!wifi_connect()) {
		printf("FATAL: could not connect to WiFi\n");
		cyw43_arch_deinit();
		return 1;
	}

	// Start HTTP server
	printf("Starting HTTP server...\n");
	if (!http_server_init()) {
		printf("FATAL: http_server_init() failed\n");
		cyw43_arch_deinit();
		return 1;
	}

	// Enable watchdog (8 second timeout)
	watchdog_enable(8000, false);
	printf("Watchdog enabled (8s timeout)\n");

	// Periodic timer (every 2 seconds)
	struct repeating_timer timer;
	if (!add_repeating_timer_ms(BROADCAST_INTERVAL_MS, periodic_timer_callback, NULL, &timer)) {
		printf("WARNING: failed to init periodic timer\n");
	}

	printf("Initialization complete. Serving dashboard...\n");

	uint8_t buffer[SERIAL_BUFFER_SIZE];
	viking_bio_data_t viking_data;
	bool timeout_triggered = false;
	bool error_notified = false;

	memset(&viking_data, 0, sizeof(viking_data));

	while (true) {
		bool work_done = false;

		// Feed watchdog
		watchdog_update();

		// Process WiFi/lwIP
		cyw43_arch_poll();
		work_done = true;

		// Process serial data
		if (serial_handler_data_available()) {
			size_t bytes = serial_handler_read(buffer, sizeof(buffer));
			if (bytes > 0) {
				viking_bio_data_t new_data;
				if (viking_bio_parse_data(buffer, bytes, &new_data)) {
					memcpy(&viking_data, &new_data, sizeof(viking_data));
					timeout_triggered = false;

					// Broadcast new data via SSE
					http_server_broadcast_data(&viking_data);

					// Send push notification if error detected (only once per error)
					if (viking_data.error_code != 0 && !error_notified) {
						error_notified = true;
						char title[] = "Viking Bio 20 Error";
						char body[64];
						snprintf(body, sizeof(body), "Error code %d detected", viking_data.error_code);
						push_manager_notify_all(title, body, viking_data.error_code);
					} else if (viking_data.error_code == 0) {
						error_notified = false;
					}
				}
			}
			work_done = true;
		}

		// Periodic tasks
		if (event_flags & EVENT_TIMEOUT_CHECK) {
			event_flags &= ~EVENT_TIMEOUT_CHECK;

			if (!timeout_triggered && viking_bio_is_data_stale(VIKING_BIO_TIMEOUT_MS)) {
				timeout_triggered = true;
				printf("Viking Bio: no data for 30s - burner may be off\n");

				// Broadcast stale state
				viking_bio_data_t stale = {
					.flame_detected = false,
					.fan_speed = 0,
					.temperature = 0,
					.error_code = 0,
					.valid = false
				};
				http_server_broadcast_data(&stale);
			}

			work_done = true;
		}

		if (event_flags & EVENT_BROADCAST) {
			event_flags &= ~EVENT_BROADCAST;

			// Periodic keep-alive broadcast (only when data is fresh)
			if (!timeout_triggered) {
				viking_bio_data_t current;
				viking_bio_get_current_data(&current);
				if (current.valid) {
					http_server_broadcast_data(&current);
				}
			}

			// Poll push manager
			push_manager_poll();

			work_done = true;
		}

		// LED: on when WiFi connected
		cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN,
		                     (netif_is_up(netif_default) && netif_is_link_up(netif_default)) ? 1 : 0);

		// Sleep briefly when idle
		if (!work_done) {
			sleep_ms(10);
		}
	}

	return 0;
}
