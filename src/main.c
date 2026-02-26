#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "pico/unique_id.h"
#include "hardware/watchdog.h"
#include "lwip/netif.h"
#include "lwip/ip6_addr.h"
#include "lwip/apps/mdns.h"
#include "serial_handler.h"
#include "viking_bio_protocol.h"
#include "http_server.h"
#include "push_manager.h"
#include "wifi_config.h"
#include "lfs_hal.h"
#include "version.h"

// Event flags (modified from interrupt context)
volatile uint32_t event_flags = 0;

#define EVENT_SERIAL_DATA   (1 << 0)
#define EVENT_TIMEOUT_CHECK (1 << 2)
#define EVENT_BROADCAST     (1 << 4)  // Periodic data update

// Broadcast interval: 2 seconds
#define BROADCAST_INTERVAL_MS 2000

// Watchdog timeout: 8 seconds
#define WATCHDOG_TIMEOUT_MS 8000

// Watchdog-based software reboot delay (milliseconds)
#define WATCHDOG_REBOOT_MS 1

// --- LED state ---
static absolute_time_t s_led_blink_time;   // Next 2 Hz toggle when disconnected
static absolute_time_t s_serial_blink_end; // Serial-data short-blink deadline
static bool s_led_blink_on = false;

static void led_update(void) {
	bool wifi_up = (netif_default != NULL) &&
	               netif_is_up(netif_default) &&
	               netif_is_link_up(netif_default);

	// Short blink overrides everything (serial data received)
	if (!time_reached(s_serial_blink_end)) {
		cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
		return;
	}

	if (wifi_up) {
		// Steady LED when connected
		cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
	} else {
		// Blink at 2 Hz (250 ms on / 250 ms off) when not connected
		if (time_reached(s_led_blink_time)) {
			s_led_blink_on = !s_led_blink_on;
			s_led_blink_time = make_timeout_time_ms(250);
			cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, s_led_blink_on ? 1 : 0);
		}
	}
}

// --- USB serial WiFi configuration ---
static char s_usb_buf[160];
static size_t s_usb_buf_len = 0;
static char s_pending_ssid[WIFI_SSID_MAX_LEN + 1];
static bool s_has_pending_ssid = false;

// Returns true when new credentials have been saved (caller should reboot).
static bool process_usb_commands(void) {
	int c;
	while ((c = getchar_timeout_us(0)) != PICO_ERROR_TIMEOUT) {
		if (c == '\r') continue;

		if (c == '\n' || s_usb_buf_len >= sizeof(s_usb_buf) - 1) {
			s_usb_buf[s_usb_buf_len] = '\0';
			s_usb_buf_len = 0;

			if (strncmp(s_usb_buf, "SSID=", 5) == 0) {
				snprintf(s_pending_ssid, sizeof(s_pending_ssid), "%s", s_usb_buf + 5);
				s_has_pending_ssid = true;
				printf("wifi: SSID staged – send PASS=<password> to save\n");

			} else if (strncmp(s_usb_buf, "PASS=", 5) == 0) {
				if (!s_has_pending_ssid) {
					printf("wifi: send SSID=<ssid> first\n");
				} else {
					const char *pass = s_usb_buf + 5;
					if (wifi_config_save(s_pending_ssid, pass)) {
						printf("wifi: credentials saved – rebooting\n");
						s_has_pending_ssid = false;
						return true;
					} else {
						printf("wifi: ERROR saving credentials\n");
					}
				}

			} else if (strncmp(s_usb_buf, "COUNTRY=", 8) == 0) {
				const char *code = s_usb_buf + 8;
				if (strlen(code) == 2 &&
				    isupper((unsigned char)code[0]) &&
				    isupper((unsigned char)code[1])) {
					if (wifi_config_save_country(code)) {
						printf("wifi: country set to %s – reboot to apply\n", code);
					} else {
						printf("wifi: ERROR saving country\n");
					}
				} else {
					printf("wifi: country must be 2 uppercase letters (e.g. SE, US, GB)\n");
				}

			} else if (strcmp(s_usb_buf, "STATUS") == 0) {
				bool up = (netif_default != NULL) &&
				          netif_is_up(netif_default) &&
				          netif_is_link_up(netif_default);
				printf("wifi: %s\n", up ? "connected" : "disconnected");
				if (up) {
					for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
						if (ip6_addr_isvalid(netif_ip6_addr_state(netif_default, i))) {
							printf("  IPv6[%d]: %s\n", i,
							       ip6addr_ntoa(netif_ip6_addr(netif_default, i)));
						}
					}
				}
				char cc[3] = "XX";
				wifi_config_load_country(cc, sizeof(cc));
				printf("  country: %s\n", cc);

			} else if (strcmp(s_usb_buf, "CLEAR") == 0) {
				wifi_config_clear();
				printf("wifi: credentials cleared – rebooting\n");
				return true;

			} else if (s_usb_buf[0] != '\0') {
				printf("wifi: unknown command '%s'\n", s_usb_buf);
				printf("  SSID=<ssid>      – set SSID\n");
				printf("  PASS=<pass>      – set password and save\n");
				printf("  COUNTRY=<CC>     – set Wi-Fi country (e.g. SE, US)\n");
				printf("  STATUS           – show WiFi status\n");
				printf("  CLEAR            – erase stored credentials\n");
			}
		} else {
			s_usb_buf[s_usb_buf_len++] = (char)c;
		}
	}
	return false;
}

bool periodic_timer_callback(struct repeating_timer *t) {
	(void)t;
	event_flags |= EVENT_TIMEOUT_CHECK | EVENT_BROADCAST;
	__sev();
	return true;
}

static bool wifi_connect(const char *ssid, const char *password) {
	printf("Connecting to WiFi SSID: %s\n", ssid);

	if (cyw43_arch_wifi_connect_timeout_ms(ssid, password,
	                                        CYW43_AUTH_WPA2_AES_PSK, 30000) != 0) {
		printf("WiFi connection failed\n");
		return false;
	}

	printf("WiFi connected\n");

	// Wait for at least one valid IPv6 address (link-local, up to 5 s)
	absolute_time_t ipv6_wait = make_timeout_time_ms(5000);
	while (!time_reached(ipv6_wait)) {
		cyw43_arch_poll();
		if (ip6_addr_isvalid(netif_ip6_addr_state(netif_default, 0))) break;
		sleep_ms(50);
	}

	for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
		if (ip6_addr_isvalid(netif_ip6_addr_state(netif_default, i))) {
			printf("  IPv6[%d]: %s\n", i,
			       ip6addr_ntoa(netif_ip6_addr(netif_default, i)));
		}
	}
	return true;
}

static void mdns_setup(void) {
	// Build a unique hostname: viking-bio-XXYY (last 2 bytes of board ID)
	pico_unique_board_id_t uid;
	pico_get_unique_board_id(&uid);
	char hostname[32];
	snprintf(hostname, sizeof(hostname), "viking-bio-%02x%02x",
	         uid.id[6], uid.id[7]);

	mdns_resp_add_netif(netif_default, hostname);
	mdns_resp_add_service(netif_default, "Viking-Bio-20", "_http",
	                      DNSSD_PROTO_TCP, HTTP_SERVER_PORT, NULL, NULL);
	printf("mDNS: %s.local registered (_http._tcp port %d)\n",
	       hostname, HTTP_SERVER_PORT);
}

int main(void) {
	stdio_init_all();
	sleep_ms(2000);

	printf("\n");
	version_print_info();
	printf("Viking Bio PWA starting...\n");

	// Initialise LED timing state
	s_led_blink_time = get_absolute_time();
	s_serial_blink_end = get_absolute_time();  // already in the past

	// Initialize protocol parser
	printf("Initializing Viking Bio protocol parser...\n");
	viking_bio_init();

	// Initialize serial handler
	printf("Initializing serial handler...\n");
	serial_handler_init();

	// Initialize LittleFS filesystem (must be before wifi_config and push_manager)
	printf("Initializing LittleFS...\n");
	if (!lfs_hal_init()) {
		printf("WARNING: LittleFS initialization failed\n");
	}

	// Initialize WiFi credential store
	wifi_config_init();

	// Load WiFi country code (default: worldwide)
	char country[3] = "XX";
	wifi_config_load_country(country, sizeof(country));
	printf("WiFi country: %s\n", country);

	// Initialize CYW43 / WiFi with country setting
	printf("Initializing WiFi...\n");
	uint32_t cyw43_country = wifi_config_country_to_cyw43(country);
	if (cyw43_arch_init_with_country(cyw43_country)) {
		printf("FATAL: cyw43_arch_init_with_country() failed\n");
		return 1;
	}
	cyw43_arch_enable_sta_mode();

	// Initialize push manager (VAPID keys)
	printf("Initializing push manager...\n");
	push_manager_init();

	// Initialize mDNS responder (must be before any mdns_resp_add_netif call)
	mdns_resp_init();

	// Load WiFi credentials: stored takes precedence, then compile-time fallback
	char ssid[WIFI_SSID_MAX_LEN + 1] = {0};
	char password[WIFI_PASS_MAX_LEN + 1] = {0};
	bool have_creds = wifi_config_load(ssid, sizeof(ssid), password, sizeof(password));

#if WIFI_COMPILE_CREDS_VALID
	if (!have_creds) {
		snprintf(ssid, sizeof(ssid), "%s", WIFI_SSID);
		snprintf(password, sizeof(password), "%s", WIFI_PASSWORD);
		have_creds = true;
	}
#endif

	bool http_started = false;
	bool watchdog_on = false;

	if (have_creds && wifi_connect(ssid, password)) {
		// Start HTTP server
		printf("Starting HTTP server...\n");
		if (!http_server_init()) {
			printf("FATAL: http_server_init() failed\n");
			cyw43_arch_deinit();
			return 1;
		}
		mdns_setup();
		http_started = true;

		// Enable watchdog only after successful WiFi + HTTP setup
		watchdog_enable(WATCHDOG_TIMEOUT_MS, false);
		watchdog_on = true;
		printf("Watchdog enabled (%d ms timeout)\n", WATCHDOG_TIMEOUT_MS);
	} else {
		printf("\nWiFi not connected. Configure credentials via USB serial:\n");
		printf("  SSID=<your-network>  (then press Enter)\n");
		printf("  PASS=<your-password> (then press Enter)\n\n");
	}

	// Periodic timer (every 2 seconds)
	struct repeating_timer timer;
	if (!add_repeating_timer_ms(BROADCAST_INTERVAL_MS, periodic_timer_callback, NULL, &timer)) {
		printf("WARNING: failed to init periodic timer\n");
	}

	printf("Initialization complete.%s\n",
	       http_started ? " Serving dashboard..." : " Waiting for WiFi config.");

	uint8_t buffer[SERIAL_BUFFER_SIZE];
	viking_bio_data_t viking_data;
	bool timeout_triggered = false;
	bool error_notified = false;

	memset(&viking_data, 0, sizeof(viking_data));

	while (true) {
		// Feed watchdog
		if (watchdog_on) watchdog_update();

		// Process WiFi/lwIP
		cyw43_arch_poll();

		// Process USB serial commands (WiFi config)
		if (process_usb_commands()) {
			// New credentials saved – reboot to apply
			sleep_ms(100);
			watchdog_enable(WATCHDOG_REBOOT_MS, false);
			while (1) {}  // Wait for watchdog reset
		}

		// Process Viking Bio serial data
		if (serial_handler_data_available()) {
			size_t bytes = serial_handler_read(buffer, sizeof(buffer));
			if (bytes > 0) {
				// Short LED blink: 50 ms when serial data is received
				s_serial_blink_end = make_timeout_time_ms(50);
				cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

				viking_bio_data_t new_data;
				if (viking_bio_parse_data(buffer, bytes, &new_data)) {
					memcpy(&viking_data, &new_data, sizeof(viking_data));
					timeout_triggered = false;

					if (http_started) {
						// Update cached data for polling
						http_server_update_data(&viking_data);

						// Send push notification on first error detection
						if (viking_data.error_code != 0 && !error_notified) {
							error_notified = true;
							char title[] = "Viking Bio 20 Error";
							char body[64];
							snprintf(body, sizeof(body), "Error code %d detected",
							         viking_data.error_code);
							push_manager_notify_all(title, body, viking_data.error_code);
						} else if (viking_data.error_code == 0) {
							error_notified = false;
						}
					}
				}
			}
		}

		// Periodic tasks
		if (event_flags & EVENT_TIMEOUT_CHECK) {
			event_flags &= ~EVENT_TIMEOUT_CHECK;

			if (!timeout_triggered && viking_bio_is_data_stale(VIKING_BIO_TIMEOUT_MS)) {
				timeout_triggered = true;
				printf("Viking Bio: no data for 30s - burner may be off\n");

				if (http_started) {
					viking_bio_data_t stale = {
						.flame_detected = false,
						.fan_speed = 0,
						.temperature = 0,
						.error_code = 0,
						.valid = false
					};
					http_server_update_data(&stale);
				}
			}
		}

		if (event_flags & EVENT_BROADCAST) {
			event_flags &= ~EVENT_BROADCAST;

			if (http_started && !timeout_triggered) {
				viking_bio_data_t current;
				viking_bio_get_current_data(&current);
				if (current.valid) {
					http_server_update_data(&current);
				}
			}

			// Poll push manager
			if (http_started) push_manager_poll();
		}

		// Update LED (must run every loop iteration for smooth blinking)
		led_update();
	}

	return 0;
}
