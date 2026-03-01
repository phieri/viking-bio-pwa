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
#include "http_client.h"
#include "push_manager.h"
#include "wifi_config.h"
#include "lfs_hal.h"
#include "version.h"

// Event flags (modified from interrupt context)
volatile uint32_t event_flags = 0;

#define EVENT_SERIAL_DATA   (1 << 0)
#define EVENT_TIMEOUT_CHECK (1 << 2)
#define EVENT_BROADCAST     (1 << 4)

// Broadcast interval: 2 seconds
#define BROADCAST_INTERVAL_MS 2000

// Watchdog timeout: 8 seconds
#define WATCHDOG_TIMEOUT_MS 8000

// Watchdog-based software reboot delay (milliseconds)
#define WATCHDOG_REBOOT_MS 1

// --- LED state ---
static absolute_time_t s_led_blink_time;
static absolute_time_t s_serial_blink_end;
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
		cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
	} else {
		if (time_reached(s_led_blink_time)) {
			s_led_blink_on = !s_led_blink_on;
			s_led_blink_time = make_timeout_time_ms(250);
			cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, s_led_blink_on ? 1 : 0);
		}
	}
}

// --- USB serial configuration ---
static char s_usb_buf[160];
static size_t s_usb_buf_len = 0;
static char s_pending_ssid[WIFI_SSID_MAX_LEN + 1];
static bool s_has_pending_ssid = false;

// Returns true when credentials were saved and device should reboot.
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
					if (wifi_config_save(s_pending_ssid, s_usb_buf + 5)) {
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

			} else if (strncmp(s_usb_buf, "SERVER=", 7) == 0) {
				const char *addr = s_usb_buf + 7;
				// Load current port, use default if not set
				char cur_ip[WIFI_SERVER_IP_MAX_LEN + 1] = {0};
				uint16_t cur_port = WIFI_SERVER_PORT_DEFAULT;
				wifi_config_load_server(cur_ip, sizeof(cur_ip), &cur_port);
				if (wifi_config_save_server(addr, cur_port)) {
					printf("webhook: server IP set to %s – reboot to apply\n", addr);
				} else {
					printf("webhook: ERROR saving server IP\n");
				}

			} else if (strncmp(s_usb_buf, "PORT=", 5) == 0) {
				int p = atoi(s_usb_buf + 5);
				if (p > 0 && p <= 65535) {
					char cur_ip[WIFI_SERVER_IP_MAX_LEN + 1] = {0};
					uint16_t cur_port = WIFI_SERVER_PORT_DEFAULT;
					wifi_config_load_server(cur_ip, sizeof(cur_ip), &cur_port);
					if (cur_ip[0] == '\0') {
						printf("webhook: set SERVER=<ip> first\n");
					} else if (wifi_config_save_server(cur_ip, (uint16_t)p)) {
						printf("webhook: port set to %d – reboot to apply\n", p);
					} else {
						printf("webhook: ERROR saving port\n");
					}
				} else {
					printf("webhook: port must be 1-65535\n");
				}

			} else if (strncmp(s_usb_buf, "TOKEN=", 6) == 0) {
				const char *tok = s_usb_buf + 6;
				if (wifi_config_save_hook_token(tok)) {
					printf("webhook: auth token saved – reboot to apply\n");
				} else {
					printf("webhook: ERROR saving token (max %d chars)\n",
					       WIFI_HOOK_TOKEN_MAX_LEN);
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
				char srv_ip[WIFI_SERVER_IP_MAX_LEN + 1] = {0};
				uint16_t srv_port = 0;
				if (wifi_config_load_server(srv_ip, sizeof(srv_ip), &srv_port)) {
					printf("  server:  %s:%d\n", srv_ip, srv_port);
				} else {
					printf("  server:  not configured\n");
				}
				printf("  webhook: %s\n", http_client_is_active() ? "active" : "idle");
				printf("  push:    %d subscription(s)\n",
				       push_manager_subscription_count());
				char tok_check[WIFI_HOOK_TOKEN_MAX_LEN + 1];
				printf("  token:   %s\n",
				       wifi_config_load_hook_token(tok_check, sizeof(tok_check))
				       ? "(set)" : "not set");
				char vapid_pub[96];
				if (push_manager_get_vapid_public_key(vapid_pub, sizeof(vapid_pub))) {
					printf("  vapid_pub: %s\n", vapid_pub);
				}

			} else if (strcmp(s_usb_buf, "CLEAR") == 0) {
				wifi_config_clear();
				printf("wifi: credentials cleared – rebooting\n");
				return true;

			} else if (s_usb_buf[0] != '\0') {
				printf("unknown command '%s'\n", s_usb_buf);
				printf("  SSID=<ssid>      – set WiFi SSID\n");
				printf("  PASS=<pass>      – set password and save\n");
				printf("  COUNTRY=<CC>     – set Wi-Fi country (e.g. SE, US)\n");
				printf("  SERVER=<ip>      – set proxy server IP/hostname\n");
				printf("  PORT=<port>      – set proxy server port (default %d)\n",
				       WIFI_SERVER_PORT_DEFAULT);
				printf("  TOKEN=<token>    – set webhook X-Hook-Auth token\n");
				printf("  STATUS           – show status and VAPID public key\n");
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
	                                        CYW43_AUTH_WPA3_WPA2_AES_PSK, 30000) != 0) {
		printf("WiFi connection failed\n");
		return false;
	}

	printf("WiFi connected\n");

	// Wait up to 5 s for IPv6 link-local address to appear
	absolute_time_t net_wait = make_timeout_time_ms(5000);
	while (!time_reached(net_wait)) {
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
	pico_unique_board_id_t uid;
	pico_get_unique_board_id(&uid);
	char hostname[32];
	snprintf(hostname, sizeof(hostname), "viking-bio-%02x%02x",
	         uid.id[6], uid.id[7]);

	mdns_resp_add_netif(netif_default, hostname);
	printf("mDNS: %s.local registered\n", hostname);
}

int main(void) {
	stdio_init_all();
	sleep_ms(2000);

	printf("\n");
	version_print_info();
	printf("Viking Bio Bridge starting...\n");

	s_led_blink_time = get_absolute_time();
	s_serial_blink_end = get_absolute_time();

	printf("Initializing protocol parser...\n");
	viking_bio_init();

	printf("Initializing serial handler...\n");
	serial_handler_init();

	printf("Initializing LittleFS...\n");
	if (!lfs_hal_init()) {
		printf("WARNING: LittleFS initialization failed\n");
	}

	printf("Initializing push manager...\n");
	if (!push_manager_init()) {
		printf("WARNING: push_manager_init() failed\n");
	}

	wifi_config_init();

	char country[3] = "XX";
	wifi_config_load_country(country, sizeof(country));
	printf("WiFi country: %s\n", country);

	printf("Initializing WiFi...\n");
	uint32_t cyw43_country = wifi_config_country_to_cyw43(country);
	if (cyw43_arch_init_with_country(cyw43_country)) {
		printf("FATAL: cyw43_arch_init_with_country() failed\n");
		return 1;
	}
	cyw43_arch_enable_sta_mode();

	mdns_resp_init();

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

	bool wifi_up = false;
	bool watchdog_on = false;

	if (have_creds && wifi_connect(ssid, password)) {
		mdns_setup();
		wifi_up = true;

		// Load proxy server config and auth token
		char srv_ip[WIFI_SERVER_IP_MAX_LEN + 1] = {0};
		uint16_t srv_port = WIFI_SERVER_PORT_DEFAULT;
		wifi_config_load_server(srv_ip, sizeof(srv_ip), &srv_port);
		char hook_token[WIFI_HOOK_TOKEN_MAX_LEN + 1] = {0};
		wifi_config_load_hook_token(hook_token, sizeof(hook_token));
		if (srv_ip[0] != '\0') {
			printf("Proxy server: %s:%d\n", srv_ip, srv_port);
			http_client_init(srv_ip, srv_port, hook_token[0] ? hook_token : NULL);
		} else {
			printf("Proxy server not configured – use SERVER=<ip> via USB serial\n");
		}

		watchdog_enable(WATCHDOG_TIMEOUT_MS, false);
		watchdog_on = true;
		printf("Watchdog enabled (%d ms)\n", WATCHDOG_TIMEOUT_MS);
	} else {
		printf("\nWiFi not connected. Configure via USB serial:\n");
		printf("  SSID=<ssid> then PASS=<password>\n\n");
	}

	struct repeating_timer timer;
	if (!add_repeating_timer_ms(BROADCAST_INTERVAL_MS, periodic_timer_callback, NULL, &timer)) {
		printf("WARNING: failed to init periodic timer\n");
	}

	printf("Initialization complete.%s\n",
	       wifi_up ? " Bridging data..." : " Waiting for WiFi config.");

	uint8_t buffer[SERIAL_BUFFER_SIZE];
	bool timeout_triggered = false;
	// State tracking for push notifications
	bool prev_flame = false;
	int  prev_err   = 0;

	while (true) {
		if (watchdog_on) watchdog_update();

		cyw43_arch_poll();

		if (process_usb_commands()) {
			// New credentials saved – flush USB output and reboot via watchdog
			stdio_flush();
			sleep_ms(100);
			watchdog_enable(WATCHDOG_REBOOT_MS, false);
			while (1) {}
		}

		// Process Viking Bio serial data
		if (serial_handler_data_available()) {
			size_t bytes = serial_handler_read(buffer, sizeof(buffer));
			if (bytes > 0) {
				s_serial_blink_end = make_timeout_time_ms(50);
				cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

				viking_bio_data_t new_data;
				if (viking_bio_parse_data(buffer, bytes, &new_data)) {
					timeout_triggered = false;
					if (wifi_up) {
						http_client_send_data(&new_data);
					}

					// Push notifications: flame state change
					if (new_data.flame_detected != prev_flame) {
						if (new_data.flame_detected) {
							push_manager_notify_all(PUSH_NOTIFY_FLAME,
								"Viking Bio: Flame ON",
								"Burner ignited");
						} else {
							push_manager_notify_all(PUSH_NOTIFY_FLAME,
								"Viking Bio: Flame OFF",
								"Burner flame extinguished");
						}
						prev_flame = new_data.flame_detected;
					}

					// Push notifications: new error
					if (new_data.error_code != 0 && new_data.error_code != prev_err) {
						char errbody[32];
						snprintf(errbody, sizeof(errbody), "Error code %d detected",
						         new_data.error_code);
						push_manager_notify_all(PUSH_NOTIFY_ERROR,
							"Viking Bio: Error", errbody);
					}
					prev_err = new_data.error_code;
				}
			}
		}

		// Periodic tasks
		if (event_flags & EVENT_TIMEOUT_CHECK) {
			event_flags &= ~EVENT_TIMEOUT_CHECK;

			if (!timeout_triggered && viking_bio_is_data_stale(VIKING_BIO_TIMEOUT_MS)) {
				timeout_triggered = true;
				printf("Viking Bio: no data for 30s – burner may be off\n");
				if (wifi_up) {
					viking_bio_data_t stale = { .valid = false };
					http_client_send_data(&stale);
				}
			}
		}

		if (event_flags & EVENT_BROADCAST) {
			event_flags &= ~EVENT_BROADCAST;
			if (wifi_up) {
				http_client_poll();
			}
		}

		led_update();
	}

	return 0;
}
