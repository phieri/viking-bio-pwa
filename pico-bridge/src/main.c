#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "hardware/watchdog.h"
#include "lwip/netif.h"
#include "lwip/ip6_addr.h"
#include "serial_handler.h"
#include "viking_bio_protocol.h"
#include "http_client.h"
#include "wifi_config.h"
#include "lfs_hal.h"
#include "dns_sd_browser.h"
#include "version.h"

// Event flags (modified from interrupt context)
volatile uint32_t event_flags = 0;

#define EVENT_SERIAL_DATA (1 << 0)
#define EVENT_TIMEOUT_CHECK (1 << 2)
#define EVENT_BROADCAST (1 << 4)

// Broadcast interval: 2 seconds
#define BROADCAST_INTERVAL_MS 2000

// Watchdog timeout: 8 seconds
#define WATCHDOG_TIMEOUT_MS 8000

// Watchdog-based software reboot delay (milliseconds)
#define WATCHDOG_REBOOT_MS 1

#define LED_BLINK_INTERVAL_MS 250
#define SERIAL_LED_BLINK_MS 50
#define USB_COMMAND_BUFFER_SIZE 160
#define WIFI_CONNECT_TIMEOUT_MS 30000
#define IPV6_WAIT_TIMEOUT_MS 5000
#define IPV6_POLL_INTERVAL_MS 50
#define STARTUP_USB_WAIT_MS 2000
#define POST_REBOOT_FLUSH_DELAY_MS 100
#define STATUS_COUNTRY_LEN 3
#define USB_SSID_PREFIX "SSID="
#define USB_PASS_PREFIX "PASS="
#define USB_COUNTRY_PREFIX "COUNTRY="
#define USB_SERVER_PREFIX "SERVER="
#define USB_PORT_PREFIX "PORT="
#define USB_TOKEN_PREFIX "TOKEN="
#define USB_STATUS_COMMAND "STATUS"
#define USB_CLEAR_COMMAND "CLEAR"

// --- LED state ---
static absolute_time_t s_led_blink_time;
static absolute_time_t s_serial_blink_end;
static bool s_led_blink_on = false;

static void led_update(void) {
	bool wifi_up =
		(netif_default != NULL) && netif_is_up(netif_default) && netif_is_link_up(netif_default);

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
			s_led_blink_time = make_timeout_time_ms(LED_BLINK_INTERVAL_MS);
			cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, s_led_blink_on ? 1 : 0);
		}
	}
}

// --- USB serial configuration ---
static char s_usb_buf[USB_COMMAND_BUFFER_SIZE];
static size_t s_usb_buf_len = 0;
static char s_pending_ssid[WIFI_SSID_MAX_LEN + 1];
static bool s_has_pending_ssid = false;

typedef bool (*usb_command_handler_fn)(const char *arg);

typedef struct {
	const char *command;
	bool exact_match;
	usb_command_handler_fn handler;
} usb_command_entry_t;

static void print_usb_help(void) {
	printf("  SSID=<ssid>      – set WiFi SSID\n");
	printf("  PASS=<pass>      – set password and save\n");
	printf("  COUNTRY=<CC>     – set Wi-Fi country (e.g. SE, US)\n");
	printf("  SERVER=<ip>      – set proxy server IP/hostname\n");
	printf("  PORT=<port>      – set proxy server port (default %d)\n", WIFI_SERVER_PORT_DEFAULT);
	printf("  TOKEN=<token>    – set webhook X-Hook-Auth token\n");
	printf("  STATUS           – show status\n");
	printf("  CLEAR            – erase stored credentials\n");
}

static void load_current_server_config(char *ip, size_t ip_size, uint16_t *port) {
	*port = WIFI_SERVER_PORT_DEFAULT;
	ip[0] = '\0';
	wifi_config_load_server(ip, ip_size, port);
}

static bool handle_ssid_command(const char *arg) {
	snprintf(s_pending_ssid, sizeof(s_pending_ssid), "%s", arg);
	s_has_pending_ssid = true;
	printf("wifi: SSID staged – send PASS=<password> to save\n");
	return false;
}

static bool handle_pass_command(const char *arg) {
	if (!s_has_pending_ssid) {
		printf("wifi: send SSID=<ssid> first\n");
		return false;
	}
	if (wifi_config_save(s_pending_ssid, arg)) {
		printf("wifi: credentials saved – rebooting\n");
		s_has_pending_ssid = false;
		return true;
	}
	printf("wifi: ERROR saving credentials\n");
	return false;
}

static bool handle_country_command(const char *arg) {
	if (strlen(arg) == 2 && isupper((unsigned char)arg[0]) && isupper((unsigned char)arg[1])) {
		if (wifi_config_save_country(arg)) {
			printf("wifi: country set to %s – reboot to apply\n", arg);
		} else {
			printf("wifi: ERROR saving country\n");
		}
	} else {
		printf("wifi: country must be 2 uppercase letters (e.g. SE, US, GB)\n");
	}
	return false;
}

static bool handle_server_command(const char *arg) {
	char cur_ip[WIFI_SERVER_IP_MAX_LEN + 1] = {0};
	uint16_t cur_port;

	load_current_server_config(cur_ip, sizeof(cur_ip), &cur_port);
	if (wifi_config_save_server(arg, cur_port)) {
		printf("webhook: server IP set to %s – reboot to apply\n", arg);
	} else {
		printf("webhook: ERROR saving server IP\n");
	}
	return false;
}

static bool handle_port_command(const char *arg) {
	int port = atoi(arg);
	if (port <= 0 || port > 65535) {
		printf("webhook: port must be 1-65535\n");
		return false;
	}

	char cur_ip[WIFI_SERVER_IP_MAX_LEN + 1] = {0};
	uint16_t cur_port;

	load_current_server_config(cur_ip, sizeof(cur_ip), &cur_port);
	if (cur_ip[0] == '\0') {
		printf("webhook: set SERVER=<ip> first\n");
	} else if (wifi_config_save_server(cur_ip, (uint16_t)port)) {
		printf("webhook: port set to %d – reboot to apply\n", port);
	} else {
		printf("webhook: ERROR saving port\n");
	}
	return false;
}

static bool handle_token_command(const char *arg) {
	if (wifi_config_save_hook_token(arg)) {
		printf("webhook: auth token saved – reboot to apply\n");
	} else {
		printf("webhook: ERROR saving token (max %d chars)\n", WIFI_HOOK_TOKEN_MAX_LEN);
	}
	return false;
}

static bool handle_status_command(const char *arg) {
	(void)arg;

	bool up =
		(netif_default != NULL) && netif_is_up(netif_default) && netif_is_link_up(netif_default);
	printf("wifi: %s\n", up ? "connected" : "disconnected");
	if (up) {
		for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
			if (ip6_addr_isvalid(netif_ip6_addr_state(netif_default, i))) {
				printf("  IPv6[%d]: %s\n", i, ip6addr_ntoa(netif_ip6_addr(netif_default, i)));
			}
		}
	}

	char country[STATUS_COUNTRY_LEN] = "XX";
	wifi_config_load_country(country, sizeof(country));
	printf("  country: %s\n", country);

	char srv_ip[WIFI_SERVER_IP_MAX_LEN + 1] = {0};
	uint16_t srv_port = 0;
	if (wifi_config_load_server(srv_ip, sizeof(srv_ip), &srv_port)) {
		printf("  server:  %s:%d\n", srv_ip, srv_port);
	} else {
		printf("  server:  not configured\n");
	}

	printf("  webhook: %s\n", http_client_is_active() ? "active" : "idle");

	char tok_check[WIFI_HOOK_TOKEN_MAX_LEN + 1];
	printf("  token:   %s\n",
		   wifi_config_load_hook_token(tok_check, sizeof(tok_check)) ? "(set)" : "not set");

	return false;
}

static bool handle_clear_command(const char *arg) {
	(void)arg;
	wifi_config_clear();
	printf("wifi: credentials cleared – rebooting\n");
	return true;
}

static const usb_command_entry_t s_usb_commands[] = {
	{USB_SSID_PREFIX, false, handle_ssid_command},
	{USB_PASS_PREFIX, false, handle_pass_command},
	{USB_COUNTRY_PREFIX, false, handle_country_command},
	{USB_SERVER_PREFIX, false, handle_server_command},
	{USB_PORT_PREFIX, false, handle_port_command},
	{USB_TOKEN_PREFIX, false, handle_token_command},
	{USB_STATUS_COMMAND, true, handle_status_command},
	{USB_CLEAR_COMMAND, true, handle_clear_command},
};

static bool handle_usb_command(const char *command) {
	for (size_t i = 0; i < sizeof(s_usb_commands) / sizeof(s_usb_commands[0]); i++) {
		size_t prefix_len = strlen(s_usb_commands[i].command);
		if (s_usb_commands[i].exact_match) {
			if (strcmp(command, s_usb_commands[i].command) == 0) {
				return s_usb_commands[i].handler(command + prefix_len);
			}
			continue;
		}
		if (strncmp(command, s_usb_commands[i].command, prefix_len) == 0) {
			return s_usb_commands[i].handler(command + prefix_len);
		}
	}

	if (command[0] != '\0') {
		printf("unknown command '%s'\n", command);
		print_usb_help();
	}
	return false;
}

// Returns true when credentials were saved and device should reboot.
static bool process_usb_commands(void) {
	int c;
	while ((c = getchar_timeout_us(0)) != PICO_ERROR_TIMEOUT) {
		if (c == '\r') {
			continue;
		}

		if (c == '\n' || s_usb_buf_len >= sizeof(s_usb_buf) - 1) {
			s_usb_buf[s_usb_buf_len] = '\0';
			s_usb_buf_len = 0;
			if (handle_usb_command(s_usb_buf)) {
				return true;
			}
		} else {
			s_usb_buf[s_usb_buf_len++] = (char)c;
		}
	}
	return false;
}

/*
 * Called from the lwIP poll context when a _viking-bio._tcp mDNS announcement
 * is received.  Saves the new proxy address and (re-)initialises the HTTP
 * webhook client only when the address actually changed.
 */
static void on_proxy_discovered(const char *ip6addr, uint16_t port) {
	char cur_ip[WIFI_SERVER_IP_MAX_LEN + 1] = {0};
	uint16_t cur_port = 0;
	wifi_config_load_server(cur_ip, sizeof(cur_ip), &cur_port);
	if (strcmp(cur_ip, ip6addr) == 0 && cur_port == port) {
		printf("dns_sd: announcement from %s:%d matches current config – no change\n", ip6addr,
			   port);
		return;
	}

	printf("dns_sd: proxy changed to %s:%d – updating config\n", ip6addr, port);
	if (!wifi_config_save_server(ip6addr, port)) {
		printf("dns_sd: failed to save proxy config\n");
	}
	char hook_token[WIFI_HOOK_TOKEN_MAX_LEN + 1] = {0};
	wifi_config_load_hook_token(hook_token, sizeof(hook_token));
	http_client_init(ip6addr, port, hook_token[0] ? hook_token : NULL);
}

bool periodic_timer_callback(struct repeating_timer *t) {
	(void)t;
	event_flags |= EVENT_TIMEOUT_CHECK | EVENT_BROADCAST;
	__sev();
	return true;
}

static bool wifi_connect(const char *ssid, const char *password) {
	printf("Connecting to WiFi SSID: %s\n", ssid);

	if (cyw43_arch_wifi_connect_timeout_ms(ssid, password, CYW43_AUTH_WPA3_WPA2_AES_PSK,
										   WIFI_CONNECT_TIMEOUT_MS) != 0) {
		printf("WiFi connection failed\n");
		return false;
	}

	printf("WiFi connected\n");

	// Wait up to 5 s for IPv6 link-local address to appear.
	// Networking is serviced by the CYW43 arch background thread on core 1;
	// cyw43_arch_poll() must not be called here.
	absolute_time_t net_wait = make_timeout_time_ms(IPV6_WAIT_TIMEOUT_MS);
	while (!time_reached(net_wait)) {
		if (ip6_addr_isvalid(netif_ip6_addr_state(netif_default, 0))) {
			break;
		}
		sleep_ms(IPV6_POLL_INTERVAL_MS);
	}

	for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
		if (ip6_addr_isvalid(netif_ip6_addr_state(netif_default, i))) {
			printf("  IPv6[%d]: %s\n", i, ip6addr_ntoa(netif_ip6_addr(netif_default, i)));
		}
	}
	return true;
}

static void reboot_via_watchdog(void) {
	stdio_flush();
	sleep_ms(POST_REBOOT_FLUSH_DELAY_MS);
	watchdog_enable(WATCHDOG_REBOOT_MS, false);
	while (1) {
	}
}

static void init_bridge_components(void) {
	stdio_init_all();
	sleep_ms(STARTUP_USB_WAIT_MS);

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

	wifi_config_init();
}

static bool init_wifi_stack(void) {
	char country[STATUS_COUNTRY_LEN] = "XX";
	wifi_config_load_country(country, sizeof(country));
	printf("WiFi country: %s\n", country);

	printf("Initializing WiFi...\n");
	uint32_t cyw43_country = wifi_config_country_to_cyw43(country);
	if (cyw43_arch_init_with_country(cyw43_country)) {
		printf("FATAL: cyw43_arch_init_with_country() failed\n");
		return false;
	}
	cyw43_arch_enable_sta_mode();
	return true;
}

static bool load_wifi_credentials(char *ssid, size_t ssid_size, char *password,
								  size_t password_size) {
	bool have_creds = wifi_config_load(ssid, ssid_size, password, password_size);

#if WIFI_COMPILE_CREDS_VALID
	if (!have_creds) {
		snprintf(ssid, ssid_size, "%s", WIFI_SSID);
		snprintf(password, password_size, "%s", WIFI_PASSWORD);
		have_creds = true;
	}
#endif

	return have_creds;
}

static bool start_wifi_services(const char *ssid, const char *password, bool have_creds,
								bool *watchdog_on) {
	if (!(have_creds && wifi_connect(ssid, password))) {
		printf("\nWiFi not connected. Configure via USB serial:\n");
		printf("  SSID=<ssid> then PASS=<password>\n\n");
		return false;
	}

	dns_sd_browser_start(on_proxy_discovered);

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
	*watchdog_on = true;
	printf("Watchdog enabled (%d ms)\n", WATCHDOG_TIMEOUT_MS);
	return true;
}

static void init_periodic_timer(struct repeating_timer *timer) {
	if (!add_repeating_timer_ms(BROADCAST_INTERVAL_MS, periodic_timer_callback, NULL, timer)) {
		printf("WARNING: failed to init periodic timer\n");
	}
}

static void handle_serial_data(uint8_t *buffer, size_t buffer_size, bool wifi_up,
							   bool *timeout_triggered, bool *flame_on) {
	if (!serial_handler_data_available()) {
		return;
	}

	size_t bytes = serial_handler_read(buffer, buffer_size);
	if (bytes == 0) {
		return;
	}

	s_serial_blink_end = make_timeout_time_ms(SERIAL_LED_BLINK_MS);
	cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

	viking_bio_data_t new_data;
	if (!viking_bio_parse_data(buffer, bytes, &new_data)) {
		return;
	}

	*timeout_triggered = false;
	*flame_on = new_data.flame_detected;
	if (wifi_up) {
		http_client_send_data(&new_data);
	}
}

static void handle_timeout_event(bool wifi_up, bool *timeout_triggered, bool *flame_on) {
	if ((event_flags & EVENT_TIMEOUT_CHECK) == 0) {
		return;
	}
	event_flags &= ~EVENT_TIMEOUT_CHECK;

	if (!*timeout_triggered && viking_bio_is_data_stale(VIKING_BIO_TIMEOUT_MS)) {
		*timeout_triggered = true;
		*flame_on = false;
		printf("Viking Bio: no data for 30s – burner may be off\n");
		if (wifi_up) {
			viking_bio_data_t stale = {.valid = false};
			http_client_send_data(&stale);
		}
	}
}

static void handle_broadcast_event(bool wifi_up, bool flame_on) {
	if ((event_flags & EVENT_BROADCAST) == 0) {
		return;
	}
	event_flags &= ~EVENT_BROADCAST;
	if (wifi_up) {
		http_client_poll();
	}
}

int main(void) {
	init_bridge_components();
	if (!init_wifi_stack()) {
		return 1;
	}

	char ssid[WIFI_SSID_MAX_LEN + 1] = {0};
	char password[WIFI_PASS_MAX_LEN + 1] = {0};
	bool have_creds = load_wifi_credentials(ssid, sizeof(ssid), password, sizeof(password));
	bool wifi_up = false;
	bool watchdog_on = false;

	wifi_up = start_wifi_services(ssid, password, have_creds, &watchdog_on);

	struct repeating_timer timer;
	init_periodic_timer(&timer);

	printf("Initialization complete.%s\n",
		   wifi_up ? " Bridging data..." : " Waiting for WiFi config.");

	uint8_t buffer[SERIAL_BUFFER_SIZE];
	bool timeout_triggered = false;
	bool flame_on = false;

	while (true) {
		if (watchdog_on) {
			watchdog_update();
		}

		// Networking (Wi-Fi + lwIP) is serviced by the CYW43 arch background
		// thread on core 1.  Do not call cyw43_arch_poll() here.
		// Direct lwIP API calls from core 0 (e.g. tcp_connect, tcp_write)
		// must be wrapped with cyw43_arch_lwip_begin() / cyw43_arch_lwip_end().
		// lwIP callbacks (tcp_recv_fn, tcp_err_fn, etc.) are invoked on core 1
		// inside the arch lock and do not need additional wrapping.

		if (process_usb_commands()) {
			reboot_via_watchdog();
		}

		handle_serial_data(buffer, sizeof(buffer), wifi_up, &timeout_triggered, &flame_on);
		handle_timeout_event(wifi_up, &timeout_triggered, &flame_on);
		handle_broadcast_event(wifi_up, flame_on);

		led_update();
	}

	return 0;
}
