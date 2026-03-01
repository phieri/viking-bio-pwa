# Copilot Instructions for viking-bio-pwa

## Project Overview

This is a **monorepo** for the Viking Bio 20 pellet burner integration system. It consists of two components:

1. **`pico-bridge/`** – Raspberry Pi Pico W firmware (C11, RP2040 + CYW43439 Wi-Fi) that reads serial data from the burner and forwards it via HTTP webhook to the proxy server.
2. **`proxy/`** – Node.js Express server that receives burner telemetry via authenticated webhook, serves the PWA dashboard, and sends Web Push notifications.

```
Viking Bio 20 ──UART──► Pico W (pico-bridge)
                              │
                     HTTP POST /api/machine-data
                     X-Hook-Auth: <token>  (IPv6)
                              │
                         Node.js Proxy (proxy)
                         ├── GET /                     Dashboard PWA
                         ├── GET /api/data             Burner state (JSON)
                         ├── POST /api/machine-data    Webhook from Pico
                         ├── GET /api/vapid-public-key VAPID key
                         ├── GET /api/subscribers      Subscription count
                         ├── POST /api/subscribe       Add/update subscription
                         └── POST /api/unsubscribe     Remove subscription
```

## Repository Structure

```
.
├── pico-bridge/                    # Raspberry Pi Pico W firmware
│   ├── CMakeLists.txt              # Build file (CMake, fetches LittleFS via FetchContent)
│   ├── CMakePresets.json           # CMake presets (pico-default, PICO_BOARD=pico_w)
│   ├── pico_sdk_import.cmake       # Pico SDK bootstrap include
│   ├── cmake/
│   │   └── gen_demo_page.py        # Generates GitHub Pages demo from proxy/public/index.html
│   ├── include/                    # Public headers for all modules
│   │   ├── http_client.h           # HTTP webhook client (POST to proxy)
│   │   ├── push_manager.h          # VAPID key management, push subscriptions
│   │   ├── wifi_config.h           # WiFi + server + token config (AES-GCM encrypted)
│   │   ├── lfs_hal.h               # LittleFS HAL API
│   │   ├── serial_handler.h        # UART0 receive handler
│   │   ├── viking_bio_protocol.h   # Binary/text protocol parser
│   │   └── version.h               # Firmware version string
│   ├── src/
│   │   ├── main.c                  # Entry point, main loop, USB serial config
│   │   ├── http_client.c           # lwIP TCP client – POSTs JSON to proxy webhook
│   │   ├── push_manager.c          # VAPID key management, subscription persistence
│   │   ├── wifi_config.c           # AES-128-GCM encrypted credentials (LittleFS)
│   │   ├── lfs_hal.c               # LittleFS HAL (flash read/prog/erase via Pico SDK)
│   │   ├── serial_handler.c        # UART0 receive handler (GP1, 9600 baud)
│   │   ├── viking_bio_protocol.c   # Binary/text protocol parser for burner data
│   │   └── version.c               # Firmware version string printing
│   └── platform/
│       ├── lwipopts.h              # lwIP configuration (IPv6-only, mDNS, TCP client)
│       ├── mbedtls_config.h        # mbedTLS configuration (ECP P-256, AES-GCM)
│       └── mbedtls_time.c          # mbedTLS time stub (no RTC on Pico)
├── proxy/                          # Node.js Express proxy + PWA dashboard
│   ├── package.json                # Dependencies: express, web-push
│   ├── .env.example                # Environment variable reference
│   ├── src/
│   │   ├── server.js               # Express app, API routes, TLS, IPv6 binding
│   │   ├── webhook-receiver.js     # Authenticated POST /api/machine-data handler
│   │   ├── push-manager.js         # VAPID keys, subscription management, web-push
│   │   ├── scheduler.js            # Cleaning reminder scheduler (Sat 07:00, Nov–Mar)
│   │   └── tcp-receiver.js         # Legacy TCP receiver (superseded by webhook)
│   └── public/                     # Static PWA files served by Express
│       ├── index.html              # Dashboard PWA
│       ├── app.js                  # Dashboard JavaScript
│       ├── style.css               # Dashboard styles
│       ├── sw.js                   # Service Worker for push notifications
│       └── manifest.json           # PWA manifest
└── .github/
    └── workflows/
        ├── build-firmware.yml      # CI: builds pico-bridge with Pico SDK 2.2.0
        ├── build-proxy.yml         # CI: installs proxy deps and smoke-tests the server
        └── pages.yml               # CI: deploys demo page to GitHub Pages
```

## Building the Firmware (pico-bridge)

### Prerequisites

- **Pico SDK 2.2.0** (set `PICO_SDK_PATH` env var)
- `cmake`, `gcc-arm-none-eabi`, `libnewlib-arm-none-eabi`, `build-essential`
- Python 3 (for `cmake/gen_demo_page.py`, invoked automatically by the pages workflow)

```bash
# Install toolchain
sudo apt-get install cmake gcc-arm-none-eabi libnewlib-arm-none-eabi build-essential

# Clone Pico SDK 2.2.0
git clone --depth 1 --branch 2.2.0 https://github.com/raspberrypi/pico-sdk.git
cd pico-sdk && git submodule update --init && cd ..
export PICO_SDK_PATH=$(pwd)/pico-sdk
```

### Build Command

```bash
mkdir pico-bridge/build && cd pico-bridge/build
cmake .. -DWIFI_SSID="your_network" -DWIFI_PASSWORD="your_password"
make -j$(nproc)
```

- `WIFI_SSID` / `WIFI_PASSWORD` are **optional** compile-time fallbacks; the primary configuration method is USB serial at runtime.
- LittleFS is fetched automatically via `FetchContent` at cmake configure time.
- Output: `pico-bridge/build/viking_bio_bridge-<git-version>.uf2` (and `.elf`, `.bin`, `.hex`).
- `PICO_BOARD` must be `pico_w` (enforced in `pico-bridge/CMakeLists.txt`).

### CI Build (Firmware)

`.github/workflows/build-firmware.yml` runs on `ubuntu-latest`, caches the Pico SDK, and builds `pico-bridge/` with `-DWIFI_SSID="ci_build" -DWIFI_PASSWORD="ci_build"`. Triggers on push/PR to `main`/`develop`, ignoring `**.md`, `docs/**`, and `proxy/**`.

## Running the Proxy

### Prerequisites

- Node.js ≥ 18

### Run Command

```bash
cd proxy
npm install
npm start       # production
npm run dev     # development (auto-restart on file changes via --watch)
```

With custom configuration:

```bash
HTTP_PORT=8080 \
MACHINE_WEBHOOK_AUTH_TOKEN=mysecrettoken \
PICO_VAPID_PUBLIC_KEY=<base64url-from-STATUS> \
PICO_BASE_URL=http://[fe80::dead:beef%25eth0]:8080 \
npm start
```

The dashboard is at `http://[::]:3000/` (or `https://` when TLS is configured).

### Proxy Environment Variables (see `proxy/.env.example`)

| Variable | Default | Description |
|---|---|---|
| `HTTP_PORT` | `3000` | HTTP/HTTPS server port |
| `MACHINE_WEBHOOK_AUTH_TOKEN` | _(empty)_ | Webhook auth token; Pico must send same value in `X-Hook-Auth` header. Leave empty to disable auth (dev only). |
| `TLS_CERT_PATH` / `TLS_KEY_PATH` | _(empty)_ | Paths to TLS cert/key; when both set, server starts HTTPS |
| `PICO_BASE_URL` | _(empty)_ | Pico W base URL (e.g. `http://[::1]:9000`); when set, push subscriptions are forwarded to the device |
| `PICO_VAPID_PUBLIC_KEY` | _(empty)_ | VAPID public key from the Pico (output of `STATUS`); when set, browsers subscribe using the Pico's on-device key |

### CI Build (Proxy)

`.github/workflows/build-proxy.yml` triggers on changes to `proxy/**`. Installs dependencies and smoke-tests that the server starts and the webhook endpoint is reachable.

## Architecture & Key Design Decisions

### pico-bridge: HTTP Webhook Client

- The Pico acts as an **HTTP client**, not a server. It POSTs burner telemetry JSON to `POST /api/machine-data` on the proxy.
- Implemented as a lwIP TCP state machine in `pico-bridge/src/http_client.c`.
- Uses IPv6 (lwIP is IPv6-only; see `platform/lwipopts.h`).
- Webhook path is fixed: `/api/machine-data`.
- Adds `X-Hook-Auth: <token>` header when a token is configured.
- DNS resolution is supported; bare IPv6 addresses (no brackets) are accepted in `SERVER=`.
- Retry on failure with 5 s backoff (`HTTP_CLIENT_RETRY_MS`); 10 s connection/response timeout (`HTTP_CLIENT_TIMEOUT_MS`).
- Only the latest data is queued; if a request is in-flight, the pending data is replaced with the most recent value.

### proxy: Webhook Receiver

- `proxy/src/webhook-receiver.js` validates the `X-Hook-Auth` header with a **constant-time comparison** (`crypto.timingSafeEqual`) to prevent timing attacks.
- Updates shared in-memory burner state and triggers push notifications on flame/error transitions.
- Accumulates flame-on seconds in `state.flame_secs`.

### proxy: Push Notifications (fully implemented)

- `proxy/src/push-manager.js` uses the `web-push` npm package for actual RFC 8291/8292 Web Push delivery.
- VAPID keys are auto-generated on first run and stored in `proxy/data/vapid.json`.
- Subscriptions are persisted to `proxy/data/subscriptions.json` (up to 32 entries).
- Three notification types: `flame` (flame on/off), `error` (non-zero error code), `clean` (periodic cleaning reminder).
- The `scheduler.js` fires a cleaning reminder every Saturday at 07:00 during November–March (heating season).

### pico-bridge: Push Notifications (partial)

- VAPID P-256 keys are generated on first boot and stored in `/vapid.dat`.
- Up to 4 subscriptions are stored in `/subs.dat` (persisted across reboots via LittleFS).
- `push_manager_notify_all()` currently **logs only**; actual outbound HTTPS delivery requires TLS client support (`pico_lwip_mbedtls`) and RFC 8291 message encryption — marked `TODO` in `pico-bridge/src/push_manager.c`.
- Proxy-side push (via `PICO_BASE_URL` forwarding) is the recommended path for actual delivery today.

### Flash / Persistent Storage (pico-bridge)

- **LittleFS** filesystem occupies the **last 64 KB** (16 × 4 KB blocks) of flash.
- HAL is in `pico-bridge/src/lfs_hal.c`; auto-formats on first boot or corruption.
- Files stored:
  - `/vapid.dat` – VAPID EC key pair (magic + private(32) + public(65) + CRC32(4) = 105 bytes)
  - `/wifi.dat` – AES-128-GCM encrypted WiFi credentials (magic + nonce(12) + tag(16) + ciphertext(112) = 144 bytes)
  - `/country.dat` – 2-byte Wi-Fi country code (e.g., `SE`)
  - `/server.dat` – Proxy server IP string + uint16_t port (49 bytes)
  - `/hook.dat` – Webhook auth token (up to 64 bytes)
  - `/subs.dat` – Push subscriptions (magic + 4 × slot + CRC32 = 2596 bytes)

### WiFi Credentials (pico-bridge)

- Stored **AES-128-GCM encrypted** in `/wifi.dat`; AES key derived via `SHA-256(board_id || "VIKINGBIO_WIFIKEY")`.
- **Primary configuration**: USB serial (115200 baud) commands (see table below).
- **Secondary (compile-time fallback)**: `-DWIFI_SSID=` / `-DWIFI_PASSWORD=` cmake options (only active if no stored credentials).

### USB Serial Commands (pico-bridge)

Connect via USB serial at 115200 baud. All commands are line-terminated (`\n`).

| Command | Description |
|---|---|
| `SSID=<ssid>` | Stage the WiFi SSID |
| `PASS=<password>` | Save staged SSID + password and reboot |
| `COUNTRY=<CC>` | Set Wi-Fi country code (2 uppercase letters, e.g. `SE`, `US`) |
| `SERVER=<ip>` | Set proxy server IP/hostname (bare IPv6 without brackets, e.g. `fe80::1`) |
| `PORT=<port>` | Set proxy server port (default: `9000`; must set `SERVER=` first) |
| `TOKEN=<token>` | Set webhook `X-Hook-Auth` token (max 64 chars) |
| `STATUS` | Show WiFi status, server/token config, subscription count, VAPID public key |
| `CLEAR` | Erase stored credentials and reboot |

After first boot, run `STATUS` to get the device VAPID public key and set `PICO_VAPID_PUBLIC_KEY` in the proxy's environment.

### Main Loop (pico-bridge)

`pico-bridge/src/main.c` is a **cooperative polling loop**:
1. Feed watchdog (8 s timeout)
2. `cyw43_arch_poll()` – drive Wi-Fi/lwIP stack
3. `process_usb_commands()` – USB serial config
4. `serial_handler_data_available()` / `serial_handler_read()` – Viking Bio UART data
5. `http_client_poll()` / `http_client_send_data()` – webhook delivery
6. Event flags set by a 2-second `repeating_timer`: `EVENT_TIMEOUT_CHECK`, `EVENT_BROADCAST`

### Viking Bio 20 Protocol

Two modes supported (`pico-bridge/src/viking_bio_protocol.c`):
- **Binary**: `[0xAA] [FLAGS] [FAN_SPEED] [TEMP_HIGH] [TEMP_LOW] [0x55]`
  - FLAGS bit 0 = flame detected, bits 1–7 = error code
- **Text**: `F:1,S:50,T:75` (Flame 0/1, Speed %, Temperature °C)
- UART0, GPIO1 (RX), 9600 baud, 8N1

### LED Behavior (pico-bridge)

- **Steady on**: Wi-Fi connected
- **2 Hz blink**: Wi-Fi not connected
- **Short 50 ms blink**: Serial data received from burner

### mDNS (pico-bridge)

- Device advertises as `viking-bio-XXYY.local` (last 2 bytes of Pico board ID).
- No HTTP service is registered (the Pico does not serve HTTP).

### lwIP Configuration

- **IPv6-only** (`LWIP_IPV4 0`, `LWIP_IPV6 1`) — the CYW43 arch uses IPv6.
- `MEMP_NUM_SYS_TIMEOUT 14` — must be ≥ 14; lower values cause an assertion panic during mDNS probe/announce startup.
- No HTTP server (`pico_lwip_http` is not linked). Only TCP client + mDNS responder.

## Code Style

Per `.editorconfig`:
- **C/H files**: tabs for indentation, max line length 100
- **CMake/Python files**: 4-space indentation
- **YAML/JSON**: 2-space indentation
- **JavaScript files**: tabs for indentation
- All files: UTF-8, LF line endings, final newline, no trailing whitespace (except `.md`)

Header guards use `#ifndef MODULE_H` / `#define MODULE_H` / `#endif // MODULE_H` style.

## Common Tasks for a Coding Agent

### Adding a new proxy API endpoint

1. Add a route in `proxy/src/server.js` (e.g., `app.get('/api/newdata', ...)`).
2. No firmware changes needed for proxy-only additions.

### Modifying the dashboard UI

1. Edit files in `proxy/public/` (`index.html`, `app.js`, `style.css`, `sw.js`, `manifest.json`).
2. Run `npm start` in `proxy/` to test locally.

### Adding a new LittleFS-persisted setting (pico-bridge)

1. Define a new file path constant (e.g., `#define NEW_SETTING_FILE "/setting.dat"`).
2. Use `lfs_hal_read_file` / `lfs_hal_write_file` / `lfs_hal_delete_file` from `pico-bridge/src/lfs_hal.c`.
3. `lfs_hal_init()` must be called and succeed before any file operations (already called in `main()`).

### Changing mbedTLS configuration (pico-bridge)

Edit `pico-bridge/platform/mbedtls_config.h`. The `MBEDTLS_ALLOW_PRIVATE_ACCESS` define is set in `pico-bridge/CMakeLists.txt` via `add_compile_definitions` and is required for accessing `MBEDTLS_PRIVATE` struct members.

### Changing lwIP configuration (pico-bridge)

Edit `pico-bridge/platform/lwipopts.h`. **Do not reduce `MEMP_NUM_SYS_TIMEOUT` below 14** — see "Errors Encountered" below.

## Known Limitations / TODOs

- Outbound HTTPS Web Push from the Pico W (`push_manager_notify_all`) logs only; actual delivery to browser push services requires `pico_lwip_mbedtls` and RFC 8291 message encryption (marked `TODO` in `pico-bridge/src/push_manager.c`). Use the proxy for Web Push delivery today.
- `pico-bridge/src/tcp_client.c` is a leftover from an older TCP transport approach and is no longer used.
- IPv4 is not shown in the `STATUS` command (lwIP is IPv6-only; only IPv6 link-local addresses are printed).
- The watchdog reboot (via `watchdog_enable(1, false)`) relies on the watchdog firing within 1 ms; USB stdio output before reboot may not fully flush.

## Errors Encountered

### mDNS startup panic: `MEMP_NUM_SYS_TIMEOUT` too low

**Symptom:** Firmware panics (assertion failure or hard fault) immediately after WiFi connects, during the mDNS probe/announce sequence.

**Root cause:** The lwIP mDNS responder allocates `sys_timeout` slots dynamically during the probe/announce sequence. With `MEMP_NUM_SYS_TIMEOUT` set to 6 (the default for a minimal lwIP build), the pool is exhausted.

**Fix:** Set `MEMP_NUM_SYS_TIMEOUT 14` in `pico-bridge/platform/lwipopts.h`. The comment in that file explains the accounting. This was introduced in PR #22.

**Lesson:** When adding new lwIP features that use timers (mDNS, SNTP, DHCP, etc.), verify that `MEMP_NUM_SYS_TIMEOUT` is large enough. Count: TCP retransmit timers + IPv6 ND/REASS/MLD + DNS + mDNS probe/announce slots.
