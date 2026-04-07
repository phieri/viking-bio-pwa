# Copilot Instructions for viking-bio-pwa

## Project Overview

This repository is a monorepo for the Viking Bio 20 pellet burner integration system.
There are two active components:

1. **`pico-bridge/`** - Raspberry Pi Pico W / Pico 2 W firmware in C. It reads burner data
   over UART, stores config in LittleFS, discovers the proxy over mDNS, posts telemetry to
   the proxy over HTTP, and stores the proxy VAPID public key for use by the PWA.
2. **`proxy/`** - Go proxy server and PWA dashboard. It receives burner telemetry, serves
   the web UI, manages browser subscriptions, can forward subscriptions back to the Pico,
   and can send proxy-side Web Push notifications as a fallback.

The proxy is **Go**, not Node.js. Older docs or memories may still mention a previous
Node.js implementation; verify against the current Go code before acting.

## Repository Structure

```text
.
├── pico-bridge/
│   ├── CMakeLists.txt              # Firmware build, Pico SDK setup, LittleFS FetchContent
│   ├── CMakePresets.json           # CMake presets for pico_w / pico2_w
│   ├── include/                    # Firmware public headers
│   ├── src/
│   │   ├── main.c                  # Main loop, USB commands, Wi-Fi startup
│   │   ├── http_client.c           # HTTP webhook client + proxy time sync
│   │   ├── push_manager.c          # Web Push delivery + cleaning reminder scheduler
│   │   ├── wifi_config.c           # Encrypted Wi-Fi/server/token storage
│   │   ├── lfs_hal.c               # LittleFS flash backend
│   │   └── dns_sd_browser.c        # Passive mDNS/DNS-SD listener for proxy discovery
│   └── platform/
│       ├── lwipopts.h              # lwIP options for IPv6 + TLS client
│       └── mbedtls_config.h        # mbedTLS config used by firmware
├── proxy/
│   ├── cmd/proxy/main.go           # Entry point, .env loading, --configure mode
│   ├── internal/
│   │   ├── server/                 # HTTP routes, handlers, tests
│   │   ├── config/                 # Environment parsing and validation
│   │   ├── push/                   # VAPID keys and push delivery
│   │   ├── storage/                # subscriptions.json persistence
│   │   ├── serial/                 # USB serial bridge for Pico configurator
│   │   ├── configure/              # Interactive TUI for device setup
│   │   ├── mdns/                   # Proxy DNS-SD advertisement
│   │   ├── ddns/                   # DuckDNS updater for ACME mode
│   │   └── cert/                   # Let's Encrypt / TLS support
│   ├── public/                     # Static PWA files (served from disk or embedded)
│   ├── assets.go                   # go:embed for proxy/public
│   ├── Makefile                    # build/run/test/configure shortcuts
│   └── README.md                   # Proxy-specific runtime docs
└── .github/workflows/
    ├── build-firmware.yml          # Builds firmware for pico_w and pico2_w
    ├── build-proxy.yml             # go vet/test/build/smoke test/cross-compile
    └── pages.yml                   # Publishes demo page from proxy/public
```

## Architecture Notes

### Data flow

```text
Viking Bio 20 ──UART──► Pico W firmware
                         ├── POST /api/machine-data to proxy
                         ├── passive mDNS listener for _viking-bio._tcp
                         └── optional direct Web Push delivery

Proxy (Go)
├── GET /                     PWA dashboard
├── GET /api/data             current burner state
├── POST /api/machine-data    authenticated webhook from Pico
├── GET /api/vapid-public-key active VAPID key source
├── GET /api/subscribers      subscription count
├── POST /api/subscribe       add/update browser subscription
└── POST /api/unsubscribe     remove browser subscription
```

### Proxy details

- Main entry point is `proxy/cmd/proxy/main.go`.
- HTTP routes are registered in `proxy/internal/server/server.go`.
- Request handling, shared burner state, webhook auth, push triggering, and Pico forwarding
  live in `proxy/internal/server/handlers.go`.
- Static files are served from disk when `proxy/public/` exists locally; otherwise the
  binary serves embedded assets from `proxy/assets.go`.
- Subscriptions are stored in `proxy/data/subscriptions.json`.
- Proxy VAPID keys are stored in `proxy/data/server-vapid.pub` and
  `proxy/data/server-vapid.priv`.
- The proxy advertises `_viking-bio._tcp` with TXT `path=/api/data` via
  `proxy/internal/mdns/advertiser.go`.
- `MDNS_DISABLE=1` disables mDNS advertisement and is used by CI smoke tests.

### Firmware details

- Main loop is in `pico-bridge/src/main.c`.
- USB serial commands are handled directly in `process_usb_commands()` inside `main.c`.
- LittleFS-backed persistent files include Wi-Fi credentials, country, proxy server/port,
  webhook token, proxy VAPID public key (`/vapid_pub.dat`), and push subscriptions.
- The default proxy port is `WIFI_SERVER_PORT_DEFAULT` in
  `pico-bridge/include/wifi_config.h`, currently **3000**.
- The Pico passively listens for unsolicited mDNS announcements from the proxy; it does
  not actively query for services.
- `pico-bridge/src/push_manager.c` contains the Web Push subscription persistence plus the
  cleaning reminder scheduler. The VAPID private key is held exclusively by the proxy; the
  firmware receives the proxy's VAPID public key via the webhook response
  (`vapid_public_key` field) and stores it in `/vapid_pub.dat`. Direct HTTPS push delivery
  from the firmware is not supported — all Web Push delivery is handled by the proxy.
  Use that file as the source of truth when changing push behavior, because
  older docs may still describe earlier partial implementations.
- The old Node.js-era `scheduler.js` no longer exists in the active proxy; scheduled
  cleaning reminders are driven from the firmware via `push_manager_tick_scheduler()`.

## Build, Test, and Validation

### Proxy

Use these commands from `proxy/`:

```bash
go vet ./...
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/viking-bio-proxy ./cmd/proxy
```

The existing CI smoke test is:

```bash
mkdir -p /tmp/proxy-data
DATA_DIR=/tmp/proxy-data MDNS_DISABLE=1 /tmp/viking-bio-proxy &
SERVER_PID=$!
sleep 2
curl -sf http://localhost:3000/api/data
curl -sf -X POST http://localhost:3000/api/machine-data \
  -H "Content-Type: application/json" \
  -d '{"flame":false,"fan":0,"temp":0,"err":0,"valid":true}'
```

Useful shortcuts:

```bash
make build
make run
make test
make configure
```

### Firmware

`build-firmware.yml` is the source of truth for firmware CI. Local build requires the Pico
SDK and ARM toolchain:

```bash
mkdir -p pico-bridge/build
cd pico-bridge/build
cmake .. -DCMAKE_BUILD_TYPE=Release -DPICO_BOARD=pico_w -DWIFI_SSID="ci_build" -DWIFI_PASSWORD="ci_build"
make -j$(nproc)
```

The workflow builds both `pico_w` and `pico2_w`.

## Where to Make Changes

### Proxy HTTP/API changes

- Add or update routes in `proxy/internal/server/server.go`.
- Implement logic in `proxy/internal/server/handlers.go`.
- Update or add tests in `proxy/internal/server/handlers_test.go` and
  `proxy/internal/server/server_test.go`.

### Proxy configuration changes

- Update parsing/validation in `proxy/internal/config/config.go`.
- Keep `proxy/.env.example` and `proxy/README.md` aligned with any new env vars or runtime
  behavior.

### Dashboard / PWA changes

- Edit files under `proxy/public/`.
- There is no JS build step; the Go server serves these files directly or from embedded
  assets.
- For Pages, `.github/workflows/pages.yml` manually copies individual files from
  `proxy/public/` after generating the demo HTML.

### Device configurator changes

- CLI entry is `./viking-bio-proxy --configure`.
- TUI lives in `proxy/internal/configure/tui.go`.
- Serial transport and STATUS parsing live in `proxy/internal/serial/bridge.go`.

### Firmware config or networking changes

- Wi-Fi/server/token persistence lives in `pico-bridge/src/wifi_config.c`.
- HTTP webhook logic lives in `pico-bridge/src/http_client.c`.
- mDNS discovery logic lives in `pico-bridge/src/dns_sd_browser.c`.
- Push delivery and scheduler logic live in `pico-bridge/src/push_manager.c`.
- USB command behavior lives in `pico-bridge/src/main.c`.

## Important Runtime Behavior

- `POST /api/machine-data` requires `Content-Type: application/json` and validates
  `X-Hook-Auth` when `MACHINE_WEBHOOK_AUTH_TOKEN` is set.
- `PICO_BASE_URL` must be a full `http://` or `https://` URL.
- For IPv6 URLs, `PICO_BASE_URL` must use brackets, for example `http://[::1]:3000`.
- For the Pico USB `SERVER=` command, use the bare IPv6 address without brackets.
- The proxy binds to `[::]:<port>` and prefers IPv6.
- The proxy serves static files from disk first, then falls back to embedded assets.
- The proxy's subscription capacity is 32 (`proxy/internal/storage/subscriptions.go`).
- The Pico's subscription capacity is 4 (`pico-bridge/include/push_manager.h`).

## Common Pitfalls

1. **Do not assume Node.js tooling exists for the proxy.** The proxy is Go; use Go commands
   and Go files.
2. **Do not trust stale docs blindly.** Older text may still mention Node.js, port `9000`,
   or push notifications handled only by the proxy.
3. **When changing proxy routes, update tests too.** Existing tests are small and fast.
4. **When editing dashboard assets, remember Pages copies files explicitly.** If you add a
   new static asset needed by the demo page, update `.github/workflows/pages.yml`.
5. **mDNS discovery on the Pico is passive.** If the Pico connects after the proxy is
   already running, restart the proxy to force a fresh unsolicited announcement.
6. **The firmware depends on regular polling.** Long-blocking logic does not fit the Pico
   main loop.

## Errors Encountered and Workarounds

### 1. Local firmware build prerequisites are usually missing in the cloud agent

Observed while auditing this repository: `PICO_SDK_PATH` was unset and `arm-none-eabi-gcc`
was not installed, so a local firmware build could not be started immediately.

**Workaround:**

- For proxy-only tasks, validate with the Go commands above.
- For firmware tasks, follow `.github/workflows/build-firmware.yml`: install `cmake`,
  `gcc-arm-none-eabi`, `libnewlib-arm-none-eabi`, `build-essential`, fetch Pico SDK 2.2.0,
  and export `PICO_SDK_PATH` before running CMake.

### 2. CI/local smoke tests can fail in environments without multicast support

The proxy publishes mDNS by default, which is unnecessary in CI and can be noisy or
unreliable in restricted environments.

**Workaround:**

- Run proxy smoke tests with `MDNS_DISABLE=1`, matching `build-proxy.yml`.

### 3. Pico auto-discovery may appear broken when the proxy was already running

The Pico only listens for unsolicited mDNS announcements and does not send queries.

**Workaround:**

- Restart the proxy after the Pico has connected to Wi-Fi so the proxy emits a fresh
  `_viking-bio._tcp` announcement.

## Code Style

From `.editorconfig`:

- C/C++: tabs, max line length 100
- CMake/Python/shell: 4 spaces
- Markdown: 2 spaces, trailing whitespace preserved
- YAML/JSON: 2 spaces
- UTF-8, LF, final newline everywhere
