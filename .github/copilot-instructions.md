# Copilot Instructions for viking-bio-pwa

## Project Overview

This repository is a monorepo for the Viking Bio 20 pellet burner integration system.
There are two active components:

1. **`pico-bridge/`** - Raspberry Pi Pico W / Pico 2 W firmware in C. It reads burner data
   over UART, stores config in LittleFS, discovers the proxy over mDNS, and streams telemetry
   to the proxy over a signed persistent TCP ingest connection.
2. **`proxy/`** - Go proxy server and PWA dashboard. It receives burner telemetry, serves
   the web UI, manages browser subscriptions, and sends Web Push notifications using
   proxy-managed VAPID keys.

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
│   │   ├── http_client.c           # Signed TCP ingest client
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
│   │   ├── configure/              # Fyne GUI (gui.go) and TUI fallback (tui.go) for device setup
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
                         ├── signed TCP frames → INGEST_TCP_PORT (default 9000)
                         ├── passive mDNS listener for _viking-bio._tcp
                         └── telemetry only

Proxy (Go)
├── TCP ingest listener (INGEST_TCP_PORT)  signed framed telemetry from Pico
├── GET /                     PWA dashboard
├── GET /api/data             current burner state
├── GET /api/vapid-public-key proxy VAPID public key
├── GET /api/subscribers      subscription count
├── POST /api/subscribe       add/update browser subscription
└── POST /api/unsubscribe     remove browser subscription
```

### Proxy details

- Main entry point is `proxy/cmd/proxy/main.go`.
- HTTP routes are registered in `proxy/internal/server/server.go`.
- Request handling, shared burner state, and push triggering live in
  `proxy/internal/server/handlers.go`.
- Static files are served from disk when `proxy/public/` exists locally; otherwise the
  binary serves embedded assets from `proxy/assets.go`.
- The ServiceWorker's cache key (in `sw.js`) needs to be incremented whenever there
  are changes made to any file in `proxy/public/`.
- Subscriptions are stored in `<DATA_DIR>/subscriptions.json`.
- Proxy VAPID keys are stored in `<DATA_DIR>/server-vapid.pub` and
  `<DATA_DIR>/server-vapid.priv`.
- The proxy advertises `_viking-bio._tcp` with TXT `path=/api/data` via
  `proxy/internal/mdns/advertiser.go`.
- `MDNS_DISABLE=1` disables mDNS advertisement and is used by CI smoke tests.

### Firmware details

- Main loop is in `pico-bridge/src/main.c`. Wi-Fi and lwIP are serviced by the CYW43 arch
  background thread on **core 1** (threadsafe background mode); `cyw43_arch_poll()` is
  **not** called from the main loop. Direct lwIP API calls from core 0 (e.g.
  `tcp_connect`, `tcp_write`) must be wrapped with `cyw43_arch_lwip_begin()` /
  `cyw43_arch_lwip_end()`; lwIP callbacks run on core 1 and do not need extra wrapping.
- USB serial commands are handled directly in `process_usb_commands()` inside `main.c`.
- LittleFS-backed persistent files include Wi-Fi credentials, country, proxy server/port,
  and telemetry device key.
- The default proxy port is `WIFI_SERVER_PORT_DEFAULT` in
  `pico-bridge/include/wifi_config.h`, currently **9000**.
- The Pico passively listens for unsolicited mDNS announcements from the proxy; it does
  not actively query for services.
- All Web Push delivery is handled by the proxy. The firmware does not cache VAPID keys,
  does not store subscriptions, and does not schedule reminders. Older docs may still
  describe earlier partial implementations.
- The old Node.js-era `scheduler.js` no longer exists in the active proxy; scheduled
  cleaning reminders are driven by the Go proxy from telemetry updates.

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
# Write a provisioned device record so the ingest listener accepts frames
cat > /tmp/proxy-data/devices.json <<'JSON'
{
  "ci-device": { "key": "ci-secret", "last_seq": 0, "updated_at": 0 }
}
JSON
DATA_DIR=/tmp/proxy-data MDNS_DISABLE=1 /tmp/viking-bio-proxy &
SERVER_PID=$!
sleep 2
curl -sf http://localhost:3000/api/data
# Send a signed TCP frame to INGEST_TCP_PORT (9000) via Python
# POST /api/machine-data returns 404 (webhook removed)
test "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:3000/api/machine-data)" = "404"
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
- GUI (Fyne) lives in `proxy/internal/configure/gui.go`; TUI fallback lives in
  `proxy/internal/configure/tui.go`.
- `RunGUI(bridge, store)` is called when a graphical display is available (X11/Wayland on
  Linux, always on Windows/macOS). Set `NO_GUI` to any non-empty value to force the TUI.
- The Fyne GUI requires native development libraries at compile time on Linux:
  `libgl1-mesa-dev xorg-dev libasound2-dev`.
- Serial transport and STATUS parsing live in `proxy/internal/serial/bridge.go`.

### Firmware config or networking changes

- Wi-Fi/server/token persistence lives in `pico-bridge/src/wifi_config.c`.
- Signed TCP ingest client logic lives in `pico-bridge/src/http_client.c`.
- mDNS discovery logic lives in `pico-bridge/src/dns_sd_browser.c`.
- USB command behavior lives in `pico-bridge/src/main.c`.

## Important Runtime Behavior

- The Pico bridge connects to `INGEST_TCP_PORT` (default `9000`) using a signed framed TCP
  connection; `POST /api/machine-data` has been removed and returns 404.
- For the Pico USB `SERVER=` command, use the bare IPv6 address without brackets.
- The proxy binds to `[::]:<port>` and prefers IPv6.
- The proxy serves static files from disk first, then falls back to embedded assets.
- The proxy's subscription capacity is 32 (`proxy/internal/storage/subscriptions.go`).

## Common Pitfalls

1. **Do not assume Node.js tooling exists for the proxy.** The proxy is Go; use Go commands
   and Go files.
2. **Do not trust stale docs blindly.** Older text may still mention Node.js, the legacy
   HTTP webhook (`/api/machine-data`), or the old dashboard port (`3000`) being used for
   telemetry. The current ingest uses signed TCP on port `9000`.
3. **When changing proxy routes, update tests too.** Existing tests are small and fast.
4. **When editing dashboard assets, remember Pages copies files explicitly.** If you add a
   new static asset needed by the demo page, update `.github/workflows/pages.yml`.
5. **mDNS discovery on the Pico is passive.** If the Pico connects after the proxy is
   already running, restart the proxy to force a fresh unsolicited announcement.
6. **Do not call `cyw43_arch_poll()` in the firmware main loop.** Networking runs in a
   CYW43 arch background thread on core 1. Long-blocking logic on core 0 is still
   undesirable, but `cyw43_arch_poll()` is a no-op and must not be (re-)introduced.

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
