# Copilot Instructions for viking-bio-pwa

## Project overview

This repository is a monorepo for the Viking Bio 20 pellet burner integration system.
There are four active components:

1. **`pico-bridge/`** - Raspberry Pi Pico W / Pico 2 W firmware in C. It reads burner data
   over UART, stores configuration in LittleFS, discovers the configurator over mDNS, and
   streams signed telemetry over a persistent TCP ingest connection.
2. **`pico-bridge/libvikingbio/`** - shared protocol parser library used by the bridge firmware.
3. **`proxy/`** - Go configurator/runtime. It receives signed telemetry, manages the Pico
   configuration flow, and exposes the local HTTP API used by automation and local tooling.
   It does not serve a dashboard anymore.
4. **`push-pwa/`** - browser push notification frontend. It registers browser subscriptions,
   keeps VAPID metadata, and sends operator-facing push notifications.

The active runtime architecture is: burner -> Pico bridge -> proxy ingest -> browser push app.
Older docs, memories, and stale README-era notes may still mention a dashboard in `proxy/`,
old Node.js paths, or legacy webhook flows; verify against the current code and CI workflow
before acting.

## How to work efficiently in this repo

When a cloud agent sees this repository for the first time, use the smallest targeted workflow
that proves the relevant behaviour:

- Start with one targeted search or symbol lookup to identify the files most likely to contain
  the change.
- Read only the relevant files and tests for the component you are touching (firmware,
  configurator, or browser push app), then patch the smallest possible surface area.
- Prefer Go validation commands for configurator work (`go test`, `go vet`, `go build`) and
  remember the CI smoke-test constraints (`MDNS_DISABLE=1` for local mDNS-disabled runs).
- For firmware work, verify the toolchain prerequisites before attempting a local build; the CI
  workflow requires Pico SDK and ARM cross-compilation tools.
- For `push-pwa/`, treat it as a distinct workflow with its own packaging and browser-push setup,
  not as part of the Go proxy runtime.
- Treat stale documentation as a risk: confirm behaviour against the current code and workflow
  files rather than older docs that describe the retired dashboard or legacy webhook model.

## Repository structure

```text
.
├── .github/
│   ├── copilot-instructions.md      # Guidance for first-time cloud agents
│   ├── dependabot.yml               # Dependency updates
│   └── workflows/
│       ├── build-firmware.yml       # C firmware build for pico_w / pico2_w
│       ├── build-proxy.yml          # Go proxy lint/test/build/smoke tests
│       ├── build-push-pwa.yml       # Push PWA packaging workflow
│       └── pages.yml                # Demo/site publish workflow
├── pico-bridge/
│   ├── CMakeLists.txt               # Firmware build, Pico SDK setup, LittleFS setup
│   ├── CMakePresets.json            # CMake presets for pico_w / pico2_w
│   ├── include/                     # Firmware public headers
│   ├── src/
│   │   ├── main.c                   # Main loop, USB commands, Wi-Fi startup
│   │   ├── http_client.c            # Signed TCP ingest client
│   │   ├── wifi_config.c            # Encrypted Wi‑Fi/server/token storage
│   │   ├── lfs_hal.c                # LittleFS flash backend
│   │   ├── dns_sd_browser.c         # Passive mDNS/DNS-SD listener for proxy discovery
│   │   └── ...
│   └── platform/
│       ├── lwipopts.h               # lwIP options for IPv6 + TLS client
│       └── mbedtls_config.h         # mbedTLS config used by firmware
├── pico-bridge/libvikingbio/        # Shared protocol parser library
├── proxy/
│   ├── cmd/proxy/main.go            # Entry point and .env loading
│   ├── internal/
│   │   ├── config/                  # Environment parsing and validation
│   │   ├── configure/               # Fyne GUI for local bridge setup
│   │   ├── mdns/                    # Proxy mDNS advertisement
│   │   ├── serial/                  # USB serial bridge for Pico configurator
│   │   ├── server/                  # HTTP API and ingest handlers
│   │   ├── storage/                 # Device registry and runtime state
│   │   └── ...
│   ├── README.md                    # Go proxy runtime documentation
│   ├── Makefile                     # build/test/run shortcuts
│   └── go.mod                       # Go module definition
├── push-pwa/
│   ├── public/                      # Browser PWA frontend, service worker, app JS
│   ├── README.md                    # Browser push app runtime notes
│   └── ...
├── docs/
│   └── architecture.md              # Current runtime architecture overview
├── README.md                        # Top-level monorepo overview
├── .editorconfig                    # Repo code style defaults
├── .gitignore                       # Ignore rules
├── .goreleaser.yml                  # Release config
└── ...
```

## Architecture notes

### Data flow

```text
Viking Bio 20 ──UART──► Pico W firmware
                         ├── signed TCP frames → INGEST_TCP_PORT (default 9000)
                         ├── passive mDNS listener for _viking-bio._tcp
                         └── bridge-owned outbound alert target

Go configurator (proxy)
├── TCP ingest listener (INGEST_TCP_PORT)  signed framed telemetry from Pico
├── local API (HTTP/HTTPS) for operational state, metrics, and config helpers
├── USB provisioning flow for Wi‑Fi/server/device key setup
├── optional TLS and mDNS advertisement
└── no dashboard endpoint is served from the proxy

Browser push app (push-pwa)
├── registers VAPID subscriptions in the browser
├── stores subscription metadata for operator clients
└── sends browser push notifications for burner alerts
```

### Proxy details

- Main entry point is `proxy/cmd/proxy/main.go`.
- HTTP routes are registered in `proxy/internal/server/server.go`.
- Request handling and shared runtime state live in `proxy/internal/server/handlers.go`.
- The proxy intentionally does not serve a dashboard at `/`; the root route returns `404`.
- The proxy is a headless service by default. `--notify-only` restricts access to local-network
  addresses and disables dashboard-style routes.
- The mDNS advertises the proxy as `_viking-bio._tcp` with TXT `path=/api/data` from the
  `mdns` package.
- `MDNS_DISABLE=1` disables mDNS advertisement and is used in CI smoke-test runs.
- The proxy no longer owns browser push delivery; browser notifications are handled by the
  separate `push-pwa/` app.

### Push PWA details

- `push-pwa/` is the browser-facing subscription and delivery app for VAPID/web-push alerts.
- It is a separate runtime from the Go proxy and not a `proxy/public` dashboard.
- Changes to browser subscription logic, UI, or notification payload handling belong under
  `push-pwa/` rather than `proxy/internal/server`.

### Firmware details

- Main loop is in `pico-bridge/src/main.c`.
- Wi‑Fi and lwIP are serviced by the CYW43 arch background thread on core 1; `cyw43_arch_poll()`
  is not called from the main loop.
- USB serial commands are handled directly in `process_usb_commands()` inside `main.c`.
- LittleFS-backed persistent files include Wi‑Fi credentials, country, server/port, telemetry
  device key, and the bridge-side webhook target.
- The default ingest port is `WIFI_SERVER_PORT_DEFAULT` in `pico-bridge/include/wifi_config.h`,
  currently `9000`.
- The Pico passively listens for unsolicited mDNS announcements from the configurator; it does
  not actively query for services.
- The bridge owns the outbound webhook target and sends alert payloads from the Pico itself; the
  Go runtime does not deliver those webhooks.

## Build, test, and validation

### Proxy

The proxy is a Go module in `proxy/` (`module github.com/phieri/viking-bio-pwa/proxy`) and
currently targets Go 1.26. The CI workflow in `.github/workflows/build-proxy.yml` is the
source of truth for proxy validation.

On Linux, install the Fyne GUI dependencies before building the configurator path:

```bash
sudo apt-get update -q
sudo apt-get install -y libgl1-mesa-dev xorg-dev libasound2-dev
```

From `proxy/`, use these validation commands:

```bash
go vet ./...
go test ./...
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/viking-bio-configurator ./cmd/proxy
```

Useful shortcuts:

```bash
make build
make run
make test        # runs go test ./...
```

The current smoke test starts the proxy, provisions a device record, sends a signed framed TCP
payload to `::1:9000`, and verifies the ingest path and API behaviour:

```bash
mkdir -p /tmp/proxy-data
cat > /tmp/proxy-data/devices.json <<'JSON'
{
  "ci-device": { "key": "ci-secret", "last_seq": 0, "updated_at": 0 }
}
JSON
DATA_DIR=/tmp/proxy-data MDNS_DISABLE=1 /tmp/viking-bio-configurator &
SERVER_PID=$!
sleep 2
curl -sf http://localhost:3000/api/data
python - <<'PY'
import base64
import hmac
import json
import socket
import struct

device = "ci-device"
secret = b"ci-secret"
seq = 1
ts = 1
data = {"flame": False, "fan": 0, "temp": 0, "err": 0, "valid": True}
data_json = json.dumps(data, separators=(",", ":"))
canonical = f"{device}\n{seq}\n{ts}\n{data_json}".encode()
sig = base64.b64encode(hmac.new(secret, canonical, "sha256").digest()).decode()
payload = json.dumps({
    "device": device,
    "seq": seq,
    "ts": ts,
    "data": data,
    "sig": sig,
}, separators=(",", ":")).encode()

sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
sock.connect(("::1", 9000))
sock.sendall(struct.pack(">I", len(payload)) + payload)
sock.close()
PY
sleep 1
python - <<'PY'
import json

with open("/tmp/proxy-data/devices.json", "r", encoding="utf-8") as f:
    devices = json.load(f)
assert devices["ci-device"]["last_seq"] == 1, devices
PY
test "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:3000/api/machine-data)" = "404"
curl -sf http://localhost:3000/api/data | grep -q '"valid":true'
kill "$SERVER_PID" || true
```

### Firmware

`build-firmware.yml` is the source of truth for firmware CI. Local builds require the Pico SDK
and ARM toolchain:

```bash
mkdir -p pico-bridge/build
cd pico-bridge/build
cmake .. -DCMAKE_BUILD_TYPE=Release -DPICO_BOARD=pico_w -DWIFI_SSID="ci_build" -DWIFI_PASSWORD="ci_build"
make -j$(nproc)
```

The workflow builds both `pico_w` and `pico2_w`.

### Push PWA

The push app is a separate browser workflow. Typical validation is not a Go build; instead, it is
packaged and served as a static site:

```bash
cd push-pwa
composer install
php -S 0.0.0.0:8000 -t public
```

Treat `push-pwa/` as a separate app with its own package/deploy workflow and browser-specific
notification config.

## Where to make changes

### Proxy HTTP/API changes

- Add or update routes in `proxy/internal/server/server.go`.
- Implement logic in `proxy/internal/server/handlers.go`.
- Update or add tests in `proxy/internal/server/*_test.go`.

### Proxy configuration changes

- Update parsing and validation in `proxy/internal/config/config.go`.
- Keep `proxy/README.md` aligned with any new env vars or runtime behaviour.

### Device configurator changes

- The local provisioning GUI is launched from the desktop/OS app entry.
- GUI (Fyne) lives in `proxy/internal/configure/gui.go`.
- `RunGUI(bridge, store)` is called when a graphical display is available (X11/Wayland on
  Linux, always on Windows/macOS).
- The Fyne GUI requires native development libraries at compile time on Linux:
  `libgl1-mesa-dev xorg-dev libasound2-dev`.
- Serial transport and status parsing live in `proxy/internal/serial/bridge.go`.

### Push PWA changes

- Browser UI, service worker, and VAPID subscription logic live under `push-pwa/`.
- This is the correct place for browser push-related logic and UI changes.
- Do not confuse it with `proxy/internal/server` or any dashboard assets under `proxy/`.

### Firmware config or networking changes

- Wi‑Fi/server/token persistence lives in `pico-bridge/src/wifi_config.c`.
- Signed TCP ingest client logic lives in `pico-bridge/src/http_client.c`.
- mDNS discovery logic lives in `pico-bridge/src/dns_sd_browser.c`.
- USB command behaviour lives in `pico-bridge/src/main.c`.

## Important runtime behaviour

- The Pico bridge connects to `INGEST_TCP_PORT` (default `9000`) using a signed framed TCP
  connection; `POST /api/machine-data` has been removed and returns `404`.
- The proxy binds to `[::]:<port>` and prefers IPv6.
- The proxy does not serve a dashboard at `/`; the server intentionally returns `404` for
  browser-root requests.
- The proxy accepts only local-network access in `--notify-only` mode.
- For the Pico USB `SERVER=` command, use the bare IPv6 address without brackets.
- `MDNS_DISABLE=1` disables the proxy mDNS advertisement and is used by CI smoke tests.
- Browser notifications are handled by the separate `push-pwa/` app, not by the Go proxy.
- `proxy/public` and related dashboard assets are not the active user-facing app; do not treat
  them as the current dashboard flow unless you are working in a legacy branch.

## Common pitfalls

1. **Do not assume the proxy is a dashboard service.** The active runtime is headless and API-only.
2. **Do not treat `push-pwa/` as part of `proxy/`.** It is a separate browser push app and has its
   own workflow.
3. **Do not trust stale docs blindly.** Older text may still mention a dashboard, Node.js, or the
   legacy webhook route `/api/machine-data`.
4. **When changing proxy routes, update tests too.** Existing tests are small and fast.
5. **mDNS discovery on the Pico is passive.** If the Pico connects after the proxy is already
   running, restart the proxy to force a fresh unsolicited announcement.
6. **Do not call `cyw43_arch_poll()` in the firmware main loop.** Networking runs in a CYW43
   background thread on core 1.

## Errors encountered and workarounds

### 1. Local firmware build prerequisites are usually missing in the cloud agent

Observed while auditing this repository: `PICO_SDK_PATH` was unset and `arm-none-eabi-gcc` was
not installed, so a local firmware build could not be started immediately.

**Workaround:**

- For proxy-only tasks, validate with the Go commands above.
- For firmware tasks, follow `.github/workflows/build-firmware.yml`: install `cmake`,
  `gcc-arm-none-eabi`, `libnewlib-arm-none-eabi`, `build-essential`, fetch Pico SDK 2.3.0,
  and export `PICO_SDK_PATH` before running CMake.

### 2. CI/local smoke tests can fail in restricted environments without multicast support

The proxy advertises mDNS by default, which is unnecessary in CI and can be noisy or unreliable
in restricted environments.

**Workaround:**

- Run proxy smoke tests with `MDNS_DISABLE=1`, matching the CI workflow.

### 3. Stale docs can mislead the agent about the current runtime

Older repo text may still describe a dashboard in `proxy/`, legacy browser-push logic in the
proxy, or webhook delivery owned by the configurator.

**Workaround:**

- Verify behaviour in `proxy/cmd/proxy/main.go`, `proxy/internal/server/server.go`, and the
  current workflow files before patching.
- Treat `push-pwa/` as the browser push app and `proxy/` as the headless Go runtime.

### 4. Pico auto-discovery may appear broken when the proxy was already running

The Pico only listens for unsolicited mDNS announcements and does not send queries.

**Workaround:**

- Restart the proxy after the Pico has connected to Wi‑Fi so the proxy emits a fresh
  `_viking-bio._tcp` announcement.

## Code style

From `.editorconfig`:

- C/C++: tabs, max line length 100
- CMake/Python/shell: 4 spaces
- Markdown: 2 spaces, trailing whitespace preserved
- YAML/JSON: 2 spaces
- UTF-8, LF, final newline everywhere
- Human-facing text uses British English spelling; code identifiers and tool flags remain as-is.
