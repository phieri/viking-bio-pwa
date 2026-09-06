# Viking Bio Monorepo

A monorepo for the [Viking Bio 20](https://varmebaronen.se/produkter/single/p-15/viking-bio-pelletsbrannare) pellet burner integration system. It consists of four active parts.

The project landing page is published at <https://phieri.github.io/viking-bio-pwa/>.

1. **[pico-bridge/](pico-bridge/)** – Raspberry Pi Pico W / Pico 2 W firmware that reads serial data from the burner and forwards it over a signed persistent TCP telemetry connection to the configurator
2. **[pico-bridge/libvikingbio/](pico-bridge/libvikingbio/)** – shared Viking Bio protocol parser used by the bridge firmware
3. **[configurator/](configurator/)** – Go configurator/runtime that receives burner data over signed TCP ingest and manages the local configuration flow for the Pico bridge
4. **[push-pwa/](push-pwa/)** – browser push notification app that registers browser subscriptions, receives bridge webhooks, and pushes burner alerts to the operator using VAPID/web-push

## Architecture

```
Viking Bio 20 ──UART──► Pico W (pico-bridge)
                              │
                     Signed TCP ingest on INGEST_TCP_PORT
                              │
                          Go Configurator
                          ├── HTTP/HTTPS server (IPv6 [::]:3000)
                          │   ├── GET /api/data             Burner state (JSON)
                          │   ├── GET /api/metrics          Optional history samples
                          │   └── USB provisioning and local config UI
                          └── Bridge provisioning and runtime state
```

## pico-bridge

The Pico firmware:
- Reads Viking Bio 20 serial data (UART0, GPIO1, auto-detecting 4800/9600/19200 baud, 8N1)
- Parses binary (`[0xAA] [FLAGS] [SPEED] [TEMP_H] [TEMP_L] [0x55]`) and text (`F:1,S:50,T:75`) protocols
- Streams parsed data to the configurator via signed persistent TCP ingest
- WiFi credentials, configurator server address, and telemetry device key stored in LittleFS (credentials encrypted with AES-128-GCM)
- Configurable via USB serial (115200 baud)

### Hardware

- Raspberry Pi Pico W or Pico 2 W
- Viking Bio 20 burner TTL serial output (5 V → 3.3 V level shifter required)
- Wiring: Viking Bio Pin 2 (TX) → level shifter → Pico W GP1 (UART0 RX)

### Building

```bash
# Prerequisites: cmake, gcc-arm-none-eabi, libnewlib-arm-none-eabi, Pico SDK 2.3.0
export PICO_SDK_PATH=/path/to/pico-sdk

mkdir pico-bridge/build && cd pico-bridge/build
cmake .. -DPICO_BOARD=pico_w -DWIFI_SSID="your_network" -DWIFI_PASSWORD="your_password"
make -j$(nproc)
```

Output: `pico-bridge/build/viking_bio_bridge-<version>.uf2`

Use `-DPICO_BOARD=pico2_w` when building for a Pico 2 W.

### USB Serial Commands

Connect via USB serial (115200 baud) to configure:

| Command | Description |
|---------|-------------|
| `SSID=<ssid>` | Set WiFi SSID |
| `PASS=<password>` | Set password and save (reboots) |
| `COUNTRY=<CC>` | Set Wi-Fi country code (e.g. SE, US, GB) |
| `SERVER=<ip>` | Set configurator server IP/hostname (IPv6 bare address without brackets) |
| `PORT=<port>` | Set configurator server port (default: 9000) |
| `DEVICEKEY=<key>` | Set the provisioned telemetry device key |
| `WEBHOOK=<url>` | Set the bridge-side webhook target for outbound alerts (for example `https://push-host/webhook.php?token=...`) |
| `STATUS` | Show WiFi, server, telemetry, and webhook status |
| `CLEAR` | Erase stored credentials (reboots) |

## Configurator

The Go configurator/runtime:
- Signed TCP ingest on `INGEST_TCP_PORT` receives framed telemetry from the Pico bridge
- Go net/http server exposes the local operational API and binds to `::` for dual-stack IPv6/IPv4
- Optional TLS: set `TLS_CERT_PATH` / `TLS_KEY_PATH` to enable HTTPS
- Bridge-side alert delivery is configured directly on the Pico; the configurator does not send outbound webhook payloads
- **Device configurator** for first-time setup of the Pico W over USB serial — opens a **Fyne GUI** when a display is available; the runtime behaves as the configurator for the bridge and keeps the operational view in the local device UI.

### Device Configurator

The configurator includes an interactive utility for configuring the Pico W bridge over
USB serial – no separate serial terminal application required.

Start `./viking-bio-configurator` from a local desktop or interactive terminal session.
Set `PICO_SERIAL_PORT` if you want it to use a specific USB serial port. Without that
variable, the UI auto-launches only when exactly one serial port is available.

When a graphical display is available (X11/Wayland on Linux, always on Windows/macOS)
a **Fyne GUI window** opens. On headless systems, use a local desktop session or a
remote X/Wayland display.

The GUI provides:

| Option | Description |
|--------|-------------|
| **Show status** | Reads WiFi state, server config, and telemetry status from the device |
| **Configure WiFi** | Sets SSID + password (device reboots to connect) |
| **Set country code** | Sets the Wi-Fi regulatory domain (e.g. `SE`, `US`, `GB`) |
| **Set server** | Sets the IP address and port of this configurator computer |
| **Set webhook** | Sets the bridge webhook URL for the push PWA backend |
| **Provision telemetry key** | Generates/stores a per-device key on the configurator and sends it to the Pico |
| **Clear credentials** | Erases all stored credentials and reboots the device |

### Local API and configurator UI

The configurator exposes the local operational API and local setup UI without serving a dashboard at `/`:
- **Local API**: the Go service manages ingest, telemetry state, and operational helpers over HTTP/HTTPS
- **USB setup flow**: the local configurator handles bridge onboarding and provisioning over serial
- **Bridge ownership**: alert delivery is configured on the Pico side, so the configurator stays focused on configuration and telemetry state rather than outbound webhooks

### Running

```bash
cd configurator
go build -o viking-bio-configurator ./cmd/configurator
./viking-bio-configurator
```

With custom configuration:

```bash
HTTP_PORT=8080 \
INGEST_TCP_PORT=9000 \
./viking-bio-configurator
```

The configurator binds to `http://[::]:3000/` for the local API and returns 404 for browser-root requests.

### Version display

The configurator shows its build version in the header of the interactive TUI and in the header area of the desktop GUI, with automatic metadata such as the current build date and GitHub Actions run number when those values are available.

Defensive validation notes:
- `HTTP_PORT` and `INGEST_TCP_PORT` must be integers in the range `1..65535`
- The bridge owns the outbound webhook target; the configurator never sends direct alert webhooks
- Existing devices must be reprovisioned to use `INGEST_TCP_PORT` (`9000`) and
  a per-device telemetry key to authenticate signed telemetry

### IPv6-only environments

The configurator binds to `::` (all IPv6 addresses) by default. On Linux this also accepts IPv4 connections via IPv4-mapped addresses unless `IPV6_V6ONLY` is forced. Use a bracketed IPv6 literal when composing the Pico's `SERVER=` address:

```
SERVER=2001:db8::1   ← enter bare (no brackets) via USB serial
```

### TLS / HTTPS

Generate a self-signed certificate for development:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'
TLS_CERT_PATH=server.crt TLS_KEY_PATH=server.key ./viking-bio-configurator
```

For production use a certificate from a private CA or a public certificate authority that matches your deployment.

### Notification Types

The webhook payload includes the same alert categories as the old browser-flow notifications:

| Type | Trigger |
|------|---------|
| `flame` | Flame state changes (on/off) |
| `error` | Non-zero error code detected |

The `push-pwa/` backend receives those alerts at `public/webhook.php` and translates them
into VAPID/web-push notifications for matching browser subscriptions.

## Wiring Diagram

```
Viking Bio 20 RJ12 ──► Level Shifter (5V→3.3V) ──► Pico W GP1 (UART0 RX)
Viking Bio 20 GND  ──────────────────────────────► Pico W GND
```
