# Viking Bio Monorepo

A monorepo for the [Viking Bio 20](https://varmebaronen.se/produkter/single/p-15/viking-bio-pelletsbrannare) pellet burner integration system. It consists of three parts:

1. **[pico-bridge/](pico-bridge/)** – Raspberry Pi Pico W / Pico 2 W firmware that reads serial data from the burner and forwards it over a signed persistent TCP telemetry connection to the proxy
2. **[pico-bridge/libvikingbio/](pico-bridge/libvikingbio/)** – shared Viking Bio protocol parser used by the bridge firmware
3. **[proxy/](proxy/)** – Go proxy server that receives burner data over signed TCP ingest, serves the PWA dashboard over IPv6-capable HTTP/HTTPS, and sends alert payloads to a configurable webhook endpoint

## Architecture

```
Viking Bio 20 ──UART──► Pico W (pico-bridge)
                              │
                     Signed TCP ingest on INGEST_TCP_PORT
                              │
                          Go Proxy (proxy)
                          ├── HTTP/HTTPS server (IPv6 [::]:3000)
                          │   ├── GET /                     Dashboard PWA
                          │   ├── GET /api/data             Burner state (JSON)
                          │   └── → POST <WEBHOOK_URL>       Outbound alert payloads
                          └── Notification processor
```

## pico-bridge

The Pico firmware:
- Reads Viking Bio 20 serial data (UART0, GPIO1, auto-detecting 4800/9600/19200 baud, 8N1)
- Parses binary (`[0xAA] [FLAGS] [SPEED] [TEMP_H] [TEMP_L] [0x55]`) and text (`F:1,S:50,T:75`) protocols
- Streams parsed data to the proxy via signed persistent TCP ingest
- WiFi credentials, proxy server address, and telemetry device key stored in LittleFS (credentials encrypted with AES-128-GCM)
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
| `SERVER=<ip>` | Set proxy server IP/hostname (IPv6 bare address without brackets) |
| `PORT=<port>` | Set proxy server port (default: 9000) |
| `DEVICEKEY=<key>` | Set the provisioned telemetry device key |
| `STATUS` | Show WiFi, server, and telemetry status |
| `CLEAR` | Erase stored credentials (reboots) |

## proxy

The Go proxy server:
- Signed TCP ingest on `INGEST_TCP_PORT` receives framed telemetry from the Pico bridge
- Go net/http server serves the PWA dashboard; binds to `::` for dual-stack IPv6/IPv4
- Optional TLS: set `TLS_CERT_PATH` / `TLS_KEY_PATH` to enable HTTPS
- Alert notifications are forwarded to `WEBHOOK_URL` as JSON payloads
- **Device configurator** (`./viking-bio-proxy --configure`) for first-time setup of the Pico W over USB serial — opens a **Fyne GUI** when a display is available, falls back to a terminal TUI on headless hosts (set `NO_GUI` to any non-empty value to force TUI)

### Device Configurator

The proxy includes an interactive utility for configuring the Pico W bridge over
USB serial – no separate serial terminal application required.

```bash
./viking-bio-proxy --configure                        # auto-detect Pico W USB port
./viking-bio-proxy --configure --port /dev/ttyACM0   # specify port directly (Linux)
./viking-bio-proxy --configure --port COM3           # Windows
```

When a graphical display is available (X11/Wayland on Linux, always on Windows/macOS)
a **Fyne GUI window** opens.  On headless machines or when `NO_GUI` is set to any
non-empty value (e.g. `NO_GUI=1`), the configurator falls back to the interactive
**terminal TUI**.

Both interfaces provide:

| Option | Description |
|--------|-------------|
| **Show status** | Reads WiFi state, server config, and telemetry status from the device |
| **Configure WiFi** | Sets SSID + password (device reboots to connect) |
| **Set country code** | Sets the Wi-Fi regulatory domain (e.g. `SE`, `US`, `GB`) |
| **Set proxy server** | Sets the IP address and port of this proxy computer |
| **Provision telemetry key** | Generates/stores a per-device key on the proxy and sends it to the Pico |
| **Clear credentials** | Erases all stored credentials and reboots the device |

### PWA Dashboard

The dashboard at `proxy/public/` is a fully installable Progressive Web App:
- **Offline support**: the app cache remains available for the dashboard shell while API requests bypass the cache
- **Icons**: SVG source icon with PNG variants at 192×192 and 512×512 (standard + maskable), plus favicon and Apple touch icon
- **Alert delivery**: the proxy sends notification payloads to the configured `WEBHOOK_URL`; no browser-side subscription flow remains

### Running

```bash
cd proxy
go build -o viking-bio-proxy ./cmd/proxy
./viking-bio-proxy
```

With custom configuration:

```bash
HTTP_PORT=8080 \
INGEST_TCP_PORT=9000 \
./viking-bio-proxy
```

Open the dashboard at `http://[::]:3000/` (or `https://` when TLS is configured).

### Command-Line Flags

| Flag | Description |
|------|-------------|
| `--configure` | Run the interactive device configurator TUI |
| `--port <port>` | Serial port for `--configure` (e.g. `/dev/ttyACM0`, `COM3`) |
| `--notify-only` | Notification-only mode: no dashboard, local network only |
| `--notify-test` | Send a test notification to `WEBHOOK_URL` and exit |
| `--no-open-browser` | Do not open the browser automatically on startup |
| `--version` | Print version and exit |

Defensive validation notes:
- `HTTP_PORT` and `INGEST_TCP_PORT` must be integers in the range `1..65535`
- `WEBHOOK_URL` must be a valid HTTP(S) URL when notification delivery is enabled
- Existing devices must be reprovisioned to use `INGEST_TCP_PORT` (`9000`) and
  a per-device telemetry key because the legacy webhook API has been removed

### IPv6-only environments

The proxy binds to `::` (all IPv6 addresses) by default. On Linux this also accepts IPv4 connections via IPv4-mapped addresses unless `IPV6_V6ONLY` is forced. Use a bracketed IPv6 literal when composing the Pico's `SERVER=` address:

```
SERVER=2001:db8::1   ← enter bare (no brackets) via USB serial
```

### TLS / HTTPS

Generate a self-signed certificate for development:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'
TLS_CERT_PATH=server.crt TLS_KEY_PATH=server.key ./viking-bio-proxy
```

For production use a certificate from a private CA or a public certificate authority that matches your deployment.

### Notification Types

The webhook payload includes the same alert categories as the old browser-flow notifications:

| Type | Trigger |
|------|---------|
| `flame` | Flame state changes (on/off) |
| `error` | Non-zero error code detected |
| `clean` | Weekly cleaning reminder during heating season (Nov–Mar) |

## Wiring Diagram

```
Viking Bio 20 RJ12 ──► Level Shifter (5V→3.3V) ──► Pico W GP1 (UART0 RX)
Viking Bio 20 GND  ──────────────────────────────► Pico W GND
```
