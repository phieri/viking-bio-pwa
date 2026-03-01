# Viking Bio Monorepo

A monorepo for the Viking Bio 20 pellet burner integration system. It consists of two components:

1. **[pico-bridge/](pico-bridge/)** – Raspberry Pi Pico W firmware that reads serial data from the burner, forwards it via HTTPS webhook to the proxy, and sends Web Push notifications directly from the device using on-device VAPID keys
2. **[proxy/](proxy/)** – Node.js proxy server that receives burner data via authenticated webhook, serves the PWA dashboard over IPv6-capable HTTP/HTTPS, and sends Web Push notifications (fallback)

## Architecture

```
Viking Bio 20 ──UART──► Pico W (pico-bridge)
                              │
                     HTTPS webhook POST /api/machine-data
                     X-Hook-Auth: <token>  (IPv6, e.g. [::1]:3000)
                              │
                         Node.js Proxy (proxy)
                         ├── HTTP/HTTPS server (IPv6 [::]:3000)
                         │   ├── GET /                     Dashboard PWA
                         │   ├── GET /api/data             Burner state (JSON)
                         │   ├── POST /api/machine-data    Webhook from Pico (auth required)
                         │   ├── GET /api/vapid-public-key VAPID key (Pico's or proxy's)
                         │   ├── GET /api/subscribers      Subscription count
                         │   ├── POST /api/subscribe       Add/update subscription
                         │   └── POST /api/unsubscribe     Remove subscription
                         └── Web Push notifications (proxy-side fallback)

Browser push subscriptions are forwarded to the Pico W (when PICO_BASE_URL is
configured) so the device can deliver Web Push notifications directly.
```

## pico-bridge

The Pico W firmware:
- Reads Viking Bio 20 serial data (UART0, GPIO1, 9600 baud, 8N1)
- Parses binary (`[0xAA] [FLAGS] [SPEED] [TEMP_H] [TEMP_L] [0x55]`) and text (`F:1,S:50,T:75`) protocols
- Posts parsed data as JSON to the proxy via **HTTPS webhook** (replaces the old TCP transport)
- Generates a VAPID EC P-256 key pair on first boot and stores it in LittleFS
- Sends **Web Push notifications** directly on flame-state changes and error codes
- WiFi credentials, proxy server address, and webhook auth token stored in LittleFS (credentials encrypted with AES-128-GCM)
- Configurable via USB serial (115200 baud)

> **Note:** Actual outbound HTTPS push delivery from the Pico W requires TLS client support (`pico_lwip_mbedtls`). The firmware scaffold logs notifications; see `src/push_manager.c` for the TODO comment.

### Hardware

- Raspberry Pi Pico W
- Viking Bio 20 burner TTL serial output (5 V → 3.3 V level shifter required)
- Wiring: Viking Bio Pin 2 (TX) → level shifter → Pico W GP1 (UART0 RX)

### Building

```bash
# Prerequisites: cmake, gcc-arm-none-eabi, libnewlib-arm-none-eabi, Pico SDK 2.2.0
export PICO_SDK_PATH=/path/to/pico-sdk

mkdir pico-bridge/build && cd pico-bridge/build
cmake .. -DWIFI_SSID="your_network" -DWIFI_PASSWORD="your_password"
make -j$(nproc)
```

Output: `pico-bridge/build/viking_bio_bridge-<version>.uf2`

### USB Serial Commands

Connect via USB serial (115200 baud) to configure:

| Command | Description |
|---------|-------------|
| `SSID=<ssid>` | Set WiFi SSID |
| `PASS=<password>` | Set password and save (reboots) |
| `COUNTRY=<CC>` | Set Wi-Fi country code (e.g. SE, US, GB) |
| `SERVER=<ip>` | Set proxy server IP/hostname (IPv6 bare address without brackets) |
| `PORT=<port>` | Set proxy server port (default: 3000) |
| `TOKEN=<token>` | Set webhook `X-Hook-Auth` authentication token |
| `STATUS` | Show WiFi, webhook, push subscription count, and VAPID public key |
| `CLEAR` | Erase stored credentials (reboots) |

After first boot, run `STATUS` to read the device's VAPID public key and set `PICO_VAPID_PUBLIC_KEY` in the proxy's environment so browsers subscribe using the Pico's on-device key.

## proxy

The Node.js proxy server:
- **HTTPS webhook** endpoint (`POST /api/machine-data`, authenticated via `X-Hook-Auth` header) receives JSON telemetry from the Pico bridge
- Express HTTP/HTTPS server serves the PWA dashboard; binds to `::` for dual-stack IPv6/IPv4
- Optional TLS: set `TLS_CERT_PATH` / `TLS_KEY_PATH` to enable HTTPS
- Web Push notifications via `web-push` (VAPID keys auto-generated on first start, or use Pico's key via `PICO_VAPID_PUBLIC_KEY`)
- Subscriptions persisted to `proxy/data/subscriptions.json`; forwarded to Pico W when `PICO_BASE_URL` is set

### Running

```bash
cd proxy
npm install
npm start
```

With custom configuration:

```bash
HTTP_PORT=8080 \
MACHINE_WEBHOOK_AUTH_TOKEN=mysecrettoken \
PICO_VAPID_PUBLIC_KEY=<base64url-from-STATUS> \
PICO_BASE_URL=http://[fe80::dead:beef%25eth0]:8080 \
npm start
```

Open the dashboard at `http://[::]:3000/` (or `https://` when TLS is configured).

### IPv6-only environments

The proxy binds to `::` (all IPv6 addresses) by default. On Linux this also accepts IPv4 connections via IPv4-mapped addresses unless `IPV6_V6ONLY` is forced. Use a bracketed IPv6 literal when composing the Pico's `SERVER=` address:

```
SERVER=2001:db8::1   ← enter bare (no brackets) via USB serial
```

The proxy's `PICO_BASE_URL` must use brackets:
```
PICO_BASE_URL=http://[2001:db8::1]:8080
```

### TLS / HTTPS

Generate a self-signed certificate for development:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'
TLS_CERT_PATH=server.crt TLS_KEY_PATH=server.key npm start
```

For production use a certificate from Let's Encrypt (requires a public IPv6 AAAA record) or a private CA.

### Push Notification Types

Subscribers can opt in to three types:

| Type | Trigger |
|------|---------|
| `flame` | Flame state changes (on/off) |
| `error` | Non-zero error code detected |
| `clean` | Cleaning reminder (Saturday 07:00, November–March) |

## Wiring Diagram

```
Viking Bio 20 RJ12 ──► Level Shifter (5V→3.3V) ──► Pico W GP1 (UART0 RX)
Viking Bio 20 GND  ──────────────────────────────► Pico W GND
```
