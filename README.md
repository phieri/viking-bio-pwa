# Viking Bio Monorepo

A monorepo for the Viking Bio 20 pellet burner integration system. It consists of two components:

1. **[pico-bridge/](pico-bridge/)** – Raspberry Pi Pico W firmware that reads serial data from the burner and forwards it via TCP to the proxy server
2. **[proxy/](proxy/)** – Node.js proxy server that receives burner data by TCP, serves the PWA dashboard, and sends Web Push notifications

## Architecture

```
Viking Bio 20 ──UART──► Pico W (pico-bridge)
                              │
                         TCP (port 9000)
                              │
                         Node.js Proxy (proxy)
                         ├── HTTP server (port 3000)
                         │   ├── GET /                Dashboard PWA
                         │   ├── GET /api/data        Burner state (JSON)
                         │   ├── GET /api/vapid-public-key  VAPID key
                         │   ├── GET /api/subscribers Subscription count
                         │   ├── POST /api/subscribe  Add/update subscription
                         │   └── POST /api/unsubscribe Remove subscription
                         └── Web Push notifications
                             ├── Flame on/off
                             ├── Error codes
                             └── Cleaning reminder (Sat 07:00, Nov–Mar)
```

## pico-bridge

The Pico W firmware:
- Reads Viking Bio 20 serial data (UART0, GPIO1, 9600 baud, 8N1)
- Parses binary (`[0xAA] [FLAGS] [SPEED] [TEMP_H] [TEMP_L] [0x55]`) and text (`F:1,S:50,T:75`) protocols
- Sends parsed data as newline-delimited JSON to the proxy server via TCP
- WiFi credentials and proxy server address stored in LittleFS (encrypted with AES-128-GCM)
- Configurable via USB serial (115200 baud)

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
| `SERVER=<ip>` | Set proxy server IP address |
| `PORT=<port>` | Set proxy server TCP port (default: 9000) |
| `STATUS` | Show WiFi and TCP connection status |
| `CLEAR` | Erase stored credentials (reboots) |

## proxy

The Node.js proxy server:
- TCP server (port 9000) receives JSON messages from the Pico bridge
- Express HTTP server (port 3000) serves the PWA dashboard
- Web Push notifications via `web-push` (VAPID keys auto-generated on first start)
- Subscriptions persisted to `proxy/data/subscriptions.json`

### Running

```bash
cd proxy
npm install
npm start
```

Or with custom ports:

```bash
HTTP_PORT=8080 TCP_PORT=9000 npm start
```

Open the dashboard at `http://<proxy-server>:3000/`.

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
