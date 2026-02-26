# Viking Bio PWA

A Progressive Web App (PWA) dashboard and Web Push notification system for the Viking Bio 20 pellet burner, running on a Raspberry Pi Pico W.

## Features

- **Real-time Dashboard**: Web-based dashboard showing live burner data (flame status, fan speed, temperature, error codes)
- **Server-Sent Events (SSE)**: Automatic data streaming — the dashboard updates in real-time without polling
- **Web Push Notifications**: Browser push notifications when errors are detected
- **PWA**: Installable on mobile/desktop, works offline (cached service worker)
- **Viking Bio 20 Protocol**: Reads TTL serial data at 9600 baud from the burner's serial port

## Hardware

- Raspberry Pi Pico W
- Viking Bio 20 burner (TTL serial at 9600 baud, 8N1)
- Serial connection: UART0 (GPIO0=TX, GPIO1=RX)

## Architecture

```
Viking Bio 20 ──UART──► Pico W ──WiFi──► Browser
                          │
                    HTTP Server (port 80)
                    ├── GET /             Dashboard PWA
                    ├── GET /sw.js        Service Worker
                    ├── GET /manifest.json PWA Manifest
                    ├── GET /data         SSE Stream
                    ├── GET /vapid-public-key  VAPID Key
                    ├── POST /subscribe   Push Subscription
                    └── POST /unsubscribe Remove Subscription
```

## Building

### Prerequisites

```bash
sudo apt-get install cmake gcc-arm-none-eabi libnewlib-arm-none-eabi build-essential

# Clone Pico SDK 2.2.0
git clone --depth 1 --branch 2.2.0 https://github.com/raspberrypi/pico-sdk.git
cd pico-sdk && git submodule update --init && cd ..

export PICO_SDK_PATH=$(pwd)/pico-sdk
```

### Build

```bash
mkdir build-pwa && cd build-pwa
cmake .. -DWIFI_SSID="your_network" -DWIFI_PASSWORD="your_password"
make -j$(nproc)
```

The firmware will be built as `viking_bio_pwa-<version>.uf2`.

### Flash

Hold BOOTSEL while plugging in the Pico W, then copy the `.uf2` file to the mounted drive.

## Web Push

1. Open the dashboard in a browser at `http://<pico-ip>/`
2. Click **Enable Push Notifications**
3. Accept the notification permission request
4. The browser is now registered for push notifications
5. When the Viking Bio 20 reports an error (non-zero error code), a push notification is sent

VAPID keys are generated on first boot and stored in the last flash sector. They persist across reboots.

## Data Format

The Viking Bio 20 protocol supports:

**Binary protocol**: `[0xAA] [FLAGS] [FAN_SPEED] [TEMP_HIGH] [TEMP_LOW] [0x55]`
- FLAGS bit 0: flame detected
- FLAGS bits 1-7: error code

**Text protocol**: `F:1,S:50,T:75` (Flame, Speed%, Temp°C)

## Serial Connection

| Signal | Pico W Pin | GPIO |
|--------|-----------|------|
| RX     | Pin 2      | GP1  |
| GND    | Pin 3      | GND  |
