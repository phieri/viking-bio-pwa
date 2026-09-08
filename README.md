# Viking Bio Networking

Viking Bio Networking connects a Viking Bio 20 pellet burner to a Pico bridge, a Go configurator, and a browser push app.

## Components

- `pico-bridge/` – Raspberry Pi Pico W / Pico 2 W firmware for UART capture, LittleFS config, and signed telemetry ingest.
- `pico-bridge/libvikingbio/` – shared protocol parser.
- `configurator/` – headless Go runtime for telemetry ingest, USB provisioning, and device state.
- `push-pwa/` – browser push app for VAPID subscriptions and operator alerts.

## Architecture

```text
Viking Bio 20 ──UART──► Pico bridge ──signed TCP──► configurator ──alerts──► push-pwa
```

## Quick start

### Firmware

```bash
cd pico-bridge
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DPICO_BOARD=pico_w -DWIFI_SSID="your_network" -DWIFI_PASSWORD="your_password"
make -j$(nproc)
```

### Configurator

```bash
cd configurator
go build -o viking-bio-configurator ./cmd/configurator
./viking-bio-configurator
```

### Push app

```bash
cd push-pwa
composer install
php -S 0.0.0.0:8000 -t public
```

See `architecture.md` for the runtime details and data flow.
