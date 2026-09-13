# Viking Bio Networking

Viking Bio Networking connects a Viking Bio 20 pellet burner to a Pico bridge, a Go configurator, and a browser push app.

## Components

- `pico-bridge/` – Raspberry Pi Pico W / Pico 2 W firmware for UART capture, LittleFS config, and signed telemetry ingest.
- `pico-bridge/libvikingbio/` – shared protocol parser.
- `configurator/` – Go runtime with a desktop GUI and terminal TUI for telemetry ingest, USB provisioning, and device state.
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
cmake .. -DCMAKE_BUILD_TYPE=Release -DPICO_BOARD=pico2_w -DWIFI_SSID="your_network" -DWIFI_PASSWORD="your_password"
make -j$(nproc)
```

### Configurator

On Ubuntu/Linux desktop systems, install the GUI dependencies before building the desktop app:

```bash
cd configurator
sudo apt-get install -y libgl1-mesa-dev xorg-dev libasound2-dev libglfw3-dev libxkbcommon-dev
CGO_ENABLED=1 go build -o viking-bio-configurator ./cmd/configurator
./viking-bio-configurator
```

On headless/TTY systems, the app falls back to the terminal TUI automatically when `DISPLAY` and `WAYLAND_DISPLAY` are unset; the desktop GUI is only used when a graphical session is available.

### Push app

```bash
cd push-pwa
composer install
php -S [::]:8000 -t public
```

See `architecture.md` for the runtime details and data flow.
