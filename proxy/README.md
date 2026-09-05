# Viking Bio Configurator (Go)

Go implementation of the Viking Bio pellet-burner configurator. It receives
signed telemetry from the Pico W bridge, serves the local operational dashboard,
and manages the bridge configuration flow without sending outbound webhook
payloads itself.

## Build

```bash
cd proxy
go build -o viking-bio-configurator ./cmd/proxy
# or
make build
```

## Command-Line Flags

| Flag | Description |
|------|-------------|
| `--notify-only` | Notification-only mode: no dashboard, local network only |
| `--version` | Print version and exit |

## Run

```bash
# Plain HTTP on port 3000
./viking-bio-configurator

# With environment variables
HTTP_PORT=8080 INGEST_TCP_PORT=9000 ./viking-bio-configurator

# Using make
make run
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `HTTP_PORT` | `3000` | HTTP/HTTPS listen port |
| `INGEST_TCP_PORT` | `9000` | Framed TCP telemetry ingest port |
| `INGEST_TCP_TLS` | `false` | Require TLS on the ingest listener (uses `TLS_CERT_PATH`/`TLS_KEY_PATH`) |
| `TLS_CERT_PATH` | _(empty)_ | Path to TLS certificate (PEM) |
| `TLS_KEY_PATH` | _(empty)_ | Path to TLS private key (PEM) |
| `MDNS_NAME` | `Viking Bio` | mDNS/DNS-SD service instance name |
| `MDNS_DISABLE` | `false` | Disable mDNS advertisement (`1` or `true`) |
| `TELEMETRY_HISTORY_ENABLED` | `false` | Enable in-memory metrics history for `GET /api/metrics` (`1` or `true`) |
| `CLEANING_REMINDER_WEEKDAY` | `Saturday` | Weekday for cleaning reminders (e.g. `Monday`, `Saturday`) |
| `CLEANING_REMINDER_TIME` | `07:00` | Start time (UTC) for the cleaning reminder window (`HH:MM`) |
| `PICO_SERIAL_PORT` | _(empty)_ | Default serial port for the local provisioning GUI |
| `DATA_DIR` | `~/.viking-bio-bridge` on Linux, `<exe_dir>/data` otherwise | Directory for device registry, logs, and local config |

## Configuration Files

The configurator loads configuration in this order (earlier sources take precedence):

1. **Environment variables** – highest priority.
2. **`.env`** – read from the current working directory at startup.
3. **`<DATA_DIR>/viking-bio.conf`** – created automatically on first run as a commented
   template; edit it and restart the configurator to apply changes without a `.env` file next
   to the binary.

Example `.env` / `viking-bio.conf` snippet:

```env
HTTP_PORT=3000
INGEST_TCP_PORT=9000
MDNS_NAME=Viking Bio
TELEMETRY_HISTORY_ENABLED=1
CLEANING_REMINDER_WEEKDAY=Saturday
CLEANING_REMINDER_TIME=07:00
```

The bridge owns outbound webhook delivery during runtime; the configurator stays
responsible for provisioning the Pico and serving the local operational UI.

## Notification-Only Mode

Run the configurator in a headless configuration without the PWA dashboard. All HTTP routes
are restricted to loopback and private-network addresses:

```bash
./viking-bio-configurator --notify-only
```

This is useful when the configurator runs on a local-only host and another service (e.g. a
reverse proxy) handles public HTTPS termination.

## TLS / HTTPS

### Manual TLS

```env
TLS_CERT_PATH=/etc/ssl/certs/server.crt
TLS_KEY_PATH=/etc/ssl/private/server.key
```

## Device Configurator

Connect the Pico W via USB and launch the local provisioning GUI from the desktop or
OS launcher. If the environment variable `PICO_SERIAL_PORT` is set, the GUI uses that
USB serial port automatically; otherwise it prompts to select one.

When a graphical display is available (X11 `DISPLAY` or Wayland `WAYLAND_DISPLAY` on
Linux; always on Windows and macOS) the configurator opens a **Fyne-based GUI window**.
On headless systems, the GUI is not supported; run it from a machine with a local
desktop session or remote X/Wayland display.

The configurator allows you to:

- View device status (IP, country, server, telemetry state)
- Set WiFi SSID + password
- Set Wi-Fi country code
- Set server address and port
- Provision and sync a per-device telemetry key over USB
- Clear all stored credentials

Provisioning stores the configurator-side device secret in `<DATA_DIR>/devices.json`
and sends the same key to the Pico over USB. The Pico then uses that key to
sign each TCP telemetry frame with HMAC-SHA256.

### Building with GUI support on Linux

The Fyne GUI requires a few native development libraries at compile time.  Install
them before running `go build` on Linux:

```bash
sudo apt-get install -y libgl1-mesa-dev xorg-dev libasound2-dev
```

For cross-compilation and producing distribution packages, see the
[Fyne packaging docs](https://docs.fyne.io/started/packaging) and
[fyne-cross](https://github.com/fyne-io/fyne-cross).  In CI, add the above
packages to the build step (or set `CGO_ENABLED=0` and build a static binary
without GUI support where only the TUI path is needed).

## Telemetry ingest

The Pico bridge now opens a long-lived TCP connection to the configurator's ingest
port and sends length-prefixed JSON frames:

```text
4-byte big-endian payload length + {"device","seq","ts","data","sig"}
```

The configurator verifies the per-device HMAC signature, persists `last_seq` for
anti-replay protection, forwards accepted messages asynchronously into the
normal state/update/notification pipeline, and writes overflow traffic to
`<DATA_DIR>/ingest-fallback.log`.

> **Note:** the default Pico server port for telemetry is now `9000` to match
> `INGEST_TCP_PORT`. The legacy HTTP webhook has been removed; existing devices
> still configured for the old dashboard/webhook port (`3000`) must be
> reprovisioned or updated over USB with a server/port change and a per-device
> telemetry key.

## HTTP API

The configurator exposes a small JSON API for the dashboard and alert consumers:

- `GET /api/data` returns the current burner state snapshot.
- `GET /api/metrics` returns the last 60 minutes of burner history as JSON samples in memory only when `TELEMETRY_HISTORY_ENABLED=1`.
- Bridge-side notifications are configured on the Pico itself; the configurator does not send outbound alert webhooks.

## mDNS / DNS-SD

The configurator advertises itself as `_viking-bio._tcp` with TXT record
`path=/api/data`. Disable with `MDNS_DISABLE=1` (useful in Docker/CI
environments without multicast).

### Local-only IPv6 addressing

The configurator enumerates its network interfaces at startup and advertises **only**
ULA (`fc00::/7`) and link-local (`fe80::/10`) IPv6 addresses via
`zeroconf.RegisterProxy`.  Global/public IPv6 addresses are excluded so that
Pico devices always discover a local-network address.  If no ULA or link-local
addresses are found the configurator falls back to advertising all addresses and logs
a warning.

The Pico-bridge DNS-SD browser applies the same policy when selecting an
address from an mDNS announcement: it prefers link-local, then ULA, and
ignores packets that carry only global IPv6 addresses.

## Running as a systemd Service

```ini
# /etc/systemd/system/viking-bio-configurator.service
[Unit]
Description=Viking Bio Configurator
After=network.target

[Service]
ExecStart=/usr/local/bin/viking-bio-configurator
Restart=on-failure
User=viking-bio
WorkingDirectory=/opt/viking-bio
EnvironmentFile=/opt/viking-bio/.env
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now viking-bio-configurator
```

## Running as a Windows Service

Using [NSSM](https://nssm.cc/):

```cmd
nssm install VikingBioConfigurator C:\viking-bio\viking-bio-configurator.exe
nssm set VikingBioConfigurator AppDirectory C:\viking-bio
nssm set VikingBioConfigurator AppEnvironmentExtra HTTP_PORT=3000
nssm start VikingBioConfigurator
```

## Data Files

| File | Description |
|---|---|
| `<DATA_DIR>/viking-bio.conf` | Configurator configuration template (created on first run) |
| `<DATA_DIR>/devices.json` | Provisioned device secrets and last accepted sequence numbers |
| `<DATA_DIR>/ingest-fallback.log` | JSONL fallback log when the ingest queue overflows |
