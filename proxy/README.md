# Viking Bio Proxy (Go)

Go rewrite of the Viking Bio pellet burner proxy server. Receives burner
telemetry from the Pico W bridge and serves the PWA dashboard with fully
proxy-managed Web Push notification support.

## Build

```bash
cd proxy
go build -o viking-bio-proxy ./cmd/proxy
# or
make build
```

## Run

```bash
# Plain HTTP on port 3000
./viking-bio-proxy

# With environment variables
HTTP_PORT=8080 INGEST_TCP_PORT=9000 ./viking-bio-proxy

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
| `ACME_EMAIL` | _(empty)_ | Email for Let's Encrypt registration |
| `ACME_STAGING` | `false` | Use Let's Encrypt staging (`1` or `true`) |
| `ACME_CERT_DIR` | `<data_dir>` | Directory for ACME certificate cache |
| `ACME_HTTP_PORT` | `80` | Port for HTTP-01 challenge server |
| `DDNS_SUBDOMAIN` | _(empty)_ | DuckDNS subdomain (part before `.duckdns.org`) |
| `DDNS_TOKEN` | _(empty)_ | DuckDNS account token |
| `VAPID_CONTACT_EMAIL` | `admin@viking-bio.local` | VAPID contact email |
| `MDNS_NAME` | `Viking Bio` | mDNS/DNS-SD service instance name |
| `MDNS_DISABLE` | `false` | Disable mDNS advertisement (`1` or `true`) |
| `PICO_SERIAL_PORT` | _(empty)_ | Default serial port for `--configure` |
| `DATA_DIR` | `~/.viking-bio-bridge` on Linux, `<exe_dir>/data` otherwise | Directory for VAPID keys and subscriptions |

## .env File

Place a `.env` file in the current working directory before starting the proxy.
Variables already set in the environment take precedence:

```env
HTTP_PORT=3000
INGEST_TCP_PORT=9000
MDNS_NAME=Viking Bio
```

Webhook removed — reprovision devices to use `INGEST_TCP_PORT` (`9000`) and
per-device telemetry keys.

## TLS / ACME

### Manual TLS (Let's Encrypt or custom cert)

```env
TLS_CERT_PATH=/etc/letsencrypt/live/example.com/fullchain.pem
TLS_KEY_PATH=/etc/letsencrypt/live/example.com/privkey.pem
```

### Automatic Let's Encrypt via DuckDNS

Set both `DDNS_SUBDOMAIN` and `DDNS_TOKEN`. Port 80 must be reachable from
the internet (for HTTP-01 challenge). The proxy will:

1. Register/update the DuckDNS record.
2. Obtain a certificate from Let's Encrypt automatically.
3. Serve HTTPS on `HTTP_PORT`.

```env
DDNS_SUBDOMAIN=my-viking-bio
DDNS_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ACME_EMAIL=you@example.com
```

Use `ACME_STAGING=1` while testing to avoid rate limits.

## Device Configurator

Connect the Pico W via USB and run the interactive configurator:

```bash
./viking-bio-proxy --configure
# or specify port directly
./viking-bio-proxy --configure --port /dev/ttyACM0
```

The TUI allows you to:

- View device status (IP, country, server, telemetry state)
- Set WiFi SSID + password
- Set Wi-Fi country code
- Set proxy server address and port
- Provision and sync a per-device telemetry key over USB
- Clear all stored credentials

Provisioning stores the proxy-side device secret in `<DATA_DIR>/devices.json`
and sends the same key to the Pico over USB. The Pico then uses that key to
sign each TCP telemetry frame with HMAC-SHA256.

## Telemetry ingest

The Pico bridge now opens a long-lived TCP connection to the proxy's ingest
port and sends length-prefixed JSON frames:

```text
4-byte big-endian payload length + {"device","seq","ts","data","sig"}
```

The proxy verifies the per-device HMAC signature, persists `last_seq` for
anti-replay protection, forwards accepted messages asynchronously into the
normal state/update/notification pipeline, and writes overflow traffic to
`<DATA_DIR>/ingest-fallback.log`.

> **Note:** the default Pico proxy port for telemetry is now `9000` to match
> `INGEST_TCP_PORT`. The legacy HTTP webhook has been removed; existing devices
> still configured for the old dashboard/webhook port (`3000`) must be
> reprovisioned or updated over USB with a server/port change and a per-device
> telemetry key.

## mDNS / DNS-SD

The proxy advertises itself as `_viking-bio._tcp` with TXT record
`path=/api/data`. Disable with `MDNS_DISABLE=1` (useful in Docker/CI
environments without multicast).

### Local-only IPv6 addressing

The proxy enumerates its network interfaces at startup and advertises **only**
ULA (`fc00::/7`) and link-local (`fe80::/10`) IPv6 addresses via
`zeroconf.RegisterProxy`.  Global/public IPv6 addresses are excluded so that
Pico devices always discover a local-network address.  If no ULA or link-local
addresses are found the proxy falls back to advertising all addresses and logs
a warning.

The Pico-bridge DNS-SD browser applies the same policy when selecting an
address from an mDNS announcement: it prefers link-local, then ULA, and
ignores packets that carry only global IPv6 addresses.

## Running as a systemd Service

```ini
# /etc/systemd/system/viking-bio-proxy.service
[Unit]
Description=Viking Bio Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/viking-bio-proxy
Restart=on-failure
User=viking-bio
WorkingDirectory=/opt/viking-bio
EnvironmentFile=/opt/viking-bio/.env
# Allow binding port 80 for ACME
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now viking-bio-proxy
```

## Running as a Windows Service

Using [NSSM](https://nssm.cc/):

```cmd
nssm install VikingBioProxy C:\viking-bio\viking-bio-proxy.exe
nssm set VikingBioProxy AppDirectory C:\viking-bio
nssm set VikingBioProxy AppEnvironmentExtra HTTP_PORT=3000
nssm start VikingBioProxy
```

## Migration from Node.js Proxy

**Subscriptions:** `<DATA_DIR>/subscriptions.json` format is identical — no migration needed.

**VAPID keys:** The Node.js proxy stored keys in `data/vapid.json` as
`{"publicKey":"...","privateKey":"..."}`. The Go proxy uses two separate files:
`<DATA_DIR>/server-vapid.pub` and `<DATA_DIR>/server-vapid.priv` (raw base64url
strings, no JSON wrapper). Existing browser subscriptions tied to the Node.js
VAPID key **will not receive push notifications** from the new Go server —
users need to re-subscribe once after migration. The subscription records
themselves are forward-compatible.

## Data Files

| File | Description |
|---|---|
| `<DATA_DIR>/subscriptions.json` | Web Push subscriptions (max 32) |
| `<DATA_DIR>/devices.json` | Provisioned device secrets and last accepted sequence numbers |
| `<DATA_DIR>/ingest-fallback.log` | JSONL fallback log when the ingest queue overflows |
| `<DATA_DIR>/server-vapid.pub` | Server VAPID public key (base64url) |
| `<DATA_DIR>/server-vapid.priv` | Server VAPID private key (base64url, mode 0600) |
