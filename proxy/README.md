# Viking Bio Proxy (Go)

Go rewrite of the Viking Bio pellet burner proxy server. Receives burner
telemetry from the Pico W bridge and serves the PWA dashboard with Web Push
notification support.

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
HTTP_PORT=8080 MACHINE_WEBHOOK_AUTH_TOKEN=mysecret ./viking-bio-proxy

# Using make
make run
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `HTTP_PORT` | `3000` | HTTP/HTTPS listen port |
| `MACHINE_WEBHOOK_AUTH_TOKEN` | _(empty)_ | Webhook auth token (`X-Hook-Auth` header) |
| `TLS_CERT_PATH` | _(empty)_ | Path to TLS certificate (PEM) |
| `TLS_KEY_PATH` | _(empty)_ | Path to TLS private key (PEM) |
| `PICO_BASE_URL` | _(empty)_ | Pico W base URL for subscription forwarding |
| `PICO_FORWARD_TIMEOUT_MS` | `5000` | Pico W forward timeout (ms) |
| `PICO_VAPID_PUBLIC_KEY` | _(empty)_ | VAPID public key from Pico W (`STATUS` command) |
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
| `DATA_DIR` | `<exe_dir>/data` | Directory for VAPID keys and subscriptions |

## .env File

Place a `.env` file next to the binary (or in the working directory). Variables
already set in the environment take precedence:

```env
HTTP_PORT=3000
MACHINE_WEBHOOK_AUTH_TOKEN=changeme
MDNS_NAME=Viking Bio
```

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

- View device status (IP, country, server, VAPID key)
- Set WiFi SSID + password
- Set Wi-Fi country code
- Set proxy server address and port
- Set webhook auth token
- Clear all stored credentials

## mDNS / DNS-SD

The proxy advertises itself as `_viking-bio._tcp` with TXT record
`path=/api/data`. Disable with `MDNS_DISABLE=1` (useful in Docker/CI
environments without multicast).

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

**Subscriptions:** `data/subscriptions.json` format is identical — no migration needed.

**VAPID keys:** The Node.js proxy stored keys in `data/vapid.json` as
`{"publicKey":"...","privateKey":"..."}`. The Go proxy uses two separate files:
`data/server-vapid.pub` and `data/server-vapid.priv` (raw base64url strings,
no JSON wrapper). Existing browser subscriptions tied to the Node.js VAPID key
**will not receive push notifications** from the new Go server — users need to
re-subscribe once after migration. The subscription records themselves are
forward-compatible.

## Data Files

| File | Description |
|---|---|
| `data/subscriptions.json` | Web Push subscriptions (max 32) |
| `data/server-vapid.pub` | Server VAPID public key (base64url) |
| `data/server-vapid.priv` | Server VAPID private key (base64url, mode 0600) |
