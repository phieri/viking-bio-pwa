# Viking Bio Networking Push

The browser app handles VAPID subscriptions and sends operator push notifications for burner alerts.

## What it does

- generates browser subscriptions for manual operator registration
- stores each subscriber in `storage/subscriptions.yaml`
- receives webhook payloads from the Pico bridge
- sends matching push notifications to the subscribed browsers

## Quick start

```bash
cd push-pwa
composer install
php -S [::]:8000 -t public
```

Open `http://[::1]:8000/` in a browser and generate the client YAML block.
The UI auto-selects English, Swedish, Norwegian, Finnish, Danish, or Icelandic from the
browser locale, and the generated YAML stores the chosen `language` per subscription so
server-generated notifications can be translated for each recipient.

## Subscriptions and device status

The browser generates a subscription snippet locally; it does **not** register it with the
server. Give the snippet privately to the server operator, who pastes it beneath the
`subscriptions:` line in `storage/subscriptions.yaml` (one indented `- endpoint:` item
per browser). Keep this file outside the public web root and restrict its permissions
to the PHP account (for example, `chmod 600 storage/subscriptions.yaml`). Do not
publish browser endpoints or authentication keys. The session token returned by
`config.php` is for sending test alerts, **not** operator authentication; it cannot
safely authorise automatic subscription registration.

The UI fetches `GET /status.php` on load to show the latest persisted heartbeat,
RSSI and LittleFS health after reload. This read-only endpoint returns only
`lastContact`, `lastRssi` and `lastLfsHealth` (null until a heartbeat arrives).
It never serves the state file, device identifiers, subscription details or credentials.
Serve `public/` as the document root, not the repository or `storage/`.

## Webhook flow

Set a shared token in `.env`:

```env
PUSH_WEBHOOK_TOKEN=your-token
```

For HTTPS delivery from the Pico, use the configurator's USB provisioning UI to
load a single PEM or DER CA certificate that signs the push server's TLS
certificate, then configure the `https://` webhook URL and reboot the Pico.
The Pico requires a valid CA chain and matching DNS hostname; without a
provisioned CA, HTTPS fails closed and never falls back to plaintext HTTP.
The Pico has no trusted clock, so **TLS certificate validity dates are not
checked**. Keep the CA narrowly scoped and rotate it as needed. Plain HTTP
may be used only for explicitly insecure testing on an isolated, trusted LAN;
HTTP exposes the token and payload to observers.

The webhook handler validates the token and sends the alert to subscribers
matching the device sender.

## Weekly cleaning reminder

Set a long, random `PUSH_REMINDER_SECRET` in the PHP server environment.
`POST /reminder.php` refuses requests when it is unset and requires
HTTP bearer-token authentication: send the configured secret as the token
in the Authorization header. Never put the secret in a URL or the browser.
Run an external scheduler on the server,
for example a Saturday job after 07:00 in the PHP server's local timezone:

```cron
5 7 * * 6 curl --config /path/to/private/reminder.curl --fail --silent --show-error --max-time 30 -X POST https://your-push-host/reminder.php
```

Put a curl `header` option containing an Authorization bearer token in
`/path/to/private/reminder.curl`, readable only by the scheduler account
(for example, mode 0600). Use the same token as the PHP server's
`PUSH_REMINDER_SECRET`, restrict the cron job and use HTTPS with certificate
verification. The handler checks Saturday after 07:00 and records the weekly
send in `storage/reminder-state.json`; other times are skipped. Do not place
secrets in crontab text or commit them.

See the PHP files in `public/` and `src/` for the send and webhook handlers.
