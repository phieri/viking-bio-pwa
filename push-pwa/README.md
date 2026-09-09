# Viking Bio Networking Push

The browser app handles VAPID subscriptions and sends operator push notifications for burner alerts.

## What it does

- registers browser subscriptions
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

## Webhook flow

Set a shared token in `.env`:

```env
PUSH_WEBHOOK_TOKEN=your-token
```

Then point the Pico bridge webhook to `https://your-token@your-push-host/webhook.php`.

The webhook handler validates the token and sends the alert to subscribers matching the device sender.

See the PHP files in `public/` and `src/` for the registration, send, and webhook handlers.
