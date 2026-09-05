# Viking Bio Push PWA

This small installable PWA is the fourth part of the Viking Bio monorepo. It generates a browser push subscription JSON block for a client, lets the operator copy it manually into a YAML file, and then uses `minishlink/web-push` to send matching alert payloads.

## Purpose

- Build a browser subscription payload with a VAPID keypair
- Add subscribers manually to a YAML file rather than through a server-side save endpoint
- Keep the storage layer read-only so subscription records are maintained by operators, not by the PHP app
- Include a `priority` field for low, normal, and high notifications
- Support multiple sender subscriptions so each browser client only receives alerts for the burner it is interested in; older `device` entries remain accepted as a legacy alias
- Offer an install CTA on iOS Safari via the native Add to Home Screen flow

## Quick start

```bash
cd push-pwa
composer install
php -S 0.0.0.0:8000 -t public
```

Then open `http://localhost:8000/` in a browser and click “Generate client JSON”.

## Manual subscription file

The generated JSON is meant to be pasted into `storage/subscriptions.yaml` as a YAML list of objects. The constructor creates the file with a starter scaffold if it is missing, so operators can replace the sample values by hand:

```yaml
- endpoint: "https://fcm.googleapis.com/..."
  keys:
    p256dh: "..."
    auth: "..."
  sender: "viking-bio-01"
  priority: "normal"
  uiUrl: "http://localhost:8000"
```

## Notes

- The app exposes `public-key.php`, `config.php`, and `send.php` for the VAPID registration flow and test send path.
- `send.php` validates a per-session bearer token issued by `/config.php` so the browser can trigger test messages without embedding a secret in the frontend source.
- `subscribe.php` is intentionally not used; operators add client entries directly to `storage/subscriptions.yaml`.
- Use `sender: "all"` only if a subscriber should receive every burner alert; otherwise set a single device-specific sender ID so the browser only receives messages for that burner.
- Set `PUSH_UI_URL` to the interface that should open when a notification is tapped; it defaults to the app URL and is linked to the web-push webhook flow.
- Subscribers are stored in a YAML file (`storage/subscriptions.yaml`) so each browser endpoint remains easy to inspect and manage.
- The browser service worker listens for `push` events and displays the notification.
- On iPhone and iPad, the UI shows a CTA telling the user to tap the Share button and choose “Add to Home Screen”.
