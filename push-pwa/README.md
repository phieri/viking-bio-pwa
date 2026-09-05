# Viking Bio Push PWA

This small installable PWA is the fourth part of the Viking Bio monorepo. It lets a user opt in to browser push notifications, persists the Web Push subscription on the PHP backend, and uses the `minishlink/web-push` library to send test and real alert payloads.

## Purpose

- Register a browser subscription with a VAPID keypair
- Persist subscriptions on the server side
- Send push notifications to all registered devices
- Offer an install CTA on iOS Safari via the native Add to Home Screen flow

## Quick start

```bash
cd push-pwa
composer install
php -S 0.0.0.0:8000 -t public
```

Then open `http://localhost:8000/` in a browser.

## Notes

- The app exposes `public-key.php`, `subscribe.php`, and `send.php` for the VAPID registration flow.
- `send.php` validates a per-session bearer token issued by `/config.php` so the browser can trigger test messages without embedding a secret in the frontend source.
- Set `PUSH_UI_URL` to the interface that should open when a notification is tapped; it defaults to the app URL and is linked to the web-push webhook flow.
- Subscriptions are stored in a flat YAML file (`storage/subscriptions.yml`) so each browser endpoint remains easy to inspect and manage.
- The browser service worker listens for `push` events and displays the notification.
- On iPhone and iPad, the UI shows a CTA telling the user to tap the Share button and choose “Add to Home Screen”.
