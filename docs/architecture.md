# Architecture

## Runtime boundary

The system has a strict process and language boundary:

- `pico-bridge/` is firmware written in C for Raspberry Pi Pico W / Pico 2 W.
- `proxy/` is a Go HTTP server and PWA host.
- The two components communicate over HTTP and JSON only.

There is no cgo, no FFI, and no shared-memory boundary between the firmware and the proxy.

## Firmware → Proxy webhook

The firmware posts burner telemetry to `POST /api/machine-data` with `Content-Type: application/json`.

Current request payload:

```json
{
  "flame": true,
  "fan": 50,
  "temp": 75,
  "err": 0,
  "valid": true
}
```

If `MACHINE_WEBHOOK_AUTH_TOKEN` is configured in the proxy, the firmware includes it in the
`X-Hook-Auth` header.

## Proxy → Firmware response

The proxy responds to the telemetry webhook with JSON including:

- `status`
- `server_time`
- `vapid_public_key`

The firmware uses:

- `server_time` to derive Unix epoch time from Pico uptime
- `vapid_public_key` to cache the proxy-managed VAPID public key locally

The VAPID private key never leaves the proxy.

## Subscription forwarding flow

Browser subscriptions are created against the proxy. The proxy persists subscriptions locally and
best-effort forwards subscribe/unsubscribe requests back to the Pico so the device can keep a small
local cache of forwarded subscriptions.

## Memory ownership and lifetime

### Firmware

- The firmware uses static or stack-backed buffers for protocol parsing, HTTP requests, HTTP
  responses, Wi-Fi configuration, and push state.
- The refactored firmware command path continues to avoid heap allocation.
- Buffer ownership remains local to each module; callers pass output buffers and lengths explicitly.

### Proxy

- The proxy uses normal Go heap allocation and garbage collection.
- HTTP handlers decode request bodies into Go structs and return JSON responses immediately.
- Subscription persistence is file-backed JSON storage guarded by mutexes.

## Push delivery ownership

- The proxy owns VAPID key generation and persistence.
- The proxy returns the public key from `/api/machine-data`.
- The firmware stores only the public key and never signs push requests.
- Web Push delivery is performed by the proxy.
