# Viking Bio Networking Architecture

## Runtime boundary

The active system has a strict process and language boundary:

- `pico-bridge/` is firmware written in C for Raspberry Pi Pico W / Pico 2 W.
- `pico-bridge/libvikingbio/` is the shared protocol parser library used by the bridge.
- `configurator/` is the Go configurator runtime and local API host.
- `push-pwa/` is the browser push notification frontend used to register subscriptions and deliver alerts to operators.
- The firmware and the configurator communicate over a signed framed TCP ingest channel.

There is no cgo, no FFI, and no shared-memory boundary between the firmware and the configurator.

## Firmware → Configurator ingest

The firmware sends burner telemetry over a long-lived TCP connection to the
configurator ingest listener (`INGEST_TCP_PORT`, default `9000`).

Current frame payload:

```json
{
  "device": "0123abcd4567ef89",
  "seq": 4294967297,
  "ts": 1234567,
  "sig": "base64-hmac",
  "data": {
  "flame": true,
  "fan": 50,
  "temp": 75,
  "err": 0,
  "valid": true
  }
}
```

The configurator verifies the device-specific HMAC, checks replay ordering via the
persisted sequence number, and updates its local runtime state. Alerts are sent
separately from the Pico to the push app's webhook.

## Memory ownership and lifetime

### Firmware

- The firmware uses static or stack-backed buffers for protocol parsing, ingest
  frames, and Wi-Fi configuration.
- The refactored firmware command path continues to avoid heap allocation.
- Buffer ownership remains local to each module; callers pass output buffers and lengths explicitly.

### Configurator

- The configurator uses normal Go heap allocation and garbage collection.
- The ingest listener decodes frames into Go structs before updating shared state.
- Provisioned device metadata and fallback ingest state are persisted in the data directory with mutex-protected access.

## Notification delivery ownership

- The configurator stores the latest telemetry in memory for its local UI; it does
  not deliver browser push notifications.
- The active browser notification flow is the `push-pwa/` app, which maintains VAPID subscriptions and delivers operator-facing alerts.
- The Pico sends flame/error/stale alerts and heartbeat payloads to its configured
  outbound webhook independently of the TCP telemetry connection.
