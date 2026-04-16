# Architecture

## Runtime boundary

The system has a strict process and language boundary:

- `pico-bridge/` is firmware written in C for Raspberry Pi Pico W / Pico 2 W.
- `proxy/` is a Go HTTP server and PWA host.
- The two components communicate over a signed framed TCP ingest channel.

There is no cgo, no FFI, and no shared-memory boundary between the firmware and the proxy.

## Firmware → Proxy ingest

The firmware sends burner telemetry over a long-lived TCP connection to the
proxy ingest listener (`INGEST_TCP_PORT`, default `9000`).

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

The proxy verifies the device-specific HMAC, checks replay ordering via the
persisted sequence number, and then forwards accepted telemetry into the normal
state/update/notification pipeline.

## Memory ownership and lifetime

### Firmware

- The firmware uses static or stack-backed buffers for protocol parsing, ingest
  frames, and Wi-Fi configuration.
- The refactored firmware command path continues to avoid heap allocation.
- Buffer ownership remains local to each module; callers pass output buffers and lengths explicitly.

### Proxy

- The proxy uses normal Go heap allocation and garbage collection.
- The ingest listener decodes frames into Go structs before updating shared state.
- Subscription persistence is file-backed JSON storage guarded by mutexes.

## Push delivery ownership

- The proxy owns VAPID key generation and persistence.
- The proxy stores browser subscriptions and evaluates notification preferences.
- The proxy derives flame, error, and cleaning reminder events from telemetry ingest frames.
- Web Push delivery is performed by the proxy.
