# Architecture

## Runtime boundary

The active system has a strict process and language boundary:

- `pico-bridge/` is firmware written in C for Raspberry Pi Pico W / Pico 2 W.
- `pico-bridge/libvikingbio/` is the shared protocol parser library used by the bridge.
- `proxy/` is the Go HTTP server and PWA host.
- The firmware and the proxy communicate over a signed framed TCP ingest channel.

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
- Provisioned device metadata and fallback ingest state are persisted in the data directory with mutex-protected access.

## Notification delivery ownership

- The proxy derives flame, error, and cleaning reminder events from telemetry ingest frames.
- The proxy formats those events into a JSON webhook payload and sends them to `WEBHOOK_URL`.
- The external endpoint owns the final notification delivery and any platform-specific UX.
