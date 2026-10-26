# Viking Bio Networking Architecture

## Runtime boundary

The active system has a strict process and language boundary:

- `pico-bridge/` is firmware written in C for Raspberry Pi Pico W / Pico 2 W.
- `pico-bridge/libvikingbio/` is the shared protocol parser library used by the bridge.
- `configurator/` is the Go configurator runtime and local API host.
- `push-pwa/` is the browser push notification frontend used to register subscriptions and deliver alerts to operators.
- The firmware and the configurator communicate over a signed framed TCP ingest channel.
- The bridge opens the ingest connection as soon as Wi‑Fi and the server/key are configured (without waiting for serial data) and sends a signed `diag` frame (RSSI, LittleFS health, flame-on time, window) every 60 seconds; the configurator logs it.

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

### Linux-host performance and isolation

The Linux-specific options in this section apply only to the Go configurator host.
The Pico firmware does not run Linux, and the push PWA is a separate browser app.
The current ingest path uses Go networking, accepts frames up to 4096 bytes, and
hands accepted telemetry to a bounded queue. Keep this path as the default: do not
add a native I/O backend unless profiling shows that ingest I/O is a bottleneck.

If that threshold is met, evaluate an isolated Linux-specific backend against the
existing implementation using representative connection counts and frame rates.
Keep frame validation, HMAC verification, replay protection, and state updates in
the existing Go pipeline. Compare latency, CPU use, allocations, and memory
pressure; retain the Go path as a fallback for other operating systems and
unsupported kernels.

An `io_uring` prototype should use a bounded ring and a bounded pool of registered
buffers only when measurements justify them. A typical operation submits a read
SQE for a buffer, waits for and checks its CQE, then submits writes for the
completed byte range, continuing on partial writes. Registered buffers can reduce
some overhead but do not make ordinary reads or writes zero-copy. Do not reuse a
buffer, close a descriptor, or unregister buffers while an operation using them
is outstanding; drain completions before tearing down the ring.

Leave worker placement to the Go scheduler initially. Use bounded queues and
minimize shared mutable state before considering CPU affinity or custom
scheduling. Treat MGLRU as kernel reclaim behavior, not an application feature.
Huge pages and `MADV_HUGEPAGE` are optional hints for large, long-lived regions,
not suitable defaults for small telemetry frames. Use `MADV_SEQUENTIAL` only for
measured sequential access patterns and `MADV_DONTNEED` only after the application
has finished using the affected pages.

For filesystem confinement in a Linux-specific component, anchor relative opens
to a trusted directory descriptor opened with `O_PATH | O_DIRECTORY` and use
`openat2` resolution constraints such as `RESOLVE_BENEATH` and
`RESOLVE_NO_SYMLINKS`. This is not a substitute for process-level service
hardening; use systemd filesystem protections and narrowly scoped writable paths
where deployment permits. Check kernel feature availability and fail safely
rather than silently weakening path constraints.

## Notification delivery ownership

- The configurator stores the latest telemetry in memory for its local UI; it does
  not deliver browser push notifications.
- The active browser notification flow is the `push-pwa/` app, which maintains VAPID subscriptions and delivers operator-facing alerts.
- The Pico sends flame/error/stale alerts and heartbeat payloads to its configured
  outbound webhook independently of the TCP telemetry connection.
