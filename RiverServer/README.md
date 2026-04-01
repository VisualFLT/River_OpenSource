# RiverServer (TCP Service Edition)

This directory contains the server-side implementation for **River**, focused on low-latency remote memory-access transport over TCP.
It is designed to pair with `RiverClient` and provide stable, high-throughput request handling under high-frequency read workloads.

## Positioning

- Role: server-side transport and command execution endpoint
- Platform: Windows (Visual Studio / MSVC)
- Core objective: low-latency, concurrent, and recoverable remote service path

## Design Focus

### 1) Session Lifecycle and Handshake

- Stage-based connection flow with bootstrap and data-session transitions.
- Session parameters are negotiated during handshake (for example port, TTL, token).
- Faulted sessions are reclaimed and reset to reconnectable state.

### 2) Request Dispatch and Isolation

- Request/response correlation through `RequestID`.
- Separation of control-plane handling and data-plane handling to reduce interference.
- Optimized execution path for high-frequency read-oriented traffic.

### 3) Concurrency Architecture

- Fixed worker pools to avoid runtime jitter from frequent thread creation.
- Queue-governed request scheduling with bounded in-flight depth.
- Improved stability under bursty and mixed-size traffic patterns.

### 4) Buffering and Send Path Efficiency

- Response buffers and send-frame buffers are reused to reduce allocation churn.
- Reduced intermediate copies on hot paths to lower CPU overhead.
- Tunable burst and batching behavior for throughput scaling without excessive latency regression.

### 5) Reliability and Recovery

- Idle timeout and disconnect detection for stale-session cleanup.
- Explicit state reset on session failure to prevent blocked reconnect paths.
- Defensive handling around handshake and runtime transport errors.

## Build

- Solution: `RiverServerSingleDll.sln`
- Suggested configuration: `x64 / Release`
- Toolchain: Visual Studio 2022 + Windows SDK
- Runtime library: choose based on deployment requirements (for example static `MT`)

## Integration Notes

- This server is intended to run with the River TCP client path.
- Keep protocol/session behavior aligned between `RiverServer` and `RiverClient` when modifying transport logic.
- Validate reconnect, timeout, and high-concurrency read scenarios after any network-layer change.

## Research Scope

RiverServer is part of River’s open engineering study on transport-layer performance and robustness.
Use in legal, authorized, and controlled test environments only.
