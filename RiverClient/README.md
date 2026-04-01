# RiverClient (TCP Network Refactor Edition)

This directory contains a re-engineered `RiverClient` built on top of LeechCore architecture.
The focus is not feature mirroring, but a low-latency remote-read client path with redesigned transport and session handling.

## Background and Positioning

- Baseline source: LeechCore device abstraction and I/O interface model.
- Re-engineering focus: remote transport protocol, connection lifecycle, concurrent scheduling, diagnostics.
- Objective: preserve interface usability while improving real-time behavior and stability for high-frequency reads.

## Main Refactor Areas

### 1) Remote Entry Path Redesign

- Keep LeechCore-style APIs such as `LcRead`, `LcReadScatter`, `LcGetOption`, and `LcCommand`.
- Converge remote-path execution to a TCP transport core with unified session context and request lifecycle.

### 2) Session and Connection Management

- Introduce staged bootstrap/session connection flow.
- Support negotiation of session parameters (port, TTL, token) and explicit state reset.
- Apply explicit state-machine handling for disconnect, timeout, and reconnect scenarios to reduce false-online states.

### 3) Request Concurrency and Multiplexing

- Match requests by `RequestID` and support multiple in-flight operations.
- Separate control traffic and data traffic scheduling to reduce cross-path interference.
- Optimize `READSCATTER` for large discrete-read workloads to improve throughput consistency.

### 4) Transport Path Performance

- Reuse connections and govern send queues to reduce blocking chains.
- Batch read requests and control in-flight depth to balance latency and bandwidth.
- Reduce allocation and memory-copy overhead on hot paths.

### 5) Observability and Diagnostics

- Enhance client-side logs with stage-specific visibility.
- Cover connection and handshake stages.
- Cover API call and read-path stages.
- Cover diagnostics stages for failure triage.
- Improve fault isolation between transport-layer behavior and upper-layer parsing behavior.

## Relationship to Upstream LeechCore

This is not a mirror of upstream and not a one-to-one drop-in replacement.
It is an engineering branch derived from LeechCore architecture with the following strategy:

- Reuse mature acquisition abstractions and baseline interfaces.
- Redesign the remote network layer for River's low-latency target scenario.
- Preserve calling semantics where practical while prioritizing concurrent low-latency read paths.

## Build

- Solution: `LeechCore.sln`
- Suggested configuration: `x64 / Release`
- Toolchain: Visual Studio 2022 + Windows SDK

## Research Directions

- High-performance C/C++ network-client refactoring
- Session state-machine and fault-recovery design
- High-concurrency discrete-read scheduling
- Transport-layer observability engineering

## Notice

This directory is intended for study and research use.
No production or security guarantee is implied.
