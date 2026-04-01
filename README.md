# River

*A river of memory data, flowing through low-latency channels.*

River is an open-source engineering study focused on **network-path refactoring for high-frequency memory read workloads**, including TCP-based `RiverServer` and `RiverClient`.
The project emphasizes low latency, concurrency design, fault recovery, and observability over feature stacking.

## Project Status

- Type: learning and research-oriented open-source project
- Platform: Windows (Visual Studio solutions)
- Primary language: C/C++
- Current focus: TCP network layer and remote read-path optimization

## Core Capabilities

- Low-latency transport path: control plane and data plane separation to reduce cross-interference.
- Concurrent request processing: multiplexing + worker pools + queue governance for high request rates.
- READSCATTER optimization: batched and windowed scatter-read scheduling to reduce overhead and wait time.
- Connection robustness: session timeout reclamation, reconnection, and state reset for long-run stability.
- Observability: layered logging (link, API, diagnostics) for fast root-cause isolation.

## Network Layer Overview

### 1) Session Establishment and Authentication

- Bootstrap and session channels are established in stages.
- Handshake negotiates session parameters (port, TTL, token), then switches to the data channel.
- Session faults trigger state reclamation and re-enter reconnectable state.

### 2) Request/Response Model

- Requests carry `RequestID`; responses are matched by `RequestID` for concurrent in-flight handling.
- Control commands and data reads are scheduled separately to avoid mutual blocking.
- `READSCATTER` traffic uses batching to reduce protocol overhead under small-packet pressure.

### 3) Concurrency and Buffer Strategy

- Fixed server worker pools avoid jitter from frequent thread creation.
- Send paths use queueing and buffer reuse to reduce repeated allocation and intermediate copies.
- In-flight depth controls tune the balance between throughput and latency.

## Repository Layout

- `RiverServer/`: server-side solutions and core implementation
- `RiverClient/`: client-side solutions and core implementation

## Build Guide

### Requirements

- Visual Studio 2022 (MSVC toolchain)
- Windows SDK

### Solution Entry Points

- Server: `RiverServer/RiverServerSingleDll.sln`
- Client: `RiverClient/LeechCore.sln`

### Recommended Configuration

- `x64`
- `Release`
- Runtime library based on deployment needs (for example static `MT`)

## Upstream Relationship

River preserves reusable acquisition abstractions from upstream and performs a systematic redesign of the network layer.
For implementation boundaries and refactor details, see [RiverClient/README.md](./RiverClient/README.md).

## Roadmap

1. Further reduce tail latency under extreme load.
2. Complete protocol documentation and reproducible performance baselines.
3. Strengthen cross-version compatibility and fault-injection testing.
4. Continue removing legacy paths to lower maintenance complexity.

## Compliance Notice

This repository is intended for systems engineering, protocol optimization, and performance research.
Use only in legal, authorized, and controlled environments.
