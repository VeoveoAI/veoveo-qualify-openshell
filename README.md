# veoveo-qualify-openshell

This suite checks an OpenShell release against what Veoveo component environments
need before an installation adopts it. It creates sandboxes on the local OpenShell
gateway, drives traffic through every path a component uses and writes one JSON report
per OpenShell release and host under `results/`.

## Requirements

| Host | Requirement |
|---|---|
| macOS on Apple Silicon | Docker Desktop 4.94 or newer, whose Linux kernel enables Landlock; host networking enabled; Enhanced Container Isolation disabled |
| Linux | Docker 28 or newer and a kernel with Landlock ABI 3; the NVIDIA Container Toolkit with a CDI specification for the GPU scenario |
| Both | The OpenShell CLI and a local gateway with the Docker compute driver, started with `OPENSHELL_TELEMETRY_ENABLED=false`; Rust 1.99.0 |

## Run

```sh
cargo run --release -- run
```

The default profile streams each scenario for 15 seconds and moves 512 MiB in the
transfer and persistence scenarios. The endurance profile streams for 30 minutes:

```sh
cargo run --release -- run --stream-seconds 1800 --transfer-mib 4096 --cache-mib 8192
```

The run exits non-zero when a scenario fails. `--keep` leaves the sandboxes and the
SurrealDB container in place for inspection.

## Scenarios

| Scenario | Rule |
|---|---|
| `exposure.http` | Exposed HTTP answers health, MCP POST and form tokens, passes one Bearer header and refuses Basic |
| `exposure.websocket`, `exposure.sse`, `exposure.frames` | Exposed WebSocket, SSE and length-framed streams deliver every message without buffering |
| `exposure.burst` | Fifty simultaneous exposed SSE opens either stream completely or are refused with 502 at setup |
| `exposure.grpc_native` | Limit: exposure relays HTTP/1.1, so native gRPC through exposure fails |
| `forward.grpc` | Native gRPC through a port forward streams in both directions |
| `outbound.http`, `outbound.sse`, `outbound.frames`, `outbound.websocket` | A sandbox reaches an uninspected endpoint on the gateway host with every transport |
| `outbound.grpc`, `outbound.grpc_tcp` | Outbound native gRPC streams on uninspected and `tcp` endpoints |
| `outbound.mcp_policy` | MCP `2026-07-28` inspection allows listed methods and tools and denies a denied tool |
| `outbound.mcp_upgrade` | Limit: endpoints inspected as MCP refuse WebSocket upgrades |
| `outbound.websocket_inspected` | An endpoint inspected as `websocket` upgrades and echoes |
| `outbound.https_rustls` | A rustls HTTPS client trusts the TLS-inspecting proxy |
| `surreal.inspected`, `surreal.tcp` | SurrealDB 3.3.0 queries and LIVE notifications work from a sandbox |
| `redap.forward` | The Rerun 0.38.1 Catalog SDK lists and reads a dataset through a port forward |
| `redap.native_exposure` | Limit: native Redap clients cannot connect through exposure |
| `redap.grpc_web` | Redap gRPC-Web, used by the Rerun WebViewer, answers through exposure |
| `transfer.outbound`, `transfer.inbound` | Large bodies cross the sandbox boundary byte-exact in both directions |
| `dev.installable` | rustup adds a target, Cargo installs a crate, Git fetches from GitHub and a Cargo Git dependency builds |
| `dev.persistence` | The workspace keeps a verified cache and Cargo output across stop, start and restart-policy replacement |
| `gpu.device` | A GPU sandbox sees the NVIDIA device; skipped on hosts without one |

A `limit` outcome records a documented limitation of the release. When a later release
removes it, the outcome becomes `limit_lifted`, and the design that worked around it can
be revisited.

## Layout

| Path | Contents |
|---|---|
| `src/bin/probe.rs` | The probe that runs inside sandboxes and on the host |
| `src/harness/` | Sandbox lifecycle, typed policies, host targets, scenarios and the report |
| `Dockerfile`, `image/` | The probe image, a sample crate and the Rerun Catalog SDK probe |
| `results/<openshell-version>/<os>-<arch>.json` | Committed reports, in the `veoveo.ai/openshell-qualification/v1` format |

## License

Apache-2.0. See [LICENSE](LICENSE).
