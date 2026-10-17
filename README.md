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

The run exits non-zero when a scenario fails. `--keep` leaves the sandboxes, the
PostgreSQL container and the generated policies in place for inspection.

The GitHub push scenario needs a provider created from a token that can write to both
of its repositories, so that only sandbox policy separates them. Import the GitHub
example profile from the OpenShell release under test, create the provider from a token
file, and name it in the run:

```sh
openshell profile import --url https://raw.githubusercontent.com/NVIDIA/OpenShell/v0.1.3/providers/github.yaml --global
GITHUB_TOKEN="$(cat ~/.config/veoveo/github-environments.token)" \
  openshell provider create --name vv-github --type github --credential GITHUB_TOKEN
cargo run --release -- run --github-provider vv-github
```

The scenario pushes a temporary branch to this repository, is refused on `veoveo-core`
and deletes the branch. `--github-push-repository` and `--github-denied-repository`
select other repositories.

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
| `postgres.inspected`, `postgres.tcp` | A sandbox reaches PostgreSQL 18.6 through an endpoint without a protocol, which OpenShell inspects, and through a `tcp` endpoint. Queries answer, a session advisory lock holds for the whole stream and `LISTEN`/`NOTIFY` delivers every write in order |
| `redap.forward` | The Rerun 0.38.1 Catalog SDK lists and reads a dataset through a port forward |
| `redap.native_exposure` | Limit: native Redap clients cannot connect through exposure |
| `redap.grpc_web` | Redap gRPC-Web, used by the Rerun WebViewer, answers through exposure |
| `transfer.outbound`, `transfer.inbound` | Large bodies cross the sandbox boundary byte-exact in both directions |
| `dev.installable` | rustup adds a target, Cargo installs a crate, Git fetches from GitHub and a Cargo Git dependency builds |
| `dev.persistence` | The workspace keeps a verified cache and Cargo output across stop, start and restart-policy replacement |
| `gpu.device` | A GPU sandbox sees the NVIDIA device; skipped on hosts without one |
| `git.provider_push` | With a GitHub provider attached, a sandbox pushes to the one repository its policy allows, is refused on another and holds only a placeholder for the token; skipped without `--github-provider` |
| `peer.exposure` | Limit: a sandbox cannot reach another sandbox's exposed service. The exposure name `default--<sandbox>.openshell.localhost` resolves to the client's own loopback, and a request to `host.openshell.internal` must carry that authority, so the gateway listener's exposure routing is out of reach |
| `peer.forward` | A sandbox reaches another sandbox's service through a port forward on the gateway host at `http://host.openshell.internal:<port>`, with MCP POST, bearer passthrough and SSE streams intact |
| `sandbox.loopback_close` | Limit: inside a sandbox a closed loopback listener keeps completing TCP handshakes, while a port that never listened refuses |
| `provider.bound_secret` | An endpointless provider's secret reaches only the endpoint a sandbox policy binds it to with `credential_binding.provider`: the sandbox holds a placeholder, the bound endpoint receives the value and another allowed endpoint is refused with `credential_endpoint_mismatch` |

Sandboxes receive the provider's token as an `openshell:resolve:` placeholder, and the
proxy substitutes the real value only on requests to the profile's GitHub endpoints. Git
sends the placeholder as the password of a credential helper. The provider grants fetch,
and the sandbox policy adds push for one repository.

A `limit` outcome records a documented limitation of the release. When a later release
removes it, the outcome becomes `limit_lifted`, and the design that worked around it can
be revisited.

## Layout

| Path | Contents |
|---|---|
| `src/bin/probe.rs` | The probe that runs inside sandboxes and on the host |
| `src/harness/` | Sandbox lifecycle, typed policies, host targets, scenarios and the report |
| `Dockerfile`, `image/` | The probe image, a sample crate and the Rerun Catalog SDK probe |
| `providers/` | The endpointless provider profile that `provider.bound_secret` imports and removes on each run |
| `results/<openshell-version>/<os>-<arch>.json` | Committed reports in the `https://veoveo.ai/formats/openshell-qualification` format |

## License

Apache-2.0. See [LICENSE](LICENSE).

## Focused macOS Native Path

The local hard cut uses OpenShell 0.1.4 with the maintained supervisor HTTP/2 patch.
This is a focused first-path qualification, separate from the broad 0.1.3 reports.
It makes no inference calls. Exact source revisions and machine-local image IDs are
recorded in the installation's [component lock](../veoveo-template-installation/openshell/component-lock.json).

Build the native SDK exercise with `cargo build --locked --features first-path --bin
first-path`. Pass `--installation` with the installation repository's absolute path.
The commands are:

- `status`: authorize through verified TLS and generic OIDC.
- `factory --image IMAGE`: create the initial factory/provider; `--replace` replaces
  only the disposable first-path factory after an image rebuild.
- `sync-factory`: update the native Lore provider and policy, waiting for supervisor
  installation. The operator provisions the fifteen-minute read grant separately.
- `lore --repository ID --forbidden ID`: read the assigned repository and reject an
  existing unassigned repository through normal Lore commands.
- `boundaries`: require the native placeholder, reject real-token exposure and
  bootstrap/operator files, and deny raw TCP to public, identity and management
  destinations.
- `service --image IMAGE`: recreate the private fixture and check MCP initialization,
  notification, discovery and echo over authenticated `ForwardTcp`. Missing app
  credentials and an OIDC workspace nonmember must fail. `--reuse` only checks it.
- `service-recreation --image IMAGE`: replace twice while a same-named default
  workspace sentinel exists. Verify its ID is unchanged and remove only a sentinel
  created by this check.

These commands passed on macOS with Docker 29.8.2 and LinuxKit 7.0.14. Native gateway
restart recovered the existing factory and private service; their Lore/MCP checks
then passed. Token rotation installed through native provider receipts without a
factory restart. The six focused supervisor regressions passed, including a
cancellation reproduction that failed before the fix and now resets stalled
upstream calls before and after response headers, beyond the relay slot limit.

The factory runs with network mode `none`, all capabilities dropped, and only the
native channel mount. Source and durable data were preserved during the hard cut.
This evidence does not qualify general builds, environment composition, all real MCP
components, durable infrastructure migration or Linux/CUDA. See the
[execution record](../veoveo-docs/OPENSHELL_HARDCUT_PLAN.md).
