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

The local installation uses stock OpenShell 0.1.4 plus the existing pinned
supervisor HTTP/2/gRPC patch. It makes no inference calls. Build its native SDK
qualification with `cargo build --locked --features first-path --bin first-path`.
Pass `--installation /absolute/path/to/veoveo-template-installation`.

The current factory credential path is direct IdP issuance, native OpenShell
client-credentials renewal/injection, and native Lore repository authorization.
Veoveo supplies trusted configuration and assignments. There is no running Veoveo
token service, refresh daemon, manual signing helper or Desktop adapter.

- `lore-preflight`: verify signatures/type/subject/audience, bounded claims/expiry,
  and omitted/unlinked optional scope denial without storing token bytes.
- `factory --image IMAGE`: create the native smoke factory/provider. `--replace`
  explicitly replaces that disposable factory. Provisioning is a setup action,
  not automatic-renewal evidence.
- `lore --repository ID --forbidden ID`: use normal Lore commands through the
  read-only smoke policy; require an existing ungranted repository to fail.
- `boundaries`: require a native opaque reference, reject IdP secrets/JWTs in the
  environment, protect operator paths and deny raw public/issuer/management egress.
- `lore-direct --image IMAGE_ID`: run bounded clone/edit/push, the existing branch
  hook and native protection, then automatic renewal, source withdrawal, binding
  removal/applied detach, termination and gateway recovery. It refuses pre-existing
  workspaces and cleans up only this run's admitted resources, including partial setup.
- `lore-negative`: use trusted HTTP/2 operator probes to compare valid direct grants
  with management bearers.
- `service --image IMAGE --reuse`: check private MCP initialization/discovery/echo,
  missing application credentials and OIDC workspace-nonmember denial through native
  `ForwardTcp`. `service-recreation --image IMAGE` checks scoped deletion and preserves
  a same-named default-workspace sentinel.

The std-only canonical workload is `src/fixtures/lore_session.rs`. Build its test
image from the factory you built (no secrets in the context):

```sh
docker build -f LoreDirect.Dockerfile \
  --build-context factory=docker-image://veoveo/factory:local \
  -t veoveo/lore-direct-fixture:local .
```

It captures the native reference once per process and executes ordinary Lore commands.
Renewal requires at least two native automatic refreshes, unchanged process/reference,
real operations and fresh connections after original expiry plus verifier leeway.
Each launch generates a random 256-bit marker. Every fresh command reply includes
that marker; a persisted readiness file is only a setup hint. Recovery records the
marker from an answered post-restart command and allows native workload replacement.
Earlier PID-only records cannot establish uninterrupted process lifetime.
Every wrong-branch attempt clones the current target branch and commits before pushing.
Protected branches and identities without a factory assignment retain native behavior.
This is a normal-push workflow guard, not complete low-level branch isolation.

`--phase workflow`, `--phase renewal`, `--phase remaining`, and `--phase recovery`
select the same individual gates without rerunning unrelated timers.
A phase report contains only gates actually measured; running `remaining` does not
qualify renewal. The local acceptance record combines completed renewal evidence with
separate remaining-gate evidence, retaining exact images and timestamps. Timed-out runs
are not reported as complete. The recovery fixture uses native OnFailure and an
idempotent workspace-aware entry point; no custom workload-recovery daemon is added.

Native OpenShell intentionally refuses detach while an endpoint references that provider.
The test first proves that precondition, removes the credential binding via native policy,
awaits the active version, then detaches and requires an applied REVOKED receipt.
Stream observations distinguish this combined transition from detach alone. Disabling
only A's IdP client tests unavailable issuance while B operates/renews. Real notification
streams must receive branch events before withdrawal. Measure events afterward, then
require native stopped state and execution rejection. No Lore transport/expiry changes
are permitted to manufacture a passing result.
The run reads the client's previous enabled value and records a restoration only
when it changes that value. Workflow/recovery and failures before mutation do not
contact the IdP during cleanup. Restoration also covers an uncertain PUT outcome.

The focused cleanup regression uses its own workspace and the enabled protected
fixture identity, independent of the lifecycle actors:

```sh
VV_INSTALLATION=/absolute/path/to/veoveo-template-installation \
VV_FACTORY_IMAGE=sha256:... \
cargo test --locked --features first-path --bin first-path \
  direct_partial_setup_cleanup_and_existing_workspace -- --ignored --nocapture
```

It injects failures after workspace, profile, provider and sandbox admission and
preserves a labelled pre-existing workspace. Source and durable data are preserved.
The separate ignored `direct_recovery_preserves_disabled_fixture_client` test uses
the same environment variables. It starts recovery with A disabled, verifies A is
still disabled afterward, then restores only the outer test's own state change.
Build the patched sources using the installation's
[build instructions](../veoveo-template-installation/openshell/README.md#build-and-provision).
Generated reports remain under the installation's `state/openshell/lore-direct/`;
current acceptance is in the [execution checklist](../veoveo-docs/OPENSHELL_HARDCUT_PLAN.md).
Entra/customer providers, interactive human Lore login,
Linux/CUDA, general builds and composition remain separate qualifications.
