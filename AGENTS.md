# Agent Instructions

This repository qualifies OpenShell releases for Veoveo component environments. Read
the README before changing a scenario.

## Rules

- Prefer upstream configuration and supported extensions. Maintained VeoveoAI
  security/transport patches are allowed by the accepted architecture. Record
  upstream and patched-build results separately; never hide a limitation in a probe.
- Each scenario states the behavior Veoveo relies on as its rule, and its outcome keeps
  the measurements behind the verdict. Do not loosen a rule to make a release pass.
- Test logic lives in Rust. The Rerun Catalog SDK probe is Python because that SDK is
  the client under test. Do not add shell scripts or a task runner.
- Policies are typed in `src/harness/policy.rs` and written as JSON, which OpenShell
  reads as YAML.
- Pin exact versions and image digests. When changing a pin, verify the latest stable
  release at its source.
- For the local hard cut, run focused checks on macOS and record results. The existing
  Linux installation is out of scope. Run broader scenarios when their affected
  behavior requires it, and qualify the replacement Linux setup separately later.
- Names, identifiers and formats follow the
  [naming and format conventions](https://github.com/VeoveoAI/veoveo-core/blob/main/docs/CONVENTIONS.md).
  Throwaway sandboxes are named `vv-qual-<run>-<role>` within 19 characters.
- Commit small, coherent changes. Commits carry no AI or tool attribution.
- Keep OpenShell telemetry disabled on every gateway that runs this suite.
