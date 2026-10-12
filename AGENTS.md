# Agent Instructions

This repository qualifies OpenShell releases for Veoveo component environments. Read
the README before changing a scenario.

## Rules

- Use OpenShell unmodified. Configure it only through supported settings, and record
  a limitation as a `limit` outcome instead of working around it in the harness.
- Each scenario states the behavior Veoveo relies on as its rule, and its outcome keeps
  the measurements behind the verdict. Do not loosen a rule to make a release pass.
- Test logic lives in Rust. The Rerun Catalog SDK probe is Python because that SDK is
  the client under test. Do not add shell scripts or a task runner.
- Policies are typed in `src/harness/policy.rs` and written as JSON, which OpenShell
  reads as YAML.
- Pin exact versions and image digests. When changing a pin, verify the latest stable
  release at its source.
- Run the suite on macOS and on Linux before committing a change to scenarios, the probe
  image or policies, and commit the resulting reports under `results/`.
- Names, identifiers and formats follow the
  [naming and format conventions](https://github.com/VeoveoAI/veoveo-core/blob/main/docs/CONVENTIONS.md).
  Throwaway sandboxes are named `vv-qual-<run>-<role>` within 19 characters.
- Commit small, coherent changes. Commits carry no AI or tool attribution.
- Keep OpenShell telemetry disabled on every gateway that runs this suite.
