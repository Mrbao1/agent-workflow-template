# Acceptance Runner Adapter Contract

Select exactly one adapter from the approved solution. A release task fails closed when its selected adapter is unavailable; Docker is not a universal fallback.

Every adapter must emit the same bounded evidence contract:

- frozen source/artifact digest and clean-state token;
- environment identity and resolved non-secret configuration hash;
- scenario IDs with expected/actual outcome and raw evidence hashes;
- input → processing → correction → confirmation → persistence → derived result → reload/re-query where applicable;
- zero residual runtime proof;
- deterministic non-zero exit for blocked or failed mandatory scenarios.

Every implemented adapter exposes three CLI operations: `preflight` may run only bounded capability checks before the integrator starts; `run` is owned exactly once by the integrator and seals its receipt; `verify` is read-only and may only revalidate the current candidate, runner, receipt, preflight and clean-state evidence. Node 7 calls only `verify`. A runner that starts tests, services, Docker cleanup or any other mutation from `verify` is non-conforming.

The machine registry, not this prose list, decides availability. Node 4 records one capability and validates that it has an executable runner and receipt schema.

Adapters:

- `web-docker`: the integrator owns Compose health, real browser/API client and containers/network cleanup once; the bundled live gate seals the report's unique runtime receipt and later verifies it without Docker execution.
- `workflow`: disposable fast/standard/release lifecycle fixtures, governance self-tests, installer lifecycle, two fresh run IDs and zero runtime/Agent residual proof. Implemented by the bundled workflow live gate.
- `api`: local command adapter. Put a bounded service/dependency probe in `preflight_commands`; put the real isolated API client and storage/log assertion entrypoint in `commands`. The integrator runs the exact commands through `testrun.py`; the gate seals and verifies that content-addressed receipt.
- `cli`: local command adapter. Its command entrypoint owns a temporary workspace and records stdin/argv/filesystem assertions and exit codes before returning. Process-group cleanup is enforced by `testrun.py`.
- `ios-simulator`: local command adapter. The runner binds a concrete runtime, UDID and reset-evidence path. The gate—not a project-supplied probe—runs fixed `xcodebuild`/`simctl` capability checks, records the booted-device baseline, validates candidate/run/Case-bound app-data reset evidence, and read-only verifies target shutdown plus zero newly booted simulators. This is simulator-host capability evidence, not physical-device hardware verification. Non-macOS, missing tools/runtime/device, or incomplete reset/cleanup evidence fails closed.

API, CLI and iOS use `acceptance-runner/v4`, the same strict command-record shape as workflow: `execution_profile`, ordered `preflight_commands`, and ordered `commands`. Each record is `{id, argv, timeout_seconds}`. Shells, `-c`, control tokens, duplicate IDs, preflight commands over 30 seconds, and a total preflight budget over 60 seconds are rejected. These are integration adapters, not magic test generators: a project must render real local entrypoints. A missing binary/runtime/test entrypoint is an explicit failed preflight or failed mandatory Case, never a claimed pass or a Docker fallback.

Provider-specific commands live in project adapters. The generic workflow validates the common receipt and never claims an unavailable adapter ran.
