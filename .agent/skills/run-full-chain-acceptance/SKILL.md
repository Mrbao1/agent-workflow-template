---
name: run-full-chain-acceptance
description: Run strict release-mode full-chain acceptance through first-principles decomposition, independent agents, user-role scenarios, adversarial and cross review, clean runtime integration, bounded fix/retest loops, and replayable live evidence. Use only for release mode, production candidates, cross-system or high-risk end-to-end verification, or when the approved requirement explicitly demands every supported scenario; do not use for fast or ordinary standard tasks.
---

# Run Full-Chain Acceptance

Treat acceptance as an evidence-producing release gate, not a summary of implementation work. AI may recommend release; a human owns final approval.

First confirm `.agent/state/TASK.json` has `mode=release` and clarified requirements. Otherwise return to the adaptive pipeline and use targeted validation.

## 1. Freeze the target

1. Read project guards, canonical TASK, authoritative requirements, delivery list, solution, and tests. Read the stage index only when its generated projection disagrees.
2. Verify nodes 1–6 are accepted. Return to the owning node if requirements, scope, assumptions, or test expectations are incomplete.
3. Freeze the tested version with a commit or SHA-256 file fingerprint. The fingerprint must use the fail-closed configured and automatic product discovery in [product-fingerprint.md](references/product-fingerprint.md); do not silently skip a missing configured or manifest-owned source path.
4. Define severity, mandatory scenarios, rollback targets, and the one canonical final report before testing.

Read [first-principles-gate.md](references/first-principles-gate.md) for the node 7 contract and evidence requirements.

## 2. Re-derive the test model

Derive actors, invariants, state transitions, calculations, trust boundaries, failure modes, persistence, and observable outcomes from the user goal. Do not copy the implementation's assumptions into expected results.

Build requirement → delivery item → scenario → evidence traceability. Cover every applicable lane in [scenario-matrix.md](references/scenario-matrix.md). “All scenarios” means all agreed and risk-relevant states, not an unbounded claim.

For release node 7, the cross reviewer—not the root—authors the canonical six-role scenario matrix. Its marker-bound report third line is `SCENARIO_RECEIPT <canonical-json>` using `agent-role-scenario-receipt/v1`; every scenario has exact ID, ordered lens, requirement IDs, assertions, content-addressed evidence and `passed` result. The `agent-node-acceptance/v3` artifact replays that exact array and its canonical JSON digest. Release `agent-node-implementation/v3` likewise names the stable initial implementer dispatch. Validation resolves either that completed member or its one same-model/same-payload ledger redispatch; the resolved terminal member alone owns the final node-6 artifact, changes/checks and candidate-subject attestation, and node 7 records that resolved identity. Fast and standard artifacts also use v3, but omit release-only authority by the mode-specific template contract.

## 3. Assign independent agents

When multi-agent capability exists, use distinct identities:

- Implementer: supplies candidate version and self-check; has no release vote.
- Adversarial reviewer: independently tries to break invariants and does not edit implementation files.
- Cross-reviewer: rebuilds coverage from authoritative requirements, uses different roles and tests adjacent cases.
- Integrator: owns the frozen version, environment, evidence index, and final recommendation.

Do not let one agent impersonate independent technical reviews. Follow [runtime-agent-control.md](references/runtime-agent-control.md) for concurrency, monitoring, interruption, and fix-loop rules.

## 4. Prove the runtime and data flow

1. Select the runner adapter approved at node 4: Web/Docker, API, CLI, iOS simulator, or workflow-governance. Read [runner-adapters.md](references/runner-adapters.md). The adapter registry must mark it implemented and name its executable runner plus receipt schema. A declared-only adapter fails at node 4; do not force every project through Docker.
2. Before dispatching a runtime or integrator Agent, run every declared capability preflight under the exact execution authority that the child will use. A workflow preflight is read-only, each command is at most 30 seconds, and the total is at most 60 seconds; do not use an end-to-end test as a preflight. Bind the passed receipt and execution profile into the handoff before releasing `LEDGER_REGISTERED`. Infrastructure failure stops before Case 1; it does not invalidate the candidate or consume a code retry.
3. Build from a clean context, start services with bounded timeouts, wait for health, record resolved configuration, image IDs, service state, and logs.
4. Use a fingerprinted test runner backed by a real client such as Playwright, an API client, or both. It must emit the `acceptance-client/v1` Case receipt. Validate input → processing → user correction → confirmation → persistence → derived result → reload or re-query.
5. Check UI, API, storage, calculations, logs, console, and network together. Screenshots alone are not proof.
6. Never claim a backend was tested when the product only contains a frontend simulation. Route a real-backend requirement to nodes 1–4.
7. Always stop and clean local services in success and failure paths.

## 5. Run the rounds

Execute in order and bind every round to the selected adapter's live receipt:

1. R0 first-principles decomposition and prewritten expected results.
2. R1 implementer self-check.
3. R2 independent adversarial review consumes the frozen candidate and existing test receipts, then runs only new fault, boundary, recovery, and idempotency attacks.
4. Fix at the root node; rerun the defect, adjacent cases, affected chain, and core smoke. Do not restart unaffected suites.
5. R3 adversarial reviewer verifies the affected receipt set.
6. R4 independent cross-review rebuilds coverage with different roles, consumes the same immutable receipts, and runs only uncovered scenarios.
7. If R4 finds a defect, the implementer fixes it; cross and adversarial reviewers retest only the defect and its affected or adjacent chains.
8. R5 read-only integrator owns the only fresh-state full-chain command execution for the final candidate. Every implemented adapter exposes the same `preflight`, `run`, and `verify` boundary. Workflow, API, CLI and iOS local-command adapters wrap that exact candidate-bound `agent-test-receipt/v3`; Web/Docker wraps a runtime receipt carrying the same canonical candidate fingerprint. Node completion calls only `verify`, which rechecks receipt bytes, current candidate, preflight and the read-only runtime assertion and is forbidden to start tests or cleanup.

Set the mode wall-time and automatic-attempt budget before R0. The default release budget is 45 minutes, one automatic full-chain attempt, and one successful clean replay. A candidate change invalidates only receipts whose bound fingerprint or impact set changed.

Any code or configuration change invalidates affected evidence. Agent completion messages never count as integrated acceptance.

## 6. Control failures

- First occurrence: record cause, evidence, owning node, and fix difference.
- Classify every failure as `candidate`, `test`, or `infrastructure`. Infrastructure failures pause for environment repair and require a fresh preflight; they do not increment the code-failure counter. Do not automatically resume after a candidate change unless a project-specific dependency map proves each reused Case unaffected.
- A runner-observed infrastructure failure is fail-closed but not permanent. After repairing the environment, use `testrun.py --prepare-infrastructure-remediation --next-run-id <32-hex> --next-case <case>` to create a content-addressed request, obtain a provider-signed human decision for gate `test-infrastructure-remediation` bound to that request SHA-256, then apply it with `--apply-infrastructure-remediation --remediation-request <path> --human-decision-source user:<decision> --human-decision-receipt <provider-receipt>`. The authorization is consumed atomically by that exact one next launch; it cannot unlock another Case, be replayed, or trigger an automatic retry. A new infrastructure failure needs a new repair, request, and human decision, while the code-attempt budget remains untouched.
- Same small task fails twice: stop patching and return to node 4.
- Same issue fails three times: stop, set `waiting_human`, and request a decision.
- A stalled agent gets a bounded status check, then interruption and one bounded redispatch; never wait indefinitely.
- A P0/P1/P2 functional or data issue, blocked mandatory case, unconfirmed assumption, unexplained error, or missing independent reviewer blocks release.

## 7. Publish only final evidence

Update the single canonical acceptance report with version, environment, canonical agent IDs, traceability, scenarios, raw evidence hashes, defects, retests, residual risks, and AI recommendation. Follow [report-contract.md](references/report-contract.md). Replace obsolete rounds and delete temporary reports.

Validate the report contract while preparing evidence:

```bash
python3 .agent/skills/run-full-chain-acceptance/scripts/validate_acceptance_report.py <canonical-report>
```

The report validator proves structure and hashes, not that commands ran. Use `--draft` only before the human decision; never treat the structural check as release approval.

Use the bounded runtime helper only when the selected adapter is Web/Docker:

```bash
python3 .agent/skills/run-full-chain-acceptance/scripts/run_acceptance_runtime.py \
  --project-name agent_acceptance_<run-id> --health-url <health-url> --no-cache --web-baseline \
  --client-command <real-client-runner> <runner-args>
```

If the wall-time or automatic-attempt budget expires, stop and route to the owning node. Never turn the entire release chain into an unbounded retry loop, even when each round discovers a differently named issue.

After changing the machine gate, run its disposable positive and adversarial fixtures:

```bash
python3 .agent/skills/run-full-chain-acceptance/scripts/self_test_gate.py
python3 .agent/skills/run-full-chain-acceptance/scripts/self_test_workflow_release_gate.py
```

The Web/Docker adapter no longer repeats a report-backed full chain at Node completion. Create the bounded preflight before the integrator; after its one runtime run is in the report, seal and verify it with:

```bash
python3 .agent/skills/run-full-chain-acceptance/scripts/run_live_release_gate.py \
  preflight --runner .agent/state/artifacts/04-acceptance-runner.json \
  --receipt .agent/state/evidence/web-preflight.json \
  --environment test --authority remote-test --candidate-sha256 <candidate-sha256>

python3 .agent/skills/run-full-chain-acceptance/scripts/run_live_release_gate.py \
  run --runner .agent/state/artifacts/04-acceptance-runner.json \
  --receipt .agent/state/evidence/web-live-gate.json \
  --preflight-receipt .agent/state/evidence/web-preflight.json \
  --report <canonical-report>

python3 .agent/skills/run-full-chain-acceptance/scripts/run_live_release_gate.py \
  verify --runner .agent/state/artifacts/04-acceptance-runner.json \
  --receipt .agent/state/evidence/web-live-gate.json
```

Only the integrator invokes `run`; Node 7 and later validation invoke `verify`. Other adapters must implement the same no-replay verification contract before they can be selected.

API, CLI and iOS use the same commands as the workflow example above: render their adapter template with a real `execution_profile`, bounded preflight records and bounded command records; execute the command records once through `testrun.py`; then call the selected registry runner's `run` with the integrator and preflight receipts. The iOS runner must also render `simulator_target` with a concrete runtime identifier, simulator UDID, and project reset-evidence path. The gate itself runs fixed, bounded `xcrun xcodebuild`/`simctl` probes, binds the preflight booted-device baseline, validates candidate/run/Case-bound app-data reset evidence, and rejects a target that is not shut down or any newly booted simulator. This proves simulator-host capability only; physical-device hardware remains unverified. Missing tools, runtime, simulator, reset evidence, or test entrypoint blocks release.

Before node 7, follow [client-profile.md](references/client-profile.md) to create and fingerprint `.agent/acceptance-client.json`. Its fixed `command` starts `node` or `python3`, points to a test_roots entrypoint, never uses a shell or `-c`, and contains separate `{base_url}` and `{fresh_state_token}` arguments. The client must clear browser/API state for that token and include the token plus zero residual state in its receipt.
