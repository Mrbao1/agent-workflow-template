# Coordination Contract

## Capacity and context

- Reserve one concurrency slot for the root. Mode limits are peak active children.
- Use only configured `gpt-5.6-sol`; record ledger/envelope `fork_turns=0` and invoke the host spawn with `fork_turns="none"`. The sealed payload is the complete child context; never duplicate parent-chat turns. One same-model capacity retry is allowed; then stop.
- Derive objective, shared constraints and acceptance criteria from the current capsule, then seal only the immutable files needed for the bounded child task into `agent-task-payload/v2`; put dispatch controls only in a fresh `agent-handoff-envelope/v3`. The estimate must fit static storage limits, the mode-specific new-dispatch ceiling, and the current mode's remaining budget.
- Atomically reserve the estimate at prepare, consume (without recharging) at register, settle it for every observed terminal child, and release it only for a cancelled unspawned preparation. Release the child only after registration and `LEDGER_REGISTERED`.
- Load child inputs progressively from immutable receipts. Never replay an unbounded transcript.

## Execution profile

- Bind runtime/integrator environment, authority, capabilities, candidate subject, and a fresh passed preflight receipt into the envelope before spawn.
- Preflight Docker, loopback bind, simulator/device, credentials, ports, and writable paths when applicable. Run it under the same authority the child will use.
- Treat environment/permission failures as `infrastructure`: stop before Case 1, preserve evidence, do not consume a code retry, and resume at the failed capability or Case after a fresh preflight.

## Independent review

- Keep implementer, adversarial, cross, and integrator identities distinct and formal roles sequential.
- Bind one immutable subject and review-chain ID: adversarial PASS → cross PASS → integrator PASS. Every successor binds the exact predecessor report digest.
- Let adversarial and cross reviewers consume verified receipts. They must not duplicate an unchanged full suite.
- Fail closed on reviewer-targeted execution until every Case is bound to its dispatch envelope, controlled runner receipt, and Agent identity. Under the current v2 attestation, require `targeted_cases: []`; a self-reported name never proves execution.
- Require cross to publish six ordered role scenarios with content-addressed evidence.
- Require integrator to reproduce every current accepted Node 6 check exactly once through the ledger-managed runner. One candidate/environment/command-plan receipt is sufficient; a second same-environment full replay is rejected.

## Supervision and retry

- Use one-shot `watchdog-plan`; the host performs real platform observations at bounded intervals. Do not start a daemon.
- Record missed polling as supervisor debt. Interrupt only for deadline or a proven unchanged progress gap beyond the stall timeout. Close a platform-lost child with `finish --lost` only after three consecutive missing platform observations or a bound human decision, each against a fresh absence-proving snapshot.
- Redispatch once at most with a new ID/envelope and the same model, payload, root task, subject, chain, and predecessor. Preserve failed attempts.
- Stop the automatic chain when the mode's wall-time or attempt budget is exhausted.

## Completion

- Accept only envelope-allowed result bytes, a canonical reviewer verdict/attestation, a matching terminal platform observation, and the exact final-message digest.
- Reuse a test receipt only when candidate fingerprint, runner, command plan, environment profile, and gate tool still match.
- Abort unfinished replay authority on unsuccessful integrator termination. Never reinterpret infrastructure failure as candidate failure or root completion.
- Require zero residual runtime and a fresh platform-empty observation before final integration. `route-resume` is the only root terminal decision.
- Trust the ledger only through its append hash chain; a legacy chainless ledger upgrades once on save, and any later break fails closed. `init --archive-existing` refuses while members are active unless `--force --force-reason <why> --source user:<message>` binds a human decision.
