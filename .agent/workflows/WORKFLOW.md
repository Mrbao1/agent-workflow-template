# Adaptive Delivery Workflow

## Hard entry gate

Every request starts in clarification. Capture purpose, users, success, scope, exclusions, constraints, risks, environment and authority. If any decision changes product direction or acceptance, set `waiting_human`; do not design or implement.

## Thought tree

```text
request
└─ clarified?
   ├─ no → clarification only
   └─ yes → risk/size/environment
      ├─ fast → compact 2–6 receipt + affected checks only (5-minute cap) + cleanup + compact retrospective
      ├─ standard → contract → hash-bound plan → impacted checks (15-minute cap) → review → human acceptance → cleanup + retrospective
      └─ release → nodes 0–8 + impacted checks while building + one candidate-bound full chain + receipt-based independent review (45-minute cap)
```

## Standard nodes

0. Bootstrap guards, state and budget.
1. Clarify and approve the requirement contract.
2. Structure roles, data, flows, errors and provenance.
3. Freeze delivery items, exclusions and batches.
4. Select templates and produce the smallest viable solution/task graph.
5. Define tests and acceptance before implementation.
6. Implement, integrate, self-check and clean local runtime.
7. Run mode-appropriate acceptance; full live gate only in `release`, once per unchanged candidate. Adversarial/cross roles consume its immutable receipt and add targeted attacks instead of duplicating it.
8. When deployment is requested, deliver the tested immutable artifact, verify and rollback if needed. Every mode then records a bounded retrospective; reusable knowledge is promoted only after a human decision.

Fast mode accepts one projection receipt at node 6 instead of fabricating node-2–5 artifacts. Governance, documentation and maintenance may use the same lightweight task projection in standard mode; their route receipt binds the task type and projection, and release mode still keeps full release controls. Standard product work and all release work require a user decision bound to the exact solution and acceptance artifacts, matching the original human-decision gates. Release additionally requires first-principles coverage, distinct identities, the selected adapter and one fresh candidate-bound replay.

Before a full chain, preflight every environment capability under the exact execution authority bound into the dispatch. Classify failures as candidate, test, or infrastructure. The managed test runner reserves and atomically settles one candidate-bound 5/15/45-minute budget across all invocations; a requested timeout may not exceed the mode cap or the remaining reservation pool. One run identity is the sole automatic code attempt. Infrastructure classification comes from runner-observed inability to execute or clean up, never from a caller label, and fails closed without silently reopening code attempts. Node completion validates the existing receipt and must not execute the suite again.

Return to the nearest node that can fix the root cause. Two failures for one stable issue return to node 4 only when that is a backward move; three cumulative repetitions across hot and archived history enter `waiting_human` and block every advance until a human decision is recorded with `workflowctl.py resolve-failure --source user:<decision>`. Keep only the configured recent rollback/failure entries in TASK and validate every content-addressed archive link before using prior counts.

At a phase boundary, renew an otherwise exact expired context without lowering its active-window estimate; do not turn a clock expiry into a human repair loop. Lowering requires the explicit `handoff_written → awaiting_host_compaction → resumed` transition and a `host-compaction-receipt/v1` verified by the configured host adapter. Actual TASK, contract, policy-bundle, integrity, size or budget drift still fails closed. Preview evidence retention separately: referenced evidence remains active, while old unreachable evidence moves only to a deep-verified, restorable archive.

After any compaction or child terminal event and before a final reply, consume `agent-workflow-route/v2`. If a signed host scheduler is unavailable, continuation is `waiting_host_resume` with a cursor-bound recovery command, not an automatic resume or task completion.

A transition, template render, Agent completion, evidence compaction or delivery receipt never substitutes for its owning gate.
