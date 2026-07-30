---
name: run-ai-coding-pipeline
description: Route clarified software work through an adaptive fast, standard, or release workflow with template selection, test-first implementation, mode-specific review, environment delivery, cleanup, context compaction, and root-cause rollback. Use after clarify-task approves a requirement contract, or when an active task needs re-routing.
---

# Run AI Coding Pipeline

1. Read `.agent/INDEX.md`, `config.json`, `state/TASK.json`, the bounded context capsule and project guards. Use the thought tree to choose exactly one `continue`, `return-node`, or `waiting_human` transition before doing stage work. Treat `STAGE_INDEX.md` only as a generated compatibility projection.
2. If requirements are not clarified, stop and use `clarify-task`.
3. Confirm or escalate `fast`, `standard`, or `release` from reversibility, files/systems touched, data/security risk and target environment. `agentctl.py start` defaults (`--complexity tiny --files 1`) route fast. Escalation refuses when the existing requirement approval would fail under the new routing policy; re-approve it with `agentctl.py escalate-mode --reapprove --source user:<decision>`.
4. Select only the templates and stack assets named by the requirement contract. Follow `.agent/workflows/TEMPLATE_ROUTING.md`.
5. Write expected tests and cleanup before implementation. Check `budget_state`; a `must_compact` task needs a verified phase handoff before any new expansion.
6. Execute the active mode:

- Fast: one node-2–6 projection receipt, minimal change, affected checks only, 5-minute test cap, cleanup, compact retrospective. Never render missing standard artifacts to imitate progress.
- Standard: contract, hash-bound solution decision, small task graph, impact-selected tests, 15-minute test cap, selected independent review, human acceptance, cleanup, retrospective.
- Release: full nodes 0–8, impact-selected implementation tests, capability preflight, one candidate-bound full-chain run within 45 minutes, independent receipt-based adversarial/cross review, and environment delivery.

Classify test failures as candidate, test, or infrastructure. Reuse a valid receipt when candidate fingerprint, control scripts, runner, command plan, execution profile, preflight and gate tool are unchanged. Reviewers add at most the configured number of missing or adversarial cases; they never duplicate the full suite. Stop when the mode's one automatic attempt is consumed; never resume from a failed Case automatically after candidate bytes change.

7. A local runtime triggers `manage-local-runtime`; test/production triggers `deliver-environments`; phase growth, TASK hot-state overflow, an expired checkpoint, or active-evidence pressure triggers `manage-task-context`.
8. Before each node transition, re-read canonical TASK and validate that the previous output, current input, gate, failure destination and next action agree. Update only canonical state and the context capsule through an integrity-linked transition; regenerate the stage projection afterward. Delete superseded drafts and temporary evidence.
9. After every child terminal event, every compaction and immediately before every final reply, run `workflowctl.py route-resume`. `terminal=false` forbids saying the root task is complete; an empty Agent ledger and an ending host turn are not terminal. Only the host scheduler can start a later model turn, so preserve the deterministic resume receipt when it cannot continue immediately.
10. Before finalization, compact rollback/failure hot state, preview evidence retention, deep-verify any new archive, and keep referenced acceptance evidence active. Finish only when `route-resume` returns `terminal=true` after the composite finalizer validates workflow, context, templates, delivery, stage, retrospective, a platform-confirmed empty Agent ledger and `agentctl.py assert-clean`.

Detailed node semantics live in [node-contracts.md](references/node-contracts.md); read only the active node.
