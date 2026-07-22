# Agent Workflow Index

This is the only orchestration entry. Load nothing else until routing requires it.

## Bootstrap

Installation and project readiness are separate. Managed defaults come only from `.agent/assets/fresh-state/v1`; live template-private config, policy, task/context, ledger, runtime, evidence and adapter state are never seed authority. A new project remains `BOOTSTRAP NOT READY` until `project-init` atomically binds completed project guardrails, readiness and fresh context.

1. Read `config.json`, `state/TASK.json` and the bounded `state/CONTEXT.json` capsule. Confirm its `policy_bundle_sha256` still binds config, this index, every workflow rule, the template manifest and the active Skill.
2. If `requirements_clarified` is false, load only `.agent/skills/clarify-task/SKILL.md` and stop before design or implementation.
   A missing human-decision adapter does not block entering clarification. Local non-deploy fast/standard tasks may use explicit current-chat decisions. A project may explicitly opt local, reversible and non-external release-mode implementation into the same boundary; test, production, deploy, irreversible and external-impact routes remain blocked.
3. Read the bounded context capsule and thought tree; choose exactly one next transition from canonical TASK: continue the current node, return to the nearest root-cause node, or stop for a human decision. Then select or escalate `fast`, `standard`, or `release`. Read `STAGE_INDEX.md` only to diagnose a projection mismatch.
4. Load the primary Skill plus at most the configured number of references for that transition.
5. Check the unified total budget, context checkpoint, workflow hot-state bounds and evidence-retention status before loading references, routing templates, spawning Agents or advancing a node. The total includes root usage, references and every reserved/settled child charge; capsule size remains a separate active-window estimate. `must_compact` requires a phase handoff; `hard_blocked` permits only cleanup, splitting or a human decision. An exact expired checkpoint may renew without lowering its estimate; a lower estimate requires a host-verified compaction receipt.
6. If the Agent ledger contains active members, reconcile it with a fresh platform snapshot verified through the configured platform adapter before spawning or waiting. With no adapter, platform state is unverified and the child orchestration gate fails closed. Never trust a stale or caller-only ledger as proof of liveness.
7. Before finishing any local validation, run `python3 .agent/scripts/agentctl.py cleanup` and `assert-clean`.
8. After every child-Agent terminal event, after every compaction, and immediately before every final reply, run `python3 .agent/scripts/workflowctl.py route-resume`. Consume exactly one `agent-workflow-route/v2` receipt. If `terminal=false`, the root task is not complete. Without a signed scheduler adapter, continuation is `waiting_host_resume` and must use the receipt's cursor-bound recovery command; do not claim an automatic next turn.

## Mode router

| Mode | Use for | Default workflow | Independent agents |
|---|---|---|---|
| `fast` | Copy, constants, tiny isolated fixes | clarify → one compact node-2–6 receipt → affected checks (5 min) → cleanup → compact retrospective | 0 |
| `standard` | Normal features, bugs, refactors | clarify → contract → hash-bound solution → impact-selected checks (15 min) → selected review → human acceptance → cleanup → retrospective | 0–1 only when risk or the user requires independent review |
| `release` | Cross-system, data, security, migration, deployment | full nodes 0–8, capability preflight, one candidate-bound full chain (45 min), receipt-based review | at most 2 active children; formal roles stay serial |

Escalate one level when scope, reversibility, data risk, environment impact, or uncertainty exceeds the current mode. Never downgrade to avoid a failed gate.

Governance, documentation and maintenance may use a task-type-aware lightweight projection in fast/standard mode. The route receipt binds this projection; release remains full even when its route identity records `lightweight-release`.

## On-demand Skills

- Requirements unclear: `.agent/skills/clarify-task/SKILL.md`
- Context is growing or a phase ends: `.agent/skills/manage-task-context/SKILL.md`
- Two or more sub-agents or independent review roles: `.agent/skills/manage-agent-team/SKILL.md`
- Local server, Docker, browser, simulator, or worker: `.agent/skills/manage-local-runtime/SKILL.md`
- Test/production delivery: `.agent/skills/deliver-environments/SKILL.md`
- Release-level acceptance only: `.agent/skills/run-full-chain-acceptance/SKILL.md`
- General routing: `.agent/skills/run-ai-coding-pipeline/SKILL.md`

Load UI, Playwright, Figma, backend, iOS, Docker, or CI/CD assets only when the task contract selects that capability.

Workflow invariants and known failure patterns are defined in `workflows/WORKFLOW.md` and `workflows/QUALITY_GATES.md`; environment behavior is defined in `workflows/ENVIRONMENTS.md`. A release acceptance adapter must be marked implemented and produce a live receipt at node 7; a declared-only adapter fails at node 4. Implemented does not mean the current host/provider/hardware passed preflight.

## Canonical state

- Active task: `state/TASK.json`
- Integrity-linked context capsule: `state/CONTEXT.json`
- Runtime registry: `state/runtime.json`
- Bounded foreground review-tool leases: `state/tool-leases.json`
- Live child-agent ledger: `state/agents.json`
- Digest-bound delivery receipts: `state/delivery.json`
- Recoverable evidence archive index: `state/EVIDENCE_INDEX.json`
- Historical stage compatibility: `state/STAGE_INDEX.md`
- Reusable capability registry: `capabilities/INDEX.md`
- Human-promoted knowledge: `knowledge/INDEX.md`
- Project-only rules: `policies/PROJECT_GUARDRAILS.md`

Use `workflowctl.py compact-state` to move superseded rollback/failure history out of TASK, and use `evidencectl.py compact --dry-run` before archiving old unreachable evidence. Never delete referenced evidence or bypass deep archive verification. Do not create parallel plans, round reports, chat transcripts, or duplicate indexes.

The separately installed `pxpipe-context` plugin has two distinct surfaces. Its primary surface is a user-default provider/proxy lifecycle: a loopback LaunchAgent plus user-level `model_provider = "pxpipe"` and `[model_providers.pxpipe]` make future Codex Local conversations pass eligible whole-request context through pxpipe without invoking `cpx`. It cannot change the current chat; `cpx` remains a one-session diagnostic override. The project capability `context-transport-pxpipe` continues to route only the optional cold-file MCP profile; it is never a memory authority and does not prove that a provider request used pxpipe. Keep TASK, CONTEXT, decisions, paths, IDs, hashes, amounts and receipts as native text. Optional MCP availability does not mean installed, loaded, enabled or approved, and remains disabled until explicit opt-in plus a valid analyze receipt and rendered v2 profile.
