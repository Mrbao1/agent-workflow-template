# Agent Workflow Index

This is the only orchestration entry. Load nothing else until routing requires it.

## Bootstrap

Installation and project readiness are separate. Managed defaults come only from `.agent/assets/fresh-state/v1`; live template-private config, policy, task/context, ledger, runtime, evidence and adapter state are never seed authority. A new project remains `BOOTSTRAP NOT READY` until `project-init` atomically binds completed project guardrails, readiness and fresh context.

1. Read `config.json`, `state/TASK.json` and the bounded `state/CONTEXT.json` capsule. Confirm its `policy_bundle_sha256` (`policy-bundle/v2`, recorded as `policy_bundle_version`) still binds `config.json`, this index, `templates/manifest.json`, every `workflows/*.md` rule, the primary Skill's `SKILL.md` plus its `scripts/**` and `references/**`, `.agent/scripts/**.py` and `policies/PROJECT_GUARDRAILS.md`; a v1 capsule is upgraded once on the next sync. The same guardrails bytes are independently bound by `project_initialization.guardrails_sha256`, verified by `bootstrap-check`. At the start of every real host/model turn, run `contextctl.py account-turn --turn-id <caller-stable-host-turn-id>` exactly once; a retry reuses the same ID and is a no-op. A turn observed after completion preserves the exact `complete-task` transition as durable checkpoint provenance, so accounting cannot reopen an accepted task. Without signed host-compaction/usage adapters this integrity binding is a procedural constraint — a self-hash any Agent can recompute — not a machine-enforced one; with those adapters configured, the transitions that depend on them require receipts covering the capsule hash.
2. If `requirements_clarified` is false, load only `.agent/skills/clarify-task/SKILL.md` and stop before design or implementation.
   A missing human-decision adapter does not block entering clarification. Local non-deploy fast/standard tasks may use explicit current-chat decisions. A project may explicitly opt local, reversible and non-external release-mode implementation into the same boundary; test, production, deploy, irreversible and external-impact routes remain blocked.
3. Project architecture and technology are user decisions, not template defaults. Before selecting any project/domain Skill, initialize `.agent/project/BLUEPRINT.json`, collect the user's design, and bind explicit confirmation with `blueprintctl.py`; repository observations remain non-authoritative suggestions. Load `.agent/skills/manage-adaptive-workflow/SKILL.md` for this route.
4. Read the bounded context capsule and thought tree; choose exactly one next transition from canonical TASK: continue the current node, return to the nearest root-cause node, or stop for a human decision. Then select or escalate `fast`, `standard`, or `release`. Read `STAGE_INDEX.md` only to diagnose a projection mismatch.
5. Load the primary Skill plus at most the configured number of references for that transition.
6. Check the unified total budget, context checkpoint, workflow hot-state bounds and evidence-retention status before loading references, routing templates, spawning Agents or advancing a node. The total includes root usage, references and every reserved/settled child charge; capsule size remains a separate active-window estimate. `TASK.budget_state` is the cumulative/base account, while `CONTEXT.resume.budget_state`, `agentctl status` and `route-resume` expose the checkpoint-effective unified state; do not compare those fields as though they were the same account. Cumulative provider usage receipts update only the cumulative-cost account; they never replace active-window growth. Reference reservations removed from TASK are settled into the active-window estimate and cannot disappear at unload or task rollover. `must_compact` requires a phase handoff and forbids new scope; an accepted task cannot roll into a same-budget requirement when the first new checkpoint would still be `must_compact` or `hard_blocked`. In that case establish a verified host compaction or select an authorized higher-budget mode before `start`. `hard_blocked` permits only cleanup, escalation within the mode ceiling, rollback/return, or a human decision. A return-node receipt opens one bounded repair lane over its existing-route `[to, from]` node interval (`reroute-existing`, routed artifact rendering, managed checks and finishing those nodes); adjacent hot return receipts merge into one contiguous interval but gaps never widen the authorization. It cannot add capabilities, references or Agents, and the three-strike ledger closes it on the third recurrence. A second late failure normally expands repair to node 4, but `standard + lightweight` expands to node 2 because that projection has no node-4 solution artifact and rebuilds nodes 2–6 through its node-6 implementation receipt. The other automatic exception is a task already in `ready_to_complete` with nodes 0–7 accepted: it may render its routed retrospective and commit `complete`, but may not route templates, implement, load references or expand scope. An exact expired checkpoint may renew without lowering its estimate; neither repair nor a phase handoff may lower it. A lower estimate requires `contextctl.py sync --request-host-compaction` (only with a configured host-compaction adapter and a prior verified handoff artifact) followed by a host-verified compaction receipt; a pending wait is abandoned with `contextctl.py abort-host-compaction --source user:<text>`, and a leftover transition journal is resolved with `contextctl.py journal [--restore|--discard]`. `capsule_reduction_tokens` is only the serialized handoff-size difference; `tokens_removed` remains zero unless a signed host receipt proves real active-window removal.
7. If the Agent ledger contains active members, reconcile it with a fresh platform snapshot before spawning or waiting. Release mode fails closed without `agent_control.platform_observer.signed_adapter`; fast/standard accept caller-authored snapshots, which are orchestrator coordination assertions, not platform proof, so the node-7 human comparison against the real tool transcript is mandatory there. Never trust a stale or caller-only ledger as proof of liveness.
8. Before finishing any local validation, run `python3 .agent/scripts/agentctl.py cleanup` and `assert-clean`.
9. After every child-Agent terminal event, after every compaction, and immediately before every final reply, run `python3 .agent/scripts/workflowctl.py route-resume`. Consume exactly one `agent-workflow-route/v2` receipt. If `terminal=false`, the root task is not complete. Scheduler receipts are replay-protected and cursor-bound, and `terminal=true` additionally binds an empty Agent ledger and a clean runtime. Without a signed scheduler adapter, continuation is `waiting_host_resume` and must use the receipt's cursor-bound recovery command, which also covers a leftover transition journal; do not claim an automatic next turn.

## Mode router

| Mode | Use for | Default workflow | Independent agents |
|---|---|---|---|
| `fast` | Copy, constants, tiny isolated fixes | clarify → one compact node-2–6 receipt → affected checks (5 min) → cleanup → compact retrospective | 0 |
| `standard` | Normal features, bugs, refactors | clarify → contract → hash-bound solution → impact-selected checks (15 min) → selected review → human acceptance → cleanup → retrospective | 0–1 only when risk or the user requires independent review |
| `release` | Cross-system, data, security, migration, deployment | full nodes 0–8, capability preflight, one candidate-bound full chain (45 min), receipt-based review | at most 2 active children; formal roles stay serial |

Escalate one level when scope, reversibility, data risk, environment impact, or uncertainty exceeds the current mode. Never downgrade to avoid a failed gate. Only the file count, a "migration" substring in changed paths, the path prefixes `.github/workflows/`, `deploy/`, `production/` and `infra/`, and test/production/deploy routes are mechanically enforced; the remaining risk flags are declarative. Splitting work into small fast tasks is not mechanically prevented — the control point is that every split requires fresh requirement approval.

Governance, documentation and maintenance may use a task-type-aware lightweight projection in fast/standard mode. The route receipt binds this projection; release remains full even when its route identity records `lightweight-release`.

## On-demand Skills

- Requirements unclear: `.agent/skills/clarify-task/SKILL.md`
- Context is growing or a phase ends: `.agent/skills/manage-task-context/SKILL.md`
- Two or more sub-agents or independent review roles: `.agent/skills/manage-agent-team/SKILL.md`
- Local server, Docker, browser, simulator, or worker: `.agent/skills/manage-local-runtime/SKILL.md`
- Test/production delivery: `.agent/skills/deliver-environments/SKILL.md`
- Release-level acceptance only: `.agent/skills/run-full-chain-acceptance/SKILL.md`
- General routing: `.agent/skills/run-ai-coding-pipeline/SKILL.md`
- User-designed project blueprint, dynamic GitHub Skill selection, knowledge/provider templates and evolution: `.agent/skills/manage-adaptive-workflow/SKILL.md`

Do not infer or preload UI, framework, language, backend, mobile, infrastructure, testing, provider, or CI technology. First bind the user's blueprint, then verify and load only the active project Skills selected from it. Existing built-in domain assets are compatibility examples and never defaults.

Workflow invariants and known failure patterns are defined in `workflows/WORKFLOW.md` and `workflows/QUALITY_GATES.md`; environment behavior is defined in `workflows/ENVIRONMENTS.md`. Release acceptance requires either an implemented legacy adapter with a live node-7 receipt or a confirmed blueprint whose stable acceptance IDs have complete executable command coverage; a declared-only legacy adapter fails at node 4. Implemented does not mean the current host/provider/hardware passed preflight.

## Canonical state

- Active task: `state/TASK.json`
- Integrity-linked context capsule: `state/CONTEXT.json`
- Runtime registry: `state/runtime.json`
- Bounded foreground review-tool leases: `state/tool-leases.json`
- Live child-agent ledger: `state/agents.json`
- Digest-bound delivery receipts: `state/delivery.json` (an epoch chain spans resets; `deliveryctl.py init` archives the prior state before resetting)
- Recoverable evidence archive index: `state/EVIDENCE_INDEX.json` (task archives are `agent-task-archive/v2`: referenced evidence is kept as digests, v2 payloads are not textually scanned, and each archive embeds `delivery.json`)
- Historical stage compatibility: `state/STAGE_INDEX.md`
- Reusable capability registry: `capabilities/INDEX.md`
- User-confirmed project design: `project/BLUEPRINT.json`
- Dynamic Skill lock/CAS/active set: `project/skills.lock.json`, `project/skill-cas/`, `project/skills/`
- Human-promoted and owner-mapped knowledge: `knowledge/INDEX.md`, `knowledge/registry.json`, `knowledge/catalog.json`
- Retrospective knowledge candidates awaiting human promotion: `state/knowledge-pending.json` (promote with `agentctl.py promote-knowledge` into `knowledge/INDEX.md` or `capabilities/INDEX.md`)
- Project-only rules: `policies/PROJECT_GUARDRAILS.md`

Use `workflowctl.py compact-state` to move superseded rollback/failure history out of TASK, and use `evidencectl.py compact --dry-run` before archiving old unreachable evidence. `evidencectl.py migrate-task-archives` upgrades legacy task-archive chains to v2, `compact --include-task-history` deep-archives task history only behind a human decision, and `compact --gc-orphans` removes unindexed archive files. Never delete referenced evidence or bypass deep archive verification. Do not create parallel plans, round reports, chat transcripts, or duplicate indexes.

The separately installed `pxpipe-context` plugin has two distinct surfaces. Its primary surface is a user-default provider/proxy lifecycle: a loopback LaunchAgent plus user-level `model_provider = "pxpipe"` and `[model_providers.pxpipe]` make future Codex Local conversations pass eligible whole-request context through pxpipe without invoking `cpx`. It cannot change the current chat; `cpx` remains a one-session diagnostic override. The project capability `context-transport-pxpipe` continues to route only the optional cold-file MCP profile; it is never a memory authority and does not prove that a provider request used pxpipe. Keep TASK, CONTEXT, decisions, paths, IDs, hashes, amounts and receipts as native text. Optional MCP availability does not mean installed, loaded, enabled or approved, and remains disabled until explicit opt-in plus a valid analyze receipt and rendered v2 profile.
