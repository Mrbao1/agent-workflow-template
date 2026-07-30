# AI Coding Methodology Mapping

This is the canonical mapping from the user's method to executable project assets.

## Core contract

Humans own direction, boundaries, trade-offs, release and knowledge promotion. AI executes bounded professional work. The thought tree routes; Skills execute; deterministic capabilities validate; knowledge is promoted only after evidence and human approval.

## Design layers

| Method layer | Project authority |
|---|---|
| Thought tree | `workflows/WORKFLOW.md`, `skills/run-ai-coding-pipeline/references/thought-tree.md` |
| Stage index | `state/TASK.json` as authority; `state/STAGE_INDEX.md` as generated readable view |
| Skill | `skills/*/SKILL.md`, loaded only after routing |
| Capability | `capabilities/INDEX.md` and deterministic scripts |
| Knowledge | `knowledge/INDEX.md`; candidates are not rules until approved |
| Acceptance checklist | `workflows/QUALITY_GATES.md`, node artifacts and mode-specific evidence |
| Human | requirement; standard/release solution and final acceptance; production and knowledge-promotion decisions with `user:` sources |
| Installation boundary | immutable `.agent/assets/fresh-state/v1` defaults plus project-owned private state initialized transactionally |
| Policy identity | context `policy_bundle_sha256` (`policy-bundle/v2`) over config, index, template manifest, workflows, the primary Skill with its `scripts/**` and `references/**`, `.agent/scripts/**.py` and `policies/PROJECT_GUARDRAILS.md` (also bound by `project_initialization.guardrails_sha256`) |
| Product identity | `testrun.py` candidate fingerprint over configured scope plus discovered product-owned manifests/source |

## Control-plane boundaries

- Install, update, adopt and migration take managed defaults only from `.agent/assets/fresh-state/v1`. They never use the template checkout's live config, policies, task/context, Agent ledger, runtime, evidence or adapter state as seed authority. A fresh project remains `BOOTSTRAP NOT READY` until `project-init` atomically binds completed guardrail bytes, their readiness digest, initialization receipt and a fresh context.
- Canonical TASK owns stage and risk. `STAGE_INDEX.md` is a readable projection, and templates are routed from approved task type, mode and capabilities. Governance, documentation and maintenance may use the lightweight fast/standard projection; release retains the full release controls.
- Context and product identity are separate. Context binds the active policy bundle and TASK invariant; the product fingerprint binds governed candidate bytes. Neither digest substitutes for the other.
- Host/provider facts require their specific adapters. An implemented local runner does not prove a provider control, platform observation, hardware capability, Token measurement, scheduler action or host compaction.

## Nodes 0–8

Each node has one input, one current artifact, one gate and one root-cause return target. Templates are registered in `templates/manifest.json`.

0. Bootstrap guards, project facts, mode, budgets and adapters.
1. Clarify the business boundary and approve the requirement contract.
2. Structure roles, flows, data, provenance, exceptions and acceptance.
3. Freeze delivery items, exclusions and batches.
4. Approve the smallest viable solution, interfaces, risk and task ownership.
5. Freeze normal, abnormal, boundary, security, performance and regression checks before code.
6. Implement the minimum closed loop, integrate, self-check and clean local runtime; render and bind the mode-selected Node 6 template before advance.
7. Render the mode-selected acceptance template, then accept requirement-to-evidence continuity with mode-appropriate independent review. Review roles reuse candidate-bound receipts and execute only missing or adversarial scenarios.
8. Promote an immutable artifact when requested, verify or roll back, then run the common retrospective/knowledge-candidate closeout.

Fast projects nodes 2–6 into one machine-validated compact receipt containing the bounded change, targeted expectation, execution evidence and cleanup result. Governance, documentation and maintenance use the same lightweight receipt family in standard mode instead of fabricating product-only planning artifacts. Standard product work runs nodes 1–7 with a small task graph and impacted tests. Release runs 0–8, binds node 7 to an implemented live adapter and permits one full-chain execution for an unchanged candidate. Clarification, observable validation, cleanup, context integrity and retrospective are never projected away, and task-type projection never downgrades a release route.

## Return and human rules

- Missing material → 0; unclear need → 1; provenance loss → 2; scope failure → 3; solution/task failure → 4; test gap → 5; implementation defect → 6; delivery failure → 8; production incident → rollback then root-cause node.
- Count failures by stable `issue_id + cause_category`; prose is evidence, not identity. A second failure returns to node 4 only when node 4 is behind the current node; it never jumps forward. Three require an artifact-bound human resolution.
- Requirements always need a human source. Any standard/release technical solution and final acceptance decision binds the exact artifact hash. Fast records solution as `not_applicable` unless it introduces a material direction or architecture decision. Production and knowledge promotion always require separate human decisions. A policy-v1 decision is accepted only through a host-provisioned, OS-protected adapter path; an Agent-created executable outside the repository is still caller-authored and fails closed.

## Cost rule

Record host/provider-measured or explicitly estimated Tokens, context-capsule Tokens, references, Agent cumulative/peak counts, retries, tests, defects, user corrections, wall time and knowledge candidates. The executable total is root usage + reference reservations + reserved/settled child charges; a child charge contains sealed input, inherited fork-window cost, system/tool margin and output margin. `measured` requires an immutable host/provider receipt whose task/model identity, token unit, coverage window/checkpoint, observation time and cumulative/delta semantics cover all activity through the current checkpoint; stale, partial or caller-authored counters remain estimates. Without the usage adapter, report `best-effort-estimate`, the configured error ratio and possible unmetered direct reads. Never present capsule size as a platform context-window measurement. `soft`, `must_compact` and `hard_blocked` are executable routing states, not advisory prose. A budget is a routing/stop condition, never permission to omit correctness or declare a non-terminal task complete.

Testing has its own bounded budget: fast 5 minutes/targeted, standard 15 minutes/impact-based, release 45 minutes/impact plus one full chain. The same candidate, runner, command plan and environment may reuse a verified content-addressed receipt. Do not count infrastructure repair as a code retry, do not let review roles rerun an already proven full suite, and do not auto-restart the whole chain after the attempt budget is exhausted.
