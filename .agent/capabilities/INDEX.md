# Capability Registry

Capabilities are deterministic, reusable actions. Skills decide when to call them.

| Capability | Entry | Contract |
|---|---|---|
| Task routing/state | `.agent/scripts/agentctl.py` | clarification, budgets, references, environment and runtime invariants |
| Context integrity | `.agent/scripts/contextctl.py` | previous-task checkpoint, bounded replacement capsule, drift detection and fail-closed repair |
| Agent coordination | `.agent/skills/manage-agent-team/scripts/agentledger.py` | platform snapshot, message/file evidence, elapsed liveness, deadline and one redispatch |
| Template routing/rendering | `.agent/scripts/templatectl.py` | contract/mode/capability route, canonical output, manifest/source/output hash chain |
| Stage validation | `.agent/skills/run-ai-coding-pipeline/scripts/validate_stage_index.py` | TASK-derived mode/node/gate/rollback projection |
| Release evidence | `.agent/scripts/blueprintacceptance.py`, `.agent/skills/run-full-chain-acceptance/scripts/` | generic confirmed-blueprint command evidence plus optional legacy Web/Docker/workflow/API/CLI/iOS adapters; structural evidence and live receipts remain mandatory |
| Test supervision | `.agent/scripts/testrun.py` | fail-closed user/project-configured scope, bounded isolated process group, hashed output and zero child residual; legacy platform detectors are compatibility-only |
| Environment promotion | `.agent/scripts/deliveryctl.py` | locked source/artifact/test/approval/promotion/rollback digest chain |
| Adaptive project | `.agent/scripts/blueprintctl.py`, `skillctl.py`, `knowledgectl.py`, `providerctl.py`, `evolutionctl.py` | user-confirmed design before dynamic project Skill selection; GitHub content stays untrusted, pinned and content-only |
| Optional context proxy compatibility | Codex plugin `pxpipe-context` provider lifecycle | disabled by default; explicit user opt-in, exact-model allowlist and provenance are required; native context remains the generic path |
| Optional cold-file transport compatibility | Codex plugin `pxpipe-context` MCP | disabled by default; explicit opt-in, analyze-before-render, newly introduced cold references only, plugin/runtime/source digest binding and native canonical truth |

Do not duplicate capability logic in prose. Add a script only for repeated or fragile operations and pair it with adversarial fixtures.
