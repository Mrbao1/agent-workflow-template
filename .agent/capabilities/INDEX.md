# Capability Registry

Capabilities are deterministic, reusable actions. Skills decide when to call them.

| Capability | Entry | Contract |
|---|---|---|
| Task routing/state | `.agent/scripts/agentctl.py` | clarification, budgets, references, environment and runtime invariants |
| Context integrity | `.agent/scripts/contextctl.py` | previous-task checkpoint, bounded replacement capsule, drift detection and fail-closed repair |
| Agent coordination | `.agent/skills/manage-agent-team/scripts/agentledger.py` | platform snapshot, message/file evidence, elapsed liveness, deadline and one redispatch |
| Template routing/rendering | `.agent/scripts/templatectl.py` | contract/mode/capability route, canonical output, manifest/source/output hash chain |
| Stage validation | `.agent/skills/run-ai-coding-pipeline/scripts/validate_stage_index.py` | TASK-derived mode/node/gate/rollback projection |
| Release evidence | `.agent/skills/run-full-chain-acceptance/scripts/` | Web/Docker, workflow, API, CLI and iOS preflight/run/read-only-verify adapters, structural evidence and live fresh-state receipt |
| Test supervision | `.agent/scripts/testrun.py` | fail-closed configured scope plus automatic iOS/Swift Package/Android/Web/API/CLI/common product discovery, bounded isolated process group, hashed output and zero child residual |
| Environment promotion | `.agent/scripts/deliveryctl.py` | locked source/artifact/test/approval/promotion/rollback digest chain |
| Primary Codex context proxy | Codex plugin `pxpipe-context` provider lifecycle | default for new Codex Local sessions, exact-model allowlist, loopback LaunchAgent, whole-request eligible content; `cpx` is diagnostic-only |
| Optional cold-file transport | Codex plugin `pxpipe-context` MCP | disabled-by-default, explicit opt-in, analyze-before-render, newly introduced cold references only, plugin/runtime/source digest binding and native canonical truth |

Do not duplicate capability logic in prose. Add a script only for repeated or fragile operations and pair it with adversarial fixtures.
