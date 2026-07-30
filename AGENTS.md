<!-- agent-workflow-bootstrap:start -->
# Agent Bootstrap

Before project work, read `.agent/INDEX.md`, `.agent/config.json`, `.agent/state/TASK.json`, `.agent/state/CONTEXT.json`, and `.agent/policies/PROJECT_GUARDRAILS.md`. The guardrails are hash-bound (`project_initialization.guardrails_sha256`) and verified by bootstrap-check. Load `.agent/skills/` only when routed. Before starting the first task, run `python3 .agent/scripts/agentctl.py bootstrap-check`. Without a provider decision adapter, local non-deploy fast/standard tasks may use explicitly recorded current-chat decisions. Projects may explicitly opt local, reversible and non-external release-mode implementation into the same boundary; test, production, deploy, irreversible and external-impact gates remain blocked. Requirements must be clarified before design or implementation; local runtimes must be bounded and cleaned with `.agent/scripts/agentctl.py`.

After every child-agent terminal event, after every compaction, and immediately before any final reply, run `python3 .agent/scripts/workflowctl.py route-resume`. Treat that receipt as the only root-task terminal decision: when `terminal=false`, do not present the root task as complete. Repository state preserves a deterministic resume contract, but only the host scheduler can start a later model turn.
<!-- agent-workflow-bootstrap:end -->
