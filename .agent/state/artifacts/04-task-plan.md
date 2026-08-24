# Task Plan

- Mode: release local reversible governance implementation
- Token budget: 96000
- Token source: estimated with durable turn accounting
- Context soft/compact/hard thresholds: soft 57600 compact 72000 hard 86400
- Primary Skill: run-ai-coding-pipeline; new manage-adaptive-workflow will document installed behavior
- Selected templates: structured requirement, deliverables, solution, task plan, acceptance matrix, review policy, workflow acceptance
- Inputs: approved requirement contract, existing template installer, Nova extraction audit, GitHub official API constraints, user correction
- Outputs: blueprint and skill CLIs, knowledge provider evolution templates, tests, docs, install release and GitLab CI
- Files allowed: .agent managed control files, README.md, install.py, tests/run_all.py, .github and .gitlab CI files
- Files forbidden: Nova source tree, credentials, production systems, user-selected stack values in defaults
- Tasks and dependencies: T1 tests; T2 blueprint gate; T3 dynamic Skill lifecycle; T4 knowledge Issue CI; T5 evolution; T6 installer docs; T7 review and full verification
- Tests written before implementation: self_test_adaptive_workflow written before production implementation; lifecycle fixtures extended before installer changes
- Cleanup command: PATH=/usr/sbin:$PATH python3 .agent/scripts/agentctl.py cleanup then assert-clean
- Rollback: git restore changed files before commit, or revert the feature commit after push; installed Skill updates retain superseded lock bundles
