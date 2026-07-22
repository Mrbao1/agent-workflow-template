---
name: clarify-task
description: Clarify a request and create an approved requirement contract before planning, design, implementation, testing, or deployment. Use at the start of every new task, whenever goals, scope, success criteria, business rules, data, permissions, environment, authority, or exclusions are uncertain, or when a user changes direction.
---

# Clarify Task

1. Read `.agent/state/TASK.json`; keep phase `clarification` and `requirements_clarified=false`.
2. Inspect existing product facts read-only. Separate user facts, code facts, document facts and AI inference.
3. `agentctl.py start` creates the single current `.agent/state/REQUIREMENT_CONTRACT.md`. While `requirements_clarified=false`, this file is an explicitly mutable, non-authoritative draft: revise it repeatedly without treating any intermediate SHA-256 as a decision. Replace every `PENDING` value with goal, users, success, scope, exclusions, constraints, data/permissions, target environment, acceptance and provenance.
4. Ask only questions whose answers materially change product behavior, scope, risk, environment or acceptance. Batch related questions.
5. Do not produce solution design, UI direction, task decomposition or code while a material question remains.
6. After explicit user approval, run:

```bash
python3 .agent/scripts/agentctl.py approve-requirements \
  --source 'user:<decision>'
```

   This adapterless form is allowed only when TASK selected decision policy v2: local, non-deploy fast/standard work, or release-mode local implementation explicitly enabled by `human_decision_observer.allow_current_chat_local_release`. It stores an explicit lower-assurance current-chat record. Test, production, deploy, irreversible, external-impact and all policy-v1 tasks require `--human-decision-receipt /path/to/provider-receipt.json` plus a healthy provider-owned adapter.
7. Approval succeeds only for the active waiting clarification, with no unresolved fields or material open questions. The command atomically writes the exact final bytes, flips `requirements_clarified=true`, and changes the context binding from `unapproved-draft` to that SHA-256. Local v2 records never claim provider verification. Policy-v1 receipts sign that exact SHA-256; old or tampered receipts fail without changing draft, TASK or CONTEXT. Route to `run-ai-coding-pipeline` only after the command succeeds.

Read [clarification-gate.md](references/clarification-gate.md) only for complex or disputed requirements.
