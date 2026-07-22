---
name: manage-agent-team
description: Coordinate bounded multi-agent implementation, role-play acceptance, adversarial review, cross-review, progress monitoring, interruption, and one-time redispatch with a live registry. Use whenever two or more sub-agents are requested or a task needs independent implementer, reviewer, integrator, or user-role validation.
---

# Manage Agent Team

Use the ledger as the machine authority. Read [coordination-contract.md](references/coordination-contract.md) only when dispatching or recovering child Agents.

## Dispatch

1. Read `.agent/config.json`, `.agent/state/TASK.json`, and the current context capsule. Before the first dispatch of each task, obtain one fresh provider/platform empty snapshot and run `agentledger.py init --platform-snapshot <snapshot>` (add `--archive-existing` only for an explicitly closed prior ledger). This is the mechanical proof that no untracked old child is still consuming capacity. Reserve one root slot and obey the lower of the platform and mode child limits.
2. Split tasks by exclusive file ownership, bounded inputs/outputs, forbidden files, evidence, deadline, and acceptance. Keep implementer, adversarial, cross, and integrator identities distinct.
3. Create `agent-task-payload-draft/v1`, then seal it:

```bash
python3 .agent/skills/manage-agent-team/scripts/agentledger.py seal-payload \
  --draft <draft-json> --output <sealed-json>
```

The reusable payload contains only the capsule-derived objective, content-addressed input artifacts, shared constraints, acceptance criteria, and its mechanically derived `estimated_tokens`. Do not put identity, role type, model, fork window, schedule, retry, output path, allowlist, review chain, or barrier instructions in it. Static migration/replay limits remain 24 inputs, 131072 bytes each, 262144 bytes total, and 65536 estimated Tokens. New dispatches additionally cap the estimate at 16000 Tokens in `standard` and 32000 in `release`; `fast` has no child budget. Split the child task or escalate its mode when that ceiling is exceeded; never truncate the capsule or required evidence. Sealing and prepare also fail when the estimate exceeds the current mode's live remaining Token budget.

4. Create one fresh `agent-handoff-envelope/v3` with the exact dispatch identity, `gpt-5.6-sol`, ledger `fork_turns=0`, deadline, retry count, sealed payload path/hash, evidence allowlist, forbidden actions, review fields, and `LEDGER_REGISTERED` barrier. Spawn through the host with `fork_turns="none"`. The payload is complete; never attach parent conversation history. For an integrator or runtime task, also bind `execution_profile` before spawn: environment, execution authority, capabilities, and a fresh passed preflight receipt for the same candidate. Never send a post-barrier permission instruction that changes how tests run.
5. Prepare, spawn with the exact envelope bytes, register from a fresh platform observation, then release the barrier. `prepare` atomically reserves the payload estimate; `register` consumes that reservation without charging it again; cancellation releases an unspawned reservation; every observed terminal status settles one immutable charge in the child-token ledger. Exact repeated prepare/register/finish/cancel commands are idempotent.

```bash
python3 .agent/skills/manage-agent-team/scripts/agentledger.py prepare \
  --id <id> --root-task-id <root> --role-type <type> --model gpt-5.6-sol \
  --fork-turns 0 --task-payload <sealed> --handoff-envelope <envelope>

python3 .agent/skills/manage-agent-team/scripts/agentledger.py register \
  --id <id> --root-task-id <root> --role-type <type> --role <display-role> \
  --task <task> --model gpt-5.6-sol --fork-turns 0 --task-payload <sealed> \
  --handoff-envelope <envelope> --deadline-minutes <n> \
  --progress-hash <sha256> --platform-snapshot <fresh-json>
```

If spawn capacity fails, record the immutable error with `capacity-failure`. Retry once with the same model and payload; never fall back to a smaller model. Cancel abandoned preparations.

## Review order and test ownership

Run formal release roles serially for one immutable subject and review chain:

1. Adversarial reviewer: consume implementation receipts and attack boundaries/faults/recovery/idempotency. Reuse existing candidate-bound receipts. Until targeted execution has an envelope-, runner-, and Agent-bound receipt schema, it is fail-closed: do not run or self-report additional Cases.
2. Cross reviewer: start only after adversarial zero-severity PASS; rebuild requirement coverage with the six product, architecture, QA, security, operations, and new-project-adopter lenses. Reuse valid candidate receipts. The same fail-closed targeted-execution rule applies.
3. Integrator: start only after cross zero-severity PASS and a passed execution preflight. Execute exactly one `agent-replay-plan/v1` reproducing all current accepted Node 6 checks in order. For workflow governance the live gate wraps this same replay plus preflight and cleanup evidence; no reviewer or gate may execute the full suite again for an unchanged candidate.

Run the replay only through:

```bash
python3 .agent/skills/manage-agent-team/scripts/agentledger.py replay-prepare \
  --integrator-id <id> --plan <plan-json>
python3 .agent/skills/manage-agent-team/scripts/agentledger.py replay-execute \
  --integrator-id <id> --run-id <run-id>
```

Classify a failure as `candidate`, `test`, or `infrastructure`. An infrastructure failure stops before Case 1 when preflight catches it and does not consume a code retry. Require a fresh preflight before continuing; after candidate bytes change, do not automatically resume from a prior Case without an explicit dependency proof. Do not auto-restart the whole review chain.

## Monitor and recover

After registration, call `watchdog-plan` before each bounded host wait. Use the real platform list/status tool at the returned deadline and submit a complete `agent-platform-snapshot/v3` to `check`. Request status after the first unchanged interval. Interrupt only at the configured deadline or after an actually observed unchanged real-progress gap beyond `stall_timeout_seconds`; a missed poll is audit debt, not proof of a dead child.

Redispatch at most once with a new canonical ID and envelope, but the same model, payload, root task, review chain, subject, and terminal predecessor. Preserve both attempts. A second stable failure returns to node 4; a third requires human judgment.

## Finish

Each completed review report begins with:

```text
VERDICT PASS|FAIL P0=n P1=n P2=n
ATTESTATION <agent-review-attestation/v2 canonical JSON>
```

The v2 attestation must include `targeted_cases: []`. A reviewer-authored Case name is not execution evidence, so `finish` rejects every non-empty list until a future schema binds each Case to the envelope, controlled `testrun.py` receipt, and Agent identity. Integrator also declares an empty list because its single full replay is bound separately. Cross adds the canonical third-line `SCENARIO_RECEIPT`. Integrator attests exactly one completed ledger-authored replay receipt. Finish only from a matching terminal platform observation:

```bash
python3 .agent/skills/manage-agent-team/scripts/agentledger.py finish \
  --id <id> --status <status> --conclusion <conclusion> \
  --evidence <allowed-result> --platform-snapshot <terminal-json>
```

`finish` derives authority from immutable report/replay bytes and the exact `FINAL_RESULT ... report_sha256=...` message. It publishes the terminal marker and aborts any unfinished replay when an integrator closes unsuccessfully. The root cannot substitute PASS.

Before final integration, require a fresh platform-empty snapshot and `validate --require-empty`. Run `workflowctl.py route-resume` after every child terminal event. When its receipt says `terminal=false`, continue or report the pending gate; never declare the root task complete.
