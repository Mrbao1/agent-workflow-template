---
name: manage-local-runtime
description: Run local servers, containers, browsers, simulators, workers, and integration dependencies with bounded startup, explicit PID or Docker project registration, health checks, failure-safe teardown, port release, and zero-residual verification. Use whenever local validation starts a background process or container.
---

# Manage Local Runtime

1. Give every runtime a bounded timeout and unique name. For a single server health check, prefer the failure-safe wrapper:

```bash
python3 .agent/scripts/agentctl.py managed-run --name <name> --timeout 30 --health-url http://127.0.0.1:<port>/health -- <command>
```

It creates an isolated process group and tears it down in `finally` on success, failure, timeout or interruption.

Before execution, `agentctl start` captures the task's project-process baseline. For an explicitly migrated active task, use `capture-runtime-baseline --source user:<decision>` only after a read-only process/container inspection. `assert-clean` compares live project-cwd processes with that baseline, so an implementation cannot obtain a clean result merely by leaving the registry empty.

2. For multi-service or interactive validation, use a new process session and immediately register it:
```bash
python3 .agent/scripts/agentctl.py register-process --pid <pid> --name <name> --kind <kind>
python3 .agent/scripts/agentctl.py register-port --port <port> --pid <pid> --host 127.0.0.1
python3 .agent/scripts/agentctl.py register-docker --project agent_<unique-id> --workdir <dir> --file <compose-file>
```

3. Wait for explicit health; do not equate a listening process with a working data flow.
4. Run validation. Capture only bounded logs and final evidence. When an independent review Agent must execute a foreground command concurrently with node-6 validation, bind it to that active platform-evidenced review identity and a hard timeout:

```bash
python3 .agent/scripts/agentctl.py tool-run --agent-id <canonical-review-agent-id> --name <review-check> --timeout 60 -- <command>
```

`tool-run` first runs the shared full `agent-team/v9` semantic validator without allowing ledger mutation, then requires an unexpired active member whose exact canonical `role_type` is one of `reviewer`, `adversarial`, `cross`, or `integrator`, with a fresh immutable monitor chain, no historical or current stall violation, a valid payload/per-dispatch-envelope provenance chain and no interrupt/terminal state. Review Agents must also carry the current review-chain, subject and predecessor bindings required by their canonical role. Free-form role text, partial ledgers, arbitrary receipt paths, legacy schemas, role/deadline edits, stale envelopes and terminal-to-active edits cannot authorize a lease. It captures the exact caller/supervisor chain and starts a stable isolated launcher behind a one-byte gate, atomically commits the lease before releasing the reviewed command, then tears the group down in `finally`. Runtime inspection derives the caller chain from two live OS process snapshots; caller-provided PID environment variables have no authority. This prevents immediate nested validation from racing ahead of its lease. An unrelated unregistered project process remains a baseline delta and fails the gate; product servers/workers still use `managed-run` or explicit runtime registration.

5. In success, failure, timeout and interruption paths run:

```bash
python3 .agent/scripts/agentctl.py cleanup
python3 .agent/scripts/agentctl.py assert-clean
```

6. Never kill by broad name, wildcard or unrelated port. PID registration captures PID, process group, start time, command and working directory; cleanup refuses identity mismatch. Docker registration captures project, working directory and exact Compose files.
7. Any new unregistered project process since the baseline, invalid/expired tool lease, residual registered PID/process group, container/network, or occupied registered port blocks node 6 and completion. Baseline processes are never killed; unrelated Docker projects and user processes remain out of scope.

Read [runtime-contract.md](references/runtime-contract.md) when defining a new stack adapter.
