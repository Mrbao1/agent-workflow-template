---
name: manage-local-runtime
description: Run local servers, containers, browsers, simulators, workers, and integration dependencies with bounded startup, explicit PID or Docker project registration, health checks, failure-safe teardown, port release, and zero-residual verification. Use whenever local validation starts a background process or container.
---

# Manage Local Runtime

1. Give every runtime a bounded timeout and unique name. For a single server health check, prefer the failure-safe wrapper:

```bash
python3 .agent/scripts/agentctl.py managed-run --name <name> --timeout 30 --health-url http://127.0.0.1:<port>/health -- <command>

Health probes accept only canonical loopback HTTP, never follow redirects, and stay inside the command's total deadline. Docker cleanup/inventory and controller subprocesses cap output bytes before decoding and fail closed on output overflow or uncertain identity cleanup.
```

It uses the shared byte/time-bounded launch-token supervisor and removes all twice-observed launch-scoped descendants before reporting normal-path cleanup. This is lifecycle cleanup, not confinement against same-UID token forgery or controller/host failure; use an external ephemeral OS/provider sandbox when crash-safe or hostile-code containment is required.

Before execution, `agentctl start` captures the task's project-process baseline. For an explicitly migrated active task, use `capture-runtime-baseline --source user:<decision>` only after a read-only process/container inspection. `assert-clean` compares live project-cwd processes with that baseline, so an implementation cannot obtain a clean result merely by leaving the registry empty.

2. For multi-service or interactive validation, use a new process session and immediately register it:
```bash
python3 .agent/scripts/agentctl.py register-process --pid <pid> --name <name> --kind <kind>
python3 .agent/scripts/agentctl.py register-port --port <port> --pid <pid> --host 127.0.0.1
python3 .agent/scripts/agentctl.py register-docker --project agent_<unique-id> --workdir <dir> --file <compose-file>
```

3. Wait for explicit health; do not equate a listening process with a working data flow.
4. Run validation. Capture only bounded logs and final evidence. Independent review commands must be launched and attributed by the Agent platform itself; a local process cannot authenticate a platform Agent by presenting an Agent ID. `agentctl.py tool-run` therefore fails closed and never executes caller argv. Product servers/workers use `managed-run` or explicit runtime registration, while reviewer concurrency stays under the platform supervisor.

5. In success, failure, timeout and interruption paths run:

```bash
python3 .agent/scripts/agentctl.py cleanup
python3 .agent/scripts/agentctl.py assert-clean
```

6. Never kill by broad name, wildcard or unrelated port. PID registration captures PID, process group, start time, command and working directory; cleanup refuses identity mismatch. Docker registration captures project, working directory and exact Compose files.
7. Any new unregistered project process since the baseline, invalid/expired tool lease, residual registered PID/process group, container/network, or occupied registered port blocks node 6 and completion. Baseline processes are never killed; unrelated Docker projects and user processes remain out of scope.

Read [runtime-contract.md](references/runtime-contract.md) when defining a new stack adapter.
