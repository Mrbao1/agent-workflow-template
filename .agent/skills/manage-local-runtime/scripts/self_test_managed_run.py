#!/usr/bin/env python3
"""Adversarial checks for bounded commands, signals, descendants and identities."""

from pathlib import Path
import datetime as dt
import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[4]
TESTRUN = ROOT / ".agent/scripts/testrun.py"
AGENT_LEDGER = ROOT / ".agent/skills/manage-agent-team/scripts/agentledger.py"


def copy_policy_runtime(project: Path) -> None:
    shutil.copytree(ROOT / ".agent/scripts/workflowlib", project / ".agent/scripts/workflowlib")
    shutil.copy2(ROOT / ".agent/INDEX.md", project / ".agent/INDEX.md")
    shutil.copytree(ROOT / ".agent/workflows", project / ".agent/workflows")
    shutil.copytree(ROOT / ".agent/templates", project / ".agent/templates")
    shutil.copytree(
        ROOT / ".agent/skills/run-ai-coding-pipeline",
        project / ".agent/skills/run-ai-coding-pipeline",
    )

# Runtime-process tests must not depend on, or mutate, the repository's active
# task.  Build a clarified disposable controller fixture so the clarification
# gate remains fail-closed even when this test is run from a fresh idle template.
_CONTROL_TEMP = tempfile.TemporaryDirectory(prefix="managed-runtime-controller-")
CONTROL_ROOT = Path(_CONTROL_TEMP.name)
shutil.copytree(ROOT / ".agent/scripts", CONTROL_ROOT / ".agent/scripts")
(CONTROL_ROOT / ".agent/state").mkdir(parents=True)
shutil.copy2(ROOT / ".agent/config.json", CONTROL_ROOT / ".agent/config.json")
shutil.copy2(ROOT / ".agent/INDEX.md", CONTROL_ROOT / ".agent/INDEX.md")
shutil.copytree(ROOT / ".agent/workflows", CONTROL_ROOT / ".agent/workflows")
shutil.copytree(ROOT / ".agent/templates", CONTROL_ROOT / ".agent/templates")
shutil.copytree(
    ROOT / ".agent/skills/run-ai-coding-pipeline",
    CONTROL_ROOT / ".agent/skills/run-ai-coding-pipeline",
)
control_task = json.loads((ROOT / ".agent/state/TASK.json").read_text(encoding="utf-8"))
control_contract = "# Requirement Contract\n\n- Human decisions: user:runtime-self-test\n- Clarified: true\n"
(CONTROL_ROOT / ".agent/state/REQUIREMENT_CONTRACT.md").write_text(control_contract, encoding="utf-8")
control_task.update({
    "title": "managed-runtime-self-test",
    "mode": "standard",
    "token_budget": 20000,
    "tokens_used": 0,
    "budget_state": "ok",
    "status": "in_progress",
    "phase": "implementation",
    "requirements_clarified": True,
    "requirement_source": "user:runtime-self-test",
    "primary_skill": "run-ai-coding-pipeline",
    "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
    "requirement_contract_sha256": hashlib.sha256(control_contract.encode()).hexdigest(),
    "open_questions": [],
})
(CONTROL_ROOT / ".agent/state/TASK.json").write_text(
    json.dumps(control_task, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
)
subprocess.run(
    [
        sys.executable, "-c",
        "import argparse,hashlib,sys;sys.path.insert(0,'.agent/scripts');import contextctl;"
        "args=argparse.Namespace(reason='runtime-self-test',summary='bounded runtime controller fixture',source='self-test',source_tokens=1200,fact=[],file=[],evidence=[],risk=[],resolve_risk=[],transition=False,reset=True);"
        "capsule=contextctl.build_capsule(args,'verified',{},'none');contextctl.atomic_json(contextctl.CONTEXT_PATH,capsule);raise SystemExit(contextctl.validate_context())",
    ],
    cwd=CONTROL_ROOT,
    check=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
)
(CONTROL_ROOT / ".agent/state/runtime.json").write_text(json.dumps({
    "schema": "agent-runtime/v2",
    "baseline": {
        "source": "user:runtime-self-test",
        "captured_at": "2026-07-18T00:00:00+00:00",
        "project_processes": [],
    },
    "processes": [], "docker_projects": [], "ports": [],
}), encoding="utf-8")
(CONTROL_ROOT / ".agent/state/tool-leases.json").write_text(
    json.dumps({"schema": "agent-tool-leases/v1", "leases": []}), encoding="utf-8",
)
CONTROLLER = CONTROL_ROOT / ".agent/scripts/agentctl.py"

# Load the disposable controller for direct identity and signal-safety checks.
sys.path.insert(0, str(CONTROL_ROOT / ".agent/scripts"))
controller_spec = importlib.util.spec_from_file_location("managed_runtime_agentctl", CONTROLLER)
if controller_spec is None or controller_spec.loader is None:
    raise AssertionError("could not load disposable managed-runtime controller")
runtime_controller = importlib.util.module_from_spec(controller_spec)
controller_spec.loader.exec_module(runtime_controller)


def supervised_env() -> dict[str, str]:
    return os.environ.copy()


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def wait_dead(pid: int, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return not alive(pid)


def kill_exact(pid: int) -> None:
    if alive(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def controller(*args: str, expected: int = 0) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [sys.executable, str(CONTROLLER), *args], cwd=CONTROL_ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20, env=supervised_env(),
    )
    if result.returncode != expected:
        raise AssertionError(f"{args}: expected {expected}, got {result.returncode}\n{result.stdout}")
    return result


controller("cleanup")
with tempfile.TemporaryDirectory(prefix="runtime-adversary-") as raw:
    temporary = Path(raw)

    # Stable identity must come from the host kernel, not lsof's missing start
    # time placeholder. An unreadable or changing identity fails closed.
    own_snapshot = runtime_controller.process_snapshot(os.getpid())
    expected_prefix = "darwin:" if sys.platform == "darwin" else "linux:"
    if own_snapshot is None or not str(own_snapshot.get("start_time", "")).startswith(expected_prefix):
        raise AssertionError(f"OS-native process identity unavailable: {own_snapshot}")

    # Only an exact host-runner sibling may be excluded. A project child or an
    # argv/name lookalike remains visible to the runtime delta gate.
    host_runner = {
        "pid": 10, "ppid": 1, "pgid": 10,
        "executable": "/trusted/platform/codex",
    }
    synthetic_ancestors = {10: host_runner}
    if not runtime_controller.platform_runner_peer(
        {"pid": 11, "ppid": 10, "pgid": 11, "executable": "/trusted/platform/cua_node/bin/node_repl"},
        synthetic_ancestors,
    ):
        raise AssertionError("exact platform tool runner was not recognized")
    for lookalike in (
        {"pid": 12, "ppid": 11, "pgid": 12, "executable": "/trusted/platform/cua_node/bin/node_repl"},
        {"pid": 13, "ppid": 10, "pgid": 13, "executable": "/project/node_repl"},
        {"pid": 14, "ppid": 10, "pgid": 14, "executable": None},
    ):
        if runtime_controller.platform_runner_peer(lookalike, synthetic_ancestors):
            raise AssertionError(f"project/lookalike process was treated as a platform peer: {lookalike}")

    # Registration and cleanup must never authorize the controller's own live
    # process group, even when its leader otherwise has a valid stable identity.
    controller_pgid = os.getpgid(0)
    controller_status, controller_identity = runtime_controller.native_process_identity(controller_pgid)
    if controller_status != "ok" or controller_identity is None:
        raise AssertionError("could not inspect controller process-group leader")
    controller_record = {
        **controller_identity,
        "scope": "isolated_process_group",
    }
    signaled = []
    original_signal_group = runtime_controller.signal_process_group
    runtime_controller.signal_process_group = lambda pgid, signum: signaled.append((pgid, signum)) or True
    try:
        if runtime_controller.terminate_isolated_group(controller_record, 1):
            raise AssertionError("controller ancestor group was accepted for termination")
        if signaled:
            raise AssertionError("controller ancestor group reached the signal boundary")
    finally:
        runtime_controller.signal_process_group = original_signal_group

    # A forged/reused leader identity must never authorize killpg, even when
    # PID and PGID still name a live isolated group.
    reused = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        cwd=CONTROL_ROOT, start_new_session=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        reused_snapshot = runtime_controller.process_snapshot(reused.pid)
        if reused_snapshot is None:
            raise AssertionError("could not snapshot PID-reuse fixture")
        forged = {key: reused_snapshot[key] for key in ("pid", "pgid", "start_time", "command", "cwd")}
        forged.update({"start_time": f"{reused_snapshot['start_time']}:reused", "scope": "isolated_process_group"})
        if runtime_controller.terminate_isolated_group(forged, 1, reused):
            raise AssertionError("mismatched leader identity authorized process-group termination")
        if reused.poll() is not None:
            raise AssertionError("PID-reuse refusal still signaled the unrelated group")
    finally:
        try:
            os.killpg(reused.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        reused.wait(timeout=3)

    # A leader may exit successfully while a child keeps its process group alive.
    leader_child = temporary / "leader-child.pid"
    leader_script = (
        "import pathlib,subprocess,sys; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); __import__('time').sleep(.3)"
    )
    result = controller(
        "managed-run", "--name", "leader-first-exit", "--timeout", "5", "--",
        sys.executable, "-c", leader_script, str(leader_child),
    )
    child_pid = int(leader_child.read_text())
    try:
        if not wait_dead(child_pid):
            raise AssertionError("managed-run left a child after its group leader exited")
    finally:
        kill_exact(child_pid)

    # SIGTERM delivered to the controller must still tear down the managed group.
    signal_child = temporary / "signal-child.pid"
    signal_script = (
        "import pathlib,subprocess,sys,time; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)"
    )
    managed = subprocess.Popen(
        [sys.executable, str(CONTROLLER), "managed-run", "--name", "signal-cleanup", "--timeout", "60", "--",
         sys.executable, "-c", signal_script, str(signal_child)],
        cwd=CONTROL_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=supervised_env(),
    )
    deadline = time.monotonic() + 5
    while not signal_child.is_file() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not signal_child.is_file():
        if managed.poll() is None:
            managed.kill()
        output = managed.communicate(timeout=5)[0]
        raise AssertionError(f"signal fixture did not start; rc={managed.returncode}\n{output}")
    signal_pid = int(signal_child.read_text())
    try:
        managed.send_signal(signal.SIGTERM)
        managed.communicate(timeout=10)
        if not wait_dead(signal_pid):
            raise AssertionError("managed-run SIGTERM path leaked a descendant")
    finally:
        kill_exact(signal_pid)
        controller("cleanup")

    # testrun must kill the entire command group on timeout, not only its leader.
    test_child = temporary / "testrun-child.pid"
    receipt = temporary / "receipt.json"
    timeout_script = (
        "import pathlib,subprocess,sys,time; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)"
    )
    timed = subprocess.run(
        [sys.executable, str(TESTRUN), "--receipt", str(receipt.relative_to(ROOT)) if ROOT in receipt.parents else str(receipt),
         "--case", "timeout-cleanup", "--timeout", "1", "--", sys.executable, "-c", timeout_script, str(test_child)],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
    )
    # Receipts are deliberately constrained to the project; repeat with a project-local temp path.
    if "receipt escapes project" in timed.stdout:
        local_dir = ROOT / ".agent/state/evidence/runtime-selftest"
        local_dir.mkdir(parents=True, exist_ok=True)
        receipt = local_dir / f"testrun-{os.getpid()}.json"
        test_child = local_dir / f"testrun-child-{os.getpid()}.pid"
        try:
            timed = subprocess.run(
                [sys.executable, str(TESTRUN), "--receipt", str(receipt.relative_to(ROOT)), "--case", "timeout-cleanup",
                 "--timeout", "1", "--", sys.executable, "-c", timeout_script, str(test_child)],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
            )
            if timed.returncode != 124:
                raise AssertionError(f"testrun timeout expected 124, got {timed.returncode}\n{timed.stdout}")
            test_pid = int(test_child.read_text())
            try:
                if not wait_dead(test_pid):
                    raise AssertionError("testrun timeout leaked a descendant")
            finally:
                kill_exact(test_pid)
        finally:
            for path in local_dir.glob(f"testrun*{os.getpid()}*"):
                path.unlink(missing_ok=True)
            for path in local_dir.glob("testrun-timeout-cleanup.log"):
                path.unlink(missing_ok=True)
            try:
                local_dir.rmdir()
            except OSError:
                pass
    else:
        raise AssertionError("off-project receipt path unexpectedly accepted")

    # Same Docker project name may only be registered with the exact same identity.
    isolated = temporary / "project"
    (isolated / ".agent/scripts").mkdir(parents=True)
    (isolated / ".agent/state").mkdir()
    shutil.copy2(CONTROLLER, isolated / ".agent/scripts/agentctl.py")
    shutil.copy2(ROOT / ".agent/scripts/contextctl.py", isolated / ".agent/scripts/contextctl.py")
    shutil.copy2(ROOT / ".agent/scripts/contexttx.py", isolated / ".agent/scripts/contexttx.py")
    shutil.copy2(ROOT / ".agent/scripts/humandecision.py", isolated / ".agent/scripts/humandecision.py")
    copy_policy_runtime(isolated)
    (isolated / ".agent/state/runtime.json").write_text(
        json.dumps({"schema": "agent-runtime/v2", "baseline": {"source": "user:fixture", "captured_at": "2026-07-17T00:00:00+00:00", "project_processes": []}, "processes": [], "docker_projects": [], "ports": []}),
        encoding="utf-8",
    )
    (isolated / "a.yml").write_text("services: {}\n", encoding="utf-8")
    (isolated / "b.yml").write_text("services: {}\n", encoding="utf-8")
    command = [sys.executable, str(isolated / ".agent/scripts/agentctl.py")]
    first = subprocess.run([*command, "register-docker", "--project", "agent_identity_fixture", "--workdir", ".", "--file", "a.yml"], cwd=isolated)
    conflict = subprocess.run([*command, "register-docker", "--project", "agent_identity_fixture", "--workdir", ".", "--file", "b.yml"], cwd=isolated, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if first.returncode or conflict.returncode == 0:
        raise AssertionError("Docker project identity conflict did not fail closed")

    # A sibling reviewer command is allowed only through a bounded,
    # platform-evidenced, listener-free foreground-tool lease.  It must not
    # mask an unrelated unregistered runtime or a registered product runtime.
    tool_project = temporary / "tool-project"
    (tool_project / ".agent/scripts").mkdir(parents=True)
    (tool_project / ".agent/skills/manage-agent-team/scripts").mkdir(parents=True)
    (tool_project / ".agent/state/evidence").mkdir(parents=True)
    shutil.copy2(CONTROLLER, tool_project / ".agent/scripts/agentctl.py")
    shutil.copy2(ROOT / ".agent/scripts/contextctl.py", tool_project / ".agent/scripts/contextctl.py")
    shutil.copy2(ROOT / ".agent/scripts/contexttx.py", tool_project / ".agent/scripts/contexttx.py")
    shutil.copy2(ROOT / ".agent/scripts/humandecision.py", tool_project / ".agent/scripts/humandecision.py")
    shutil.copy2(ROOT / ".agent/scripts/testrun.py", tool_project / ".agent/scripts/testrun.py")
    shutil.copy2(AGENT_LEDGER, tool_project / ".agent/skills/manage-agent-team/scripts/agentledger.py")
    copy_policy_runtime(tool_project)
    tool_config = json.loads((ROOT / ".agent/config.json").read_text(encoding="utf-8"))
    tool_config["runtime"]["term_timeout_seconds"] = 1
    tool_config["routing"]["modes"]["standard"]["max_child_agents"] = 2
    (tool_project / ".agent/config.json").write_text(json.dumps(tool_config), encoding="utf-8")
    tool_task = json.loads((ROOT / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    tool_contract = "# Requirement Contract\n\n- Human decisions: user:runtime-self-test\n- Clarified: true\n"
    (tool_project / ".agent/state/REQUIREMENT_CONTRACT.md").write_text(tool_contract, encoding="utf-8")
    tool_task.update({
        # This disposable fixture keeps an adversarial reviewer and implementer
        # active together without claiming release/provider platform assurance.
        "mode": "standard", "token_budget": tool_config["routing"]["modes"]["standard"]["token_budget"],
        "tokens_used": 0, "budget_state": "ok",
        "status": "in_progress", "phase": "implementation", "requirements_clarified": True,
        "requirement_source": "user:runtime-self-test", "primary_skill": "run-ai-coding-pipeline",
        "child_agents_used": 0, "peak_child_agents": 0,
        "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
        "requirement_contract_sha256": hashlib.sha256(tool_contract.encode()).hexdigest(),
        "open_questions": [],
    })
    (tool_project / ".agent/state/TASK.json").write_text(json.dumps(tool_task), encoding="utf-8")
    tool_agents = json.loads((ROOT / ".agent/state/agents.json").read_text(encoding="utf-8"))
    tool_agents["token_accounting"]["token_budget"] = tool_task["token_budget"]
    (tool_project / ".agent/state/agents.json").write_text(json.dumps(tool_agents), encoding="utf-8")
    subprocess.run(
        [
            sys.executable, "-c",
            "import argparse,sys;sys.path.insert(0,'.agent/scripts');import contextctl;"
            "args=argparse.Namespace(reason='runtime-agent-self-test',summary='bounded agent runtime fixture',source='self-test',source_tokens=1200,fact=[],file=[],evidence=[],risk=[],resolve_risk=[],transition=False,reset=True);"
            "capsule=contextctl.build_capsule(args,'verified',{},'none');contextctl.atomic_json(contextctl.CONTEXT_PATH,capsule);raise SystemExit(contextctl.validate_context())",
        ],
        cwd=tool_project,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    (tool_project / ".agent/state/runtime.json").write_text(json.dumps({
        "schema": "agent-runtime/v2",
        "baseline": {"source": "user:fixture", "captured_at": "2026-07-17T00:00:00+00:00", "project_processes": []},
        "processes": [], "docker_projects": [], "ports": [],
    }), encoding="utf-8")
    (tool_project / ".agent/state/tool-leases.json").write_text(
        json.dumps({"schema": "agent-tool-leases/v1", "leases": []}), encoding="utf-8",
    )
    runtime_input = b"read-only runtime fixture"
    runtime_input_hash = hashlib.sha256(runtime_input).hexdigest()
    runtime_input_internal = f".agent/state/evidence/agent-input-artifacts/{runtime_input_hash}.blob"
    (tool_project / runtime_input_internal).parent.mkdir(parents=True, exist_ok=True)
    (tool_project / runtime_input_internal).write_bytes(runtime_input)
    payload = {
        "schema": "agent-task-payload/v2",
        "objective": "exercise reusable runtime review authorization",
        "input_artifacts": [{"label": "runtime-input.txt", "path": runtime_input_internal,
                             "sha256": runtime_input_hash, "bytes": len(runtime_input)}],
        "shared_constraints": ["Treat input artifacts as read-only", "Use the envelope as the sole output authority"],
        "acceptance_criteria": ["Authorize only the exact active canonical reviewer"],
    }
    payload_semantics = {
        "objective": payload["objective"],
        "shared_constraints": payload["shared_constraints"],
        "acceptance_criteria": payload["acceptance_criteria"],
    }
    semantic_bytes = len(json.dumps(payload_semantics, sort_keys=True, separators=(",", ":")).encode())
    payload["estimated_tokens"] = (len(runtime_input) + semantic_bytes + 3) // 4
    payload_data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    payload_hash = hashlib.sha256(payload_data).hexdigest()
    payload_path = tool_project / "payload.txt"
    payload_path.write_bytes(payload_data)
    (tool_project / "runtime-input.txt").write_bytes(runtime_input)
    payload_internal = f".agent/state/evidence/agent-task-payloads/{payload_hash}.ctx"
    observed_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    observed = observed_at.isoformat()
    empty_snapshot = tool_project / "platform-empty.json"
    empty_snapshot.write_text(json.dumps({
        "schema": "agent-platform-snapshot/v3", "observed_at": observed, "members": [],
    }), encoding="utf-8")
    ledger_command = [sys.executable, str(tool_project / ".agent/skills/manage-agent-team/scripts/agentledger.py")]
    initialized = subprocess.run(
        [*ledger_command, "init", "--platform-snapshot", empty_snapshot.name], cwd=tool_project,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    initial_ledger = json.loads((tool_project / ".agent/state/agents.json").read_text(encoding="utf-8"))
    reviewer_envelope_path = tool_project / "reviewer-envelope.json"
    reviewer_envelope_path.write_text(json.dumps({
        "schema": "agent-handoff-envelope/v3", "ledger_epoch": initial_ledger["epoch"],
        "agent_id": "/root/reviewer", "root_task_id": "runtime-fixture", "role_type": "adversarial",
        "model": "gpt-5.6-sol", "fork_turns": 0, "started_at": observed,
        "deadline_at": (observed_at + dt.timedelta(minutes=5)).isoformat(), "redispatch_count": 0,
        "task_payload_path": payload_internal, "task_payload_sha256": payload_hash,
        "allowed_evidence_paths": ["reviewer-report.txt"],
        "forbidden_actions": ["approve-node7", "modify-managed-files"],
        "review_chain_id": "runtime-fixture-chain", "review_subject_sha256": payload_hash,
        "predecessor_result_sha256": None, "result_report_path": "reviewer-report.txt",
        "start_barrier": "LEDGER_REGISTERED",
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    reviewer_envelope_hash = hashlib.sha256(reviewer_envelope_path.read_bytes()).hexdigest()
    reviewer_contract = {
        "id": "/root/reviewer", "status": "running", "ledger_epoch": initial_ledger["epoch"],
        "root_task_id": "runtime-fixture", "role_type": "adversarial",
        "started_at": observed, "deadline_at": (observed_at + dt.timedelta(minutes=5)).isoformat(),
        "redispatch_count": 0, "model": "gpt-5.6-sol", "fork_turns": 0,
        "task_payload_sha256": payload_hash, "handoff_envelope_sha256": reviewer_envelope_hash,
        "message_cursor": 0,
    }
    registration_snapshot = tool_project / "platform-registration.json"
    registration_snapshot.write_text(json.dumps({
        "schema": "agent-platform-snapshot/v3", "observed_at": observed, "members": [reviewer_contract],
    }), encoding="utf-8")
    prepared = subprocess.run(
        [*ledger_command, "prepare", "--id", "/root/reviewer", "--root-task-id", "runtime-fixture",
         "--role-type", "adversarial", "--model", "gpt-5.6-sol", "--fork-turns", "0",
         "--task-payload", payload_path.name, "--handoff-envelope", reviewer_envelope_path.name],
        cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    registered = subprocess.run(
        [*ledger_command, "register", "--id", "/root/reviewer", "--root-task-id", "runtime-fixture",
         "--role-type", "adversarial", "--role", "independent adversarial reviewer", "--task", "runtime integration",
         "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", payload_path.name,
         "--handoff-envelope", reviewer_envelope_path.name, "--deadline-minutes", "5", "--progress-hash", payload_hash,
         "--platform-snapshot", registration_snapshot.name],
        cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if initialized.returncode or prepared.returncode or registered.returncode:
        raise AssertionError(f"real agentledger fixture failed\n{initialized.stdout}\n{prepared.stdout}\n{registered.stdout}")
    reviewer_state = json.loads((tool_project / ".agent/state/agents.json").read_text(encoding="utf-8"))["members"][0]
    reviewer_live = {
        "id": reviewer_state["id"], "status": "running", "ledger_epoch": initial_ledger["epoch"],
        "root_task_id": reviewer_state["root_task_id"], "role_type": reviewer_state["role_type"],
        "started_at": reviewer_state["started_at"], "deadline_at": reviewer_state["deadline_at"],
        "redispatch_count": reviewer_state["redispatch_count"], "model": reviewer_state["model"],
        "fork_turns": reviewer_state["fork_turns"], "task_payload_sha256": reviewer_state["task_payload_sha256"],
        "handoff_envelope_sha256": reviewer_state["handoff_envelope_sha256"],
        "message_cursor": 0,
    }
    implementer_observed_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    implementer_envelope_path = tool_project / "implementer-envelope.json"
    implementer_envelope_path.write_text(json.dumps({
        "schema": "agent-handoff-envelope/v3", "ledger_epoch": initial_ledger["epoch"],
        "agent_id": "/root/implementer", "root_task_id": "runtime-implementer", "role_type": "implementer",
        "model": "gpt-5.6-sol", "fork_turns": 0, "started_at": implementer_observed_at.isoformat(),
        "deadline_at": (implementer_observed_at + dt.timedelta(minutes=5)).isoformat(), "redispatch_count": 0,
        "task_payload_path": payload_internal, "task_payload_sha256": payload_hash,
        "allowed_evidence_paths": ["implementer-report.txt"], "forbidden_actions": ["approve-node7"],
        "review_chain_id": None, "review_subject_sha256": None,
        "predecessor_result_sha256": None, "result_report_path": None,
        "start_barrier": "LEDGER_REGISTERED",
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    implementer_envelope_hash = hashlib.sha256(implementer_envelope_path.read_bytes()).hexdigest()
    implementer_contract = {
        "id": "/root/implementer", "status": "running", "ledger_epoch": initial_ledger["epoch"],
        "root_task_id": "runtime-implementer", "role_type": "implementer",
        "started_at": implementer_observed_at.isoformat(),
        "deadline_at": (implementer_observed_at + dt.timedelta(minutes=5)).isoformat(),
        "redispatch_count": 0, "model": "gpt-5.6-sol", "fork_turns": 0,
        "task_payload_sha256": payload_hash, "handoff_envelope_sha256": implementer_envelope_hash,
        "message_cursor": 0,
    }
    implementer_snapshot = tool_project / "platform-implementer-registration.json"
    implementer_snapshot.write_text(json.dumps({
        "schema": "agent-platform-snapshot/v3", "observed_at": implementer_observed_at.isoformat(),
        "members": [reviewer_live, implementer_contract],
    }), encoding="utf-8")
    implementer_prepared = subprocess.run(
        [*ledger_command, "prepare", "--id", "/root/implementer", "--root-task-id", "runtime-implementer",
         "--role-type", "implementer", "--model", "gpt-5.6-sol", "--fork-turns", "0",
         "--task-payload", payload_path.name, "--handoff-envelope", implementer_envelope_path.name],
        cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    implementer_registered = subprocess.run(
        [*ledger_command, "register", "--id", "/root/implementer", "--root-task-id", "runtime-implementer",
         "--role-type", "implementer", "--role", "primary implementer-review owner", "--task", "implementation",
         "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", payload_path.name,
         "--handoff-envelope", implementer_envelope_path.name, "--deadline-minutes", "5", "--progress-hash", payload_hash,
         "--platform-snapshot", implementer_snapshot.name],
        cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if implementer_prepared.returncode or implementer_registered.returncode:
        raise AssertionError(f"canonical implementer fixture failed\n{implementer_prepared.stdout}\n{implementer_registered.stdout}")
    tool_command = [sys.executable, str(tool_project / ".agent/scripts/agentctl.py")]
    agents_path = tool_project / ".agent/state/agents.json"
    valid_agents_bytes = agents_path.read_bytes()
    valid_ledger = subprocess.run(
        [*ledger_command, "validate"], cwd=tool_project, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if valid_ledger.returncode:
        raise AssertionError(f"registered reviewer ledger is invalid before tool authorization\n{valid_ledger.stdout}")

    def rejected_owner(mutator, label: str) -> None:
        value = json.loads(valid_agents_bytes)
        mutator(value)
        agents_path.write_text(json.dumps(value), encoding="utf-8")
        try:
            rejected = subprocess.run(
                [*tool_command, "tool-run", "--agent-id", "/root/reviewer", "--name", label,
                 "--timeout", "5", "--", sys.executable, "-c", "pass"],
                cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            if rejected.returncode == 0 or "requires an active platform-evidenced" not in rejected.stdout:
                raise AssertionError(f"{label} owner was accepted\n{rejected.stdout}")
        finally:
            agents_path.write_bytes(valid_agents_bytes)

    rejected_owner(lambda value: value.clear() or value.update({"schema": "agent-team/v6", "members": []}), "partial-v6")
    rejected_owner(lambda value: value.update({"schema": "agent-team/v5"}), "legacy-v5")
    rejected_owner(lambda value: value.update({"schema": "agent-team/v4"}), "legacy-v4")
    rejected_owner(lambda value: value.update({"schema": "agent-team/v3"}), "legacy-v3")
    rejected_owner(lambda value: value.update({"schema": "agent-team/v2"}), "legacy-v2")
    rejected_owner(lambda value: value["members"][0].update({
        "registration_platform_evidence": {
            "path": registration_snapshot.name,
            "sha256": hashlib.sha256(registration_snapshot.read_bytes()).hexdigest(),
            "bytes": len(registration_snapshot.read_bytes()),
        },
    }), "arbitrary-registration-path")
    rejected_owner(lambda value: value["members"][0].update({
        "terminal_platform_evidence": value["members"][0]["registration_platform_evidence"],
    }), "terminal-active-tamper")
    rejected_owner(lambda value: value["members"][0].update({"role_type": "implementer"}), "role-type-tamper")
    rejected_owner(lambda value: value["members"][0].update({
        "started_at": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=2)).replace(microsecond=0).isoformat(),
        "deadline_at": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).replace(microsecond=0).isoformat(),
    }), "expired-owner")
    unregistered = subprocess.run(
        [*tool_command, "tool-run", "--agent-id", "/root/not-registered", "--name", "unregistered-owner",
         "--timeout", "5", "--", sys.executable, "-c", "pass"],
        cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if unregistered.returncode == 0:
        raise AssertionError("unregistered owner was accepted")
    hybrid = subprocess.run(
        [*tool_command, "tool-run", "--agent-id", "/root/implementer", "--name", "implementer-review-hybrid",
         "--timeout", "5", "--", sys.executable, "-c", "pass"],
        cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if hybrid.returncode == 0 or "requires an active platform-evidenced" not in hybrid.stdout:
        raise AssertionError(f"implementer with review-like display text was authorized\n{hybrid.stdout}")

    # Keep a real Bash parent alive while the leased child immediately checks
    # runtime state.  This attacks both the lease-before-exec barrier and the
    # direct-parent supervisor capture used by collaboration shells.
    nested_command = [
        *tool_command, "tool-run", "--agent-id", "/root/reviewer", "--name", "nested-live-validation",
        "--timeout", "10", "--", *tool_command, "assert-clean",
    ]
    nested_shell = f"{shlex.join(nested_command)} & child=$!; wait \"$child\""
    nested = subprocess.run(
        ["/bin/bash", "-c", nested_shell], cwd=tool_project, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )
    nested_leases = json.loads((tool_project / ".agent/state/tool-leases.json").read_text(encoding="utf-8"))["leases"]
    if nested.returncode or "RUNTIME CLEAN" not in nested.stdout or nested_leases:
        raise AssertionError(f"live reviewer lease was not visible before nested validation\n{nested.stdout}")

    ready = tool_project / "reviewer-ready"
    foreground = subprocess.Popen(
        [*tool_command, "tool-run", "--agent-id", "/root/reviewer", "--name", "read-only-review",
         "--timeout", "10", "--", sys.executable, "-c",
         "import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(10)", str(ready)],
        cwd=tool_project, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        leases = json.loads((tool_project / ".agent/state/tool-leases.json").read_text(encoding="utf-8"))
        if ready.is_file() and leases.get("leases"):
            break
        time.sleep(0.05)
    else:
        foreground.kill()
        raise AssertionError("foreground reviewer lease did not become observable")
    clean_with_reviewer = subprocess.run([*tool_command, "assert-clean"], cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if clean_with_reviewer.returncode:
        raise AssertionError(f"audited foreground reviewer was misclassified as runtime\n{clean_with_reviewer.stdout}")
    forged = json.loads(valid_agents_bytes)
    forged["members"][0]["terminal_platform_evidence"] = forged["members"][0]["registration_platform_evidence"]
    agents_path.write_text(json.dumps(forged), encoding="utf-8")
    try:
        rejected_allowance = subprocess.run(
            [*tool_command, "assert-clean"], cwd=tool_project, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if rejected_allowance.returncode != 1 or "tool lease" not in rejected_allowance.stdout:
            raise AssertionError(f"forged owner retained audited allowance\n{rejected_allowance.stdout}")
    finally:
        agents_path.write_bytes(valid_agents_bytes)
    cleanup_with_reviewer = subprocess.run([*tool_command, "cleanup"], cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    leases_after_cleanup = json.loads((tool_project / ".agent/state/tool-leases.json").read_text(encoding="utf-8"))["leases"]
    if cleanup_with_reviewer.returncode or not leases_after_cleanup:
        raise AssertionError(f"product cleanup failed or erased a valid active reviewer lease\n{cleanup_with_reviewer.stdout}")
    illegal = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], cwd=tool_project,
        start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.2)
        dirty_with_reviewer = subprocess.run([*tool_command, "assert-clean"], cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if dirty_with_reviewer.returncode != 1 or f"pid={illegal.pid}" not in dirty_with_reviewer.stdout:
            raise AssertionError(f"foreground lease masked an unrelated unregistered runtime\n{dirty_with_reviewer.stdout}")
    finally:
        if illegal.poll() is None:
            illegal.kill()
            illegal.wait(timeout=5)
    foreground.send_signal(signal.SIGTERM)
    foreground_output = foreground.communicate(timeout=10)[0]
    if foreground.returncode == 0 or json.loads((tool_project / ".agent/state/tool-leases.json").read_text(encoding="utf-8"))["leases"]:
        raise AssertionError(f"interrupted foreground tool did not remove its exact lease\n{foreground_output}")

    forged_ledger = json.loads((tool_project / ".agent/state/agents.json").read_text(encoding="utf-8"))
    forged_ledger["members"][0]["fork_turns"] = 9
    (tool_project / ".agent/state/agents.json").write_text(json.dumps(forged_ledger), encoding="utf-8")
    forged = subprocess.run(
        [*tool_command, "tool-run", "--agent-id", "/root/reviewer", "--name", "forged-review",
         "--timeout", "2", "--", sys.executable, "-c", "print('must not run')"],
        cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if forged.returncode == 0:
        raise AssertionError("forged reviewer ledger bypassed platform/model/context binding")
    forged_ledger["members"][0]["fork_turns"] = 10
    (tool_project / ".agent/state/agents.json").write_text(json.dumps(forged_ledger), encoding="utf-8")

    controller_group_registration = subprocess.run(
        [*tool_command, "register-process", "--pid", str(os.getpgid(0)), "--name", "controller-group"],
        cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if (
        controller_group_registration.returncode == 0
        or "cannot target the controller or its live ancestor process group" not in controller_group_registration.stdout
    ):
        raise AssertionError(
            "manual registration accepted the controller process group\n"
            + controller_group_registration.stdout
        )

    registered = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], cwd=tool_project,
        start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        subprocess.run([*tool_command, "register-process", "--pid", str(registered.pid), "--name", "fixture-server"], cwd=tool_project, check=True)
        registered_dirty = subprocess.run([*tool_command, "assert-clean"], cwd=tool_project, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if registered_dirty.returncode != 1 or "live registered process" not in registered_dirty.stdout:
            raise AssertionError(f"registered product runtime was not handled as registered state\n{registered_dirty.stdout}")
        # The fixture parent owns this process.  End it exactly, then require
        # cleanup to remove the now-stale registration without broad killing.
        registered.terminate()
        registered.wait(timeout=5)
        subprocess.run([*tool_command, "cleanup"], cwd=tool_project, check=True)
        subprocess.run([*tool_command, "assert-clean"], cwd=tool_project, check=True)
    finally:
        if registered.poll() is None:
            registered.kill()
            registered.wait(timeout=5)

    # An implementation that bypasses managed-run/registration is still visible
    # as a project-cwd delta from the captured task baseline.
    unregistered = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], cwd=CONTROL_ROOT, start_new_session=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.2)
        dirty = controller("assert-clean", expected=1)
        if "unregistered project process since baseline" not in dirty.stdout:
            raise AssertionError(f"unregistered project process was not reported\n{dirty.stdout}")
        spoofed_environment = os.environ.copy()
        spoofed_environment["AGENT_SUPERVISOR_PIDS"] = str(unregistered.pid)
        spoofed = subprocess.run(
            [sys.executable, str(CONTROLLER), "assert-clean"], cwd=CONTROL_ROOT,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=20, env=spoofed_environment,
        )
        if spoofed.returncode != 1 or "unregistered project process since baseline" not in spoofed.stdout:
            raise AssertionError(f"caller-supplied supervisor PID hid an unregistered runtime\n{spoofed.stdout}")
    finally:
        try:
            os.killpg(unregistered.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        unregistered.wait(timeout=5)

controller("assert-clean")
_CONTROL_TEMP.cleanup()
print("MANAGED RUNTIME SELF-TEST PASSED: tool leases, leader exit, signals, timeout descendants, baseline delta and Docker identity")
