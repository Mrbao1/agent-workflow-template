#!/usr/bin/env python3
"""Disposable platform-snapshot, liveness and terminal-evidence attacks."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Optional


SOURCE = Path(__file__).resolve().with_name("agentledger.py")
TESTRUN_SOURCE = SOURCE.parents[3] / "scripts/testrun.py"
INPUT_BYTES = b"read-only input"
INPUT_SHA = hashlib.sha256(INPUT_BYTES).hexdigest()
INPUT_INTERNAL = f".agent/state/evidence/agent-input-artifacts/{INPUT_SHA}.blob"
NODE6_PATH = ".agent/state/artifacts/06-implementation.json"
NODE6_VALUE = {
    "schema": "agent-node-implementation/v3", "status": "verified",
    "requirement_contract_sha256": "a" * 64,
    "implementer_agent_id": "attester-contract",
    "changes": [{"path": "managed.txt", "sha256": "b" * 64, "bytes": 1}],
    "checks": [
        {"id": "alpha", "command": [sys.executable, "replay-case.py", "alpha"], "exit_code": 0},
        {"id": "beta", "command": [sys.executable, "replay-case.py", "beta"], "exit_code": 0},
    ],
}
NODE6_BYTES = (json.dumps(NODE6_VALUE, sort_keys=True, separators=(",", ":")) + "\n").encode()
NODE6_SHA = hashlib.sha256(NODE6_BYTES).hexdigest()
NODE6_INTERNAL = f".agent/state/evidence/agent-input-artifacts/{NODE6_SHA}.blob"
PAYLOAD_VALUE = {
    "schema": "agent-task-payload/v2",
    "objective": "exercise one bounded reusable task contract",
    "input_artifacts": [
        {"label": "input.txt", "path": INPUT_INTERNAL, "sha256": INPUT_SHA, "bytes": len(INPUT_BYTES)},
        {"label": NODE6_PATH, "path": NODE6_INTERNAL, "sha256": NODE6_SHA, "bytes": len(NODE6_BYTES)},
    ],
    "shared_constraints": ["Treat input artifacts as read-only", "The dispatch envelope is the sole output authority"],
    "acceptance_criteria": ["Complete the bounded fixture without changing dispatch semantics"],
}
PAYLOAD_VALUE["estimated_tokens"] = (
    sum(item["bytes"] for item in PAYLOAD_VALUE["input_artifacts"])
    + len(json.dumps({
        "objective": PAYLOAD_VALUE["objective"],
        "shared_constraints": PAYLOAD_VALUE["shared_constraints"],
        "acceptance_criteria": PAYLOAD_VALUE["acceptance_criteria"],
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    + 3
) // 4
PAYLOAD_BYTES = (json.dumps(PAYLOAD_VALUE, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
PAYLOAD_SHA = hashlib.sha256(PAYLOAD_BYTES).hexdigest()
PAYLOAD_INTERNAL = f".agent/state/evidence/agent-task-payloads/{PAYLOAD_SHA}.ctx"
PROOF_ATTESTATION = {
    "schema": "agent-review-attestation/v2", "role_type": "reviewer",
    "review_chain_id": None, "review_subject_sha256": PAYLOAD_SHA,
    "predecessor_result_sha256": None, "lenses": [], "clean_replays": [],
    "targeted_cases": [],
}
PROOF_BYTES = (
    "VERDICT PASS P0=0 P1=0 P2=0\nATTESTATION "
    + json.dumps(PROOF_ATTESTATION, sort_keys=True, separators=(",", ":"))
    + "\nfixture review report\n"
).encode()
PROOF_SHA = hashlib.sha256(PROOF_BYTES).hexdigest()


def run(root: Path, *args: str, expected: int = 0) -> str:
    result = subprocess.run(
        [sys.executable, str(root / ".agent/skills/manage-agent-team/scripts/agentledger.py"), *args],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode != expected:
        raise AssertionError(f"{args}: expected {expected}, got {result.returncode}\n{result.stdout}")
    return result.stdout


def candidate_fingerprint(root: Path) -> str:
    result = subprocess.run(
        [sys.executable, "-c", (
            "import json,sys;sys.path.insert(0,'.agent/scripts');import testrun;"
            "print(testrun.candidate_fingerprint(json.load(open('.agent/config.json'))))"
        )],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode:
        raise AssertionError(f"canonical candidate fingerprint failed:\n{result.stdout}")
    return result.stdout.strip()


def snapshot(root: Path, name: str, members: list[dict[str, object]],
             observed_at: Optional[dt.datetime] = None, default_deadline_minutes: int = 5) -> str:
    path = root / f"snapshot-{name}.json"
    observed = (observed_at or dt.datetime.now(dt.timezone.utc)).replace(microsecond=0)
    ledger_path = root / ".agent/state/agents.json"
    try:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        ledger = {}
    known = {item.get("id"): item for item in ledger.get("members", []) if isinstance(item, dict)}
    enriched = []
    for raw_member in members:
        item = dict(raw_member)
        existing = known.get(item.get("id"), {})
        item.setdefault("ledger_epoch", ledger.get("epoch", "e" * 64))
        item.setdefault("root_task_id", existing.get("root_task_id", item.get("id")))
        item.setdefault("role_type", existing.get("role_type", "reviewer"))
        item.setdefault("started_at", existing.get("started_at", observed.isoformat()))
        item.setdefault("deadline_at", existing.get("deadline_at", (observed + dt.timedelta(minutes=default_deadline_minutes)).isoformat()))
        item.setdefault("redispatch_count", existing.get("redispatch_count", 0))
        item.setdefault("task_payload_sha256", existing.get("task_payload_sha256", PAYLOAD_SHA))
        if "handoff_envelope_sha256" not in item:
            if existing:
                item["handoff_envelope_sha256"] = existing["handoff_envelope_sha256"]
            else:
                is_review = item["role_type"] in {"reviewer", "adversarial", "cross", "integrator"}
                envelope = {
                    "schema": "agent-handoff-envelope/v3", "ledger_epoch": item["ledger_epoch"],
                    "agent_id": item["id"], "root_task_id": item["root_task_id"],
                    "role_type": item["role_type"], "model": item.get("model", "gpt-5.6-sol"),
                    "fork_turns": item.get("fork_turns", 0), "started_at": item["started_at"],
                    "deadline_at": item["deadline_at"], "redispatch_count": item["redispatch_count"],
                    "task_payload_path": PAYLOAD_INTERNAL, "task_payload_sha256": item["task_payload_sha256"],
                    "allowed_evidence_paths": ["proof.txt"],
                    "forbidden_actions": ["approve-node7", "modify-managed-files"],
                    "start_barrier": "LEDGER_REGISTERED",
                    "review_chain_id": None,
                    "review_subject_sha256": item["task_payload_sha256"] if is_review else None,
                    "predecessor_result_sha256": None,
                    "result_report_path": "proof.txt" if is_review else None,
                }
                envelope_path = root / f"envelope-{re.sub(r'[^A-Za-z0-9._-]', '_', str(item['id']))}.json"
                envelope_path.write_text(json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
                item["handoff_envelope_sha256"] = hashlib.sha256(envelope_path.read_bytes()).hexdigest()
        enriched.append(item)
    path.write_text(json.dumps({
        "schema": "agent-platform-snapshot/v3",
        "observed_at": observed.isoformat(),
        "members": enriched,
    }), encoding="utf-8")
    return path.name


def platform_member(agent_id: str, status: str, cursor: int = 0, message: str = "", model: str = "gpt-5.6-sol",
                    fork_turns: object = 0, envelope_sha: Optional[str] = None,
                    role_type: Optional[str] = None, root_task_id: Optional[str] = None,
                    redispatch_count: Optional[int] = None) -> dict[str, object]:
    value: dict[str, object] = {
        "id": agent_id, "status": status, "model": model, "fork_turns": fork_turns,
        "task_payload_sha256": PAYLOAD_SHA, "message_cursor": cursor,
    }
    if envelope_sha is not None:
        value["handoff_envelope_sha256"] = envelope_sha
    if role_type is not None:
        value["role_type"] = role_type
    if root_task_id is not None:
        value["root_task_id"] = root_task_id
    if redispatch_count is not None:
        value["redispatch_count"] = redispatch_count
    if message or cursor > 0:
        if message:
            committed_message = message
        elif status == "completed":
            committed_message = f"FINAL_RESULT PASS P0=0 P1=0 P2=0 report_sha256={PROOF_SHA}"
        else:
            committed_message = f"{agent_id}:{status}:{cursor}"
        value["message_sha256"] = hashlib.sha256(committed_message.encode()).hexdigest()
        value["message_kind"] = "commentary"
    return value


def age_checks(root: Path) -> None:
    path = root / ".agent/state/agents.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=31)).replace(microsecond=0).isoformat()
    for item in value["members"]:
        if item.get("status") == "active":
            item["last_check_at"] = old
    path.write_text(json.dumps(value), encoding="utf-8")


def prepare_dispatch(root: Path, agent_id: str, role_type: str = "reviewer", model: str = "gpt-5.6-sol",
                     fork_turns: int = 0, root_task_id: Optional[str] = None,
                     redispatch_count: int = 0, expected: int = 0) -> str:
    envelope_name = f"envelope-{re.sub(r'[^A-Za-z0-9._-]', '_', agent_id)}.json"
    args = [
        "prepare", "--id", agent_id, "--role-type", role_type, "--model", model,
        "--fork-turns", str(fork_turns), "--redispatch-count", str(redispatch_count),
        "--task-payload", "payload.txt", "--handoff-envelope", envelope_name,
    ]
    if root_task_id is not None:
        args.extend(["--root-task-id", root_task_id])
    return run(root, *args, expected=expected)


def write_review_envelope(root: Path, agent_id: str, role_type: str, chain_id: str,
                          predecessor_sha: Optional[str], report_path: str,
                          allowed_paths: Optional[list[str]] = None,
                          started_at: Optional[dt.datetime] = None,
                          subject_sha: str = PAYLOAD_SHA,
                          root_task_id: str = "formal-chain",
                          redispatch_count: int = 0) -> tuple[str, str, dt.datetime]:
    ledger = json.loads((root / ".agent/state/agents.json").read_text(encoding="utf-8"))
    started = (started_at or dt.datetime.now(dt.timezone.utc)).replace(microsecond=0)
    value = {
        "schema": "agent-handoff-envelope/v3", "ledger_epoch": ledger["epoch"],
        "agent_id": agent_id, "root_task_id": root_task_id, "role_type": role_type,
        "model": "gpt-5.6-sol", "fork_turns": 0, "started_at": started.isoformat(),
        "deadline_at": (started + dt.timedelta(minutes=5)).isoformat(),
        "redispatch_count": redispatch_count,
        "task_payload_path": PAYLOAD_INTERNAL, "task_payload_sha256": PAYLOAD_SHA,
        "allowed_evidence_paths": allowed_paths or [report_path],
        "forbidden_actions": ["approve-node7", "modify-managed-files"],
        "start_barrier": "LEDGER_REGISTERED", "review_chain_id": chain_id,
        "review_subject_sha256": subject_sha, "predecessor_result_sha256": predecessor_sha,
        "result_report_path": report_path,
    }
    if role_type == "integrator":
        observed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        preflight_path = root / f"preflight-{agent_id}.json"
        preflight_path.write_text(json.dumps({
            "schema": "agent-execution-preflight/v1", "environment": "local",
            "authority": "default", "candidate_sha256": candidate_fingerprint(root),
            "observed_at": observed.isoformat(),
            "expires_at": (observed + dt.timedelta(minutes=15)).isoformat(),
            "status": "passed", "capabilities": ["python-runtime"],
            "checks": [{"capability": "python-runtime", "status": "passed", "evidence": "fixture"}],
        }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        value["execution_profile"] = {
            "environment": "local", "authority": "default",
            "capabilities": ["python-runtime"],
            "preflight_receipt": {
                "path": preflight_path.name,
                "sha256": hashlib.sha256(preflight_path.read_bytes()).hexdigest(),
                "bytes": len(preflight_path.read_bytes()),
            },
        }
    name = f"envelope-{agent_id}.json"
    path = root / name
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return name, hashlib.sha256(path.read_bytes()).hexdigest(), started


def review_report_bytes(role_type: str, chain_id: str, predecessor_sha: Optional[str],
                        lenses: list[str], clean_replays: list[dict[str, object]],
                        verdict: str = "PASS", p0: int = 0, p1: int = 0,
                        p2: int = 0, targeted_cases: Optional[list[str]] = None) -> bytes:
    attestation = {
        "schema": "agent-review-attestation/v2", "role_type": role_type,
        "review_chain_id": chain_id, "review_subject_sha256": PAYLOAD_SHA,
        "predecessor_result_sha256": predecessor_sha, "lenses": lenses,
        "clean_replays": clean_replays, "targeted_cases": targeted_cases or [],
    }
    return (
        f"VERDICT {verdict} P0={p0} P1={p1} P2={p2}\nATTESTATION "
        + json.dumps(attestation, sort_keys=True, separators=(",", ":"))
        + f"\n{role_type} fixture report\n"
    ).encode()


def cross_report_bytes(root: Path, agent_id: str, chain_id: str, predecessor_sha: str) -> bytes:
    evidence_bytes = b"cross scenario fixture evidence\n"
    evidence_sha = hashlib.sha256(evidence_bytes).hexdigest()
    evidence_path = root / f".agent/state/evidence/scenario-evidence/{evidence_sha}.evidence"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_bytes(evidence_bytes)
    evidence = {"path": str(evidence_path.relative_to(root)), "sha256": evidence_sha, "bytes": len(evidence_bytes)}
    scenarios = [
        {
            "id": f"scenario-{index + 1}", "lens": lens,
            "requirement_ids": [f"REQ-{index + 1}"],
            "assertions": [f"{lens} assertion is observable"],
            "evidence": [evidence], "result": "passed",
        }
        for index, lens in enumerate((
            "product", "architecture", "qa", "security", "operations",
            "ai-workflow-new-project-adopter",
        ))
    ]
    scenario_receipt = {
        "schema": "agent-role-scenario-receipt/v1", "review_chain_id": chain_id,
        "review_subject_sha256": PAYLOAD_SHA, "reviewer_agent_id": agent_id,
        "scenarios": scenarios,
    }
    first_two = review_report_bytes(
        "cross", chain_id, predecessor_sha,
        [scenario["lens"] for scenario in scenarios], [],
    ).decode().splitlines()[:2]
    return (
        "\n".join([
            *first_two,
            "SCENARIO_RECEIPT " + json.dumps(scenario_receipt, sort_keys=True, separators=(",", ":")),
            "cross fixture report",
        ]) + "\n"
    ).encode()


def write_clean_replay(root: Path, suffix: str, run_id: str, replay_time: dt.datetime,
                       runner_receipt: dict[str, object]) -> dict[str, object]:
    replay_path = root / f"replay-{suffix}.json"
    output_path = root / f"replay-{suffix}-full-chain.log"
    output_path.write_text("full-chain passed\n", encoding="utf-8")
    output_receipt = {
        "path": output_path.name, "sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
        "bytes": len(output_path.read_bytes()),
    }
    timestamp = replay_time.replace(microsecond=0).isoformat()
    replay_case = {
        "id": "full-chain", "run_id": run_id,
        "candidate_sha256": candidate_fingerprint(root),
        "command": ["python3", "full-chain.py"],
        "started_at": timestamp, "finished_at": timestamp, "exit_code": 0,
        "outcome": "completed", "cleanup": "passed", "output": output_receipt,
    }
    replay_case["case_sha256"] = hashlib.sha256(
        json.dumps(replay_case, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    replay_path.write_text(json.dumps({
        "schema": "agent-test-receipt/v3", "run_id": run_id,
        "candidate_sha256": candidate_fingerprint(root),
        "runner": runner_receipt, "cases": [replay_case],
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return {
        "source_path": replay_path.name,
        "sha256": hashlib.sha256(replay_path.read_bytes()).hexdigest(),
        "bytes": len(replay_path.read_bytes()),
    }


def write_replay_plan(root: Path, suffix: str, run_id: str,
                      checks: Optional[list[dict[str, object]]] = None,
                      timeout: int = 30) -> str:
    name = f"replay-plan-{suffix}.json"
    selected = checks if checks is not None else NODE6_VALUE["checks"]
    (root / name).write_text(json.dumps({
        "schema": "agent-replay-plan/v1", "run_id": run_id,
        "receipt_path": f"replay-{suffix}.json",
        "cases": [{
            "id": check["id"], "command": check["command"], "timeout_seconds": timeout,
            "expected_exit_code": 0, "expected_outcome": "completed",
            "expected_cleanup": "passed",
            "expected_output_path": f"replay-{suffix}-{check['id']}.log",
        } for check in selected],
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return name


def run_managed_replay(root: Path, run_id: str, expected: int = 0) -> str:
    return run(root, "replay-execute", "--integrator-id", "formal-integrator",
               "--run-id", run_id, expected=expected)


def replay_source_receipt(root: Path, suffix: str) -> dict[str, object]:
    path = root / f"replay-{suffix}.json"
    data = path.read_bytes()
    return {"source_path": path.name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def register_formal(root: Path, agent_id: str, role_type: str, envelope_sha: str,
                    started: dt.datetime, seed: str,
                    root_task_id: str = "formal-chain",
                    redispatch_count: int = 0) -> None:
    item = platform_member(
        agent_id, "running", envelope_sha=envelope_sha, role_type=role_type,
        root_task_id=root_task_id, redispatch_count=redispatch_count,
    )
    item["started_at"] = started.isoformat()
    item["deadline_at"] = (started + dt.timedelta(minutes=5)).isoformat()
    registration = snapshot(root, f"register-{agent_id}", [item], observed_at=started)
    run(root, "register", "--id", agent_id, "--root-task-id", root_task_id,
        "--role-type", role_type, "--role", role_type, "--task", role_type,
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt",
        "--handoff-envelope", f"envelope-{agent_id}.json", "--deadline-minutes", "5",
        "--progress-hash", seed, "--platform-snapshot", registration)


with tempfile.TemporaryDirectory(prefix="agent-ledger-test-") as raw:
    root = Path(raw)
    scripts = root / ".agent/skills/manage-agent-team/scripts"
    state = root / ".agent/state"
    scripts.mkdir(parents=True)
    state.mkdir(parents=True)
    shutil.copy2(SOURCE, scripts / "agentledger.py")
    (root / ".agent/scripts").mkdir(exist_ok=True)
    shutil.copytree(TESTRUN_SOURCE.parent / "workflowlib", root / ".agent/scripts/workflowlib")
    (root / ".agent/scripts/agentctl.py").write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\nimport sys\n"
        "if 'budget-gate' in sys.argv and '--action' in sys.argv:\n"
        " p=Path('.agent/state/budget-actions.log')\n"
        " p.write_text((p.read_text() if p.exists() else '') + sys.argv[sys.argv.index('--action')+1] + '\\n')\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    shutil.copy2(TESTRUN_SOURCE, root / ".agent/scripts/testrun.py")
    shutil.copy2(TESTRUN_SOURCE.with_name("humandecision.py"), root / ".agent/scripts/humandecision.py")
    platform_adapter = root / "platform-adapter.py"
    platform_adapter.write_text(
        "#!/usr/bin/env python3\nimport hashlib,sys\np=sys.argv[sys.argv.index('--snapshot')+1]\nprint('VERIFIED PLATFORM SNAPSHOT sha256='+hashlib.sha256(open(p,'rb').read()).hexdigest())\n",
        encoding="utf-8",
    )
    platform_adapter.chmod(0o755)
    # Positive platform-protocol fixtures simulate the provider trust boundary
    # through a test-only sitecustomize patch scoped to this one adapter. The
    # production path still rejects this Agent-writable executable.
    site_dir = root / "test-site"
    site_dir.mkdir()
    (site_dir / "sitecustomize.py").write_text(
        "import os,sys\nfrom pathlib import Path\n"
        "sys.path.insert(0,str(Path.cwd()/'.agent/scripts'))\n"
        "import humandecision\n_original=humandecision.adapter_path\n"
        "def _fixture(root,raw):\n"
        " return Path(raw).resolve() if str(Path(str(raw)).resolve())==os.environ.get('AGENT_TEST_PLATFORM_ADAPTER') else _original(root,raw)\n"
        "humandecision.adapter_path=_fixture\n",
        encoding="utf-8",
    )
    os.environ["AGENT_TEST_PLATFORM_ADAPTER"] = str(platform_adapter.resolve())
    os.environ["PYTHONPATH"] = str(site_dir) + os.pathsep + os.environ.get("PYTHONPATH", "")
    (root / ".agent/config.json").write_text(json.dumps({
        "routing": {"modes": {
            "fast": {"max_child_agents": 0, "token_budget": 6000},
            "standard": {"max_child_agents": 1, "token_budget": 20000},
            "release": {
                "max_child_agents": 3, "clean_reruns": 1,
                "token_budget": 1000000,
                "wall_time_minutes": 45, "max_automatic_test_attempts": 1,
            },
        }},
        "testing": {
            "reviewer_targeted_case_limit": 0,
            "max_automatic_full_chain_attempts": 1,
            "infrastructure_failure_consumes_code_retry": False,
            "attempt_classes": ["candidate", "test", "infrastructure"],
            "budget_registry": ".agent/state/test-budget.json",
            "budget_receipt_dir": ".agent/state/evidence/test-budget",
        },
        "scope": {
            "fingerprint_paths": [".agent/scripts", "replay-case.py"],
            "product_roots": [".agent/scripts"],
        },
        "agent_control": {
            "default_model": "gpt-5.6-sol", "allow_model_fallback": False,
            "context_strategy": "long-window-capsule", "max_fork_turns": 10, "capacity_retry_limit": 1,
            "inherit_parent_history": False,
            "dispatch_payload_token_limits": {"fast": 0, "standard": 16000, "release": 32000},
            "max_task_payload_input_count": 24, "max_task_payload_single_bytes": 131072,
            "max_task_payload_total_bytes": 262144, "max_task_payload_estimated_tokens": 65536,
            "platform_limit": 4, "reserve_root_slots": 1, "status_interval_seconds": 30,
            "monitor_grace_seconds": 30, "stall_timeout_seconds": 300,
            "allowed_role_types": ["worker", "researcher", "documentation-worker", "implementer", "reviewer", "adversarial", "cross", "integrator"],
            "review_role_types": ["reviewer", "adversarial", "cross", "integrator"],
            "status_request_after_unchanged_checks": 1,
            "platform_observer": {
                "source": "orchestrator-tool-transcript", "automatic_release_trust": False,
                "human_verification_required": True, "signed_adapter": str(platform_adapter),
            },
            "human_decision_observer": {
                "source": "orchestrator-user-message", "automatic_gate_trust": False,
                "human_verification_required": True,
                "allow_current_chat_local_release": False, "signed_adapter": None,
                "max_receipt_age_seconds": 900,
            },
            "max_redispatch": 1,
        },
    }), encoding="utf-8")
    (state / "TASK.json").write_text(json.dumps({
        "mode": "release", "title": "fixture", "current_node": 7,
        "token_budget": 1000000, "tokens_used": 0,
        "accepted_nodes": [0, 1, 2, 3, 4, 5, 6],
        "node_artifacts": {"6": {"path": NODE6_PATH, "sha256": NODE6_SHA, "bytes": len(NODE6_BYTES)}},
    }), encoding="utf-8")
    (state / "agents.json").write_text("{}", encoding="utf-8")
    (root / "proof.txt").write_bytes(PROOF_BYTES)
    (root / "input.txt").write_bytes(INPUT_BYTES)
    sealed_input = root / INPUT_INTERNAL
    sealed_input.parent.mkdir(parents=True, exist_ok=True)
    sealed_input.write_bytes(INPUT_BYTES)
    sealed_input.chmod(0o444)
    node6_path = root / NODE6_PATH
    node6_path.parent.mkdir(parents=True, exist_ok=True)
    node6_path.write_bytes(NODE6_BYTES)
    sealed_node6 = root / NODE6_INTERNAL
    sealed_node6.parent.mkdir(parents=True, exist_ok=True)
    sealed_node6.write_bytes(NODE6_BYTES)
    sealed_node6.chmod(0o444)
    (root / "payload.txt").write_bytes(PAYLOAD_BYTES)
    seed = hashlib.sha256(b"seed").hexdigest()
    empty = snapshot(root, "empty", [])

    run(root, "init", expected=1)
    run(root, "init", "--platform-snapshot", empty)
    empty_watchdog = json.loads(run(root, "watchdog-plan"))
    if (
        empty_watchdog.get("terminal") is not False
        or empty_watchdog.get("active_ids") != []
        or empty_watchdog.get("host_scheduler", {}).get("required") is not False
        or empty_watchdog.get("terminal_reason") != "agent ledger has no main-task completion authority"
    ):
        raise AssertionError("empty Agent ledger was misreported as main-task completion")

    # New dispatches must carry their complete bounded payload instead of
    # replaying parent-chat turns. Historical ledger entries may still record
    # an older non-zero fork window, but no new prepare may create one.
    snapshot(root, "history-inheritance-rejected", [
        platform_member("history-inheritance-rejected", "running", fork_turns=1),
    ])
    policy_ledger_before = (state / "agents.json").read_bytes()
    policy_evidence_before = sorted(
        str(path.relative_to(root)) for path in (state / "evidence").rglob("*") if path.is_file()
    )
    prepare_dispatch(root, "history-inheritance-rejected", fork_turns=1, expected=1)
    if (state / "agents.json").read_bytes() != policy_ledger_before:
        raise AssertionError("rejected parent-history inheritance mutated the ledger")
    if sorted(str(path.relative_to(root)) for path in (state / "evidence").rglob("*") if path.is_file()) != policy_evidence_before:
        raise AssertionError("rejected parent-history inheritance published internal evidence")

    # The static storage envelope remains generous for migration/replay, while
    # tighter mode-specific dispatch ceilings fail closed without truncating
    # the capsule-derived semantics or input bytes.
    config_path = root / ".agent/config.json"
    task_path = state / "TASK.json"

    def seal_exact_estimate(mode: str, estimate: int, name: str, expected: int) -> None:
        objective = f"exercise the {mode} dispatch payload boundary {estimate}"
        constraints = ["Preserve every required input byte"]
        acceptance = ["Reject the whole payload instead of truncating it"]
        semantic_bytes = len(json.dumps({
            "objective": objective,
            "shared_constraints": constraints,
            "acceptance_criteria": acceptance,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        input_size = estimate * 4 - semantic_bytes
        if input_size < 1 or input_size > 131072:
            raise AssertionError("dispatch boundary fixture cannot fit the static single-file limit")
        input_path = root / f"{name}.bin"
        input_bytes = (name.encode("utf-8") or b"x")
        input_path.write_bytes((input_bytes * ((input_size + len(input_bytes) - 1) // len(input_bytes)))[:input_size])
        draft_path = root / f"{name}-draft.json"
        draft_path.write_text(json.dumps({
            "schema": "agent-task-payload-draft/v1",
            "objective": objective,
            "input_artifacts": [input_path.name],
            "shared_constraints": constraints,
            "acceptance_criteria": acceptance,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        task_value = json.loads(task_path.read_text(encoding="utf-8"))
        task_value["mode"] = mode
        task_value["token_budget"] = json.loads(config_path.read_text(encoding="utf-8"))["routing"]["modes"][mode]["token_budget"]
        task_path.write_text(json.dumps(task_value), encoding="utf-8")
        mode_ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
        mode_ledger["token_accounting"]["token_budget"] = task_value["token_budget"]
        (state / "agents.json").write_text(json.dumps(mode_ledger), encoding="utf-8")
        output_path = root / f"{name}-sealed.json"
        evidence_before = sorted(
            (str(path.relative_to(root)), hashlib.sha256(path.read_bytes()).hexdigest())
            for path in (state / "evidence").rglob("*") if path.is_file()
        )
        source_before = input_path.read_bytes()
        result = run(root, "seal-payload", "--draft", draft_path.name,
                     "--output", output_path.name, expected=expected)
        if expected == 0:
            sealed = json.loads(output_path.read_text(encoding="utf-8"))
            if sealed.get("estimated_tokens") != estimate:
                raise AssertionError("accepted dispatch boundary changed the exact payload estimate")
        elif (
            output_path.exists()
            or input_path.read_bytes() != source_before
            or sorted(
                (str(path.relative_to(root)), hashlib.sha256(path.read_bytes()).hexdigest())
                for path in (state / "evidence").rglob("*") if path.is_file()
            ) != evidence_before
            or "exceeds the" not in result
        ):
            raise AssertionError("rejected dispatch payload was truncated or published partial evidence")

    seal_exact_estimate("fast", 1000, "fast-child-forbidden", 1)
    seal_exact_estimate("standard", 16000, "standard-boundary", 0)
    seal_exact_estimate("standard", 16001, "standard-overflow", 1)
    seal_exact_estimate("release", 32000, "release-boundary", 0)
    seal_exact_estimate("release", 32001, "release-overflow", 1)
    task_value = json.loads(task_path.read_text(encoding="utf-8"))
    task_value.update({"mode": "release", "token_budget": 1000000})
    task_path.write_text(json.dumps(task_value), encoding="utf-8")
    release_ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    release_ledger["token_accounting"]["token_budget"] = 1000000
    (state / "agents.json").write_text(json.dumps(release_ledger), encoding="utf-8")

    # A pre-migration fork=10 preparation remains valid and exact prepare is
    # idempotent. It may register/finish, but its replacement is a genuinely
    # new child and must use a fresh fork=0 envelope and platform receipt.
    historical_id = "historical-fork-ten"
    historical_started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    historical_envelope = {
        "schema": "agent-handoff-envelope/v3",
        "ledger_epoch": json.loads((state / "agents.json").read_text())["epoch"],
        "agent_id": historical_id, "root_task_id": historical_id,
        "role_type": "worker", "model": "gpt-5.6-sol", "fork_turns": 0,
        "started_at": historical_started.isoformat(),
        "deadline_at": (historical_started + dt.timedelta(minutes=5)).isoformat(),
        "redispatch_count": 0, "task_payload_path": PAYLOAD_INTERNAL,
        "task_payload_sha256": PAYLOAD_SHA, "allowed_evidence_paths": ["proof.txt"],
        "forbidden_actions": ["approve-node7", "modify-managed-files"],
        "start_barrier": "LEDGER_REGISTERED", "review_chain_id": None,
        "review_subject_sha256": None, "predecessor_result_sha256": None,
        "result_report_path": None,
    }
    historical_envelope_path = root / f"envelope-{historical_id}.json"
    historical_envelope_path.write_text(
        json.dumps(historical_envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    prepare_dispatch(root, historical_id, role_type="worker")
    historical_ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    historical_preparation = next(
        item for item in historical_ledger["prepared_dispatches"] if item["id"] == historical_id
    )
    historical_envelope["fork_turns"] = 10
    historical_envelope_data = (
        json.dumps(historical_envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    historical_envelope_path.write_bytes(historical_envelope_data)
    historical_envelope_sha = hashlib.sha256(historical_envelope_data).hexdigest()
    historical_internal = state / "evidence/agent-handoff-envelopes" / f"{historical_envelope_sha}.json"
    historical_internal.write_bytes(historical_envelope_data); historical_internal.chmod(0o444)
    historical_record = {
        "path": str(historical_internal.relative_to(root)),
        "sha256": historical_envelope_sha, "bytes": len(historical_envelope_data),
    }
    historical_preparation.update({
        "fork_turns": 10,
        "handoff_envelope_sha256": historical_envelope_sha,
        "handoff_envelope_evidence": historical_record,
    })
    (state / "agents.json").write_text(json.dumps(historical_ledger), encoding="utf-8")
    run(root, "validate")
    historical_before_repeat = (state / "agents.json").read_bytes()
    prepare_dispatch(root, historical_id, role_type="worker", fork_turns=10)
    if (state / "agents.json").read_bytes() != historical_before_repeat:
        raise AssertionError("exact historical preparation replay was not idempotent")
    historical_platform_item = platform_member(
        historical_id, "running", fork_turns=10, envelope_sha=historical_envelope_sha,
        role_type="worker", root_task_id=historical_id,
    )
    historical_platform_item["started_at"] = historical_envelope["started_at"]
    historical_platform_item["deadline_at"] = historical_envelope["deadline_at"]
    historical_registration = snapshot(
        root, "historical-fork-ten-register", [historical_platform_item], observed_at=historical_started,
    )
    run(root, "register", "--id", historical_id, "--role-type", "worker", "--role", "worker",
        "--task", "historical worker", "--model", "gpt-5.6-sol", "--fork-turns", "10",
        "--task-payload", "payload.txt", "--handoff-envelope", historical_envelope_path.name,
        "--deadline-minutes", "5", "--progress-hash", seed,
        "--platform-snapshot", historical_registration)
    historical_terminal = snapshot(root, "historical-fork-ten-terminal", [
        platform_member(historical_id, "interrupted", fork_turns=10, role_type="worker"),
    ])
    run(root, "finish", "--id", historical_id, "--status", "interrupted",
        "--conclusion", "historical child interrupted", "--platform-snapshot", historical_terminal)

    retry_id = "historical-fork-zero-retry"
    retry_started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    retry_envelope = dict(historical_envelope)
    retry_envelope.update({
        "agent_id": retry_id, "fork_turns": 0, "redispatch_count": 1,
        "started_at": retry_started.isoformat(),
        "deadline_at": (retry_started + dt.timedelta(minutes=5)).isoformat(),
    })
    retry_envelope_path = root / f"envelope-{retry_id}.json"
    retry_envelope_path.write_text(
        json.dumps(retry_envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    retry_envelope_sha = hashlib.sha256(retry_envelope_path.read_bytes()).hexdigest()
    prepare_dispatch(root, retry_id, role_type="worker", root_task_id=historical_id, redispatch_count=1)
    retry_item = platform_member(
        retry_id, "running", fork_turns=0, envelope_sha=retry_envelope_sha,
        role_type="worker", root_task_id=historical_id, redispatch_count=1,
    )
    retry_item["started_at"] = retry_envelope["started_at"]
    retry_item["deadline_at"] = retry_envelope["deadline_at"]
    retry_registration = snapshot(
        root, "historical-fork-zero-retry-register", [retry_item], observed_at=retry_started,
    )
    run(root, "redispatch", "--from-id", historical_id, "--to-id", retry_id,
        "--handoff-envelope", retry_envelope_path.name, "--deadline-minutes", "5",
        "--platform-snapshot", retry_registration)
    retry_terminal = snapshot(root, "historical-fork-zero-retry-terminal", [
        platform_member(retry_id, "completed", fork_turns=0, role_type="worker", redispatch_count=1),
    ])
    run(root, "finish", "--id", retry_id, "--status", "completed",
        "--conclusion", "replacement completed without parent history", "--platform-snapshot", retry_terminal)
    run(root, "validate")
    historical_members = {
        item["id"]: item for item in json.loads((state / "agents.json").read_text())["members"]
        if item["id"] in {historical_id, retry_id}
    }
    if (
        historical_members[historical_id]["fork_turns"] != 10
        or historical_members[retry_id]["fork_turns"] != 0
        or historical_members[historical_id]["redispatched_to"] != retry_id
    ):
        raise AssertionError("historical fork audit or zero-history redispatch contract was lost")

    # A no-write implementer that only commits its exact implementation
    # attestation is acceptance work. It must use the review budget action at
    # the compact watermark without gaining a reviewer role.
    ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    attester_started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    attester_envelope = {
        "schema": "agent-handoff-envelope/v3", "ledger_epoch": ledger["epoch"],
        "agent_id": "attester", "root_task_id": "attester", "role_type": "implementer",
        "model": "gpt-5.6-sol", "fork_turns": 0,
        "started_at": attester_started.isoformat(),
        "deadline_at": (attester_started + dt.timedelta(minutes=5)).isoformat(),
        "redispatch_count": 0, "task_payload_path": PAYLOAD_INTERNAL,
        "task_payload_sha256": PAYLOAD_SHA,
        "allowed_evidence_paths": [
            ".agent/state/evidence/implementation-attestation-budget-test.json",
        ],
        "forbidden_actions": ["approve-node7", "modify-managed-files"],
        "start_barrier": "LEDGER_REGISTERED", "review_chain_id": None,
        "review_subject_sha256": None, "predecessor_result_sha256": None,
        "result_report_path": None,
    }
    (root / "envelope-attester.json").write_text(
        json.dumps(attester_envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    prepare_dispatch(root, "attester", role_type="implementer")
    prepared_once = (state / "agents.json").read_bytes()
    prepare_dispatch(root, "attester", role_type="implementer")
    if (state / "agents.json").read_bytes() != prepared_once:
        raise AssertionError("repeated prepare changed the atomic token reservation")
    prepared_watchdog_ledger = (state / "agents.json").read_bytes()
    expired_preparation = json.loads(prepared_watchdog_ledger)
    next(
        item for item in expired_preparation["prepared_dispatches"] if item["id"] == "attester"
    )["prepared_at"] = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=301)
    ).replace(microsecond=0).isoformat()
    (state / "agents.json").write_text(json.dumps(expired_preparation), encoding="utf-8")
    expired_plan = json.loads(run(root, "watchdog-plan"))
    if not any(
        action.get("action") == "cancel-prepare"
        and action.get("id") == "attester"
        and action.get("reason") == "prepared-dispatch-expired"
        for action in expired_plan.get("actions", [])
    ):
        raise AssertionError("expired preparation lacks a bounded cancel action")
    (state / "agents.json").write_bytes(prepared_watchdog_ledger)
    actions = (state / "budget-actions.log").read_text(encoding="utf-8").splitlines()
    if not actions or actions[-1] != "spawn-review-agent":
        raise AssertionError("attestation-only implementer was misclassified as new coding scope")
    run(root, "cancel-prepare", "--id", "attester")
    run(root, "cancel-prepare", "--id", "attester")
    cancelled_ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    cancelled = next(item for item in cancelled_ledger["prepared_dispatches"] if item["id"] == "attester")
    if cancelled["token_reservation"]["status"] != "released":
        raise AssertionError("cancel did not release its prepare-time token reservation")
    # A plausible schema alias must be rejected before completion; the exact
    # eight-field, current-Node6-bound implementer result then succeeds.
    contract_id = "attester-contract"
    contract_path = ".agent/state/evidence/implementation-attestation-contract-test.json"
    contract_started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    contract_envelope = dict(attester_envelope)
    contract_envelope.update({
        "agent_id": contract_id, "root_task_id": contract_id,
        "started_at": contract_started.isoformat(),
        "deadline_at": (contract_started + dt.timedelta(minutes=5)).isoformat(),
        "allowed_evidence_paths": [contract_path],
    })
    (root / f"envelope-{contract_id}.json").write_text(
        json.dumps(contract_envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    prepare_dispatch(root, contract_id, role_type="implementer")
    contract_envelope_sha = hashlib.sha256((root / f"envelope-{contract_id}.json").read_bytes()).hexdigest()
    contract_member = platform_member(
        contract_id, "running", role_type="implementer", envelope_sha=contract_envelope_sha,
    )
    contract_member["started_at"] = contract_envelope["started_at"]
    contract_member["deadline_at"] = contract_envelope["deadline_at"]
    contract_registration = snapshot(
        root, "register-attester-contract", [contract_member], observed_at=contract_started,
    )
    run(root, "register", "--id", contract_id, "--role-type", "implementer", "--role", "attester",
        "--task", "verify Node6", "--model", "gpt-5.6-sol", "--fork-turns", "0",
        "--task-payload", "payload.txt", "--handoff-envelope", f"envelope-{contract_id}.json",
        "--deadline-minutes", "5", "--progress-hash", hashlib.sha256(b"contract").hexdigest(),
        "--platform-snapshot", contract_registration)
    registered_once = (state / "agents.json").read_bytes()
    run(root, "register", "--id", contract_id, "--role-type", "implementer", "--role", "attester",
        "--task", "verify Node6", "--model", "gpt-5.6-sol", "--fork-turns", "0",
        "--task-payload", "payload.txt", "--handoff-envelope", f"envelope-{contract_id}.json",
        "--deadline-minutes", "5", "--progress-hash", hashlib.sha256(b"contract").hexdigest(),
        "--platform-snapshot", contract_registration)
    if (state / "agents.json").read_bytes() != registered_once:
        raise AssertionError("repeated register changed or duplicated the token reservation")
    node6_receipt = {"path": NODE6_PATH, "sha256": NODE6_SHA, "bytes": len(NODE6_BYTES)}
    implementation = {
        "schema": "implementation-attestation/v1", "agent_id": contract_id,
        "root_task_id": contract_id, "candidate_review_subject_sha256": PAYLOAD_SHA,
        "requirement_contract_sha256": NODE6_VALUE["requirement_contract_sha256"],
        "node6_artifact": node6_receipt, "changes": NODE6_VALUE["changes"],
        "checks": NODE6_VALUE["checks"],
    }
    implementation_path = root / contract_path
    implementation_path.parent.mkdir(parents=True, exist_ok=True)
    implementation_path.write_text(json.dumps(implementation), encoding="utf-8")
    contract_terminal = snapshot(
        root, "terminal-attester-contract",
        [platform_member(contract_id, "completed", 1, role_type="implementer")],
    )
    run(root, "finish", "--id", contract_id, "--status", "completed",
        "--conclusion", "implementation complete", "--evidence", contract_path,
        "--platform-snapshot", contract_terminal, expected=1)
    implementation["schema"] = "agent-implementation-attestation/v1"
    implementation_path.write_text(json.dumps(implementation), encoding="utf-8")
    run(root, "finish", "--id", contract_id, "--status", "completed",
        "--conclusion", "implementation complete", "--evidence", contract_path,
        "--platform-snapshot", contract_terminal)
    finished_once = (state / "agents.json").read_bytes()
    run(root, "finish", "--id", contract_id, "--status", "completed",
        "--conclusion", "implementation complete", "--evidence", contract_path,
        "--platform-snapshot", contract_terminal)
    if (state / "agents.json").read_bytes() != finished_once:
        raise AssertionError("repeated finish charged the child payload twice")
    replacement_node6 = dict(NODE6_VALUE)
    replacement_node6["changes"] = [
        *NODE6_VALUE["changes"],
        {"path": "rollback-repair.txt", "sha256": "c" * 64, "bytes": 1},
    ]
    node6_path.write_text(
        json.dumps(replacement_node6, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    run(root, "validate")
    node6_path.write_bytes(NODE6_BYTES)
    draft_payload = {
        "schema": "agent-task-payload-draft/v1",
        "objective": PAYLOAD_VALUE["objective"],
        "input_artifacts": ["input.txt", NODE6_PATH],
        "shared_constraints": PAYLOAD_VALUE["shared_constraints"],
        "acceptance_criteria": PAYLOAD_VALUE["acceptance_criteria"],
    }
    (root / "payload-draft.json").write_text(
        json.dumps(draft_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    run(root, "seal-payload", "--draft", "payload-draft.json", "--output", "sealed-payload.json")
    if json.loads((root / "sealed-payload.json").read_text(encoding="utf-8")) != PAYLOAD_VALUE:
        raise AssertionError("sealed payload did not bind exact immutable input bytes")
    task_value = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    accounting = json.loads((state / "agents.json").read_text(encoding="utf-8"))["token_accounting"]
    task_value["tokens_used"] = task_value["token_budget"] - accounting["settled_tokens"] - PAYLOAD_VALUE["estimated_tokens"] + 1
    (state / "TASK.json").write_text(json.dumps(task_value), encoding="utf-8")
    run(root, "seal-payload", "--draft", "payload-draft.json", "--output", "budget-sealed.json", expected=1)
    task_value["tokens_used"] = 0
    (state / "TASK.json").write_text(json.dumps(task_value), encoding="utf-8")
    missing_draft = dict(draft_payload); missing_draft["input_artifacts"] = ["missing-input.txt"]
    (root / "missing-draft.json").write_text(json.dumps(missing_draft), encoding="utf-8")
    run(root, "seal-payload", "--draft", "missing-draft.json", "--output", "missing-sealed.json", expected=1)
    (root / "input-link.txt").symlink_to(root / "input.txt")
    symlink_draft = dict(draft_payload); symlink_draft["input_artifacts"] = ["input-link.txt"]
    (root / "symlink-draft.json").write_text(json.dumps(symlink_draft), encoding="utf-8")
    run(root, "seal-payload", "--draft", "symlink-draft.json", "--output", "symlink-sealed.json", expected=1)
    (root / "input-directory").mkdir()
    directory_draft = dict(draft_payload); directory_draft["input_artifacts"] = ["input-directory"]
    (root / "directory-draft.json").write_text(json.dumps(directory_draft), encoding="utf-8")
    run(root, "seal-payload", "--draft", "directory-draft.json", "--output", "directory-sealed.json", expected=1)
    count_inputs = []
    for index in range(25):
        name = f"bounded-input-{index:02d}.txt"
        (root / name).write_text("x", encoding="utf-8")
        count_inputs.append(name)
    count_draft = dict(draft_payload); count_draft["input_artifacts"] = count_inputs
    (root / "count-draft.json").write_text(json.dumps(count_draft), encoding="utf-8")
    run(root, "seal-payload", "--draft", "count-draft.json", "--output", "count-sealed.json", expected=1)
    (root / "oversized-input.bin").write_bytes(b"x" * 131073)
    single_draft = dict(draft_payload); single_draft["input_artifacts"] = ["oversized-input.bin"]
    (root / "single-draft.json").write_text(json.dumps(single_draft), encoding="utf-8")
    run(root, "seal-payload", "--draft", "single-draft.json", "--output", "single-sealed.json", expected=1)
    total_inputs = []
    for index in range(3):
        name = f"total-input-{index}.bin"
        (root / name).write_bytes(bytes([index]) * 90000)
        total_inputs.append(name)
    total_draft = dict(draft_payload); total_draft["input_artifacts"] = total_inputs
    (root / "total-draft.json").write_text(json.dumps(total_draft), encoding="utf-8")
    run(root, "seal-payload", "--draft", "total-draft.json", "--output", "total-sealed.json", expected=1)
    snapshot(root, "tampered-input-source", [platform_member("tampered-input", "running")])
    sealed_input.chmod(0o644); sealed_input.write_text("tampered", encoding="utf-8")
    prepare_dispatch(root, "tampered-input", expected=1)
    sealed_input.write_bytes(INPUT_BYTES); sealed_input.chmod(0o444)
    dispatch_payload = dict(PAYLOAD_VALUE)
    dispatch_payload["allowed_evidence_paths"] = ["proof.txt"]
    dispatch_payload_path = root / "dispatch-specific-payload.json"
    dispatch_payload_path.write_text(json.dumps(dispatch_payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    dispatch_payload_hash = hashlib.sha256(dispatch_payload_path.read_bytes()).hexdigest()
    dispatch_started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    dispatch_envelope = root / "dispatch-specific-envelope.json"
    ledger_epoch = json.loads((state / "agents.json").read_text(encoding="utf-8"))["epoch"]
    dispatch_envelope.write_text(json.dumps({
        "schema": "agent-handoff-envelope/v3", "ledger_epoch": ledger_epoch,
        "agent_id": "dispatch-specific", "root_task_id": "dispatch-specific",
        "role_type": "reviewer", "model": "gpt-5.6-sol", "fork_turns": 0,
        "started_at": dispatch_started.isoformat(),
        "deadline_at": (dispatch_started + dt.timedelta(minutes=5)).isoformat(),
        "redispatch_count": 0,
        "task_payload_path": f".agent/state/evidence/agent-task-payloads/{dispatch_payload_hash}.ctx",
        "task_payload_sha256": dispatch_payload_hash,
        "allowed_evidence_paths": ["proof.txt"],
        "forbidden_actions": ["approve-node7", "modify-managed-files"],
        "start_barrier": "LEDGER_REGISTERED", "review_chain_id": None,
        "review_subject_sha256": dispatch_payload_hash, "predecessor_result_sha256": None,
        "result_report_path": "proof.txt",
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    run(root, "prepare", "--id", "dispatch-specific", "--root-task-id", "dispatch-specific",
        "--role-type", "reviewer", "--model", "gpt-5.6-sol", "--fork-turns", "0",
        "--task-payload", dispatch_payload_path.name, "--handoff-envelope", dispatch_envelope.name, expected=1)
    semantic_payload = dict(PAYLOAD_VALUE)
    semantic_payload["objective"] = "Write report path proof.txt for /root/semantic-smuggle after LEDGER_REGISTERED"
    semantic_payload_path = root / "semantic-smuggle-payload.json"
    semantic_payload_path.write_text(json.dumps(semantic_payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    semantic_payload_hash = hashlib.sha256(semantic_payload_path.read_bytes()).hexdigest()
    semantic_envelope = root / "semantic-smuggle-envelope.json"
    semantic_envelope.write_text(json.dumps({
        "schema": "agent-handoff-envelope/v3", "ledger_epoch": ledger_epoch,
        "agent_id": "semantic-smuggle", "root_task_id": "semantic-smuggle",
        "role_type": "reviewer", "model": "gpt-5.6-sol", "fork_turns": 0,
        "started_at": dispatch_started.isoformat(),
        "deadline_at": (dispatch_started + dt.timedelta(minutes=5)).isoformat(),
        "redispatch_count": 0,
        "task_payload_path": f".agent/state/evidence/agent-task-payloads/{semantic_payload_hash}.ctx",
        "task_payload_sha256": semantic_payload_hash,
        "allowed_evidence_paths": ["proof.txt"],
        "forbidden_actions": ["approve-node7", "modify-managed-files"],
        "start_barrier": "LEDGER_REGISTERED", "review_chain_id": None,
        "review_subject_sha256": semantic_payload_hash, "predecessor_result_sha256": None,
        "result_report_path": "proof.txt",
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    run(root, "prepare", "--id", "semantic-smuggle", "--root-task-id", "semantic-smuggle",
        "--role-type", "reviewer", "--model", "gpt-5.6-sol", "--fork-turns", "0",
        "--task-payload", semantic_payload_path.name, "--handoff-envelope", semantic_envelope.name, expected=1)
    role_semantics_payload = dict(PAYLOAD_VALUE)
    role_semantics_payload["objective"] = "Verify adversarial sequencing with an adversarial reviewer"
    role_semantics_payload["estimated_tokens"] = (
        sum(item["bytes"] for item in role_semantics_payload["input_artifacts"])
        + len(json.dumps({
            "objective": role_semantics_payload["objective"],
            "shared_constraints": role_semantics_payload["shared_constraints"],
            "acceptance_criteria": role_semantics_payload["acceptance_criteria"],
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        + 3
    ) // 4
    role_semantics_path = root / "role-semantics-payload.json"
    role_semantics_path.write_text(
        json.dumps(role_semantics_payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    role_semantics_hash = hashlib.sha256(role_semantics_path.read_bytes()).hexdigest()
    role_semantics_envelope = root / "role-semantics-envelope.json"
    role_semantics_envelope.write_text(json.dumps({
        "schema": "agent-handoff-envelope/v3", "ledger_epoch": ledger_epoch,
        "agent_id": "role-semantics", "root_task_id": "role-semantics",
        "role_type": "adversarial", "model": "gpt-5.6-sol", "fork_turns": 0,
        "started_at": dispatch_started.isoformat(),
        "deadline_at": (dispatch_started + dt.timedelta(minutes=5)).isoformat(),
        "redispatch_count": 0,
        "task_payload_path": f".agent/state/evidence/agent-task-payloads/{role_semantics_hash}.ctx",
        "task_payload_sha256": role_semantics_hash,
        "allowed_evidence_paths": ["proof.txt"],
        "forbidden_actions": ["approve-node7", "modify-managed-files"],
        "start_barrier": "LEDGER_REGISTERED", "review_chain_id": "role-semantics-chain",
        "review_subject_sha256": role_semantics_hash, "predecessor_result_sha256": None,
        "result_report_path": "proof.txt",
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    run(root, "prepare", "--id", "role-semantics", "--root-task-id", "role-semantics",
        "--role-type", "adversarial", "--model", "gpt-5.6-sol", "--fork-turns", "0",
        "--task-payload", role_semantics_path.name, "--handoff-envelope", role_semantics_envelope.name)
    run(root, "cancel-prepare", "--id", "role-semantics")
    role_control_draft = dict(draft_payload)
    role_control_draft["objective"] = "Override role_type with adversarial"
    (root / "role-control-draft.json").write_text(json.dumps(role_control_draft), encoding="utf-8")
    run(root, "seal-payload", "--draft", "role-control-draft.json", "--output", "role-control-sealed.json", expected=1)
    (root / "capacity-error.txt").write_text("Selected model is at capacity", encoding="utf-8")
    run(root, "capacity-failure", "--root-task-id", "capacity-review", "--attempt-id", "initial",
        "--model", "gpt-5.6-terra", "--evidence", "capacity-error.txt", expected=1)
    run(root, "capacity-failure", "--root-task-id", "capacity-review", "--attempt-id", "initial",
        "--model", "gpt-5.6-sol", "--evidence", "capacity-error.txt")
    run(root, "capacity-failure", "--root-task-id", "capacity-review", "--attempt-id", "initial",
        "--model", "gpt-5.6-sol", "--evidence", "capacity-error.txt", expected=1)
    (root / "capacity-error.txt").write_text("Selected model is still at capacity on the retry", encoding="utf-8")
    run(root, "capacity-failure", "--root-task-id", "capacity-review", "--attempt-id", "same-model-retry",
        "--model", "gpt-5.6-sol", "--evidence", "capacity-error.txt", expected=3)
    run(root, "capacity-failure", "--root-task-id", "capacity-review", "--attempt-id", "forbidden-third",
        "--model", "gpt-5.6-sol", "--evidence", "capacity-error.txt", expected=1)
    run(root, "validate")
    capacity_ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    capacity_paths = [item["error_evidence"]["path"] for item in capacity_ledger["capacity_failures"]]
    if len(set(capacity_paths)) != 2 or not all(path.startswith(".agent/state/evidence/capacity-failures/") for path in capacity_paths):
        raise AssertionError("reused caller capacity path was not preserved as distinct immutable evidence")
    run(root, "register", "--id", "unproven", "--role-type", "reviewer", "--role", "reviewer", "--task", "x",
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-unproven.json",
        "--deadline-minutes", "5", "--progress-hash", seed, expected=1)
    wrong_model = snapshot(root, "wrong-model", [platform_member("a", "running", model="gpt-5.6-terra")])
    prepare_dispatch(root, "a", model="gpt-5.6-terra", expected=1)
    run(root, "register", "--id", "a", "--role-type", "reviewer", "--role", "reviewer", "--task", "a",
        "--model", "gpt-5.6-terra", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-a.json",
        "--deadline-minutes", "5", "--progress-hash", seed,
        "--platform-snapshot", wrong_model, expected=1)
    snapshot(root, "fork-envelope-source", [platform_member("fork-bound", "running", fork_turns=11)])
    prepare_dispatch(root, "fork-bound", fork_turns=11, expected=1)
    snapshot(root, "correct-envelope-source", [platform_member("cancel-a", "running")])
    prepare_dispatch(root, "cancel-a")
    wrong_handoff = snapshot(root, "wrong-handoff", [platform_member("cancel-a", "running", envelope_sha="f" * 64)])
    run(root, "register", "--id", "cancel-a", "--role-type", "reviewer", "--role", "reviewer", "--task", "cancel-a",
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-cancel-a.json",
        "--deadline-minutes", "5", "--progress-hash", seed, "--platform-snapshot", wrong_handoff, expected=1)
    run(root, "cancel-prepare", "--id", "cancel-a")
    wrong_role = snapshot(root, "wrong-role", [platform_member("a", "running", role_type="implementer")])
    prepare_dispatch(root, "a", role_type="reviewer", expected=1)
    run(root, "register", "--id", "a", "--role-type", "reviewer", "--role", "reviewer", "--task", "a",
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-a.json",
        "--deadline-minutes", "5", "--progress-hash", seed, "--platform-snapshot", wrong_role, expected=1)
    registered: list[str] = []
    for name in ("a", "b", "c"):
        registered.append(name)
        # A polling client is allowed to reuse and overwrite one input path.
        registration = snapshot(root, "shared-running", [platform_member(item, "running") for item in registered])
        prepare_dispatch(root, name)
        run(root, "register", "--id", name, "--role-type", "reviewer", "--role", "reviewer", "--task", name,
            "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", f"envelope-{name}.json",
            "--deadline-minutes", "5", "--progress-hash", seed, "--platform-snapshot", registration)
    ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    registration_paths = [item["registration_platform_evidence"]["path"] for item in ledger["members"]]
    if not all(path.startswith(".agent/state/evidence/platform-snapshots/") for path in registration_paths):
        raise AssertionError("registration receipts still reference mutable caller paths")
    run(root, "validate")
    overflow_snapshot = snapshot(root, "register-overflow", [platform_member(item, "running") for item in ("a", "b", "c", "overflow")])
    prepare_dispatch(root, "overflow", expected=1)
    run(root, "register", "--id", "overflow", "--role-type", "reviewer", "--role", "reviewer", "--task", "x",
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-overflow.json",
        "--deadline-minutes", "5", "--progress-hash", seed, "--platform-snapshot", overflow_snapshot, expected=1)

    active = snapshot(root, "active", [platform_member(name, "running") for name in ("a", "b", "c")])
    run(root, "check", "--platform-snapshot", active, expected=2)
    active_watchdog_before = (state / "agents.json").read_bytes()
    active_watchdog = json.loads(run(root, "watchdog-plan"))
    generated_at = dt.datetime.fromisoformat(active_watchdog["generated_at"])
    next_due_at = dt.datetime.fromisoformat(active_watchdog["host_scheduler"]["next_check_due_at"])
    if (
        active_watchdog.get("terminal") is not False
        or active_watchdog.get("active_ids") != ["a", "b", "c"]
        or active_watchdog.get("foreground_one_shot") is not True
        or active_watchdog.get("background_process_started") is not False
        or active_watchdog.get("platform_authority") is not False
        or active_watchdog.get("host_scheduler", {}).get("max_delay_seconds") != 60
        or not generated_at <= next_due_at <= generated_at + dt.timedelta(seconds=60)
        or not any(action.get("action") == "platform-list" for action in active_watchdog.get("actions", []))
        or not any(action.get("action") == "submit-platform-snapshot" for action in active_watchdog.get("actions", []))
    ):
        raise AssertionError("active watchdog plan is not bounded, non-terminal or platform-honest")
    if (state / "agents.json").read_bytes() != active_watchdog_before:
        raise AssertionError("watchdog planning mutated the Agent ledger")

    over_capacity = json.loads(active_watchdog_before)
    over_capacity["platform_limit"] = 3
    (state / "agents.json").write_text(json.dumps(over_capacity), encoding="utf-8")
    over_capacity_plan = json.loads(run(root, "watchdog-plan"))
    if (
        over_capacity_plan.get("capacity", {}).get("over_by") != 1
        or not any(
            action.get("action") == "platform-capacity-reconcile"
            and action.get("excess") == 1
            for action in over_capacity_plan.get("actions", [])
        )
    ):
        raise AssertionError("over-capacity watchdog plan lacks a bounded reconciliation action")
    (state / "agents.json").write_bytes(active_watchdog_before)

    stalled = json.loads(active_watchdog_before)
    stalled_a = next(item for item in stalled["members"] if item.get("id") == "a")
    stall_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    stalled_a["stall_violation_at"] = stall_at
    stalled_a["interrupt_requested_at"] = stall_at
    stalled_a["interrupt_reason"] = "stall-timeout"
    (state / "agents.json").write_text(json.dumps(stalled), encoding="utf-8")
    stalled_plan = json.loads(run(root, "watchdog-plan"))
    if not any(
        action.get("action") == "platform-interrupt"
        and action.get("id") == "a"
        and action.get("reason") == "stall-timeout"
        and action.get("requires_real_platform_confirmation") is True
        for action in stalled_plan.get("actions", [])
    ):
        raise AssertionError("observed real stall lacks a bounded host interrupt action")
    (state / "agents.json").write_bytes(active_watchdog_before)
    # A rapid duplicate poll must not manufacture a second unchanged check.
    run(root, "check", "--platform-snapshot", active, expected=2)
    ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    if {item["unchanged_checks"] for item in ledger["members"] if item.get("status") == "active"} != {1}:
        raise AssertionError("rapid checks changed liveness counters")

    # File evidence is real progress and must refresh time/reset unchanged state.
    before_progress = next(item for item in ledger["members"] if item["id"] == "b")["last_progress_at"]
    proof_record = {"path": "proof.txt", "sha256": hashlib.sha256((root / "proof.txt").read_bytes()).hexdigest(), "bytes": len((root / "proof.txt").read_bytes())}
    progress_hash = hashlib.sha256(json.dumps([proof_record], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    run(root, "heartbeat", "--id", "b", "--progress-hash", progress_hash, "--evidence", "proof.txt")
    ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    b = next(item for item in ledger["members"] if item["id"] == "b")
    if b["last_progress_at"] < before_progress or b["unchanged_checks"] != 0 or b["progress_observed"] is not True:
        raise AssertionError("evidence heartbeat did not refresh liveness")

    # A platform-observed read-only message is progress even without a file mutation.
    age_checks(root)
    message = snapshot(root, "message", [
        platform_member("a", "running", 1, "read-only review is still progressing"),
        platform_member("b", "running"), platform_member("c", "running"),
    ])
    run(root, "check", "--platform-snapshot", message, expected=2)
    ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    a = next(item for item in ledger["members"] if item["id"] == "a")
    if a["unchanged_checks"] != 0 or a["platform_cursor"] != 1:
        raise AssertionError("new read-only platform cursor did not reset liveness")

    run(root, "check", "--platform-snapshot", snapshot(root, "mismatch", [platform_member("a", "running")]), expected=4)
    age_checks(root)
    # Repeated unchanged observations request status; their count has no
    # interrupt authority. Stall/deadline/platform supervision owns interrupts.
    run(root, "check", "--platform-snapshot", message, expected=2)

    run(root, "finish", "--id", "a", "--status", "interrupted", "--conclusion", "bounded interrupt", expected=1)
    terminal_a = snapshot(root, "terminal-a", [
        platform_member("a", "interrupted", 2), platform_member("b", "running"), platform_member("c", "running"),
    ])
    run(root, "finish", "--id", "a", "--status", "interrupted", "--conclusion", "bounded interrupt",
        "--platform-snapshot", terminal_a)
    # A fresh platform message may recover a still-running Agent from an
    # unchanged-progress interrupt request. The immutable monitor chain, not
    # a self-reported heartbeat, is what makes completion eligible again.
    recovered = snapshot(root, "recovered", [
        platform_member("b", "running", 1, "b recovered with review progress"),
        platform_member("c", "running", 1, "c recovered with review progress"),
    ])
    run(root, "check", "--platform-snapshot", recovered)
    terminal_b = snapshot(root, "terminal-b", [platform_member("b", "completed", 2), platform_member("c", "running", 1)])
    terminal_b_wrong_message = snapshot(root, "terminal-b-wrong-message", [
        platform_member("b", "completed", 2, "FINAL_RESULT FAIL P0=0 P1=1 P2=0 report_sha256=" + PROOF_SHA),
        platform_member("c", "running", 1),
    ])
    run(root, "finish", "--id", "b", "--status", "completed", "--conclusion", "PASS P0=0 P1=0 P2=0",
        "--evidence", "proof.txt", "--platform-snapshot", terminal_b_wrong_message, expected=1)
    run(root, "finish", "--id", "b", "--status", "completed", "--conclusion", "FAIL P0=0 P1=1 P2=0",
        "--evidence", "proof.txt", "--platform-snapshot", terminal_b, expected=1)
    run(root, "finish", "--id", "b", "--status", "completed", "--conclusion", "PASS P0=0 P1=0 P2=0",
        "--evidence", "proof.txt", "--platform-snapshot", terminal_b)
    terminal_c_wrong_role = snapshot(root, "terminal-c-wrong-role", [platform_member("c", "completed", 2, role_type="implementer")])
    run(root, "finish", "--id", "c", "--status", "completed", "--conclusion", "must fail",
        "--platform-snapshot", terminal_c_wrong_role, expected=1)
    terminal_c = snapshot(root, "terminal-c", [platform_member("c", "completed", 2)])
    (root / "other.txt").write_text("outside envelope allowlist", encoding="utf-8")
    run(root, "finish", "--id", "c", "--status", "completed", "--conclusion", "must fail",
        "--evidence", "other.txt", "--platform-snapshot", terminal_c, expected=1)
    run(root, "finish", "--id", "c", "--status", "completed", "--conclusion", "PASS P0=0 P1=0 P2=0",
        "--evidence", "proof.txt", "--platform-snapshot", terminal_c)

    registration_d = snapshot(root, "register-d", [platform_member("d", "running", root_task_id="a", redispatch_count=1)])
    prepare_dispatch(root, "d", root_task_id="a", redispatch_count=1)
    # A failed replacement registration must not consume the one redispatch.
    bad_registration_d = snapshot(root, "register-d-bad", [])
    run(root, "redispatch", "--from-id", "a", "--to-id", "d", "--handoff-envelope", "envelope-d.json", "--deadline-minutes", "5",
        "--platform-snapshot", bad_registration_d, expected=1)
    ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    if next(item for item in ledger["members"] if item["id"] == "a")["redispatched_to"] is not None:
        raise AssertionError("failed redispatch consumed the single retry")
    # Reusing the expired Agent's identity-bearing envelope must fail even
    # though the reusable task payload stays the same.
    run(root, "redispatch", "--from-id", "a", "--to-id", "d", "--handoff-envelope", "envelope-a.json",
        "--deadline-minutes", "5", "--platform-snapshot", registration_d, expected=1)
    run(root, "redispatch", "--from-id", "a", "--to-id", "d", "--handoff-envelope", "envelope-d.json",
        "--deadline-minutes", "5", "--platform-snapshot", registration_d)
    run(root, "redispatch", "--from-id", "a", "--to-id", "e", "--handoff-envelope", "envelope-d.json", "--deadline-minutes", "5", expected=1)
    terminal_d = snapshot(root, "terminal-d", [platform_member("d", "errored", 1)])
    run(root, "finish", "--id", "d", "--status", "errored", "--conclusion", "failed once",
        "--platform-snapshot", terminal_d)
    run(root, "redispatch", "--from-id", "d", "--to-id", "e", "--handoff-envelope", "envelope-d.json", "--deadline-minutes", "5", expected=1)

    # Time spent obeying the pre-registration start barrier is auditable spawn
    # latency, not post-registration inactivity.  A registration observed 70
    # seconds after the immutable dispatch start must still receive a fresh
    # supervision target and an independent child-progress window.
    barrier_started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(seconds=129)
    snapshot(root, "barrier-envelope-source", [platform_member("barrier", "running")], observed_at=barrier_started)
    prepare_dispatch(root, "barrier")
    barrier_envelope = root / "envelope-barrier.json"
    barrier_member = platform_member(
        "barrier", "running", envelope_sha=hashlib.sha256(barrier_envelope.read_bytes()).hexdigest(),
    )
    barrier_member["started_at"] = barrier_started.isoformat()
    barrier_member["deadline_at"] = (barrier_started + dt.timedelta(minutes=5)).isoformat()
    barrier_registered = barrier_started + dt.timedelta(seconds=70)
    registration_barrier = snapshot(
        root, "register-barrier", [barrier_member], observed_at=barrier_registered,
    )
    run(root, "register", "--id", "barrier", "--role-type", "reviewer", "--role", "reviewer", "--task", "barrier",
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-barrier.json",
        "--deadline-minutes", "5", "--progress-hash", seed, "--platform-snapshot", registration_barrier)
    barrier_poll_at = barrier_registered + dt.timedelta(seconds=59)
    barrier_poll = snapshot(
        root, "barrier-poll", [platform_member("barrier", "running")], observed_at=barrier_poll_at,
    )
    run(root, "check", "--platform-snapshot", barrier_poll, expected=2)
    terminal_barrier = snapshot(
        root, "terminal-barrier", [platform_member("barrier", "completed", 1)], observed_at=barrier_poll_at,
    )
    run(root, "finish", "--id", "barrier", "--status", "completed", "--conclusion", "PASS P0=0 P1=0 P2=0",
        "--evidence", "proof.txt", "--platform-snapshot", terminal_barrier)

    # The configured target is 30 seconds with 30 seconds of scheduling grace.
    # Missing that target is auditable supervisor debt, not proof that the
    # child died and therefore not authority to interrupt it.
    near_started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(seconds=59)
    registration_near = snapshot(
        root, "register-near", [platform_member("near", "running")], observed_at=near_started,
    )
    prepare_dispatch(root, "near")
    run(root, "register", "--id", "near", "--role-type", "reviewer", "--role", "reviewer", "--task", "near",
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-near.json",
        "--deadline-minutes", "5", "--progress-hash", seed, "--platform-snapshot", registration_near)
    near_poll = snapshot(
        root, "near-poll", [platform_member("near", "running")], observed_at=near_started + dt.timedelta(seconds=59),
    )
    run(root, "check", "--platform-snapshot", near_poll, expected=2)
    terminal_near = snapshot(
        root, "terminal-near", [platform_member("near", "completed", 1)],
        observed_at=near_started + dt.timedelta(seconds=59),
    )
    run(root, "finish", "--id", "near", "--status", "completed", "--conclusion", "PASS P0=0 P1=0 P2=0",
        "--evidence", "proof.txt", "--platform-snapshot", terminal_near)

    # A 61-second supervisor gap is recorded, requests status, and remains
    # reviewable, but it cannot auto-end a live child or invalidate its result.
    gap_started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(seconds=61)
    registration_gap = snapshot(
        root, "register-gap", [platform_member("gap", "running")],
        observed_at=gap_started,
    )
    prepare_dispatch(root, "gap")
    run(root, "register", "--id", "gap", "--role-type", "reviewer", "--role", "reviewer", "--task", "gap",
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-gap.json",
        "--deadline-minutes", "5", "--progress-hash", seed, "--platform-snapshot", registration_gap)
    stale_poll = snapshot(root, "stale-poll", [platform_member("gap", "running")], observed_at=gap_started + dt.timedelta(seconds=61))
    run(root, "check", "--platform-snapshot", stale_poll, expected=2)
    gap_ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    gap_member = next(item for item in gap_ledger["members"] if item["id"] == "gap")
    if gap_member.get("monitoring_violation_at") != (gap_started + dt.timedelta(seconds=61)).isoformat():
        raise AssertionError("supervision gap was not preserved as audit evidence")
    premature_marker = state / "evidence/agent-terminal-markers" / gap_ledger["epoch"] / f"{hashlib.sha256(b'gap').hexdigest()}.json"
    if gap_member.get("status") != "active" or premature_marker.exists():
        raise AssertionError("a supervisor polling gap auto-ended the child or published terminal authority")
    terminal_gap = snapshot(root, "terminal-gap", [platform_member("gap", "completed", 1)])
    run(root, "finish", "--id", "gap", "--status", "completed", "--conclusion", "PASS P0=0 P1=0 P2=0",
        "--evidence", "proof.txt", "--platform-snapshot", terminal_gap)
    pristine_gap_ledger = (state / "agents.json").read_bytes()
    attacked_gap_ledger = json.loads(pristine_gap_ledger)
    attacked_gap_member = next(item for item in attacked_gap_ledger["members"] if item["id"] == "gap")
    attacked_gap_member["monitoring_violation_at"] = (gap_started + dt.timedelta(seconds=62)).isoformat()
    (state / "agents.json").write_text(json.dumps(attacked_gap_ledger), encoding="utf-8")
    run(root, "validate", expected=1)
    (state / "agents.json").write_bytes(pristine_gap_ledger)
    pristine_gap_marker = premature_marker.read_bytes()
    attacked_gap_marker = json.loads(pristine_gap_marker)
    attacked_gap_marker["monitoring_violation_at"] = (gap_started + dt.timedelta(seconds=62)).isoformat()
    premature_marker.chmod(0o644)
    premature_marker.write_text(json.dumps(attacked_gap_marker), encoding="utf-8")
    run(root, "validate", expected=1)
    premature_marker.write_bytes(pristine_gap_marker)

    # A long unmonitored or overdue Agent cannot be smuggled through finish as
    # completed. It can only be closed as expired so the root slot is released
    # without treating the result as accepted work.
    # Keep the terminal observation one second beyond the one-minute deadline,
    # while leaving preparation enough wall-clock margin to avoid a flaky
    # expiry on slower runners. The terminal timestamp remains within the
    # production five-second platform clock-skew bound.
    registration_late = snapshot(
        root, "register-late", [platform_member("late", "running")],
        observed_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=56),
        default_deadline_minutes=1,
    )
    prepare_dispatch(root, "late")
    run(root, "register", "--id", "late", "--role-type", "reviewer", "--role", "reviewer", "--task", "late",
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-late.json",
        "--deadline-minutes", "1", "--progress-hash", seed, "--platform-snapshot", registration_late)
    late_started = dt.datetime.fromisoformat(json.loads((state / "agents.json").read_text(encoding="utf-8"))["members"][-1]["started_at"])
    terminal_late = snapshot(root, "terminal-late", [platform_member("late", "completed", 1)],
                             observed_at=late_started + dt.timedelta(seconds=61))
    run(root, "finish", "--id", "late", "--status", "completed", "--conclusion", "must fail",
        "--platform-snapshot", terminal_late, expected=1)
    run(root, "finish", "--id", "late", "--status", "expired", "--conclusion", "deadline and monitoring expired",
        "--platform-snapshot", terminal_late)

    # Unchanged-check counts only request status. A 100-second gpt-5.6-sol task
    # remains healthy under the default 300-second stall window when platform
    # observations remain sparse but below the independent stall timeout.
    long_started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(seconds=100)
    long_registration = snapshot(root, "register-long-ok", [platform_member("long-ok", "running")],
                                 observed_at=long_started)
    prepare_dispatch(root, "long-ok")
    run(root, "register", "--id", "long-ok", "--role-type", "reviewer", "--role", "reviewer", "--task", "long-ok",
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-long-ok.json",
        "--deadline-minutes", "5", "--progress-hash", seed, "--platform-snapshot", long_registration)
    long_poll = snapshot(root, "long-ok-poll", [platform_member("long-ok", "running")],
                         observed_at=long_started + dt.timedelta(seconds=50))
    run(root, "check", "--platform-snapshot", long_poll, expected=2)
    long_terminal = snapshot(root, "long-ok-terminal", [platform_member("long-ok", "completed", 1)],
                             observed_at=long_started + dt.timedelta(seconds=100))
    run(root, "finish", "--id", "long-ok", "--status", "completed", "--conclusion", "PASS P0=0 P1=0 P2=0",
        "--evidence", "proof.txt", "--platform-snapshot", long_terminal)

    # Exercise the lower bounded policy without sleeping. The real project
    # default remains 300 seconds; 120 makes over-threshold cases deterministic.
    config_path = root / ".agent/config.json"
    stall_config = json.loads(config_path.read_text(encoding="utf-8"))
    stall_config["agent_control"]["stall_timeout_seconds"] = 120
    config_path.write_text(json.dumps(stall_config), encoding="utf-8")
    stall_ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    stall_ledger["stall_timeout_seconds"] = 120
    (state / "agents.json").write_text(json.dumps(stall_ledger), encoding="utf-8")

    stall_started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(seconds=121)
    stall_registration = snapshot(root, "register-stall-late", [platform_member("stall-late", "running")],
                                  observed_at=stall_started)
    prepare_dispatch(root, "stall-late")
    run(root, "register", "--id", "stall-late", "--role-type", "reviewer", "--role", "reviewer", "--task", "stall-late",
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-stall-late.json",
        "--deadline-minutes", "5", "--progress-hash", seed, "--platform-snapshot", stall_registration)
    for offset in (50, 100):
        stall_poll = snapshot(root, f"stall-late-poll-{offset}", [platform_member("stall-late", "running")],
                              observed_at=stall_started + dt.timedelta(seconds=offset))
        run(root, "check", "--platform-snapshot", stall_poll, expected=2)
    stall_message = snapshot(root, "stall-late-message", [
        platform_member("stall-late", "running", 1, "new platform progress is observed before a proven stall"),
    ], observed_at=stall_started + dt.timedelta(seconds=121))
    run(root, "check", "--platform-snapshot", stall_message)
    stall_terminal = snapshot(root, "stall-late-terminal", [platform_member("stall-late", "completed", 2)],
                              observed_at=stall_started + dt.timedelta(seconds=121))
    run(root, "finish", "--id", "stall-late", "--status", "completed", "--conclusion", "PASS P0=0 P1=0 P2=0",
        "--evidence", "proof.txt", "--platform-snapshot", stall_terminal)

    historical_started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(seconds=121)
    historical_registration = snapshot(root, "register-stall-historical", [platform_member("stall-historical", "running")],
                                       observed_at=historical_started)
    prepare_dispatch(root, "stall-historical")
    run(root, "register", "--id", "stall-historical", "--role-type", "reviewer", "--role", "reviewer", "--task", "stall-historical",
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-stall-historical.json",
        "--deadline-minutes", "5", "--progress-hash", seed, "--platform-snapshot", historical_registration)
    for offset in (50, 100):
        historical_poll = snapshot(root, f"stall-historical-poll-{offset}", [platform_member("stall-historical", "running")],
                                   observed_at=historical_started + dt.timedelta(seconds=offset))
        run(root, "check", "--platform-snapshot", historical_poll, expected=2)
    # Here an unchanged observation crosses the real-progress timeout. That is
    # direct liveness evidence and must still force interruption.
    historical_terminal = snapshot(root, "stall-historical-terminal", [platform_member("stall-historical", "running")],
                                   observed_at=historical_started + dt.timedelta(seconds=121))
    run(root, "check", "--platform-snapshot", historical_terminal, expected=3)
    historical_expired = snapshot(root, "stall-historical-expired", [platform_member("stall-historical", "completed")],
                                  observed_at=historical_started + dt.timedelta(seconds=121))
    run(root, "finish", "--id", "stall-historical", "--status", "completed", "--conclusion", "must fail",
        "--platform-snapshot", historical_expired, expected=1)
    run(root, "finish", "--id", "stall-historical", "--status", "expired", "--conclusion", "proven stall expired",
        "--platform-snapshot", historical_expired)

    # If the first observation after a sparse interval is a terminal message,
    # that new cursor proves completion; the supervisor cannot invent a stall
    # inside an interval it did not observe.
    sparse_started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(seconds=121)
    sparse_registration = snapshot(root, "register-sparse-terminal", [platform_member("sparse-terminal", "running")],
                                   observed_at=sparse_started)
    prepare_dispatch(root, "sparse-terminal")
    run(root, "register", "--id", "sparse-terminal", "--role-type", "reviewer", "--role", "reviewer", "--task", "sparse terminal",
        "--model", "gpt-5.6-sol", "--fork-turns", "0", "--task-payload", "payload.txt", "--handoff-envelope", "envelope-sparse-terminal.json",
        "--deadline-minutes", "5", "--progress-hash", seed, "--platform-snapshot", sparse_registration)
    sparse_terminal = snapshot(root, "sparse-terminal", [platform_member("sparse-terminal", "completed", 1)],
                               observed_at=sparse_started + dt.timedelta(seconds=121))
    run(root, "finish", "--id", "sparse-terminal", "--status", "completed", "--conclusion", "PASS P0=0 P1=0 P2=0",
        "--evidence", "proof.txt", "--platform-snapshot", sparse_terminal)

    stall_config["agent_control"]["stall_timeout_seconds"] = 300
    config_path.write_text(json.dumps(stall_config), encoding="utf-8")
    stall_ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    stall_ledger["stall_timeout_seconds"] = 300
    (state / "agents.json").write_text(json.dumps(stall_ledger), encoding="utf-8")

    # Formal reviews are an immutable serial chain, not three independent labels.
    chain_id = "formal-chain-001"
    adversarial_path = root / "formal-adversarial.md"
    adversarial_path.write_bytes(review_report_bytes(
        "adversarial", chain_id, None, [], [],
        targeted_cases=["self-reported-unbound-case"],
    ))
    _, adversarial_envelope_sha, adversarial_started = write_review_envelope(
        root, "formal-adversarial", "adversarial", chain_id, None, adversarial_path.name,
    )
    prepare_dispatch(root, "formal-adversarial", role_type="adversarial", root_task_id="formal-chain")
    register_formal(root, "formal-adversarial", "adversarial", adversarial_envelope_sha, adversarial_started, seed)

    # A Case name without an envelope+runner+Agent receipt is not execution
    # evidence, even when it is below the configured numerical ceiling.
    over_limit_sha = hashlib.sha256(adversarial_path.read_bytes()).hexdigest()
    over_limit_message = f"FINAL_RESULT PASS P0=0 P1=0 P2=0 report_sha256={over_limit_sha}"
    over_limit_terminal = snapshot(root, "formal-adversarial-over-limit", [
        platform_member("formal-adversarial", "completed", 1, over_limit_message),
    ])
    run(root, "finish", "--id", "formal-adversarial", "--status", "completed",
        "--conclusion", "PASS P0=0 P1=0 P2=0", "--evidence", adversarial_path.name,
        "--platform-snapshot", over_limit_terminal, expected=1)
    adversarial_path.write_bytes(review_report_bytes("adversarial", chain_id, None, [], []))
    adversarial_sha = hashlib.sha256(adversarial_path.read_bytes()).hexdigest()

    # Even a correctly predicted report digest cannot authorize an overlapping successor.
    write_review_envelope(root, "formal-cross", "cross", chain_id, adversarial_sha, "formal-cross.md")
    prepare_dispatch(root, "formal-cross", role_type="cross", root_task_id="formal-chain", expected=1)
    adversarial_message = f"FINAL_RESULT PASS P0=0 P1=0 P2=0 report_sha256={adversarial_sha}"
    adversarial_terminal = snapshot(root, "formal-adversarial-terminal", [
        platform_member("formal-adversarial", "completed", 1, adversarial_message),
    ])
    run(root, "finish", "--id", "formal-adversarial", "--status", "completed",
        "--conclusion", "PASS P0=0 P1=0 P2=0", "--evidence", adversarial_path.name,
        "--platform-snapshot", adversarial_terminal)
    adversarial_terminal_at = dt.datetime.fromisoformat(
        next(item for item in json.loads((state / "agents.json").read_text())["members"]
             if item["id"] == "formal-adversarial")["terminal_observed_at"]
    )

    write_review_envelope(
        root, "formal-cross", "cross", chain_id, adversarial_sha, "formal-cross.md",
        subject_sha="f" * 64,
    )
    prepare_dispatch(root, "formal-cross", role_type="cross", root_task_id="formal-chain", expected=1)
    write_review_envelope(root, "formal-cross", "cross", chain_id, "e" * 64, "formal-cross.md")
    prepare_dispatch(root, "formal-cross", role_type="cross", root_task_id="formal-chain", expected=1)
    committed_adversarial_ledger = (state / "agents.json").read_bytes()
    forged_ledger = json.loads(committed_adversarial_ledger)
    forged_adversarial = next(
        item for item in forged_ledger["members"] if item["id"] == "formal-adversarial"
    )
    forged_adversarial["review_verdict"]["report_sha256"] = "e" * 64
    (state / "agents.json").write_text(json.dumps(forged_ledger), encoding="utf-8")
    prepare_dispatch(root, "formal-cross", role_type="cross", root_task_id="formal-chain", expected=1)
    (state / "agents.json").write_bytes(committed_adversarial_ledger)
    write_review_envelope(
        root, "formal-cross", "cross", chain_id, adversarial_sha, "formal-cross.md",
        started_at=adversarial_terminal_at - dt.timedelta(seconds=1),
    )
    prepare_dispatch(root, "formal-cross", role_type="cross", root_task_id="formal-chain", expected=1)
    _, cross_envelope_sha, cross_started = write_review_envelope(
        root, "formal-cross", "cross", chain_id, adversarial_sha, "formal-cross.md",
    )
    prepare_dispatch(root, "formal-cross", role_type="cross", root_task_id="formal-chain")
    register_formal(root, "formal-cross", "cross", cross_envelope_sha, cross_started, seed)

    integrator_allowed = [
        "formal-integrator.md", "replay-a.json", "replay-extra.json",
        "replay-forged-a.json", "replay-post-terminal.json",
    ]
    # The configured governed-product path must exist before the integrator's
    # preflight is bound to the canonical candidate (not its review payload).
    replay_script = root / "replay-case.py"
    replay_script.write_text(
        "from pathlib import Path\nimport sys\n"
        "if sys.argv[1] == 'mismatch': Path('mismatch-executed.txt').write_text('bad')\n"
        "if Path('force-replay-failure.txt').exists(): print('intentional failure ' + sys.argv[1]); raise SystemExit(1)\n"
        "print('full-chain passed ' + sys.argv[1])\n",
        encoding="utf-8",
    )
    write_review_envelope(root, "formal-integrator", "integrator", chain_id, "d" * 64,
                          "formal-integrator.md", allowed_paths=integrator_allowed)
    prepare_dispatch(root, "formal-integrator", role_type="integrator", root_task_id="formal-chain", expected=1)

    cross_path = root / "formal-cross.md"
    cross_path.write_bytes(review_report_bytes("cross", chain_id, adversarial_sha, [], []))
    invalid_cross_sha = hashlib.sha256(cross_path.read_bytes()).hexdigest()
    invalid_cross_terminal = snapshot(root, "formal-cross-invalid-terminal", [
        platform_member("formal-cross", "completed", 1,
                        f"FINAL_RESULT PASS P0=0 P1=0 P2=0 report_sha256={invalid_cross_sha}"),
    ])
    run(root, "finish", "--id", "formal-cross", "--status", "completed",
        "--conclusion", "PASS P0=0 P1=0 P2=0", "--evidence", cross_path.name,
        "--platform-snapshot", invalid_cross_terminal, expected=1)
    cross_lenses = [
        "product", "architecture", "qa", "security", "operations",
        "ai-workflow-new-project-adopter",
    ]
    cross_path.write_bytes(review_report_bytes("cross", chain_id, adversarial_sha, cross_lenses, []))
    missing_scenario_sha = hashlib.sha256(cross_path.read_bytes()).hexdigest()
    missing_scenario_terminal = snapshot(root, "formal-cross-missing-scenario", [
        platform_member("formal-cross", "completed", 1,
                        f"FINAL_RESULT PASS P0=0 P1=0 P2=0 report_sha256={missing_scenario_sha}"),
    ])
    run(root, "finish", "--id", "formal-cross", "--status", "completed",
        "--conclusion", "PASS P0=0 P1=0 P2=0", "--evidence", cross_path.name,
        "--platform-snapshot", missing_scenario_terminal, expected=1)
    cross_path.write_bytes(cross_report_bytes(root, "formal-cross", chain_id, adversarial_sha))
    cross_sha = hashlib.sha256(cross_path.read_bytes()).hexdigest()
    cross_terminal = snapshot(root, "formal-cross-terminal", [
        platform_member("formal-cross", "completed", 1,
                        f"FINAL_RESULT PASS P0=0 P1=0 P2=0 report_sha256={cross_sha}"),
    ])
    run(root, "finish", "--id", "formal-cross", "--status", "completed",
        "--conclusion", "PASS P0=0 P1=0 P2=0", "--evidence", cross_path.name,
        "--platform-snapshot", cross_terminal)

    runner_path = root / ".agent/scripts/testrun.py"
    runner_receipt = {
        "path": ".agent/scripts/testrun.py",
        "sha256": hashlib.sha256(runner_path.read_bytes()).hexdigest(),
        "bytes": len(runner_path.read_bytes()),
    }
    _, integrator_envelope_sha, integrator_started = write_review_envelope(
        root, "formal-integrator", "integrator", chain_id, cross_sha, "formal-integrator.md",
        allowed_paths=integrator_allowed,
    )
    prepare_dispatch(root, "formal-integrator", role_type="integrator", root_task_id="formal-chain")
    register_formal(root, "formal-integrator", "integrator", integrator_envelope_sha, integrator_started, seed)
    integrator_path = root / "formal-integrator.md"
    integrator_path.write_bytes(review_report_bytes("integrator", chain_id, cross_sha, [], []))
    invalid_integrator_sha = hashlib.sha256(integrator_path.read_bytes()).hexdigest()
    invalid_integrator_terminal = snapshot(root, "formal-integrator-invalid-terminal", [
        platform_member("formal-integrator", "completed", 1,
                        f"FINAL_RESULT PASS P0=0 P1=0 P2=0 report_sha256={invalid_integrator_sha}"),
    ])
    run(root, "finish", "--id", "formal-integrator", "--status", "completed",
        "--conclusion", "PASS P0=0 P1=0 P2=0", "--evidence", integrator_path.name,
        "--platform-snapshot", invalid_integrator_terminal, expected=1)

    # Caller-authored timestamps/case hashes and an authentic runner file digest
    # do not constitute replay authority. Neither future-dated nor copied output
    # can be admitted without a pre-registered ledger run and runner observations.
    forged_time = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) + dt.timedelta(seconds=60)
    forged_receipts = [write_clean_replay(root, "forged-a", "9" * 32, forged_time, runner_receipt)]
    integrator_path.write_bytes(review_report_bytes(
        "integrator", chain_id, cross_sha, [], forged_receipts,
    ))
    forged_integrator_sha = hashlib.sha256(integrator_path.read_bytes()).hexdigest()
    forged_terminal = snapshot(root, "formal-integrator-unregistered-rerun", [
        platform_member("formal-integrator", "completed", 1,
                        f"FINAL_RESULT PASS P0=0 P1=0 P2=0 report_sha256={forged_integrator_sha}"),
    ])
    run(root, "finish", "--id", "formal-integrator", "--status", "completed",
        "--conclusion", "PASS P0=0 P1=0 P2=0", "--evidence", integrator_path.name,
        "--evidence", "replay-forged-a.json",
        "--platform-snapshot", forged_terminal, expected=1)

    run_ids = {"a": "1" * 32, "extra": "3" * 32}
    trivial_plan = write_replay_plan(root, "trivial", "7" * 32, [{
        "id": "trivial", "command": ["/usr/bin/true"], "exit_code": 0,
    }])
    run(root, "replay-prepare", "--integrator-id", "formal-integrator", "--plan", trivial_plan, expected=1)
    missing_plan = write_replay_plan(root, "missing", "6" * 32, [NODE6_VALUE["checks"][0]])
    run(root, "replay-prepare", "--integrator-id", "formal-integrator", "--plan", missing_plan, expected=1)

    task_path = state / "TASK.json"; current_task = task_path.read_bytes(); current_node6 = node6_path.read_bytes()
    old_node6_value = dict(NODE6_VALUE); old_node6_value["checks"] = [NODE6_VALUE["checks"][0]]
    old_node6_bytes = (json.dumps(old_node6_value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    node6_path.write_bytes(old_node6_bytes)
    old_task = json.loads(current_task)
    old_task["node_artifacts"]["6"].update({
        "sha256": hashlib.sha256(old_node6_bytes).hexdigest(), "bytes": len(old_node6_bytes),
    })
    task_path.write_text(json.dumps(old_task), encoding="utf-8")
    old_plan = write_replay_plan(root, "old", "5" * 32)
    run(root, "replay-prepare", "--integrator-id", "formal-integrator", "--plan", old_plan, expected=1)
    node6_path.write_bytes(current_node6); task_path.write_bytes(current_task)

    mismatched_output_plan = write_replay_plan(root, "mismatched-output", "6" * 32)
    mismatched_output_path = root / mismatched_output_plan
    mismatched_output_value = json.loads(mismatched_output_path.read_text(encoding="utf-8"))
    mismatched_output_value["cases"][0]["expected_output_path"] = "wrong-runner-derived-name.log"
    mismatched_output_path.write_text(json.dumps(mismatched_output_value), encoding="utf-8")
    run(root, "replay-prepare", "--integrator-id", "formal-integrator",
        "--plan", mismatched_output_plan, expected=1)

    # A real failing Node 6 command is an auditable failed replay, not corrupt
    # ledger structure. It remains permanently ineligible for integrator PASS.
    with tempfile.TemporaryDirectory(prefix="agent-ledger-failed-replay-") as failed_raw:
        failed_root = Path(failed_raw) / "project"
        shutil.copytree(root, failed_root)
        (failed_root / "force-replay-failure.txt").write_text("fail\n", encoding="utf-8")
        failed_plan = write_replay_plan(failed_root, "a", run_ids["a"])
        run(failed_root, "replay-prepare", "--integrator-id", "formal-integrator", "--plan", failed_plan)
        failed_replay_output = run_managed_replay(failed_root, run_ids["a"], expected=1)
        failed_state = json.loads((failed_root / ".agent/state/agents.json").read_text(encoding="utf-8"))
        failed_run = next(item for item in failed_state["replay_runs"] if item["run_id"] == run_ids["a"])
        if failed_run.get("status") != "failed" or failed_run.get("failure_reason") != "test-result-mismatch":
            raise AssertionError(
                "real test failure was not preserved as an auditable failed replay: "
                + json.dumps(failed_run, ensure_ascii=False, sort_keys=True)
                + "\nrunner output:\n" + failed_replay_output
            )
        run(failed_root, "validate")
        interrupted_terminal = snapshot(failed_root, "formal-integrator-interrupted", [
            platform_member("formal-integrator", "interrupted", 2, "integration replay failed; stop"),
        ])
        run(failed_root, "finish", "--id", "formal-integrator", "--status", "interrupted",
            "--conclusion", "the single replay failed",
            "--platform-snapshot", interrupted_terminal)
        interrupted_state = json.loads((failed_root / ".agent/state/agents.json").read_text(encoding="utf-8"))
        run(failed_root, "validate")

    plan_name = write_replay_plan(root, "a", run_ids["a"])
    run(root, "replay-prepare", "--integrator-id", "formal-integrator", "--plan", plan_name)

    supervised_ledger = (state / "agents.json").read_bytes()
    overdue_ledger = json.loads(supervised_ledger)
    overdue_integrator = next(item for item in overdue_ledger["members"] if item["id"] == "formal-integrator")
    overdue_integrator["deadline_at"] = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
    ).replace(microsecond=0).isoformat()
    (state / "agents.json").write_text(json.dumps(overdue_ledger), encoding="utf-8")
    run_managed_replay(root, run_ids["a"], expected=1)
    aborted_ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    aborted_run = next(item for item in aborted_ledger["replay_runs"] if item["run_id"] == run_ids["a"])
    if aborted_run.get("status") != "aborted" or aborted_run.get("failure_reason") != "supervision-window-closed":
        raise AssertionError("overdue replay was not preserved as an auditable aborted authority")
    (state / "agents.json").write_bytes(supervised_ledger)
    if (root / "replay-a.json").exists():
        raise AssertionError("overdue integrator started a replay subprocess")

    # Execution has no caller-controlled command/result interface. Unknown runs,
    # removed callbacks and injected argv all fail before a test subprocess.
    run_managed_replay(root, "f" * 32, expected=1)
    run(root, "replay-start", expected=2)
    run(root, "replay-execute", "--integrator-id", "formal-integrator", "--run-id", run_ids["a"],
        "--command-json", json.dumps([sys.executable, replay_script.name, "mismatch"]), expected=2)
    if (root / "mismatch-executed.txt").exists():
        raise AssertionError("mismatched replay command executed before authority rejection")
    run_managed_replay(root, run_ids["a"])

    # A review payload digest is not the governed product candidate. Even if a
    # caller substitutes the active review subject into replay authority, the
    # ledger must reject the otherwise well-formed completed run.
    candidate_bound_ledger = (state / "agents.json").read_bytes()
    conflated_ledger = json.loads(candidate_bound_ledger)
    conflated_run = next(
        item for item in conflated_ledger["replay_runs"] if item["run_id"] == run_ids["a"]
    )
    if conflated_run["candidate_sha256"] == PAYLOAD_SHA:
        raise AssertionError("fixture candidate unexpectedly equals its review payload")
    conflated_run["candidate_sha256"] = PAYLOAD_SHA
    (state / "agents.json").write_text(json.dumps(conflated_ledger), encoding="utf-8")
    run(root, "validate", expected=1)
    (state / "agents.json").write_bytes(candidate_bound_ledger)

    replay_receipts = [replay_source_receipt(root, "a")]
    extra_plan = write_replay_plan(root, "extra", run_ids["extra"])
    run(root, "replay-prepare", "--integrator-id", "formal-integrator", "--plan", extra_plan, expected=1)

    # Rewriting an authority-produced receipt's time cannot manufacture a new
    # authority. Restore the caller view afterward; immutable ledger evidence
    # never changes.
    replay_a_path = root / "replay-a.json"
    replay_a_original = replay_a_path.read_bytes()
    forged_a = json.loads(replay_a_original)
    forged_a["cases"][0]["started_at"] = forged_time.isoformat()
    forged_a["cases"][0]["finished_at"] = forged_time.isoformat()
    forged_unsigned = {key: value for key, value in forged_a["cases"][0].items() if key != "case_sha256"}
    forged_a["cases"][0]["case_sha256"] = hashlib.sha256(
        json.dumps(forged_unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    replay_a_path.write_text(json.dumps(forged_a, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    forged_time_receipts = [replay_source_receipt(root, "a")]
    integrator_path.write_bytes(review_report_bytes("integrator", chain_id, cross_sha, [], forged_time_receipts))
    forged_time_sha = hashlib.sha256(integrator_path.read_bytes()).hexdigest()
    forged_time_terminal = snapshot(root, "formal-integrator-forged-time", [
        platform_member("formal-integrator", "completed", 1,
                        f"FINAL_RESULT PASS P0=0 P1=0 P2=0 report_sha256={forged_time_sha}"),
    ])
    run(root, "finish", "--id", "formal-integrator", "--status", "completed",
        "--conclusion", "PASS P0=0 P1=0 P2=0", "--evidence", integrator_path.name,
        "--evidence", "replay-a.json",
        "--platform-snapshot", forged_time_terminal, expected=1)
    replay_a_path.write_bytes(replay_a_original)
    replay_receipts = [replay_source_receipt(root, "a")]

    integrator_path.write_bytes(review_report_bytes(
        "integrator", chain_id, cross_sha, [], sorted(replay_receipts, key=lambda item: item["source_path"]),
    ))
    integrator_sha = hashlib.sha256(integrator_path.read_bytes()).hexdigest()
    integrator_terminal = snapshot(root, "formal-integrator-terminal", [
        platform_member("formal-integrator", "completed", 1,
                        f"FINAL_RESULT PASS P0=0 P1=0 P2=0 report_sha256={integrator_sha}"),
    ])
    run(root, "finish", "--id", "formal-integrator", "--status", "completed",
        "--conclusion", "PASS P0=0 P1=0 P2=0", "--evidence", integrator_path.name,
        "--evidence", "replay-a.json",
        "--platform-snapshot", integrator_terminal)
    post_plan = write_replay_plan(root, "post-terminal", "4" * 32)
    run(root, "replay-prepare", "--integrator-id", "formal-integrator", "--plan", post_plan, expected=1)
    run(root, "validate")

    # One root+subject cannot switch review_chain_id after a FAIL to hide the
    # old attempt or its supervision debt. The single controlled retry stays
    # in the original chain, so downstream Node 7 aggregation sees both.
    retry_root = "formal-retry-root"
    retry_chain = "formal-retry-chain-001"
    first_retry_report = root / "formal-retry-adversarial-1.md"
    first_retry_report.write_bytes(review_report_bytes(
        "adversarial", retry_chain, None, [], [], verdict="FAIL", p1=1,
    ))
    first_retry_sha = hashlib.sha256(first_retry_report.read_bytes()).hexdigest()
    _, first_retry_envelope_sha, first_retry_started = write_review_envelope(
        root, "formal-retry-adversarial-1", "adversarial", retry_chain, None,
        first_retry_report.name, root_task_id=retry_root,
    )
    prepare_dispatch(
        root, "formal-retry-adversarial-1", role_type="adversarial",
        root_task_id=retry_root,
    )
    register_formal(
        root, "formal-retry-adversarial-1", "adversarial",
        first_retry_envelope_sha, first_retry_started, seed,
        root_task_id=retry_root,
    )
    first_retry_terminal = snapshot(root, "formal-retry-adversarial-1-terminal", [
        platform_member(
            "formal-retry-adversarial-1", "completed", 1,
            f"FINAL_RESULT FAIL P0=0 P1=1 P2=0 report_sha256={first_retry_sha}",
        ),
    ])
    run(root, "finish", "--id", "formal-retry-adversarial-1", "--status", "completed",
        "--conclusion", "FAIL P0=0 P1=1 P2=0", "--evidence", first_retry_report.name,
        "--platform-snapshot", first_retry_terminal)

    write_review_envelope(
        root, "formal-retry-chain-wash", "adversarial", "formal-retry-chain-NEW", None,
        "formal-retry-chain-wash.md", root_task_id=retry_root,
    )
    prepare_dispatch(
        root, "formal-retry-chain-wash", role_type="adversarial",
        root_task_id=retry_root, expected=1,
    )

    second_retry_report = root / "formal-retry-adversarial-2.md"
    second_retry_report.write_bytes(review_report_bytes(
        "adversarial", retry_chain, None, [], [],
    ))
    second_retry_sha = hashlib.sha256(second_retry_report.read_bytes()).hexdigest()
    _, second_retry_envelope_sha, second_retry_started = write_review_envelope(
        root, "formal-retry-adversarial-2", "adversarial", retry_chain, None,
        second_retry_report.name, root_task_id=retry_root, redispatch_count=1,
    )
    prepare_dispatch(
        root, "formal-retry-adversarial-2", role_type="adversarial",
        root_task_id=retry_root, redispatch_count=1,
    )
    retry_platform_member = platform_member(
        "formal-retry-adversarial-2", "running",
        envelope_sha=second_retry_envelope_sha, role_type="adversarial",
        root_task_id=retry_root, redispatch_count=1,
    )
    retry_platform_member["started_at"] = second_retry_started.isoformat()
    retry_platform_member["deadline_at"] = (
        second_retry_started + dt.timedelta(minutes=5)
    ).isoformat()
    second_retry_registration = snapshot(
        root, "formal-retry-adversarial-2-register", [retry_platform_member],
        observed_at=second_retry_started,
    )
    run(root, "redispatch", "--from-id", "formal-retry-adversarial-1",
        "--to-id", "formal-retry-adversarial-2", "--handoff-envelope",
        "envelope-formal-retry-adversarial-2.json", "--deadline-minutes", "5",
        "--platform-snapshot", second_retry_registration)
    second_retry_terminal = snapshot(root, "formal-retry-adversarial-2-terminal", [
        platform_member(
            "formal-retry-adversarial-2", "completed", 1,
            f"FINAL_RESULT PASS P0=0 P1=0 P2=0 report_sha256={second_retry_sha}",
            redispatch_count=1,
        ),
    ])
    run(root, "finish", "--id", "formal-retry-adversarial-2", "--status", "completed",
        "--conclusion", "PASS P0=0 P1=0 P2=0", "--evidence", second_retry_report.name,
        "--platform-snapshot", second_retry_terminal)
    run(root, "validate")
    retry_members = [
        item for item in json.loads((state / "agents.json").read_text())["members"]
        if item.get("root_task_id") == retry_root
        and item.get("review_subject_sha256") == PAYLOAD_SHA
    ]
    if len(retry_members) != 2 or {item.get("review_chain_id") for item in retry_members} != {retry_chain}:
        raise AssertionError("controlled review retry did not preserve one complete chain history")

    final_empty = snapshot(root, "final-empty", [])
    run(root, "validate", "--require-empty", expected=1)
    run(root, "validate", "--require-empty", "--platform-snapshot", final_empty)

    # A valid empty snapshot cannot partially mutate a ledger that already has
    # unrelated validation errors. Failure is transactional for agents.json.
    clean_empty_ledger = (state / "agents.json").read_bytes()
    invalid_empty_ledger = json.loads(clean_empty_ledger)
    invalid_empty_ledger["default_model"] = "tampered-model"
    (state / "agents.json").write_text(json.dumps(invalid_empty_ledger), encoding="utf-8")
    invalid_before = (state / "agents.json").read_bytes()
    fresh_empty = snapshot(root, "transactional-final-empty", [])
    run(root, "validate", "--require-empty", "--platform-snapshot", fresh_empty, expected=1)
    if (state / "agents.json").read_bytes() != invalid_before:
        raise AssertionError("failed require-empty validation mutated the ledger")
    (state / "agents.json").write_bytes(clean_empty_ledger)

    # Authorization-critical registration fields are replayed from immutable
    # platform evidence, and an epoch/id terminal marker makes reactivation
    # fail even if every editable terminal pointer is removed.
    pristine_terminal_ledger = (state / "agents.json").read_bytes()
    ledger = json.loads(pristine_terminal_ledger)
    b = next(item for item in ledger["members"] if item["id"] == "b")
    b["role_type"] = "adversarial"
    (state / "agents.json").write_text(json.dumps(ledger), encoding="utf-8")
    run(root, "validate", expected=1)
    (state / "agents.json").write_bytes(pristine_terminal_ledger)

    ledger = json.loads(pristine_terminal_ledger)
    b = next(item for item in ledger["members"] if item["id"] == "b")
    b["deadline_at"] = (dt.datetime.fromisoformat(b["deadline_at"]) + dt.timedelta(minutes=1)).isoformat()
    (state / "agents.json").write_text(json.dumps(ledger), encoding="utf-8")
    run(root, "validate", expected=1)
    (state / "agents.json").write_bytes(pristine_terminal_ledger)

    ledger = json.loads(pristine_terminal_ledger)
    b = next(item for item in ledger["members"] if item["id"] == "b")
    b["conclusion"] = "PASS rewritten after terminal publication"
    (state / "agents.json").write_text(json.dumps(ledger), encoding="utf-8")
    run(root, "validate", expected=1)
    (state / "agents.json").write_bytes(pristine_terminal_ledger)

    ledger = json.loads(pristine_terminal_ledger)
    b = next(item for item in ledger["members"] if item["id"] == "b")
    b["result_evidence"] = []
    (state / "agents.json").write_text(json.dumps(ledger), encoding="utf-8")
    run(root, "validate", expected=1)
    (state / "agents.json").write_bytes(pristine_terminal_ledger)

    ledger = json.loads(pristine_terminal_ledger)
    b = next(item for item in ledger["members"] if item["id"] == "b")
    b.update({"status": "active", "terminal_platform_evidence": None, "terminal_observed_at": None})
    b.pop("finished_at", None); b.pop("conclusion", None)
    (state / "agents.json").write_text(json.dumps(ledger), encoding="utf-8")
    run(root, "validate", expected=1)
    (state / "agents.json").write_bytes(pristine_terminal_ledger)
    run(root, "validate")

    # Editable terminal times/deadlines cannot rewrite the immutable receipt.
    ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    b = next(item for item in ledger["members"] if item["id"] == "b")
    original_terminal_observed = b["terminal_observed_at"]
    b["terminal_observed_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).replace(microsecond=0).isoformat()
    (state / "agents.json").write_text(json.dumps(ledger), encoding="utf-8")
    run(root, "validate", expected=1)
    b["terminal_observed_at"] = original_terminal_observed
    (state / "agents.json").write_text(json.dumps(ledger), encoding="utf-8")
    run(root, "validate")

    # Historical immutable snapshots must be semantically cross-checked with
    # the editable ledger, not merely accepted because their receipt exists.
    ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    snapshot_bound_member = next(item for item in ledger["members"] if item["id"] == "b")
    original_snapshot_fork = snapshot_bound_member["fork_turns"]
    snapshot_bound_member["fork_turns"] = 9
    (state / "agents.json").write_text(json.dumps(ledger), encoding="utf-8")
    run(root, "validate", expected=1)
    snapshot_bound_member["fork_turns"] = original_snapshot_fork
    (state / "agents.json").write_text(json.dumps(ledger), encoding="utf-8")
    run(root, "validate")

    # Internal content-addressed evidence is fail-closed if tampered with.  The
    # bounded recovery is an explicit empty-platform reinitialization which
    # archives the damaged ledger instead of silently re-signing old facts.
    ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    capacity_record = ledger["capacity_failures"][0]["error_evidence"]
    capacity_internal = root / capacity_record["path"]
    capacity_original = capacity_internal.read_bytes()
    capacity_internal.chmod(0o644)
    capacity_internal.write_text("tampered", encoding="utf-8")
    run(root, "validate", expected=1)
    capacity_internal.write_bytes(capacity_original)
    capacity_internal.chmod(0o444)
    run(root, "validate")
    completed_review = next(item for item in ledger["members"] if item.get("id") == "b")
    result_record = completed_review["result_evidence"][0]
    result_internal = root / result_record["path"]
    result_original = result_internal.read_bytes()
    result_internal.chmod(0o644)
    result_internal.write_text("rewritten reviewer result", encoding="utf-8")
    run(root, "validate", expected=1)
    result_internal.write_bytes(result_original)
    result_internal.chmod(0o444)
    run(root, "validate")
    internal = root / ledger["members"][0]["registration_platform_evidence"]["path"]
    internal.chmod(0o644)
    internal.write_text("{}", encoding="utf-8")
    run(root, "validate", expected=1)
    run(root, "init", "--archive-existing", "--platform-snapshot", final_empty)
    run(root, "validate", "--require-empty", "--platform-snapshot", final_empty)
    recovered = json.loads((state / "agents.json").read_text(encoding="utf-8"))
    if not recovered.get("migration_source"):
        raise AssertionError("audited recovery did not retain the archived damaged ledger receipt")

print("AGENT LEDGER SELF-TEST PASSED: serial review chain, six-lens cross review, one preflighted clean replay and marker-bound results")
