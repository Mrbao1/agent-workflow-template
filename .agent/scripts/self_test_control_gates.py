#!/usr/bin/env python3
"""Disposable requirement and token control-plane attacks."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile


SOURCE = Path(__file__).resolve().parents[1]


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run(root: Path, tool: str, *args: str, expected: int = 0) -> str:
    result = subprocess.run(
        [sys.executable, f".agent/scripts/{tool}.py", *args], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode != expected:
        raise AssertionError(f"{tool} {args}: expected {expected}, got {result.returncode}\n{result.stdout}")
    return result.stdout


def copy_policy_runtime(root: Path, scripts: Path) -> None:
    shutil.copytree(SOURCE / "scripts/workflowlib", scripts / "workflowlib", dirs_exist_ok=True)
    shutil.copy2(SOURCE / "INDEX.md", root / ".agent/INDEX.md")
    shutil.copytree(SOURCE / "workflows", root / ".agent/workflows", dirs_exist_ok=True)
    shutil.copytree(SOURCE / "templates", root / ".agent/templates", dirs_exist_ok=True)
    shutil.copytree(SOURCE / "policies", root / ".agent/policies", dirs_exist_ok=True)
    shutil.copytree(SOURCE / "skills/run-ai-coding-pipeline", root / ".agent/skills/run-ai-coding-pipeline", dirs_exist_ok=True)
    shutil.copytree(SOURCE / "skills/clarify-task", root / ".agent/skills/clarify-task", dirs_exist_ok=True)


with tempfile.TemporaryDirectory(prefix="agentctl-context-transport-") as raw:
    root = Path(raw)
    shutil.copytree(SOURCE, root / ".agent", symlinks=True)
    seed = root / ".agent/assets/fresh-state/v1"
    shutil.rmtree(root / ".agent/state")
    shutil.rmtree(root / ".agent/policies")
    shutil.copytree(seed / "state", root / ".agent/state")
    shutil.copytree(seed / "policies", root / ".agent/policies")
    shutil.copy2(seed / "config.json", root / ".agent/config.json")
    subprocess.run(["git","init","-q"],cwd=root,check=True)
    subprocess.run(["git","checkout","-q","-b","fix/workflow-hardening"],cwd=root,check=True)
    run(root, "agentctl", "validate")
    config_path = root / ".agent/config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["context_transport"]["pxpipe"]["selection"] = "render-without-analysis"
    write(config_path, config)
    output = run(root, "agentctl", "validate", expected=1)
    if "optional context transport policy is invalid" not in output:
        raise AssertionError(f"agentctl rejected the invalid plugin policy for the wrong reason:\n{output}")


with tempfile.TemporaryDirectory(prefix="control-gates-") as raw:
    root = Path(raw)
    scripts = root / ".agent/scripts"
    state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in (
        "agentctl.py", "contextctl.py", "contexttx.py", "workflowctl.py",
        "artifactctl.py", "humandecision.py",
    ):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    shutil.copytree(SOURCE / "scripts/workflowlib", scripts / "workflowlib")
    shutil.copy2(SOURCE / "INDEX.md", root / ".agent/INDEX.md")
    shutil.copytree(SOURCE / "workflows", root / ".agent/workflows")
    shutil.copytree(SOURCE / "templates", root / ".agent/templates")
    shutil.copytree(SOURCE / "policies", root / ".agent/policies")
    shutil.copytree(SOURCE / "skills/run-ai-coding-pipeline", root / ".agent/skills/run-ai-coding-pipeline")
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    contract = "# Requirement Contract\n\n- Human decisions: user:fixture\n- Clarified: true\n"
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    digest = hashlib.sha256(contract.encode()).hexdigest()
    task = {
        "schema": "agent-task/v2", "title": "control fixture", "task_type": "maintenance",
        "complexity": "bounded", "mode": "release", "files": 1, "environment": "local",
        "deployment_requested": False, "branch": "unversioned", "status": "in_progress",
        "phase": "implementation", "requirements_clarified": True,
        "requirement_source": "user:fixture", "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
        "requirement_contract_sha256": digest, "primary_skill": "run-ai-coding-pipeline",
        "risk_flags": {key: False for key in ("deploy", "data_risk", "cross_system", "uncertain", "security", "compliance", "migration", "irreversible", "external_impact")},
        "token_budget": 96000, "tokens_used": 79200, "token_usage_source": "estimated",
        "usage_receipts": [], "budget_state": "must_compact", "child_agents_used": 0,
        "peak_child_agents": 0, "loaded_references": [], "selected_templates": ["requirement-contract"],
        "selected_capabilities": ["core"], "template_route": None, "rendered_artifacts": [],
        "decisions": [], "open_questions": [], "next_action": "finish implementation",
        "current_node": 6, "accepted_nodes": list(range(6)), "node_artifacts": {},
        "gate_approvals": {"requirement": "user:fixture"}, "pending_gate_artifacts": {},
        "rollback_ledger": [], "rollback_archive": None,
        "failure_ledger": {}, "failure_archive": None, "mode_status": "confirmed",
        "metrics": {"tokens": 79200, "token_source": "estimated", "child_agents": 0, "peak_children": 0,
                    "tool_calls": 0, "test_runs": 0, "test_failures": 0, "repair_rounds": 0,
                    "user_corrections": 0, "context_compactions": 0, "references_loaded": 0},
        "updated": "2026-07-17",
    }
    write(state / "TASK.json", task)
    run(root, "contextctl", "sync", "--reason", "fixture", "--summary", "control fixture", "--source-tokens", "1600")

    run(root, "agentctl", "budget-gate", "--action", "unknown-typo", expected=2)
    run(root, "agentctl", "budget-gate", "--action", "route-templates", expected=2)
    pristine_context=(state/"CONTEXT.json").read_bytes()
    missing_handoff=json.loads(pristine_context); missing_handoff.pop("resume")
    write(state/"CONTEXT.json",missing_handoff)
    run(root,"agentctl","budget-gate","--action","finish-node",expected=2)
    (state/"CONTEXT.json").write_bytes(pristine_context)
    run(root, "agentctl", "budget-gate", "--action", "finish-node")
    run(root, "agentctl", "budget-gate", "--action", "spawn-review-agent")

    # Observed/estimated usage is never discarded merely because it crossed the
    # hard watermark; it is recorded and all expansion is then blocked.
    run(root, "agentctl", "record-usage", "--tokens", "7200", "--source", "estimated")
    hard = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if hard["tokens_used"] != 86400 or hard["budget_state"] != "hard_blocked":
        raise AssertionError("hard-watermark usage was not recorded truthfully")
    run(root, "agentctl", "budget-gate", "--action", "finish-node", expected=2)
    run(root, "agentctl", "budget-gate", "--action", "rollback")

    before = (state / "TASK.json").read_bytes()
    run(root, "workflowctl", "advance", "--node", "6", "--artifact", "missing.json", expected=1)
    if (state / "TASK.json").read_bytes() != before:
        raise AssertionError("hard-blocked workflow advance mutated TASK")

    # Local execution is a later-phase mutator and cannot be used while the
    # requirement contract is unclarified.
    hard["requirements_clarified"] = False
    hard["requirement_source"] = "pending"
    write(state / "TASK.json", hard)
    run(root, "agentctl", "managed-run", "--name", "forbidden", "--timeout", "1", "--", "/usr/bin/true", expected=1)

with tempfile.TemporaryDirectory(prefix="human-decision-v1-") as raw:
    root = Path(raw)
    scripts = root / ".agent/scripts"
    state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in ("agentctl.py", "contextctl.py", "contexttx.py", "humandecision.py"):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    copy_policy_runtime(root, scripts)
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    fixture_config = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))
    fixture_config["guardrails_ready"] = True
    write(root / ".agent/config.json", fixture_config)
    contract = """# Requirement Contract

- Goal: verify provider-owned human approval
- Users: workflow maintainers
- Success: unsigned approval is rejected
- In scope: requirement approval gate
- Out of scope: implementation
- Constraints: no external effects
- Data and permissions: fixture data only
- Target environment: local
- Acceptance: fail closed without a signed receipt
- Provenance: user fixture
- Human decisions: pending
- Clarified: false
"""
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    task = {
        "schema": "agent-task/v2", "title": "human decision v1 fixture",
        "task_type": "governance", "complexity": "bounded", "mode": "release",
        "files": 1, "environment": "local", "deployment_requested": False,
        "branch": "unversioned", "status": "waiting_human", "phase": "clarification",
        "requirements_clarified": False, "requirement_source": "pending",
        "primary_skill": "clarify-task", "decision_policy_version": 1,
        "risk_flags": {key: False for key in (
            "deploy", "data_risk", "cross_system", "uncertain", "security",
            "compliance", "migration", "irreversible", "external_impact",
        )},
        "token_budget": 96000, "tokens_used": 0, "token_usage_source": "estimated",
        "usage_receipts": [], "budget_state": "ok", "child_agents_used": 0,
        "peak_child_agents": 0, "loaded_references": [],
        "selected_templates": ["requirement-contract"], "selected_capabilities": ["core"],
        "template_route": None, "rendered_artifacts": [], "decisions": [],
        "open_questions": ["requirement contract approval"],
        "next_action": "approve requirement contract", "current_node": 1,
        "accepted_nodes": [0], "node_artifacts": {}, "gate_approvals": {},
        "pending_gate_artifacts": {}, "rollback_ledger": [], "rollback_archive": None,
        "failure_ledger": {}, "failure_archive": None,
        "mode_status": "provisional",
        "metrics": {
            "tokens": 0, "token_source": "estimated", "child_agents": 0,
            "peak_children": 0, "tool_calls": 0, "test_runs": 0,
            "test_failures": 0, "repair_rounds": 0, "user_corrections": 0,
            "context_compactions": 0, "references_loaded": 0,
        },
        "updated": "2026-07-18",
    }
    write(state / "TASK.json", task)
    run(
        root, "contextctl", "sync", "--reason", "fixture",
        "--summary", "unsigned human decision fixture", "--source-tokens", "1200",
    )
    before_task = (state / "TASK.json").read_bytes()
    before_contract = (state / "REQUIREMENT_CONTRACT.md").read_bytes()
    failure = run(
        root, "agentctl", "approve-requirements", "--source", "user:fixture",
        expected=1,
    )
    if "provider-signed human decision receipt" not in failure:
        raise AssertionError(f"v1 requirement gate failed for the wrong reason:\n{failure}")
    if (state / "TASK.json").read_bytes() != before_task or (state / "REQUIREMENT_CONTRACT.md").read_bytes() != before_contract:
        raise AssertionError("rejected unsigned v1 requirement approval mutated authoritative state")
    forged_provider_dir = Path(tempfile.mkdtemp(prefix="forged-human-provider-"))
    forged_adapter = forged_provider_dir / "verify-human-decision.py"
    forged_adapter.write_text("""#!/usr/bin/env python3
import hashlib, pathlib, sys
receipt = pathlib.Path(sys.argv[sys.argv.index('--receipt') + 1])
print('VERIFIED HUMAN DECISION sha256=' + hashlib.sha256(receipt.read_bytes()).hexdigest())
""", encoding="utf-8")
    forged_adapter.chmod(0o755)
    fixture_config["agent_control"]["human_decision_observer"]["signed_adapter"] = str(forged_adapter.resolve())
    write(root / ".agent/config.json", fixture_config)
    approved_contract = contract.replace("- Human decisions: pending", "- Human decisions: user:fixture").replace(
        "- Clarified: false", "- Clarified: true",
    )
    approved_sha = hashlib.sha256(approved_contract.encode()).hexdigest()
    profile = {
        key: task.get(key)
        for key in (
            "task_type", "complexity", "mode", "files", "environment",
            "deployment_requested", "branch", "risk_flags",
        )
    }
    routing_sha = hashlib.sha256(
        json.dumps(profile, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    forged_receipt = ".agent/state/evidence/forged-human-decision.json"
    write(root / forged_receipt, {
        "schema": "agent-human-decision/v1", "decision_id": "forged-temp-adapter",
        "gate": "requirement", "decision": "approved", "artifact_sha256": approved_sha,
        "source": "user:fixture", "task_title": task["title"], "task_mode": task["mode"],
        "routing_profile_sha256": routing_sha,
        "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "authority": "provider-signed-user-message",
    })
    forged_failure = run(
        root, "agentctl", "approve-requirements", "--source", "user:fixture",
        "--human-decision-receipt", forged_receipt, expected=1,
    )
    if "temporary boundary" not in forged_failure:
        raise AssertionError(f"Agent-created external adapter failed for the wrong reason:\n{forged_failure}")
    if (state / "TASK.json").read_bytes() != before_task or (state / "REQUIREMENT_CONTRACT.md").read_bytes() != before_contract:
        raise AssertionError("forged temporary adapter mutated or approved the v1 requirement gate")
    shutil.rmtree(forged_provider_dir)

with tempfile.TemporaryDirectory(prefix="workflow-hot-state-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in (
        "agentctl.py", "artifactctl.py", "contextctl.py", "contexttx.py",
        "humandecision.py", "workflowctl.py",
    ):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    copy_policy_runtime(root, scripts)
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    fixture_config = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))
    fixture_config.setdefault("context", {})["max_rollback_entries"] = 2
    fixture_config.setdefault("context", {})["max_failure_entries"] = 2
    fixture_config.setdefault("context", {})["max_failure_archive_depth"] = 2
    write(root / ".agent/config.json", fixture_config)
    contract = "# Requirement Contract\n\n- Human decisions: user:fixture\n- Clarified: true\n"
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    contract_sha = hashlib.sha256(contract.encode()).hexdigest()
    solution_path = state / "artifacts/04-solution.md"
    solution_path.parent.mkdir(parents=True)
    solution_path.write_text("# Approved candidate solution\n", encoding="utf-8")
    solution_sha = hashlib.sha256(solution_path.read_bytes()).hexdigest()
    task = {
        "schema": "agent-task/v2", "title": "decision and hot-state fixture",
        "task_type": "maintenance", "complexity": "bounded", "mode": "standard",
        "files": 1, "environment": "local", "deployment_requested": False,
        "branch": "unversioned", "status": "in_progress", "phase": "tests",
        "requirements_clarified": True, "requirement_source": "user:fixture",
        "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
        "requirement_contract_sha256": contract_sha, "primary_skill": "run-ai-coding-pipeline",
        "risk_flags": {key: False for key in (
            "deploy", "data_risk", "cross_system", "uncertain", "security",
            "compliance", "migration", "irreversible", "external_impact",
        )},
        "token_budget": 48000, "tokens_used": 0, "token_usage_source": "estimated",
        "usage_receipts": [], "budget_state": "ok", "child_agents_used": 0,
        "peak_child_agents": 0, "loaded_references": [], "selected_templates": ["solution"],
        "selected_capabilities": ["core"], "template_route": None,
        "rendered_artifacts": [{
            "template_id": "solution", "path": ".agent/state/artifacts/04-solution.md",
            "sha256": solution_sha, "bytes": len(solution_path.read_bytes()),
        }],
        "decisions": [], "open_questions": [], "next_action": "test rollback",
        "current_node": 5, "accepted_nodes": [0, 1, 2, 3, 4], "node_artifacts": {},
        "gate_approvals": {"requirement": "user:fixture", "solution": {
            "source": "user:old", "artifact_sha256": "0" * 64,
        }},
        "pending_gate_artifacts": {},
        "rollback_ledger": [{"sequence": number} for number in range(5)],
        "rollback_archive": None,
        "failure_ledger": {
            hashlib.sha256("archived-repeat|tests".encode()).hexdigest(): 2,
            **{hashlib.sha256(f"old-failure-{number}".encode()).hexdigest(): 1 for number in range(4)},
        },
        "failure_archive": None, "mode_status": "confirmed", "metrics": {},
    }
    write(state / "TASK.json", task)
    run(root, "contextctl", "sync", "--reason", "fixture", "--summary", "hot state fixture", "--source-tokens", "1200")
    compact_output = run(root, "workflowctl", "compact-state")
    compacted = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    head = compacted.get("rollback_archive", {})
    archive = root / str(head.get("path", ""))
    failure_head = compacted.get("failure_archive", {})
    if len(compacted["rollback_ledger"]) != 2 or head.get("total_entries") != 3:
        raise AssertionError("compact-state did not bound rollback hot state")
    if len(compacted["failure_ledger"]) != 2 or failure_head.get("total_signatures") != 3 or failure_head.get("total_events") != 4:
        raise AssertionError("compact-state did not bound failure hot state")
    if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != head.get("sha256"):
        raise AssertionError("compact-state did not publish content-addressed archive evidence")
    if "STATE COMPACTED" not in compact_output:
        raise AssertionError("compact-state did not report its archive head")
    before_noop = (state / "TASK.json").read_bytes()
    run(root, "workflowctl", "compact-state")
    if (state / "TASK.json").read_bytes() != before_noop:
        raise AssertionError("compact-state no-op rewrote canonical TASK")
    run(
        root, "workflowctl", "return-node", "--from-node", "5", "--to", "4",
        "--issue-id", "fixture-return", "--cause-category", "tests",
        "--subtask", "hot-state", "--root-cause", "fixture root cause",
        "--change", "fixture repair",
    )
    returned = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if len(returned["rollback_ledger"]) != 2 or returned["rollback_archive"].get("total_entries") != 4:
        raise AssertionError("return-node did not automatically compact and chain rollback history")
    if (
        len(returned["failure_ledger"]) != 2
        or returned["failure_archive"].get("total_signatures") != 4
        or returned["failure_archive"].get("depth") != 1
    ):
        raise AssertionError("return-node did not automatically compact failure history")
    submitted = run(
        root, "workflowctl", "submit-gate", "--gate", "solution",
        "--artifact", ".agent/state/artifacts/04-solution.md",
    )
    decided = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    packet = decided.get("decision_packet", {})
    if "solution" in decided["gate_approvals"]:
        raise AssertionError("submit-gate retained a stale approval for the resubmitted gate")
    if (
        packet.get("schema") != "agent-decision-packet/v1"
        or packet.get("approval_destination") != "node 5 test and acceptance planning"
        or "does not execute deployment" not in str(packet.get("scope_boundary"))
        or "does not execute deployment" not in decided["next_action"]
        or "DECISION REQUIRED" not in submitted
        or "advance to node 5" not in submitted
    ):
        raise AssertionError("submit-gate did not publish a readable bounded decision packet")
    run(
        root, "workflowctl", "return-node", "--from-node", "4", "--to", "3",
        "--issue-id", "archived-repeat", "--cause-category", "tests",
        "--subtask", "archived-count", "--root-cause", "same archived root cause",
        "--change", "request human decision",
    )
    repeated = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if repeated.get("status") != "waiting_human" or "three times" not in repeated.get("next_action", ""):
        raise AssertionError("archived failure count did not preserve the third-failure human gate")
    if repeated.get("accepted_nodes") != list(range(int(repeated["current_node"]))):
        raise AssertionError("third-failure waiting_human state is not a valid node prefix")
    state_probe = subprocess.run(
        [sys.executable, "-c", (
            "import json,sys;sys.path.insert(0,'.agent/scripts');import workflowctl;"
            "t=json.load(open('.agent/state/TASK.json'));"
            "e=workflowctl.state_machine_errors(t);print('\\n'.join(e));raise SystemExit(bool(e))"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if state_probe.returncode:
        raise AssertionError(f"third-failure state machine is invalid:\n{state_probe.stdout}")

with tempfile.TemporaryDirectory(prefix="fast-route-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in ("agentctl.py", "contextctl.py", "contexttx.py", "templatectl.py", "humandecision.py"):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    copy_policy_runtime(root, scripts)
    shutil.copytree(SOURCE / "assets", root / ".agent/assets")
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    contract = "# Requirement Contract\n\n- Human decisions: user:fixture\n- Clarified: true\n"
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    digest = hashlib.sha256(contract.encode()).hexdigest()
    fast = {
        "schema": "agent-task/v2", "title": "fast route", "task_type": "maintenance", "complexity": "tiny",
        "mode": "fast", "files": 1, "environment": "local", "deployment_requested": False,
        "branch": "unversioned", "status": "in_progress", "phase": "planning",
        "requirements_clarified": True, "requirement_source": "user:fixture",
        "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md", "requirement_contract_sha256": digest,
        "token_budget": 16000, "tokens_used": 0, "token_usage_source": "estimated", "usage_receipts": [],
        "budget_state": "ok", "child_agents_used": 0, "peak_child_agents": 0,
        "loaded_references": [], "selected_templates": ["requirement-contract"], "selected_capabilities": ["core"],
        "template_route": None, "rendered_artifacts": [], "decisions": [], "open_questions": [],
        "next_action": "route fast templates", "current_node": 2, "accepted_nodes": [0, 1],
        "node_artifacts": {}, "gate_approvals": {"requirement": "user:fixture"}, "pending_gate_artifacts": {},
        "rollback_ledger": [], "rollback_archive": None,
        "failure_ledger": {}, "failure_archive": None, "mode_status": "confirmed", "metrics": {},
    }
    write(state / "TASK.json", fast)
    run(root, "contextctl", "sync", "--reason", "fast", "--summary", "fast route fixture", "--source-tokens", "1400")
    run(root, "templatectl", "route")
    routed = json.loads((state / "TASK.json").read_text(encoding="utf-8"))["selected_templates"]
    expected = ["requirement-contract", "node-implementation", "retrospective"]
    if routed != expected or any(item in routed for item in ("task-plan", "acceptance-matrix", "node-acceptance")):
        raise AssertionError(f"fast route is still heavy or dependency-invalid: {routed}")

ESCALATION_RISKS = {key: False for key in (
    "deploy", "data_risk", "cross_system", "uncertain", "security",
    "compliance", "migration", "irreversible", "external_impact",
)}


def escalation_task(contract_sha: str) -> dict:
    return {
        "schema": "agent-task/v2", "title": "escalation fixture", "task_type": "maintenance",
        "complexity": "tiny", "mode": "fast", "files": 1, "environment": "local",
        "deployment_requested": False, "branch": "unversioned", "status": "in_progress",
        "phase": "planning", "requirements_clarified": True, "requirement_source": "user:fixture",
        "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
        "requirement_contract_sha256": contract_sha, "primary_skill": "run-ai-coding-pipeline",
        "risk_flags": dict(ESCALATION_RISKS), "decision_policy_version": 2,
        "token_budget": 16000, "tokens_used": 0, "token_usage_source": "estimated",
        "usage_receipts": [], "budget_state": "ok", "child_agents_used": 0,
        "peak_child_agents": 0, "loaded_references": [],
        "selected_templates": ["requirement-contract"], "selected_capabilities": ["core"],
        "template_route": None, "rendered_artifacts": [], "decisions": [], "open_questions": [],
        "next_action": "route templates", "current_node": 2, "accepted_nodes": [0, 1],
        "node_artifacts": {}, "gate_approvals": {}, "pending_gate_artifacts": {},
        "rollback_ledger": [], "rollback_archive": None,
        "failure_ledger": {}, "failure_archive": None, "mode_status": "confirmed",
        "projection": "lightweight", "metrics": {}, "updated": "2026-07-30",
    }


with tempfile.TemporaryDirectory(prefix="escalate-policy-flip-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in ("agentctl.py", "contextctl.py", "contexttx.py", "humandecision.py"):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    copy_policy_runtime(root, scripts)
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    shutil.copy2(SOURCE / "assets/fresh-state/v1/state/agents.json", state / "agents.json")
    contract = "# Requirement Contract\n\n- Human decisions: user:fixture\n- Clarified: true\n"
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    contract_sha = hashlib.sha256(contract.encode()).hexdigest()
    write(state / "TASK.json", escalation_task(contract_sha))
    # Bind the requirement approval to the current routing profile via the real helper.
    bind = subprocess.run(
        [sys.executable, "-c", (
            "import json,sys;sys.path.insert(0,'.agent/scripts');import humandecision;"
            "p='.agent/state/TASK.json';t=json.load(open(p));"
            "t['gate_approvals']={'requirement':humandecision.local_approval("
            "'user:fixture',t['requirement_contract_sha256'],t)};"
            "json.dump(t,open(p,'w'),ensure_ascii=False,indent=2)"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if bind.returncode:
        raise AssertionError(f"could not bind the local routing-profile approval:\n{bind.stdout}")
    run(root, "contextctl", "sync", "--reason", "fixture", "--summary", "escalation fixture", "--source-tokens", "1200")

    # A routing-profile-changing escalation must refuse to strand the old approval.
    before_task = (state / "TASK.json").read_bytes()
    refusal = run(root, "agentctl", "escalate-mode", "--new-mode", "standard", expected=1)
    if "would invalidate the current requirement approval" not in refusal or "--reapprove --source user:<decision>" not in refusal:
        raise AssertionError(f"profile-changing escalation refused for the wrong reason:\n{refusal}")
    if (state / "TASK.json").read_bytes() != before_task:
        raise AssertionError("a refused escalation mutated TASK")
    misuse = run(root, "agentctl", "escalate-mode", "--new-mode", "standard", "--source", "user:fixture", expected=1)
    if "valid only with --reapprove" not in misuse:
        raise AssertionError(f"--source without --reapprove failed for the wrong reason:\n{misuse}")

    # The combined command switches policy and re-records the approval atomically.
    run(root, "agentctl", "escalate-mode", "--new-mode", "standard", "--reapprove", "--source", "user:escalated")
    escalated = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if escalated.get("mode") != "standard" or escalated.get("decision_policy_version") != 2 or escalated.get("requirement_source") != "user:escalated":
        raise AssertionError(f"reapprove escalation committed a wrong task state: {escalated.get('mode')}")
    route_archive = escalated.get("route_archive", {})
    if not (root / str(route_archive.get("path", ""))).is_file():
        raise AssertionError("escalation did not publish its route archive evidence")
    reapproval_check = subprocess.run(
        [sys.executable, "-c", (
            "import json,sys;sys.path.insert(0,'.agent/scripts');import humandecision;"
            "t=json.load(open('.agent/state/TASK.json'));a=t['gate_approvals']['requirement'];"
            "ok=(a.get('routing_profile_sha256')==humandecision.routing_profile_sha256(t)"
            " and humandecision.local_approval_valid(t,a,source='user:escalated',"
            "artifact_sha256=t['requirement_contract_sha256'],config=json.load(open('.agent/config.json'))));"
            "raise SystemExit(0 if ok else 1)"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if reapproval_check.returncode:
        raise AssertionError(f"re-approved requirement is not valid under the new routing profile:\n{reapproval_check.stdout}")
    noop = run(root, "agentctl", "escalate-mode", "--new-mode", "standard", "--reapprove", "--source", "user:escalated", expected=1)
    if "no-op" not in noop:
        raise AssertionError(f"repeated escalation was not rejected as a no-op:\n{noop}")

    # A v2 -> v1 policy flip is refused with the provider-receipt remedy, and the
    # combined command cannot complete v1 re-approval without that receipt.
    before_task = (state / "TASK.json").read_bytes()
    flip = run(root, "agentctl", "escalate-mode", "--new-risk", "irreversible", expected=1)
    if "would invalidate the current requirement approval" not in flip or "--human-decision-receipt" not in flip:
        raise AssertionError(f"v2->v1 escalation refused for the wrong reason:\n{flip}")
    if (state / "TASK.json").read_bytes() != before_task:
        raise AssertionError("a refused v2->v1 escalation mutated TASK")
    no_receipt = run(
        root, "agentctl", "escalate-mode", "--new-risk", "irreversible",
        "--reapprove", "--source", "user:escalated", expected=1,
    )
    if "provider-signed human decision receipt" not in no_receipt:
        raise AssertionError(f"v1 re-approval without a receipt failed for the wrong reason:\n{no_receipt}")
    if (state / "TASK.json").read_bytes() != before_task:
        raise AssertionError("a failed v1 re-approval mutated TASK")

with tempfile.TemporaryDirectory(prefix="task-archive-v2-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in (
        "agentctl.py", "contextctl.py", "contexttx.py",
        "humandecision.py", "deliveryctl.py", "evidencectl.py",
    ):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    shutil.copytree(SOURCE / "scripts/workflowlib", scripts / "workflowlib")
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    (state / "evidence").mkdir()
    (state / "evidence/referenced-note.txt").write_text("referenced evidence bytes\n", encoding="utf-8")
    (state / "evidence/unreferenced-note.txt").write_text("unreferenced evidence bytes\n", encoding="utf-8")
    contract = "# Requirement Contract\n\n- Human decisions: user:fixture\n- Clarified: true\n"
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    (state / "delivery.json").write_text('{"schema":"agent-delivery/v3","epochs":[]}\n', encoding="utf-8")
    write(state / "TASK.json", {
        "schema": "agent-task/v2",
        "title": "archive fixture referencing .agent/state/evidence/referenced-note.txt",
        "task_archive": None, "status": "accepted",
    })
    archive_probe = subprocess.run(
        [sys.executable, "-c", (
            "import hashlib,json,sys;sys.path.insert(0,'.agent/scripts');"
            "import agentctl,evidencectl;"
            "state=agentctl.AGENT_DIR/'state';"
            "task_bytes=(state/'TASK.json').read_bytes();"
            "contract_bytes=(state/'REQUIREMENT_CONTRACT.md').read_bytes();"
            "delivery_bytes=(state/'delivery.json').read_bytes();"
            "ref=hashlib.sha256((state/'evidence/referenced-note.txt').read_bytes()).hexdigest();"
            "unref=hashlib.sha256((state/'evidence/unreferenced-note.txt').read_bytes()).hexdigest();"
            "previous=json.loads(task_bytes);"
            "head1,path1,data1=agentctl.build_task_archive(previous,source='user:fixture',reason='first',decision_receipt=None,assurance='test');"
            "path1.parent.mkdir(parents=True,exist_ok=True);path1.write_bytes(data1);"
            "p1=json.loads(data1);"
            "assert p1['schema']=='agent-task-archive/v2',p1['schema'];"
            "assert p1['task']=={'sha256':hashlib.sha256(task_bytes).hexdigest(),'bytes':len(task_bytes),'utf8':task_bytes.decode('utf-8')},'task bytes not embedded exactly';"
            "assert p1['requirement_contract']=={'sha256':hashlib.sha256(contract_bytes).hexdigest(),'bytes':len(contract_bytes),'utf8':contract_bytes.decode('utf-8')},'contract bytes not embedded exactly';"
            "assert p1['delivery']=={'sha256':hashlib.sha256(delivery_bytes).hexdigest(),'bytes':len(delivery_bytes),'utf8':delivery_bytes.decode('utf-8')},'delivery bytes not embedded exactly';"
            "assert p1['referenced_evidence']==[ref],p1['referenced_evidence'];"
            "assert unref not in p1['referenced_evidence'];"
            "assert p1['previous'] is None;"
            "assert data1==json.dumps(p1,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()+b'\\n','payload bytes are not canonical';"
            "assert head1=={'schema':'agent-task-archive-head/v1','path':str(path1.relative_to(agentctl.AGENT_DIR.parent)),'sha256':hashlib.sha256(data1).hexdigest(),'bytes':len(data1),'total_archives':1},head1;"
            "head2,path2,data2=agentctl.build_task_archive({'task_archive':head1},source='user:fixture',reason='second',decision_receipt=None,assurance='test');"
            "path2.write_bytes(data2);p2=json.loads(data2);"
            "assert p2['previous']==head1 and head2['total_archives']==2,'chain head not anchored';"
            "chain=evidencectl.task_archive_chain(head2);"
            "assert len(chain)==2 and all(item[1]['schema']=='agent-task-archive/v2' for item in chain),'evidencectl rejected the v2 chain';"
            "(state/'REQUIREMENT_CONTRACT.md').unlink();"
            "head3,path3,data3=agentctl.build_task_archive({'task_archive':head2},source='s',reason='r',decision_receipt=None,assurance='a');"
            "assert json.loads(data3)['requirement_contract'] is None,'missing contract must archive as null';"
            "print('TASK ARCHIVE V2 PROBE OK')"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if archive_probe.returncode or "TASK ARCHIVE V2 PROBE OK" not in archive_probe.stdout:
        raise AssertionError(f"task-archive v2 writer contract violated:\n{archive_probe.stdout}")

with tempfile.TemporaryDirectory(prefix="cleanup-leases-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in ("agentctl.py", "contextctl.py", "contexttx.py", "humandecision.py", "evidencectl.py"):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    shutil.copytree(SOURCE / "scripts/workflowlib", scripts / "workflowlib")
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    shutil.copy2(SOURCE / "assets/fresh-state/v1/state/agents.json", state / "agents.json")
    shutil.copy2(SOURCE / "assets/fresh-state/v1/state/EVIDENCE_INDEX.json", state / "EVIDENCE_INDEX.json")
    write(state / "runtime.json", {
        "schema": "agent-runtime/v2",
        "baseline": {"source": "user:fixture", "captured_at": "2026-07-30T00:00:00+00:00", "project_processes": []},
        "processes": [], "docker_projects": [], "ports": [],
    })
    now = dt.datetime.now(dt.timezone.utc)
    past = (now - dt.timedelta(minutes=10)).replace(microsecond=0).isoformat()
    auth_dir = state / ".context-authorizations"
    auth_dir.mkdir()
    write(auth_dir / "stale.json", {"issued_at": past})
    write(auth_dir / "fresh.json", {"issued_at": now.replace(microsecond=0).isoformat()})
    write(state / "tool-leases.json", {
        "schema": "agent-tool-leases/v1",
        "leases": [{
            "id": "malformed", "owner_agent_id": "nobody", "name": "malformed",
            "started_at": past, "deadline_at": past, "supervisor": None,
            "process": "not-a-dict", "command": ["true"],
            "policy": "bounded-platform-review-tool/v1",
        }],
    })
    # A lease without a dict process record is retained and reported, never dropped.
    failed = run(root, "agentctl", "cleanup", expected=1)
    if "malformed-process-record" not in failed or "CLEANUP FAILED" not in failed:
        raise AssertionError(f"cleanup did not report the malformed tool lease:\n{failed}")
    retained = json.loads((state / "tool-leases.json").read_text(encoding="utf-8"))["leases"]
    if len(retained) != 1 or retained[0].get("id") != "malformed":
        raise AssertionError(f"cleanup silently dropped the malformed tool lease: {retained}")
    # Stranded context authorizations past their validity window are swept; fresh stay.
    if "swept 1 stranded context authorization(s)" not in failed:
        raise AssertionError(f"cleanup did not report the stranded authorization sweep:\n{failed}")
    if (auth_dir / "stale.json").exists() or not (auth_dir / "fresh.json").is_file():
        raise AssertionError("context authorization sweep removed the wrong records")
    write(state / "tool-leases.json", {"schema": "agent-tool-leases/v1", "leases": []})
    passed = run(root, "agentctl", "cleanup")
    if "CLEANUP PASSED" not in passed or "deep verification skipped" in passed:
        raise AssertionError(f"cleanup did not pass with a wired deep evidence verification:\n{passed}")

    # Supervisor liveness is part of lease retention: a live, fresh, owned lease
    # survives; the same lease with a dead supervisor is reaped exactly.
    lease_probe_script = root / "lease_probe.py"
    lease_probe_script.write_text(
        """import datetime as dt
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, ".agent/scripts")
import agentctl

now = dt.datetime.now(dt.timezone.utc)
future = (now + dt.timedelta(minutes=10)).replace(microsecond=0).isoformat()
started = now.replace(microsecond=0).isoformat()
kept = subprocess.Popen(["sleep", "30"], start_new_session=True)
reaped = subprocess.Popen(["sleep", "30"], start_new_session=True)


def lease(lease_id, process):
    snap = None
    for _ in range(50):
        snap = agentctl.process_snapshot(process.pid)
        if snap is not None:
            break
        if process.poll() is not None:
            break
        time.sleep(0.02)
    assert snap is not None, f"could not snapshot leased process {process.pid}"
    record = {key: snap[key] for key in ("pid", "pgid", "start_time", "command", "cwd")}
    record.update({"name": lease_id, "kind": "foreground-tool", "scope": "isolated_process_group"})
    supervisor = agentctl.process_snapshot(os.getpid()) if lease_id == "kept" else {
        "pid": 999999, "pgid": 999999, "start_time": 1,
        "command": "dead-supervisor", "cwd": record["cwd"],
    }
    return {
        "id": lease_id, "owner_agent_id": "owner", "name": lease_id,
        "started_at": started, "deadline_at": future,
        "supervisor": supervisor, "supervisor_chain": [],
        "process": record, "command": ["sleep", "30"],
        "policy": "bounded-platform-review-tool/v1",
    }


try:
    agentctl.TOOL_LEASES_PATH.write_text(json.dumps({
        "schema": "agent-tool-leases/v1",
        "leases": [lease("kept", kept), lease("reaped", reaped)],
    }, indent=2) + "\\n", encoding="utf-8")
    # The owner check is exercised elsewhere; here every lease is owner-active so
    # only supervisor/group/deadline liveness decides retention.
    agentctl.active_review_agent_member = lambda agent_id: {"id": agent_id}
    failures = agentctl.cleanup_tool_leases(5)
    remaining = [item["id"] for item in json.loads(agentctl.TOOL_LEASES_PATH.read_text())["leases"]]
    assert failures == [], failures
    assert remaining == ["kept"], remaining
    assert not agentctl.process_group_alive(reaped.pid), "dead-supervisor lease group survived"
    assert agentctl.process_group_alive(kept.pid), "live-supervisor lease group was killed"
    print("LEASE SUPERVISOR PROBE OK")
finally:
    for process in (kept, reaped):
        try:
            process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
""",
        encoding="utf-8",
    )
    lease_probe = subprocess.run(
        [sys.executable, str(lease_probe_script)], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if lease_probe.returncode or "LEASE SUPERVISOR PROBE OK" not in lease_probe.stdout:
        raise AssertionError(f"tool-lease supervisor reaping is broken:\n{lease_probe.stdout}")

    # Docker residuals include named volumes: declared volumes force `down -v`
    # and leftover named volumes fail assert-clean.
    fakebin = root / "fakebin"
    fakebin.mkdir()
    docker_log = root / "docker.log"
    (fakebin / "docker").write_text(
        "#!/bin/bash\n"
        f"echo \"$*\" >> {docker_log}\n"
        "if [ \"$1\" = \"volume\" ] && [ \"$FAKE_DOCKER_VOLUME_RESIDUAL\" = \"1\" ]; then\n"
        "  echo leftover-volume\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    (fakebin / "docker").chmod(0o755)
    (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    run(
        root, "agentctl", "register-docker", "--project", "agent_fixture1",
        "--workdir", ".", "--file", "compose.yaml", "--volume", "datavol",
    )
    original_path = os.environ["PATH"]
    os.environ["PATH"] = f"{fakebin}:{original_path}"
    try:
        run(root, "agentctl", "cleanup")
        log_lines = docker_log.read_text(encoding="utf-8").splitlines()
        if not any("compose" in line and "-p agent_fixture1 down --remove-orphans -v" in line for line in log_lines):
            raise AssertionError(f"declared volumes did not force compose down -v:\n{log_lines}")
        if not any(line.startswith("volume ls") for line in log_lines):
            raise AssertionError(f"docker residual check does not count named volumes:\n{log_lines}")
        run(
            root, "agentctl", "register-docker", "--project", "agent_fixture1",
            "--workdir", ".", "--file", "compose.yaml", "--volume", "datavol",
        )
        os.environ["FAKE_DOCKER_VOLUME_RESIDUAL"] = "1"
        residual = run(root, "agentctl", "assert-clean", expected=1)
        if "agent_fixture1" not in residual or "volume" not in residual:
            raise AssertionError(f"assert-clean ignored a leftover named volume:\n{residual}")
        del os.environ["FAKE_DOCKER_VOLUME_RESIDUAL"]
        run(root, "agentctl", "cleanup")
    finally:
        os.environ["PATH"] = original_path
        os.environ.pop("FAKE_DOCKER_VOLUME_RESIDUAL", None)

    # Capturing a baseline over pre-existing unregistered processes requires an
    # explicit confirmation flag so leaks cannot become invisible.
    sleeper = subprocess.Popen(["sleep", "30"], cwd=root)
    try:
        baseline_refusal = run(
            root, "agentctl", "capture-runtime-baseline", "--source", "user:fixture", expected=1,
        )
        if "unregistered project processes already exist" not in baseline_refusal or "--confirm-existing-processes" not in baseline_refusal:
            raise AssertionError(f"baseline capture absorbed a pre-existing process:\n{baseline_refusal}")
        confirmed = run(
            root, "agentctl", "capture-runtime-baseline",
            "--source", "user:fixture", "--confirm-existing-processes",
        )
        if "RUNTIME BASELINE WARNING" not in confirmed:
            raise AssertionError(f"confirmed baseline capture did not warn:\n{confirmed}")
    finally:
        sleeper.kill()
        sleeper.wait()


with tempfile.TemporaryDirectory(prefix="knowledge-loop-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in ("agentctl.py", "contextctl.py", "contexttx.py", "humandecision.py"):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    shutil.copytree(SOURCE / "scripts/workflowlib", scripts / "workflowlib")
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    (root / ".agent/knowledge").mkdir()
    (root / ".agent/capabilities").mkdir()
    shutil.copy2(SOURCE / "knowledge/INDEX.md", root / ".agent/knowledge/INDEX.md")
    shutil.copy2(SOURCE / "capabilities/INDEX.md", root / ".agent/capabilities/INDEX.md")
    # The archival path lifts retrospective candidates into the pending registry.
    pending_probe = subprocess.run(
        [sys.executable, "-c", (
            "import json,sys;sys.path.insert(0,'.agent/scripts');import agentctl;"
            "effect=agentctl.knowledge_pending_side_effect({"
            "'title':'old task','knowledge_candidates':['  always pin deps  ','',42,'keep INDEX short']});"
            "assert effect is not None;"
            "path,data=effect;path.write_bytes(data);"
            "pending=json.loads(path.read_text());"
            "assert pending['schema']=='agent-knowledge-pending/v1';"
            "assert [c['candidate'] for c in pending['candidates']]==['always pin deps','keep INDEX short'];"
            "assert all(c['task_title']=='old task' and c['recorded_at'] for c in pending['candidates']);"
            "notice=agentctl.knowledge_pending_notice();"
            "assert '2 retrospective knowledge candidate(s)' in notice,notice;"
            "assert agentctl.knowledge_pending_side_effect({'title':'t'}) is None;"
            "assert agentctl.knowledge_pending_side_effect({'knowledge_candidates':[]}) is None;"
            "print('KNOWLEDGE PENDING PROBE OK')"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if pending_probe.returncode or "KNOWLEDGE PENDING PROBE OK" not in pending_probe.stdout:
        raise AssertionError(f"knowledge pending extraction is broken:\n{pending_probe.stdout}")
    bad_source = run(root, "agentctl", "promote-knowledge", "0", "--target", "knowledge", "--source", "bogus", expected=1)
    if "user:" not in bad_source:
        raise AssertionError(f"promotion without a human source failed for the wrong reason:\n{bad_source}")
    run(root, "agentctl", "promote-knowledge", "0", "--target", "knowledge", "--source", "user:promo")
    knowledge_text = (root / ".agent/knowledge/INDEX.md").read_text(encoding="utf-8")
    if "always pin deps" not in knowledge_text or "promoted from task 'old task'" not in knowledge_text:
        raise AssertionError(f"knowledge promotion did not write the index:\n{knowledge_text}")
    pending = json.loads((state / "knowledge-pending.json").read_text(encoding="utf-8"))
    if (
        [c["candidate"] for c in pending["candidates"]] != ["keep INDEX short"]
        or len(pending["promotions"]) != 1
        or pending["promotions"][0].get("source") != "user:promo"
        or pending["promotions"][0].get("target") != "knowledge"
    ):
        raise AssertionError(f"promotion receipt or pending removal is wrong: {pending}")
    out_of_range = run(root, "agentctl", "promote-knowledge", "5", "--target", "knowledge", "--source", "user:promo", expected=1)
    if "out of range" not in out_of_range:
        raise AssertionError(f"stale candidate index failed for the wrong reason:\n{out_of_range}")
    missing_entry = run(root, "agentctl", "promote-knowledge", "0", "--target", "capabilities", "--source", "user:promo", expected=1)
    if "--entry" not in missing_entry:
        raise AssertionError(f"capability promotion without entry failed for the wrong reason:\n{missing_entry}")
    run(
        root, "agentctl", "promote-knowledge", "0", "--target", "capabilities",
        "--source", "user:promo", "--entry", ".agent/scripts/example.py", "--contract", "does example work",
    )
    capabilities_text = (root / ".agent/capabilities/INDEX.md").read_text(encoding="utf-8")
    if "| keep INDEX short | `.agent/scripts/example.py` | does example work |" not in capabilities_text:
        raise AssertionError(f"capability promotion did not write the registry table:\n{capabilities_text}")
    pending = json.loads((state / "knowledge-pending.json").read_text(encoding="utf-8"))
    if pending["candidates"] or len(pending["promotions"]) != 2:
        raise AssertionError(f"capability promotion did not drain the pending registry: {pending}")

with tempfile.TemporaryDirectory(prefix="bootstrap-adapters-") as raw:
    root = Path(raw)
    shutil.copytree(SOURCE, root / ".agent", symlinks=True)
    seed = root / ".agent/assets/fresh-state/v1"
    shutil.rmtree(root / ".agent/state")
    shutil.rmtree(root / ".agent/policies")
    shutil.copytree(seed / "state", root / ".agent/state")
    shutil.copytree(seed / "policies", root / ".agent/policies")
    shutil.copy2(seed / "config.json", root / ".agent/config.json")
    config = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))
    config["acceptance_adapters"] = {
        "acceptance-web-docker": {"implemented": True, "runner": ".agent/scripts/missing-docker-runner.py"},
        "acceptance-ios": {"implemented": True, "runner": ".agent/scripts/missing-ios-runner.py"},
        "acceptance-cli": {"implemented": False, "runner": ".agent/scripts/missing-cli-runner.py"},
    }
    write(root / ".agent/config.json", config)
    # Editing config is policy-bundle drift under the bound capsule; re-bind the
    # seeded checkpoint through the fail-closed repair path before probing.
    run(root, "contextctl", "repair", "--reason", "fixture config", "--summary", "fixture config", "--source-tokens", "800", expected=1)
    run(root, "contextctl", "approve-repair", "--source", "user:fixture")
    # Guardrails stay uninitialized in the seed: warnings are non-fatal and the
    # check still reports its usual next-step exit.
    output = run(root, "agentctl", "bootstrap-check", expected=2)
    if "acceptance-web-docker declares implemented=true but its runner is missing" not in output:
        raise AssertionError(f"bootstrap-check did not probe the declared docker runner:\n{output}")
    if "acceptance-ios declares implemented=true but its runner is missing" not in output:
        raise AssertionError(f"bootstrap-check did not probe the declared ios runner:\n{output}")
    if "missing-cli-runner" in output:
        raise AssertionError(f"bootstrap-check probed an adapter not declared implemented:\n{output}")
    if shutil.which("docker") is None and "docker is not on PATH" not in output:
        raise AssertionError(f"bootstrap-check missed the absent docker host prerequisite:\n{output}")
    if shutil.which("xcodebuild") is None and "xcodebuild is not on PATH" not in output:
        raise AssertionError(f"bootstrap-check missed the absent xcodebuild host prerequisite:\n{output}")

with tempfile.TemporaryDirectory(prefix="start-node0-") as raw:
    root = Path(raw)
    shutil.copytree(SOURCE, root / ".agent", symlinks=True)
    seed = root / ".agent/assets/fresh-state/v1"
    shutil.rmtree(root / ".agent/state")
    shutil.rmtree(root / ".agent/policies")
    shutil.copytree(seed / "state", root / ".agent/state")
    shutil.copytree(seed / "policies", root / ".agent/policies")
    shutil.copy2(seed / "config.json", root / ".agent/config.json")
    state = root / ".agent/state"
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "checkout", "-q", "-b", "fix/node0-fixture"], cwd=root, check=True)
    # Node 0's minimal contract refuses a task without a usable title.
    refusal = run(
        root, "agentctl", "start", "--title", "", "--mode", "fast", "--environment", "local",
        "--task-type", "maintenance", "--complexity", "tiny", "--files", "1", expected=1,
    )
    if "node 0 minimal contract failed" not in refusal:
        raise AssertionError(f"start without the node-0 contract failed for the wrong reason:\n{refusal}")
    if json.loads((state / "TASK.json").read_text(encoding="utf-8")).get("status") != "idle":
        raise AssertionError("a refused start mutated the idle TASK")
    # A pending knowledge registry is surfaced at every start.
    (state / "evidence").mkdir()
    (state / "evidence/fixture-note.txt").write_text("archive reachability fixture\n", encoding="utf-8")
    write(state / "knowledge-pending.json", {
        "schema": "agent-knowledge-pending/v1",
        "candidates": [{"candidate": "older candidate", "task_title": "older task", "recorded_at": "2026-07-30T00:00:00+00:00"}],
        "promotions": [],
    })
    started = run(
        root, "agentctl", "start",
        "--title", "first fixture uses .agent/state/evidence/fixture-note.txt",
        "--mode", "fast", "--environment", "local", "--task-type", "maintenance",
        "--complexity", "tiny", "--files", "1",
    )
    if "STARTED fast task in clarification" not in started:
        raise AssertionError(f"fresh start failed:\n{started}")
    if "KNOWLEDGE PENDING" not in started or "promote-knowledge" not in started:
        raise AssertionError(f"start did not surface the pending knowledge candidates:\n{started}")
    first = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if first.get("projection") != "lightweight" or first.get("decision_policy_version") != 2:
        raise AssertionError(f"start did not persist the routing projection: {first.get('projection')}")
    first_task_bytes = (state / "TASK.json").read_bytes()
    first_delivery_bytes = (state / "delivery.json").read_bytes()

    # Replacing an active task archives it as a byte-exact task-archive/v2 payload
    # with the delivery state and digest-bound evidence references embedded.
    rotated = run(
        root, "agentctl", "start", "--title", "second fixture",
        "--mode", "fast", "--environment", "local", "--task-type", "governance",
        "--complexity", "tiny", "--files", "1",
        "--archive-active", "--archive-source", "user:rotate", "--archive-reason", "rotate fixture",
    )
    if "STARTED fast task in clarification" not in rotated:
        raise AssertionError(f"archiving start failed:\n{rotated}")
    second = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    head = second.get("task_archive", {})
    archive = root / str(head.get("path", ""))
    if (
        head.get("schema") != "agent-task-archive-head/v1"
        or head.get("total_archives") != 1
        or not archive.is_file()
        or hashlib.sha256(archive.read_bytes()).hexdigest() != head.get("sha256")
        or len(archive.read_bytes()) != head.get("bytes")
    ):
        raise AssertionError(f"archiving start did not anchor a verified v2 head: {head}")
    payload = json.loads(archive.read_bytes())
    referenced_sha = hashlib.sha256((state / "evidence/fixture-note.txt").read_bytes()).hexdigest()
    if (
        payload.get("schema") != "agent-task-archive/v2"
        or payload.get("source") != "user:rotate"
        or payload.get("reason") != "rotate fixture"
        or payload.get("previous") is not None
        or payload.get("task", {}).get("utf8") != first_task_bytes.decode("utf-8")
        or payload.get("task", {}).get("sha256") != hashlib.sha256(first_task_bytes).hexdigest()
    ):
        raise AssertionError(f"task archive payload is not the byte-exact v2 contract: {sorted(payload)}")
    delivery = payload.get("delivery")
    if (
        not isinstance(delivery, dict)
        or delivery.get("utf8") != first_delivery_bytes.decode("utf-8")
        or delivery.get("sha256") != hashlib.sha256(first_delivery_bytes).hexdigest()
    ):
        raise AssertionError(f"task archive did not embed the exact delivery bytes: {delivery}")
    if referenced_sha not in payload.get("referenced_evidence", []):
        raise AssertionError(f"task archive lost the referenced evidence digest: {payload.get('referenced_evidence')}")
    if second.get("projection") != "lightweight":
        raise AssertionError(f"archiving start persisted a wrong projection: {second.get('projection')}")
    chain_probe = subprocess.run(
        [sys.executable, "-c", (
            "import json,sys;sys.path.insert(0,'.agent/scripts');import evidencectl;"
            "head=json.load(open('.agent/state/TASK.json'))['task_archive'];"
            "chain=evidencectl.task_archive_chain(head);"
            "assert len(chain)==1 and chain[0][1]['schema']=='agent-task-archive/v2';"
            "print('START ARCHIVE CHAIN OK')"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if chain_probe.returncode or "START ARCHIVE CHAIN OK" not in chain_probe.stdout:
        raise AssertionError(f"evidencectl rejected the start-produced v2 archive chain:\n{chain_probe.stdout}")

with tempfile.TemporaryDirectory(prefix="start-defaults-") as raw:
    root = Path(raw)
    shutil.copytree(SOURCE, root / ".agent", symlinks=True)
    seed = root / ".agent/assets/fresh-state/v1"
    shutil.rmtree(root / ".agent/state")
    shutil.rmtree(root / ".agent/policies")
    shutil.copytree(seed / "state", root / ".agent/state")
    shutil.copytree(seed / "policies", root / ".agent/policies")
    shutil.copy2(seed / "config.json", root / ".agent/config.json")
    state = root / ".agent/state"
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "checkout", "-q", "-b", "fix/defaults-fixture"], cwd=root, check=True)
    # A bare start declares nothing: the minimal defaults must route it to fast,
    # leaving the node-6 scope gate as the post-hoc corrector for under-declaration.
    started = run(root, "agentctl", "start", "--title", "bare start defaults fixture")
    if "STARTED fast task in clarification" not in started:
        raise AssertionError(f"bare start did not route to fast:\n{started}")
    task = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if (
        task.get("mode") != "fast"
        or task.get("complexity") != "tiny"
        or task.get("files") != 1
        or task.get("decision_policy_version") != 2
    ):
        raise AssertionError(f"bare start persisted wrong routing defaults: {task.get('mode')}/{task.get('complexity')}/{task.get('files')}")
    # Explicit declarations are unchanged: bounded complexity with 3 files still
    # routes to standard on the exact same command surface.
    rotated = run(
        root, "agentctl", "start", "--title", "declared standard fixture",
        "--complexity", "bounded", "--files", "3",
        "--archive-active", "--archive-source", "user:rotate", "--archive-reason", "defaults fixture",
    )
    if "STARTED standard task in clarification" not in rotated:
        raise AssertionError(f"explicitly declared start did not route to standard:\n{rotated}")

print(
    "CONTROL GATES SELF-TEST PASSED: budget routing, clarification, signed v1 human decisions, "
    "escalation re-approval, task-archive v2, cleanup/lease/docker/baseline hygiene, "
    "knowledge promotion, adapter probes, node-0 start contracts and fast start defaults"
)
