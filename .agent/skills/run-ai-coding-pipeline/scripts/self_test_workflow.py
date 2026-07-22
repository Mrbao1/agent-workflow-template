#!/usr/bin/env python3
"""Disposable adaptive-mode, adapter, rollback and finalizer attacks."""

from pathlib import Path
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, Optional


SOURCE = Path(__file__).resolve().parents[3]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def receipt(root: Path, relative: str) -> dict[str, object]:
    path = root / relative
    return {"path": relative, "sha256": digest(path), "bytes": len(path.read_bytes())}


def workflow_candidate_fingerprint(root: Path, config: dict[str, object]) -> str:
    probe = subprocess.run(
        [sys.executable, "-c", (
            "import json,sys;sys.path.insert(0,'.agent/scripts');import testrun;"
            "print(testrun.candidate_fingerprint(json.load(open('.agent/config.json'))))"
        )],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if probe.returncode:
        raise AssertionError(f"canonical candidate fingerprint failed:\n{probe.stdout}")
    return probe.stdout.strip()


def workflow_candidate_records(root: Path) -> dict[str, str]:
    probe = subprocess.run(
        [sys.executable, "-c", (
            "import json,sys;sys.path.insert(0,'.agent/scripts');import testrun;"
            "c=json.load(open('.agent/config.json'));"
            "print(json.dumps({r['path']:r['sha256'] for r in testrun.candidate_records(c)},sort_keys=True))"
        )],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if probe.returncode:
        raise AssertionError(f"canonical candidate record probe failed:\n{probe.stdout}")
    return json.loads(probe.stdout)


def bind_node_template(root: Path, template_id: str, relative: str) -> None:
    task_path = root / ".agent/state/TASK.json"
    task_value = json.loads(task_path.read_text(encoding="utf-8"))
    manifest_path = root / ".agent/templates/manifest.json"
    manifest_data = manifest_path.read_bytes()
    manifest = json.loads(manifest_data)
    entry = next(item for item in manifest["templates"] if item["id"] == template_id)
    route = task_value.get("template_route")
    if not isinstance(route, dict) or not isinstance(route.get("sha256"), str):
        route = {"sha256": "c" * 64}
        task_value["template_route"] = route
    selected = task_value.setdefault("selected_templates", [])
    if template_id not in selected:
        selected.append(template_id)
    source = root / ".agent" / entry["path"]
    artifact = receipt(root, relative)
    record = {
        "schema": "agent-template-render/v1", "template_id": template_id,
        **artifact,
        "requirement_contract_sha256": task_value["requirement_contract_sha256"],
        "manifest_sha256": hashlib.sha256(manifest_data).hexdigest(),
        "route_sha256": route["sha256"],
        "source_path": str(source.relative_to(root)),
        "source_sha256": digest(source), "source_bytes": len(source.read_bytes()),
    }
    records = task_value.setdefault("rendered_artifacts", [])
    task_value["rendered_artifacts"] = [
        item for item in records
        if not isinstance(item, dict) or item.get("template_id") != template_id
    ] + [record]
    write_json(task_path, task_value)


def empty_platform_snapshot(root: Path, label: str) -> str:
    relative = f".agent/state/evidence/{label}.json"
    write_json(root / relative, {
        "schema": "agent-platform-snapshot/v3",
        "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "members": [],
    })
    return relative


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run(root: Path, *args: str, expected: int = 0) -> str:
    result = subprocess.run(
        [sys.executable, ".agent/scripts/workflowctl.py", *args], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode != expected:
        raise AssertionError(f"{args}: expected {expected}, got {result.returncode}\n{result.stdout}")
    return result.stdout


def task(mode: str, node: int, accepted: list[int]) -> dict[str, object]:
    token_budget = {"fast": 6000, "standard": 20000, "release": 40000}[mode]
    value = json.loads((SOURCE / "state/TASK.json").read_text(encoding="utf-8"))
    value.update({
        "schema": "agent-task/v2", "title": f"{mode} fixture", "mode": mode,
        "task_type": "maintenance", "complexity": "small" if mode == "fast" else "bounded",
        "files": 1 if mode == "fast" else 3,
        "environment": "local", "deployment_requested": False, "branch": "unversioned",
        "status": "in_progress",
        "risk_flags": {name: False for name in (
            "deploy", "data_risk", "cross_system", "uncertain", "security",
            "compliance", "migration", "irreversible", "external_impact",
        )},
        "phase": {2: "structuring", 3: "scope", 4: "solution", 5: "tests", 6: "implementation", 7: "acceptance", 8: "delivery"}.get(node, "idle"),
        "requirements_clarified": True, "requirement_source": "user:fixture",
        "decision_policy_version": 0,
        "requirement_contract_sha256": "a" * 64, "current_node": node,
        "accepted_nodes": accepted, "node_artifacts": {}, "gate_approvals": {},
        "pending_gate_artifacts": {}, "rollback_ledger": [], "rollback_archive": None,
        "failure_ledger": {}, "failure_archive": None,
        "token_budget": token_budget, "tokens_used": 0,
        "token_usage_source": "estimated", "usage_receipts": [], "budget_state": "ok",
        "child_agents_used": 0, "peak_child_agents": 0,
        "mode_status": "confirmed", "selected_templates": ["requirement-contract", "task-plan", "acceptance-matrix", "retrospective"],
        "selected_capabilities": ["core"], "template_route": None,
        "rendered_artifacts": [], "open_questions": [], "decisions": [],
        "next_action": f"complete node {node}", "updated": "2026-07-17",
    })
    return value


def stage(root: Path, value: dict[str, object]) -> None:
    accepted = value["accepted_nodes"]
    last = max(accepted) if accepted else "none"
    mode = value["mode"]
    gate = "required" if mode == "release" else "not_applicable"
    reason = "strict release gate is required for release mode" if mode == "release" else f"{mode} mode uses targeted acceptance and has no release live gate"
    (root / ".agent/state/STAGE_INDEX.md").write_text(f"""# AI Coding Stage Index

- Pipeline version: 2.0
- Task: {value['title']}
- Task type: {value['task_type']}
- Complexity: {value['complexity']}
- Mode: {mode}
- Current node: {value['current_node']}
- Status: {value['status']}
- Last accepted node: {last}
- Release gate: {gate}
- Release gate reason: {reason}
- Next action: {value['next_action']}
- Updated: {value['updated']}

## Input provenance
- fixture
## Assumptions requiring confirmation
- none
## Gate status
- fixture
## Rollback ledger
- fixture
## Canonical outputs
- `.agent/state/TASK.json`
""", encoding="utf-8")


def install_task(root: Path, value: dict[str, object]) -> None:
    contract = (
        "# Requirement Contract\n\n"
        "- Goal: verify the workflow state machine\n"
        "- Users: template maintainers\n"
        "- Success: every selected workflow gate passes\n"
        "- In scope: bounded local workflow verification\n"
        "- Out of scope: production deployment\n"
        "- Constraints: deterministic fixture only\n"
        "- Data and permissions: no external data or privileges\n"
        "- Target environment: local\n"
        "- Context transport: native\n"
        "- Acceptance: current mode gate succeeds\n"
        "- Provenance: user:fixture\n"
        "- Production provider target: none\n"
        "- Human decisions: user:fixture\n"
        "- Clarified: true\n"
    )
    (root / ".agent/state/REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    value["requirement_contract_sha256"] = hashlib.sha256(contract.encode()).hexdigest()
    value.setdefault("node_artifacts", {})["1"] = receipt(root, ".agent/state/REQUIREMENT_CONTRACT.md")
    value["gate_approvals"] = {**value.get("gate_approvals", {}), "requirement": "user:fixture"}
    write_json(root / ".agent/state/TASK.json", value)
    stage(root, value)


def implementation(root: Path, mode: str) -> str:
    task_value = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    projected = mode == "fast" or (
        mode != "release" and task_value.get("task_type") in {"governance", "documentation", "maintenance"}
    )
    (root / "change.txt").write_text("change", encoding="utf-8")
    (root / "check.log").write_text("VERDICT PASS P0=0 P1=0 P2=0\nfixture review report\n", encoding="utf-8")
    write_json(root / ".agent/state/runtime.json", {
        "schema": "agent-runtime/v2",
        "baseline": {"source": "user:fixture", "captured_at": "2026-07-17T00:00:00+00:00", "project_processes": []},
        "processes": [], "docker_projects": [], "ports": [],
    })
    relative = ".agent/state/artifacts/06-implementation.json"
    write_json(root / relative, {
        "schema": "agent-node-implementation/v3", "mode": mode, "status": "verified",
        "requirement_contract_sha256": task_value["requirement_contract_sha256"],
        "implementer_agent_id": "implementer" if mode == "release" else None,
        "projection": [2, 3, 4, 5, 6] if projected else [6],
        "changes": [receipt(root, "change.txt")],
        "checks": [{"id": "targeted", "command": ["python3", "fixture.py"], "exit_code": 0,
                    "output": receipt(root, "check.log")}],
        "cleanup": {"runtime_state": receipt(root, ".agent/state/runtime.json"),
                    "residual": {"processes": 0, "docker_projects": 0, "ports": 0}},
        "scope": {"summary": "fixture change", "unapproved_assumptions": []},
    })
    bind_node_template(root, "node-implementation", relative)
    return relative


def acceptance(root: Path, mode: str, task_value: Dict[str, object], live: Optional[Dict[str, object]] = None) -> str:
    relative = ".agent/state/artifacts/07-acceptance.json"
    bindings = {
        "requirement_contract_sha256": task_value["requirement_contract_sha256"],
        "implementation_sha256": task_value["node_artifacts"]["6"]["sha256"],
    }
    projected = mode == "fast" or (
        mode != "release" and task_value.get("task_type") in {"governance", "documentation", "maintenance"}
    )
    if not projected:
        bindings.update({
            "deliverables_sha256": task_value["node_artifacts"]["3"]["sha256"],
            "acceptance_matrix_sha256": task_value["node_artifacts"]["5"]["sha256"],
        })
    value: dict[str, object] = {
        "schema": "agent-node-acceptance/v3", "mode": mode,
        "status": "ready_for_human_review" if mode in {"standard", "release"} else "verified",
        "human_decision": "pending" if mode in {"standard", "release"} else "not_required",
        "bindings": bindings, "open_findings": [],
        "recommendation": "request_human_acceptance" if mode in {"standard", "release"} else "complete",
        "checks": [{"id": "goal", "result": "passed", "case_ids": ["CASE-1"],
                    "assertions": ["observable result"], "evidence": [receipt(root, "check.log")],
                    "reviewer": "cross" if mode == "release" else "root"}],
    }
    if mode == "release":
        ledger = json.loads((root / ".agent/state/agents.json").read_text(encoding="utf-8"))
        members = {item["id"]: item for item in ledger["members"]}
        observer = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))["agent_control"]["platform_observer"]
        value["platform_assurance"] = observer
        value["supervision_debt"] = sorted([
            {"agent_id": item["id"], "first_gap_at": item["monitoring_violation_at"]}
            for item in members.values() if item.get("monitoring_violation_at") is not None
        ], key=lambda item: item["agent_id"])
        value["supervision_debt_sha256"] = canonical_digest(value["supervision_debt"])
        value["platform_observation_set"] = sorted([
            {
                "agent_id": item["id"], "registration": item["registration_platform_evidence"],
                "monitors": item["monitor_platform_evidence"], "terminal": item["terminal_platform_evidence"],
            }
            for item in members.values()
        ], key=lambda item: item["agent_id"])
        value["platform_observation_set_sha256"] = canonical_digest(value["platform_observation_set"])
        value["recommendation"] = "request_human_acceptance_with_control_waiver"
        value["reviewers"] = {"implementer": "implementer", "adversarial": "adversary", "cross_reviewer": "cross", "integrator": "integrator"}
        value["review_chain"] = {
            "review_chain_id": "workflow-release-fixture",
            "review_subject_sha256": members["adversary"]["review_subject_sha256"],
        }
        cross_report = next(
            item for item in members["cross"]["result_evidence"]
            if item["source_path"] == members["cross"]["result_report_path"]
        )
        lines = (root / cross_report["path"]).read_text(encoding="utf-8").splitlines()
        scenario_raw = lines[2][len("SCENARIO_RECEIPT "):]
        scenario_receipt = json.loads(scenario_raw)
        value["scenario_receipt_sha256"] = hashlib.sha256(scenario_raw.encode()).hexdigest()
        value["scenarios"] = scenario_receipt["scenarios"]
        value["live_gate_receipt"] = live
    write_json(root / relative, value)
    bind_node_template(root, "targeted-acceptance" if mode == "fast" else "node-acceptance", relative)
    return relative


def completed_ledger(
    root: Path,
    node6_path: Optional[str] = None,
    replay_case_windows=((31, 32),),
    scenario_attack: Optional[str] = None,
    implementer_only: bool = False,
) -> None:
    proof = receipt(root, "check.log")
    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    deadline = (started + dt.timedelta(minutes=5)).isoformat()
    epoch = "b" * 64
    task_value = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    inputs = []
    for node in range(1, 7):
        source = node6_path if node == 6 and node6_path else task_value["node_artifacts"][str(node)]["path"]
        data = (root / source).read_bytes()
        input_sha = hashlib.sha256(data).hexdigest()
        input_path = f".agent/state/evidence/agent-input-artifacts/{input_sha}.blob"
        (root / input_path).parent.mkdir(parents=True, exist_ok=True)
        (root / input_path).write_bytes(data)
        inputs.append({"label": source, "path": input_path, "sha256": input_sha, "bytes": len(data)})
    payload_value = {
        "schema": "agent-task-payload/v2",
        "objective": "exercise reusable release-review evidence",
        "input_artifacts": inputs,
        "shared_constraints": ["Treat input artifacts as read-only", "Use the envelope as the sole output authority"],
        "acceptance_criteria": ["Preserve requirement-to-evidence continuity across all reviewers"],
    }
    semantic_value = {
        key: payload_value[key]
        for key in ("objective", "shared_constraints", "acceptance_criteria")
    }
    semantic_bytes = len(json.dumps(semantic_value, sort_keys=True, separators=(",", ":")).encode())
    payload_estimated_tokens = (sum(item["bytes"] for item in inputs) + semantic_bytes + 3) // 4
    payload_value["estimated_tokens"] = payload_estimated_tokens
    payload_data = (json.dumps(payload_value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    payload_sha = hashlib.sha256(payload_data).hexdigest()
    payload_path = f".agent/state/evidence/agent-task-payloads/{payload_sha}.ctx"
    (root / payload_path).parent.mkdir(parents=True, exist_ok=True)
    (root / payload_path).write_bytes(payload_data)
    payload_receipt = receipt(root, payload_path)
    chain_id = "workflow-release-fixture"
    product_candidate_sha256 = workflow_candidate_fingerprint(
        root, json.loads((root / ".agent/config.json").read_text(encoding="utf-8")),
    )

    def test_receipt(sequence: int, case_window):
        run_id = f"{sequence:032x}"
        source = f".agent/state/evidence/integrator-clean-{sequence}.json"
        resolved_node6_path = node6_path or str(task_value["node_artifacts"]["6"]["path"])
        node6_value = json.loads((root / resolved_node6_path).read_text(encoding="utf-8"))
        node6_check = node6_value["checks"][0]
        case_id = str(node6_check["id"])
        case_command = list(node6_check["command"])
        receipt_path = Path(source)
        planned_output_path = str(
            receipt_path.with_name(receipt_path.stem + "-" + case_id + ".log")
        )
        output_data = b"full-chain passed\n"
        output_sha = hashlib.sha256(output_data).hexdigest()
        output_path = f".agent/state/evidence/agent-replay-outputs/{output_sha}.log"
        (root / output_path).parent.mkdir(parents=True, exist_ok=True)
        (root / output_path).write_bytes(output_data)
        output_receipt = receipt(root, output_path)
        plan_source = f".agent/state/evidence/replay-plan-{sequence}.json"
        plan_value = {
            "schema": "agent-replay-plan/v1", "run_id": run_id, "receipt_path": source,
            "cases": [{
                "id": case_id, "command": case_command, "timeout_seconds": 120,
                "expected_exit_code": 0, "expected_outcome": "completed", "expected_cleanup": "passed",
                "expected_output_path": planned_output_path,
            }],
        }
        write_json(root / plan_source, plan_value)
        plan_data = (root / plan_source).read_bytes(); plan_sha = hashlib.sha256(plan_data).hexdigest()
        plan_path = f".agent/state/evidence/agent-replay-plans/{plan_sha}.json"
        (root / plan_path).parent.mkdir(parents=True, exist_ok=True); (root / plan_path).write_bytes(plan_data)
        plan_receipt = receipt(root, plan_path)
        runner = receipt(root, ".agent/scripts/testrun.py")
        unsigned = {
            "id": case_id, "run_id": run_id,
            "candidate_sha256": product_candidate_sha256, "command": case_command,
            "started_at": (started + dt.timedelta(seconds=case_window[0])).isoformat(),
            "finished_at": (started + dt.timedelta(seconds=case_window[1])).isoformat(),
            "exit_code": 0, "outcome": "completed", "cleanup": "passed", "output": output_receipt,
        }
        case = dict(unsigned)
        case["case_sha256"] = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        write_json(root / source, {
            "schema": "agent-test-receipt/v3", "run_id": run_id,
            "candidate_sha256": product_candidate_sha256,
            "runner": runner, "cases": [case],
        })
        receipt_data = (root / source).read_bytes(); receipt_sha = hashlib.sha256(receipt_data).hexdigest()
        final_path = f".agent/state/evidence/agent-replay-receipts/{receipt_sha}.receipt"
        (root / final_path).parent.mkdir(parents=True, exist_ok=True); (root / final_path).write_bytes(receipt_data)
        authority_id = hashlib.sha256(f"authority-{sequence}".encode()).hexdigest()
        claim_id = hashlib.sha256(f"claim-{sequence}".encode()).hexdigest()
        common = {
            "authority_id": authority_id, "integrator_id": "integrator", "review_chain_id": chain_id,
            "review_subject_sha256": payload_sha, "run_id": run_id, "case_id": case_id, "sequence": 0,
            "claim_id": claim_id,
            "runner_sha256": runner["sha256"], "plan_sha256": plan_sha,
        }
        start_value = {"schema": "agent-replay-observation/v1", "event": "start", **common,
                       "observed_at": unsigned["started_at"], "previous_observation_sha256": None,
                       "command": plan_value["cases"][0]["command"],
                       "timeout_seconds": plan_value["cases"][0]["timeout_seconds"],
                       "output_path": plan_value["cases"][0]["expected_output_path"]}
        start_data = (json.dumps(start_value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        start_sha = hashlib.sha256(start_data).hexdigest()
        start_path = f".agent/state/evidence/agent-replay-observations/{start_sha}.json"
        (root / start_path).parent.mkdir(parents=True, exist_ok=True); (root / start_path).write_bytes(start_data)
        start_receipt = receipt(root, start_path)
        finish_value = {"schema": "agent-replay-observation/v1", "event": "finish", **common,
                        "observed_at": unsigned["finished_at"], "previous_observation_sha256": start_sha,
                        "output": output_receipt, "exit_code": 0, "outcome": "completed",
                        "cleanup": "passed"}
        finish_data = (json.dumps(finish_value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        finish_sha = hashlib.sha256(finish_data).hexdigest()
        finish_path = f".agent/state/evidence/agent-replay-observations/{finish_sha}.json"
        (root / finish_path).write_bytes(finish_data)
        node6_task_receipt = dict(task_value["node_artifacts"]["6"])
        node6_inputs = [
            item for item in inputs
            if item["label"] == node6_task_receipt["path"]
            and item["sha256"] == node6_task_receipt["sha256"]
            and item["bytes"] == node6_task_receipt["bytes"]
        ]
        if len(node6_inputs) != 1:
            raise AssertionError("fixture replay lacks one exact sealed Node 6 input")
        run = {
            "authority_id": authority_id, "integrator_id": "integrator", "review_chain_id": chain_id,
            "review_subject_sha256": payload_sha,
            "candidate_sha256": product_candidate_sha256,
            "run_id": run_id, "receipt_path": source,
            "source_plan": receipt(root, plan_source), "plan_evidence": plan_receipt, "runner_evidence": runner,
            "node6_task_receipt": node6_task_receipt, "node6_input_evidence": dict(node6_inputs[0]),
            "prepared_at": unsigned["started_at"], "status": "completed",
            "cases": [{"id": case_id, "claim_id": claim_id, "start": start_receipt,
                       "finish": receipt(root, finish_path), "case": case}],
            "last_observation_sha256": finish_sha, "completed_at": unsigned["finished_at"],
            "final_receipt_evidence": receipt(root, final_path), "final_receipt_sha256": receipt_sha,
            "failure_reason": None,
        }
        return source, run

    def immutable_result(source: str) -> dict[str, object]:
        data = (root / source).read_bytes()
        result_sha = hashlib.sha256(data).hexdigest()
        result_path = f".agent/state/evidence/agent-result-evidence/{result_sha}.result"
        (root / result_path).parent.mkdir(parents=True, exist_ok=True)
        (root / result_path).write_bytes(data)
        return {"source_path": source, "path": result_path, "sha256": result_sha, "bytes": len(data)}

    replay_pairs = [] if implementer_only else [
        test_receipt(sequence, case_window)
        for sequence, case_window in enumerate(replay_case_windows, start=1)
    ]
    replay_records = [immutable_result(source) for source, _ in replay_pairs]
    replay_runs = [run for _, run in replay_pairs]
    members = []
    prepared_dispatches = []
    last_terminal = None

    def platform_evidence(value: dict[str, object]) -> dict[str, object]:
        data = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
        digest_value = hashlib.sha256(data).hexdigest()
        relative = f".agent/state/evidence/platform-snapshots/{digest_value}.json"
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return receipt(root, relative)

    scenario_data = (root / "check.log").read_bytes()
    scenario_sha = hashlib.sha256(scenario_data).hexdigest()
    scenario_path = f".agent/state/evidence/scenario-evidence/{scenario_sha}.evidence"
    (root / scenario_path).parent.mkdir(parents=True, exist_ok=True)
    (root / scenario_path).write_bytes(scenario_data)
    scenario_proof = receipt(root, scenario_path)
    lenses = ["product", "architecture", "qa", "security", "operations", "ai-workflow-new-project-adopter"]
    role_scenarios = [
        {"id": f"SCENARIO-{index}", "lens": lens, "requirement_ids": ["REQ-1"],
         "assertions": [f"{lens} full chain"], "evidence": [scenario_proof], "result": "passed"}
        for index, lens in enumerate(lenses, start=1)
    ]
    if scenario_attack == "duplicate_evidence":
        role_scenarios[0]["evidence"].append(scenario_proof)

    previous_report_sha = None
    role_sequence = (("implementer", "implementer", "implementation author"),) if implementer_only else (
        ("implementer", "implementer", "implementation author"),
        ("adversary", "adversarial", "adversarial reviewer"),
        ("cross", "cross", "cross reviewer"),
        ("integrator", "integrator", "integrator"),
    )
    for sequence, (agent_id, role_type, role) in enumerate(role_sequence):
        now = (started + dt.timedelta(seconds=sequence * 10)).isoformat()
        terminal_at = (started + dt.timedelta(seconds=sequence * 10 + 5)).isoformat()
        deadline = (started + dt.timedelta(seconds=sequence * 10, minutes=5)).isoformat()
        if role_type == "implementer":
            report_source = ".agent/state/evidence/implementation-attestation-fixture.json"
            resolved_node6_path = node6_path or str(task_value["node_artifacts"]["6"]["path"])
            node6 = root / resolved_node6_path
            node6_value = json.loads(node6.read_text(encoding="utf-8"))
            implementation_value = {
                "schema": "agent-implementation-attestation/v1", "agent_id": agent_id,
                "root_task_id": "workflow-release-fixture", "candidate_review_subject_sha256": payload_sha,
                "requirement_contract_sha256": node6_value["requirement_contract_sha256"],
                "node6_artifact": receipt(root, resolved_node6_path),
                "changes": node6_value["changes"], "checks": node6_value["checks"],
            }
            write_json(root / report_source, implementation_value)
            report_record = immutable_result(report_source)
            result_records = [report_record]
            report_sha = None; review_verdict = None; attestation = None
            final_message_sha = hashlib.sha256(b"IMPLEMENTATION_RESULT COMPLETED").hexdigest()
            review_chain_id = review_subject = predecessor = result_report_path = None
            conclusion = "implementation complete"
        else:
            report_source = f".agent/state/evidence/{role_type}-review.md"
            attestation = {
                "schema": "agent-review-attestation/v2", "role_type": role_type,
                "review_chain_id": chain_id, "review_subject_sha256": payload_sha,
                "predecessor_result_sha256": previous_report_sha,
                "lenses": lenses if role_type == "cross" else [],
                "clean_replays": [
                    {key: record[key] for key in ("source_path", "sha256", "bytes")} for record in replay_records
                ] if role_type == "integrator" else [],
                "targeted_cases": [],
            }
            report = "VERDICT PASS P0=0 P1=0 P2=0\nATTESTATION " + json.dumps(attestation, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            if role_type == "cross":
                scenario_receipt = {
                    "schema": "agent-role-scenario-receipt/v1", "review_chain_id": chain_id,
                    "review_subject_sha256": payload_sha, "reviewer_agent_id": agent_id,
                    "scenarios": role_scenarios,
                }
                scenario_raw = json.dumps(scenario_receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                if scenario_attack == "duplicate_key":
                    scenario_raw = scenario_raw.replace(
                        '"schema":',
                        '"schema":"agent-role-scenario-receipt/v1","schema":',
                        1,
                    )
                report += "\nSCENARIO_RECEIPT " + scenario_raw
            report += "\nfixture review\n"
            (root / report_source).write_text(report, encoding="utf-8")
            report_record = immutable_result(report_source)
            result_records = [report_record, *replay_records] if role_type == "integrator" else [report_record]
            report_sha = report_record["sha256"]
            review_verdict = {"status": "PASS", "p0": 0, "p1": 0, "p2": 0, "report_sha256": report_sha}
            final_message_sha = hashlib.sha256(
                f"FINAL_RESULT PASS P0=0 P1=0 P2=0 report_sha256={report_sha}".encode()
            ).hexdigest()
            review_chain_id = chain_id; review_subject = payload_sha
            predecessor = previous_report_sha; result_report_path = report_source
            conclusion = "PASS P0=0 P1=0 P2=0"
        allowed_paths = ["check.log", *[record["source_path"] for record in result_records]]
        envelope_value = {
            "schema": "agent-handoff-envelope/v3", "ledger_epoch": epoch, "agent_id": agent_id,
            "root_task_id": "workflow-release-fixture", "role_type": role_type, "model": "gpt-5.6-sol", "fork_turns": 0,
            "started_at": now, "deadline_at": deadline, "redispatch_count": 0,
            "task_payload_path": payload_path, "task_payload_sha256": payload_sha,
            "allowed_evidence_paths": allowed_paths,
            "forbidden_actions": ["approve-node7", "modify-managed-files"],
            "start_barrier": "LEDGER_REGISTERED",
            "review_chain_id": review_chain_id, "review_subject_sha256": review_subject,
            "predecessor_result_sha256": predecessor, "result_report_path": result_report_path,
        }
        envelope_data = (json.dumps(envelope_value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        envelope_sha = hashlib.sha256(envelope_data).hexdigest()
        envelope_path = f".agent/state/evidence/agent-handoff-envelopes/{envelope_sha}.json"
        (root / envelope_path).parent.mkdir(parents=True, exist_ok=True)
        (root / envelope_path).write_bytes(envelope_data)
        envelope_receipt = receipt(root, envelope_path)
        spawn_fields = {"id": agent_id, "ledger_epoch": epoch, "root_task_id": "workflow-release-fixture",
                        "role_type": role_type, "started_at": now, "deadline_at": deadline,
                        "redispatch_count": 0, "model": "gpt-5.6-sol", "fork_turns": 0,
                        "task_payload_sha256": payload_sha, "handoff_envelope_sha256": envelope_sha,
                        "message_cursor": 0}
        registration_record = platform_evidence({"schema": "agent-platform-snapshot/v3", "observed_at": now,
                                                 "members": [{**spawn_fields, "status": "running"}]})
        last_terminal = platform_evidence({"schema": "agent-platform-snapshot/v3", "observed_at": terminal_at,
                                           "members": [{**spawn_fields, "status": "completed", "message_cursor": 1,
                                                        "message_sha256": final_message_sha, "message_kind": "final"}]})
        marker_path = root / ".agent/state/evidence/agent-terminal-markers" / epoch / f"{hashlib.sha256(agent_id.encode()).hexdigest()}.json"
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_value = {
            "schema": "agent-terminal-marker/v6", "ledger_epoch": epoch, "agent_id": agent_id,
            "terminal_status": "completed", "terminal_platform_evidence": last_terminal,
            "task_payload_sha256": payload_sha, "handoff_envelope_sha256": envelope_sha,
            "terminal_observed_at": terminal_at, "finished_at": terminal_at, "conclusion": conclusion,
            "result_evidence": result_records, "review_verdict": review_verdict, "final_message_cursor": 1,
            "final_message_sha256": final_message_sha,
            "review_chain_id": review_chain_id, "review_subject_sha256": review_subject,
            "predecessor_result_sha256": predecessor, "result_report_path": result_report_path,
            "review_attestation": attestation, "monitoring_violation_at": None, "stall_violation_at": None,
        }
        marker_path.write_text(json.dumps(marker_value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        reservation_id = hashlib.sha256(
            f"{epoch}|{agent_id}|{payload_sha}|{payload_estimated_tokens}".encode()
        ).hexdigest()
        charge_value = {
            "schema": "agent-child-token-charge/v1", "ledger_epoch": epoch,
            "reservation_id": reservation_id, "agent_id": agent_id,
            "root_task_id": "workflow-release-fixture", "task_payload_sha256": payload_sha,
            "estimated_tokens": payload_estimated_tokens, "terminal_status": "completed",
            "terminal_observed_at": terminal_at,
        }
        charge_data = (json.dumps(charge_value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        charge_sha = hashlib.sha256(charge_data).hexdigest()
        charge_path = f".agent/state/evidence/agent-token-charges/{charge_sha}.json"
        (root / charge_path).parent.mkdir(parents=True, exist_ok=True)
        (root / charge_path).write_bytes(charge_data)
        charge_receipt = receipt(root, charge_path)
        prepared_dispatches.append({
            "id": agent_id, "root_task_id": "workflow-release-fixture", "role_type": role_type,
            "model": "gpt-5.6-sol", "fork_turns": 0, "started_at": now, "deadline_at": deadline,
            "redispatch_count": 0, "task_payload_sha256": payload_sha, "task_payload_evidence": payload_receipt,
            "handoff_envelope_sha256": envelope_sha, "handoff_envelope_evidence": envelope_receipt,
            "allowed_evidence_paths": allowed_paths,
            "forbidden_actions": ["approve-node7", "modify-managed-files"],
            "prepared_at": now, "consumed_at": now, "cancelled_at": None,
            "review_chain_id": review_chain_id, "review_subject_sha256": review_subject,
            "predecessor_result_sha256": predecessor, "result_report_path": result_report_path,
            "token_reservation": {
                "id": reservation_id, "estimated_tokens": payload_estimated_tokens,
                "status": "settled", "reserved_at": now, "closed_at": terminal_at,
                "charge_receipt": charge_receipt,
            },
        })
        members.append({
            "id": agent_id, "root_task_id": "workflow-release-fixture", "role_type": role_type, "role": role, "task": role,
            "model": "gpt-5.6-sol", "fork_turns": 0, "context_strategy": "long-window-capsule",
            "task_payload_sha256": payload_sha, "task_payload_evidence": payload_receipt,
            "handoff_envelope_sha256": envelope_sha, "handoff_envelope_evidence": envelope_receipt,
            "payload_estimated_tokens": payload_estimated_tokens,
            "token_reservation_id": reservation_id,
            "allowed_evidence_paths": allowed_paths,
            "forbidden_actions": ["approve-node7", "modify-managed-files"], "status": "completed",
            "started_at": now, "deadline_at": deadline, "last_progress_at": now, "last_check_at": now,
            "progress_hash": "b" * 64, "platform_cursor": 1, "last_platform_message_sha256": final_message_sha,
            "progress_observed": False, "unchanged_checks": 0, "redispatch_count": 0,
            "redispatched_to": None, "evidence": [proof], "result_evidence": result_records,
            "review_verdict": review_verdict,
            "registration_platform_evidence": registration_record,
            "registration_observed_at": now, "monitor_platform_evidence": [], "monitoring_violation_at": None,
            "stall_violation_at": None,
            "interrupt_requested_at": None, "interrupt_reason": None, "finished_at": terminal_at,
            "conclusion": conclusion, "terminal_platform_evidence": last_terminal,
            "terminal_observed_at": terminal_at,
            "review_chain_id": review_chain_id, "review_subject_sha256": review_subject,
            "predecessor_result_sha256": predecessor, "result_report_path": result_report_path,
            "review_attestation": attestation,
        })
        if role_type != "implementer":
            previous_report_sha = report_sha
    write_json(root / ".agent/state/agents.json", {
        "schema": "agent-team/v9", "task_payload_schema": "agent-task-payload/v2",
        "platform_limit": 4, "default_model": "gpt-5.6-sol",
        "allow_model_fallback": False, "context_strategy": "long-window-capsule", "max_fork_turns": 10,
        "capacity_retry_limit": 1, "reserved_root_slots": 1,
        "task_payload_limits": {
            "max_input_count": 24, "max_single_bytes": 131072,
            "max_total_bytes": 262144, "max_estimated_tokens": 65536,
        },
        "status_interval_seconds": 30, "monitor_grace_seconds": 30, "stall_timeout_seconds": 300,
        "allowed_role_types": [
            "worker", "researcher", "documentation-worker", "implementer",
            "reviewer", "adversarial", "cross", "integrator",
        ],
        "review_role_types": ["reviewer", "adversarial", "cross", "integrator"],
        "status_request_after_unchanged_checks": 1,
        "platform_observer": json.loads(
            (root / ".agent/config.json").read_text(encoding="utf-8")
        )["agent_control"]["platform_observer"],
        "max_redispatch": 1, "epoch": epoch,
        "members": members, "prepared_dispatches": prepared_dispatches, "capacity_failures": [], "replay_runs": replay_runs, "last_platform_snapshot": last_terminal,
        "token_accounting": {
            "schema": "agent-child-token-accounting/v1",
            "token_budget": int(task_value["token_budget"]),
            "settled_tokens": payload_estimated_tokens * len(members),
        },
        "platform_empty_verified": False, "migration_source": None, "updated_at": now,
    })


thought_tree = (SOURCE / "skills/run-ai-coding-pipeline/references/thought-tree.md").read_text(encoding="utf-8")
for required_route in (
    "continue`, `return-node`, or `waiting_human`",
    "1 clarify → human requirement gate; no downstream work before approval",
    "4 solution/tasks → first-principles design, boundaries and dependencies",
    "7 acceptance → reuse candidate receipt → targeted adversarial → six-lens cross → one integrator replay; human gate",
    "8 delivery → environment-specific promote/rollback/observe/retrospective",
):
    if required_route not in thought_tree:
        raise SystemExit(f"thought tree lost canonical stage routing: {required_route}")


with tempfile.TemporaryDirectory(prefix="workflow-state-test-") as raw:
    root = Path(raw)
    shutil.copytree(SOURCE, root / ".agent")
    (root / "AGENTS.md").write_text("fixture", encoding="utf-8")
    # Isolate state-machine tests from context/runtime implementations, which have their own suites.
    pristine_agentctl = (root / ".agent/scripts/agentctl.py").read_bytes()
    (root / ".agent/scripts/contextctl.py").write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")
    (root / ".agent/scripts/agentctl.py").write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")
    (root / ".agent/scripts/contexttx.py").write_text(
        "from pathlib import Path\nimport datetime,hashlib,json\nclass contextctl:\n @staticmethod\n def invariant_sha256(value): return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()\ndef transition_task(before,after,**kwargs):\n p=Path('.agent/state/TASK.json'); p.write_text(json.dumps(after,ensure_ascii=False,indent=2)+'\\n',encoding='utf-8')\n invariant=contextctl.invariant_sha256(after); observed=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(); sequence=1\n context={'schema':'agent-context/v2','task_invariant_sha256':invariant,'resume':{'schema':'agent-context-resume/v1','task_status':after.get('status'),'current_node':after.get('current_node'),'next_action':after.get('next_action'),'budget_state':after.get('budget_state'),'terminal':after.get('status')=='accepted','resume_action':'complete' if after.get('status')=='accepted' else 'continue','task_invariant_sha256':invariant},'checkpoint':{'sequence':sequence,'updated_at':observed,'transition_authorization':{'mutator':kwargs.get('mutator'),'operation':kwargs.get('operation')}},'usage_freshness':{'schema':'agent-context-usage/v1','checkpoint_sequence':sequence,'task_invariant_sha256':invariant,'coverage':'through-current-checkpoint','source':'explicit-estimate','estimated_tokens':1000,'observed_at':observed}}\n Path('.agent/state/CONTEXT.json').write_text(json.dumps(context,ensure_ascii=False,indent=2)+'\\n',encoding='utf-8')\n",
        encoding="utf-8",
    )
    config = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))
    platform_provider_dir = Path(tempfile.mkdtemp(prefix="workflow-platform-provider-"))
    platform_provider = platform_provider_dir / "verify-platform.py"
    platform_provider.write_text("""#!/usr/bin/env python3
import hashlib, pathlib, sys
snapshot = pathlib.Path(sys.argv[sys.argv.index('--snapshot') + 1])
print('VERIFIED PLATFORM SNAPSHOT sha256=' + hashlib.sha256(snapshot.read_bytes()).hexdigest())
""", encoding="utf-8")
    platform_provider.chmod(0o755)
    platform_test_site = root / ".agent/test-site"
    platform_test_site.mkdir()
    (platform_test_site / "sitecustomize.py").write_text(
        "import os,sys\nfrom pathlib import Path\n"
        "sys.path.insert(0,str(Path.cwd()/'.agent/scripts'))\n"
        "import humandecision\n_original=humandecision.adapter_path\n"
        "def _fixture(root,raw):\n"
        " return Path(raw).resolve() if raw==os.environ.get('AGENT_TEST_PLATFORM_ADAPTER') else _original(root,raw)\n"
        "humandecision.adapter_path=_fixture\n",
        encoding="utf-8",
    )
    os.environ["AGENT_TEST_PLATFORM_ADAPTER"] = str(platform_provider.resolve())
    os.environ["PYTHONPATH"] = str(platform_test_site) + os.pathsep + os.environ.get("PYTHONPATH", "")
    config["agent_control"]["platform_observer"]["signed_adapter"] = str(platform_provider.resolve())
    fixture_guardrails = """# Project Guardrails

- Product and users: Disposable workflow state-machine fixture for maintainers.
- Technology and architecture: Python, JSON, and Markdown control-plane fixture.
- Writable and read-only areas: Only the disposable fixture is writable.
- Security, privacy, compliance and performance red lines: No external effects or private state.
- Build, test and lint commands: Run only this bounded self-test.
- Deployment authority and rollback owner: Deployment is forbidden; the fixture owns rollback.
""".encode()
    (root / ".agent/policies/PROJECT_GUARDRAILS.md").write_bytes(fixture_guardrails)
    config["guardrails_ready"] = True
    config["project_initialization"] = {
        "schema": "agent-project-initialization/v1",
        "guardrails_sha256": hashlib.sha256(fixture_guardrails).hexdigest(),
        "guardrails_bytes": len(fixture_guardrails),
        "initialized_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    }
    config["acceptance_adapters"] = {
        "acceptance-workflow": {"implemented": True, "runner": ".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py", "receipt_schema": "workflow-release-gate/v4"},
        "acceptance-api": {"implemented": False, "runner": None, "receipt_schema": "api-release-gate/v1"},
    }
    # This state-machine fixture intentionally contains only the private Agent
    # control plane plus AGENTS.md, not a full installed project checkout.
    config["scope"] = {
        "fingerprint_paths": [
            ".agent/config.json", ".agent/scripts", ".agent/skills", ".agent/assets",
            ".agent/templates", ".agent/workflows", ".agent/state/TASK.json",
            ".agent/state/REQUIREMENT_CONTRACT.md",
            ".agent/policies/PROJECT_GUARDRAILS.md", "AGENTS.md",
        ],
        "product_roots": ["."],
    }
    write_json(root / ".agent/config.json", config)

    # Fast mode projects nodes 2-6 into one bounded implementation receipt.
    fast = task("fast", 2, [0, 1])
    install_task(root, fast)
    impl = implementation(root, "fast")
    run(root, "advance", "--node", "2", "--artifact", impl, expected=1)
    run(root, "advance", "--node", "6", "--artifact", impl)
    fast = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    if fast["accepted_nodes"] != list(range(7)) or fast["current_node"] != 7:
        raise AssertionError("fast projection did not land at targeted acceptance")
    accept = acceptance(root, "fast", fast)
    run(root, "advance", "--node", "7", "--artifact", accept)

    # A valid-looking lower-level receipt cannot advance a forged unclarified
    # TASK; the mutator owns this precondition instead of trusting a prior validate.
    unclarified = task("standard", 6, list(range(6)))
    unclarified["requirements_clarified"] = False
    unclarified["requirement_source"] = "pending"
    install_task(root, unclarified)
    unclarified_impl = implementation(root, "standard")
    run(root, "advance", "--node", "6", "--artifact", unclarified_impl, expected=1)
    if json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))["current_node"] != 6:
        raise AssertionError("rejected unclarified advance mutated workflow state")

    # A schema-valid Node 6 artifact cannot advance unless the dynamic
    # node-implementation template is rendered and content-addressed first.
    missing_render = task("standard", 6, list(range(6)))
    install_task(root, missing_render)
    missing_render_impl = implementation(root, "standard")
    missing_render = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    missing_render["rendered_artifacts"] = [
        item for item in missing_render["rendered_artifacts"]
        if item.get("template_id") != "node-implementation"
    ]
    write_json(root / ".agent/state/TASK.json", missing_render)
    run(root, "advance", "--node", "6", "--artifact", missing_render_impl, expected=1)
    if json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))["current_node"] != 6:
        raise AssertionError("missing Node 6 template provenance mutated workflow state")

    stale_render = task("standard", 6, list(range(6)))
    install_task(root, stale_render)
    stale_render_impl = implementation(root, "standard")
    stale_render = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    next(
        item for item in stale_render["rendered_artifacts"]
        if item.get("template_id") == "node-implementation"
    )["manifest_sha256"] = "0" * 64
    write_json(root / ".agent/state/TASK.json", stale_render)
    run(root, "advance", "--node", "6", "--artifact", stale_render_impl, expected=1)

    # Node 6 must never bind a mutable coordination/runtime state file as a
    # supposedly immutable implementation change receipt.
    dynamic = task("standard", 6, list(range(6)))
    install_task(root, dynamic)
    dynamic_impl = implementation(root, "standard")
    write_json(root / ".agent/state/tool-leases.json", {"schema": "agent-tool-leases/v1", "leases": []})
    dynamic_value = json.loads((root / dynamic_impl).read_text(encoding="utf-8"))
    dynamic_value["changes"] = [receipt(root, ".agent/state/tool-leases.json")]
    write_json(root / dynamic_impl, dynamic_value)
    run(root, "advance", "--node", "6", "--artifact", dynamic_impl, expected=1)

    # Standard uses ordinary node 6 evidence and targeted node 7 acceptance, never a release adapter.
    standard = task("standard", 6, list(range(6)))
    for node in (3, 5):
        path = root / f"standard-node-{node}.txt"; path.write_text(f"node {node}", encoding="utf-8")
        standard["node_artifacts"][str(node)] = receipt(root, path.name)
    solution_path = root / "standard-node-4.txt"; solution_path.write_text("node 4", encoding="utf-8")
    standard["node_artifacts"]["4"] = receipt(root, solution_path.name)
    standard["gate_approvals"]["solution"] = {"source": "user:fixture", "artifact_sha256": standard["node_artifacts"]["4"]["sha256"]}
    install_task(root, standard)
    standard_impl = implementation(root, "standard")
    run(root, "advance", "--node", "6", "--artifact", standard_impl)
    standard = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    standard_acceptance = acceptance(root, "standard", standard)
    standard_acceptance_digest = digest(root / standard_acceptance)
    run(root, "submit-gate", "--gate", "acceptance", "--artifact", standard_acceptance)
    run(root, "approve-gate", "--gate", "acceptance", "--source", "user:fixture", "--artifact-sha256", standard_acceptance_digest)
    run(root, "advance", "--node", "7", "--artifact", standard_acceptance)

    # Stable issue identity ignores mutable prose; a second early failure never jumps forward to node 4.
    early = task("standard", 3, [0, 1, 2])
    early["failure_ledger"] = {hashlib.sha256(b"ISSUE-1|solution").hexdigest(): 1}
    install_task(root, early)
    run(root, "return-node", "--from-node", "3", "--to", "2", "--issue-id", "ISSUE-1",
        "--cause-category", "solution", "--subtask", "x", "--root-cause", "changed prose", "--change", "retry")
    early = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    if early["current_node"] != 2 or list(early["failure_ledger"].values()) != [2]:
        raise AssertionError("stable second-failure or early-node rule failed")

    # Release node 4 fails closed when the selected adapter registry entry is unavailable.
    unavailable = task("release", 4, [0, 1, 2, 3])
    unavailable["selected_templates"].append("acceptance-api")
    (root / ".agent/state/artifacts/04-solution.md").write_text("approved solution", encoding="utf-8")
    (root / ".agent/state/artifacts/04-api.json").write_text('{"schema":"acceptance-runner/v1","adapter":"api"}', encoding="utf-8")
    solution_receipt = receipt(root, ".agent/state/artifacts/04-solution.md")
    unavailable["rendered_artifacts"] = [dict(solution_receipt, template_id="solution"),
                                          dict(receipt(root, ".agent/state/artifacts/04-api.json"), template_id="acceptance-api")]
    unavailable["gate_approvals"] = {"solution": {"source": "user:fixture", "artifact_sha256": solution_receipt["sha256"]}}
    install_task(root, unavailable)
    run(root, "advance", "--node", "4", "--artifact", ".agent/state/artifacts/04-solution.md", expected=1)

    # Release acceptance binds one real workflow adapter receipt; human approval
    # verifies the unchanged receipt and never executes the suite again.
    release = task("release", 6, list(range(6)))
    release["selected_templates"].append("acceptance-workflow")
    for node in (2, 3, 4, 5):
        path = root / f"node-{node}.txt"
        path.write_text(f"node {node}", encoding="utf-8")
        release["node_artifacts"][str(node)] = receipt(root, path.name)
    gate_fixture = root / "gate_fixture.py"
    gate_fixture.write_text(
        "from pathlib import Path\n"
        "p=Path('workflow-gate-count.txt')\n"
        "p.write_text(str(int(p.read_text()) + 1) if p.exists() else '1')\n"
        "print('PASS workflow fixture')\n",
        encoding="utf-8",
    )
    runner_path = ".agent/state/artifacts/04-workflow-runner.json"
    write_json(root / runner_path, {
        "schema": "acceptance-runner/v4", "adapter": "workflow",
        "execution_profile": {
            "environment": "local", "authority": "default", "capabilities": ["python-runtime"],
        },
        "preflight_commands": [{
            "id": "python-runtime",
            "argv": ["python3", ".agent/skills/run-full-chain-acceptance/scripts/preflight_environment.py"],
            "timeout_seconds": 10,
        }],
        "commands": [{"id": "targeted", "argv": ["python3", "fixture.py"], "timeout_seconds": 120}],
    })
    release["rendered_artifacts"] = [dict(receipt(root, runner_path), template_id="acceptance-workflow")]
    install_task(root, release)
    impl = implementation(root, "release")
    # Node 6 is released by an orchestrator-observed implementer only. Formal review
    # and its ledger-parent replays are constructed after Node 6 is accepted,
    # because replay authority is bound to the current accepted Node 6 receipt.
    completed_ledger(root, node6_path=impl, implementer_only=True)
    forged_impl_path = ".agent/state/artifacts/06-forged-implementer.json"
    forged_impl = json.loads((root / impl).read_text(encoding="utf-8"))
    forged_impl["implementer_agent_id"] = "fabricated-implementer"
    write_json(root / forged_impl_path, forged_impl)
    forged_impl_result = subprocess.run(
        [sys.executable, ".agent/scripts/artifactctl.py", "--node", "6", "--path", forged_impl_path],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if forged_impl_result.returncode == 0:
        raise AssertionError("node 6 accepted a root-authored implementer identity without platform evidence")
    run(root, "advance", "--node", "6", "--artifact", impl)
    release = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    # The state-machine section uses a stub controller, but the release gate
    # must exercise the real baseline-delta process detector.
    (root / ".agent/scripts/agentctl.py").write_bytes(pristine_agentctl)
    # Completion-path template semantics are covered by the dedicated template
    # suite. Install this fixture stub before signing the release candidate so
    # the signed control-surface fingerprint remains immutable afterwards.
    template_tool = root / ".agent/scripts/templatectl.py"
    pristine_template_tool = template_tool.read_bytes()
    template_tool.write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")
    # Freeze the governed bytes before constructing the integrator's v3 replay;
    # its candidate SHA is distinct from the review payload and must already
    # match the candidate the workflow release gate will verify.
    completed_ledger(root, node6_path=impl)
    ledger = json.loads((root / ".agent/state/agents.json").read_text(encoding="utf-8"))
    integrator = next(item for item in ledger["members"] if item["role_type"] == "integrator")
    replay_records = [
        item for item in integrator["result_evidence"]
        if item["source_path"] != integrator["result_report_path"]
    ]
    if len(replay_records) != 1:
        raise AssertionError("fixture integrator does not own exactly one clean replay")
    integrator_receipt_path = replay_records[0]["path"]
    preflight_path = ".agent/state/evidence/workflow-preflight.json"
    fingerprint = workflow_candidate_fingerprint(
        root, json.loads((root / ".agent/config.json").read_text(encoding="utf-8")),
    )
    signed_candidate_records = workflow_candidate_records(root)
    preflight = subprocess.run([
        sys.executable, ".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py",
        "preflight", "--runner", runner_path, "--receipt", preflight_path,
        "--environment", "local", "--authority", "default", "--candidate-sha256", fingerprint,
    ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if preflight.returncode:
        raise AssertionError(preflight.stdout)
    live_path = ".agent/state/evidence/workflow-live.json"
    gate = subprocess.run([
        sys.executable, ".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py",
        "run", "--runner", runner_path, "--receipt", live_path,
        "--integrator-receipt", integrator_receipt_path, "--preflight-receipt", preflight_path,
    ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if gate.returncode:
        raise AssertionError(gate.stdout)
    if (root / "workflow-gate-count.txt").exists():
        raise AssertionError("workflow gate executed the integrator command a second time")
    unregistered = root / "unregistered-runtime.py"
    unregistered.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    stray = subprocess.Popen([sys.executable, str(unregistered)], cwd=root, start_new_session=True)
    try:
        clean_probe = subprocess.run(
            [sys.executable, ".agent/scripts/agentctl.py", "assert-clean"],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        dirty_runtime_verify = subprocess.run([
            sys.executable, ".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py",
            "verify", "--runner", runner_path, "--receipt", live_path,
        ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if dirty_runtime_verify.returncode == 0:
            raise AssertionError(
                "workflow gate reused a receipt while an unregistered project process was live\n"
                + "direct assert-clean:\n" + clean_probe.stdout + "\nverify:\n"
                + dirty_runtime_verify.stdout
            )
    finally:
        stray.terminate(); stray.wait(timeout=5)
        unregistered.unlink()
    reused_gate = subprocess.run([
        sys.executable, ".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py",
        "run", "--runner", runner_path, "--receipt", live_path,
        "--integrator-receipt", integrator_receipt_path, "--preflight-receipt", preflight_path,
    ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if reused_gate.returncode or "REUSED workflow release gate" not in reused_gate.stdout:
        raise AssertionError("unchanged candidate did not reuse its release receipt\n" + reused_gate.stdout)
    if (root / "workflow-gate-count.txt").exists():
        raise AssertionError("receipt reuse executed workflow commands")
    cleanup_trap = root / "cleanup_fixture.py"
    cleanup_trap.write_text(
        "from pathlib import Path\nPath('workflow-cleanup-count.txt').write_text('executed')\n",
        encoding="utf-8",
    )
    legacy_runner = json.loads((root / runner_path).read_text(encoding="utf-8"))
    legacy_runner["cleanup_commands"] = [{
        "id": "cleanup-fixture", "argv": ["python3", "cleanup_fixture.py"], "timeout_seconds": 10,
    }]
    legacy_runner_path = ".agent/state/artifacts/04-workflow-runner-with-cleanup.json"
    write_json(root / legacy_runner_path, legacy_runner)
    rejected_cleanup_runner = subprocess.run([
        sys.executable, ".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py",
        "run", "--runner", legacy_runner_path, "--receipt", ".agent/state/evidence/legacy-live.json",
        "--integrator-receipt", integrator_receipt_path, "--preflight-receipt", preflight_path,
    ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if rejected_cleanup_runner.returncode == 0:
        raise AssertionError("v4 workflow gate accepted a runner-owned cleanup command")
    if (root / "workflow-cleanup-count.txt").exists():
        raise AssertionError("workflow gate executed a rejected cleanup command")
    cleanup_trap.unlink()
    live = receipt(root, live_path)
    report = acceptance(root, "release", release, live)
    pristine_report = (root / report).read_bytes()

    def assert_node7_rejected(mutator, label: str) -> None:
        value = json.loads(pristine_report)
        mutator(value)
        write_json(root / report, value)
        rejected = subprocess.run(
            [sys.executable, ".agent/scripts/artifactctl.py", "--node", "7", "--path", report],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if rejected.returncode == 0:
            raise AssertionError(f"node 7 accepted {label}\n{rejected.stdout}")
        (root / report).write_bytes(pristine_report)

    assert_node7_rejected(
        lambda value: value["reviewers"].update({"adversarial": "cross", "cross_reviewer": "adversary"}),
        "swapped canonical reviewer roles",
    )
    assert_node7_rejected(lambda value: value["checks"][0].update({"reviewer": "unknown"}), "unknown check reviewer")
    assert_node7_rejected(lambda value: value["scenarios"][0].update({"reviewer": "unknown"}), "unknown scenario reviewer")
    assert_node7_rejected(lambda value: value["review_chain"].update({"review_chain_id": "historical-chain"}), "historical review chain")
    assert_node7_rejected(lambda value: value["review_chain"].update({"review_subject_sha256": "0" * 64}), "mixed review subject")
    assert_node7_rejected(lambda value: value["scenarios"].pop(), "missing role-play lens")
    assert_node7_rejected(lambda value: value["scenarios"][1].update({"lens": "product"}), "duplicate role-play lens")
    assert_node7_rejected(
        lambda value: value["reviewers"].update({"implementer": "fabricated-implementer"}),
        "root-authored implementer identity",
    )
    assert_node7_rejected(
        lambda value: value["scenarios"][0]["assertions"].append("root-forged assertion"),
        "root-authored role scenario",
    )
    assert_node7_rejected(
        lambda value: value.update({"scenario_receipt_sha256": "0" * 64}),
        "drifted scenario receipt digest",
    )
    assert_node7_rejected(
        lambda value: value["platform_assurance"].update({"automatic_release_trust": True}),
        "automatic trust for caller-authored platform observations",
    )
    assert_node7_rejected(
        lambda value: value["supervision_debt"].append({"agent_id": "fabricated", "first_gap_at": "2026-07-17T00:00:00+00:00"}),
        "fabricated supervision debt",
    )
    assert_node7_rejected(
        lambda value: value.update({"supervision_debt_sha256": "0" * 64}),
        "drifted supervision debt digest",
    )
    assert_node7_rejected(
        lambda value: value["platform_observation_set"].pop(),
        "incomplete platform observation transcript set",
    )
    assert_node7_rejected(
        lambda value: value.update({"platform_observation_set_sha256": "0" * 64}),
        "drifted platform observation set digest",
    )
    assert_node7_rejected(
        lambda value: value.update({"recommendation": "request_human_acceptance"}),
        "ordinary acceptance without the required control waiver",
    )
    assert_node7_rejected(
        lambda value: value["scenarios"][0]["evidence"].append(value["scenarios"][0]["evidence"][0]),
        "duplicated root-authored scenario evidence",
    )

    pristine_acceptance = json.loads(pristine_report)
    scenario_evidence_path = root / pristine_acceptance["scenarios"][0]["evidence"][0]["path"]
    pristine_scenario_evidence = scenario_evidence_path.read_bytes()
    scenario_evidence_path.write_bytes(pristine_scenario_evidence + b"drift")
    drifted_scenario = subprocess.run(
        [sys.executable, ".agent/scripts/artifactctl.py", "--node", "7", "--path", report],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if drifted_scenario.returncode == 0:
        raise AssertionError("node 7 accepted drifted cross-authored scenario evidence")
    scenario_evidence_path.write_bytes(pristine_scenario_evidence)

    implementation_member = next(
        item for item in json.loads((root / ".agent/state/agents.json").read_text(encoding="utf-8"))["members"]
        if item["id"] == "implementer"
    )
    implementation_result_path = root / implementation_member["result_evidence"][0]["path"]
    pristine_implementation_result = implementation_result_path.read_bytes()
    implementation_result_path.write_bytes(pristine_implementation_result + b"drift")
    drifted_attestation = subprocess.run(
        [sys.executable, ".agent/scripts/artifactctl.py", "--node", "7", "--path", report],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if drifted_attestation.returncode == 0:
        raise AssertionError("node 7 accepted drifted implementer attestation evidence")
    implementation_result_path.write_bytes(pristine_implementation_result)

    # Even a fully valid historical ledger cannot release a newly changed
    # candidate: the sealed subject must contain the current node authorities.
    task_path = root / ".agent/state/TASK.json"
    pristine_task = task_path.read_bytes()
    changed_candidate = root / "changed-node-4.txt"
    changed_candidate.write_text("different candidate", encoding="utf-8")
    changed_task = json.loads(pristine_task)
    changed_task["node_artifacts"]["4"] = receipt(root, changed_candidate.name)
    write_json(task_path, changed_task)
    stale_candidate = subprocess.run(
        [sys.executable, ".agent/scripts/artifactctl.py", "--node", "7", "--path", report],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if stale_candidate.returncode == 0:
        raise AssertionError("node 7 accepted a historical sealed payload for a changed candidate")
    task_path.write_bytes(pristine_task)

    ledger_path = root / ".agent/state/agents.json"
    pristine_ledger = ledger_path.read_bytes()
    marker_root = root / ".agent/state/evidence/agent-terminal-markers"
    pristine_markers = {
        path.relative_to(marker_root): path.read_bytes() for path in marker_root.rglob("*.json")
    }
    rewritten = json.loads(pristine_ledger)
    rewritten["members"][0]["conclusion"] = "PASS rewritten by integrator"
    ledger_path.write_text(json.dumps(rewritten), encoding="utf-8")
    rewritten_result = subprocess.run(
        [sys.executable, ".agent/scripts/artifactctl.py", "--node", "7", "--path", report],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if rewritten_result.returncode == 0:
        raise AssertionError("node 7 accepted a conclusion not committed by the terminal reviewer")
    ledger_path.write_bytes(pristine_ledger)
    rewritten = json.loads(pristine_ledger)
    rewritten["members"][0]["result_evidence"] = []
    ledger_path.write_text(json.dumps(rewritten), encoding="utf-8")
    rewritten_evidence = subprocess.run(
        [sys.executable, ".agent/scripts/artifactctl.py", "--node", "7", "--path", report],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if rewritten_evidence.returncode == 0:
        raise AssertionError("node 7 accepted report evidence not committed by the terminal reviewer")
    ledger_path.write_bytes(pristine_ledger)

    def assert_ledger_attack_rejected(mutator, label: str) -> None:
        attacked = json.loads(pristine_ledger)
        mutator(attacked)
        write_json(ledger_path, attacked)
        result = subprocess.run(
            [sys.executable, ".agent/scripts/artifactctl.py", "--node", "7", "--path", report],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if result.returncode == 0:
            raise AssertionError(f"node 7 accepted {label}\n{result.stdout}")
        ledger_path.write_bytes(pristine_ledger)

    assert_ledger_attack_rejected(
        lambda value: value["members"][2].update({"predecessor_result_sha256": "0" * 64}),
        "cross review with a forged predecessor digest",
    )
    assert_ledger_attack_rejected(
        lambda value: value["members"][2].update({"registration_observed_at": value["members"][1]["started_at"]}),
        "cross review registered before adversarial completion",
    )
    assert_ledger_attack_rejected(
        lambda value: value["members"][2]["review_attestation"].update({"lenses": ["product"]}),
        "cross attestation missing five role lenses",
    )
    assert_ledger_attack_rejected(
        lambda value: value["members"][3].update({"result_evidence": value["members"][3]["result_evidence"][:1]}),
        "integrator without the required clean replay",
    )
    assert_ledger_attack_rejected(
        lambda value: value["members"][3]["result_evidence"].__setitem__(1, value["members"][3]["result_evidence"][0]),
        "integrator with report bytes impersonating a clean replay",
    )

    def assert_cross_receipt_attack_rejected(attack: str, label: str) -> None:
        completed_ledger(root, node6_path=impl, scenario_attack=attack)
        attacked_report = acceptance(root, "release", release, live)
        result = subprocess.run(
            [sys.executable, ".agent/scripts/artifactctl.py", "--node", "7", "--path", attacked_report],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if result.returncode == 0:
            raise AssertionError(f"node 7 accepted {label}\n{result.stdout}")
        (root / report).write_bytes(pristine_report)
        ledger_path.write_bytes(pristine_ledger)
        for relative, data in pristine_markers.items():
            target = marker_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.chmod(0o644)
            target.write_bytes(data)

    assert_cross_receipt_attack_rejected("duplicate_evidence", "cross scenario receipt with duplicated evidence")
    assert_cross_receipt_attack_rejected("duplicate_key", "cross scenario receipt with duplicated JSON fields")

    def assert_replay_window_rejected(case_windows, label: str) -> None:
        completed_ledger(root, replay_case_windows=case_windows)
        result = subprocess.run(
            [sys.executable, ".agent/scripts/artifactctl.py", "--node", "7", "--path", report],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if result.returncode == 0:
            raise AssertionError(f"node 7 accepted {label}\n{result.stdout}")
        ledger_path.write_bytes(pristine_ledger)
        for relative, data in pristine_markers.items():
            target = marker_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.chmod(0o644)
            target.write_bytes(data)

    # The integrator registers at +30s and terminates at +35s. The shared
    # clock-skew allowance is five seconds, so these windows are invalid.
    assert_replay_window_rejected(((0, 1),), "a registration-preceding historical clean replay")
    assert_replay_window_rejected(((41, 42),), "a post-terminal clean replay")

    # Full-chain completion revalidates every accepted artifact. Supply the
    # legacy fixture's previously accepted solution approval/render records;
    # template semantics themselves are covered by the template suite.
    bind_node_template(root, "node-acceptance", report)
    release_state = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    release_state["gate_approvals"]["solution"] = {
        "source": "user:fixture",
        "artifact_sha256": release_state["node_artifacts"]["4"]["sha256"],
    }
    rendered_by_node = {2: "structured-requirement", 3: "deliverables", 4: "solution", 5: "acceptance-matrix"}
    terminal_renders = [
        item for item in release_state["rendered_artifacts"]
        if item.get("template_id") in {"node-implementation", "node-acceptance", "acceptance-workflow"}
    ]
    release_state["rendered_artifacts"] = [
        dict(release_state["node_artifacts"][str(node)], template_id=template_id)
        for node, template_id in rendered_by_node.items()
    ] + terminal_renders
    write_json(root / ".agent/state/TASK.json", release_state)
    stage(root, release_state)

    final_gate_verify = subprocess.run([
        sys.executable, ".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py",
        "verify", "--runner", runner_path, "--receipt", live_path,
    ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if final_gate_verify.returncode:
        current_records = workflow_candidate_records(root)
        drift = {
            path: {"signed": signed_candidate_records.get(path), "current": current_records.get(path)}
            for path in sorted(set(signed_candidate_records) | set(current_records))
            if signed_candidate_records.get(path) != current_records.get(path)
        }
        raise AssertionError(
            "final workflow gate fixture is no longer valid\n" + final_gate_verify.stdout
            + "candidate record drift:\n" + json.dumps(drift, indent=2, sort_keys=True)
        )
    report_digest = digest(root / report)
    run(root, "submit-gate", "--gate", "acceptance", "--artifact", report)
    run(root, "approve-gate", "--gate", "acceptance", "--source", "user:fixture", "--artifact-sha256", report_digest, expected=1)
    approved_report=json.loads((root/report).read_text(encoding="utf-8"))
    completion_snapshot = empty_platform_snapshot(root, "workflow-final-empty-platform")
    run(
        root, "approve-gate", "--gate", "acceptance", "--source", "user:fixture",
        "--artifact-sha256", report_digest,
        "--platform-transcript-verified-sha256", approved_report["platform_observation_set_sha256"],
        "--supervision-debt-waiver-sha256", approved_report["supervision_debt_sha256"],
    )
    run(root, "advance", "--node", "7", "--artifact", report)
    if (root / "workflow-gate-count.txt").exists():
        raise AssertionError("node completion executed workflow commands outside the integrator replay")
    release = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    if release["current_node"] != 8:
        raise AssertionError("release live gate did not advance to delivery")

    # Build a legal release terminal fixture, then prove complete-task is
    # transactional under Node 7/8 bytes, node records and approval drift.
    for command in (("init",), ("snapshot-node8",)):
        result = subprocess.run(
            [sys.executable, ".agent/scripts/deliveryctl.py", *command], cwd=root,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if result.returncode:
            raise AssertionError(f"delivery fixture {command} failed\n{result.stdout}")
    node8_path = ".agent/state/artifacts/08-delivery.json"
    run(root, "advance", "--node", "8", "--artifact", node8_path)
    ready_task_path = root / ".agent/state/TASK.json"
    ready_context_path = root / ".agent/state/CONTEXT.json"
    ready_task = json.loads(ready_task_path.read_text(encoding="utf-8"))
    if ready_task["status"] != "ready_to_complete" or ready_task["accepted_nodes"] != list(range(9)):
        raise AssertionError("release fixture did not reach the complete-task boundary")

    retrospective = ".agent/state/artifacts/08-retrospective.md"
    (root / retrospective).write_text("""# Retrospective

- Result and success criteria: passed
- Wall / waiting time: fixture
- Measured or estimated Tokens: fixture
- References / Agent cumulative and peak: fixture
- Rework / user corrections / tests / defects / blocks: fixture
- What worked / failed: fixture
- Knowledge candidates: none
- Promotion decision and source: user:fixture
""", encoding="utf-8")

    def assert_complete_rejected_without_state_mutation(label: str) -> None:
        before_task = ready_task_path.read_bytes()
        before_context = ready_context_path.read_bytes()
        run(
            root, "complete-task", "--retrospective", retrospective,
            "--platform-snapshot", completion_snapshot,
            "--completion-source", "user:fixture",
            "--completion-platform-transcript-verified-sha256", digest(root / completion_snapshot),
            expected=1,
        )
        if ready_task_path.read_bytes() != before_task or ready_context_path.read_bytes() != before_context:
            raise AssertionError(f"failed complete-task mutated TASK/CONTEXT for {label}")

    for artifact_key, label in (("7", "Node 7 bytes drift"), ("8", "Node 8 bytes drift")):
        artifact_path = root / str(ready_task["node_artifacts"][artifact_key]["path"])
        pristine_artifact = artifact_path.read_bytes()
        artifact_path.write_bytes(pristine_artifact + b"\ndrift")
        assert_complete_rejected_without_state_mutation(label)
        artifact_path.write_bytes(pristine_artifact)

    pristine_ready_task = ready_task_path.read_bytes()
    missing_node = json.loads(pristine_ready_task)
    del missing_node["node_artifacts"]["8"]
    write_json(ready_task_path, missing_node)
    assert_complete_rejected_without_state_mutation("missing terminal node artifact")
    ready_task_path.write_bytes(pristine_ready_task)

    drifted_approval = json.loads(pristine_ready_task)
    drifted_approval["gate_approvals"]["acceptance"]["artifact_sha256"] = "0" * 64
    write_json(ready_task_path, drifted_approval)
    assert_complete_rejected_without_state_mutation("release acceptance approval drift")
    ready_task_path.write_bytes(pristine_ready_task)

    before_missing_decision_task = ready_task_path.read_bytes()
    before_missing_decision_context = ready_context_path.read_bytes()
    run(
        root, "complete-task", "--retrospective", retrospective,
        "--platform-snapshot", completion_snapshot, expected=1,
    )
    run(
        root, "complete-task", "--retrospective", retrospective,
        "--platform-snapshot", completion_snapshot,
        "--completion-source", "user:fixture",
        "--completion-platform-transcript-verified-sha256", "0" * 64,
        expected=1,
    )
    if (
        ready_task_path.read_bytes() != before_missing_decision_task
        or ready_context_path.read_bytes() != before_missing_decision_context
    ):
        raise AssertionError("missing or wrongly bound completion decision mutated TASK/CONTEXT")

    completion_provider_dir = Path(tempfile.mkdtemp(prefix="workflow-completion-provider-"))
    completion_provider = completion_provider_dir / "verify-human-decision.py"
    completion_provider.write_text("""#!/usr/bin/env python3
import hashlib, pathlib, sys
receipt = pathlib.Path(sys.argv[sys.argv.index('--receipt') + 1])
print('VERIFIED HUMAN DECISION sha256=' + hashlib.sha256(receipt.read_bytes()).hexdigest())
""", encoding="utf-8")
    completion_provider.chmod(0o755)
    completion_config = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))
    completion_config["agent_control"]["human_decision_observer"]["signed_adapter"] = str(completion_provider.resolve())
    write_json(root / ".agent/config.json", completion_config)

    policy_ready_task = json.loads(pristine_ready_task)
    policy_ready_task["decision_policy_version"] = 1

    def completion_routing_profile(value: dict[str, object]) -> str:
        return canonical_digest({
            key: value.get(key)
            for key in (
                "task_type", "complexity", "mode", "files", "environment",
                "deployment_requested", "branch", "risk_flags",
            )
        })

    def completion_decision(gate: str, artifact_sha256: str) -> tuple[str, dict[str, object]]:
        decision_id = f"completion-policy-{gate}"
        relative = f".agent/state/evidence/{decision_id}.json"
        write_json(root / relative, {
            "schema": "agent-human-decision/v1", "decision_id": decision_id,
            "gate": gate, "decision": "approved", "artifact_sha256": artifact_sha256,
            "source": "user:fixture", "task_title": policy_ready_task["title"],
            "task_mode": policy_ready_task["mode"],
            "routing_profile_sha256": completion_routing_profile(policy_ready_task),
            "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "authority": "provider-signed-user-message",
        })
        return relative, {
            "schema": "agent-human-decision/v1", "path": relative,
            "sha256": digest(root / relative), "bytes": len((root / relative).read_bytes()),
            "decision_id": decision_id, "authority": "provider-signed-user-message",
            "adapter_path": str(completion_provider.resolve()), "adapter_sha256": digest(completion_provider),
        }

    requirement_decision_path, requirement_decision_record = completion_decision(
        "requirement", str(policy_ready_task["requirement_contract_sha256"]),
    )
    _, solution_decision_record = completion_decision(
        "solution", str(policy_ready_task["node_artifacts"]["4"]["sha256"]),
    )
    _, acceptance_decision_record = completion_decision(
        "acceptance", str(policy_ready_task["node_artifacts"]["7"]["sha256"]),
    )
    completion_decision_path, _ = completion_decision(
        "completion", digest(root / completion_snapshot),
    )
    policy_ready_task["gate_approvals"]["requirement"] = {
        "source": "user:fixture", "artifact_sha256": policy_ready_task["requirement_contract_sha256"],
        "decision_receipt": requirement_decision_record,
    }
    policy_ready_task["gate_approvals"]["solution"]["decision_receipt"] = solution_decision_record
    policy_ready_task["gate_approvals"]["acceptance"]["decision_receipt"] = acceptance_decision_record
    write_json(ready_task_path, policy_ready_task)
    stage(root, policy_ready_task)

    assert_complete_rejected_without_state_mutation("decision-policy v1 missing completion receipt")
    completion_config["agent_control"]["human_decision_observer"]["signed_adapter"] = None
    write_json(root / ".agent/config.json", completion_config)
    before_missing_adapter_task = ready_task_path.read_bytes()
    before_missing_adapter_context = ready_context_path.read_bytes()
    run(
        root, "complete-task", "--retrospective", retrospective,
        "--platform-snapshot", completion_snapshot,
        "--completion-source", "user:fixture",
        "--completion-platform-transcript-verified-sha256", digest(root / completion_snapshot),
        "--human-decision-receipt", completion_decision_path, expected=1,
    )
    if (
        ready_task_path.read_bytes() != before_missing_adapter_task
        or ready_context_path.read_bytes() != before_missing_adapter_context
    ):
        raise AssertionError("missing external completion adapter mutated TASK/CONTEXT")
    completion_config["agent_control"]["human_decision_observer"]["signed_adapter"] = str(completion_provider.resolve())
    write_json(root / ".agent/config.json", completion_config)
    before_untrusted_adapter_task = ready_task_path.read_bytes()
    before_untrusted_adapter_context = ready_context_path.read_bytes()
    run(
        root, "complete-task", "--retrospective", retrospective,
        "--platform-snapshot", completion_snapshot,
        "--completion-source", "user:fixture",
        "--completion-platform-transcript-verified-sha256", digest(root / completion_snapshot),
        "--human-decision-receipt", completion_decision_path, expected=1,
    )
    if (
        ready_task_path.read_bytes() != before_untrusted_adapter_task
        or ready_context_path.read_bytes() != before_untrusted_adapter_context
    ):
        raise AssertionError("Agent-created external completion adapter mutated TASK/CONTEXT")
    completion_config["agent_control"]["human_decision_observer"]["signed_adapter"] = None
    write_json(root / ".agent/config.json", completion_config)
    legacy_ready_task = json.loads(pristine_ready_task)
    write_json(ready_task_path, legacy_ready_task)
    stage(root, legacy_ready_task)
    run(
        root, "complete-task", "--retrospective", retrospective,
        "--platform-snapshot", completion_snapshot,
        "--completion-source", "user:fixture",
        "--completion-platform-transcript-verified-sha256", digest(root / completion_snapshot),
    )
    completed_task_value = json.loads(ready_task_path.read_text(encoding="utf-8"))
    completion_binding = completed_task_value.get("completion_binding", {})
    completed_artifact_set = [
        {"node": int(node), **record}
        for node, record in sorted(
            completed_task_value["node_artifacts"].items(), key=lambda item: int(item[0]),
        )
    ]
    if (
        set(completion_binding) != {
            "schema", "accepted_artifact_set_sha256", "terminal_artifact_sha256",
            "release_approval_sha256", "completion_platform_snapshot_sha256",
            "completion_decision_source", "completion_decision_receipt",
        }
        or completion_binding.get("accepted_artifact_set_sha256") != canonical_digest(completed_artifact_set)
        or completion_binding.get("release_approval_sha256") != canonical_digest(
            completed_task_value["gate_approvals"]["acceptance"],
        )
        or completion_binding.get("completion_platform_snapshot_sha256") != digest(root / completion_snapshot)
        or completion_binding.get("completion_decision_source") != "user:fixture"
        or completion_binding.get("completion_decision_receipt") is not None
        or completion_binding.get("terminal_artifact_sha256") != ready_task["node_artifacts"]["8"]["sha256"]
    ):
        raise AssertionError("completion binding did not commit the terminal artifact, final snapshot and human source")
    completed_route = json.loads(run(root, "route-resume"))
    if completed_route["terminal"] is not True or completed_route["action"] != "complete":
        raise AssertionError("legal complete-task checkpoint was not recognized as terminal")
    shutil.rmtree(completion_provider_dir)
    shutil.rmtree(platform_provider_dir)
    template_tool.write_bytes(pristine_template_tool)

    # A compacted root resumes from canonical TASK even when the Agent ledger
    # is empty. Only an explicit complete-task checkpoint is terminal.
    resume_task=task("standard",4,[0,1,2,3]); resume_task["budget_state"]="must_compact"
    install_task(root,resume_task)
    resume_sha=hashlib.sha256(json.dumps(resume_task,ensure_ascii=False,sort_keys=True,separators=(",", ":")).encode()).hexdigest()
    write_json(root/".agent/state/CONTEXT.json",{
        "task_invariant_sha256":resume_sha,
        "resume":{"schema":"agent-context-resume/v1","task_status":"in_progress","current_node":4,
                  "next_action":resume_task["next_action"],"budget_state":"must_compact","terminal":False,
                  "resume_action":"continue","task_invariant_sha256":resume_sha},
        "checkpoint":{"transition_authorization":None},
    })
    routed=json.loads(run(root,"route-resume"))
    if (
        routed["terminal"] is not False
        or routed["action"] != "waiting_host_resume"
        or routed["current_node"] != 4
        or not str(routed.get("resume_command", "")).startswith(
            f"HOST RESUME REQUIRED: cursor={routed.get('resume_cursor')} "
        )
        or "route-resume" in str(routed.get("resume_command", ""))
    ):
        raise AssertionError("compacted task did not publish its cursor-bound host resume command")
    # route-resume uses the effective active-window estimate together with
    # outstanding child reservations, rather than trusting TASK.tokens_used
    # or its cached budget_state in isolation.
    agents_path = root / ".agent/state/agents.json"
    agents_before = agents_path.read_bytes()
    context_path = root / ".agent/state/CONTEXT.json"
    context_before = context_path.read_bytes()
    combined_context = json.loads(context_before)
    combined_context["usage_freshness"] = {"estimated_tokens": 10000}
    write_json(context_path, combined_context)
    write_json(agents_path, {"prepared_dispatches": [{
        "fork_turns": 0,
        "token_reservation": {"status": "reserved", "estimated_tokens": 6000},
    }]})
    combined_route = json.loads(run(root, "route-resume"))
    if combined_route.get("budget_state") != "hard_blocked" or combined_route.get("action") != "waiting_human":
        raise AssertionError("route-resume undercounted active context plus child reservation")
    agents_path.write_bytes(agents_before)
    context_path.write_bytes(context_before)
    invalid_terminal={**resume_task,"status":"accepted","current_node":4}
    write_json(root/".agent/state/TASK.json",invalid_terminal)
    rejected_route=json.loads(run(root,"route-resume",expected=1))
    if rejected_route["terminal"] is not False or rejected_route["action"]!="waiting_human":
        raise AssertionError("illegal accepted/current-node state was treated as terminal")
    fake_completed_task={**resume_task,"status":"accepted","current_node":"idle","phase":"idle",
                         "accepted_nodes":list(range(8)),"next_action":"start the next requirement in clarification"}
    write_json(root/".agent/state/TASK.json",fake_completed_task)
    completed_sha=hashlib.sha256(json.dumps(fake_completed_task,ensure_ascii=False,sort_keys=True,separators=(",", ":")).encode()).hexdigest()
    write_json(root/".agent/state/CONTEXT.json",{
        "task_invariant_sha256":completed_sha,
        "resume":{"schema":"agent-context-resume/v1","task_status":"accepted","current_node":"idle",
                  "next_action":fake_completed_task["next_action"],"budget_state":"must_compact","terminal":True,
                  "resume_action":"complete","task_invariant_sha256":completed_sha},
        "checkpoint":{"transition_authorization":{"mutator":"workflowctl","operation":"complete-task"}},
    })
    forged_route=json.loads(run(root,"route-resume",expected=1))
    if forged_route["terminal"] is not False or forged_route["action"]!="waiting_human":
        raise AssertionError("pseudo completion checkpoint made an incomplete accepted task terminal")

    # Decision-policy v1 never accepts a caller label by itself. A missing
    # receipt is rejected even when the requirement receipt is provider
    # verified; a valid-looking receipt is still unusable without the external
    # provider-owned adapter.
    provider_dir = Path(tempfile.mkdtemp(prefix="workflow-provider-adapter-"))
    provider_adapter = provider_dir / "verify-human-decision.py"
    provider_adapter.write_text("""#!/usr/bin/env python3
import hashlib, pathlib, sys
receipt = pathlib.Path(sys.argv[sys.argv.index('--receipt') + 1])
print('VERIFIED HUMAN DECISION sha256=' + hashlib.sha256(receipt.read_bytes()).hexdigest())
""", encoding="utf-8")
    provider_adapter.chmod(0o755)

    policy_task = task("standard", 4, [0, 1, 2, 3])
    policy_task["decision_policy_version"] = 1
    solution_decision_path = ".agent/state/artifacts/04-policy-solution.md"
    (root / solution_decision_path).write_text("provider-bound solution\n", encoding="utf-8")
    solution_decision_record = receipt(root, solution_decision_path)
    policy_task["rendered_artifacts"] = [dict(solution_decision_record, template_id="solution")]
    policy_task["pending_gate_artifacts"] = {"solution": solution_decision_record}
    policy_task["status"] = "waiting_human"
    install_task(root, policy_task)
    policy_task = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    policy_task["pending_gate_artifacts"] = {"solution": solution_decision_record}
    policy_task["status"] = "waiting_human"

    def routing_profile(value: dict[str, object]) -> str:
        profile = {
            key: value.get(key)
            for key in (
                "task_type", "complexity", "mode", "files", "environment",
                "deployment_requested", "branch", "risk_flags",
            )
        }
        return canonical_digest(profile)

    def human_decision_receipt(gate: str, artifact_sha256: str, decision_id: str) -> str:
        relative = f".agent/state/evidence/{gate}-human-decision.json"
        write_json(root / relative, {
            "schema": "agent-human-decision/v1", "decision_id": decision_id,
            "gate": gate, "decision": "approved", "artifact_sha256": artifact_sha256,
            "source": "user:fixture", "task_title": policy_task["title"],
            "task_mode": policy_task["mode"], "routing_profile_sha256": routing_profile(policy_task),
            "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "authority": "provider-signed-user-message",
        })
        return relative

    requirement_decision = human_decision_receipt(
        "requirement", str(policy_task["requirement_contract_sha256"]), "requirement-fixture",
    )
    solution_decision = human_decision_receipt(
        "solution", str(solution_decision_record["sha256"]), "solution-fixture",
    )
    fixture_config = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))
    fixture_config["agent_control"]["human_decision_observer"]["signed_adapter"] = str(provider_adapter.resolve())
    write_json(root / ".agent/config.json", fixture_config)
    policy_task["gate_approvals"]["requirement"] = {
        "source": "user:fixture",
        "artifact_sha256": policy_task["requirement_contract_sha256"],
        "decision_receipt": {
            "schema": "agent-human-decision/v1", "path": requirement_decision,
            "sha256": digest(root / requirement_decision), "bytes": len((root / requirement_decision).read_bytes()),
            "decision_id": "requirement-fixture", "authority": "provider-signed-user-message",
            "adapter_path": str(provider_adapter.resolve()), "adapter_sha256": digest(provider_adapter),
        },
    }
    write_json(root / ".agent/state/TASK.json", policy_task)
    stage(root, policy_task)
    before_policy_task = (root / ".agent/state/TASK.json").read_bytes()
    run(
        root, "approve-gate", "--gate", "solution", "--source", "user:fixture",
        "--artifact-sha256", str(solution_decision_record["sha256"]), expected=1,
    )
    if (root / ".agent/state/TASK.json").read_bytes() != before_policy_task:
        raise AssertionError("missing provider decision receipt mutated or approved the gate")

    run(
        root, "approve-gate", "--gate", "solution", "--source", "user:fixture",
        "--artifact-sha256", str(solution_decision_record["sha256"]),
        "--human-decision-receipt", solution_decision, expected=1,
    )
    if (root / ".agent/state/TASK.json").read_bytes() != before_policy_task:
        raise AssertionError("Agent-created external adapter mutated or approved the solution gate")

    fixture_config["agent_control"]["human_decision_observer"]["signed_adapter"] = None
    write_json(root / ".agent/config.json", fixture_config)
    run(
        root, "approve-gate", "--gate", "solution", "--source", "user:fixture",
        "--artifact-sha256", str(solution_decision_record["sha256"]),
        "--human-decision-receipt", solution_decision, expected=1,
    )
    if (root / ".agent/state/TASK.json").read_bytes() != before_policy_task:
        raise AssertionError("gate was mutated without a configured external decision adapter")
    shutil.rmtree(provider_dir)

# Node 6 commits the initial implementer ID so a one-time retry can reuse the
# exact sealed candidate. Node 7 must resolve only the single same-authority
# replacement, never an arbitrary parallel member.
sys.path.insert(0, str(SOURCE / "scripts"))
artifact_spec = importlib.util.spec_from_file_location(
    "workflow_artifactctl_fixture", SOURCE / "scripts/artifactctl.py",
)
if artifact_spec is None or artifact_spec.loader is None:
    raise AssertionError("cannot load artifactctl resolver fixture")
artifact_module = importlib.util.module_from_spec(artifact_spec)
artifact_spec.loader.exec_module(artifact_module)
initial = {
    "id": "implementer-a", "root_task_id": "task", "role_type": "implementer",
    "redispatch_count": 0, "status": "interrupted", "redispatched_to": "implementer-b",
    "task_payload_sha256": "a" * 64, "task_payload_evidence": {"fixture": "same"},
    "model": "gpt-5.6-sol", "fork_turns": 10,
}
replacement = {
    **initial, "id": "implementer-b", "redispatch_count": 1,
    "status": "completed", "redispatched_to": None, "fork_turns": 0,
}
resolver_errors: list[str] = []
resolved = artifact_module.resolved_implementer(
    {"members": [initial, replacement]}, "implementer-a", resolver_errors,
)
if resolver_errors or not isinstance(resolved, dict) or resolved.get("id") != "implementer-b":
    raise AssertionError(f"bounded implementer redispatch did not resolve: {resolver_errors}")
for attacked, label in (
    ([initial, {**replacement, "task_payload_sha256": "b" * 64}], "changed payload"),
    ([initial, {**replacement, "fork_turns": 10}], "replacement inherited parent history"),
    ([initial, replacement, {**replacement, "id": "implementer-c"}], "parallel attempt"),
    ([initial, {**replacement, "status": "interrupted"}], "nonterminal replacement"),
):
    attack_errors: list[str] = []
    if artifact_module.resolved_implementer({"members": attacked}, "implementer-a", attack_errors) is not None:
        raise AssertionError(f"implementer resolver accepted {label}")

control_errors: list[str] = []
control_members = artifact_module.delivery_control_members(
    {
        "implementer-a": {**initial, "redispatched_to": "implementer-b"},
        "implementer-b": replacement,
        "adversary-failed": {"id": "adversary-failed", "root_task_id": "task", "role_type": "adversarial",
                              "review_chain_id": "chain", "review_subject_sha256": "s" * 64},
        "adversary-pass": {"id": "adversary-pass", "root_task_id": "task", "role_type": "adversarial",
                            "review_chain_id": "chain", "review_subject_sha256": "s" * 64},
        "historical-other": {"id": "historical-other", "root_task_id": "task", "role_type": "cross",
                              "review_chain_id": "old", "review_subject_sha256": "s" * 64},
    },
    "implementer-a", "task", "chain", "s" * 64, control_errors,
)
if control_errors or {item["id"] for item in control_members} != {
    "implementer-a", "implementer-b", "adversary-failed", "adversary-pass",
}:
    raise AssertionError("Node 7 control debt set omitted a redispatch source or failed formal review attempt")

print("WORKFLOW SELF-TEST PASSED: adaptive projection, stable rollback and executable adapter gate")
