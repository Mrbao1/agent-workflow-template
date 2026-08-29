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
import time
from typing import Dict, Optional


SOURCE = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(SOURCE/"scripts"))
import testrun as canonical_testrun
import agentctl as canonical_agentctl
FIXTURE_MODEL = "vendor-x/reasoning.model+2026"
TEST_EXECUTION_BOUNDARY=canonical_testrun.TEST_EXECUTION_BOUNDARY


PROVIDER_WRAPPER = r"""
import hashlib, runpy, sys
from pathlib import Path

target = sys.argv[1]
sys.path.insert(0, str(Path(target).resolve().parent))
import humandecision


def provider_verify(root, config, task, *, gate, artifact_sha256, source, receipt, require_fresh=True):
    path = humandecision.resolve_receipt(root, receipt)
    raw, _ = humandecision.receipt_snapshot(path)
    value = humandecision.parse_receipt(
        path, task, gate, artifact_sha256, source,
        900 if require_fresh else 0,
        raw=raw,
    )
    return {
        "schema": humandecision.SCHEMA, "path": str(path.relative_to(root.resolve())),
        "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
        "decision_id": value["decision_id"], "authority": value["authority"],
        "source": source, "artifact_sha256": artifact_sha256,
        "adapter_path": "/test-only/provider-verifier", "adapter_sha256": "e" * 64,
    }


def provider_reverify(root, config, task, *, gate, artifact_sha256, source, record):
    if not isinstance(record, dict) or not isinstance(record.get("path"), str):
        return False
    try:
        return record == provider_verify(
            root, config, task, gate=gate, artifact_sha256=artifact_sha256,
            source=source, receipt=record["path"], require_fresh=False,
        )
    except Exception:
        return False
    except SystemExit:
        return False


humandecision.verify = provider_verify
humandecision.reverify = provider_reverify
sys.argv = sys.argv[1:]
runpy.run_path(target, run_name="__main__")
"""
PROVIDER_SITE_PATCH = (
    "import hashlib\n"
    + PROVIDER_WRAPPER[PROVIDER_WRAPPER.index("def provider_verify"):PROVIDER_WRAPPER.index("sys.argv =")]
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def decision_project_identity(root:Path)->str:
    config=json.loads((root/".agent/config.json").read_text(encoding="utf-8")); initialization=config.get("project_initialization",{})
    return canonical_digest({"root":str(root.resolve()),"project":config.get("project"),
                             "guardrails_sha256":initialization.get("guardrails_sha256") if isinstance(initialization,dict) else None})


def decision_task_generation(value:dict[str,object])->str:
    return canonical_digest({key:value.get(key) for key in (
        "task_generation_id","title","mode","task_type","requirement_contract_sha256","files","environment","deployment_requested","branch","task_archive")})


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
            "print(json.dumps({r['kind']+':'+r['path']:r for r in testrun.candidate_records(c)},sort_keys=True))"
        )],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if probe.returncode:
        raise AssertionError(f"canonical candidate record probe failed:\n{probe.stdout}")
    return json.loads(probe.stdout)


def refresh_node_capture(root: Path, relative: str) -> None:
    result=subprocess.run([sys.executable,"-c","import sys;sys.path.insert(0,'.agent/scripts');import workflowctl;workflowctl.node_artifact(sys.argv[1])",relative],cwd=root,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if result.returncode: raise AssertionError("failed to reseal restored node artifact:\n"+result.stdout)


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


def decision_receipt(root: Path, task_value: dict[str, object], gate: str, artifact_sha256: str, source: str = "user:fixture") -> str:
    decision_id = hashlib.sha256(f"{gate}:{artifact_sha256}:{source}".encode()).hexdigest()[:24]
    relative = f".agent/state/evidence/provider-decision-{decision_id}.json"
    write_json(root / relative, {
        "schema": "agent-human-decision/v1", "decision_id": decision_id,
        "gate": gate, "decision": "approved", "artifact_sha256": artifact_sha256,
        "source": source, "task_title": task_value["title"], "task_mode": task_value["mode"],
        "routing_profile_sha256":canonical_digest({key:task_value.get(key) for key in (
            "task_type","complexity","mode","files","environment","deployment_requested","branch","risk_flags")}),
        "project_identity_sha256":canonical_digest({
            "root":str(root.resolve()),"project":json.loads((root/".agent/config.json").read_text(encoding="utf-8")).get("project"),
            "guardrails_sha256":json.loads((root/".agent/config.json").read_text(encoding="utf-8")).get("project_initialization",{}).get("guardrails_sha256"),
        }),
        "task_generation_sha256":canonical_digest({key:task_value.get(key) for key in (
            "task_generation_id","title","mode","task_type","requirement_contract_sha256","files","environment","deployment_requested","branch","task_archive")}),
        "task_generation_id":task_value["task_generation_id"],
        "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "authority": "provider-signed-user-message",
    })
    return relative


def provider_record(root: Path, receipt_path: str) -> dict[str, object]:
    value = json.loads((root / receipt_path).read_text(encoding="utf-8"))
    raw = (root / receipt_path).read_bytes()
    return {
        "schema": "agent-human-decision/v1", "path": receipt_path,
        "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
        "decision_id": value["decision_id"], "authority": "provider-signed-user-message",
        "source": value["source"], "artifact_sha256": value["artifact_sha256"],
        "adapter_path": "/test-only/provider-verifier", "adapter_sha256": "e" * 64,
    }


def run(root: Path, *args: str, expected: int = 0) -> str:
    arguments = list(args)
    if expected == 0 and "--human-decision-receipt" not in arguments:
        task_value = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        if arguments and arguments[0] == "approve-gate":
            gate = arguments[arguments.index("--gate") + 1]
            artifact_sha256 = arguments[arguments.index("--artifact-sha256") + 1]
            source = arguments[arguments.index("--source") + 1]
            arguments += ["--human-decision-receipt", decision_receipt(root, task_value, gate, artifact_sha256, source)]
        elif arguments and arguments[0] == "resolve-failure":
            artifact_sha256 = task_value["failure_escalation"]["artifact_sha256"]
            source = arguments[arguments.index("--source") + 1]
            arguments += ["--human-decision-receipt", decision_receipt(root, task_value, "failure-escalation", artifact_sha256, source)]
        elif arguments and arguments[0] == "complete-task" and task_value.get("mode") == "release":
            artifact_sha256 = arguments[arguments.index("--completion-platform-transcript-verified-sha256") + 1]
            source = arguments[arguments.index("--completion-source") + 1]
            arguments += ["--human-decision-receipt", decision_receipt(root, task_value, "completion", artifact_sha256, source)]
    result = subprocess.run(
        [sys.executable, "-c", PROVIDER_WRAPPER, ".agent/scripts/workflowctl.py", *arguments], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode != expected:
        raise AssertionError(f"{tuple(arguments)}: expected {expected}, got {result.returncode}\n{result.stdout}")
    return result.stdout


def task(mode: str, node: int, accepted: list[int]) -> dict[str, object]:
    token_budget = {"fast": 16000, "standard": 48000, "release": 96000}[mode]
    value = json.loads((SOURCE / "state/TASK.json").read_text(encoding="utf-8"))
    value.update({
        "schema": "agent-task/v2", "title": f"{mode} fixture", "mode": mode,
        "task_generation_id":f"fixture-{mode}-{node}",
        "task_type": "maintenance", "complexity": "small" if mode == "fast" else "bounded",
        "projection": "lightweight-release" if mode == "release" else "lightweight",
        "files": 1 if mode == "fast" else 3,
        "environment": "local", "deployment_requested": False, "branch": "unversioned",
        "status": "in_progress", "selected_model":FIXTURE_MODEL, "completed_model":None,
        "risk_flags": {name: False for name in (
            "deploy", "data_risk", "cross_system", "uncertain", "security",
            "compliance", "migration", "irreversible", "external_impact",
        )},
        "phase": {2: "structuring", 3: "scope", 4: "solution", 5: "tests", 6: "implementation", 7: "acceptance", 8: "delivery"}.get(node, "idle"),
        "requirements_clarified": True, "requirement_source": "user:fixture",
        "decision_policy_version": 1,
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
    value.pop("task_archive", None)
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

def bind_empty_skill_activation(root: Path, value: dict[str, object]) -> None:
    activation,data=canonical_agentctl.build_task_skill_activation(
        str(value["task_generation_id"]),{"status":"NO_DYNAMIC_SKILLS_REQUIRED","active":[],"covered_capabilities":[]},None,{}
    )
    path=root/".agent/state/SKILL_ACTIVATION.json"; path.write_bytes(data); value["skill_activation"]=activation



def install_task(root: Path, value: dict[str, object]) -> None:
    # This low-level fixture bypasses agentctl start, so reproduce its exact
    # active model binding across config, ledger and TASK.
    config_path=root / ".agent/config.json"; config=json.loads(config_path.read_text(encoding="utf-8"))
    config["agent_control"]["default_model"]=FIXTURE_MODEL; write_json(config_path,config)
    agents_path=root / ".agent/state/agents.json"; prior_agents_data=agents_path.read_bytes(); agents=json.loads(prior_agents_data)
    agents["default_model"]=FIXTURE_MODEL
    agents["token_accounting"]={"schema":"agent-child-token-accounting/v1","token_budget":int(value["token_budget"]),"settled_tokens":0}
    if isinstance(agents.get("revision"),int):
        agents["revision"]+=1; agents["prev_sha256"]=hashlib.sha256(prior_agents_data).hexdigest()
        agents_data=(json.dumps(agents,ensure_ascii=False,indent=2)+"\n").encode(); agents_path.write_bytes(agents_data)
        chain_path=root / ".agent/state/agents-chain.jsonl"
        with chain_path.open("a",encoding="utf-8") as handle:
            handle.write(json.dumps({"revision":agents["revision"],"prev_sha256":agents["prev_sha256"],"file_sha256":hashlib.sha256(agents_data).hexdigest()},sort_keys=True,separators=(",",":"))+"\n")
    else:
        write_json(agents_path,agents)
    value["selected_model"]=FIXTURE_MODEL; value["completed_model"]=None
    bind_empty_skill_activation(root,value)
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
    requirement_decision = decision_receipt(
        root, value, "requirement", str(value["requirement_contract_sha256"]),
    )
    value["gate_approvals"] = {
        **value.get("gate_approvals", {}),
        "requirement": {
            "source": "user:fixture", "artifact_sha256": value["requirement_contract_sha256"],
            "decision_receipt": provider_record(root, requirement_decision),
        },
    }
    write_json(root / ".agent/state/TASK.json", value)
    stage(root, value)


def implementation(root: Path, mode: str, preserve_runtime: bool = False) -> str:
    task_value = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    projected = mode == "fast" or (
        mode != "release" and task_value.get("task_type") in {"governance", "documentation", "maintenance"}
    )
    (root / "change.txt").write_text("change", encoding="utf-8")
    (root / "check.log").write_text("VERDICT PASS P0=0 P1=0 P2=0\nfixture review report\n", encoding="utf-8")
    if not preserve_runtime:
        write_json(root / ".agent/state/runtime.json", {
            "schema": "agent-runtime/v2",
            "baseline": {"source": "user:fixture", "captured_at": "2026-07-17T00:00:00+00:00", "project_processes": []},
            "processes": [], "docker_projects": [], "ports": [],
        })
    relative=".agent/state/artifacts/06-implementation.json"
    change=receipt(root,"change.txt")
    write_json(root / relative, {
        "schema": "agent-node-implementation/v3", "mode": mode, "status": "verified",
        "requirement_contract_sha256": task_value["requirement_contract_sha256"],
        "implementer_agent_id": "implementer" if mode == "release" else None,
        "projection": [2, 3, 4, 5, 6] if projected else [6],
        "changes":[change],"candidate_snapshot":[{**change,"mode":420}],
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
            "exit_code": 0, "outcome": "completed", "cleanup": "passed",
            "execution_boundary": dict(TEST_EXECUTION_BOUNDARY), "output": output_receipt,
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
            "root_task_id": "workflow-release-fixture", "role_type": role_type, "model": FIXTURE_MODEL, "fork_turns": 0,
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
                        "redispatch_count": 0, "model": FIXTURE_MODEL, "fork_turns": 0,
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
            "model": FIXTURE_MODEL, "fork_turns": 0, "started_at": now, "deadline_at": deadline,
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
            "model": FIXTURE_MODEL, "fork_turns": 0, "context_strategy": "long-window-capsule",
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
        "platform_limit": 4, "default_model": FIXTURE_MODEL,
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
    # The disposable runtime tests retain process-delta coverage on hosts that
    # do not install lsof by exposing only processes whose command names this
    # fixture root. agentctl still resolves and validates each PID itself.
    test_bin = root / ".test-bin"
    test_bin.mkdir()
    lsof_shim = test_bin / "lsof"
    lsof_shim.write_text("""#!/usr/bin/env python3
import os, subprocess
root = os.getcwd()
probe = subprocess.run(
    ["ps", "-axo", "pid=,ppid=,pgid=,comm=,args="], text=True,
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
)
for line in probe.stdout.splitlines():
    parts = line.strip().split(None, 4)
    if len(parts) != 5 or root not in parts[4]:
        continue
    pid, ppid, pgid, command, _ = parts
    print(f"p{pid}\nR{ppid}\ng{pgid}\nc{command}\nn{root}")
""", encoding="utf-8")
    lsof_shim.chmod(0o755)
    os.environ["PATH"] = str(test_bin) + os.pathsep + os.environ.get("PATH", "")
    shutil.copytree(SOURCE, root / ".agent")
    (root / "AGENTS.md").write_text("fixture", encoding="utf-8")
    # Isolate state-machine tests from context/runtime implementations, which have their own suites.
    pristine_agentctl = (root / ".agent/scripts/agentctl.py").read_bytes()
    (root / ".agent/scripts/contextctl.py").write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")
    (root / ".agent/scripts/agentctl.py").write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")
    (root / ".agent/scripts/contexttx.py").write_text(
        "from pathlib import Path\nimport datetime,hashlib,json\nclass contextctl:\n @staticmethod\n def invariant_sha256(value): return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()\n @staticmethod\n def hard_repair_interval(task):\n  ledger=task.get('rollback_ledger'); failures=task.get('failure_ledger'); receipts=[]\n  if not isinstance(ledger,list) or not ledger or not isinstance(failures,dict): return None\n  for item in reversed(ledger):\n   if not isinstance(item,dict): break\n   start=item.get('to'); end=item.get('from'); count=failures.get(item.get('signature'))\n   if not isinstance(start,int) or isinstance(start,bool) or not isinstance(end,int) or isinstance(end,bool) or not isinstance(count,int) or isinstance(count,bool) or not 0<count<3: break\n   if receipts and start!=receipts[-1]['from']: break\n   receipts.append(item)\n  return (receipts[0]['to'],receipts[-1]['from']) if receipts else None\n @staticmethod\n def bounded_hard_repair(task):\n  interval=contextctl.hard_repair_interval(task); current=task.get('current_node')\n  return task.get('status')=='in_progress' and isinstance(current,int) and not isinstance(current,bool) and interval is not None and interval[0]<=current<=interval[1]\n @staticmethod\n def resume_next_action(task,budget_state):\n  terminal=task.get('status')=='accepted' and task.get('current_node')=='idle'; closure=task.get('status')=='ready_to_complete' and task.get('current_node')==7 and task.get('accepted_nodes')==list(range(8))\n  if terminal and budget_state in {'must_compact','hard_blocked'}: return 'before starting another requirement, establish a verified host compaction or select an authorized higher-budget mode'\n  if budget_state=='hard_blocked' and not closure and not contextctl.bounded_hard_repair(task): return 'use rollback, return-node, cleanup or an explicit human decision; do not continue or expand scope'\n  return task.get('next_action')\n @staticmethod\n def resume_contract(task,snapshot_sha256,budget_state=None):\n  state=str(budget_state or task.get('budget_state') or 'hard_blocked'); status=task.get('status'); current=task.get('current_node'); terminal=status=='accepted' and current=='idle'; closure=status=='ready_to_complete' and current==7 and task.get('accepted_nodes')==list(range(8)); repair=contextctl.bounded_hard_repair(task)\n  action='complete' if terminal else ('waiting_human' if status in {'idle','waiting_human'} or state=='hard_blocked' and not closure and not repair else 'continue')\n  return {'schema':'agent-context-resume/v1','task_status':status,'current_node':current,'next_action':contextctl.resume_next_action(task,state),'budget_state':state,'terminal':terminal,'resume_action':action,'task_invariant_sha256':snapshot_sha256}\ndef transition_journal_status():\n p=Path('.agent/state/.context-transition-journal.json')\n if not p.is_file(): return None\n try: value=json.loads(p.read_text(encoding='utf-8'))\n except Exception: return {'schema':'agent-context-transition-journal-status/v1','state':'malformed'}\n return {'schema':'agent-context-transition-journal-status/v1','state':value.get('state','interrupted'),'recovery':value.get('recovery','')}\ndef transition_task(before,after,**kwargs):\n task_path=Path('.agent/state/TASK.json'); context_path=Path('.agent/state/CONTEXT.json')\n effects=[(Path(path),data) for path,data in (kwargs.get('side_effects') or [])]\n backups={task_path:task_path.read_bytes() if task_path.is_file() else None,context_path:context_path.read_bytes() if context_path.is_file() else None}\n for path,_ in effects: backups[path]=path.read_bytes() if path.is_file() else None\n try:\n  for path,data in effects: path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data)\n  task_path.write_text(json.dumps(after,ensure_ascii=False,indent=2)+'\\n',encoding='utf-8')\n except BaseException:\n  for path,data in backups.items():\n   if data is None: path.unlink(missing_ok=True)\n   else: path.write_bytes(data)\n  raise\n invariant=contextctl.invariant_sha256(after); observed=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(); sequence=1\n context={'schema':'agent-context/v2','task_invariant_sha256':invariant,'resume':contextctl.resume_contract(after,invariant,after.get('budget_state')),'checkpoint':{'sequence':sequence,'updated_at':observed,'transition_authorization':{'mutator':kwargs.get('mutator'),'operation':kwargs.get('operation')}},'usage_freshness':{'schema':'agent-context-usage/v1','checkpoint_sequence':sequence,'task_invariant_sha256':invariant,'coverage':'through-current-checkpoint','source':'explicit-estimate','estimated_tokens':1000,'observed_at':observed}}\n context_path.write_text(json.dumps(context,ensure_ascii=False,indent=2)+'\\n',encoding='utf-8')\n",
        encoding="utf-8",
    )
    with (root / ".agent/scripts/contexttx.py").open("a", encoding="utf-8") as handle:
        handle.write("""
import fcntl
TASK_LOCK=Path('.agent/state/.task.lock')
_transition_task_unlocked=transition_task
def transition_task(before,after,**kwargs):
 TASK_LOCK.parent.mkdir(parents=True,exist_ok=True); TASK_LOCK.touch(exist_ok=True)
 with TASK_LOCK.open('r+') as lock:
  fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
  task_path=Path('.agent/state/TASK.json'); observed=json.loads(task_path.read_text(encoding='utf-8'))
  if json.dumps(observed,sort_keys=True,separators=(',',':'))!=json.dumps(before,sort_keys=True,separators=(',',':')): raise SystemExit('canonical TASK changed before the authorized transaction acquired its lock')
  return _transition_task_unlocked(before,after,**kwargs)
""")
    stub_contract = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys;sys.path.insert(0,'.agent/scripts');import contexttx;"
            "required=('invariant_sha256','hard_repair_interval','bounded_hard_repair','resume_next_action','resume_contract');"
            "assert all(hasattr(contexttx.contextctl,name) for name in required),required;"
            "assert hasattr(contexttx,'TASK_LOCK') and hasattr(contexttx,'transition_task')",
        ],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if stub_contract.returncode:
        raise AssertionError(
            "state-machine contexttx stub drifted from workflowctl's routed interface:\n"
            + stub_contract.stdout
        )
    config = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))
    config["agent_control"]["default_model"] = FIXTURE_MODEL
    agents_path = root / ".agent/state/agents.json"
    agents_state = json.loads(agents_path.read_text(encoding="utf-8"))
    agents_state["default_model"] = FIXTURE_MODEL
    write_json(agents_path, agents_state)
    task_path=root/".agent/state/TASK.json"; fixture_task=json.loads(task_path.read_text(encoding="utf-8"))
    fixture_task["selected_model"]=FIXTURE_MODEL; fixture_task["completed_model"]=None; write_json(task_path,fixture_task)
    # The budget-calibration workstream is mid-migration: the installed
    # agentctl validator still requires the pre-rename increment key and the
    # pre-calibration margin, so pin both in the disposable fixture config.
    config["context"]["automatic_transition_token_increment"] = {"fast": 150, "standard": 300, "release": 500}
    config["agent_control"]["child_system_tool_margin_tokens"] = 1000
    platform_provider_dir = Path(tempfile.mkdtemp(prefix="workflow-platform-provider-"))
    platform_provider = platform_provider_dir / "verify-platform.py"
    platform_provider.write_text("""#!/usr/bin/env python3
import datetime as dt, hashlib, json, pathlib, sys
snapshot = pathlib.Path(sys.argv[sys.argv.index('--snapshot') + 1]); raw=snapshot.read_bytes(); value=json.loads(raw)
if '--ledger-reset-challenge' not in sys.argv:
    print('VERIFIED PLATFORM SNAPSHOT sha256=' + hashlib.sha256(raw).hexdigest()); raise SystemExit(0)
def arg(name): return sys.argv[sys.argv.index(name)+1]
proof={'schema':'agent-ledger-reset-proof/v1','nonce':arg('--ledger-reset-challenge'),'authority':'provider-signed-platform-observer',
       'status':'approved-empty-platform','observed_at':dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
       'project_identity_sha256':arg('--project-identity-sha256'),'task_generation_sha256':arg('--task-generation-sha256'),
       'task_generation_id':arg('--task-generation-id'),'legacy_ledger_sha256':arg('--legacy-ledger-sha256'),
       'legacy_ledger_bytes':int(arg('--legacy-ledger-bytes')),'platform_snapshot_sha256':arg('--platform-snapshot-sha256'),
       'platform_observed_at':value['observed_at']}
print(json.dumps(proof,sort_keys=True,separators=(',',':')))
""", encoding="utf-8")
    platform_provider.chmod(0o755)
    platform_test_site = root / ".agent/test-site"
    platform_test_site.mkdir()
    (platform_test_site / "sitecustomize.py").write_text(
        "import os,sys\nfrom pathlib import Path\n"
        "sys.path.insert(0,str(Path.cwd()/'.agent/scripts'))\n"
        "import humandecision\n_original=humandecision.adapter_path\n_original_metadata=humandecision.verify_adapter_metadata\n"
        "def _fixture(root,raw,*args,**kwargs):\n"
        " return Path(raw).resolve() if raw==os.environ.get('AGENT_TEST_PLATFORM_ADAPTER') else _original(root,raw,*args,**kwargs)\n"
        "def _metadata(path,*args,**kwargs):\n"
        " return None if str(path.resolve())==os.environ.get('AGENT_TEST_PLATFORM_ADAPTER') else _original_metadata(path,*args,**kwargs)\n"
        "humandecision.adapter_path=_fixture\nhumandecision.verify_adapter_metadata=_metadata\n" + PROVIDER_SITE_PATCH,
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

    # Policy-v2 and caller-local approvals are advisory only. Even at an active
    # acceptance gate they must fail without mutating TASK.
    local = task("standard", 6, list(range(6)))
    install_task(root, local)
    local_impl = implementation(root, "standard")
    run(root, "advance", "--node", "6", "--artifact", local_impl)
    local = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    local_accept = acceptance(root, "standard", local)
    local_accept_digest = digest(root / local_accept)
    run(root, "submit-gate", "--gate", "acceptance", "--artifact", local_accept)
    local = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    local["decision_policy_version"] = 2
    local["gate_approvals"]["requirement"] = {
        "source": "user:fixture", "artifact_sha256": local["requirement_contract_sha256"],
        "assurance": "explicit-user-message;local-advisory;not-authoritative",
    }
    write_json(root / ".agent/state/TASK.json", local)
    stage(root, local)
    before_local_gate = (root / ".agent/state/TASK.json").read_bytes()
    run(
        root, "approve-gate", "--gate", "acceptance", "--source", "user:fixture",
        "--artifact-sha256", local_accept_digest, expected=1,
    )
    if (root / ".agent/state/TASK.json").read_bytes() != before_local_gate:
        raise AssertionError("rejected local gate approval mutated workflow state")

    # Stable issue identity ignores mutable prose; a second early failure never jumps forward to node 4.
    early = task("standard", 3, [0, 1, 2])
    early["failure_ledger"] = {hashlib.sha256(b"ISSUE-1|solution").hexdigest(): 1}
    install_task(root, early)
    run(root, "return-node", "--from-node", "3", "--to", "2", "--issue-id", "ISSUE-1",
        "--cause-category", "solution", "--subtask", "x", "--root-cause", "changed prose", "--change", "retry")
    early = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    if early["current_node"] != 2 or list(early["failure_ledger"].values()) != [2]:
        raise AssertionError("stable second-failure or early-node rule failed")

    # A second late failure on standard+lightweight must return to node 2.
    # That route has no node-4 solution template and can only rebuild nodes
    # 2-6 through its projected node-6 implementation receipt.
    lightweight_late = task("standard", 7, list(range(7)))
    lightweight_late["projection"] = "lightweight"
    lightweight_signature = hashlib.sha256(b"ISSUE-LIGHTWEIGHT|implementation").hexdigest()
    lightweight_late["failure_ledger"] = {lightweight_signature: 1}
    install_task(root, lightweight_late)
    run(root, "return-node", "--from-node", "7", "--to", "6",
        "--issue-id", "ISSUE-LIGHTWEIGHT", "--cause-category", "implementation",
        "--subtask", "x", "--root-cause", "same projected defect", "--change", "retry")
    lightweight_late = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    if (
        lightweight_late["current_node"] != 2
        or lightweight_late["accepted_nodes"] != [0, 1]
        or lightweight_late["rollback_ledger"][-1]["to"] != 2
    ):
        raise AssertionError("standard lightweight second failure did not return to its rebuildable node")

    # Three-strike escalation blocks progression until a bound human decision exists.
    strikes = task("standard", 5, [0, 1, 2, 3, 4])
    install_task(root, strikes)
    for from_node, to_node in ((5, 4), (4, 3), (3, 2)):
        run(root, "return-node", "--from-node", str(from_node), "--to", str(to_node),
            "--issue-id", "ISSUE-STRIKE", "--cause-category", "implementation",
            "--subtask", "x", "--root-cause", "same defect", "--change", "retry")
    strikes = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    if strikes["status"] != "waiting_human" or "human decision required" not in strikes["next_action"]:
        raise AssertionError("third same-cause return did not escalate to a human decision")
    blocked = run(root, "advance", "--node", "2", "--artifact", ".agent/state/REQUIREMENT_CONTRACT.md", expected=1)
    if "resolve-failure" not in blocked:
        raise AssertionError("three-strike advance was not blocked by the escalation gate")
    provider_strikes = (root / ".agent/state/TASK.json").read_bytes()
    local_strikes = json.loads(provider_strikes)
    local_strikes["decision_policy_version"] = 2
    write_json(root / ".agent/state/TASK.json", local_strikes)
    stage(root, local_strikes)
    before_local_resolution = (root / ".agent/state/TASK.json").read_bytes()
    run(root, "resolve-failure", "--source", "user:fixture", expected=1)
    if (root / ".agent/state/TASK.json").read_bytes() != before_local_resolution:
        raise AssertionError("rejected local failure resolution mutated workflow state")
    (root / ".agent/state/TASK.json").write_bytes(provider_strikes)
    stage(root, json.loads(provider_strikes))
    run(root, "resolve-failure", "--source", "user:fixture")
    resolved = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    if "failure-escalation" not in resolved.get("gate_approvals", {}):
        raise AssertionError("resolve-failure did not record the escalation decision")
    structured_path = root / "structured-requirement.md"
    structured_path.write_text("structured requirement", encoding="utf-8")
    bind_node_template(root, "structured-requirement", structured_path.name)
    run(root, "advance", "--node", "2", "--artifact", structured_path.name)
    cleared = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    if cleared["status"] != "in_progress" or "failure-escalation" in cleared.get("gate_approvals", {}):
        raise AssertionError("successful advance did not consume the escalation decision")

    # A failing stage side effect rolls the whole transition back instead of
    # stranding a committed TASK with a stale stage index.
    rollback_fixture = task("standard", 2, [0, 1])
    install_task(root, rollback_fixture)
    rollback_impl = implementation(root, "standard")
    stage_path = root / ".agent/state/STAGE_INDEX.md"
    stage_bytes = stage_path.read_bytes()
    stage_path.unlink()
    stage_path.mkdir()
    before_rollback = (root / ".agent/state/TASK.json").read_bytes()
    try:
        run(root, "advance", "--node", "6", "--artifact", rollback_impl, expected=1)
    finally:
        stage_path.rmdir()
        stage_path.write_bytes(stage_bytes)
    if (root / ".agent/state/TASK.json").read_bytes() != before_rollback:
        raise AssertionError("failed stage side effect stranded a committed transition")

    # Rollback archives consolidate into a single bounded snapshot at the
    # configured depth while staying fully verifiable.
    depth_config_bytes = (root / ".agent/config.json").read_bytes()
    depth_config = json.loads(depth_config_bytes)
    depth_config["context"]["max_rollback_entries"] = 2
    write_json(root / ".agent/config.json", depth_config)
    archive_task = task("standard", 3, [0, 1, 2])
    install_task(root, archive_task)
    for cycle in range(4):
        current = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        additions = 3 - len(current.get("rollback_ledger", []))
        if additions < 1:
            raise AssertionError("rollback depth fixture lost its hot ledger")
        current["rollback_ledger"] = current.get("rollback_ledger", []) + [
            {
                "from": 3, "to": 2, "issue_id": f"ISSUE-DEPTH-{cycle}-{index}", "cause_category": "solution",
                "subtask": "x", "root_cause": "depth fixture", "change": "retry",
                "signature": hashlib.sha256(f"ISSUE-DEPTH-{cycle}-{index}|solution".encode()).hexdigest(), "count": 1,
            }
            for index in range(additions)
        ]
        write_json(root / ".agent/state/TASK.json", current)
        run(root, "compact-state")
    archived = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    archive_head = archived.get("rollback_archive", {})
    archive_value = json.loads((root / archive_head["path"]).read_text(encoding="utf-8"))
    if (
        archive_head.get("depth") != 1
        or archive_head.get("total_entries") != 4
        or archive_value.get("previous") is not None
        or len(archive_value.get("entries", [])) != 4
        or len(archived.get("rollback_ledger", [])) != 2
    ):
        raise AssertionError("rollback archive did not consolidate into a bounded snapshot")
    run(root, "validate")

    # Legacy (pre-depth) rollback heads stay valid, and compacting past them
    # derives depth by counting the chain instead of resetting it.
    legacy_task = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    legacy_head = dict(legacy_task["rollback_archive"])
    del legacy_head["depth"]
    legacy_task["rollback_archive"] = legacy_head
    write_json(root / ".agent/state/TASK.json", legacy_task)
    run(root, "validate")
    legacy_task["rollback_ledger"] = legacy_task["rollback_ledger"] + [
        {
            "from": 3, "to": 2, "issue_id": "ISSUE-DEPTH-legacy", "cause_category": "solution",
            "subtask": "x", "root_cause": "legacy depth fixture", "change": "retry",
            "signature": hashlib.sha256(b"ISSUE-DEPTH-legacy|solution").hexdigest(), "count": 1,
        }
    ]
    write_json(root / ".agent/state/TASK.json", legacy_task)
    run(root, "compact-state")
    mixed = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    mixed_head = mixed.get("rollback_archive", {})
    mixed_value = json.loads((root / mixed_head["path"]).read_text(encoding="utf-8"))
    if (
        mixed_head.get("depth") != 2
        or mixed_head.get("total_entries") != 5
        or mixed_value.get("previous") != legacy_head
    ):
        raise AssertionError("compaction past a legacy rollback head derived the wrong depth")
    run(root, "validate")
    (root / ".agent/config.json").write_bytes(depth_config_bytes)

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
    before_unavailable = (root / ".agent/state/TASK.json").read_bytes()
    run(root, "advance", "--node", "4", "--artifact", ".agent/state/artifacts/04-solution.md", expected=1)
    if (root / ".agent/state/TASK.json").read_bytes() != before_unavailable:
        raise AssertionError("rejected local solution approval mutated workflow state")

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
    release = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    solution_sha256 = release["node_artifacts"]["4"]["sha256"]
    solution_decision = decision_receipt(root, release, "solution", solution_sha256)
    release["gate_approvals"]["solution"] = {
        "source": "user:fixture", "artifact_sha256": solution_sha256,
        "decision_receipt": provider_record(root, solution_decision),
    }
    write_json(root / ".agent/state/TASK.json", release)
    # Replace the state-machine stub and capture the live outer fixture before
    # staging the task/context invariant or binding node 6 runtime evidence.
    (root / ".agent/scripts/agentctl.py").write_bytes(pristine_agentctl)
    baseline_refresh = subprocess.run([
        sys.executable, ".agent/scripts/agentctl.py", "capture-runtime-baseline",
        "--source", "user:self-test-release-baseline",
    ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if baseline_refresh.returncode:
        raise AssertionError("workflow release baseline refresh failed\n" + baseline_refresh.stdout)
    release = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    stage(root, release)
    impl = implementation(root, "release", preserve_runtime=True)
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
    context_refresh = subprocess.run([
        sys.executable, "-c",
        "import json,sys;from pathlib import Path;sys.path.insert(0,'.agent/scripts');import contexttx;"
        "p=Path('.agent/state/TASK.json');task=json.loads(p.read_text(encoding='utf-8'));"
        "contexttx.transition_task(task,task,mutator='self-test-workflow',operation='fixture-context-rebind')",
    ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if context_refresh.returncode:
        raise AssertionError("workflow release context refresh failed\n" + context_refresh.stdout)
    current_task = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    current_context = json.loads((root / ".agent/state/CONTEXT.json").read_text(encoding="utf-8"))
    expected_invariant = hashlib.sha256(json.dumps(current_task, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    usage_freshness = current_context.get("usage_freshness", {})
    if (current_context.get("task_invariant_sha256") != expected_invariant
            or usage_freshness.get("task_invariant_sha256") != expected_invariant
            or usage_freshness.get("source") != "explicit-estimate"
            or usage_freshness.get("checkpoint_sequence") != current_context.get("checkpoint", {}).get("sequence")):
        raise AssertionError("workflow release budget context was not rebound to exact task/freshness fields: "
                             + json.dumps({"expected": expected_invariant, "context": current_context.get("task_invariant_sha256"),
                                           "freshness": usage_freshness}, sort_keys=True))
    run(root, "advance", "--node", "6", "--artifact", impl)
    release = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    # The release gate now exercises the real baseline-delta process detector.
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
    settled_candidate = workflow_candidate_fingerprint(
        root, json.loads((root / ".agent/config.json").read_text(encoding="utf-8")),
    )
    # Some fresh filesystems materialize previously absent governed directory
    # topology during the first ledger fixture pass. Rebuild the disposable
    # evidence only after that topology settles, then require exact stability.
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
    if fingerprint != settled_candidate:
        raise AssertionError(
            "workflow candidate changed after its settled ledger rebuild: "
            + json.dumps({"settled": settled_candidate, "current": fingerprint}, sort_keys=True)
        )
    signed_candidate_records = workflow_candidate_records(root)
    live_path = ".agent/state/evidence/workflow-live.json"
    def refresh_release_gate(candidate_sha256: str) -> None:
        try:
            (root / live_path).unlink()
        except FileNotFoundError:
            pass
        preflight = subprocess.run([
            sys.executable, ".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py",
            "preflight", "--runner", runner_path, "--receipt", preflight_path,
            "--environment", "local", "--authority", "default", "--candidate-sha256", candidate_sha256,
        ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if preflight.returncode:
            raise AssertionError("workflow release preflight refresh failed\n" + preflight.stdout)
        receipt_value = json.loads((root / integrator_receipt_path).read_text(encoding="utf-8"))
        post_preflight_fingerprint = workflow_candidate_fingerprint(
            root, json.loads((root / ".agent/config.json").read_text(encoding="utf-8")),
        )
        if (set(receipt_value) != {"schema", "run_id", "candidate_sha256", "runner", "cases"}
                or receipt_value.get("schema") != "agent-test-receipt/v3"
                or receipt_value.get("candidate_sha256") != post_preflight_fingerprint):
            raise AssertionError("workflow integrator receipt mismatch before gate: " + json.dumps({
                "keys": sorted(receipt_value), "schema": receipt_value.get("schema"),
                "receipt_candidate": receipt_value.get("candidate_sha256"),
                "preflight_candidate": candidate_sha256,
                "post_preflight_candidate": post_preflight_fingerprint,
                "path": integrator_receipt_path,
            }, sort_keys=True))
        gate = subprocess.run([
            sys.executable, ".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py",
            "run", "--runner", runner_path, "--receipt", live_path,
            "--integrator-receipt", integrator_receipt_path, "--preflight-receipt", preflight_path,
        ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if gate.returncode:
            raise AssertionError("workflow release gate refresh failed\n" + gate.stdout)
    refresh_release_gate(fingerprint)
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

    # The adversarial matrix may consume the 15-minute preflight window. Mint
    # a new exact chain and bind the regenerated acceptance artifact immediately
    # before the final read-only verification; production freshness stays strict.
    refresh_release_gate(workflow_candidate_fingerprint(
        root, json.loads((root / ".agent/config.json").read_text(encoding="utf-8")),
    ))
    report = acceptance(root, "release", release_state, receipt(root, live_path))
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
    live_file = root / live_path; live_bytes = live_file.read_bytes(); reversed_live = json.loads(live_bytes)
    reversed_live["finished_at"] = (
        dt.datetime.fromisoformat(reversed_live["started_at"]) - dt.timedelta(seconds=1)
    ).isoformat()
    write_json(live_file, reversed_live)
    try:
        reversed_verify = subprocess.run([
            sys.executable, ".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py",
            "verify", "--runner", runner_path, "--receipt", live_path,
        ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if reversed_verify.returncode == 0 or "chronology" not in reversed_verify.stdout:
            raise AssertionError("release gate accepted reversed execution timestamps")
    finally:
        live_file.write_bytes(live_bytes)

    report_digest = digest(root / report)
    # Rebuild the signed release evidence under a disposable candidate, then
    # prove policy-v2 caller-local approval remains advisory and cannot mutate
    # the acceptance gate. Restore every candidate byte afterwards.
    v2_snapshots = {
        relative: (root / relative).read_bytes()
        for relative in (
            ".agent/config.json", ".agent/state/TASK.json", ".agent/state/CONTEXT.json",
            ".agent/state/STAGE_INDEX.md", ".agent/state/agents.json",
            preflight_path, live_path, report,
        )
    }
    v2_marker_root = root / ".agent/state/evidence/agent-terminal-markers"
    v2_markers = {path.relative_to(v2_marker_root): path.read_bytes() for path in v2_marker_root.rglob("*.json")}
    v2_config = json.loads(v2_snapshots[".agent/config.json"])
    v2_config["agent_control"]["human_decision_observer"]["allow_current_chat_local_release"] = False
    write_json(root / ".agent/config.json", v2_config)
    v2_task = json.loads(v2_snapshots[".agent/state/TASK.json"])
    v2_task["decision_policy_version"] = 1
    write_json(root / ".agent/state/TASK.json", v2_task)
    stage(root, v2_task)
    completed_ledger(root, node6_path=impl)
    v2_ledger = json.loads((root / ".agent/state/agents.json").read_text(encoding="utf-8"))
    v2_integrator = next(item for item in v2_ledger["members"] if item["role_type"] == "integrator")
    v2_replay = [
        item for item in v2_integrator["result_evidence"]
        if item["source_path"] != v2_integrator["result_report_path"]
    ]
    v2_fingerprint = workflow_candidate_fingerprint(root, v2_config)
    v2_preflight = subprocess.run([
        sys.executable, ".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py",
        "preflight", "--runner", runner_path, "--receipt", preflight_path,
        "--environment", "local", "--authority", "default", "--candidate-sha256", v2_fingerprint,
    ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if v2_preflight.returncode:
        raise AssertionError("v2 release preflight failed\n" + v2_preflight.stdout)
    v2_gate = subprocess.run([
        sys.executable, ".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py",
        "run", "--runner", runner_path, "--receipt", live_path,
        "--integrator-receipt", v2_replay[0]["path"], "--preflight-receipt", preflight_path,
    ], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if v2_gate.returncode:
        raise AssertionError("v2 release gate run failed\n" + v2_gate.stdout)
    v2_replay_value=json.loads((root/v2_replay[0]["path"]).read_text(encoding="utf-8"))
    v2_current_fingerprint=workflow_candidate_fingerprint(root,v2_config)
    if v2_replay_value.get("candidate_sha256")!=v2_current_fingerprint:
        raise AssertionError(f"v2 replay candidate drifted before acceptance: stored={v2_replay_value.get('candidate_sha256')} current={v2_current_fingerprint}")
    v2_report_path = acceptance(root, "release", v2_task, receipt(root, live_path))
    v2_after_acceptance=workflow_candidate_fingerprint(root,v2_config)
    if v2_replay_value.get("candidate_sha256")!=v2_after_acceptance:
        raise AssertionError(f"v2 replay candidate drifted while rendering acceptance: stored={v2_replay_value.get('candidate_sha256')} current={v2_after_acceptance}")
    v2_report_digest = digest(root / v2_report_path)
    run(root, "submit-gate", "--gate", "acceptance", "--artifact", v2_report_path)
    v2_report = json.loads((root / v2_report_path).read_text(encoding="utf-8"))
    local_release = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    local_release["decision_policy_version"] = 2
    local_release["gate_approvals"]["requirement"] = {
        "source": "user:fixture", "artifact_sha256": local_release["requirement_contract_sha256"],
        "assurance": "explicit-user-message;local-advisory;not-authoritative",
    }
    write_json(root / ".agent/state/TASK.json", local_release)
    stage(root, local_release)
    before_local_release = (root / ".agent/state/TASK.json").read_bytes()
    run(
        root, "approve-gate", "--gate", "acceptance", "--source", "user:fixture",
        "--artifact-sha256", v2_report_digest,
        "--platform-transcript-verified-sha256", v2_report["platform_observation_set_sha256"],
        "--supervision-debt-waiver-sha256", v2_report["supervision_debt_sha256"],
        expected=1,
    )
    if (root / ".agent/state/TASK.json").read_bytes() != before_local_release:
        raise AssertionError("rejected local release gate approval mutated workflow state")
    for relative, data in v2_snapshots.items():
        (root / relative).write_bytes(data)
    for relative, data in v2_markers.items():
        target = v2_marker_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.chmod(0o644)
        target.write_bytes(data)
    # Build a new real preflight/live chain for the final restored candidate so
    # the acceptance consumer receives current environmental authority.
    refreshed_fingerprint = workflow_candidate_fingerprint(
        root, json.loads((root / ".agent/config.json").read_text(encoding="utf-8")),
    )
    refresh_release_gate(refreshed_fingerprint)
    restored_release = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    report = acceptance(root, "release", restored_release, receipt(root, live_path))
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
    ready_candidate_sha256 = workflow_candidate_fingerprint(
        root, json.loads((root / ".agent/config.json").read_text(encoding="utf-8")),
    )
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
        refresh_node_capture(root,str(artifact_path.relative_to(root)))

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
import hashlib, json, pathlib, sys
operation=sys.argv[1]; receipt = pathlib.Path(sys.argv[sys.argv.index('--receipt') + 1]); raw=receipt.read_bytes(); value=json.loads(raw)
binding={key:value[key] for key in ('project_identity_sha256','task_generation_sha256','task_generation_id','gate','artifact_sha256','decision_id')}
binding_sha=hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest()
prefix='CONSUMED' if operation=='consume-human-decision' else 'ACTIVE'
print(prefix+' HUMAN DECISION sha256='+hashlib.sha256(raw).hexdigest()+' binding-sha256='+binding_sha+' sequence=1')
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
            "routing_profile_sha256":completion_routing_profile(policy_ready_task),
            "project_identity_sha256":decision_project_identity(root),
            "task_generation_sha256":decision_task_generation(policy_ready_task),
            "task_generation_id":"provider-completion-generation",
            "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "authority": "provider-signed-user-message",
        })
        binding={
            "project_identity_sha256":decision_project_identity(root),
            "task_generation_sha256":decision_task_generation(policy_ready_task),
            "task_generation_id":"provider-completion-generation",
            "gate":gate,"artifact_sha256":artifact_sha256,"decision_id":decision_id,
        }
        return relative, {
            "schema": "agent-human-decision/v1", "path": relative,
            "sha256": digest(root / relative), "bytes": len((root / relative).read_bytes()),
            "decision_id": decision_id, "authority": "provider-signed-user-message",
            "adapter_path": str(completion_provider.resolve()), "adapter_sha256": digest(completion_provider),
            "provider_consumption":{**binding,"binding_sha256":canonical_digest(binding),"sequence":1},
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
    solution_probe = subprocess.run(
        [sys.executable, "-c", (
            "import json,sys;sys.path.insert(0,'.agent/scripts');import workflowctl;"
            "t=json.load(open('.agent/state/TASK.json'));a=t['gate_approvals']['solution'];"
            "r=t['node_artifacts']['4'];print(workflowctl.human_gate_approval_valid(t,'solution',a,r));print(a);print(r)"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if solution_probe.returncode or not solution_probe.stdout.startswith("True\n"):
        raise AssertionError("provider solution receipt is invalid before completion:\n" + solution_probe.stdout)
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
            "completed_model", "candidate_sha256",
        }
        or completion_binding.get("schema") != "agent-completion-binding/v2"
        or completion_binding.get("completed_model") != FIXTURE_MODEL
        or completion_binding.get("candidate_sha256") != ready_candidate_sha256
        or completion_binding.get("accepted_artifact_set_sha256") != canonical_digest(completed_artifact_set)
        or completion_binding.get("release_approval_sha256") != canonical_digest(
            completed_task_value["gate_approvals"]["acceptance"],
        )
        or completion_binding.get("completion_platform_snapshot_sha256") != digest(root / completion_snapshot)
        or completion_binding.get("completion_decision_source") != "user:fixture"
        or not isinstance(completion_binding.get("completion_decision_receipt"), dict)
        or completion_binding["completion_decision_receipt"].get("authority") != "provider-signed-user-message"
        or completion_binding.get("terminal_artifact_sha256") != ready_task["node_artifacts"]["8"]["sha256"]
    ):
        raise AssertionError("completion binding did not commit the terminal artifact, final snapshot and human source")
    completion_receipt_path = root / completion_binding["completion_decision_receipt"]["path"]
    completion_receipt_bytes = completion_receipt_path.read_bytes()
    completion_receipt_path.write_bytes(completion_receipt_bytes + b"\n")
    tampered_completion_output=run(root,"route-resume",expected=1)
    try: tampered_completion_route=json.loads(tampered_completion_output)
    except json.JSONDecodeError as error: raise AssertionError(f"tampered completion route emitted invalid JSON: {tampered_completion_output!r}") from error
    if tampered_completion_route["terminal"] is not False:
        raise AssertionError("release checkpoint ignored a tampered provider completion receipt")
    completion_receipt_path.write_bytes(completion_receipt_bytes)
    completed_route = json.loads(run(root, "route-resume"))
    if completed_route["terminal"] is not True or completed_route["action"] != "complete":
        raise AssertionError("legal complete-task checkpoint was not recognized as terminal")

    # Every historical local release approval shape is advisory-only. Probe
    # both human_gate_approval_valid and the node-7 release validator to keep
    # policy 0/2, partial, forged and malformed records fail-closed.
    approval_probe = subprocess.run(
        [sys.executable, "-c", """
import json, sys
sys.path.insert(0, '.agent/scripts')
import humandecision, workflowctl

task = {
    'decision_policy_version': 2, 'environment': 'local', 'mode': 'release',
    'deployment_requested': False,
    'risk_flags': {name: False for name in ('deploy', 'irreversible', 'external_impact')},
    'task_type': 'governance', 'complexity': 'small', 'files': 1, 'branch': 'unversioned',
}
artifact = 'a' * 64
record = {'path': 'x.json', 'sha256': artifact, 'bytes': 1}
approval = humandecision.local_approval('user:fixture', artifact, task)
approval.update({
    'platform_transcript_verified_sha256': 'b' * 64,
    'supervision_debt_waiver_sha256': 'c' * 64,
})
with open('x.json', 'w', encoding='utf-8') as handle:
    json.dump({
        'platform_observation_set_sha256': 'b' * 64,
        'supervision_debt_sha256': 'c' * 64,
    }, handle)
config_path = '.agent/config.json'
config_bytes = open(config_path, 'rb').read()
config = json.loads(config_bytes)
config['agent_control']['human_decision_observer']['allow_current_chat_local_release'] = False
for mode, environment, deployment_requested, flags in (
    ('fast', 'local', False, {}),
    ('standard', 'test', False, {'external_impact': False}),
    ('release', 'production', True, {'deploy': True}),
):
    assert humandecision.decision_policy_version(
        config, mode=mode, environment=environment,
        deployment_requested=deployment_requested, risk_flags=flags,
    ) == 1, 'decision policy selection did not stay provider-only'
config['agent_control']['human_decision_observer']['allow_current_chat_local_release'] = True
try:
    with open(config_path, 'w', encoding='utf-8') as handle:
        json.dump(config, handle)
    try:
        humandecision.decision_policy_version(
            config, mode='release', environment='local', deployment_requested=False,
        )
    except SystemExit:
        pass
    else:
        raise AssertionError('allow_current_chat_local_release=true was accepted')
    config['agent_control']['human_decision_observer']['allow_current_chat_local_release'] = False
    with open(config_path, 'w', encoding='utf-8') as handle:
        json.dump(config, handle)
    def check(value, observed=None):
        return workflowctl.human_gate_approval_valid(observed or task, 'acceptance', value, record)
    def rcheck(value, observed=None):
        return workflowctl.release_acceptance_approval_valid(observed or task, value, record)
    assert not check(approval), 'policy-v2 local 6-key release approval was accepted'
    legacy5 = {key: approval[key] for key in (
        'source', 'artifact_sha256', 'assurance',
        'platform_transcript_verified_sha256', 'supervision_debt_waiver_sha256')}
    assert not check(legacy5), 'legacy local 5-key release approval was accepted'
    legacy3 = {key: approval[key] for key in ('source', 'artifact_sha256', 'assurance')}
    assert not check(legacy3), 'legacy local 3-key release approval was accepted'
    assert not check(dict(approval, routing_profile_sha256='0' * 64)), 'forged routing profile accepted'
    partial = {key: approval[key] for key in (
        'source', 'artifact_sha256', 'assurance', 'platform_transcript_verified_sha256')}
    assert not check(partial), 'partial release commitments accepted'
    assert not check(dict(approval, supervision_debt_waiver_sha256='not-a-digest')), 'malformed release digest accepted'
    assert not check(dict(approval, unexpected='x')), 'unknown approval key accepted'
    # The node-7 layer must accept exactly the legitimately minted shapes and
    # keep rejecting everything else, with both release digests bound to the
    # accepted artifact.
    assert not rcheck(approval), 'node 7 accepted the current local release approval'
    assert not rcheck(legacy5), 'node 7 accepted the legacy local release approval'
    assert not rcheck(legacy3), 'node 7 accepted an approval without release commitments'
    assert not rcheck(partial), 'node 7 accepted partial release commitments'
    assert not rcheck(dict(approval, unexpected='x')), 'node 7 accepted an unknown approval key'
    assert not rcheck(dict(approval, platform_transcript_verified_sha256='d' * 64)), \\
        'node 7 accepted a mismatched transcript digest'
    assert not rcheck(dict(approval, supervision_debt_waiver_sha256='not-a-digest')), \\
        'node 7 accepted a malformed debt digest'
    assert not rcheck(dict(legacy5, routing_profile_sha256='0' * 64)), \\
        'node 7 accepted a forged routing profile'
    provider_task = dict(task, decision_policy_version=1)
    assert not rcheck(approval, provider_task), 'node 7 accepted a local shape under provider policy'
    legacy4 = {key: approval[key] for key in (
        'source', 'artifact_sha256',
        'platform_transcript_verified_sha256', 'supervision_debt_waiver_sha256')}
    pre_policy = dict(task, decision_policy_version=0)
    assert not rcheck(legacy4, pre_policy), 'node 7 accepted the pre-policy local shape'
    assert not rcheck(legacy5, pre_policy), 'node 7 accepted an assurance key outside the local policy'
    with open(config_path, 'w', encoding='utf-8') as handle:
        json.dump([1, 2, 3], handle)
    assert not check(approval), 'release approval stayed valid when the config could not be loaded'
    assert not rcheck(approval), 'node 7 release approval stayed valid when the config could not be loaded'
    standard = dict(task, mode='standard')
    standard_approval = humandecision.local_approval('user:fixture', artifact, standard)
    assert not check(standard_approval, standard), 'standard local approval survived an unloadable config'
finally:
    open(config_path, 'wb').write(config_bytes)
print('local approval rejection probes OK')
"""],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if approval_probe.returncode:
        raise AssertionError(f"local approval shape probes failed:\n{approval_probe.stdout}")

    # A terminal route binds the ledger and runtime: injecting an active member
    # flips route-resume back to non-terminal.
    ledger_bytes = (root / ".agent/state/agents.json").read_bytes()
    dirty_ledger = json.loads(ledger_bytes)
    dirty_ledger["members"].append({"id": "stray-active", "status": "active"})
    write_json(root / ".agent/state/agents.json", dirty_ledger)
    dirty_route = json.loads(run(root, "route-resume", expected=1))
    if dirty_route["terminal"] is not False:
        raise AssertionError(f"terminal route ignored an active ledger member: {dirty_route}")
    (root / ".agent/state/agents.json").write_bytes(ledger_bytes)
    restored_route = json.loads(run(root, "route-resume"))
    if restored_route["terminal"] is not True:
        raise AssertionError("restored ledger did not return the terminal route")

    # Archive the completed generation while its completion-v2 candidate/model
    # authority is still present. A new TASK must never be substituted before
    # historical Agent evidence is validated and reset.
    ledger_init = subprocess.run(
        [sys.executable, ".agent/skills/manage-agent-team/scripts/agentledger.py", "init",
         "--archive-existing", "--platform-snapshot", completion_snapshot],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if ledger_init.returncode:
        raise AssertionError(f"ledger archive-reset after completion failed\n{ledger_init.stdout}")

    # A standard task on the lightweight projection completes without the
    # node 4 solution gate, exactly mirroring the fast-mode shape.
    light = task("standard", 2, [0, 1])
    install_task(root, light)
    light_impl = implementation(root, "standard")
    # agentctl is pristine again at this point, so its fail-closed budget gate
    # needs a context capsule bound to the current on-disk task (template
    # binding above rewrote TASK.json).
    light = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    light_sha = hashlib.sha256(
        json.dumps(light, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    light_observed = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    write_json(root / ".agent/state/CONTEXT.json", {
        "schema": "agent-context/v2", "task_invariant_sha256": light_sha,
        "checkpoint": {"sequence": 1, "updated_at": light_observed, "transition_authorization": None},
        "usage_freshness": {
            "schema": "agent-context-usage/v1", "checkpoint_sequence": 1,
            "task_invariant_sha256": light_sha, "coverage": "through-current-checkpoint",
            "source": "explicit-estimate", "estimated_tokens": 1000, "observed_at": light_observed,
        },
    })
    light_before_advance = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    if light_before_advance.get("current_node") != 2:
        raise AssertionError(f"lightweight fixture drifted before projection: {light_before_advance.get('current_node')}")
    run(root, "advance", "--node", "6", "--artifact", light_impl)
    light = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    if light["accepted_nodes"] != list(range(7)) or light["current_node"] != 7:
        raise AssertionError("standard lightweight projection did not land at acceptance")
    run(root, "validate")
    light_accept = acceptance(root, "standard", light)
    light_digest = digest(root / light_accept)
    run(root, "submit-gate", "--gate", "acceptance", "--artifact", light_accept)
    run(root, "approve-gate", "--gate", "acceptance", "--source", "user:fixture", "--artifact-sha256", light_digest)
    run(root, "advance", "--node", "7", "--artifact", light_accept)
    # The bound projection field is part of the invariant: tampering with it
    # re-demands the full node set and fails route-resume closed.
    tampered_bytes = (root / ".agent/state/TASK.json").read_bytes()
    tampered = json.loads(tampered_bytes)
    tampered["projection"] = "full"
    write_json(root / ".agent/state/TASK.json", tampered)
    stage(root, tampered)
    tampered_route = json.loads(run(root, "route-resume", expected=1))
    if tampered_route["terminal"] is not False:
        raise AssertionError("projection field tampering did not fail closed")
    (root / ".agent/state/TASK.json").write_bytes(tampered_bytes)
    stage(root, json.loads(tampered_bytes))
    # Completion must run the exact governed controller bytes that were tested.
    # Prove cleanup ordering statically, then execute the real controller; replacing
    # agentctl during completion would now (correctly) drift the candidate binding.
    workflow_source=(root/".agent/scripts/workflowctl.py").read_text(encoding="utf-8")
    capture_source=workflow_source[workflow_source.index("def node_capture_paths"):workflow_source.index("def load_node_captures")]
    if "with os.scandir(directory)" not in capture_source or "observed>4096" not in capture_source or ".glob(" in capture_source:
        raise AssertionError("node provenance capture inventory is not streamed under an explicit bound")
    completion_source=workflow_source[workflow_source.index("def command_complete"):workflow_source.index("def state_machine_errors")]
    validate_index=completion_source.index('str(AGENT_DIR/"scripts/agentctl.py"),"validate"')
    cleanup_index=completion_source.index('str(AGENT_DIR/"scripts/agentctl.py"),"cleanup"')
    assert_index=completion_source.index('str(AGENT_DIR/"scripts/agentctl.py"),"assert-clean"')
    transition_index=completion_source.index("contexttx.transition_task")
    if not validate_index<cleanup_index<assert_index<transition_index:
        raise AssertionError("complete-task does not validate, clean, assert, then commit in order")
    run(
        root,"complete-task","--retrospective",retrospective,
        "--platform-snapshot",completion_snapshot,
    )
    light_done = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    if light_done["status"] != "accepted":
        raise AssertionError("standard lightweight task did not complete")
    light_completion_binding = light_done.get("completion_binding", {})
    if (
        light_completion_binding.get("completion_decision_source") != "not_required"
        or light_completion_binding.get("completion_decision_receipt") is not None
    ):
        raise AssertionError("non-release completion checkpoint retained a human decision receipt")
    light_route = json.loads(run(root, "route-resume"))
    if light_route["terminal"] is not True or light_route["action"] != "complete":
        raise AssertionError("completed standard lightweight task was not terminal")
    capture_dir=root/".agent/state/evidence/node-artifact-captures"; capture_backup=capture_dir.with_name("node-artifact-captures.backup")
    capture_outside=root/"capture-outside"; capture_outside.mkdir(); capture_dir.rename(capture_backup); capture_dir.symlink_to(capture_outside,target_is_directory=True)
    try:
        unsafe_capture_route=json.loads(run(root,"route-resume",expected=1))
        if unsafe_capture_route["terminal"] is not False or any(capture_outside.iterdir()):
            raise AssertionError("terminal validation followed an unsafe provenance directory symlink")
    finally:
        capture_dir.unlink(); capture_backup.rename(capture_dir); capture_outside.rmdir()
    if json.loads(run(root,"route-resume"))["terminal"] is not True:
        raise AssertionError("restored exact provenance directory did not recover terminal route")
    governed_readme=root/"AGENTS.md"; governed_readme_bytes=governed_readme.read_bytes()
    governed_readme.write_bytes(governed_readme_bytes+b"\npost-completion drift\n")
    drifted_route=json.loads(run(root,"route-resume",expected=1))
    if drifted_route["terminal"] is not False or "accepted workflow lacks its complete-task checkpoint" not in drifted_route["errors"]:
        raise AssertionError("accepted completion ignored governed candidate drift")
    governed_readme.write_bytes(governed_readme_bytes)
    restored_route=json.loads(run(root,"route-resume"))
    if restored_route["terminal"] is not True: raise AssertionError("restored exact governed candidate did not recover terminal route")
    # The standard terminal route reaches the ledger/runtime binding itself:
    # a ledger mutation that agentledger validate rejects yields a cleanup
    # cursor instead of a terminal receipt.
    light_ledger_bytes = (root / ".agent/state/agents.json").read_bytes()
    tainted_ledger = json.loads(light_ledger_bytes)
    tainted_ledger["members"].append({"id": "stray-active", "status": "active"})
    write_json(root / ".agent/state/agents.json", tainted_ledger)
    tainted_route = json.loads(run(root, "route-resume", expected=1))
    if tainted_route["terminal"] is not False or not tainted_route.get("cleanup"):
        raise AssertionError(f"terminal route ignored a tainted ledger: {tainted_route}")
    (root / ".agent/state/agents.json").write_bytes(light_ledger_bytes)
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
    combined_context["usage_freshness"] = {"estimated_tokens": 39000}
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

    # Scheduler resume receipts are single-use and degrade to a structured
    # receipt (never a bare failure) when no adapter is configured.
    scheduler_task = task("standard", 4, [0, 1, 2, 3]); scheduler_task["task_generation_id"]="provider-generation-31"
    install_task(root, scheduler_task)
    scheduler_sha = hashlib.sha256(
        json.dumps(scheduler_task, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    write_json(root / ".agent/state/CONTEXT.json", {
        "task_invariant_sha256": scheduler_sha,
        "resume": {"schema": "agent-context-resume/v1", "task_status": "in_progress", "current_node": 4,
                   "next_action": scheduler_task["next_action"], "budget_state": "ok", "terminal": False,
                   "resume_action": "continue", "task_invariant_sha256": scheduler_sha},
        "checkpoint": {"transition_authorization": None},
    })
    scheduler_cursor = canonical_digest({
        "task": scheduler_sha, "checkpoint": None, "next_action": scheduler_task["next_action"],
    })

    def scheduler_receipt(nonce: str, *, project_id: str = "provider-project-17", repository_id: str = "provider-repository-23", generation_id: str = "provider-generation-31") -> str:
        relative = f".agent/state/evidence/scheduler-resume-{nonce}.json"
        write_json(root / relative, {
            "schema": "host-scheduler-resume/v2", "resume_cursor": scheduler_cursor,
            "task_invariant_sha256": scheduler_sha,
            "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "scheduler_id": "fixture-scheduler", "nonce": nonce,
            "provider_project_id":project_id,"provider_repository_id":repository_id,
            "task_generation_id":generation_id,
        })
        return relative

    no_adapter = json.loads(run(root, "route-resume", "--scheduler-receipt", scheduler_receipt("nonce-no-adapter")))
    if no_adapter["scheduler_available"] is not False or not no_adapter.get("scheduler_error"):
        raise AssertionError("missing scheduler adapter did not degrade to a structured receipt")
    scheduler_dir = Path(tempfile.mkdtemp(prefix="workflow-scheduler-adapter-"))
    scheduler_adapter = scheduler_dir / "consume-scheduler.py"
    provider_nonce_state=scheduler_dir/"provider-consumed-nonces.json"
    scheduler_adapter.write_text(f"""#!/usr/bin/env python3
import fcntl, hashlib, json, os, pathlib, sys, tempfile, time
state=pathlib.Path({str(provider_nonce_state)!r}); lock=state.with_suffix('.lock')
receipt=pathlib.Path(sys.argv[sys.argv.index('--receipt')+1]); raw=receipt.read_bytes(); value=json.loads(raw)
descriptor=os.open(lock,os.O_RDWR|os.O_CREAT,0o600)
try:
 fcntl.flock(descriptor,fcntl.LOCK_EX)
 pause=state.parent/'pause-provider'
 if pause.exists():
  (state.parent/'provider-entered').write_text('entered\\n')
  deadline=time.monotonic()+10
  while not (state.parent/'release-provider').exists():
   if time.monotonic()>=deadline: raise SystemExit(13)
   time.sleep(0.01)
 current=json.loads(state.read_text()) if state.exists() else {{'sequence':0,'keys':[]}}
 if (value['provider_project_id'],value['provider_repository_id'],value['task_generation_id'])!=('provider-project-17','provider-repository-23','provider-generation-31'): raise SystemExit(14)
 binding={{key:value[key] for key in ('provider_project_id','provider_repository_id','task_generation_id','scheduler_id','nonce')}}
 binding_sha=hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if binding_sha in current['keys']: raise SystemExit(12)
 current['sequence']+=1; current['keys'].append(binding_sha)
 temporary_descriptor,temporary=tempfile.mkstemp(prefix='.provider-nonces-',dir=state.parent)
 with os.fdopen(temporary_descriptor,'w') as handle:
  json.dump(current,handle,sort_keys=True); handle.flush(); os.fsync(handle.fileno())
 os.replace(temporary,state)
 directory=os.open(state.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)); os.fsync(directory); os.close(directory)
finally: os.close(descriptor)
print('CONSUMED SCHEDULER RESUME sha256='+hashlib.sha256(raw).hexdigest()+' binding-sha256='+binding_sha+' sequence='+str(current['sequence']))
""", encoding="utf-8")
    scheduler_adapter.chmod(0o755)
    os.environ["AGENT_TEST_PLATFORM_ADAPTER"] = str(scheduler_adapter.resolve())
    scheduler_config = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))
    scheduler_config["agent_control"]["scheduler"]["signed_adapter"] = str(scheduler_adapter.resolve())
    scheduler_config["agent_control"]["scheduler"]["provider_project_id"]="provider-project-17"
    scheduler_config["agent_control"]["scheduler"]["provider_repository_id"]="provider-repository-23"
    write_json(root / ".agent/config.json", scheduler_config)
    for bad_receipt in (
        scheduler_receipt("nonce-wrong-project",project_id="other-provider-project"),
        scheduler_receipt("nonce-wrong-generation",generation_id="other-task-generation"),
    ):
        provider_before=provider_nonce_state.read_bytes() if provider_nonce_state.exists() else None
        rejected=json.loads(run(root,"route-resume","--scheduler-receipt",bad_receipt))
        provider_after=provider_nonce_state.read_bytes() if provider_nonce_state.exists() else None
        if (rejected["scheduler_available"] is not False
                or "project/repository/task generation identities" not in str(rejected.get("scheduler_error"))
                or provider_after!=provider_before):
            raise AssertionError("scheduler did not locally reject a receipt for another trusted identity before provider consumption")
    first_receipt = scheduler_receipt("nonce-first")
    nonce_registry=root/".agent/state/.scheduler-receipt-nonces.json"
    registry_before_first=nonce_registry.read_bytes()
    resumed = json.loads(run(root, "route-resume", "--scheduler-receipt", first_receipt))
    if resumed["scheduler_available"] is not True or resumed["action"] != "continue":
        raise AssertionError(f"verified scheduler receipt did not resume the workflow: {resumed}")
    if not (root / ".agent/state/.scheduler-receipt-nonces.json").is_file():
        raise AssertionError("verified scheduler receipt did not consume its nonce")
    nonce_registry_bytes=nonce_registry.read_bytes()
    nonce_registry.write_bytes(registry_before_first); nonce_registry.chmod(0o600)
    rollback_replay=json.loads(run(root,"route-resume","--scheduler-receipt",first_receipt))
    if (rollback_replay["scheduler_available"] is not False
            or "atomically consume" not in str(rollback_replay.get("scheduler_error"))):
        raise AssertionError("rollback of the local registry replayed a provider-consumed nonce")
    nonce_registry.write_bytes(nonce_registry_bytes); nonce_registry.chmod(0o600)
    replayed = json.loads(run(root, "route-resume", "--scheduler-receipt", first_receipt))
    if replayed["scheduler_available"] is not False or "nonce" not in str(replayed.get("scheduler_error")):
        raise AssertionError("replayed scheduler receipt nonce was not rejected")
    nonce_registry.unlink()
    missing_registry=json.loads(run(root,"route-resume","--scheduler-receipt",scheduler_receipt("nonce-after-delete")))
    if missing_registry["scheduler_available"] is not False or "registry is missing" not in str(missing_registry.get("scheduler_error")):
        raise AssertionError("deleted scheduler nonce registry reset replay protection")
    nonce_registry.write_bytes(nonce_registry_bytes); nonce_registry.chmod(0o600)
    nonce_registry.write_text('{"schema":"agent-scheduler-receipt-nonces/v1","nonces":{"nonce-first":"invalid"}}\n',encoding="utf-8")
    malformed_registry=json.loads(run(root,"route-resume","--scheduler-receipt",scheduler_receipt("nonce-after-corruption")))
    if malformed_registry["scheduler_available"] is not False or "invalid expiry" not in str(malformed_registry.get("scheduler_error")):
        raise AssertionError("corrupt scheduler nonce registry reset replay protection")
    nonce_registry.write_bytes(nonce_registry_bytes); nonce_registry.chmod(0o600)
    nonce_lock=root/".agent/state/.scheduler-receipt-nonces.lock"
    if nonce_lock.exists() or nonce_lock.is_symlink(): nonce_lock.unlink()
    lock_target=root/"unsafe-scheduler-lock-target"; lock_target.write_text("unchanged\n",encoding="utf-8")
    nonce_lock.symlink_to(lock_target)
    unsafe_lock=json.loads(run(root,"route-resume","--scheduler-receipt",scheduler_receipt("nonce-unsafe-lock")))
    if (unsafe_lock["scheduler_available"] is not False or "lock is missing or unsafe" not in str(unsafe_lock.get("scheduler_error"))
            or lock_target.read_text(encoding="utf-8")!="unchanged\n"):
        raise AssertionError("scheduler nonce lock followed an unsafe symlink")
    nonce_lock.unlink(); lock_target.unlink()
    # Two concurrent route-resume processes race on the same receipt: the
    # provider's durable monotonic store lets exactly one consume it; the local
    # registry remains only a defense-in-depth audit cache.
    race_receipt = scheduler_receipt("nonce-race")
    racers = [
        subprocess.Popen(
            [sys.executable, ".agent/scripts/workflowctl.py", "route-resume",
             "--scheduler-receipt", race_receipt],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        for _ in range(2)
    ]
    race_results = [json.loads(process.communicate()[0]) for process in racers]
    race_winners = [item for item in race_results if item.get("scheduler_available") is True]
    race_losers = [item for item in race_results if item.get("scheduler_available") is not True]
    if (
        len(race_winners) != 1 or len(race_losers) != 1
        or not any(fragment in str(race_losers[0].get("scheduler_error")) for fragment in ("nonce", "atomically consume"))
    ):
        raise AssertionError(f"concurrent scheduler resumes did not consume the nonce exactly once: {race_results}")

    # Hold the protected provider inside route-resume, then start a canonical
    # TASK/CONTEXT transition.  The transition must reach transition_task but
    # remain blocked until the provider nonce is consumed and the route receipt
    # is fully emitted under the shared .task.lock.
    pause_provider=scheduler_dir/"pause-provider"; pause_provider.write_text("pause\n",encoding="utf-8")
    provider_entered=scheduler_dir/"provider-entered"; release_provider=scheduler_dir/"release-provider"
    linear_receipt=scheduler_receipt("nonce-lock-linearization")
    route_process=subprocess.Popen(
        [sys.executable,".agent/scripts/workflowctl.py","route-resume","--scheduler-receipt",linear_receipt],
        cwd=root,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
    )
    deadline=time.monotonic()+5
    while not provider_entered.exists() and route_process.poll() is None and time.monotonic()<deadline: time.sleep(0.01)
    if not provider_entered.exists():
        output=route_process.communicate(timeout=5)[0]
        raise AssertionError(f"scheduler provider did not enter the linearization fixture: {output}")
    transition_marker=root/".agent/state/evidence/lock-linearization-transition-entered"
    transition_code=(
        "import copy,json,sys;from pathlib import Path;sys.path.insert(0,'.agent/scripts');import contexttx;"
        "task_path=Path('.agent/state/TASK.json');before=json.loads(task_path.read_text(encoding='utf-8'));after=copy.deepcopy(before);"
        "after['title']=str(after['title'])+' lock-linearized';"
        f"Path({str(transition_marker.relative_to(root))!r}).write_text('entered\\n',encoding='utf-8');"
        "contexttx.transition_task(before,after,mutator='fixture',operation='lock-linearization',"
        "reason='prove scheduler route lock',summary='serialized canonical transition after scheduler route')"
    )
    transition_process=subprocess.Popen(
        [sys.executable,"-c",transition_code],cwd=root,text=True,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
    )
    deadline=time.monotonic()+5
    while not transition_marker.exists() and transition_process.poll() is None and time.monotonic()<deadline: time.sleep(0.01)
    time.sleep(0.2)
    transitioned_early=transition_process.poll() is not None
    release_provider.write_text("release\n",encoding="utf-8")
    route_output=route_process.communicate(timeout=10)[0]
    transition_output=transition_process.communicate(timeout=15)[0]
    if transitioned_early:
        raise AssertionError(f"canonical transition interleaved with provider nonce consumption: {transition_output}")
    if route_process.returncode!=0:
        raise AssertionError(f"linearized scheduler route failed: {route_output}")
    linear_route=json.loads(route_output)
    if linear_route.get("scheduler_available") is not True or linear_route.get("action")!="continue":
        raise AssertionError(f"linearized scheduler route emitted the wrong receipt: {linear_route}")
    if transition_process.returncode!=0:
        raise AssertionError(f"blocked canonical transition failed after route emission: {transition_output}")
    transitioned_task=json.loads((root/".agent/state/TASK.json").read_text(encoding="utf-8"))
    if not str(transitioned_task.get("title","")).endswith(" lock-linearized"):
        raise AssertionError("canonical transition did not commit after the route released .task.lock")
    transition_marker.unlink(); pause_provider.unlink(); provider_entered.unlink(); release_provider.unlink()
    shutil.rmtree(scheduler_dir)

    # A leftover transition journal surfaces a concrete recovery cursor and
    # never lets the route report terminal.
    journal_path = root / ".agent/state/.context-transition-journal.json"
    write_json(journal_path, {"state": "interrupted"})
    journal_route = json.loads(run(root, "route-resume", expected=1))
    if (
        journal_route["terminal"] is not False
        or journal_route.get("recovery") != "python3 .agent/scripts/contextctl.py journal --restore"
    ):
        raise AssertionError("interrupted transition journal did not surface a restore cursor")
    write_json(journal_path, {"state": "committed"})
    committed_journal = json.loads(run(root, "route-resume", expected=1))
    if committed_journal.get("recovery") != "python3 .agent/scripts/contextctl.py journal --discard":
        raise AssertionError("committed transition journal did not surface a discard cursor")
    journal_path.unlink()

    # Decision-policy v1 never accepts a caller label by itself. A missing
    # receipt is rejected even when the requirement receipt is provider
    # verified; a valid-looking receipt is still unusable without the external
    # provider-owned adapter.
    provider_dir = Path(tempfile.mkdtemp(prefix="workflow-provider-adapter-"))
    provider_adapter = provider_dir / "verify-human-decision.py"
    provider_adapter.write_text("""#!/usr/bin/env python3
import hashlib, json, pathlib, sys
operation=sys.argv[1]; receipt = pathlib.Path(sys.argv[sys.argv.index('--receipt') + 1]); raw=receipt.read_bytes(); value=json.loads(raw)
binding={key:value[key] for key in ('project_identity_sha256','task_generation_sha256','task_generation_id','gate','artifact_sha256','decision_id')}
binding_sha=hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest()
prefix='CONSUMED' if operation=='consume-human-decision' else 'ACTIVE'
print(prefix+' HUMAN DECISION sha256='+hashlib.sha256(raw).hexdigest()+' binding-sha256='+binding_sha+' sequence=1')
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
            "task_mode":policy_task["mode"],"routing_profile_sha256":routing_profile(policy_task),
            "project_identity_sha256":decision_project_identity(root),
            "task_generation_sha256":decision_task_generation(policy_task),
            "task_generation_id":policy_task["task_generation_id"],
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
    "model": FIXTURE_MODEL, "fork_turns": 10,
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
