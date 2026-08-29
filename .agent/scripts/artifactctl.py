#!/usr/bin/env python3
"""Mode-aware semantic validators for executable node receipts."""

from pathlib import Path
import argparse
import datetime as dt
import hashlib
import json
import re
import os
import subprocess
import stat
import sys
from typing import Dict, List, Optional

def _reject_nonfinite_json(token):
    raise json.JSONDecodeError(f"non-finite JSON number is forbidden: {token}",token,0)

def strict_json_loads(raw,**kwargs):
    return json.loads(raw,parse_constant=_reject_nonfinite_json,**kwargs)

def strict_json_dumps(value,**kwargs):
    kwargs["allow_nan"]=False
    return json.dumps(value,**kwargs)


from workflowlib import boundedio,boundedprocess
from workflowlib.state import task_projection
import testrun as supervised_test
# Keep validation bootstrap-light: migration fixtures need no acceptance runner import.
# self_test_schema_contracts.py binds this literal to blueprintacceptance.RECEIPT_SCHEMA.
ADAPTIVE_ACCEPTANCE_RECEIPT_SCHEMA = "agent-blueprint-acceptance/v4"


def root() -> Path:
    for path in (Path.cwd().resolve(), *Path.cwd().resolve().parents):
        if (path / ".agent").is_dir(): return path
    raise SystemExit(".agent directory not found")


ROOT = root(); AGENT = ROOT / ".agent"; SHA = re.compile(r"[0-9a-f]{64}")
AGENT_LEDGER_TOOL = AGENT / "skills/manage-agent-team/scripts/agentledger.py"
REVIEW_LENSES = [
    "product", "architecture", "qa", "security", "operations",
    "ai-workflow-new-project-adopter",
]
DYNAMIC_STATE = {
    ".agent/state/TASK.json", ".agent/state/CONTEXT.json", ".agent/state/runtime.json",
    ".agent/state/tool-leases.json", ".agent/state/agents.json", ".agent/state/delivery.json",
}


def supervised_env() -> Dict[str, str]:
    return os.environ.copy()


def canonical_sha256(value: object) -> str:
    encoded = strict_json_dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def platform_observation_set(members: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """Expose the exact immutable observation receipts a human must compare to the orchestrator transcript."""
    return sorted(
        [
            {
                "agent_id": item.get("id"),
                "registration": item.get("registration_platform_evidence"),
                "monitors": item.get("monitor_platform_evidence"),
                "terminal": item.get("terminal_platform_evidence"),
            }
            for item in members
        ],
        key=lambda item: str(item["agent_id"]),
    )


def delivery_control_members(
    members: Dict[object, Dict[str, object]], initial_implementer_id: object,
    root_task_id: object, chain_id: object, subject: object, errors: List[str],
) -> List[Dict[str, object]]:
    implementer_attempt_ids={initial_implementer_id}; cursor=members.get(initial_implementer_id)
    while isinstance(cursor,dict) and cursor.get("redispatched_to") is not None:
        next_id=cursor.get("redispatched_to")
        if next_id in implementer_attempt_ids:
            errors.append("release implementer redispatch lineage contains a cycle")
            break
        implementer_attempt_ids.add(next_id); cursor=members.get(next_id)
    return [
        item for item in members.values()
        if item.get("root_task_id")==root_task_id and (
            item.get("id") in implementer_attempt_ids
            or (
                item.get("role_type") in {"adversarial","cross","integrator"}
                and item.get("review_chain_id")==chain_id
                and item.get("review_subject_sha256")==subject
            )
        )
    ]


def load(path: Path) -> Dict[str, object]:
    try: value = strict_json_loads(boundedio.read_text(path,label="artifact JSON"))
    except (OSError, ValueError): return {}
    return value if isinstance(value, dict) else {}


def receipt(value: object, errors: List[str], label: str) -> Optional[Path]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "bytes"}: errors.append(f"{label} receipt is invalid"); return None
    path = (ROOT / str(value["path"])).resolve()
    try: path.relative_to(ROOT)
    except ValueError: errors.append(f"{label} escapes project"); return None
    if not path.is_file() or path.is_symlink(): errors.append(f"{label} is missing"); return None
    data = boundedio.read_bytes(path,label="artifact file")
    if hashlib.sha256(data).hexdigest() != value["sha256"] or len(data) != value["bytes"]: errors.append(f"{label} evidence drifted"); return None
    return path


def selected_adapter(task: Dict[str, object], errors: List[str]):
    config = load(AGENT / "config.json"); registry = config.get("acceptance_adapters", {})
    if not isinstance(registry, dict): errors.append("acceptance adapter registry is missing"); return None
    selected = [name for name in task.get("selected_templates", []) if name in registry]
    if not selected:
        adaptive = task.get("template_route", {}).get("adaptive_project", {}) if isinstance(task.get("template_route"), dict) else {}
        digest = adaptive.get("blueprint_sha256") if isinstance(adaptive, dict) else None
        blueprint = AGENT / "project/BLUEPRINT.json"; runner = AGENT / "scripts/blueprintacceptance.py"
        if not digest or not blueprint.is_file() or blueprint.is_symlink() or not runner.is_file() or runner.is_symlink():
            errors.append("release requires one legacy adapter or a confirmed blueprint acceptance contract"); return None
        result = boundedprocess.run([sys.executable, str(AGENT / "scripts/blueprintctl.py"), "--root", str(ROOT), "check", "--require-confirmed", "--expect-design-sha256", digest],
                                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30, env=supervised_env())
        if result.returncode:
            errors.append("confirmed blueprint acceptance contract is stale"); return None
        raw = boundedio.read_bytes(blueprint,label="project blueprint")
        return "adaptive-blueprint", {"implemented": True, "runner": str(runner.relative_to(ROOT)), "receipt_schema": ADAPTIVE_ACCEPTANCE_RECEIPT_SCHEMA}, {
            "template_id": "adaptive-blueprint", "path": str(blueprint.relative_to(ROOT)),
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
        }
    if len(selected) != 1: errors.append("release selects multiple legacy acceptance adapters"); return None
    adapter_id = selected[0]; entry = registry[adapter_id]
    if not isinstance(entry, dict) or entry.get("implemented") is not True: errors.append(f"selected adapter is not implemented: {adapter_id}"); return None
    runner = (ROOT / str(entry.get("runner", ""))).resolve()
    try: runner.relative_to(ROOT)
    except ValueError: errors.append("adapter runner escapes project"); return None
    if not runner.is_file() or runner.is_symlink() or not entry.get("receipt_schema"): errors.append("adapter runner/schema is unavailable"); return None
    rendered = [item for item in task.get("rendered_artifacts", []) if isinstance(item, dict) and item.get("template_id") == adapter_id]
    if len(rendered) != 1 or receipt({key: rendered[0].get(key) for key in ("path", "sha256", "bytes")}, errors, "adapter config") is None: return None
    return adapter_id, entry, rendered[0]


def validated_agent_ledger(errors: List[str]) -> Dict[str, object]:
    """Share the complete ledger validator and reject validation-time mutation."""
    path = AGENT / "state/agents.json"
    if not path.is_file() or not AGENT_LEDGER_TOOL.is_file():
        errors.append("release reviewer ledger or validator is missing")
        return {}
    try:
        before = boundedio.read_bytes(path,label="artifact file")
        result = boundedprocess.run(
            [sys.executable, str(AGENT_LEDGER_TOOL), "validate"], cwd=str(ROOT),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30, text=True,
            env=supervised_env(),
        )
        after = boundedio.read_bytes(path,label="artifact file")
        value = strict_json_loads(after)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
        errors.append("release reviewer ledger validation failed")
        return {}
    if result.returncode or before != after or not isinstance(value, dict) or value.get("schema") != "agent-team/v9":
        errors.append(f"release reviewer ledger failed complete v8 validation: {result.stdout.strip()}")
        return {}
    return value


def timestamp(raw: object, errors: List[str], label: str) -> Optional[dt.datetime]:
    if not isinstance(raw, str):
        errors.append(f"{label} timestamp is missing")
        return None
    try:
        value = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{label} timestamp is invalid")
        return None
    if value.tzinfo is None:
        errors.append(f"{label} timestamp lacks a timezone")
        return None
    return value


def result_record(value: object, errors: List[str], label: str) -> Optional[Path]:
    if not isinstance(value, dict) or set(value) != {"source_path", "path", "sha256", "bytes"}:
        errors.append(f"{label} result evidence is invalid")
        return None
    if not isinstance(value.get("source_path"), str) or not value["source_path"]:
        errors.append(f"{label} result source is invalid")
        return None
    path = receipt({key: value.get(key) for key in ("path", "sha256", "bytes")}, errors, label)
    expected = f".agent/state/evidence/agent-result-evidence/{value.get('sha256')}.result"
    if value.get("path") != expected:
        errors.append(f"{label} is not content-addressed result evidence")
        return None
    return path


def review_report_attestation(
    member: Dict[str, object], records: List[Dict[str, object]], errors: List[str], label: str,
) -> Optional[Dict[str, object]]:
    report_path = member.get("result_report_path")
    matching = [item for item in records if item.get("source_path") == report_path]
    if not isinstance(report_path, str) or len(matching) != 1:
        errors.append(f"{label} does not bind exactly one result report")
        return None
    evidence_path = result_record(matching[0], errors, f"{label} report")
    verdict = member.get("review_verdict")
    if (
        evidence_path is None
        or not isinstance(verdict, dict)
        or set(verdict) != {"status", "p0", "p1", "p2", "report_sha256"}
        or verdict.get("status") != "PASS"
        or [verdict.get("p0"), verdict.get("p1"), verdict.get("p2")] != [0, 0, 0]
        or verdict.get("report_sha256") != matching[0].get("sha256")
    ):
        errors.append(f"{label} lacks a zero-severity reviewer-authored PASS")
        return None
    try:
        lines = boundedio.read_text(evidence_path,label="test evidence").splitlines()
    except (OSError, UnicodeDecodeError):
        errors.append(f"{label} report is not UTF-8 text")
        return None
    if not lines or lines[0] != "VERDICT PASS P0=0 P1=0 P2=0" or len(lines) < 2 or not lines[1].startswith("ATTESTATION "):
        errors.append(f"{label} report lacks canonical verdict/attestation lines")
        return None
    try:
        attestation = strict_json_loads(lines[1][len("ATTESTATION "):])
    except json.JSONDecodeError:
        errors.append(f"{label} report attestation is invalid JSON")
        return None
    required = {
        "schema", "role_type", "review_chain_id", "review_subject_sha256",
        "predecessor_result_sha256", "lenses", "clean_replays", "targeted_cases",
    }
    canonical = "ATTESTATION " + strict_json_dumps(attestation, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if (
        not isinstance(attestation, dict)
        or set(attestation) != required
        or lines[1] != canonical
        or attestation.get("schema") != "agent-review-attestation/v2"
        or attestation != member.get("review_attestation")
        or any(attestation.get(key) != member.get(key) for key in (
            "role_type", "review_chain_id", "review_subject_sha256", "predecessor_result_sha256",
        ))
    ):
        errors.append(f"{label} attestation is non-canonical or differs from the terminal member commitment")
        return None
    targeted_cases = attestation.get("targeted_cases")
    targeted_limit = load(AGENT / "config.json").get("testing", {}).get("reviewer_targeted_case_limit")
    if (
        not isinstance(targeted_limit, int) or targeted_limit < 0
        or not isinstance(targeted_cases, list) or len(targeted_cases) > targeted_limit
        or len(targeted_cases) != len(set(targeted_cases))
        or any(not isinstance(case, str) or not case or len(case) > 128 for case in targeted_cases)
        or (member.get("role_type") == "integrator" and bool(targeted_cases))
    ):
        errors.append(f"{label} targeted Case declaration exceeds the configured limit")
        return None
    return attestation


def cross_scenario_receipt(
    member: Dict[str, object], records: List[Dict[str, object]], errors: List[str],
) -> tuple[Optional[Dict[str, object]], Optional[str]]:
    reports = [item for item in records if item.get("source_path") == member.get("result_report_path")]
    report_path = result_record(reports[0], errors, "cross scenario report") if len(reports) == 1 else None
    if report_path is None:
        errors.append("cross scenario receipt lacks its marker-bound report")
        return None, None
    try:
        lines = boundedio.read_text(report_path,label="acceptance report").splitlines()
    except (OSError, UnicodeDecodeError):
        lines = []
    prefix = "SCENARIO_RECEIPT "
    if len(lines) < 3 or not lines[2].startswith(prefix):
        errors.append("cross report lacks canonical scenario receipt line")
        return None, None
    raw = lines[2][len(prefix):]
    try:
        value = strict_json_loads(raw)
    except json.JSONDecodeError:
        errors.append("cross scenario receipt is invalid JSON")
        return None, None
    required = {"schema", "review_chain_id", "review_subject_sha256", "reviewer_agent_id", "scenarios"}
    if (
        not isinstance(value, dict) or set(value) != required
        or value.get("schema") != "agent-role-scenario-receipt/v1"
        or raw != strict_json_dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        or value.get("review_chain_id") != member.get("review_chain_id")
        or value.get("review_subject_sha256") != member.get("review_subject_sha256")
        or value.get("reviewer_agent_id") != member.get("id")
    ):
        errors.append("cross scenario receipt is non-canonical or belongs to another reviewer/candidate")
        return None, None
    scenarios = value.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != len(REVIEW_LENSES):
        errors.append("cross scenario receipt must contain exactly six role scenarios")
        return None, None
    scenario_ids: List[str] = []
    for index, scenario in enumerate(scenarios):
        required_scenario = {"id", "lens", "requirement_ids", "assertions", "evidence", "result"}
        if not isinstance(scenario, dict) or set(scenario) != required_scenario:
            errors.append(f"cross scenario {index} fields are invalid")
            continue
        scenario_id = scenario.get("id")
        if not isinstance(scenario_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", scenario_id):
            errors.append(f"cross scenario {index} ID is invalid")
        else:
            scenario_ids.append(scenario_id)
        if scenario.get("lens") != REVIEW_LENSES[index] or scenario.get("result") != "passed":
            errors.append(f"cross scenario {index} lens/result is invalid")
        for field in ("requirement_ids", "assertions"):
            items = scenario.get(field)
            if (
                not isinstance(items, list) or not items or len(items) > 64
                or any(not isinstance(item, str) or not item or len(item) > 500 for item in items)
                or len(items) != len(set(items))
            ):
                errors.append(f"cross scenario {index} {field} is invalid")
        evidence = scenario.get("evidence")
        if not isinstance(evidence, list) or not evidence or len(evidence) > 32:
            errors.append(f"cross scenario {index} lacks immutable evidence")
            continue
        evidence_identities = [
            (item.get("path"), item.get("sha256")) for item in evidence if isinstance(item, dict)
        ]
        if len(evidence_identities) != len(evidence) or len(evidence_identities) != len(set(evidence_identities)):
            errors.append(f"cross scenario {index} evidence is duplicated or malformed")
        for evidence_index, record in enumerate(evidence):
            evidence_path = receipt(record, errors, f"cross scenario {index} evidence {evidence_index}")
            expected = f".agent/state/evidence/scenario-evidence/{record.get('sha256')}.evidence" if isinstance(record, dict) else ""
            if evidence_path is None or str(evidence_path.relative_to(ROOT)) != expected:
                errors.append(f"cross scenario {index} evidence {evidence_index} is not content-addressed")
    if len(scenario_ids) != len(set(scenario_ids)):
        errors.append("cross scenario IDs must be unique")
    return value, hashlib.sha256(raw.encode()).hexdigest()


def verify_test_receipt(
    path: Path, errors: List[str], label: str,
    window_start: Optional[dt.datetime], window_end: Optional[dt.datetime],
) -> Optional[str]:
    value = load(path)
    candidate_sha256 = supervised_test.candidate_fingerprint(load(AGENT / "config.json"))
    if (
        set(value) != {"schema", "run_id", "candidate_sha256", "runner", "cases"}
        or value.get("schema") != "agent-test-receipt/v3"
        or value.get("candidate_sha256") != candidate_sha256
    ):
        errors.append(f"{label} is not an agent-test-receipt/v3 for the current candidate")
        return None
    run_id = value.get("run_id")
    cases = value.get("cases")
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id) or not isinstance(cases, list) or not cases:
        errors.append(f"{label} has no valid run or cases")
        return None
    runner_path = receipt(value.get("runner"), errors, f"{label} runner")
    if runner_path is None or str(runner_path.relative_to(ROOT)) != ".agent/scripts/testrun.py":
        errors.append(f"{label} was not produced by the canonical test runner")
    case_ids: List[str] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            errors.append(f"{label} case {index} is invalid")
            continue
        if isinstance(case.get("id"), str):
            case_ids.append(case["id"])
        expected_keys = {
            "id", "run_id", "candidate_sha256", "command", "started_at", "finished_at", "exit_code",
            "outcome", "cleanup", "execution_boundary", "output", "case_sha256",
        }
        unsigned = {key: item for key, item in case.items() if key != "case_sha256"}
        expected_sha = hashlib.sha256(strict_json_dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if (
            set(case) != expected_keys
            or not isinstance(case.get("id"), str) or not case.get("id")
            or case.get("run_id") != run_id
            or case.get("candidate_sha256") != candidate_sha256
            or not isinstance(case.get("command"), list) or not case.get("command")
            or not all(isinstance(token, str) and token for token in case.get("command", []))
            or case.get("exit_code") != 0 or case.get("outcome") != "completed"
            or case.get("cleanup") != "passed"
            or case.get("execution_boundary") != supervised_test.TEST_EXECUTION_BOUNDARY
            or case.get("case_sha256") != expected_sha
        ):
            errors.append(f"{label} case {index} is not a clean completed replay")
        started_at = timestamp(case.get("started_at"), errors, f"{label} case {index} start")
        finished_at = timestamp(case.get("finished_at"), errors, f"{label} case {index} finish")
        if started_at and finished_at and finished_at < started_at:
            errors.append(f"{label} case {index} finishes before it starts")
        if started_at and finished_at and window_start and window_end:
            skew = dt.timedelta(seconds=5)
            if started_at < window_start - skew or finished_at > window_end + skew:
                errors.append(f"{label} case {index} falls outside the integrator registration/terminal window")
        receipt(case.get("output"), errors, f"{label} case {index} output")
    if len(case_ids) != len(set(case_ids)):
        errors.append(f"{label} case IDs are not unique")
    return run_id


def current_review_subject(member: Dict[str, object], task: Dict[str, object], errors: List[str]) -> None:
    subject = member.get("review_subject_sha256")
    evidence = member.get("task_payload_evidence")
    payload_path = receipt(evidence, errors, "review subject payload")
    if (
        not SHA.fullmatch(str(subject or ""))
        or member.get("task_payload_sha256") != subject
        or not isinstance(evidence, dict) or evidence.get("sha256") != subject
        or payload_path is None
    ):
        errors.append("review subject does not match its sealed payload")
        return
    payload = load(payload_path)
    inputs = payload.get("input_artifacts") if payload.get("schema") == "agent-task-payload/v2" else None
    if not isinstance(inputs, list):
        errors.append("review subject is not a sealed v2 payload")
        return
    indexed = {item.get("label"): item for item in inputs if isinstance(item, dict)}
    expected: List[Dict[str, object]] = []
    requirement = task.get("node_artifacts", {}).get("1")
    if isinstance(requirement, dict):
        expected.append(requirement)
        if requirement.get("sha256") != task.get("requirement_contract_sha256"):
            errors.append("current node 1 authority differs from the requirement contract")
    else:
        contract_path = AGENT / "state/REQUIREMENT_CONTRACT.md"
        if contract_path.is_file():
            data = boundedio.read_bytes(contract_path,label="requirement contract")
            expected.append({
                "path": ".agent/state/REQUIREMENT_CONTRACT.md",
                "sha256": task.get("requirement_contract_sha256"), "bytes": len(data),
            })
        else:
            errors.append("current review subject lacks current requirement authority")
    for node in (2, 3, 4, 5, 6):
        artifact = task.get("node_artifacts", {}).get(str(node))
        if isinstance(artifact, dict):
            expected.append(artifact)
        else:
            errors.append(f"current review subject lacks current node {node} authority")
    for index, authority in enumerate(expected):
        if receipt(authority, errors, f"current candidate authority {index}") is None:
            continue
        sealed = indexed.get(authority.get("path"))
        if (
            not isinstance(sealed, dict)
            or sealed.get("sha256") != authority.get("sha256")
            or sealed.get("bytes") != authority.get("bytes")
        ):
            errors.append(f"review subject does not contain current candidate: {authority.get('path')}")
        elif receipt({key: sealed.get(key) for key in ("path", "sha256", "bytes")}, errors, f"sealed candidate {index}") is None:
            continue


def resolved_implementer(
    ledger: Dict[str, object], initial_id: object, errors: List[str],
) -> Optional[Dict[str, object]]:
    """Resolve one bounded implementer redispatch without changing Node 6 bytes.

    Node 6 commits the initial canonical dispatch identity. If that attempt is
    platform-terminal but unsuccessful, the ledger may point to exactly one
    same-payload replacement. The replacement is the actual attestation owner.
    """
    members = [item for item in ledger.get("members", []) if isinstance(item, dict)]
    initial_matches = [item for item in members if item.get("id") == initial_id]
    if len(initial_matches) != 1:
        errors.append("release node 6 implementer root is not one unique ledger identity")
        return None
    initial = initial_matches[0]
    if initial.get("role_type") != "implementer" or initial.get("redispatch_count") != 0:
        errors.append("release node 6 implementer root is not an initial implementer dispatch")
        return None
    resolved = initial
    replacement_id = initial.get("redispatched_to")
    if initial.get("status") == "completed":
        if replacement_id is not None:
            errors.append("completed implementer cannot also claim a replacement")
            return None
    else:
        if initial.get("status") not in {"interrupted", "errored", "expired"} or not isinstance(replacement_id, str):
            errors.append("failed implementer lacks one bounded redispatch")
            return None
        replacements = [item for item in members if item.get("id") == replacement_id]
        if len(replacements) != 1:
            errors.append("implementer redispatch target is not one unique ledger identity")
            return None
        resolved = replacements[0]
        if (
            resolved.get("role_type") != "implementer"
            or resolved.get("redispatch_count") != 1
            or resolved.get("root_task_id") != initial.get("root_task_id")
            or resolved.get("task_payload_sha256") != initial.get("task_payload_sha256")
            or resolved.get("task_payload_evidence") != initial.get("task_payload_evidence")
            or resolved.get("model") != initial.get("model")
            # A replacement is a new host dispatch.  Migration 34 preserves a
            # predecessor's historical fork window for audit, but every new
            # child must use the sealed payload without parent-chat history.
            or resolved.get("fork_turns") != 0
            or resolved.get("redispatched_to") is not None
        ):
            errors.append("implementer redispatch changed identity-independent task authority")
            return None
    chain_ids = {initial.get("id"), resolved.get("id")}
    same_authority = [
        item for item in members
        if item.get("role_type") == "implementer"
        and item.get("root_task_id") == initial.get("root_task_id")
        and item.get("task_payload_sha256") == initial.get("task_payload_sha256")
    ]
    if {item.get("id") for item in same_authority} != chain_ids or len(same_authority) != len(chain_ids):
        errors.append("implementer authority contains an unbounded parallel attempt")
        return None
    if resolved.get("status") != "completed":
        errors.append("resolved implementer is not completed")
        return None
    return resolved


def accepted_node_bytes(task: Dict[str,object], node: int, fallback: Path) -> bytes:
    record=task.get("node_artifacts",{}).get(str(node),{}) if isinstance(task.get("node_artifacts"),dict) else {}
    if node in task.get("node_artifact_capture_nodes",[]) and isinstance(record,dict):
        path=AGENT/"state/evidence/node-artifact-captures"/f"{record.get('sha256')}.artifact"
    else: path=fallback
    try: return boundedio.read_bytes(path,maximum=16*1024*1024,label="accepted node snapshot")
    except RuntimeError as error: raise SystemExit(str(error)) from error


def implementation_attestation(
    member: Dict[str, object], ledger: Dict[str, object], artifact_path: Path, artifact_data: bytes,
    value: Dict[str, object], errors: List[str],
) -> Optional[Dict[str, object]]:
    records = member.get("result_evidence")
    allowed = set(member.get("allowed_evidence_paths", [])) if isinstance(member.get("allowed_evidence_paths"), list) else set()
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict) or records[0].get("source_path") not in allowed:
        errors.append("release implementer must commit exactly one envelope-allowed implementation attestation")
        return None
    evidence_path = result_record(records[0], errors, "implementer attestation")
    attestation = load(evidence_path) if evidence_path else {}
    required = {
        "schema", "agent_id", "root_task_id", "candidate_review_subject_sha256",
        "requirement_contract_sha256", "node6_artifact", "changes", "checks",
    }
    expected_artifact = {
        "path": str(artifact_path.relative_to(ROOT)),
        "sha256": hashlib.sha256(artifact_data).hexdigest(), "bytes": len(artifact_data),
    }
    if (
        set(attestation) != required
        or attestation.get("schema") != "agent-implementation-attestation/v1"
        or attestation.get("agent_id") != member.get("id")
        or attestation.get("root_task_id") != member.get("root_task_id")
        or not SHA.fullmatch(str(attestation.get("candidate_review_subject_sha256", "")))
        or attestation.get("requirement_contract_sha256") != value.get("requirement_contract_sha256")
        or attestation.get("node6_artifact") != expected_artifact
        or attestation.get("changes") != value.get("changes")
        or attestation.get("checks") != value.get("checks")
    ):
        errors.append("implementer attestation does not bind the exact node 6 candidate, changes and checks")
        return None
    marker_path = AGENT / "state/evidence/agent-terminal-markers" / str(ledger.get("epoch")) / f"{hashlib.sha256(str(member.get('id')).encode()).hexdigest()}.json"
    marker = load(marker_path)
    if (
        marker.get("schema") != "agent-terminal-marker/v6"
        or marker.get("agent_id") != member.get("id")
        or marker.get("terminal_status") != "completed"
        or marker.get("task_payload_sha256") != member.get("task_payload_sha256")
        or marker.get("handoff_envelope_sha256") != member.get("handoff_envelope_sha256")
        or marker.get("result_evidence") != records
        or marker.get("terminal_platform_evidence") != member.get("terminal_platform_evidence")
        or marker.get("monitoring_violation_at") != member.get("monitoring_violation_at")
    ):
        errors.append("implementer terminal marker does not bind its orchestrator-observed result")
        return None
    return attestation


def validate_impl(
    value: Dict[str, object], task: Dict[str, object], artifact_path: Path, artifact_data: bytes, errors: List[str],
) -> None:
    mode = task.get("mode")
    projected = mode == "fast" or task_projection(str(task.get("task_type")), str(mode)) == "lightweight"
    expected_projection = [2, 3, 4, 5, 6] if projected else [6]
    if value.get("schema") != "agent-node-implementation/v3" or value.get("mode") != mode or value.get("status") != "verified": errors.append("node 6 schema/mode/status is invalid")
    if value.get("requirement_contract_sha256") != task.get("requirement_contract_sha256") or value.get("projection") != expected_projection: errors.append("node 6 requirement/projection binding is invalid")
    changes = value.get("changes"); checks = value.get("checks")
    if not isinstance(changes, list) or not changes: errors.append("node 6 requires at least one changed artifact")
    else:
        for index, item in enumerate(changes):
            changed = receipt(item, errors, f"change {index}")
            if changed is not None and str(changed.relative_to(ROOT)) in DYNAMIC_STATE:
                errors.append(f"change {index} binds mutable workflow state; use its dedicated evidence field")
        if len({item.get("path") for item in changes if isinstance(item, dict)}) != len(changes): errors.append("changed artifacts must be unique")
    snapshot=value.get("candidate_snapshot")
    if not isinstance(snapshot,list) or not snapshot or len(snapshot)>8192:
        errors.append("node 6 requires one bounded exact candidate snapshot")
    else:
        paths=[]; snapshot_records={}
        for index,item in enumerate(snapshot):
            if (not isinstance(item,dict) or set(item)!={"path","sha256","bytes","mode"}
                    or not isinstance(item.get("mode"),int) or isinstance(item.get("mode"),bool)
                    or item.get("mode")<0 or item.get("mode")>0o777):
                errors.append(f"candidate snapshot {index} is invalid"); continue
            paths.append(item["path"])
            snapshot_records[item["path"]]={key:item[key] for key in ("path","sha256","bytes")}
            receipt(snapshot_records[item["path"]],errors,f"candidate snapshot {index}")
        if paths!=sorted(set(paths)): errors.append("candidate snapshot paths must be unique and sorted")
        if isinstance(changes,list):
            for index,item in enumerate(changes):
                if isinstance(item,dict) and snapshot_records.get(item.get("path"))!=item:
                    errors.append(f"change {index} is absent or differs in the exact candidate snapshot")
    if not isinstance(checks, list) or not checks: errors.append("node 6 requires observable checks")
    else:
        ids = []
        for index, item in enumerate(checks):
            if not isinstance(item, dict): errors.append(f"check {index} is invalid"); continue
            ids.append(item.get("id")); command = item.get("command")
            if not item.get("id") or item.get("exit_code") != 0 or not isinstance(command, list) or not command or not all(isinstance(token, str) and token for token in command) or "-c" in command: errors.append(f"check {index} is not a bounded passing command")
            receipt(item.get("output"), errors, f"check {index} output")
        if len(ids) != len(set(ids)): errors.append("check IDs must be unique")
    cleanup = value.get("cleanup", {}); runtime = receipt(cleanup.get("runtime_state") if isinstance(cleanup, dict) else None, errors, "runtime state")
    if not isinstance(cleanup, dict) or cleanup.get("residual") != {"processes": 0, "docker_projects": 0, "ports": 0}: errors.append("node 6 lacks zero-residual cleanup proof")
    if runtime:
        state = load(runtime)
        if any(state.get(key) for key in ("processes", "docker_projects", "ports")): errors.append("runtime state is not clean")
        if state.get("schema") != "agent-runtime/v2" or not isinstance(state.get("baseline"), dict) or not isinstance(state["baseline"].get("project_processes"), list):
            errors.append("runtime cleanup lacks a project-process baseline attestation")
        else:
            live = boundedprocess.run(
                [sys.executable, str(AGENT / "scripts/agentctl.py"), "assert-clean"], cwd=str(ROOT),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30, env=os.environ.copy(),
            )
            if live.returncode:
                errors.append("live runtime baseline-delta assertion failed")
    scope = value.get("scope")
    if not isinstance(scope, dict) or not str(scope.get("summary", "")).strip() or scope.get("unapproved_assumptions") != []: errors.append("node 6 scope truth is incomplete")
    implementer_id = value.get("implementer_agent_id")
    if mode == "release":
        ledger = validated_agent_ledger(errors)
        member = resolved_implementer(ledger, implementer_id, errors)
        if member is not None:
            if (
                member.get("role_type") != "implementer" or member.get("status") != "completed"
                or receipt(member.get("terminal_platform_evidence"), errors, "implementer terminal platform proof") is None
                or not member.get("handoff_envelope_sha256")
            ):
                errors.append("release node 6 implementer is not completed and orchestrator-observed")
            implementation_attestation(member, ledger, artifact_path, artifact_data, value, errors)
    elif implementer_id is not None:
        errors.append("fast/standard node 6 must not claim release implementer authority")


def expected_bindings(task: Dict[str, object]) -> Dict[str, object]:
    value = {"requirement_contract_sha256": task.get("requirement_contract_sha256"), "implementation_sha256": task.get("node_artifacts", {}).get("6", {}).get("sha256")}
    if task.get("mode") != "fast" and task_projection(str(task.get("task_type")), str(task.get("mode"))) != "lightweight": value.update({"deliverables_sha256": task.get("node_artifacts", {}).get("3", {}).get("sha256"), "acceptance_matrix_sha256": task.get("node_artifacts", {}).get("5", {}).get("sha256")})
    return value


def validate_accept(value: Dict[str, object], task: Dict[str, object], errors: List[str]) -> None:
    mode = task.get("mode")
    if value.get("schema") != "agent-node-acceptance/v3" or value.get("mode") != mode or value.get("bindings") != expected_bindings(task): errors.append("node 7 schema/mode/evidence chain is invalid")
    checks = value.get("checks")
    if not isinstance(checks, list) or not checks: errors.append("node 7 requires acceptance checks")
    else:
        for index, item in enumerate(checks):
            if not isinstance(item, dict) or item.get("result") != "passed" or not item.get("case_ids") or not item.get("assertions") or not item.get("reviewer"): errors.append(f"acceptance check {index} is incomplete"); continue
            for evidence_index, record in enumerate(item.get("evidence", [])): receipt(record, errors, f"acceptance check {index} evidence {evidence_index}")
    if value.get("open_findings") != []: errors.append("node 7 has open findings")
    if mode == "fast":
        if value.get("status") != "verified" or value.get("human_decision") != "not_required" or value.get("recommendation") != "complete" or "live_gate_receipt" in value: errors.append("fast node 7 evidence incorrectly uses a human/release gate")
        return
    if mode == "standard":
        if value.get("status") != "ready_for_human_review" or value.get("human_decision") != "pending" or value.get("recommendation") != "request_human_acceptance" or "live_gate_receipt" in value:
            errors.append("standard node 7 must request artifact-bound human acceptance without a release live gate")
        return
    if value.get("status") != "ready_for_human_review" or value.get("human_decision") != "pending":
        errors.append("release node 7 decision state is invalid")
    config = load(AGENT / "config.json")
    adapter_registry = config.get("acceptance_adapters", {}) if isinstance(config.get("acceptance_adapters"), dict) else {}
    adaptive_route = task.get("template_route", {}).get("adaptive_project", {}) if isinstance(task.get("template_route"), dict) else {}
    adaptive_release = not any(item in adapter_registry for item in task.get("selected_templates", [])) and bool(adaptive_route.get("blueprint_sha256"))
    expected_clean_replays = config.get("routing", {}).get("modes", {}).get("release", {}).get("clean_reruns")
    if expected_clean_replays != 1:
        errors.append("release clean replay policy must be exactly one")
    expected_platform_assurance = config.get("agent_control", {}).get("platform_observer")
    if (
        not isinstance(expected_platform_assurance, dict)
        or value.get("platform_assurance") != expected_platform_assurance
        or expected_platform_assurance.get("source") != "orchestrator-tool-transcript"
        or expected_platform_assurance.get("automatic_release_trust") is not False
        or expected_platform_assurance.get("human_verification_required") is not True
        or not isinstance(expected_platform_assurance.get("signed_adapter"), str)
        or not expected_platform_assurance.get("signed_adapter")
    ):
        errors.append("release node 7 must disclose human transcript verification for platform observations")
    reviewers = value.get("reviewers", {}); roles = {"implementer", "adversarial", "cross_reviewer", "integrator"}
    integrator_gate_source: Optional[Dict[str, object]] = None
    verified_reviewers: set[object] = set(); cross_receipt_value: Optional[Dict[str, object]] = None
    cross_receipt_sha256: Optional[str] = None
    control_members: List[Dict[str, object]] = []
    if not isinstance(reviewers, dict) or set(reviewers) != roles or len(set(reviewers.values())) != 4:
        errors.append("release node 7 requires four distinct identities")
    else:
        ledger = validated_agent_ledger(errors); members = {item.get("id"): item for item in ledger.get("members", []) if isinstance(item, dict)}
        ordered_roles = [("adversarial", "adversarial"), ("cross_reviewer", "cross"), ("integrator", "integrator")]
        chain = value.get("review_chain")
        if not isinstance(chain, dict) or set(chain) != {"review_chain_id", "review_subject_sha256"}:
            errors.append("release node 7 lacks an exact review chain commitment")
            chain = {}
        elif (
            not isinstance(chain.get("review_chain_id"), str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", chain["review_chain_id"])
            or not SHA.fullmatch(str(chain.get("review_subject_sha256", "")))
        ):
            errors.append("release node 7 review chain identity/subject is invalid")
        selected_members: List[Dict[str, object]] = []
        reports: List[Optional[Dict[str, object]]] = []
        report_hashes: List[object] = []
        for role, role_type in ordered_roles:
            item = members.get(reviewers[role])
            if not isinstance(item, dict):
                errors.append(f"release reviewer is absent from the validated ledger: {role}")
                selected_members.append({}); reports.append(None); report_hashes.append(None)
                continue
            selected_members.append(item)
            result_records = item.get("result_evidence")
            records = result_records if isinstance(result_records, list) else []
            allowed_paths = set(item.get("allowed_evidence_paths", [])) if isinstance(item.get("allowed_evidence_paths"), list) else set()
            evidence_paths = {record.get("source_path") for record in records if isinstance(record, dict)}
            for evidence_index, record in enumerate(records):
                result_record(record, errors, f"{role} result evidence {evidence_index}")
            attestation = review_report_attestation(item, records, errors, role)
            if role_type == "cross":
                cross_receipt_value, cross_receipt_sha256 = cross_scenario_receipt(item, records, errors)
            reports.append(attestation)
            report_hashes.append(item.get("review_verdict", {}).get("report_sha256") if isinstance(item.get("review_verdict"), dict) else None)
            expected_count = 1 + expected_clean_replays if role_type == "integrator" else 1
            if (
                item.get("role_type") != role_type or item.get("status") != "completed"
                or item.get("review_chain_id") != chain.get("review_chain_id")
                or item.get("review_subject_sha256") != chain.get("review_subject_sha256")
                or len(records) != expected_count or not evidence_paths or not evidence_paths.issubset(allowed_paths)
                or not item.get("handoff_envelope_sha256")
                or receipt(item.get("terminal_platform_evidence"), errors, f"{role} terminal platform proof") is None
            ):
                errors.append(f"release reviewer is not independently chain/subject committed and orchestrator-observed: {role}")
        if all(selected_members):
            common_root = {item.get("root_task_id") for item in selected_members}
            common_chain = {item.get("review_chain_id") for item in selected_members}
            common_subject = {item.get("review_subject_sha256") for item in selected_members}
            if len(common_root) != 1 or len(common_chain) != 1 or None in common_chain or len(common_subject) != 1 or None in common_subject:
                errors.append("review roles do not belong to one root task, chain and sealed subject")
            if selected_members[0].get("predecessor_result_sha256") is not None:
                errors.append("adversarial review must have no predecessor")
            if selected_members[1].get("predecessor_result_sha256") != report_hashes[0]:
                errors.append("cross review is not digest-linked to the adversarial result")
            if selected_members[2].get("predecessor_result_sha256") != report_hashes[1]:
                errors.append("integrator review is not digest-linked to the cross result")
            adversarial_terminal = timestamp(selected_members[0].get("terminal_observed_at"), errors, "adversarial terminal")
            cross_registration = timestamp(selected_members[1].get("registration_observed_at"), errors, "cross registration")
            cross_terminal = timestamp(selected_members[1].get("terminal_observed_at"), errors, "cross terminal")
            integrator_registration = timestamp(selected_members[2].get("registration_observed_at"), errors, "integrator registration")
            if adversarial_terminal and cross_registration and adversarial_terminal > cross_registration:
                errors.append("cross review started before adversarial terminal completion")
            if cross_terminal and integrator_registration and cross_terminal > integrator_registration:
                errors.append("integrator started before cross terminal completion")
            current_review_subject(selected_members[0], task, errors)
            node6_authority = task.get("node_artifacts", {}).get("6")
            node6_path = receipt(node6_authority, errors, "current node 6 implementer authority")
            node6_data = accepted_node_bytes(task,6,node6_path) if node6_path else b""
            try: node6_value = strict_json_loads(node6_data.decode("utf-8")) if node6_data else {}
            except (UnicodeError,json.JSONDecodeError): node6_value={}
            implementer = resolved_implementer(ledger, node6_value.get("implementer_agent_id"), errors)
            implementer_attestation = None
            if not isinstance(implementer, dict):
                errors.append("release implementer is absent from the validated ledger")
            elif (
                implementer.get("id") != reviewers["implementer"]
                or implementer.get("role_type") != "implementer"
                or implementer.get("status") != "completed"
                or implementer.get("root_task_id") != selected_members[0].get("root_task_id")
                or receipt(implementer.get("terminal_platform_evidence"), errors, "implementer terminal platform proof") is None
            ):
                errors.append("release implementer is not the distinct orchestrator-observed node 6 author")
            else:
                implementer_attestation = implementation_attestation(
                    implementer, ledger, node6_path, node6_data, node6_value, errors,
                )
            if (
                implementer_attestation is not None
                and implementer_attestation.get("candidate_review_subject_sha256") != chain.get("review_subject_sha256")
            ):
                errors.append("release implementer attested a different candidate review subject")
        if reports[0] is not None and (reports[0].get("lenses") != [] or reports[0].get("clean_replays") != []):
            errors.append("adversarial attestation must not impersonate cross lenses or integrator replays")
        if reports[1] is not None and (reports[1].get("lenses") != REVIEW_LENSES or reports[1].get("clean_replays") != []):
            errors.append("cross attestation does not cover the exact six required role lenses")
        if reports[2] is not None:
            replay_attestations = reports[2].get("clean_replays")
            if reports[2].get("lenses") != [] or not isinstance(replay_attestations, list) or len(replay_attestations) != expected_clean_replays:
                errors.append("integrator attestation must bind exactly one clean replay")
            else:
                integrator = selected_members[2]
                records = integrator.get("result_evidence", [])
                replay_records = sorted(
                    [item for item in records if isinstance(item, dict) and item.get("source_path") != integrator.get("result_report_path")],
                    key=lambda item: str(item.get("source_path")),
                )
                if len(replay_records) == 1:
                    integrator_gate_source = {
                        key: replay_records[0].get(key) for key in ("path", "sha256", "bytes")
                    }
                expected_attestations = [
                    {key: item.get(key) for key in ("source_path", "sha256", "bytes")} for item in replay_records
                ]
                if replay_attestations != expected_attestations or any(
                    not isinstance(item, dict) or set(item) != {"source_path", "sha256", "bytes"}
                    for item in replay_attestations
                ):
                    errors.append("integrator clean replay attestations differ from immutable result evidence")
                replay_ids: List[Optional[str]] = []
                replay_window_start = timestamp(
                    integrator.get("registration_observed_at"), errors, "integrator replay window start",
                )
                replay_window_end = timestamp(
                    integrator.get("terminal_observed_at"), errors, "integrator replay window end",
                )
                if replay_window_start and replay_window_end and replay_window_end < replay_window_start:
                    errors.append("integrator replay window is temporally reversed")
                for index, record in enumerate(replay_records):
                    path = result_record(record, errors, f"integrator clean replay {index}")
                    if adaptive_release and path:
                        adaptive_receipt = load(path)
                        replay_id = adaptive_receipt.get("receipt_sha256")
                        if adaptive_receipt.get("schema") != ADAPTIVE_ACCEPTANCE_RECEIPT_SCHEMA or not SHA.fullmatch(str(replay_id or "")):
                            errors.append(f"integrator clean replay {index} is not an adaptive acceptance receipt")
                            replay_id = None
                        replay_ids.append(replay_id)
                    else:
                        replay_ids.append(verify_test_receipt(
                            path, errors, f"integrator clean replay {index}", replay_window_start, replay_window_end,
                        ) if path else None)
                if len(replay_records) != expected_clean_replays or None in replay_ids or len(set(replay_ids)) != expected_clean_replays:
                    errors.append("integrator clean replay does not match the one-run release policy")
                if len({item.get("source_path") for item in replay_records}) != expected_clean_replays or len({item.get("sha256") for item in replay_records}) != expected_clean_replays:
                    errors.append("integrator clean replay path or content digest is invalid")
        if all(selected_members) and isinstance(implementer, dict):
            root_task_id = selected_members[0].get("root_task_id")
            chain_id = chain.get("review_chain_id")
            subject = chain.get("review_subject_sha256")
            initial_implementer_id = node6_value.get("implementer_agent_id")
            control_members=delivery_control_members(
                members,initial_implementer_id,root_task_id,chain_id,subject,errors,
            )
        verified_reviewers = {reviewers[role] for role, _ in ordered_roles}
        for index, item in enumerate(checks if isinstance(checks, list) else []):
            if not isinstance(item, dict) or item.get("reviewer") not in verified_reviewers:
                errors.append(f"release acceptance check {index} is not owned by a verified review identity")
    expected_supervision_debt = sorted(
        [
            {"agent_id": item.get("id"), "first_gap_at": item.get("monitoring_violation_at")}
            for item in control_members if item.get("monitoring_violation_at") is not None
        ],
        key=lambda item: str(item["agent_id"]),
    )
    if value.get("supervision_debt") != expected_supervision_debt:
        errors.append("release node 7 supervision debt differs from the complete current delivery attempt history")
    if value.get("supervision_debt_sha256") != canonical_sha256(expected_supervision_debt):
        errors.append("release node 7 supervision debt digest is invalid")
    expected_observation_set = platform_observation_set(control_members)
    if value.get("platform_observation_set") != expected_observation_set:
        errors.append("release node 7 platform observation set differs from the complete current delivery attempt history")
    if value.get("platform_observation_set_sha256") != canonical_sha256(expected_observation_set):
        errors.append("release node 7 platform observation set digest is invalid")
    needs_control_waiver = bool(expected_supervision_debt) or (
        isinstance(expected_platform_assurance, dict)
        and expected_platform_assurance.get("human_verification_required") is True
    )
    expected_recommendation = (
        "request_human_acceptance_with_control_waiver"
        if needs_control_waiver else "request_human_acceptance"
    )
    if value.get("recommendation") != expected_recommendation:
        errors.append("release node 7 recommendation does not disclose required control waiver")
    scenarios = value.get("scenarios")
    if cross_receipt_value is None or scenarios != cross_receipt_value.get("scenarios"):
        errors.append("release scenarios differ from the cross reviewer-authored canonical receipt")
    if value.get("scenario_receipt_sha256") != cross_receipt_sha256:
        errors.append("release scenario receipt digest differs from the marker-bound cross report")
    selected = selected_adapter(task, errors); live_path = receipt(value.get("live_gate_receipt"), errors, "live gate")
    if selected and live_path:
        adapter_id, entry, rendered = selected; live = load(live_path)
        if live.get("schema") != entry.get("receipt_schema"): errors.append("live gate receipt schema differs from adapter registry")
        if entry.get("receipt_schema") == "workflow-release-gate/v4" and live.get("integrator_test_receipt") != integrator_gate_source:
            errors.append("workflow live gate is not bound to the selected integrator's one replay")
        if adapter_id == "adaptive-blueprint" and (len(selected_members) < 3 or live.get("integrator_id") != str(selected_members[2].get("id"))):
            errors.append("adaptive live gate is not bound to the selected verified integrator identity")
        if adapter_id == "adaptive-blueprint" and value.get("live_gate_receipt") != integrator_gate_source:
            errors.append("adaptive live gate receipt is not the selected integrator's marker-bound result evidence")
        if adapter_id == "adaptive-blueprint" and live.get("requires_integrator_ledger_binding") is not True:
            errors.append("adaptive live gate integrator-ledger binding requirement is invalid")
        verify_command = [sys.executable, str(ROOT / entry["runner"]), "verify", "--runner", str(rendered["path"]), "--receipt", str(value["live_gate_receipt"]["path"])]
        if adapter_id == "adaptive-blueprint":
            candidate_sha256 = task.get("node_artifacts", {}).get("6", {}).get("sha256")
            if not isinstance(candidate_sha256, str) or len(candidate_sha256) != 64:
                errors.append("adaptive live gate lacks the current implementation candidate digest")
            else:
                verify_command += ["--candidate-sha256", candidate_sha256]
        result = boundedprocess.run(
            verify_command,
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
            env=supervised_env(),
        )
        if result.returncode:
            detail = result.stdout.strip()
            errors.append(
                f"{adapter_id} live gate receipt verification failed"
                + (f": {detail}" if detail else "")
            )


def validate_node(node: int, path: Path, artifact_data: bytes) -> int:
    errors: List[str] = []; task = load(AGENT / "state/TASK.json")
    try: value = strict_json_loads(artifact_data.decode("utf-8"))
    except (UnicodeError,json.JSONDecodeError): value={}; errors.append(f"node {node} artifact snapshot is not strict UTF-8 JSON")
    if not isinstance(value,dict): value={}; errors.append(f"node {node} artifact snapshot root is not an object")
    relative = str(path.relative_to(ROOT))
    if not re.fullmatch(rf"\.agent/state/artifacts/{node:02d}-[A-Za-z0-9._-]+", relative): errors.append(f"node {node} artifact must use its canonical prefix")
    if node == 6: validate_impl(value, task, path, artifact_data, errors)
    elif node == 7: validate_accept(value, task, errors)
    elif node == 8:
        required_v2 = {
            "schema", "status", "environment", "artifact_digest",
            "promotion_receipt_sha256", "rollback_receipt_sha256", "delivery_state",
        }
        required_v3 = {
            "schema", "status", "environment", "artifact_digest", "legacy_assurance",
            "legacy_archive_sha256", "reusable_as_release_receipt", "delivery_state",
        }
        schema = value.get("schema")
        if not (
            schema == "agent-node-delivery/v2" and set(value) == required_v2
            or schema == "agent-node-delivery/v3" and set(value) == required_v3
        ):
            errors.append("node 8 schema/fields are invalid")
        state_path = receipt(value.get("delivery_state"), errors, "delivery state")
        expected_state_path = AGENT / "state" / "delivery.json"
        state_bytes = boundedio.read_bytes(state_path,label="artifact state") if state_path is not None else None
        if state_path != expected_state_path.resolve():
            errors.append("node 8 must bind the current .agent/state/delivery.json")
        elif state_bytes is not None:
            validator = AGENT / "scripts" / "deliveryctl.py"
            try:
                result = boundedprocess.run(
                    [sys.executable, str(validator), "validate"], cwd=ROOT,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30, text=True,
                    env=supervised_env(),
                )
                stable_bytes = boundedio.read_bytes(state_path,label="artifact state")
                delivery = strict_json_loads(state_bytes)
            except (OSError, json.JSONDecodeError, subprocess.TimeoutExpired):
                result = None
                stable_bytes = None
                delivery = {}
            if result is None or result.returncode:
                errors.append("node 8 delivery state failed complete delivery validation")
            if stable_bytes != state_bytes:
                errors.append("node 8 delivery state changed during validation")
            status = delivery.get("status")
            artifact = delivery.get("artifact")
            ordinary_terminal = {"not_requested", "promoted", "rolled_back"}
            historical_terminal = {"legacy_promoted", "legacy_rolled_back"}
            if status not in ordinary_terminal | historical_terminal:
                errors.append("node 8 delivery state is not terminal")
            if value.get("status") != status:
                errors.append("node 8 status differs from current delivery state")
            if value.get("environment") != delivery.get("environment"):
                errors.append("node 8 environment differs from current delivery state")
            expected_artifact_digest = artifact.get("digest") if isinstance(artifact, dict) else None
            if value.get("artifact_digest") != expected_artifact_digest:
                errors.append("node 8 artifact digest differs from current delivery state")
            if status in ordinary_terminal:
                if schema != "agent-node-delivery/v2":
                    errors.append("ordinary terminal delivery requires Node8 v2")
                expected_promotion = canonical_sha256(delivery.get("promotion_receipt")) if delivery.get("promotion_receipt") is not None else None
                expected_rollback = canonical_sha256(delivery.get("rollback_receipt")) if delivery.get("rollback_receipt") is not None else None
                if value.get("promotion_receipt_sha256") != expected_promotion:
                    errors.append("node 8 promotion receipt digest differs from current delivery state")
                if value.get("rollback_receipt_sha256") != expected_rollback:
                    errors.append("node 8 rollback receipt digest differs from current delivery state")
            else:
                legacy = delivery.get("legacy_production_chain")
                archive = legacy.get("archive") if isinstance(legacy, dict) else None
                if (
                    schema != "agent-node-delivery/v3"
                    or value.get("legacy_assurance") != "legacy"
                    or value.get("reusable_as_release_receipt") is not False
                    or not isinstance(archive, dict)
                    or value.get("legacy_archive_sha256") != archive.get("sha256")
                ):
                    errors.append("historical Node8 must bind the non-reusable legacy delivery archive")
    if errors:
        print(f"INVALID NODE {node} ARTIFACT")
        for error in errors: print(f"- {error}")
        return 1
    print(f"VALID NODE {node} ARTIFACT: {relative}"); return 0


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--node", type=int, choices=(6, 7, 8), required=True); parser.add_argument("--path", required=True); parser.add_argument("--snapshot-fd",type=int); args = parser.parse_args()
    relative=Path(args.path)
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise SystemExit("artifact path must remain lexical and project-relative")
    path=ROOT/relative
    descriptor=args.snapshot_fd; owned=False
    if descriptor is None:
        if not hasattr(os,"O_NOFOLLOW") or not hasattr(os,"O_DIRECTORY"):
            raise SystemExit("artifact validation requires POSIX descriptor-relative no-follow support")
        descriptor=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); owned=True
        try:
            for index,part in enumerate(relative.parts):
                final=index==len(relative.parts)-1
                child=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|(0 if final else os.O_DIRECTORY),dir_fd=descriptor)
                os.close(descriptor); descriptor=child
        except BaseException:
            os.close(descriptor); raise
    metadata=os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 or metadata.st_size>16*1024*1024:
        raise SystemExit("artifact snapshot descriptor is not one bounded single-link regular file")
    identity=(metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_size,metadata.st_mtime_ns,metadata.st_ctime_ns)
    chunks=[]; total=0
    while True:
        chunk=os.read(descriptor,min(1024*1024,16*1024*1024+1-total))
        if not chunk: break
        chunks.append(chunk); total+=len(chunk)
        if total>16*1024*1024: raise SystemExit("artifact snapshot descriptor exceeds its byte limit")
    final=os.fstat(descriptor)
    if identity!=(final.st_dev,final.st_ino,final.st_mode,final.st_size,final.st_mtime_ns,final.st_ctime_ns) or total!=metadata.st_size:
        if owned: os.close(descriptor)
        raise SystemExit("artifact snapshot changed during semantic validation")
    if owned: os.close(descriptor)
    return validate_node(args.node, path, b"".join(chunks))


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
