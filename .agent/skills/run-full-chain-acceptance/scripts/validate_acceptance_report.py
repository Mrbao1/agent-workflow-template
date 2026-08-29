#!/usr/bin/env python3
"""Validate a canonical acceptance report and its referenced evidence."""

from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import stat
import sys
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"scripts"))
from adaptive_common import AdaptiveError,canonical_sha256,validate_design
from workflowlib import boundedio

MAX_DOCUMENT_BYTES=16*1024*1024


def confirmed_application_service_authority(root: Path,errors: List[str]) -> Tuple[List[str],str]:
    try:
        raw=json.loads(bounded_read_text(root/".agent/project/BLUEPRINT.json","confirmed Blueprint"))
        if (not isinstance(raw,dict) or raw.get("schema")!="agent-project-blueprint/v1" or raw.get("status")!="confirmed"):
            raise ValueError("Blueprint is not confirmed")
        design=validate_design(raw.get("design"),require_material=True)
        confirmation=raw.get("confirmation")
        if (not isinstance(confirmation,dict) or set(confirmation)!={"source","design_sha256","confirmed_at","decision_receipt"}
                or not isinstance(confirmation.get("source"),str) or not confirmation["source"].startswith("user:")
                or not isinstance(confirmation.get("decision_receipt"),dict)
                or confirmation.get("design_sha256")!=canonical_sha256(design)):
            raise ValueError("Blueprint confirmation does not bind the exact normalized design")
        services=design.get("application_services")
        if not isinstance(services,list) or not services:
            raise ValueError("Blueprint has no application_services authority")
        return services,str(confirmation["design_sha256"])
    except (OSError,ValueError,TypeError,KeyError,json.JSONDecodeError,AdaptiveError) as error:
        errors.append(f"confirmed Blueprint application-service authority is invalid: {error}")
        return [],""


def bounded_read_text(path: Path,label: str) -> str:
    try: return boundedio.read_text(path,maximum=MAX_DOCUMENT_BYTES,label=label)
    except RuntimeError as error: raise ValueError(str(error)) from error


FIELDS = (
    "Tested fingerprint", "Fingerprint manifest", "Fingerprint manifest SHA-256",
    "Acceptance plan", "Acceptance plan SHA-256",
    "Runtime", "Implementer agent", "Adversarial reviewer agent", "Cross reviewer agent",
    "Integrator agent", "Requirements", "Requirement coverage", "Mandatory cases", "Passed", "Failed",
    "Blocked", "P0", "P1", "P2", "P3", "P3 disposition", "Clean full-chain reruns",
    "AI recommendation", "Human decision", "Human decision source",
)
HEADINGS = (
    "Traceability", "Runtime evidence", "Scenario results", "Adversarial review",
    "Cross-review", "Defects and retest", "Residual risks",
)
CASE_RE = re.compile(
    r"^- Case: (?P<case>CASE-[A-Za-z0-9_-]+) \| Requirement: (?P<req>REQ-[A-Za-z0-9_-]+) "
    r"\| Status: (?P<status>Pass|Fail|Blocked) \| Evidence: (?P<path>[^|]+?) "
    r"\| SHA-256: (?P<sha>[a-f0-9]{64})\s*$", re.MULTILINE,
)
RERUN_RE = re.compile(
    r"^- Rerun: (?P<run>RUN-[A-Za-z0-9_-]+) \| Evidence: (?P<path>[^|]+?) "
    r"\| SHA-256: (?P<sha>[a-f0-9]{64})\s*$", re.MULTILINE,
)
AGENT_RE = re.compile(r"^[A-Za-z0-9_./:-]+#[A-Za-z0-9_-]+$")
SHA_RE = re.compile(r"^[a-f0-9]{64}$")
LANES = {
    "happy-path", "alternative-path", "validation", "boundary", "interruption-recovery",
    "concurrency-idempotency", "persistence-data-integrity", "accessibility", "privacy-security",
    "compatibility-responsive", "regression-operations",
}
ATTACK_TYPES = {"fault", "boundary", "recovery", "idempotency", "invalid-input", "interruption", "concurrency", "security"}


def occurrences(text: str, name: str) -> List[str]:
    return [value.strip(" `") for value in re.findall(
        rf"^- {re.escape(name)}:\s*(.+?)\s*$", text, re.MULTILINE
    )]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_evidence_path(raw: str, expected: str, root: Path, errors: List[str]) -> Optional[Path]:
    path = (root / raw.strip()).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        errors.append(f"evidence escapes project root: {raw.strip()}")
        return None
    if not path.is_file() or path.is_symlink():
        errors.append(f"evidence file missing or symlinked: {raw.strip()}")
        return None
    if path.stat().st_size > 256 * 1024:
        errors.append(f"indexed evidence exceeds 256 KiB: {raw.strip()}")
        return None
    actual = sha256(path)
    if actual != expected:
        errors.append(f"evidence hash mismatch: {raw.strip()}")
        return None
    return path


def json_evidence(path: Optional[Path], errors: List[str]) -> Optional[Dict[str, object]]:
    if path is None:
        return None
    if path.stat().st_size > 64 * 1024:
        errors.append(f"JSON evidence exceeds 64 KiB: {path}")
        return None
    try:
        data = json.loads(bounded_read_text(path,"acceptance JSON"))
    except (OSError, ValueError) as error:
        errors.append(f"evidence must be valid JSON: {path} ({error})")
        return None
    if not isinstance(data, dict):
        errors.append(f"evidence must be a JSON object: {path}")
        return None
    return data


def require_keys(data: Dict[str, object], keys: Tuple[str, ...], label: str, errors: List[str]) -> None:
    for key in keys:
        if key not in data or data[key] in (None, "", []):
            errors.append(f"{label} missing evidence key: {key}")


def validate_fingerprint_manifest(path: Optional[Path], root: Path, errors: List[str]) -> None:
    if path is None:
        return
    entries = 0
    for line in bounded_read_text(path,"acceptance JSON").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([a-f0-9]{64})  (.+)", line)
        if not match:
            errors.append(f"invalid fingerprint manifest line: {line}")
            continue
        entries += 1
        checked_evidence_path(match.group(2), match.group(1), root, errors)
    if entries < 1:
        errors.append("fingerprint manifest must contain at least one verified file")


def manifest_paths(path: Optional[Path]) -> Set[str]:
    if path is None:
        return set()
    paths = set()
    for line in bounded_read_text(path,"acceptance JSON").splitlines():
        match = re.fullmatch(r"[a-f0-9]{64}  (.+)", line)
        if match:
            paths.add(match.group(1))
    return paths


def manifest_entries(path: Optional[Path]) -> Dict[str, str]:
    if path is None:
        return {}
    result = {}
    for line in bounded_read_text(path,"acceptance JSON").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  (.+)", line)
        if match:
            result[match.group(2)] = match.group(1)
    return result


MAX_SCOPE_ENTRIES=32768
MAX_SCOPE_FILES=16384


def safe_scope_path(root: Path,raw: str,*,directory: Optional[bool],errors: List[str],label: str) -> Optional[Path]:
    relative=Path(raw)
    if relative.is_absolute() or not relative.parts or any(part in {"",".",".."} for part in relative.parts):
        errors.append(f"{label} is not one safe project-relative path: {raw}"); return None
    current=root
    try:
        for part in relative.parts:
            current=current/part; observed=os.lstat(current)
            if stat.S_ISLNK(observed.st_mode):
                errors.append(f"{label} traverses a symlink: {raw}"); return None
        final=os.lstat(current)
    except OSError:
        errors.append(f"{label} is missing: {raw}"); return None
    expected=(stat.S_ISDIR(final.st_mode) or stat.S_ISREG(final.st_mode)) if directory is None else (stat.S_ISDIR(final.st_mode) if directory else stat.S_ISREG(final.st_mode))
    if not expected:
        errors.append(f"{label} has the wrong file type: {raw}"); return None
    return current


def bounded_scope_files(path: Path,root: Path,errors: List[str],state: Dict[str,int]):
    stack=[path]
    while stack:
        directory=stack.pop()
        try:
            with os.scandir(directory) as scanner:
                entries=[]
                for entry in scanner:
                    state["entries"]+=1
                    if state["entries"]>MAX_SCOPE_ENTRIES:
                        raise RuntimeError("acceptance scope entry limit exceeded")
                    entries.append(entry)
        except (OSError,RuntimeError) as error:
            errors.append(str(error)); return
        for entry in sorted(entries,key=lambda item:os.fsencode(item.name),reverse=True):
            try: observed=entry.stat(follow_symlinks=False)
            except OSError:
                errors.append(f"acceptance scope entry became unreadable: {entry.path}"); return
            if stat.S_ISLNK(observed.st_mode):
                errors.append(f"acceptance scope contains a symlink: {entry.path}"); return
            if stat.S_ISDIR(observed.st_mode): stack.append(Path(entry.path)); continue
            if not stat.S_ISREG(observed.st_mode):
                errors.append(f"acceptance scope contains a special file: {entry.path}"); return
            state["files"]+=1
            if state["files"]>MAX_SCOPE_FILES:
                errors.append("acceptance scope file limit exceeded"); return
            yield Path(entry.path)


def scoped_files(scope: Dict[str, object], root: Path, errors: List[str]) -> Set[str]:
    categories = ("source_roots", "test_roots", "config_files", "container_files", "requirement_files")
    for category in categories:
        if not isinstance(scope.get(category), list) or not scope[category]:
            errors.append(f"acceptance scope requires non-empty {category}")
    declared_source_roots = {str(item).rstrip("/") for item in scope.get("source_roots", []) if isinstance(item, str)}
    declared_test_roots = {str(item).rstrip("/") for item in scope.get("test_roots", []) if isinstance(item, str)}
    conventional_source = {name for name in ("src", "app", "lib", "frontend", "backend", "server", "api", "packages", "services") if (root / name).is_dir()}
    conventional_tests = {name for name in ("tests", "test", "e2e", "integration") if (root / name).is_dir()}
    if not conventional_source.issubset(declared_source_roots):
        errors.append("scope source_roots omit conventional project roots: " + ", ".join(sorted(conventional_source - declared_source_roots)))
    if not conventional_tests.issubset(declared_test_roots):
        errors.append("scope test_roots omit conventional project roots: " + ", ".join(sorted(conventional_tests - declared_test_roots)))

    declared_root_paths=[]
    for item in sorted(declared_source_roots|declared_test_roots):
        declared=safe_scope_path(root,item,directory=True,errors=errors,label="scope root")
        if declared is not None: declared_root_paths.append(declared)
    exclusions = scope.get("exclude_paths", [])
    excluded: Set[str] = set()
    if not isinstance(exclusions, list):
        errors.append("scope exclude_paths must be a list"); exclusions = []
    for item in exclusions:
        if not isinstance(item, dict) or not item.get("path") or not item.get("reason") or not str(item.get("approver", "")).startswith("user:"):
            errors.append("each scope exclusion needs path, reason, and user approver"); continue
        exclusion_path=safe_scope_path(root,str(item["path"]),directory=None,errors=errors,label="scope exclusion")
        if exclusion_path is None: continue
        if not any(exclusion_path==declared or declared in exclusion_path.parents for declared in declared_root_paths):
            errors.append(f"scope exclusion is outside declared source/test roots: {item['path']}"); continue
        excluded.add(exclusion_path.relative_to(root).as_posix())
    result: Set[str] = set(); traversal={"entries":0,"files":0}
    for category in ("source_roots", "test_roots"):
        for raw in scope.get(category, []):
            path=safe_scope_path(root,str(raw),directory=True,errors=errors,label="scope root")
            if path is None: continue
            contribution=0
            for file_path in bounded_scope_files(path,root,errors,traversal):
                relative=file_path.relative_to(root).as_posix()
                if relative not in excluded:
                    result.add(relative); contribution+=1
            if contribution<1: errors.append(f"scope root contributes no tested files: {raw}")
    for category in ("config_files", "container_files", "requirement_files"):
        for raw in scope.get(category, []):
            path=safe_scope_path(root,str(raw),directory=False,errors=errors,label="scope file")
            if path is not None:
                traversal["files"]+=1
                if traversal["files"]>MAX_SCOPE_FILES: errors.append("acceptance scope file limit exceeded")
                else: result.add(path.relative_to(root).as_posix())
    return result


def number(values: Dict[str, str], name: str, errors: List[str]) -> Optional[int]:
    raw = values.get(name, "")
    if not raw.isdigit():
        errors.append(f"{name} must be a non-negative integer")
        return None
    return int(raw)


def nonempty_heading(text: str, heading: str) -> bool:
    match = re.search(rf"^## {re.escape(heading)}\s*$\n(?P<body>.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    if not match:
        return False
    body = re.sub(r"<!--.*?-->|```.*?```", "", match.group("body"), flags=re.DOTALL).strip()
    return bool(body and body.lower() not in {"none", "n/a", "无"})


def valid_document_anchor(path: Path, raw_anchor: object) -> bool:
    """Accept an exact Markdown heading or an existing one-based line anchor."""
    anchor = str(raw_anchor).strip().lstrip("#").strip()
    if not anchor:
        return False
    text = bounded_read_text(path,"acceptance JSON")
    line_match = re.fullmatch(r"L([1-9][0-9]*)", anchor)
    if line_match:
        return int(line_match.group(1)) <= len(text.splitlines())
    return re.search(rf"^#{{1,6}}[ \t]+{re.escape(anchor)}[ \t]*$", text, re.MULTILINE) is not None


def authoritative_source(raw_source: object, requirement_files: Set[str], root: Path) -> bool:
    if not isinstance(raw_source, dict) or set(raw_source) != {"file", "anchor"}:
        return False
    source_file = str(raw_source.get("file", ""))
    source_path = (root / source_file).resolve()
    if source_file not in requirement_files or not source_path.is_file() or source_path.is_symlink():
        return False
    try:
        source_path.relative_to(root)
    except ValueError:
        return False
    return valid_document_anchor(source_path, raw_source.get("anchor"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--draft", action="store_true", help="allow a pending human decision")
    args = parser.parse_args()

    report = Path(args.report).resolve()
    root = Path.cwd().resolve()
    text = bounded_read_text(report,"acceptance report")
    errors: List[str] = []
    values: Dict[str, str] = {}
    blueprint_services,blueprint_sha256=confirmed_application_service_authority(root,errors)
    try:
        configured_clean_reruns = int(json.loads(
            bounded_read_text(root/".agent/config.json","agent config")
        )["routing"]["modes"]["release"]["clean_reruns"])
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        configured_clean_reruns = -1
        errors.append("release clean-rerun policy is unavailable")

    for name in FIELDS:
        found = occurrences(text, name)
        if len(found) != 1:
            errors.append(f"field must occur exactly once: {name}")
        values[name] = found[0] if found else ""
    for heading in HEADINGS:
        if not nonempty_heading(text, heading):
            errors.append(f"missing or empty heading: ## {heading}")

    role_names = ("Implementer agent", "Adversarial reviewer agent", "Cross reviewer agent", "Integrator agent")
    roles = [values[name] for name in role_names]
    for role in roles:
        if role and not AGENT_RE.fullmatch(role):
            errors.append(f"agent identity must include canonical id and task id: {role}")
    canonical_roles = [role.split("#", 1)[0] for role in roles]
    if all(roles) and len(set(canonical_roles)) != len(canonical_roles):
        errors.append("implementer, reviewers, and integrator must use distinct canonical agent IDs")

    manifest_hash = values["Fingerprint manifest SHA-256"]
    if manifest_hash and not SHA_RE.fullmatch(manifest_hash):
        errors.append("Fingerprint manifest SHA-256 must be 64 lowercase hex characters")
    if values["Tested fingerprint"] != manifest_hash:
        errors.append("Tested fingerprint must equal the verified fingerprint manifest hash")
    if values["Fingerprint manifest"] and manifest_hash:
        manifest_path = checked_evidence_path(values["Fingerprint manifest"], manifest_hash, root, errors)
        validate_fingerprint_manifest(manifest_path, root, errors)
    else:
        manifest_path = None

    plan_hash = values["Acceptance plan SHA-256"]
    if plan_hash and not SHA_RE.fullmatch(plan_hash):
        errors.append("Acceptance plan SHA-256 must be 64 lowercase hex characters")
    plan_path = checked_evidence_path(values["Acceptance plan"], plan_hash, root, errors) if values["Acceptance plan"] and plan_hash else None
    plan = json_evidence(plan_path, errors)
    plan_requirements: Set[str] = set()
    plan_requirement_items: List[Dict[str, object]] = []
    plan_requirement_sources: Dict[str, Dict[str, object]] = {}
    plan_lanes: Dict[str, Dict[str, object]] = {}
    requirement_files: Set[str] = set()
    approved_test_files: Set[str] = set()
    runtime_required_files: Set[str] = set()
    if plan is not None:
        require_keys(plan, ("requirements", "scope", "lanes", "adjacencies", "agents"), "acceptance plan", errors)
        requirements = plan.get("requirements")
        if not isinstance(requirements, list):
            errors.append("acceptance plan requirements must be a list")
        else:
            for requirement in requirements:
                if not isinstance(requirement, dict) or not all(requirement.get(key) for key in ("id", "source", "delivery")):
                    errors.append("each acceptance requirement needs id, source, and delivery")
                    continue
                requirement_id = str(requirement["id"])
                if not requirement_id.startswith("REQ-") or requirement_id in plan_requirements:
                    errors.append("acceptance requirement IDs must be unique and start with REQ-")
                plan_requirements.add(requirement_id)
                plan_requirement_items.append(requirement)
        scope = plan.get("scope")
        if not isinstance(scope, dict):
            errors.append("acceptance plan scope must be an object")
        else:
            all_scoped = scoped_files(scope, root, errors)
            for raw_root in scope.get("test_roots", []):
                test_root = (root / str(raw_root)).resolve()
                for relative in all_scoped:
                    candidate = (root / relative).resolve()
                    try:
                        candidate.relative_to(test_root)
                        approved_test_files.add(relative)
                    except ValueError:
                        continue
            missing_from_fingerprint = all_scoped - manifest_paths(manifest_path)
            if missing_from_fingerprint:
                errors.append("fingerprint omits scoped files: " + ", ".join(sorted(missing_from_fingerprint)))
            source_root_paths=[path for raw in scope.get("source_roots", [])
                for path in [safe_scope_path(root,str(raw),directory=True,errors=errors,label="scope root")] if path is not None]
            runtime_required_files={relative for relative in all_scoped
                if any((root/relative)==source_root or source_root in (root/relative).parents for source_root in source_root_paths)}
            runtime_required_files.update(str(item) for category in ("config_files", "container_files") for item in scope.get(category, []))
            requirement_files = {str(item) for item in scope.get("requirement_files", [])}
            for requirement in plan_requirement_items:
                source = requirement.get("source")
                if not isinstance(source, dict) or not source.get("file") or not source.get("anchor"):
                    errors.append(f"requirement source must contain file and anchor: {requirement.get('id')}")
                    continue
                source_file = str(source["file"])
                if source_file not in requirement_files:
                    errors.append(f"requirement source is outside requirement_files: {requirement.get('id')}")
                    continue
                source_path = root / source_file
                if not valid_document_anchor(source_path, source["anchor"]):
                    errors.append(f"requirement anchor not found: {requirement.get('id')}")
                else:
                    plan_requirement_sources[str(requirement.get("id"))] = {
                        "file": source_file,
                        "anchor": str(source["anchor"]),
                    }
        lanes = plan.get("lanes")
        if not isinstance(lanes, list):
            errors.append("acceptance plan lanes must be a list")
        else:
            for lane in lanes:
                if not isinstance(lane, dict) or lane.get("id") not in LANES:
                    errors.append("acceptance plan contains an invalid lane")
                    continue
                plan_lanes[str(lane["id"])] = lane
            if set(plan_lanes) != LANES or len(lanes) != len(LANES):
                errors.append("acceptance plan must declare all 11 scenario lanes exactly once")
        plan_adjacencies = plan.get("adjacencies")
        if not isinstance(plan_adjacencies, list) or not plan_adjacencies:
            errors.append("acceptance plan needs at least one authoritative controlled adjacency")
        agents = plan.get("agents")
        if not isinstance(agents, dict):
            errors.append("acceptance plan agents must be an object")
        else:
            require_keys(agents, ("platform_limit", "max_active_children", "peak_active_children", "root_slot_reserved", "assignments", "events"), "agent ledger", errors)
            limit = agents.get("platform_limit")
            maximum = agents.get("max_active_children")
            peak = agents.get("peak_active_children")
            if not all(isinstance(item, int) and not isinstance(item, bool) for item in (limit, maximum, peak)):
                errors.append("agent ledger concurrency fields must be integers")
            elif agents.get("root_slot_reserved") is not True or maximum > limit - 1 or peak > maximum:
                errors.append("agent ledger exceeds concurrency or does not reserve the root slot")
            assignments = agents.get("assignments")
            if not isinstance(assignments, list):
                errors.append("agent assignments must be a list")
            else:
                expected = dict(zip(("implementer", "adversarial", "cross", "integrator"), roles))
                seen_roles = set()
                for assignment in assignments:
                    if not isinstance(assignment, dict):
                        errors.append("agent assignment must be an object")
                        continue
                    role = assignment.get("role")
                    seen_roles.add(role)
                    if role not in expected or assignment.get("agent") != expected.get(role):
                        errors.append("agent assignment does not match report roles")
                    if role in {"adversarial", "cross", "integrator"} and assignment.get("read_only") is not True:
                        errors.append(f"{role} agent must be read-only")
                if seen_roles != set(expected) or len(assignments) != 4:
                    errors.append("agent ledger must include all four roles")
            events = agents.get("events")
            role_events: Dict[str, List[Dict[str, object]]] = {role: [] for role in ("implementer", "adversarial", "cross", "integrator")}
            if not isinstance(events, list):
                errors.append("agent ledger events must be a list")
            else:
                sequences = []
                for event in events:
                    if not isinstance(event, dict) or not all(event.get(key) is not None for key in ("sequence", "timestamp", "role", "phase", "action", "fingerprint")):
                        errors.append("each agent event needs sequence, timestamp, role, phase, action, and fingerprint")
                        continue
                    role = event.get("role")
                    if role not in role_events or event.get("action") not in {"started", "status_check", "finished", "interrupted", "redispatched"}:
                        errors.append("agent event has invalid role or action")
                        continue
                    if event.get("fingerprint") != values["Tested fingerprint"]:
                        errors.append("agent event fingerprint differs from tested fingerprint")
                    sequences.append(event.get("sequence"))
                    role_events[role].append(event)
                if not all(isinstance(item, int) and not isinstance(item, bool) for item in sequences) or sequences != list(range(1, len(sequences) + 1)):
                    errors.append("agent events must have ordered contiguous sequence numbers")
                for role, items in role_events.items():
                    actions = [item.get("action") for item in items]
                    if not {"started", "status_check", "finished"}.issubset(set(actions)):
                        errors.append(f"agent event lifecycle is incomplete: {role}")
                    if actions.count("interrupted") > 1 or actions.count("redispatched") > 1 or actions.count("interrupted") != actions.count("redispatched"):
                        errors.append(f"agent interruption/redispatch budget invalid: {role}")
                phase_groups: Dict[str, List[Dict[str, object]]] = {}
                for event in events:
                    if isinstance(event, dict) and isinstance(event.get("phase"), str):
                        phase_groups.setdefault(str(event["phase"]), []).append(event)
                ordered_phases = []
                for phase, items in phase_groups.items():
                    items.sort(key=lambda item: int(item["sequence"]))
                    roles_in_phase = {item.get("role") for item in items}
                    actions = [item.get("action") for item in items]
                    phase_sequences = [int(item["sequence"]) for item in items]
                    contiguous = phase_sequences == list(range(min(phase_sequences), max(phase_sequences) + 1))
                    ordered_actions = actions[0] == "started" and actions[-1] == "finished" and "status_check" in actions[1:-1]
                    if "interrupted" in actions or "redispatched" in actions:
                        ordered_actions = ordered_actions and actions.count("interrupted") == 1 and actions.count("redispatched") == 1 and actions.index("interrupted") < actions.index("redispatched")
                    if len(roles_in_phase) != 1 or not contiguous or not ordered_actions:
                        errors.append(f"agent phase is incomplete or mixes roles: {phase}")
                    ordered_phases.append((min(int(item["sequence"]) for item in items), phase, next(iter(roles_in_phase), None)))
                ordered_phases.sort()
                workflow = [(phase, role) for _, phase, role in ordered_phases]
                cursor = 0

                def consume(expected_phase: str, expected_role: str) -> bool:
                    nonlocal cursor
                    if cursor >= len(workflow) or workflow[cursor] != (expected_phase, expected_role):
                        return False
                    cursor += 1
                    return True

                valid_workflow = consume("candidate", "implementer") and consume("adversarial", "adversarial")
                while valid_workflow and cursor < len(workflow) and workflow[cursor][0].startswith("fix:"):
                    defect = workflow[cursor][0].split(":", 1)[1]
                    valid_workflow = consume(f"fix:{defect}", "implementer") and consume(f"adversarial-retest:{defect}", "adversarial")
                valid_workflow = valid_workflow and consume("cross", "cross")
                while valid_workflow and cursor < len(workflow) and workflow[cursor][0].startswith("fix:"):
                    defect = workflow[cursor][0].split(":", 1)[1]
                    valid_workflow = (
                        consume(f"fix:{defect}", "implementer")
                        and consume(f"cross-retest:{defect}", "cross")
                        and consume(f"adversarial-affected:{defect}", "adversarial")
                    )
                valid_workflow = valid_workflow and consume("integrator", "integrator") and cursor == len(workflow)
                if not valid_workflow:
                    errors.append("agent phases violate the required review/fix/retest state machine")

    if values["Requirement coverage"] != "100%":
        errors.append("Requirement coverage must be 100%")
    names = ("Requirements", "Mandatory cases", "Passed", "Failed", "Blocked", "P0", "P1", "P2", "P3", "Clean full-chain reruns")
    nums = {name: number(values, name, errors) for name in names}
    if nums["Requirements"] is not None and nums["Requirements"] < 1:
        errors.append("Requirements must be at least 1")
    if nums["Mandatory cases"] is not None and nums["Mandatory cases"] < 2:
        errors.append("Mandatory cases must be at least 2 for independent review")
    for name in ("Failed", "Blocked", "P0", "P1", "P2"):
        if nums[name] not in (None, 0):
            errors.append(f"{name} must be 0")
    if nums["Mandatory cases"] is not None and nums["Passed"] != nums["Mandatory cases"]:
        errors.append("Passed must equal Mandatory cases")
    if nums["Clean full-chain reruns"] is not None and nums["Clean full-chain reruns"] != configured_clean_reruns:
        errors.append("Clean full-chain reruns must equal the configured release policy")
    if nums["P3"] == 0 and values["P3 disposition"] != "none":
        errors.append("P3 disposition must be none when P3 is 0")
    if nums["P3"] not in (None, 0) and not values["P3 disposition"].startswith("user:"):
        errors.append("non-zero P3 disposition must start with 'user:'")

    cases = list(CASE_RE.finditer(text))
    case_ids = [match.group("case") for match in cases]
    if nums["Mandatory cases"] is not None and len(cases) != nums["Mandatory cases"]:
        errors.append("structured Case entries must equal Mandatory cases")
    if len(case_ids) != len(set(case_ids)):
        errors.append("Case IDs must be unique")
    requirement_ids = {match.group("req") for match in cases}
    if nums["Requirements"] is not None and len(requirement_ids) != nums["Requirements"]:
        errors.append("unique structured Requirement IDs must equal Requirements")
    if plan_requirements and requirement_ids != plan_requirements:
        errors.append("structured cases must cover every requirement in the acceptance plan")
    evidence_reviewers = set()
    user_roles = set()
    adversarial_attack_types = set()
    covered_lanes = set()
    case_lanes: Dict[str, str] = {}
    case_evidence_data: List[Dict[str, object]] = []
    for match in cases:
        if match.group("status") != "Pass":
            errors.append(f"mandatory case is not Pass: {match.group('case')}")
        path = checked_evidence_path(match.group("path"), match.group("sha"), root, errors)
        data = json_evidence(path, errors)
        if data is not None:
            case_evidence_data.append(data)
            require_keys(data, ("case_id", "requirement_id", "tested_fingerprint", "reviewer_agent", "environment", "precondition", "expected", "actual", "assertions", "command", "exit_code", "timestamp", "lane", "user_role", "risk", "review_type", "observed_layers", "data_flow_steps", "execution_run_ids", "scenario_vector"), match.group("case"), errors)
            if data.get("case_id") != match.group("case") or data.get("requirement_id") != match.group("req"):
                errors.append(f"case evidence identity mismatch: {match.group('case')}")
            if data.get("tested_fingerprint") != values["Tested fingerprint"]:
                errors.append(f"case evidence fingerprint mismatch: {match.group('case')}")
            reviewer = data.get("reviewer_agent")
            if isinstance(reviewer, str):
                evidence_reviewers.add(reviewer)
            if reviewer not in {values["Adversarial reviewer agent"], values["Cross reviewer agent"]}:
                errors.append(f"case reviewer is not an independent reviewer: {match.group('case')}")
            assertions = data.get("assertions")
            if not isinstance(assertions, list) or len(assertions) < 2 or any(not isinstance(item, dict) or item.get("passed") is not True for item in assertions):
                errors.append(f"case evidence requires at least two passing assertions: {match.group('case')}")
            if data.get("exit_code") != 0:
                errors.append(f"case evidence exit_code must be 0: {match.group('case')}")
            lane = data.get("lane")
            if lane not in LANES:
                errors.append(f"case evidence has invalid lane: {match.group('case')}")
            else:
                covered_lanes.add(lane)
                case_lanes[match.group("case")] = str(lane)
            if isinstance(data.get("user_role"), str):
                user_roles.add(data["user_role"])
            layers = data.get("observed_layers")
            if not isinstance(layers, list) or len(set(layers)) < 2:
                errors.append(f"case must observe at least two system layers: {match.group('case')}")
            steps = data.get("data_flow_steps")
            if not isinstance(steps, list) or len(steps) < 2:
                errors.append(f"case must verify at least two data-flow steps: {match.group('case')}")
            review_type = data.get("review_type")
            if review_type == "adversarial":
                attacks = data.get("attack_types")
                if not isinstance(attacks, list) or len(attacks) < 2 or not set(attacks).issubset(ATTACK_TYPES) or not data.get("fault_injection"):
                    errors.append(f"adversarial case needs attack_types: {match.group('case')}")
                else:
                    adversarial_attack_types.update(str(item) for item in attacks)
                if reviewer != values["Adversarial reviewer agent"]:
                    errors.append(f"adversarial case reviewer mismatch: {match.group('case')}")
            elif review_type == "cross":
                adjacent = data.get("adjacent_case")
                controlled_field = data.get("controlled_field")
                declared_edge = False
                if isinstance(plan.get("adjacencies") if isinstance(plan, dict) else None, list):
                    for edge in plan["adjacencies"]:
                        if not isinstance(edge, dict):
                            continue
                        endpoints = {edge.get("case_a"), edge.get("case_b")}
                        if endpoints == {match.group("case"), adjacent} and edge.get("controlled_field") == controlled_field and edge.get("source") == data.get("derivation_source"):
                            declared_edge = True
                            break
                if (
                    reviewer != values["Cross reviewer agent"]
                    or not authoritative_source(data.get("derivation_source"), requirement_files, root)
                    or data.get("derivation_source") != plan_requirement_sources.get(match.group("req"))
                    or adjacent not in case_ids
                    or adjacent == match.group("case")
                    or not isinstance(controlled_field, str)
                    or not controlled_field
                    or not declared_edge
                ):
                    errors.append(f"cross case needs authoritative derivation and adjacent case: {match.group('case')}")
            else:
                errors.append(f"case review_type must be adversarial or cross: {match.group('case')}")
    for reviewer_name in ("Adversarial reviewer agent", "Cross reviewer agent"):
        if values[reviewer_name] not in evidence_reviewers:
            errors.append(f"no structured case evidence from {reviewer_name}")
    if len(user_roles) < 2:
        errors.append("mandatory cases must cover at least two distinct user roles")
    if len(adversarial_attack_types) < 2:
        errors.append("adversarial evidence must cover at least two attack types")
    evidence_by_case = {str(item.get("case_id")): item for item in case_evidence_data}
    for data in case_evidence_data:
        if data.get("review_type") != "cross":
            continue
        adjacent = evidence_by_case.get(str(data.get("adjacent_case")))
        controlled_field = data.get("controlled_field")
        left = data.get("scenario_vector")
        right = adjacent.get("scenario_vector") if isinstance(adjacent, dict) else None
        linked = False
        required_invariants = {"flow", "state", "input_shape"}
        controlled_fields = {"amount_class", "input_variant", "boundary_value", "error_mode", "state_transition", "permission"}
        vectors_are_scalars = all(isinstance(value, str) and value.strip() for value in list(left.values()) + list(right.values())) if isinstance(left, dict) and isinstance(right, dict) else False
        if isinstance(left, dict) and isinstance(right, dict) and vectors_are_scalars and set(left) == set(right) and required_invariants.issubset(left) and controlled_field in controlled_fields and controlled_field in left and len(left) >= 4:
            differences = {key for key in left if left.get(key) != right.get(key)}
            linked = differences == {controlled_field}
        if not linked:
            errors.append(f"cross case adjacency is not evidenced by both cases: {data.get('case_id')}")
    if plan_lanes:
        for lane_id, lane in plan_lanes.items():
            status_value = lane.get("status")
            lane_cases = set(lane.get("cases", [])) if isinstance(lane.get("cases"), list) else set()
            if status_value == "covered":
                if not lane_cases or not lane_cases.issubset(set(case_ids)) or lane_id not in covered_lanes or any(case_lanes.get(case_id) != lane_id for case_id in lane_cases):
                    errors.append(f"covered lane lacks valid case evidence: {lane_id}")
            elif status_value == "not_applicable":
                if not lane.get("reason") or not str(lane.get("approver", "")).startswith("user:"):
                    errors.append(f"not-applicable lane needs reason and user approver: {lane_id}")
            else:
                errors.append(f"lane status must be covered or not_applicable: {lane_id}")

    reruns = list(RERUN_RE.finditer(text))
    rerun_ids = [match.group("run") for match in reruns]
    runtime_ids = set()
    image_digests = set()
    runtime_evidence_paths = set()
    if nums["Clean full-chain reruns"] is not None and len(reruns) != nums["Clean full-chain reruns"]:
        errors.append("structured Rerun entries must equal Clean full-chain reruns")
    if len(rerun_ids) != len(set(rerun_ids)):
        errors.append("Rerun IDs must be unique")
    for match in reruns:
        path = checked_evidence_path(match.group("path"), match.group("sha"), root, errors)
        data = json_evidence(path, errors)
        if data is not None:
            require_keys(data, ("run_id", "tested_fingerprint", "candidate_sha256", "fresh_state", "fresh_state_token", "reviewer_agent", "cases", "new_defects", "command", "exit_code", "timestamp", "runtime_id", "image_digest", "state_reset_evidence", "runtime_evidence", "runtime_evidence_sha256"), match.group("run"), errors)
            if data.get("run_id") != match.group("run") or data.get("tested_fingerprint") != values["Tested fingerprint"]:
                errors.append(f"rerun evidence identity or fingerprint mismatch: {match.group('run')}")
            if data.get("fresh_state") is not True or data.get("new_defects") != 0 or data.get("exit_code") != 0:
                errors.append(f"rerun must be fresh, successful, and have zero new defects: {match.group('run')}")
            if data.get("reviewer_agent") != values["Integrator agent"]:
                errors.append(f"rerun reviewer must be Integrator agent: {match.group('run')}")
            rerun_cases = data.get("cases")
            if (
                not isinstance(rerun_cases, list)
                or not all(isinstance(item, str) for item in rerun_cases)
                or len(rerun_cases) != len(set(rerun_cases))
                or rerun_cases != case_ids
            ):
                errors.append(f"rerun must include every mandatory Case ID: {match.group('run')}")
            runtime_id = data.get("runtime_id")
            image_digest = data.get("image_digest")
            if not isinstance(runtime_id, str) or not runtime_id:
                errors.append(f"rerun runtime_id must be a string: {match.group('run')}")
            else:
                runtime_ids.add(runtime_id)
            if not isinstance(image_digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_digest):
                errors.append(f"rerun image_digest must be a sha256 digest: {match.group('run')}")
            else:
                image_digests.add(image_digest)
            reset = data.get("state_reset_evidence")
            if not isinstance(reset, dict) or reset.get("exit_code") != 0 or reset.get("residual") != 0 or not reset.get("command") or reset.get("token") != data.get("fresh_state_token"):
                errors.append(f"rerun needs successful structured state reset evidence: {match.group('run')}")
            runtime_path_raw = data.get("runtime_evidence")
            runtime_hash = data.get("runtime_evidence_sha256")
            if not isinstance(runtime_path_raw, str) or not isinstance(runtime_hash, str):
                errors.append(f"rerun needs runtime evidence path and hash: {match.group('run')}")
            else:
                runtime_evidence_paths.add(runtime_path_raw)
                runtime_path = checked_evidence_path(runtime_path_raw, runtime_hash, root, errors)
                runtime = json_evidence(runtime_path, errors)
                if runtime is not None:
                    require_keys(runtime, ("schema", "tool", "tool_sha256", "candidate_sha256", "blueprint_sha256", "docker", "compose", "resolved_compose", "build", "loaded_image_id", "application_services", "candidate_services", "up", "containers", "health", "client", "logs", "source", "source_after", "namespace_preflight", "cleanup_command", "cleanup"), f"runtime {match.group('run')}", errors)
                    helper_path = Path(__file__).with_name("run_acceptance_runtime.py").resolve()
                    helper_hash = sha256(helper_path) if helper_path.is_file() else ""
                    if runtime.get("schema") != "run_acceptance_runtime/v2" or runtime.get("tool") != "run_acceptance_runtime" or runtime.get("tool_sha256") != helper_hash:
                        errors.append(f"runtime evidence schema/tool mismatch: {match.group('run')}")
                    if (
                        not isinstance(data.get("candidate_sha256"), str)
                        or re.fullmatch(r"[a-f0-9]{64}", data["candidate_sha256"]) is None
                        or runtime.get("candidate_sha256") != data.get("candidate_sha256")
                    ):
                        errors.append(f"runtime candidate fingerprint mismatch: {match.group('run')}")
                    if runtime.get("status") != "passed" or runtime.get("project") != runtime_id:
                        errors.append(f"runtime evidence status or id mismatch: {match.group('run')}")
                    namespace_preflight=runtime.get("namespace_preflight")
                    if not isinstance(namespace_preflight,dict) or any(namespace_preflight.get(kind)!=0 for kind in ("containers","networks","volumes","images")):
                        errors.append(f"runtime Docker namespace was not clean before mutation: {match.group('run')}")
                    cleanup=runtime.get("cleanup")
                    if (not isinstance(cleanup,dict) or any(cleanup.get(kind)!=0 for kind in ("containers","networks","volumes","images"))):
                        errors.append(f"runtime evidence cleanup failed: {match.group('run')}")
                    loaded_image_id=runtime.get("loaded_image_id")
                    candidate_services=runtime.get("candidate_services")
                    if (runtime.get("blueprint_sha256")!=blueprint_sha256
                            or runtime.get("application_services")!=blueprint_services
                            or candidate_services!=blueprint_services):
                        errors.append(f"runtime candidate services differ from exact confirmed Blueprint authority: {match.group('run')}")
                    containers=runtime.get("containers")
                    if loaded_image_id!=image_digest or not isinstance(loaded_image_id,str) or re.fullmatch(r"sha256:[a-f0-9]{64}",loaded_image_id) is None:
                        errors.append(f"runtime loaded candidate image mismatch: {match.group('run')}")
                    if (not isinstance(candidate_services,list) or not candidate_services
                            or candidate_services!=sorted(set(candidate_services))
                            or not all(isinstance(item,str) and item for item in candidate_services)):
                        errors.append(f"runtime candidate service authority is invalid: {match.group('run')}")
                        candidate_services=[]
                    if not isinstance(containers,list) or not containers or not all(isinstance(item,dict) for item in containers):
                        errors.append(f"runtime evidence container mismatch: {match.group('run')}")
                    else:
                        if any(item.get("status")!="running" or item.get("health")!="healthy" for item in containers):
                            errors.append(f"runtime evidence container mismatch: {match.group('run')}")
                        observed_candidate={item.get("service") for item in containers if item.get("image")==loaded_image_id}
                        governed=[item for item in containers if item.get("service") in candidate_services]
                        if observed_candidate!=set(candidate_services) or len(governed)!=len(candidate_services) or any(item.get("image")!=loaded_image_id for item in governed):
                            errors.append(f"runtime did not exercise exact loaded candidate services: {match.group('run')}")
                    client = runtime.get("client")
                    client_command = client.get("command") if isinstance(client, dict) else None
                    client_output = client.get("output") if isinstance(client, dict) else None
                    client_receipt = client.get("receipt") if isinstance(client, dict) else None
                    client_process_cleanup = client.get("process_cleanup") if isinstance(client, dict) else None
                    command_test_files = {item for item in client_command if isinstance(item, str) and item in approved_test_files} if isinstance(client_command, list) else set()
                    receipt_cases = client_receipt.get("case_ids") if isinstance(client_receipt, dict) else None
                    receipt_assertions = client_receipt.get("assertions") if isinstance(client_receipt, dict) else None
                    receipt_assertion_ids = [item.get("case_id") for item in receipt_assertions if isinstance(item, dict)] if isinstance(receipt_assertions, list) else []
                    if (
                        not isinstance(client, dict)
                        or not isinstance(client_command, list)
                        or not client_command
                        or not all(isinstance(item, str) and item for item in client_command)
                        or not command_test_files
                        or client.get("exit_code") != 0
                        or client.get("output_limit_exceeded") is not False
                        or client_process_cleanup != {"remaining": 0}
                        or not isinstance(client_output, dict)
                        or not re.fullmatch(r"[a-f0-9]{64}", str(client_output.get("sha256", "")))
                        or not isinstance(client_receipt, dict)
                        or client_receipt.get("schema") != "acceptance-client/v1"
                        or client_receipt.get("passed") is not True
                        or client_receipt.get("fresh_state_token") != data.get("fresh_state_token")
                        or not isinstance(client_receipt.get("state_reset"), dict)
                        or client_receipt["state_reset"].get("performed") is not True
                        or client_receipt["state_reset"].get("residual") != 0
                        or not isinstance(receipt_cases, list)
                        or len(receipt_cases) != len(set(receipt_cases))
                        or receipt_cases != case_ids
                        or not isinstance(receipt_assertions, list)
                        or len(receipt_assertions) < len(case_ids)
                        or len(receipt_assertion_ids) != len(set(receipt_assertion_ids))
                        or set(receipt_assertion_ids) != set(case_ids)
                        or any(not isinstance(item, dict) or item.get("passed") is not True or not isinstance(item.get("name"), str) or not item["name"].strip() for item in receipt_assertions)
                        or data.get("command") != client_command
                    ):
                        errors.append(f"runtime evidence lacks successful real client command: {match.group('run')}")
                    runtime_health = runtime.get("health")
                    if not isinstance(runtime_health, dict) or runtime_health.get("status") != 200:
                        errors.append(f"runtime evidence health probe is missing: {match.group('run')}")
                    source_after = runtime.get("source_after")
                    if not isinstance(source_after, dict) or not isinstance(runtime.get("source"), dict) or source_after.get("sha256") != runtime["source"].get("sha256"):
                        errors.append(f"runtime source changed during acceptance: {match.group('run')}")
                    if not isinstance(runtime.get("cleanup_command"), dict) or not runtime["cleanup_command"].get("sha256"):
                        errors.append(f"runtime cleanup command evidence is missing: {match.group('run')}")
                    for compact_name in ("resolved_compose", "build", "up", "logs", "cleanup_command"):
                        compact_value = runtime.get(compact_name)
                        if not isinstance(compact_value, dict) or not re.fullmatch(r"[a-f0-9]{64}", str(compact_value.get("sha256", ""))) or not isinstance(compact_value.get("line_count"), int) or not isinstance(compact_value.get("tail"), list):
                            errors.append(f"runtime bounded artifact is invalid: {compact_name} ({match.group('run')})")
                    source = runtime.get("source")
                    source_files = {item.get("path"): item.get("sha256") for item in source.get("files", []) if isinstance(item, dict)} if isinstance(source, dict) else {}
                    expected_manifest = manifest_entries(manifest_path)
                    if any(source_files.get(path) != expected_manifest.get(path) for path in runtime_required_files):
                        errors.append(f"runtime source fingerprint omits or mismatches tested scope: {match.group('run')}")
    if len(runtime_ids) != len(reruns):
        errors.append("each clean rerun needs a distinct runtime_id")
    if len(image_digests) != 1:
        errors.append("all clean reruns must use the same frozen image_digest")
    if len(runtime_evidence_paths) != len(reruns):
        errors.append("each clean rerun needs distinct runtime evidence")
    expected_runs = set(rerun_ids)
    for data in case_evidence_data:
        execution_runs = data.get("execution_run_ids")
        if (
            not isinstance(execution_runs, list)
            or len(execution_runs) != len(set(execution_runs))
            or set(execution_runs) != expected_runs
        ):
            errors.append(f"case evidence must bind to every clean rerun: {data.get('case_id')}")

    if values["AI recommendation"] != "release":
        errors.append("AI recommendation must be release")
    human = values["Human decision"]
    if args.draft:
        if human not in {"pending", "approved"}:
            errors.append("Human decision must be pending or approved in draft mode")
    elif human != "approved":
        errors.append("Human decision must be approved for the release gate")
    if human == "approved" and not values["Human decision source"].startswith("user:"):
        errors.append("approved Human decision source must start with 'user:'")

    if errors:
        print("INVALID acceptance report")
        for error in errors:
            print(f"- {error}")
        return 1
    print("VALID acceptance report contract" + (" draft" if args.draft else " approved"))
    return 0


if __name__ == "__main__":
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"scripts"))
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
