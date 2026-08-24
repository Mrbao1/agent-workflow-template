#!/usr/bin/env python3
"""Plan, run, and verify a confirmed blueprint acceptance contract."""
from pathlib import Path
import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys

from adaptive_common import (
    AdaptiveError, acceptance_method, canonical_sha256, fail, load_blueprint,
    load_json, record_provider_human_decision, resolve_root, safe_relative_path, utc_now,
    verify_provider_human_decision, write_json,
)

PREFLIGHT_SCHEMA = "agent-blueprint-acceptance-preflight/v2"
RECEIPT_SCHEMA = "agent-blueprint-acceptance/v2"
INTEGRATOR_SCHEMA = "agent-blueprint-integrator-evidence/v1"
HEX = set("0123456789abcdef")


def digest_ok(value):
    return isinstance(value, str) and len(value) == 64 and not (set(value) - HEX)


def parse_time(value, label):
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise AdaptiveError("INVALID_ACCEPTANCE_TIME", f"{label} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise AdaptiveError("INVALID_ACCEPTANCE_TIME", f"{label} timestamp lacks timezone")
    return parsed


def regular_bytes(root, value, label, maximum=2 * 1024 * 1024):
    supplied = Path(value)
    unresolved = root / supplied if not supplied.is_absolute() else supplied
    try:
        observed = os.lstat(unresolved)
    except OSError as error:
        raise AdaptiveError("UNSAFE_ACCEPTANCE_PATH", f"{label} is unavailable") from error
    if stat.S_ISLNK(observed.st_mode):
        raise AdaptiveError("UNSAFE_ACCEPTANCE_PATH", f"{label} must not be a symlink")
    path = unresolved.resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise AdaptiveError("UNSAFE_ACCEPTANCE_PATH", f"{label} escapes the project") from error
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1 or observed.st_size > maximum:
        raise AdaptiveError("UNSAFE_ACCEPTANCE_PATH", f"{label} is not one bounded single-link regular file")
    flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino) or opened.st_nlink != 1:
            raise AdaptiveError("UNSAFE_ACCEPTANCE_PATH", f"{label} changed while opening")
        raw = b""
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(descriptor)
    if len(raw) > maximum:
        raise AdaptiveError("UNSAFE_ACCEPTANCE_PATH", f"{label} exceeds its byte limit")
    return path, str(relative), raw


def json_bytes(root, value, label, maximum=2 * 1024 * 1024):
    path, relative, raw = regular_bytes(root, value, label, maximum)
    try:
        parsed = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AdaptiveError("INVALID_ACCEPTANCE_JSON", f"{label} is not valid JSON") from error
    return path, relative, raw, parsed


def output_path(root, value):
    return root / safe_relative_path(value)


def acceptance_contract(blueprint):
    records = blueprint["design"]["acceptance"]
    executable_ids = {item["id"] for item in records if acceptance_method(item) == "executable"}
    commands = [item for item in blueprint["design"]["commands"] if item["stage"] in {"acceptance", "ci"}]
    covered = {value for item in commands for value in item["covers"]}
    if covered != executable_ids:
        raise AdaptiveError("INCOMPLETE_ACCEPTANCE", "executable acceptance coverage differs from the confirmed contract")
    non_executable = [{"id": item["id"], "method": acceptance_method(item)} for item in records if acceptance_method(item) != "executable"]
    return commands, non_executable


def runner_binding(root, runner):
    path, relative, raw = regular_bytes(root, runner, "blueprint runner")
    if path != (root / ".agent/project/BLUEPRINT.json").resolve():
        raise AdaptiveError("INVALID_ACCEPTANCE_RUNNER", "runner must be the authoritative project blueprint")
    return relative, hashlib.sha256(raw).hexdigest()


def verified_skills_lock(root, blueprint):
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "skillctl.py"), "--root", str(root), "verify"],
        cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=60,
    )
    if result.returncode:
        raise AdaptiveError("INVALID_ACCEPTANCE_SKILLS", "dynamic Skill lock, reviewed capability coverage, or active bytes failed verification")
    path = root / ".agent/project/skills.lock.json"
    if not path.exists():
        if blueprint["design"]["capabilities"]:
            raise AdaptiveError("INVALID_ACCEPTANCE_SKILLS", "confirmed capabilities require a Skill lock")
        return None
    lock = load_json(path, "Skills lock")
    digest = lock.get("lock_sha256") if isinstance(lock, dict) else None
    if not digest_ok(digest) or lock.get("blueprint_sha256") != blueprint["confirmation"]["design_sha256"]:
        raise AdaptiveError("INVALID_ACCEPTANCE_SKILLS", "Skill lock does not bind the confirmed blueprint")
    return digest


def command_records(commands):
    return [{"id": item["id"], "argv_sha256": canonical_sha256(item["argv"]),
             "covers": item["covers"], "environment": item.get("environment", [])} for item in commands]


def executable_probe(root, command):
    executable = command["argv"][0]
    if "/" in executable:
        candidate = (root / executable).resolve() if not Path(executable).is_absolute() else Path(executable).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as error:
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE", f"command {command['id']} executable escapes the project") from error
        available = candidate.is_file() and not candidate.is_symlink() and os.access(candidate, os.X_OK)
        resolved = str(candidate.relative_to(root)) if available else None
    else:
        inherited_path = os.environ.get("PATH") if "PATH" in command.get("environment", []) else None
        resolved = shutil.which(executable, path=inherited_path or os.defpath)
        available = resolved is not None
    if not available:
        raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE", f"command {command['id']} executable is unavailable in its declared environment")
    return {"id": command["id"], "available": True, "resolved_sha256": hashlib.sha256(str(resolved).encode()).hexdigest()}


def load_preflight(root, path, blueprint, runner_sha256, skills_lock_sha256, expected):
    _, _, _, value = json_bytes(root, path, "acceptance preflight")
    required = {"schema", "environment", "authority", "candidate_sha256", "blueprint_sha256", "skills_lock_sha256",
                "runner_sha256", "commands", "probes", "observed_at", "expires_at", "status", "preflight_sha256"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != PREFLIGHT_SCHEMA:
        raise AdaptiveError("INVALID_ACCEPTANCE_PREFLIGHT", "preflight fields are invalid")
    payload = {key: value[key] for key in value if key != "preflight_sha256"}
    if value["preflight_sha256"] != canonical_sha256(payload):
        raise AdaptiveError("INVALID_ACCEPTANCE_PREFLIGHT", "preflight digest drifted")
    now = dt.datetime.now(dt.timezone.utc)
    observed, expires = parse_time(value["observed_at"], "preflight observed"), parse_time(value["expires_at"], "preflight expiry")
    if expires <= observed or expires - observed > dt.timedelta(hours=1) or now > expires or observed > now + dt.timedelta(minutes=1):
        raise AdaptiveError("STALE_ACCEPTANCE_PREFLIGHT", "acceptance preflight is stale or has invalid bounds")
    commands, _ = acceptance_contract(blueprint)
    if (value["status"] != "ready" or value["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"]
            or value["skills_lock_sha256"] != skills_lock_sha256 or value["runner_sha256"] != runner_sha256
            or value["commands"] != command_records(commands)
            or any(set(item) != {"id", "available", "resolved_sha256"} or item["available"] is not True or not digest_ok(item["resolved_sha256"]) for item in value["probes"])
            or [item["id"] for item in value["probes"]] != [item["id"] for item in commands]):
        raise AdaptiveError("INVALID_ACCEPTANCE_PREFLIGHT", "preflight no longer binds verified acceptance prerequisites")
    for key in ("candidate_sha256", "environment", "authority"):
        if value[key] != expected[key]:
            raise AdaptiveError("ACCEPTANCE_CANDIDATE_DRIFT", f"preflight {key} differs from the current release candidate")
    return value


def load_integrator(root, path, blueprint, skills_lock_sha256, expected, non_executable):
    _, relative, raw, value = json_bytes(root, path, "integrator evidence")
    required = {"schema", "candidate_sha256", "blueprint_sha256", "skills_lock_sha256", "environment", "authority",
                "integrator_id", "acceptance", "evidence", "recorded_at", "expires_at", "status", "receipt_sha256"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != INTEGRATOR_SCHEMA:
        raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", "integrator evidence fields are invalid")
    payload = {key: value[key] for key in value if key != "receipt_sha256"}
    if value["receipt_sha256"] != canonical_sha256(payload):
        raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", "integrator evidence digest drifted")
    now = dt.datetime.now(dt.timezone.utc)
    recorded, expires = parse_time(value["recorded_at"], "integrator recorded"), parse_time(value["expires_at"], "integrator expiry")
    if expires <= recorded or expires - recorded > dt.timedelta(hours=24) or now > expires or recorded > now + dt.timedelta(minutes=1):
        raise AdaptiveError("STALE_INTEGRATOR_EVIDENCE", "integrator evidence is stale or has invalid bounds")
    expected_acceptance = [{**item, "status": "passed"} for item in non_executable]
    if (value["status"] != "passed" or value["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"]
            or value["skills_lock_sha256"] != skills_lock_sha256 or value["acceptance"] != expected_acceptance
            or not isinstance(value["integrator_id"], str) or not value["integrator_id"]
            or any(value[key] != expected[key] for key in ("candidate_sha256", "environment", "authority"))):
        raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", "integrator evidence does not bind the current candidate and acceptance contract")
    evidence = value["evidence"]
    if not isinstance(evidence, list) or len(evidence) > 64:
        raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", "integrator evidence inventory is invalid")
    covered = set()
    for index, record in enumerate(evidence):
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes", "acceptance_ids"}:
            raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", f"integrator evidence[{index}] fields are invalid")
        _, evidence_relative, evidence_raw = regular_bytes(root, record["path"], f"integrator evidence[{index}]")
        ids = record["acceptance_ids"]
        if (record["path"] != evidence_relative or record["bytes"] != len(evidence_raw)
                or record["sha256"] != hashlib.sha256(evidence_raw).hexdigest()
                or not isinstance(ids, list) or not ids or len(ids) != len(set(ids))):
            raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", f"integrator evidence[{index}] bytes or coverage drifted")
        covered.update(ids)
    required_ids = {item["id"] for item in non_executable}
    if covered != required_ids or (required_ids and not evidence):
        raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", "manual/evidence acceptance lacks exact evidence coverage")
    return relative, raw, value


def integrator_file_record(relative, raw):
    return {"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def manual_approval_action(blueprint, expected, skills_lock_sha256, preflight, integrator_relative, integrator_raw, integrator, non_executable):
    manual_ids = sorted(item["id"] for item in non_executable if item["method"] == "manual")
    evidence = [record for record in integrator["evidence"] if set(record["acceptance_ids"]) & set(manual_ids)]
    return {
        "schema": "agent-blueprint-manual-acceptance-action/v1",
        "candidate_sha256": expected["candidate_sha256"], "environment": expected["environment"], "authority": expected["authority"],
        "blueprint_sha256": blueprint["confirmation"]["design_sha256"], "skills_lock_sha256": skills_lock_sha256,
        "preflight_sha256": preflight["preflight_sha256"], "integrator_evidence": integrator_file_record(integrator_relative, integrator_raw),
        "integrator_receipt_sha256": integrator["receipt_sha256"], "manual_acceptance_ids": manual_ids, "evidence": evidence,
    }


def manual_decision(root, args, action):
    if not action["manual_acceptance_ids"]:
        return None
    digest = canonical_sha256(action)
    if args.plan:
        print(json.dumps({"schema": "agent-blueprint-manual-acceptance-approval/v1", "payload": action,
                          "approval_sha256": digest, "mutation": False}, sort_keys=True))
        return "planned"
    if args.manual_approve_digest != digest:
        raise AdaptiveError("MANUAL_ACCEPTANCE_APPROVAL_REQUIRED", f"approve the exact manual acceptance action digest: {digest}")
    receipt = record_provider_human_decision(root, gate="adaptive-blueprint-manual-acceptance", artifact_sha256=digest,
                                    source=args.manual_decision_source, receipt=args.manual_decision_receipt)
    return {"action": action, "action_sha256": digest, "source": args.manual_decision_source, "receipt": receipt}


def command_preflight(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    runner_relative, runner_sha256 = runner_binding(root, args.runner)
    skills_lock_sha256 = verified_skills_lock(root, blueprint)
    commands, _ = acceptance_contract(blueprint)
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "schema": PREFLIGHT_SCHEMA, "environment": args.environment, "authority": args.authority,
        "candidate_sha256": args.candidate_sha256, "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
        "skills_lock_sha256": skills_lock_sha256, "runner_sha256": runner_sha256,
        "commands": command_records(commands), "probes": [executable_probe(root, item) for item in commands],
        "observed_at": now.isoformat(), "expires_at": (now + dt.timedelta(hours=1)).isoformat(), "status": "ready",
    }
    value = {**payload, "preflight_sha256": canonical_sha256(payload)}
    write_json(output_path(root, args.receipt), value)
    print("VALID blueprint acceptance preflight")
    return 0


def execute_commands(root, blueprint, commands):
    results = []
    for command in commands:
        try:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve().parent / "blueprintctl.py"), "--root", str(root), "run-command",
                 "--id", command["id"], "--stage", command["stage"], "--expect-design-sha256", blueprint["confirmation"]["design_sha256"]],
                cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=command["timeout_seconds"] + 5,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AdaptiveError("ACCEPTANCE_COMMAND_FAILED", f"acceptance command did not complete under the canonical runner: {command['id']}") from error
        record = {"id": command["id"], "argv_sha256": canonical_sha256(command["argv"]),
                  "covers": command["covers"], "environment": command.get("environment", []), "exit_code": result.returncode}
        results.append(record)
        if result.returncode:
            raise AdaptiveError("ACCEPTANCE_COMMAND_FAILED", f"acceptance command failed during runner-owned execution: {command['id']}")
    return results


def command_run(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    runner_relative, runner_sha256 = runner_binding(root, args.runner)
    skills_lock_sha256 = verified_skills_lock(root, blueprint)
    expected = {"candidate_sha256": args.candidate_sha256, "environment": args.environment, "authority": args.authority}
    preflight = load_preflight(root, args.preflight_receipt, blueprint, runner_sha256, skills_lock_sha256, expected)
    commands, non_executable = acceptance_contract(blueprint)
    integrator_relative, integrator_raw, integrator = load_integrator(root, args.integrator_receipt, blueprint, skills_lock_sha256, expected, non_executable)
    action = manual_approval_action(blueprint, expected, skills_lock_sha256, preflight, integrator_relative, integrator_raw, integrator, non_executable)
    decision = manual_decision(root, args, action)
    if decision == "planned":
        return 0
    if args.plan:
        print(json.dumps({"schema": "agent-blueprint-manual-acceptance-approval/v1", "payload": None,
                          "approval_sha256": None, "mutation": False, "manual_approval_required": False}, sort_keys=True))
        return 0
    results = execute_commands(root, blueprint, commands)
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "schema": RECEIPT_SCHEMA, "candidate_sha256": args.candidate_sha256, "environment": args.environment,
        "authority": args.authority, "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
        "skills_lock_sha256": skills_lock_sha256, "runner_path": runner_relative, "runner_sha256": runner_sha256,
        "preflight_path": str(safe_relative_path(args.preflight_receipt)), "preflight_sha256": preflight["preflight_sha256"],
        "integrator_path": integrator_relative, "integrator_sha256": hashlib.sha256(integrator_raw).hexdigest(),
        "integrator_evidence": integrator_file_record(integrator_relative, integrator_raw),
        "integrator_receipt_sha256": integrator["receipt_sha256"], "integrator_id": integrator["integrator_id"],
        "requires_integrator_ledger_binding": True, "manual_decision": decision, "results": results,
        "acceptance": [{"id": item["id"], "method": acceptance_method(item), "status": "passed"} for item in blueprint["design"]["acceptance"]],
        "recorded_at": now.isoformat(), "expires_at": (now + dt.timedelta(hours=24)).isoformat(), "status": "passed",
    }
    value = {**payload, "receipt_sha256": canonical_sha256(payload)}
    write_json(output_path(root, args.receipt), value)
    print("VALID blueprint acceptance receipt")
    return 0


def command_verify(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    runner_relative, runner_sha256 = runner_binding(root, args.runner)
    skills_lock_sha256 = verified_skills_lock(root, blueprint)
    _, _, _, value = json_bytes(root, args.receipt, "acceptance receipt")
    required = {"schema", "candidate_sha256", "environment", "authority", "blueprint_sha256", "skills_lock_sha256",
                "runner_path", "runner_sha256", "preflight_path", "preflight_sha256", "integrator_path", "integrator_sha256",
                "integrator_evidence", "integrator_receipt_sha256", "integrator_id", "requires_integrator_ledger_binding",
                "manual_decision", "results", "acceptance", "recorded_at", "expires_at", "status", "receipt_sha256"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != RECEIPT_SCHEMA:
        raise AdaptiveError("INVALID_ACCEPTANCE_RECEIPT", "acceptance receipt fields are invalid")
    payload = {key: value[key] for key in value if key != "receipt_sha256"}
    if value["receipt_sha256"] != canonical_sha256(payload):
        raise AdaptiveError("INVALID_ACCEPTANCE_RECEIPT", "acceptance receipt digest drifted")
    expected_candidate = args.candidate_sha256 or value["candidate_sha256"]
    expected = {"candidate_sha256": expected_candidate, "environment": value["environment"], "authority": value["authority"]}
    preflight = load_preflight(root, value["preflight_path"], blueprint, runner_sha256, skills_lock_sha256, expected)
    commands, non_executable = acceptance_contract(blueprint)
    integrator_relative, integrator_raw, integrator = load_integrator(root, value["integrator_path"], blueprint, skills_lock_sha256, expected, non_executable)
    action = manual_approval_action(blueprint, expected, skills_lock_sha256, preflight, integrator_relative, integrator_raw, integrator, non_executable)
    manual_ids = action["manual_acceptance_ids"]
    decision = value["manual_decision"]
    if manual_ids:
        if (not isinstance(decision, dict) or set(decision) != {"action", "action_sha256", "source", "receipt"}
                or decision["action"] != action or decision["action_sha256"] != canonical_sha256(action)):
            raise AdaptiveError("INVALID_MANUAL_ACCEPTANCE_DECISION", "manual acceptance decision does not bind exact evidence")
        verify_provider_human_decision(root, gate="adaptive-blueprint-manual-acceptance", artifact_sha256=decision["action_sha256"],
                              source=decision["source"], record=decision["receipt"])
    elif decision is not None:
        raise AdaptiveError("INVALID_MANUAL_ACCEPTANCE_DECISION", "manual acceptance decision exists without manual criteria")
    expected_results = [{"id": item["id"], "argv_sha256": canonical_sha256(item["argv"]), "covers": item["covers"],
                         "environment": item.get("environment", []), "exit_code": 0} for item in commands]
    expected_acceptance = [{"id": item["id"], "method": acceptance_method(item), "status": "passed"} for item in blueprint["design"]["acceptance"]]
    now = dt.datetime.now(dt.timezone.utc)
    recorded, expires = parse_time(value["recorded_at"], "acceptance recorded"), parse_time(value["expires_at"], "acceptance expiry")
    if expires <= recorded or expires - recorded > dt.timedelta(hours=24) or now > expires or recorded > now + dt.timedelta(minutes=1):
        raise AdaptiveError("STALE_ACCEPTANCE_RECEIPT", "acceptance receipt is stale or has invalid bounds")
    if (value["status"] != "passed" or not digest_ok(value["candidate_sha256"]) or value["candidate_sha256"] != expected_candidate
            or value["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"] or value["skills_lock_sha256"] != skills_lock_sha256
            or value["runner_path"] != runner_relative or value["runner_sha256"] != runner_sha256
            or value["preflight_sha256"] != preflight["preflight_sha256"] or value["integrator_path"] != integrator_relative
            or value["integrator_sha256"] != hashlib.sha256(integrator_raw).hexdigest()
            or value["integrator_evidence"] != integrator_file_record(integrator_relative, integrator_raw)
            or value["requires_integrator_ledger_binding"] is not True
            or value["integrator_receipt_sha256"] != integrator["receipt_sha256"] or value["integrator_id"] != integrator["integrator_id"]
            or value["results"] != expected_results or value["acceptance"] != expected_acceptance):
        raise AdaptiveError("INVALID_ACCEPTANCE_RECEIPT", "acceptance receipt no longer binds current candidate, commands, Skills, and evidence")
    replayed_results = execute_commands(root, blueprint, commands)
    if replayed_results != value["results"]:
        raise AdaptiveError("INVALID_ACCEPTANCE_EXECUTION", "runner-owned command replay differs from the stored result", 3)
    print("VALID blueprint acceptance receipt")
    return 0


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--root")
    sub = value.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("preflight"); preflight.add_argument("--runner", required=True); preflight.add_argument("--receipt", required=True)
    preflight.add_argument("--environment", choices=("local", "test"), required=True); preflight.add_argument("--authority", choices=("default", "elevated", "remote-test"), required=True)
    preflight.add_argument("--candidate-sha256", required=True)
    run = sub.add_parser("run"); run.add_argument("--runner", required=True); run.add_argument("--receipt", required=True)
    run.add_argument("--integrator-receipt", required=True); run.add_argument("--preflight-receipt", required=True)
    run.add_argument("--environment", choices=("local", "test"), required=True); run.add_argument("--authority", choices=("default", "elevated", "remote-test"), required=True)
    run.add_argument("--candidate-sha256", required=True); run.add_argument("--plan", action="store_true")
    run.add_argument("--manual-approve-digest"); run.add_argument("--manual-decision-source"); run.add_argument("--manual-decision-receipt")
    verify = sub.add_parser("verify"); verify.add_argument("--runner", required=True); verify.add_argument("--receipt", required=True)
    verify.add_argument("--candidate-sha256")
    return value


def main():
    args = parser().parse_args()
    try:
        root = resolve_root(args.root, __file__)
        candidate = getattr(args, "candidate_sha256", None)
        if candidate is not None and not digest_ok(candidate):
            raise AdaptiveError("INVALID_CANDIDATE_DIGEST", "candidate SHA-256 must be full lowercase hex")
        return {"preflight": command_preflight, "run": command_run, "verify": command_verify}[args.command](root, args)
    except Exception as error:
        return fail(error)


if __name__ == "__main__":
    raise SystemExit(main())
