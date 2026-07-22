#!/usr/bin/env python3
"""Wrap one web/Docker integrator receipt; verify it without rerunning anything."""

from pathlib import Path
import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from typing import Dict, List, Tuple

import run_workflow_release_gate as common


ROOT = common.ROOT
AGENT = ROOT / ".agent"
RERUN_RE = re.compile(
    r"^- Rerun: (?P<run>RUN-[A-Za-z0-9_-]+) \| Evidence: (?P<path>[^|]+?) "
    r"\| SHA-256: (?P<sha>[a-f0-9]{64})\s*$", re.MULTILINE,
)
RUNNER_KEYS = {"schema", "adapter", "execution_profile", "preflight_commands", "client_profile"}
GATE_KEYS = {
    "schema", "adapter_id", "status", "failure_class", "started_at", "finished_at",
    "runner", "gate_tool", "candidate_fingerprint", "execution_profile",
    "preflight_receipt", "report", "integrator_receipt", "integrator_run_id",
    "required_clean_reruns", "zero_residual_runtime", "runtime_assertion",
}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load(path: Path, label: str) -> Dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid {label}: {error}")
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be an object")
    return value


def file_record(path: Path, label: str) -> Dict[str, object]:
    resolved = path.resolve()
    try:
        relative = str(resolved.relative_to(ROOT))
    except ValueError:
        raise SystemExit(f"{label} escapes project")
    if not resolved.is_file() or resolved.is_symlink():
        raise SystemExit(f"{label} is missing or unsafe")
    data = resolved.read_bytes()
    return {"path": relative, "sha256": digest(data), "bytes": len(data)}


def runner_contract(path: Path) -> Tuple[Dict[str, object], List[Tuple[str, List[str], int]], str]:
    value = load(path, "web/Docker runner")
    if set(value) != RUNNER_KEYS or value.get("schema") != "acceptance-runner/v2" or value.get("adapter") != "web-docker":
        raise SystemExit("web/Docker runner schema/adapter is invalid")
    profile = value.get("execution_profile")
    if (
        not isinstance(profile, dict) or set(profile) != common.PROFILE_KEYS
        or profile.get("environment") not in {"local", "test"}
        or profile.get("authority") not in {"default", "elevated", "remote-test"}
        or not isinstance(profile.get("capabilities"), list) or not profile["capabilities"]
    ):
        raise SystemExit("web/Docker execution_profile is invalid")
    preflight_raw = value.get("preflight_commands")
    if not isinstance(preflight_raw, list) or not preflight_raw:
        raise SystemExit("web/Docker runner requires preflight commands")
    preflight = [common.clean_command(item, f"preflight {index}", 30) for index, item in enumerate(preflight_raw)]
    if sum(item[2] for item in preflight) > 60:
        raise SystemExit("web/Docker preflight timeout budget exceeds 60 seconds")
    if profile["capabilities"] != [item[0] for item in preflight]:
        raise SystemExit("web/Docker profile capabilities differ from preflight commands")
    client_profile = value.get("client_profile")
    if not isinstance(client_profile, str) or not client_profile:
        raise SystemExit("web/Docker client profile is missing")
    file_record(ROOT / client_profile, "web/Docker client profile")
    return profile, preflight, client_profile


def report_integrator(report: Path, candidate_sha256: str) -> Tuple[Dict[str, object], str]:
    report_record = file_record(report, "acceptance report")
    validator = Path(__file__).with_name("validate_acceptance_report.py").resolve()
    result = subprocess.run(
        [sys.executable, str(validator), str(report), "--draft"], cwd=ROOT,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
    )
    if result.returncode or file_record(report, "acceptance report") != report_record:
        raise SystemExit("acceptance report is invalid or changed during read-only validation:\n" + result.stdout)
    text = report.read_text(encoding="utf-8")
    reruns = list(RERUN_RE.finditer(text))
    if len(reruns) != 1:
        raise SystemExit("acceptance report must bind exactly one integrator rerun")
    match = reruns[0]
    path = (ROOT / match.group("path").strip()).resolve()
    record = file_record(path, "integrator receipt")
    if record["sha256"] != match.group("sha"):
        raise SystemExit("integrator receipt differs from the acceptance report")
    value = load(path, "integrator receipt")
    if (
        value.get("run_id") != match.group("run") or value.get("fresh_state") is not True
        or value.get("exit_code") != 0 or value.get("candidate_sha256") != candidate_sha256
    ):
        raise SystemExit("integrator receipt does not prove one successful fresh-state run")
    return {"report": report_record, "integrator": record}, match.group("run")


def preflight_gate(runner_raw: str, receipt_raw: str, environment: str,
                   authority: str, candidate_sha256: str) -> int:
    runner_path, _ = common.project_file(runner_raw, "runner")
    profile, commands, _ = runner_contract(runner_path)
    config = load(AGENT / "config.json", "config")
    fingerprint = common.candidate_fingerprint(config)
    if candidate_sha256 != fingerprint:
        raise SystemExit("preflight candidate SHA-256 differs from the current candidate")
    if environment != profile["environment"] or authority != profile["authority"]:
        raise SystemExit("preflight authority/environment differs from runner execution_profile")
    target = (ROOT / receipt_raw).resolve()
    try:
        target.relative_to(ROOT)
    except ValueError:
        raise SystemExit("preflight receipt escapes project")
    if target.is_symlink():
        raise SystemExit("preflight receipt may not be a symlink")
    observed = common.utc_now()
    checks = []
    passed = True
    for command_id, argv, timeout in commands:
        result = common.execute(argv, timeout, "preflight", profile)
        ok = result["exit_code"] == 0 and result["process_cleanup"] == {"remaining": 0}
        checks.append({
            "capability": command_id, "status": "passed" if ok else "failed",
            "evidence": f"sha256:{result['output_sha256']}",
        })
        if not ok:
            passed = False
            break
    value = {
        "schema": "agent-execution-preflight/v1", "environment": environment,
        "authority": authority, "candidate_sha256": candidate_sha256,
        "observed_at": observed.isoformat(),
        "expires_at": (observed + dt.timedelta(minutes=15)).isoformat(),
        "status": "passed" if passed and len(checks) == len(commands) else "failed",
        "capabilities": [item[0] for item in commands], "checks": checks,
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(("VALID" if value["status"] == "passed" else "INVALID") + f" execution preflight: {target.relative_to(ROOT)}")
    return 0 if value["status"] == "passed" else 1


def run_gate(runner_raw: str, receipt_raw: str, preflight_raw: str, report_raw: str) -> int:
    runner_path, runner_record = common.project_file(runner_raw, "runner")
    profile, _, configured_client = runner_contract(runner_path)
    config = load(AGENT / "config.json", "config")
    if int(config.get("routing", {}).get("modes", {}).get("release", {}).get("clean_reruns", 0)) != 1:
        raise SystemExit("release clean_reruns must be exactly 1")
    fingerprint = common.candidate_fingerprint(config)
    preflight_path, preflight_record = common.project_file(preflight_raw, "execution preflight")
    try:
        common.validate_preflight(load(preflight_path, "execution preflight"), profile, fingerprint)
    except ValueError as error:
        raise SystemExit(str(error))
    report = (ROOT / report_raw).resolve()
    evidence, run_id = report_integrator(report, fingerprint)
    report_profile = config.get("acceptance", {}).get("client_profile") if isinstance(config.get("acceptance"), dict) else None
    if configured_client != report_profile:
        raise SystemExit("runner client profile differs from the configured acceptance client")
    clean, assertion = common.runtime_assert_clean()
    started = now()
    tool = file_record(Path(__file__), "live gate tool")
    value = {
        "schema": "acceptance-live-gate/v2", "adapter_id": "acceptance-web-docker",
        "status": "passed" if clean else "blocked", "failure_class": None if clean else "infrastructure",
        "started_at": started, "finished_at": now(), "runner": runner_record,
        "gate_tool": tool, "candidate_fingerprint": fingerprint, "execution_profile": profile,
        "preflight_receipt": preflight_record, "report": evidence["report"],
        "integrator_receipt": evidence["integrator"], "integrator_run_id": run_id,
        "required_clean_reruns": 1, "zero_residual_runtime": clean, "runtime_assertion": assertion,
    }
    target = (ROOT / receipt_raw).resolve()
    try:
        target.relative_to(ROOT)
    except ValueError:
        raise SystemExit("live gate receipt escapes project")
    if target.is_symlink():
        raise SystemExit("live gate receipt may not be a symlink")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not clean:
        print("INVALID web/Docker release gate: current runtime is not clean")
        return 1
    print(f"VALID web/Docker release gate: {target.relative_to(ROOT)}")
    return 0


def verify_gate(runner_raw: str, receipt_raw: str) -> int:
    errors: List[str] = []
    runner_path, runner_record = common.project_file(runner_raw, "runner")
    profile, _, _ = runner_contract(runner_path)
    receipt_path, _ = common.project_file(receipt_raw, "live gate receipt")
    value = load(receipt_path, "live gate receipt")
    config = load(AGENT / "config.json", "config")
    fingerprint = common.candidate_fingerprint(config)
    if (
        set(value) != GATE_KEYS or value.get("schema") != "acceptance-live-gate/v2"
        or value.get("adapter_id") != "acceptance-web-docker"
        or value.get("status") != "passed" or value.get("failure_class") is not None
    ):
        errors.append("receipt schema, adapter or status is invalid")
    if value.get("runner") != runner_record or value.get("execution_profile") != profile:
        errors.append("receipt runner/profile binding drifted")
    if value.get("candidate_fingerprint") != fingerprint:
        errors.append("receipt candidate fingerprint is stale")
    if value.get("gate_tool") != file_record(Path(__file__), "live gate tool"):
        errors.append("receipt gate tool drifted")
    try:
        preflight_path = common.receipt_path(value.get("preflight_receipt"), "execution preflight")
        common.validate_preflight(load(preflight_path, "execution preflight"), profile, fingerprint)
    except (SystemExit, ValueError) as error:
        errors.append(str(error))
    try:
        report_path = common.receipt_path(value.get("report"), "acceptance report")
        evidence, run_id = report_integrator(report_path, fingerprint)
        if value.get("integrator_receipt") != evidence["integrator"] or value.get("integrator_run_id") != run_id:
            errors.append("receipt is not bound to the report's unique integrator run")
    except (SystemExit, ValueError) as error:
        errors.append(str(error))
    assertion = value.get("runtime_assertion")
    agentctl_record = file_record(AGENT / "scripts/agentctl.py", "agentctl")
    if (
        not isinstance(assertion, dict) or assertion.get("mode") != "baseline-delta-assert-clean"
        or assertion.get("tool") != agentctl_record or assertion.get("exit_code") != 0
    ):
        errors.append("recorded runtime assertion is invalid")
    if value.get("required_clean_reruns") != 1 or value.get("zero_residual_runtime") is not True:
        errors.append("receipt does not prove the one integrator run and clean runtime")
    clean, _ = common.runtime_assert_clean()
    if not clean:
        errors.append("current agentctl baseline-delta assertion is not clean")
    if errors:
        print("INVALID web/Docker release gate receipt")
        for error in errors:
            print(f"- {error}")
        return 1
    print("VALID web/Docker release gate receipt")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--runner", required=True)
    preflight.add_argument("--receipt", required=True)
    preflight.add_argument("--environment", choices=("local", "test"), required=True)
    preflight.add_argument("--authority", choices=("default", "elevated", "remote-test"), required=True)
    preflight.add_argument("--candidate-sha256", required=True)
    run = sub.add_parser("run")
    run.add_argument("--runner", required=True)
    run.add_argument("--receipt", required=True)
    run.add_argument("--preflight-receipt", required=True)
    run.add_argument("--report", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--runner", required=True)
    verify.add_argument("--receipt", required=True)
    args = parser.parse_args()
    if args.command == "preflight":
        return preflight_gate(args.runner, args.receipt, args.environment, args.authority, args.candidate_sha256)
    if args.command == "run":
        return run_gate(args.runner, args.receipt, args.preflight_receipt, args.report)
    return verify_gate(args.runner, args.receipt)


if __name__ == "__main__":
    raise SystemExit(main())
