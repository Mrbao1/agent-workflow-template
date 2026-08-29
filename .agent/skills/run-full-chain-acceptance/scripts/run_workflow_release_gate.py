#!/usr/bin/env python3
"""Verify one integrator replay and a fresh execution preflight for workflow releases."""

from pathlib import Path
import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import time
import uuid
from typing import Dict, List, Optional, Tuple


def find_root() -> Path:
    for candidate in (Path.cwd().resolve(), *Path.cwd().resolve().parents):
        if (candidate / ".agent").is_dir():
            return candidate
    raise SystemExit(".agent directory not found")


ROOT = find_root()
AGENT = ROOT / ".agent"
sys.path.insert(0, str(AGENT / "scripts"))
import testrun as supervised_test
from workflowlib import boundedio
import ios_simulator_gate

RUN_ID = re.compile(r"[0-9a-f]{32}")
TEST_EXECUTION_BOUNDARY = supervised_test.TEST_EXECUTION_BOUNDARY
PROFILE_KEYS = {"environment", "authority", "capabilities"}
ADAPTER_IDS = {
    "workflow": "acceptance-workflow",
    "api": "acceptance-api",
    "cli": "acceptance-cli",
    "ios-simulator": "acceptance-ios",
}
GATE_SCHEMAS = {
    "workflow": "workflow-release-gate/v4",
    "api": "local-command-release-gate/v1",
    "cli": "local-command-release-gate/v1",
    "ios-simulator": "local-command-release-gate/v1",
}
PREFLIGHT_KEYS = {
    "schema", "environment", "authority", "candidate_sha256", "observed_at",
    "expires_at", "status", "capabilities", "checks",
}
GATE_KEYS = {
    "schema", "adapter_id", "status", "failure_class", "started_at", "finished_at",
    "runner", "gate_tool", "candidate_fingerprint", "execution_profile",
    "preflight_receipt", "integrator_test_receipt", "integrator_run_id",
    "command_plan_sha256", "required_clean_reruns",
    "zero_residual_runtime", "runtime_assertion", "ios_simulator_cleanup",
    "ios_simulator_reset_evidence",
}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def now() -> str:
    return utc_now().isoformat()


def parse_time(raw: object, label: str) -> dt.datetime:
    if not isinstance(raw, str):
        raise ValueError(f"{label} timestamp is missing")
    value = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError(f"{label} timestamp lacks timezone")
    return value.astimezone(dt.timezone.utc)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


MAX_PROJECT_FILE_BYTES = 16 * 1024 * 1024


def bounded_file_bytes(path: Path,label: str,limit: int=MAX_PROJECT_FILE_BYTES) -> bytes:
    try: return boundedio.read_bytes(path,maximum=limit,label=label)
    except RuntimeError as error: raise ValueError(str(error)) from error


def project_file(raw: str, label: str) -> Tuple[Path, Dict[str, object]]:
    path=Path(os.path.abspath(str(ROOT/raw)))
    try: relative_path=path.relative_to(ROOT)
    except ValueError: raise SystemExit(f"{label} escapes project")
    current=ROOT
    try:
        for part in relative_path.parts:
            current=current/part
            if stat.S_ISLNK(os.lstat(current).st_mode): raise SystemExit(f"{label} has a symlink component")
    except FileNotFoundError: raise SystemExit(f"{label} is missing")
    relative=str(relative_path)
    if not path.is_file(): raise SystemExit(f"{label} is missing")
    try: data=bounded_file_bytes(path,label)
    except (OSError,ValueError) as error: raise SystemExit(str(error))
    return path, {"path": relative, "sha256": digest(data), "bytes": len(data)}


def receipt_path(record: object, label: str) -> Path:
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
        raise ValueError(f"{label} receipt is invalid")
    path, actual = project_file(str(record.get("path", "")), label)
    if actual != record:
        raise ValueError(f"{label} receipt drifted")
    return path


def load_json(path: Path, label: str) -> Dict[str, object]:
    try: value=json.loads(bounded_file_bytes(path,label).decode("utf-8"))
    except (OSError,UnicodeDecodeError,ValueError) as error:
        raise SystemExit(f"invalid {label}: {error}")
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be an object")
    return value


def clean_command(raw: object, label: str, maximum_timeout: int = 300) -> Tuple[str, List[str], int]:
    if not isinstance(raw, dict) or set(raw) != {"id", "argv", "timeout_seconds"}:
        raise SystemExit(f"{label} must contain id, argv and timeout_seconds")
    command_id, argv, timeout = raw["id"], raw["argv"], raw["timeout_seconds"]
    if not isinstance(command_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", command_id):
        raise SystemExit(f"{label} has invalid id")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
        raise SystemExit(f"{label} argv must be a non-empty string array")
    if argv[0] in {"sh", "bash", "zsh", "fish", "cmd", "powershell"} or "-c" in argv:
        raise SystemExit(f"{label} may not invoke a shell or -c")
    if any(item in {"&&", "||", ";", "|", ">", ">>", "<"} for item in argv):
        raise SystemExit(f"{label} contains shell control tokens")
    if not isinstance(timeout, int) or not 1 <= timeout <= maximum_timeout:
        raise SystemExit(f"{label} timeout must be 1-{maximum_timeout} seconds")
    return command_id, argv, timeout


def runner_contract(path: Path) -> Tuple[
        Dict[str, object], Dict[str, object], List[Tuple[str, List[str], int]],
        List[Tuple[str, List[str], int]]]:
    value = load_json(path, "acceptance runner")
    adapter = value.get("adapter")
    required = {"schema", "adapter", "execution_profile", "preflight_commands", "commands"}
    if adapter == "ios-simulator":
        required.add("simulator")
    if (
        set(value) != required or value.get("schema") != "acceptance-runner/v4"
        or value.get("adapter") not in ADAPTER_IDS
    ):
        raise SystemExit("acceptance runner schema/adapter is invalid")
    profile = value.get("execution_profile")
    if (
        not isinstance(profile, dict) or set(profile) != PROFILE_KEYS
        or profile.get("environment") not in {"local", "test"}
        or profile.get("authority") not in {"default", "elevated", "remote-test"}
        or not isinstance(profile.get("capabilities"), list) or not profile["capabilities"]
        or len(profile["capabilities"]) != len(set(profile["capabilities"]))
        or any(not isinstance(item, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", item) for item in profile["capabilities"])
    ):
        raise SystemExit("acceptance runner execution_profile is invalid")
    preflight = value.get("preflight_commands")
    commands = value.get("commands")
    if not isinstance(preflight, list) or not preflight or not isinstance(commands, list) or not commands:
        raise SystemExit("acceptance runner requires preflight_commands and commands arrays")
    parsed_preflight = [clean_command(item, f"preflight {index}", 30) for index, item in enumerate(preflight)]
    if sum(item[2] for item in parsed_preflight) > 60:
        raise SystemExit("acceptance runner preflight timeout budget exceeds 60 seconds")
    parsed = [clean_command(item, f"command {index}") for index, item in enumerate(commands)]
    ids = [item[0] for item in [*parsed_preflight, *parsed]]
    if len(ids) != len(set(ids)):
        raise SystemExit("acceptance runner command IDs must be unique")
    if profile["capabilities"] != [item[0] for item in parsed_preflight]:
        raise SystemExit("execution_profile capabilities must exactly match ordered preflight commands")
    if adapter == "ios-simulator":
        try:
            ios_simulator_gate.target_contract(value.get("simulator"))
        except ValueError as error:
            raise SystemExit(str(error))
    return value, profile, parsed_preflight, parsed

MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
SAFE_COMMAND_ENVIRONMENT = ("PATH","LANG","LC_ALL","LC_CTYPE","TZ","TMPDIR","TMP","TEMP","TERM","DEVELOPER_DIR","SDKROOT")


def execute(argv: List[str], timeout: int, token: str, profile: Dict[str, object]) -> Dict[str, object]:
    started = now()
    environment={key:os.environ[key] for key in SAFE_COMMAND_ENVIRONMENT if key in os.environ}
    environment.setdefault("PATH",os.defpath); environment.setdefault("LANG","C"); environment.setdefault("LC_ALL","C")
    environment["AGENT_FRESH_STATE_TOKEN"] = token
    environment["AGENT_EXECUTION_ENVIRONMENT"] = str(profile["environment"])
    environment["AGENT_EXECUTION_AUTHORITY"] = str(profile["authority"])
    launch_token=uuid.uuid4().hex; environment[supervised_test.LAUNCH_TOKEN_NAME]=launch_token
    if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
        raise RuntimeError("workflow release gate requires default SIGCHLD ownership")
    with supervised_test.child_subreaper() as boundary_supported:
        if not boundary_supported:
            raise RuntimeError("workflow release gate cannot establish its process supervision boundary")
        process = subprocess.Popen(
            argv,cwd=ROOT,env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,start_new_session=True,close_fds=True,bufsize=0,
        )
        result=supervised_test.supervise_bounded_process(
            process,timeout,launch_token,output_limit=MAX_COMMAND_OUTPUT_BYTES,grace=5.0)
    output=bytes(result["output"]); text=output.decode("utf-8",errors="replace")
    return {
        "argv": argv, "started_at": started, "finished_at": now(), "exit_code": int(result["exit_code"]),
        "output_sha256": digest(output), "output_bytes": len(output), "output_tail": text.splitlines()[-20:],
        "process_cleanup": {"remaining": 0 if result["cleanup_ok"] else -1}, "captured_output": text,
        "output_limit_exceeded": bool(result["output_limit_exceeded"]),
    }


def runtime_assert_clean() -> Tuple[bool, Dict[str, object]]:
    """Reuse agentctl's read-only registry + baseline-delta clean assertion."""
    tool_path=AGENT/"scripts/agentctl.py"; tool_data=bounded_file_bytes(tool_path,"agentctl")
    try:
        result=execute([sys.executable,str(tool_path),"assert-clean"],30,"runtime-assert-clean",{
            "environment":"local","authority":"default","capabilities":["runtime-clean"],
        })
        output=str(result["captured_output"]).encode()
        if result["exit_code"] and str(result["captured_output"]).strip():
            print("agentctl assert-clean rejected runtime:\n"+str(result["captured_output"]).strip(),file=sys.stderr)
        return result["exit_code"]==0 and result["process_cleanup"]=={"remaining":0},{
            "mode":"baseline-delta-assert-clean",
            "tool":{"path":str(tool_path.relative_to(ROOT)),"sha256":digest(tool_data),"bytes":len(tool_data)},
            "exit_code":int(result["exit_code"]),"output_sha256":digest(output),"output_bytes":len(output),
        }
    except (OSError,RuntimeError,ValueError):
        return False,{"mode":"baseline-delta-assert-clean","tool":{
            "path":str(tool_path.relative_to(ROOT)),"sha256":digest(tool_data),"bytes":len(tool_data),
        },"exit_code":125,"output_sha256":digest(b""),"output_bytes":0}



def plan_sha(profile: Dict[str, object], preflight: List[Tuple[str, List[str], int]],
             commands: List[Tuple[str, List[str], int]]) -> str:
    value = {"execution_profile": profile, "preflight": preflight, "commands": commands}
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def candidate_fingerprint(config: Dict[str, object]) -> str:
    # The test supervisor is the canonical product-scope implementation.  Import
    # it rather than maintaining a second, subtly different receipt fingerprint.
    return supervised_test.candidate_fingerprint(config)


def validate_preflight(value: Dict[str, object], profile: Dict[str, object], candidate_sha256: str,
                       adapter: str = "workflow", simulator: object = None) -> None:
    expected_keys = set(PREFLIGHT_KEYS)
    if adapter == "ios-simulator":
        expected_keys.add("ios_simulator_capability")
    if set(value) != expected_keys or value.get("schema") != "agent-execution-preflight/v1":
        raise ValueError("execution preflight schema is invalid")
    if (
        value.get("environment") != profile["environment"]
        or value.get("authority") != profile["authority"]
        or value.get("capabilities") != profile["capabilities"]
        or value.get("candidate_sha256") != candidate_sha256
        or value.get("status") != "passed"
    ):
        raise ValueError("execution preflight differs from candidate or execution profile")
    checks = value.get("checks")
    if (
        not isinstance(checks, list) or len(checks) != len(profile["capabilities"])
        or [item.get("capability") for item in checks if isinstance(item, dict)] != profile["capabilities"]
        or any(
            not isinstance(item, dict) or set(item) != {"capability", "status", "evidence"}
            or item.get("status") != "passed"
            or re.fullmatch(r"sha256:[0-9a-f]{64}", str(item.get("evidence", ""))) is None
            for item in checks
        )
    ):
        raise ValueError("execution preflight checks are invalid")
    observed = parse_time(value.get("observed_at"), "preflight observed")
    expires = parse_time(value.get("expires_at"), "preflight expiry")
    current = utc_now()
    if observed > current + dt.timedelta(seconds=5) or expires <= current or expires <= observed or expires - observed > dt.timedelta(minutes=15):
        raise ValueError("execution preflight is stale, future, or overlong")
    if adapter == "ios-simulator":
        ios_simulator_gate.validate_assertion(value.get("ios_simulator_capability"), simulator, "capability")


def validate_test_receipt(value: Dict[str, object], commands: List[Tuple[str, List[str], int]],
                          candidate_sha256: str) -> str:
    if (
        set(value) != {"schema", "run_id", "candidate_sha256", "runner", "cases"}
        or value.get("schema") != "agent-test-receipt/v3"
        or value.get("candidate_sha256") != candidate_sha256
    ):
        raise ValueError("integrator receipt is not agent-test-receipt/v3 for the current candidate")
    run_id = value.get("run_id")
    cases = value.get("cases")
    if not isinstance(run_id, str) or RUN_ID.fullmatch(run_id) is None or not isinstance(cases, list):
        raise ValueError("integrator receipt run is invalid")
    runner = receipt_path(value.get("runner"), "integrator test runner")
    if str(runner.relative_to(ROOT)) != ".agent/scripts/testrun.py":
        raise ValueError("integrator receipt was not produced by testrun.py")
    if len(cases) != len(commands):
        raise ValueError("integrator receipt does not contain the exact workflow command set")
    seen = set()
    for index, (case, expected) in enumerate(zip(cases, commands)):
        if not isinstance(case, dict):
            raise ValueError(f"integrator case {index} is invalid")
        expected_keys = {
            "id", "run_id", "candidate_sha256", "command", "started_at", "finished_at", "exit_code",
            "outcome", "cleanup", "execution_boundary", "output", "case_sha256",
        }
        unsigned = {key: item for key, item in case.items() if key != "case_sha256"}
        expected_sha = digest(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode())
        started = parse_time(case.get("started_at"), f"integrator case {index} start")
        finished = parse_time(case.get("finished_at"), f"integrator case {index} finish")
        if (
            set(case) != expected_keys or case.get("id") != expected[0] or case.get("id") in seen
            or case.get("run_id") != run_id or case.get("command") != expected[1]
            or case.get("candidate_sha256") != candidate_sha256
            or case.get("exit_code") != 0 or case.get("outcome") != "completed"
            or case.get("cleanup") != "passed"
            or case.get("execution_boundary") != TEST_EXECUTION_BOUNDARY
            or case.get("case_sha256") != expected_sha
            or finished < started
        ):
            raise ValueError(f"integrator case {index} is not the exact clean workflow command")
        seen.add(case.get("id"))
        receipt_path(case.get("output"), f"integrator case {index} output")
    return run_id


def validate_integrator_record(record: object, path: Path) -> None:
    if not isinstance(record, dict):
        raise ValueError("integrator receipt record is invalid")
    expected = f".agent/state/evidence/agent-result-evidence/{record.get('sha256')}.result"
    if str(path.relative_to(ROOT)) != expected:
        raise ValueError("integrator receipt is not the unique content-addressed replay result")


def validate_ios_reset_evidence(value: Dict[str, object], simulator: object,
                                candidate_sha256: str, run_id: str,
                                case_ids: List[str]) -> None:
    target = ios_simulator_gate.target_contract(simulator)
    expected_keys = {
        "schema", "candidate_sha256", "integrator_run_id", "device_udid",
        "runtime_identifier", "case_ids", "app_data_reset", "reset_method",
    }
    cases = value.get("case_ids")
    if (
        set(value) != expected_keys or value.get("schema") != "ios-simulator-reset/v1"
        or value.get("candidate_sha256") != candidate_sha256
        or value.get("integrator_run_id") != run_id
        or value.get("device_udid") != target["device_udid"]
        or value.get("runtime_identifier") != target["runtime_identifier"]
        or not isinstance(cases, list) or cases != case_ids or len(cases) != len(set(cases))
        or value.get("app_data_reset") is not True
        or value.get("reset_method") not in {"erase", "uninstall-and-clear-container"}
    ):
        raise ValueError("iOS simulator reset evidence is invalid or stale")


def preflight_gate(runner_raw: str, receipt_raw: str, environment: str,
                   authority: str, candidate_sha256: str) -> int:
    runner_path, _ = project_file(runner_raw, "runner")
    runner_value, profile, preflight, _ = runner_contract(runner_path)
    adapter = str(runner_value["adapter"])
    config = load_json(AGENT / "config.json", "config")
    fingerprint = candidate_fingerprint(config)
    if candidate_sha256 != fingerprint:
        raise SystemExit("preflight candidate SHA-256 differs from the current candidate")
    if environment != profile["environment"] or authority != profile["authority"]:
        raise SystemExit("preflight authority/environment differs from runner execution_profile")
    receipt_path_raw = (ROOT / receipt_raw).resolve()
    try:
        receipt_path_raw.relative_to(ROOT)
    except ValueError:
        raise SystemExit("preflight receipt escapes project")
    if receipt_path_raw.is_symlink():
        raise SystemExit("preflight receipt may not be a symlink")
    observed = utc_now()
    checks: List[Dict[str, object]] = []
    passed = True
    ios_capability = None
    if adapter == "ios-simulator":
        ios_capability = ios_simulator_gate.probe(
            runner_value.get("simulator"), "capability",
            lambda argv, timeout: execute(argv, timeout, "ios-gate-preflight", profile),
            sys.platform, platform.machine(),
        )
        passed = ios_capability.get("status") == "passed"
    for command_id, argv, timeout in preflight:
        if not passed:
            break
        result = execute(argv, timeout, "preflight", profile)
        ok = result["exit_code"] == 0 and result["process_cleanup"] == {"remaining": 0}
        checks.append({"capability": command_id, "status": "passed" if ok else "failed",
                       "evidence": f"sha256:{result['output_sha256']}"})
        if not ok:
            passed = False
            break
    value = {
        "schema": "agent-execution-preflight/v1", "environment": environment,
        "authority": authority, "candidate_sha256": candidate_sha256,
        "observed_at": observed.isoformat(), "expires_at": (observed + dt.timedelta(minutes=15)).isoformat(),
        "status": "passed" if passed and len(checks) == len(preflight) else "failed",
        "capabilities": [item[0] for item in preflight], "checks": checks,
    }
    if adapter == "ios-simulator":
        value["ios_simulator_capability"] = ios_capability
    receipt_path_raw.parent.mkdir(parents=True, exist_ok=True)
    receipt_path_raw.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(("VALID" if value["status"] == "passed" else "INVALID") + f" execution preflight: {receipt_path_raw.relative_to(ROOT)}")
    return 0 if value["status"] == "passed" else 1


def run_gate(runner_raw: str, receipt_raw: str, integrator_raw: str, preflight_raw: str) -> int:
    runner_path, runner_receipt = project_file(runner_raw, "runner")
    runner_value, profile, preflight, commands = runner_contract(runner_path)
    adapter = str(runner_value["adapter"])
    config = load_json(AGENT / "config.json", "config")
    if int(config.get("routing", {}).get("modes", {}).get("release", {}).get("clean_reruns", 0)) != 1:
        raise SystemExit("release clean_reruns must be exactly 1")
    receipt_path_raw = (ROOT / receipt_raw).resolve()
    try:
        receipt_path_raw.relative_to(ROOT)
    except ValueError:
        raise SystemExit("receipt escapes project")
    receipt_path_raw.parent.mkdir(parents=True, exist_ok=True)
    if receipt_path_raw.is_symlink():
        raise SystemExit("receipt may not be a symlink")
    fingerprint = candidate_fingerprint(config)
    if receipt_path_raw.is_file() and config.get("testing", {}).get("reuse_receipts_when_candidate_unchanged") is True:
        if verify_gate(runner_raw, receipt_raw, announce=False) == 0:
            print(f"REUSED workflow release gate: {receipt_path_raw.relative_to(ROOT)} candidate={fingerprint}")
            return 0
    integrator_path, integrator_record = project_file(integrator_raw, "integrator test receipt")
    preflight_path, preflight_record = project_file(preflight_raw, "execution preflight receipt")
    try:
        validate_integrator_record(integrator_record, integrator_path)
        integrator_run_id = validate_test_receipt(
            load_json(integrator_path, "integrator test receipt"), commands, fingerprint
        )
        preflight_value = load_json(preflight_path, "execution preflight receipt")
        validate_preflight(
            preflight_value, profile, fingerprint,
            adapter, runner_value.get("simulator"),
        )
    except ValueError as error:
        raise SystemExit(str(error))
    started = now()
    # The integrator owns command execution and per-case cleanup.  The release
    # gate is deliberately receipt-only: this read-only assertion reuses
    # agentctl's registry plus process-baseline delta and never performs cleanup.
    clean, runtime_assertion = runtime_assert_clean()
    ios_cleanup = None
    ios_reset_record = None
    if adapter == "ios-simulator":
        simulator = ios_simulator_gate.target_contract(runner_value.get("simulator"))
        reset_path, ios_reset_record = project_file(
            simulator["reset_evidence_path"], "iOS simulator reset evidence"
        )
        try:
            validate_ios_reset_evidence(
                load_json(reset_path, "iOS simulator reset evidence"), simulator,
                fingerprint, integrator_run_id, [item[0] for item in commands],
            )
        except ValueError as error:
            raise SystemExit(str(error))
        baseline = preflight_value["ios_simulator_capability"]["booted_device_udids"]
        ios_cleanup = ios_simulator_gate.probe(
            runner_value.get("simulator"), "cleanup",
            lambda argv, timeout: execute(argv, timeout, "ios-gate-cleanup", profile),
            sys.platform, platform.machine(), baseline,
        )
    passed = clean and (adapter != "ios-simulator" or ios_cleanup.get("status") == "passed")
    tool_path = Path(__file__).resolve()
    tool_data=bounded_file_bytes(tool_path,"release gate tool")
    value = {
        "schema": GATE_SCHEMAS[adapter], "adapter_id": ADAPTER_IDS[adapter],
        "status": "passed" if passed else "blocked", "failure_class": None if passed else "infrastructure",
        "started_at": started, "finished_at": now(), "runner": runner_receipt,
        "gate_tool": {"path": str(tool_path.relative_to(ROOT)), "sha256": digest(tool_data), "bytes": len(tool_data)},
        "candidate_fingerprint": fingerprint, "execution_profile": profile,
        "preflight_receipt": preflight_record, "integrator_test_receipt": integrator_record,
        "integrator_run_id": integrator_run_id,
        "command_plan_sha256": plan_sha(profile, preflight, commands),
        "required_clean_reruns": 1,
        "zero_residual_runtime": passed,
        "runtime_assertion": runtime_assertion, "ios_simulator_cleanup": ios_cleanup,
        "ios_simulator_reset_evidence": ios_reset_record,
    }
    receipt_path_raw.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not passed:
        print("INVALID workflow release gate")
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return 1
    print(f"VALID workflow release gate: {receipt_path_raw.relative_to(ROOT)}")
    return 0


def verify_gate(runner_raw: str, receipt_raw: str, announce: bool = True) -> int:
    errors: List[str] = []
    runner_path, runner_receipt = project_file(runner_raw, "runner")
    runner_value, profile, preflight, commands = runner_contract(runner_path)
    adapter = str(runner_value["adapter"])
    receipt_path_raw, _ = project_file(receipt_raw, "live gate receipt")
    value = load_json(receipt_path_raw, "live gate receipt")
    config = load_json(AGENT / "config.json", "config")
    if (
        set(value) != GATE_KEYS or value.get("schema") != GATE_SCHEMAS[adapter] or value.get("adapter_id") != ADAPTER_IDS[adapter]
        or value.get("status") != "passed" or value.get("failure_class") is not None
    ):
        errors.append("receipt schema, adapter or status is invalid")
    if value.get("runner") != runner_receipt or value.get("execution_profile") != profile:
        errors.append("receipt is not bound to the selected runner execution profile")
    if value.get("command_plan_sha256") != plan_sha(profile, preflight, commands):
        errors.append("receipt command plan drifted")
    fingerprint = candidate_fingerprint(config)
    if value.get("candidate_fingerprint") != fingerprint:
        errors.append("receipt candidate fingerprint is stale")
    tool_path = Path(__file__).resolve()
    tool_data=bounded_file_bytes(tool_path,"release gate tool")
    expected_tool = {"path": str(tool_path.relative_to(ROOT)), "sha256": digest(tool_data), "bytes": len(tool_data)}
    if value.get("gate_tool") != expected_tool:
        errors.append("receipt gate tool drifted")
    gate_started = None
    try:
        gate_started = parse_time(value.get("started_at"), "release gate start")
        gate_finished = parse_time(value.get("finished_at"), "release gate finish")
        current = utc_now()
        if (
            gate_started > current + dt.timedelta(seconds=5)
            or gate_finished > current + dt.timedelta(seconds=5)
            or gate_finished < gate_started
            or gate_finished - gate_started > dt.timedelta(minutes=15)
        ):
            raise ValueError("release gate chronology is future, reversed, or overlong")
    except ValueError as error:
        errors.append(str(error))
    try:
        preflight_path = receipt_path(value.get("preflight_receipt"), "execution preflight")
        validate_preflight(
            load_json(preflight_path, "execution preflight"), profile, fingerprint,
            adapter, runner_value.get("simulator"),
        )
    except (SystemExit, ValueError) as error:
        errors.append(str(error))
    try:
        integrator_path = receipt_path(value.get("integrator_test_receipt"), "integrator test")
        validate_integrator_record(value.get("integrator_test_receipt"), integrator_path)
        run_id = validate_test_receipt(load_json(integrator_path, "integrator test"), commands, fingerprint)
        if value.get("integrator_run_id") != run_id:
            errors.append("receipt integrator run ID differs from its test receipt")
    except (SystemExit, ValueError) as error:
        errors.append(str(error))
    assertion = value.get("runtime_assertion")
    agentctl_path=AGENT/"scripts/agentctl.py"; agentctl_data=bounded_file_bytes(agentctl_path,"agentctl")
    expected_assertion_tool = {
        "path": str(agentctl_path.relative_to(ROOT)),
        "sha256": digest(agentctl_data),
        "bytes": len(agentctl_data),
    }
    if (
        not isinstance(assertion, dict)
        or set(assertion) != {"mode", "tool", "exit_code", "output_sha256", "output_bytes"}
        or assertion.get("mode") != "baseline-delta-assert-clean"
        or assertion.get("tool") != expected_assertion_tool
        or assertion.get("exit_code") != 0
        or re.fullmatch(r"[0-9a-f]{64}", str(assertion.get("output_sha256", ""))) is None
        or not isinstance(assertion.get("output_bytes"), int)
        or assertion.get("output_bytes", -1) < 0
    ):
        errors.append("receipt runtime assertion is not the canonical read-only agentctl baseline-delta check")
    if value.get("required_clean_reruns") != 1 or value.get("zero_residual_runtime") is not True:
        errors.append("receipt does not prove the one clean integrator replay and zero residual runtime")
    if adapter == "ios-simulator":
        try:
            simulator = ios_simulator_gate.target_contract(runner_value.get("simulator"))
            reset_path = receipt_path(value.get("ios_simulator_reset_evidence"), "iOS simulator reset evidence")
            validate_ios_reset_evidence(
                load_json(reset_path, "iOS simulator reset evidence"), simulator,
                fingerprint, str(value.get("integrator_run_id")), [item[0] for item in commands],
            )
            ios_simulator_gate.validate_assertion(
                value.get("ios_simulator_cleanup"), runner_value.get("simulator"), "cleanup"
            )
            recorded_cleanup = value["ios_simulator_cleanup"]
            current_ios = ios_simulator_gate.probe(
                runner_value.get("simulator"), "cleanup",
                lambda argv, timeout: execute(argv, timeout, "ios-gate-verify", profile),
                sys.platform, platform.machine(), recorded_cleanup["baseline_booted_device_udids"],
            )
            ios_simulator_gate.validate_assertion(current_ios, runner_value.get("simulator"), "cleanup")
        except (SystemExit, ValueError) as error:
            errors.append(str(error))
    elif value.get("ios_simulator_cleanup") is not None:
        errors.append("non-iOS receipt contains iOS simulator cleanup evidence")
    elif value.get("ios_simulator_reset_evidence") is not None:
        errors.append("non-iOS receipt contains iOS simulator reset evidence")
    current_clean, _ = runtime_assert_clean()
    if not current_clean:
        errors.append("current agentctl baseline-delta assertion is not clean")
    if errors:
        if not announce:
            return 1
        print("INVALID workflow release gate receipt")
        for error in errors:
            print(f"- {error}")
        return 1
    if announce:
        print("VALID workflow release gate receipt")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--runner", required=True)
    run.add_argument("--receipt", required=True)
    run.add_argument("--integrator-receipt", required=True)
    run.add_argument("--preflight-receipt", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--runner", required=True)
    verify.add_argument("--receipt", required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--runner", required=True)
    preflight.add_argument("--receipt", required=True)
    preflight.add_argument("--environment", choices=("local", "test"), required=True)
    preflight.add_argument("--authority", choices=("default", "elevated", "remote-test"), required=True)
    preflight.add_argument("--candidate-sha256", required=True)
    args = parser.parse_args()
    if args.command == "preflight":
        return preflight_gate(args.runner, args.receipt, args.environment, args.authority, args.candidate_sha256)
    if args.command == "run":
        return run_gate(args.runner, args.receipt, args.integrator_receipt, args.preflight_receipt)
    return verify_gate(args.runner, args.receipt)


if __name__ == "__main__":
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"scripts"))
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
