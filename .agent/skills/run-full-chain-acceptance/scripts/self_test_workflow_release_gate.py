#!/usr/bin/env python3
"""Bounded regression for workflow-gate process termination and pipe draining."""

from pathlib import Path
import importlib.util
import hashlib
import json
import os
import sys
import tempfile
import time


SOURCE = Path(__file__).with_name("run_workflow_release_gate.py").resolve()
ARTIFACT_SOURCE = SOURCE.parents[3] / "scripts/artifactctl.py"


def load_gate():
    spec = importlib.util.spec_from_file_location("workflow_release_gate_under_test", SOURCE)
    if spec is None or spec.loader is None:
        raise AssertionError("workflow gate module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_artifactctl():
    spec = importlib.util.spec_from_file_location("artifactctl_under_test", ARTIFACT_SOURCE)
    if spec is None or spec.loader is None:
        raise AssertionError("artifact controller module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def process_alive(pid: int) -> bool:
    try: os.kill(pid,0)
    except ProcessLookupError: return False
    except PermissionError: return True
    return True

def main() -> int:
    gate = load_gate()
    artifactctl = load_artifactctl()
    with tempfile.TemporaryDirectory(prefix="local-adapter-contract-") as raw:
        root = Path(raw)
        for adapter in ("workflow", "api", "cli", "ios-simulator"):
            path = root / f"{adapter}.json"
            runner = {
                "schema": "acceptance-runner/v4", "adapter": adapter,
                "execution_profile": {
                    "environment": "local", "authority": "default",
                    "capabilities": [f"{adapter}-available"],
                },
                "preflight_commands": [{
                    "id": f"{adapter}-available", "argv": ["python3", "probe.py"],
                    "timeout_seconds": 10,
                }],
                "commands": [{
                    "id": f"{adapter}-acceptance", "argv": ["python3", "acceptance.py"],
                    "timeout_seconds": 120,
                }],
            }
            if adapter == "ios-simulator":
                runner["simulator"] = {
                    "device_udid": "12345678-1234-1234-1234-123456789ABC",
                    "runtime_identifier": "com.apple.CoreSimulator.SimRuntime.iOS-18-0",
                    "reset_evidence_path": ".agent/state/evidence/ios-reset.json",
                }
            path.write_text(json.dumps(runner), encoding="utf-8")
            value, profile, preflight, commands = gate.runner_contract(path)
            if value["adapter"] != adapter or profile["capabilities"] != [f"{adapter}-available"]:
                raise AssertionError(f"{adapter} local adapter contract was not usable")
            if gate.ADAPTER_IDS[adapter] not in {
                "acceptance-workflow", "acceptance-api", "acceptance-cli", "acceptance-ios",
            } or not preflight or not commands:
                raise AssertionError(f"{adapter} adapter registry mapping is incomplete")

        invalid = root / "invalid.json"
        invalid.write_text(json.dumps({
            "schema": "acceptance-runner/v4", "adapter": "cli",
            "execution_profile": {"environment": "local", "authority": "default", "capabilities": ["bad"]},
            "preflight_commands": [{"id": "bad", "argv": ["sh", "-c", "true"], "timeout_seconds": 1}],
            "commands": [{"id": "case", "argv": ["python3", "case.py"], "timeout_seconds": 1}],
        }), encoding="utf-8")
        try:
            gate.runner_contract(invalid)
        except SystemExit as error:
            if "shell or -c" not in str(error):
                raise
        else:
            raise AssertionError("local adapter accepted a shell-backed integration stub")

        missing_ios_target = root / "ios-missing-target.json"
        missing_ios_target.write_text(json.dumps({
            "schema": "acceptance-runner/v4", "adapter": "ios-simulator",
            "execution_profile": {"environment": "local", "authority": "default", "capabilities": ["probe"]},
            "preflight_commands": [{"id": "probe", "argv": ["python3", "probe.py"], "timeout_seconds": 1}],
            "commands": [{"id": "case", "argv": ["python3", "case.py"], "timeout_seconds": 1}],
        }), encoding="utf-8")
        try:
            gate.runner_contract(missing_ios_target)
        except SystemExit:
            pass
        else:
            raise AssertionError("generic commands were accepted as an iOS simulator capability contract")

    candidate = "a" * 64
    commands = [("case", ["python3", "acceptance.py"], 30)]
    case = {
        "id": "case", "run_id": "1" * 32, "candidate_sha256": candidate,
        "command": commands[0][1], "started_at": "2026-07-22T00:00:00+00:00",
        "finished_at": "2026-07-22T00:00:01+00:00", "exit_code": 0,
        "outcome": "completed", "cleanup": "passed",
        "execution_boundary": dict(gate.TEST_EXECUTION_BOUNDARY),
        "output": {"path": "fixture.log", "sha256": "2" * 64, "bytes": 0},
    }
    case["case_sha256"] = hashlib.sha256(
        json.dumps(case, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    receipt = {
        "schema": "agent-test-receipt/v3", "run_id": "1" * 32,
        "candidate_sha256": candidate,
        "runner": {"path": ".agent/scripts/testrun.py", "sha256": "3" * 64, "bytes": 1},
        "cases": [case],
    }
    original_receipt_path = gate.receipt_path
    gate.receipt_path = lambda record, label: gate.AGENT / "scripts/testrun.py"
    if gate.validate_test_receipt(receipt, commands, candidate) != "1" * 32:
        raise AssertionError("current-candidate integrator receipt was not accepted")
    original_candidate_fingerprint = artifactctl.supervised_test.candidate_fingerprint
    original_artifact_receipt = artifactctl.receipt
    artifactctl.supervised_test.candidate_fingerprint = lambda _config: candidate
    artifactctl.receipt = lambda record, _errors, _label: artifactctl.ROOT / record["path"]

    def artifact_validation(value):
        with tempfile.TemporaryDirectory(prefix="artifact-receipt-boundary-") as raw:
            path = Path(raw) / "receipt.json"
            path.write_text(json.dumps(value) + "\n", encoding="utf-8")
            errors = []
            run_id = artifactctl.verify_test_receipt(path, errors, "integrator replay", None, None)
            return run_id, errors

    artifact_run_id, artifact_errors = artifact_validation(receipt)
    if artifact_run_id != "1" * 32 or artifact_errors:
        raise AssertionError(f"artifact controller rejected canonical private boundary: {artifact_errors}")
    try:
        gate.validate_test_receipt(receipt, commands, "b" * 64)
    except ValueError as error:
        if "current candidate" not in str(error):
            raise
    else:
        raise AssertionError("stale integrator receipt replay was accepted for a new candidate")
    for label, attack in (
        ("missing", lambda value: value.pop("execution_boundary")),
        ("drifted", lambda value: value["execution_boundary"].update({"credentials_inherited": True})),
        ("extended", lambda value: value["execution_boundary"].update({"unreviewed_claim": "trusted"})),
    ):
        attacked = json.loads(json.dumps(receipt))
        attack(attacked["cases"][0])
        attacked_case = attacked["cases"][0]
        attacked_case["case_sha256"] = hashlib.sha256(
            json.dumps(
                {key: item for key, item in attacked_case.items() if key != "case_sha256"},
                sort_keys=True, separators=(",", ":"),
            ).encode()
        ).hexdigest()
        try:
            gate.validate_test_receipt(attacked, commands, candidate)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{label} private-runner execution boundary was accepted")
        artifact_run_id, artifact_errors = artifact_validation(attacked)
        if artifact_run_id != "1" * 32 or not any("clean completed replay" in error for error in artifact_errors):
            raise AssertionError(f"artifact controller accepted {label} private boundary: {artifact_errors}")
    gate.receipt_path = original_receipt_path
    artifactctl.supervised_test.candidate_fingerprint = original_candidate_fingerprint
    artifactctl.receipt = original_artifact_receipt

    ios_target = {
        "device_udid": "12345678-1234-1234-1234-123456789ABC",
        "runtime_identifier": "com.apple.CoreSimulator.SimRuntime.iOS-18-0",
        "reset_evidence_path": ".agent/state/evidence/ios-reset.json",
    }
    simctl_output = json.dumps({"devices": {ios_target["runtime_identifier"]: [{
        "name": "iPhone Fixture", "udid": ios_target["device_udid"],
        "state": "Shutdown", "isAvailable": True,
    }]}})

    def ios_runner(argv, _timeout):
        output = simctl_output if "simctl" in argv else "Xcode 18.0\n"
        return {
            "argv": argv, "started_at": "2026-07-22T00:00:00+00:00",
            "finished_at": "2026-07-22T00:00:01+00:00", "exit_code": 0,
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            "output_bytes": len(output.encode()), "output_tail": output.splitlines(),
            "process_cleanup": {"remaining": 0}, "captured_output": output,
        }

    assertion = gate.ios_simulator_gate.probe(ios_target, "cleanup", ios_runner, "darwin", "arm64")
    gate.ios_simulator_gate.validate_assertion(assertion, ios_target, "cleanup")
    assertion["device"]["state"] = "Booted"
    try:
        gate.ios_simulator_gate.validate_assertion(assertion, ios_target, "cleanup")
    except ValueError:
        pass
    else:
        raise AssertionError("booted simulator was accepted as cleanup evidence")

    residual_output = json.dumps({"devices": {ios_target["runtime_identifier"]: [
        {"name": "iPhone Fixture", "udid": ios_target["device_udid"],
         "state": "Shutdown", "isAvailable": True},
        {"name": "Residual", "udid": "ABCDEFAB-1234-1234-1234-ABCDEFABCDEF",
         "state": "Booted", "isAvailable": True},
    ]}})

    def residual_runner(argv, _timeout):
        output = residual_output if "simctl" in argv else "Xcode 18.0\n"
        return {
            "argv": argv, "started_at": "2026-07-22T00:00:00+00:00",
            "finished_at": "2026-07-22T00:00:01+00:00", "exit_code": 0,
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            "output_bytes": len(output.encode()), "output_tail": output.splitlines(),
            "process_cleanup": {"remaining": 0}, "captured_output": output,
        }

    residual = gate.ios_simulator_gate.probe(
        ios_target, "cleanup", residual_runner, "darwin", "arm64", []
    )
    if residual["status"] != "failed":
        raise AssertionError("newly booted simulator residual was accepted")
    reset = {
        "schema": "ios-simulator-reset/v1", "candidate_sha256": candidate,
        "integrator_run_id": "1" * 32, "device_udid": ios_target["device_udid"],
        "runtime_identifier": ios_target["runtime_identifier"], "case_ids": ["case"],
        "app_data_reset": True, "reset_method": "erase",
    }
    gate.validate_ios_reset_evidence(reset, ios_target, candidate, "1" * 32, ["case"])
    reset["candidate_sha256"] = "b" * 64
    try:
        gate.validate_ios_reset_evidence(reset, ios_target, candidate, "1" * 32, ["case"])
    except ValueError:
        pass
    else:
        raise AssertionError("stale iOS reset evidence was accepted")

    with tempfile.TemporaryDirectory(prefix="workflow-bounded-output-") as raw:
        fixture=Path(raw); child_pid=fixture/"child.pid"; escaping=fixture/"escaping.py"
        escaping.write_text("""#!/usr/bin/env python3
import os,sys,time
pid=os.fork()
if pid==0:
 os.setsid(); open(sys.argv[1],"w").write(str(os.getpid())); time.sleep(30); os._exit(0)
os.write(1,b'invalid-utf8-\\xff\\n'); os._exit(0)
""",encoding="utf-8")
        result=gate.execute([sys.executable,str(escaping),str(child_pid)],2,"fresh",{
            "environment":"local","authority":"default","capabilities":["fixture"],
        })
        if result["exit_code"]!=125 or result["process_cleanup"]!={"remaining":0}:
            raise AssertionError("escaped invalid-UTF8 command was not cleaned as bounded infrastructure failure")
        if "invalid-utf8-" not in result["captured_output"]:
            raise AssertionError("invalid UTF-8 output was not captured with replacement decoding")
        if child_pid.exists() and process_alive(int(child_pid.read_text(encoding="utf-8"))):
            raise AssertionError("workflow command left its token-bound escaped child alive")

        gate.MAX_COMMAND_OUTPUT_BYTES=1024
        flooded=gate.execute([sys.executable,"-c","import os;os.write(1,b'x'*8192)"],2,"fresh",{
            "environment":"local","authority":"default","capabilities":["fixture"],
        })
        if flooded["exit_code"]!=125 or not flooded["output_limit_exceeded"] or flooded["output_bytes"]>1024:
            raise AssertionError("workflow command output was not byte-bounded and failed closed")

        original_snapshot=gate.supervised_test.process_snapshot; captured=[]; original_popen=gate.subprocess.Popen
        def capture(*args,**kwargs):
            process=original_popen(*args,**kwargs); captured.append(process); return process
        gate.subprocess.Popen=capture
        gate.supervised_test.process_snapshot=lambda: (_ for _ in ()).throw(RuntimeError("injected observer failure"))
        try:
            try: gate.execute([sys.executable,"-c","import time;time.sleep(30)"],2,"fresh",{
                "environment":"local","authority":"default","capabilities":["fixture"],
            })
            except RuntimeError as error:
                if "observer failure" not in str(error): raise
            else: raise AssertionError("observer exception was accepted")
        finally:
            gate.supervised_test.process_snapshot=original_snapshot; gate.subprocess.Popen=original_popen
        if len(captured)!=1 or captured[0].returncode is None:
            raise AssertionError("observer exception left the exact workflow leader unreaped")

        previous=os.environ.get("GITHUB_TOKEN"); os.environ["GITHUB_TOKEN"]="poison-secret"
        try:
            sanitized=gate.execute([sys.executable,"-c","import os;print('GITHUB_TOKEN' in os.environ)"],2,"fresh",{
                "environment":"local","authority":"default","capabilities":["fixture"],
            })
        finally:
            if previous is None: os.environ.pop("GITHUB_TOKEN",None)
            else: os.environ["GITHUB_TOKEN"]=previous
        if sanitized["exit_code"]!=0 or sanitized["captured_output"].strip()!="False":
            raise AssertionError("workflow command inherited an ambient credential")
    print("PASS: candidate-bound receipts, bounded binary output, guaranteed cleanup, and credential stripping")
    return 0


if __name__ == "__main__":
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"scripts"))
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
