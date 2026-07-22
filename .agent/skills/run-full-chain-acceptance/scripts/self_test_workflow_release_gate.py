#!/usr/bin/env python3
"""Bounded regression for workflow-gate process termination and pipe draining."""

from pathlib import Path
import importlib.util
import hashlib
import json
import signal
import subprocess
import tempfile
import time


SOURCE = Path(__file__).with_name("run_workflow_release_gate.py").resolve()


def load_gate():
    spec = importlib.util.spec_from_file_location("workflow_release_gate_under_test", SOURCE)
    if spec is None or spec.loader is None:
        raise AssertionError("workflow gate module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Pipe:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class StuckProcess:
    pid = 424242
    returncode = None

    def __init__(self):
        self.stdout = Pipe()
        self.timeouts = []

    def communicate(self, timeout=None):
        if timeout is None:
            raise AssertionError("workflow gate attempted an unbounded communicate")
        self.timeouts.append(timeout)
        raise subprocess.TimeoutExpired(["fixture"], timeout, output=b"partial-output\n")

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if timeout is None:
            raise AssertionError("workflow gate attempted an unbounded wait")
        raise subprocess.TimeoutExpired(["fixture"], timeout)


def main() -> int:
    gate = load_gate()
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
    try:
        gate.validate_test_receipt(receipt, commands, "b" * 64)
    except ValueError as error:
        if "current candidate" not in str(error):
            raise
    else:
        raise AssertionError("stale integrator receipt replay was accepted for a new candidate")
    gate.receipt_path = original_receipt_path

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

    process = StuckProcess()
    signals = []
    gate.subprocess.Popen = lambda *args, **kwargs: process
    gate.os.killpg = lambda pid, sent: signals.append((pid, sent))
    gate.stop_group = lambda pgid: True
    started = time.monotonic()
    result = gate.execute(
        ["fixture"], 1, "fresh", {
            "environment": "local", "authority": "default", "capabilities": ["fixture"],
        },
    )
    elapsed = time.monotonic() - started
    if elapsed > 1:
        raise AssertionError(f"fake stuck-pipe fixture exceeded its bound: {elapsed:.3f}s")
    if process.timeouts != [1, 5, 2]:
        raise AssertionError(f"unexpected communicate timeouts: {process.timeouts}")
    if signals != [(process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL)]:
        raise AssertionError(f"termination did not escalate TERM -> KILL: {signals}")
    if not process.stdout.closed:
        raise AssertionError("stuck output pipe was not closed after its final timeout")
    if result["exit_code"] != 125 or result["process_cleanup"] != {"remaining": -1}:
        raise AssertionError("partial cleanup was not returned as bounded infrastructure failure")
    if result["output_tail"] != ["partial-output"]:
        raise AssertionError("partial output was not preserved")
    print("PASS: candidate-bound receipts, gate-owned iOS evidence, and TERM/KILL drain are bounded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
