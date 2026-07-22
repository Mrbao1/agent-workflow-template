#!/usr/bin/env python3
"""Gate-owned, fail-closed iOS simulator capability and cleanup probes."""

from __future__ import annotations

import json
import re
from typing import Callable, Dict, List, Tuple


TARGET_KEYS = {"device_udid", "runtime_identifier", "reset_evidence_path"}
ASSERTION_KEYS = {
    "schema", "purpose", "target", "host", "commands", "device",
    "baseline_booted_device_udids", "booted_device_udids", "status",
}
COMMAND_KEYS = {
    "argv", "started_at", "finished_at", "exit_code", "output_sha256",
    "output_bytes", "output_tail", "process_cleanup",
}
DEVICE_KEYS = {"name", "udid", "runtime_identifier", "state", "available"}
UDID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
RUNTIME = re.compile(r"^com\.apple\.CoreSimulator\.SimRuntime\.[A-Za-z0-9._-]+$")
ARCHITECTURES = {"arm64", "x86_64"}


def target_contract(value: object) -> Dict[str, str]:
    if (
        not isinstance(value, dict) or set(value) != TARGET_KEYS
        or not isinstance(value.get("device_udid"), str)
        or UDID.fullmatch(value["device_udid"]) is None
        or not isinstance(value.get("runtime_identifier"), str)
        or RUNTIME.fullmatch(value["runtime_identifier"]) is None
        or not isinstance(value.get("reset_evidence_path"), str)
        or not value["reset_evidence_path"].strip()
    ):
        raise ValueError("iOS runner simulator target is invalid")
    return {
        "device_udid": value["device_udid"], "runtime_identifier": value["runtime_identifier"],
        "reset_evidence_path": value["reset_evidence_path"],
    }


def _public_command(value: Dict[str, object]) -> Dict[str, object]:
    return {key: value.get(key) for key in COMMAND_KEYS}


def _devices_from_simctl(raw: str, target: Dict[str, str]) -> Tuple[Dict[str, object] | None, List[str]]:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None, []
    devices = value.get("devices") if isinstance(value, dict) else None
    runtime_devices = devices.get(target["runtime_identifier"]) if isinstance(devices, dict) else None
    if not isinstance(runtime_devices, list):
        return None, []
    booted = sorted({
        str(item.get("udid"))
        for entries in devices.values() if isinstance(entries, list)
        for item in entries if isinstance(item, dict) and item.get("state") == "Booted"
        and isinstance(item.get("udid"), str) and UDID.fullmatch(item["udid"])
    })
    for item in runtime_devices:
        if isinstance(item, dict) and item.get("udid") == target["device_udid"]:
            available = item.get("isAvailable") is True and item.get("availabilityError") in {None, ""}
            return {
                "name": item.get("name"), "udid": item.get("udid"),
                "runtime_identifier": target["runtime_identifier"], "state": item.get("state"),
                "available": available,
            }, booted
    return None, booted


def probe(target_raw: object, purpose: str, runner: Callable[[List[str], int], Dict[str, object]],
          host_platform: str, machine: str, baseline_booted: object = None) -> Dict[str, object]:
    """Probe fixed Apple tools; runner must provide bounded process-cleanup evidence."""
    target = target_contract(target_raw)
    if purpose not in {"capability", "cleanup"}:
        raise ValueError("iOS simulator probe purpose is invalid")
    commands: List[Dict[str, object]] = []
    device = None
    booted: List[str] = []
    baseline = sorted(set(baseline_booted or [])) if purpose == "cleanup" else []
    if host_platform == "darwin" and machine in ARCHITECTURES:
        xcode = runner(["/usr/bin/xcrun", "xcodebuild", "-version"], 15)
        commands.append(_public_command(xcode))
        if xcode.get("exit_code") == 0 and xcode.get("process_cleanup") == {"remaining": 0}:
            simctl = runner(["/usr/bin/xcrun", "simctl", "list", "devices", "available", "--json"], 20)
            commands.append(_public_command(simctl))
            if simctl.get("exit_code") == 0 and simctl.get("process_cleanup") == {"remaining": 0}:
                device, booted = _devices_from_simctl(str(simctl.get("captured_output", "")), target)
                if purpose == "capability":
                    baseline = list(booted)
    passed = (
        host_platform == "darwin" and machine in ARCHITECTURES and len(commands) == 2
        and all(item.get("exit_code") == 0 and item.get("process_cleanup") == {"remaining": 0} for item in commands)
        and isinstance(device, dict) and device.get("available") is True
        and (purpose != "cleanup" or device.get("state") == "Shutdown")
        and (purpose != "cleanup" or not (set(booted) - set(baseline)))
    )
    return {
        "schema": "ios-simulator-gate-assertion/v1", "purpose": purpose,
        "target": target, "host": {"platform": host_platform, "machine": machine},
        "commands": commands, "device": device,
        "baseline_booted_device_udids": baseline, "booted_device_udids": booted,
        "status": "passed" if passed else "failed",
    }


def validate_assertion(value: object, target_raw: object, purpose: str) -> None:
    target = target_contract(target_raw)
    if (
        not isinstance(value, dict) or set(value) != ASSERTION_KEYS
        or value.get("schema") != "ios-simulator-gate-assertion/v1"
        or value.get("purpose") != purpose or value.get("target") != target
        or value.get("status") != "passed"
    ):
        raise ValueError(f"iOS simulator {purpose} assertion is invalid")
    host = value.get("host")
    commands = value.get("commands")
    device = value.get("device")
    baseline = value.get("baseline_booted_device_udids")
    booted = value.get("booted_device_udids")
    if (
        not isinstance(host, dict) or set(host) != {"platform", "machine"}
        or host.get("platform") != "darwin" or host.get("machine") not in ARCHITECTURES
        or not isinstance(commands, list) or len(commands) != 2
        or any(
            not isinstance(item, dict) or set(item) != COMMAND_KEYS
            or item.get("exit_code") != 0 or item.get("process_cleanup") != {"remaining": 0}
            or not isinstance(item.get("output_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", item["output_sha256"]) is None
            for item in commands
        )
        or commands[0].get("argv") != ["/usr/bin/xcrun", "xcodebuild", "-version"]
        or commands[1].get("argv") != ["/usr/bin/xcrun", "simctl", "list", "devices", "available", "--json"]
        or not isinstance(device, dict) or set(device) != DEVICE_KEYS
        or device.get("udid") != target["device_udid"]
        or device.get("runtime_identifier") != target["runtime_identifier"]
        or device.get("available") is not True
        or purpose == "cleanup" and device.get("state") != "Shutdown"
        or not isinstance(baseline, list) or baseline != sorted(set(baseline))
        or not isinstance(booted, list) or booted != sorted(set(booted))
        or any(not isinstance(item, str) or UDID.fullmatch(item) is None for item in [*baseline, *booted])
        or purpose == "capability" and baseline != booted
        or purpose == "cleanup" and bool(set(booted) - set(baseline))
    ):
        raise ValueError(f"iOS simulator {purpose} evidence is incomplete or unsafe")
