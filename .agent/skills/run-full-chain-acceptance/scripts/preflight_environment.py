#!/usr/bin/env python3
"""Cheap, read-only workflow-gate capability probe."""

from pathlib import Path
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile


parser = argparse.ArgumentParser()
parser.add_argument(
    "--capability", action="append", choices=("python", "state-write", "loopback", "docker"),
    default=[],
)
args = parser.parse_args()
capabilities = args.capability or ["python", "state-write"]
root = Path.cwd().resolve()
state = root / ".agent" / "state"
checks = {}
if "python" in capabilities:
    checks["python"] = [sys.version_info.major, sys.version_info.minor]
if "state-write" in capabilities:
    if not state.is_dir() or not os.access(state, os.W_OK):
        raise SystemExit("workflow state directory is unavailable or not writable")
    handle, raw = tempfile.mkstemp(prefix=".workflow-preflight-", dir=str(state))
    try:
        os.write(handle, b"workflow-preflight\n")
        os.fsync(handle)
    finally:
        os.close(handle)
        Path(raw).unlink(missing_ok=True)
    checks["state-write"] = True
if "loopback" in capabilities:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        checks["loopback"] = probe.getsockname()[1]
    finally:
        probe.close()
if "docker" in capabilities:
    docker = shutil.which("docker")
    if docker is None:
        raise SystemExit("docker CLI is unavailable")
    result = subprocess.run(
        [docker, "info", "--format", "{{json .ServerVersion}}"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
    )
    if result.returncode:
        raise SystemExit("docker daemon is unavailable under this execution authority: " + result.stdout.strip())
    checks["docker"] = result.stdout.strip()
print(json.dumps({
    "schema": "workflow-preflight-environment/v1",
    "capabilities": capabilities,
    "checks": checks,
    "environment": os.environ.get("AGENT_EXECUTION_ENVIRONMENT"),
    "authority": os.environ.get("AGENT_EXECUTION_AUTHORITY"),
}, sort_keys=True, separators=(",", ":")))
