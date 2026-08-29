#!/usr/bin/env python3
"""Cheap, read-only workflow-gate capability probe."""

from pathlib import Path
import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0,str((Path.cwd()/".agent/scripts").resolve()))
import testrun as supervised_test


def main() -> int:
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
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            raise SystemExit("docker probe requires default SIGCHLD ownership")
        launch_token=uuid.uuid4().hex; environment=dict(os.environ)
        environment[supervised_test.LAUNCH_TOKEN_NAME]=launch_token
        with supervised_test.child_subreaper() as boundary_supported:
            if not boundary_supported: raise SystemExit("docker probe supervision boundary is unavailable")
            process=subprocess.Popen(
                [docker,"info","--format","{{json .ServerVersion}}"],stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,start_new_session=True,
                close_fds=True,bufsize=0,env=environment,
            )
            result=supervised_test.supervise_bounded_process(process,10,launch_token,output_limit=65536,grace=2)
        output=bytes(result["output"]).decode("utf-8",errors="replace").strip()
        if result["exit_code"] or not result["cleanup_ok"] or result["output_limit_exceeded"]:
            raise SystemExit("docker daemon is unavailable under this execution authority: "+output)
        checks["docker"]=output
    print(json.dumps({
        "schema": "workflow-preflight-environment/v1",
        "capabilities": capabilities,
        "checks": checks,
        "environment": os.environ.get("AGENT_EXECUTION_ENVIRONMENT"),
        "authority": os.environ.get("AGENT_EXECUTION_AUTHORITY"),
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"scripts"))
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
