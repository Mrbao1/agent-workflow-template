#!/usr/bin/env python3
"""Bounded regressions for acceptance-client termination and pipe draining."""

from pathlib import Path
import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import time


SOURCE = Path(__file__).with_name("run_acceptance_runtime.py").resolve()


def load_runtime():
    spec = importlib.util.spec_from_file_location("acceptance_runtime_under_test", SOURCE)
    if spec is None or spec.loader is None:
        raise AssertionError("acceptance runtime module could not be loaded")
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
            raise AssertionError("acceptance runtime attempted an unbounded communicate")
        self.timeouts.append(timeout)
        raise subprocess.TimeoutExpired(["fixture"], timeout, output=b"partial-output\n")

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if timeout is None:
            raise AssertionError("acceptance runtime attempted an unbounded wait")
        raise subprocess.TimeoutExpired(["fixture"], timeout)


def unit_stuck_pipe(runtime) -> None:
    process = StuckProcess()
    signals = []
    original_popen = runtime.subprocess.Popen
    original_killpg = runtime.os.killpg
    original_terminate = runtime.terminate_process_group
    try:
        runtime.subprocess.Popen = lambda *args, **kwargs: process
        runtime.os.killpg = lambda pid, sent: signals.append((pid, sent))
        runtime.terminate_process_group = lambda pgid: True
        result = runtime.run_client(["fixture"], 1, {})
    finally:
        runtime.subprocess.Popen = original_popen
        runtime.os.killpg = original_killpg
        runtime.terminate_process_group = original_terminate
    expected_timeouts = [1, runtime.CLIENT_TERM_DRAIN_SECONDS, runtime.CLIENT_KILL_DRAIN_SECONDS]
    if process.timeouts != expected_timeouts:
        raise AssertionError(f"unexpected communicate timeouts: {process.timeouts}")
    if signals != [(process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL)]:
        raise AssertionError(f"termination did not escalate TERM -> KILL: {signals}")
    if not process.stdout.closed:
        raise AssertionError("stuck output pipe was not closed after its final timeout")
    if result["exit_code"] != 125 or result["process_cleanup"] != {"remaining": -1}:
        raise AssertionError("partial cleanup was not returned as fail-closed infrastructure failure")
    if result["raw_output"] != "partial-output\n":
        raise AssertionError("partial output was not preserved exactly once")


def escaped_stdout_pipe(runtime) -> None:
    original_popen = runtime.subprocess.Popen
    original_killpg = runtime.os.killpg
    original_terminate = runtime.terminate_process_group
    with tempfile.TemporaryDirectory(prefix="acceptance-runtime-pipe-") as raw_root:
        root = Path(raw_root)
        child_pid_path = root / "escaped.pid"
        helper = root / "escape_stdout.py"
        helper.write_text(
            """#!/usr/bin/env python3
import os
import sys
import time

pid = os.fork()
if pid == 0:
    os.setsid()
    with open(sys.argv[1], "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))
    time.sleep(30)
    os._exit(0)
print("real-partial-output", flush=True)
os._exit(0)
""",
            encoding="utf-8",
        )
        runtime.subprocess.Popen = original_popen
        runtime.os.killpg = original_killpg
        runtime.terminate_process_group = original_terminate
        runtime.CLIENT_TERM_DRAIN_SECONDS = 0.2
        runtime.CLIENT_KILL_DRAIN_SECONDS = 0.2
        runtime.CLIENT_REAP_SECONDS = 0.2
        started = time.monotonic()
        try:
            result = runtime.run_client([sys.executable, str(helper), str(child_pid_path)], 0.2, dict(os.environ))
        finally:
            deadline = time.monotonic() + 1
            while not child_pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if child_pid_path.exists():
                try:
                    os.kill(int(child_pid_path.read_text(encoding="utf-8")), signal.SIGKILL)
                except (ProcessLookupError, ValueError):
                    pass
        elapsed = time.monotonic() - started
        # Regression bound: run_client must not block on the escaped grandchild's
        # 30s sleep. Keep the bound far below 30s but tolerant of loaded CI
        # runners, where process scheduling alone can add several seconds.
        if elapsed > 15:
            raise AssertionError(f"escaped stdout fixture exceeded its hard bound: {elapsed:.3f}s")
        if result["exit_code"] != 125 or result["process_cleanup"] != {"remaining": -1}:
            raise AssertionError("escaped inherited stdout was not classified as infrastructure failure")
        if "real-partial-output" not in result["raw_output"]:
            raise AssertionError("real subprocess partial output was lost")


def main() -> int:
    runtime = load_runtime()
    unit_stuck_pipe(runtime)
    runtime = load_runtime()
    escaped_stdout_pipe(runtime)
    print("PASS: acceptance runtime TERM/KILL drains are bounded and escaped stdout fails closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
