#!/usr/bin/env python3
"""Single controlled full-suite entry across three private-state contexts."""

from pathlib import Path
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time


SELF_TESTS = (
    ".agent/scripts/self_test_budget_context_gates.py",
    ".agent/scripts/self_test_control_gates.py",
    ".agent/scripts/self_test_evidence_retention.py",
    ".agent/scripts/self_test_hardening_core.py",
    ".agent/scripts/self_test_local_decision_archive.py",
    ".agent/scripts/self_test_plugin_install_lifecycle.py",
    ".agent/scripts/self_test_template_lifecycle.py",
    ".agent/scripts/self_test_templatectl.py",
    ".agent/skills/deliver-environments/scripts/self_test_delivery.py",
    ".agent/skills/deliver-environments/scripts/self_test_delivery_migration.py",
    ".agent/skills/manage-agent-team/scripts/self_test_agentledger.py",
    ".agent/skills/manage-local-runtime/scripts/self_test_docker_http.py",
    ".agent/skills/manage-local-runtime/scripts/self_test_managed_run.py",
    ".agent/skills/manage-task-context/scripts/self_test_context.py",
    ".agent/skills/run-ai-coding-pipeline/scripts/self_test_stage_index.py",
    ".agent/skills/run-ai-coding-pipeline/scripts/self_test_workflow.py",
    ".agent/skills/run-full-chain-acceptance/scripts/self_test_acceptance_runtime.py",
    ".agent/skills/run-full-chain-acceptance/scripts/self_test_gate.py",
    ".agent/skills/run-full-chain-acceptance/scripts/self_test_product_fingerprint.py",
    ".agent/skills/run-full-chain-acceptance/scripts/self_test_workflow_release_gate.py",
)

SELF_TEST_ARGUMENTS = {
    ".agent/scripts/self_test_template_lifecycle.py": ("--template-root", "."),
}


class RunFailure(RuntimeError):
    def __init__(self, record):
        super().__init__(json.dumps(record, ensure_ascii=False))
        self.record = record


class CleanupFailure(RuntimeError):
    def __init__(self, records):
        super().__init__("one or more cleanup controls failed")
        self.records = records


def output_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def run(command, cwd, timeout=900, expected=(0,)):
    started = time.monotonic()
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPYCACHEPREFIX"] = "/tmp/agent-workflow-pycache"
    process = subprocess.Popen(
        command, cwd=str(cwd), env=env, text=True, start_new_session=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    timed_out = False
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        output = output_text(error.output)
        try: os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try:
            tail, _ = process.communicate(timeout=5); output += output_text(tail)
        except subprocess.TimeoutExpired:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            tail, _ = process.communicate(timeout=5); output += output_text(tail)
    exit_code = 124 if timed_out else int(process.returncode)
    record = {
        "command": command,
        "cwd": str(cwd),
        "exit_code": exit_code,
        "seconds": round(time.monotonic() - started, 3),
        "output": output[-12000:],
    }
    if exit_code not in expected:
        raise RunFailure(record)
    return record


def copy_project_without_agent(source: Path, target: Path) -> None:
    ignored = {".agent", ".git", ".idea", "__pycache__"}
    shutil.copytree(
        source, target, symlinks=True,
        ignore=lambda _p, names: [
            name for name in names if name in ignored or name.endswith(".pyc")
        ],
    )


def guardrails(path: Path) -> None:
    path.write_text("""# Project Guardrails

## Required project facts
- Product and users: Disposable full-suite fixture for workflow maintainers.
- Technology and architecture: Python, JSON, Markdown, and optional Node.js plugin controls.
- Writable and read-only areas: The temporary fixture is writable and the source template is read-only.
- Security, privacy, compliance and performance red lines: No credentials, network, deployment, or external effects.
- Build, test and lint commands: Run tests/run_all.py with bounded subprocess timeouts.
- Deployment authority and rollback owner: Deployment is forbidden and the fixture owner controls rollback.

## Universal project constraints
- Remain local, bounded, reversible, isolated, and zero-residual.
""",encoding="utf-8")


def make_context(source: Path, workspace: Path, name: str) -> Path:
    target = workspace / name
    copy_project_without_agent(source, target)
    run(
        [
            sys.executable, str(source / "install.py"), str(target),
            "--project-name", name,
        ],
        source,
    )
    if name == "polluted-source":
        evidence = target / ".agent/state/evidence/polluted"
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "sentinel.txt").write_text(
            "PRIVATE_SOURCE_POLLUTION\n", encoding="utf-8",
        )
        # The sentinel deliberately makes this otherwise fresh template source
        # private and non-pristine.  Do not mutate TASK.json: doing so without
        # rebuilding CONTEXT.json would make the context inconsistent.
        return target
    if name == "installed-project":
        policy = target / "fixture-guardrails.md"
        guardrails(policy)
        run(
            [
                sys.executable, ".agent/scripts/agentctl.py", "project-init",
                "--guardrails-file", policy.name,
            ],
            target,
        )
    return target


def assert_self_test_inventory(root: Path) -> None:
    discovered = {
        path.relative_to(root).as_posix()
        for path in root.glob(".agent/**/self_test_*.py")
    }
    expected = set(SELF_TESTS)
    if discovered != expected:
        raise RuntimeError(json.dumps({
            "error": "Python self-test inventory drift",
            "root": str(root),
            "missing": sorted(expected - discovered),
            "unexpected": sorted(discovered - expected),
        }, ensure_ascii=False))


def self_test_command(relative: str):
    return [
        sys.executable,
        relative,
        *SELF_TEST_ARGUMENTS.get(relative, ()),
    ]


def clean_context(root: Path) -> list[dict]:
    records = []
    failed = False
    for name, command in (
        ("cleanup", [sys.executable, ".agent/scripts/agentctl.py", "cleanup"]),
        ("assert-clean", [sys.executable, ".agent/scripts/agentctl.py", "assert-clean"]),
    ):
        try:
            record = run(command, root, timeout=60)
        except RunFailure as error:
            record = error.record
            failed = True
        records.append({"name": name, **record})
    if failed:
        raise CleanupFailure(records)
    return records


def append_cleanup(records: list[dict], context: str, root: Path) -> None:
    try:
        cleanup_records = clean_context(root)
    except CleanupFailure as error:
        cleanup_records = error.records
        for record in cleanup_records:
            records.append({"context": context, **record})
        raise
    for record in cleanup_records:
        records.append({"context": context, **record})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template-root", default=".")
    parser.add_argument("--report", default="outputs/full-suite.json")
    args = parser.parse_args()
    source = Path(args.template_root).resolve()
    report = (source / args.report).resolve()
    records = []
    assert_self_test_inventory(source)
    failure = None
    try:
        with tempfile.TemporaryDirectory(prefix="agent-workflow-full-suite-") as raw:
            workspace = Path(raw)
            for name in ("idle-source", "polluted-source", "installed-project"):
                context = make_context(source, workspace, name)
                try:
                    records.append({
                        "context": name,
                        "name": "capture-runtime-baseline",
                        **run([
                            sys.executable, ".agent/scripts/agentctl.py",
                            "capture-runtime-baseline", "--source", "user:full-suite-controller",
                        ], context, timeout=60),
                    })
                    assert_self_test_inventory(context)
                    if name == "polluted-source":
                        records.append({"context": name,"name": "agent-state-validation",**run([sys.executable, ".agent/scripts/agentctl.py", "validate"],context)})
                        records.append({"context": name,"name": "context-validation",**run([sys.executable, ".agent/scripts/contextctl.py", "check"],context)})
                    for relative in SELF_TESTS:
                        records.append({"context": name,"name": relative,**run(self_test_command(relative), context)})
                finally:
                    append_cleanup(records, name, context)
            try:
                records.append({"context": "source","name": "install-lifecycle",**run([sys.executable, "tests/test_install_lifecycle.py","--template-root", "."], source)})
                records.append({"context": "source","name": "pxpipe-self-test",**run(["node", "plugins/pxpipe-context/scripts/self-test.mjs"], source)})
                records.append({"context": "source","name": "pxpipe-provider-integration",**run(["node","plugins/pxpipe-context/scripts/provider-integration-self-test.mjs"], source)})
            finally:
                append_cleanup(records, "source", source)
    except Exception as error:
        if isinstance(error, RunFailure):
            records.append({"context": "failed-command", **error.record})
        failure = f"{type(error).__name__}: {error}"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({
        "schema": "agent-workflow-full-suite/v1",
        "status": "failed" if failure else "passed",
        "failure": failure,
        "runs": records,
    }, ensure_ascii=False, indent=2) + "\n")
    try:
        display_report = report.relative_to(source)
    except ValueError:
        display_report = report
    if failure:
        print(f"FULL SUITE FAIL: runs={len(records)} report={display_report}")
        return 1
    print(f"FULL SUITE PASS: runs={len(records)} report={display_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
