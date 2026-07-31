#!/usr/bin/env python3
"""Bounded self-suite entry across private-state install contexts.

Default run: source-level checks plus the idle-source context only.
Use --full for all three contexts (idle-source, polluted-source,
installed-project).  Use --shard K/N for deterministic modulo sharding
over the registered self-test list and --only NAME... for a named subset.
Every test runs with a per-test subprocess timeout (default 300s); on
timeout the whole process group is killed and the test is recorded as a
failure with its elapsed time.  The process exits non-zero if any test,
setup step, or cleanup control fails.

Source-level checks run only on shard 1 (or unsharded runs), and sharded
runs default to a per-shard report path (outputs/full-suite-shard-K-N.json)
so parallel shards do not overwrite each other.
"""

from concurrent.futures import ThreadPoolExecutor
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

ALL_CONTEXTS = ("idle-source", "polluted-source", "installed-project")
DEFAULT_CONTEXTS = ("idle-source",)

SOURCE_CHECKS = (
    ("freshness", ("tests/check_freshness.py",)),
    ("install-lifecycle", ("tests/test_install_lifecycle.py", "--template-root", ".")),
    ("pxpipe-self-test", ("plugins/pxpipe-context/scripts/self-test.mjs",)),
    ("pxpipe-provider-integration", ("plugins/pxpipe-context/scripts/provider-integration-self-test.mjs",)),
)


class RunFailure(RuntimeError):
    def __init__(self, record):
        super().__init__(json.dumps(record, ensure_ascii=False))
        self.record = record


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


def execute(name, command, cwd, timeout):
    """Run one check, converting any failure into a result row."""
    try:
        record = run(command, cwd, timeout=timeout)
        return {"name": name, "status": "pass", **record}
    except RunFailure as error:
        status = "timeout" if error.record["exit_code"] == 124 else "fail"
        return {"name": name, "status": status, **error.record}


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


def source_check_command(entry):
    name, arguments = entry
    if arguments[0].endswith(".py"):
        return name, [sys.executable, *arguments]
    return name, ["node", *arguments]


def parse_shard(text: str):
    try:
        k_text, n_text = text.split("/", 1)
        k, n = int(k_text), int(n_text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid shard {text!r}: expected K/N with integer K and N"
        )
    if n < 1 or not 1 <= k <= n:
        raise argparse.ArgumentTypeError(
            f"invalid shard {text!r}: expected 1 <= K <= N"
        )
    return (k, n)


def resolve_only(names) -> list:
    by_basename = {}
    for relative in SELF_TESTS:
        by_basename.setdefault(Path(relative).name, relative)
        by_basename.setdefault(Path(relative).stem, relative)
    wanted = set()
    unknown = []
    for name in names:
        if name in SELF_TESTS:
            wanted.add(name)
        elif name in by_basename:
            wanted.add(by_basename[name])
        else:
            unknown.append(name)
    if unknown:
        raise SystemExit(
            "unknown self-test name(s): {}\nregistered tests:\n  {}".format(
                ", ".join(unknown), "\n  ".join(SELF_TESTS),
            )
        )
    return [relative for relative in SELF_TESTS if relative in wanted]


def select_tests(shard, only) -> list:
    tests = list(SELF_TESTS)
    if shard:
        k, n = shard
        tests = [t for i, t in enumerate(tests) if i % n == k - 1]
    if only:
        wanted = set(resolve_only(only))
        tests = [t for t in tests if t in wanted]
    return tests


def run_batch(context, items, cwd, timeout, jobs):
    """Run (name, command) items, preserving order; capture output per test."""
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        futures = [
            pool.submit(execute, name, command, cwd, timeout)
            for name, command in items
        ]
        results = [future.result() for future in futures]
    for result in results:
        result["context"] = context
    return results


def print_failures(records) -> None:
    for record in records:
        if record["status"] == "pass":
            continue
        print(
            f"--- FAIL {record['context']} :: {record['name']} "
            f"({record['status']}, exit={record['exit_code']}, "
            f"{record['seconds']:.1f}s) ---"
        )
        tail = output_text(record.get("output"))[-4000:]
        if tail.strip():
            print(tail)
        print("---")


def print_summary(records, wall_seconds) -> int:
    width = max((len(Path(r["name"]).name) for r in records), default=4)
    print("\ncontext            {:<{w}}  result   seconds".format("test", w=width))
    failures = 0
    for record in records:
        if record["status"] != "pass":
            failures += 1
        print(
            "{:<18} {:<{w}}  {:<8} {:>7.1f}".format(
                record["context"], Path(record["name"]).name,
                record["status"], record["seconds"], w=width,
            )
        )
    print(
        f"\ntotal={len(records)} passed={len(records) - failures} "
        f"failed={failures} wall={wall_seconds:.1f}s"
    )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template-root", default=".")
    parser.add_argument(
        "--report", default=None,
        help="report path (default: outputs/full-suite.json, or "
             "outputs/full-suite-shard-K-N.json for shard K/N)",
    )
    parser.add_argument(
        "--shard", type=parse_shard, default=None, metavar="K/N",
        help="run shard K of N over the registered self-test list",
    )
    parser.add_argument(
        "--only", nargs="+", default=None, metavar="NAME",
        help="run only the named self-tests (path, basename, or stem)",
    )
    parser.add_argument(
        "--test-timeout", type=int, default=300, metavar="SECONDS",
        help="per-test subprocess timeout (default: 300)",
    )
    parser.add_argument(
        "--full", action="store_true",
        help="run all three install contexts (default: idle-source only)",
    )
    parser.add_argument(
        "-j", "--jobs", type=int, default=4, metavar="N",
        help="parallel tests within a context (default: 4)",
    )
    args = parser.parse_args()
    if args.report is None:
        if args.shard:
            args.report = f"outputs/full-suite-shard-{args.shard[0]}-{args.shard[1]}.json"
        else:
            args.report = "outputs/full-suite.json"
    started = time.monotonic()
    source = Path(args.template_root).resolve()
    report = (source / args.report).resolve()
    # Hard tripwire: the registered list must match the on-disk inventory.
    assert_self_test_inventory(source)
    tests = select_tests(args.shard, args.only)
    if not tests:
        print("warning: selection is empty (no registered self-test matched)")
    contexts = ALL_CONTEXTS if args.full else DEFAULT_CONTEXTS
    records = []
    with tempfile.TemporaryDirectory(prefix="agent-workflow-self-suite-") as raw:
        workspace = Path(raw)
        for name in contexts:
            print(f"== context {name}: {len(tests)} self-tests "
                  f"(jobs={args.jobs}, timeout={args.test_timeout}s) ==")
            try:
                context = make_context(source, workspace, name)
            except RunFailure as error:
                records.append({
                    "context": name, "name": "install-context",
                    "status": "fail", **error.record,
                })
                continue
            context_records = []
            context_records.append(execute(
                "capture-runtime-baseline",
                [
                    sys.executable, ".agent/scripts/agentctl.py",
                    "capture-runtime-baseline",
                    "--source", "user:full-suite-controller",
                ],
                context, timeout=60,
            ))
            try:
                assert_self_test_inventory(context)
            except RuntimeError as error:
                context_records.append({
                    "context": name, "name": "self-test-inventory",
                    "status": "fail", "command": [], "cwd": str(context),
                    "exit_code": 1, "seconds": 0.0, "output": str(error),
                })
            if name == "polluted-source":
                context_records.append(execute(
                    "agent-state-validation",
                    [sys.executable, ".agent/scripts/agentctl.py", "validate"],
                    context, timeout=args.test_timeout,
                ))
                context_records.append(execute(
                    "context-validation",
                    [sys.executable, ".agent/scripts/contextctl.py", "check"],
                    context, timeout=args.test_timeout,
                ))
            batch = run_batch(
                name,
                [(relative, self_test_command(relative)) for relative in tests],
                context, timeout=args.test_timeout, jobs=args.jobs,
            )
            context_records.extend(batch)
            for control, command in (
                ("cleanup", [sys.executable, ".agent/scripts/agentctl.py", "cleanup"]),
                ("assert-clean", [sys.executable, ".agent/scripts/agentctl.py", "assert-clean"]),
            ):
                row = execute(control, command, context, timeout=60)
                row["context"] = name
                context_records.append(row)
            for row in context_records:
                row.setdefault("context", name)
            print_failures(context_records)
            records.extend(context_records)
        if args.shard is None or args.shard[0] == 1:
            # Source-level checks do not depend on the shard selection; running
            # them on every shard would duplicate them across the CI matrix.
            print(f"== context source: {len(SOURCE_CHECKS)} source-level checks ==")
            source_records = run_batch(
                "source",
                [source_check_command(entry) for entry in SOURCE_CHECKS],
                source, timeout=args.test_timeout, jobs=args.jobs,
            )
            for control, command in (
                ("cleanup", [sys.executable, ".agent/scripts/agentctl.py", "cleanup"]),
                ("assert-clean", [sys.executable, ".agent/scripts/agentctl.py", "assert-clean"]),
            ):
                row = execute(control, command, source, timeout=60)
                row["context"] = "source"
                source_records.append(row)
            print_failures(source_records)
            records.extend(source_records)
    wall_seconds = time.monotonic() - started
    failures = print_summary(records, wall_seconds)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({
        "schema": "agent-workflow-full-suite/v1",
        "status": "failed" if failures else "passed",
        "shard": f"{args.shard[0]}/{args.shard[1]}" if args.shard else None,
        "full": bool(args.full),
        "jobs": args.jobs,
        "test_timeout": args.test_timeout,
        "wall_seconds": round(wall_seconds, 3),
        "runs": records,
    }, ensure_ascii=False, indent=2) + "\n")
    try:
        display_report = report.relative_to(source)
    except ValueError:
        display_report = report
    if failures:
        print(f"SELF SUITE FAIL: failures={failures} runs={len(records)} report={display_report}")
        return 1
    print(f"SELF SUITE PASS: runs={len(records)} report={display_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
