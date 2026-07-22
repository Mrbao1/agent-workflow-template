#!/usr/bin/env python3
"""Bounded regression for cumulative test budgets and context control gates."""

from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap


SOURCE = Path(__file__).resolve().parent
AGENT = SOURCE.parent


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run(root: Path, *args: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
    if result.returncode != expected:
        raise AssertionError(f"expected {expected}, got {result.returncode}: {' '.join(args)}\n{result.stdout}")
    return result


def fixture(root: Path) -> None:
    scripts = root / ".agent/scripts"
    scripts.mkdir(parents=True)
    for name in ("testrun.py", "contextctl.py", "humandecision.py"):
        shutil.copy2(SOURCE / name, scripts / name)
    shutil.copytree(SOURCE / "workflowlib", scripts / "workflowlib")
    shutil.copy2(AGENT / "INDEX.md", root / ".agent/INDEX.md")
    shutil.copytree(AGENT / "workflows", root / ".agent/workflows")
    shutil.copytree(AGENT / "templates", root / ".agent/templates")
    config = {
        "routing": {"modes": {
            "fast": {"token_budget": 6000, "wall_time_minutes": 5, "max_automatic_test_attempts": 1},
            "standard": {"token_budget": 20000, "wall_time_minutes": 15, "max_automatic_test_attempts": 1},
            "release": {"token_budget": 40000, "wall_time_minutes": 45, "max_automatic_test_attempts": 1},
        }},
        "testing": {
            "max_automatic_full_chain_attempts": 1,
            "infrastructure_failure_consumes_code_retry": False,
            "attempt_classes": ["candidate", "test", "infrastructure"],
            "budget_registry": ".agent/state/test-budget.json",
            "budget_receipt_dir": ".agent/state/evidence/test-budgets",
        },
        "scope": {"fingerprint_paths": ["source.txt"]},
        "context": {
            "max_bytes": 8192, "max_list_items": 10,
            "max_capsule_tokens": {"fast": 2200, "standard": 2600, "release": 3200},
            "soft_budget_ratio": 0.6, "compact_budget_ratio": 0.75,
            "hard_budget_ratio": 0.9, "max_active_checkpoint_age_minutes": 45,
        },
        "agent_control": {
            "default_model": "gpt-5.6-sol",
            "human_decision_observer": {
                "source": "orchestrator-user-message", "automatic_gate_trust": False,
                "human_verification_required": True,
                "allow_current_chat_local_release": False, "signed_adapter": None,
                "max_receipt_age_seconds": 900,
            },
        },
    }
    task = {
        "schema": "agent-task/v2", "title": "budget fixture", "mode": "standard",
        "status": "in_progress", "phase": "implementation", "current_node": 6,
        "next_action": "test", "token_budget": 20000, "tokens_used": 0,
        "token_usage_source": "estimated", "usage_receipts": [], "budget_state": "ok",
        "loaded_references": [], "decisions": [], "open_questions": [],
        "requirements_clarified": False, "requirement_source": "pending",
        "environment": "local",
    }
    write(root / ".agent/config.json", config)
    write(root / ".agent/state/TASK.json", task)
    write(root / ".agent/state/test-budget.json", {"schema": "agent-test-budget/v1", "candidates": {}})
    (root / "source.txt").write_text("candidate one\n", encoding="utf-8")


def candidate(root: Path) -> str:
    result = run(
        root, sys.executable, "-c",
        "import json,sys;sys.path.insert(0,'.agent/scripts');import testrun;print(testrun.candidate_fingerprint(json.load(open('.agent/config.json'))))",
    )
    return result.stdout.strip()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="budget-context-gates-") as raw:
        root = Path(raw)
        fixture(root)
        runner = ".agent/scripts/testrun.py"
        # A caller cannot replace the 15-minute standard cap with a larger timeout.
        run(root, sys.executable, runner, "--receipt", "oversized.json", "--case", "oversized",
            "--timeout", "901", "--", sys.executable, "-c", "pass", expected=1)
        run_id = "a" * 32
        run(root, sys.executable, runner, "--receipt", "run.json", "--run-id", run_id,
            "--case", "one", "--timeout", "2", "--", sys.executable, "-c", "pass")
        # The same attempt may contain another planned case, but cumulative time
        # prevents each call from independently claiming the full 15 minutes.
        run(root, sys.executable, runner, "--receipt", "run.json", "--run-id", run_id,
            "--case", "two", "--timeout", "900", "--", sys.executable, "-c", "pass", expected=1)
        run(root, sys.executable, runner, "--receipt", "second.json", "--run-id", "b" * 32,
            "--case", "retry", "--timeout", "1", "--", sys.executable, "-c", "pass", expected=1)
        state = json.loads((root / ".agent/state/test-budget.json").read_text())
        record = state["candidates"][candidate(root)]
        latest = record["latest_receipt"]
        latest_path = root / latest["path"]
        if hashlib.sha256(latest_path.read_bytes()).hexdigest() != latest["sha256"]:
            raise AssertionError("budget receipt is not content-addressed")

        # A failed attempt is terminal. Changing the Case ID under the same
        # run_id must not turn one bounded attempt into an unbounded retry loop.
        (root / "source.txt").write_text("candidate sealed attempt\n", encoding="utf-8")
        sealed_run_id = "9" * 32
        run(root, sys.executable, runner, "--receipt", "sealed.json", "--run-id", sealed_run_id,
            "--case", "failing-case", "--timeout", "2", "--", sys.executable, "-c",
            "raise SystemExit(7)", expected=7)
        sealed = run(root, sys.executable, runner, "--receipt", "sealed.json", "--run-id", sealed_run_id,
            "--case", "renamed-case", "--timeout", "2", "--", sys.executable, "-c", "pass", expected=1)
        if "failed candidate test attempt is sealed" not in sealed.stdout:
            raise AssertionError("failed attempt accepted another Case ID")

        # Dead runner reservations charge their full amount and cannot remain a
        # permanent lock or reopen elapsed budget after a crash.
        (root / "source.txt").write_text("candidate crash\n", encoding="utf-8")
        crash_candidate = candidate(root)
        state = json.loads((root / ".agent/state/test-budget.json").read_text())
        state["candidates"][crash_candidate] = {
            "mode": "standard", "budget_seconds": 900,
            "max_automatic_test_attempts": 1, "consumed_seconds": 0,
            "infrastructure_failures": 0, "attempts": {},
            "active_reservations": [{
                "id": "dead", "pid": 99999999, "run_id": "c" * 32,
                "case": "dead", "reserved_seconds": 899,
                "started_at": "2026-01-01T00:00:00+00:00",
            }], "latest_receipt": None,
        }
        write(root / ".agent/state/test-budget.json", state)
        run(root, sys.executable, runner, "--receipt", "crash.json", "--run-id", "d" * 32,
            "--case", "after-crash", "--timeout", "2", "--", sys.executable, "-c", "pass", expected=1)
        state = json.loads((root / ".agent/state/test-budget.json").read_text())
        if state["candidates"][crash_candidate]["consumed_seconds"] != 0:
            # Reconciliation is deliberately committed only together with a new
            # reservation. A rejected oversized reservation makes no state claim.
            raise AssertionError("rejected reservation partially mutated the atomic budget")
        run(root, sys.executable, runner, "--receipt", "crash.json", "--run-id", "d" * 32,
            "--case", "bounded-after-crash", "--timeout", "1", "--", sys.executable, "-c", "pass")
        state = json.loads((root / ".agent/state/test-budget.json").read_text())
        recovered = state["candidates"][crash_candidate]
        if recovered["active_reservations"] or recovered["consumed_seconds"] != 900:
            raise AssertionError("dead reservation was not conservatively recovered and closed")

        # A cleanup failure with an inherited stdout pipe must return partial
        # output within a bound, classify as infrastructure, and require a
        # provider-approved one-launch remediation instead of locking forever.
        (root / "source.txt").write_text("candidate infrastructure\n", encoding="utf-8")
        fake_runner = root / ".agent/fixtures/fake-pipe-runner.py"
        fake_runner.parent.mkdir(parents=True, exist_ok=True)
        fake_runner.write_text(textwrap.dedent(f"""
            import os, subprocess, sys
            os.chdir({str(root)!r})
            sys.path.insert(0, '.agent/scripts')
            import testrun

            class Pipe:
                closed = False
                def close(self):
                    self.closed = True

            class Process:
                pid = 777777
                returncode = None
                stdout = Pipe()
                def communicate(self, timeout=None):
                    if timeout is None:
                        raise AssertionError('unbounded communicate/read attempted')
                    raise subprocess.TimeoutExpired(['fixture'], timeout, output=b'partial-output\\n')
                def poll(self):
                    return self.returncode
                def wait(self, timeout=None):
                    raise subprocess.TimeoutExpired(['fixture'], timeout)

            testrun.subprocess.Popen = lambda *args, **kwargs: Process()
            testrun.terminate_group = lambda process: True
            sys.argv = [
                'testrun.py', '--receipt', 'infra.json', '--run-id', {'e' * 32!r},
                '--case', 'pipe-cleanup', '--timeout', '1', '--', sys.executable, '-c', 'pass',
            ]
            raise SystemExit(testrun.main())
        """), encoding="utf-8")
        infrastructure_candidate = candidate(root)
        run(root, sys.executable, str(fake_runner), expected=125)
        state = json.loads((root / ".agent/state/test-budget.json").read_text())
        infrastructure = state["candidates"][infrastructure_candidate]
        if infrastructure["infrastructure_failures"] != 1:
            raise AssertionError("runner-observed cleanup failure was not classified as infrastructure")
        if [item.get("track") for item in infrastructure["attempts"].values()] != ["infrastructure"]:
            raise AssertionError("infrastructure failure consumed the code-attempt track")
        run(root, sys.executable, runner, "--receipt", "blocked.json", "--run-id", "f" * 32,
            "--case", "after-infra", "--timeout", "1", "--", sys.executable, "-c", "pass", expected=1)

        prepared = run(
            root, sys.executable, runner, "--prepare-infrastructure-remediation",
            "--next-run-id", "f" * 32, "--next-case", "after-infra",
        )
        request_path = prepared.stdout.split("path=", 1)[1].split(" ", 1)[0]
        request_sha = prepared.stdout.split("sha256=", 1)[1].split(" ", 1)[0]
        apply_wrapper = root / ".agent/fixtures/apply-remediation.py"
        apply_wrapper.write_text(textwrap.dedent(f"""
            import os, sys
            os.chdir({str(root)!r})
            sys.path.insert(0, '.agent/scripts')
            import testrun

            observed = {{}}
            def verified(root, config, task, **kwargs):
                observed.update(kwargs)
                return {{
                    'schema': 'agent-human-decision/v1', 'path': '.agent/state/evidence/provider.json',
                    'sha256': {'1' * 64!r}, 'bytes': 1, 'decision_id': 'fixture',
                    'authority': 'provider-signed-user-message', 'adapter_path': '/provider/fixture',
                    'adapter_sha256': {'2' * 64!r},
                }}
            testrun.humandecision.verify = verified
            sys.argv = [
                'testrun.py', '--apply-infrastructure-remediation',
                '--remediation-request', {request_path!r},
                '--human-decision-source', 'user:fixture-approved',
                '--human-decision-receipt', '.agent/state/evidence/provider.json',
            ]
            code = testrun.main()
            assert observed['gate'] == 'test-infrastructure-remediation'
            assert observed['artifact_sha256'] == {request_sha!r}
            assert observed['source'] == 'user:fixture-approved'
            assert observed['require_fresh'] is True
            raise SystemExit(code)
        """), encoding="utf-8")
        run(root, sys.executable, str(apply_wrapper))
        state = json.loads((root / ".agent/state/test-budget.json").read_text())
        remediated = state["candidates"][infrastructure_candidate]
        if remediated["infrastructure_failures"] != 0 or len(remediated["infrastructure_remediations"]) != 1:
            raise AssertionError("provider-approved remediation did not clear exactly one infrastructure block")
        if remediated["remediation_allowance"] != {
            "request_sha256": request_sha, "run_id": "f" * 32, "case": "after-infra",
            "applied_at": remediated["remediation_allowance"]["applied_at"],
        }:
            raise AssertionError("remediation was not restricted to one exact next launch")
        run(root, sys.executable, runner, "--receipt", "wrong.json", "--run-id", "f" * 32,
            "--case", "wrong-case", "--timeout", "1", "--", sys.executable, "-c", "pass", expected=1)
        run(root, sys.executable, runner, "--receipt", "recovered.json", "--run-id", "f" * 32,
            "--case", "after-infra", "--timeout", "1", "--", sys.executable, "-c", "pass")
        state = json.loads((root / ".agent/state/test-budget.json").read_text())
        remediated = state["candidates"][infrastructure_candidate]
        if remediated["remediation_allowance"] is not None:
            raise AssertionError("single-launch remediation allowance was replayable")
        if len([item for item in remediated["attempts"].values() if item.get("track") == "code"]) != 1:
            raise AssertionError("infrastructure failure incorrectly consumed the one code retry")
        run(root, sys.executable, str(apply_wrapper), expected=1)

        # Repair remains needs_review when only a caller label is supplied.
        context = run(root, sys.executable, ".agent/scripts/contextctl.py", "sync",
            "--reason", "initial", "--summary", "bounded fixture", "--source-tokens", "1000")
        if "VALID context capsule" not in context.stdout:
            raise AssertionError("freshness-bound context was not created")
        (root / ".agent/state/CONTEXT.json").write_text("corrupt", encoding="utf-8")
        run(root, sys.executable, ".agent/scripts/contextctl.py", "repair", "--reset",
            "--reason", "corrupt", "--summary", "reconstructed", "--source-tokens", "1000", expected=1)
        run(root, sys.executable, ".agent/scripts/contextctl.py", "approve-repair",
            "--source", "user:forged", expected=2)
        repaired = json.loads((root / ".agent/state/CONTEXT.json").read_text())
        if repaired["integrity"]["status"] != "needs_review":
            raise AssertionError("unverified repair approval mutated context")
    print("PASS: atomic and sealed test budget, bounded pipe cleanup, provider-gated infrastructure remediation, context freshness and repair approval gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
