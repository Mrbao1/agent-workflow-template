#!/usr/bin/env python3
"""Bounded regression for cumulative test budgets and context control gates."""

from pathlib import Path
import base64
import hashlib
import json
import re
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
    for name in ("testrun.py", "contextctl.py", "contexttx.py", "humandecision.py"):
        shutil.copy2(SOURCE / name, scripts / name)
    shutil.copytree(SOURCE / "workflowlib", scripts / "workflowlib")
    shutil.copy2(AGENT / "INDEX.md", root / ".agent/INDEX.md")
    shutil.copytree(AGENT / "workflows", root / ".agent/workflows")
    shutil.copytree(AGENT / "templates", root / ".agent/templates")
    shutil.copytree(AGENT / "policies", root / ".agent/policies")
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
            "estimated_turn_overhead_tokens": {"fast": 150, "standard": 300, "release": 500},
            "bootstrap_overhead_tokens": 1200,
            "soft_budget_ratio": 0.6, "compact_budget_ratio": 0.75,
            "hard_budget_ratio": 0.9, "max_active_checkpoint_age_minutes": 45,
            "host_compaction_observer": {
                "source": "host-runtime-receipt", "signed_adapter": None,
                "max_receipt_age_seconds": 300,
            },
        },
        "agent_control": {
            "default_model": "gpt-5.6-sol",
            "dispatch_payload_token_limits": {"fast": 0, "standard": 4000, "release": 8000},
            "inherited_turn_estimated_tokens": 800,
            "human_decision_observer": {
                "source": "orchestrator-user-message", "automatic_gate_trust": False,
                "human_verification_required": True,
                "allow_current_chat_local_release": False, "signed_adapter": None,
                "max_receipt_age_seconds": 900,
            },
        },
    }
    task = {
        "schema": "agent-task/v2", "title": "budget fixture", "task_type": "maintenance",
        "complexity": "small", "mode": "standard", "files": 1,
        "status": "in_progress", "phase": "implementation", "current_node": 6,
        "next_action": "test", "token_budget": 20000, "tokens_used": 0,
        "token_usage_source": "estimated", "usage_receipts": [], "budget_state": "ok",
        "loaded_references": [], "decisions": [], "open_questions": [],
        "requirements_clarified": False, "requirement_source": "pending",
        "environment": "local", "deployment_requested": False, "branch": "unversioned",
        "risk_flags": {name: False for name in (
            "deploy", "data_risk", "cross_system", "uncertain", "security",
            "compliance", "migration", "irreversible", "external_impact",
        )},
        "decision_policy_version": 2,
    }
    write(root / ".agent/config.json", config)
    write(root / ".agent/state/TASK.json", task)
    write(root / ".agent/state/test-budget.json", {"schema": "agent-test-budget/v1", "candidates": {}})
    (root / "source.txt").write_text("candidate one\n", encoding="utf-8")


def rewrite_context(root: Path, body: str) -> None:
    """Rewrite CONTEXT.json through a probe that keeps its own integrity chain valid."""
    probe = subprocess.run(
        [sys.executable, "-c", (
            "import json,sys;sys.path.insert(0,'.agent/scripts');import contextctl;"
            "p='.agent/state/CONTEXT.json';v=json.load(open(p));"
            + body
            + "comp=v['compaction'];est=contextctl.normalized_token_estimate(v);"
            "comp['capsule_estimated_tokens']=est;"
            "comp['tokens_removed']=int(comp['source_estimated_tokens'])-est;"
            "comp['compression_ratio']=round(int(comp['source_estimated_tokens'])/max(est,1),2);"
            "v['integrity']['content_sha256']='0'*64;"
            "v['integrity']['content_sha256']=contextctl.content_sha256(v);"
            "open(p,'w').write(json.dumps(v,ensure_ascii=False,indent=2)+'\\n')"
        )],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if probe.returncode:
        raise AssertionError(probe.stdout)


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

        # --- Context control gates (contextctl/contexttx/humandecision) ---
        contextctl = ".agent/scripts/contextctl.py"
        task_path = root / ".agent/state/TASK.json"
        context_path = root / ".agent/state/CONTEXT.json"

        # A host-compaction request on initial creation would fabricate a
        # handoff that was never written.
        denied = run(root, sys.executable, contextctl, "sync",
            "--reason", "premature-handoff", "--summary", "no capsule exists yet",
            "--source-tokens", "1000", "--request-host-compaction", expected=1)
        if "no handoff has been written" not in denied.stdout:
            raise AssertionError("initial host-compaction request was not rejected")

        context = run(root, sys.executable, contextctl, "sync",
            "--reason", "initial", "--summary", "bounded fixture", "--source-tokens", "1000")
        if "VALID context capsule" not in context.stdout:
            raise AssertionError("freshness-bound context was not created")
        capsule = json.loads(context_path.read_text())
        if capsule.get("policy_bundle_version") != "policy-bundle/v2":
            raise AssertionError("fresh capsule did not record policy-bundle/v2")

        # With a null host-compaction observer adapter, entering the awaiting
        # state is a one-way deadlock and must be rejected up front.
        denied = run(root, sys.executable, contextctl, "sync",
            "--reason", "host-compaction-handoff", "--summary", "await the host",
            "--source-tokens", "1000", "--request-host-compaction", expected=1)
        if "signed_adapter" not in denied.stdout:
            raise AssertionError("null-adapter host-compaction request was not rejected")

        # policy-bundle/v2 binds enforcement code and guardrails: editing
        # either is policy drift.
        for drift_path in (
            root / ".agent/policies/PROJECT_GUARDRAILS.md",
            root / ".agent/scripts/workflowlib/budget.py",
        ):
            original_bytes = drift_path.read_bytes()
            drift_path.write_bytes(original_bytes + b"# drift probe\n")
            run(root, sys.executable, contextctl, "check", "--quiet", expected=1)
            drift_path.write_bytes(original_bytes)
            run(root, sys.executable, contextctl, "check", "--quiet")

        # An authentic policy-bundle/v1 capsule stays valid and is upgraded to
        # v2 by the next plain sync (one-shot migration).
        rewrite_context(root, (
            "v.pop('policy_bundle_version',None);"
            "t=json.load(open('.agent/state/TASK.json'));"
            "v['policy_bundle_sha256']=contextctl.policy_bundle_sha256(t,contextctl.LEGACY_POLICY_BUNDLE_VERSION);"
        ))
        run(root, sys.executable, contextctl, "check", "--quiet")
        run(root, sys.executable, contextctl, "sync",
            "--reason", "bundle-upgrade", "--summary", "upgrade legacy bundle", "--source-tokens", "1000")
        capsule = json.loads(context_path.read_text())
        if capsule.get("policy_bundle_version") != "policy-bundle/v2":
            raise AssertionError("legacy policy-bundle/v1 capsule was not upgraded by sync")

        # A pre-freshness legacy capsule (only its usage freshness receipt
        # missing) is upgraded by one plain sync, and nothing else passes.
        rewrite_context(root, "v.pop('usage_freshness',None);")
        run(root, sys.executable, contextctl, "check", "--quiet", expected=1)
        run(root, sys.executable, contextctl, "sync",
            "--reason", "freshness-upgrade", "--summary", "upgrade legacy usage receipt", "--source-tokens", "1000")
        if "usage_freshness" not in json.loads(context_path.read_text()):
            raise AssertionError("legacy usage capsule was not upgraded by sync")

        # Repair approval routes through the task decision policy: provider
        # routes still demand a signed receipt, while the default (no adapter)
        # v2 local boundary accepts a bound local user-message approval.
        context_path.write_text("corrupt", encoding="utf-8")
        run(root, sys.executable, contextctl, "repair", "--reset",
            "--reason", "corrupt", "--summary", "reconstructed", "--source-tokens", "1000", expected=1)
        run(root, sys.executable, contextctl, "check", "--quiet", expected=1)
        task = json.loads(task_path.read_text())
        task["decision_policy_version"] = 1
        write(task_path, task)
        denied = run(root, sys.executable, contextctl, "approve-repair",
            "--source", "user:forged", expected=1)
        if "provider-signed human decision receipt" not in denied.stdout:
            raise AssertionError("provider-routed repair approval did not demand a receipt")
        repaired = json.loads(context_path.read_text())
        if repaired["integrity"]["status"] != "needs_review":
            raise AssertionError("unverified repair approval mutated context")
        task["decision_policy_version"] = 2
        write(task_path, task)
        run(root, sys.executable, contextctl, "approve-repair", "--source", "user:fixture-review")
        repaired = json.loads(context_path.read_text())
        approval = repaired["integrity"].get("repair_approval", {})
        if (
            repaired["integrity"]["status"] != "verified"
            or approval.get("assurance") != "explicit-user-message;local-only;not-provider-verified"
            or not re.fullmatch(r"[0-9a-f]{64}", str(approval.get("routing_profile_sha256", "")))
        ):
            raise AssertionError("local repair approval was not recorded with its routing profile")
        run(root, sys.executable, contextctl, "check", "--quiet")

        # A canonical transition cleans up its crash journal and records
        # non-invariant TASK changes for audit.
        transition = run(root, sys.executable, "-c", (
            "import copy,json,sys;sys.path.insert(0,'.agent/scripts');import contexttx;"
            "p='.agent/state/TASK.json';before=json.load(open(p));after=copy.deepcopy(before);"
            "after['next_action']='journal probe transition';after['scratch_note']='audit me';"
            "contexttx.transition_task(before,after,mutator='workflowctl',operation='advance',"
            "reason='journal-probe',summary='exercise the transition journal')"
        ))
        journal_path = root / ".agent/state/.context-transition-journal.json"
        if journal_path.exists():
            raise AssertionError("successful transition left a crash journal behind")
        capsule = json.loads(context_path.read_text())
        authorization = capsule["checkpoint"]["transition_authorization"]
        if authorization.get("non_invariant_changed_fields") != ["scratch_note"]:
            raise AssertionError("non-invariant TASK change was not audited in the transition receipt")
        if json.loads(task_path.read_text()).get("scratch_note") != "audit me":
            raise AssertionError("canonical transition did not commit the non-invariant field")

        # A stuck awaiting_host_compaction capsule pauses sync and plain
        # repair, but repair --reset rebuilds without resurrecting the wait.
        awaiting_body = (
            "v['host_compaction']={'schema':'agent-host-compaction-state/v1',"
            "'state':'awaiting_host_compaction','history':['handoff_written'],'receipt':None};"
        )
        rewrite_context(root, awaiting_body)
        paused = run(root, sys.executable, contextctl, "sync",
            "--reason", "paused", "--summary", "must be paused", "--source-tokens", "1400", expected=1)
        if "paused" not in paused.stdout:
            raise AssertionError("sync was not paused by the awaiting host compaction")
        run(root, sys.executable, contextctl, "repair",
            "--reason", "paused", "--summary", "plain repair stays paused", "--source-tokens", "1000", expected=1)
        run(root, sys.executable, contextctl, "repair", "--reset",
            "--reason", "stuck", "--summary", "rebuild a stuck awaiting capsule", "--source-tokens", "1000", expected=1)
        rebuilt = json.loads(context_path.read_text())
        if "host_compaction" in rebuilt:
            raise AssertionError("repair --reset resurrected the awaiting host compaction state")
        run(root, sys.executable, contextctl, "approve-repair", "--source", "user:unstick")
        run(root, sys.executable, contextctl, "check", "--quiet")

        # abort-host-compaction clears the wait under the same approval
        # discipline, preserves the checkpoint and records the aborted event.
        rewrite_context(root, awaiting_body)
        stuck = json.loads(context_path.read_text())
        denied = run(root, sys.executable, contextctl, "abort-host-compaction",
            "--source", "agent:not-a-user", expected=1)
        aborted = run(root, sys.executable, contextctl, "abort-host-compaction",
            "--source", "user:abort-the-wait")
        if "HOST COMPACTION ABORTED" not in aborted.stdout:
            raise AssertionError("abort-host-compaction did not clear the awaiting state")
        capsule = json.loads(context_path.read_text())
        abort_event = capsule["compaction"].get("host_compaction_abort", {})
        if (
            "host_compaction" in capsule
            or abort_event.get("event") != "aborted"
            or abort_event.get("source") != "user:abort-the-wait"
            or capsule["checkpoint"] != stuck["checkpoint"]
        ):
            raise AssertionError("abort did not preserve the checkpoint or record the aborted event")
        run(root, sys.executable, contextctl, "abort-host-compaction",
            "--source", "user:double-abort", expected=1)
        run(root, sys.executable, contextctl, "sync",
            "--reason", "post-abort", "--summary", "renew after abort", "--source-tokens", "1000")

        # A leftover transition journal classifies the crash and restores the
        # pre-commit bytes; a stale committed journal can only be discarded.
        task_bytes = task_path.read_bytes()
        context_bytes = context_path.read_bytes()
        tampered = json.loads(task_bytes)
        tampered["scratch_note"] = "tampered mid-commit"
        write(task_path, tampered)
        tampered_bytes = task_path.read_bytes()

        def journal_entry(data: bytes) -> dict[str, object]:
            return {
                "data_b64": base64.b64encode(data).decode("ascii"),
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }

        write(journal_path, {
            "schema": "agent-context-transition-journal/v1",
            "mutator": "workflowctl", "operation": "advance", "reason": "crash-fixture",
            "issued_at": "2026-07-30T00:00:00+00:00",
            "backups": {
                ".agent/state/TASK.json": journal_entry(task_bytes),
                ".agent/state/CONTEXT.json": journal_entry(context_bytes),
            },
            "absent_before": [],
            "after_sha256": {
                ".agent/state/TASK.json": hashlib.sha256(tampered_bytes).hexdigest(),
                ".agent/state/CONTEXT.json": None,
            },
        })
        status = json.loads(run(root, sys.executable, contextctl, "journal", expected=1).stdout)
        if status.get("state") != "interrupted" or "--restore" not in status.get("recovery", ""):
            raise AssertionError("interrupted transition journal was not classified for restore")
        run(root, sys.executable, contextctl, "journal", "--discard", expected=1)
        run(root, sys.executable, contextctl, "journal", "--restore")
        if task_path.read_bytes() != task_bytes:
            raise AssertionError("journal restore did not roll back the pre-commit TASK bytes")
        run(root, sys.executable, contextctl, "check", "--quiet")
        status = json.loads(run(root, sys.executable, contextctl, "journal").stdout)
        if status.get("state") != "none":
            raise AssertionError("restored transition journal was not cleaned up")

        write(journal_path, {
            "schema": "agent-context-transition-journal/v1",
            "mutator": "workflowctl", "operation": "advance", "reason": "crash-after-commit",
            "issued_at": "2026-07-30T00:00:00+00:00",
            "backups": {
                ".agent/state/TASK.json": journal_entry(tampered_bytes),
                ".agent/state/CONTEXT.json": journal_entry(context_bytes),
            },
            "absent_before": [],
            "after_sha256": {
                ".agent/state/TASK.json": hashlib.sha256(task_bytes).hexdigest(),
                ".agent/state/CONTEXT.json": None,
            },
        })
        context_path.write_bytes(context_bytes + b" \n")
        status = json.loads(run(root, sys.executable, contextctl, "journal", expected=1).stdout)
        if status.get("state") != "committed" or "--discard" not in status.get("recovery", ""):
            raise AssertionError("committed transition journal was not classified for discard")
        run(root, sys.executable, contextctl, "journal", "--discard")
        context_path.write_bytes(context_bytes)
        run(root, sys.executable, contextctl, "check", "--quiet")

        # Function-level contracts: plural usage receipts, guarded risk flags,
        # routing-profile-bound local approvals, retroactive config tightening
        # and the non-raising adapter resolver.
        run(root, sys.executable, "-c", textwrap.dedent("""
            import json, sys
            sys.path.insert(0, '.agent/scripts')
            import contextctl, humandecision
            from workflowlib import budget, state

            config = json.load(open('.agent/config.json'))
            config.setdefault('agent_control', {})['usage_observer'] = {'signed_adapter': '/adapter'}
            measured = {
                'mode': 'standard', 'token_budget': 20000, 'tokens_used': 0,
                'token_usage_source': 'measured', 'loaded_references': [],
                'usage_receipts': [{'sha256': '0' * 64, 'semantics': 'cumulative'}],
            }
            level = budget.snapshot(measured, config)['assurance']['level']
            assert level == 'provider-observed-measurement', level
            measured['usage_receipts'] = []
            level = budget.snapshot(measured, config)['assurance']['level']
            assert level == 'best-effort-estimate', level
            assert state.required_mode('local', 1, 'not-a-dict', 'maintenance', 'tiny') == 'fast'
            assert state.monotonic_risks(None, []) == {name: False for name in state.RISK_NAMES}

            release_task = {
                'decision_policy_version': 2, 'environment': 'local', 'mode': 'release',
                'deployment_requested': False, 'risk_flags': {}, 'task_type': 'governance',
                'complexity': 'small', 'files': 1, 'branch': 'unversioned',
            }
            artifact = 'a' * 64
            approval = humandecision.local_approval('user:fixture', artifact, release_task)
            assert approval['routing_profile_sha256'] == humandecision.routing_profile_sha256(release_task)
            assert humandecision.local_approval_valid(
                release_task, approval, source='user:fixture', artifact_sha256=artifact)
            observer = dict(humandecision.POLICY)
            tightened = {'agent_control': {'human_decision_observer': observer}}
            assert not humandecision.local_approval_valid(
                release_task, approval, source='user:fixture', artifact_sha256=artifact, config=tightened)
            permissive = {'agent_control': {'human_decision_observer': {
                **humandecision.POLICY, 'allow_current_chat_local_release': True}}}
            assert humandecision.local_approval_valid(
                release_task, approval, source='user:fixture', artifact_sha256=artifact, config=permissive)
            legacy = {key: approval[key] for key in ('source', 'artifact_sha256', 'assurance')}
            assert humandecision.local_approval_valid(
                release_task, legacy, source='user:fixture', artifact_sha256=artifact, config=permissive)
            forged = dict(approval, routing_profile_sha256='b' * 64)
            assert not humandecision.local_approval_valid(
                release_task, forged, source='user:fixture', artifact_sha256=artifact, config=permissive)

            assert humandecision.try_adapter_path(None, None) is None
            assert humandecision.try_adapter_path(None, '  ') is None
            assert 'projection' in contextctl.TASK_INVARIANT_KEYS
            assert 'projection' not in contextctl.task_invariant({'title': 'x'})
            assert contextctl.task_invariant({'title': 'x', 'projection': 'lightweight'})['projection'] == 'lightweight'
            print('function probes OK')
        """))

        # --- P7 token-ledger calibration gates ---
        # The shipped template config satisfies the arithmetic invariant with
        # real headroom: one fully-charged standard child must not reach
        # must_compact, and the bootstrap overhead is counted exactly once.
        run(root, sys.executable, "-c", textwrap.dedent(f"""
            import json, sys
            sys.path.insert(0, '.agent/scripts')
            import contextctl
            from workflowlib import budget

            shipped = json.load(open({str(AGENT / "config.json")!r}))
            errors = budget.config_budget_errors(shipped)
            assert errors == [], errors

            child = {{'fork_turns': 0, 'token_reservation': {{'status': 'reserved', 'estimated_tokens': 16000}}}}
            task = {{'mode': 'standard', 'token_budget': 48000, 'tokens_used': 0,
                    'token_usage_source': 'estimated', 'loaded_references': []}}
            snap = budget.snapshot(task, shipped, additional_child=child)
            assert snap['bootstrap_overhead_tokens'] == 7000, snap
            assert snap['root_tokens'] == 7000, snap
            assert snap['child_reserved_tokens'] == 22000, snap
            assert snap['state'] != 'must_compact', snap
            task['tokens_used'] = 9000
            again = budget.snapshot(task, shipped, additional_child=child)
            assert again['root_tokens'] == 9000, again
            assert again['consumed_tokens'] - snap['consumed_tokens'] == 2000, (snap, again)

            bad = json.loads(json.dumps(shipped))
            bad['routing']['modes']['standard']['token_budget'] = 24000
            errors = budget.config_budget_errors(bad)
            assert errors, 'shrunk standard budget must violate the invariant'
            message = errors[0]
            for field in ('dispatch_payload_token_limits.standard', 'child_system_tool_margin_tokens',
                          'child_output_margin_tokens', 'bootstrap_overhead_tokens',
                          'estimated_turn_overhead_tokens.standard', 'hard_budget_ratio'):
                assert field in message, (field, message)

            # The deprecated alias keeps its exact legacy arithmetic; the
            # current key charges turn overhead + inherited host context.
            previous = {{'usage_freshness': {{'estimated_tokens': 1000}}}}
            plain = {{'mode': 'standard', 'usage_receipts': []}}
            legacy = {{'context': {{'automatic_transition_token_increment': {{'standard': 300}}}}, 'agent_control': {{}}}}
            assert contextctl.automatic_transition_source_tokens(legacy, previous, plain) == 1300
            current = {{'context': {{'estimated_turn_overhead_tokens': {{'standard': 300}}}},
                        'agent_control': {{'inherited_turn_estimated_tokens': 800}}}}
            assert contextctl.automatic_transition_source_tokens(current, previous, plain) == 2100

            # A provider-observed delta between the two latest cumulative
            # receipts is preferred over the configured estimate; a shrinking
            # delta (real compaction) falls back to the estimate.
            measured = {{'mode': 'standard', 'usage_receipts': [
                {{'total_tokens': 5000, 'sha256': '0' * 64}},
                {{'total_tokens': 14000, 'sha256': '1' * 64}},
            ]}}
            assert contextctl.automatic_transition_source_tokens(current, previous, measured) == 10000
            shrinking = {{'mode': 'standard', 'usage_receipts': [
                {{'total_tokens': 9000, 'sha256': '0' * 64}},
                {{'total_tokens': 4000, 'sha256': '1' * 64}},
            ]}}
            assert contextctl.automatic_transition_source_tokens(current, previous, shrinking) == 2100
            print('P7 function probes OK')
        """))

        # The invariant is enforced fail-closed at capsule validation: a
        # config that lets one permitted child cross the hard watermark is
        # rejected with a message naming the offending fields.
        config_path = root / ".agent/config.json"
        fixture_config = json.loads(config_path.read_text())
        broken = json.loads(json.dumps(fixture_config))
        broken["agent_control"]["dispatch_payload_token_limits"]["standard"] = 16000
        write(config_path, broken)
        denied = run(root, sys.executable, contextctl, "check", expected=1)
        if (
            "dispatch_payload_token_limits.standard" not in denied.stdout
            or "hard_budget_ratio" not in denied.stdout
            or "bootstrap_overhead_tokens" not in denied.stdout
        ):
            raise AssertionError(f"capsule validation did not fail closed on the budget invariant:\n{denied.stdout}")
        write(config_path, fixture_config)
        run(root, sys.executable, contextctl, "check", "--quiet")
    print("PASS: atomic and sealed test budget, bounded pipe cleanup, provider-gated infrastructure remediation, context freshness, bundle migration, host-compaction and journal gates, token-ledger calibration")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
