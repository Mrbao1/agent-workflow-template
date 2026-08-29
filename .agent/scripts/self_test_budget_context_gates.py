#!/usr/bin/env python3
"""Bounded regression for cumulative test budgets and context control gates."""

from pathlib import Path
import base64
import hashlib
import json
import os
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
    for name in (
        "testrun.py", "agentctl.py", "contextctl.py", "contexttx.py",
        "humandecision.py", "process_observation.py",
    ):
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
            "transition_token_increment": {"fast": 200, "standard": 400, "release": 800},
            "bootstrap_overhead_tokens": 1200,
            "soft_budget_ratio": 0.6, "compact_budget_ratio": 0.75,
            "hard_budget_ratio": 0.9, "max_active_checkpoint_age_minutes": 45,
            "host_compaction_observer": {
                "source": "host-runtime-receipt", "signed_adapter": None,
                "max_receipt_age_seconds": 300,
            },
        },
        "agent_control": {
            "default_model": "provider-neutral/primary-model-v1",
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
            "comp['capsule_reduction_tokens']=int(comp['source_estimated_tokens'])-est;"
            "comp['tokens_removed']=0;"
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


def install_test_provider_verifier(root: Path) -> str:
    """Install a subprocess-only provider verifier; production code stays untouched."""
    receipt = root / ".agent/state/evidence/test-provider-decision.json"
    write(receipt, {"test_only": "provider-owned adapter input"})
    patch_dir = root / ".agent/fixtures/provider-sitecustomize"
    patch_dir.mkdir(parents=True)
    (patch_dir / "sitecustomize.py").write_text(textwrap.dedent(r'''
        import json
        from pathlib import Path
        import humandecision

        def provider_verify(root, _config, _task, *, receipt=None, **_kwargs):
            path = (Path(root) / str(receipt)).resolve()
            expected = {"test_only": "provider-owned adapter input"}
            if json.loads(path.read_text(encoding="utf-8")) != expected:
                raise SystemExit("self-test provider verifier rejected receipt fixture")
            return {
                "schema": "agent-human-decision/v1",
                "path": str(path.relative_to(Path(root).resolve())),
                "sha256": "f" * 64,
                "bytes": path.stat().st_size,
                "decision_id": "self-test-provider",
                "authority": "provider-signed-user-message",
                "adapter_path": "/self-test/provider-verifier",
                "adapter_sha256": "e" * 64,
            }

        def provider_reverify(root, config, task, *, record=None, **kwargs):
            try:
                if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                    return False
                return record == provider_verify(
                    root, config, task, receipt=record["path"], **kwargs
                )
            except (OSError, ValueError, TypeError, SystemExit, json.JSONDecodeError):
                return False

        humandecision.verify = provider_verify
        humandecision.reverify = provider_reverify
    '''), encoding="utf-8")
    scripts = root / ".agent/scripts"
    inherited = os.environ.get("PYTHONPATH")
    paths = [str(patch_dir), str(scripts)]
    if inherited:
        paths.append(inherited)
    os.environ["PYTHONPATH"] = os.pathsep.join(paths)
    return str(receipt.relative_to(root))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="budget-context-gates-") as raw:
        root = Path(raw)
        fixture(root)
        runner = ".agent/scripts/testrun.py"
        # Ignored authoritative dependencies cannot trigger a writable-root fallback.
        (root / "node_modules").mkdir()
        refused=run(root,sys.executable,runner,"--receipt","dependency.json","--case","dependency",
                    "--timeout","2","--","npm","test",expected=1)
        if "absent from the private candidate" not in refused.stdout:
            raise AssertionError(f"private dependency refusal failed for the wrong reason:\n{refused.stdout}")
        if json.loads((root/".agent/state/test-budget.json").read_text())["candidates"]:
            raise AssertionError("dependency compatibility refusal consumed a test reservation")
        (root / "node_modules").rmdir()
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

        # Dead or PID-reused runner reservations charge their full amount and cannot
        # remain a permanent lock or reopen elapsed budget after a crash.
        (root / "source.txt").write_text("candidate crash\n", encoding="utf-8")
        crash_candidate = candidate(root)
        state = json.loads((root / ".agent/state/test-budget.json").read_text())
        state["candidates"][crash_candidate] = {
            "mode": "standard", "budget_seconds": 900,
            "max_automatic_test_attempts": 1, "consumed_seconds": 0,
            "infrastructure_failures": 0, "attempts": {},
            "active_reservations": [{
                "id": "dead", "pid": os.getpid(), "start_identity": "reused-pid-start-object", "run_id": "c" * 32,
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
            import io, os, subprocess, sys
            os.chdir({str(root)!r})
            sys.path.insert(0, '.agent/scripts')
            import testrun

            class Process:
                pid = 777777
                returncode = None
                stdout = io.BytesIO(b'partial-output\\n')

            testrun.launch_supervised_process = lambda *args, **kwargs: Process()
            testrun.process_snapshot = lambda: {{777777: (1, 777777, 'fixture-start', 'R')}}
            testrun.terminate_process_tree = lambda process, known, **_kwargs: (False, True)
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

        # Repair approval is provider-authoritative under every decision policy.
        # Missing receipts and current-chat labels must fail without mutation;
        # the positive path uses an explicit subprocess-only provider fixture.
        task = json.loads(task_path.read_text())
        task["decision_policy_version"] = 1
        write(task_path, task)
        context_path.write_text("corrupt", encoding="utf-8")
        run(root, sys.executable, contextctl, "repair", "--reset",
            "--reason", "corrupt", "--summary", "reconstructed", "--source-tokens", "1000", expected=1)
        run(root, sys.executable, contextctl, "check", "--quiet", expected=1)
        before_missing_receipt = context_path.read_bytes()
        denied = run(root, sys.executable, contextctl, "approve-repair",
            "--source", "user:forged", expected=1)
        if (
            "provider-signed human decision receipt" not in denied.stdout
            or context_path.read_bytes() != before_missing_receipt
        ):
            raise AssertionError("provider-routed repair approval did not fail immutably without a receipt")
        task["decision_policy_version"] = 2
        write(task_path, task)
        before_local_advisory = context_path.read_bytes()
        denied = run(root, sys.executable, contextctl, "approve-repair",
            "--source", "user:fixture-review", expected=1)
        if (
            "local user-message evidence is advisory only" not in denied.stdout
            or context_path.read_bytes() != before_local_advisory
        ):
            raise AssertionError("local repair advisory crossed the authoritative gate or mutated context")
        task["decision_policy_version"] = 1
        write(task_path, task)
        provider_receipt = install_test_provider_verifier(root)
        run(root, sys.executable, contextctl, "approve-repair",
            "--source", "user:fixture-review",
            "--human-decision-receipt", provider_receipt)
        repaired = json.loads(context_path.read_text())
        approval = repaired["integrity"].get("repair_approval", {})
        if (
            repaired["integrity"]["status"] != "verified"
            or approval.get("authority") != "provider-signed-user-message"
            or approval.get("adapter_path") != "/self-test/provider-verifier"
            or approval.get("adapter_sha256") != "e" * 64
        ):
            raise AssertionError("provider-verified repair approval was not recorded with adapter provenance")
        run(root, sys.executable, contextctl, "check", "--quiet")
        run(root, sys.executable, contextctl, "account-turn", "--turn-id", "reviewed-repair-turn")
        reviewed_turn = json.loads(context_path.read_text())
        if (
            reviewed_turn.get("integrity", {}).get("source") != "user:fixture-review"
            or reviewed_turn.get("compaction", {}).get("source", "").startswith("host-turn:") is not True
        ):
            raise AssertionError("host-turn accounting overwrote reviewed repair approval provenance")
        run(root, sys.executable, contextctl, "check", "--quiet")

        # A reviewed repair belongs to the verified pre-transition capsule.
        # The next legal TASK transition may intentionally change the routing
        # profile; contextctl must reverify the old approval against the
        # authorization's before_task, then seal a fresh post-transition
        # capsule. Revalidating it against the already-written after_task
        # deadlocks every new task/profile.
        run(root, sys.executable, "-c", (
            "import copy,json,sys;sys.path.insert(0,'.agent/scripts');import contexttx;"
            "p='.agent/state/TASK.json';before=json.load(open(p));after=copy.deepcopy(before);"
            "after['files']=int(before.get('files',0))+1;"
            "after['next_action']='legal post-repair routing transition';"
            "contexttx.transition_task(before,after,mutator='agentctl',operation='start',"
            "reason='post-repair-route-change',summary='change route after reviewed repair')"
        ))
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

        # The authorized transition subprocess is bounded: the 120s timeout is
        # passed through, and a hang rolls the whole transaction back instead
        # of stranding a committed TASK.
        run(root, sys.executable, "-c", textwrap.dedent("""
            import copy, json, subprocess, sys
            from pathlib import Path
            sys.path.insert(0, '.agent/scripts')
            import contexttx

            task_path = Path('.agent/state/TASK.json')
            journal = Path('.agent/state/.context-transition-journal.json')
            before_bytes = task_path.read_bytes()
            before = json.loads(before_bytes)

            observed = {}
            class Failed:
                returncode = 1
                stdout = 'forced transition failure'

            def recording_run(command, **kwargs):
                observed['timeout'] = kwargs.get('timeout')
                return Failed()

            contexttx.boundedprocess.run = recording_run
            after = copy.deepcopy(before)
            after['next_action'] = 'timeout kwarg probe'
            try:
                contexttx.transition_task(before, after, mutator='workflowctl', operation='advance',
                                          reason='timeout-probe', summary='forced failure probe')
            except SystemExit:
                pass
            else:
                raise AssertionError('forced transition failure was not rejected')
            assert observed['timeout'] == 120, observed
            assert task_path.read_bytes() == before_bytes
            assert not journal.exists()

            def hanging_run(command, **kwargs):
                raise subprocess.TimeoutExpired(command, kwargs.get('timeout'))

            contexttx.boundedprocess.run = hanging_run
            after = copy.deepcopy(before)
            after['next_action'] = 'hang probe'
            try:
                contexttx.transition_task(before, after, mutator='workflowctl', operation='advance',
                                          reason='hang-probe', summary='simulated hang probe')
            except SystemExit as error:
                assert str(error).startswith(
                    'TASK/context transaction rolled back: '
                    'authorized context transition timed out after 120s'
                ), error
            else:
                raise AssertionError('hanging transition subprocess was not rejected')
            assert task_path.read_bytes() == before_bytes
            assert not journal.exists()
            print('transition timeout probes OK')
        """))

        # A stuck awaiting_host_compaction capsule pauses sync and plain
        # repair, but repair --reset rebuilds without resurrecting the wait.
        awaiting_body = (
            "v['host_compaction']={'schema':'agent-host-compaction-state/v1',"
            "'state':'awaiting_host_compaction','history':['handoff_written'],'receipt':None};"
        )
        rewrite_context(root, awaiting_body)
        awaiting_estimate = json.loads(
            context_path.read_text()
        )["usage_freshness"]["estimated_tokens"]
        paused = run(root, sys.executable, contextctl, "sync",
            "--reason", "paused", "--summary", "must be paused",
            "--source-tokens", str(awaiting_estimate), expected=1)
        if "paused" not in paused.stdout:
            raise AssertionError("sync was not paused by the awaiting host compaction")
        run(root, sys.executable, contextctl, "repair",
            "--reason", "paused", "--summary", "plain repair stays paused",
            "--source-tokens", str(awaiting_estimate), expected=1)
        run(root, sys.executable, contextctl, "repair", "--reset",
            "--reason", "stuck", "--summary", "rebuild a stuck awaiting capsule",
            "--source-tokens", str(awaiting_estimate), expected=1)
        rebuilt = json.loads(context_path.read_text())
        if "host_compaction" in rebuilt:
            raise AssertionError("repair --reset resurrected the awaiting host compaction state")
        run(root, sys.executable, contextctl, "approve-repair",
            "--source", "user:unstick",
            "--human-decision-receipt", provider_receipt)
        run(root, sys.executable, contextctl, "check", "--quiet")

        # abort-host-compaction clears the wait under the same approval
        # discipline, preserves the checkpoint and records the aborted event.
        rewrite_context(root, awaiting_body)
        stuck = json.loads(context_path.read_text())
        denied = run(root, sys.executable, contextctl, "abort-host-compaction",
            "--source", "agent:not-a-user", expected=1)
        before_local_abort = context_path.read_bytes()
        denied = run(root, sys.executable, contextctl, "abort-host-compaction",
            "--source", "user:abort-the-wait", expected=1)
        if (
            "provider-signed human decision receipt" not in denied.stdout
            or context_path.read_bytes() != before_local_abort
        ):
            raise AssertionError("local abort advisory crossed the authoritative gate or mutated context")
        aborted = run(root, sys.executable, contextctl, "abort-host-compaction",
            "--source", "user:abort-the-wait",
            "--human-decision-receipt", provider_receipt)
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
        # The stored abort approval is revalidated on every check with the
        # same discipline as repair approvals: a forged or drifted approval
        # invalidates the capsule until it is restored.
        original_abort = capsule["compaction"]["host_compaction_abort"]
        forged_abort = {
            **original_abort,
            "approval": {**original_abort["approval"], "adapter_sha256": "0" * 64},
        }
        rewrite_context(root, f"v['compaction']['host_compaction_abort']={json.dumps(forged_abort)};")
        denied = run(root, sys.executable, contextctl, "check", expected=1)
        if "host compaction abort" not in denied.stdout:
            raise AssertionError(f"forged abort approval was not revalidated:\n{denied.stdout}")
        rewrite_context(root, f"v['compaction']['host_compaction_abort']={json.dumps(original_abort)};")
        run(root, sys.executable, contextctl, "check", "--quiet")
        run(root, sys.executable, contextctl, "abort-host-compaction",
            "--source", "user:double-abort", expected=1)
        run(root, sys.executable, contextctl, "sync",
            "--reason", "post-abort", "--summary", "renew after abort",
            "--source-tokens", str(capsule["usage_freshness"]["estimated_tokens"]))

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

        # A rolled-back journal is stale too: restore must refuse it, name the
        # actual state and the safe discard command, and leave files untouched.
        write(journal_path, {
            "schema": "agent-context-transition-journal/v1",
            "mutator": "workflowctl", "operation": "advance", "reason": "crash-after-rollback",
            "issued_at": "2026-07-30T00:00:00+00:00",
            "backups": {
                ".agent/state/TASK.json": journal_entry(task_path.read_bytes()),
                ".agent/state/CONTEXT.json": journal_entry(context_path.read_bytes()),
            },
            "absent_before": [],
            "after_sha256": {
                ".agent/state/TASK.json": "0" * 64,
                ".agent/state/CONTEXT.json": None,
            },
        })
        status = json.loads(run(root, sys.executable, contextctl, "journal", expected=1).stdout)
        if status.get("state") != "rolled_back":
            raise AssertionError("rolled-back transition journal was not classified as stale")
        current_task_bytes = task_path.read_bytes()
        denied = run(root, sys.executable, contextctl, "journal", "--restore", expected=1)
        if "rolled_back" not in denied.stdout or "--discard" not in denied.stdout:
            raise AssertionError(f"restore did not refuse a rolled-back journal:\n{denied.stdout}")
        if task_path.read_bytes() != current_task_bytes:
            raise AssertionError("a refused restore still mutated TASK")
        run(root, sys.executable, contextctl, "journal", "--discard")

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
        # Restoring a stale committed journal would silently revert the valid
        # committed state, so restore refuses it and names the discard path.
        denied = run(root, sys.executable, contextctl, "journal", "--restore", expected=1)
        if "committed" not in denied.stdout or "--discard" not in denied.stdout:
            raise AssertionError(f"restore did not refuse a committed journal:\n{denied.stdout}")
        if task_path.read_bytes() != task_bytes or context_path.read_bytes() != context_bytes + b" \n":
            raise AssertionError("restore on a committed journal reverted valid committed state")
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
            # Local/current-chat evidence can still be validated as advisory
            # metadata, but it is never authoritative gate approval.
            assert humandecision.local_advisory_valid(
                release_task, approval, source='user:fixture', artifact_sha256=artifact)
            assert not humandecision.local_approval_valid(
                release_task, approval, source='user:fixture', artifact_sha256=artifact)
            observer = dict(humandecision.POLICY)
            tightened = {'agent_control': {'human_decision_observer': observer}}
            assert not humandecision.local_advisory_valid(
                release_task, approval, source='user:fixture', artifact_sha256=artifact, config=tightened)
            permissive = {'agent_control': {'human_decision_observer': {
                **humandecision.POLICY, 'allow_current_chat_local_release': True}}}
            assert not humandecision.local_advisory_valid(
                release_task, approval, source='user:fixture', artifact_sha256=artifact, config=permissive)
            assert not humandecision.local_approval_valid(
                release_task, approval, source='user:fixture', artifact_sha256=artifact, config=permissive)
            legacy = {key: approval[key] for key in ('source', 'artifact_sha256', 'assurance')}
            assert humandecision.local_advisory_valid(
                release_task, legacy, source='user:fixture', artifact_sha256=artifact)
            assert not humandecision.local_approval_valid(
                release_task, legacy, source='user:fixture', artifact_sha256=artifact)
            forged = dict(approval, routing_profile_sha256='b' * 64)
            assert not humandecision.local_advisory_valid(
                release_task, forged, source='user:fixture', artifact_sha256=artifact)

            # Release advisory records retain transcript/debt shape coverage,
            # while every shape remains non-authoritative.
            release_pair = {
                'platform_transcript_verified_sha256': 'c' * 64,
                'supervision_debt_waiver_sha256': 'd' * 64,
            }
            current_release = {**approval, **release_pair}
            assert humandecision.local_advisory_valid(
                release_task, current_release, source='user:fixture', artifact_sha256=artifact)
            assert not humandecision.local_approval_valid(
                release_task, current_release, source='user:fixture', artifact_sha256=artifact)
            legacy_release = {key: current_release[key] for key in (
                'source', 'artifact_sha256', 'assurance',
                'platform_transcript_verified_sha256', 'supervision_debt_waiver_sha256')}
            assert humandecision.local_advisory_valid(
                release_task, legacy_release, source='user:fixture', artifact_sha256=artifact)
            assert not humandecision.local_approval_valid(
                release_task, legacy_release, source='user:fixture', artifact_sha256=artifact)
            partial_release = {key: current_release[key] for key in (
                'source', 'artifact_sha256', 'assurance', 'platform_transcript_verified_sha256')}
            assert not humandecision.local_advisory_valid(
                release_task, partial_release, source='user:fixture', artifact_sha256=artifact)
            bad_release_digest = dict(current_release, supervision_debt_waiver_sha256='not-a-digest')
            assert not humandecision.local_advisory_valid(
                release_task, bad_release_digest, source='user:fixture', artifact_sha256=artifact)
            unknown_key = dict(current_release, unexpected='x')
            assert not humandecision.local_advisory_valid(
                release_task, unknown_key, source='user:fixture', artifact_sha256=artifact)

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
            import agentctl
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

            # The deprecated alias keeps its exact legacy arithmetic. The
            # current transition key is independent from the honest per-turn
            # overhead: state changes inside one turn must not fabricate
            # another system-prompt replay.
            previous = {{'usage_freshness': {{'estimated_tokens': 1000}}}}
            plain = {{'mode': 'standard', 'usage_receipts': []}}
            legacy = {{'context': {{'automatic_transition_token_increment': {{'standard': 300}}}}, 'agent_control': {{}}}}
            assert contextctl.automatic_transition_source_tokens(legacy, previous, plain) == 1300
            current = {{'context': {{
                            'estimated_turn_overhead_tokens': {{'standard': 3000}},
                            'transition_token_increment': {{'standard': 400}},
                       }},
                        'agent_control': {{'inherited_turn_estimated_tokens': 800}}}}
            assert contextctl.automatic_transition_source_tokens(current, previous, plain) == 1400

            # Cumulative provider receipts affect the cumulative-cost account
            # only. Their latest delta is a useful diagnostic, but must not be
            # replayed at one or more active-window transitions.
            measured = {{'mode': 'standard', 'usage_receipts': [
                {{'total_tokens': 5000, 'sha256': '0' * 64}},
                {{'total_tokens': 14000, 'sha256': '1' * 64}},
            ]}}
            assert budget.measured_turn_delta(measured) == 9000
            first = contextctl.automatic_transition_source_tokens(current, previous, measured)
            second = contextctl.automatic_transition_source_tokens(
                current, {{'usage_freshness': {{'estimated_tokens': first}}}}, measured
            )
            assert (first, second) == (1400, 1800), (first, second)
            shrinking = {{'mode': 'standard', 'usage_receipts': [
                {{'total_tokens': 9000, 'sha256': '0' * 64}},
                {{'total_tokens': 4000, 'sha256': '1' * 64}},
            ]}}
            assert contextctl.automatic_transition_source_tokens(current, previous, shrinking) == 1400

            # Resume state is derived from the active checkpoint, not TASK's
            # cumulative/base budget marker. A terminal compact checkpoint
            # must also replace the unsafe "start next requirement" prose.
            resume_task = {{
                'status': 'accepted', 'current_node': 'idle',
                'mode': 'standard', 'token_budget': 48000,
                'tokens_used': 0, 'token_usage_source': 'estimated',
                'loaded_references': [], 'budget_state': 'ok',
                'next_action': 'start the next requirement in clarification',
            }}
            resume_state = contextctl.effective_budget_state(shipped, resume_task, 37000)
            assert resume_state == 'must_compact', resume_state
            effective_resume = contextctl.resume_contract(
                resume_task, 'f' * 64, resume_state
            )
            assert effective_resume['budget_state'] == 'must_compact', effective_resume
            assert 'verified host compaction' in effective_resume['next_action'], effective_resume
            assert effective_resume['terminal'] is True, effective_resume
            blocked_task = dict(
                resume_task, status='in_progress', current_node=6,
                next_action='continue implementation',
            )
            blocked_resume = contextctl.resume_contract(
                blocked_task, 'e' * 64, 'hard_blocked'
            )
            assert blocked_resume['resume_action'] == 'waiting_human', blocked_resume
            assert 'do not continue' in blocked_resume['next_action'], blocked_resume
            closure_task = dict(
                blocked_task, status='ready_to_complete', current_node=7,
                accepted_nodes=list(range(8)), next_action='render retrospective and complete task',
            )
            closure_resume = contextctl.resume_contract(
                closure_task, 'd' * 64, 'hard_blocked'
            )
            assert closure_resume['resume_action'] == 'continue', closure_resume
            hard_snapshot = {{'state': 'hard_blocked'}}
            assert agentctl.budget_action_allowed(
                hard_snapshot, 'render-artifact', closure_task
            )
            assert agentctl.budget_action_allowed(hard_snapshot, 'complete', closure_task)
            assert not agentctl.budget_action_allowed(
                hard_snapshot, 'route-templates', closure_task
            )
            assert not agentctl.budget_action_allowed(
                hard_snapshot, 'render-artifact', blocked_task
            )
            signature = 'c' * 64
            repair_task = dict(
                blocked_task,
                rollback_ledger=[{{'from': 7, 'to': 6, 'signature': signature}}],
                failure_ledger={{signature: 1}},
                next_action='repair root cause at node 6',
            )
            repair_resume = contextctl.resume_contract(
                repair_task, 'b' * 64, 'hard_blocked'
            )
            assert repair_resume['resume_action'] == 'continue', repair_resume
            for action in ('reroute-existing', 'render-artifact', 'finish-node', 'managed-run'):
                assert agentctl.budget_action_allowed(
                    hard_snapshot, action, repair_task
                ), (action, repair_task)
            for action in ('route-templates', 'load-reference', 'spawn-agent'):
                assert not agentctl.budget_action_allowed(
                    hard_snapshot, action, repair_task
                ), (action, repair_task)
            progressed_repair = dict(
                repair_task, current_node=7, accepted_nodes=list(range(7)),
                next_action='rerun acceptance at node 7',
            )
            assert agentctl.budget_action_allowed(
                hard_snapshot, 'render-artifact', progressed_repair
            )
            assert contextctl.resume_contract(
                progressed_repair, 'a' * 64, 'hard_blocked'
            )['resume_action'] == 'continue'
            chained_signature = 'd' * 64
            chained_repair = dict(
                progressed_repair,
                rollback_ledger=[
                    {{'from': 7, 'to': 4, 'signature': signature}},
                    {{'from': 4, 'to': 2, 'signature': chained_signature}},
                ],
                failure_ledger={{signature: 2, chained_signature: 1}},
            )
            assert contextctl.hard_repair_interval(chained_repair) == (2, 7)
            assert agentctl.hard_repair_interval(chained_repair) == (2, 7)
            assert agentctl.budget_action_allowed(
                hard_snapshot, 'render-artifact', chained_repair
            )
            disconnected_repair = dict(
                chained_repair,
                rollback_ledger=[
                    {{'from': 7, 'to': 5, 'signature': signature}},
                    {{'from': 4, 'to': 2, 'signature': chained_signature}},
                ],
            )
            assert contextctl.hard_repair_interval(disconnected_repair) == (2, 4)
            assert not agentctl.budget_action_allowed(
                hard_snapshot, 'render-artifact', disconnected_repair
            )
            third_strike = dict(
                repair_task, failure_ledger={{signature: 3}}
            )
            assert not agentctl.budget_action_allowed(
                hard_snapshot, 'render-artifact', third_strike
            )

            # Post-completion accounting preserves either an ordinary
            # complete-task receipt or one of the two installer-verified
            # terminal migration origins. Arbitrary markers fail closed.
            completion_auth = {{
                'mutator': 'workflowctl', 'operation': 'complete-task',
                'receipt_sha256': 'a' * 64,
            }}
            ordinary_origin = contextctl.terminal_completion_origin({{
                'checkpoint': {{'transition_authorization': completion_auth}},
                'compaction': {{'source': 'mutator:workflowctl'}},
            }})
            assert ordinary_origin == {{
                'schema': 'agent-terminal-completion-origin/v1',
                'kind': 'complete-task',
                'transition_authorization': completion_auth,
            }}
            for reason, source in (
                ('migration-26-final-state-rebind', 'installer-verified-active-migration'),
                ('migration-34-final-state-rebind', 'installer-verified-context-efficiency-migration'),
                ('migration-39-budget-resume-rebind', 'installer-verified-budget-resume-migration'),
            ):
                migration_origin = contextctl.terminal_completion_origin({{
                    'checkpoint': {{'reason': reason, 'transition_authorization': None}},
                    'compaction': {{'source': source}},
                }})
                assert migration_origin == {{
                    'schema': 'agent-terminal-completion-origin/v1',
                    'kind': 'installer-migration',
                    'reason': reason,
                    'source': source,
                }}
            try:
                contextctl.terminal_completion_origin({{
                    'checkpoint': {{'reason': 'forged-terminal'}},
                    'compaction': {{'source': 'agent-self-assertion'}},
                }})
            except SystemExit:
                pass
            else:
                raise AssertionError('forged terminal completion origin was accepted')
            print('P7 function probes OK')
        """))

        # A real host turn is charged independently and exactly once. Retrying
        # the same caller-stable ID must leave the entire capsule byte-identical.
        before_turn = json.loads((root / ".agent/state/CONTEXT.json").read_text())
        before_turn_count = before_turn.get("turn_accounting", {}).get("turns_accounted", 0)
        run(root, sys.executable, contextctl, "account-turn", "--turn-id", "fixture-turn-1")
        after_turn_path = root / ".agent/state/CONTEXT.json"
        after_turn = json.loads(after_turn_path.read_text())
        if (
            after_turn["usage_freshness"]["estimated_tokens"]
            != before_turn["usage_freshness"]["estimated_tokens"] + 300
            or after_turn.get("turn_accounting", {}).get("turns_accounted") != before_turn_count + 1
        ):
            raise AssertionError("host turn did not charge the configured per-turn estimate exactly once")
        once_bytes = after_turn_path.read_bytes()
        replay = run(root, sys.executable, contextctl, "account-turn", "--turn-id", "fixture-turn-1")
        if "ALREADY ACCOUNTED" not in replay.stdout or after_turn_path.read_bytes() != once_bytes:
            raise AssertionError("same host turn ID was not an idempotent byte-for-byte no-op")
        run(root, sys.executable, contextctl, "account-turn", "--turn-id", "fixture-turn-2")
        twice = json.loads(after_turn_path.read_text())
        if twice["usage_freshness"]["estimated_tokens"] != before_turn["usage_freshness"]["estimated_tokens"] + 600:
            raise AssertionError("distinct host turns did not receive independent per-turn charges")
        before_repair_bytes = after_turn_path.read_bytes()
        lowered_repair = run(
            root, sys.executable, contextctl, "repair",
            "--source-tokens", str(twice["usage_freshness"]["estimated_tokens"] - 1),
            "--reason", "forged-lower-estimate", "--reset", expected=1,
        )
        if (
            "repair cannot lower the active-window estimate" not in lowered_repair.stdout
            or after_turn_path.read_bytes() != before_repair_bytes
        ):
            raise AssertionError(
                "repair reset lowered usage or mutated the checkpoint before rejecting it"
            )

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

        # Private context locks and authorization roots reject symlinks before external mutation.
        def invoke_context(statement):
            code=("import copy,json,os,runpy,sys; os.chdir("+repr(str(root))+ "); "
                  "sys.path.insert(0,'.agent/scripts'); module=runpy.run_path('.agent/scripts/contexttx.py'); "+statement)
            return subprocess.run([sys.executable,"-c",code],cwd=root,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

        external_lock=root/"external-task-lock"; external_lock.write_text("unchanged\n",encoding="utf-8")
        task_lock=root/".agent/state/.task.lock"
        if task_lock.exists() or task_lock.is_symlink(): task_lock.unlink()
        task_lock.symlink_to(external_lock)
        locked=invoke_context("before=json.loads(module['TASK_PATH'].read_text()); after=copy.deepcopy(before); after['title']=str(before.get('title','task'))+'-changed'; module['transition_task'](before,after,mutator='fixture',operation='fixture',reason='fixture',summary='fixture')")
        if locked.returncode==0 or "lock is missing or unsafe" not in locked.stdout or external_lock.read_text(encoding="utf-8")!="unchanged\n":
            raise AssertionError(f"task transition lock followed an unsafe symlink:\n{locked.stdout}")
        task_lock.unlink(); external_lock.unlink()

        outside_auth=root/"outside-auth"; outside_auth.mkdir(); authorization=root/".agent/state/.context-authorizations"
        if authorization.exists(): shutil.rmtree(authorization)
        authorization.symlink_to(outside_auth,target_is_directory=True)
        denied_auth=invoke_context("before=json.loads(module['TASK_PATH'].read_text()); after=copy.deepcopy(before); after['title']=str(before.get('title','task'))+'-changed'; module['_authorization'](before,after,'fixture','fixture','fixture')")
        if denied_auth.returncode==0 or "directory is unsafe" not in denied_auth.stdout or list(outside_auth.iterdir()):
            raise AssertionError(f"context authorization wrote through a symlinked root:\n{denied_auth.stdout}")
        authorization.unlink(); outside_auth.rmdir()
    trust=run(SOURCE.parents[1],sys.executable,str(SOURCE/"self_test_runner_trust.py"))
    if "PASS: descriptor-bound snapshot" not in trust.stdout:
        raise AssertionError(f"runner trust regression did not complete:\n{trust.stdout}")
    print("PASS: atomic and sealed test budget, exact private candidate trust, bounded pipe cleanup, provider-gated infrastructure remediation, context freshness, bundle migration, host-compaction abort revalidation and journal restore guards, bounded transition timeout, token-ledger calibration")
    return 0


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
