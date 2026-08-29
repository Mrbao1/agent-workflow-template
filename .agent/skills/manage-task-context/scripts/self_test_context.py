#!/usr/bin/env python3
"""Exercise valid and adversarial context transitions in disposable projects."""

from pathlib import Path
import copy
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile


SOURCE_AGENT = Path(__file__).resolve().parents[3]


def invoke(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, ".agent/scripts/contextctl.py", *args],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def run(root: Path, *args: str) -> int:
    return invoke(root, *args).returncode


def automatic_transition(root: Path, next_action: str) -> subprocess.CompletedProcess[str]:
    program = (
        "import copy,json,sys;"
        "sys.path.insert(0,'.agent/scripts');import contexttx;"
        "p='.agent/state/TASK.json';before=json.load(open(p));after=copy.deepcopy(before);"
        f"after['next_action']={next_action!r};"
        "contexttx.transition_task(before,after,mutator='workflowctl',operation='advance',"
        "reason='automatic-growth-probe',summary='advance a canonical checkpoint')"
    )
    return subprocess.run(
        [sys.executable, "-c", program], cwd=root,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def cumulative_usage_transition(root: Path, tokens: int) -> subprocess.CompletedProcess[str]:
    program = (
        "import copy,json,sys;"
        "sys.path.insert(0,'.agent/scripts');import contexttx;"
        "p='.agent/state/TASK.json';before=json.load(open(p));after=copy.deepcopy(before);"
        f"after['tokens_used']={tokens};after['budget_state']='hard_blocked';"
        f"after['metrics']['tokens']={tokens};"
        "contexttx.transition_task(before,after,mutator='agentctl',operation='record-usage',"
        "reason='cumulative-usage-probe',summary='record cumulative cost independently')"
    )
    return subprocess.run(
        [sys.executable, "-c", program], cwd=root,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def authorize(root: Path, before: dict[str, object], after: dict[str, object], from_sha: str, reason: str) -> str:
    relative = ".agent/state/.context-authorizations/self-test.json"
    changed = sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))
    # The fixture changes only workflowctl.advance fields, which is the canonical
    # profile under test; contextctl independently recomputes this list.
    write_json(root / relative, {
        "schema": "agent-context-transition-authorization/v1",
        "mutator": "workflowctl",
        "operation": "advance",
        "reason": reason,
        "issued_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "from_task_sha256": from_sha,
        "to_task_sha256": "pending-recomputed-by-validator",
        "changed_fields": changed,
        "before_task": before,
        "after_task": after,
    })
    # Fill the target digest using the same canonical invariant algorithm by
    # asking a disposable contextctl import in the fixture process.
    helper = subprocess.run(
        [sys.executable, "-c", "import sys,json;sys.path.insert(0,'.agent/scripts');import contextctl;p='.agent/state/.context-authorizations/self-test.json';v=json.load(open(p));v['to_task_sha256']=contextctl.invariant_sha256(v['after_task']);open(p,'w').write(json.dumps(v,ensure_ascii=False,indent=2)+'\\n')"],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if helper.returncode:
        raise AssertionError(helper.stdout)
    return relative


def fixture(root: Path) -> None:
    (root / ".agent/state/artifacts").mkdir(parents=True)
    (root / ".agent/scripts").mkdir(parents=True)
    shutil.copy2(SOURCE_AGENT / "scripts/contextctl.py", root / ".agent/scripts/contextctl.py")
    shutil.copy2(SOURCE_AGENT / "scripts/contexttx.py", root / ".agent/scripts/contexttx.py")
    shutil.copy2(SOURCE_AGENT / "scripts/humandecision.py", root / ".agent/scripts/humandecision.py")
    shutil.copy2(SOURCE_AGENT / "scripts/process_observation.py", root / ".agent/scripts/process_observation.py")
    shutil.copy2(SOURCE_AGENT / "scripts/testrun.py",root/".agent/scripts/testrun.py")
    shutil.copytree(SOURCE_AGENT / "scripts/workflowlib", root / ".agent/scripts/workflowlib")
    shutil.copy2(SOURCE_AGENT / "INDEX.md", root / ".agent/INDEX.md")
    shutil.copytree(SOURCE_AGENT / "workflows", root / ".agent/workflows")
    shutil.copytree(SOURCE_AGENT / "templates", root / ".agent/templates")
    shutil.copytree(SOURCE_AGENT / "policies", root / ".agent/policies")
    shutil.copytree(SOURCE_AGENT / "skills/run-ai-coding-pipeline", root / ".agent/skills/run-ai-coding-pipeline")
    shutil.copytree(SOURCE_AGENT / "skills/clarify-task", root / ".agent/skills/clarify-task")
    host_adapter = root / "host-compaction-adapter.py"
    host_adapter.write_text(
        "#!/usr/bin/env python3\nimport hashlib,sys\np=sys.argv[sys.argv.index('--receipt')+1]\nprint('VERIFIED HOST COMPACTION sha256='+hashlib.sha256(open(p,'rb').read()).hexdigest())\n",
        encoding="utf-8",
    )
    host_adapter.chmod(0o755)
    Path(str(host_adapter)+".agent-workflow-adapter.json").write_text(json.dumps({
        "schema":"agent-provider-adapter/v1","purpose":"provider-verifiable-agent-control",
        "executable_sha256":hashlib.sha256(host_adapter.read_bytes()).hexdigest(),"operations":["verify-host-compaction"],
    },sort_keys=True)+"\n",encoding="utf-8")
    site_dir = root / "test-site"
    site_dir.mkdir()
    (site_dir / "sitecustomize.py").write_text(
        "import os,sys\nfrom pathlib import Path\n"
        "sys.path.insert(0,str(Path.cwd()/'.agent/scripts'))\n"
        "import humandecision\n_original=humandecision.adapter_path\n_original_chain=humandecision.protected_path_chain\n"
        "def _fixture(root,raw,required_operations=('health','verify')):\n"
        " if raw==os.environ.get('AGENT_TEST_HOST_ADAPTER'):\n"
        "  assert tuple(required_operations)==('verify-host-compaction',)\n"
        "  return Path(raw).resolve()\n"
        " return _original(root,raw,required_operations=required_operations)\n"
        "def _chain(path):\n"
        " adapter=Path(os.environ['AGENT_TEST_HOST_ADAPTER']).resolve(); metadata=Path(str(adapter)+'.agent-workflow-adapter.json').resolve()\n"
        " return True if Path(path).resolve() in {adapter,metadata} else _original_chain(path)\n"
        "humandecision.adapter_path=_fixture\n"
        "humandecision.protected_path_chain=_chain\n",
        encoding="utf-8",
    )
    os.environ["AGENT_TEST_HOST_ADAPTER"] = str(host_adapter.resolve())
    os.environ["PYTHONPATH"] = str(site_dir) + os.pathsep + os.environ.get("PYTHONPATH", "")
    config = {
        "routing": {"modes": {"fast": {"token_budget": 4000}}},
        "context": {
            "max_bytes": 8192,
            "max_list_items": 10,
            "max_capsule_tokens": {"fast": 2200, "standard": 2600, "release": 3200},
            "automatic_transition_token_increment": {"fast": 150, "standard": 300, "release": 500},
            "soft_budget_ratio": 0.6,
            "compact_budget_ratio": 0.75,
            "hard_budget_ratio": 0.9,
            "max_active_checkpoint_age_minutes": 45,
            "host_compaction_observer": {"source": "host-runtime-receipt", "signed_adapter": str(host_adapter.resolve()), "max_receipt_age_seconds": 300},
        },
        "agent_control": {
            "usage_observer": {"signed_adapter": None},
            "human_decision_observer": {
                "source": "orchestrator-user-message",
                "automatic_gate_trust": False,
                "human_verification_required": True,
                "allow_current_chat_local_release": False,
                "signed_adapter": None,
                "max_receipt_age_seconds": 900,
            }
        },
        "token_estimation": {"max_error_ratio": 0.35},
    }
    task = {
        "schema": "agent-task/v2",
        "title": "fixture",
        "task_type": "maintenance",
        "complexity": "small",
        "mode": "fast",
        "files": 1,
        "environment": "local",
        "deployment_requested": False,
        "branch": "unversioned",
        "risk_flags": {
            "deploy": False,
            "data_risk": False,
            "cross_system": False,
            "uncertain": False,
            "security": False,
            "compliance": False,
            "migration": False,
            "irreversible": False,
            "external_impact": False,
        },
        "requirements_clarified": True,
        "requirement_source": "user:fixture",
        "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
        "requirement_contract_sha256": "pending",
        "token_budget": 4000,
        "tokens_used": 100,
        "token_usage_source": "estimated",
        "child_agents_used": 0,
        "peak_child_agents": 0,
        "selected_templates": ["requirement-contract"],
        "selected_capabilities": ["core"],
        "rendered_artifacts": [],
        "loaded_references": [],
        "primary_skill": "run-ai-coding-pipeline",
        "phase": "implementation",
        "status": "in_progress",
        "decisions": ["keep scope small"],
        "open_questions": [],
        "next_action": "validate fixture",
        "current_node": 6,
        "accepted_nodes": [0, 1, 2, 3, 4, 5],
        "node_artifacts": {},
        "gate_approvals": {"requirement": "user:fixture"},
        "pending_gate_artifacts": {},
        "rollback_ledger": [],
        "rollback_archive": None,
        "failure_ledger": {},
        "failure_archive": None,
        "mode_status": "confirmed",
        "metrics": {
            "tokens": 100,
            "token_source": "estimated",
            "child_agents": 0,
            "peak_children": 0,
            "tool_calls": 1,
            "test_runs": 1,
            "test_failures": 0,
            "repair_rounds": 0,
            "user_corrections": 0,
            "context_compactions": 0,
            "references_loaded": 0,
        },
    }
    contract = "# Requirement Contract\n\n- Goal: fixture\n- Clarified: true\n"
    (root / ".agent/state/REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    task["requirement_contract_sha256"] = hashlib.sha256(contract.encode()).hexdigest()
    (root / ".agent/state/artifacts/old.md").write_text("old evidence\n", encoding="utf-8")
    (root / ".agent/state/artifacts/new.md").write_text("new evidence\n", encoding="utf-8")
    write_json(root / ".agent/config.json", config)
    write_json(root / ".agent/state/TASK.json", task)


def requirement_transition(root: Path, after: dict[str, object], contract: bytes) -> subprocess.CompletedProcess[str]:
    write_json(root / "approval-after.json", after)
    (root / "approval-contract.md").write_bytes(contract)
    program = (
        "import json,sys;from pathlib import Path;"
        "sys.path.insert(0,'.agent/scripts');import contexttx;"
        "before=json.load(open('.agent/state/TASK.json'));after=json.load(open('approval-after.json'));"
        "data=Path('approval-contract.md').read_bytes();"
        "contexttx.transition_task(before,after,mutator='agentctl',operation='approve-requirements',"
        "reason='requirement-approved',summary='approve exact final requirement bytes',"
        "side_effects=[(Path('.agent/state/REQUIREMENT_CONTRACT.md'),data)])"
    )
    return subprocess.run(
        [sys.executable, "-c", program], cwd=root,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def draft_contract_probe() -> None:
    with tempfile.TemporaryDirectory(prefix="context-draft-contract-") as raw:
        root = Path(raw)
        fixture(root)
        task_path = root / ".agent/state/TASK.json"
        contract_path = root / ".agent/state/REQUIREMENT_CONTRACT.md"
        task = json.loads(task_path.read_text())
        task.update({
            "status": "waiting_human", "phase": "clarification",
            "requirements_clarified": False, "requirement_source": "pending",
            "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
            "requirement_contract_sha256": None, "primary_skill": "clarify-task",
            "open_questions": ["requirement contract approval"],
            "next_action": "approve the exact final requirement", "current_node": 1,
            "accepted_nodes": [0], "mode_status": "provisional",
            "gate_approvals": {}, "node_artifacts": {},
        })
        write_json(task_path, task)
        draft_one = b"# Requirement Contract\n\n- Goal: draft one\n- Clarified: false\n"
        draft_two = b"# Requirement Contract\n\n- Goal: draft two\n- Clarified: false\n"
        draft_three = b"# Requirement Contract\n\n- Goal: final candidate\n- Clarified: false\n"
        contract_path.write_bytes(draft_one)
        initial = invoke(root, "sync", "--reason", "draft-start", "--summary", "clarify mutable draft", "--source-tokens", "1800")
        if initial.returncode != 0:
            raise AssertionError(initial.stdout)
        for draft in (draft_two, draft_three):
            contract_path.write_bytes(draft)
            if run(root, "check") != 0:
                raise AssertionError("unapproved requirement draft bytes caused context drift")
            context = json.loads((root / ".agent/state/CONTEXT.json").read_text())
            if context.get("requirement_contract_sha256") != "unapproved-draft":
                raise AssertionError("unapproved draft acquired an authoritative byte hash")

        final_contract = draft_three.replace(b"false", b"true")
        old_contract = draft_two.replace(b"false", b"true")
        exact = copy.deepcopy(task)
        exact.update({
            "requirements_clarified": True, "requirement_source": "user:fixture",
            "requirement_contract_sha256": hashlib.sha256(final_contract).hexdigest(),
            "status": "in_progress", "phase": "planning",
            "primary_skill": "run-ai-coding-pipeline", "open_questions": [],
            "next_action": "plan from approved requirements", "current_node": 2,
            "accepted_nodes": [0, 1], "mode_status": "confirmed",
        })
        stale = copy.deepcopy(exact)
        stale["requirement_contract_sha256"] = hashlib.sha256(old_contract).hexdigest()
        before_task = task_path.read_bytes(); before_context = (root / ".agent/state/CONTEXT.json").read_bytes()
        rejected = requirement_transition(root, stale, final_contract)
        if rejected.returncode == 0 or task_path.read_bytes() != before_task or contract_path.read_bytes() != draft_three or (root / ".agent/state/CONTEXT.json").read_bytes() != before_context:
            raise AssertionError("stale requirement digest was accepted or atomic rollback failed")
        approved = requirement_transition(root, exact, final_contract)
        if approved.returncode != 0 or run(root, "check") != 0:
            raise AssertionError(approved.stdout or "exact requirement transition failed")
        locked = json.loads((root / ".agent/state/CONTEXT.json").read_text())
        if locked.get("requirement_contract_sha256") != hashlib.sha256(final_contract).hexdigest():
            raise AssertionError("approved contract did not switch to its exact SHA-256 binding")
        contract_path.write_bytes(final_contract + b"tamper")
        if run(root, "check") == 0:
            raise AssertionError("approved contract bytes remained mutable after exact binding")


def expect_failure(root: Path, label: str, *args: str) -> None:
    if run(root, *args) == 0:
        raise AssertionError(f"adversarial context passed: {label}")


def main() -> int:
    attacks = 0
    draft_contract_probe()
    with tempfile.TemporaryDirectory(prefix="context-capsule-") as raw:
        root = Path(raw)
        fixture(root)
        initial = invoke(
            root,
            "sync",
            "--reason",
            "fixture",
            "--summary",
            "initial bounded phase summary",
            "--source-tokens",
            "2000",
            "--fact",
            "old phase fact",
            "--file",
            ".agent/state/artifacts/old.md",
            "--evidence",
            ".agent/state/artifacts/old.md",
            "--risk",
            "risk carried until explicitly resolved",
        )
        if initial.returncode != 0 or run(root, "check") != 0:
            print("FAIL: valid context fixture was rejected")
            print(initial.stdout)
            return 1
        original_text = (root / ".agent/state/CONTEXT.json").read_text(encoding="utf-8")
        original = json.loads(original_text)

        mutations = {
            "empty": {},
            "garbage-schema": {"schema": "garbage"},
            "wrong-task": {**original, "task_title": "other"},
            "lost-decisions": {**original, "decisions": []},
            "wrong-contract": {**original, "requirement_contract_sha256": "0" * 64},
            "stale-token-estimate": {
                **original,
                "compaction": {**original["compaction"], "capsule_estimated_tokens": 1},
            },
            "oversized-single-item": {**original, "confirmed_facts": ["x" * 10000]},
            "washed-task-binding": {**original, "task_invariant_sha256": "0" * 64},
            "missing-phase-summary": {key: value for key, value in original.items() if key != "phase_summary"},
        }
        for name, value in mutations.items():
            write_json(root / ".agent/state/CONTEXT.json", value)
            expect_failure(root, name, "check")
            attacks += 1
        (root / ".agent/state/CONTEXT.json").write_text(original_text, encoding="utf-8")

        # Every canonical field that can change routing, gates, cost or evidence is integrity-bound.
        task_path = root / ".agent/state/TASK.json"
        canonical_task = json.loads(task_path.read_text(encoding="utf-8"))
        critical_mutations = {
            "primary_skill": "forged-skill",
            "selected_capabilities": ["core", "delivery"],
            "rendered_artifacts": [{"template_id": "forged"}],
            "rollback_ledger": [{"signature": "forged"}],
            "failure_archive": {"forged": True},
            "metrics": {**canonical_task["metrics"], "tool_calls": 99},
            "mode_status": "provisional",
        }
        for field, value in critical_mutations.items():
            mutated = {**canonical_task, field: value}
            write_json(task_path, mutated)
            expect_failure(root, f"critical-task-invariant-{field}", "check")
            attacks += 1
        write_json(task_path, canonical_task)

        # A transition cannot be used as an unbound reset/wash operation.
        before_hash = hashlib.sha256((root / ".agent/state/CONTEXT.json").read_bytes()).hexdigest()
        expect_failure(
            root,
            "transition-reset-wash",
            "sync",
            "--transition",
            "--reset",
            "--reason",
            "wash",
            "--summary",
            "forged replacement",
            "--source-tokens",
            "2000",
            "--from-task-sha256",
            original["task_invariant_sha256"],
        )
        if hashlib.sha256((root / ".agent/state/CONTEXT.json").read_bytes()).hexdigest() != before_hash:
            print("FAIL: rejected transition modified the capsule")
            return 1
        attacks += 1

        # Knowing the previous public hash is insufficient: a naked transition
        # cannot wash an arbitrary TASK edit into a verified capsule.
        washed = {**canonical_task, "next_action": "forged naked transition"}
        write_json(task_path, washed)
        expect_failure(
            root, "naked-transition-wash", "sync", "--transition",
            "--reason", "wash", "--summary", "forged replacement",
            "--source-tokens", "2000", "--from-task-sha256", original["task_invariant_sha256"],
        )
        write_json(task_path, canonical_task)
        attacks += 1
        expect_failure(
            root,
            "unbound-transition",
            "sync",
            "--transition",
            "--reason",
            "phase-change",
            "--summary",
            "new phase",
            "--source-tokens",
            "2000",
        )
        attacks += 1
        expect_failure(
            root,
            "transition-without-source-budget",
            "sync",
            "--transition",
            "--reason",
            "phase-change",
            "--summary",
            "new phase",
            "--from-task-sha256",
            original["task_invariant_sha256"],
        )
        attacks += 1

        # A legitimate phase transition replaces phase-local narration/evidence but carries risks.
        transitioned_task = {**canonical_task, "phase": "validation", "current_node": 7, "next_action": "validate full chain"}
        write_json(task_path, transitioned_task)
        authorization = authorize(root, canonical_task, transitioned_task, original["task_invariant_sha256"], "enter-validation")
        transition = invoke(
            root,
            "sync",
            "--transition",
            "--reason",
            "enter-validation",
            "--summary",
            "implementation closed; validate the full chain",
            "--source-tokens",
            "2300",
            "--from-task-sha256",
            original["task_invariant_sha256"],
            "--authorization",
            authorization,
            "--fact",
            "new phase fact",
            "--file",
            ".agent/state/artifacts/new.md",
            "--evidence",
            ".agent/state/artifacts/new.md",
        )
        if transition.returncode != 0 or run(root, "check") != 0:
            print("FAIL: bound transition was rejected")
            print(transition.stdout)
            return 1
        transitioned = json.loads((root / ".agent/state/CONTEXT.json").read_text(encoding="utf-8"))
        if "old phase fact" in transitioned["confirmed_facts"] or transitioned["changed_files"] != [".agent/state/artifacts/new.md"]:
            print("FAIL: phase-local summary/files accumulated across transition")
            return 1
        if transitioned["open_risks"] != ["risk carried until explicitly resolved"]:
            print("FAIL: unresolved risk was silently washed")
            return 1
        compaction = transitioned["compaction"]
        if (
            compaction.get("method") != "explicit-estimate/v1"
            or compaction.get("tokens_removed") != 0
            or compaction.get("capsule_reduction_tokens")
            != compaction["source_estimated_tokens"] - compaction["capsule_estimated_tokens"]
            or compaction.get("capsule_reduction_tokens", 0) <= 0
            or compaction.get("reason") != "enter-validation"
        ):
            print("FAIL: transition lacks auditable budget-compression evidence")
            return 1

        # Old risks disappear only through an exact, explicit resolution declaration.
        from_sha = transitioned["task_invariant_sha256"]
        next_task = {**transitioned_task, "next_action": "accept clean validation"}
        write_json(task_path, next_task)
        authorization = authorize(root, transitioned_task, next_task, from_sha, "risk-resolved")
        resolved = invoke(
            root,
            "sync",
            "--transition",
            "--reason",
            "risk-resolved",
            "--summary",
            "validation evidence closed the prior risk",
            "--source-tokens",
            "2600",
            "--from-task-sha256",
            from_sha,
            "--authorization",
            authorization,
            "--resolve-risk",
            "risk carried until explicitly resolved",
            "--evidence",
            ".agent/state/artifacts/new.md",
        )
        if resolved.returncode != 0 or run(root, "check") != 0:
            print("FAIL: explicit risk resolution was rejected")
            print(resolved.stdout)
            return 1
        if json.loads((root / ".agent/state/CONTEXT.json").read_text())["open_risks"]:
            print("FAIL: explicitly resolved risk remained active")
            return 1

        # Expiry is a lease-renewal event, not corruption. An otherwise exact,
        # integrity-bound capsule may compact itself without a human repair
        # round-trip; any other drift still fails closed.
        age_probe = subprocess.run(
            [sys.executable, "-c", (
                "import datetime as dt,json,sys;"
                "sys.path.insert(0,'.agent/scripts');import contextctl;"
                "p='.agent/state/CONTEXT.json';v=json.load(open(p));"
                "v['checkpoint']['updated_at']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=2)).replace(microsecond=0).isoformat();"
                "v['usage_freshness']['observed_at']=v['checkpoint']['updated_at'];"
                "v['integrity']['content_sha256']='0'*64;"
                "v['integrity']['content_sha256']=contextctl.content_sha256(v);"
                "open(p,'w').write(json.dumps(v,ensure_ascii=False,indent=2)+'\\n')"
            )],
            cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if age_probe.returncode or run(root, "check") == 0:
            print("FAIL: stale-checkpoint fixture was not created")
            print(age_probe.stdout)
            return 1
        refreshed = invoke(
            root, "sync", "--reason", "checkpoint-renewal",
            "--summary", "renew an otherwise exact context lease",
            "--source-tokens", "2600",
        )
        if refreshed.returncode != 0 or run(root, "check") != 0:
            print("FAIL: exact expired context could not renew without repair")
            print(refreshed.stdout)
            return 1

        # Canonical mutators cannot reuse their former 1000-token default as a
        # low-value overwrite. Two successive transitions grow by the fast-mode
        # policy increment and their budget ratios grow with them.
        first_growth = automatic_transition(root, "automatic growth checkpoint one")
        first_context = json.loads((root / ".agent/state/CONTEXT.json").read_text())
        second_growth = automatic_transition(root, "automatic growth checkpoint two")
        second_context = json.loads((root / ".agent/state/CONTEXT.json").read_text())
        first_estimate = first_context.get("usage_freshness", {}).get("estimated_tokens")
        second_estimate = second_context.get("usage_freshness", {}).get("estimated_tokens")
        first_ratio = first_context.get("compaction", {}).get("budget_snapshot", {}).get("budget_ratio")
        second_ratio = second_context.get("compaction", {}).get("budget_snapshot", {}).get("budget_ratio")
        if (
            first_growth.returncode != 0
            or second_growth.returncode != 0
            or first_estimate != 2750
            or second_estimate != 2900
            or not isinstance(first_ratio, float)
            or not isinstance(second_ratio, float)
            or second_ratio <= first_ratio
        ):
            print("FAIL: automatic canonical transitions did not grow the usage estimate and budget waterline")
            print(first_growth.stdout)
            print(second_growth.stdout)
            return 1

        # Only an explicit, real context compaction may establish a lower new
        # active-context baseline. Plain sync records that deliberate reset.
        silent_lowering = invoke(
            root, "sync", "--reason", "unproven-reset",
            "--summary", "attempted to lower active context without a host event",
            "--source-tokens", "1500",
        )
        if silent_lowering.returncode == 0 or "cannot lower" not in silent_lowering.stdout:
            print("FAIL: ordinary sync silently lowered the active-window estimate")
            print(silent_lowering.stdout)
            return 1

        handoff = invoke(
            root, "sync", "--reason", "host-compaction-handoff",
            "--summary", "wrote bounded handoff and now await the host",
            "--source-tokens", "2900", "--request-host-compaction",
        )
        awaiting = json.loads((root / ".agent/state/CONTEXT.json").read_text())
        if handoff.returncode != 0 or awaiting.get("host_compaction", {}).get("state") != "awaiting_host_compaction":
            print("FAIL: compaction handoff did not enter awaiting_host_compaction")
            print(handoff.stdout)
            return 1
        receipt = root / "host-compaction-receipt.json"
        write_json(receipt, {
            "schema": "host-compaction-receipt/v1",
            "task_invariant_sha256": awaiting["task_invariant_sha256"],
            "from_estimated_tokens": 2900, "to_estimated_tokens": 1500,
            "observed_at": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).replace(microsecond=0).isoformat(),
            "host_id": "self-test-host", "nonce": "self-test-1",
        })
        stale_compaction = invoke(
            root, "sync", "--reason", "stale-host-context-compaction",
            "--summary", "stale host receipt must not lower the active context",
            "--source-tokens", "1500", "--host-compaction", "--source", "host:self-test-compaction",
            "--host-compaction-receipt", receipt.name,
        )
        if stale_compaction.returncode == 0 or "stale or future-dated" not in stale_compaction.stdout:
            print("FAIL: stale host compaction receipt was accepted")
            print(stale_compaction.stdout)
            return 1
        attacks += 1
        write_json(receipt, {
            "schema": "host-compaction-receipt/v1",
            "task_invariant_sha256": awaiting["task_invariant_sha256"],
            "from_estimated_tokens": 2900, "to_estimated_tokens": 1500,
            "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "host_id": "self-test-host", "nonce": "self-test-1",
        })
        adapter_path = root / "host-compaction-adapter.py"
        adapter_bytes = adapter_path.read_bytes()
        adapter_path.write_text("#!/usr/bin/env python3\nprint('FORGED')\n", encoding="utf-8")
        adapter_path.chmod(0o755)
        rejected_compaction = invoke(
            root, "sync", "--reason", "rejected-host-context-compaction",
            "--summary", "adapter must authenticate the host event",
            "--source-tokens", "1500", "--host-compaction", "--source", "host:self-test-compaction",
            "--host-compaction-receipt", receipt.name,
        )
        adapter_path.write_bytes(adapter_bytes); adapter_path.chmod(0o755)
        if (rejected_compaction.returncode == 0
                or not any(marker in rejected_compaction.stdout for marker in ("adapter rejected","metadata does not bind"))):
            print("FAIL: forged host compaction adapter output was accepted")
            print(rejected_compaction.stdout)
            return 1
        attacks += 1
        compacted = invoke(
            root, "sync", "--reason", "explicit-host-context-compaction",
            "--summary", "host compacted the active context and retained the bounded capsule",
            "--source-tokens", "1500", "--host-compaction", "--source", "host:self-test-compaction",
            "--host-compaction-receipt", receipt.name,
        )
        compacted_context = json.loads((root / ".agent/state/CONTEXT.json").read_text())
        if (
            compacted.returncode != 0
            or compacted_context.get("usage_freshness", {}).get("estimated_tokens") != 1500
            or compacted_context.get("host_compaction", {}).get("state") != "resumed"
            or compacted_context.get("compaction", {}).get("tokens_removed") != 1400
            or run(root, "check") != 0
        ):
            print("FAIL: explicit host context compaction could not establish a smaller honest baseline")
            print(compacted.stdout)
            return 1

        # Cumulative provider/TASK cost and active-window context are separate
        # accounts. A high cumulative value still hard-blocks total cost, but
        # cannot undo the just-recorded active-context compaction.
        cumulative = cumulative_usage_transition(root, 3600)
        cumulative_context = json.loads((root / ".agent/state/CONTEXT.json").read_text())
        cumulative_usage = cumulative_context.get("usage_freshness", {}).get("estimated_tokens")
        cumulative_budget = cumulative_context.get("compaction", {}).get("budget_snapshot", {})
        if (
            cumulative.returncode != 0
            or cumulative_usage != 1650
            or cumulative_budget.get("task_tokens_used") != 3600
            or cumulative_budget.get("watermark") != "hard"
        ):
            print("FAIL: cumulative cost either undid active compaction or failed its independent budget gate")
            print(cumulative.stdout)
            return 1

        # Context and control-plane budgets must count loaded-reference
        # reservations identically; references alone can cross the compact line.
        budget_task={**next_task,"tokens_used":2000,"token_budget":4000,
                     "loaded_references":[{"estimated_tokens":1200}]}
        write_json(root/"budget-task.json",budget_task)
        budget_probe=subprocess.run(
            [sys.executable,"-c",
             "import json,sys;sys.path.insert(0,'.agent/scripts');import contextctl;c=json.load(open('.agent/config.json'));t=json.load(open('budget-task.json'));print(json.dumps(contextctl.budget_snapshot(c,t),sort_keys=True))"],
            cwd=root,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
        )
        if budget_probe.returncode:
            print("FAIL: context budget probe failed")
            print(budget_probe.stdout)
            return 1
        budget_value=json.loads(budget_probe.stdout)
        if budget_value.get("reserved_reference_tokens")!=1200 or budget_value.get("watermark")!="compact":
            print("FAIL: context budget omitted loaded-reference reservations")
            return 1

        # Repair is the only reset path and stays blocked until a provider-
        # verified human decision binds the exact repaired capsule bytes. A
        # caller-authored user: label is not approval authority.
        (root / ".agent/state/CONTEXT.json").write_text("not-json", encoding="utf-8")
        if run(
            root,
            "repair",
            "--reset",
            "--reason",
            "corrupt",
            "--summary",
            "reconstructed from canonical task after corruption",
            "--source-tokens",
            "2000",
        ) == 0:
            print("FAIL: repair did not fail closed")
            return 1
        if run(root, "check") == 0:
            print("FAIL: repaired context passed without review")
            return 1
        if run(root, "approve-repair", "--source", "user:fixture-review") == 0:
            print("FAIL: user: prefix bypassed provider-verified repair approval")
            return 1
        repaired = json.loads((root / ".agent/state/CONTEXT.json").read_text())
        if repaired.get("integrity", {}).get("status") != "needs_review":
            print("FAIL: rejected repair approval mutated fail-closed state")
            return 1
        attacks += 1
    print(f"PASS: context capsule positive transitions and {attacks} adversarial fixtures")
    return 0


if __name__ == "__main__":
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"scripts"))
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
