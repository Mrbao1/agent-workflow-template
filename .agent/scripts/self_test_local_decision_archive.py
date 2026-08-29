#!/usr/bin/env python3
"""Verify local decisions are advisory and active-task archival is atomic."""

from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile



if __name__=="__main__" and not globals().get("_PUBLICATION_SELF_TEST_REENTRY"):
    import runpy
    from workflowlib.publication import discover_project_root,run_cli
    def _publication_self_test():
        runpy.run_path(__file__,run_name="__main__",init_globals={"_PUBLICATION_SELF_TEST_REENTRY":True})
        return 0
    raise SystemExit(run_cli(discover_project_root(),_publication_self_test))

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "install.py"
sys.path.insert(0,str(ROOT/".agent/scripts"))
import humandecision

# Wrapper-level observer failure must still capture, terminate and reap the exact
# unreaped leader plus same-session children through the independent native path.
with tempfile.TemporaryDirectory(prefix="adapter-observer-failure-") as observer_raw:
    child_record=Path(observer_raw)/"child.pid"
    observer_code="import pathlib,subprocess,sys,time; c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); pathlib.Path(sys.argv[1]).write_text(str(c.pid)); time.sleep(60)"
    observer_process=subprocess.Popen([sys.executable,"-c",observer_code,str(child_record)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    for _attempt in range(200):
        if child_record.exists(): break
        import time; time.sleep(0.01)
    if not child_record.exists(): raise AssertionError("observer failure child fixture did not start")
    child_pid=int(child_record.read_text())
    original_adapter_snapshot=humandecision.adapter_snapshot; humandecision.adapter_snapshot=lambda:None
    try:
        if humandecision.stop_adapter_process(observer_process,{}) is not False: raise AssertionError("observer failure was reported as proven cleanup")
        if observer_process.returncode is None: raise AssertionError("observer failure left adapter leader unreaped")
        observed=humandecision.native_adapter_snapshot() or {}; child=observed.get(child_pid)
        if child is not None and not str(child.get("state","")).startswith("Z"): raise AssertionError("observer failure left an adapter child alive")
    finally:
        humandecision.adapter_snapshot=original_adapter_snapshot
        if observer_process.returncode is None:
            observer_process.kill(); observer_process.wait(timeout=2)
        try: os.kill(child_pid,9)
        except ProcessLookupError: pass

PROVIDER_WRAPPER = r"""
import runpy, sys
from pathlib import Path

target = sys.argv[1]
sys.path.insert(0, str(Path(target).resolve().parent))
import humandecision


def provider_verify(*_args, receipt=None, **_kwargs):
    return {
        "schema": "agent-human-decision/v1",
        "path": str(receipt),
        "sha256": "f" * 64,
        "bytes": 1,
        "decision_id": "self-test-provider",
        "authority": "provider-signed-user-message",
        "adapter_path": "/self-test/provider",
        "adapter_sha256": "e" * 64,
    }


def provider_reverify(*_args, record=None, **_kwargs):
    return isinstance(record, dict) and record.get("authority") == "provider-signed-user-message"


humandecision.verify = provider_verify
humandecision.reverify = provider_reverify
humandecision.record_decision_approval = provider_verify
sys.argv = [target, *sys.argv[2:]]
runpy.run_path(target, run_name="__main__")
"""


def run(project: Path, command: list[str], expected: int = 0) -> str:
    environment={**os.environ, "PATH": f"/usr/sbin:{os.environ.get('PATH', '')}"}
    provider_site=project/".test-provider-site"
    if provider_site.is_dir():
        inherited=environment.get("PYTHONPATH","")
        environment["PYTHONPATH"]=str(provider_site)+(os.pathsep+inherited if inherited else "")
    result = subprocess.run(
        command, cwd=project, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=30, env=environment,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"expected {expected}, got {result.returncode}: {' '.join(command)}\n{result.stdout}"
        )
    return result.stdout


def run_with_test_provider(
    project: Path, arguments: list[str], *, expected: int = 0,
    script: str = "agentctl.py",
) -> str:
    provider_site=project/".test-provider-site"
    provider_site.mkdir(exist_ok=True)
    (provider_site/"sitecustomize.py").write_text(
        "import sys\nfrom pathlib import Path\n"
        "sys.path.insert(0,str(Path.cwd()/'.agent/scripts'))\n"
        "import humandecision\n"
        "def _provider_reverify(*_args,record=None,**_kwargs):\n"
        " return isinstance(record,dict) and record.get('authority')=='provider-signed-user-message'\n"
        "humandecision.reverify=_provider_reverify\n",
        encoding="utf-8",
    )
    receipt = project / ".agent/state/test-provider-receipt.json"
    receipt.write_text('{"test_only":"provider-owned adapter input"}\n', encoding="utf-8")
    return run(project, [
        sys.executable, "-c", PROVIDER_WRAPPER,
        str(project / ".agent/scripts" / script), *arguments,
    ], expected=expected)


def install(project: Path, *, allow_local_release: bool = False) -> None:
    guardrails = project.parent / f".{project.name}-fixture-guardrails.md"
    guardrails.write_text("""# Project Guardrails

- Product and users: Disposable workflow decision fixture for maintainers.
- Technology and architecture: Python control-plane fixture.
- Writable and read-only areas: Only the disposable fixture is writable.
- Security, privacy, compliance and performance red lines: No external effects or private state.
- Build, test and lint commands: Run only this bounded self-test.
- Deployment authority and rollback owner: Deployment is forbidden; the fixture owns rollback.
""", encoding="utf-8")
    command = [
        sys.executable, str(INSTALLER), str(project), "--project-name", "decision-fixture",
        "--guardrails-file", str(guardrails),
    ]
    if allow_local_release:
        command.append("--allow-current-chat-local-release")
    try:
        if allow_local_release:
            blocked = run(ROOT, command, expected=2)
            if "--allow-current-chat-local-release is retired" not in blocked:
                raise AssertionError(f"retired local-release opt-in failed for the wrong reason:\n{blocked}")
            if any(project.iterdir()):
                raise AssertionError("retired local-release opt-in partially installed a project")
        else:
            run(ROOT, command)
    finally:
        guardrails.unlink(missing_ok=True)


def fill_contract(project: Path) -> bytes:
    contract = """# Requirement Contract

- Goal: verify advisory local decisions and active-task archival
- Users: local workflow maintainers
- Success: local records cannot authorize and the replaced task remains content-addressed
- In scope: local non-deploy standard control flow
- Out of scope: release, test, production and deployment authority
- Constraints: no external effects
- Data and permissions: fixture-only local files
- Target environment: local
- Context transport: native
- Acceptance: exact archived local record and provider-authorized positive transition
- Provenance: user fixture
- Production provider target: none
- Human decisions: pending
- Clarified: false
""".encode()
    (project / ".agent/state/REQUIREMENT_CONTRACT.md").write_bytes(contract)
    return contract


def reseal_context(project: Path, reason: str) -> None:
    script = (
        "import argparse,hashlib,json,sys;sys.path.insert(0,'.agent/scripts');import contextctl;"
        "p=contextctl.CONTEXT_PATH;previous=json.loads(p.read_text());"
        f"args=argparse.Namespace(reason={reason!r},summary='self-test state fixture',"
        "source='fixture:local-decision-archive',source_tokens=4000,fact=[],file=[],evidence=[],risk=[],"
        "resolve_risk=[],transition=False,reset=False,request_host_compaction=False,host_compaction=False);"
        "capsule=contextctl.build_capsule(args,'verified',previous,hashlib.sha256(p.read_bytes()).hexdigest());"
        "contextctl.atomic_json(p,capsule);raise SystemExit(contextctl.validate_context())"
    )
    run(project, [sys.executable, "-c", script])


def cross_repository_identity_case():
    with tempfile.TemporaryDirectory(prefix="human-decision-repository-identity-") as raw:
        base=Path(raw); roots=[base/"one",base/"two"]
        config={"project":{"name":"same","type":"same"},"project_initialization":{"schema":"agent-project-initialization/v1","guardrails_sha256":"a"*64,"guardrails_bytes":1,"initialized_at":"2026-01-01T00:00:00+00:00"}}
        for root in roots: root.mkdir(); (root/".git").mkdir()
        first=humandecision.project_identity_sha256(roots[0],config)
        second=humandecision.project_identity_sha256(roots[1],config)
        if first==second: raise AssertionError("identical project metadata allowed a human-decision receipt identity to replay across repositories")
        worktree=base/"worktree"; worktree.mkdir(); gitdir=base/"worktree-metadata"; gitdir.mkdir()
        (worktree/".git").write_text("gitdir: ../worktree-metadata\n",encoding="utf-8")
        if not humandecision.project_identity_sha256(worktree,config):
            raise AssertionError("safe Git worktree metadata did not produce a repository identity")
        (roots[1]/".git").rmdir(); (roots[1]/".git").symlink_to(roots[0]/".git",target_is_directory=True)
        try: humandecision.project_identity_sha256(roots[1],config)
        except SystemExit: pass
        else: raise AssertionError("symlinked repository metadata was accepted as human-decision identity authority")


cross_repository_identity_case()
with tempfile.TemporaryDirectory(prefix="local-decision-archive-") as raw:
    project = Path(raw)
    install(project)
    bootstrap = run(
        project,
        [sys.executable, ".agent/scripts/agentctl.py", "bootstrap-check"],
        expected=2,
    )
    if (
        "BOOTSTRAP NOT READY: provider-owned human-decision adapter is not configured" not in bootstrap
        or "AUTHORITATIVE GATES BLOCKED" not in bootstrap
        or "LOCAL READY" in bootstrap
    ):
        raise AssertionError(f"adapterless bootstrap did not fail closed:\n{bootstrap}")

    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "start", "--model", "provider-neutral/model.fixture",
        "--title", "first local task", "--mode", "standard",
        "--environment", "local", "--files", "3",
    ])
    task_path = project / ".agent/state/TASK.json"
    first = json.loads(task_path.read_text(encoding="utf-8"))
    if first.get("decision_policy_version") != 1:
        raise AssertionError("adapterless local task did not select the provider policy")

    fill_contract(project)
    before_missing_receipt = task_path.read_bytes()
    blocked = run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "approve-requirements",
        "--source", "user:local-fixture",
    ], expected=1)
    if "requires --human-decision-receipt" not in blocked:
        raise AssertionError(f"local approval failed for the wrong reason:\n{blocked}")
    if task_path.read_bytes() != before_missing_receipt:
        raise AssertionError("receipt-less local approval changed TASK")

    run_with_test_provider(project, [
        "approve-requirements", "--source", "user:local-fixture",
        "--human-decision-receipt", ".agent/state/test-provider-receipt.json",
    ])
    approved = json.loads(task_path.read_text(encoding="utf-8"))
    requirement = approved.get("gate_approvals", {}).get("requirement")
    if (
        approved.get("decision_policy_version") != 1
        or not isinstance(requirement, dict)
        or requirement.get("artifact_sha256") != approved.get("requirement_contract_sha256")
        or requirement.get("decision_receipt", {}).get("authority") != "provider-signed-user-message"
    ):
        raise AssertionError("provider approval was not stored as authoritative receipt evidence")

    reference = project / "bounded-reference.txt"
    reference.write_text("bounded reference bytes remain charged after unload\n", encoding="utf-8")
    before_reference_tokens = int(approved.get("tokens_used", 0))
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "reference-load",
        "--path", reference.name, "--purpose", "verify retained accounting",
    ])
    loaded = json.loads(task_path.read_text(encoding="utf-8"))
    loaded_context = json.loads((project / ".agent/state/CONTEXT.json").read_text(encoding="utf-8"))
    charge = int(loaded["loaded_references"][0]["estimated_tokens"])
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "reference-unload", "--path", reference.name,
    ])
    unloaded = json.loads(task_path.read_text(encoding="utf-8"))
    unloaded_context = json.loads((project / ".agent/state/CONTEXT.json").read_text(encoding="utf-8"))
    if unloaded.get("loaded_references") != [] or unloaded.get("tokens_used") != before_reference_tokens + charge:
        raise AssertionError("reference unload released already-active Token charge")
    loaded_estimate = int(loaded_context["usage_freshness"]["estimated_tokens"])
    unloaded_estimate = int(unloaded_context["usage_freshness"]["estimated_tokens"])
    transition_increment = 400
    if unloaded_estimate != loaded_estimate + transition_increment + charge:
        raise AssertionError("reference unload failed to settle its reservation")

    run_with_test_provider(project, [
        "escalate-mode", "--files", "5", "--reapprove",
        "--source", "user:local-fixture-escalation",
        "--human-decision-receipt", ".agent/state/test-provider-receipt.json",
    ])
    escalated = json.loads(task_path.read_text(encoding="utf-8"))
    if (
        escalated.get("files") != 5
        or escalated.get("current_node") != 2
        or escalated.get("decision_policy_version") != 1
        or not isinstance(escalated.get("route_archive"), dict)
    ):
        raise AssertionError("provider-authorized escalation did not reopen deterministic routing")
    before_decrease = task_path.read_bytes()
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "update-risk", "--files", "4",
    ], expected=1)
    if task_path.read_bytes() != before_decrease:
        raise AssertionError("declared file count decrease mutated task state")

    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "start", "--model", "provider-neutral/model.fixture",
        "--title", "must fail without archive", "--mode", "standard",
        "--environment", "local", "--files", "3",
    ], expected=1)
    run(project, [sys.executable, ".agent/scripts/templatectl.py", "route"])
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "reference-load",
        "--path", reference.name, "--purpose", "verify task-rollover accounting",
    ])
    rollover_task = json.loads(task_path.read_text(encoding="utf-8"))
    rollover_charge = int(rollover_task["loaded_references"][0]["estimated_tokens"])
    rollover_context = json.loads((project / ".agent/state/CONTEXT.json").read_text(encoding="utf-8"))
    rollover_estimate = int(rollover_context["usage_freshness"]["estimated_tokens"])

    # Model a historical policy-v2/current-chat approval. Even explicit task
    # replacement must reject it before archival or mutation.
    valid_rollover_task_bytes = task_path.read_bytes()
    historical = json.loads(valid_rollover_task_bytes)
    historical["decision_policy_version"] = 2
    historical["gate_approvals"]["requirement"] = {
        "source": "user:historical-local-fixture",
        "artifact_sha256": historical["requirement_contract_sha256"],
        "assurance": "explicit-user-message;local-only;not-provider-verified",
    }
    task_path.write_text(json.dumps(historical, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    reseal_context(project, "historical-local-record-fixture")
    rollover_estimate = int(json.loads(
        (project / ".agent/state/CONTEXT.json").read_text(encoding="utf-8")
    )["usage_freshness"]["estimated_tokens"])
    old_task_bytes = task_path.read_bytes()
    old_contract_bytes = (project / ".agent/state/REQUIREMENT_CONTRACT.md").read_bytes()
    invalid_context_path = project / ".agent/state/CONTEXT.json"
    invalid_context_before = invalid_context_path.read_bytes()
    rejected_legacy_archive = run_with_test_provider(project, [
        "start", "--model", "provider-neutral/model.fixture",
        "--title", "blocked legacy archive", "--mode", "standard",
        "--environment", "local", "--files", "3", "--archive-active",
        "--archive-source", "user:switch-fixture",
        "--archive-reason", "the user explicitly replaced the unfinished local task",
    ], expected=1)
    if (
        "starting active work requires a valid workflow state" not in rejected_legacy_archive
        or task_path.read_bytes() != old_task_bytes
        or invalid_context_path.read_bytes() != invalid_context_before
    ):
        raise AssertionError("legacy advisory workflow state was archived, mutated, or accepted as active authority")

    # Restore the exact provider-authorized task and rebuild its capsule. Only a
    # valid active state may be atomically archived while starting replacement work.
    task_path.write_bytes(valid_rollover_task_bytes)
    reseal_context(project, "restore-provider-authorized-rollover")
    rollover_estimate = int(json.loads(invalid_context_path.read_text(encoding="utf-8"))[
        "usage_freshness"
    ]["estimated_tokens"])
    old_task_bytes = task_path.read_bytes()
    valid_archived_task = json.loads(old_task_bytes)

    run_with_test_provider(project, [
        "start", "--model", "provider-neutral/model.fixture", "--title", "second local task", "--mode", "standard",
        "--environment", "local", "--files", "3", "--archive-active",
        "--archive-source", "user:switch-fixture",
        "--archive-reason", "the user explicitly replaced the unfinished local task",
        "--archive-human-decision-receipt", ".agent/state/evidence/test-archive-provider-receipt.json",
    ])
    second = json.loads(task_path.read_text(encoding="utf-8"))
    second_context = json.loads((project / ".agent/state/CONTEXT.json").read_text(encoding="utf-8"))
    head = second.get("task_archive")
    if (
        second.get("title") != "second local task"
        or second.get("decision_policy_version") != 1
        or not isinstance(head, dict)
    ):
        raise AssertionError("active task replacement did not start under provider policy")
    if (
        second.get("loaded_references") != []
        or int(second_context["usage_freshness"]["estimated_tokens"])
        != rollover_estimate + transition_increment + rollover_charge
    ):
        raise AssertionError("task rollover released an active reference reservation")
    archive_path = project / str(head.get("path", ""))
    archive_bytes = archive_path.read_bytes()
    archive = json.loads(archive_bytes)
    archived_task = json.loads(archive.get("task", {}).get("utf8", "{}"))
    archived_requirement = archived_task.get("gate_approvals", {}).get("requirement")
    if (
        hashlib.sha256(archive_bytes).hexdigest() != head.get("sha256")
        or archive.get("task", {}).get("utf8", "").encode() != old_task_bytes
        or archive.get("requirement_contract", {}).get("utf8", "").encode() != old_contract_bytes
        or archive.get("assurance") != "provider-signed-user-message"
        or not isinstance(archive.get("decision_receipt"), dict)
        or archive["decision_receipt"].get("authority") != "provider-signed-user-message"
        or archived_task.get("decision_policy_version") != 1
        or archived_requirement != valid_archived_task["gate_approvals"]["requirement"]
    ):
        raise AssertionError("provider-authorized active task was not preserved as non-authoritative archive data")

    # Both legacy policy identifiers fail closed even when accompanied by a
    # current-chat-shaped local record. Restore the canonical task after each
    # immutable rejection so the archive chain remains independently valid.
    fill_contract(project)
    canonical_second = task_path.read_bytes()
    for legacy_policy in (0, 2):
        candidate = json.loads(canonical_second)
        candidate["decision_policy_version"] = legacy_policy
        candidate["gate_approvals"]["requirement"] = {
            "source": "user:forged-current-chat",
            "artifact_sha256": hashlib.sha256(
                (project / ".agent/state/REQUIREMENT_CONTRACT.md").read_bytes()
            ).hexdigest(),
            "assurance": "explicit-user-message;local-only;not-provider-verified",
        }
        task_path.write_text(json.dumps(candidate, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        before_legacy_attempt = task_path.read_bytes()
        denied = run(project, [
            sys.executable, ".agent/scripts/agentctl.py", "approve-requirements",
            "--source", "user:forged-current-chat",
        ], expected=1)
        if "requires migration to the provider-owned decision policy" not in denied:
            raise AssertionError(f"legacy policy {legacy_policy} failed for the wrong reason:\n{denied}")
        if task_path.read_bytes() != before_legacy_attempt:
            raise AssertionError(f"legacy policy {legacy_policy} authority attempt changed TASK")
        task_path.write_bytes(canonical_second)

    before_current_chat_attempt = task_path.read_bytes()
    denied = run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "approve-requirements",
        "--source", "user:current-chat-only",
    ], expected=1)
    if "requires --human-decision-receipt" not in denied:
        raise AssertionError(f"current-chat-only approval failed for the wrong reason:\n{denied}")
    if task_path.read_bytes() != before_current_chat_attempt:
        raise AssertionError("current-chat-only approval changed TASK")

    run_with_test_provider(project, ["validate"], script="workflowctl.py")
    run(project, [sys.executable, ".agent/scripts/contextctl.py", "check"])


with tempfile.TemporaryDirectory(prefix="opted-local-release-") as raw:
    install(Path(raw), allow_local_release=True)


print("PASS: provider-only authority, advisory legacy decisions, and exact local task archival")
