#!/usr/bin/env python3
"""Verify adaptive local decisions and atomic active-task archival."""

from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "install.py"


def run(project: Path, command: list[str], expected: int = 0) -> str:
    result = subprocess.run(
        command, cwd=project, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=30,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"expected {expected}, got {result.returncode}: {' '.join(command)}\n{result.stdout}"
        )
    return result.stdout


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
        run(ROOT, command)
    finally:
        guardrails.unlink(missing_ok=True)


def fill_contract(project: Path) -> bytes:
    contract = """# Requirement Contract

- Goal: verify adaptive local approval and active-task archival
- Users: local workflow maintainers
- Success: local approval succeeds and the replaced task remains content-addressed
- In scope: local non-deploy standard control flow
- Out of scope: release, test, production and deployment authority
- Constraints: no external effects
- Data and permissions: fixture-only local files
- Target environment: local
- Context transport: native
- Acceptance: exact local decision record and valid archive chain
- Provenance: user fixture
- Production provider target: none
- Human decisions: pending
- Clarified: false
""".encode()
    (project / ".agent/state/REQUIREMENT_CONTRACT.md").write_bytes(contract)
    return contract


with tempfile.TemporaryDirectory(prefix="local-decision-archive-") as raw:
    project = Path(raw)
    install(project)
    bootstrap = run(project, [sys.executable, ".agent/scripts/agentctl.py", "bootstrap-check"])
    if "BOOTSTRAP LOCAL READY" not in bootstrap or "PROTECTED GATES BLOCKED" not in bootstrap:
        raise AssertionError(f"adapterless bootstrap reported the wrong trust tier:\n{bootstrap}")
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "start",
        "--title", "first local task", "--mode", "standard",
        "--environment", "local", "--files", "3",
    ])
    task_path = project / ".agent/state/TASK.json"
    first = json.loads(task_path.read_text(encoding="utf-8"))
    if first.get("decision_policy_version") != 2:
        raise AssertionError("adapterless local standard task did not select decision policy v2")
    fill_contract(project)
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "approve-requirements",
        "--source", "user:local-fixture",
    ])
    approved = json.loads(task_path.read_text(encoding="utf-8"))
    requirement = approved.get("gate_approvals", {}).get("requirement")
    if (
        not isinstance(requirement, dict)
        or requirement.get("assurance") != "explicit-user-message;local-only;not-provider-verified"
        or requirement.get("artifact_sha256") != approved.get("requirement_contract_sha256")
    ):
        raise AssertionError("local requirement decision was not exact or honestly labeled")
    reference = project / "bounded-reference.txt"
    reference.write_text("bounded reference bytes remain charged after unload\n", encoding="utf-8")
    before_reference_tokens = int(approved.get("tokens_used", 0))
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "reference-load",
        "--path", reference.name, "--purpose", "verify retained accounting",
    ])
    loaded = json.loads(task_path.read_text(encoding="utf-8"))
    loaded_context = json.loads(
        (project / ".agent/state/CONTEXT.json").read_text(encoding="utf-8")
    )
    charge = int(loaded["loaded_references"][0]["estimated_tokens"])
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "reference-unload", "--path", reference.name,
    ])
    unloaded = json.loads(task_path.read_text(encoding="utf-8"))
    unloaded_context = json.loads(
        (project / ".agent/state/CONTEXT.json").read_text(encoding="utf-8")
    )
    if unloaded.get("loaded_references") != [] or unloaded.get("tokens_used") != before_reference_tokens + charge:
        raise AssertionError("reference unload released already-active Token charge")
    loaded_estimate = int(loaded_context["usage_freshness"]["estimated_tokens"])
    unloaded_estimate = int(unloaded_context["usage_freshness"]["estimated_tokens"])
    transition_increment = 400
    if unloaded_estimate != loaded_estimate + transition_increment + charge:
        raise AssertionError(
            "reference unload failed to settle its reservation into the active-window estimate: "
            f"loaded={loaded_estimate} unloaded={unloaded_estimate} charge={charge}"
        )

    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "escalate-mode", "--files", "5",
        "--reapprove", "--source", "user:local-fixture-escalation",
    ])
    escalated = json.loads(task_path.read_text(encoding="utf-8"))
    if escalated.get("files") != 5 or escalated.get("current_node") != 2 or not isinstance(escalated.get("route_archive"), dict):
        raise AssertionError("monotonic file escalation did not reopen deterministic routing")
    before_decrease = task_path.read_bytes()
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "update-risk", "--files", "4",
    ], expected=1)
    if task_path.read_bytes() != before_decrease:
        raise AssertionError("declared file count decrease mutated task state")
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "start",
        "--title", "must fail without archive", "--mode", "standard",
        "--environment", "local", "--files", "3",
    ], expected=1)
    # A task rollover clears the reusable reference registry, but the bytes
    # remain in the same host context and must be settled into its estimate.
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "reference-load",
        "--path", reference.name, "--purpose", "verify task-rollover accounting",
    ])
    rollover_task = json.loads(task_path.read_text(encoding="utf-8"))
    rollover_charge = int(rollover_task["loaded_references"][0]["estimated_tokens"])
    rollover_context = json.loads(
        (project / ".agent/state/CONTEXT.json").read_text(encoding="utf-8")
    )
    rollover_estimate = int(rollover_context["usage_freshness"]["estimated_tokens"])
    old_task_bytes = task_path.read_bytes()
    old_contract_bytes = (project / ".agent/state/REQUIREMENT_CONTRACT.md").read_bytes()
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "start",
        "--title", "second local task", "--mode", "standard",
        "--environment", "local", "--files", "3", "--archive-active",
        "--archive-source", "user:switch-fixture",
        "--archive-reason", "the user explicitly replaced the unfinished local task",
    ])
    second = json.loads(task_path.read_text(encoding="utf-8"))
    second_context = json.loads(
        (project / ".agent/state/CONTEXT.json").read_text(encoding="utf-8")
    )
    head = second.get("task_archive")
    if second.get("title") != "second local task" or not isinstance(head, dict):
        raise AssertionError("active task replacement did not start the new clarification")
    if (
        second.get("loaded_references") != []
        or int(second_context["usage_freshness"]["estimated_tokens"])
        != rollover_estimate + transition_increment + rollover_charge
    ):
        raise AssertionError("task rollover released an active reference reservation")
    archive_path = project / str(head.get("path", ""))
    archive_bytes = archive_path.read_bytes()
    archive = json.loads(archive_bytes)
    if (
        hashlib.sha256(archive_bytes).hexdigest() != head.get("sha256")
        or archive.get("task", {}).get("utf8", "").encode() != old_task_bytes
        or archive.get("requirement_contract", {}).get("utf8", "").encode() != old_contract_bytes
        or archive.get("assurance") != "explicit-user-message;local-cancellation;not-provider-verified"
    ):
        raise AssertionError("active task archive did not preserve exact prior bytes and assurance")
    run(project, [sys.executable, ".agent/scripts/workflowctl.py", "validate"])
    run(project, [sys.executable, ".agent/scripts/contextctl.py", "check"])


with tempfile.TemporaryDirectory(prefix="protected-decision-") as raw:
    project = Path(raw)
    install(project)
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "start",
        "--title", "protected release", "--mode", "release",
        "--environment", "local", "--files", "3", "--cross-system",
    ])
    protected = json.loads((project / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    if (
        protected.get("mode") != "release"
        or protected.get("phase") != "clarification"
        or protected.get("requirements_clarified") is not False
        or protected.get("decision_policy_version") != 1
    ):
        raise AssertionError("adapterless release did not stop safely in clarification")
    fill_contract(project)
    before = (project / ".agent/state/TASK.json").read_bytes()
    blocked = run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "approve-requirements",
        "--source", "user:protected-fixture",
    ], expected=1)
    if "provider-signed human decision receipt" not in blocked:
        raise AssertionError(f"adapterless release approval failed for the wrong reason:\n{blocked}")
    if (project / ".agent/state/TASK.json").read_bytes() != before:
        raise AssertionError("blocked protected approval changed TASK")


with tempfile.TemporaryDirectory(prefix="opted-local-release-") as raw:
    project = Path(raw)
    install(project, allow_local_release=True)
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "start",
        "--title", "local release", "--mode", "release",
        "--environment", "local", "--files", "3", "--cross-system",
    ])
    task_path = project / ".agent/state/TASK.json"
    local_release = json.loads(task_path.read_text(encoding="utf-8"))
    if local_release.get("decision_policy_version") != 2:
        raise AssertionError("explicit local release opt-in did not select current-chat decisions")
    fill_contract(project)
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "approve-requirements",
        "--source", "user:codex-current-chat-fixture",
    ])
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "start",
        "--title", "external release", "--mode", "release",
        "--environment", "local", "--files", "3", "--external-impact",
        "--archive-active", "--archive-source", "user:external-fixture",
        "--archive-reason", "replace the local-only fixture with an external-impact fixture",
    ])
    external_release = json.loads(task_path.read_text(encoding="utf-8"))
    if external_release.get("decision_policy_version") != 1:
        raise AssertionError("external-impact release did not retain the provider policy")


with tempfile.TemporaryDirectory(prefix="local-release-migration-") as raw:
    project = Path(raw)
    install(project, allow_local_release=True)
    run(project, [
        sys.executable, ".agent/scripts/agentctl.py", "start",
        "--title", "migration release", "--mode", "release",
        "--environment", "local", "--files", "3", "--cross-system",
    ])
    task_path = project / ".agent/state/TASK.json"
    manifest_path = project / ".agent/.workflow-manifest.json"
    task = json.loads(task_path.read_text(encoding="utf-8"))
    task["decision_policy_version"] = 1
    task_path.write_text(json.dumps(task, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # Model a valid migration-30 predecessor: its active capsule must bind the
    # old canonical decision policy before the installer is allowed to change it.
    run(project, [sys.executable, "-c", (
        "import argparse,hashlib,json,sys;sys.path.insert(0,'.agent/scripts');import contextctl;"
        "p=contextctl.CONTEXT_PATH;previous=json.loads(p.read_text());"
        "args=argparse.Namespace(reason='migration-30-fixture',summary='valid local release predecessor',"
        "source='fixture:migration-30',source_tokens=4000,fact=[],file=[],evidence=[],risk=[],"
        "resolve_risk=[],transition=False,reset=False);"
        "capsule=contextctl.build_capsule(args,'verified',previous,hashlib.sha256(p.read_bytes()).hexdigest());"
        "contextctl.atomic_json(p,capsule);raise SystemExit(contextctl.validate_context())"
    )])
    install_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    install_manifest["version"] = "3.1.36"
    install_manifest["migration_version"] = 30
    manifest_path.write_text(
        json.dumps(install_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    run(ROOT, [
        sys.executable, str(INSTALLER), str(project), "--update",
        "--allow-current-chat-local-release",
    ])
    migrated = json.loads(task_path.read_text(encoding="utf-8"))
    if migrated.get("decision_policy_version") != 2:
        raise AssertionError("migration 31 did not rebind an eligible unapproved local release task")


print("PASS: adaptive local decisions, explicit Codex local-release opt-in, protected effects and migration 31")
