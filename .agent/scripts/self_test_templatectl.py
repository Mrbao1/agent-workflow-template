#!/usr/bin/env python3
"""Adversarial fixtures for deterministic template routing and rendering."""

from pathlib import Path
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile


SOURCE_AGENT = Path(__file__).resolve().parents[1]


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def invoke(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, ".agent/scripts/templatectl.py", *args],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def require_failure(root: Path, label: str, *args: str) -> None:
    result = invoke(root, *args)
    if result.returncode == 0:
        raise AssertionError(f"adversarial template fixture passed: {label}\n{result.stdout}")


def fixture(root: Path, clarified: bool) -> None:
    (root / ".agent/scripts").mkdir(parents=True, exist_ok=True)
    (root / ".agent/templates").mkdir(parents=True, exist_ok=True)
    (root / ".agent/state/artifacts").mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE_AGENT / "scripts/templatectl.py", root / ".agent/scripts/templatectl.py")
    shutil.copy2(SOURCE_AGENT / "scripts/adaptive_common.py", root / ".agent/scripts/adaptive_common.py")
    shutil.copy2(SOURCE_AGENT / "scripts/skillctl.py", root / ".agent/scripts/skillctl.py")
    shutil.copy2(SOURCE_AGENT / "scripts/contextctl.py", root / ".agent/scripts/contextctl.py")
    shutil.copy2(SOURCE_AGENT / "scripts/contexttx.py", root / ".agent/scripts/contexttx.py")
    shutil.copy2(SOURCE_AGENT / "scripts/agentctl.py", root / ".agent/scripts/agentctl.py")
    shutil.copy2(SOURCE_AGENT / "scripts/humandecision.py", root / ".agent/scripts/humandecision.py")
    shutil.copy2(SOURCE_AGENT / "scripts/workflowctl.py", root / ".agent/scripts/workflowctl.py")
    shutil.copytree(SOURCE_AGENT / "scripts/workflowlib", root / ".agent/scripts/workflowlib", dirs_exist_ok=True)
    shutil.copy2(SOURCE_AGENT / "INDEX.md", root / ".agent/INDEX.md")
    shutil.copytree(SOURCE_AGENT / "workflows", root / ".agent/workflows", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "policies", root / ".agent/policies", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "skills/run-ai-coding-pipeline", root / ".agent/skills/run-ai-coding-pipeline", dirs_exist_ok=True)
    templates = [
        {
            "id": "requirement-contract",
            "path": "templates/requirement.md.tmpl",
            "output": ".agent/state/REQUIREMENT_CONTRACT.md",
            "renderable": False,
            "depends_on": [],
            "nodes": [1],
            "modes": ["release"],
            "capabilities": ["core"],
            "required": ["goal"],
        },
        {
            "id": "task-plan",
            "path": "templates/task.md.tmpl",
            "output": ".agent/state/artifacts/04-task-plan.md",
            "renderable": True,
            "depends_on": ["requirement-contract"],
            "nodes": [4],
            "modes": ["release"],
            "capabilities": ["core"],
            "required": ["task"],
        },
        {
            "id": "delivery-plan",
            "path": "templates/delivery.md.tmpl",
            "output": ".agent/state/artifacts/08-delivery-plan.md",
            "renderable": True,
            "depends_on": ["task-plan"],
            "nodes": [8],
            "modes": ["release"],
            "capabilities": ["delivery"],
            "required": ["delivery"],
        },
        {
            "id": "ci-contract",
            "path": "templates/ci.md.tmpl",
            "output": ".agent/state/artifacts/08-ci-contract.md",
            "renderable": True,
            "depends_on": ["delivery-plan"],
            "nodes": [8],
            "modes": ["release"],
            "capabilities": ["ci-provider-github"],
            "required": ["provider"],
        },
        {
            "id": "review-policy",
            "path": "templates/review.json.tmpl",
            "output": ".agent/state/artifacts/05-review-policy.json",
            "renderable": True,
            "depends_on": ["task-plan"],
            "nodes": [5, 7],
            "modes": ["release"],
            "capabilities": ["multi-agent"],
            "required": ["policy"],
        },
        {
            "id": "acceptance-workflow",
            "path": "templates/acceptance.json.tmpl",
            "output": ".agent/state/artifacts/04-acceptance-runner.json",
            "renderable": True,
            "depends_on": ["task-plan", "review-policy"],
            "nodes": [4, 7],
            "modes": ["release"],
            "capabilities": ["acceptance-workflow"],
            "required": ["runner"],
        },
        {
            "id": "acceptance-api",
            "path": "templates/acceptance.json.tmpl",
            "output": ".agent/state/artifacts/04-acceptance-runner.json",
            "renderable": True,
            "depends_on": ["task-plan", "review-policy"],
            "nodes": [4, 7],
            "modes": ["release"],
            "capabilities": ["acceptance-api"],
            "required": ["runner"],
        },
        {
            "id": "context-transport-profile",
            "path": "templates/context-transport-profile.json.tmpl",
            "output": ".agent/state/artifacts/04-context-transport-profile.json",
            "renderable": True,
            "depends_on": ["task-plan"],
            "nodes": [4, 6],
            "modes": ["release"],
            "capabilities": ["context-transport-pxpipe"],
            "required": [
                "model", "plugin_name", "plugin_version", "plugin_manifest_sha256",
                "plugin_integrity_sha256", "mcp_server_sha256", "mcp_worker_sha256",
                "runtime_bundle_sha256", "workflow_manifest_sha256",
                "workflow_source_tree_sha256", "workflow_plugin_files_sha256",
                "trusted_root_sha256",
                "source_sha256", "analyze_receipt_path", "analyze_receipt_sha256", "requirement_contract_sha256",
                "task_invariant_sha256", "approval_source", "approval_receipt_sha256",
            ],
        },
    ]
    write_json(root / ".agent/templates/manifest.json", {"schema": "agent-template-manifest/v2", "templates": templates})
    (root / ".agent/templates/requirement.md.tmpl").write_text("# {{goal}}\n", encoding="utf-8")
    (root / ".agent/templates/task.md.tmpl").write_text("# Task\n\n{{task}}\n", encoding="utf-8")
    (root / ".agent/templates/delivery.md.tmpl").write_text("# Delivery\n\n{{delivery}}\n", encoding="utf-8")
    (root / ".agent/templates/ci.md.tmpl").write_text("# CI\n\n{{provider}}\n", encoding="utf-8")
    (root / ".agent/templates/acceptance.json.tmpl").write_text('{"runner":"{{runner}}"}\n', encoding="utf-8")
    (root / ".agent/templates/review.json.tmpl").write_text('{"policy":"{{policy}}"}\n', encoding="utf-8")
    shutil.copy2(
        SOURCE_AGENT / "templates/context-transport-profile.json.tmpl",
        root / ".agent/templates/context-transport-profile.json.tmpl",
    )
    config = {
        "context": {
            "max_bytes": 8192,
            "max_list_items": 30,
            "max_capsule_tokens": {"release": 2200},
            "max_active_checkpoint_age_minutes": 45,
            "soft_budget_ratio": 0.6,
            "compact_budget_ratio": 0.75,
            "hard_budget_ratio": 0.9,
        },
        "routing": {"modes": {"release": {"token_budget": 48000}}},
        "acceptance_adapters": {
            "acceptance-workflow": {"implemented": True},
            "acceptance-api": {"implemented": False},
        },
        "context_transport": {
            "default": "native",
            "pxpipe": {
                "enabled": False,
                "activation": "explicit-opt-in",
                "plugin_name": "pxpipe-context",
                "plugin_version": "0.1.0+codex.20260721210500",
                "models": ["gpt-5.6-sol"],
                "primary_mode": "provider-proxy",
                "provider_activation": "default-new-local-sessions",
                "provider_configuration": "user-model-provider-plus-launch-agent",
                "provider_content_scope": "whole-request-eligible-content",
                "mcp_role": "optional-cold-reference",
                "selection": "analyze-then-render",
                "content_scope": "new-cold-reference-only",
                "session_boundary": "plugin-load-requires-new-chat",
                "fallback": "native",
            },
        },
    }
    write_json(root / ".agent/config.json", config)
    contract = "# Requirement Contract\n\nClarified by user.\n\n- Context transport: pxpipe-plugin-explicit-opt-in\n"
    (root / ".agent/state/REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    task = {
        "schema": "agent-task/v2",
        "title": "template fixture",
        "task_type": "governance",
        "complexity": "complex",
        "mode": "release",
        "files": 2,
        "environment": "local",
        "deployment_requested": False,
        "branch": "unversioned",
        "risk_flags": {},
        "requirements_clarified": clarified,
        "requirement_source": "user:fixture" if clarified else "pending",
        "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
        "requirement_contract_sha256": hashlib.sha256(contract.encode()).hexdigest() if clarified else "pending",
        "token_budget": 48000,
        "tokens_used": 100,
        "token_usage_source": "estimated",
        "child_agents_used": 0,
        "peak_child_agents": 0,
        "loaded_references": [],
        "primary_skill": "run-ai-coding-pipeline" if clarified else "clarify-task",
        "phase": "planning" if clarified else "clarification",
        "status": "in_progress" if clarified else "waiting_human",
        "decisions": [],
        "open_questions": [] if clarified else ["requirement contract approval"],
        "next_action": "route templates" if clarified else "clarify requirements",
        "current_node": 2 if clarified else 1,
        "accepted_nodes": [0, 1] if clarified else [0],
        "node_artifacts": {},
        "gate_approvals": {"requirement": {
            "source": "user:fixture",
            "decision_receipt": {"sha256": "a" * 64},
        }} if clarified else {},
        "decision_policy_version": 1,
        "pending_gate_artifacts": {},
        "rollback_ledger": [],
        "rollback_archive": None,
        "failure_ledger": {},
        "failure_archive": None,
        "mode_status": "confirmed" if clarified else "provisional",
        "selected_templates": ["requirement-contract"],
        "selected_capabilities": ["core"],
        "rendered_artifacts": [],
        "metrics": {
            "tokens": 100,
            "token_source": "estimated",
            "child_agents": 0,
            "peak_children": 0,
            "tool_calls": 0,
            "test_runs": 0,
            "test_failures": 0,
            "repair_rounds": 0,
            "user_corrections": 0,
            "context_compactions": 0,
            "references_loaded": 0,
        },
    }
    write_json(root / ".agent/state/TASK.json", task)


MODE_BUDGETS = {"fast": 16000, "standard": 48000, "release": 96000}


def mode_fixture(root: Path, mode: str, task_type: str, *, sync_context: bool = True) -> None:
    """Clarified fixture over the REAL template manifest for route regressions."""
    (root / ".agent/scripts").mkdir(parents=True, exist_ok=True)
    (root / ".agent/state/artifacts").mkdir(parents=True, exist_ok=True)
    for script in ("templatectl.py", "adaptive_common.py", "skillctl.py", "blueprintctl.py", "blueprintacceptance.py", "contextctl.py", "contexttx.py", "agentctl.py", "humandecision.py", "workflowctl.py"):
        shutil.copy2(SOURCE_AGENT / "scripts" / script, root / ".agent/scripts" / script)
    shutil.copytree(SOURCE_AGENT / "scripts/workflowlib", root / ".agent/scripts/workflowlib", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "templates", root / ".agent/templates", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "assets/templates", root / ".agent/assets/templates", dirs_exist_ok=True)
    shutil.copy2(SOURCE_AGENT / "INDEX.md", root / ".agent/INDEX.md")
    shutil.copytree(SOURCE_AGENT / "workflows", root / ".agent/workflows", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "policies", root / ".agent/policies", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "skills/run-ai-coding-pipeline", root / ".agent/skills/run-ai-coding-pipeline", dirs_exist_ok=True)
    config = {
        "context": {
            "max_bytes": 8192,
            "max_list_items": 30,
            "max_capsule_tokens": {"fast": 1000, "standard": 1200, "release": 2000},
            "estimated_turn_overhead_tokens": {"fast": 2000, "standard": 3000, "release": 4000},
            "transition_token_increment": {"fast": 200, "standard": 400, "release": 800},
            "bootstrap_overhead_tokens": 7000,
            "max_active_checkpoint_age_minutes": 45,
            "soft_budget_ratio": 0.6,
            "compact_budget_ratio": 0.75,
            "hard_budget_ratio": 0.9,
        },
        "routing": {
            "modes": {
                mode_name: {"token_budget": budget}
                for mode_name, budget in MODE_BUDGETS.items()
            },
        },
        "acceptance_adapters": {},
        "context_transport": {
            "default": "native",
            "pxpipe": {
                "enabled": False,
                "activation": "explicit-opt-in",
                "plugin_name": "pxpipe-context",
                "plugin_version": "0.1.0+codex.20260721210500",
                "models": ["gpt-5.6-sol"],
                "primary_mode": "provider-proxy",
                "provider_activation": "default-new-local-sessions",
                "provider_configuration": "user-model-provider-plus-launch-agent",
                "provider_content_scope": "whole-request-eligible-content",
                "mcp_role": "optional-cold-reference",
                "selection": "analyze-then-render",
                "content_scope": "new-cold-reference-only",
                "session_boundary": "plugin-load-requires-new-chat",
                "fallback": "native",
            },
        },
    }
    write_json(root / ".agent/config.json", config)
    contract = "# Requirement Contract\n\nClarified by user.\n"
    (root / ".agent/state/REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    task = {
        "schema": "agent-task/v2",
        "title": f"{mode} {task_type} route fixture",
        "task_type": task_type,
        "complexity": "simple",
        "mode": mode,
        "files": 1,
        "environment": "local",
        "deployment_requested": False,
        "branch": "unversioned",
        "risk_flags": {},
        "requirements_clarified": True,
        "requirement_source": "user:fixture",
        "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
        "requirement_contract_sha256": hashlib.sha256(contract.encode()).hexdigest(),
        "token_budget": MODE_BUDGETS[mode],
        "tokens_used": 100,
        "token_usage_source": "estimated",
        "child_agents_used": 0,
        "peak_child_agents": 0,
        "loaded_references": [],
        "primary_skill": "run-ai-coding-pipeline",
        "phase": "planning",
        "status": "in_progress",
        "decisions": [],
        "open_questions": [],
        "next_action": "route templates",
        "current_node": 2,
        "accepted_nodes": [0, 1],
        "node_artifacts": {},
        "gate_approvals": {"requirement": {
            "source": "user:fixture",
            "decision_receipt": {"sha256": "a" * 64},
        }},
        "decision_policy_version": 1,
        "pending_gate_artifacts": {},
        "rollback_ledger": [],
        "rollback_archive": None,
        "failure_ledger": {},
        "failure_archive": None,
        "mode_status": "confirmed",
        "selected_templates": ["requirement-contract"],
        "selected_capabilities": ["core"],
        "rendered_artifacts": [],
        "metrics": {
            "tokens": 100,
            "token_source": "estimated",
            "child_agents": 0,
            "peak_children": 0,
            "tool_calls": 0,
            "test_runs": 0,
            "test_failures": 0,
            "repair_rounds": 0,
            "user_corrections": 0,
            "context_compactions": 0,
            "references_loaded": 0,
        },
    }
    write_json(root / ".agent/state/TASK.json", task)
    if sync_context:
        context = subprocess.run(
            [
                sys.executable, ".agent/scripts/contextctl.py", "sync",
                "--reason", "fixture", "--summary", f"{mode} {task_type} route fixture",
                "--source-tokens", "1800",
            ],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if context.returncode:
            raise SystemExit(context.stdout)


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()


def secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def secure_json(path: Path, value: object) -> None:
    secure_directory(path.parent)
    write_json(path, value)
    path.chmod(0o600)


def adaptive_route_fixture(root: Path, capability_id: str) -> tuple[str, str, Path, dict[str, object]]:
    """Add one confirmed project capability and one fully verified dynamic Skill."""
    mode_fixture(root, "release", "governance", sync_context=False)

    config_path = root / ".agent/config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["agent_control"] = {"human_decision_observer": {
        "source": "orchestrator-user-message",
        "automatic_gate_trust": False,
        "human_verification_required": True,
        "allow_current_chat_local_release": True,
        "signed_adapter": None,
        "max_receipt_age_seconds": 900,
    }}
    secure_json(config_path, config)

    task_path = root / ".agent/state/TASK.json"
    task = json.loads(task_path.read_text(encoding="utf-8"))
    task["decision_policy_version"] = 2
    secure_json(task_path, task)

    # templatectl imports skillctl, whose default policy lives under assets. The
    # route fixture intentionally copies that managed policy instead of inventing
    # a weaker project policy.
    policy_path = root / ".agent/assets/policies/skill-policy.json"
    secure_directory(policy_path.parent)
    shutil.copy2(SOURCE_AGENT / "assets/policies/skill-policy.json", policy_path)
    policy_path.chmod(0o600)
    policy = json.loads(policy_path.read_text(encoding="utf-8"))

    design = {
        "goals": ["Route a user-confirmed project capability"],
        "architecture": ["Project capability execution is supplied by a locked dynamic Skill"],
        "technology_choices": [],
        "capabilities": [{"id": capability_id, "description": "project-defined release verification"}],
        "constraints": ["Dynamic Skill bytes remain content-addressed and offline-verifiable"],
        "acceptance": [{"id": "project-release", "criterion": "The confirmed project release route is selected"}],
        "commands": [{
            "id": "project-release-check", "argv": ["python3", "--version"],
            "stage": "acceptance", "timeout_seconds": 30, "covers": ["project-release"], "environment": ["PATH"],
        }],
        "providers": [],
    }
    blueprint_sha256 = canonical_sha256(design)
    source = "user:confirmed arbitrary project capability"
    blueprint = {
        "schema": "agent-project-blueprint/v1",
        "status": "confirmed",
        "design": design,
        "suggestions": [],
        "confirmation": {
            "source": source,
            "design_sha256": blueprint_sha256,
            "confirmed_at": "2026-01-01T00:00:00+00:00",
            "decision_receipt": {
                "source": source,
                "artifact_sha256": blueprint_sha256,
                "assurance": "explicit-user-message;local-only;not-provider-verified",
                "routing_profile_sha256": canonical_sha256({
                    key: task.get(key) for key in (
                        "task_type", "complexity", "mode", "files", "environment",
                        "deployment_requested", "branch", "risk_flags",
                    )
                }),
            },
        },
    }
    blueprint_path = root / ".agent/project/BLUEPRINT.json"
    secure_json(blueprint_path, blueprint)

    skill_id = "fixture-project-release"
    skill_files = {
        "LICENSE.txt": b"MIT License\n\nCopyright fixture\n",
        "SKILL.md": (
            "---\nname: fixture-project-release\n"
            "description: Verify the project-defined release capability.\n---\n"
            f"# {capability_id}\n\nExecute project-defined release verification.\n"
        ).encode(),
    }
    file_records = [
        {"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": "100600"}
        for name, raw in sorted(skill_files.items())
    ]
    bundle_sha256 = canonical_sha256({"files": file_records})
    for bundle_root in (
        root / ".agent/project/skill-cas" / bundle_sha256,
        root / ".agent/project/skills" / skill_id,
    ):
        secure_directory(bundle_root)
        for name, raw in skill_files.items():
            target = bundle_root / name
            target.write_bytes(raw)
            target.chmod(0o600)

    action = {
        "candidate": skill_id, "candidate_sha256": "b" * 64, "bundle_sha256": bundle_sha256,
        "approved_capabilities": [capability_id],
        "candidate_provenance": {"mode": "offline-user-reviewed", "source": "fixture-reviewed-catalog"},
    }
    action_sha256 = canonical_sha256(action)
    skill_source = "user:approved exact fixture Skill bytes"
    entry = {
        "id": skill_id,
        "status": "active",
        "source": {
            "host": "github.com", "owner": "fixture", "repository": "fixture-skill",
            "repository_id": 1, "commit": "a" * 40, "path": "skills/fixture/SKILL.md",
            "provenance_mode": "offline-user-reviewed", "provenance_source": "fixture-reviewed-catalog",
        },
        "license": {"spdx": "MIT", "sha256": file_records[0]["sha256"]},
        "candidate_sha256": "b" * 64,
        "recommendation_sha256": "c" * 64,
        "blueprint_sha256": blueprint_sha256,
        "score": 100.0,
        "matched_capabilities": [capability_id],
        "bundle_sha256": bundle_sha256,
        "files": file_records,
        "installed_at": "2026-01-01T00:00:00+00:00",
        "decision": {
            "gate": "adaptive-skill-install",
            "source": skill_source,
            "action_sha256": action_sha256,
            "action": action,
            "receipt": {
                "source": skill_source,
                "artifact_sha256": action_sha256,
                "assurance": "explicit-user-message;local-only;not-provider-verified",
                "routing_profile_sha256": blueprint["confirmation"]["decision_receipt"]["routing_profile_sha256"],
            },
        },
    }
    lock = {
        "schema": "agent-skills-lock/v1",
        "blueprint_sha256": blueprint_sha256,
        "policy_sha256": canonical_sha256(policy),
        "skills": [entry],
        "lock_sha256": None,
    }
    lock["lock_sha256"] = canonical_sha256({key: value for key, value in lock.items() if key != "lock_sha256"})
    secure_json(root / ".agent/project/skills.lock.json", lock)
    context = subprocess.run(
        [
            sys.executable, ".agent/scripts/contextctl.py", "sync",
            "--reason", "fixture", "--summary", "adaptive release route fixture",
            "--source-tokens", "1800",
        ],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if context.returncode:
        raise SystemExit(context.stdout)
    return blueprint_sha256, str(lock["lock_sha256"]), blueprint_path, lock


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="templatectl-") as raw:
        root = Path(raw)
        fixture(root, clarified=False)

        # No template routing or rendering can cross the clarification gate.
        before = (root / ".agent/state/TASK.json").read_bytes()
        require_failure(root, "unclarified-route", "route", "--capability", "acceptance-workflow")
        require_failure(
            root,
            "unclarified-render",
            "render",
            "--id",
            "task-plan",
            "--output",
            ".agent/state/artifacts/04-task-plan.md",
            "--var",
            "task=forged",
        )
        if (root / ".agent/state/TASK.json").read_bytes() != before:
            raise SystemExit("rejected unclarified operation mutated TASK.json")

        # Rebuild as clarified, bootstrap context, then route deterministically.
        fixture(root, clarified=True)
        context = subprocess.run(
            [
                sys.executable,
                ".agent/scripts/contextctl.py",
                "sync",
                "--reason",
                "fixture",
                "--summary",
                "clarified fixture ready for routing",
                "--source-tokens",
                "1800",
            ],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if context.returncode:
            raise SystemExit(context.stdout)

        # The manifest's exact variable contract must match the placeholders
        # in its governed source. Otherwise a selected template can become
        # impossible to render: manifest variables are rejected by the source,
        # while source variables are rejected by the manifest.
        manifest_path = root / ".agent/templates/manifest.json"
        original_manifest = manifest_path.read_text(encoding="utf-8")
        mismatched_manifest = json.loads(original_manifest)
        next(
            item for item in mismatched_manifest["templates"]
            if item["id"] == "task-plan"
        )["required"] = ["wrong_variable"]
        write_json(manifest_path, mismatched_manifest)
        require_failure(
            root,
            "manifest-placeholder-contract",
            "route",
            "--capability",
            "acceptance-workflow",
        )
        manifest_path.write_text(original_manifest, encoding="utf-8")

        require_failure(root, "unimplemented-release-adapter", "route", "--capability", "acceptance-api")
        routed = invoke(root, "route", "--capability", "ci-provider-github", "--capability", "acceptance-workflow")
        if routed.returncode:
            raise SystemExit(routed.stdout)
        task_path = root / ".agent/state/TASK.json"
        task = json.loads(task_path.read_text(encoding="utf-8"))
        if "delivery" not in task["selected_capabilities"]:
            raise SystemExit("CI provider did not automatically select its delivery dependency")
        if "multi-agent" not in task["selected_capabilities"]:
            raise SystemExit("release acceptance did not automatically select independent review")
        if task["selected_templates"] != [
            "requirement-contract",
            "task-plan",
            "delivery-plan",
            "ci-contract",
            "review-policy",
            "acceptance-workflow",
        ]:
            raise SystemExit(f"unexpected deterministic route: {task['selected_templates']}")
        route_receipt = task.get("template_route", {})
        if (
            route_receipt.get("schema") != "agent-template-route/v3"
            or route_receipt.get("adaptive_project") != {"blueprint_sha256": None, "skills_lock_sha256": None, "project_capabilities": []}
            or route_receipt.get("task_type") != task.get("task_type")
            or route_receipt.get("projection") != "lightweight-release"
            or not route_receipt.get("sha256")
        ):
            raise SystemExit("route did not persist a digest-bound receipt")

        # Provider text cannot disagree with the provider capability bound into the route.
        require_failure(
            root, "ci-provider-mismatch", "render", "--id", "ci-contract",
            "--output", ".agent/state/artifacts/08-ci-contract.md", "--var", "provider=gitlab",
        )

        # At must_compact, a new capability is an executable budget violation, not a warning.
        compact_task = json.loads(task_path.read_text(encoding="utf-8"))
        compact_task["tokens_used"] = 36000
        compact_task["budget_state"] = "must_compact"
        write_json(task_path, compact_task)
        before_expansion = task_path.read_bytes()
        require_failure(root, "must-compact-capability-expansion", "route", "--capability", "multi-agent", "--capability", "acceptance-workflow")
        if task_path.read_bytes() != before_expansion:
            raise SystemExit("blocked budget expansion mutated TASK")
        write_json(task_path, task)

        # Output is manifest-driven; arbitrary project and protected state paths are rejected.
        for label, output in (
            ("source-overwrite", "src/owned.md"),
            ("task-overwrite", ".agent/state/TASK.json"),
            ("different-artifact", ".agent/state/artifacts/not-canonical.md"),
            ("path-escape", "../escape.md"),
        ):
            require_failure(
                root,
                label,
                "render",
                "--id",
                "task-plan",
                "--output",
                output,
                "--var",
                "task=fixture task",
            )

        rendered = invoke(
            root,
            "render",
            "--id",
            "task-plan",
            "--output",
            ".agent/state/artifacts/04-task-plan.md",
            "--var",
            "task=fixture task",
        )
        if rendered.returncode:
            raise SystemExit(rendered.stdout)
        task = json.loads(task_path.read_text(encoding="utf-8"))
        record = next(item for item in task["rendered_artifacts"] if item["template_id"] == "task-plan")
        required_binding = {
            "schema",
            "template_id",
            "path",
            "sha256",
            "bytes",
            "requirement_contract_sha256",
            "manifest_sha256",
            "route_sha256",
            "source_path",
            "source_sha256",
            "source_bytes",
        }
        if set(record) != required_binding:
            raise SystemExit(f"render record lacks full provenance binding: {sorted(set(record) ^ required_binding)}")

        # Expected route/dependencies are recomputed, not trusted from selected_templates.
        valid_task = json.loads(task_path.read_text(encoding="utf-8"))
        tampered = {**valid_task, "selected_templates": [item for item in valid_task["selected_templates"] if item != "delivery-plan"]}
        write_json(task_path, tampered)
        require_failure(root, "missing-route-dependency", "validate")
        write_json(task_path, valid_task)

        # Terminal workflow replay is read-only and must remain valid after
        # complete-task changes the task to accepted/idle. Mutating operations
        # stay blocked at the same terminal state.
        terminal = {
            **valid_task,
            "status": "accepted",
            "phase": "idle",
            "current_node": "idle",
            "next_action": "start the next requirement in clarification",
        }
        write_json(task_path, terminal)
        terminal_validation = invoke(root, "validate")
        if terminal_validation.returncode:
            raise SystemExit(f"terminal template validation was incorrectly blocked:\n{terminal_validation.stdout}")
        require_failure(root, "terminal-route-remains-blocked", "route", "--capability", "acceptance-workflow")
        require_failure(
            root, "terminal-render-remains-blocked", "render", "--id", "task-plan",
            "--output", ".agent/state/artifacts/04-task-plan.md", "--var", "task=terminal mutation",
        )
        write_json(task_path, valid_task)

        # A rendered artifact becomes stale when its source, contract, manifest or output changes.
        source = root / ".agent/templates/task.md.tmpl"
        original_source = source.read_text(encoding="utf-8")
        source.write_text(original_source + "changed\n", encoding="utf-8")
        require_failure(root, "stale-template-source", "validate")
        source.write_text(original_source, encoding="utf-8")

        # The original manifest path identity itself must be a regular file, not
        # an in-boundary symlink whose resolved target merely looks safe.
        link = root / ".agent/templates/task-link.md.tmpl"
        link.symlink_to(source.name)
        manifest_path = root / ".agent/templates/manifest.json"
        original_manifest = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        next(item for item in manifest["templates"] if item["id"] == "task-plan")["path"] = "templates/task-link.md.tmpl"
        write_json(manifest_path, manifest)
        require_failure(root, "template-source-symlink", "validate")
        manifest_path.write_text(original_manifest, encoding="utf-8")

        output = root / ".agent/state/artifacts/04-task-plan.md"
        output.write_text("tampered output\n", encoding="utf-8")
        require_failure(root, "stale-render-output", "validate")

    with tempfile.TemporaryDirectory(prefix="templatectl-pxpipe-") as raw:
        root = Path(raw)
        fixture(root, clarified=True)
        agents_path = root / "AGENTS.md"
        agents_path.write_text("# Fixture bootstrap\n", encoding="utf-8")
        plugin_root = root / "plugins/pxpipe-context"
        plugin_manifest_path = plugin_root / ".codex-plugin/plugin.json"
        integrity_path = plugin_root / "integrity.json"
        server_path = plugin_root / "mcp/server.mjs"
        worker_path = plugin_root / "mcp/worker.mjs"
        runtime_path = plugin_root / "mcp/vendor/pxpipe-runtime.mjs"
        write_json(plugin_manifest_path, {"name": "pxpipe-context", "version": "0.1.0+codex.20260721210500"})
        server_path.parent.mkdir(parents=True, exist_ok=True)
        runtime_path.parent.mkdir(parents=True, exist_ok=True)
        server_path.write_text("// fixture server\n", encoding="utf-8")
        worker_path.write_text("// fixture worker\n", encoding="utf-8")
        runtime_path.write_text("export {};\n", encoding="utf-8")
        runtime_sha256 = hashlib.sha256(runtime_path.read_bytes()).hexdigest()
        write_json(integrity_path, {
            "plugin_version": "0.1.0+codex.20260721210500",
            "runtime_bundle": "mcp/vendor/pxpipe-runtime.mjs",
            "runtime_bundle_sha256": runtime_sha256,
        })
        plugin_files = {
            ".codex-plugin/plugin.json": hashlib.sha256(plugin_manifest_path.read_bytes()).hexdigest(),
            "integrity.json": hashlib.sha256(integrity_path.read_bytes()).hexdigest(),
            "mcp/server.mjs": hashlib.sha256(server_path.read_bytes()).hexdigest(),
            "mcp/worker.mjs": hashlib.sha256(worker_path.read_bytes()).hexdigest(),
            "mcp/vendor/pxpipe-runtime.mjs": runtime_sha256,
        }
        # Project installations retain only content attestations. The actual
        # Skill + MCP bundle is installed globally and must not be copied here.
        shutil.rmtree(plugin_root)
        workflow_manifest_path = root / ".agent/.workflow-manifest.json"
        write_json(workflow_manifest_path, {
            "schema": "agent-workflow-install/v3",
            "version": "fixture",
            "migration_version": 1,
            "source_tree_sha256": "f" * 64,
            "agent_files": {},
            "repo_plugin_files": plugin_files,
            "marketplace_entry": {"name": "pxpipe-context", "sha256": "9" * 64},
            "agents_bootstrap": {
                "path": "AGENTS.md",
                "sha256": hashlib.sha256(agents_path.read_bytes()).hexdigest(),
            },
        })
        workflow_manifest_sha256 = hashlib.sha256(workflow_manifest_path.read_bytes()).hexdigest()
        workflow_plugin_files_sha256 = hashlib.sha256(json.dumps(
            plugin_files, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        trusted_root_sha256 = hashlib.sha256(str(root.resolve()).encode()).hexdigest()
        context = subprocess.run(
            [
                sys.executable, ".agent/scripts/contextctl.py", "sync",
                "--reason", "fixture", "--summary", "pxpipe plugin route fixture",
                "--source-tokens", "1800",
            ],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if context.returncode:
            raise SystemExit(context.stdout)
        require_failure(
            root, "available-plugin-is-not-enabled", "route",
            "--capability", "context-transport-pxpipe",
            "--capability", "acceptance-workflow",
        )
        config_path = root / ".agent/config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["context_transport"]["pxpipe"]["enabled"] = True
        write_json(config_path, config)
        routed = invoke(
            root, "route", "--capability", "context-transport-pxpipe",
            "--capability", "acceptance-workflow",
        )
        if routed.returncode:
            raise SystemExit(routed.stdout)
        task = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        invariant = hashlib.sha256(json.dumps({
            key: task.get(key)
            for key in (
                "title", "mode", "task_type", "complexity", "environment",
                "branch", "requirement_contract_sha256", "selected_capabilities",
            )
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        analyze_receipt = {
            "schema": "pxpipe-context-analyze/v1",
            "model": "gpt-5.6-sol",
            "purpose": "cold-semantic-reference",
            "status": "eligible",
            "source_sha256": "c" * 64,
            "file_count": 1,
            "source_bytes": 4096,
            "page_count": 1,
            "total_image_bytes": 2048,
            "token_report": {
                "text_tokens": 1200,
                "image_tokens": 500,
                "percent_saved": 58.3,
            },
            "rejection_reasons": [],
            "provenance": {
                "plugin_name": "pxpipe-context",
                "plugin_version": "0.1.0+codex.20260721210500",
                "plugin_manifest_sha256": plugin_files[".codex-plugin/plugin.json"],
                "plugin_integrity_sha256": plugin_files["integrity.json"],
                "mcp_server_sha256": plugin_files["mcp/server.mjs"],
                "mcp_worker_sha256": plugin_files["mcp/worker.mjs"],
                "pxpipe_package": "pxpipe-proxy",
                "pxpipe_version": "0.9.0",
                "runtime_bundle_sha256": runtime_sha256,
                "source_package_sha256": "e" * 64,
                "provenance_assurance": "content-and-install-anchored;no-host-signature",
                "trusted_root_sha256": trusted_root_sha256,
                "trusted_root_source": "mcp-roots/list",
                "workflow_manifest_sha256": workflow_manifest_sha256,
                "workflow_source_tree_sha256": "f" * 64,
                "workflow_plugin_files_sha256": workflow_plugin_files_sha256,
                "attestation_mode": "agent-workflow-v3",
            },
        }
        analyze_receipt_sha256 = hashlib.sha256(json.dumps(
            analyze_receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        analyze_receipt["analyze_receipt_sha256"] = analyze_receipt_sha256
        analyze_receipt_relative = Path(
            ".agent/state/evidence/context-transport"
        ) / f"{analyze_receipt_sha256}.json"
        write_json(root / analyze_receipt_relative, analyze_receipt)
        variables = [
            "model=gpt-5.6-sol",
            "plugin_name=pxpipe-context",
            "plugin_version=0.1.0+codex.20260721210500",
            f"plugin_manifest_sha256={plugin_files['.codex-plugin/plugin.json']}",
            f"plugin_integrity_sha256={plugin_files['integrity.json']}",
            f"mcp_server_sha256={plugin_files['mcp/server.mjs']}",
            f"mcp_worker_sha256={plugin_files['mcp/worker.mjs']}",
            f"runtime_bundle_sha256={runtime_sha256}",
            f"workflow_manifest_sha256={workflow_manifest_sha256}",
            "workflow_source_tree_sha256=" + "f" * 64,
            f"workflow_plugin_files_sha256={workflow_plugin_files_sha256}",
            f"trusted_root_sha256={trusted_root_sha256}",
            f"source_sha256={'c' * 64}",
            f"analyze_receipt_path={analyze_receipt_relative}",
            f"analyze_receipt_sha256={analyze_receipt_sha256}",
            f"requirement_contract_sha256={task['requirement_contract_sha256']}",
            f"task_invariant_sha256={invariant}",
            "approval_source=user:fixture",
            f"approval_receipt_sha256={'a' * 64}",
        ]
        invalid = [
            "source_sha256=not-a-digest" if item.startswith("source_sha256=") else item
            for item in variables
        ]
        invalid_args = [value for variable in invalid for value in ("--var", variable)]
        require_failure(
            root, "unbound-plugin-source", "render", "--id", "context-transport-profile",
            "--output", ".agent/state/artifacts/04-context-transport-profile.json", *invalid_args,
        )
        render_args = [value for variable in variables for value in ("--var", variable)]
        original_agents = agents_path.read_text(encoding="utf-8")
        agents_path.write_text(original_agents + "drift\n", encoding="utf-8")
        require_failure(
            root, "workflow-bootstrap-drift", "render", "--id", "context-transport-profile",
            "--output", ".agent/state/artifacts/04-context-transport-profile.json", *render_args,
        )
        agents_path.write_text(original_agents, encoding="utf-8")
        rendered = invoke(
            root, "render", "--id", "context-transport-profile",
            "--output", ".agent/state/artifacts/04-context-transport-profile.json", *render_args,
        )
        if rendered.returncode:
            raise SystemExit(rendered.stdout)
        profile = json.loads((root / ".agent/state/artifacts/04-context-transport-profile.json").read_text(encoding="utf-8"))
        forbidden = {
            "pxpipe_repository", "pxpipe_commit", "openai_upstream", "loopback_port", "runner",
        }
        if (
            profile.get("schema") != "agent-context-transport-profile/v2"
            or profile.get("selection") != "analyze-then-render"
            or profile.get("content_scope") != "new-cold-reference-only"
            or forbidden.intersection(profile)
        ):
            raise AssertionError(f"pxpipe plugin profile retained the old proxy contract: {profile}")

        forged = [
            f"analyze_receipt_sha256={'d' * 64}"
            if item.startswith("analyze_receipt_sha256=") else item
            for item in variables
        ]
        forged_args = [value for variable in forged for value in ("--var", variable)]
        require_failure(
            root, "forged-analyze-receipt", "render", "--id", "context-transport-profile",
            "--output", ".agent/state/artifacts/04-context-transport-profile.json", *forged_args,
        )

    # Fresh installs write agent-workflow-install/v4 manifests. Render the same
    # pxpipe profile against a manifest produced by the real installer writer so
    # the v4 installation anchor can never drift out of the accepted render path.
    with tempfile.TemporaryDirectory(prefix="templatectl-pxpipe-v4-") as raw:
        root = Path(raw)
        fixture(root, clarified=True)
        agents_path = root / "AGENTS.md"
        agents_path.write_text("# Fixture bootstrap\n", encoding="utf-8")
        claude_path = root / "CLAUDE.md"
        claude_path.write_text("# Fixture Claude bootstrap\n", encoding="utf-8")
        plugin_root = root / "plugins/pxpipe-context"
        plugin_manifest_path = plugin_root / ".codex-plugin/plugin.json"
        integrity_path = plugin_root / "integrity.json"
        server_path = plugin_root / "mcp/server.mjs"
        worker_path = plugin_root / "mcp/worker.mjs"
        runtime_path = plugin_root / "mcp/vendor/pxpipe-runtime.mjs"
        write_json(plugin_manifest_path, {"name": "pxpipe-context", "version": "0.1.0+codex.20260721210500"})
        server_path.parent.mkdir(parents=True, exist_ok=True)
        runtime_path.parent.mkdir(parents=True, exist_ok=True)
        server_path.write_text("// fixture server\n", encoding="utf-8")
        worker_path.write_text("// fixture worker\n", encoding="utf-8")
        runtime_path.write_text("export {};\n", encoding="utf-8")
        runtime_sha256 = hashlib.sha256(runtime_path.read_bytes()).hexdigest()
        write_json(integrity_path, {
            "plugin_version": "0.1.0+codex.20260721210500",
            "runtime_bundle": "mcp/vendor/pxpipe-runtime.mjs",
            "runtime_bundle_sha256": runtime_sha256,
        })
        plugin_files = {
            ".codex-plugin/plugin.json": hashlib.sha256(plugin_manifest_path.read_bytes()).hexdigest(),
            "integrity.json": hashlib.sha256(integrity_path.read_bytes()).hexdigest(),
            "mcp/server.mjs": hashlib.sha256(server_path.read_bytes()).hexdigest(),
            "mcp/worker.mjs": hashlib.sha256(worker_path.read_bytes()).hexdigest(),
            "mcp/vendor/pxpipe-runtime.mjs": runtime_sha256,
        }
        shutil.rmtree(plugin_root)
        installer_spec = importlib.util.spec_from_file_location(
            "workflow_installer", SOURCE_AGENT.parent / "install.py",
        )
        installer = importlib.util.module_from_spec(installer_spec)
        installer_spec.loader.exec_module(installer)
        workflow_manifest_path = root / ".agent/.workflow-manifest.json"
        write_json(workflow_manifest_path, installer.install_manifest(
            installer.files(root / ".agent"),
            plugin_files,
            installer.canonical_sha256({"name": "pxpipe-context", "source": "fixture"}),
            hashlib.sha256(agents_path.read_bytes()).hexdigest(),
            hashlib.sha256(claude_path.read_bytes()).hexdigest(),
        ))
        workflow_manifest = json.loads(workflow_manifest_path.read_text(encoding="utf-8"))
        if workflow_manifest.get("schema") != "agent-workflow-install/v4":
            raise SystemExit("installer no longer writes v4 manifests; extend the pxpipe render fixtures")
        workflow_source_tree_sha256 = workflow_manifest["source_tree_sha256"]
        workflow_manifest_sha256 = hashlib.sha256(workflow_manifest_path.read_bytes()).hexdigest()
        workflow_plugin_files_sha256 = hashlib.sha256(json.dumps(
            plugin_files, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        trusted_root_sha256 = hashlib.sha256(str(root.resolve()).encode()).hexdigest()
        context = subprocess.run(
            [
                sys.executable, ".agent/scripts/contextctl.py", "sync",
                "--reason", "fixture", "--summary", "pxpipe v4 install route fixture",
                "--source-tokens", "1800",
            ],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if context.returncode:
            raise SystemExit(context.stdout)
        config_path = root / ".agent/config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["context_transport"]["pxpipe"]["enabled"] = True
        write_json(config_path, config)
        routed = invoke(
            root, "route", "--capability", "context-transport-pxpipe",
            "--capability", "acceptance-workflow",
        )
        if routed.returncode:
            raise SystemExit(routed.stdout)
        task = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        invariant = hashlib.sha256(json.dumps({
            key: task.get(key)
            for key in (
                "title", "mode", "task_type", "complexity", "environment",
                "branch", "requirement_contract_sha256", "selected_capabilities",
            )
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        analyze_receipt = {
            "schema": "pxpipe-context-analyze/v1",
            "model": "gpt-5.6-sol",
            "purpose": "cold-semantic-reference",
            "status": "eligible",
            "source_sha256": "c" * 64,
            "file_count": 1,
            "source_bytes": 4096,
            "page_count": 1,
            "total_image_bytes": 2048,
            "token_report": {
                "text_tokens": 1200,
                "image_tokens": 500,
                "percent_saved": 58.3,
            },
            "rejection_reasons": [],
            "provenance": {
                "plugin_name": "pxpipe-context",
                "plugin_version": "0.1.0+codex.20260721210500",
                "plugin_manifest_sha256": plugin_files[".codex-plugin/plugin.json"],
                "plugin_integrity_sha256": plugin_files["integrity.json"],
                "mcp_server_sha256": plugin_files["mcp/server.mjs"],
                "mcp_worker_sha256": plugin_files["mcp/worker.mjs"],
                "pxpipe_package": "pxpipe-proxy",
                "pxpipe_version": "0.9.0",
                "runtime_bundle_sha256": runtime_sha256,
                "source_package_sha256": "e" * 64,
                "provenance_assurance": "content-and-install-anchored;no-host-signature",
                "trusted_root_sha256": trusted_root_sha256,
                "trusted_root_source": "mcp-roots/list",
                "workflow_manifest_sha256": workflow_manifest_sha256,
                "workflow_source_tree_sha256": workflow_source_tree_sha256,
                "workflow_plugin_files_sha256": workflow_plugin_files_sha256,
                "attestation_mode": "agent-workflow-v4",
            },
        }
        analyze_receipt_sha256 = hashlib.sha256(json.dumps(
            analyze_receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        analyze_receipt["analyze_receipt_sha256"] = analyze_receipt_sha256
        analyze_receipt_relative = Path(
            ".agent/state/evidence/context-transport"
        ) / f"{analyze_receipt_sha256}.json"
        write_json(root / analyze_receipt_relative, analyze_receipt)
        variables = [
            "model=gpt-5.6-sol",
            "plugin_name=pxpipe-context",
            "plugin_version=0.1.0+codex.20260721210500",
            f"plugin_manifest_sha256={plugin_files['.codex-plugin/plugin.json']}",
            f"plugin_integrity_sha256={plugin_files['integrity.json']}",
            f"mcp_server_sha256={plugin_files['mcp/server.mjs']}",
            f"mcp_worker_sha256={plugin_files['mcp/worker.mjs']}",
            f"runtime_bundle_sha256={runtime_sha256}",
            f"workflow_manifest_sha256={workflow_manifest_sha256}",
            f"workflow_source_tree_sha256={workflow_source_tree_sha256}",
            f"workflow_plugin_files_sha256={workflow_plugin_files_sha256}",
            f"trusted_root_sha256={trusted_root_sha256}",
            f"source_sha256={'c' * 64}",
            f"analyze_receipt_path={analyze_receipt_relative}",
            f"analyze_receipt_sha256={analyze_receipt_sha256}",
            f"requirement_contract_sha256={task['requirement_contract_sha256']}",
            f"task_invariant_sha256={invariant}",
            "approval_source=user:fixture",
            f"approval_receipt_sha256={'a' * 64}",
        ]
        render_args = [value for variable in variables for value in ("--var", variable)]
        # v4 additionally anchors the CLAUDE.md bootstrap; drift must fail closed.
        original_claude = claude_path.read_text(encoding="utf-8")
        claude_path.write_text(original_claude + "drift\n", encoding="utf-8")
        require_failure(
            root, "workflow-claude-bootstrap-drift", "render", "--id", "context-transport-profile",
            "--output", ".agent/state/artifacts/04-context-transport-profile.json", *render_args,
        )
        claude_path.write_text(original_claude, encoding="utf-8")
        rendered = invoke(
            root, "render", "--id", "context-transport-profile",
            "--output", ".agent/state/artifacts/04-context-transport-profile.json", *render_args,
        )
        if rendered.returncode:
            raise SystemExit(rendered.stdout)
        profile = json.loads((root / ".agent/state/artifacts/04-context-transport-profile.json").read_text(encoding="utf-8"))
        if profile.get("schema") != "agent-context-transport-profile/v2":
            raise AssertionError(f"v4 install render produced an unexpected profile: {profile}")

    # Regression: fast + lightweight (maintenance/governance/documentation)
    # dead-ended at node 7 because the lightweight route filter dropped
    # targeted-acceptance, the template fast node 7 is accepted by.  The fast
    # lightweight route must keep the full fast acceptance chain and render
    # must accept targeted-acceptance for it.
    with tempfile.TemporaryDirectory(prefix="templatectl-fast-lightweight-") as raw:
        root = Path(raw)
        mode_fixture(root, "fast", "maintenance")
        routed = invoke(root, "route")
        if routed.returncode:
            raise SystemExit(routed.stdout)
        task = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        expected_fast = [
            "requirement-contract",
            "fast-projection",
            "node-implementation",
            "targeted-acceptance",
            "retrospective",
        ]
        if task["selected_templates"] != expected_fast:
            raise SystemExit(f"fast lightweight route cannot pass node 7: {task['selected_templates']}")
        if task.get("next_action") != "render routed artifacts and complete projected nodes 2-6":
            raise SystemExit("fast route left a stale pre-route next_action")
        if task.get("template_route", {}).get("projection") != "lightweight":
            raise SystemExit("fast maintenance task must keep the lightweight projection")
        require_failure(
            root, "fast-lightweight-node-acceptance-not-selected", "render", "--id", "node-acceptance",
            "--output", ".agent/state/artifacts/07-acceptance.json",
            "--var", "mode=fast", "--var", "status=verified", "--var", "human_decision=not_required",
            "--var", "node_bindings=[]", "--var", "acceptance_checks=[]",
            "--var", "mode_appropriate_reviewers=[]", "--var", "release_review_chain=null",
            "--var", "release_scenario_receipt_sha256=null", "--var", "release_scenarios=null",
            "--var", "release_live_gate_receipt=null", "--var", "release_platform_assurance=null",
            "--var", "release_platform_observation_set=null",
            "--var", "release_platform_observation_set_sha256=", "--var", "release_supervision_debt=null",
            "--var", "release_supervision_debt_sha256=", "--var", "recommendation=complete",
        )
        rendered_projection = invoke(
            root, "render", "--id", "fast-projection",
            "--output", ".agent/state/artifacts/01-fast-projection.json",
            "--var", f"requirement_contract_sha256={task['requirement_contract_sha256']}",
            "--var", "scope_summary=fixture", "--var", "change_receipts=[]",
            "--var", "check_receipts=[]", "--var", "cleanup_receipt={}", "--var", "exclusions=[]",
        )
        if rendered_projection.returncode:
            raise SystemExit(f"fast lightweight projection template refused by render:\n{rendered_projection.stdout}")
        rendered = invoke(
            root, "render", "--id", "targeted-acceptance",
            "--output", ".agent/state/artifacts/07-acceptance.json",
            "--var", "mode=fast", "--var", "node_bindings=[]", "--var", "acceptance_checks=[]",
        )
        if rendered.returncode:
            raise SystemExit(f"fast lightweight node 7 template refused by render:\n{rendered.stdout}")
        validated = invoke(root, "validate")
        if validated.returncode:
            raise SystemExit(f"fast lightweight route failed validation:\n{validated.stdout}")

    # Fast product tasks keep the same acceptance chain (no lightweight filter).
    with tempfile.TemporaryDirectory(prefix="templatectl-fast-product-") as raw:
        root = Path(raw)
        mode_fixture(root, "fast", "feature")
        routed = invoke(root, "route")
        if routed.returncode:
            raise SystemExit(routed.stdout)
        task = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        if task["selected_templates"] != [
            "requirement-contract",
            "fast-projection",
            "node-implementation",
            "targeted-acceptance",
            "retrospective",
        ]:
            raise SystemExit(f"fast product route regressed: {task['selected_templates']}")

    # Standard lightweight keeps its existing working route untouched.
    with tempfile.TemporaryDirectory(prefix="templatectl-standard-lightweight-") as raw:
        root = Path(raw)
        mode_fixture(root, "standard", "documentation")
        routed = invoke(root, "route")
        if routed.returncode:
            raise SystemExit(routed.stdout)
        task = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        if task["selected_templates"] != [
            "requirement-contract",
            "node-implementation",
            "node-acceptance",
            "retrospective",
        ]:
            raise SystemExit(f"standard lightweight route regressed: {task['selected_templates']}")
        if task.get("next_action") != "render routed artifacts and complete projected nodes 2-6":
            raise SystemExit("standard lightweight route left a stale reroute next_action")

    # Existing domain capability IDs are project choices, not compatibility
    # built-ins. Each must fail closed without a confirmed blueprint.
    domain_capabilities = ("frontend", "backend", "ios", "docker")
    with tempfile.TemporaryDirectory(prefix="templatectl-domain-no-blueprint-") as raw:
        root = Path(raw)
        mode_fixture(root, "standard", "feature")
        for capability_id in domain_capabilities:
            require_failure(
                root, f"domain-capability-without-blueprint-{capability_id}",
                "route", "--capability", capability_id,
            )

    # A confirmed blueprint alone is insufficient: the active Skill bytes must
    # still match the verified lock for every pre-existing domain capability.
    for capability_id in domain_capabilities:
        with tempfile.TemporaryDirectory(prefix=f"templatectl-domain-unverified-{capability_id}-") as raw:
            root = Path(raw)
            adaptive_route_fixture(root, capability_id)
            active_skill = root / ".agent/project/skills/fixture-project-release/SKILL.md"
            active_skill.unlink()
            require_failure(
                root, f"domain-capability-with-unverified-skill-{capability_id}",
                "route", "--capability", capability_id,
            )

    # A confirmed blueprint may introduce any stable project capability ID. Its
    # release route is authorized by the blueprint acceptance contract and a
    # verified dynamic Skill, not by the legacy acceptance-adapter registry.
    with tempfile.TemporaryDirectory(prefix="templatectl-adaptive-route-") as raw:
        root = Path(raw)
        capability_id = "project-defined-release-47"
        blueprint_sha256, lock_sha256, blueprint_path, lock = adaptive_route_fixture(root, capability_id)
        routed = invoke(root, "route", "--capability", capability_id)
        if routed.returncode:
            raise SystemExit(f"confirmed arbitrary capability did not route:\n{routed.stdout}")
        task_path = root / ".agent/state/TASK.json"
        task = json.loads(task_path.read_text(encoding="utf-8"))
        adaptive = task.get("template_route", {}).get("adaptive_project")
        if (
            task.get("template_route", {}).get("schema") != "agent-template-route/v3"
            or adaptive != {
                "blueprint_sha256": blueprint_sha256,
                "skills_lock_sha256": lock_sha256,
                "project_capabilities": [capability_id],
            }
            or any(item.startswith("acceptance-") for item in task.get("selected_capabilities", []))
        ):
            raise AssertionError(f"adaptive release route lost blueprint/Skill binding: {task.get('template_route')}")

        adapter_probe = subprocess.run([
            sys.executable, "-c",
            "import json,sys;sys.path.insert(0,'.agent/scripts');import workflowctl;"
            "task=json.load(open('.agent/state/TASK.json'));print(workflowctl.adapter(task)[0])",
        ], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if adapter_probe.returncode or adapter_probe.stdout.strip() != "adaptive-blueprint":
            raise AssertionError(f"release gate did not select generic blueprint acceptance: {adapter_probe.stdout}")

        confirmed_blueprint = json.loads(blueprint_path.read_text(encoding="utf-8"))
        reopened = {**confirmed_blueprint, "status": "draft", "confirmation": None}
        secure_json(blueprint_path, reopened)
        require_failure(
            root, "reopened-blueprint", "route", "--capability", capability_id,
        )
        secure_json(blueprint_path, confirmed_blueprint)

        lock_path = root / ".agent/project/skills.lock.json"
        drifted_lock = json.loads(json.dumps(lock))
        drifted_lock["skills"][0]["score"] = 99.0
        secure_json(lock_path, drifted_lock)
        require_failure(
            root, "dynamic-skill-lock-drift", "route", "--capability", capability_id,
        )
        secure_json(lock_path, lock)

    print("TEMPLATECTL SELF-TEST PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
