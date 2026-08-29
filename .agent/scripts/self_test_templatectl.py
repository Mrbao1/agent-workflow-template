#!/usr/bin/env python3
"""Adversarial fixtures for deterministic template routing and rendering."""

from pathlib import Path
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types


SOURCE_AGENT = Path(__file__).resolve().parents[1]
BASE_PYTHONPATH = os.environ.get("PYTHONPATH", "")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def pxpipe_policy(enabled: bool = False) -> dict:
    return {
        "enabled": enabled,
        "activation": "explicit-opt-in",
        "plugin_name": "pxpipe-context",
        "plugin_version": "0.1.0+codex.20260721210500",
        "models": ["vendor-x/reasoning.model+2026"],
        "primary_mode": "provider-proxy",
        "provider_activation": "task-explicit-opt-in",
        "provider_configuration": "user-model-provider-plus-launch-agent",
        "provider_content_scope": "whole-request-eligible-content",
        "mcp_role": "optional-cold-reference",
        "selection": "analyze-then-render",
        "content_scope": "new-cold-reference-only",
        "session_boundary": "plugin-load-requires-new-chat",
        "fallback": "native",
    }


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
    shutil.copy2(SOURCE_AGENT / "scripts/schema_validation.py", root / ".agent/scripts/schema_validation.py")
    shutil.copy2(SOURCE_AGENT / "scripts/skillctl.py", root / ".agent/scripts/skillctl.py")
    shutil.copy2(SOURCE_AGENT / "scripts/contextctl.py", root / ".agent/scripts/contextctl.py")
    shutil.copy2(SOURCE_AGENT / "scripts/contexttx.py", root / ".agent/scripts/contexttx.py")
    shutil.copy2(SOURCE_AGENT / "scripts/agentctl.py", root / ".agent/scripts/agentctl.py")
    shutil.copy2(SOURCE_AGENT / "scripts/humandecision.py", root / ".agent/scripts/humandecision.py")
    shutil.copy2(SOURCE_AGENT / "scripts/process_observation.py", root / ".agent/scripts/process_observation.py")
    shutil.copy2(SOURCE_AGENT / "scripts/testrun.py", root / ".agent/scripts/testrun.py")
    shutil.copy2(SOURCE_AGENT / "scripts/workflowctl.py", root / ".agent/scripts/workflowctl.py")
    shutil.copytree(SOURCE_AGENT / "scripts/workflowlib", root / ".agent/scripts/workflowlib", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "assets/schemas", root / ".agent/assets/schemas", dirs_exist_ok=True)
    shutil.copy2(SOURCE_AGENT / "INDEX.md", root / ".agent/INDEX.md")
    shutil.copytree(SOURCE_AGENT / "workflows", root / ".agent/workflows", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "policies", root / ".agent/policies", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "skills/run-ai-coding-pipeline", root / ".agent/skills/run-ai-coding-pipeline", dirs_exist_ok=True)
    site_dir = root / "test-site"
    site_dir.mkdir(exist_ok=True)
    (site_dir / "sitecustomize.py").write_text(
        "import base64,datetime as dt,hashlib,json,sys\nfrom pathlib import Path\n"
        "sys.path.insert(0,str(Path.cwd()/'.agent/scripts'))\n"
        "import humandecision\n"
        "def _canon(v): return json.dumps(v,sort_keys=True,separators=(',',':')).encode()\n"
        "def _fixture_verify(root,config,task,*,gate,artifact_sha256,source,receipt,require_fresh=True):\n"
        " p=(Path(root)/receipt).resolve(); relative=str(p.relative_to(Path(root).resolve()))\n"
        " data=p.read_bytes(); expected={'gate':gate,'artifact_sha256':artifact_sha256,'source':source}\n"
        " if json.loads(data)!=expected: raise SystemExit('test provider receipt binding mismatch')\n"
        " return {'path':relative,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'gate':gate,'artifact_sha256':artifact_sha256,'source':source}\n"
        "def _fixture_reverify(root,config,task,*,gate,artifact_sha256,source,record):\n"
        " try: return _fixture_verify(root,config,task,gate=gate,artifact_sha256=artifact_sha256,source=source,receipt=record.get('path'))==record\n"
        " except Exception: return False\n"
        "def _fixture_prepare(root,config,task,*,gate,artifact_sha256,source,receipt,require_fresh=True):\n"
        " p=(Path(root)/receipt).resolve(); rel=str(p.relative_to(Path(root).resolve())); raw=p.read_bytes(); digest=hashlib.sha256(raw).hexdigest(); decision='fixture-'+digest[:24]\n"
        " binding={'project_identity_sha256':'1'*64,'task_generation_sha256':'2'*64,'task_generation_id':str(task.get('task_generation_id') or 'fixture-generation'),'gate':gate,'artifact_sha256':artifact_sha256,'decision_id':decision}; bsha=hashlib.sha256(_canon(binding)).hexdigest()\n"
        " record={'schema':'agent-human-decision-receipt/v1','path':rel,'sha256':digest,'bytes':len(raw),'decision_id':decision,'authority':'provider-signed-user-message','adapter_path':'/fixture/provider-adapter','adapter_sha256':'3'*64}\n"
        " unsigned={'schema':'agent-human-decision-consumption-request/v1','path':rel,'raw_base64':base64.b64encode(raw).decode(),'sha256':digest,'bytes':len(raw),'decision_id':decision,'authority':'provider-signed-user-message','adapter_path':'/fixture/provider-adapter','adapter_sha256':'3'*64,'binding':binding,'binding_sha256':bsha,'record':record}\n"
        " return {**unsigned,'request_sha256':hashlib.sha256(_canon(unsigned)).hexdigest()}\n"
        "def _fixture_result(prepared,via):\n"
        " binding=prepared['binding']; bsha=prepared['binding_sha256']; sequence=1; consumption={'binding_sha256':bsha,**binding,'sequence':sequence}; record={**prepared['record'],'provider_consumption':consumption}; authorization={'kind':'provider-human-decision','status':'consumed','sequence':sequence,'binding_sha256':bsha,'receipt_sha256':prepared['sha256'],'confirmed_via':via,'recorded_at':dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()}; return {'status':'consumed','record':record,'authorization':authorization}\n"
        "def _fixture_consume(root,config,task,*,gate,artifact_sha256,source,prepared): return _fixture_result(prepared,'consume-human-decision')\n"
        "def _fixture_status(root,config,task,*,gate,artifact_sha256,source,prepared): return _fixture_result(prepared,'status-human-decision')\n"
        "humandecision.verify=_fixture_verify\nhumandecision.reverify=_fixture_reverify\nhumandecision.prepare_decision_request=_fixture_prepare\nhumandecision.consume_prepared_decision=_fixture_consume\nhumandecision.status_prepared_decision=_fixture_status\n",
        encoding="utf-8",
    )
    os.environ["PYTHONPATH"] = str(site_dir) + (os.pathsep + BASE_PYTHONPATH if BASE_PYTHONPATH else "")
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
        "context_transport": {"default": "native"},
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
    for script in ("templatectl.py", "adaptive_common.py", "schema_validation.py", "skillctl.py", "blueprintctl.py", "blueprintacceptance.py", "contextctl.py", "contexttx.py", "agentctl.py", "humandecision.py", "process_observation.py", "testrun.py", "workflowctl.py"):
        shutil.copy2(SOURCE_AGENT / "scripts" / script, root / ".agent/scripts" / script)
    shutil.copytree(SOURCE_AGENT / "scripts/workflowlib", root / ".agent/scripts/workflowlib", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "assets/schemas", root / ".agent/assets/schemas", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "templates", root / ".agent/templates", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "assets/templates", root / ".agent/assets/templates", dirs_exist_ok=True)
    shutil.copy2(SOURCE_AGENT / "INDEX.md", root / ".agent/INDEX.md")
    shutil.copytree(SOURCE_AGENT / "workflows", root / ".agent/workflows", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "policies", root / ".agent/policies", dirs_exist_ok=True)
    shutil.copytree(SOURCE_AGENT / "skills/run-ai-coding-pipeline", root / ".agent/skills/run-ai-coding-pipeline", dirs_exist_ok=True)
    site_dir = root / "test-site"
    site_dir.mkdir(exist_ok=True)
    (site_dir / "sitecustomize.py").write_text(
        "import base64,datetime as dt,hashlib,json,sys\nfrom pathlib import Path\n"
        "sys.path.insert(0,str(Path.cwd()/'.agent/scripts'))\n"
        "import humandecision\n"
        "def _canon(v): return json.dumps(v,sort_keys=True,separators=(',',':')).encode()\n"
        "def _fixture_verify(root,config,task,*,gate,artifact_sha256,source,receipt,require_fresh=True):\n"
        " p=(Path(root)/receipt).resolve(); relative=str(p.relative_to(Path(root).resolve()))\n"
        " data=p.read_bytes(); expected={'gate':gate,'artifact_sha256':artifact_sha256,'source':source}\n"
        " if json.loads(data)!=expected: raise SystemExit('test provider receipt binding mismatch')\n"
        " return {'path':relative,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'gate':gate,'artifact_sha256':artifact_sha256,'source':source}\n"
        "def _fixture_reverify(root,config,task,*,gate,artifact_sha256,source,record):\n"
        " try: return _fixture_verify(root,config,task,gate=gate,artifact_sha256=artifact_sha256,source=source,receipt=record.get('path'))==record\n"
        " except Exception: return False\n"
        "def _fixture_prepare(root,config,task,*,gate,artifact_sha256,source,receipt,require_fresh=True):\n"
        " p=(Path(root)/receipt).resolve(); rel=str(p.relative_to(Path(root).resolve())); raw=p.read_bytes(); digest=hashlib.sha256(raw).hexdigest(); decision='fixture-'+digest[:24]\n"
        " binding={'project_identity_sha256':'1'*64,'task_generation_sha256':'2'*64,'task_generation_id':str(task.get('task_generation_id') or 'fixture-generation'),'gate':gate,'artifact_sha256':artifact_sha256,'decision_id':decision}; bsha=hashlib.sha256(_canon(binding)).hexdigest()\n"
        " record={'schema':'agent-human-decision-receipt/v1','path':rel,'sha256':digest,'bytes':len(raw),'decision_id':decision,'authority':'provider-signed-user-message','adapter_path':'/fixture/provider-adapter','adapter_sha256':'3'*64}\n"
        " unsigned={'schema':'agent-human-decision-consumption-request/v1','path':rel,'raw_base64':base64.b64encode(raw).decode(),'sha256':digest,'bytes':len(raw),'decision_id':decision,'authority':'provider-signed-user-message','adapter_path':'/fixture/provider-adapter','adapter_sha256':'3'*64,'binding':binding,'binding_sha256':bsha,'record':record}\n"
        " return {**unsigned,'request_sha256':hashlib.sha256(_canon(unsigned)).hexdigest()}\n"
        "def _fixture_result(prepared,via):\n"
        " binding=prepared['binding']; bsha=prepared['binding_sha256']; sequence=1; consumption={'binding_sha256':bsha,**binding,'sequence':sequence}; record={**prepared['record'],'provider_consumption':consumption}; authorization={'kind':'provider-human-decision','status':'consumed','sequence':sequence,'binding_sha256':bsha,'receipt_sha256':prepared['sha256'],'confirmed_via':via,'recorded_at':dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()}; return {'status':'consumed','record':record,'authorization':authorization}\n"
        "def _fixture_consume(root,config,task,*,gate,artifact_sha256,source,prepared): return _fixture_result(prepared,'consume-human-decision')\n"
        "def _fixture_status(root,config,task,*,gate,artifact_sha256,source,prepared): return _fixture_result(prepared,'status-human-decision')\n"
        "humandecision.verify=_fixture_verify\nhumandecision.reverify=_fixture_reverify\nhumandecision.prepare_decision_request=_fixture_prepare\nhumandecision.consume_prepared_decision=_fixture_consume\nhumandecision.status_prepared_decision=_fixture_status\n",
        encoding="utf-8",
    )
    os.environ["PYTHONPATH"] = str(site_dir) + (os.pathsep + BASE_PYTHONPATH if BASE_PYTHONPATH else "")
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
        "context_transport": {"default": "native"},
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


def provider_receipt(root: Path, name: str, gate: str, artifact_sha256: str, source: str) -> dict[str, object]:
    path = root / "test-provider-receipts" / name
    write_json(path, {
        "gate": gate, "artifact_sha256": artifact_sha256, "source": source,
    })
    path.chmod(0o600)
    data = path.read_bytes()
    return {
        "path": str(path.relative_to(root)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "gate": gate,
        "artifact_sha256": artifact_sha256,
        "source": source,
    }


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()


def bind_legacy_migrated_route(root: Path, capabilities: list[str], templates: list[str]) -> None:
    task_path=root/".agent/state/TASK.json"
    task=json.loads(task_path.read_text(encoding="utf-8"))
    base={
        "schema":"agent-template-route/v3","task_type":task["task_type"],
        "projection":"lightweight-release","mode":task["mode"],
        "capabilities":capabilities,"templates":templates,
        "requirement_contract_sha256":task["requirement_contract_sha256"],
        "manifest_sha256":hashlib.sha256((root/".agent/templates/manifest.json").read_bytes()).hexdigest(),
        "adaptive_project":{"blueprint_sha256":None,"skills_lock_sha256":None,"project_capabilities":[]},
    }
    task["template_route"]={**base,"sha256":canonical_sha256(base)}
    task["selected_capabilities"]=capabilities
    task["selected_templates"]=templates
    secure_json(task_path,task)


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
    if capability_id.startswith("acceptance-"):
        config.setdefault("acceptance_adapters",{})[capability_id]={"implemented":True}
    config["agent_control"] = {"human_decision_observer": {
        "source": "orchestrator-user-message",
        "automatic_gate_trust": False,
        "human_verification_required": True,
        "allow_current_chat_local_release": False,
        "signed_adapter": None,
        "max_receipt_age_seconds": 900,
    }}
    secure_json(config_path, config)

    task_path = root / ".agent/state/TASK.json"
    task = json.loads(task_path.read_text(encoding="utf-8"))
    task["decision_policy_version"] = 1
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
        "capabilities": [{"id": capability_id, "description": "project-defined release verification"},
                         {"id":"ci-provider-github","description":"explicit built-in GitHub CI authorization"}],
        "constraints": ["Dynamic Skill bytes remain content-addressed and offline-verifiable"],
        "acceptance": [{"id": "project-release", "criterion": "The confirmed project release route is selected"}],
        "commands": [{
            "id": "project-release-check", "argv": ["python3", "--version"],
            "stage": "acceptance", "timeout_seconds": 30, "covers": ["project-release"], "environment": ["PATH"],
        }],
        "providers": [{"id":"github","runner":["self-hosted","linux","candidate"],"protected_runner":["self-hosted","linux","protected"],"candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,"container_image":None,"default_branch":"trunk"}],
    }
    blueprint_sha256 = canonical_sha256(design)
    source = "user:confirmed arbitrary project capability"
    blueprint_decision = provider_receipt(
        root, "blueprint-confirm.json", "adaptive-blueprint-confirm", blueprint_sha256, source,
    )
    blueprint = {
        "schema": "agent-project-blueprint/v1",
        "status": "confirmed",
        "design": design,
        "suggestions": [],
        "confirmation": {
            "source": source,
            "design_sha256": blueprint_sha256,
            "confirmed_at": "2026-01-01T00:00:00+00:00",
            "decision_receipt": blueprint_decision,
        },
    }
    blueprint_path = root / ".agent/project/BLUEPRINT.json"
    secure_json(blueprint_path, blueprint)

    skill_id = "fixture-project-release"
    skill_files = {
        "LICENSE.txt": (SOURCE_AGENT / "LICENSE").read_bytes(),
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
    repository={
        "host":"github.com","owner":"fixture","name":"fixture-skill","repository_id":1,
        "owner_type":"Organization","archived":False,"fork":False,"stars":1,
        "pushed_at":"2026-01-01T00:00:00+00:00",
    }
    candidate={
        "id":skill_id,"repository":repository,"commit":"a"*40,"path":"skills/fixture/SKILL.md",
        "content":skill_files["SKILL.md"].decode("utf-8"),
        "license":{"spdx":"MIT","path":"LICENSE","content":skill_files["LICENSE.txt"].decode("utf-8"),
                   "documents":[{"path":"LICENSE","kind":"license","content":skill_files["LICENSE.txt"].decode("utf-8")}]},
    }
    candidate_sha256=canonical_sha256(candidate)
    candidate_set_sha256=canonical_sha256([candidate])
    policy["offline_content_catalogs"]=[{"id":"fixture-reviewed-catalog","candidate_set_sha256":candidate_set_sha256}]
    secure_json(policy_path,policy)
    candidate_provenance={"mode":"offline-user-reviewed","source":"offline:fixture-reviewed-catalog",
        "blueprint_sha256":blueprint_sha256,"query":None,"requests":0,
        "observed_at":"2026-01-01T00:00:00+00:00","candidate_set_sha256":candidate_set_sha256}
    source_pin={
        "schema":"agent-skill-source-pin/v2","authenticity":"offline-user-reviewed-no-source-host-authenticity",
        "repository":repository,"commit":candidate["commit"],"path":candidate["path"],
        "skill":{"source_path":candidate["path"],"sha256":hashlib.sha256(skill_files["SKILL.md"]).hexdigest(),"bytes":len(skill_files["SKILL.md"])},
        "license":{"spdx":"MIT","classifier":"strict-license-set/v2",
                   "sha256":hashlib.sha256(skill_files["LICENSE.txt"]).hexdigest(),"bytes":len(skill_files["LICENSE.txt"]),
                   "documents":[{"source_path":"LICENSE","kind":"license","classifier":"strict-mit-text/v1",
                                  "sha256":hashlib.sha256(skill_files["LICENSE.txt"]).hexdigest(),"bytes":len(skill_files["LICENSE.txt"])}]},
        "relative_assets":[],"authenticated_evidence":None,
    }
    source_pin_sha256=canonical_sha256(source_pin)
    reviewed_documents=[{
        "path":name,"encoding":"utf-8","content":skill_files[name].decode("utf-8"),
        "sha256":hashlib.sha256(skill_files[name]).hexdigest(),"bytes":len(skill_files[name]),
    } for name in ("SKILL.md","LICENSE.txt")]
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
        "schema":"agent-skill-selection-action/v4","operation":"install",
        "activation_boundary":"candidate-quarantine-to-content-only-active/v1",
        "blueprint_sha256":blueprint_sha256,"policy_sha256":canonical_sha256(policy),
        "current_lock_sha256":canonical_sha256({"schema":"agent-skills-lock/v2","blueprint_sha256":blueprint_sha256,
            "policy_sha256":canonical_sha256(policy),"skills":[]}),
        "content_review":{
            "schema":"agent-skill-human-content-review/v3","candidate_sha256":candidate_sha256,
            "source_pin_sha256":source_pin_sha256,
            "skill_content_sha256":hashlib.sha256(skill_files["SKILL.md"]).hexdigest(),
            "license_content_sha256":hashlib.sha256(skill_files["LICENSE.txt"]).hexdigest(),
            "license_spdx":"MIT","reviewed_coverage":[capability_id],"relative_assets":[],
            "documents":reviewed_documents,
            "license_documents":[{"source_path":"LICENSE","kind":"license","encoding":"utf-8",
                                  "content":skill_files["LICENSE.txt"].decode("utf-8"),"sha256":hashlib.sha256(skill_files["LICENSE.txt"]).hexdigest(),
                                  "bytes":len(skill_files["LICENSE.txt"]) }],
            "review_scope":"provider authority receives exact UTF-8 SKILL.md bytes and every applicable nearest-ancestor LICENSE/COPYING/NOTICE term, their canonical LICENSE.txt aggregate, complete immutable source pin, strict MIT-only classification, reviewed coverage, and proof that no relative assets are activated",
        },
        "candidate":skill_id,"candidate_sha256":candidate_sha256,"bundle_sha256":bundle_sha256,
        "approved_capabilities":[capability_id],"recommendation_sha256":"c"*64,"score":100.0,
        "candidate_provenance":candidate_provenance,
        "source_pin":source_pin,"source_pin_sha256":source_pin_sha256,
    }
    action_sha256 = canonical_sha256(action)
    skill_source = "user:approved exact fixture Skill bytes"
    skill_decision = provider_receipt(
        root, "skill-install.json", "adaptive-skill-install", action_sha256, skill_source,
    )
    entry = {
        "id": skill_id,
        "status": "active",
        "source_pin":source_pin,
        "source": {
            "host": "github.com", "owner": "fixture", "repository": "fixture-skill",
            "repository_id": 1, "commit": "a" * 40, "path": "skills/fixture/SKILL.md",
            "provenance_mode":"offline-user-reviewed","provenance_source":"offline:fixture-reviewed-catalog",
            "authenticity":"offline-user-reviewed-no-source-host-authenticity",
        },
        "license":{"spdx":"MIT","path":"LICENSE","sha256":hashlib.sha256(skill_files["LICENSE.txt"]).hexdigest(),
                   "documents":[{"path":"LICENSE","kind":"license","sha256":hashlib.sha256(skill_files["LICENSE.txt"]).hexdigest(),
                                  "bytes":len(skill_files["LICENSE.txt"])}]},
        "candidate_sha256":candidate_sha256,
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
            "receipt": skill_decision,
        },
    }
    lock = {
        "schema": "agent-skills-lock/v2",
        "blueprint_sha256": blueprint_sha256,
        "policy_sha256": canonical_sha256(policy),
        "skills": [entry],
        "lock_sha256": None,
    }
    lock["lock_sha256"] = canonical_sha256({key: value for key, value in lock.items() if key != "lock_sha256"})
    # Exercise the production prepare -> consume -> publish journal path. A lock
    # file plus active bytes alone is deliberately not routing authority.
    shutil.rmtree(root/".agent/project/skills"/skill_id)
    plan_path=root/"test-skill-mutation-plan.json"
    secure_json(plan_path,{"lock":lock,"skill_id":skill_id,"bundle_sha256":bundle_sha256,"files":file_records,
                           "action_sha256":action_sha256,"gate":"adaptive-skill-install","source":skill_source,
                           "receipt":skill_decision["path"]})
    journal_probe=subprocess.run([sys.executable,"-c",(
        "import json,sys;from pathlib import Path;sys.path.insert(0,'.agent/scripts');import skillctl;"
        "root=Path('.').resolve();plan=json.loads(Path('test-skill-mutation-plan.json').read_text());"
        "blueprint=skillctl.load_blueprint(root,require_confirmed=True);policy=skillctl.load_policy(root);"
        "previous=skillctl.empty_lock(blueprint,policy);lifecycle=skillctl.load_lifecycle(root);"
        "request=skillctl.prepare_provider_human_decision(root,gate=plan['gate'],artifact_sha256=plan['action_sha256'],source=plan['source'],receipt=plan['receipt']);"
        "post=plan['lock'];post['skills'][0]['decision']['receipt']=skillctl.decision_placeholder(request);post=skillctl.finalize_lock(post);"
        "pre_state=skillctl.mutation_state(root,previous,lifecycle,[plan['skill_id']],lock_exists=False,lifecycle_exists=False);"
        "post_state=skillctl.intended_post_state(root,previous,post,lifecycle,[plan['skill_id']],[{'bundle_sha256':plan['bundle_sha256'],'files':plan['files'],'preexisting':True}],post_lifecycle_exists=False);"
        "journal=skillctl.prepare_mutation_journal(root,operation='install',action_sha256=plan['action_sha256'],gate=plan['gate'],source=plan['source'],approval={'kind':'provider-human-decision','request':request},pre_state=pre_state,post_state=post_state);"
        "journal=skillctl.authorize_prepared_mutation(root,journal);skillctl.publish_intended_state(root,journal)"
    )],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    plan_path.unlink()
    if journal_probe.returncode: raise SystemExit(f"adaptive route Skill journal fixture failed:\n{journal_probe.stdout}")
    lock=json.loads((root/".agent/project/skills.lock.json").read_text(encoding="utf-8"))
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


def confirmed_choice_fixture(root: Path, capability_id: str, providers: list[dict[str, object]], *, reset_mode: bool = True, extra_capabilities=None) -> str:
    if reset_mode: mode_fixture(root,"release","feature",sync_context=False)
    config_path=root/".agent/config.json"
    config=json.loads(config_path.read_text(encoding="utf-8"))
    config["acceptance_adapters"][capability_id]={"implemented":True}
    config["agent_control"]={"human_decision_observer":{
        "source":"orchestrator-user-message","automatic_gate_trust":False,
        "human_verification_required":True,"allow_current_chat_local_release":False,
        "signed_adapter":None,"max_receipt_age_seconds":900,
    }}
    secure_json(config_path,config)
    policy_path=root/".agent/assets/policies/skill-policy.json"
    secure_directory(policy_path.parent)
    shutil.copy2(SOURCE_AGENT/"assets/policies/skill-policy.json",policy_path)
    policy_path.chmod(0o600)
    design={
        "goals":["Route only confirmed built-in delivery choices"],
        "architecture":["The confirmed Blueprint is authoritative for adapter and CI provider selection"],
        "technology_choices":[],
        "capabilities":[{"id":capability_id,"description":"confirmed built-in acceptance adapter"}]+[
            {"id":item,"description":"explicit confirmed optional built-in capability"} for item in (extra_capabilities or [])
        ]+[
            {"id":f"ci-provider-{provider['id']}","description":"explicit confirmed CI provider capability"}
            for provider in providers if provider.get("id") in {"github","gitlab"}
        ],
        "constraints":["Fresh compatibility routes fail closed without exact Blueprint choices"],
        "acceptance":[{"id":"confirmed-route","criterion":"The selected route exactly matches confirmed choices"}],
        "commands":[{"id":"confirmed-route-check","argv":["python3","--version"],"stage":"acceptance",
                     "timeout_seconds":30,"covers":["confirmed-route"],"environment":["PATH"]}],
        "providers":providers,
    }
    digest=canonical_sha256(design)
    source="user:confirmed built-in route choices"
    decision=provider_receipt(root,"builtin-blueprint.json","adaptive-blueprint-confirm",digest,source)
    secure_json(root/".agent/project/BLUEPRINT.json",{
        "schema":"agent-project-blueprint/v1","status":"confirmed","design":design,"suggestions":[],
        "confirmation":{"source":source,"design_sha256":digest,"confirmed_at":"2026-01-01T00:00:00+00:00","decision_receipt":decision},
    })
    context=subprocess.run([
        sys.executable,".agent/scripts/contextctl.py","sync","--reason","fixture",
        "--summary","confirmed built-in route fixture","--source-tokens","1800",
    ],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    if context.returncode: raise SystemExit(context.stdout)
    return digest


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

        require_failure(root,"fresh-adapter-requires-blueprint","route","--capability","acceptance-api")
        require_failure(root,"fresh-github-route-requires-blueprint","route","--capability","ci-provider-github","--capability","acceptance-workflow")
        shutil.rmtree(root)
        root.mkdir()
        fixture(root,clarified=True)
        legacy_capabilities=["acceptance-workflow","ci-provider-github","core","delivery","multi-agent"]
        legacy_templates=["requirement-contract","task-plan","delivery-plan","ci-contract","review-policy","acceptance-workflow"]
        bind_legacy_migrated_route(root,legacy_capabilities,legacy_templates)
        context=subprocess.run([
            sys.executable,".agent/scripts/contextctl.py","sync","--reason","fixture",
            "--summary","explicit legacy migrated route binding","--source-tokens","1800",
        ],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        if context.returncode: raise SystemExit(context.stdout)
        require_failure(root,"legacy-null-route-requires-current-blueprint","route","--capability","ci-provider-github","--capability","acceptance-workflow")
        shutil.rmtree(root); root.mkdir(); fixture(root,clarified=True)
        blueprint_digest=confirmed_choice_fixture(root,"acceptance-workflow",[{"id":"github","runner":"ubuntu-latest","protected_runner":"ubuntu-latest","candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,"container_image":None,"default_branch":"main"}],reset_mode=False)
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
            "requirement-contract","task-plan","delivery-plan","ci-contract","review-policy","acceptance-workflow",
        ]:
            raise SystemExit(f"unexpected deterministic route: {task['selected_templates']}")
        route_receipt = task.get("template_route", {})
        if (
            route_receipt.get("schema") != "agent-template-route/v3"
            or route_receipt.get("adaptive_project") != {"blueprint_sha256": blueprint_digest, "skills_lock_sha256": None, "project_capabilities": []}
            or route_receipt.get("task_type") != task.get("task_type")
            or route_receipt.get("projection") != task.get("projection", route_receipt.get("projection"))
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

    # Fresh/live configuration is native-only. Optional extension policy is
    # absent until an explicit task opt-in and must fail closed when partial.
    with tempfile.TemporaryDirectory(prefix="templatectl-native-transport-") as raw:
        root = Path(raw)
        fixture(root, clarified=True)
        config_path = root / ".agent/config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if config.get("context_transport") != {"default": "native"}:
            raise AssertionError("fresh template fixture reintroduced an optional transport")
        confirmed_choice_fixture(root,"acceptance-workflow",[],reset_mode=False)
        native = invoke(root, "route", "--capability", "acceptance-workflow")
        if native.returncode:
            raise SystemExit(f"native-only transport route failed:\n{native.stdout}")
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["context_transport"]["pxpipe"] = {"enabled": True}
        write_json(config_path, config)
        require_failure(root, "partial-pxpipe-opt-in", "route", "--capability", "acceptance-workflow")
        config["context_transport"] = {"default": "native"}
        write_json(config_path, config)
        bind_legacy_migrated_route(root, ["acceptance-workflow", "context-transport-pxpipe", "core", "multi-agent"], ["requirement-contract"])
        require_failure(root, "absent-pxpipe-policy-selected", "route", "--capability", "context-transport-pxpipe", "--capability", "acceptance-workflow")

        config["context_transport"]["pxpipe"] = pxpipe_policy(True)
        write_json(config_path, config)
        write_json(root / ".agent/.workflow-manifest.json", {"schema": "agent-workflow-install/v3", "repo_plugin_files": {}})
        bind_legacy_migrated_route(root, ["acceptance-workflow", "context-transport-pxpipe", "core", "multi-agent"], ["requirement-contract"])
        require_failure(root, "unverified-legacy-pxpipe-installation", "route", "--capability", "context-transport-pxpipe", "--capability", "acceptance-workflow")

    with tempfile.TemporaryDirectory(prefix="templatectl-pxpipe-") as raw:
        root = Path(raw)
        fixture(root, clarified=True)
        agents_path = root / "AGENTS.md"
        claude_path = root / "CLAUDE.md"
        agents_path.write_text("# Fixture bootstrap\n", encoding="utf-8")
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
        # Project installations retain only content attestations. The actual
        # Skill + MCP bundle is installed globally and must not be copied here.
        shutil.rmtree(plugin_root)
        workflow_manifest_path = root / ".agent/.workflow-manifest.json"
        write_json(workflow_manifest_path, {
            "schema": "agent-workflow-install/v5",
            "version": "fixture",
            "migration_version": 1,
            "source_tree_sha256": "f" * 64,
            "agent_files": {},
            "pxpipe": {
                "name": "pxpipe-context", "provenance_status": "verified",
                "marketplace_entry_sha256": "9" * 64, "files": plugin_files,
            },
            "agents_bootstrap": {
                "path": "AGENTS.md", "sha256": hashlib.sha256(agents_path.read_bytes()).hexdigest(),
            },
            "claude_bootstrap": {
                "path": "CLAUDE.md", "sha256": hashlib.sha256(claude_path.read_bytes()).hexdigest(),
            },
        })
        workflow_manifest_sha256 = hashlib.sha256(workflow_manifest_path.read_bytes()).hexdigest()
        workflow_plugin_files_sha256 = hashlib.sha256(json.dumps(
            plugin_files, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        trusted_root_sha256 = hashlib.sha256(str(root.resolve()).encode()).hexdigest()
        bind_legacy_migrated_route(
            root,["acceptance-workflow","context-transport-pxpipe","core","multi-agent"],["requirement-contract"],
        )
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
        config_path = root / ".agent/config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["context_transport"]["pxpipe"] = pxpipe_policy(False)
        write_json(config_path, config)
        require_failure(
            root, "available-plugin-is-not-enabled", "route",
            "--capability", "context-transport-pxpipe",
            "--capability", "acceptance-workflow",
        )
        config_path = root / ".agent/config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["context_transport"]["pxpipe"] = pxpipe_policy(True)
        write_json(config_path, config)
        (root/".agent/state/CONTEXT.json").unlink(missing_ok=True)
        confirmed_choice_fixture(root,"acceptance-workflow",[],reset_mode=False,extra_capabilities=["context-transport-pxpipe"])
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
            "model": "vendor-x/reasoning.model+2026",
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
                "attestation_mode": "agent-workflow-v5",
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
            "model=vendor-x/reasoning.model+2026",
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

    # Fresh installs write agent-workflow-install/v5 manifests. Render the same
    # pxpipe profile against a manifest produced by the real installer writer so
    # the current installation anchor can never drift out of the accepted render path.
    with tempfile.TemporaryDirectory(prefix="templatectl-pxpipe-v5-") as raw:
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
        workflow_manifest_path=root/".agent/.workflow-manifest.json"
        write_json(root/".agent/assets/managed-executables.json",{"schema":"agent-managed-executable-inventory/v1","paths":[]})
        fixture_agent_files = installer.files(root / ".agent")
        write_json(workflow_manifest_path, installer.install_manifest(
            fixture_agent_files,
            installer.portable_file_modes(root / ".agent", fixture_agent_files),
            plugin_files,
            installer.canonical_sha256({"name": "pxpipe-context", "source": "fixture"}),
            "verified",
            hashlib.sha256(agents_path.read_bytes()).hexdigest(),
            hashlib.sha256(claude_path.read_bytes()).hexdigest(),
        ))
        workflow_manifest = json.loads(workflow_manifest_path.read_text(encoding="utf-8"))
        if workflow_manifest.get("schema") != "agent-workflow-install/v5":
            raise SystemExit("installer no longer writes v5 manifests; extend the pxpipe render fixtures")
        workflow_source_tree_sha256 = workflow_manifest["source_tree_sha256"]
        workflow_manifest_sha256 = hashlib.sha256(workflow_manifest_path.read_bytes()).hexdigest()
        workflow_plugin_files_sha256 = hashlib.sha256(json.dumps(
            plugin_files, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        trusted_root_sha256 = hashlib.sha256(str(root.resolve()).encode()).hexdigest()
        bind_legacy_migrated_route(
            root,["acceptance-workflow","context-transport-pxpipe","core","multi-agent"],["requirement-contract"],
        )
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
        config["context_transport"]["pxpipe"] = pxpipe_policy(True)
        write_json(config_path, config)
        (root/".agent/state/CONTEXT.json").unlink(missing_ok=True)
        confirmed_choice_fixture(root,"acceptance-workflow",[],reset_mode=False,extra_capabilities=["context-transport-pxpipe"])
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
            "model": "vendor-x/reasoning.model+2026",
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
                "attestation_mode": "agent-workflow-v5",
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
            "model=vendor-x/reasoning.model+2026",
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
        # v5 anchors the CLAUDE.md bootstrap; drift must fail closed.
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
            raise AssertionError(f"v5 install render produced an unexpected profile: {profile}")

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
            "--var", "candidate_snapshot_receipts=[]", "--var", "check_receipts=[]", "--var", "cleanup_receipt={}", "--var", "exclusions=[]",
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

    # Fresh compatibility routes are exact Blueprint choices, while built-in
    # acceptance and CI capabilities remain outside dynamic Skill coverage.
    with tempfile.TemporaryDirectory(prefix="templatectl-confirmed-builtin-") as raw:
        root=Path(raw)
        blueprint_sha256=confirmed_choice_fixture(root,"acceptance-web-docker",[{
            "id":"github","runner":"ubuntu-latest","protected_runner":"ubuntu-latest","candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,"container_image":None,"default_branch":"main",
        }])
        routed=invoke(root,"route","--capability","ci-provider-github","--capability","acceptance-web-docker")
        if routed.returncode: raise SystemExit(f"exact confirmed built-in choices did not route:\n{routed.stdout}")
        task=json.loads((root/".agent/state/TASK.json").read_text(encoding="utf-8"))
        if task.get("template_route",{}).get("adaptive_project")!={
            "blueprint_sha256":blueprint_sha256,"skills_lock_sha256":None,"project_capabilities":[],
        }:
            raise SystemExit(f"fresh built-in route did not bind the exact confirmed Blueprint authority: {task.get('template_route',{}).get('adaptive_project')!r}")

    with tempfile.TemporaryDirectory(prefix="templatectl-adapter-mismatch-") as raw:
        root=Path(raw)
        confirmed_choice_fixture(root,"acceptance-api",[])
        require_failure(root,"adapter-differs-from-blueprint","route","--capability","acceptance-web-docker")

    with tempfile.TemporaryDirectory(prefix="templatectl-provider-mismatch-") as raw:
        root=Path(raw)
        confirmed_choice_fixture(root,"acceptance-workflow",[{
            "id":"gitlab","platform":"linux","image":None,"tags":["linux","candidate"],"protected_tags":["linux","protected"],"candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,
        }])
        require_failure(root,"github-provider-absent-from-blueprint","route","--capability","ci-provider-github","--capability","acceptance-workflow")

    # Existing domain capability IDs are project choices, not compatibility
    # built-ins. Each must fail closed without a confirmed blueprint.
    domain_capabilities = ("frontend", "backend", "ios", "docker")
    with tempfile.TemporaryDirectory(prefix="templatectl-domain-no-blueprint-") as raw:
        root = Path(raw)
        mode_fixture(root, "standard", "feature")
        for capability_id in domain_capabilities:
            require_failure(
                root, f"domain-capability-without-blueprint-{capability_id}",
                "route", "--capability", capability_id, "--capability", "ci-provider-github",
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
                "route", "--capability", capability_id, "--capability", "ci-provider-github",
            )

    # A confirmed blueprint may introduce any stable project capability ID. Its
    # release route is authorized by the blueprint acceptance contract and a
    # verified dynamic Skill, not by the legacy acceptance-adapter registry.
    with tempfile.TemporaryDirectory(prefix="templatectl-adaptive-route-") as raw:
        root = Path(raw)
        capability_id = "project-defined-release-47"
        blueprint_sha256, lock_sha256, blueprint_path, lock = adaptive_route_fixture(root, capability_id)
        routed = invoke(root, "route", "--capability", capability_id, "--capability", "ci-provider-github")
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
            root,"reopened-blueprint","route","--capability",capability_id,"--capability","ci-provider-github",
        )
        secure_json(blueprint_path, confirmed_blueprint)

        lock_path = root / ".agent/project/skills.lock.json"
        drifted_lock = json.loads(json.dumps(lock))
        drifted_lock["skills"][0]["score"] = 99.0
        secure_json(lock_path, drifted_lock)
        require_failure(
            root,"dynamic-skill-lock-drift","route","--capability",capability_id,"--capability","ci-provider-github",
        )
        secure_json(lock_path, lock)

    # GitHub workflow values are rendered as typed YAML scalars. Newlines,
    # tags, anchors, comments and quotes remain command bytes instead of nodes;
    # GitHub expressions and structural authority strings are rejected.
    module_spec=importlib.util.spec_from_file_location("templatectl_yaml_security",SOURCE_AGENT/"scripts/templatectl.py")
    template_module=importlib.util.module_from_spec(module_spec)
    dependency_names=("contexttx","adaptive_common","skillctl","workflowlib","workflowlib.state","workflowlib.boundedprocess","workflowlib.boundedio")
    saved_dependencies={name:sys.modules.get(name) for name in dependency_names}
    stubs={name:types.ModuleType(name) for name in dependency_names}
    stubs["adaptive_common"].AdaptiveError=type("AdaptiveError",(Exception,),{})
    stubs["adaptive_common"].load_blueprint=lambda *args,**kwargs: None
    stubs["skillctl"].load_lock=lambda *args,**kwargs: {}
    stubs["skillctl"].load_policy=lambda *args,**kwargs: {}
    stubs["skillctl"].verify_activation=lambda *args,**kwargs: ({},None,{})
    stubs["workflowlib.state"].task_projection=lambda *args: "full"
    stubs["workflowlib"].boundedprocess=stubs["workflowlib.boundedprocess"]
    stubs["workflowlib"].boundedio=stubs["workflowlib.boundedio"]
    sys.modules.update(stubs)
    try: module_spec.loader.exec_module(template_module)
    finally:
        for name,previous in saved_dependencies.items():
            if previous is None: sys.modules.pop(name,None)
            else: sys.modules[name]=previous
    provider={"id":"github","runner":["self-hosted","linux","candidate"],"protected_runner":["self-hosted","linux","protected"],"candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,"container_image":"ghcr.io/example/tool@sha256:"+"a"*64,"default_branch":"trunk"}
    authority=template_module.github_workflow_authority(provider,"d"*64)
    governed_source=(
        'on:\n  push:\n    branches: ["{{github_default_branch}}"]\n'
        'jobs:\n  verify:\n    runs-on: {{github_candidate_runner}}\n{{github_container}}\n  publish:\n    runs-on: {{github_protected_runner}}\n'
        '    env:\n      AGENT_BLUEPRINT_SHA256: "{{blueprint_sha256}}"\n'
        '    steps:\n      - run: "python3 .agent/scripts/blueprintctl.py run-command --id {{verify_command_id}} --stage ci"\n'
    )
    safe_variables={**authority,"verify_command_id":"project-verify"}
    rendered=template_module.render_github_workflow_yaml(governed_source,safe_variables,authority).decode()
    run_line=next(line for line in rendered.splitlines() if line.lstrip().startswith("- run: "))
    if json.loads(run_line.split("run: ",1)[1])!="python3 .agent/scripts/blueprintctl.py run-command --id project-verify --stage ci":
        raise SystemExit("exact Blueprint command ID did not render as one controlled YAML run scalar")
    for payload in (
        'printf "quoted # value"',
        "!!python/object:evil",
        "&anchor", "\u0085", "verify\n- uses: attacker/action@main",
    ):
        try: template_module.render_github_workflow_yaml(governed_source,{**authority,"verify_command_id":payload},authority)
        except SystemExit: pass
        else: raise SystemExit("shell-shaped or malformed Blueprint command ID was accepted")
    artifact_source=(
        'jobs:\n  verify:\n    runs-on: {{github_candidate_runner}}\n{{github_container}}\n  publish:\n    runs-on: {{github_protected_runner}}\n'
        '    env:\n      AGENT_BLUEPRINT_SHA256: "{{blueprint_sha256}}"\n      ARTIFACT_ROOT: "{{artifact_path}}"\n'
        '    steps:\n      - run: "python3 .agent/scripts/blueprintctl.py run-command --id {{verify_command_id}} --stage ci"\n'
        '    name: {{github_default_branch}}\n'
    )
    safe_artifact="dist/release-artifacts_1.2"
    artifact_rendered=template_module.render_github_workflow_yaml(
        artifact_source,{**authority,"artifact_path":safe_artifact,"verify_command_id":"build"},authority,
    ).decode()
    artifact_line=next(line for line in artifact_rendered.splitlines() if "ARTIFACT_ROOT:" in line)
    if (artifact_rendered.count("ARTIFACT_ROOT:")!=1
            or json.loads(artifact_line.split("ARTIFACT_ROOT:",1)[1].strip())!=safe_artifact):
        raise SystemExit("artifact_path did not render once as its exact JSON-quoted YAML scalar")
    for unsafe_artifact in (
        "","/tmp/artifacts","../artifacts","dist/../artifacts","dist//artifacts",
        "dist\\artifacts","dist\njobs: injected","${{ github.workspace }}","&anchor","!!tag","x"*257,
    ):
        try:
            template_module.render_github_workflow_yaml(
                artifact_source,{**authority,"artifact_path":unsafe_artifact,"verify_command_id":"build"},authority,
            )
        except SystemExit: pass
        else: raise SystemExit(f"unsafe artifact_path was accepted: {unsafe_artifact!r}")
    for malformed_artifact_source in (
        artifact_source.replace('ARTIFACT_ROOT: "{{artifact_path}}"','ARTIFACT_ROOT: {{artifact_path}}'),
        artifact_source.replace('ARTIFACT_ROOT: "{{artifact_path}}"','ARTIFACT_ROOT: "{{artifact_path}}"\n      COPY: "{{artifact_path}}"'),
    ):
        try:
            template_module.render_github_workflow_yaml(
                malformed_artifact_source,{**authority,"artifact_path":safe_artifact,"verify_command_id":"build"},authority,
            )
        except SystemExit: pass
        else: raise SystemExit("artifact_path outside its exact single typed-scalar shape was accepted")

    for expression in ("${{ secrets.TOKEN }}","echo ${{ github.ref }}"):
        try: template_module.render_github_workflow_yaml(governed_source,{**authority,"verify_command_id":expression},authority)
        except SystemExit: pass
        else: raise SystemExit("GitHub expression was accepted through a command placeholder")
    for field,value in (
        ("default_branch","trunk\njobs: injected"),("default_branch","!!tag"),
        ("default_branch","&anchor"),("default_branch","${{ github.head_ref }}"),
        ("runner",["self-hosted","${{ fromJSON(inputs.runner) }}"]),
        ("protected_runner",["self-hosted","${{ fromJSON(inputs.runner) }}"]),
        ("container_image","image\npermissions: write"),
    ):
        invalid=dict(provider); invalid[field]=value
        try: template_module.github_workflow_authority(invalid,"d"*64)
        except SystemExit: pass
        else: raise SystemExit(f"unsafe Blueprint GitHub authority was accepted: {field}={value!r}")
    try:
        template_module.render_github_workflow_yaml(
            governed_source.replace('- run: "python3 .agent/scripts/blueprintctl.py run-command --id {{verify_command_id}} --stage ci"','- uses: {{verify_command_id}}'),
            {**authority,"verify_command_id":"safe"},authority,
        )
    except SystemExit: pass
    else: raise SystemExit("command placeholder outside exact run shape was accepted")

    print("TEMPLATECTL SELF-TEST PASSED")
    return 0


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
