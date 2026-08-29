#!/usr/bin/env python3
"""Deterministically route, render and validate provenance-bound templates."""

from pathlib import Path
import argparse
import copy
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import stat
from typing import Dict, Iterable, List, Optional, Tuple

import contexttx
from adaptive_common import AdaptiveError, load_blueprint
from skillctl import load_lock,load_policy,verify_activation
from workflowlib import boundedio,boundedprocess
from workflowlib.state import task_projection


def find_agent_dir() -> Path:
    current = Path.cwd().resolve()
    for root in (current, *current.parents):
        candidate = root / ".agent"
        if candidate.is_dir():
            return candidate
    raise SystemExit(".agent directory not found")


AGENT_DIR = find_agent_dir()
ROOT = AGENT_DIR.parent.resolve()
MANIFEST_PATH = AGENT_DIR / "templates" / "manifest.json"
CONFIG_PATH = AGENT_DIR / "config.json"
TASK_PATH = AGENT_DIR / "state" / "TASK.json"
CONTEXT_PATH = AGENT_DIR / "state" / "CONTEXT.json"
CONTRACT_PATH = AGENT_DIR / "state" / "REQUIREMENT_CONTRACT.md"
CONTEXT_TOOL = AGENT_DIR / "scripts" / "contextctl.py"
LOCK_PATH = AGENT_DIR / "state" / ".template.lock"
PLACEHOLDER = re.compile(r"{{([a-zA-Z0-9_]+)}}")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ACCEPTANCE_PREFIX = "acceptance-"
CAPABILITY_DEPENDENCIES = {
    "ci-provider-github": {"delivery"},
    "ci-provider-gitlab": {"delivery"},
    "acceptance-web-docker": {"multi-agent"},
    "acceptance-api": {"multi-agent"},
    "acceptance-cli": {"multi-agent"},
    "acceptance-ios": {"multi-agent"},
    "acceptance-workflow": {"multi-agent"},
}
CI_PROVIDER_CAPABILITIES = {"ci-provider-github": "github", "ci-provider-gitlab": "gitlab"}
CONTEXT_TRANSPORT_CAPABILITY = "context-transport-pxpipe"
STACK_NEUTRAL_CAPABILITIES = frozenset({
    "core",
    "delivery",
    "multi-agent",
    "context-transport-pxpipe",
})
BUILTIN_ACCEPTANCE_CAPABILITIES = frozenset({
    "acceptance-web-docker",
    "acceptance-api",
    "acceptance-cli",
    "acceptance-ios",
    "acceptance-workflow",
})
BLUEPRINT_BOUND_CAPABILITIES = frozenset({*CI_PROVIDER_CAPABILITIES, *BUILTIN_ACCEPTANCE_CAPABILITIES})
NODE_ACCEPTANCE_RELEASE_VARS = {
    "release_review_chain",
    "release_scenario_receipt_sha256",
    "release_scenarios",
    "release_live_gate_receipt",
    "release_platform_assurance",
    "release_platform_observation_set",
    "release_platform_observation_set_sha256",
    "release_supervision_debt",
    "release_supervision_debt_sha256",
}
NODE_ACCEPTANCE_RELEASE_FIELDS = {
    "review_chain",
    "scenario_receipt_sha256",
    "scenarios",
    "live_gate_receipt",
    "platform_assurance",
    "platform_observation_set",
    "platform_observation_set_sha256",
    "supervision_debt",
    "supervision_debt_sha256",
}


def load(path: Path) -> Dict[str, object]:
    value = json.loads(boundedio.read_text(path,label="template JSON"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON object required: {path}")
    return value


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def object_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(encoded)


def atomic_text(path: Path, text: str) -> None:
    try: boundedio.atomic_write(path,text.encode("utf-8"),mode=0o600,label="template state")
    except RuntimeError as error: raise SystemExit(str(error)) from error


def atomic_bytes(path: Path, data: bytes) -> None:
    try: boundedio.atomic_write(path,data,mode=0o600,label="template state")
    except RuntimeError as error: raise SystemExit(str(error)) from error


def save_json(path: Path, value: Dict[str, object]) -> None:
    atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def relative_real_file(path: Path, boundary: Path, label: str) -> Path:
    if path.is_symlink():
        raise SystemExit(f"{label} must not be a symlink")
    resolved = path.resolve()
    try:
        resolved.relative_to(boundary.resolve())
    except ValueError:
        raise SystemExit(f"{label} escapes its allowed boundary")
    if not resolved.is_file() or resolved.is_symlink():
        raise SystemExit(f"{label} must be a regular non-symlink file")
    return resolved


def manifest_data() -> Tuple[Dict[str, object], str]:
    raw = boundedio.read_bytes(MANIFEST_PATH,label="template manifest")
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or manifest.get("schema") != "agent-template-manifest/v2":
        raise SystemExit("invalid template manifest")
    templates = manifest.get("templates")
    if not isinstance(templates, list) or not templates:
        raise SystemExit("template manifest must contain templates")
    seen: set[str] = set()
    known_modes = {"fast", "standard", "release"}
    for position, item in enumerate(templates):
        if not isinstance(item, dict):
            raise SystemExit(f"template entry {position} must be an object")
        required_keys={"id","path","output","renderable","depends_on","nodes","modes","capabilities","required"}
        if set(item) not in (required_keys,required_keys|{"authority"}):
            raise SystemExit(f"template entry {position} has invalid fields")
        template_id = item.get("id")
        if not isinstance(template_id, str) or not template_id or template_id in seen:
            raise SystemExit(f"template ID must be unique and non-empty: {template_id}")
        seen.add(template_id)
        if not isinstance(item.get("renderable"), bool):
            raise SystemExit(f"template renderable flag is invalid: {template_id}")
        for field in ("depends_on","nodes","modes","capabilities","required",*( ["authority"] if "authority" in item else [] )):
            values=item.get(field)
            if not isinstance(values, list) or len(values) != len(set(map(str, values))):
                raise SystemExit(f"template {template_id} has invalid {field}")
        if not item["nodes"] or any(not isinstance(node, int) or node < 0 or node > 8 for node in item["nodes"]):
            raise SystemExit(f"template {template_id} has invalid nodes")
        if not item["modes"] or not set(item["modes"]).issubset(known_modes):
            raise SystemExit(f"template {template_id} has invalid modes")
        if not item["capabilities"] or any(not isinstance(value, str) or not value for value in item["capabilities"]):
            raise SystemExit(f"template {template_id} has invalid capabilities")
        if any(not isinstance(value, str) or not value for value in item["required"]):
            raise SystemExit(f"template {template_id} has invalid required variables")
        source = relative_real_file(AGENT_DIR / str(item["path"]), AGENT_DIR, f"template source {template_id}")
        authority=set(item.get("authority",[]))
        expected_authority={
            "github-ci":{"github_candidate_runner","github_protected_runner","github_container","github_default_branch","blueprint_sha256"},
            "github-test-cd":{"github_protected_runner","github_container","github_default_branch","blueprint_sha256"},
            "github-production-cd":{"github_protected_runner","github_container","github_default_branch","blueprint_sha256"},
            "gitlab-ci":{"gitlab_sys_platform","gitlab_image","gitlab_candidate_tags","blueprint_sha256"},
            "gitlab-test-cd":{"gitlab_sys_platform","gitlab_image","gitlab_protected_tags","blueprint_sha256"},
            "gitlab-production-cd":{"gitlab_sys_platform","gitlab_image","gitlab_protected_tags","blueprint_sha256"},
        }.get(template_id,set())
        if authority!=expected_authority:
            raise SystemExit(f"template {template_id} has invalid blueprint authority variables")
        source_variables=set(PLACEHOLDER.findall(boundedio.read_text(source,label="template source")))
        declared_variables=set(item["required"])|authority
        if declared_variables != source_variables:
            raise SystemExit(
                f"template {template_id} required variables do not match source placeholders: "
                f"missing={sorted(source_variables - declared_variables)} "
                f"extra={sorted(declared_variables - source_variables)}"
            )
        output = str(item["output"])
        output_path = (ROOT / output).resolve()
        artifacts = (AGENT_DIR / "state" / "artifacts").resolve()
        if item["renderable"]:
            try:
                output_path.relative_to(artifacts)
            except ValueError:
                raise SystemExit(f"template {template_id} output must stay under .agent/state/artifacts")
        elif output_path != CONTRACT_PATH.resolve():
            raise SystemExit(f"non-renderable template {template_id} must identify the governed requirement contract")
    for item in templates:
        for dependency in item["depends_on"]:
            if dependency not in seen:
                raise SystemExit(f"template {item['id']} has unknown dependency {dependency}")
    return manifest, sha256_bytes(raw)


def entries() -> List[Dict[str, object]]:
    manifest, _ = manifest_data()
    return manifest["templates"]  # type: ignore[return-value]


def entry(template_id: str) -> Dict[str, object]:
    matches = [item for item in entries() if item.get("id") == template_id]
    if len(matches) != 1:
        raise SystemExit(f"template ID must occur exactly once: {template_id}")
    return matches[0]


def require_clarified(task: Dict[str, object], allow_terminal_validation: bool = False) -> None:
    if task.get("requirements_clarified") is not True:
        raise SystemExit("requirements must be clarified and human-approved before template routing or rendering")
    terminal_validation = (
        allow_terminal_validation
        and task.get("status") == "accepted"
        and task.get("phase") == "idle"
    )
    if (
        task.get("phase") in {None, "clarification"}
        or task.get("status") in {"idle", "blocked"}
        or (task.get("status") == "accepted" and not terminal_validation)
    ):
        raise SystemExit("template operation is not allowed in the current task phase/status")
    contract_hash = str(task.get("requirement_contract_sha256", ""))
    if not CONTRACT_PATH.is_file() or not HEX64.fullmatch(contract_hash):
        raise SystemExit("approved requirement contract binding is missing")
    if sha256_bytes(boundedio.read_bytes(CONTRACT_PATH,label="requirement contract")) != contract_hash:
        raise SystemExit("approved requirement contract has drifted")


def enforce_budget(action: str) -> None:
    result = boundedprocess.run(
        [sys.executable, str(AGENT_DIR / "scripts" / "agentctl.py"), "budget-gate", "--action", action],
        cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode:
        raise SystemExit(result.stdout.strip() or f"budget gate blocked {action}")


def normalize_capabilities(raw: Iterable[str]) -> List[str]:
    supplied = [str(value) for value in raw if str(value)]
    if any(re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", item) is None for item in supplied):
        raise SystemExit("capabilities must use stable lowercase IDs")
    capabilities = {"core", *supplied}
    changed = True
    while changed:
        changed = False
        for capability, dependencies in CAPABILITY_DEPENDENCIES.items():
            if capability in capabilities and not dependencies.issubset(capabilities):
                capabilities.update(dependencies)
                changed = True
    return sorted(capabilities)


def generic_compatibility_capabilities() -> set[str]:
    """Return only stack-neutral controls; project choices are Blueprint-bound."""
    return set(STACK_NEUTRAL_CAPABILITIES)


def exact_legacy_migration_binding(task: Dict[str, object], capabilities: List[str]) -> bool:
    """Recognize only an intact migration-produced v3 null adaptive binding."""
    route=task.get("template_route")
    required={
        "schema","task_type","projection","mode","capabilities","templates",
        "requirement_contract_sha256","manifest_sha256","adaptive_project","sha256",
    }
    null_binding={"blueprint_sha256":None,"skills_lock_sha256":None,"project_capabilities":[]}
    if not isinstance(route,dict) or set(route)!=required or route.get("schema")!="agent-template-route/v3":
        return False
    if route.get("adaptive_project")!=null_binding or route.get("capabilities")!=capabilities:
        return False
    if (
        route.get("task_type")!=task.get("task_type")
        or route.get("mode")!=task.get("mode")
        or route.get("projection")!=task_projection(str(task.get("task_type")),str(task.get("mode")))
        or route.get("requirement_contract_sha256")!=task.get("requirement_contract_sha256")
        or task.get("selected_capabilities")!=capabilities
        or task.get("selected_templates")!=route.get("templates")
    ):
        return False
    return route.get("sha256")==object_sha256({key:route[key] for key in route if key!="sha256"})


def adaptive_route_binding(task: Dict[str, object], capabilities: List[str]) -> Dict[str, object]:
    selected=set(capabilities)
    project_capabilities=sorted(selected-STACK_NEUTRAL_CAPABILITIES-BLUEPRINT_BOUND_CAPABILITIES)
    static_acceptance=sorted(selected&BUILTIN_ACCEPTANCE_CAPABILITIES)
    blueprint_choices=selected&BLUEPRINT_BOUND_CAPABILITIES
    # Every non-core optional/provider/acceptance route is bound to the exact
    # current confirmed Blueprint even when it uses only built-in templates.
    needs_blueprint=bool(selected-{"core"}) or task.get("mode")=="release"
    null_binding={"blueprint_sha256":None,"skills_lock_sha256":None,"project_capabilities":[]}
    if not needs_blueprint:
        return null_binding
    try:
        blueprint=load_blueprint(ROOT,require_confirmed=True)
        configured={item["id"] for item in blueprint["design"]["capabilities"]}
        configured_adapters=configured&BUILTIN_ACCEPTANCE_CAPABILITIES
        if configured_adapters!=set(static_acceptance):
            raise SystemExit(
                "selected built-in acceptance adapters differ from the confirmed Blueprint: "
                f"selected={sorted(static_acceptance)} confirmed={sorted(configured_adapters)}"
            )
        configured_project=(configured-BUILTIN_ACCEPTANCE_CAPABILITIES
                            -set(CI_PROVIDER_CAPABILITIES)-STACK_NEUTRAL_CAPABILITIES)
        if configured_project!=set(project_capabilities):
            raise SystemExit(
                "selected project capabilities differ from the confirmed Blueprint: "
                f"selected={project_capabilities} confirmed={sorted(configured_project)}"
            )
        confirmed_ci=configured&set(CI_PROVIDER_CAPABILITIES)
        provider_ids={provider["id"] for provider in blueprint["design"]["providers"]}
        if any(CI_PROVIDER_CAPABILITIES[capability] not in provider_ids for capability in confirmed_ci):
            raise SystemExit("confirmed CI capability lacks its matching confirmed provider")
        selected_ci=selected&set(CI_PROVIDER_CAPABILITIES)
        if selected_ci!=confirmed_ci:
            raise SystemExit(
                "selected CI provider differs from the confirmed Blueprint: "
                f"selected={sorted(selected_ci)} confirmed={sorted(confirmed_ci)}"
            )
        policy=load_policy(ROOT)
        if project_capabilities:
            _verification,verified_lock,_captured=verify_activation(ROOT,blueprint,policy)
            lock=verified_lock if verified_lock is not None else load_lock(ROOT,blueprint,policy,required=True)
        else:
            # Matching built-in provider/acceptance templates are their explicit
            # authorizer; an unrelated dynamic Skill lock must not be invented.
            lock=load_lock(ROOT,blueprint,policy,required=False)
        if lock["skills"] and (lock["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"] or lock["policy_sha256"] != object_sha256(policy)):
            raise SystemExit("dynamic Skill lock does not bind the current blueprint and policy")
    except AdaptiveError as error:
        raise SystemExit(f"adaptive project route is invalid: {error.code}: {error}") from error
    if project_capabilities:
        active_coverage = {
            capability for skill in lock["skills"] if skill["status"] == "active"
            for capability in skill["matched_capabilities"]
        }
        uncovered = set(project_capabilities) - active_coverage
        if uncovered:
            raise SystemExit(f"project capabilities lack an active verified Skill: {sorted(uncovered)}")
    return {
        "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
        "skills_lock_sha256": lock["lock_sha256"] if lock["skills"] else None,
        "project_capabilities": project_capabilities,
    }


def verify_ci_provider(capabilities: List[str]) -> None:
    selected = [item for item in capabilities if item in CI_PROVIDER_CAPABILITIES]
    if len(selected) > 1:
        raise SystemExit("exactly one CI provider capability may be selected")


def verify_acceptance_capability(task: Dict[str, object], capabilities: List[str], adaptive: Dict[str, object]) -> None:
    acceptance = [
        item for item in capabilities
        if item in BUILTIN_ACCEPTANCE_CAPABILITIES
    ]
    if task.get("mode") == "release" and len(acceptance) != 1 and adaptive.get("blueprint_sha256") is None:
        raise SystemExit("release mode must select one legacy adapter or a confirmed blueprint acceptance contract")
    if len(acceptance) > 1:
        raise SystemExit("at most one legacy acceptance adapter may be selected")
    registry = load(CONFIG_PATH).get("acceptance_adapters", {})
    if not isinstance(registry, dict):
        registry = {}
    for adapter_id in acceptance:
        adapter = registry.get(adapter_id)
        if not isinstance(adapter, dict) or adapter.get("implemented") is not True:
            raise SystemExit(f"acceptance adapter is declared but not implemented: {adapter_id}")


def context_transport_policy() -> Optional[Dict[str, object]]:
    """Return an explicit extension policy; native-only configuration needs none."""
    policy = load(CONFIG_PATH).get("context_transport")
    if (not isinstance(policy, dict) or policy.get("default") != "native"
            or set(policy) not in ({"default"}, {"default", "pxpipe"})):
        raise SystemExit("context transport policy is invalid")
    if "pxpipe" not in policy:
        return None
    expected_pxpipe = {
        "enabled", "activation", "plugin_name", "plugin_version", "models",
        "primary_mode", "provider_activation", "provider_configuration",
        "provider_content_scope", "mcp_role", "selection", "content_scope",
        "session_boundary", "fallback",
    }
    pxpipe = policy["pxpipe"]
    if not isinstance(pxpipe, dict) or set(pxpipe) != expected_pxpipe:
        raise SystemExit("pxpipe context transport policy is invalid")
    if (
        not isinstance(pxpipe.get("enabled"), bool)
        or pxpipe.get("activation") != "explicit-opt-in"
        or pxpipe.get("plugin_name") != "pxpipe-context"
        or pxpipe.get("plugin_version") != "0.1.0+codex.20260721210500"
        or not isinstance(pxpipe.get("models"), list)
        or len(pxpipe.get("models", [])) > 32
        or any(not isinstance(model, str) for model in pxpipe.get("models", []))
        or len(set(pxpipe.get("models", []))) != len(pxpipe.get("models", []))
        or any(
            model.lower() in {"none", "null", "unset", "unselected", "default", "model", "model-id"}
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,127}", model) is None
            for model in pxpipe.get("models", [])
        )
        or (pxpipe.get("enabled") is True and not pxpipe.get("models"))
        or pxpipe.get("primary_mode") != "provider-proxy"
        or pxpipe.get("provider_activation") != "task-explicit-opt-in"
        or pxpipe.get("provider_configuration") != "user-model-provider-plus-launch-agent"
        or pxpipe.get("provider_content_scope") != "whole-request-eligible-content"
        or pxpipe.get("mcp_role") != "optional-cold-reference"
        or pxpipe.get("selection") != "analyze-then-render"
        or pxpipe.get("content_scope") != "new-cold-reference-only"
        or pxpipe.get("session_boundary") != "plugin-load-requires-new-chat"
        or pxpipe.get("fallback") != "native"
    ):
        raise SystemExit("pxpipe context transport policy is invalid")
    return pxpipe


def verified_pxpipe_installation() -> Tuple[Dict[str, object], bytes, Dict[str, object]]:
    """Require the explicit extension to come from a verified v5 installation."""
    path = relative_real_file(
        AGENT_DIR / ".workflow-manifest.json", AGENT_DIR, "workflow installation manifest",
    )
    raw = boundedio.read_bytes(path,label="template file")
    manifest = load(path)
    binding = manifest.get("pxpipe")
    files = binding.get("files") if isinstance(binding, dict) else None
    critical = {
        ".codex-plugin/plugin.json", "integrity.json", "mcp/server.mjs",
        "mcp/worker.mjs", "mcp/vendor/pxpipe-runtime.mjs",
    }
    if (manifest.get("schema") != "agent-workflow-install/v5"
            or not isinstance(binding, dict)
            or set(binding) != {"name", "provenance_status", "marketplace_entry_sha256", "files"}
            or binding.get("name") != "pxpipe-context"
            or binding.get("provenance_status") != "verified"
            or not HEX64.fullmatch(str(binding.get("marketplace_entry_sha256", "")))
            or not isinstance(files, dict) or not critical.issubset(files)
            or any(not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts
                   or not HEX64.fullmatch(str(digest)) for name, digest in files.items())):
        raise SystemExit("pxpipe requires an explicit provenance-verified v5 installation binding")
    return manifest, raw, files


def require_pxpipe_contract(task: Dict[str, object]) -> None:
    if not CONTRACT_PATH.is_file():
        raise SystemExit("pxpipe activation requires an approved requirement contract")
    text = boundedio.read_text(CONTRACT_PATH,label="requirement contract")
    if len(re.findall(r"^- Context transport:\s*pxpipe-plugin-explicit-opt-in\s*$", text, re.MULTILINE)) != 1:
        raise SystemExit("approved requirement contract must explicitly opt in to the pxpipe plugin")
    if not str(task.get("requirement_source", "")).startswith("user:"):
        raise SystemExit("pxpipe activation requires a user-approved requirement source")


def context_transport_task_invariant(task: Dict[str, object]) -> str:
    return object_sha256({
        key: task.get(key)
        for key in (
            "title", "mode", "task_type", "complexity", "environment",
            "branch", "requirement_contract_sha256", "selected_capabilities",
        )
    })


def validate_context_transport_vars(task: Dict[str, object], variables: Dict[str, str]) -> None:
    pxpipe = context_transport_policy()
    require_pxpipe_contract(task)
    if not isinstance(pxpipe, dict) or pxpipe.get("enabled") is not True:
        raise SystemExit("pxpipe context transport is disabled; explicit user opt-in must enable it first")
    if variables.get("model") not in pxpipe.get("models", []):
        raise SystemExit("pxpipe model is not explicitly allowlisted")
    if variables.get("plugin_name") != pxpipe.get("plugin_name"):
        raise SystemExit("pxpipe profile must bind the configured plugin name")
    if variables.get("plugin_version") != pxpipe.get("plugin_version"):
        raise SystemExit("pxpipe profile must bind the configured plugin version")
    digest_keys = (
        "plugin_manifest_sha256", "plugin_integrity_sha256", "mcp_server_sha256",
        "mcp_worker_sha256", "runtime_bundle_sha256", "workflow_manifest_sha256",
        "workflow_source_tree_sha256", "workflow_plugin_files_sha256",
        "trusted_root_sha256", "source_sha256", "analyze_receipt_sha256",
    )
    for key in digest_keys:
        if not re.fullmatch(r"[0-9a-f]{64}", variables.get(key, "")):
            raise SystemExit(f"{key} must be a full lowercase SHA-256")

    workflow_manifest, workflow_manifest_bytes, plugin_files = verified_pxpipe_installation()
    workflow_schema = workflow_manifest.get("schema")
    bootstrap = workflow_manifest.get("agents_bootstrap")
    claude_bootstrap = workflow_manifest.get("claude_bootstrap")
    bootstrap_schemas = {
        "agent-workflow-install/v3", "agent-workflow-install/v4", "agent-workflow-install/v5",
    }
    claude_bootstrap_schemas = {"agent-workflow-install/v4", "agent-workflow-install/v5"}
    if (
        workflow_schema != "agent-workflow-install/v5"
        or not isinstance(plugin_files, dict)
        or not re.fullmatch(r"[0-9a-f]{64}", str(workflow_manifest.get("source_tree_sha256", "")))
        or (
            workflow_schema in bootstrap_schemas
            and (
                not isinstance(bootstrap, dict)
                or bootstrap.get("path") != "AGENTS.md"
                or not re.fullmatch(r"[0-9a-f]{64}", str(bootstrap.get("sha256", "")))
            )
        )
        or (
            workflow_schema in claude_bootstrap_schemas
            and (
                not isinstance(claude_bootstrap, dict)
                or claude_bootstrap.get("path") != "CLAUDE.md"
                or not re.fullmatch(r"[0-9a-f]{64}", str(claude_bootstrap.get("sha256", "")))
            )
        )
    ):
        raise SystemExit("pxpipe requires a valid v2 or later workflow installation manifest with plugin hashes")
    if workflow_schema in bootstrap_schemas:
        bootstrap_path = relative_real_file(ROOT / "AGENTS.md", ROOT, "workflow AGENTS bootstrap")
        if sha256_bytes(boundedio.read_bytes(bootstrap_path,label="AGENTS bootstrap")) != bootstrap.get("sha256"):
            raise SystemExit("workflow AGENTS bootstrap differs from the installation anchor")
    if workflow_schema in claude_bootstrap_schemas:
        claude_path = relative_real_file(ROOT / "CLAUDE.md", ROOT, "workflow CLAUDE bootstrap")
        if sha256_bytes(boundedio.read_bytes(claude_path,label="Claude bootstrap")) != claude_bootstrap.get("sha256"):
            raise SystemExit("workflow CLAUDE bootstrap differs from the installation anchor")
    critical_plugin_files = {
        ".codex-plugin/plugin.json": "plugin_manifest_sha256",
        "integrity.json": "plugin_integrity_sha256",
        "mcp/server.mjs": "mcp_server_sha256",
        "mcp/worker.mjs": "mcp_worker_sha256",
        "mcp/vendor/pxpipe-runtime.mjs": "runtime_bundle_sha256",
    }
    for relative, recorded_sha256 in plugin_files.items():
        if (
            not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or not re.fullmatch(r"[0-9a-f]{64}", str(recorded_sha256))
        ):
            raise SystemExit("workflow installation manifest contains an invalid plugin binding")
    if not set(critical_plugin_files).issubset(plugin_files):
        raise SystemExit("workflow installation manifest omits a critical pxpipe plugin binding")
    for relative, variable_name in critical_plugin_files.items():
        if variables.get(variable_name) != plugin_files.get(relative):
            raise SystemExit(f"pxpipe profile does not bind the expected global plugin file: {relative}")
    actual_install_bindings = {
        "workflow_manifest_sha256": sha256_bytes(workflow_manifest_bytes),
        "workflow_source_tree_sha256": str(workflow_manifest["source_tree_sha256"]),
        "workflow_plugin_files_sha256": object_sha256(plugin_files),
        "trusted_root_sha256": sha256_bytes(str(ROOT).encode()),
    }
    for variable_name, expected in actual_install_bindings.items():
        if variables.get(variable_name) != expected:
            raise SystemExit(f"pxpipe profile does not bind current installation: {variable_name}")
    receipt_raw = Path(variables.get("analyze_receipt_path", ""))
    if receipt_raw.is_absolute() or receipt_raw.suffix != ".json":
        raise SystemExit("analyze_receipt_path must be a relative JSON path")
    receipt_boundary = (AGENT_DIR / "state" / "evidence" / "context-transport").resolve()
    receipt_path = relative_real_file(
        ROOT / receipt_raw,
        receipt_boundary,
        "pxpipe analyze receipt",
    )
    receipt = load(receipt_path)
    receipt_keys = {
        "schema", "model", "purpose", "status", "source_sha256", "file_count",
        "source_bytes", "page_count", "total_image_bytes", "token_report",
        "rejection_reasons", "provenance", "analyze_receipt_sha256",
    }
    provenance = receipt.get("provenance")
    provenance_keys = {
        "plugin_name", "plugin_version", "plugin_manifest_sha256",
        "plugin_integrity_sha256", "mcp_server_sha256", "mcp_worker_sha256",
        "pxpipe_package", "pxpipe_version", "runtime_bundle_sha256",
        "source_package_sha256", "provenance_assurance", "trusted_root_sha256",
        "trusted_root_source", "workflow_manifest_sha256",
        "workflow_source_tree_sha256", "workflow_plugin_files_sha256",
        "attestation_mode",
    }
    receipt_without_hash = {
        key: value for key, value in receipt.items() if key != "analyze_receipt_sha256"
    }
    expected_receipt_sha256 = object_sha256(receipt_without_hash)
    if (
        set(receipt) != receipt_keys
        or receipt.get("schema") != "pxpipe-context-analyze/v1"
        or receipt.get("model") != variables.get("model")
        or receipt.get("purpose") != "cold-semantic-reference"
        or receipt.get("status") != "eligible"
        or receipt.get("source_sha256") != variables.get("source_sha256")
        or receipt.get("rejection_reasons") != []
        or not isinstance(provenance, dict)
        or set(provenance) != provenance_keys
        or provenance.get("plugin_name") != variables.get("plugin_name")
        or provenance.get("plugin_version") != variables.get("plugin_version")
        or any(provenance.get(key) != variables.get(key) for key in digest_keys if key not in {"source_sha256", "analyze_receipt_sha256"})
        or provenance.get("provenance_assurance") != "content-and-install-anchored;no-host-signature"
        or provenance.get("attestation_mode") != {
            "agent-workflow-install/v3": "agent-workflow-v3",
            "agent-workflow-install/v4": "agent-workflow-v4",
            "agent-workflow-install/v5": "agent-workflow-v5",
        }.get(workflow_schema, "agent-workflow-v2")
        or provenance.get("trusted_root_source") not in {
            "mcp-roots/list", "host-env:CODEX_PROJECT_ROOT",
            "host-env:PXPIPE_CONTEXT_PROJECT_ROOT",
            "host-file:PXPIPE_CONTEXT_ALLOWED_ROOTS_FILE",
            "host-env:PXPIPE_CONTEXT_ALLOWED_ROOTS",
        }
        or receipt.get("analyze_receipt_sha256") != expected_receipt_sha256
        or variables.get("analyze_receipt_sha256") != expected_receipt_sha256
        or receipt_raw.stem != expected_receipt_sha256
    ):
        raise SystemExit("pxpipe analyze receipt is invalid, ineligible, drifted, or not content-addressed")
    if variables.get("requirement_contract_sha256") != task.get("requirement_contract_sha256"):
        raise SystemExit("pxpipe profile must bind the approved requirement contract")
    if variables.get("task_invariant_sha256") != context_transport_task_invariant(task):
        raise SystemExit("pxpipe profile must bind the current task routing invariant")
    if variables.get("approval_source") != task.get("requirement_source"):
        raise SystemExit("pxpipe approval_source must equal the approved requirement source")
    requirement_approval = (
        task.get("gate_approvals", {}).get("requirement")
        if isinstance(task.get("gate_approvals"), dict) else None
    )
    decision_receipt = requirement_approval.get("decision_receipt") if isinstance(requirement_approval, dict) else None
    if (
        task.get("decision_policy_version") != 1
        or not isinstance(decision_receipt, dict)
        or variables.get("approval_receipt_sha256") != decision_receipt.get("sha256")
        or not re.fullmatch(r"[0-9a-f]{64}", str(decision_receipt.get("sha256", "")))
    ):
        raise SystemExit("pxpipe profile requires the provider-verified requirement approval receipt")


def expected_route(task: Dict[str, object], capabilities: List[str]) -> List[str]:
    mode = task.get("mode")
    selected: List[str] = []
    selected_set: set[str] = set()
    manifest_entries = entries()
    for item in manifest_entries:
        if mode in item["modes"] and set(capabilities).intersection(item["capabilities"]):
            selected.append(str(item["id"]))
            selected_set.add(str(item["id"]))
    changed = True
    while changed:
        changed = False
        for item in manifest_entries:
            if item["id"] in selected_set:
                for dependency in item["depends_on"]:
                    if dependency not in selected_set:
                        dependency_entry = next(candidate for candidate in manifest_entries if candidate["id"] == dependency)
                        if mode not in dependency_entry["modes"]:
                            raise SystemExit(f"template dependency is unavailable in {mode}: {dependency}")
                        selected_set.add(str(dependency))
                        changed = True
    ordered = [str(item["id"]) for item in manifest_entries if item["id"] in selected_set]
    if task_projection(str(task.get("task_type")), str(mode)) == "lightweight":
        lightweight = {"requirement-contract", "node-implementation", "node-acceptance", "retrospective"}
        if mode == "fast":
            # Fast node 7 is accepted by the rendered targeted-acceptance
            # template (which depends on fast-projection), never by
            # node-acceptance, so the lightweight projection must keep the
            # full fast acceptance chain or node 7 can never pass.
            lightweight = {
                "requirement-contract", "fast-projection", "node-implementation",
                "targeted-acceptance", "retrospective",
            }
        ordered = [template_id for template_id in ordered if template_id in lightweight]
    selected_outputs: Dict[str, str] = {}
    for template_id in ordered:
        item = next(candidate for candidate in manifest_entries if candidate["id"] == template_id)
        if item.get("renderable") is not True:
            continue
        output = str(item["output"])
        if output in selected_outputs:
            raise SystemExit(
                f"selected templates collide on canonical output {output}: "
                f"{selected_outputs[output]}, {template_id}"
            )
        selected_outputs[output] = template_id
    return ordered


def route_receipt(task: Dict[str, object], capabilities: List[str], selected: List[str], manifest_sha256: str, adaptive: Dict[str, object]) -> Dict[str, object]:
    base: Dict[str, object] = {
        "schema": "agent-template-route/v3",
        "mode": task.get("mode"),
        "task_type": task.get("task_type"),
        "projection": task_projection(str(task.get("task_type")), str(task.get("mode"))),
        "capabilities": capabilities,
        "templates": selected,
        "requirement_contract_sha256": task.get("requirement_contract_sha256"),
        "manifest_sha256": manifest_sha256,
        "adaptive_project": adaptive,
    }
    return {**base, "sha256": object_sha256(base)}


def github_workflow_authority(provider: Dict[str, object], blueprint_sha256: Optional[str] = None) -> Dict[str, object]:
    """Return strictly typed, non-expression GitHub execution authority."""
    runner=provider.get("runner")
    default_branch=provider.get("default_branch")
    container_image=provider.get("container_image")
    labels=[runner] if isinstance(runner,str) else runner
    if (not isinstance(labels,list) or not labels or len(labels)>8
            or any(not isinstance(value,str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,255}",value) is None for value in labels)
            or len(labels)!=len(set(labels))):
        raise SystemExit("confirmed GitHub runner authority is invalid")
    if (not isinstance(default_branch,str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}",default_branch) is None
            or ".." in default_branch or "//" in default_branch or default_branch.endswith(("/",".lock"))
            or "@{" in default_branch or "${{" in default_branch):
        raise SystemExit("confirmed GitHub default-branch authority is invalid")
    if (container_image is not None and (
            not isinstance(container_image,str)
            or re.fullmatch(r"(?:[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?/)?(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:[0-9a-f]{64}",container_image) is None
            or "${{" in container_image)):
        raise SystemExit("confirmed GitHub container authority is invalid")
    if blueprint_sha256 is None or HEX64.fullmatch(blueprint_sha256) is None:
        raise SystemExit("confirmed Blueprint digest authority is invalid")
    protected_runner=provider.get("protected_runner")
    protected_labels=[protected_runner] if isinstance(protected_runner,str) else protected_runner
    if (not isinstance(protected_labels,list) or not protected_labels or len(protected_labels)>8
            or any(not isinstance(value,str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,255}",value) is None for value in protected_labels)
            or len(protected_labels)!=len(set(protected_labels))
            or any(provider.get(key) is not True for key in ("candidate_ephemeral","protected_ephemeral","protected_isolated"))):
        raise SystemExit("confirmed GitHub protected runner authority is invalid")
    normalized_labels={value.casefold() for value in labels}; normalized_protected={value.casefold() for value in protected_labels}
    for name,selected in (("candidate",normalized_labels),("protected",normalized_protected)):
        if (any(re.search(r"(?:^|[-_.])windows(?:$|[-_.])|^windows-|^win32$",label) for label in selected)
                or not any(label in {"linux","macos"} or label.startswith(("ubuntu-","macos-")) for label in selected)):
            raise SystemExit(f"confirmed GitHub {name} runner platform authority is invalid")
    if container_image is not None and any(label=="macos" or label.startswith("macos-") for label in normalized_labels|normalized_protected):
        raise SystemExit("confirmed GitHub macOS runner cannot use a Linux container image")
    if "self-hosted" in normalized_labels|normalized_protected and (normalized_labels==normalized_protected or not normalized_labels-normalized_protected or not normalized_protected-normalized_labels):
        raise SystemExit("confirmed GitHub self-hosted runner authorities are not separated")
    return {"github_candidate_runner":runner,"github_protected_runner":protected_runner,"github_default_branch":default_branch,"github_container":container_image,
            "blueprint_sha256":blueprint_sha256}


def gitlab_workflow_authority(provider: Dict[str, object], blueprint_sha256: Optional[str] = None) -> Dict[str, object]:
    platform_name=provider.get("platform"); image=provider.get("image"); tags=provider.get("tags"); protected_tags=provider.get("protected_tags")
    if (platform_name not in {"linux","macos"} or not isinstance(tags,list) or not 1<=len(tags)<=16 or len(tags)!=len(set(tags))
            or not isinstance(protected_tags,list) or not 1<=len(protected_tags)<=16 or len(protected_tags)!=len(set(protected_tags))
            or any(provider.get(key) is not True for key in ("candidate_ephemeral","protected_ephemeral","protected_isolated"))):
        raise SystemExit("confirmed GitLab runner labels/platform authority is invalid")
    if any(not isinstance(tag,str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",tag) is None for tag in tags+protected_tags):
        raise SystemExit("confirmed GitLab runner labels/platform authority is invalid")
    candidate_set={tag.casefold() for tag in tags}; protected_set={tag.casefold() for tag in protected_tags}
    if any(re.search(r"(?:^|[-_.])windows(?:$|[-_.])|^windows-|^win32$",tag) for tag in candidate_set|protected_set):
        raise SystemExit("confirmed GitLab runner platform authority is invalid")
    if candidate_set==protected_set or not candidate_set-protected_set or not protected_set-candidate_set:
        raise SystemExit("confirmed GitLab candidate/protected runner authorities are not separated")
    image_pattern=r"(?:[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?/)?(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:[0-9a-f]{64}"
    if image is not None and (not isinstance(image,str) or re.fullmatch(image_pattern,image) is None or "" in image):
        raise SystemExit("confirmed GitLab image authority is invalid")
    if platform_name=="macos" and image is not None:
        raise SystemExit("confirmed GitLab macOS runner cannot use a Linux container image")
    if blueprint_sha256 is None or HEX64.fullmatch(blueprint_sha256) is None:
        raise SystemExit("confirmed Blueprint digest authority is invalid")
    return {"gitlab_sys_platform":"darwin" if platform_name=="macos" else "linux",
            "gitlab_image":image,"gitlab_candidate_tags":tags,"gitlab_protected_tags":protected_tags,
            "blueprint_sha256":blueprint_sha256}


def render_gitlab_workflow_yaml(source: str, variables: Dict[str, object], authority: Dict[str, object]) -> bytes:
    common={"gitlab_sys_platform","gitlab_image","blueprint_sha256"}
    if set(authority) not in (common|{"gitlab_candidate_tags"},common|{"gitlab_protected_tags"}): raise SystemExit("GitLab workflow authority fields are incomplete")
    artifact=variables.get("artifact_path")
    if artifact is not None: validated_artifact_path(artifact)
    command_ids={key:value for key,value in variables.items() if key.endswith("_command_id")}
    if set(variables)-set(command_ids)-set(authority)-({"artifact_path"} if artifact is not None else set()):
        raise SystemExit("GitLab workflow contains unknown render variables")
    text=source
    image_line="  image: {{gitlab_image}}\n"
    if image_line not in text: raise SystemExit("GitLab image authority placeholder is missing")
    text=text.replace(image_line,"" if authority["gitlab_image"] is None else "  image: "+json.dumps(authority["gitlab_image"])+"\n")
    key=next(name for name in ("gitlab_candidate_tags","gitlab_protected_tags") if name in authority)
    tag_line="{{"+key+"}}"
    if tag_line not in text: raise SystemExit(f"GitLab {key} authority placeholder is missing")
    rendered_tags="  tags:\n"+"".join("    - "+json.dumps(tag)+"\n" for tag in authority[key])
    text=text.replace(tag_line,rendered_tags)
    for key,value in command_ids.items():
        if not isinstance(value,str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}",value) is None:
            raise SystemExit("GitLab workflow command ID is invalid")
        text=text.replace("{{"+key+"}}",value)
    replacements={"blueprint_sha256":authority["blueprint_sha256"],
                  "gitlab_sys_platform":authority["gitlab_sys_platform"]}
    if artifact is not None: replacements["artifact_path"]=artifact
    for key,value in replacements.items():
        text=text.replace("{{"+key+"}}",str(value))
    if PLACEHOLDER.search(text): raise SystemExit("rendered GitLab workflow retains a placeholder")
    return text.encode("utf-8")


def _source_yaml_scalar(value: str) -> str:
    if len(value)>=2 and value[0]==value[-1]=='"':
        decoded=json.loads(value)
        if not isinstance(decoded,str): raise SystemExit("workflow template run scalar is invalid")
        return decoded
    if len(value)>=2 and value[0]==value[-1]=="'":
        return value[1:-1].replace("''", "'")
    raise SystemExit("workflow template controlled run must be one quoted scalar")


def require_installed_github_template(source: Path, data: bytes) -> None:
    install_path=AGENT_DIR/".workflow-manifest.json"
    installed=load(relative_real_file(install_path,AGENT_DIR,"workflow installation manifest"))
    managed=installed.get("agent_files")
    modes=installed.get("agent_modes")
    relative=str(source.relative_to(AGENT_DIR))
    if (not isinstance(managed,dict) or not isinstance(modes,dict)
            or managed.get(relative)!=sha256_bytes(data) or modes.get(relative)!=(source.stat().st_mode&0o777)):
        raise SystemExit("GitHub workflow template differs from its installed canonical authority")


def validated_artifact_path(value: object) -> str:
    if not isinstance(value,str) or not value or len(value.encode("utf-8"))>256:
        raise SystemExit("artifact_path must be one bounded project-relative path")
    if (value.startswith("/") or value.endswith("/") or "\\" in value
            or any(ord(character)<32 or ord(character)==127 for character in value)
            or "${{" in value):
        raise SystemExit("artifact_path must be one bounded project-relative path")
    parts=value.split("/")
    if (any(part in {"",".",".."} for part in parts)
            or any(re.fullmatch(r"[A-Za-z0-9._-]+",part) is None for part in parts)):
        raise SystemExit("artifact_path must be one bounded project-relative path")
    return value


def render_github_workflow_yaml(source: str, variables: Dict[str, object], authority: Dict[str, object]) -> bytes:
    """Render controlled YAML values without allowing data to create YAML nodes."""
    common={"github_default_branch","github_container","blueprint_sha256"}
    if set(authority) not in (common|{"github_candidate_runner","github_protected_runner"},common|{"github_protected_runner"}):
        raise SystemExit("GitHub workflow authority fields are incomplete")
    command_values={key:value for key,value in variables.items() if key.endswith("_command_id")}
    scalar_values={key:value for key,value in variables.items() if key not in authority and key not in command_values}
    if set(scalar_values)-{"artifact_path"}:
        raise SystemExit("GitHub workflow contains an unknown typed scalar variable")
    if "artifact_path" in scalar_values:
        scalar_values["artifact_path"]=validated_artifact_path(scalar_values["artifact_path"])
    if any(not isinstance(value,str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}",value) is None for value in command_values.values()):
        raise SystemExit("GitHub workflow command IDs must be exact bounded identifiers")
    if any(not isinstance(value,str) or not value or "\x00" in value or "${{" in value for value in scalar_values.values()):
        raise SystemExit("GitHub workflow scalar variables must be non-empty literals without expressions")
    expected_occurrences={key:source.count("{{"+key+"}}") for key in variables}
    if any(count==0 for count in expected_occurrences.values()):
        raise SystemExit("GitHub workflow render variable is not used by its governed template")
    if "artifact_path" in scalar_values and expected_occurrences["artifact_path"]!=1:
        raise SystemExit("artifact_path must occur exactly once in its governed template")
    rendered=[]; observed_commands=[]; observed_scalars=[]; observed_authority={key:0 for key in authority}
    run_pattern=re.compile(r"^(?P<prefix>\s*(?:-\s+)?run:\s*)(?P<scalar>.*)$")
    typed_scalar_pattern=re.compile(r"^(?P<prefix>\s*[A-Za-z_][A-Za-z0-9_-]*:\s*)(?P<scalar>.*)$")
    source_lines=source.splitlines()
    for line in source_lines:
        placeholders=PLACEHOLDER.findall(line)
        if not placeholders:
            rendered.append(line); continue
        if "github_container" in placeholders:
            if placeholders!=["github_container"] or line.strip()!="{{github_container}}":
                raise SystemExit("GitHub container placeholder has unsafe template context")
            observed_authority["github_container"]+=1
            image=authority["github_container"]
            if image is not None:
                indent=line[:len(line)-len(line.lstrip())]
                rendered.extend([indent+"container:",indent+"  image: "+json.dumps(image,ensure_ascii=True,separators=(",",":"))])
            continue
        match=run_pattern.fullmatch(line)
        if match and any(key in command_values for key in placeholders):
            scalar=_source_yaml_scalar(match.group("scalar"))
            for key in placeholders:
                if key not in command_values:
                    raise SystemExit("workflow command line mixes command and non-command authority")
                scalar=scalar.replace("{{"+key+"}}",str(command_values[key]))
            if PLACEHOLDER.search(scalar): raise SystemExit("workflow command scalar retains a placeholder")
            rendered.append(match.group("prefix")+json.dumps(scalar,ensure_ascii=True,separators=(",",":")))
            observed_commands.append((len(rendered)-1,scalar,len(placeholders)))
            continue
        replacement=line
        for key in placeholders:
            if key in {"github_candidate_runner","github_protected_runner"}:
                replacement=replacement.replace("{{"+key+"}}",json.dumps(authority[key],ensure_ascii=True,separators=(",",":")))
                observed_authority[key]+=1
            elif key=="github_default_branch":
                replacement=replacement.replace("{{github_default_branch}}",str(authority[key]))
                observed_authority[key]+=1
            elif key=="blueprint_sha256":
                if placeholders!=[key] or '"{{blueprint_sha256}}"' not in replacement:
                    raise SystemExit("Blueprint digest placeholder has unsafe workflow context")
                replacement=replacement.replace('"{{blueprint_sha256}}"',json.dumps(authority[key]))
                observed_authority[key]+=1
            elif key in scalar_values:
                if placeholders!=[key]:
                    raise SystemExit(f"workflow scalar variable {key} must be the line's only placeholder")
                double='"{{'+key+'}}"'; single="'{{"+key+"}}'"
                encoded=json.dumps(scalar_values[key],ensure_ascii=True,separators=(",",":"))
                if double in replacement:
                    replacement=replacement.replace(double,encoded)
                elif single in replacement:
                    replacement=replacement.replace(single,encoded)
                else:
                    raise SystemExit(f"workflow scalar variable {key} lacks one exact quoted context")
                observed_scalars.append((len(rendered),key,scalar_values[key]))
            else:
                raise SystemExit(f"workflow variable {key} occurs outside one controlled run scalar")
        rendered.append(replacement)
    text="\n".join(rendered)+("\n" if source.endswith("\n") else "")
    if PLACEHOLDER.search(text): raise SystemExit("rendered GitHub workflow retains a placeholder")
    if any(observed_authority[key]!=expected_occurrences[key] for key in authority):
        raise SystemExit("rendered GitHub workflow authority occurrence count changed")
    rendered_lines=text.splitlines()
    if any(sum(1 for _index,observed_key,_value in observed_scalars if observed_key==key)!=expected_occurrences[key] for key in scalar_values):
        raise SystemExit("rendered GitHub workflow typed scalar occurrence count changed")
    for index,key,expected in observed_scalars:
        match=typed_scalar_pattern.fullmatch(rendered_lines[index])
        try: actual=json.loads(match.group("scalar") if match else "")
        except json.JSONDecodeError as error: raise SystemExit(f"rendered {key} is not one typed YAML scalar") from error
        if actual!=expected: raise SystemExit(f"rendered {key} differs from its exact authority")
    for index,expected,_placeholder_count in observed_commands:
        match=run_pattern.fullmatch(rendered_lines[index])
        try: actual=json.loads(match.group("scalar") if match else "")
        except json.JSONDecodeError as error: raise SystemExit("rendered GitHub command is not one typed YAML scalar") from error
        if actual!=expected: raise SystemExit("rendered GitHub command differs from its exact authority")
    controlled_count=sum(expected_occurrences[key] for key in command_values)
    observed_count=sum(placeholder_count for _index,_expected,placeholder_count in observed_commands)
    if controlled_count!=observed_count:
        raise SystemExit("rendered GitHub workflow command shape changed")
    return text.encode("utf-8")


def parse_vars(raw: List[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for item in raw:
        if "=" not in item:
            raise SystemExit(f"template variable must be key=value: {item}")
        key, value = item.split("=", 1)
        if not key or not value or key in result:
            raise SystemExit(f"invalid or duplicate template variable: {key}")
        result[key] = value
    return result


def commit_with_context(
    task: Dict[str, object],
    reason: str,
    summary: str,
    output: Optional[Tuple[Path, bytes]] = None,
    side_effects: Iterable[Tuple[Path, bytes]] = (),
) -> None:
    before = load(TASK_PATH)
    operation = "route" if reason == "templates-routed" else "render"
    contexttx.transition_task(
        before,
        task,
        mutator="templatectl",
        operation=operation,
        reason=reason,
        summary=summary,
        side_effects=([output] if output else []) + list(side_effects),
        files=([str(output[0].relative_to(ROOT))] if output else []),
    )


def command_route(args: argparse.Namespace) -> int:
    task = load(TASK_PATH)
    require_clarified(task)
    _, manifest_sha256 = manifest_data()
    capabilities = normalize_capabilities(args.capability or [])
    verify_ci_provider(capabilities)
    adaptive = adaptive_route_binding(task, capabilities)
    pxpipe = context_transport_policy()
    if CONTEXT_TRANSPORT_CAPABILITY in capabilities:
        if not isinstance(pxpipe, dict) or pxpipe.get("enabled") is not True:
            raise SystemExit("pxpipe plugin capability is disabled; native transport remains the default")
        require_pxpipe_contract(task)
        verified_pxpipe_installation()
    prior = task.get("selected_capabilities", [])
    action = "reroute-existing" if isinstance(prior, list) and set(capabilities).issubset(set(prior)) else "route-templates"
    enforce_budget(action)
    verify_acceptance_capability(task, capabilities, adaptive)
    selected = expected_route(task, capabilities)
    receipt = route_receipt(task, capabilities, selected, manifest_sha256, adaptive)
    previous_records = task.get("rendered_artifacts", [])
    records = [
        record for record in previous_records
        if isinstance(record, dict)
        and record.get("template_id") in selected
        and record.get("route_sha256") == receipt["sha256"]
    ] if isinstance(previous_records, list) else []
    task["selected_templates"] = selected
    task["selected_capabilities"] = capabilities
    task["template_route"] = receipt
    task["rendered_artifacts"] = records
    current_node = task.get("current_node")
    if isinstance(current_node, int) and current_node >= 2:
        if current_node == 2 and (
            task.get("mode") == "fast" or task_projection(
                str(task.get("task_type")), str(task.get("mode"))
            ) == "lightweight"
        ):
            task["next_action"] = "render routed artifacts and complete projected nodes 2-6"
        else:
            task["next_action"] = f"execute the routed workflow from node {current_node}"
    import workflowctl
    commit_with_context(
        task, "templates-routed", "deterministically routed provenance-bound templates",
        side_effects=[workflowctl.stage_side_effect(task)],
    )
    print(json.dumps({"mode": task.get("mode"), "capabilities": capabilities, "templates": selected, "route": receipt["sha256"]}, indent=2))
    return 0


def command_render(args: argparse.Namespace) -> int:
    item = entry(args.id)
    task = load(TASK_PATH)
    require_clarified(task)
    enforce_budget("render-artifact")
    errors = template_state_errors(task, require_rendered=False)
    if errors:
        raise SystemExit("template route is invalid:\n- " + "\n- ".join(errors))
    if item.get("renderable") is not True:
        raise SystemExit("template is an externally governed source and cannot be rendered by templatectl")
    if args.id not in task.get("selected_templates", []):
        raise SystemExit("template was not selected by the deterministic route")
    canonical = str(item["output"])
    if args.output != canonical:
        raise SystemExit(f"render output must equal the manifest canonical path: {canonical}")
    variables = parse_vars(args.var or [])
    authority_variables={}
    provider_workflows={
        "github":{"github-ci","github-test-cd","github-production-cd"},
        "gitlab":{"gitlab-ci","gitlab-test-cd","gitlab-production-cd"},
    }
    selected_provider=next((provider for provider,ids in provider_workflows.items() if args.id in ids),None)
    if selected_provider is not None:
        blueprint=load_blueprint(ROOT,require_confirmed=True)
        matches=[provider for provider in blueprint["design"]["providers"] if provider["id"]==selected_provider]
        if len(matches)!=1: raise SystemExit(f"{selected_provider} workflow rendering requires one matching confirmed provider")
        complete_authority=github_workflow_authority(matches[0],blueprint["confirmation"]["design_sha256"]) if selected_provider=="github" else gitlab_workflow_authority(matches[0],blueprint["confirmation"]["design_sha256"])
        authority_variables.update({key:value for key,value in complete_authority.items() if key in set(item.get("authority",[]))})
        confirmed_commands={command["id"] for command in blueprint["design"]["commands"]}
        command_ids={key:value for key,value in variables.items() if key.endswith("_command_id")}
        if (any(re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}",value or "") is None for value in command_ids.values())
                or not set(command_ids.values()).issubset(confirmed_commands)):
            raise SystemExit("workflow command IDs must identify exact commands in the confirmed Blueprint")
    required=set(item["required"])
    dynamic_standard_acceptance = args.id == "node-acceptance" and task.get("mode") != "release"
    if dynamic_standard_acceptance:
        required -= NODE_ACCEPTANCE_RELEASE_VARS
    if set(variables) != required:
        raise SystemExit(f"variables must match required set; missing={sorted(required-set(variables))} extra={sorted(set(variables)-required)}")
    if args.id == "ci-contract":
        providers = [item for item in task.get("selected_capabilities", []) if item in CI_PROVIDER_CAPABILITIES]
        if len(providers) != 1 or variables.get("provider") != CI_PROVIDER_CAPABILITIES[providers[0]]:
            raise SystemExit("CI contract provider must match the selected provider capability")
    if args.id == "context-transport-profile":
        validate_context_transport_vars(task, variables)
    render_variables = dict(variables)
    render_variables.update(authority_variables)
    if dynamic_standard_acceptance:
        render_variables.update({
            "release_review_chain": "null",
            "release_scenario_receipt_sha256": "null",
            "release_scenarios": "null",
            "release_live_gate_receipt": "null",
            "release_platform_assurance": "null",
            "release_platform_observation_set": "null",
            "release_platform_observation_set_sha256": "",
            "release_supervision_debt": "null",
            "release_supervision_debt_sha256": "",
        })
    source = relative_real_file(AGENT_DIR / str(item["path"]), AGENT_DIR, f"template source {args.id}")
    source_data = boundedio.read_bytes(source,label="template source")
    text = source_data.decode("utf-8")
    if canonical.endswith((".yml",".yaml")):
        if selected_provider not in {"github","gitlab"}:
            raise SystemExit("only governed provider workflows may render YAML")
        require_installed_github_template(source,source_data)
        rendered_data = (render_github_workflow_yaml(text,render_variables,authority_variables)
                         if selected_provider=="github" else render_gitlab_workflow_yaml(text,render_variables,authority_variables))
        text = rendered_data.decode("utf-8")
    else:
        for key, value in render_variables.items():
            if not isinstance(value,str): raise SystemExit("non-YAML template variables must be strings")
            text = text.replace("{{" + key + "}}", value)
        unresolved = PLACEHOLDER.findall(text)
        if unresolved:
            raise SystemExit(f"unresolved placeholders: {sorted(set(unresolved))}")
        rendered_data = text.encode("utf-8")
    output = (ROOT / canonical).resolve()
    artifacts = (AGENT_DIR / "state" / "artifacts").resolve()
    try:
        output.relative_to(artifacts)
    except ValueError:
        raise SystemExit("render output escapes the generated artifact boundary")
    if output.suffix == ".json":
        rendered_value = json.loads(text)
        if dynamic_standard_acceptance:
            if not isinstance(rendered_value, dict):
                raise SystemExit("node-acceptance template must render a JSON object")
            for field in NODE_ACCEPTANCE_RELEASE_FIELDS:
                rendered_value.pop(field, None)
            rendered_data = (json.dumps(rendered_value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    route = task["template_route"]
    assert isinstance(route, dict)
    _, manifest_sha256 = manifest_data()
    record = {
        "schema": "agent-template-render/v1",
        "template_id": args.id,
        "path": canonical,
        "sha256": sha256_bytes(rendered_data),
        "bytes": len(rendered_data),
        "requirement_contract_sha256": task.get("requirement_contract_sha256"),
        "manifest_sha256": manifest_sha256,
        "route_sha256": route.get("sha256"),
        "source_path": str(source.relative_to(ROOT)),
        "source_sha256": sha256_bytes(source_data),
        "source_bytes": len(source_data),
    }
    records = task.get("rendered_artifacts", [])
    if not isinstance(records, list):
        records = []
    task["rendered_artifacts"] = [
        existing for existing in records
        if not isinstance(existing, dict) or existing.get("template_id") != args.id
    ] + [record]
    commit_with_context(task, "template-rendered", f"rendered provenance-bound template {args.id}", (output, rendered_data))
    print(f"RENDERED {args.id}: {canonical}")
    return 0


def template_state_errors(task: Dict[str, object], require_rendered: bool = True) -> List[str]:
    errors: List[str] = []
    try:
        require_clarified(task, allow_terminal_validation=True)
        manifest, manifest_sha256 = manifest_data()
    except SystemExit as error:
        return [str(error)]
    capabilities = task.get("selected_capabilities")
    if not isinstance(capabilities, list) or any(not isinstance(item, str) for item in capabilities):
        return ["selected_capabilities must be a string list"]
    normalized = normalize_capabilities(capabilities)
    if capabilities != normalized:
        errors.append("selected_capabilities are not normalized or dependency-complete")
    try:
        adaptive = adaptive_route_binding(task, normalized)
        verify_acceptance_capability(task, normalized, adaptive)
        expected = expected_route(task, normalized)
    except SystemExit as error:
        errors.append(str(error))
        expected = []
        adaptive = {"blueprint_sha256": None, "skills_lock_sha256": None, "project_capabilities": []}
    selected = task.get("selected_templates")
    if selected != expected:
        errors.append("selected_templates differ from the deterministic manifest route")
    expected_receipt = route_receipt(task, normalized, expected, manifest_sha256, adaptive)
    if task.get("template_route") != expected_receipt:
        errors.append("template route receipt is missing, stale or not hash-bound")
    records = task.get("rendered_artifacts")
    if not isinstance(records, list):
        return errors + ["rendered_artifacts must be a list"]
    record_ids: List[str] = []
    known = {str(item["id"]): item for item in manifest["templates"]}  # type: ignore[index]
    required_fields = {
        "schema", "template_id", "path", "sha256", "bytes",
        "requirement_contract_sha256", "manifest_sha256", "route_sha256",
        "source_path", "source_sha256", "source_bytes",
    }
    for record in records:
        if not isinstance(record, dict) or set(record) != required_fields:
            errors.append("rendered artifact record lacks exact provenance fields")
            continue
        template_id = str(record.get("template_id"))
        record_ids.append(template_id)
        item = known.get(template_id)
        if item is None or template_id not in expected or item.get("renderable") is not True:
            errors.append(f"rendered artifact is not selected/renderable: {template_id}")
            continue
        if record.get("schema") != "agent-template-render/v1":
            errors.append(f"rendered artifact schema is invalid: {template_id}")
        bindings = {
            "path": item["output"],
            "requirement_contract_sha256": task.get("requirement_contract_sha256"),
            "manifest_sha256": manifest_sha256,
            "route_sha256": expected_receipt["sha256"],
            "source_path": str((AGENT_DIR / str(item["path"])).resolve().relative_to(ROOT)),
        }
        for field, value in bindings.items():
            if record.get(field) != value:
                errors.append(f"rendered artifact {template_id} has stale {field}")
        source = (ROOT / str(record.get("source_path"))).resolve()
        output = (ROOT / str(record.get("path"))).resolve()
        for label, path, digest_key, bytes_key in (
            ("source", source, "source_sha256", "source_bytes"),
            ("output", output, "sha256", "bytes"),
        ):
            try:
                data = boundedio.read_bytes(relative_real_file(path,ROOT,f"rendered {label} {template_id}"),label=f"rendered {label} {template_id}")
            except SystemExit as error:
                errors.append(str(error))
                continue
            if sha256_bytes(data) != record.get(digest_key) or len(data) != record.get(bytes_key):
                errors.append(f"rendered artifact {template_id} {label} drifted")
            if label == "output" and PLACEHOLDER.search(data.decode(errors="replace")):
                errors.append(f"rendered artifact {template_id} has unresolved placeholders")
    if len(record_ids) != len(set(record_ids)):
        errors.append("rendered_artifacts contain duplicate template IDs")
    if require_rendered:
        accepted = task.get("accepted_nodes", [])
        last = max(accepted) if isinstance(accepted, list) and accepted else 0
        for template_id in expected:
            item = known[template_id]
            if item.get("renderable") is True and min(item["nodes"]) <= last and template_id not in record_ids:
                errors.append(f"selected template required by accepted node is not rendered: {template_id}")
    return errors


def command_validate(args: argparse.Namespace) -> int:
    try:
        context_transport_policy()
    except SystemExit as error:
        print("INVALID TEMPLATE STATE")
        print(f"- {error}")
        return 1
    errors = template_state_errors(load(TASK_PATH))
    if errors:
        print("INVALID TEMPLATE STATE")
        for error in errors:
            print(f"- {error}")
        return 1
    task = load(TASK_PATH)
    print(f"VALID TEMPLATE STATE: selected={len(task.get('selected_templates', []))} rendered={len(task.get('rendered_artifacts', []))}")
    return 0


def open_template_lock():
    try: return boundedio.open_private_lock(LOCK_PATH,label="template state lock")
    except RuntimeError as error: raise SystemExit(str(error)) from error


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    route = sub.add_parser("route")
    route.add_argument("--capability", action="append")
    render = sub.add_parser("render")
    render.add_argument("--id", required=True)
    render.add_argument("--output", required=True)
    render.add_argument("--var", action="append")
    sub.add_parser("validate")
    args = parser.parse_args()
    with open_template_lock() as template_lock:
        fcntl.flock(template_lock.fileno(),fcntl.LOCK_EX if args.command!="validate" else fcntl.LOCK_SH)
        try:
            return {"route":lambda:command_route(args),"render":lambda:command_render(args),"validate":lambda:command_validate(args)}[args.command]()
        finally: fcntl.flock(template_lock.fileno(),fcntl.LOCK_UN)


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
