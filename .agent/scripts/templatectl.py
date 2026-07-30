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
import tempfile
from typing import Dict, Iterable, List, Optional, Tuple

import contexttx
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
    "acceptance-web-docker": {"multi-agent"},
    "acceptance-api": {"multi-agent"},
    "acceptance-cli": {"multi-agent"},
    "acceptance-ios": {"multi-agent"},
    "acceptance-workflow": {"multi-agent"},
}
CI_PROVIDER_CAPABILITIES = {"ci-provider-github": "github"}
CONTEXT_TRANSPORT_CAPABILITY = "context-transport-pxpipe"
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
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON object required: {path}")
    return value


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def object_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(encoded)


def atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


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
    raw = MANIFEST_PATH.read_bytes()
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
        required_keys = {"id", "path", "output", "renderable", "depends_on", "nodes", "modes", "capabilities", "required"}
        if set(item) != required_keys:
            raise SystemExit(f"template entry {position} has invalid fields")
        template_id = item.get("id")
        if not isinstance(template_id, str) or not template_id or template_id in seen:
            raise SystemExit(f"template ID must be unique and non-empty: {template_id}")
        seen.add(template_id)
        if not isinstance(item.get("renderable"), bool):
            raise SystemExit(f"template renderable flag is invalid: {template_id}")
        for field in ("depends_on", "nodes", "modes", "capabilities", "required"):
            values = item.get(field)
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
        source_variables = set(PLACEHOLDER.findall(source.read_text(encoding="utf-8")))
        declared_variables = set(item["required"])
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
    if sha256_bytes(CONTRACT_PATH.read_bytes()) != contract_hash:
        raise SystemExit("approved requirement contract has drifted")


def enforce_budget(action: str) -> None:
    result = subprocess.run(
        [sys.executable, str(AGENT_DIR / "scripts" / "agentctl.py"), "budget-gate", "--action", action],
        cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode:
        raise SystemExit(result.stdout.strip() or f"budget gate blocked {action}")


def normalize_capabilities(raw: Iterable[str]) -> List[str]:
    capabilities = {"core", *(str(value) for value in raw if str(value))}
    changed = True
    while changed:
        changed = False
        for capability, dependencies in CAPABILITY_DEPENDENCIES.items():
            if capability in capabilities and not dependencies.issubset(capabilities):
                capabilities.update(dependencies)
                changed = True
    return sorted(capabilities)


def verify_ci_provider(capabilities: List[str]) -> None:
    selected = [item for item in capabilities if item in CI_PROVIDER_CAPABILITIES]
    if len(selected) > 1:
        raise SystemExit("exactly one CI provider capability may be selected")


def verify_acceptance_capability(task: Dict[str, object], capabilities: List[str]) -> None:
    acceptance = [item for item in capabilities if item.startswith(ACCEPTANCE_PREFIX)]
    if task.get("mode") == "release" and len(acceptance) != 1:
        raise SystemExit("release mode must select exactly one acceptance adapter capability")
    registry = load(CONFIG_PATH).get("acceptance_adapters", {})
    if not isinstance(registry, dict):
        registry = {}
    for adapter_id in acceptance:
        adapter = registry.get(adapter_id)
        if not isinstance(adapter, dict) or adapter.get("implemented") is not True:
            raise SystemExit(f"acceptance adapter is declared but not implemented: {adapter_id}")


def context_transport_policy() -> Dict[str, object]:
    policy = load(CONFIG_PATH).get("context_transport")
    expected_pxpipe = {
        "enabled", "activation", "plugin_name", "plugin_version", "models",
        "primary_mode", "provider_activation", "provider_configuration",
        "provider_content_scope", "mcp_role", "selection", "content_scope",
        "session_boundary", "fallback",
    }
    if (
        not isinstance(policy, dict)
        or set(policy) != {"default", "pxpipe"}
        or policy.get("default") != "native"
        or not isinstance(policy.get("pxpipe"), dict)
        or set(policy["pxpipe"]) != expected_pxpipe
    ):
        raise SystemExit("context transport policy is invalid")
    pxpipe = policy["pxpipe"]
    assert isinstance(pxpipe, dict)
    if (
        not isinstance(pxpipe.get("enabled"), bool)
        or pxpipe.get("activation") != "explicit-opt-in"
        or pxpipe.get("plugin_name") != "pxpipe-context"
        or pxpipe.get("plugin_version") != "0.1.0+codex.20260721210500"
        or pxpipe.get("models") != ["gpt-5.6-sol"]
        or pxpipe.get("primary_mode") != "provider-proxy"
        or pxpipe.get("provider_activation") != "default-new-local-sessions"
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


def require_pxpipe_contract(task: Dict[str, object]) -> None:
    if not CONTRACT_PATH.is_file():
        raise SystemExit("pxpipe activation requires an approved requirement contract")
    text = CONTRACT_PATH.read_text(encoding="utf-8")
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
    if pxpipe.get("enabled") is not True:
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

    workflow_manifest_path = relative_real_file(
        AGENT_DIR / ".workflow-manifest.json", AGENT_DIR, "workflow installation manifest",
    )
    workflow_manifest_bytes = workflow_manifest_path.read_bytes()
    workflow_manifest = load(workflow_manifest_path)
    plugin_files = workflow_manifest.get("repo_plugin_files")
    workflow_schema = workflow_manifest.get("schema")
    bootstrap = workflow_manifest.get("agents_bootstrap")
    claude_bootstrap = workflow_manifest.get("claude_bootstrap")
    bootstrap_schemas = {"agent-workflow-install/v3", "agent-workflow-install/v4"}
    if (
        workflow_schema not in {"agent-workflow-install/v2", *bootstrap_schemas}
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
            workflow_schema == "agent-workflow-install/v4"
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
        if sha256_bytes(bootstrap_path.read_bytes()) != bootstrap.get("sha256"):
            raise SystemExit("workflow AGENTS bootstrap differs from the installation anchor")
    if workflow_schema == "agent-workflow-install/v4":
        claude_path = relative_real_file(ROOT / "CLAUDE.md", ROOT, "workflow CLAUDE bootstrap")
        if sha256_bytes(claude_path.read_bytes()) != claude_bootstrap.get("sha256"):
            raise SystemExit("workflow CLAUDE bootstrap differs from the v4 installation anchor")
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


def route_receipt(task: Dict[str, object], capabilities: List[str], selected: List[str], manifest_sha256: str) -> Dict[str, object]:
    base: Dict[str, object] = {
        "schema": "agent-template-route/v2",
        "mode": task.get("mode"),
        "task_type": task.get("task_type"),
        "projection": task_projection(str(task.get("task_type")), str(task.get("mode"))),
        "capabilities": capabilities,
        "templates": selected,
        "requirement_contract_sha256": task.get("requirement_contract_sha256"),
        "manifest_sha256": manifest_sha256,
    }
    return {**base, "sha256": object_sha256(base)}


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
        side_effects=([output] if output else []),
        files=([str(output[0].relative_to(ROOT))] if output else []),
    )


def command_route(args: argparse.Namespace) -> int:
    task = load(TASK_PATH)
    require_clarified(task)
    _, manifest_sha256 = manifest_data()
    capabilities = normalize_capabilities(args.capability or [])
    verify_ci_provider(capabilities)
    if CONTEXT_TRANSPORT_CAPABILITY in capabilities:
        if context_transport_policy().get("enabled") is not True:
            raise SystemExit("pxpipe plugin capability is disabled; availability is not installation or user opt-in")
        require_pxpipe_contract(task)
    prior = task.get("selected_capabilities", [])
    action = "reroute-existing" if isinstance(prior, list) and set(capabilities).issubset(set(prior)) else "route-templates"
    enforce_budget(action)
    verify_acceptance_capability(task, capabilities)
    selected = expected_route(task, capabilities)
    receipt = route_receipt(task, capabilities, selected, manifest_sha256)
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
    commit_with_context(task, "templates-routed", "deterministically routed provenance-bound templates")
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
    required = set(item["required"])
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
    source_data = source.read_bytes()
    text = source_data.decode("utf-8")
    for key, value in render_variables.items():
        text = text.replace("{{" + key + "}}", value)
    unresolved = PLACEHOLDER.findall(text)
    if unresolved:
        raise SystemExit(f"unresolved placeholders: {sorted(set(unresolved))}")
    output = (ROOT / canonical).resolve()
    artifacts = (AGENT_DIR / "state" / "artifacts").resolve()
    try:
        output.relative_to(artifacts)
    except ValueError:
        raise SystemExit("render output escapes the generated artifact boundary")
    rendered_data = text.encode("utf-8")
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
        verify_acceptance_capability(task, normalized)
        expected = expected_route(task, normalized)
    except SystemExit as error:
        errors.append(str(error))
        expected = []
    selected = task.get("selected_templates")
    if selected != expected:
        errors.append("selected_templates differ from the deterministic manifest route")
    expected_receipt = route_receipt(task, normalized, expected, manifest_sha256)
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
                data = relative_real_file(path, ROOT, f"rendered {label} {template_id}").read_bytes()
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
    errors = template_state_errors(load(TASK_PATH))
    if errors:
        print("INVALID TEMPLATE STATE")
        for error in errors:
            print(f"- {error}")
        return 1
    task = load(TASK_PATH)
    print(f"VALID TEMPLATE STATE: selected={len(task.get('selected_templates', []))} rendered={len(task.get('rendered_artifacts', []))}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    route = sub.add_parser("route")
    route.add_argument(
        "--capability", action="append",
        choices=("frontend", "backend", "ios", "docker", "ci-provider-github", "delivery", "multi-agent",
                 "context-transport-pxpipe", "acceptance-web-docker", "acceptance-api", "acceptance-cli",
                 "acceptance-ios", "acceptance-workflow"),
    )
    render = sub.add_parser("render")
    render.add_argument("--id", required=True)
    render.add_argument("--output", required=True)
    render.add_argument("--var", action="append")
    sub.add_parser("validate")
    args = parser.parse_args()
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOCK_PATH.touch(exist_ok=True)
    with LOCK_PATH.open("r+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return {
            "route": lambda: command_route(args),
            "render": lambda: command_render(args),
            "validate": lambda: command_validate(args),
        }[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
