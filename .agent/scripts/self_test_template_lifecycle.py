#!/usr/bin/env python3
"""Fresh-install, update and missing-manifest adversarial lifecycle fixtures."""

from pathlib import Path
import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Optional


def run(*command: str, cwd: Optional[Path] = None, expected: int = 0) -> subprocess.CompletedProcess:
    command=list(command)
    caller_line=sys._getframe(1).f_lineno
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"]="1"
    fixture_root = Path(cwd).resolve() if cwd is not None else Path.cwd().resolve()
    provider_site = fixture_root / ".test-provider-site"
    if provider_site.is_dir():
        inherited = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = str(provider_site) + (os.pathsep + inherited if inherited else "")
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=120,
    )
    if result.returncode != expected:
        raise SystemExit(
            f"unexpected exit {result.returncode}, expected {expected} "
            f"(fixture call line {caller_line}, cwd={cwd or Path.cwd()}): {' '.join(command)}\n{result.stdout}"
        )
    return result


def install_test_provider_verifier(root: Path) -> None:
    """Install a process-scoped provider simulator in one disposable project."""
    site = root / ".test-provider-site"
    site.mkdir()
    (site / "sitecustomize.py").write_text(
        "import hashlib,json,sys\nfrom pathlib import Path\n"
        "sys.path.insert(0,str(Path.cwd()/'.agent/scripts'))\n"
        "import humandecision\n"
        "def _verify(root,config,task,*,gate,artifact_sha256,source,receipt,require_fresh=True):\n"
        " path=(Path(root)/receipt).resolve();raw=path.read_bytes()\n"
        " if json.loads(raw)!={'test_provider_receipt':True}: raise SystemExit('test provider rejected receipt')\n"
        " return {'schema':'agent-human-decision-receipt/v1','path':str(path.relative_to(Path(root).resolve())),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'decision_id':'template-lifecycle-provider','authority':'provider-signed-user-message','adapter_path':'/test/provider/decision-adapter','adapter_sha256':'b'*64}\n"
        "def _reverify(root,config,task,*,gate,artifact_sha256,source,record):\n"
        " try: return isinstance(record,dict) and record==_verify(root,config,task,gate=gate,artifact_sha256=artifact_sha256,source=source,receipt=record.get('path',''),require_fresh=False)\n"
        " except BaseException: return False\n"
        "humandecision.verify=_verify\nhumandecision.reverify=_reverify\n",
        encoding="utf-8",
    )


def write_test_provider_receipt(root: Path, name: str) -> Path:
    path = root / ".agent/state" / name
    path.write_text('{"test_provider_receipt":true}\n', encoding="utf-8")
    return path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()


def released_legacy_manifest(current: dict[str, object],schema: str,version: str,migration: int) -> dict[str, object]:
    """Build one exact released v1/v3/v4 predecessor from a current v5 manifest."""
    agent_files=dict(current["agent_files"])
    if schema=="agent-workflow-install/v1":
        return {"schema":schema,"version":version,"migration_version":migration,"files":agent_files,
                "source_tree_sha256":hashlib.sha256(json.dumps(agent_files,sort_keys=True,separators=(",",":")).encode()).hexdigest()}
    if schema not in {"agent-workflow-install/v3","agent-workflow-install/v4"}:
        raise AssertionError(f"unsupported legacy fixture schema: {schema}")
    value={
        "schema":schema,"version":version,"migration_version":migration,"agent_files":agent_files,
        "repo_plugin_files":{},"marketplace_entry":{"name":"pxpipe-context","sha256":"0"*64},
        "agents_bootstrap":dict(current["agents_bootstrap"]),
    }
    payload={"agent_files":agent_files,"repo_plugin_files":{},"marketplace_entry_sha256":"0"*64,
             "agents_bootstrap_sha256":value["agents_bootstrap"]["sha256"]}
    if schema=="agent-workflow-install/v4":
        value["claude_bootstrap"]=dict(current["claude_bootstrap"])
        payload["claude_bootstrap_sha256"]=value["claude_bootstrap"]["sha256"]
    value["source_tree_sha256"]=canonical_sha256(payload)
    return value


def receipt(root: Path, path: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {
        "path": str(path.relative_to(root)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def project_tree_bytes(target: Path) -> dict[str, bytes]:
    """Capture the installed workflow and bootstrap exactly for fail-closed tests."""
    paths = [path for path in (target / ".agent").rglob("*") if path.is_file()]
    agents = target / "AGENTS.md"
    if agents.is_file():
        paths.append(agents)
    return {str(path.relative_to(target)): path.read_bytes() for path in sorted(paths)}


def empty_platform_snapshot(path: Path) -> Path:
    path.write_text(json.dumps({
        "schema": "agent-platform-snapshot/v3",
        "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "members": [],
    }), encoding="utf-8")
    return path


def downgrade_empty_v8_to_v6(target: Path) -> Path:
    """Create an exact history-free migration-17/v6 input from a fresh fixture."""
    config_path = target / ".agent/config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    control = config["agent_control"]
    control.pop("platform_observer", None)
    control.pop("stall_timeout_seconds", None)
    control["interrupt_after_unchanged_checks"] = 3
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    agents_path = target / ".agent/state/agents.json"
    agents = json.loads(agents_path.read_text(encoding="utf-8"))
    agents["schema"] = "agent-team/v6"
    agents.pop("token_accounting", None)
    agents.pop("platform_observer", None)
    agents.pop("stall_timeout_seconds", None)
    agents.pop("replay_runs", None)
    agents["interrupt_after_unchanged_checks"] = 3
    agents_path.write_text(json.dumps(agents, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    manifest_path = target / ".agent/.workflow-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = "3.1.16"
    manifest["migration_version"] = 17
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return agents_path


def downgrade_empty_v8_to_v7(target: Path) -> Path:
    """Create the exact history-free 3.1.19/migration-18 predecessor."""
    config_path=target/".agent/config.json"; config=json.loads(config_path.read_text(encoding="utf-8"))
    config["agent_control"].pop("platform_observer",None)
    config_path.write_text(json.dumps(config,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    agents_path=target/".agent/state/agents.json"; agents=json.loads(agents_path.read_text(encoding="utf-8"))
    agents["schema"]="agent-team/v7"; agents.pop("platform_observer",None); agents.pop("token_accounting",None)
    agents_path.write_text(json.dumps(agents,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    manifest_path=target/".agent/.workflow-manifest.json"; manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"]="3.1.19"; manifest["migration_version"]=18
    manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    return agents_path


def activate_migration22_hot_state(target: Path) -> None:
    """Build an integrity-bound active predecessor with oversized hot ledgers.

    The predecessor carries the authentic pre-recalibration policy shape:
    the deprecated ``automatic_transition_token_increment`` alias with its
    legacy arithmetic (no bootstrap floor, no inherited-turn surcharge), the
    old child system/tool margin and the migration-30..34 default budgets.
    Its release budget is 40000 — the largest legacy default that still
    satisfies the fail-closed budget invariant under legacy arithmetic — so
    the pre-migration capsule validates while the migration chain still
    rewrites it (40000 -> 48000 -> 96000).
    """
    agent = target / ".agent"; state = agent / "state"
    config_path = agent / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["agent_control"]["default_model"] = "vendor-x/reasoning.model+2026"
    config["context"]["max_rollback_entries"] = 8
    config["context"].pop("max_failure_entries", None)
    config["context"].pop("max_failure_archive_depth", None)
    config["context"].pop("estimated_turn_overhead_tokens", None)
    config["context"].pop("transition_token_increment", None)
    config["context"].pop("bootstrap_overhead_tokens", None)
    config["context"]["automatic_transition_token_increment"] = {
        "fast": 150, "standard": 300, "release": 500,
    }
    config["agent_control"]["child_system_tool_margin_tokens"] = 1000
    config.pop("evidence_retention", None)
    for mode, budget in (("fast", 12000), ("standard", 24000), ("release", 40000)):
        config["routing"]["modes"][mode]["token_budget"] = budget
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    contract = "# Requirement Contract\n\n- Human decisions: user:migration-fixture\n- Clarified: true\n"
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    agents_path = state / "agents.json"
    agents = json.loads(agents_path.read_text(encoding="utf-8"))
    agents["default_model"] = "vendor-x/reasoning.model+2026"
    agents_path.write_text(json.dumps(agents, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    task_path = state / "TASK.json"; task = json.loads(task_path.read_text(encoding="utf-8"))
    task.update({
        "title": "migration 22 active hot-state fixture",
        "mode": "release", "complexity": "complex", "token_budget": 40000,
        "status": "in_progress", "phase": "structuring",
        "requirements_clarified": True, "requirement_source": "user:migration-fixture",
        "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
        "requirement_contract_sha256": hashlib.sha256(contract.encode()).hexdigest(),
        "primary_skill": "run-ai-coding-pipeline", "open_questions": [],
        # Keep the synthetic predecessor before generated stage artifacts.
        # Claiming later nodes accepted without their provenance-bound outputs
        # would make the predecessor invalid before migration begins.
        "next_action": "complete node 2: structuring", "current_node": 2,
        "accepted_nodes": list(range(2)), "node_artifacts": {},
        "gate_approvals": {"requirement": "user:migration-fixture"},
        "rollback_ledger": [{"sequence": number} for number in range(9)],
        "rollback_archive": None,
        "failure_ledger": {
            hashlib.sha256(f"migration-failure-{number}".encode()).hexdigest(): 1
            for number in range(17)
        },
        "failure_archive": None, "mode_status": "confirmed",
        "selected_capabilities": ["core", "acceptance-workflow"],
    })
    task.pop("decision_policy_version", None)
    task_path.write_text(json.dumps(task, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    run(
        sys.executable, "-c",
        "import json,sys;sys.path.insert(0,'.agent/scripts');import workflowctl;workflowctl.update_stage(json.load(open('.agent/state/TASK.json')))",
        cwd=target,
    )
    # This is a synthetic migration predecessor, not a repair authorization
    # flow. Build its ordinary verified capsule directly so the fixture never
    # invents a provider-owned human decision receipt.
    run(
        sys.executable, "-c",
        "import argparse,hashlib,json,sys;from pathlib import Path;"
        "sys.path.insert(0,'.agent/scripts');import contextctl;"
        "p=contextctl.CONTEXT_PATH;previous=json.loads(p.read_text());"
        "args=argparse.Namespace(reason='migration-22-fixture',summary='active predecessor hot state',source='migration-fixture',source_tokens=4000,fact=[],file=[],evidence=[],risk=[],resolve_risk=[],transition=False,reset=True);"
        "capsule=contextctl.build_capsule(args,'verified',previous,hashlib.sha256(p.read_bytes()).hexdigest());"
        "contextctl.atomic_json(p,capsule);raise SystemExit(contextctl.validate_context())",
        cwd=target,
    )
    (state / "EVIDENCE_INDEX.json").unlink(missing_ok=True)
    manifest_path = agent / ".workflow-manifest.json"
    manifest = released_legacy_manifest(
        json.loads(manifest_path.read_text(encoding="utf-8")),
        "agent-workflow-install/v1","3.1.40",32,
    )
    manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template-root", required=True)
    args = parser.parse_args()
    source = Path(args.template_root).resolve()
    installer = source / "install.py"
    if not installer.is_file():
        raise SystemExit("template installer missing")

    with tempfile.TemporaryDirectory(prefix="workflow-template-test-") as raw:
        workspace = Path(raw)

        def initialize_migration_fixture(project: Path, label: str) -> None:
            guardrails=project/f"{label}-guardrails.md"
            guardrails.write_text("# Project Guardrails\n\n## Required project facts\n\n"
                "- Product and users: Disposable workflow migration fixture.\n"
                "- Technology and architecture: Python controls and local JSON state.\n"
                "- Writable and read-only areas: The fixture is writable; external paths are read-only.\n"
                "- Security, privacy, compliance and performance red lines: No credentials or external effects.\n"
                "- Build, test and lint commands: Run the template lifecycle self-test.\n"
                "- Deployment authority and rollback owner: No deployment; the fixture owner rolls back.\n",encoding="utf-8")
            run(sys.executable,".agent/scripts/agentctl.py","project-init","--guardrails-file",guardrails.name,cwd=project)

        # Positive fresh install and transactional managed update.
        target = workspace / "project"
        target.mkdir()
        existing_agents = "# Existing project rules\n\nDo not replace this project-owned content.\n"
        (target / "AGENTS.md").write_text(existing_agents, encoding="utf-8")
        run(sys.executable, str(installer), str(target), "--project-name", "fixture")
        run(sys.executable, ".agent/scripts/agentctl.py", "validate", cwd=target)
        installed_agents = (target / "AGENTS.md").read_text(encoding="utf-8")
        installed_manifest = json.loads((target / ".agent/.workflow-manifest.json").read_text(encoding="utf-8"))
        if (
            not installed_agents.startswith(existing_agents)
            or installed_manifest.get("agents_bootstrap") != {
                "path": "AGENTS.md", "sha256": digest(target / "AGENTS.md"),
            }
            or installed_manifest.get("claude_bootstrap") != {
                "path": "CLAUDE.md", "sha256": digest(target / "CLAUDE.md"),
            }
            or (target / "CLAUDE.md").read_text(encoding="utf-8").count("<!-- agent-workflow-bootstrap:start -->") != 1
        ):
            raise SystemExit("install manifest does not bind the complete preserved AGENTS.md and managed CLAUDE.md")
        fresh_full_config = json.loads((target / ".agent/config.json").read_text(encoding="utf-8"))
        fresh_config = fresh_full_config["agent_control"]
        fresh_task = json.loads((target / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        fresh_agents = json.loads((target / ".agent/state/agents.json").read_text(encoding="utf-8"))
        if (
            fresh_agents.get("schema") != "agent-team/v9"
            or fresh_agents.get("prepared_dispatches") != []
            or fresh_agents.get("replay_runs") != []
            or fresh_agents.get("task_payload_schema") != "agent-task-payload/v2"
            or fresh_agents.get("token_accounting") != {
                "schema": "agent-child-token-accounting/v1", "token_budget": 48000,
                "settled_tokens": 0,
            }
            or fresh_agents.get("task_payload_limits") != {
                "max_input_count": 24, "max_single_bytes": 131072,
                "max_total_bytes": 262144, "max_estimated_tokens": 65536,
            }
            or {name: entry.get("token_budget") for name, entry in fresh_full_config.get("routing", {}).get("modes", {}).items()} != {
                "fast": 16000, "standard": 48000, "release": 96000,
            }
            or fresh_full_config.get("context", {}).get("estimated_turn_overhead_tokens") != {
                "fast": 2000, "standard": 3000, "release": 4000,
            }
            or fresh_full_config.get("context", {}).get("transition_token_increment") != {
                "fast": 200, "standard": 400, "release": 800,
            }
            or fresh_full_config.get("context", {}).get("bootstrap_overhead_tokens") != 7000
            or "automatic_transition_token_increment" in fresh_full_config.get("context", {})
            or fresh_config.get("status_interval_seconds") != 30
            or fresh_config.get("monitor_grace_seconds") != 30
            or fresh_config.get("stall_timeout_seconds") != 300
            or fresh_agents.get("stall_timeout_seconds") != 300
            or fresh_config.get("status_request_after_unchanged_checks") != 1
            or "interrupt_after_unchanged_checks" in fresh_config
            or "interrupt_after_unchanged_checks" in fresh_agents
            or fresh_config.get("max_task_payload_input_count") != 24
            or fresh_config.get("max_task_payload_single_bytes") != 131072
            or fresh_config.get("max_task_payload_total_bytes") != 262144
            or fresh_config.get("max_task_payload_estimated_tokens") != 65536
            or fresh_config.get("inherit_parent_history") is not False
            or fresh_config.get("dispatch_payload_token_limits") != {
                "fast": 0, "standard": 16000, "release": 32000,
            }
            or fresh_config.get("default_fork_turns") != 0
            or fresh_config.get("inherited_turn_estimated_tokens") != 800
            or fresh_config.get("child_system_tool_margin_tokens") != 4000
            or fresh_config.get("child_output_margin_tokens") != 2000
            or fresh_config.get("allowed_role_types") != [
                "worker", "researcher", "documentation-worker", "implementer",
                "reviewer", "adversarial", "cross", "integrator",
            ]
            or fresh_config.get("review_role_types") != ["reviewer", "adversarial", "cross", "integrator"]
            or fresh_config.get("platform_observer") != {
                "source": "orchestrator-tool-transcript", "automatic_release_trust": False,
                "human_verification_required": True, "signed_adapter": None,
            }
            or fresh_config.get("human_decision_observer") != {
                "source": "orchestrator-user-message", "automatic_gate_trust": False,
                "human_verification_required": True,
                "allow_current_chat_local_release": False,
                "signed_adapter": None,
                "max_receipt_age_seconds": 900,
            }
            or fresh_task.get("decision_policy_version") != 1
            or fresh_task.get("task_archive") is not None
            or fresh_agents.get("platform_observer") != fresh_config.get("platform_observer")
            or fresh_agents.get("platform_empty_verified") is not False
            or fresh_agents.get("last_platform_snapshot") is not None
        ):
            raise SystemExit("fresh install lacks the fail-closed workflow and v9 Agent defaults")

        def assert_fresh_fast_start(
            name: str, requested_mode: str, approve: bool = False, complete: bool = False,
        ) -> Path:
            fast_target = workspace / name
            adapterless_install = subprocess.run(
                [
                    sys.executable, str(installer), str(fast_target),
                    "--project-name", name,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )
            if adapterless_install.returncode:
                raise SystemExit(
                    f"adapterless fresh fast install failed: {name}\n{adapterless_install.stdout}"
                )
            guardrails = fast_target / "project-guardrails.md"
            guardrails.write_text(
                "# Project Guardrails\n\n"
                "## Required project facts\n\n"
                "- Product and users: Disposable fast lifecycle fixture for template maintainers.\n"
                "- Technology and architecture: Python workflow controls and local JSON state.\n"
                "- Writable and read-only areas: The temporary fixture is writable; external paths are read-only.\n"
                "- Security, privacy, compliance and performance red lines: No credentials or external effects.\n"
                "- Build, test and lint commands: Run the template lifecycle self-test.\n"
                "- Deployment authority and rollback owner: No deployment; the fixture owner rolls back.\n",
                encoding="utf-8",
            )
            run(
                sys.executable, ".agent/scripts/agentctl.py", "project-init",
                "--guardrails-file", guardrails.name, cwd=fast_target,
            )
            bootstrap = run(
                sys.executable, ".agent/scripts/agentctl.py", "bootstrap-check",
                cwd=fast_target, expected=2,
            )
            if (
                "BOOTSTRAP NOT READY: provider-owned human-decision adapter is not configured" not in bootstrap.stdout
                or "AUTHORITATIVE GATES BLOCKED" not in bootstrap.stdout
            ):
                raise SystemExit(f"adapterless initialized project overclaimed authority:\n{bootstrap.stdout}")
            run(
                sys.executable, ".agent/scripts/agentctl.py", "start", "--model", "provider-neutral/model.fixture",
                "--title", f"{name} bounded fast fixture",
                "--mode", requested_mode,
                "--environment", "local",
                "--task-type", "maintenance",
                "--complexity", "tiny",
                "--files", "1",
                cwd=fast_target,
            )
            fast_config = json.loads((fast_target / ".agent/config.json").read_text(encoding="utf-8"))
            fast_task = json.loads((fast_target / ".agent/state/TASK.json").read_text(encoding="utf-8"))
            fast_context = json.loads((fast_target / ".agent/state/CONTEXT.json").read_text(encoding="utf-8"))
            fast_limit = fast_config["context"]["max_capsule_tokens"]["fast"]
            if (
                fast_limit != 1000
                or fast_task.get("mode") != "fast"
                or fast_task.get("status") != "waiting_human"
                or fast_task.get("current_node") != 1
                or fast_context.get("mode") != "fast"
                or fast_context.get("compaction", {}).get("capsule_estimated_tokens", fast_limit + 1) > fast_limit
            ):
                raise SystemExit(f"fresh {requested_mode} start did not enter bounded fast clarification")
            run(sys.executable, ".agent/scripts/contextctl.py", "check", cwd=fast_target)
            run(sys.executable, ".agent/scripts/workflowctl.py", "validate", cwd=fast_target)
            if approve:
                install_test_provider_verifier(fast_target)
                requirement_receipt = write_test_provider_receipt(
                    fast_target, "test-fast-requirement-receipt.json",
                )
                contract_path = fast_target / ".agent/state/REQUIREMENT_CONTRACT.md"
                contract_path.write_text(
                    "# Requirement Contract\n\n"
                    "- Goal: Verify fresh fast approval.\n"
                    "- Users: Template lifecycle maintainers.\n"
                    "- Success: Enter Node 2 with a valid bounded capsule.\n"
                    "- In scope: Disposable local workflow state.\n"
                    "- Out of scope: External effects.\n"
                    "- Constraints: Remain local and reversible.\n"
                    "- Data and permissions: No credentials or external data.\n"
                    "- Target environment: local\n"
                    "- Context transport: native\n"
                    "- Acceptance: Canonical context and workflow validation pass.\n"
                    "- Provenance: template lifecycle fixture\n"
                    "- Production provider target: none\n"
                    "- Human decisions: user:template-lifecycle-fast\n"
                    "- Clarified: true\n",
                    encoding="utf-8",
                )
                run(
                    sys.executable, ".agent/scripts/agentctl.py", "approve-requirements",
                    "--source", "user:template-lifecycle-fast",
                    "--human-decision-receipt", str(requirement_receipt.relative_to(fast_target)),
                    cwd=fast_target,
                )
                approved_task = json.loads((fast_target / ".agent/state/TASK.json").read_text(encoding="utf-8"))
                approved_context = json.loads((fast_target / ".agent/state/CONTEXT.json").read_text(encoding="utf-8"))
                if (
                    approved_task.get("current_node") != 2
                    or approved_task.get("requirements_clarified") is not True
                    or approved_context.get("compaction", {}).get("capsule_estimated_tokens", fast_limit + 1) > fast_limit
                ):
                    raise SystemExit("fresh fast approval exceeded its bounded capsule or failed to enter Node 2")
                run(sys.executable, ".agent/scripts/contextctl.py", "check", cwd=fast_target)
                run(sys.executable, ".agent/scripts/workflowctl.py", "validate", cwd=fast_target)
                if complete:
                    # Real installed lifecycle: do not replace contextctl,
                    # contexttx, workflowctl or agentctl. This covers the
                    # fast+lightweight template route and proves that the
                    # canonical transition estimate survives the whole chain
                    # below the fast hard watermark.
                    run(sys.executable, ".agent/scripts/templatectl.py", "route", cwd=fast_target)
                    routed_task = json.loads(
                        (fast_target / ".agent/state/TASK.json").read_text(encoding="utf-8")
                    )
                    if routed_task.get("selected_templates") != [
                        "requirement-contract", "fast-projection", "node-implementation",
                        "targeted-acceptance", "retrospective",
                    ]:
                        raise SystemExit("real fast lightweight lifecycle lacks its node 7 template")

                    change_path = fast_target / "real-lifecycle-change.txt"
                    change_path.write_text("real contexttx lifecycle candidate\n", encoding="utf-8")
                    check_result = run(
                        sys.executable, ".agent/scripts/contextctl.py", "check", cwd=fast_target,
                    )
                    check_output = fast_target / ".agent/state/evidence/real-lifecycle-context-check.txt"
                    check_output.parent.mkdir(parents=True, exist_ok=True)
                    check_output.write_text(check_result.stdout, encoding="utf-8")
                    cleanup = {
                        "runtime_state": receipt(
                            fast_target, fast_target / ".agent/state/runtime.json"
                        ),
                        "residual": {"processes": 0, "docker_projects": 0, "ports": 0},
                    }
                    changes = [receipt(fast_target, change_path)]
                    checks = [{
                        "id": "real-contexttx-lifecycle",
                        "command": [
                            sys.executable, ".agent/scripts/contextctl.py", "check",
                        ],
                        "exit_code": 0,
                        "output": receipt(fast_target, check_output),
                    }]

                    def render(template_id: str, output: str, variables: dict[str, object]) -> None:
                        command = [
                            sys.executable, ".agent/scripts/templatectl.py", "render",
                            "--id", template_id, "--output", output,
                        ]
                        for key, value in variables.items():
                            rendered = (
                                json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                                if not isinstance(value, str) else value
                            )
                            command.extend(["--var", f"{key}={rendered}"])
                        run(*command, cwd=fast_target)

                    render("fast-projection", ".agent/state/artifacts/01-fast-projection.json", {
                        "requirement_contract_sha256": routed_task["requirement_contract_sha256"],
                        "scope_summary": "real installed fast lifecycle",
                        "change_receipts":changes,
                        "candidate_snapshot_receipts":[{**item,"mode":420} for item in changes],
                        "check_receipts":checks,
                        "cleanup_receipt": cleanup,
                        "exclusions": [],
                    })
                    render("node-implementation", ".agent/state/artifacts/06-implementation.json", {
                        "mode": "fast",
                        "requirement_contract_sha256": routed_task["requirement_contract_sha256"],
                        "mode_appropriate_implementer_agent_id": None,
                        "projection": [2, 3, 4, 5, 6],
                        "change_receipts":changes,
                        "candidate_snapshot_receipts":[{**item,"mode":420} for item in changes],
                        "check_receipts":checks,
                        "cleanup_receipt": cleanup,
                        "scope_summary": "real installed fast lifecycle",
                    })
                    run(
                        sys.executable, ".agent/scripts/workflowctl.py", "advance",
                        "--node", "6", "--artifact", ".agent/state/artifacts/06-implementation.json",
                        cwd=fast_target,
                    )
                    node6_task = json.loads(
                        (fast_target / ".agent/state/TASK.json").read_text(encoding="utf-8")
                    )
                    acceptance_checks = [{
                        "id": "real-lifecycle-acceptance",
                        "result": "passed",
                        "case_ids": ["fast-lightweight-route", "real-contexttx-budget"],
                        "assertions": ["node 7 template is routed", "context remains below hard watermark"],
                        "reviewer": "fixture-integrator",
                        "evidence": [receipt(fast_target, check_output)],
                    }]
                    render("targeted-acceptance", ".agent/state/artifacts/07-acceptance.json", {
                        "mode": "fast",
                        "node_bindings": {
                            "requirement_contract_sha256": node6_task["requirement_contract_sha256"],
                            "implementation_sha256": node6_task["node_artifacts"]["6"]["sha256"],
                        },
                        "acceptance_checks": acceptance_checks,
                    })
                    run(
                        sys.executable, ".agent/scripts/workflowctl.py", "advance",
                        "--node", "7", "--artifact", ".agent/state/artifacts/07-acceptance.json",
                        cwd=fast_target,
                    )
                    # A task with every workflow node accepted must be able to
                    # close honestly even if accumulated real host turns have
                    # reached the hard watermark. Only the already-routed
                    # retrospective and complete actions are admitted.
                    preclosure_estimate = json.loads(
                        (fast_target / ".agent/state/CONTEXT.json").read_text(
                            encoding="utf-8"
                        )
                    )["usage_freshness"]["estimated_tokens"]
                    hard_limit = (
                        fast_config["routing"]["modes"]["fast"]["token_budget"]
                        * fast_config["context"]["hard_budget_ratio"]
                    )
                    if preclosure_estimate >= hard_limit:
                        raise SystemExit(
                            "minimum real fast lifecycle reached the hard watermark "
                            f"before the explicit closure probe: estimate={preclosure_estimate} "
                            f"hard={hard_limit}"
                        )
                    closure_route = json.loads(run(
                        sys.executable, ".agent/scripts/workflowctl.py", "route-resume",
                        cwd=fast_target,
                    ).stdout)
                    for index in range(1, 9):
                        if closure_route.get("budget_state") == "hard_blocked":
                            break
                        run(
                            sys.executable, ".agent/scripts/contextctl.py", "account-turn",
                            "--turn-id", f"real-lifecycle-terminal-closure-{index}",
                            cwd=fast_target,
                        )
                        closure_route = json.loads(run(
                            sys.executable, ".agent/scripts/workflowctl.py", "route-resume",
                            cwd=fast_target,
                        ).stdout)
                    closure_context = json.loads(
                        (fast_target / ".agent/state/CONTEXT.json").read_text(
                            encoding="utf-8"
                        )
                    )
                    if (
                        closure_route.get("budget_state") != "hard_blocked"
                        or closure_context.get("resume", {}).get("resume_action")
                        != "continue"
                        or closure_route.get("next_action")
                        != "render retrospective and complete task"
                    ):
                        raise SystemExit(
                            "hard-watermark terminal closure did not remain executable: "
                            f"route={closure_route} resume={closure_context.get('resume')}"
                        )
                    render("retrospective", ".agent/state/artifacts/08-retrospective.md", {
                        "result": "real fast lifecycle completed",
                        "time": "bounded fixture",
                        "tokens": "estimated honestly through hard-watermark closure",
                        "resources": "no child agents",
                        "costs": "one bounded lifecycle",
                        "learning": "real contexttx path is required",
                        "candidates": "none",
                        "promotion": "not requested",
                    })
                    final_snapshot = empty_platform_snapshot(
                        fast_target / ".agent/state/evidence/real-lifecycle-empty-platform.json"
                    )
                    run(
                        sys.executable,
                        ".agent/skills/manage-agent-team/scripts/agentledger.py", "init",
                        "--platform-snapshot", str(final_snapshot.relative_to(fast_target)),
                        cwd=fast_target,
                    )
                    terminal_risk = "fixture terminal risk requires explicit resolution"
                    before_completion_context = json.loads(
                        (fast_target / ".agent/state/CONTEXT.json").read_text(encoding="utf-8")
                    )
                    run(
                        sys.executable, ".agent/scripts/contextctl.py", "sync",
                        "--reason", "terminal-risk-fixture",
                        "--summary", "record an explicit terminal risk",
                        "--source-tokens", str(
                            before_completion_context["usage_freshness"]["estimated_tokens"]
                        ),
                        "--source", "fixture:terminal-risk",
                        "--risk", terminal_risk,
                        cwd=fast_target,
                    )
                    blocked_completion = run(
                        sys.executable, ".agent/scripts/workflowctl.py", "complete-task",
                        "--retrospective", ".agent/state/artifacts/08-retrospective.md",
                        "--platform-snapshot", str(final_snapshot.relative_to(fast_target)),
                        expected=1, cwd=fast_target,
                    )
                    if "unresolved context risks" not in blocked_completion.stdout:
                        raise SystemExit(
                            "terminal completion did not fail closed on an unresolved risk"
                        )
                    # The negative completion and concurrent lifecycle load may
                    # consume the bounded observation window. Re-observe the
                    # still-empty platform immediately before authorization.
                    final_snapshot = empty_platform_snapshot(final_snapshot)
                    run(
                        sys.executable, ".agent/scripts/workflowctl.py", "complete-task",
                        "--retrospective", ".agent/state/artifacts/08-retrospective.md",
                        "--platform-snapshot", str(final_snapshot.relative_to(fast_target)),
                        "--resolve-risk", terminal_risk,
                        cwd=fast_target,
                    )
                    completed_task = json.loads(
                        (fast_target / ".agent/state/TASK.json").read_text(encoding="utf-8")
                    )
                    completed_context = json.loads(
                        (fast_target / ".agent/state/CONTEXT.json").read_text(encoding="utf-8")
                    )
                    estimate = completed_context["usage_freshness"]["estimated_tokens"]
                    completed_compaction = completed_context.get("compaction", {})
                    if (
                        completed_task.get("status") != "accepted"
                        or completed_task.get("budget_state") == "hard_blocked"
                        or preclosure_estimate >= hard_limit
                        or estimate < hard_limit
                        or completed_context.get("open_risks") != []
                        or completed_compaction.get("tokens_removed") != 0
                        or completed_compaction.get("capsule_reduction_tokens")
                        != completed_compaction.get("source_estimated_tokens")
                        - completed_compaction.get("capsule_estimated_tokens")
                    ):
                        raise SystemExit(
                            f"real fast lifecycle hit the fabricated budget ratchet: "
                            f"preclosure={preclosure_estimate} estimate={estimate} "
                            f"hard={hard_limit}"
                        )
                    routed = run(
                        sys.executable, ".agent/scripts/workflowctl.py", "route-resume",
                        cwd=fast_target,
                    )
                    if json.loads(routed.stdout).get("terminal") is not True:
                        raise SystemExit("real fast lifecycle did not reach a terminal route receipt")
                    # The next real host/model turn must be charged without
                    # erasing the explicit complete-task origin. This used to
                    # turn an accepted task back into a non-terminal route
                    # because account-turn replaced the current checkpoint.
                    run(
                        sys.executable, ".agent/scripts/contextctl.py", "account-turn",
                        "--turn-id", "real-lifecycle-post-completion-turn",
                        cwd=fast_target,
                    )
                    post_turn_context_path = fast_target / ".agent/state/CONTEXT.json"
                    post_turn_context = json.loads(
                        post_turn_context_path.read_text(encoding="utf-8")
                    )
                    completion_origin = post_turn_context.get("checkpoint", {}).get(
                        "terminal_completion_origin", {}
                    )
                    completion_authorization = completion_origin.get(
                        "transition_authorization", {}
                    )
                    if (
                        completion_origin.get("schema")
                        != "agent-terminal-completion-origin/v1"
                        or completion_origin.get("kind") != "complete-task"
                        or completion_authorization.get("mutator") != "workflowctl"
                        or completion_authorization.get("operation") != "complete-task"
                    ):
                        raise SystemExit(
                            "post-completion host turn did not preserve the complete-task origin"
                        )
                    first_accounting_bytes = post_turn_context_path.read_bytes()
                    duplicate_turn = run(
                        sys.executable, ".agent/scripts/contextctl.py", "account-turn",
                        "--turn-id", "real-lifecycle-post-completion-turn",
                        cwd=fast_target,
                    )
                    if (
                        "ALREADY ACCOUNTED" not in duplicate_turn.stdout
                        or post_turn_context_path.read_bytes() != first_accounting_bytes
                    ):
                        raise SystemExit(
                            "post-completion host turn replay was not a byte-identical no-op"
                        )
                    post_turn_route = run(
                        sys.executable, ".agent/scripts/workflowctl.py", "route-resume",
                        cwd=fast_target,
                    )
                    if json.loads(post_turn_route.stdout).get("terminal") is not True:
                        raise SystemExit(
                            "post-completion host turn erased the terminal route receipt"
                        )
                    # A completed task may not roll directly into new scope
                    # when the next checkpoint would already be compact or
                    # hard-blocked. Drive the real accepted capsule to that
                    # boundary and prove start fails before replacing TASK or
                    # CONTEXT. The persisted resume contract and route receipt
                    # must report the same effective state and recovery step.
                    rollover_route = json.loads(post_turn_route.stdout)
                    for index in range(1, 6):
                        if rollover_route.get("budget_state") in {
                            "must_compact", "hard_blocked"
                        }:
                            break
                        run(
                            sys.executable, ".agent/scripts/contextctl.py", "account-turn",
                            "--turn-id", f"real-lifecycle-rollover-boundary-{index}",
                            cwd=fast_target,
                        )
                        rollover_route = json.loads(run(
                            sys.executable, ".agent/scripts/workflowctl.py", "route-resume",
                            cwd=fast_target,
                        ).stdout)
                    if rollover_route.get("budget_state") not in {
                        "must_compact", "hard_blocked"
                    }:
                        raise SystemExit(
                            "real lifecycle could not reach the rollover budget boundary"
                        )
                    boundary_context = json.loads(
                        post_turn_context_path.read_text(encoding="utf-8")
                    )
                    boundary_resume = boundary_context.get("resume", {})
                    if (
                        boundary_resume.get("budget_state")
                        != rollover_route.get("budget_state")
                        or boundary_resume.get("next_action")
                        != rollover_route.get("next_action")
                        or "verified host compaction"
                        not in str(rollover_route.get("next_action", ""))
                    ):
                        raise SystemExit(
                            "persisted resume and terminal route disagree at rollover boundary"
                        )
                    before_rollover_task = (
                        fast_target / ".agent/state/TASK.json"
                    ).read_bytes()
                    before_rollover_context = post_turn_context_path.read_bytes()
                    blocked_rollover = run(
                        sys.executable, ".agent/scripts/agentctl.py", "start", "--model", "provider-neutral/model.fixture",
                        "--title", "blocked compact rollover",
                        "--mode", "fast", "--environment", "local",
                        "--task-type", "maintenance", "--complexity", "tiny",
                        "--files", "1", expected=1, cwd=fast_target,
                    )
                    if (
                        "new task would enter" not in blocked_rollover.stdout
                        or (fast_target / ".agent/state/TASK.json").read_bytes()
                        != before_rollover_task
                        or post_turn_context_path.read_bytes()
                        != before_rollover_context
                    ):
                        raise SystemExit(
                            "compact rollover did not fail before replacing task/context state"
                        )
                    # Migration 39 preserves the monotonic budget estimate;
                    # migration 41 then conservatively revokes every unverifiable
                    # predecessor approval and rebinds route/stage to Node 1.
                    installed_manifest_path = (
                        fast_target / ".agent/.workflow-manifest.json"
                    )
                    installed_manifest = json.loads(
                        installed_manifest_path.read_text(encoding="utf-8")
                    )
                    installed_manifest["schema"] = "agent-workflow-install/v4"
                    installed_manifest["version"] = "3.1.46"
                    installed_manifest["migration_version"] = 38
                    installed_manifest["repo_plugin_files"] = {}
                    installed_manifest["marketplace_entry"] = {
                        "name": "pxpipe-context", "sha256": "0" * 64,
                    }
                    legacy_payload = {
                        "agent_files": installed_manifest["agent_files"],
                        "repo_plugin_files": installed_manifest["repo_plugin_files"],
                        "marketplace_entry_sha256": installed_manifest["marketplace_entry"]["sha256"],
                        "agents_bootstrap_sha256": installed_manifest["agents_bootstrap"]["sha256"],
                        "claude_bootstrap_sha256": installed_manifest["claude_bootstrap"]["sha256"],
                    }
                    installed_manifest["source_tree_sha256"] = hashlib.sha256(
                        json.dumps(legacy_payload, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")).encode()
                    ).hexdigest()
                    installed_manifest_path.write_text(
                        json.dumps(installed_manifest, indent=2) + "\n",
                        encoding="utf-8",
                    )
                    before_migration_estimate = boundary_context[
                        "usage_freshness"
                    ]["estimated_tokens"]
                    run(
                        sys.executable, str(installer), str(fast_target), "--update",
                        cwd=fast_target,
                    )
                    migrated_context = json.loads(
                        post_turn_context_path.read_text(encoding="utf-8")
                    )
                    migrated_route = json.loads(run(
                        sys.executable, ".agent/scripts/workflowctl.py", "route-resume",
                        cwd=fast_target,
                    ).stdout)
                    migrated_task = json.loads((fast_target / ".agent/state/TASK.json").read_text(encoding="utf-8"))
                    if (
                        migrated_context.get("checkpoint", {}).get("reason")
                        != "migration-39-budget-resume-rebind"
                        or migrated_context.get("compaction", {}).get("source")
                        != "installer-verified-budget-resume-migration"
                        or migrated_context["usage_freshness"]["estimated_tokens"]
                        < before_migration_estimate
                        or migrated_context.get("resume", {}).get("budget_state")
                        != migrated_route.get("budget_state")
                        or migrated_route.get("terminal") is not False
                        or migrated_route.get("control") != "human-decision-required"
                        or migrated_task.get("status") != "waiting_human"
                        or migrated_task.get("requirements_clarified") is not False
                        or migrated_task.get("gate_approvals") != {}
                        or migrated_task.get("current_node") != 1
                        or migrated_task.get("accepted_nodes") != [0]
                    ):
                        raise SystemExit("migration 39/41 state mismatch: " + json.dumps({
                            "checkpoint": migrated_context.get("checkpoint"),
                            "compaction": migrated_context.get("compaction"),
                            "usage": migrated_context.get("usage_freshness"),
                            "resume": migrated_context.get("resume"),
                            "route": migrated_route,
                            "task": {key: migrated_task.get(key) for key in (
                                "status", "current_node", "accepted_nodes", "requirements_clarified", "gate_approvals")},
                        }, sort_keys=True))
                    run(
                        sys.executable, ".agent/scripts/contextctl.py", "account-turn",
                        "--turn-id", "real-lifecycle-post-migration-39-turn",
                        cwd=fast_target,
                    )
                    post_migration_turn_route = json.loads(run(
                        sys.executable, ".agent/scripts/workflowctl.py", "route-resume",
                        cwd=fast_target,
                    ).stdout)
                    if (post_migration_turn_route.get("terminal") is not False
                            or post_migration_turn_route.get("current_node") != 1
                            or post_migration_turn_route.get("control") != "human-decision-required"):
                        raise SystemExit(
                            "host-turn accounting restored authority revoked by migration 41"
                        )
            return fast_target

        assert_fresh_fast_start("fresh-explicit-fast", "fast", approve=True, complete=True)
        assert_fresh_fast_start("fresh-auto-fast", "auto")

        # Real three-strike recovery over installed contexttx/contextctl. The
        # state-machine unit fixture intentionally stubs those modules, so it
        # cannot prove that resolve-failure has an authorized transition
        # profile. Prepare a valid in-progress checkpoint, drive three actual
        # return-node transactions, then exercise the real approval exit.
        strike_target = workspace / "real-three-strike-recovery"
        strike_install = subprocess.run(
            [
                sys.executable, str(installer), str(strike_target),
                "--project-name", "real-three-strike-recovery",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        if strike_install.returncode:
            raise SystemExit(f"real three-strike install failed:\n{strike_install.stdout}")
        install_test_provider_verifier(strike_target)
        strike_requirement_receipt = write_test_provider_receipt(
            strike_target, "test-strike-requirement-receipt.json",
        )
        strike_lightweight_repair_receipt = write_test_provider_receipt(
            strike_target, "test-strike-lightweight-repair-receipt.json",
        )
        strike_repair_receipt = write_test_provider_receipt(
            strike_target, "test-strike-repair-receipt.json",
        )
        strike_failure_receipt = write_test_provider_receipt(
            strike_target, "test-strike-failure-receipt.json",
        )
        strike_guardrails = strike_target / "project-guardrails.md"
        strike_guardrails.write_text(
            "# Project Guardrails\n\n"
            "## Required project facts\n\n"
            "- Product and users: Disposable three-strike lifecycle fixture.\n"
            "- Technology and architecture: Installed Python workflow controls and JSON state.\n"
            "- Writable and read-only areas: The temporary fixture is writable; external paths are read-only.\n"
            "- Security, privacy, compliance and performance red lines: No credentials or external effects.\n"
            "- Build, test and lint commands: Run the template lifecycle self-test.\n"
            "- Deployment authority and rollback owner: No deployment; the fixture owner rolls back.\n",
            encoding="utf-8",
        )
        run(
            sys.executable, ".agent/scripts/agentctl.py", "project-init",
            "--guardrails-file", strike_guardrails.name, cwd=strike_target,
        )
        run(
            sys.executable, ".agent/scripts/agentctl.py", "start", "--model", "provider-neutral/model.fixture",
            "--title", "real three-strike recovery", "--mode", "standard",
            "--environment", "local", "--task-type", "maintenance",
            "--complexity", "bounded", "--files", "3", cwd=strike_target,
        )
        strike_contract = strike_target / ".agent/state/REQUIREMENT_CONTRACT.md"
        strike_contract.write_text(
            "# Requirement Contract\n\n"
            "- Goal: Verify the real three-strike recovery exit.\n"
            "- Users: Template lifecycle maintainers.\n"
            "- Success: resolve-failure commits through real contexttx.\n"
            "- In scope: Disposable local workflow state.\n"
            "- Out of scope: External effects.\n"
            "- Constraints: Remain local and reversible.\n"
            "- Data and permissions: No credentials or external data.\n"
            "- Target environment: local\n"
            "- Context transport: native\n"
            "- Acceptance: Context authorization records resolve-failure.\n"
            "- Provenance: template lifecycle fixture\n"
            "- Production provider target: none\n"
            "- Human decisions: user:real-three-strike\n"
            "- Clarified: true\n",
            encoding="utf-8",
        )
        run(
            sys.executable, ".agent/scripts/agentctl.py", "approve-requirements",
            "--source", "user:real-three-strike",
            "--human-decision-receipt", str(strike_requirement_receipt.relative_to(strike_target)),
            cwd=strike_target,
        )
        run(
            sys.executable, ".agent/scripts/templatectl.py", "route",
            cwd=strike_target,
        )
        strike_task_path = strike_target / ".agent/state/TASK.json"
        strike_task = json.loads(strike_task_path.read_text(encoding="utf-8"))
        lightweight_signature = hashlib.sha256(
            b"REAL-LIGHTWEIGHT-SECOND|implementation"
        ).hexdigest()
        strike_task.update({
            "current_node": 7,
            "accepted_nodes": [0, 1, 2, 3, 4, 5, 6],
            "status": "in_progress",
            "phase": "acceptance",
            "next_action": "exercise the lightweight second-failure return",
            "failure_ledger": {lightweight_signature: 1},
            "rollback_ledger": [],
        })
        strike_task_path.write_text(
            json.dumps(strike_task, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        lightweight_estimate = json.loads(
            (strike_target / ".agent/state/CONTEXT.json").read_text(encoding="utf-8")
        )["usage_freshness"]["estimated_tokens"]
        run(
            sys.executable, ".agent/scripts/contextctl.py", "repair", "--reset",
            "--reason", "prepare-real-lightweight-second-failure",
            "--summary", "bind the projected second-failure fixture",
            "--source-tokens", str(lightweight_estimate), expected=1, cwd=strike_target,
        )
        run(
            sys.executable, ".agent/scripts/contextctl.py", "approve-repair",
            "--source", "user:real-three-strike",
            "--human-decision-receipt", str(strike_lightweight_repair_receipt.relative_to(strike_target)),
            cwd=strike_target,
        )
        run(
            sys.executable, ".agent/scripts/workflowctl.py", "return-node",
            "--from-node", "7", "--to", "6",
            "--issue-id", "REAL-LIGHTWEIGHT-SECOND",
            "--cause-category", "implementation",
            "--subtask", "real projected transaction",
            "--root-cause", "same projected defect",
            "--change", "rebuild through the node-six projection",
            cwd=strike_target,
        )
        lightweight_returned = json.loads(strike_task_path.read_text(encoding="utf-8"))
        lightweight_context = json.loads(
            (strike_target / ".agent/state/CONTEXT.json").read_text(encoding="utf-8")
        )
        if (
            lightweight_returned.get("current_node") != 2
            or lightweight_returned.get("accepted_nodes") != [0, 1]
            or lightweight_returned.get("rollback_ledger", [{}])[-1].get("to") != 2
            or lightweight_context.get("checkpoint", {})
            .get("transition_authorization", {}).get("operation") != "return-node"
        ):
            raise SystemExit(
                "real standard-lightweight second failure did not return to rebuildable node 2"
            )

        strike_task = lightweight_returned
        strike_task.update({
            "current_node": 5,
            "accepted_nodes": [0, 1, 2, 3, 4],
            "status": "in_progress",
            "phase": "testing",
            "next_action": "exercise repeated root-cause returns",
            "failure_ledger": {},
            "rollback_ledger": [],
        })
        strike_task_path.write_text(
            json.dumps(strike_task, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        strike_estimate = json.loads(
            (strike_target / ".agent/state/CONTEXT.json").read_text(encoding="utf-8")
        )["usage_freshness"]["estimated_tokens"]
        run(
            sys.executable, ".agent/scripts/contextctl.py", "repair", "--reset",
            "--reason", "prepare-real-three-strike",
            "--summary", "bind the real repeated-failure fixture",
            "--source-tokens", str(strike_estimate), expected=1, cwd=strike_target,
        )
        run(
            sys.executable, ".agent/scripts/contextctl.py", "approve-repair",
            "--source", "user:real-three-strike",
            "--human-decision-receipt", str(strike_repair_receipt.relative_to(strike_target)),
            cwd=strike_target,
        )
        for from_node, to_node in ((5, 4), (4, 3), (3, 2)):
            run(
                sys.executable, ".agent/scripts/workflowctl.py", "return-node",
                "--from-node", str(from_node), "--to", str(to_node),
                "--issue-id", "REAL-STRIKE", "--cause-category", "implementation",
                "--subtask", "real transaction", "--root-cause", "same defect",
                "--change", "retry after root-cause repair", cwd=strike_target,
            )
        escalated = json.loads(strike_task_path.read_text(encoding="utf-8"))
        if (
            escalated.get("status") != "waiting_human"
            or "three times" not in str(escalated.get("next_action"))
        ):
            raise SystemExit("real three-strike lifecycle did not reach its human decision gate")
        run(
            sys.executable, ".agent/scripts/workflowctl.py", "resolve-failure",
            "--source", "user:real-three-strike",
            "--human-decision-receipt", str(strike_failure_receipt.relative_to(strike_target)),
            cwd=strike_target,
        )
        resolved = json.loads(strike_task_path.read_text(encoding="utf-8"))
        resolved_context = json.loads(
            (strike_target / ".agent/state/CONTEXT.json").read_text(encoding="utf-8")
        )
        authorization = resolved_context.get("checkpoint", {}).get("transition_authorization", {})
        if (
            "failure-escalation" not in resolved.get("gate_approvals", {})
            or authorization.get("mutator") != "workflowctl"
            or authorization.get("operation") != "resolve-failure"
            or resolved.get("status") != "in_progress"
            or resolved.get("failure_escalation", {}).get("state") != "resolved"
        ):
            raise SystemExit("real resolve-failure did not commit its bound context transition")
        resumed = run(
            sys.executable, ".agent/scripts/workflowctl.py", "route-resume",
            cwd=strike_target,
        )
        resumed_receipt = json.loads(resumed.stdout)
        if (
            resumed_receipt.get("action") == "waiting_human"
            or resumed_receipt.get("control") == "human-decision-required"
        ):
            raise SystemExit("resolved three-strike recovery remained stuck at waiting_human")

        strike_change = strike_target / "real-three-strike-change.txt"
        strike_change.write_text("repaired three-strike candidate\n", encoding="utf-8")
        strike_check = run(
            sys.executable, ".agent/scripts/contextctl.py", "check", cwd=strike_target,
        )
        strike_check_output = strike_target / ".agent/state/evidence/real-three-strike-check.txt"
        strike_check_output.parent.mkdir(parents=True, exist_ok=True)
        strike_check_output.write_text(strike_check.stdout, encoding="utf-8")
        strike_variables = {
            "mode": "standard",
            "requirement_contract_sha256": resolved["requirement_contract_sha256"],
            "mode_appropriate_implementer_agent_id": None,
            "projection": [2, 3, 4, 5, 6],
            "change_receipts":[receipt(strike_target,strike_change)],
            "candidate_snapshot_receipts":[{**receipt(strike_target,strike_change),"mode":420}],
            "check_receipts": [{
                "id": "resolved-three-strike-context",
                "command": [sys.executable, ".agent/scripts/contextctl.py", "check"],
                "exit_code": 0,
                "output": receipt(strike_target, strike_check_output),
            }],
            "cleanup_receipt": {
                "runtime_state": receipt(strike_target, strike_target / ".agent/state/runtime.json"),
                "residual": {"processes": 0, "docker_projects": 0, "ports": 0},
            },
            "scope_summary": "advance the repaired real three-strike lifecycle",
        }
        strike_render = [
            sys.executable, ".agent/scripts/templatectl.py", "render",
            "--id", "node-implementation",
            "--output", ".agent/state/artifacts/06-implementation.json",
        ]
        for key, value in strike_variables.items():
            rendered = (
                json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                if not isinstance(value, str) else value
            )
            strike_render.extend(["--var", f"{key}={rendered}"])
        run(*strike_render, cwd=strike_target)
        run(
            sys.executable, ".agent/scripts/workflowctl.py", "advance",
            "--node", "6", "--artifact", ".agent/state/artifacts/06-implementation.json",
            cwd=strike_target,
        )
        advanced = json.loads(strike_task_path.read_text(encoding="utf-8"))
        if (
            advanced.get("current_node") != 7
            or "failure_escalation" in advanced
            or "failure-escalation" in advanced.get("gate_approvals", {})
        ):
            raise SystemExit("first successful advance did not consume the resolved failure escalation")
        run(sys.executable, ".agent/scripts/contextctl.py", "check", cwd=strike_target)
        run(sys.executable, ".agent/scripts/workflowctl.py", "validate", cwd=strike_target)

        # Updating an active current-version project must not preserve a stale
        # generation-bound built-in Skill snapshot. Rebind the activation and
        # its context/stage atomically against the new managed bytes.
        stale_activation_target=workspace/"active-stale-builtin-activation"
        run(sys.executable,str(installer),str(stale_activation_target),"--project-name","active-stale-builtin-activation")
        stale_guardrails=stale_activation_target/"project-guardrails.md"
        stale_guardrails.write_text("# Project Guardrails\n\n## Required project facts\n\n"
            "- Product and users: Disposable active installer update fixture.\n"
            "- Technology and architecture: Python workflow controls and local JSON state.\n"
            "- Writable and read-only areas: The temporary fixture is writable; external paths are read-only.\n"
            "- Security, privacy, compliance and performance red lines: No credentials or external effects.\n"
            "- Build, test and lint commands: Run the template lifecycle self-test.\n"
            "- Deployment authority and rollback owner: No deployment; the fixture owner rolls back.\n",encoding="utf-8")
        run(sys.executable,".agent/scripts/agentctl.py","project-init","--guardrails-file",stale_guardrails.name,cwd=stale_activation_target)
        run(sys.executable,".agent/scripts/agentctl.py","start","--model","vendor-alpha/model.one",
            "--title","active stale built-in update fixture",cwd=stale_activation_target)
        stale_manifest_path=stale_activation_target/".agent/.workflow-manifest.json"
        stale_manifest=json.loads(stale_manifest_path.read_text(encoding="utf-8"))
        changed_relative="skills/clarify-task/SKILL.md"; changed_path=stale_activation_target/".agent"/changed_relative
        changed_path.write_bytes(changed_path.read_bytes()+b"\n<!-- prior released built-in fixture -->\n")
        stale_manifest["agent_files"][changed_relative]=hashlib.sha256(changed_path.read_bytes()).hexdigest()
        manifest_payload={"schema":stale_manifest["schema"],"version":stale_manifest["version"],
            "migration_version":stale_manifest["migration_version"],"agent_root_mode":stale_manifest["agent_root_mode"],
            "agent_files":stale_manifest["agent_files"],"pxpipe":stale_manifest["pxpipe"],
            "agents_bootstrap_sha256":stale_manifest["agents_bootstrap"]["sha256"],
            "claude_bootstrap_sha256":stale_manifest["claude_bootstrap"]["sha256"],"agent_modes":stale_manifest["agent_modes"]}
        stale_manifest["source_tree_sha256"]=canonical_sha256(manifest_payload)
        stale_manifest_path.write_text(json.dumps(stale_manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        rebind_fixture="""
import copy,json,sys
sys.path.insert(0,'.agent/scripts')
import agentctl
before=json.loads(agentctl.TASK_PATH.read_text(encoding='utf-8'))
verification,lock,captured=agentctl.capture_dynamic_skill_activation()
receipt,data=agentctl.build_task_skill_activation(before['task_generation_id'],verification,lock,captured)
after=copy.deepcopy(before); after['skill_activation']=receipt
agentctl.sync_context('prior-release-builtin-fixture',before_task=before,after_task=after,operation='start',
    summary='bind prior released built-in Skill bytes',side_effects=((agentctl.AGENT_DIR/'state/SKILL_ACTIVATION.json',data),))
"""
        run(sys.executable,"-B","-c",rebind_fixture,cwd=stale_activation_target)
        run(sys.executable,".agent/scripts/agentctl.py","validate",cwd=stale_activation_target)
        old_activation=(stale_activation_target/".agent/state/SKILL_ACTIVATION.json").read_bytes()
        run(sys.executable,str(installer),str(stale_activation_target),"--update")
        run(sys.executable,".agent/scripts/agentctl.py","validate",cwd=stale_activation_target)
        new_activation=(stale_activation_target/".agent/state/SKILL_ACTIVATION.json").read_bytes()
        if (new_activation==old_activation or changed_path.read_bytes()!=(source/".agent"/changed_relative).read_bytes()
                or json.loads(new_activation)["task_generation_id"]!=json.loads(old_activation)["task_generation_id"]):
            raise SystemExit("active update retained stale built-in activation or broke generation binding")

        # 3.1.38/migration 31 was never a released install-manifest tuple.
        # Strict migration authority rejects it before touching project state;
        # the oldest accepted predecessor is 3.1.40/migration 32.
        unreleased = workspace / "unreleased-migration31"
        run(sys.executable, str(installer), str(unreleased), "--project-name", "unreleased-migration31")
        unreleased_config_path = unreleased / ".agent/config.json"
        unreleased_config = json.loads(unreleased_config_path.read_text(encoding="utf-8"))
        unreleased_config["context"]["max_capsule_tokens"]["fast"] = 600
        unreleased_config_path.write_text(
            json.dumps(unreleased_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        unreleased_manifest_path = unreleased / ".agent/.workflow-manifest.json"
        unreleased_manifest = json.loads(unreleased_manifest_path.read_text(encoding="utf-8"))
        unreleased_manifest["version"] = "3.1.38"
        unreleased_manifest["migration_version"] = 31
        unreleased_manifest_path.write_text(
            json.dumps(unreleased_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        unreleased_config_before = unreleased_config_path.read_bytes()
        unreleased_manifest_before = unreleased_manifest_path.read_bytes()
        rejected_unreleased = subprocess.run(
            [sys.executable, str(installer), str(unreleased), "--update"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
        )
        if (
            rejected_unreleased.returncode == 0
            or "not a supported release" not in rejected_unreleased.stdout
            or unreleased_config_path.read_bytes() != unreleased_config_before
            or unreleased_manifest_path.read_bytes() != unreleased_manifest_before
        ):
            raise SystemExit("unreleased migration 31 tuple was accepted or mutated")

        rejected_v2=workspace/"rejected-v2-manifest"
        run(sys.executable,str(installer),str(rejected_v2),"--project-name","fixture-rejected-v2")
        rejected_v2_manifest_path=rejected_v2/".agent/.workflow-manifest.json"
        rejected_v2_manifest=json.loads(rejected_v2_manifest_path.read_text(encoding="utf-8"))
        rejected_v2_manifest["schema"]="agent-workflow-install/v2"
        rejected_v2_manifest["version"]="3.1.40"; rejected_v2_manifest["migration_version"]=32
        rejected_v2_manifest_path.write_text(json.dumps(rejected_v2_manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        rejected_v2_before=project_tree_bytes(rejected_v2)
        rejected_v2_result=run(sys.executable,str(installer),str(rejected_v2),"--update",expected=1)
        if "invalid workflow install manifest" not in rejected_v2_result.stdout or project_tree_bytes(rejected_v2)!=rejected_v2_before:
            raise SystemExit("v2 manifest schema was accepted or mutated")

        fresh_agents_before=(target/".agent/state/agents.json").read_bytes()
        (target / ".agent/workflows/METHODOLOGY.md").unlink()
        run(sys.executable, str(installer), str(target), "--update")
        run(sys.executable, ".agent/scripts/agentctl.py", "validate", cwd=target)
        run(sys.executable, str(installer), str(target), "--check")
        if (target/".agent/state/agents.json").read_bytes()!=fresh_agents_before:
            raise SystemExit("idempotent v9 update rewrote the Agent ledger")
        idle_context_before=(target/".agent/state/CONTEXT.json").read_bytes()
        idle_stage_before=(target/".agent/state/STAGE_INDEX.md").read_bytes()
        run(sys.executable, str(installer), str(target), "--update")
        if (
            (target/".agent/state/CONTEXT.json").read_bytes()!=idle_context_before
            or (target/".agent/state/STAGE_INDEX.md").read_bytes()!=idle_stage_before
        ):
            raise SystemExit("write-free update reseeded the idle CONTEXT/STAGE_INDEX bytes")
        run(sys.executable, ".agent/scripts/contextctl.py", "check", cwd=target)

        # v5/3.1.29/migration-26 was never released. Even a history-free
        # v8 ledger cannot use an invented manifest tuple to enter migrations.
        v8 = workspace / "empty-v8-unreleased"
        run(sys.executable,str(installer),str(v8),"--project-name","fixture-empty-v8-unreleased")
        v8_agents_path=v8/".agent/state/agents.json"; v8_agents=json.loads(v8_agents_path.read_text(encoding="utf-8"))
        v8_agents["schema"]="agent-team/v8"; v8_agents.pop("token_accounting")
        v8_agents_path.write_text(json.dumps(v8_agents,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        v8_manifest_path=v8/".agent/.workflow-manifest.json"; v8_manifest=json.loads(v8_manifest_path.read_text(encoding="utf-8"))
        v8_manifest["version"]="3.1.29"; v8_manifest["migration_version"]=26
        v8_manifest_path.write_text(json.dumps(v8_manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        v8_before=project_tree_bytes(v8)
        rejected_v8=run(sys.executable,str(installer),str(v8),"--update",expected=1)
        if "not a supported release" not in rejected_v8.stdout or project_tree_bytes(v8)!=v8_before:
            raise SystemExit("unreleased migration-26 tuple was accepted or mutated")

        migration28 = workspace / "migration28-active-context"
        run(sys.executable, str(installer), str(migration28), "--project-name", "fixture-migration28")
        initialize_migration_fixture(migration28,"migration")
        run(
            sys.executable, ".agent/scripts/agentctl.py", "start", "--model", "provider-neutral/model.fixture",
            "--title", "active context rebind fixture", "--mode", "standard",
            "--environment", "local", "--files", "3", cwd=migration28,
        )
        run(
            sys.executable, ".agent/scripts/contextctl.py", "sync",
            "--source-tokens", "8000", "--reason", "migration-34-preservation-fixture",
            "--summary", "preserve complete active context across migration",
            "--source", "fixture:migration-34", "--fact", "context fact must survive",
            "--file", ".agent/state/TASK.json", "--evidence", ".agent/state/TASK.json",
            "--risk", "context risk must survive", cwd=migration28,
        )
        # Entering the awaiting state requires a configured host compaction
        # observer adapter (fail-closed entry), which an installed project does
        # not have. Model the awaiting state directly so the migration-34
        # preservation assertion stays independent of a host adapter.
        run(
            sys.executable, "-c", (
                "import json,sys;sys.path.insert(0,'.agent/scripts');import contextctl;"
                "p='.agent/state/CONTEXT.json';v=json.load(open(p));"
                "v['host_compaction']={'schema':'agent-host-compaction-state/v1',"
                "'state':'awaiting_host_compaction','history':['handoff_written'],'receipt':None};"
                "comp=v['compaction'];est=contextctl.normalized_token_estimate(v);"
                "comp['capsule_estimated_tokens']=est;"
                "comp['capsule_reduction_tokens']=int(comp['source_estimated_tokens'])-est;"
                "comp['tokens_removed']=0;"
                "comp['compression_ratio']=round(int(comp['source_estimated_tokens'])/max(est,1),2);"
                "v['integrity']['content_sha256']='0'*64;"
                "v['integrity']['content_sha256']=contextctl.content_sha256(v);"
                "open(p,'w').write(json.dumps(v,ensure_ascii=False,indent=2)+'\\n')"
            ),
            cwd=migration28,
        )
        context_path = migration28 / ".agent/state/CONTEXT.json"
        context_bytes_before = context_path.read_bytes()
        context_before = json.loads(context_path.read_text(encoding="utf-8"))
        task_bytes_before = (migration28 / ".agent/state/TASK.json").read_bytes()
        migration28_manifest_path = migration28 / ".agent/.workflow-manifest.json"
        migration28_manifest = released_legacy_manifest(
            json.loads(migration28_manifest_path.read_text(encoding="utf-8")),
            "agent-workflow-install/v1","3.1.40",32,
        )
        migration28_manifest_path.write_text(
            json.dumps(migration28_manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        run(sys.executable, str(installer), str(migration28), "--update")
        context_after = json.loads(context_path.read_text(encoding="utf-8"))
        before_sequence = context_before.get("checkpoint", {}).get("sequence", 0)
        after_sequence = context_after.get("checkpoint", {}).get("sequence")
        if after_sequence != before_sequence + 1:
            raise SystemExit(
                "migration 34 did not rebind the active context capsule: "
                f"{before_sequence} -> {after_sequence}"
            )
        task_after=json.loads((migration28/".agent/state/TASK.json").read_text(encoding="utf-8"))
        task_before=json.loads(task_bytes_before)
        activation_path=migration28/".agent/state/SKILL_ACTIVATION.json"; activation_raw=activation_path.read_bytes()
        activation=json.loads(activation_raw); activation_pointer=task_after.get("skill_activation",{})
        if ((migration28/".agent/state/TASK.json").read_bytes()==task_bytes_before
                or task_after.get("task_generation_id")==task_before.get("task_generation_id")
                or not str(task_after.get("task_generation_id","")).startswith("migration-")
                or task_after.get("decision_policy_version")!=1 or task_after.get("gate_approvals")!={}
                or task_after.get("requirements_clarified") is not False or task_after.get("status")!="waiting_human"
                or task_after.get("current_node")!=1 or task_after.get("accepted_nodes")!=[0]
                or activation.get("task_generation_id")!=task_after.get("task_generation_id")
                or activation_pointer.get("sha256")!=hashlib.sha256(activation_raw).hexdigest()
                or activation_pointer.get("bytes")!=len(activation_raw)):
            raise SystemExit("legacy migration did not rotate generation, revoke unbound authority, and reseal Skill activation")
        for field in ("confirmed_facts", "changed_files", "evidence", "open_risks", "host_compaction"):
            if context_after.get(field) != context_before.get(field):
                raise SystemExit(f"migration 34 lost active context field: {field}")
        if (
            context_after.get("checkpoint", {}).get("previous_sha256")
            != hashlib.sha256(context_bytes_before).hexdigest()
            or context_after.get("checkpoint", {}).get("previous_task_invariant_sha256")
            != context_before.get("task_invariant_sha256")
            or context_after.get("checkpoint", {}).get("reason") != "migration-34-final-state-rebind"
            or context_after.get("compaction", {}).get("source")
            != "installer-verified-context-efficiency-migration"
        ):
            raise SystemExit("migration 34 context checkpoint linkage or provenance is invalid")
        run(sys.executable, ".agent/scripts/contextctl.py", "check", cwd=migration28)
        run(sys.executable, ".agent/scripts/workflowctl.py", "validate", cwd=migration28)

        # Migration 35 raises the exact old routing/token defaults
        # (6000/20000/40000) to 12000/24000/48000 and migration 36 then lifts
        # them to the recalibrated 16000/48000/96000 without disturbing a
        # project-owned custom budget.
        migration35 = workspace / "migration35-token-budgets"
        run(sys.executable, str(installer), str(migration35), "--project-name", "fixture-migration35")
        m35_config_path = migration35 / ".agent/config.json"
        m35_config = json.loads(m35_config_path.read_text(encoding="utf-8"))
        for mode, budget in (("fast", 6000), ("standard", 20000), ("release", 40000)):
            m35_config["routing"]["modes"][mode]["token_budget"] = budget
        m35_config_path.write_text(json.dumps(m35_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        m35_task_path = migration35 / ".agent/state/TASK.json"
        m35_task = json.loads(m35_task_path.read_text(encoding="utf-8"))
        m35_task["token_budget"] = 20000
        m35_task_path.write_text(json.dumps(m35_task, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        m35_agents_path = migration35 / ".agent/state/agents.json"
        m35_agents = json.loads(m35_agents_path.read_text(encoding="utf-8"))
        m35_agents["token_accounting"]["token_budget"] = 20000
        m35_agents_path.write_text(json.dumps(m35_agents, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        m35_manifest_path = migration35 / ".agent/.workflow-manifest.json"
        m35_manifest = released_legacy_manifest(
            json.loads(m35_manifest_path.read_text(encoding="utf-8")),
            "agent-workflow-install/v3","3.1.41",34,
        )
        m35_manifest_path.write_text(json.dumps(m35_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        run(sys.executable, str(installer), str(migration35), "--update")
        m35_migrated = json.loads(m35_config_path.read_text(encoding="utf-8"))
        if {mode: m35_migrated["routing"]["modes"][mode]["token_budget"] for mode in ("fast", "standard", "release")} != {
            "fast": 16000, "standard": 48000, "release": 96000,
        }:
            raise SystemExit("migrations 35/36 did not raise the exact old routing token budgets")
        m35_task_after = json.loads(m35_task_path.read_text(encoding="utf-8"))
        if m35_task_after["token_budget"] != 48000:
            raise SystemExit("migrations 35/36 did not rebind the active standard task budget")
        run(sys.executable, ".agent/scripts/agentctl.py", "validate", cwd=migration35)

        custom35 = workspace / "migration35-custom-budgets"
        run(sys.executable, str(installer), str(custom35), "--project-name", "fixture-migration35-custom")
        custom35_config_path = custom35 / ".agent/config.json"
        custom35_config = json.loads(custom35_config_path.read_text(encoding="utf-8"))
        custom35_config["routing"]["modes"]["fast"]["token_budget"] = 11000
        custom35_config_path.write_text(json.dumps(custom35_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        custom35_manifest_path = custom35 / ".agent/.workflow-manifest.json"
        custom35_manifest = released_legacy_manifest(
            json.loads(custom35_manifest_path.read_text(encoding="utf-8")),
            "agent-workflow-install/v3","3.1.41",34,
        )
        custom35_manifest_path.write_text(json.dumps(custom35_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        run(sys.executable, str(installer), str(custom35), "--update")
        custom35_migrated = json.loads(custom35_config_path.read_text(encoding="utf-8"))
        if custom35_migrated["routing"]["modes"]["fast"]["token_budget"] != 11000:
            raise SystemExit("migrations 35/36 overwrote a project-owned custom fast token budget")

        # Migration 36 carries CUSTOMIZED legacy transition-increment values
        # into the per-transition increment key instead of silently
        # discarding them; only the legacy seed constants are recalibrated
        # away (covered by the migration-22 fixture above).  The alias's true
        # historical semantic was the per-transition increment, so each
        # carried value is clamped to the sane range [50, 1000]
        # (250 -> 250, 1200 -> 1000, 1500 -> 1000) and the honest per-turn
        # overhead is never rewritten from the alias.
        tuned36 = workspace / "migration36-tuned-increment"
        run(sys.executable, str(installer), str(tuned36), "--project-name", "fixture-migration36-tuned")
        tuned36_config_path = tuned36 / ".agent/config.json"
        tuned36_config = json.loads(tuned36_config_path.read_text(encoding="utf-8"))
        tuned36_config["context"].pop("estimated_turn_overhead_tokens", None)
        tuned36_config["context"]["automatic_transition_token_increment"] = {
            "fast": 250, "standard": 1200, "release": 1500,
        }
        tuned36_config_path.write_text(json.dumps(tuned36_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tuned36_manifest_path = tuned36 / ".agent/.workflow-manifest.json"
        tuned36_manifest = released_legacy_manifest(
            json.loads(tuned36_manifest_path.read_text(encoding="utf-8")),
            "agent-workflow-install/v3","3.1.41",34,
        )
        tuned36_manifest_path.write_text(json.dumps(tuned36_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        run(sys.executable, str(installer), str(tuned36), "--update")
        tuned36_migrated = json.loads(tuned36_config_path.read_text(encoding="utf-8"))
        if (
            tuned36_migrated["context"].get("transition_token_increment")
            != {"fast": 250, "standard": 1000, "release": 1000}
            or tuned36_migrated["context"].get("estimated_turn_overhead_tokens")
            != {"fast": 2000, "standard": 3000, "release": 4000}
            or "automatic_transition_token_increment" in tuned36_migrated["context"]
        ):
            raise SystemExit("migration 36 discarded a project's customized legacy transition-increment values")

        # A project that already tuned the per-turn overhead key keeps it:
        # the alias carry targets the transition-increment key only, so the
        # two policies stay independent and the alias is still retired.
        kept36 = workspace / "migration36-tuned-overhead"
        run(sys.executable, str(installer), str(kept36), "--project-name", "fixture-migration36-kept")
        kept36_config_path = kept36 / ".agent/config.json"
        kept36_config = json.loads(kept36_config_path.read_text(encoding="utf-8"))
        kept36_config["context"]["estimated_turn_overhead_tokens"] = {
            "fast": 2100, "standard": 3100, "release": 4100,
        }
        kept36_config["context"]["automatic_transition_token_increment"] = {
            "fast": 250, "standard": 350, "release": 600,
        }
        kept36_config_path.write_text(json.dumps(kept36_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        kept36_manifest_path = kept36 / ".agent/.workflow-manifest.json"
        kept36_manifest = released_legacy_manifest(
            json.loads(kept36_manifest_path.read_text(encoding="utf-8")),
            "agent-workflow-install/v3","3.1.41",34,
        )
        kept36_manifest_path.write_text(json.dumps(kept36_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        run(sys.executable, str(installer), str(kept36), "--update")
        kept36_migrated = json.loads(kept36_config_path.read_text(encoding="utf-8"))
        if (
            kept36_migrated["context"].get("estimated_turn_overhead_tokens")
            != {"fast": 2100, "standard": 3100, "release": 4100}
            or kept36_migrated["context"].get("transition_token_increment")
            != {"fast": 250, "standard": 350, "release": 600}
            or "automatic_transition_token_increment" in kept36_migrated["context"]
        ):
            raise SystemExit("migration 36 overwrote a project-owned estimated_turn_overhead_tokens policy")

        # Migration 37 fills the honest per-transition increment for projects
        # that already passed migration 36 (alias long retired) and removes
        # nothing else from the project config.
        filled37 = workspace / "migration37-fill-increment"
        run(sys.executable, str(installer), str(filled37), "--project-name", "fixture-migration37-fill")
        filled37_config_path = filled37 / ".agent/config.json"
        filled37_before = json.loads(filled37_config_path.read_text(encoding="utf-8"))
        filled37_before["context"].pop("transition_token_increment", None)
        filled37_config_path.write_text(
            json.dumps(filled37_before, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        filled37_manifest_path = filled37 / ".agent/.workflow-manifest.json"
        filled37_manifest = released_legacy_manifest(
            json.loads(filled37_manifest_path.read_text(encoding="utf-8")),
            "agent-workflow-install/v4","3.1.43",36,
        )
        filled37_manifest_path.write_text(json.dumps(filled37_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        run(sys.executable, str(installer), str(filled37), "--update")
        filled37_after = json.loads(filled37_config_path.read_text(encoding="utf-8"))
        if filled37_after["context"].get("transition_token_increment") != {
            "fast": 200, "standard": 400, "release": 800,
        }:
            raise SystemExit("migration 37 did not fill the honest per-transition increment defaults")
        filled37_after["context"].pop("transition_token_increment")
        if filled37_after != filled37_before:
            raise SystemExit("migration 37 mutated project config beyond filling transition_token_increment")

        # Starting from released v4/3.1.43/migration-36 executes migration
        # 37 then 38; the already-present invalid map is preserved by 37 and
        # normalized by 38 without inventing the unreleased 3.1.44/37 tuple.
        normalized38 = workspace / "migration38-normalize-increment"
        run(sys.executable, str(installer), str(normalized38), "--project-name", "fixture-migration38-normalize")
        normalized38_config_path = normalized38 / ".agent/config.json"
        normalized38_config = json.loads(normalized38_config_path.read_text(encoding="utf-8"))
        normalized38_config["context"]["transition_token_increment"] = {
            "fast": 900, "standard": 400, "release": 800,
        }
        normalized38_config_path.write_text(
            json.dumps(normalized38_config, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        normalized38_manifest_path = normalized38 / ".agent/.workflow-manifest.json"
        normalized38_manifest = released_legacy_manifest(
            json.loads(normalized38_manifest_path.read_text(encoding="utf-8")),
            "agent-workflow-install/v4","3.1.43",36,
        )
        normalized38_manifest_path.write_text(
            json.dumps(normalized38_manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        run(sys.executable, str(installer), str(normalized38), "--update")
        normalized38_after = json.loads(normalized38_config_path.read_text(encoding="utf-8"))
        if normalized38_after["context"].get("transition_token_increment") != {
            "fast": 900, "standard": 900, "release": 900,
        }:
            raise SystemExit("migration 38 did not repair the v3.1.44 non-monotonic increment")
        run(sys.executable, ".agent/scripts/agentctl.py", "validate", cwd=normalized38)

        # An install from before the budget recalibration that has NOT been
        # migrated still validates: the deprecated transition-increment alias
        # keeps its exact legacy arithmetic (no bootstrap floor, no
        # inherited-turn surcharge), so its old budgets stay inside the
        # fail-closed invariant.
        legacy35 = workspace / "legacy-unmigrated-budgets"
        run(sys.executable, str(installer), str(legacy35), "--project-name", "fixture-legacy35")
        legacy_config_path = legacy35 / ".agent/config.json"
        legacy_config = json.loads(legacy_config_path.read_text(encoding="utf-8"))
        for mode, budget in (("fast", 12000), ("standard", 24000), ("release", 48000)):
            legacy_config["routing"]["modes"][mode]["token_budget"] = budget
        legacy_config["context"].pop("estimated_turn_overhead_tokens", None)
        legacy_config["context"].pop("transition_token_increment", None)
        legacy_config["context"].pop("bootstrap_overhead_tokens", None)
        legacy_config["context"]["automatic_transition_token_increment"] = {
            "fast": 150, "standard": 300, "release": 500,
        }
        legacy_config["agent_control"]["child_system_tool_margin_tokens"] = 1000
        legacy_config_path.write_text(json.dumps(legacy_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        legacy_task_path = legacy35 / ".agent/state/TASK.json"
        legacy_task = json.loads(legacy_task_path.read_text(encoding="utf-8"))
        legacy_task["token_budget"] = 24000
        legacy_task_path.write_text(json.dumps(legacy_task, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        legacy_agents_path = legacy35 / ".agent/state/agents.json"
        legacy_agents = json.loads(legacy_agents_path.read_text(encoding="utf-8"))
        legacy_agents["token_accounting"]["token_budget"] = 24000
        legacy_agents_path.write_text(json.dumps(legacy_agents, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        # Re-seal the idle capsule against the legacy-shaped policy so the
        # fixture is an authentic unmigrated install, not canonical drift.
        run(
            sys.executable, "-c",
            "import argparse,hashlib,json,sys;from pathlib import Path;"
            "sys.path.insert(0,'.agent/scripts');import contextctl;"
            "p=contextctl.CONTEXT_PATH;previous=json.loads(p.read_text());"
            "args=argparse.Namespace(reason='legacy-unmigrated-fixture',summary='pre-recalibration idle state',source='migration-fixture',source_tokens=800,fact=[],file=[],evidence=[],risk=[],resolve_risk=[],transition=False,reset=True);"
            "capsule=contextctl.build_capsule(args,'verified',previous,hashlib.sha256(p.read_bytes()).hexdigest());"
            "contextctl.atomic_json(p,capsule);raise SystemExit(contextctl.validate_context())",
            cwd=legacy35,
        )
        run(sys.executable, ".agent/scripts/agentctl.py", "validate", cwd=legacy35)
        run(sys.executable, ".agent/scripts/contextctl.py", "check", cwd=legacy35)

        # If a template-managed reference was actively loaded under v33, its
        # purpose/phase stay live while migration 34 rebinds the changed bytes.
        loaded33 = workspace / "migration33-loaded-managed-reference"
        run(sys.executable, str(installer), str(loaded33), "--project-name", "fixture-loaded33")
        initialize_migration_fixture(loaded33,"loaded")
        run(
            sys.executable, ".agent/scripts/agentctl.py", "start", "--model", "provider-neutral/model.fixture",
            "--title", "managed reference rebind fixture", "--mode", "standard",
            "--environment", "local", "--files", "3", cwd=loaded33,
        )
        loaded_reference_path = (
            loaded33 / ".agent/skills/manage-agent-team/references/coordination-contract.md"
        )
        synthetic_v33_bytes = loaded_reference_path.read_bytes() + b"\n<!-- migration-33 fixture -->\n"
        loaded_reference_path.write_bytes(synthetic_v33_bytes)
        run(
            sys.executable, ".agent/scripts/agentctl.py", "reference-load",
            "--path", ".agent/skills/manage-agent-team/references/coordination-contract.md",
            "--purpose", "preserve managed coordination authority", cwd=loaded33,
        )
        (loaded33 / "project-owned-reference.md").write_text(
            "project-owned reference bytes\n", encoding="utf-8",
        )
        run(
            sys.executable, ".agent/scripts/agentctl.py", "reference-load",
            "--path", "project-owned-reference.md", "--purpose", "preserve project-owned metadata",
            cwd=loaded33,
        )
        loaded_task_before = json.loads((loaded33 / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        loaded_record_before = next(
            item for item in loaded_task_before["loaded_references"]
            if item["path"] == ".agent/skills/manage-agent-team/references/coordination-contract.md"
        )
        project_record_before = next(
            item for item in loaded_task_before["loaded_references"]
            if item["path"] == "project-owned-reference.md"
        )
        loaded_manifest_path = loaded33 / ".agent/.workflow-manifest.json"
        loaded_current = json.loads(loaded_manifest_path.read_text(encoding="utf-8"))
        loaded_current["agent_files"]["skills/manage-agent-team/references/coordination-contract.md"] = hashlib.sha256(synthetic_v33_bytes).hexdigest()
        loaded_manifest = released_legacy_manifest(
            loaded_current,"agent-workflow-install/v1","3.1.40",32,
        )
        loaded_manifest_path.write_text(
            json.dumps(loaded_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        run(sys.executable, str(installer), str(loaded33), "--update")
        loaded_task = json.loads((loaded33 / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        loaded_matches = [
            item for item in loaded_task.get("loaded_references", [])
            if item.get("path") == ".agent/skills/manage-agent-team/references/coordination-contract.md"
        ]
        current_reference_bytes = loaded_reference_path.read_bytes()
        project_record_after = next(
            item for item in loaded_task["loaded_references"]
            if item["path"] == "project-owned-reference.md"
        )
        if (
            len(loaded_matches) != 1
            or loaded_matches[0].get("purpose") != loaded_record_before.get("purpose")
            or loaded_matches[0].get("phase") != loaded_record_before.get("phase")
            or loaded_matches[0].get("sha256") != hashlib.sha256(current_reference_bytes).hexdigest()
            or loaded_matches[0].get("bytes") != len(current_reference_bytes)
            or loaded_matches[0].get("estimated_tokens") != (len(current_reference_bytes) + 3) // 4
            or project_record_after != project_record_before
        ):
            raise SystemExit("migration 34 did not rebind the active managed reference exactly")
        run(sys.executable, ".agent/scripts/agentctl.py", "validate", cwd=loaded33)
        run(sys.executable, ".agent/scripts/contextctl.py", "check", cwd=loaded33)

        # Migration 34 must not turn a merely self-consistent capsule into a
        # verified checkpoint when it has drifted from canonical TASK state.
        drifted33 = workspace / "migration33-drifted-active-context"
        run(sys.executable, str(installer), str(drifted33), "--project-name", "fixture-migration33")
        initialize_migration_fixture(drifted33,"drifted")
        run(
            sys.executable, ".agent/scripts/agentctl.py", "start", "--model", "provider-neutral/model.fixture",
            "--title", "migration 33 drift rejection fixture", "--mode", "standard",
            "--environment", "local", "--files", "3", cwd=drifted33,
        )
        drifted_context_path = drifted33 / ".agent/state/CONTEXT.json"
        drifted_context = json.loads(drifted_context_path.read_text(encoding="utf-8"))
        drifted_context["task_title"] = "self-consistent but canonically drifted title"
        hash_input = json.loads(json.dumps(drifted_context))
        hash_input["integrity"]["content_sha256"] = "0" * 64
        drifted_context["integrity"]["content_sha256"] = hashlib.sha256(
            json.dumps(hash_input, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        drifted_context_path.write_text(
            json.dumps(drifted_context, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        drifted_manifest_path = drifted33 / ".agent/.workflow-manifest.json"
        drifted_manifest = released_legacy_manifest(
            json.loads(drifted_manifest_path.read_text(encoding="utf-8")),
            "agent-workflow-install/v1","3.1.40",32,
        )
        drifted_manifest_path.write_text(
            json.dumps(drifted_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        drifted_before = project_tree_bytes(drifted33)
        rejected33 = subprocess.run(
            [sys.executable, str(installer), str(drifted33), "--update"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
        )
        if (
            rejected33.returncode == 0
            or "active context has drift or corruption" not in rejected33.stdout
            or project_tree_bytes(drifted33) != drifted_before
        ):
            raise SystemExit(
                "migration 34 accepted, obscured, or mutated a self-consistent active context drift"
            )

        # v5/3.1.25/migration-22 was never released. A syntactically rich
        # active predecessor still fails at manifest authority without mutation.
        migration22=workspace/"migration22-unreleased"
        run(sys.executable,str(installer),str(migration22),"--project-name","fixture-migration22-unreleased")
        activate_migration22_hot_state(migration22)
        migration22_manifest_path=migration22/".agent/.workflow-manifest.json"
        migration22_manifest=json.loads(migration22_manifest_path.read_text(encoding="utf-8"))
        migration22_manifest["version"]="3.1.25"; migration22_manifest["migration_version"]=22
        migration22_manifest_path.write_text(json.dumps(migration22_manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        migration22_before=project_tree_bytes(migration22)
        rejected22=run(sys.executable,str(installer),str(migration22),"--update",expected=1)
        if "not a supported release" not in rejected22.stdout or project_tree_bytes(migration22)!=migration22_before:
            raise SystemExit("unreleased migration-22 tuple was accepted or mutated")

        # The immediate 3.1.19/v7 predecessor may migrate only when completely
        # history-free and accompanied by a fresh empty orchestration assertion.
        old_empty_v7=workspace/"old-empty-v7"
        run(sys.executable,str(installer),str(old_empty_v7),"--project-name","fixture-old-empty-v7")
        old_empty_v7_path=downgrade_empty_v8_to_v7(old_empty_v7)
        old_empty_v7_before=old_empty_v7_path.read_bytes(); old_empty_v7_config=old_empty_v7/".agent/config.json"
        old_empty_v7_config_before=old_empty_v7_config.read_bytes()
        rejected_v7=subprocess.run(
            [sys.executable,str(installer),str(old_empty_v7),"--update"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,
        )
        if rejected_v7.returncode==0 or old_empty_v7_path.read_bytes()!=old_empty_v7_before or old_empty_v7_config.read_bytes()!=old_empty_v7_config_before:
            raise SystemExit("migration 19 replaced an empty v7 ledger without a fresh platform-empty assertion")
        for history_field,history_value in {
            "members":[{"id":"legacy-member","status":"completed"}],
            "prepared_dispatches":[{"id":"legacy-preparation"}],
            "capacity_failures":[{"attempt_id":"legacy-capacity"}],
            "replay_runs":[{"run_id":"legacy-run"}],
        }.items():
            historical_v7=workspace/f"historical-v7-{history_field}"
            run(sys.executable,str(installer),str(historical_v7),"--project-name",f"fixture-historical-v7-{history_field}")
            historical_v7_path=downgrade_empty_v8_to_v7(historical_v7)
            historical_v7_value=json.loads(historical_v7_path.read_text(encoding="utf-8")); historical_v7_value[history_field]=history_value
            historical_v7_path.write_text(json.dumps(historical_v7_value,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
            historical_before=historical_v7_path.read_bytes(); historical_config=historical_v7/".agent/config.json"; historical_config_before=historical_config.read_bytes()
            blocked=subprocess.run(
                [sys.executable,str(installer),str(historical_v7),"--update","--agent-platform-snapshot",str(empty_platform_snapshot(workspace/f"historical-v7-{history_field}-platform.json"))],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,
            )
            if blocked.returncode==0 or historical_v7_path.read_bytes()!=historical_before or historical_config.read_bytes()!=historical_config_before:
                raise SystemExit(f"migration 19 invented v8 authority for v7 {history_field} history")

        tampered_observer=workspace/"tampered-v8-observer"
        run(sys.executable,str(installer),str(tampered_observer),"--project-name","fixture-tampered-observer")
        tampered_config=tampered_observer/".agent/config.json"; tampered=json.loads(tampered_config.read_text(encoding="utf-8"))
        tampered["agent_control"]["platform_observer"]["automatic_release_trust"]=True
        tampered_config.write_text(json.dumps(tampered,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        tampered_before=tampered_config.read_bytes(); tampered_agents=tampered_observer/".agent/state/agents.json"; tampered_agents_before=tampered_agents.read_bytes()
        rejected_observer=subprocess.run(
            [sys.executable,str(installer),str(tampered_observer),"--update"],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120,
        )
        if rejected_observer.returncode==0 or tampered_config.read_bytes()!=tampered_before or tampered_agents.read_bytes()!=tampered_agents_before:
            raise SystemExit("tampered v8 platform observer policy was not rejected transactionally")

        for case_name, mutate_policy in (
            (
                "automatic-trust",
                lambda policy: policy.__setitem__("automatic_gate_trust", True),
            ),
            (
                "missing-key",
                lambda policy: policy.pop("human_verification_required"),
            ),
            (
                "invalid-local-release-opt-in",
                lambda policy: policy.__setitem__("allow_current_chat_local_release", "yes"),
            ),
        ):
            tampered_human = workspace / f"tampered-human-decision-{case_name}"
            run(
                sys.executable, str(installer), str(tampered_human),
                "--project-name", f"fixture-tampered-human-{case_name}",
            )
            human_config_path = tampered_human / ".agent/config.json"
            human_config = json.loads(human_config_path.read_text(encoding="utf-8"))
            mutate_policy(human_config["agent_control"]["human_decision_observer"])
            human_config_path.write_text(
                json.dumps(human_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
            )
            human_config_before = human_config_path.read_bytes()
            human_agents_path = tampered_human / ".agent/state/agents.json"
            human_agents_before = human_agents_path.read_bytes()
            rejected_human = subprocess.run(
                [sys.executable, str(installer), str(tampered_human), "--update"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
            )
            if (
                rejected_human.returncode == 0
                or human_config_path.read_bytes() != human_config_before
                or human_agents_path.read_bytes() != human_agents_before
            ):
                raise SystemExit(
                    f"tampered human decision policy ({case_name}) was not rejected transactionally"
                )

        configured_human = workspace / "configured-human-decision-adapter"
        run(
            sys.executable, str(installer), str(configured_human),
            "--project-name", "fixture-configured-human-adapter",
        )
        configured_human_path = configured_human / ".agent/config.json"
        configured_human_config = json.loads(configured_human_path.read_text(encoding="utf-8"))
        configured_human_config["agent_control"]["human_decision_observer"]["signed_adapter"] = "/usr/bin/true"
        configured_human_path.write_text(
            json.dumps(configured_human_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        run(sys.executable, str(installer), str(configured_human), "--update")
        preserved_human_policy = json.loads(
            configured_human_path.read_text(encoding="utf-8")
        )["agent_control"]["human_decision_observer"]
        if preserved_human_policy.get("signed_adapter") != "/usr/bin/true":
            raise SystemExit("configured human decision signed adapter was not preserved")

        # Missing install provenance must never be treated as "current" or adopted by update.
        unmanaged = workspace / "missing-manifest"
        run(sys.executable, str(installer), str(unmanaged), "--project-name", "fixture-missing-manifest")
        manifest = unmanaged / ".agent/.workflow-manifest.json"
        protected = unmanaged / ".agent/workflows/METHODOLOGY.md"
        before = digest(protected)
        manifest.unlink()
        check = subprocess.run(
            [sys.executable, str(installer), str(unmanaged), "--check"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        update = subprocess.run(
            [sys.executable, str(installer), str(unmanaged), "--update"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        if check.returncode == 0 or update.returncode == 0:
            raise SystemExit("missing install manifest was falsely accepted as a managed lifecycle")
        if manifest.exists() or digest(protected) != before:
            raise SystemExit("rejected missing-manifest lifecycle mutated the target")

        # Adopt must run private-state migration against a candidate manifest.
        # A history-free v8 ledger is upgraded, while a v8 ledger with history
        # remains untrusted and leaves the unmanaged project untouched.
        adopt_v8 = workspace / "adopt-empty-v8"
        run(sys.executable, str(installer), str(adopt_v8), "--project-name", "fixture-adopt-v8")
        adopt_v8_manifest = adopt_v8 / ".agent/.workflow-manifest.json"
        adopt_v8_manifest.unlink()
        adopt_v8_agents_path = adopt_v8 / ".agent/state/agents.json"
        adopt_v8_agents = json.loads(adopt_v8_agents_path.read_text(encoding="utf-8"))
        adopt_v8_agents["schema"] = "agent-team/v8"
        adopt_v8_agents.pop("token_accounting")
        adopt_v8_agents_path.write_text(
            json.dumps(adopt_v8_agents, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        run(sys.executable, str(installer), str(adopt_v8), "--adopt")
        adopted_v8_agents = json.loads(adopt_v8_agents_path.read_text(encoding="utf-8"))
        if (
            adopted_v8_agents.get("schema") != "agent-team/v9"
            or adopted_v8_agents.get("token_accounting") != {
                "schema": "agent-child-token-accounting/v1", "token_budget": 48000,
                "settled_tokens": 0,
            }
        ):
            raise SystemExit("adopt did not migrate a history-free v8 private ledger")
        run(sys.executable, ".agent/scripts/agentctl.py", "validate", cwd=adopt_v8)

        adopt_history = workspace / "adopt-historical-v8"
        run(
            sys.executable, str(installer), str(adopt_history),
            "--project-name", "fixture-adopt-historical-v8",
        )
        adopt_history_manifest = adopt_history / ".agent/.workflow-manifest.json"
        adopt_history_manifest.unlink()
        adopt_history_agents_path = adopt_history / ".agent/state/agents.json"
        adopt_history_agents = json.loads(adopt_history_agents_path.read_text(encoding="utf-8"))
        adopt_history_agents["schema"] = "agent-team/v8"
        adopt_history_agents.pop("token_accounting")
        adopt_history_agents["members"] = [{"id": "untrusted-history", "status": "completed"}]
        adopt_history_agents_path.write_text(
            json.dumps(adopt_history_agents, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        adopt_history_before = adopt_history_agents_path.read_bytes()
        rejected_adopt_history = subprocess.run(
            [sys.executable, str(installer), str(adopt_history), "--adopt"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
        )
        if (
            rejected_adopt_history.returncode == 0
            or adopt_history_manifest.exists()
            or adopt_history_agents_path.read_bytes() != adopt_history_before
        ):
            raise SystemExit("adopt trusted or mutated a historical v8 private ledger")

        # Private links must fail closed for both adopt and update.  A copying
        # implementation that dereferences the link would import this external
        # payload as a regular project file and incorrectly commit the lifecycle.
        for lifecycle in ("adopt", "update"):
            linked = workspace / f"{lifecycle}-private-symlink"
            run(
                sys.executable, str(installer), str(linked),
                "--project-name", f"fixture-{lifecycle}-private-symlink",
            )
            linked_manifest = linked / ".agent/.workflow-manifest.json"
            if lifecycle == "adopt":
                linked_manifest.unlink()
            external = workspace / f"{lifecycle}-external-private.json"
            external_payload = f'{{"outside":"{lifecycle}-secret"}}\n'.encode()
            external.write_bytes(external_payload)
            private_link = linked / ".agent/state/external-private.json"
            private_link.symlink_to(external)
            rejected_link = subprocess.run(
                [sys.executable, str(installer), str(linked), f"--{lifecycle}"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
            )
            if (
                rejected_link.returncode == 0
                or "private .agent tree contains a symlink" not in rejected_link.stdout
                or not private_link.is_symlink()
                or external.read_bytes() != external_payload
                or (lifecycle == "adopt" and linked_manifest.exists())
            ):
                raise SystemExit(
                    f"{lifecycle} accepted, dereferenced, or mutated an external private-state symlink"
                )

        # Migration 19 can replace only a history-free legacy ledger and requires a
        # fresh platform-empty proof. It never invents v8 stall/replay semantics.
        old_empty_v5 = workspace / "old-empty-v5"
        run(sys.executable, str(installer), str(old_empty_v5), "--project-name", "fixture-old-empty-v5")
        old_empty_config_path = old_empty_v5 / ".agent/config.json"
        old_empty_config = json.loads(old_empty_config_path.read_text(encoding="utf-8"))
        old_empty_control = old_empty_config["agent_control"]
        old_empty_control["status_request_after_unchanged_checks"] = 2
        old_empty_control.pop("stall_timeout_seconds", None)
        old_empty_control["interrupt_after_unchanged_checks"] = 3
        for name in (
            "max_task_payload_input_count", "max_task_payload_single_bytes",
            "max_task_payload_total_bytes", "max_task_payload_estimated_tokens",
        ):
            old_empty_control.pop(name)
        old_empty_config_path.write_text(json.dumps(old_empty_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        old_empty_path = old_empty_v5 / ".agent/state/agents.json"
        old_empty_value = json.loads(old_empty_path.read_text(encoding="utf-8"))
        old_empty_value["schema"] = "agent-team/v5"
        old_empty_value.pop("prepared_dispatches")
        old_empty_value.pop("replay_runs")
        old_empty_value.pop("stall_timeout_seconds")
        old_empty_value.pop("task_payload_schema")
        old_empty_value.pop("task_payload_limits")
        old_empty_value["status_request_after_unchanged_checks"] = 2
        old_empty_value["interrupt_after_unchanged_checks"] = 3
        old_empty_path.write_text(json.dumps(old_empty_value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        old_empty_manifest_path = old_empty_v5 / ".agent/.workflow-manifest.json"
        old_empty_manifest = json.loads(old_empty_manifest_path.read_text(encoding="utf-8"))
        old_empty_manifest["version"] = "3.1.14"
        old_empty_manifest["migration_version"] = 15
        old_empty_manifest_path.write_text(json.dumps(old_empty_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        old_empty_before = old_empty_path.read_bytes()
        rejected_empty_without_proof = subprocess.run(
            [sys.executable, str(installer), str(old_empty_v5), "--update"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
        )
        if rejected_empty_without_proof.returncode == 0 or old_empty_path.read_bytes() != old_empty_before:
            raise SystemExit("migration 19 replaced an empty v5 ledger without a fresh platform-empty proof")
        old_history_v5 = workspace / "old-history-v5"
        run(sys.executable, str(installer), str(old_history_v5), "--project-name", "fixture-old-history-v5")
        old_history_path = old_history_v5 / ".agent/state/agents.json"
        old_history_value = json.loads(old_history_path.read_text(encoding="utf-8"))
        old_history_value["schema"] = "agent-team/v5"
        old_history_value.pop("prepared_dispatches")
        old_history_value.pop("replay_runs")
        old_history_value.pop("stall_timeout_seconds")
        old_history_value.pop("task_payload_schema")
        old_history_value.pop("task_payload_limits")
        old_history_value["status_request_after_unchanged_checks"] = 2
        old_history_value["interrupt_after_unchanged_checks"] = 3
        old_history_value["members"] = [{"id": "historical-child", "status": "completed"}]
        old_history_path.write_text(json.dumps(old_history_value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        old_history_manifest_path = old_history_v5 / ".agent/.workflow-manifest.json"
        old_history_manifest = json.loads(old_history_manifest_path.read_text(encoding="utf-8"))
        old_history_manifest["version"] = "3.1.14"
        old_history_manifest["migration_version"] = 15
        old_history_manifest_path.write_text(json.dumps(old_history_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        old_history_before = old_history_path.read_bytes()
        rejected_history = subprocess.run(
            [sys.executable, str(installer), str(old_history_v5), "--update", "--agent-platform-snapshot", str(empty_platform_snapshot(workspace / "old-history-v5-platform.json"))],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
        )
        if rejected_history.returncode == 0 or old_history_path.read_bytes() != old_history_before:
            raise SystemExit("migration 19 invented v8 semantics for an existing v5 member")

        old_semantic_v5 = workspace / "old-semantic-v5"
        run(sys.executable, str(installer), str(old_semantic_v5), "--project-name", "fixture-old-semantic-v5")
        old_semantic_path = old_semantic_v5 / ".agent/state/agents.json"
        old_semantic_value = json.loads(old_semantic_path.read_text(encoding="utf-8"))
        old_semantic_value["schema"] = "agent-team/v5"
        old_semantic_value.pop("replay_runs")
        old_semantic_value.pop("stall_timeout_seconds")
        old_semantic_value["task_payload_schema"] = "agent-task-payload/v1"
        old_semantic_value["members"] = [{"id": "old-payload-review", "status": "completed"}]
        old_semantic_path.write_text(json.dumps(old_semantic_value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        old_semantic_manifest_path = old_semantic_v5 / ".agent/.workflow-manifest.json"
        old_semantic_manifest = json.loads(old_semantic_manifest_path.read_text(encoding="utf-8"))
        old_semantic_manifest["version"] = "3.1.14"
        old_semantic_manifest["migration_version"] = 15
        old_semantic_manifest_path.write_text(json.dumps(old_semantic_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        old_semantic_before = old_semantic_path.read_bytes()
        rejected_semantic = subprocess.run(
            [sys.executable, str(installer), str(old_semantic_v5), "--update", "--agent-platform-snapshot", str(empty_platform_snapshot(workspace / "old-semantic-v5-platform.json"))],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
        )
        if rejected_semantic.returncode == 0 or old_semantic_path.read_bytes() != old_semantic_before:
            raise SystemExit("migration 19 silently re-signed v1 payload or pre-review-chain history")

        # The immediate migration-17/v6 predecessor is the important boundary:
        # only a completely history-free ledger may acquire v8 progress-stall and
        # ledger-parent replay authority, and only after a fresh platform-empty proof.
        old_empty_v6 = workspace / "old-empty-v6"
        run(sys.executable, str(installer), str(old_empty_v6), "--project-name", "fixture-old-empty-v6")
        old_empty_v6_path = downgrade_empty_v8_to_v6(old_empty_v6)
        old_empty_v6_digest = digest(old_empty_v6_path)
        old_empty_v6_config_path = old_empty_v6 / ".agent/config.json"
        old_empty_v6_config_before = old_empty_v6_config_path.read_bytes()
        rejected_v6_without_proof = subprocess.run(
            [sys.executable, str(installer), str(old_empty_v6), "--update"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
        )
        if (
            rejected_v6_without_proof.returncode == 0
            or digest(old_empty_v6_path) != old_empty_v6_digest
            or old_empty_v6_config_path.read_bytes() != old_empty_v6_config_before
        ):
            raise SystemExit("migration 19 replaced an empty v6 ledger without a fresh platform-empty proof")
        v6_history_cases = {
            "members": [{"id": "legacy-member", "status": "completed"}],
            "prepared_dispatches": [{"id": "legacy-preparation"}],
            "capacity_failures": [{"attempt_id": "legacy-capacity"}],
            "replay_runs": [{"run_id": "legacy-run"}],
        }
        for history_field, history_value in v6_history_cases.items():
            historical_v6 = workspace / f"historical-v6-{history_field}"
            run(
                sys.executable, str(installer), str(historical_v6),
                "--project-name", f"fixture-historical-v6-{history_field}",
            )
            historical_v6_path = downgrade_empty_v8_to_v6(historical_v6)
            historical_v6_value = json.loads(historical_v6_path.read_text(encoding="utf-8"))
            historical_v6_value[history_field] = history_value
            historical_v6_path.write_text(
                json.dumps(historical_v6_value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
            )
            historical_v6_before = historical_v6_path.read_bytes()
            historical_v6_config_path = historical_v6 / ".agent/config.json"
            historical_v6_config_before = historical_v6_config_path.read_bytes()
            rejected_historical_v6 = subprocess.run(
                [
                    sys.executable, str(installer), str(historical_v6), "--update",
                    "--agent-platform-snapshot",
                    str(empty_platform_snapshot(workspace / f"historical-v6-{history_field}-platform.json")),
                ],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
            )
            if (
                rejected_historical_v6.returncode == 0
                or historical_v6_path.read_bytes() != historical_v6_before
                or historical_v6_config_path.read_bytes() != historical_v6_config_before
            ):
                raise SystemExit(f"migration 19 invented v8 authority for v6 {history_field} history")

        # Migration 19 requires a fresh platform-empty v3 proof. All deployed empty
        # legacy schemas migrate with immutable archive evidence; active v2/v3/v4/v5
        # ledgers fail transactionally even when a caller supplies an empty snapshot.
        for legacy_schema in ("agent-team/v2", "agent-team/v3", "agent-team/v4", "agent-team/v5"):
            suffix = legacy_schema.rsplit("v", 1)[-1]
            legacy_agents = workspace / f"legacy-agent-ledger-v{suffix}"
            run(sys.executable, str(installer), str(legacy_agents), "--project-name", f"fixture-legacy-v{suffix}")
            legacy_agents_path = legacy_agents / ".agent/state/agents.json"
            legacy_value = json.loads(legacy_agents_path.read_text(encoding="utf-8"))
            legacy_value["schema"] = legacy_schema
            legacy_value["platform_empty_verified"] = False
            legacy_agents_path.write_text(json.dumps(legacy_value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            legacy_digest = digest(legacy_agents_path)
            rejected_without_proof = subprocess.run(
                [sys.executable, str(installer), str(legacy_agents), "--update"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
            )
            if rejected_without_proof.returncode == 0 or digest(legacy_agents_path) != legacy_digest:
                raise SystemExit(f"inactive {legacy_schema} migrated without fresh platform-empty proof")
            active_agents = workspace / f"active-legacy-agent-ledger-v{suffix}"
            run(sys.executable, str(installer), str(active_agents), "--project-name", f"fixture-active-v{suffix}")
            active_agents_path = active_agents / ".agent/state/agents.json"
            active_value = json.loads(active_agents_path.read_text(encoding="utf-8"))
            active_value["schema"] = legacy_schema
            active_value["members"] = [{"id": "legacy-child", "status": "active"}]
            active_agents_path.write_text(json.dumps(active_value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            active_before = active_agents_path.read_bytes()
            blocked_agents = subprocess.run(
                [sys.executable, str(installer), str(active_agents), "--update", "--agent-platform-snapshot", str(empty_platform_snapshot(workspace / f"active-empty-v{suffix}.json"))],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
            )
            if blocked_agents.returncode == 0 or active_agents_path.read_bytes() != active_before:
                raise SystemExit(f"active {legacy_schema} ledger was silently replaced during migration")

        # Runtime migration must not invent a baseline for an already-active legacy
        # task; that would bless unknown residual processes after the fact.
        legacy = workspace / "active-legacy-runtime"
        run(sys.executable, str(installer), str(legacy), "--project-name", "fixture-legacy")
        task_path = legacy / ".agent/state/TASK.json"
        task = json.loads(task_path.read_text(encoding="utf-8"))
        task["status"] = "in_progress"; task["phase"] = "implementation"; task["current_node"] = 6
        task_path.write_text(json.dumps(task, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        runtime_path = legacy / ".agent/state/runtime.json"
        runtime_path.write_text(json.dumps({"schema": "agent-runtime/v1", "processes": [], "docker_projects": [], "ports": []}), encoding="utf-8")
        before_runtime = runtime_path.read_bytes()
        blocked = subprocess.run(
            [sys.executable, str(installer), str(legacy), "--update"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
        )
        if blocked.returncode == 0 or runtime_path.read_bytes() != before_runtime:
            raise SystemExit("active legacy runtime was silently assigned an unaudited baseline")

    print("TEMPLATE LIFECYCLE SELF-TEST PASSED")
    return 0


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
