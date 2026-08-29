#!/usr/bin/env python3
"""Repeatable install isolation and transaction lifecycle regression test."""

from pathlib import Path
import argparse
import base64
import hashlib
import importlib.util
import fcntl
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


SOURCE_SENTINEL = "SOURCE_PRIVATE_SENTINEL_NEVER_INSTALL"
TARGET_SENTINEL = "TARGET_PRIVATE_SENTINEL_PRESERVE"


def run(*command: str, cwd: Path, env=None, expected=(0,), timeout=180) -> subprocess.CompletedProcess:
    result = subprocess.run(
        list(command), cwd=str(cwd), env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
    )
    if result.returncode not in expected:
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}")
    return result


def tree(root: Path):
    result = {}
    if not root.exists() and not root.is_symlink():
        return result
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            result[relative] = ("link", os.readlink(path))
        elif path.is_file():
            result[relative] = ("file", hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode & 0o777)
        elif path.is_dir():
            result[relative] = ("dir", path.stat().st_mode & 0o777)
    return result


def canonical_sha256(value) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def bind_v5_manifest_metadata(value: dict) -> dict:
    payload = {
        "schema": value["schema"], "version": value["version"],
        "migration_version": value["migration_version"],
        "agent_root_mode": value["agent_root_mode"],
        "agent_files": value["agent_files"], "pxpipe": value["pxpipe"],
        "agents_bootstrap_sha256": value["agents_bootstrap"]["sha256"],
        "claude_bootstrap_sha256": value["claude_bootstrap"]["sha256"],
    }
    if value.get("agent_modes") is not None: payload["agent_modes"] = value["agent_modes"]
    value["source_tree_sha256"] = canonical_sha256(payload)
    return value


def as_legacy_v1_manifest(value: dict, version: str, migration_version: int) -> dict:
    files = value["agent_files"]
    return {
        "schema": "agent-workflow-install/v1", "version": version,
        "migration_version": migration_version, "files": files,
        "source_tree_sha256": canonical_sha256(files),
    }


def as_released_v4_manifest(value: dict, version: str, migration_version: int) -> dict:
    pxpipe = value["pxpipe"]
    entry_digest = pxpipe.get("marketplace_entry_sha256") or "0" * 64
    payload = {
        "agent_files": value["agent_files"], "repo_plugin_files": pxpipe["files"],
        "marketplace_entry_sha256": entry_digest,
        "agents_bootstrap_sha256": value["agents_bootstrap"]["sha256"],
        "claude_bootstrap_sha256": value["claude_bootstrap"]["sha256"],
    }
    return {
        "schema": "agent-workflow-install/v4", "version": version,
        "migration_version": migration_version, "source_tree_sha256": canonical_sha256(payload),
        "agent_files": value["agent_files"], "repo_plugin_files": pxpipe["files"],
        "marketplace_entry": {"name": "pxpipe-context", "sha256": entry_digest},
        "agents_bootstrap": value["agents_bootstrap"], "claude_bootstrap": value["claude_bootstrap"],
    }


def project_init_journal(target: Path, phase: str = "prepared") -> dict:
    paths = (
        target / ".agent/config.json",
        target / ".agent/policies/PROJECT_GUARDRAILS.md",
        target / ".agent/state/agents.json",
        target / ".agent/state/CONTEXT.json",
    )
    backups = {}
    committed = {}
    for path in paths:
        data = path.read_bytes()
        relative = str(path.relative_to(target))
        backups[relative] = {
            "data_b64": base64.b64encode(data).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
        committed[relative] = hashlib.sha256(data).hexdigest()
    return {
        "schema": "agent-project-init-transaction/v1",
        "phase": phase,
        "backups": backups,
        "committed_sha256": committed if phase == "committed" else None,
    }


def assert_no_sentinel(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink() and SOURCE_SENTINEL.encode() in path.read_bytes():
            raise SystemExit(f"source-private bytes escaped into installed target: {path}")


def pollute_source(template: Path, external: Path) -> None:
    agent = template / ".agent"
    (agent / "config.json").write_text(
        json.dumps({"source_private": SOURCE_SENTINEL}) + "\n", encoding="utf-8",
    )
    (agent / "policies/PROJECT_GUARDRAILS.md").write_text(SOURCE_SENTINEL + "\n", encoding="utf-8")
    state = agent / "state"
    for name in ("TASK.json", "CONTEXT.json", "agents.json", "EVIDENCE_INDEX.json"):
        (state / name).write_text(json.dumps({"source_private": SOURCE_SENTINEL}) + "\n", encoding="utf-8")
    evidence = state / "evidence"; evidence.mkdir(exist_ok=True)
    (evidence / "source-private.txt").write_text(SOURCE_SENTINEL, encoding="utf-8")
    external.write_text(SOURCE_SENTINEL, encoding="utf-8")
    (state / "source-private-link").symlink_to(external)


def completed_guardrails(path: Path) -> None:
    path.write_text(
        """# Project Guardrails

## Required project facts

- Product and users: Disposable install lifecycle fixture for template maintainers.
- Technology and architecture: Python installer with local JSON and Markdown state.
- Writable and read-only areas: The temporary fixture is writable; external paths are read-only.
- Security, privacy, compliance and performance red lines: No credentials, network, or external effects.
- Build, test and lint commands: Run tests/test_install_lifecycle.py in a clean temporary directory.
- Deployment authority and rollback owner: Deployment is forbidden; the fixture owner controls rollback.

## Universal project constraints

- Keep every operation local, bounded, reversible, and transactionally recoverable.
""",
        encoding="utf-8",
    )


def crash_and_recover(installer: Path, target: Path, mode_args, recovery_args, cwd: Path) -> None:
    env = dict(os.environ); env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_TARGET"] = "1"
    run(sys.executable, str(installer), str(target), *mode_args, cwd=cwd, env=env, expected=(97,))
    crashed = tree(target)
    observed = run(sys.executable, str(installer), str(target), *recovery_args, cwd=cwd, expected=(2,))
    if "RECOVERY REQUIRED" not in observed.stdout or tree(target) != crashed:
        raise SystemExit(f"observational recovery mutated target for {' '.join(mode_args)}")
    run(sys.executable, str(installer), str(target), *mode_args, cwd=cwd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template-root", default=".")
    args = parser.parse_args()
    source = Path(args.template_root).resolve()
    with tempfile.TemporaryDirectory(prefix="install-lifecycle-") as raw:
        workspace = Path(raw)
        polluted = workspace / "polluted-template"
        shutil.copytree(
            source, polluted, symlinks=True,
            ignore=shutil.ignore_patterns(".git", ".idea", "__pycache__", "*.pyc"),
        )
        pollute_source(polluted, workspace / "external-private.txt")
        # A checkout umask may narrow owner bits, but the released data/executable
        # contract remains portable 0644/0755.
        (polluted/".agent/INDEX.md").chmod(0o600)
        inventory=json.loads((polluted/".agent/assets/managed-executables.json").read_text(encoding="utf-8"))
        declared_executable=polluted/".agent"/inventory["paths"][0]; declared_executable.chmod(0o600)
        (polluted/".agent/scripts/agentctl.py").chmod(0o755)
        installer = polluted / "install.py"
        installer_spec = importlib.util.spec_from_file_location("workflow_installer", installer)
        installer_module = importlib.util.module_from_spec(installer_spec)
        installer_spec.loader.exec_module(installer_module)
        if installer_module.RELEASED_MANIFEST_METADATA["agent-workflow-install/v5"]!={("4.0.0",42),("4.0.1",42),("4.0.2",42)}:
            raise SystemExit("v4 patch release manifest compatibility window drifted")
        real_read_parent=workspace/"real-read-parent"; real_read_parent.mkdir(); (real_read_parent/"value").write_bytes(b"ok")
        linked_read_parent=workspace/"linked-read-parent"; linked_read_parent.symlink_to(real_read_parent,target_is_directory=True)
        try: installer_module.read_installer_bytes(linked_read_parent/"value")
        except RuntimeError: pass
        else: raise SystemExit("installer bounded read followed a symlinked parent")
        aggregate_root=workspace/"aggregate-quarantine"; first=aggregate_root/"first"; second=aggregate_root/"second"; first.mkdir(parents=True); second.mkdir()
        (first/"a").write_bytes(b"a"); (second/"b").write_bytes(b"b")
        original_record_limit=installer_module.MAX_LEGACY_QUARANTINE_RECORDS; installer_module.MAX_LEGACY_QUARANTINE_RECORDS=3
        try:
            try: installer_module.aggregate_private_namespace_records([first,second],aggregate_root)
            except RuntimeError as error:
                if "aggregate" not in str(error): raise
            else: raise SystemExit("legacy Skill quarantine accepted aggregate records beyond its shared limit")
        finally: installer_module.MAX_LEGACY_QUARANTINE_RECORDS=original_record_limit
        manifest_probe=workspace/"malicious-manifest.json"
        for bad_path,bad_digest in (("../escape","a"*64),("/absolute","a"*64),("a//b","a"*64),("a\\b","a"*64),("a/./b","a"*64),("x"*256,"a"*64),("safe/path","A"*64)):
            forged=installer_module.install_manifest({"INDEX.md":"a"*64},{"INDEX.md":0o644},{},None,"disabled","b"*64,"c"*64)
            forged["agent_files"]={bad_path:bad_digest}; forged["agent_modes"]={bad_path:0o644}
            metadata={"schema":forged["schema"],"version":forged["version"],"migration_version":forged["migration_version"]}
            forged["source_tree_sha256"]=installer_module.canonical_sha256({**metadata,"agent_root_mode":forged["agent_root_mode"],"agent_files":forged["agent_files"],"agent_modes":forged["agent_modes"],"pxpipe":forged["pxpipe"],"agents_bootstrap_sha256":forged["agents_bootstrap"]["sha256"],"claude_bootstrap_sha256":forged["claude_bootstrap"]["sha256"]})
            manifest_probe.write_text(json.dumps(forged)+"\n",encoding="utf-8")
            try: installer_module.manifest(manifest_probe,required=True)
            except SystemExit: pass
            else: raise SystemExit(f"manifest path/digest escape was accepted: {bad_path!r}")
        target = workspace / "installed-project"

        unsafe_parent = workspace / "unsafe-parent"
        unsafe_parent.mkdir(); unsafe_parent.chmod(0o777)
        unsafe_target = unsafe_parent / "project"
        unsafe_result = run(sys.executable, str(installer), str(unsafe_target), "--project-name", "unsafe", cwd=polluted, expected=(1,))
        if "owner-controlled directory" not in unsafe_result.stdout or unsafe_target.exists():
            raise SystemExit("group/world-writable target parent was accepted or mutated")
        unsafe_parent.chmod(0o700)
        real_parent=workspace/"real-parent"; real_parent.mkdir(mode=0o700)
        linked_parent=workspace/"linked-parent"; linked_parent.symlink_to(real_parent,target_is_directory=True)
        linked_target=linked_parent/"project"
        linked_result=run(sys.executable,str(installer),str(linked_target),"--project-name","linked",cwd=polluted,expected=(1,))
        if "parent chain is unsafe" not in linked_result.stdout or (real_parent/"project").exists():
            raise SystemExit("lexical target-parent symlink was followed or mutated")
        observation=workspace/"observation-only"; observation.mkdir(mode=0o700)
        observation_before=set(path.name for path in workspace.iterdir())
        run(sys.executable,str(installer),str(observation),"--check",cwd=polluted,expected=(1,))
        if set(path.name for path in workspace.iterdir())!=observation_before:
            raise SystemExit("--check created a publication lock for an unmanaged target")
        unsafe_existing = workspace / "unsafe-existing"
        unsafe_existing.mkdir(); unsafe_existing.chmod(0o777)
        unsafe_before = tree(unsafe_existing)
        unsafe_result = run(sys.executable, str(installer), str(unsafe_existing), "--check", cwd=polluted, expected=(1,))
        if "owner-controlled directory" not in unsafe_result.stdout or tree(unsafe_existing) != unsafe_before:
            raise SystemExit("group/world-writable existing target was accepted or mutated")
        unsafe_existing.chmod(0o700)
        unsafe_source_dir = polluted / ".agent/scripts"
        unsafe_source_dir.chmod(0o777)
        unsafe_source_target = workspace / "unsafe-source-project"
        unsafe_source_result = run(sys.executable, str(installer), str(unsafe_source_target), "--project-name", "unsafe-source", cwd=polluted, expected=(1,))
        if "managed source entry is not owner-controlled" not in unsafe_source_result.stdout or unsafe_source_target.exists():
            raise SystemExit("group/world-writable managed source was accepted or installed")
        unsafe_source_dir.chmod(0o755)

        tampered_inventory=workspace/"tampered-inventory-template"
        shutil.copytree(polluted,tampered_inventory,symlinks=True)
        tampered_path=tampered_inventory/".agent/assets/managed-executables.json"
        tampered_value=json.loads(tampered_path.read_text(encoding="utf-8")); tampered_value["paths"].append("unknown-executable")
        tampered_path.write_text(json.dumps(tampered_value,indent=2)+"\n",encoding="utf-8")
        tampered_target=workspace/"tampered-inventory-target"
        tampered_result=run(sys.executable,str(tampered_inventory/"install.py"),str(tampered_target),"--project-name","tampered",cwd=tampered_inventory,expected=(1,))
        if "unsafe or unknown path" not in tampered_result.stdout or tampered_target.exists():
            raise SystemExit("tampered executable inventory was accepted or mutated a target")

        # Pxpipe is optional and absent in the released source contract. A
        # genuinely absent tree with no marketplace entry installs as disabled,
        # while every present empty/partial/symlink tree must validate and fail
        # closed before target mutation.
        source_plugin=polluted/"plugins/pxpipe-context"; source_plugin.parent.mkdir(parents=True,exist_ok=True)
        # A working tree can retain the now-untracked empty directory after its
        # quarantined files are removed; the isolated source fixture models the
        # released absent namespace explicitly.
        if source_plugin.is_symlink(): source_plugin.unlink()
        elif source_plugin.exists(): shutil.rmtree(source_plugin)
        external_plugin=workspace/"external-plugin-source"; external_plugin.mkdir()
        for label in ("empty","partial","symlink"):
            malicious_target=workspace/f"malicious-source-{label}-target"
            if label=="symlink": source_plugin.symlink_to(external_plugin,target_is_directory=True)
            else:
                source_plugin.mkdir()
                if label=="partial": (source_plugin/"integrity.json").write_text("{}\n",encoding="utf-8")
            rejected=run(sys.executable,str(installer),str(malicious_target),"--project-name",label,
                         cwd=polluted,expected=(1,))
            if "repo plugin" not in rejected.stdout and "candidate plugin metadata" not in rejected.stdout:
                raise SystemExit(f"malicious {label} optional plugin source failed for the wrong reason: {rejected.stdout}")
            if malicious_target.exists(): raise SystemExit(f"malicious {label} plugin source mutated install target")
            if source_plugin.is_symlink(): source_plugin.unlink()
            else: shutil.rmtree(source_plugin)

        source_marketplace=polluted/".agents/plugins/marketplace.json"
        marketplace_bytes=source_marketplace.read_bytes(); marketplace_mode=source_marketplace.stat().st_mode&0o777
        source_marketplace.unlink()
        marketless_target=workspace/"marketless-optional-source-target"
        run(sys.executable,str(installer),str(marketless_target),"--project-name","marketless",cwd=polluted)
        marketless_manifest=json.loads((marketless_target/".agent/.workflow-manifest.json").read_text(encoding="utf-8"))
        if (marketless_manifest.get("pxpipe")!={
                "name":"pxpipe-context","provenance_status":"disabled","files":{},"marketplace_entry_sha256":None,
            } or (marketless_target/".agents/plugins/marketplace.json").exists()):
            raise SystemExit("fully absent plugin/marketplace source did not bind disabled empty/null authority")
        external_marketplace=workspace/"external-marketplace.json"
        external_marketplace.write_bytes(marketplace_bytes)
        for label in ("symlink","special","malformed","absent-plugin-entry"):
            unsafe_market_target=workspace/f"unsafe-marketplace-{label}-target"
            if label=="symlink": source_marketplace.symlink_to(external_marketplace)
            elif label=="special": os.mkfifo(source_marketplace)
            elif label=="malformed": source_marketplace.write_text("{not-json",encoding="utf-8")
            else: source_marketplace.write_text(json.dumps({"plugins":[{"name":"pxpipe-context"}]})+"\n",encoding="utf-8")
            try:
                if label=="absent-plugin-entry": installer_module.source_contract(polluted)
                else: installer_module.read_marketplace(source_marketplace,required=False)
            except RuntimeError as error:
                if "marketplace" not in str(error): raise
            else: raise SystemExit(f"unsafe {label} marketplace source did not fail closed")
            if unsafe_market_target.exists(): raise SystemExit(f"unsafe {label} marketplace probe mutated a target")
            source_marketplace.unlink()
        source_marketplace.write_text(json.dumps({"plugins":[{"name":"unrelated-project-plugin"}]})+"\n",encoding="utf-8")
        unrelated_contract=installer_module.source_contract(polluted)
        if unrelated_contract[2:]!=({},None,None,"disabled"):
            raise SystemExit("unrelated marketplace entry became pxpipe authority")
        source_marketplace.write_bytes(marketplace_bytes); source_marketplace.chmod(marketplace_mode)

        native_transport={"context_transport":{"default":"native"},"agent_control":{"default_model":None}}
        installer_module.validate_context_transport_policy(native_transport,"disabled")
        for malformed_transport in (
            {"context_transport":{"default":"native","pxpipe":{}},"agent_control":{"default_model":None}},
            {"context_transport":{"default":"native","unexpected":{}},"agent_control":{"default_model":None}},
        ):
            try: installer_module.validate_context_transport_policy(malformed_transport,"verified")
            except RuntimeError: pass
            else: raise SystemExit("partial or malformed optional pxpipe opt-in was accepted")
        legacy_pxpipe_policy={
            "enabled":False,"activation":"explicit-opt-in","plugin_name":"pxpipe-context",
            "plugin_version":"0.1.0+codex.20260721210500","models":[],"primary_mode":"provider-proxy",
            "provider_activation":"default-new-local-sessions","provider_configuration":"user-model-provider-plus-launch-agent",
            "provider_content_scope":"whole-request-eligible-content","mcp_role":"optional-cold-reference",
            "selection":"analyze-then-render","content_scope":"new-cold-reference-only",
            "session_boundary":"plugin-load-requires-new-chat","fallback":"native",
        }
        legacy_transport={"context_transport":{"default":"native","pxpipe":dict(legacy_pxpipe_policy)},"agent_control":{"default_model":None}}
        installer_module.validate_context_transport_policy(legacy_transport,"disabled",normalize_legacy_disabled=True)
        if legacy_transport["context_transport"]!={"default":"native"}:
            raise SystemExit("legacy disabled pxpipe transport was not retired to exact native-only policy")
        enabled_policy=dict(legacy_pxpipe_policy); enabled_policy.update({
            "enabled":True,"models":["provider/model"],"provider_activation":"task-explicit-opt-in",
        })
        enabled_transport={"context_transport":{"default":"native","pxpipe":enabled_policy},"agent_control":{"default_model":"provider/model"}}
        try: installer_module.validate_context_transport_policy(enabled_transport,"disabled")
        except RuntimeError as error:
            if "verified plugin provenance" not in str(error): raise
        else: raise SystemExit("unverified pxpipe provenance enabled an optional transport")
        installer_module.validate_context_transport_policy(enabled_transport,"verified")

        # Polluted source private config/policies/state/evidence/links are ignored.
        installed = run(
            sys.executable, str(installer), str(target), "--project-name", "isolation-fixture",
            cwd=polluted,
        )
        if "PROJECT INIT REQUIRED" not in installed.stdout or "BOOTSTRAP NOT READY" not in installed.stdout or "NEXT: local" in installed.stdout:
            raise SystemExit("fresh install bootstrap output overclaimed readiness")
        assert_no_sentinel(target)
        unsafe_private = target / ".agent/config.json"
        unsafe_private.chmod(0o666)
        unsafe_private_before = tree(target)
        unsafe_private_result = run(sys.executable, str(installer), str(target), "--check", cwd=polluted, expected=(1,))
        if ("private .agent entry is not owner-controlled" not in unsafe_private_result.stdout
                or tree(target) != unsafe_private_before):
            raise SystemExit("group/world-writable private workflow state was accepted or mutated")
        unsafe_private.chmod(0o644)
        if (target / ".agent/LICENSE").read_bytes() != (source / "LICENSE").read_bytes():
            raise SystemExit("installed template did not retain the exact root MIT license")
        fresh_manifest = json.loads((target / ".agent/.workflow-manifest.json").read_text(encoding="utf-8"))
        if fresh_manifest.get("agent_root_mode")!=0o700 or stat.S_IMODE(os.lstat(target/".agent").st_mode)!=0o700:
            raise SystemExit("fresh install did not bind and apply canonical private .agent root mode")
        if set(fresh_manifest.get("agent_modes", {})) != set(fresh_manifest.get("agent_files", {})):
            raise SystemExit("fresh install manifest did not bind every managed file mode")
        if fresh_manifest.get("pxpipe")!={
            "name":"pxpipe-context","provenance_status":"disabled","files":{},"marketplace_entry_sha256":None,
        }:
            raise SystemExit("absent optional pxpipe source was not bound as disabled with empty/null authority")
        if (fresh_manifest["agent_modes"].get("INDEX.md")!=0o644
                or fresh_manifest["agent_modes"].get(inventory["paths"][0])!=0o755
                or fresh_manifest["agent_modes"].get("scripts/agentctl.py")!=0o644):
            raise SystemExit("checkout mode bits overrode the checked-in executable inventory")
        for relative, expected_mode in fresh_manifest["agent_modes"].items():
            if (target / ".agent" / relative).stat().st_mode & 0o777 != expected_mode:
                raise SystemExit(f"fresh install mode differs from manifest: {relative}")
        readonly_target=workspace/"read-only-installed"; shutil.copytree(target,readonly_target,symlinks=True)
        readonly_lock=workspace/f".{readonly_target.name}.agent-workflow-publication.lock"
        for readonly_args in (("--check",),("--update","--dry-run")):
            before=tree(workspace)
            observed=run(sys.executable,str(installer),str(readonly_target),*readonly_args,cwd=polluted,expected=(0,1))
            if readonly_args[-1]=="--dry-run" and observed.returncode and "managed built-in Skill bytes drifted" not in observed.stdout:
                raise SystemExit("dry-run feasibility failed for an unrelated reason")
            if readonly_lock.exists() or readonly_lock.is_symlink() or tree(workspace)!=before:
                raise SystemExit(f"read-only installer mode mutated target parent: {readonly_args}")
        manifest_path = target / ".agent/.workflow-manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        for label, corrupt_modes in (
            ("missing", {key: value for key, value in fresh_manifest["agent_modes"].items() if key != "INDEX.md"}),
            ("boolean", {**fresh_manifest["agent_modes"], "INDEX.md": True}),
        ):
            malformed_manifest = json.loads(manifest_bytes)
            malformed_manifest["agent_modes"] = corrupt_modes
            manifest_path.write_text(json.dumps(malformed_manifest, indent=2) + "\n", encoding="utf-8")
            malformed_before = tree(target)
            rejected = run(sys.executable, str(installer), str(target), "--check", cwd=polluted, expected=(1,))
            if "managed mode binding" not in rejected.stdout or tree(target) != malformed_before:
                raise SystemExit(f"malformed {label} mode map was accepted or mutated the target")
            manifest_path.write_bytes(manifest_bytes)
        config = json.loads((target / ".agent/config.json").read_text(encoding="utf-8"))
        task = json.loads((target / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        fresh_context=json.loads((target/".agent/state/CONTEXT.json").read_text(encoding="utf-8")); fresh_checkpoint=fresh_context.get("checkpoint",{})
        if (fresh_checkpoint.get("sequence")!=1 or fresh_checkpoint.get("previous_sha256")!="none"
                or fresh_checkpoint.get("previous_task_invariant_sha256")!="none"
                or fresh_checkpoint.get("task_delta")!=["initial_canonical_task_state"]
                or fresh_context.get("usage_freshness",{}).get("checkpoint_sequence")!=1):
            raise SystemExit("fresh project inherited template checkpoint ancestry")
        agents = json.loads((target / ".agent/state/agents.json").read_text(encoding="utf-8"))
        if config.get("agent_control", {}).get("default_model") is not None or agents.get("default_model") is not None:
            raise SystemExit("fresh install silently selected a child model")
        dispatch_probe=run(sys.executable,"-c","import sys;sys.path[:0]=['.agent/scripts','.agent/skills/manage-agent-team/scripts'];import agentledger;agentledger.configured_model()",cwd=target,expected=(1,))
        if "child dispatch blocked: default model is unselected" not in dispatch_probe.stdout:
            raise SystemExit("unselected fresh model did not fail clearly before child dispatch")
        if (
            config.get("project") != {"name": "isolation-fixture", "type": "general-project"}
            or config.get("guardrails_ready") is not False
            or config.get("project_initialization") is not None
            or task.get("status") != "idle" or task.get("requirements_clarified") is not False
            or task.get("decision_policy_version") != 1
            or config.get("context_transport") != {"default": "native"}
            or "pxpipe" in config.get("context_transport", {})
            or any(agents.get(name) != [] for name in ("members", "prepared_dispatches", "capacity_failures", "replay_runs"))
        ):
            raise SystemExit("fresh install did not use the canonical isolated idle seed")

        for suffix,bad_model in (("valid","provider+beta:model_2"),("syntax","bad model\n"),("placeholder","none")):
            malformed_model_target=workspace/f"rejected-default-model-{suffix}"
            malformed_model=run(sys.executable,str(installer),str(malformed_model_target),"--project-name","bad-model","--default-model",bad_model,cwd=polluted,expected=(1,))
            if "--default-model" not in malformed_model.stdout or malformed_model_target.exists():
                raise SystemExit(f"idle default model {bad_model!r} did not fail before target mutation")
        retired_target=workspace/"retired-local-authority"
        retired=run(sys.executable,str(installer),str(retired_target),"--project-name","retired","--allow-current-chat-local-release",cwd=polluted,expected=(2,))
        if "is retired" not in retired.stdout or retired_target.exists():
            raise SystemExit("retired current-chat authority flag did not fail before mutation")

        # Project-writable verifier scripts cannot impersonate provider-owned
        # platform, scheduler, or host-compaction trust boundaries.
        config_path = target / ".agent/config.json"
        pristine_config = config_path.read_bytes()
        forged_adapter = target / "forged-provider-adapter.py"
        forged_adapter.write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")
        forged_adapter.chmod(0o755)
        forged_config = json.loads(pristine_config)
        forged_config["agent_control"]["platform_observer"]["signed_adapter"] = str(forged_adapter)
        forged_config["agent_control"]["scheduler"]["signed_adapter"] = str(forged_adapter)
        forged_config["context"]["host_compaction_observer"]["signed_adapter"] = str(forged_adapter)
        config_path.write_text(json.dumps(forged_config, indent=2) + "\n", encoding="utf-8")
        rejected_adapters = run(
            sys.executable, ".agent/scripts/agentctl.py", "validate", cwd=target, expected=(1,),
        ).stdout
        if not all(label in rejected_adapters for label in (
            "configured platform adapter is invalid",
            "configured scheduler adapter is invalid",
            "configured host compaction adapter is invalid",
        )):
            raise SystemExit("project-writable protected adapters were not all rejected")
        config_path.write_bytes(pristine_config)
        forged_adapter.unlink()

        # A fully prepared but interrupted project-init is rolled back before
        # any later command observes partial config/policy/context bytes.
        journal_path = target / ".agent/state/.project-init-transaction.json"
        recovery_before = {
            path: path.read_bytes() for path in (
                target / ".agent/config.json",
                target / ".agent/policies/PROJECT_GUARDRAILS.md",
                target / ".agent/state/CONTEXT.json",
            )
        }
        journal_path.write_text(json.dumps(project_init_journal(target), indent=2) + "\n", encoding="utf-8")
        for path in recovery_before:
            path.write_text("{}\n", encoding="utf-8")
        partial_before = tree(target)
        blocked_status = run(sys.executable, ".agent/scripts/agentctl.py", "status", cwd=target, expected=(1,))
        if "RECOVERY REQUIRED" not in blocked_status.stdout or tree(target) != partial_before or not journal_path.exists():
            raise SystemExit("read-only status mutated or ignored a prepared project-init transaction")
        run(sys.executable, ".agent/scripts/agentctl.py", "cleanup", cwd=target)
        if journal_path.exists() or any(path.read_bytes() != data for path, data in recovery_before.items()):
            raise SystemExit("mutating project-init recovery did not restore all targets atomically")

        # Recovery validates every backup before writing the first target.
        malformed = project_init_journal(target)
        malformed["backups"][".agent/state/CONTEXT.json"]["sha256"] = "0" * 64
        journal_path.write_text(json.dumps(malformed, indent=2) + "\n", encoding="utf-8")
        before_malformed = {path: path.read_bytes() for path in recovery_before}
        run(sys.executable, ".agent/scripts/agentctl.py", "status", cwd=target, expected=(1,))
        if any(path.read_bytes() != data for path, data in before_malformed.items()):
            raise SystemExit("malformed project-init journal caused a partial restore")
        journal_path.unlink()

        incomplete = target / "incomplete-guardrails.md"
        incomplete.write_text("# Project Guardrails\n\n- Product and users: TODO\n", encoding="utf-8")
        before_init_failure = tree(target)
        no_bytecode = dict(os.environ); no_bytecode["PYTHONDONTWRITEBYTECODE"] = "1"
        run(
            sys.executable, ".agent/scripts/agentctl.py", "project-init", "--guardrails-file", incomplete.name,
            cwd=target, env=no_bytecode, expected=(1,),
        )
        if tree(target) != before_init_failure:
            raise SystemExit("failed project-init changed installed project bytes")
        mismatch_init = workspace / "project-init-model-mismatch"
        shutil.copytree(target, mismatch_init, symlinks=True)
        mismatch_agents_path = mismatch_init / ".agent/state/agents.json"
        mismatch_agents = json.loads(mismatch_agents_path.read_text(encoding="utf-8"))
        mismatch_agents["default_model"] = "provider-neutral/mismatched-model"
        mismatch_agents_path.write_text(json.dumps(mismatch_agents, indent=2) + "\n", encoding="utf-8")
        mismatch_before = tree(mismatch_init)
        mismatch_result = run(
            sys.executable, ".agent/scripts/agentctl.py", "project-init", "--guardrails-file", incomplete.name,
            cwd=mismatch_init, env=no_bytecode, expected=(1,), timeout=15,
        )
        if ("model authorities to agree" not in mismatch_result.stdout
                or tree(mismatch_init) != mismatch_before):
            raise SystemExit("project-init healed or mutated disagreeing model authorities")
        guardrails = target / "project-guardrails.md"; completed_guardrails(guardrails)

        # Guardrail readiness is independent from model selection while no task
        # is active. Install, check, and update preserve explicit null neutrality.
        neutral_target = workspace / "initialized-idle-null-model"
        run(sys.executable, str(installer), str(neutral_target),
            "--project-name", "neutral-idle-fixture", "--guardrails-file", str(guardrails), cwd=polluted)
        neutral_config_path = neutral_target / ".agent/config.json"
        neutral_agents_path = neutral_target / ".agent/state/agents.json"
        neutral_task_path = neutral_target / ".agent/state/TASK.json"
        neutral_config = json.loads(neutral_config_path.read_text(encoding="utf-8"))
        neutral_agents = json.loads(neutral_agents_path.read_text(encoding="utf-8"))
        neutral_task = json.loads(neutral_task_path.read_text(encoding="utf-8"))
        if (neutral_config.get("guardrails_ready") is not True or neutral_task.get("status") != "idle"
                or neutral_config["agent_control"].get("default_model") is not None
                or neutral_agents.get("default_model") is not None):
            raise SystemExit("initialized idle install forced or corrupted default-model neutrality")
        run(sys.executable, str(installer), str(neutral_target), "--check", cwd=polluted)
        neutral_managed = neutral_target / ".agent/INDEX.md"
        neutral_managed.chmod(0o600)
        run(sys.executable, str(installer), str(neutral_target), "--update", cwd=polluted)
        if neutral_managed.stat().st_mode & 0o777 != 0o644:
            raise SystemExit("initialized idle update did not repair the managed update trigger")
        neutral_config = json.loads(neutral_config_path.read_text(encoding="utf-8"))
        neutral_agents = json.loads(neutral_agents_path.read_text(encoding="utf-8"))
        if (neutral_config["agent_control"].get("default_model") is not None
                or neutral_agents.get("default_model") is not None
                or json.loads(neutral_task_path.read_text(encoding="utf-8")).get("status") != "idle"):
            raise SystemExit("initialized idle update forced a default model")
        run(sys.executable, str(installer), str(neutral_target), "--check", cwd=polluted)

        leaf_link = target / "guardrails-link.md"
        leaf_link.symlink_to(guardrails.name)
        before_link = tree(target)
        run(
            sys.executable, ".agent/scripts/agentctl.py", "project-init", "--guardrails-file", leaf_link.name,
            cwd=target, env=no_bytecode, expected=(1,),
        )
        if tree(target) != before_link:
            raise SystemExit("symlinked guardrails input changed project state")
        leaf_link.unlink()
        real_dir = target / "guardrail-files"; real_dir.mkdir()
        nested = real_dir / "policy.md"; completed_guardrails(nested)
        directory_link = target / "guardrail-link-dir"; directory_link.symlink_to(real_dir.name, target_is_directory=True)
        before_ancestor_link = tree(target)
        run(
            sys.executable, ".agent/scripts/agentctl.py", "project-init",
            "--guardrails-file", str(directory_link.name + "/policy.md"),
            cwd=target, env=no_bytecode, expected=(1,),
        )
        if tree(target) != before_ancestor_link:
            raise SystemExit("symlink-ancestor guardrails input changed project state")
        directory_link.unlink(); shutil.rmtree(real_dir)
        run(
            sys.executable, ".agent/scripts/agentctl.py", "project-init", "--guardrails-file", guardrails.name,
            cwd=target, env=no_bytecode,
        )
        config = json.loads((target / ".agent/config.json").read_text(encoding="utf-8"))
        policy = (target / ".agent/policies/PROJECT_GUARDRAILS.md").read_bytes()
        binding = config.get("project_initialization", {})
        agents = json.loads((target / ".agent/state/agents.json").read_text(encoding="utf-8"))
        task_after_init = json.loads((target / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        if config.get("guardrails_ready") is not True or binding.get("guardrails_sha256") != hashlib.sha256(policy).hexdigest():
            raise SystemExit("project-init did not atomically bind readiness to guardrails bytes")
        if (config["agent_control"].get("default_model") is not None or agents.get("default_model") is not None
                or task_after_init.get("status") != "idle"):
            raise SystemExit("project-init without --default-model did not preserve idle model neutrality")

        # Idle authorities stay null; each start binds one explicit model atomically.
        model_fixture=workspace/"per-task-model-start"
        shutil.copytree(target,model_fixture,symlinks=True)
        subprocess.run(["git","init","-q"],cwd=model_fixture,check=True)
        subprocess.run(["git","checkout","-q","-b","fix/per-task-model"],cwd=model_fixture,check=True)
        model_before=tree(model_fixture)
        missing_start_model=run(sys.executable,".agent/scripts/agentctl.py","start","--title","missing model",cwd=model_fixture,env=no_bytecode,expected=(2,))
        if "--model" not in missing_start_model.stdout or tree(model_fixture)!=model_before:
            raise SystemExit("missing per-task model did not fail immutably at the parser")
        rejected_selector=run(sys.executable,".agent/scripts/agentctl.py","select-model","--model","vendor-alpha/model.one",cwd=model_fixture,env=no_bytecode,expected=(1,))
        if "no longer persists idle authority" not in rejected_selector.stdout or tree(model_fixture)!=model_before:
            raise SystemExit("retired select-model command mutated idle authority")
        started=run(sys.executable,".agent/scripts/agentctl.py","start","--model","vendor-alpha/model.one","--title","explicit model fixture",cwd=model_fixture,env=no_bytecode)
        if "STARTED" not in started.stdout: raise SystemExit("explicit per-task model did not start")
        model_config=json.loads((model_fixture/".agent/config.json").read_text(encoding="utf-8"))
        model_agents=json.loads((model_fixture/".agent/state/agents.json").read_text(encoding="utf-8"))
        model_task=json.loads((model_fixture/".agent/state/TASK.json").read_text(encoding="utf-8"))
        if (model_task.get("selected_model")!="vendor-alpha/model.one" or model_config["agent_control"].get("default_model")!="vendor-alpha/model.one"
                or model_agents.get("default_model")!="vendor-alpha/model.one"):
            raise SystemExit("task start did not atomically bind all active model authorities")
        run(sys.executable,".agent/scripts/agentctl.py","validate",cwd=model_fixture,env=no_bytecode)
        active_before=tree(model_fixture)
        no_archive_receipt=run(sys.executable,".agent/scripts/agentctl.py","start","--model","vendor-alpha/model.two","--title","rollover",
            "--archive-active","--archive-source","user:test","--archive-reason","test",cwd=model_fixture,env=no_bytecode,expected=(1,))
        if "provider-signed human decision receipt" not in no_archive_receipt.stdout or tree(model_fixture)!=active_before:
            raise SystemExit(f"active rollover without provider receipt failed incorrectly: {no_archive_receipt.stdout!r} mutated={tree(model_fixture)!=active_before}")

        # A same-migration patch that changes managed policy bytes must first
        # validate the existing active capsule and then rebind it to the final bytes.
        patch_upgrade=workspace/"active-v400-policy-upgrade"
        shutil.copytree(target,patch_upgrade,symlinks=True)
        subprocess.run(["git","init","-q"],cwd=patch_upgrade,check=True)
        subprocess.run(["git","checkout","-q","-b","fix/active-patch-upgrade"],cwd=patch_upgrade,check=True)
        old_script=patch_upgrade/".agent/scripts/self_test_plugin_install_lifecycle.py"
        old_bytes=old_script.read_bytes().replace(b'manifest.get("version")!="4.0.2"',b'manifest.get("version")!="4.0.0"')
        if old_bytes==old_script.read_bytes(): raise SystemExit("active patch fixture did not downgrade one managed policy file")
        old_script.write_bytes(old_bytes)
        old_manifest_path=patch_upgrade/".agent/.workflow-manifest.json"
        old_manifest=json.loads(old_manifest_path.read_text(encoding="utf-8"))
        old_manifest["version"]="4.0.0"
        old_manifest["agent_files"]["scripts/self_test_plugin_install_lifecycle.py"]=hashlib.sha256(old_bytes).hexdigest()
        bind_v5_manifest_metadata(old_manifest)
        old_manifest_path.write_text(json.dumps(old_manifest,indent=2)+"\n",encoding="utf-8")
        fixture_rebind="""import sys
sys.path.insert(0,'.agent/scripts')
import contextctl
context=contextctl.load_json(contextctl.CONTEXT_PATH)
task=contextctl.load_json(contextctl.TASK_PATH)
context['policy_bundle_sha256']=contextctl.policy_bundle_sha256(task)
context['integrity']['content_sha256']='0'*64
context['integrity']['content_sha256']=contextctl.content_sha256(context)
contextctl.atomic_json(contextctl.CONTEXT_PATH,context)
raise SystemExit(contextctl.validate_context(quiet=True))
"""
        run(sys.executable,"-I","-B","-c",fixture_rebind,cwd=patch_upgrade,env=no_bytecode)
        run(sys.executable,".agent/scripts/agentctl.py","start","--model","vendor-alpha/model.patch","--title","active patch upgrade",cwd=patch_upgrade,env=no_bytecode)
        before_patch_context=json.loads((patch_upgrade/".agent/state/CONTEXT.json").read_text(encoding="utf-8"))
        drifted_patch=workspace/"active-v400-policy-upgrade-drifted"
        shutil.copytree(patch_upgrade,drifted_patch,symlinks=True)
        drifted_context_path=drifted_patch/".agent/state/CONTEXT.json"
        drifted_context=json.loads(drifted_context_path.read_text(encoding="utf-8"))
        drifted_context["phase_summary"]="tampered before same-migration patch update"
        drifted_context_path.write_text(json.dumps(drifted_context,indent=2)+"\n",encoding="utf-8")
        drifted_before=tree(drifted_patch)
        refused_patch=run(sys.executable,str(installer),str(drifted_patch),"--update",cwd=polluted,expected=(1,))
        if "active context has drift or corruption" not in refused_patch.stdout or tree(drifted_patch)!=drifted_before:
            raise SystemExit("same-migration patch update did not prevalidate active context byte-for-byte")
        run(sys.executable,str(installer),str(patch_upgrade),"--update",cwd=polluted)
        run(sys.executable,".agent/scripts/contextctl.py","check","--quiet",cwd=patch_upgrade,env=no_bytecode)
        run(sys.executable,str(installer),str(patch_upgrade),"--check",cwd=polluted)
        after_patch_context=json.loads((patch_upgrade/".agent/state/CONTEXT.json").read_text(encoding="utf-8"))
        if (after_patch_context.get("checkpoint",{}).get("sequence",0)<=before_patch_context.get("checkpoint",{}).get("sequence",0)
                or after_patch_context.get("checkpoint",{}).get("reason")!="release-managed-policy-rebind"
                or after_patch_context.get("policy_bundle_sha256")==before_patch_context.get("policy_bundle_sha256")):
            raise SystemExit("active v4.0.0 patch update did not rebind the final managed policy bundle")

        # A durable commit marker is never interpreted as permission to undo
        # later drift. Recovery fails closed and preserves both bytes and journal.
        committed_fixture = workspace / "committed-project-init-drift"
        shutil.copytree(target, committed_fixture, symlinks=True)
        committed_journal = committed_fixture / ".agent/state/.project-init-transaction.json"
        committed_journal.write_text(
            json.dumps(project_init_journal(committed_fixture, "committed"), indent=2) + "\n",
            encoding="utf-8",
        )
        committed_fixture.joinpath(".agent/config.json").write_text("{}\n", encoding="utf-8")
        drift_before = tree(committed_fixture)
        run(sys.executable, ".agent/scripts/agentctl.py", "status", cwd=committed_fixture, expected=(1,))
        if tree(committed_fixture) != drift_before or not committed_journal.exists():
            raise SystemExit("committed project-init drift was rolled back or journal was discarded")

        # Installed private additions survive update/migration; source sentinels do not.
        private = target / ".agent/state/evidence/project-private.txt"
        private.parent.mkdir(parents=True, exist_ok=True); private.write_text(TARGET_SENTINEL, encoding="utf-8")
        manifest_path = target / ".agent/.workflow-manifest.json"
        # v1 retains its explicit pre-release migration-32 compatibility path;
        # it is intentionally outside the released v3+ metadata mapping.
        manifest = as_legacy_v1_manifest(
            json.loads(manifest_path.read_text(encoding="utf-8")), "3.1.40", 32,
        )
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        crash_and_recover(installer, target, ("--update",), ("--check",), polluted)

        # A committed installer journal authorizes cleanup after mutable state advances.
        committed_env = dict(no_bytecode)
        committed_env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_COMMIT"] = "1"
        committed_trigger = target / ".agent/INDEX.md"; committed_trigger.chmod(0o600)
        run(sys.executable, str(installer), str(target), "--update", cwd=polluted, env=committed_env, expected=(98,))
        mutable_task = target / ".agent/state/TASK.json"
        mutable_value = json.loads(mutable_task.read_text(encoding="utf-8"))
        mutable_value["updated_at"] = "2099-01-01T00:00:00+00:00"
        mutable_bytes = (json.dumps(mutable_value, indent=2) + "\n").encode(); mutable_task.write_bytes(mutable_bytes)
        run(sys.executable, str(installer), str(target), "--update", cwd=polluted, env=no_bytecode)
        pending_installer_journal = target.parent / f".{target.name}.agent-workflow-transaction.json"
        if mutable_task.read_bytes() != mutable_bytes or pending_installer_journal.exists():
            raise SystemExit("committed recovery rejected or discarded legitimate mutable state")

        if private.read_text(encoding="utf-8") != TARGET_SENTINEL:
            raise SystemExit("update/migration replaced installed project-private evidence")
        assert_no_sentinel(target)

        # Adopt has the same isolation and rollback properties.
        manifest_path.unlink()
        crash_and_recover(installer, target, ("--adopt",), ("--adopt", "--dry-run"), polluted)
        if private.read_text(encoding="utf-8") != TARGET_SENTINEL:
            raise SystemExit("adopt replaced installed project-private evidence")
        assert_no_sentinel(target)
        run(sys.executable, str(installer), str(target), "--check", cwd=polluted)

        # v1 Skill locks do not prove the complete applicable legal-document set.
        # Idle updates quarantine their exact authority/content without converting
        # it to v2 approval; active tasks and mutation journals block byte-for-byte.
        legacy_skill=workspace/"legacy-skill-v1"
        shutil.copytree(target,legacy_skill,symlinks=True)
        legacy_project=legacy_skill/".agent/project"; legacy_project.mkdir(parents=True,exist_ok=True)
        legacy_lock={"schema":"agent-skills-lock/v1","skills":[{"id":"legacy-skill","license":"MIT"}]}
        (legacy_project/"skills.lock.json").write_text(json.dumps(legacy_lock,indent=2)+"\n",encoding="utf-8")
        for relative,content,mode in (
            ("skills/legacy-skill/SKILL.md","legacy active bytes\n",0o640),
            ("skill-cas/blob","legacy CAS bytes\n",0o600),
            ("skill-lock-history/old.json","{}\n",0o600),
            ("skill-lifecycle.json","{\"legacy\":true}\n",0o600),
            ("skill-candidates.json","{\"schema\":\"agent-skill-candidates/v1\"}\n",0o600),
            ("skill-recommendation.json","{\"legacy\":true}\n",0o600),
        ):
            path=legacy_project/relative; path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(content,encoding="utf-8"); path.chmod(mode)
        unrelated_private=legacy_project/"project-owned-private.txt"
        unrelated_private.write_text("preserve unrelated private bytes\n",encoding="utf-8")
        skill_before_check=tree(legacy_skill)
        skill_check=run(sys.executable,str(installer),str(legacy_skill),"--check",cwd=polluted,expected=(1,))
        if "UPDATE AVAILABLE" not in skill_check.stdout or tree(legacy_skill)!=skill_before_check:
            raise SystemExit("--check did not report v1 Skill quarantine without mutation")

        for blocked_role in ("active-task","mutation-journal"):
            blocked_skill=workspace/f"legacy-skill-v1-{blocked_role}"
            shutil.copytree(legacy_skill,blocked_skill,symlinks=True)
            if blocked_role=="active-task":
                blocked_task_path=blocked_skill/".agent/state/TASK.json"
                blocked_task=json.loads(blocked_task_path.read_text(encoding="utf-8")); blocked_task["status"]="running"
                blocked_task_path.write_text(json.dumps(blocked_task,indent=2)+"\n",encoding="utf-8")
            else:
                (blocked_skill/".agent/project/skill-mutation-journal.json").write_text("{}\n",encoding="utf-8")
            blocked_before=tree(blocked_skill)
            blocked_result=run(sys.executable,str(installer),str(blocked_skill),"--update",cwd=polluted,expected=(1,))
            expected_message=("non-idle task" if blocked_role=="active-task" else "mutation journal")
            if expected_message not in blocked_result.stdout or tree(blocked_skill)!=blocked_before:
                raise SystemExit(f"v1 Skill {blocked_role} did not block byte-for-byte")

        capability_legacy=workspace/"legacy-skill-v1-capability-blueprint"
        shutil.copytree(legacy_skill,capability_legacy,symlinks=True)
        capability_project=capability_legacy/".agent/project"
        run(sys.executable,".agent/scripts/blueprintctl.py","init",cwd=capability_legacy)
        capability_blueprint_path=capability_project/"BLUEPRINT.json"
        capability_blueprint=json.loads(capability_blueprint_path.read_text(encoding="utf-8"))
        capability_blueprint["design"]["capabilities"]=[{"id":"legacy-required-skill","description":"Require explicit legacy protocol guidance"}]
        capability_blueprint["status"]="confirmed"
        capability_blueprint["confirmation"]={"source":"user:legacy-confirmation","design_sha256":canonical_sha256(capability_blueprint["design"]),
            "confirmed_at":"2025-01-01T00:00:00+00:00","decision_receipt":{"legacy":"provider decision bytes"}}
        capability_blueprint_path.write_text(json.dumps(capability_blueprint,ensure_ascii=False,indent=2)+"\n",encoding="utf-8"); capability_blueprint_path.chmod(0o600)
        capability_blueprint_before=capability_blueprint_path.read_bytes()
        run(sys.executable,str(installer),str(capability_legacy),"--update",cwd=polluted)
        migrated_blueprint=json.loads(capability_blueprint_path.read_text(encoding="utf-8"))
        capability_quarantines=list((capability_project/"skill-quarantine").glob("legacy-v1-*"))
        archived_blueprint=capability_quarantines[0]/"payload/BLUEPRINT.json" if len(capability_quarantines)==1 else Path("missing")
        capability_activation=json.loads((capability_legacy/".agent/state/SKILL_ACTIVATION.json").read_text(encoding="utf-8"))
        capability_receipt=json.loads((capability_quarantines[0]/"RECEIPT.json").read_text(encoding="utf-8")) if len(capability_quarantines)==1 else {}
        if (migrated_blueprint.get("status")!="draft" or migrated_blueprint.get("confirmation") is not None
                or migrated_blueprint.get("design")!=capability_blueprint["design"] or not archived_blueprint.is_file()
                or archived_blueprint.read_bytes()!=capability_blueprint_before or capability_activation.get("skills")!=[]
                or capability_activation.get("lock_sha256") is not None or capability_receipt.get("blueprint_confirmation_revoked") is not True):
            raise SystemExit("capability-bearing v1 Blueprint remained wedged or migration fabricated replacement Skill authority")
        run(sys.executable,".agent/scripts/agentctl.py","validate",cwd=capability_legacy)

        symlinked_quarantine=workspace/"legacy-skill-v1-symlinked-quarantine"
        shutil.copytree(legacy_skill,symlinked_quarantine,symlinks=True)
        external_quarantine=workspace/"external-skill-quarantine"; external_quarantine.mkdir()
        external_sentinel=external_quarantine/"sentinel"; external_sentinel.write_text("preserve external bytes\n",encoding="utf-8")
        (symlinked_quarantine/".agent/project/skill-quarantine").symlink_to(external_quarantine,target_is_directory=True)
        blocked_symlink=run(sys.executable,str(installer),str(symlinked_quarantine),"--update",cwd=polluted,expected=(1,))
        if (not any(message in blocked_symlink.stdout.lower() for message in ("quarantine parent","symlink")) or external_sentinel.read_text(encoding="utf-8")!="preserve external bytes\n"
                or len(list(external_quarantine.iterdir()))!=1):
            raise SystemExit("v1 Skill quarantine followed or mutated a symlinked archive parent")

        run(sys.executable,str(installer),str(legacy_skill),"--update",cwd=polluted)
        if unrelated_private.read_text(encoding="utf-8")!="preserve unrelated private bytes\n":
            raise SystemExit("v1 Skill quarantine changed unrelated private state")
        for retired_name in ("skills.lock.json","skills","skill-cas","skill-lock-history","skill-lifecycle.json","skill-candidates.json","skill-recommendation.json"):
            if (legacy_project/retired_name).exists(): raise SystemExit(f"v1 Skill authority remained active: {retired_name}")
        quarantine_roots=list((legacy_project/"skill-quarantine").glob("legacy-v1-*"))
        if len(quarantine_roots)!=1: raise SystemExit("v1 Skill quarantine did not create one digest-bound archive")
        quarantine=quarantine_roots[0]; receipt_path=quarantine/"RECEIPT.json"
        receipt=json.loads(receipt_path.read_text(encoding="utf-8"))
        if (quarantine.stat().st_mode&0o777!=0o700 or receipt_path.stat().st_mode&0o777!=0o600
                or receipt.get("source_lock_schema")!="agent-skills-lock/v1"
                or receipt.get("authority_converted") is not False
                or receipt.get("legal_approval_fabricated") is not False):
            raise SystemExit("v1 Skill quarantine receipt fabricated or weakened authority")
        archived_lock=quarantine/"payload/skills.lock.json"
        archived_skill=quarantine/"payload/skills/legacy-skill/SKILL.md"
        if (json.loads(archived_lock.read_text(encoding="utf-8"))!=legacy_lock
                or archived_skill.read_text(encoding="utf-8")!="legacy active bytes\n"
                or archived_skill.stat().st_mode&0o777!=0o640
                or any(path.name=="skills.lock.json" and "skill-quarantine" not in path.parts
                       for path in legacy_project.rglob("skills.lock.json"))):
            raise SystemExit("v1 Skill quarantine did not preserve exact content/modes or left authority active")
        run(sys.executable,str(installer),str(legacy_skill),"--check",cwd=polluted)

        managed_mode_path = target / ".agent/scripts/agentctl.py"
        canonical_mode=fresh_manifest["agent_modes"]["scripts/agentctl.py"]
        managed_mode_path.chmod(canonical_mode ^ 0o100)
        mode_check = run(sys.executable, str(installer), str(target), "--check", cwd=polluted, expected=(1,))
        if "UPDATE AVAILABLE" not in mode_check.stdout:
            raise SystemExit("managed mode drift was not reported")
        run(sys.executable, str(installer), str(target), "--update", cwd=polluted)
        if managed_mode_path.stat().st_mode & 0o777 != canonical_mode:
            raise SystemExit("managed mode drift was not repaired from the bound source mode")

        managed_directory=target/".agent/scripts"; managed_directory.chmod(0o700)
        directory_check=run(sys.executable,str(installer),str(target),"--check",cwd=polluted,expected=(1,))
        if "UPDATE AVAILABLE" not in directory_check.stdout:
            raise SystemExit("managed directory mode drift was not reported")
        run(sys.executable,str(installer),str(target),"--update",cwd=polluted)
        if managed_directory.stat().st_mode&0o777!=0o755:
            raise SystemExit("managed directory mode drift was not repaired to 0755")
        agent_root=target/".agent"; agent_root.chmod(0o755)
        root_check=run(sys.executable,str(installer),str(target),"--check",cwd=polluted,expected=(1,))
        if "UPDATE AVAILABLE" not in root_check.stdout:
            raise SystemExit(".agent root mode drift was not reported")
        run(sys.executable,str(installer),str(target),"--update",cwd=polluted)
        if stat.S_IMODE(os.lstat(agent_root).st_mode)!=0o700:
            raise SystemExit(".agent root mode drift was not repaired to 0700")

        # Exact legacy-managed pxpipe is removed with its marketplace entry in
        # the same crash-recoverable transaction; unrelated plugins survive.
        legacy_pxpipe = workspace / "legacy-pxpipe-install"
        run(sys.executable, str(installer), str(legacy_pxpipe), "--project-name", "legacy-pxpipe", cwd=polluted)
        legacy_plugin = legacy_pxpipe / "plugins/pxpipe-context"
        legacy_plugin.mkdir(parents=True)
        legacy_bundle = legacy_plugin / "legacy-bundle.mjs"
        legacy_bundle.write_text("export const legacy = true;\n", encoding="utf-8")
        legacy_scripts=legacy_plugin/"scripts"; legacy_scripts.mkdir()
        for helper_name in ("uninstall-codex-default.sh","codex-default-config.mjs"):
            shutil.copy2(source/"plugins/pxpipe-context/scripts"/helper_name,legacy_scripts/helper_name)
        unrelated_plugin = legacy_pxpipe / "plugins/project-owned"
        unrelated_plugin.mkdir()
        (unrelated_plugin / "sentinel.txt").write_text(TARGET_SENTINEL, encoding="utf-8")
        legacy_entry = {"name": "pxpipe-context", "source": "./plugins/pxpipe-context", "version": "legacy"}
        unrelated_entry = {"name": "project-owned", "source": "./plugins/project-owned"}
        marketplace_path = legacy_pxpipe / ".agents/plugins/marketplace.json"
        marketplace_path.parent.mkdir(parents=True)
        marketplace_path.write_text(json.dumps({"schema": "fixture/v1", "owner": "project", "plugins": [unrelated_entry, legacy_entry]}, indent=2) + "\n", encoding="utf-8")
        current_manifest_path = legacy_pxpipe / ".agent/.workflow-manifest.json"
        current_manifest = json.loads(current_manifest_path.read_text(encoding="utf-8"))
        legacy_config_path=legacy_pxpipe/".agent/config.json"
        legacy_config=json.loads(legacy_config_path.read_text(encoding="utf-8"))
        legacy_config["context_transport"]={"default":"native","pxpipe":dict(enabled_policy)}
        legacy_config["agent_control"]["default_model"]="provider/model"
        legacy_config["project_retained_fixture"]={"exact":"preserve-me"}
        legacy_config_path.write_text(json.dumps(legacy_config,indent=2)+"\n",encoding="utf-8")
        legacy_agents_path=legacy_pxpipe/".agent/state/agents.json"
        legacy_agents=json.loads(legacy_agents_path.read_text(encoding="utf-8")); legacy_agents["default_model"]="provider/model"
        legacy_agents_path.write_text(json.dumps(legacy_agents,indent=2)+"\n",encoding="utf-8")
        plugin_files = {
            str(path.relative_to(legacy_plugin)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(legacy_plugin.rglob("*")) if path.is_file()
        }
        entry_digest = canonical_sha256(legacy_entry)
        legacy_pxpipe_binding={"name":"pxpipe-context","provenance_status":"verified","files":plugin_files,
                               "marketplace_entry_sha256":entry_digest}
        legacy_payload = {
            "schema":"agent-workflow-install/v5","version":"4.0.0","migration_version":42,"agent_root_mode":0o700,
            "agent_files":current_manifest["agent_files"],"agent_modes":current_manifest["agent_modes"],
            "pxpipe":legacy_pxpipe_binding,
            "agents_bootstrap_sha256":current_manifest["agents_bootstrap"]["sha256"],
            "claude_bootstrap_sha256":current_manifest["claude_bootstrap"]["sha256"],
        }
        legacy_manifest = {
            "schema":"agent-workflow-install/v5","version":"4.0.0","migration_version":42,
            "source_tree_sha256":canonical_sha256(legacy_payload),"agent_root_mode":0o700,"agent_files":current_manifest["agent_files"],
            "agent_modes":current_manifest["agent_modes"],"pxpipe":legacy_pxpipe_binding,
            "agents_bootstrap":current_manifest["agents_bootstrap"],"claude_bootstrap":current_manifest["claude_bootstrap"],
        }
        current_manifest_path.write_text(json.dumps(legacy_manifest, indent=2) + "\n", encoding="utf-8")
        legacy_manifest_digest=hashlib.sha256(current_manifest_path.read_bytes()).hexdigest()

        unsafe_nested = workspace / "legacy-pxpipe-unsafe-nested"
        shutil.copytree(legacy_pxpipe, unsafe_nested, symlinks=True)
        unsafe_nested_parent = unsafe_nested / ".agents/plugins"
        unsafe_nested_parent.chmod(0o777)
        unsafe_nested_before = tree(unsafe_nested)
        unsafe_nested_result = run(sys.executable, str(installer), str(unsafe_nested), "--update", cwd=polluted, expected=(1,))
        if ("owner-controlled directory" not in unsafe_nested_result.stdout
                or tree(unsafe_nested) != unsafe_nested_before):
            raise SystemExit(f"writable nested transaction namespace was accepted or mutated: output={unsafe_nested_result.stdout[-1200:]!r} tree_equal={tree(unsafe_nested)==unsafe_nested_before}")
        unsafe_nested_parent.chmod(0o755)

        drifted_pxpipe = workspace / "legacy-pxpipe-drift"
        shutil.copytree(legacy_pxpipe, drifted_pxpipe, symlinks=True)
        (drifted_pxpipe / "plugins/pxpipe-context/legacy-bundle.mjs").write_text("drifted\n", encoding="utf-8")
        drifted_before = tree(drifted_pxpipe)
        drifted_result = run(sys.executable, str(installer), str(drifted_pxpipe), "--update", cwd=polluted, expected=(2,))
        if "owned tree drift" not in drifted_result.stdout or tree(drifted_pxpipe) != drifted_before:
            raise SystemExit("drifted legacy pxpipe was not preserved and rejected")

        drifted_marketplace=workspace/"legacy-pxpipe-marketplace-drift"
        shutil.copytree(legacy_pxpipe,drifted_marketplace,symlinks=True)
        drifted_marketplace_path=drifted_marketplace/".agents/plugins/marketplace.json"
        drifted_marketplace_value=json.loads(drifted_marketplace_path.read_text(encoding="utf-8"))
        drifted_marketplace_value["plugins"][-1]["version"]="project-drift"
        drifted_marketplace_path.write_text(json.dumps(drifted_marketplace_value,indent=2)+"\n",encoding="utf-8")
        drifted_marketplace_before=tree(drifted_marketplace)
        drifted_marketplace_result=run(sys.executable,str(installer),str(drifted_marketplace),"--update",cwd=polluted,expected=(2,))
        if ("unowned or drifted pxpipe entry" not in drifted_marketplace_result.stdout
                or tree(drifted_marketplace)!=drifted_marketplace_before):
            raise SystemExit("drifted pxpipe marketplace authority was not preserved and rejected")

        for missing_role in ("plugin","marketplace"):
            missing=workspace/f"legacy-pxpipe-missing-{missing_role}"
            shutil.copytree(legacy_pxpipe,missing,symlinks=True)
            missing_path=(missing/"plugins/pxpipe-context" if missing_role=="plugin"
                          else missing/".agents/plugins/marketplace.json")
            if missing_path.is_dir(): shutil.rmtree(missing_path)
            else: missing_path.unlink()
            missing_before=tree(missing)
            missing_result=run(sys.executable,str(installer),str(missing),"--update",cwd=polluted,expected=(1,))
            if ("verified plugin provenance" not in missing_result.stdout
                    or tree(missing)!=missing_before):
                raise SystemExit(f"missing pxpipe {missing_role} did not fail closed byte-for-byte")

        isolated_home=workspace/"pxpipe-global-home"; isolated_home.mkdir(mode=0o700)
        crash_env = dict(os.environ); crash_env["HOME"]=str(isolated_home)
        crash_env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_TARGET"] = "3"
        run(sys.executable, str(installer), str(legacy_pxpipe), "--update", cwd=polluted, env=crash_env, expected=(97,))
        pxpipe_crashed = tree(legacy_pxpipe)
        pending = run(sys.executable, str(installer), str(legacy_pxpipe), "--check", cwd=polluted, expected=(2,))
        if "RECOVERY REQUIRED" not in pending.stdout or tree(legacy_pxpipe) != pxpipe_crashed:
            raise SystemExit("read-only check mutated interrupted legacy pxpipe cleanup")
        recovery_env=dict(os.environ); recovery_env["HOME"]=str(isolated_home)
        run(sys.executable, str(installer), str(legacy_pxpipe), "--update", cwd=polluted, env=recovery_env)
        if legacy_plugin.exists() or not (unrelated_plugin / "sentinel.txt").is_file():
            raise SystemExit("legacy pxpipe cleanup removed the wrong plugin tree")
        global_receipt_path=legacy_pxpipe/".agent/state/evidence/agent-global-pxpipe-retirement-receipt.json"
        global_receipt=json.loads(global_receipt_path.read_text(encoding="utf-8"))
        if (global_receipt_path.stat().st_mode&0o777!=0o600
                or global_receipt.get("schema")!="agent-global-pxpipe-retirement-receipt/v1"
                or global_receipt.get("terminal") is not True
                or global_receipt.get("prior_manifest_sha256")!=legacy_manifest_digest
                or set(global_receipt.get("helper_sha256",{}))!={"scripts/uninstall-codex-default.sh","scripts/codex-default-config.mjs"}
                or any(record!={"kind":"absent"} for record in global_receipt.get("post_state",{}).values())
                or (legacy_pxpipe/".agent/state/agent-global-pxpipe-retirement-intent.json").exists()):
            raise SystemExit("global pxpipe retirement receipt is incomplete or not terminal")
        cleaned_marketplace = json.loads(marketplace_path.read_text(encoding="utf-8"))
        if cleaned_marketplace != {"schema": "fixture/v1", "owner": "project", "plugins": [unrelated_entry]}:
            raise SystemExit("legacy pxpipe cleanup did not preserve unrelated marketplace data")
        retired_config=json.loads(legacy_config_path.read_text(encoding="utf-8"))
        if (retired_config.get("context_transport")!={"default":"native"}
                or retired_config.get("project_retained_fixture")!={"exact":"preserve-me"}):
            raise SystemExit("verified pxpipe retirement did not replace only the exact transport policy")
        retirement_dir=legacy_pxpipe/".agent/state/evidence/context-transport-retirements"
        retirement_files=list(retirement_dir.iterdir()) if retirement_dir.is_dir() else []
        if len(retirement_files)!=1:
            raise SystemExit("verified pxpipe retirement did not archive exactly one private receipt")
        retirement=json.loads(retirement_files[0].read_text(encoding="utf-8"))
        if (retirement_files[0].stat().st_mode&0o777!=0o600
                or retirement.get("replacement")!={"default":"native"}
                or retirement.get("retired_policy")!=legacy_config["context_transport"]):
            raise SystemExit("verified pxpipe retirement receipt lost exact private policy evidence")
        run(sys.executable, str(installer), str(legacy_pxpipe), "--check", cwd=polluted, env=recovery_env)

        unowned_pxpipe = workspace / "unowned-pxpipe-install"
        run(sys.executable, str(installer), str(unowned_pxpipe), "--project-name", "unowned-pxpipe", cwd=polluted)
        (unowned_pxpipe / "plugins/pxpipe-context").mkdir(parents=True)
        (unowned_pxpipe / "plugins/pxpipe-context/README").write_text("project bytes\n", encoding="utf-8")
        unowned_before = tree(unowned_pxpipe)
        unowned_result = run(sys.executable, str(installer), str(unowned_pxpipe), "--update", cwd=polluted, expected=(2,))
        if "unowned reserved path" not in unowned_result.stdout or tree(unowned_pxpipe) != unowned_before:
            raise SystemExit("unowned pxpipe namespace did not fail closed byte-for-byte")

        poison = target / ".agent/scripts/typing.py"
        poison.write_text("from pathlib import Path\nPath('LEGACY_EXECUTED').write_text('bad')\n", encoding="utf-8")
        blocked = run(sys.executable, str(installer), str(target), "--update", cwd=polluted, expected=(2,))
        if "typing.py" not in blocked.stdout or (target / "LEGACY_EXECUTED").exists():
            raise SystemExit("unmanifested legacy Python was not rejected before execution")
        poison.unlink()

        # An older installer must never silently downgrade a newer install.
        newer = workspace / "newer-install"
        run(sys.executable, str(installer), str(newer), "--project-name", "downgrade-fixture", cwd=polluted)
        newer_manifest_path = newer / ".agent/.workflow-manifest.json"
        newer_manifest = json.loads(newer_manifest_path.read_text(encoding="utf-8"))
        newer_manifest["version"] = "99.0.0"; newer_manifest["migration_version"] = 99
        bind_v5_manifest_metadata(newer_manifest)
        newer_manifest_path.write_text(json.dumps(newer_manifest, indent=2) + "\n", encoding="utf-8")
        newer_before = tree(newer)
        for mode_args in (("--check",), ("--update",)):
            refused = run(sys.executable, str(installer), str(newer), *mode_args, cwd=polluted, expected=(1,))
            if "version/migration combination is not a supported release" not in refused.stdout or tree(newer) != newer_before:
                raise SystemExit("unknown v5 release combination was accepted or mutated byte-for-byte")
        for removed_args in (("--allow-downgrade",),("--agent-platform-snapshot","unused")):
            rejected=run(sys.executable,str(installer),str(newer),"--update",*removed_args,cwd=polluted,expected=(2,))
            if "unrecognized arguments" not in rejected.stdout or tree(newer)!=newer_before:
                raise SystemExit(f"removed installer CLI surface remained accepted: {removed_args[0]}")

        # Unknown installed version syntax cannot be ordered safely. Both
        # read-only checks and updates fail closed without changing any bytes.
        unknown_version = workspace / "unknown-workflow-version"
        run(
            sys.executable, str(installer), str(unknown_version),
            "--project-name", "unknown-version-fixture", cwd=polluted,
        )
        unknown_manifest_path = unknown_version / ".agent/.workflow-manifest.json"
        for bad_value in ("3.2.1-rc.1", "v99.0.0", "99"):
            unknown_manifest = json.loads(unknown_manifest_path.read_text(encoding="utf-8"))
            unknown_manifest["version"] = bad_value
            unknown_manifest["migration_version"] = 42
            unknown_manifest_path.write_text(json.dumps(unknown_manifest, indent=2) + "\n", encoding="utf-8")
            version_before = tree(unknown_version)
            check_unknown = run(
                sys.executable, str(installer), str(unknown_version), "--check",
                cwd=polluted, expected=(1,),
            )
            if "manifest version is malformed or unsupported" not in check_unknown.stdout or tree(unknown_version) != version_before:
                raise SystemExit(f"--check did not reject unknown workflow version {bad_value!r} byte-for-byte")
            update_unknown = run(
                sys.executable, str(installer), str(unknown_version), "--update",
                cwd=polluted, expected=(1,),
            )
            if "manifest version is malformed or unsupported" not in update_unknown.stdout or tree(unknown_version) != version_before:
                raise SystemExit(f"--update did not reject unknown workflow version {bad_value!r} byte-for-byte")

        # A malformed migration_version fails closed with a clean message and
        # never leaks an uncaught ValueError traceback or mutates the target.
        malformed_version = workspace / "malformed-migration-version"
        run(
            sys.executable, str(installer), str(malformed_version),
            "--project-name", "malformed-version-fixture", cwd=polluted,
        )
        malformed_manifest_path = malformed_version / ".agent/.workflow-manifest.json"
        for bad_value in ("abc", True, -1, 2**31):
            malformed_manifest = json.loads(malformed_manifest_path.read_text(encoding="utf-8"))
            malformed_manifest["migration_version"] = bad_value
            malformed_manifest_path.write_text(json.dumps(malformed_manifest, indent=2) + "\n", encoding="utf-8")
            version_before = tree(malformed_version)
            for mode_args in (("--check",), ("--update",)):
                refused = run(
                    sys.executable, str(installer), str(malformed_version), *mode_args,
                    cwd=polluted, expected=(1, 2, 3),
                )
                if "Traceback" in refused.stdout or "migration version" not in refused.stdout:
                    raise SystemExit(
                        f"malformed migration_version {bad_value!r} did not fail closed cleanly:\n{refused.stdout}"
                    )
            if tree(malformed_version) != version_before:
                raise SystemExit(f"malformed migration_version {bad_value!r} changed project bytes")

        # Well-formed but unreleased legacy metadata fails before update
        # planning and cannot create a transaction or mutate target bytes.
        unknown_legacy_pair = workspace / "unknown-legacy-release-pair"
        run(sys.executable, str(installer), str(unknown_legacy_pair),
            "--project-name", "unknown-legacy-pair", cwd=polluted)
        unknown_legacy_manifest_path = unknown_legacy_pair / ".agent/.workflow-manifest.json"
        unknown_legacy_manifest = as_released_v4_manifest(
            json.loads(unknown_legacy_manifest_path.read_text(encoding="utf-8")), "3.1.44", 40,
        )
        unknown_legacy_manifest_path.write_text(json.dumps(unknown_legacy_manifest, indent=2) + "\n", encoding="utf-8")
        unknown_legacy_before = tree(unknown_legacy_pair)
        for mode_args in (("--check",), ("--update",)):
            refused = run(sys.executable, str(installer), str(unknown_legacy_pair), *mode_args,
                          cwd=polluted, expected=(1,))
            pending = unknown_legacy_pair.parent / f".{unknown_legacy_pair.name}.agent-workflow-transaction.json"
            if ("schema/version/migration combination is not a supported release" not in refused.stdout
                    or tree(unknown_legacy_pair) != unknown_legacy_before or pending.exists()):
                raise SystemExit("well-formed unknown legacy release reached planning or mutated bytes")

        # v5 binds schema, version, and migration authority into the canonical
        # source digest; even syntactically valid metadata edits cannot skip work.
        bound_metadata = workspace / "bound-manifest-metadata"
        run(sys.executable, str(installer), str(bound_metadata),
            "--project-name", "bound-metadata-fixture", cwd=polluted)
        bound_manifest_path = bound_metadata / ".agent/.workflow-manifest.json"
        baseline_manifest = bound_manifest_path.read_bytes()
        for field, bad_value, expected_text in (
            ("version", "4.0.3", "schema/version/migration combination is not a supported release"),
            ("migration_version", 41, "schema/version/migration combination is not a supported release"),
            ("schema", "agent-workflow-install/v6", "invalid workflow install manifest"),
        ):
            candidate_manifest = json.loads(baseline_manifest)
            candidate_manifest[field] = bad_value
            bound_manifest_path.write_text(json.dumps(candidate_manifest, indent=2) + "\n", encoding="utf-8")
            metadata_before = tree(bound_metadata)
            for mode_args in (("--check",), ("--update",)):
                refused = run(sys.executable, str(installer), str(bound_metadata), *mode_args,
                              cwd=polluted, expected=(1,))
                if expected_text not in refused.stdout or tree(bound_metadata) != metadata_before:
                    raise SystemExit(f"v5 {field} tamper was not rejected byte-for-byte: {refused.stdout}")
            bound_manifest_path.write_bytes(baseline_manifest)
        for field, bad_value in (("version", "4.0.3"), ("migration_version", 41)):
            candidate_manifest = json.loads(baseline_manifest)
            candidate_manifest[field] = bad_value
            bind_v5_manifest_metadata(candidate_manifest)
            bound_manifest_path.write_text(json.dumps(candidate_manifest, indent=2) + "\n", encoding="utf-8")
            metadata_before = tree(bound_metadata)
            for mode_args in (("--check",), ("--update",)):
                refused = run(sys.executable, str(installer), str(bound_metadata), *mode_args,
                              cwd=polluted, expected=(1,))
                if ("version/migration combination is not a supported release" not in refused.stdout
                        or tree(bound_metadata) != metadata_before):
                    raise SystemExit(f"self-consistent unknown v5 {field} release was accepted: {refused.stdout}")
            bound_manifest_path.write_bytes(baseline_manifest)

        # Migration 36 retires the transition-increment alias honestly: the
        # alias's true historical semantic was the per-transition increment,
        # so a mode is carried into context.transition_token_increment only
        # when its legacy value differs from that mode's legacy seed constant
        # (150/300/500), clamped to [50, 1000] (release 900 -> 900).  The
        # honest per-turn overhead is never rewritten by the alias, and
        # migration 37 fills the remaining modes with 200/400/800.
        carry = workspace / "migration-36-carry"
        run(
            sys.executable, str(installer), str(carry),
            "--project-name", "migration-carry-fixture", cwd=polluted,
        )
        carry_config_path = carry / ".agent/config.json"
        carry_config = json.loads(carry_config_path.read_text(encoding="utf-8"))
        carry_config["context"]["automatic_transition_token_increment"] = {"fast": 150, "standard": 300, "release": 900}
        carry_config_path.write_text(json.dumps(carry_config, indent=2) + "\n", encoding="utf-8")
        carry_manifest_path = carry / ".agent/.workflow-manifest.json"
        carry_manifest = as_released_v4_manifest(
            json.loads(carry_manifest_path.read_text(encoding="utf-8")), "3.1.42", 35,
        )
        carry_manifest_path.write_text(json.dumps(carry_manifest, indent=2) + "\n", encoding="utf-8")
        run(sys.executable, str(installer), str(carry), "--update", cwd=polluted)
        migrated_context = json.loads(carry_config_path.read_text(encoding="utf-8"))["context"]
        if "automatic_transition_token_increment" in migrated_context:
            raise SystemExit("migration 36 left the deprecated transition-increment alias behind")
        carried = migrated_context.get("transition_token_increment")
        if carried != {"fast": 200, "standard": 400, "release": 900}:
            raise SystemExit(f"migration 36 did not carry per-mode honestly: {carried}")
        if migrated_context.get("estimated_turn_overhead_tokens") != {"fast": 2000, "standard": 3000, "release": 4000}:
            raise SystemExit("migration 36 rewrote the honest per-turn overhead from the alias")

        # Migration 38 repairs every lower-mode carry permutation that
        # Released v3.2.0 could leave non-monotonic while reporting update success.
        for label, legacy, expected in (
            (
                "fast", {"fast": 900, "standard": 300, "release": 500},
                {"fast": 900, "standard": 900, "release": 900},
            ),
            (
                "standard", {"fast": 150, "standard": 900, "release": 500},
                {"fast": 200, "standard": 900, "release": 900},
            ),
            (
                "release", {"fast": 150, "standard": 300, "release": 900},
                {"fast": 200, "standard": 400, "release": 900},
            ),
        ):
            target = workspace / f"migration-38-{label}-carry"
            run(
                sys.executable, str(installer), str(target),
                "--project-name", f"migration-38-{label}", cwd=polluted,
            )
            config_path = target / ".agent/config.json"
            value = json.loads(config_path.read_text(encoding="utf-8"))
            value["context"].pop("transition_token_increment", None)
            value["context"]["automatic_transition_token_increment"] = legacy
            config_path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            manifest_path = target / ".agent/.workflow-manifest.json"
            manifest = as_released_v4_manifest(
                json.loads(manifest_path.read_text(encoding="utf-8")), "3.1.42", 35,
            )
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            run(sys.executable, str(installer), str(target), "--update", cwd=polluted)
            migrated = json.loads(config_path.read_text(encoding="utf-8"))
            if migrated["context"].get("transition_token_increment") != expected:
                raise SystemExit(
                    f"migration 38 did not normalize {label} legacy carry: "
                    f"{migrated['context'].get('transition_token_increment')}"
                )
            run(
                sys.executable, str(target / ".agent/scripts/agentctl.py"), "validate",
                cwd=target,
            )

        # Read-only modes never create directories for missing targets.
        ghost = workspace / "ghost-parent" / "ghost-project"
        run(sys.executable, str(installer), str(ghost), "--check", cwd=polluted, expected=(1,))
        if (workspace / "ghost-parent").exists():
            raise SystemExit("--check created directories for a missing target")
        dry_ghost = run(
            sys.executable, str(installer), str(ghost), "--project-name", "ghost", "--dry-run",
            cwd=polluted,expected=(1,),
        )
        if "target parent must already exist" not in dry_ghost.stdout or (workspace / "ghost-parent").exists():
            raise SystemExit("--dry-run skipped the mutating parent feasibility check")
        dry_parent=workspace/"dry-parent"; dry_parent.mkdir(); dry_target=dry_parent/"project"
        adapter_rejections=[]
        for mode_args in (("--dry-run",),()):
            rejected=run(sys.executable,str(installer),str(dry_target),"--project-name","dry",
                *mode_args,"--provider-preflight-adapter",sys.executable,cwd=polluted,expected=(1,))
            terminal=rejected.stdout.strip().splitlines()[-1] if rejected.stdout.strip() else ""
            adapter_rejections.append(terminal)
            if "provider preflight adapter must be" not in terminal or dry_target.exists():
                raise SystemExit("dry-run and mutation did not reject the same invalid adapter before writing")
        if adapter_rejections[0]!=adapter_rejections[1]:
            raise SystemExit("dry-run and mutation adapter rejection reasons diverged")
        dry_ok=run(sys.executable,str(installer),str(dry_target),"--project-name","dry","--dry-run",cwd=polluted)
        if "DRY RUN" not in dry_ok.stdout or dry_target.exists():
            raise SystemExit("successful fresh dry-run wrote target bytes or skipped candidate validation")
        missing_parent_install = run(
            sys.executable, str(installer), str(ghost), "--project-name", "ghost",
            cwd=polluted, expected=(1,),
        )
        if ("target parent must already exist" not in missing_parent_install.stdout
                or (workspace / "ghost-parent").exists()):
            raise SystemExit("mutating install created or accepted an unbound target parent")

        # Installer guardrails are opened lexically and no-follow. Resolving a
        # leaf symlink, accepting a hard link, or accepting a special file must
        # fail before any target transaction is created.
        safe_guardrails=workspace/"installer-guardrails.md"; completed_guardrails(safe_guardrails)
        linked_guardrails=workspace/"installer-guardrails-link.md"; linked_guardrails.symlink_to(safe_guardrails.name)
        hard_guardrails=workspace/"installer-guardrails-hard.md"; os.link(safe_guardrails,hard_guardrails)
        fifo_guardrails=workspace/"installer-guardrails.fifo"; os.mkfifo(fifo_guardrails)
        for label,unsafe in (("symlink",linked_guardrails),("hardlink",hard_guardrails),("special",fifo_guardrails)):
            unsafe_target=workspace/f"unsafe-guardrails-{label}"
            rejected=run(sys.executable,str(installer),str(unsafe_target),"--project-name",label,
                         "--guardrails-file",str(unsafe),cwd=polluted,expected=(1,))
            if "guardrails file" not in rejected.stdout or unsafe_target.exists():
                raise SystemExit(f"{label} installer guardrails source was accepted or mutated target")

        # A dangling journal symlink is occupied recovery authority in every
        # read-only mode; pathlib.exists() alone would incorrectly hide it.
        dangling_journal=target.parent/f".{target.name}.agent-workflow-transaction.json"
        dangling_journal.symlink_to("missing-journal-target")
        try:
            for readonly_args in (("--check",),("--update","--dry-run")):
                pending=run(sys.executable,str(installer),str(target),*readonly_args,cwd=polluted,expected=(2,))
                if "RECOVERY REQUIRED" not in pending.stdout or not dangling_journal.is_symlink():
                    raise SystemExit("dangling transaction journal did not fail closed in read-only mode")
        finally: dangling_journal.unlink()

        # A dedicated executable stub emitting the exact provider-preflight
        # health line passes the health protocol; wrong output is rejected.
        # Existing project roots bind only explicit absence or directory
        # identity. Unmanaged .git/build/dependency bytes are not transaction
        # replacements and must neither hit the 512 MiB content bound nor make
        # unrelated product writes abort installation.
        scalable_target=(workspace/"large-unmanaged-project").resolve(); scalable_target.mkdir()
        unmanaged_build=scalable_target/"build"; unmanaged_build.mkdir()
        oversized=unmanaged_build/"dependency-cache.bin"
        with oversized.open("wb") as handle:
            handle.seek(512*1024*1024); handle.write(b"x")
        root_authority=installer_module.planned_transaction_root(scalable_target)
        if set(root_authority)!={"present","identity"} or root_authority["present"] is not True:
            raise SystemExit("present project root plan unexpectedly includes content authority")
        real_begin_transaction=installer_module.begin_transaction
        def mutate_unmanaged_after_root_plan(transaction_target):
            (transaction_target/"build/product-write.txt").write_text("concurrent product write",encoding="utf-8")
            return real_begin_transaction(transaction_target)
        installer_module.begin_transaction=mutate_unmanaged_after_root_plan
        scalable_args=argparse.Namespace(
            guardrails_file=None,project_name="large-unmanaged",project_type="general-project",
            default_model=None,human_decision_adapter=None,provider_preflight_adapter=None,
            dry_run=False,agent_platform_snapshot=None,
        )
        try: installer_module.install(polluted,scalable_target,scalable_args)
        finally: installer_module.begin_transaction=real_begin_transaction
        if (not (scalable_target/".agent").is_dir()
                or oversized.stat().st_size!=512*1024*1024+1
                or (scalable_target/"build/product-write.txt").read_text(encoding="utf-8")!="concurrent product write"):
            raise SystemExit("identity-only root transaction changed or rejected unmanaged project content")
        fingerprint_probe=run(
            sys.executable,"-B","-c",
            "import json,sys;sys.path.insert(0,'.agent/scripts');import testrun;"
            "config=json.loads(testrun.CONFIG_PATH.read_text(encoding='utf-8'));"
            "snapshot=testrun.capture_candidate_snapshot(config);"
            "sys.exit('empty installed candidate snapshot') if not snapshot['files'] else None",
            cwd=scalable_target,
        )
        if fingerprint_probe.stdout:
            raise SystemExit(f"minimal adopter fingerprint probe emitted unexpected output: {fingerprint_probe.stdout}")

        # Exercise the real new-install call site: a project/.agent that
        # appears only after initial absence planning is never adopted by the
        # later commit, and recovery cleanup preserves the concurrent owner.
        install_race_target=(workspace/"new-install-planned-absence-race").resolve()
        real_begin_transaction=installer_module.begin_transaction
        def create_target_after_install_plan(race_target):
            race_target.mkdir(); (race_target/".agent").mkdir()
            (race_target/".agent/concurrent-sentinel").write_text("concurrent owner",encoding="utf-8")
            return real_begin_transaction(race_target)
        installer_module.begin_transaction=create_target_after_install_plan
        race_args=argparse.Namespace(
            guardrails_file=None,project_name="planned-race",project_type="general-project",
            default_model=None,human_decision_adapter=None,provider_preflight_adapter=None,
            dry_run=False,agent_platform_snapshot=None,
        )
        try:
            try: installer_module.install(polluted,install_race_target,race_args)
            except RuntimeError as error:
                if "planned transaction target absence changed" not in str(error): raise
            else: raise SystemExit("new install overwrote a target that appeared after absence planning")
        finally: installer_module.begin_transaction=real_begin_transaction
        if ((install_race_target/".agent/concurrent-sentinel").read_text()!="concurrent owner"
                or installer_module.transaction_journal_path(install_race_target).exists()):
            raise SystemExit("new-install absence race changed concurrent bytes or stranded recovery authority")

        # A cooperating writer cannot enter after publication validation and
        # before committed-journal cleanup; attempt/acquire markers fix ordering.
        lock_target = workspace / "publication-lock-project"; lock_target.mkdir()
        lock_parent = os.open(lock_target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        publication = installer_module.open_publication_lock(lock_parent, lock_target.name, create=True)
        fcntl.flock(publication, fcntl.LOCK_EX)
        attempted = workspace / "writer-attempted"; acquired = workspace / "writer-acquired"
        writer_code = "import fcntl,os,sys;open(sys.argv[2],'w').close();fd=os.open(sys.argv[1],os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX);open(sys.argv[3],'w').close()"
        writer = subprocess.Popen([sys.executable, "-c", writer_code, str(installer_module.publication_lock_path(lock_target)), str(attempted), str(acquired)])
        deadline = time.monotonic() + 5
        while not attempted.exists() and time.monotonic() < deadline: time.sleep(0.01)
        if not attempted.exists() or acquired.exists():
            raise SystemExit("publication writer did not block deterministically behind installer lock")
        fcntl.flock(publication, fcntl.LOCK_UN); os.close(publication); os.close(lock_parent)
        if writer.wait(timeout=5) != 0 or not acquired.exists():
            raise SystemExit("publication writer did not resume after installer cleanup lock release")

        # Installer-internal candidate template migrations inherit the same
        # locked open-file descriptions. Reacquiring the parent lock on a new
        # description would deadlock while the installer waits for this child.
        inherited_candidate=target.parent/f".{target.name}.agent-workflow-txn-{'a'*32}"
        shutil.copytree(target/".agent",inherited_candidate/".agent",symlinks=True)
        inherited_parent=os.open(target.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
        inherited_publication=installer_module.open_publication_lock(inherited_parent,target.name,create=True)
        fcntl.flock(inherited_parent,fcntl.LOCK_EX); fcntl.flock(inherited_publication,fcntl.LOCK_EX)
        installer_module.INSTALLER_PUBLICATION_AUTHORITY=(inherited_parent,inherited_publication)
        installer_module.LOGICAL_TARGET_ROOT=target
        inherited_started=time.monotonic()
        try:
            inherited_output=installer_module.candidate_tool(
                polluted/".agent",inherited_candidate/".agent","scripts/templatectl.py","validate",
                expected=(1,),readonly=True,
            )
            if ("INVALID TEMPLATE STATE" not in inherited_output
                    or "requirements must be clarified and human-approved" not in inherited_output):
                raise SystemExit(f"candidate templatectl did not reach intended validation: {inherited_output}")
        finally:
            installer_module.INSTALLER_PUBLICATION_AUTHORITY=None
            installer_module.LOGICAL_TARGET_ROOT=None
            fcntl.flock(inherited_publication,fcntl.LOCK_UN); os.close(inherited_publication)
            fcntl.flock(inherited_parent,fcntl.LOCK_UN); os.close(inherited_parent)
        if time.monotonic()-inherited_started>10:
            raise SystemExit("candidate templatectl deadlocked while inheriting installer publication authority")

        # The shipped templatectl writer participates in that exact authority,
        # rather than only its private .template.lock. It must not even enter
        # validation while an installer owns publication.
        target_parent_fd=os.open(target.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
        target_publication=installer_module.open_publication_lock(target_parent_fd,target.name,create=True)
        fcntl.flock(target_publication,fcntl.LOCK_EX)
        template_process=subprocess.Popen(
            [sys.executable,".agent/scripts/templatectl.py","route","--capability","core"],cwd=str(target),
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,
        )
        try:
            deadline=time.monotonic()+5
            while True:
                probe_parent=os.open(target.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
                try:
                    try: fcntl.flock(probe_parent,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    except BlockingIOError: break
                    else: fcntl.flock(probe_parent,fcntl.LOCK_UN)
                finally: os.close(probe_parent)
                if time.monotonic()>=deadline:
                    raise SystemExit("templatectl never acquired parent publication authority")
                time.sleep(0.01)
            if template_process.poll() is not None:
                raise SystemExit("templatectl did not block behind installer publication authority")
            fcntl.flock(target_publication,fcntl.LOCK_UN); os.close(target_publication); os.close(target_parent_fd)
            template_output,_=template_process.communicate(timeout=15)
            if template_process.returncode != 1 or "requirements must be clarified" not in template_output:
                raise SystemExit(f"templatectl did not resume its intended route after publication release: {template_output}")
        finally:
            if template_process.poll() is None: template_process.kill(); template_process.wait(timeout=5)

        # A normal shared-lock owner may synchronously invoke other wrapped CLIs
        # without upgrading or deadlocking either the parent or sibling lock.
        nested_started=time.monotonic()
        nested=run(sys.executable,".agent/scripts/agentctl.py","validate",cwd=target,expected=(0,1,3))
        if time.monotonic()-nested_started>30 or not ("VALID .agent structure" in nested.stdout or "INVALID .agent structure" in nested.stdout):
            raise SystemExit("normal nested publication-lock CLIs deadlocked or skipped their intended validation")

        # Sibling recovery authority blocks ordinary state readers even when no
        # installer process currently owns the publication locks.
        pending_cli_journal=installer_module.transaction_journal_path(target)
        pending_cli_journal.write_text("{}\n",encoding="utf-8"); pending_cli_journal.chmod(0o600)
        try:
            blocked_cli=run(sys.executable,".agent/scripts/templatectl.py","validate",cwd=target,expected=(1,))
            if "RECOVERY REQUIRED: pending installer transaction blocks project commands" not in blocked_cli.stdout:
                raise SystemExit("normal project CLI read state while installer recovery was pending")
        finally:
            pending_cli_journal.unlink(); installer_module.fsync_directory(pending_cli_journal.parent)

        cwd_injection=workspace/"python-cwd-injection"; destination=cwd_injection/".agent"
        shutil.copytree(polluted/".agent/assets/fresh-state/v1/state",destination/"state")
        marker=cwd_injection/"target-import-executed"
        (cwd_injection/"copy.py").write_text(f"from pathlib import Path;Path({str(marker)!r}).write_text('executed')\n",encoding="utf-8")
        try: installer_module.validate_legacy_active_context(polluted/".agent",destination)
        except RuntimeError: pass
        if marker.exists():
            raise SystemExit("isolated migration probe imported target-project copy.py (Python 3.9 CWD injection)")
        binding_parent = workspace / "binding-parent"
        binding_target = binding_parent / "project"
        binding_target.mkdir(parents=True)
        moved_parent = workspace / "binding-parent-moved"
        real_execute = installer_module.execute
        binding_argv = sys.argv
        def swapped_parent_execute(_args, _source, relative_target):
            os.rename(binding_parent, moved_parent)
            binding_parent.mkdir()
            attacker_target = binding_parent / "project"
            attacker_target.mkdir()
            (attacker_target / "attacker-sentinel").write_text("untouched\n", encoding="utf-8")
            (relative_target / "descriptor-bound-write").write_text("old parent only\n", encoding="utf-8")
            return 0
        installer_module.execute = swapped_parent_execute
        sys.argv = [str(installer), str(binding_target), "--check"]
        try:
            try: installer_module.main()
            except RuntimeError as error:
                if "target parent was replaced" not in str(error): raise
            else: raise SystemExit("locked parent swap was not detected")
        finally:
            installer_module.execute = real_execute
            sys.argv = binding_argv
        if not (moved_parent / "project/descriptor-bound-write").is_file():
            raise SystemExit("parent swap redirected a descriptor-bound installer write")
        if (binding_parent / "project/descriptor-bound-write").exists() or (binding_parent / "project/attacker-sentinel").read_text(encoding="utf-8") != "untouched\n":
            raise SystemExit("parent swap changed attacker replacement bytes")

        authority_fixture = workspace / "shape-valid-authority/.agent"
        authority_fixture.mkdir(parents=True)
        shaped_record = {
            "source": "user:forged-pre-v41", "artifact_sha256": "a" * 64,
            "decision_receipt": {
                "schema": "agent-human-decision-receipt/v1", "authority": "provider-signed-user-message",
                "path": "forged.json", "sha256": "b" * 64, "bytes": 1,
                "adapter_path": "/usr/bin/false", "adapter_sha256": "c" * 64,
            },
        }
        shaped_task = {
            "decision_policy_version": 1, "requirements_clarified": True,
            "gate_approvals": {"requirement": shaped_record}, "status": "in_progress",
            "current_node": 6, "accepted_nodes": list(range(7)), "open_questions": [],
            "selected_templates": ["workflow-task"], "selected_capabilities": ["core"],
            "template_variables": {"task_title": "forged"}, "template_artifacts": ["forged"],
        }
        migrated_authority = installer_module.migrate_provider_decision_authority(authority_fixture, shaped_task, 40)
        archives = list((authority_fixture / "state/evidence/decision-archives").glob("*.json"))
        if migrated_authority[0].get("gate_approvals") != {} or migrated_authority[0].get("requirements_clarified") is not False or not migrated_authority[1] or len(archives) != 1:
            raise SystemExit("shape-valid pre-v41 authority survived conservative revocation")

        def seed_current_activation(fixture,task):
            payload={"schema":"agent-task-skill-activation/v2","task_generation_id":task["task_generation_id"],
                     "lock_sha256":"0"*64,"skills":[],"builtins":[]}
            payload["activation_sha256"]=installer_module.canonical_sha256(payload)
            raw=(json.dumps(payload,sort_keys=True,separators=(",",":"))+"\n").encode()
            path=fixture/"state/SKILL_ACTIVATION.json"; path.parent.mkdir(parents=True); path.write_bytes(raw)
            task["skill_activation"]={"path":".agent/state/SKILL_ACTIVATION.json","sha256":hashlib.sha256(raw).hexdigest(),
                "bytes":len(raw),"activation_sha256":payload["activation_sha256"],"lock_sha256":payload["lock_sha256"],"skill_ids":[],"builtin_skill_ids":[]}

        valid_current_fixture=workspace/"valid-current-authority/.agent"; valid_current_fixture.mkdir(parents=True)
        valid_current_task=json.loads(json.dumps(shaped_task)); valid_current_task["task_generation_id"]="existing-authority-generation"
        valid_artifact="d"*64; valid_decision="decision-current-1"
        valid_binding={"project_identity_sha256":"e"*64,"task_generation_sha256":"f"*64,
            "task_generation_id":valid_current_task["task_generation_id"],"gate":"requirement",
            "artifact_sha256":valid_artifact,"decision_id":valid_decision}
        valid_consumption={"binding_sha256":installer_module.canonical_sha256(valid_binding),**valid_binding,"sequence":7}
        valid_current_task["gate_approvals"]={"requirement":{"source":"user:current exact authority",
            "artifact_sha256":valid_artifact,"decision_receipt":{"schema":"agent-human-decision-receipt/v1",
            "path":".agent/state/evidence/current-receipt.json","sha256":"1"*64,"bytes":100,"decision_id":valid_decision,
            "authority":"provider-signed-user-message","adapter_path":"/protected/provider-adapter",
            "adapter_sha256":"2"*64,"provider_consumption":valid_consumption}}}
        valid_current_task["requirements_clarified"]=True; seed_current_activation(valid_current_fixture,valid_current_task)
        valid_before=json.loads(json.dumps(valid_current_task))
        valid_current=installer_module.migrate_provider_decision_authority(valid_current_fixture,valid_current_task,installer_module.MIGRATION_VERSION)
        if valid_current!=(valid_before,False):
            raise SystemExit("idempotent same-version update revoked valid current generation authority or activation")

        forged_current_fixture=workspace/"forged-current-authority/.agent"; forged_current_fixture.mkdir(parents=True)
        forged_current_task=json.loads(json.dumps(valid_before)); forged_current_task["gate_approvals"]={"requirement":shaped_record}
        forged_current_task["requirements_clarified"]=True; seed_current_activation(forged_current_fixture,forged_current_task)
        forged_current=installer_module.migrate_provider_decision_authority(forged_current_fixture,forged_current_task,installer_module.MIGRATION_VERSION)
        if (forged_current[0].get("gate_approvals")!={} or forged_current[0].get("requirements_clarified") is not False
                or not forged_current[1] or forged_current[0].get("task_generation_id")==valid_before["task_generation_id"]):
            raise SystemExit("forged current-migration claim bypassed authority revocation or generation rotation")

        missing_generation_fixture=workspace/"missing-current-generation/.agent"; missing_generation_fixture.mkdir(parents=True)
        missing_generation_task=json.loads(json.dumps(valid_before)); missing_generation_task.pop("task_generation_id",None)
        missing_generation_task.pop("skill_activation",None); missing_generation_task["gate_approvals"]={}; missing_generation_task["requirements_clarified"]=False
        migrated_missing_generation=installer_module.migrate_provider_decision_authority(
            missing_generation_fixture,missing_generation_task,installer_module.MIGRATION_VERSION)
        if (not migrated_missing_generation[1] or not str(migrated_missing_generation[0].get("task_generation_id","")).startswith("migration-")):
            raise SystemExit("missing current task generation was not safely rotated")

        missing_activation_fixture=workspace/"missing-current-activation/.agent"; missing_activation_fixture.mkdir(parents=True)
        missing_activation_task=json.loads(json.dumps(valid_before)); missing_activation_task.pop("skill_activation",None)
        prior_generation=missing_activation_task["task_generation_id"]
        migrated_missing_activation=installer_module.migrate_provider_decision_authority(
            missing_activation_fixture,missing_activation_task,installer_module.MIGRATION_VERSION)
        if (not migrated_missing_activation[1] or migrated_missing_activation[0]["task_generation_id"]==prior_generation
                or migrated_missing_activation[0]["gate_approvals"]!={}):
            raise SystemExit("missing current Skill activation preserved stale generation authority")

        invalid_activation_fixture=workspace/"invalid-current-activation/.agent"; invalid_activation_fixture.mkdir(parents=True)
        invalid_activation_task=json.loads(json.dumps(valid_before)); seed_current_activation(invalid_activation_fixture,invalid_activation_task)
        invalid_activation_path=invalid_activation_fixture/"state/SKILL_ACTIVATION.json"
        invalid_activation_path.write_bytes(invalid_activation_path.read_bytes()+b"tamper")
        invalid_before=json.dumps(invalid_activation_task,sort_keys=True)
        try: installer_module.migrate_provider_decision_authority(
            invalid_activation_fixture,invalid_activation_task,installer_module.MIGRATION_VERSION)
        except RuntimeError as error:
            if "activation receipt is tampered or invalid" not in str(error): raise
        else: raise SystemExit("invalid current Skill activation was silently replaced")
        if json.dumps(invalid_activation_task,sort_keys=True)!=invalid_before:
            raise SystemExit("invalid current Skill activation rejection mutated task authority")

        for unknown_policy in (None,0,2,99,"1"):
            unknown_fixture=workspace/f"unknown-policy-{str(unknown_policy).replace('/','-')}/.agent"; unknown_fixture.mkdir(parents=True)
            unknown_task=json.loads(json.dumps(shaped_task)); unknown_task["decision_policy_version"]=unknown_policy
            unknown_before=json.dumps(unknown_task,sort_keys=True)
            try: installer_module.migrate_provider_decision_authority(unknown_fixture,unknown_task,installer_module.MIGRATION_VERSION)
            except RuntimeError as error:
                if "tampered or unknown" not in str(error): raise
            else: raise SystemExit(f"unknown current decision policy was accepted: {unknown_policy!r}")
            if json.dumps(unknown_task,sort_keys=True)!=unknown_before or any(unknown_fixture.rglob("*")):
                raise SystemExit("unknown decision policy rejection mutated private authority state")

        original_platform = installer_module.platform.system; original_fcntl = installer_module.fcntl; original_argv = sys.argv
        try:
            installer_module.platform.system = lambda: "Windows"; installer_module.fcntl = None; sys.argv = [str(installer), str(workspace / "unsupported")]
            try: installer_module.main()
            except SystemExit as error:
                if "supports Linux and macOS" not in str(error): raise
            else: raise SystemExit("unsupported OS did not fail early with a clear diagnostic")
        finally:
            installer_module.platform.system = original_platform; installer_module.fcntl = original_fcntl; sys.argv = original_argv

        # The canonical transaction marker must remain until every sibling has
        # been durably removed so interrupted cleanup is always recoverable.
        cleanup_target=workspace/"marker-last-target"; cleanup_target.mkdir(); cleanup_target=cleanup_target.resolve()
        cleanup_staging=installer_module.begin_transaction(cleanup_target)
        (cleanup_staging/"sibling.txt").write_text("cleanup sibling",encoding="utf-8")
        cleanup_journal=installer_module.read_transaction_journal(cleanup_target)
        real_unlink=installer_module.os.unlink; marker_observed_last=False
        def interrupt_marker_unlink(name,*args,**kwargs):
            nonlocal marker_observed_last
            if str(name)==".agent-workflow-transaction-marker.json":
                directory=kwargs.get("dir_fd")
                remaining=sorted(os.listdir(directory)) if directory is not None else []
                if remaining!=[".agent-workflow-transaction-marker.json"]:
                    raise SystemExit(f"transaction marker was not deleted last: {remaining}")
                marker_observed_last=True; raise OSError("simulated marker unlink crash")
            return real_unlink(name,*args,**kwargs)
        installer_module.os.unlink=interrupt_marker_unlink
        try:
            try: installer_module.finish_transaction_cleanup(cleanup_target,cleanup_journal)
            except OSError: pass
            else: raise SystemExit("interrupted transaction marker cleanup unexpectedly succeeded")
        finally: installer_module.os.unlink=real_unlink
        if (not marker_observed_last or not (cleanup_staging/".agent-workflow-transaction-marker.json").is_file()
                or not installer_module.transaction_journal_path(cleanup_target).is_file()):
            raise SystemExit("interrupted marker-last cleanup lost recovery authority")
        installer_module.recover_transaction(cleanup_target)
        if cleanup_staging.exists() or installer_module.transaction_journal_path(cleanup_target).exists():
            raise SystemExit("marker-last interrupted cleanup did not recover")

        # Planned absence and identity are durable commit authority. An
        # interloper appearing after planning is never adopted as a predecessor,
        # and same bytes on a replacement inode do not satisfy the CAS.
        planned_target=workspace/"planned-authority-target"; planned_target.mkdir(); planned_target=planned_target.resolve()
        planned_root=installer_module.planned_transaction_root(planned_target)
        planned_absence={"AGENTS.md":installer_module.planned_transaction_target(planned_target/"AGENTS.md")}
        planned_staging=installer_module.begin_transaction(planned_target)
        (planned_staging/"AGENTS.md").write_text("candidate bytes",encoding="utf-8")
        (planned_target/"AGENTS.md").write_text("concurrent owner bytes",encoding="utf-8")
        concurrent_identity=installer_module.filesystem_identity(planned_target/"AGENTS.md")
        try:
            installer_module.commit_transaction(
                planned_target,planned_staging,[(planned_staging/"AGENTS.md",planned_target/"AGENTS.md")],
                planned_absence,planned_root,
            )
        except RuntimeError as error:
            if "planned transaction target absence changed" not in str(error): raise
        else: raise SystemExit("target appearing after planned absence was overwritten")
        finally: installer_module.abort_transaction(planned_target)
        if ((planned_target/"AGENTS.md").read_text(encoding="utf-8")!="concurrent owner bytes"
                or installer_module.filesystem_identity(planned_target/"AGENTS.md")!=concurrent_identity
                or installer_module.transaction_journal_path(planned_target).exists()):
            raise SystemExit("planned-absence rejection changed concurrent target or stranded recovery state")

        existing_plan={"AGENTS.md":installer_module.planned_transaction_target(planned_target/"AGENTS.md")}
        old=(planned_target/"AGENTS.md"); replacement=planned_target/"replacement"
        replacement.write_bytes(old.read_bytes()); os.replace(replacement,old)
        replacement_identity=installer_module.filesystem_identity(old)
        identity_staging=installer_module.begin_transaction(planned_target)
        (identity_staging/"AGENTS.md").write_text("new candidate",encoding="utf-8")
        try:
            installer_module.commit_transaction(
                planned_target,identity_staging,[(identity_staging/"AGENTS.md",old)],existing_plan,planned_root,
            )
        except RuntimeError as error:
            if "identity or content changed" not in str(error): raise
        else: raise SystemExit("same-content replacement inode satisfied stale planning authority")
        finally: installer_module.abort_transaction(planned_target)
        if installer_module.filesystem_identity(old)!=replacement_identity or old.read_text()!="concurrent owner bytes":
            raise SystemExit("planned-identity rejection changed replacement inode")

        # A writer racing after predecessor rename must keep its exact inode and
        # bytes at the managed pathname while earlier installs roll back.
        race_target=workspace/"predecessor-race-target"; race_target.mkdir(); race_target=race_target.resolve()
        (race_target/".agent").mkdir(); (race_target/".agent/original.txt").write_text("old tree",encoding="utf-8")
        (race_target/".agent/.workflow-manifest.json").write_text(json.dumps({
            "agent_files":{"original.txt":hashlib.sha256(b"old tree").hexdigest()},"agent_modes":{"original.txt":0o644},
        })+"\n",encoding="utf-8")
        (race_target/"AGENTS.md").write_text("old bootstrap",encoding="utf-8")
        race_staging=installer_module.begin_transaction(race_target)
        (race_staging/".agent").mkdir(); (race_staging/".agent/candidate.txt").write_text("new tree",encoding="utf-8")
        (race_staging/".agent/.workflow-manifest.json").write_text(json.dumps({
            "agent_files":{"candidate.txt":hashlib.sha256(b"new tree").hexdigest()},"agent_modes":{"candidate.txt":0o644},
        })+"\n",encoding="utf-8")
        (race_staging/"AGENTS.md").write_text("new bootstrap",encoding="utf-8")
        real_transaction_hash=installer_module.transaction_content_sha256; raced=False
        race_fd=os.open(race_target/"AGENTS.md",os.O_RDWR|getattr(os,"O_NOFOLLOW",0))
        race_fd_identity=(os.fstat(race_fd).st_dev,os.fstat(race_fd).st_ino)
        def mutate_backed_up_predecessor(path):
            nonlocal raced
            if path==race_staging/"backups/1" and not raced:
                if (path.stat().st_dev,path.stat().st_ino)!=race_fd_identity:
                    raise SystemExit("open predecessor descriptor did not follow the renamed inode")
                raced=True; raw=b"concurrent predecessor bytes"
                os.lseek(race_fd,0,os.SEEK_SET); os.write(race_fd,raw); os.ftruncate(race_fd,len(raw)); os.fsync(race_fd)
            return real_transaction_hash(path)
        installer_module.transaction_content_sha256=mutate_backed_up_predecessor
        try:
            try: installer_module.commit_transaction(race_target,race_staging,[(race_staging/".agent",race_target/".agent"),(race_staging/"AGENTS.md",race_target/"AGENTS.md")])
            except RuntimeError as error:
                if "predecessor content changed" not in str(error): raise
            else: raise SystemExit("post-rename open-predecessor mutation was installed")
        finally:
            installer_module.transaction_content_sha256=real_transaction_hash; os.close(race_fd)
        if (not raced or (race_target/"AGENTS.md").read_text(encoding="utf-8")!="concurrent predecessor bytes"
                or not (race_target/".agent/original.txt").is_file() or (race_target/".agent/candidate.txt").exists()
                or installer_module.transaction_journal_path(race_target).exists()):
            raise SystemExit("predecessor race stranded a path or failed to roll back prior installs")

        # Link count is rechecked at the descriptor-relative mutation boundary,
        # after planning identities have already been captured.
        for linked_role in ("source","target"):
            link_root=workspace/f"hardlink-{linked_role}"; link_root.mkdir(); link_root=link_root.resolve()
            source_file=link_root/"source"; target_file=link_root/"target"; extra=link_root/"extra"
            source_file.write_text("source bytes",encoding="utf-8"); target_file.write_text("target bytes",encoding="utf-8")
            source_identity=installer_module.filesystem_identity(source_file); target_identity=installer_module.filesystem_identity(target_file)
            os.link(source_file if linked_role=="source" else target_file,extra)
            try:
                installer_module.durable_replace(source_file,target_file,expected_source=source_identity,expected_target=target_identity)
            except RuntimeError as error:
                if "hard-linked" not in str(error): raise
            else: raise SystemExit(f"hard-linked rename {linked_role} crossed the mutation boundary")
            if source_file.read_text()!="source bytes" or target_file.read_text()!="target bytes" or extra.read_text()!=("source bytes" if linked_role=="source" else "target bytes"):
                raise SystemExit("rejected hard-linked rename mutated an entry")

        # Private source capture is descriptor-relative and rejects a namespace
        # swap even when the already-open old inode still yields reviewed bytes.
        capture_root=workspace/"private-capture"; capture_root.mkdir()
        capture_source=capture_root/"source"; capture_source.mkdir(); capture_file=capture_source/"state.json"
        capture_file.write_bytes(b"reviewed-source\n"); capture_file.chmod(0o640)
        capture_destination=capture_root/"destination"
        real_os_read=installer_module.os.read; source_inode=os.lstat(capture_file).st_ino; swapped={"done":False}
        def swap_private_source(descriptor,count):
            chunk=real_os_read(descriptor,count)
            if not swapped["done"] and os.fstat(descriptor).st_ino==source_inode:
                retired=capture_source/"retired"; capture_file.rename(retired)
                capture_file.write_bytes(b"replacement-source\n"); capture_file.chmod(0o640); swapped["done"]=True
            return chunk
        installer_module.os.read=swap_private_source
        try:
            try: installer_module.copy_private_tree(capture_source,capture_destination)
            except RuntimeError as error:
                if "changed during private capture" not in str(error): raise
            else: raise SystemExit("private source pathname swap was accepted")
        finally: installer_module.os.read=real_os_read
        if capture_destination.exists(): raise SystemExit("failed private source capture left a candidate tree")
        destination_source=capture_root/"destination-source"; destination_source.mkdir(); (destination_source/"data").write_text("reviewed",encoding="utf-8")
        destination_swap=capture_root/"destination-swap"; displaced=capture_root/"destination-displaced"
        real_validate_private_tree=installer_module.validate_private_tree; destination_swapped={"done":False}
        def swap_destination_during_validation(root):
            if Path(root)==destination_swap and not destination_swapped["done"]:
                destination_swap.rename(displaced); destination_swap.mkdir(); (destination_swap/"data").write_text("replacement",encoding="utf-8")
                destination_swapped["done"]=True
            return real_validate_private_tree(root)
        installer_module.validate_private_tree=swap_destination_during_validation
        try:
            try: installer_module.copy_private_tree(destination_source,destination_swap)
            except RuntimeError as error:
                if "destination changed during validation" not in str(error): raise
            else: raise SystemExit("private copy destination swap was accepted")
        finally: installer_module.validate_private_tree=real_validate_private_tree
        if (destination_swap/"data").read_text()!="replacement" or (displaced/"data").read_text()!="reviewed":
            raise SystemExit("destination swap rejection deleted or confused either namespace")
        shutil.rmtree(destination_swap); shutil.rmtree(displaced)

        stable_source=capture_root/"stable"; stable_source.mkdir(); (stable_source/"nested").mkdir()
        stable_file=stable_source/"nested/data"; stable_file.write_bytes(b"stable\n"); stable_file.chmod(0o640)
        stable_destination=capture_root/"stable-copy"; installer_module.copy_private_tree(stable_source,stable_destination)
        if (stable_destination/"nested/data").read_bytes()!=b"stable\n" or stat.S_IMODE(os.lstat(stable_destination/"nested/data").st_mode)!=0o640:
            raise SystemExit("descriptor-relative private source capture changed bytes or mode")
        linked=stable_source/"linked"; os.link(stable_file,linked)
        try: installer_module.copy_private_tree(stable_source,capture_root/"hardlink-copy")
        except RuntimeError as error:
            if "hard-linked" not in str(error): raise
        else: raise SystemExit("hard-linked private source was copied")
        linked.unlink()
        outside=capture_root/"outside"; outside.write_text("outside",encoding="utf-8")
        (stable_source/"escape").symlink_to(outside)
        try: installer_module.copy_private_tree(stable_source,capture_root/"symlink-copy")
        except RuntimeError as error:
            if "symlink" not in str(error): raise
        else: raise SystemExit("symlinked private source escaped capture")
        (stable_source/"escape").unlink()

        def adapter_process(program):
            return subprocess.Popen([sys.executable,"-c",program],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,start_new_session=True)
        exact=adapter_process(f"import os;os.write(1,b'x'*{installer_module.INSTALLER_ADAPTER_OUTPUT_LIMIT})")
        if len(installer_module.bounded_installer_adapter_output(exact,5))!=installer_module.INSTALLER_ADAPTER_OUTPUT_LIMIT:
            raise SystemExit("exact-limit installer adapter output was rejected")
        merged=adapter_process("import os;os.write(2,b'merged-stderr')")
        if installer_module.bounded_installer_adapter_output(merged,5)!=b"merged-stderr":
            raise SystemExit("installer adapter stderr was not merged into bounded output")
        overflow=adapter_process("import os\nwhile True: os.write(1,b'x'*65536)")
        overflow_started=time.monotonic()
        try: installer_module.bounded_installer_adapter_output(overflow,10)
        except RuntimeError as error:
            if "protocol limit" not in str(error) or time.monotonic()-overflow_started>5: raise
        else: raise SystemExit("unbounded installer adapter output was buffered or accepted")
        try:
            installer_module.run_installer_command([sys.executable,"-c","import os;os.write(1,b'x'*8192)"],timeout=5,output_limit=1024)
        except RuntimeError as error:
            if "output exceeds" not in str(error): raise
        else: raise SystemExit("generic installer command output was buffered or accepted")
        blocked_started=time.monotonic()
        try: installer_module.run_installer_command([sys.executable,"-c","import time;time.sleep(60)"],input_data=b"x"*(1024*1024),timeout=0.2)
        except subprocess.TimeoutExpired: pass
        else: raise SystemExit("blocked installer stdin bypassed command timeout")
        if time.monotonic()-blocked_started>5: raise SystemExit("blocked installer stdin cleanup exceeded its bound")
        timeout_process=adapter_process("import time;time.sleep(60)")
        try: installer_module.bounded_installer_adapter_output(timeout_process,0.1)
        except subprocess.TimeoutExpired: pass
        else: raise SystemExit("silent installer adapter timeout was accepted")

        observer_failure=adapter_process("import time;time.sleep(60)")
        real_discover=installer_module.installer_discover_descendants
        def failed_discover(*_args,**_kwargs): raise RuntimeError("injected installer identity observation failure")
        installer_module.installer_discover_descendants=failed_discover
        try:
            try: installer_module.bounded_installer_adapter_output(observer_failure,5)
            except RuntimeError as error:
                if "identity observation failure" not in str(error): raise
            else: raise SystemExit("installer observer failure was accepted")
        finally: installer_module.installer_discover_descendants=real_discover
        if observer_failure.returncode is None:
            raise SystemExit("installer observer failure left its owned leader unreaped")

        with tempfile.TemporaryDirectory(prefix="installer-adapter-group-") as adapter_raw:
            descendant_pid=Path(adapter_raw)/"descendant.pid"
            leader_program="import os,signal,sys,time; p=os.fork(); " \
                "(signal.signal(signal.SIGTERM,signal.SIG_IGN),open(sys.argv[1],'w').write(str(os.getpid())),os.close(1),os.close(2),time.sleep(60),os._exit(0)) if p==0 else os._exit(0)"
            leader=adapter_process(leader_program.replace("sys.argv[1]",repr(str(descendant_pid))))
            deadline=time.monotonic()+2
            while time.monotonic()<deadline and not descendant_pid.exists(): time.sleep(.01)
            if not descendant_pid.exists(): raise SystemExit("leader-exit descendant fixture did not start")
            descendant=int(descendant_pid.read_text().strip())
            try: installer_module.bounded_installer_adapter_output(leader,5)
            except RuntimeError as error:
                if not any(marker in str(error) for marker in ("identity-bound descendant","identity observation")): raise
            else: raise SystemExit("leader-exit adapter descendant was accepted")
            child_state=subprocess.run(["/bin/ps","-p",str(descendant),"-o","stat="],text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL).stdout.strip()
            if leader.returncode is None or (child_state and not child_state.startswith("Z")):
                raise SystemExit("leader-exit adapter process group was not killed and drained")

        class ReapedLaunch:
            pid=424242
            returncode=0
        reused_snapshot={424242:(1,424242,"darwin:reused","R"),424243:(424242,424242,"darwin:unrelated","R")}
        reaped_signals=[]; real_identity_kill=installer_module.os.kill
        installer_module.os.kill=lambda pid,signum:reaped_signals.append((pid,signum))
        try:
            if installer_module.installer_signal_launch_session(
                    ReapedLaunch(),{424242:"darwin:original"},signal.SIGTERM,reused_snapshot):
                raise SystemExit("reaped installer launch session was accepted as signal authority")
            if reaped_signals: raise SystemExit("reaped installer launch session signaled a reused identity")
        finally: installer_module.os.kill=real_identity_kill

        real_adapter_snapshot=installer_module.installer_process_snapshot
        def denied_identity_inventory():
            raise RuntimeError("injected identity observation failure")
        installer_module.installer_process_snapshot=denied_identity_inventory
        try:
            try: installer_module.installer_adapter_group_exists(os.getpgrp())
            except RuntimeError as error:
                if "identity observation" not in str(error): raise
            else: raise SystemExit("unavailable identity observation was accepted as clean")
        finally: installer_module.installer_process_snapshot=real_adapter_snapshot

        legacy_bootstrap = workspace / "legacy-AGENTS.md"
        legacy_bootstrap.write_text("prefix\n" + installer_module.LEGACY_BOOTSTRAP + "suffix\n", encoding="utf-8")
        legacy_bootstrap = legacy_bootstrap.resolve()
        trusted = hashlib.sha256(legacy_bootstrap.read_bytes()).hexdigest()
        write_needed, conflicts = installer_module.plan_bootstrap(legacy_bootstrap, "AGENTS.md", trusted)
        rendered = installer_module.render_bootstrap(legacy_bootstrap, trusted)
        if not write_needed or conflicts or not rendered.startswith("prefix\n") or not rendered.endswith("suffix\n") or rendered.count(installer_module.BOOTSTRAP_START) != 1:
            raise SystemExit("trusted prior canonical bootstrap was not safely upgraded")
        unknown_bootstrap = workspace / "unknown-AGENTS.md"
        unknown_bootstrap.write_text(legacy_bootstrap.read_text(encoding="utf-8").replace("# Agent Bootstrap", "# Locally edited bootstrap"), encoding="utf-8")
        unknown_bootstrap = unknown_bootstrap.resolve()
        if not installer_module.plan_bootstrap(unknown_bootstrap, "AGENTS.md", hashlib.sha256(unknown_bootstrap.read_bytes()).hexdigest())[1]:
            raise SystemExit("unknown edited bootstrap body was accepted through a target-controlled manifest hash")

        rebind_fixture = workspace / "provider-authority-v40/.agent/state"
        rebind_fixture.mkdir(parents=True)
        (rebind_fixture / "TASK.json").write_text("{}\n", encoding="utf-8")
        real_subprocess_run = installer_module.run_installer_command
        rebind_calls = []
        def fake_rebind_run(*args, **kwargs):
            rebind_calls.append((args, kwargs))
            return subprocess.CompletedProcess(args[0] if args else [], 0, "VALID context capsule\n", "")
        installer_module.run_installer_command = fake_rebind_run
        try:
            installer_module.finalize_active_context_binding(polluted / ".agent", rebind_fixture.parent, 40)
            if len(rebind_calls) != 1 or "migration-41-provider-authority-rebind" not in " ".join(rebind_calls[0][0][0]):
                raise SystemExit("v40 to v41 provider-authority migration skipped its final context rebind")
            installer_module.finalize_active_context_binding(polluted / ".agent", rebind_fixture.parent, 41)
            if len(rebind_calls) != 2 or "migration-42-scheduler-replay-rebind" not in " ".join(rebind_calls[1][0][0]):
                raise SystemExit("v41 to v42 scheduler-replay migration skipped its final context rebind")
            installer_module.finalize_active_context_binding(polluted/".agent",rebind_fixture.parent,42)
            if len(rebind_calls)!=2:
                raise SystemExit("current migration unexpectedly rebuilt an unchanged context")
            installer_module.finalize_active_context_binding(polluted/".agent",rebind_fixture.parent,42,force=True)
            forced=" ".join(rebind_calls[2][0][0]) if len(rebind_calls)==3 else ""
            if "release-managed-policy-rebind" not in forced or "installer-verified-release-policy-rebind" not in forced:
                raise SystemExit("same-migration managed policy update skipped its final context rebind")
        finally:
            installer_module.run_installer_command = real_subprocess_run

        real_guard = installer_module.protected_external_adapter
        real_preflight_reject = installer_module.protected_external_adapter_reject_reason
        installer_module.protected_external_adapter = lambda owner, raw: True
        installer_module.protected_external_adapter_reject_reason = lambda owner, raw, require_executable=True: None if Path(raw).exists() else "cannot resolve test fixture"
        try:
            stub = workspace / "provider-preflight-stub"
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "PROVIDER PREFLIGHT ADAPTER READY"\n', encoding="utf-8")
            stub.chmod(0o755)
            Path(str(stub)+".agent-workflow-adapter.json").write_text(json.dumps({
                "schema":"agent-provider-adapter/v1","purpose":"provider-verifiable-agent-control",
                "executable_sha256":hashlib.sha256(stub.read_bytes()).hexdigest(),
                "operations":["health-provider-preflight","verify-provider-preflight"],
            },indent=2)+"\n",encoding="utf-8")
            if installer_module.bootstrap_provider_preflight_adapter(workspace, str(stub)) != str(stub.resolve()):
                raise SystemExit("provider preflight stub with the exact health output was not accepted")
            wrong = workspace / "provider-preflight-wrong"
            wrong.write_text('#!/bin/sh\nprintf "%s\\n" "WRONG HEALTH OUTPUT"\n', encoding="utf-8")
            wrong.chmod(0o755)
            Path(str(wrong)+".agent-workflow-adapter.json").write_text(json.dumps({
                "schema":"agent-provider-adapter/v1","purpose":"provider-verifiable-agent-control",
                "executable_sha256":hashlib.sha256(wrong.read_bytes()).hexdigest(),
                "operations":["health-provider-preflight","verify-provider-preflight"],
            },indent=2)+"\n",encoding="utf-8")
            try:
                installer_module.bootstrap_provider_preflight_adapter(workspace, str(wrong))
            except RuntimeError:
                pass
            else:
                raise SystemExit("provider preflight stub with wrong health output was accepted")
        finally:
            installer_module.protected_external_adapter = real_guard
            installer_module.protected_external_adapter_reject_reason = real_preflight_reject

        real_reject_reason = installer_module.protected_external_adapter_reject_reason
        installer_module.protected_external_adapter_reject_reason = lambda owner, raw, require_executable=True: None if Path(raw).exists() else "cannot resolve test fixture"
        try:
            health_marker = workspace / "human-adapter-health-executed"
            human_adapter = workspace / "dedicated-human-adapter"
            human_adapter.write_text(f'#!/bin/sh\nprintf invoked >> "{health_marker}"\nexit 0\n', encoding="utf-8")
            human_adapter.chmod(0o755)
            metadata_path = Path(str(human_adapter) + ".agent-workflow-adapter.json")
            try:
                installer_module.bootstrap_human_decision_adapter(workspace, str(human_adapter))
            except RuntimeError as error:
                if "metadata" not in str(error): raise
            else:
                raise SystemExit("human adapter without protocol metadata was accepted")
            if health_marker.exists():
                raise SystemExit("human adapter health executed before missing metadata was rejected")
            metadata = {
                "schema": "agent-provider-adapter/v1",
                "purpose": "provider-verifiable-agent-control",
                "executable_sha256": "0" * 64,
                "operations": ["health", "verify"],
            }
            metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
            try:
                installer_module.bootstrap_human_decision_adapter(workspace, str(human_adapter))
            except RuntimeError as error:
                if "does not bind" not in str(error): raise
            else:
                raise SystemExit("hash-mismatched human adapter metadata was accepted")
            if health_marker.exists():
                raise SystemExit("human adapter health executed before hash mismatch was rejected")
            metadata["executable_sha256"] = hashlib.sha256(human_adapter.read_bytes()).hexdigest()
            metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
            if installer_module.bootstrap_human_decision_adapter(workspace, str(human_adapter)) != str(human_adapter.resolve()):
                raise SystemExit("metadata-bound dedicated human adapter was rejected")
            if not health_marker.exists():
                raise SystemExit("validated human adapter health was not executed")
            generic_marker = workspace / "generic-adapter-executed"
            generic = workspace / "python3"
            generic.write_text(f'#!/bin/sh\nprintf invoked > "{generic_marker}"\n', encoding="utf-8")
            generic.chmod(0o755)
            try:
                installer_module.bootstrap_human_decision_adapter(workspace, str(generic))
            except RuntimeError as error:
                if "generic interpreter" not in str(error): raise
            else:
                raise SystemExit("generic interpreter was accepted as a human decision adapter")
            if generic_marker.exists():
                raise SystemExit("generic interpreter executed before rejection")
        finally:
            installer_module.protected_external_adapter_reject_reason = real_reject_reason

    # Manifest-bound uninstall removes only owned bytes, preserves private state,
    # and uses the same crash-recoverable multi-target publication transaction.
    workspace.mkdir(parents=True,exist_ok=True,mode=0o700)
    uninstall_installer=source/"install.py"
    uninstall_target=workspace/"uninstall-preservation"
    run(sys.executable,str(uninstall_installer),str(uninstall_target),"--project-name","uninstall-fixture",cwd=source)
    private_note=uninstall_target/".agent/project/private-owner-note.txt"; private_note.parent.mkdir(parents=True,exist_ok=True); private_note.write_text("retain me\n",encoding="utf-8")
    for name in ("AGENTS.md","CLAUDE.md"):
        path=uninstall_target/name; path.write_text(path.read_text(encoding="utf-8")+f"\n# unrelated {name} owner content\n",encoding="utf-8")
    run(sys.executable,str(uninstall_installer),str(uninstall_target),"--uninstall",cwd=source)
    if (not private_note.is_file() or private_note.read_text(encoding="utf-8")!="retain me\n"
            or (uninstall_target/".agent/.workflow-manifest.json").exists()
            or (uninstall_target/".agent/scripts/agentctl.py").exists()):
        raise SystemExit("manifest uninstall removed private state or retained owned bytes")
    for name in ("AGENTS.md","CLAUDE.md"):
        text=(uninstall_target/name).read_text(encoding="utf-8")
        if "agent-workflow-bootstrap:start" in text or f"unrelated {name} owner content" not in text:
            raise SystemExit("manifest uninstall did not preserve only unrelated bootstrap content")
    husk_before=private_note.read_bytes()
    run(sys.executable,str(uninstall_installer),str(uninstall_target),"--project-name","uninstall-fixture",cwd=source)
    if (private_note.read_bytes()!=husk_before or not (uninstall_target/".agent/.workflow-manifest.json").is_file()
            or not (uninstall_target/".agent/scripts/agentctl.py").is_file()):
        raise SystemExit("private uninstall husk did not support authenticated reinstall")
    run(sys.executable,str(uninstall_installer),str(uninstall_target),"--check",cwd=source)

    drift_uninstall=workspace/"uninstall-drift"
    run(sys.executable,str(uninstall_installer),str(drift_uninstall),"--project-name","uninstall-drift",cwd=source)
    (drift_uninstall/".agent/scripts/agentctl.py").write_text("# local drift\n",encoding="utf-8")
    drift_before=tree(drift_uninstall)
    refused=run(sys.executable,str(uninstall_installer),str(drift_uninstall),"--uninstall",cwd=source,expected=(2,))
    if "UNINSTALL BLOCKED" not in refused.stdout or tree(drift_uninstall)!=drift_before:
        raise SystemExit("uninstall did not fail immutably on manifest-owned byte drift")

    crash_uninstall=workspace/"uninstall-crash"
    run(sys.executable,str(uninstall_installer),str(crash_uninstall),"--project-name","uninstall-crash",cwd=source)
    crash_private=crash_uninstall/".agent/project/crash-private.txt"; crash_private.parent.mkdir(parents=True,exist_ok=True); crash_private.write_text("durable\n",encoding="utf-8")
    crash_env=dict(os.environ); crash_env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_TARGET"]="1"
    run(sys.executable,str(uninstall_installer),str(crash_uninstall),"--uninstall",cwd=source,env=crash_env,expected=(97,))
    run(sys.executable,str(uninstall_installer),str(crash_uninstall),"--uninstall",cwd=source)
    if (not crash_private.is_file() or crash_private.read_text(encoding="utf-8")!="durable\n"
            or (crash_uninstall/".agent/.workflow-manifest.json").exists()
            or (crash_uninstall/".agent/scripts/agentctl.py").exists()
            or (crash_uninstall.parent/f".{crash_uninstall.name}.agent-workflow-transaction.json").exists()):
        raise SystemExit("crash-recovered uninstall did not converge while preserving private state")

    print("INSTALL LIFECYCLE PASS: idle/polluted/installed isolation and rollback")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
