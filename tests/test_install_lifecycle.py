#!/usr/bin/env python3
"""Repeatable install isolation and transaction lifecycle regression test."""

from pathlib import Path
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile


SOURCE_SENTINEL = "SOURCE_PRIVATE_SENTINEL_NEVER_INSTALL"
TARGET_SENTINEL = "TARGET_PRIVATE_SENTINEL_PRESERVE"


def run(*command: str, cwd: Path, env=None, expected=(0,)) -> subprocess.CompletedProcess:
    result = subprocess.run(
        list(command), cwd=str(cwd), env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180,
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
            result[relative] = ("file", hashlib.sha256(path.read_bytes()).hexdigest())
        elif path.is_dir():
            result[relative] = ("dir", None)
    return result


def project_init_journal(target: Path, phase: str = "prepared") -> dict:
    paths = (
        target / ".agent/config.json",
        target / ".agent/policies/PROJECT_GUARDRAILS.md",
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
    before = tree(target)
    env = dict(os.environ); env["AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_TARGET"] = "1"
    run(sys.executable, str(installer), str(target), *mode_args, cwd=cwd, env=env, expected=(97,))
    run(sys.executable, str(installer), str(target), *recovery_args, cwd=cwd, expected=(0, 1))
    if tree(target) != before:
        raise SystemExit(f"transaction rollback changed target for {' '.join(mode_args)}")


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
        installer = polluted / "install.py"
        target = workspace / "installed-project"

        # Polluted source private config/policies/state/evidence/links are ignored.
        installed = run(
            sys.executable, str(installer), str(target), "--project-name", "isolation-fixture",
            cwd=polluted,
        )
        if "PROJECT INIT REQUIRED" not in installed.stdout or "BOOTSTRAP NOT READY" not in installed.stdout or "NEXT: local" in installed.stdout:
            raise SystemExit("fresh install bootstrap output overclaimed readiness")
        assert_no_sentinel(target)
        config = json.loads((target / ".agent/config.json").read_text(encoding="utf-8"))
        task = json.loads((target / ".agent/state/TASK.json").read_text(encoding="utf-8"))
        agents = json.loads((target / ".agent/state/agents.json").read_text(encoding="utf-8"))
        if (
            config.get("project") != {"name": "isolation-fixture", "type": "general-project"}
            or config.get("guardrails_ready") is not False
            or config.get("project_initialization") is not None
            or task.get("status") != "idle" or task.get("requirements_clarified") is not False
            or any(agents.get(name) != [] for name in ("members", "prepared_dispatches", "capacity_failures", "replay_runs"))
        ):
            raise SystemExit("fresh install did not use the canonical isolated idle seed")

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
        run(sys.executable, ".agent/scripts/agentctl.py", "status", cwd=target)
        if journal_path.exists() or any(path.read_bytes() != data for path, data in recovery_before.items()):
            raise SystemExit("prepared project-init recovery did not restore all targets atomically")

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
        guardrails = target / "project-guardrails.md"; completed_guardrails(guardrails)
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
        if config.get("guardrails_ready") is not True or binding.get("guardrails_sha256") != hashlib.sha256(policy).hexdigest():
            raise SystemExit("project-init did not atomically bind readiness to guardrails bytes")

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
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["version"] = "3.1.39"; manifest["migration_version"] = 32
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        crash_and_recover(installer, target, ("--update",), ("--check",), polluted)
        run(sys.executable, str(installer), str(target), "--update", cwd=polluted)
        if private.read_text(encoding="utf-8") != TARGET_SENTINEL:
            raise SystemExit("update/migration replaced installed project-private evidence")
        assert_no_sentinel(target)

        # Adopt has the same isolation and rollback properties.
        manifest_path.unlink()
        crash_and_recover(installer, target, ("--adopt",), ("--adopt", "--dry-run"), polluted)
        run(sys.executable, str(installer), str(target), "--adopt", cwd=polluted)
        if private.read_text(encoding="utf-8") != TARGET_SENTINEL:
            raise SystemExit("adopt replaced installed project-private evidence")
        assert_no_sentinel(target)
        run(sys.executable, str(installer), str(target), "--check", cwd=polluted)

        # An older installer must never silently downgrade a newer install.
        newer = workspace / "newer-install"
        run(sys.executable, str(installer), str(newer), "--project-name", "downgrade-fixture", cwd=polluted)
        newer_manifest_path = newer / ".agent/.workflow-manifest.json"
        newer_manifest = json.loads(newer_manifest_path.read_text(encoding="utf-8"))
        newer_manifest["version"] = "99.0.0"; newer_manifest["migration_version"] = 99
        newer_manifest_path.write_text(json.dumps(newer_manifest, indent=2) + "\n", encoding="utf-8")
        newer_before = tree(newer)
        refused = run(sys.executable, str(installer), str(newer), "--update", cwd=polluted, expected=(2,))
        if "UPDATE REFUSED" not in refused.stdout or tree(newer) != newer_before:
            raise SystemExit("older installer did not refuse a newer target byte-for-byte")
        check_newer = run(sys.executable, str(installer), str(newer), "--check", cwd=polluted, expected=(3,))
        if "TARGET NEWER" not in check_newer.stdout or tree(newer) != newer_before:
            raise SystemExit("--check did not flag a newer target with its distinct exit code")
        forced = run(
            sys.executable, str(installer), str(newer), "--update", "--allow-downgrade", cwd=polluted, expected=(2,),
        )
        if "reverse migrations are unsupported" not in forced.stdout or tree(newer) != newer_before:
            raise SystemExit("--allow-downgrade bypassed the tested reverse-migration boundary")

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
            unknown_manifest["migration_version"] = 40
            unknown_manifest_path.write_text(json.dumps(unknown_manifest, indent=2) + "\n", encoding="utf-8")
            version_before = tree(unknown_version)
            check_unknown = run(
                sys.executable, str(installer), str(unknown_version), "--check",
                cwd=polluted, expected=(3,),
            )
            if "TARGET VERSION INVALID" not in check_unknown.stdout or tree(unknown_version) != version_before:
                raise SystemExit(f"--check did not reject unknown workflow version {bad_value!r} byte-for-byte")
            update_unknown = run(
                sys.executable, str(installer), str(unknown_version), "--update",
                cwd=polluted, expected=(2,),
            )
            if "UPDATE REFUSED" not in update_unknown.stdout or tree(unknown_version) != version_before:
                raise SystemExit(f"--update did not reject unknown workflow version {bad_value!r} byte-for-byte")

        # A malformed migration_version fails closed with a clean message and
        # never leaks an uncaught ValueError traceback or mutates the target.
        malformed_version = workspace / "malformed-migration-version"
        run(
            sys.executable, str(installer), str(malformed_version),
            "--project-name", "malformed-version-fixture", cwd=polluted,
        )
        malformed_manifest_path = malformed_version / ".agent/.workflow-manifest.json"
        for bad_value in ("abc", True):
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
        carry_manifest = json.loads(carry_manifest_path.read_text(encoding="utf-8"))
        carry_manifest["migration_version"] = 35
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
        # v3.1.44 could leave non-monotonic while reporting update success.
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
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["version"] = "3.1.42"
            manifest["migration_version"] = 35
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
            sys.executable, str(installer), str(ghost), "--project-name", "ghost", "--dry-run", cwd=polluted,
        )
        if "DRY RUN" not in dry_ghost.stdout or (workspace / "ghost-parent").exists():
            raise SystemExit("--dry-run install created directories for a missing target")

        # A dedicated executable stub emitting the exact provider-preflight
        # health line passes the health protocol; wrong output is rejected.
        installer_spec = importlib.util.spec_from_file_location("workflow_installer", installer)
        installer_module = importlib.util.module_from_spec(installer_spec)
        installer_spec.loader.exec_module(installer_module)
        rebind_fixture = workspace / "route-v39/.agent/state"
        rebind_fixture.mkdir(parents=True)
        (rebind_fixture / "TASK.json").write_text("{}\n", encoding="utf-8")
        real_subprocess_run = installer_module.subprocess.run
        rebind_calls = []
        def fake_rebind_run(*args, **kwargs):
            rebind_calls.append((args, kwargs))
            return subprocess.CompletedProcess(args[0] if args else [], 0, "VALID context capsule\n", "")
        installer_module.subprocess.run = fake_rebind_run
        try:
            installer_module.finalize_active_context_binding(rebind_fixture.parent, 39)
            if len(rebind_calls) != 1 or "migration-40-template-route-rebind" not in rebind_calls[0][0][0][2]:
                raise SystemExit("v39 to v40 route migration skipped its final context rebind")
            installer_module.finalize_active_context_binding(rebind_fixture.parent, 40)
            if len(rebind_calls) != 1:
                raise SystemExit("current migration unexpectedly rebuilt an unchanged context")
        finally:
            installer_module.subprocess.run = real_subprocess_run

        real_guard = installer_module.protected_external_adapter
        installer_module.protected_external_adapter = lambda owner, raw: True
        try:
            stub = workspace / "provider-preflight-stub"
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "PROVIDER PREFLIGHT ADAPTER READY"\n', encoding="utf-8")
            stub.chmod(0o755)
            if installer_module.bootstrap_provider_preflight_adapter(workspace, str(stub)) != str(stub.resolve()):
                raise SystemExit("provider preflight stub with the exact health output was not accepted")
            wrong = workspace / "provider-preflight-wrong"
            wrong.write_text('#!/bin/sh\nprintf "%s\\n" "WRONG HEALTH OUTPUT"\n', encoding="utf-8")
            wrong.chmod(0o755)
            try:
                installer_module.bootstrap_provider_preflight_adapter(workspace, str(wrong))
            except RuntimeError:
                pass
            else:
                raise SystemExit("provider preflight stub with wrong health output was accepted")
        finally:
            installer_module.protected_external_adapter = real_guard

    print("INSTALL LIFECYCLE PASS: idle/polluted/installed isolation and rollback")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
