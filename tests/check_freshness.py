#!/usr/bin/env python3
"""Freshness gate: bundle-covered or managed file changes must ship resealed state.

policy-bundle v2 binds `.agent/scripts/**.py`, the workflow/index/guardrails
documents and the primary skill; the install manifest binds every managed file.
Editing any of those without resealing the fresh-state seed capsule, the live
capsule and the manifests leaves installed contexts failing closed (this exact
failure reached CI once). This check fails fast at source level so it cannot.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / ".agent" / "assets" / "fresh-state" / "v1"


def load_install():
    spec = importlib.util.spec_from_file_location("install", ROOT / "install.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bundle_errors(contextctl, install) -> list:
    errors = []
    # Seed capsule: rebuild a fresh candidate with install.py's own machinery
    # (seed config + seed guardrails + current managed files) and compare the
    # bundle hash it produces against the committed seed capsule.
    tmp = Path(tempfile.mkdtemp(prefix="freshness-seed-"))
    try:
        candidate = tmp / "proj" / ".agent"
        install.copy_managed_fresh_install(ROOT / ".agent", candidate)
        install.initialize_fresh_context(ROOT / ".agent", candidate)
        rebuilt = json.loads((candidate / "state" / "CONTEXT.json").read_text(encoding="utf-8"))
        committed = json.loads((SEED / "state" / "CONTEXT.json").read_text(encoding="utf-8"))
        if committed.get("policy_bundle_sha256") != rebuilt.get("policy_bundle_sha256"):
            errors.append(
                "seed capsule policy_bundle_sha256 is stale; rebuild the seed "
                "capsule and reseal the seed manifest before committing"
            )
    except (RuntimeError, OSError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        errors.append(f"seed capsule rebuild failed: {error}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Live capsule: recompute the bundle against the live config directly. A
    # partial checkout may lack these files; report a clean failure instead of
    # a raw traceback.
    try:
        capsule = json.loads((ROOT / ".agent" / "state" / "CONTEXT.json").read_text(encoding="utf-8"))
        task = json.loads((ROOT / ".agent" / "state" / "TASK.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"live capsule is unreadable: {error}")
        return errors
    version = capsule.get("policy_bundle_version") or contextctl.LEGACY_POLICY_BUNDLE_VERSION
    if capsule.get("policy_bundle_sha256") != contextctl.policy_bundle_sha256(task, version):
        errors.append("live capsule policy_bundle_sha256 is stale; rebind it before committing")
    return errors


def main() -> int:
    failures = []
    # contextctl resolves AGENT_DIR from Path.cwd() upward; anchor at ROOT so
    # an absolute-path invocation from another project hashes this tree.
    os.chdir(ROOT)
    install = load_install()
    try:
        install.fresh_state_seed(ROOT / ".agent")
    except RuntimeError as error:
        failures.append(f"fresh-state seed invalid: {error}")

    sys.path.insert(0, str(ROOT / ".agent" / "scripts"))
    import contextctl  # noqa: E402

    failures.extend(bundle_errors(contextctl, install))

    try:
        result = subprocess.run(
            [sys.executable, ".agent/scripts/contextctl.py", "check"],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
        )
    except subprocess.TimeoutExpired:
        failures.append("contextctl check timed out after 120s")
    else:
        if result.returncode:
            failures.append(f"contextctl check failed: {result.stdout.strip().splitlines()[-1] if result.stdout.strip() else result.returncode}")

    try:
        with tempfile.TemporaryDirectory(prefix="freshness-manifest-") as raw:
            target = Path(raw) / "project"
            shutil.copytree(ROOT / ".agent", target / ".agent")
            (target / ".agent").chmod(0o700)
            for bootstrap in ("AGENTS.md", "CLAUDE.md"):
                shutil.copy2(ROOT / bootstrap, target / bootstrap)
            result = subprocess.run(
                [sys.executable, str(ROOT / "install.py"), str(target), "--check"],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
            )
    except subprocess.TimeoutExpired:
        failures.append("install manifest check timed out after 120s")
    else:
        if result.returncode or "WORKFLOW CURRENT" not in result.stdout:
            failures.append(f"install manifest is not current: {result.stdout.strip().splitlines()[-1] if result.stdout.strip() else result.returncode}")

    if failures:
        for failure in failures:
            print(f"FRESHNESS FAIL: {failure}")
        return 1
    print("FRESHNESS PASS: seed, live capsule, bundle and manifest are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
