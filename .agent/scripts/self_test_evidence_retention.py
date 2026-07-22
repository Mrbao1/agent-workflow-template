#!/usr/bin/env python3
"""Disposable reachability, archive integrity and restore attacks."""

from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time


SOURCE = Path(__file__).resolve().with_name("evidencectl.py")
CONFIG_SOURCE = Path(__file__).resolve().parents[1] / "config.json"


def run(root: Path, *args: str, expected: int = 0) -> str:
    result = subprocess.run(
        [sys.executable, ".agent/scripts/evidencectl.py", *args], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode != expected:
        raise AssertionError(f"{args}: expected {expected}, got {result.returncode}\n{result.stdout}")
    return result.stdout


with tempfile.TemporaryDirectory(prefix="evidence-retention-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    evidence = state / "evidence"; scripts.mkdir(parents=True); evidence.mkdir(parents=True)
    shutil.copy2(SOURCE, scripts / "evidencectl.py")
    shutil.copy2(CONFIG_SOURCE, root / ".agent/config.json")
    (state / "EVIDENCE_INDEX.json").write_text(json.dumps({
        "schema": "agent-evidence-index/v2", "archives": [], "archive_page": None, "updated_at": None,
    }), encoding="utf-8")

    live = evidence / "live proof 证据.json"; transitive = evidence / "transitive child 证据.log"
    cold = evidence / "cold.log"; recent = evidence / "recent.log"
    knowledge_only = evidence / "knowledge proof 证据.md"
    transitive.write_text("must remain reachable\n", encoding="utf-8")
    live.write_text(json.dumps({"next": str(transitive.relative_to(root))}), encoding="utf-8")
    cold_bytes = b"cold evidence\n" * 30000; cold.write_bytes(cold_bytes)
    recent.write_text("recent unreferenced evidence\n", encoding="utf-8")
    knowledge_only.write_text("knowledge-indexed evidence\n", encoding="utf-8")
    knowledge = root / ".agent/knowledge/INDEX.md"; knowledge.parent.mkdir(parents=True)
    knowledge.write_text(f"- [{knowledge_only.name}]({knowledge_only.relative_to(root)})\n", encoding="utf-8")
    old = time.time() - 48 * 3600
    for path in (live, transitive, cold, knowledge_only): os.utime(path, (old, old))
    (state / "TASK.json").write_text(json.dumps({
        "evidence": {"path": str(live.relative_to(root)), "sha256": hashlib.sha256(live.read_bytes()).hexdigest()},
    }), encoding="utf-8")

    before = {path: path.read_bytes() for path in (live, transitive, cold, recent, knowledge_only)}
    dry = json.loads(run(root, "compact", "--dry-run"))
    if dry["selected"] != [str(cold.relative_to(root))] or dry["reachable_files"] != 3:
        raise AssertionError(f"reachability/age plan is unsafe: {dry}")
    if any(path.read_bytes() != data for path, data in before.items()):
        raise AssertionError("dry-run mutated active evidence")

    output = run(root, "compact")
    if "EVIDENCE COMPACTED" not in output or cold.exists() or not all(path.exists() for path in (live, transitive, recent, knowledge_only)):
        raise AssertionError("compaction did not archive only cold unreachable evidence")
    run(root, "verify", "--deep")
    index = json.loads((state / "EVIDENCE_INDEX.json").read_text(encoding="utf-8"))
    if len(index["archives"]) != 1 or index["archives"][0]["file_count"] != 1:
        raise AssertionError("evidence index did not bind one exact archive")
    archive_sha = index["archives"][0]["sha256"]

    run(root, "restore", "--archive", archive_sha)
    if cold.read_bytes() != cold_bytes:
        raise AssertionError("archive restore did not reproduce exact evidence bytes")

    # A restored byte-identical copy is still active when canonical state now
    # references it. Reconciliation must never break that live reference.
    (state / "TASK.json").write_text(json.dumps({
        "evidence": [str(live.relative_to(root)), str(cold.relative_to(root))],
    }), encoding="utf-8")
    retained = run(root, "compact")
    if not cold.exists() or "reconciled=0" not in retained:
        raise AssertionError("reachable restored evidence was incorrectly reconciled away")
    (state / "TASK.json").write_text(json.dumps({
        "evidence": str(live.relative_to(root)),
    }), encoding="utf-8")
    reconcile = run(root, "compact")
    if cold.exists() or "reconciled=1" not in reconcile:
        raise AssertionError("archived duplicate reconciliation is not idempotent")

    # Reusing a stable evidence filename with new task bytes creates another
    # version; it must not poison status or future compaction.
    run(root, "restore", "--archive", archive_sha)
    cold.chmod(0o644); new_bytes = b"new task evidence at the same path\n"; cold.write_bytes(new_bytes)
    os.utime(cold, (old, old))
    config_path = root / ".agent/config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["evidence_retention"]["max_archives"] = 1
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    run(root, "compact", "--force", "--min-age-hours", "0")
    index = json.loads((state / "EVIDENCE_INDEX.json").read_text(encoding="utf-8"))
    if (
        len(index["archives"]) != 1
        or index.get("archive_page", {}).get("total_archives") != 1
    ):
        raise AssertionError("archive saturation did not page old records while preserving the new version")
    run(root, "verify", "--deep")

    run(root, "restore", "--archive", archive_sha)
    cold.chmod(0o644); cold.write_bytes(b"collision")
    run(root, "restore", "--archive", archive_sha, expected=1)

    cold.unlink(); forbidden = evidence / "forbidden-link"
    forbidden.symlink_to(recent)
    run(root, "status", expected=1)

print("EVIDENCE RETENTION SELF-TEST PASSED: reachability, deterministic archive, restore and collision gates")
