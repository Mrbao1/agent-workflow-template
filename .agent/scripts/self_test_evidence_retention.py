#!/usr/bin/env python3
"""Disposable reachability, archive integrity and restore attacks."""

from pathlib import Path
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time


SOURCE = Path(__file__).resolve().with_name("evidencectl.py")
DELIVERY_SOURCE = Path(__file__).resolve().with_name("deliveryctl.py")
DECISION_SOURCE = Path(__file__).resolve().with_name("humandecision.py")
CONFIG_SOURCE = Path(__file__).resolve().parents[1] / "config.json"


def run(root: Path, *args: str, expected: int = 0) -> str:
    result = subprocess.run(
        [sys.executable, ".agent/scripts/evidencectl.py", *args], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode != expected:
        raise AssertionError(f"{args}: expected {expected}, got {result.returncode}\n{result.stdout}")
    return result.stdout


def run_delivery(root: Path, *args: str, expected: int = 0) -> str:
    result = subprocess.run(
        [sys.executable, ".agent/scripts/deliveryctl.py", *args], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode != expected:
        raise AssertionError(f"deliveryctl {args}: expected {expected}, got {result.returncode}\n{result.stdout}")
    return result.stdout


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fresh_project(root: Path, *, delivery: bool = False) -> Path:
    scripts = root / ".agent/scripts"; state = root / ".agent/state"
    evidence = state / "evidence"; scripts.mkdir(parents=True); evidence.mkdir(parents=True)
    shutil.copy2(SOURCE, scripts / "evidencectl.py")
    shutil.copy2(DECISION_SOURCE, scripts / "humandecision.py")
    if delivery:
        shutil.copy2(DELIVERY_SOURCE, scripts / "deliveryctl.py")
    shutil.copy2(CONFIG_SOURCE, root / ".agent/config.json")
    if delivery:
        config_path = root / ".agent/config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["branches"] = {"local": ["feature/*"], "test": ["release/*"], "production": ["main"]}
        write_json(config_path, config)
    write_json(state / "EVIDENCE_INDEX.json", {
        "schema": "agent-evidence-index/v2", "archives": [], "archive_page": None, "updated_at": None,
    })
    return evidence


def write_task_archive(root: Path, payload: dict, total: int) -> dict:
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    value_sha = sha256(data)
    path = root / ".agent/state/evidence/task-archives" / f"{value_sha}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {
        "schema": "agent-task-archive-head/v1", "path": str(path.relative_to(root)),
        "sha256": value_sha, "bytes": len(data), "total_archives": total,
    }


def v1_payload(utf8: str, previous: object) -> dict:
    return {
        "schema": "agent-task-archive/v1", "archived_at": "2026-01-01T00:00:00+00:00",
        "source": "workflow:accepted", "reason": "self-test", "assurance": "self-test",
        "decision_receipt": None,
        "task": {"sha256": "0" * 64, "bytes": len(utf8.encode()), "utf8": utf8},
        "requirement_contract": None, "previous": previous,
    }


with tempfile.TemporaryDirectory(prefix="evidence-retention-") as raw:
    root = Path(raw); state = root / ".agent/state"
    evidence = fresh_project(root)

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
    write_json(state / "TASK.json", {
        "evidence": {"path": str(live.relative_to(root)), "sha256": sha256(live.read_bytes())},
    })

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
    write_json(state / "TASK.json", {
        "evidence": [str(live.relative_to(root)), str(cold.relative_to(root))],
    })
    retained = run(root, "compact")
    if not cold.exists() or "reconciled=0" not in retained:
        raise AssertionError("reachable restored evidence was incorrectly reconciled away")
    write_json(state / "TASK.json", {
        "evidence": str(live.relative_to(root)),
    })
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

# Task-archive reachability: v1 payloads stay textually scanned (fail-safe),
# v2 payloads only traverse referenced_evidence digests and previous heads.
with tempfile.TemporaryDirectory(prefix="evidence-task-archives-") as raw:
    root = Path(raw); state = root / ".agent/state"
    evidence = fresh_project(root)
    a_ref = evidence / "a-v1-text.log"; b_ref = evidence / "b-v2-text.log"
    c_ref = evidence / "c-v2-digest.log"; d_cold = evidence / "d-cold.log"
    a_ref.write_text("referenced by legacy v1 text\n", encoding="utf-8")
    b_ref.write_text("only inside v2 payload text\n", encoding="utf-8")
    c_ref.write_text("digest referenced evidence\n", encoding="utf-8")
    d_cold.write_text("cold unreferenced\n", encoding="utf-8")
    head1 = write_task_archive(root, v1_payload(json.dumps({"evidence": str(a_ref.relative_to(root))}), None), 1)
    v2 = v1_payload(f"full archived task text mentioning {b_ref.relative_to(root)}", head1)
    v2["schema"] = "agent-task-archive/v2"
    v2["referenced_evidence"] = [sha256(c_ref.read_bytes())]
    head2 = write_task_archive(root, v2, 2)
    write_json(state / "TASK.json", {"task_archive": head2})
    old = time.time() - 72 * 3600
    for path in (a_ref, b_ref, c_ref, d_cold): os.utime(path, (old, old))
    run(root, "compact", "--force")
    if not a_ref.exists():
        raise AssertionError("legacy v1 task-archive text no longer protects referenced evidence")
    if not c_ref.exists():
        raise AssertionError("v2 referenced_evidence digest does not protect evidence")
    if not (root / head1["path"]).exists() or not (root / head2["path"]).exists():
        raise AssertionError("task-archive head chain was compacted away")
    if b_ref.exists() or d_cold.exists():
        raise AssertionError("v2 payload text leaked textual reachability or cold evidence survived")
    run(root, "verify", "--deep")

# Migration rewrites a legacy v1 chain to digest-bound v2 and re-anchors heads.
with tempfile.TemporaryDirectory(prefix="evidence-task-migration-") as raw:
    root = Path(raw); state = root / ".agent/state"
    evidence = fresh_project(root)
    m_ref = evidence / "m-ref.log"; m_cold = evidence / "m-cold.log"
    m_ref.write_text("referenced from an archived task\n", encoding="utf-8")
    m_cold.write_text("cold\n", encoding="utf-8")
    head1 = write_task_archive(root, v1_payload(json.dumps({"proof": str(m_ref.relative_to(root))}), None), 1)
    head2 = write_task_archive(root, v1_payload("no references here", head1), 2)
    write_json(state / "TASK.json", {"task_archive": head2, "status": "in_progress"})

    plan = json.loads(run(root, "migrate-task-archives", "--dry-run"))
    if plan["rewritten"] != 2 or plan["new_head"]["sha256"] == head2["sha256"]:
        raise AssertionError(f"migration dry-run plan is wrong: {plan}")
    task = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if task["task_archive"]["sha256"] != head2["sha256"]:
        raise AssertionError("migration dry-run moved the TASK head")

    output = run(root, "migrate-task-archives")
    if "TASK ARCHIVE MIGRATED" not in output:
        raise AssertionError(f"migration did not run: {output}")
    task = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    new_head = task["task_archive"]
    if new_head["sha256"] == head2["sha256"] or new_head["total_archives"] != 2:
        raise AssertionError("TASK head was not re-anchored to the rewritten chain")
    if not (root / head1["path"]).exists() or not (root / head2["path"]).exists():
        raise AssertionError("migration destroyed the legacy v1 archive bytes")
    newest = json.loads((root / new_head["path"]).read_text(encoding="utf-8"))
    if newest["schema"] != "agent-task-archive/v2" or newest["referenced_evidence"] != []:
        raise AssertionError("rewritten head payload is not digest-bound v2")
    oldest_head = newest["previous"]
    oldest = json.loads((root / oldest_head["path"]).read_text(encoding="utf-8"))
    if (
        oldest["schema"] != "agent-task-archive/v2" or oldest["previous"] is not None
        or oldest["referenced_evidence"] != [sha256(m_ref.read_bytes())]
        or oldest_head["total_archives"] != 1
    ):
        raise AssertionError("referenced evidence paths were not extracted into digests")
    if "TASK ARCHIVE MIGRATION: chain is already v2" not in run(root, "migrate-task-archives"):
        raise AssertionError("migration is not idempotent on a v2 chain")

    old = time.time() - 72 * 3600
    for path in (m_ref, m_cold): os.utime(path, (old, old))
    run(root, "compact", "--force")
    if not m_ref.exists() or m_cold.exists():
        raise AssertionError("migrated v2 digests do not protect evidence across compaction")
    run(root, "verify", "--deep")

# --include-task-history deep-archives the chain behind a human decision and
# clears the dangling TASK head.
with tempfile.TemporaryDirectory(prefix="evidence-task-history-") as raw:
    root = Path(raw); state = root / ".agent/state"
    evidence = fresh_project(root)
    e_ref = evidence / "e.log"
    e_ref.write_text("ordinary evidence\n", encoding="utf-8")
    payload = v1_payload("archived task", None)
    payload["schema"] = "agent-task-archive/v2"
    payload["referenced_evidence"] = []
    head = write_task_archive(root, payload, 1)
    write_json(state / "TASK.json", {"task_archive": head, "decision_policy_version": 2})

    dry = json.loads(run(root, "compact", "--include-task-history", "--dry-run"))
    if not dry["include_task_history"] or str((root / head["path"]).relative_to(root)) not in dry["selected"]:
        raise AssertionError(f"task-history dry-run plan is wrong: {dry}")
    if not (root / head["path"]).exists():
        raise AssertionError("task-history dry-run mutated evidence")
    run(root, "compact", "--include-task-history", expected=1)
    if not (root / head["path"]).exists():
        raise AssertionError("task history was compacted without a human decision source")
    output = run(root, "compact", "--include-task-history", "--source", "user:self-test-history")
    if "TASK HISTORY DECISION" not in output or "EVIDENCE COMPACTED" not in output:
        raise AssertionError(f"task-history compaction did not bind a decision: {output}")
    if (root / head["path"]).exists() or not e_ref.exists():
        raise AssertionError("task history was not deep-archived exactly")
    task = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if task.get("task_archive") is not None:
        raise AssertionError("dangling TASK task_archive head survived history compaction")
    run(root, "verify", "--deep")
    index = json.loads((state / "EVIDENCE_INDEX.json").read_text(encoding="utf-8"))
    run(root, "restore", "--archive", index["archives"][0]["sha256"])
    if not (root / head["path"]).exists():
        raise AssertionError("deep-archived task history is not restorable")

# deliveryctl init archives non-empty states and validate verifies the epoch chain.
with tempfile.TemporaryDirectory(prefix="delivery-chain-") as raw:
    root = Path(raw); state = root / ".agent/state"
    fresh_project(root, delivery=True)
    write_json(state / "TASK.json", {"environment": "local", "deployment_requested": True})

    run_delivery(root, "init")
    current = json.loads((state / "delivery.json").read_text(encoding="utf-8"))
    if current["epoch"] != 1 or current["previous_head"] is not None or current["status"] != "awaiting_artifact":
        raise AssertionError(f"fresh init did not start epoch 1: {current}")
    run_delivery(root, "validate")

    # A legacy state without chain fields must stay valid (pre-chain installs).
    legacy = {key: value for key, value in current.items() if key not in {"epoch", "previous_head"}}
    write_json(state / "delivery.json", legacy)
    run_delivery(root, "validate")

    artifact = root / "dist/app.bin"; artifact.parent.mkdir(parents=True)
    artifact_bytes = b"binary-artifact\n"; artifact.write_bytes(artifact_bytes)
    artifact_sha = sha256(artifact_bytes)
    legacy.update({
        "status": "awaiting_test",
        "artifact": {
            "path": "dist/app.bin", "sha256": artifact_sha, "bytes": len(artifact_bytes),
            "digest": f"sha256:{artifact_sha}", "built_by": "builder-1",
            "source_branch": "release/1.0", "source_revision": "a" * 40,
            "build_run_id": "run-1", "recorded_at": "2026-01-01T00:00:00+00:00",
        },
        "updated_at": "2026-01-01T00:00:00+00:00",
    })
    write_json(state / "delivery.json", legacy)
    run_delivery(root, "validate")
    prior_bytes = (state / "delivery.json").read_bytes()

    run_delivery(root, "init")
    current = json.loads((state / "delivery.json").read_text(encoding="utf-8"))
    if current["epoch"] != 2 or current["status"] != "awaiting_artifact" or current["artifact"] is not None:
        raise AssertionError(f"non-empty init did not advance the epoch: {current}")
    head = current["previous_head"]
    archived_path = root / head["path"]
    if (
        not isinstance(head, dict) or head["sha256"] != sha256(prior_bytes)
        or head["bytes"] != len(prior_bytes) or not archived_path.is_file()
        or archived_path.read_bytes() != prior_bytes
    ):
        raise AssertionError("init did not archive the exact prior delivery receipts")
    run_delivery(root, "validate")

    archived_path.chmod(0o644); archived_path.write_bytes(b"tampered receipts")
    run_delivery(root, "validate", expected=1)
    archived_path.write_bytes(prior_bytes); archived_path.chmod(0o444)
    run_delivery(root, "validate")

    # A second reset links epoch 3 back through the epoch 2 archive.
    current.update({
        "status": "awaiting_test",
        "artifact": legacy["artifact"],
    })
    write_json(state / "delivery.json", current)
    run_delivery(root, "init")
    current = json.loads((state / "delivery.json").read_text(encoding="utf-8"))
    if current["epoch"] != 3:
        raise AssertionError("epoch did not advance across repeated non-empty resets")
    run_delivery(root, "validate")

# A corrupt or foreign prior delivery state must never poison the epoch chain:
# init archives the exact bytes UNLINKED and restarts at a fresh epoch 1.
with tempfile.TemporaryDirectory(prefix="delivery-chain-break-") as raw:
    root = Path(raw); state = root / ".agent/state"
    fresh_project(root, delivery=True)
    write_json(state / "TASK.json", {"environment": "local", "deployment_requested": True})

    (state / "delivery.json").write_bytes(b"{not json")
    output = run_delivery(root, "init")
    if "DELIVERY CHAIN BREAK" not in output or "unparseable JSON" not in output:
        raise AssertionError(f"corrupt prior state did not break the chain loudly: {output}")
    current = json.loads((state / "delivery.json").read_text(encoding="utf-8"))
    if current["epoch"] != 1 or current["previous_head"] is not None:
        raise AssertionError(f"chain break did not restart at an unlinked epoch 1: {current}")
    run_delivery(root, "validate")
    broken_archives = list((state / "evidence/delivery-archives").glob("*.json"))
    if len(broken_archives) != 1 or broken_archives[0].read_bytes() != b"{not json":
        raise AssertionError("corrupt prior bytes were not preserved as unlinked evidence")

    # A foreign-schema state (parseable but not a delivery state) breaks too.
    foreign = dict(current)
    foreign["schema"] = "agent-delivery/v99"
    foreign["epoch"] = 7
    write_json(state / "delivery.json", foreign)
    output = run_delivery(root, "init")
    if "DELIVERY CHAIN BREAK" not in output or "foreign schema" not in output:
        raise AssertionError(f"foreign prior state did not break the chain loudly: {output}")
    current = json.loads((state / "delivery.json").read_text(encoding="utf-8"))
    if current["epoch"] != 1 or current["previous_head"] is not None:
        raise AssertionError(f"foreign schema did not restart the chain: {current}")
    run_delivery(root, "validate")

    # A schema-valid state with a non-integer epoch would be archived and
    # linked, wedging every later validate on chain continuity: break instead.
    wedged = dict(current)
    wedged["epoch"] = "corrupt"
    write_json(state / "delivery.json", wedged)
    output = run_delivery(root, "init")
    if "DELIVERY CHAIN BREAK" not in output or "invalid epoch" not in output:
        raise AssertionError(f"non-integer epoch did not break the chain loudly: {output}")
    current = json.loads((state / "delivery.json").read_text(encoding="utf-8"))
    if current["epoch"] != 1 or current["previous_head"] is not None:
        raise AssertionError(f"invalid epoch did not restart the chain: {current}")
    run_delivery(root, "validate")

    # An empty state whose previous_head is a malformed head would be KEPT and
    # fail "archive head is invalid or missing" on every validate: break instead.
    wedged = dict(current)
    wedged["previous_head"] = {"path": "bogus", "sha256": "not-hex", "bytes": "lots"}
    write_json(state / "delivery.json", wedged)
    output = run_delivery(root, "init")
    if "DELIVERY CHAIN BREAK" not in output or "malformed previous_head" not in output:
        raise AssertionError(f"malformed previous_head did not break the chain loudly: {output}")
    current = json.loads((state / "delivery.json").read_text(encoding="utf-8"))
    if current["epoch"] != 1 or current["previous_head"] is not None:
        raise AssertionError(f"malformed previous_head did not restart the chain: {current}")
    run_delivery(root, "validate")

    # The chain keeps working after a break: the next non-empty reset links
    # epoch 2 back to the post-break state and validate accepts it.
    artifact = root / "dist/app.bin"; artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact_bytes = b"post-break artifact\n"; artifact.write_bytes(artifact_bytes)
    artifact_sha = sha256(artifact_bytes)
    current.update({
        "status": "awaiting_test",
        "artifact": {
            "path": "dist/app.bin", "sha256": artifact_sha, "bytes": len(artifact_bytes),
            "digest": f"sha256:{artifact_sha}", "built_by": "builder-1",
            "source_branch": "release/1.0", "source_revision": "a" * 40,
            "build_run_id": "run-1", "recorded_at": "2026-01-01T00:00:00+00:00",
        },
        "updated_at": "2026-01-01T00:00:00+00:00",
    })
    write_json(state / "delivery.json", current)
    run_delivery(root, "init")
    current = json.loads((state / "delivery.json").read_text(encoding="utf-8"))
    if current["epoch"] != 2 or not isinstance(current["previous_head"], dict):
        raise AssertionError(f"post-break reset did not link epoch 2: {current}")
    run_delivery(root, "validate")

# Reference roots are configurable; orphans are reported then GC'd; restore holds the lock.
with tempfile.TemporaryDirectory(prefix="evidence-roots-") as raw:
    root = Path(raw); state = root / ".agent/state"
    evidence = fresh_project(root)
    skill_ref = evidence / "skill-referenced.log"; cold2 = evidence / "cold2.log"
    skill_ref.write_text("only a skill references this\n", encoding="utf-8")
    cold2.write_text("cold\n", encoding="utf-8")
    skill = root / ".agent/skills/demo/SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text(f"evidence: {skill_ref.relative_to(root)}\n", encoding="utf-8")
    old = time.time() - 72 * 3600
    for path in (skill_ref, cold2): os.utime(path, (old, old))
    write_json(state / "TASK.json", {"status": "in_progress"})

    run(root, "compact", "--force")
    if not skill_ref.exists() or cold2.exists():
        raise AssertionError("default reference roots do not cover .agent/skills")
    config_path = root / ".agent/config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["evidence"] = {"reference_roots": [".agent/state"]}
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    run(root, "compact", "--force")
    if skill_ref.exists():
        raise AssertionError("configured reference_roots did not replace the default roots")
    run(root, "verify", "--deep")

    archives = state / "evidence-archives"
    leftover = archives / ".evidence-archive.leftover.zip"; leftover.write_bytes(b"junk")
    unindexed = archives / ("f" * 64 + ".zip"); unindexed.write_bytes(b"unindexed")
    report = run(root, "verify")
    if report.count("EVIDENCE ORPHAN ARCHIVE") != 2 or "orphans=2" not in report:
        raise AssertionError(f"verify did not report both orphan archives: {report}")
    gc_plan = json.loads(run(root, "compact", "--gc-orphans", "--dry-run"))
    if len(gc_plan["orphans"]) != 2 or not leftover.exists() or not unindexed.exists():
        raise AssertionError("gc-orphans dry-run was not dry")
    collected = run(root, "compact", "--gc-orphans")
    if "removed=2" not in collected or leftover.exists() or unindexed.exists():
        raise AssertionError(f"gc-orphans did not remove exactly the reported orphans: {collected}")
    run(root, "verify", "--deep")

    index = json.loads((state / "EVIDENCE_INDEX.json").read_text(encoding="utf-8"))
    if len(index["archives"]) != 2:
        raise AssertionError("orphan GC destroyed indexed archives")
    restored_sha = index["archives"][-1]["sha256"]
    lock = state / ".evidence.lock"; lock.touch(exist_ok=True)
    handle = lock.open("r+")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    process = subprocess.Popen(
        [sys.executable, ".agent/scripts/evidencectl.py", "restore", "--archive", restored_sha],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    time.sleep(2)
    if process.poll() is not None:
        raise AssertionError(f"restore ignored the evidence lock: {process.communicate()[0]}")
    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    output = process.communicate(timeout=30)[0]
    if process.returncode != 0 or "EVIDENCE RESTORED" not in output:
        raise AssertionError(f"restore did not complete after the lock released: {output}")
    handle.close()

print("EVIDENCE RETENTION SELF-TEST PASSED: reachability, deterministic archive, restore and collision gates")
