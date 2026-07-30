#!/usr/bin/env python3
"""Atomically commit canonical TASK changes with an authorized context transition."""

from pathlib import Path
import base64
import contextlib
import copy
import datetime as dt
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import contextctl


AGENT_DIR = contextctl.AGENT_DIR
ROOT = contextctl.ROOT
TASK_PATH = contextctl.TASK_PATH
CONTEXT_PATH = contextctl.CONTEXT_PATH
CONTEXT_TOOL = AGENT_DIR / "scripts" / "contextctl.py"
TASK_LOCK = AGENT_DIR / "state" / ".task.lock"
AUTH_DIR = AGENT_DIR / "state" / ".context-authorizations"
TRANSITION_JOURNAL_PATH = AGENT_DIR / "state" / ".context-transition-journal.json"
TRANSITION_JOURNAL_SCHEMA = "agent-context-transition-journal/v1"
TRANSITION_JOURNAL_STATUS_SCHEMA = "agent-context-transition-journal-status/v1"


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


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def changed_fields(before: Dict[str, object], after: Dict[str, object]) -> list[str]:
    old = contextctl.task_invariant(before)
    new = contextctl.task_invariant(after)
    return sorted(key for key in contextctl.TASK_INVARIANT_KEYS if old.get(key) != new.get(key))


def _authorization(
    before: Dict[str, object], after: Dict[str, object], mutator: str, operation: str, reason: str
) -> Tuple[Path, str]:
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    value = {
        "schema": "agent-context-transition-authorization/v1",
        "mutator": mutator,
        "operation": operation,
        "reason": reason,
        "issued_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "from_task_sha256": contextctl.invariant_sha256(before),
        "to_task_sha256": contextctl.invariant_sha256(after),
        "changed_fields": changed_fields(before, after),
        "before_task": before,
        "after_task": after,
    }
    descriptor, raw = tempfile.mkstemp(prefix="context-transition-", suffix=".json", dir=str(AUTH_DIR))
    path = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            data = json.dumps(value, ensure_ascii=False, indent=2).encode() + b"\n"
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return path, hashlib.sha256(path.read_bytes()).hexdigest()
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_parents(paths: Iterable[Path]) -> None:
    for parent in dict.fromkeys(path.parent for path in paths):
        _fsync_directory(parent)


def _restore_all(backups: Dict[Path, Optional[bytes]]) -> None:
    """Roll back committed files: stage every temporary first, then rename.

    A crash during rollback then leaves at worst unrenamed temporaries next to
    untouched targets, and the transition journal still holds the pre-commit
    bytes for a later recovery pass.
    """
    staged: List[Tuple[Path, Optional[Path]]] = []
    try:
        for path, previous in backups.items():
            if previous is None:
                staged.append((path, None))
                continue
            descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.restore-", dir=str(path.parent))
            temporary = Path(raw)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(previous)
                handle.flush()
                os.fsync(handle.fileno())
            staged.append((path, temporary))
        for path, temporary in staged:
            if temporary is None:
                path.unlink(missing_ok=True)
            else:
                os.replace(temporary, path)
    finally:
        for _, temporary in staged:
            if temporary is not None and temporary.exists():
                temporary.unlink()
    _fsync_parents(list(backups))


def _journal_relative(path: Path) -> str:
    return str(Path(os.path.abspath(path)).relative_to(ROOT))


def _transition_journal(backups: Dict[Path, Optional[bytes]], after_digests: Dict[Path, Optional[str]],
                        mutator: str, operation: str, reason: str) -> Dict[str, object]:
    return {
        "schema": TRANSITION_JOURNAL_SCHEMA,
        "mutator": mutator,
        "operation": operation,
        "reason": reason,
        "issued_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "backups": {
            _journal_relative(path): {
                "data_b64": base64.b64encode(previous).decode("ascii"),
                "sha256": hashlib.sha256(previous).hexdigest(),
                "bytes": len(previous),
            }
            for path, previous in backups.items()
            if previous is not None
        },
        "absent_before": sorted(
            _journal_relative(path) for path, previous in backups.items() if previous is None
        ),
        "after_sha256": {
            _journal_relative(path): digest for path, digest in after_digests.items()
        },
    }


def _write_transition_journal(journal: Dict[str, object]) -> None:
    TRANSITION_JOURNAL_PATH.parent.mkdir(parents=True, exist_ok=True)
    atomic_bytes(
        TRANSITION_JOURNAL_PATH,
        (json.dumps(journal, ensure_ascii=False, indent=2) + "\n").encode(),
    )
    _fsync_directory(TRANSITION_JOURNAL_PATH.parent)


def _discard_transition_journal() -> None:
    TRANSITION_JOURNAL_PATH.unlink(missing_ok=True)
    _fsync_directory(TRANSITION_JOURNAL_PATH.parent)


def _read_transition_journal() -> Optional[Dict[str, object]]:
    if not TRANSITION_JOURNAL_PATH.is_file() or TRANSITION_JOURNAL_PATH.is_symlink():
        return None
    try:
        journal = json.loads(TRANSITION_JOURNAL_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return journal if isinstance(journal, dict) else {}


def transition_journal_status() -> Optional[Dict[str, object]]:
    """Recovery info for an interrupted TASK/CONTEXT transition, or None.

    Every file touched by the transaction is classified against the journaled
    before/after digests: ``rolled_back`` and ``committed`` journals are stale
    and may be discarded, ``interrupted`` journals still hold the pre-commit
    bytes and are recoverable with ``restore_transition_journal``.
    """
    journal = _read_transition_journal()
    if journal is None:
        return None
    base = {
        "schema": TRANSITION_JOURNAL_STATUS_SCHEMA,
        "journal_path": str(TRANSITION_JOURNAL_PATH.relative_to(ROOT)),
    }
    backups = journal.get("backups")
    after_digests = journal.get("after_sha256")
    absent_before = journal.get("absent_before")
    if (
        journal.get("schema") != TRANSITION_JOURNAL_SCHEMA
        or not isinstance(backups, dict)
        or not isinstance(after_digests, dict)
        or not isinstance(absent_before, list)
    ):
        return {
            **base,
            "state": "malformed",
            "recovery": "inspect the journal manually, then run contextctl repair --reset or contextctl journal --discard",
        }
    context_relative = str(CONTEXT_PATH.relative_to(ROOT))

    def classify(relative: str, before_sha256: Optional[str]) -> Dict[str, object]:
        path = ROOT / relative
        current = (
            hashlib.sha256(path.read_bytes()).hexdigest()
            if path.is_file() and not path.is_symlink()
            else None
        )
        after = after_digests.get(relative)
        if current is not None and after is not None and current == after:
            state = "after"
        elif current == before_sha256:
            state = "before"
        elif current is None:
            state = "missing"
        else:
            state = "unknown"
        return {
            "path": relative,
            "state": state,
            "before_sha256": before_sha256,
            "after_sha256": after,
            "current_sha256": current,
        }

    files = [
        classify(relative, str(entry.get("sha256")) if isinstance(entry, dict) else None)
        for relative, entry in sorted(backups.items())
    ]
    files.extend(classify(relative, None) for relative in sorted(absent_before))
    states = {entry["state"] for entry in files}
    non_context = {entry["state"] for entry in files if entry["path"] != context_relative}
    context_state = next((entry["state"] for entry in files if entry["path"] == context_relative), None)
    if states <= {"before"}:
        overall = "rolled_back"
        recovery = "transition was rolled back; discard the stale journal with contextctl journal --discard"
    elif non_context <= {"after"} and context_state in {"after", "unknown", None}:
        # CONTEXT is committed by the contextctl subprocess, so its after
        # digest is unknowable in advance; a changed CONTEXT plus every other
        # target at its after digest means the crash hit after the commit.
        overall = "committed"
        recovery = "transition committed but its journal was not cleaned; discard it with contextctl journal --discard"
    else:
        overall = "interrupted"
        recovery = "restore pre-transition bytes with contextctl journal --restore, then rerun the mutator"
    return {
        **base,
        "state": overall,
        "mutator": journal.get("mutator"),
        "operation": journal.get("operation"),
        "reason": journal.get("reason"),
        "issued_at": journal.get("issued_at"),
        "files": files,
        "recovery": recovery,
    }


def restore_transition_journal() -> Dict[str, object]:
    """Roll an interrupted transition back to its journaled pre-commit bytes."""
    TASK_LOCK.parent.mkdir(parents=True, exist_ok=True)
    TASK_LOCK.touch(exist_ok=True)
    with TASK_LOCK.open("r+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        journal = _read_transition_journal()
        if journal is None:
            raise SystemExit("no context transition journal to restore")
        if journal.get("schema") != TRANSITION_JOURNAL_SCHEMA:
            raise SystemExit("context transition journal is malformed; restore manually or discard it")
        backups: Dict[Path, Optional[bytes]] = {}
        entries = journal.get("backups")
        if not isinstance(entries, dict):
            raise SystemExit("context transition journal is malformed; restore manually or discard it")
        for relative, entry in entries.items():
            path = (ROOT / str(relative)).resolve()
            try:
                path.relative_to(ROOT)
            except ValueError:
                raise SystemExit("context transition journal backup escapes the project")
            if not isinstance(entry, dict):
                raise SystemExit("context transition journal backup is malformed")
            try:
                data = base64.b64decode(str(entry.get("data_b64", "")))
            except (ValueError, TypeError):
                raise SystemExit("context transition journal backup is corrupt")
            if len(data) != entry.get("bytes") or hashlib.sha256(data).hexdigest() != entry.get("sha256"):
                raise SystemExit("context transition journal backup digest is corrupt")
            backups[path] = data
        absent_before = journal.get("absent_before")
        if not isinstance(absent_before, list):
            raise SystemExit("context transition journal is malformed; restore manually or discard it")
        for relative in absent_before:
            path = (ROOT / str(relative)).resolve()
            try:
                path.relative_to(ROOT)
            except ValueError:
                raise SystemExit("context transition journal backup escapes the project")
            backups[path] = None
        _restore_all(backups)
        _discard_transition_journal()
    return {
        "schema": TRANSITION_JOURNAL_STATUS_SCHEMA,
        "journal_path": str(TRANSITION_JOURNAL_PATH.relative_to(ROOT)),
        "state": "restored",
        "restored_files": sorted(str(path.relative_to(ROOT)) for path in backups),
        "recovery": "pre-transition bytes restored; rerun the mutator",
    }


def discard_transition_journal() -> None:
    """Remove a stale journal; an interrupted commit must be restored first."""
    status = transition_journal_status()
    if status is not None and status.get("state") == "interrupted":
        raise SystemExit(
            "transition journal shows an interrupted commit; run contextctl journal --restore before discarding"
        )
    _discard_transition_journal()


def transition_task(
    before: Dict[str, object],
    after: Dict[str, object],
    *,
    mutator: str,
    operation: str,
    reason: str,
    summary: str,
    source_tokens: Optional[int] = None,
    side_effects: Sequence[Tuple[Path, bytes]] = (),
    facts: Iterable[str] = (),
    files: Iterable[str] = (),
    evidence: Iterable[str] = (),
    risks: Iterable[str] = (),
    resolve_risks: Iterable[str] = (),
) -> None:
    """Commit TASK, side effects and CONTEXT as one rollback-safe transaction."""
    if not changed_fields(before, after):
        raise SystemExit("authorized task transition requires at least one invariant field change")
    TASK_LOCK.parent.mkdir(parents=True, exist_ok=True)
    TASK_LOCK.touch(exist_ok=True)
    with TASK_LOCK.open("r+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        observed = json.loads(TASK_PATH.read_text(encoding="utf-8"))
        if canonical(observed) != canonical(before):
            raise SystemExit("canonical TASK changed before the authorized transaction acquired its lock")
        try:
            previous_context = contextctl.load_json(CONTEXT_PATH)
        except (OSError, ValueError, SystemExit, json.JSONDecodeError) as error:
            raise SystemExit(f"verified context is required before a canonical TASK transition: {error}")
        effective_source_tokens = contextctl.automatic_transition_source_tokens(
            contextctl.load_json(contextctl.CONFIG_PATH), previous_context, after, source_tokens
        )
        backups = {
            TASK_PATH: TASK_PATH.read_bytes(),
            CONTEXT_PATH: CONTEXT_PATH.read_bytes() if CONTEXT_PATH.is_file() else None,
        }
        for path, _ in side_effects:
            backups[path] = path.read_bytes() if path.is_file() else None
        after_payload = json.dumps(after, ensure_ascii=False, indent=2).encode() + b"\n"
        after_digests: Dict[Path, Optional[str]] = {
            TASK_PATH: hashlib.sha256(after_payload).hexdigest(),
            # CONTEXT is committed by the contextctl subprocess; its after
            # digest cannot be known before the transition runs.
            CONTEXT_PATH: None,
        }
        for path, data in side_effects:
            after_digests[path] = hashlib.sha256(data).hexdigest()
        # Crash journal: if this process dies between the TASK and CONTEXT
        # commits, the journaled pre-commit bytes drive a deterministic
        # rollback instead of a manual repair.
        _write_transition_journal(_transition_journal(backups, after_digests, mutator, operation, reason))
        authorization: Optional[Path] = None
        try:
            for path, data in side_effects:
                atomic_bytes(path, data)
            atomic_bytes(TASK_PATH, after_payload)
            authorization, _ = _authorization(before, after, mutator, operation, reason)
            command = [
                sys.executable,
                str(CONTEXT_TOOL),
                "sync",
                "--transition",
                "--from-task-sha256",
                contextctl.invariant_sha256(before),
                "--authorization",
                str(authorization.relative_to(ROOT)),
                "--reason",
                reason,
                "--summary",
                summary,
                "--source-tokens",
                str(effective_source_tokens),
                "--source",
                f"mutator:{mutator}",
            ]
            for flag, values in (
                ("--fact", facts), ("--file", files), ("--evidence", evidence),
                ("--risk", risks), ("--resolve-risk", resolve_risks),
            ):
                for value in values:
                    command.extend([flag, str(value)])
            result = subprocess.run(command, cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if result.returncode:
                raise RuntimeError(result.stdout.strip() or "authorized context transition failed")
        except BaseException as error:
            _restore_all(backups)
            _discard_transition_journal()
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise SystemExit(f"TASK/context transaction rolled back: {error}")
        else:
            _discard_transition_journal()
        finally:
            if authorization is not None:
                authorization.unlink(missing_ok=True)
