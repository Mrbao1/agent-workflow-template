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
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import contextctl
from workflowlib import boundedio,boundedprocess


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
    try: boundedio.atomic_write(path,data,mode=0o600,label="context transaction state")
    except RuntimeError as error: raise SystemExit(str(error)) from error


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def changed_fields(before: Dict[str, object], after: Dict[str, object]) -> list[str]:
    old = contextctl.task_invariant(before)
    new = contextctl.task_invariant(after)
    return sorted(key for key in contextctl.TASK_INVARIANT_KEYS if old.get(key) != new.get(key))


def _authorization(
    before: Dict[str, object], after: Dict[str, object], mutator: str, operation: str, reason: str
) -> Tuple[Path, str]:
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
    data=json.dumps(value,ensure_ascii=False,indent=2).encode()+b"\n"
    try: path=boundedio.create_private_file(AUTH_DIR,data,prefix="context-transition-",suffix=".json",mode=0o600,label="context authorization")
    except RuntimeError as error: raise SystemExit(str(error)) from error
    return path,hashlib.sha256(data).hexdigest()


def _fsync_directory(path: Path) -> None:
    try: descriptor=boundedio.private_directory_fd(path,"context transaction directory",False)
    except RuntimeError as error: raise SystemExit(str(error)) from error
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def _fsync_parents(paths: Iterable[Path]) -> None:
    for parent in dict.fromkeys(path.parent for path in paths):
        _fsync_directory(parent)


def _restore_all(backups: Dict[Path, Optional[bytes]]) -> None:
    """Roll back through no-follow atomic writes; the journal survives interruption."""
    for path,previous in backups.items():
        try:
            if previous is None: boundedio.unlink_private(path,missing_ok=True,label="context transaction rollback")
            else: boundedio.atomic_write(path,previous,mode=0o600,label="context transaction rollback")
        except RuntimeError as error: raise SystemExit(str(error)) from error
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
    atomic_bytes(
        TRANSITION_JOURNAL_PATH,
        (json.dumps(journal, ensure_ascii=False, indent=2) + "\n").encode(),
    )
    _fsync_directory(TRANSITION_JOURNAL_PATH.parent)


def _discard_transition_journal() -> None:
    try: boundedio.unlink_private(TRANSITION_JOURNAL_PATH,missing_ok=True,label="context transition journal")
    except RuntimeError as error: raise SystemExit(str(error)) from error
    _fsync_directory(TRANSITION_JOURNAL_PATH.parent)


def _read_transition_journal() -> Optional[Dict[str, object]]:
    if not TRANSITION_JOURNAL_PATH.is_file() or TRANSITION_JOURNAL_PATH.is_symlink():
        return None
    try:
        journal = json.loads(boundedio.read_text(TRANSITION_JOURNAL_PATH,label="context transition journal"))
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
            hashlib.sha256(boundedio.read_bytes(path,label="context transaction file")).hexdigest()
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
    try: lock_handle=boundedio.open_private_lock(TASK_LOCK,label="task transition lock")
    except RuntimeError as error: raise SystemExit(str(error)) from error
    with lock_handle as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        # Restore is only safe for a genuinely interrupted transition: a stale
        # "committed" or "rolled_back" journal (crash between commit and
        # journal cleanup) would silently revert valid current state. Mirror
        # the discard guard and refuse, naming the actual state and the safe
        # command.
        status = transition_journal_status()
        if status is None:
            raise SystemExit("no context transition journal to restore")
        state = str(status.get("state", ""))
        if state == "malformed":
            raise SystemExit("context transition journal is malformed; restore manually or discard it")
        if state != "interrupted":
            raise SystemExit(
                f"transition journal shows a {state} transition, not an interrupted one; "
                "restore would revert valid state — run contextctl journal --discard instead"
            )
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
    try: lock_handle=boundedio.open_private_lock(TASK_LOCK,label="task transition lock")
    except RuntimeError as error: raise SystemExit(str(error)) from error
    with lock_handle as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        observed = json.loads(boundedio.read_text(TASK_PATH,label="task state"))
        if canonical(observed) != canonical(before):
            raise SystemExit("canonical TASK changed before the authorized transaction acquired its lock")
        try:
            previous_context = contextctl.load_json(CONTEXT_PATH)
        except (OSError, ValueError, SystemExit, json.JSONDecodeError) as error:
            raise SystemExit(f"verified context is required before a canonical TASK transition: {error}")
        effective_source_tokens = contextctl.automatic_transition_source_tokens(
            contextctl.load_json(contextctl.CONFIG_PATH), previous_context, after, source_tokens
        )
        # A loaded reference is a separate reservation only while it remains
        # reusable. Removing it from TASK (explicit unload or new-task reset)
        # does not remove its bytes from the active provider window. Settle the
        # released reservation into the monotonic active-window estimate so the
        # unified total cannot decrease without verified host compaction.
        def reference_tokens(value: Dict[str, object]) -> int:
            references = value.get("loaded_references")
            return sum(
                max(0, int(item.get("estimated_tokens", 0)))
                for item in references
                if isinstance(references, list) and isinstance(item, dict)
            ) if isinstance(references, list) else 0

        released_reference_tokens = max(
            0, reference_tokens(before) - reference_tokens(after)
        )
        effective_source_tokens += released_reference_tokens
        backups = {
            TASK_PATH: boundedio.read_bytes(TASK_PATH,label="task state"),
            CONTEXT_PATH: boundedio.read_bytes(CONTEXT_PATH,label="context state") if CONTEXT_PATH.is_file() else None,
        }
        for path, _ in side_effects:
            backups[path] = boundedio.read_bytes(path,label="context transaction file") if path.is_file() else None
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
            try:
                result = boundedprocess.run(
                    command, cwd=str(ROOT), text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
                )
            except subprocess.TimeoutExpired as error:
                raise RuntimeError(
                    "authorized context transition timed out after "
                    f"{int(error.timeout or 120)}s"
                ) from error
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
                try: boundedio.unlink_private(authorization,missing_ok=True,label="context authorization")
                except RuntimeError as error: raise SystemExit(str(error)) from error
