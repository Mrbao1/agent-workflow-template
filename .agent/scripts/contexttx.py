#!/usr/bin/env python3
"""Atomically commit canonical TASK changes with an authorized context transition."""

from pathlib import Path
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
from typing import Dict, Iterable, Optional, Sequence, Tuple

import contextctl


AGENT_DIR = contextctl.AGENT_DIR
ROOT = contextctl.ROOT
TASK_PATH = contextctl.TASK_PATH
CONTEXT_PATH = contextctl.CONTEXT_PATH
CONTEXT_TOOL = AGENT_DIR / "scripts" / "contextctl.py"
TASK_LOCK = AGENT_DIR / "state" / ".task.lock"
AUTH_DIR = AGENT_DIR / "state" / ".context-authorizations"


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


def _restore(path: Path, previous: Optional[bytes]) -> None:
    if previous is None:
        path.unlink(missing_ok=True)
    else:
        atomic_bytes(path, previous)


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
        authorization: Optional[Path] = None
        try:
            for path, data in side_effects:
                atomic_bytes(path, data)
            atomic_bytes(TASK_PATH, json.dumps(after, ensure_ascii=False, indent=2).encode() + b"\n")
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
            for path, previous in backups.items():
                _restore(path, previous)
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise SystemExit(f"TASK/context transaction rolled back: {error}")
        finally:
            if authorization is not None:
                authorization.unlink(missing_ok=True)
