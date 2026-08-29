#!/usr/bin/env python3
"""Small deterministic controller for task state, routing, and local cleanup."""

from pathlib import Path
import argparse
import base64
import copy
from contextlib import contextmanager
import ctypes
import datetime as dt
import errno
import fcntl
import fnmatch
import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Sequence, Tuple

sys.dont_write_bytecode = True

import contexttx
import humandecision
from process_observation import ProcessObservationError,linux_signal_identity
from workflowlib import boundedio
from workflowlib import budget as total_budget
from workflowlib import state as workflow_state

try:
    import deliveryctl
except ImportError:  # adversarial test fixtures may ship a script subset
    deliveryctl = None
try:
    import skillctl
except ImportError:
    skillctl=None
try:
    import evidencectl
except ImportError:
    evidencectl = None
try:
    import workflowctl as workflow_validator
except ImportError:
    workflow_validator = None


MAX_CONTROL_COMMAND_OUTPUT_BYTES=1024*1024
MAX_DOCKER_CONTROL_OUTPUT_BYTES=64*1024


def run_bounded_trusted_observer(command,*,env=None,timeout=5,output_limit=64*1024):
    """Bound output from one OS-protected observer without recursive observation."""
    process=subprocess.Popen(list(command),env=None if env is None else dict(env),stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True,bufsize=0)
    if process.stdout is None: raise OSError("trusted observer output pipe is unavailable")
    selector=selectors.DefaultSelector(); selector.register(process.stdout,selectors.EVENT_READ); data=bytearray(); deadline=time.monotonic()+timeout
    try:
        reached_eof=False
        while not reached_eof:
            remaining=deadline-time.monotonic()
            if remaining<=0: raise subprocess.TimeoutExpired(command,timeout,output=bytes(data))
            events=selector.select(remaining)
            if not events: raise subprocess.TimeoutExpired(command,timeout,output=bytes(data))
            for key,_mask in events:
                chunk=os.read(key.fileobj.fileno(),65536)
                if not chunk: reached_eof=True; break
                if len(data)+len(chunk)>output_limit: raise OSError(f"trusted observer exceeded {output_limit} output bytes")
                data.extend(chunk)
        completed=subprocess.CompletedProcess(list(command),process.wait(timeout=2),data.decode("utf-8",errors="replace"),None)
        completed.captured_observer_pid=process.pid
        return completed
    except BaseException:
        try:
            if process.returncode is None: process.kill()
            process.wait(timeout=2)
        except (OSError,subprocess.TimeoutExpired): pass
        raise
    finally:
        selector.close(); process.stdout.close()


def run_bounded_command(command,*,cwd=None,env=None,timeout=120,output_limit=MAX_CONTROL_COMMAND_OUTPUT_BYTES,stderr_to_stdout=True):
    """Run an owned command with bounded bytes and exact launch-scoped cleanup."""
    try: import testrun as bounded_supervisor
    except ImportError as error: raise OSError("bounded command supervisor is unavailable") from error
    launch_token=secrets.token_hex(16); launch_environment=dict(os.environ if env is None else env)
    launch_environment[bounded_supervisor.LAUNCH_TOKEN_NAME]=launch_token
    with bounded_supervisor.child_subreaper() as supported:
        if not supported: raise OSError("bounded command subreaper/pidfd support is unavailable")
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            raise OSError("bounded command requires default SIGCHLD ownership")
        process=subprocess.Popen(
            list(command),cwd=None if cwd is None else str(cwd),env=launch_environment,
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if stderr_to_stdout else subprocess.DEVNULL,
            start_new_session=True,close_fds=True,bufsize=0,
        )
        result=bounded_supervisor.supervise_bounded_process(
            process,timeout=timeout,launch_token=launch_token,output_limit=output_limit,grace=5.0,
        )
    output=result["output"].decode("utf-8",errors="replace")
    if result["timed_out"]:
        raise subprocess.TimeoutExpired(command,timeout,output=output)
    if result["output_limit_exceeded"]:
        raise OSError(f"bounded command exceeded {output_limit} output bytes")
    if result["uncertain"] or result["residual_descendants"] or not result["cleanup_ok"]:
        raise OSError("bounded command cleanup identity is uncertain")
    return subprocess.CompletedProcess(list(command),int(result["exit_code"]),output,None)


def find_agent_dir() -> Path:
    current = Path.cwd().resolve()
    for root in (current, *current.parents):
        candidate = root / ".agent"
        if candidate.is_dir():
            return candidate
    raise SystemExit(".agent directory not found")


AGENT_DIR = find_agent_dir()
CONFIG_PATH = AGENT_DIR / "config.json"
TASK_PATH = AGENT_DIR / "state" / "TASK.json"
RUNTIME_PATH = AGENT_DIR / "state" / "runtime.json"
TOOL_LEASES_PATH = AGENT_DIR / "state" / "tool-leases.json"
AGENTS_PATH = AGENT_DIR / "state" / "agents.json"
AGENTS_LOCK_PATH = AGENT_DIR / "state" / ".agents.lock"
AGENTS_CHAIN_JOURNAL_PATH = AGENT_DIR / "state" / "agents-chain.jsonl"
STAGE_PATH = AGENT_DIR / "state" / "STAGE_INDEX.md"
CONTRACT_PATH = AGENT_DIR / "state" / "REQUIREMENT_CONTRACT.md"
PROJECT_INIT_LOCK_PATH = AGENT_DIR / "state" / ".project-init.lock"
PROJECT_INIT_JOURNAL_PATH = AGENT_DIR / "state" / ".project-init-transaction.json"
TASK_LOCK_PATH = AGENT_DIR / "state" / ".task.lock"
CONTEXT_LOCK_PATH = AGENT_DIR / "state" / ".context.lock"
CONTEXT_TOOL = AGENT_DIR / "scripts" / "contextctl.py"
EVIDENCE_TOOL = AGENT_DIR / "scripts" / "evidencectl.py"
EVIDENCE_INDEX_PATH = AGENT_DIR / "state" / "EVIDENCE_INDEX.json"
TASK_ARCHIVE_DIR = AGENT_DIR / "state" / "evidence" / "task-archives"
AGENT_LEDGER_TOOL = AGENT_DIR / "skills" / "manage-agent-team" / "scripts" / "agentledger.py"
CONTEXT_PATH = AGENT_DIR / "state" / "CONTEXT.json"
TEST_BUDGET_PATH = AGENT_DIR / "state" / "test-budget.json"
SKILL_ACTIVATION_PATH=AGENT_DIR/"state"/"SKILL_ACTIVATION.json"
RUNTIME_LOCK_PATH = AGENT_DIR / "state" / ".runtime.lock"
TOOL_LEASES_LOCK_PATH = AGENT_DIR / "state" / ".tool-leases.lock"
DELIVERY_PATH = AGENT_DIR / "state" / "delivery.json"
KNOWLEDGE_PENDING_PATH = AGENT_DIR / "state" / "knowledge-pending.json"
KNOWLEDGE_PROMOTION_LOCK_PATH = AGENT_DIR / "state" / ".knowledge-promotion.lock"
KNOWLEDGE_PROMOTION_JOURNAL_PATH = AGENT_DIR / "state" / ".knowledge-promotion-transaction.json"
KNOWLEDGE_PROMOTED_RULES_PATH = AGENT_DIR / "knowledge" / "promoted-rules.md"
KNOWLEDGE_PROMOTED_CAPABILITIES_PATH = AGENT_DIR / "knowledge" / "promoted-capabilities.md"
KNOWLEDGE_INDEX_PATH = AGENT_DIR / "knowledge" / "INDEX.md"
CAPABILITIES_INDEX_PATH = AGENT_DIR / "capabilities" / "INDEX.md"
CONTEXT_AUTH_DIR = AGENT_DIR / "state" / ".context-authorizations"
CONTEXT_AUTHORIZATION_TTL_SECONDS = 60
TASK_ARCHIVE_HEAD_FIELDS = {"schema", "path", "sha256", "bytes", "total_archives"}
TASK_ARCHIVE_PAYLOAD_SCHEMAS = {"agent-task-archive/v1", "agent-task-archive/v2"}
CONTRACT_FIELDS = (
    "Goal", "Users", "Success", "In scope", "Out of scope", "Constraints",
    "Data and permissions", "Target environment", "Acceptance", "Provenance",
    "Production provider target", "Human decisions", "Clarified",
)
PRODUCTION_PROVIDER_TARGET_FIELDS = {
    "schema", "provider", "repository", "default_branch", "test_environment",
    "production_environment", "required_status_checks", "min_required_reviewers",
}
USAGE_OBSERVER_POLICY = {
    "source": "host-session-usage",
    "automatic_gate_trust": False,
    "provider_verification_required": True,
    "signed_adapter": None,
    "max_receipt_age_seconds": 300,
}
PROVIDER_PREFLIGHT_OBSERVER_POLICY = {
    "source": "provider-read-only-api",
    "automatic_release_trust": False,
    "provider_verification_required": True,
    "signed_adapter": None,
    "max_receipt_age_seconds": 300,
}


def nonnegative_int(raw: str) -> int:
    value = int(raw)
    if value < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return value


def load_json(path: Path) -> Dict[str, object]:
    value = json.loads(boundedio.read_text(path,label="agent JSON"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON object required: {path}")
    return value


def save_json(path: Path, value: Dict[str, object]) -> None:
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def atomic_write(path: Path, text: str) -> None:
    try: boundedio.atomic_write(path,text.encode("utf-8"),mode=0o600,label="agent state")
    except RuntimeError as error: raise SystemExit(str(error)) from error


def _fsync_directory(path: Path) -> None:
    try: descriptor=boundedio.private_directory_fd(path,"agent state",False)
    except RuntimeError as error: raise SystemExit(str(error)) from error
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def agents_chain_advance(ledger: Dict[str, object]) -> bytes:
    """Advance the agent ledger append hash chain; return the exact bytes to commit.

    Mirrors `chain_upgrade`/`save` in
    `.agent/skills/manage-agent-team/scripts/agentledger.py` — the source of
    truth, owned by another workstream and not importable from every reduced
    agentctl harness (it pulls the full skill script set).  Every agents.json
    rewrite that bypasses `agentledger.py save` must advance the chain
    identically, or the next `agentledger.py validate` fails closed on a
    stale append-chain tip.
    """
    previous = boundedio.read_bytes(AGENTS_PATH,label="AGENTS bootstrap") if AGENTS_PATH.is_file() else None
    revision = ledger.get("revision")
    if revision is None:
        ledger["revision"] = 1
        ledger["prev_sha256"] = None
    else:
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise SystemExit("agent ledger chain revision is invalid")
        if previous is None:
            raise SystemExit("agent ledger chain continuity is lost: state file is missing")
        ledger["revision"] = revision + 1
        ledger["prev_sha256"] = hashlib.sha256(previous).hexdigest()
    return (json.dumps(ledger, ensure_ascii=False, indent=2) + "\n").encode()


def agents_chain_journal_append(ledger: Dict[str, object], data: bytes) -> None:
    """Append the chain tip exactly like agentledger.chain_journal_append.

    Call only AFTER the transaction committing `data` to agents.json has
    finished, so a rolled-back transition never leaves a dangling tip.
    """
    entry = {
        "revision": ledger["revision"], "prev_sha256": ledger["prev_sha256"],
        "file_sha256": hashlib.sha256(data).hexdigest(),
    }
    data=(json.dumps(entry,sort_keys=True,separators=(",",":"))+"\n").encode("utf-8")
    try: boundedio.append_private(AGENTS_CHAIN_JOURNAL_PATH,data,mode=0o600,label="agent chain journal")
    except RuntimeError as error: raise SystemExit(str(error)) from error


@contextmanager
def locked_model_authority():
    """Serialize config/ledger model authority before any TASK/context locks."""
    try:
        project_handle=boundedio.open_private_lock(PROJECT_INIT_LOCK_PATH,label="project initialization lock")
        agents_handle=boundedio.open_private_lock(AGENTS_LOCK_PATH,label="agent ledger lock")
    except RuntimeError as error: raise SystemExit(str(error)) from error
    with project_handle as project_lock:
        fcntl.flock(project_lock.fileno(),fcntl.LOCK_EX)
        with agents_handle as agents_lock:
            fcntl.flock(agents_lock.fileno(),fcntl.LOCK_EX)
            yield


@contextmanager
def locked_project_init():
    """Exclusive model barrier, then canonical Agent/TASK/context locks."""
    with locked_model_authority():
        try:
            task_handle=boundedio.open_private_lock(TASK_LOCK_PATH,label="task transition lock")
            context_handle=boundedio.open_private_lock(CONTEXT_LOCK_PATH,label="context capsule lock")
        except RuntimeError as error: raise SystemExit(str(error)) from error
        with task_handle as task_lock:
            fcntl.flock(task_lock.fileno(),fcntl.LOCK_EX)
            with context_handle as context_lock:
                fcntl.flock(context_lock.fileno(),fcntl.LOCK_EX)
                yield


def _project_init_targets() -> Dict[str, Path]:
    return {
        str(path.relative_to(AGENT_DIR.parent)): path
        for path in (CONFIG_PATH, AGENT_DIR / "policies/PROJECT_GUARDRAILS.md", AGENTS_PATH, CONTEXT_PATH)
    }


def _fsync_target_parents(paths: Sequence[Path]) -> None:
    for parent in sorted({path.parent for path in paths}, key=str):
        _fsync_directory(parent)


def _read_project_regular_file_no_links(root: Path, relative: Path, limit: int) -> bytes:
    """Open every component relative to a stable root descriptor, no links."""
    if not relative.parts:
        raise SystemExit("guardrails file is missing or unsafe")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptors: List[int] = []
    try:
        current = os.open(str(root), directory_flags)
        descriptors.append(current)
        for component in relative.parts[:-1]:
            current = os.open(component, directory_flags, dir_fd=current)
            descriptors.append(current)
        descriptor = os.open(relative.parts[-1], file_flags, dir_fd=current)
        descriptors.append(descriptor)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise SystemExit("guardrails file is missing or unsafe")
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            return handle.read(limit + 1)
    except OSError:
        raise SystemExit("guardrails file is missing or unsafe")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _project_init_backup_payloads(journal: Dict[str, object], targets: Dict[str, Path]) -> Dict[Path, bytes]:
    backups = journal.get("backups")
    if not isinstance(backups, dict) or set(backups) != set(targets):
        raise SystemExit("project-init recovery backup set is invalid")
    decoded: Dict[Path, bytes] = {}
    for relative, path in targets.items():
        record = backups.get(relative)
        if not isinstance(record, dict) or set(record) != {"data_b64", "sha256", "bytes"}:
            raise SystemExit("project-init recovery backup record is invalid")
        encoded = record.get("data_b64")
        digest = record.get("sha256")
        length = record.get("bytes")
        if not isinstance(encoded, str) or not isinstance(digest, str) or not isinstance(length, int):
            raise SystemExit("project-init recovery backup record is invalid")
        try:
            data = base64.b64decode(encoded, validate=True)
            data.decode("utf-8")
        except (ValueError, TypeError, UnicodeError):
            raise SystemExit("project-init recovery backup is corrupt")
        if len(data) != length or hashlib.sha256(data).hexdigest() != digest:
            raise SystemExit("project-init recovery backup digest is corrupt")
        if path in {CONFIG_PATH, CONTEXT_PATH}:
            try: parsed = json.loads(data)
            except (UnicodeError, json.JSONDecodeError):
                raise SystemExit("project-init recovery JSON backup is corrupt")
            if not isinstance(parsed, dict):
                raise SystemExit("project-init recovery JSON backup is corrupt")
        decoded[path] = data
    return decoded


def recover_project_init_transaction() -> None:
    """Recover a killed three-file initialization before any Agent command."""
    with locked_project_init():
        if not PROJECT_INIT_JOURNAL_PATH.is_file():
            return
        journal = load_json(PROJECT_INIT_JOURNAL_PATH)
        if journal.get("schema") != "agent-project-init-transaction/v1" or journal.get("phase") not in {"prepared", "committed"}:
            raise SystemExit("project-init transaction journal is malformed")
        if set(journal) != {"schema", "phase", "backups", "committed_sha256"}:
            raise SystemExit("project-init transaction journal is malformed")
        targets = _project_init_targets()
        if journal.get("phase") == "committed":
            committed = journal.get("committed_sha256")
            if (
                not isinstance(committed, dict) or set(committed) != set(targets)
                or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in committed.values())
            ):
                raise SystemExit("project-init committed journal is malformed")
            if not all(
                path.is_file() and committed[relative] == hashlib.sha256(boundedio.read_bytes(path,label="agent file")).hexdigest()
                for relative, path in targets.items()
            ):
                raise SystemExit("committed project-init targets drifted; journal retained for review")
        else:
            backups = _project_init_backup_payloads(journal, targets)
            for path, data in backups.items():
                atomic_write(path, data.decode("utf-8"))
            _fsync_target_parents(list(backups))
        PROJECT_INIT_JOURNAL_PATH.unlink()
        _fsync_directory(PROJECT_INIT_JOURNAL_PATH.parent)

def _promotion_relative(path: Path) -> Tuple[str, ...]:
    try:
        relative=path.relative_to(AGENT_DIR)
    except ValueError as error:
        raise SystemExit("knowledge promotion target escapes .agent") from error
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise SystemExit("knowledge promotion target path is invalid")
    return relative.parts


def _promotion_validate_directory(descriptor: int,label: str) -> None:
    observed=os.fstat(descriptor); expected_uid=os.geteuid() if hasattr(os,"geteuid") else observed.st_uid
    if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid!=expected_uid or stat.S_IMODE(observed.st_mode)&0o022):
        raise SystemExit(f"{label} is not an owner-controlled non-writable real directory")


def _promotion_open_parent(path: Path) -> Tuple[int, str]:
    """Open one trusted parent chain; integrity isolation, not hostile-code confinement."""
    if not hasattr(os,"O_NOFOLLOW") or not hasattr(os,"O_DIRECTORY"):
        raise SystemExit("knowledge promotion requires descriptor-relative no-follow support")
    parts=_promotion_relative(path)
    current=os.open(str(AGENT_DIR),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        _promotion_validate_directory(current,".agent promotion root")
        for part in parts[:-1]:
            following=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current)
            os.close(current); current=following
            _promotion_validate_directory(current,"knowledge promotion parent")
        return current,parts[-1]
    except BaseException:
        os.close(current); raise


def _assert_safe_promotion_path(path: Path) -> None:
    parent,_name=_promotion_open_parent(path); os.close(parent)


def promotion_snapshot(path:Path,label:str,maximum=2*1024*1024):
    parent,name=_promotion_open_parent(path)
    try:
        try: before=os.stat(name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError: return None
        expected_uid=os.geteuid() if hasattr(os,"geteuid") else before.st_uid
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=expected_uid
                or stat.S_IMODE(before.st_mode)&0o022 or before.st_size<0 or before.st_size>maximum):
            raise SystemExit(f"{label} is not one bounded owner-controlled regular file")
        descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            opened=os.fstat(descriptor); chunks=[]; total=0
            while total<=maximum:
                chunk=os.read(descriptor,min(65536,maximum+1-total))
                if not chunk: break
                chunks.append(chunk); total+=len(chunk)
            after=os.fstat(descriptor)
        finally: os.close(descriptor)
    finally: os.close(parent)
    data=b"".join(chunks)
    identity=lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns,item.st_mode,item.st_uid,item.st_nlink)
    if total>maximum or identity(before)!=identity(opened) or identity(opened)!=identity(after) or total!=opened.st_size:
        raise SystemExit(f"{label} changed during bounded snapshot")
    return {"bytes":data,"identity":identity(opened),"sha256":hashlib.sha256(data).hexdigest()}


def require_promotion_snapshot(path,snapshot,label):
    current=promotion_snapshot(path,label)
    if snapshot is None:
        if current is not None: raise SystemExit(f"{label} appeared after planning")
    elif current is None or current["identity"]!=snapshot["identity"] or current["bytes"]!=snapshot["bytes"]:
        raise SystemExit(f"{label} changed after planning")


def _promotion_atomic_write(path:Path,data:bytes) -> None:
    parent,name=_promotion_open_parent(path); temporary=None; descriptor=-1
    try:
        for _attempt in range(64):
            temporary=f".{name}.{secrets.token_hex(16)}"
            try:
                descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent); break
            except FileExistsError: continue
        if descriptor<0: raise SystemExit("knowledge promotion could not allocate a private temporary file")
        view=memoryview(data)
        while view:
            written=os.write(descriptor,view)
            if written<=0: raise SystemExit("knowledge promotion temporary write made no progress")
            view=view[written:]
        os.fsync(descriptor); os.close(descriptor); descriptor=-1
        os.rename(temporary,name,src_dir_fd=parent,dst_dir_fd=parent); temporary=None; os.fsync(parent)
    finally:
        if descriptor>=0: os.close(descriptor)
        if temporary is not None:
            try: os.unlink(temporary,dir_fd=parent)
            except FileNotFoundError: pass
        os.close(parent)


def _promotion_unlink(path:Path,expected=None) -> None:
    parent,name=_promotion_open_parent(path)
    try:
        if expected is not None:
            descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
            try:
                opened=os.fstat(descriptor); chunks=[]
                while True:
                    chunk=os.read(descriptor,65536)
                    if not chunk: break
                    chunks.append(chunk)
            finally: os.close(descriptor)
            current=os.stat(name,dir_fd=parent,follow_symlinks=False)
            if ((current.st_dev,current.st_ino)!=(opened.st_dev,opened.st_ino)
                    or hashlib.sha256(b"".join(chunks)).hexdigest()!=expected["sha256"]):
                raise SystemExit("knowledge promotion unlink target changed before deletion")
        os.unlink(name,dir_fd=parent); os.fsync(parent)
    finally: os.close(parent)


@contextmanager
def locked_knowledge_promotion():
    parent,name=_promotion_open_parent(KNOWLEDGE_PROMOTION_LOCK_PATH); descriptor=-1
    try:
        descriptor=os.open(name,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=parent)
        observed=os.fstat(descriptor); expected_uid=os.geteuid() if hasattr(os,"geteuid") else observed.st_uid
        if (not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1 or observed.st_uid!=expected_uid
                or stat.S_IMODE(observed.st_mode)&0o022):
            raise SystemExit("knowledge promotion lock has unsafe topology")
        fcntl.flock(descriptor,fcntl.LOCK_EX); yield
    finally:
        if descriptor>=0: os.close(descriptor)
        os.close(parent)


def _promotion_target(relative: str) -> Path:
    path=Path(relative)
    if path.is_absolute() or any(part in {"",".",".."} for part in path.parts): raise SystemExit("knowledge promotion target path is invalid")
    normalized=path.as_posix(); pending=KNOWLEDGE_PENDING_PATH.relative_to(AGENT_DIR.parent).as_posix(); prefix=".agent/project/knowledge/"
    if normalized!=pending and (not normalized.startswith(prefix) or normalized==prefix): raise SystemExit("knowledge promotion target is outside the project knowledge registry")
    target=AGENT_DIR.parent/path; _assert_safe_promotion_path(target); return target

def _promotion_json(path:Path,label:str,maximum=2*1024*1024):
    snapshot=promotion_snapshot(path,label,maximum)
    if snapshot is None: raise SystemExit(f"{label} is missing")
    try: value=json.loads(snapshot["bytes"])
    except (UnicodeError,json.JSONDecodeError) as error: raise SystemExit(f"{label} is malformed") from error
    if not isinstance(value,dict): raise SystemExit(f"{label} must be a JSON object")
    return value,snapshot


def _require_promotion_completion(task,current):
    if workflow_validator is None: raise SystemExit("canonical workflow validator is unavailable for knowledge promotion")
    archive_errors=workflow_validator.task_archive_errors(current)
    if archive_errors: raise SystemExit("knowledge candidate task archive authority is invalid: "+"; ".join(archive_errors))
    if not workflow_validator.completion_checkpoint_valid(task):
        raise SystemExit("knowledge candidate accepted task lacks a valid completion checkpoint")
    return task


def _promotion_task_from_archive(entry:Dict[str,object]) -> Dict[str,object]:
    current,_snapshot=_promotion_json(TASK_PATH,"current task",4*1024*1024)
    generation=entry.get("task_generation_id")
    if current.get("status")=="accepted" and current.get("task_generation_id")==generation:
        return _require_promotion_completion(current,current)
    head=current.get("task_archive"); seen=set(); matches=[]; expected_total=head.get("total_archives") if isinstance(head,dict) else 0
    if not isinstance(expected_total,int) or isinstance(expected_total,bool) or expected_total<1 or expected_total>256: raise SystemExit("knowledge candidate task archive length is invalid or unbounded")
    while head is not None:
        if (not isinstance(head,dict) or set(head)!=TASK_ARCHIVE_HEAD_FIELDS or head.get("schema")!="agent-task-archive-head/v1"
                or re.fullmatch(r"[0-9a-f]{64}",str(head.get("sha256",""))) is None
                or not isinstance(head.get("bytes"),int) or isinstance(head.get("bytes"),bool) or head["bytes"]<1
                or not isinstance(head.get("total_archives"),int) or isinstance(head.get("total_archives"),bool) or head["total_archives"]<1):
            raise SystemExit("knowledge candidate task archive head is invalid")
        if head["total_archives"]!=expected_total: raise SystemExit("knowledge candidate task archive count drifted")
        digest=str(head["sha256"])
        if digest in seen: raise SystemExit("knowledge candidate task archive chain repeats")
        seen.add(digest); relative=f".agent/state/evidence/task-archives/{digest}.json"
        if head.get("path")!=relative: raise SystemExit("knowledge candidate task archive path is invalid")
        payload_path=AGENT_DIR.parent/relative; payload_snapshot=promotion_snapshot(payload_path,"knowledge candidate task archive",16*1024*1024)
        if payload_snapshot is None or len(payload_snapshot["bytes"])!=head["bytes"] or payload_snapshot["sha256"]!=digest:
            raise SystemExit("knowledge candidate task archive bytes drifted")
        try: payload=json.loads(payload_snapshot["bytes"])
        except (UnicodeError,json.JSONDecodeError) as error: raise SystemExit("knowledge candidate task archive is malformed") from error
        if not isinstance(payload,dict) or payload.get("schema") not in TASK_ARCHIVE_PAYLOAD_SCHEMAS:
            raise SystemExit("knowledge candidate task archive schema is invalid")
        task_record=payload.get("task")
        if not isinstance(task_record,dict) or set(task_record)!={"sha256","bytes","utf8"}:
            raise SystemExit("knowledge candidate task archive record is invalid")
        encoded=task_record.get("utf8")
        if not isinstance(encoded,str): raise SystemExit("knowledge candidate archived task is invalid")
        raw=encoded.encode("utf-8")
        if (len(raw)!=task_record.get("bytes") or hashlib.sha256(raw).hexdigest()!=task_record.get("sha256")):
            raise SystemExit("knowledge candidate archived task bytes drifted")
        try: archived=json.loads(raw)
        except json.JSONDecodeError as error: raise SystemExit("knowledge candidate archived task is malformed") from error
        if isinstance(archived,dict) and archived.get("status")=="accepted" and archived.get("task_generation_id")==generation:
            matches.append(archived)
        head=payload.get("previous"); expected_total-=1
    if expected_total!=0 or len(seen)>256: raise SystemExit("knowledge candidate task archive length is inconsistent")
    if len(matches)!=1: raise SystemExit("knowledge candidate exact accepted task generation is missing or ambiguous")
    return _require_promotion_completion(matches[0],current)


def _project_regular_snapshot(relative_raw,label,maximum=16*1024*1024):
    relative=Path(str(relative_raw))
    if relative.is_absolute() or not relative.parts or any(part in {"",".",".."} for part in relative.parts): raise SystemExit(f"{label} path is unsafe")
    if not hasattr(os,"O_NOFOLLOW") or not hasattr(os,"O_DIRECTORY"): raise SystemExit(f"{label} requires descriptor-relative no-follow support")
    current=os.open(str(AGENT_DIR.parent),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            following=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current); os.close(current); current=following
        descriptor=os.open(relative.parts[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=current)
        try:
            before=os.fstat(descriptor); expected_uid=os.geteuid() if hasattr(os,"geteuid") else before.st_uid
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=expected_uid or before.st_size<0 or before.st_size>maximum): raise SystemExit(f"{label} is not one bounded owner-controlled regular file")
            chunks=[]; total=0
            while total<=maximum:
                chunk=os.read(descriptor,min(65536,maximum+1-total))
                if not chunk: break
                chunks.append(chunk); total+=len(chunk)
            after=os.fstat(descriptor)
        finally: os.close(descriptor)
    finally: os.close(current)
    identity=lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns,item.st_mode,item.st_uid,item.st_nlink)
    if total>maximum or identity(before)!=identity(after) or total!=before.st_size: raise SystemExit(f"{label} changed during bounded read")
    data=b"".join(chunks); return {"bytes":data,"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)}


def _require_evidence_record(record,label):
    if (not isinstance(record,dict) or not isinstance(record.get("path"),str) or re.fullmatch(r"[0-9a-f]{64}",str(record.get("sha256",""))) is None
            or not isinstance(record.get("bytes"),int) or isinstance(record.get("bytes"),bool) or record["bytes"]<0): raise SystemExit(f"{label} authority is invalid")
    observed=_project_regular_snapshot(record["path"],label)
    if observed["sha256"]!=record["sha256"] or observed["size"]!=record["bytes"]: raise SystemExit(f"{label} bytes drifted")
    return observed


def _promotion_validate_candidate(entry,task,candidate_id):
    candidate_fields={"schema","rule","observation","evidence_sha256","reuse_scope","counterexample","expires_at","owner_id","source_artifact","candidate_id"}
    pending_fields=candidate_fields|{"task_generation_id","task_title","completion_binding_sha256","recorded_at","status"}
    completed=[item for item in task.get("knowledge_candidates",[]) if isinstance(item,dict) and item.get("candidate_id")==candidate_id]
    if (task.get("status")!="accepted" or task.get("task_generation_id")!=entry.get("task_generation_id")
            or set(entry)!=pending_fields or len(completed)!=1 or set(completed[0])!=candidate_fields
            or any(entry.get(key)!=completed[0].get(key) for key in candidate_fields)
            or entry.get("task_title")!=task.get("title") or entry.get("status")!="pending"):
        raise SystemExit("knowledge pending candidate differs from the exact accepted task candidate")
    try:
        recorded=dt.datetime.fromisoformat(str(entry.get("recorded_at","")).replace("Z","+00:00")); expiry=dt.datetime.fromisoformat(str(entry.get("expires_at","")).replace("Z","+00:00"))
    except ValueError as error: raise SystemExit("knowledge candidate timestamps are invalid") from error
    now=dt.datetime.now(dt.timezone.utc)
    if recorded.tzinfo is None or expiry.tzinfo is None or recorded.astimezone(dt.timezone.utc)>now+dt.timedelta(seconds=30) or recorded>=expiry:
        raise SystemExit("knowledge candidate timestamps are stale, future-dated, or misordered")
    candidate_unsigned={key:completed[0][key] for key in candidate_fields if key!="candidate_id"}
    if hashlib.sha256(json.dumps(candidate_unsigned,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()!=candidate_id:
        raise SystemExit("knowledge candidate ID no longer binds its exact evidence and rule")
    binding=task.get("completion_binding")
    if (not isinstance(binding,dict) or binding.get("schema")!="agent-completion-binding/v2"
            or hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()!=entry.get("completion_binding_sha256")):
        raise SystemExit("knowledge candidate completion binding drifted")
    artifacts=task.get("node_artifacts")
    if not isinstance(artifacts,dict): raise SystemExit("knowledge candidate accepted artifact authority is invalid")
    artifact_set=[]
    for node,record in sorted(artifacts.items(),key=lambda item:int(item[0]) if str(item[0]).isdigit() else -1):
        if not str(node).isdigit() or not isinstance(record,dict) or re.fullmatch(r"[0-9a-f]{64}",str(record.get("sha256",""))) is None:
            raise SystemExit("knowledge candidate accepted artifact authority is invalid")
        artifact_set.append({"node":int(node),**record})
    accepted_digest=hashlib.sha256(json.dumps(artifact_set,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    if binding.get("accepted_artifact_set_sha256")!=accepted_digest:
        raise SystemExit("knowledge candidate accepted artifact set drifted")
    retrospective=task.get("retrospective")
    _require_evidence_record(retrospective,"knowledge candidate retrospective")
    source=completed[0].get("source_artifact")
    source_observed=_require_evidence_record(source,"knowledge candidate source artifact")
    try: source_value=json.loads(source_observed["bytes"])
    except (UnicodeError,json.JSONDecodeError) as error: raise SystemExit("knowledge candidate source artifact is malformed") from error
    source_fields={"schema","rule","observation","evidence_sha256","reuse_scope","counterexample","expires_at","owner_id"}
    if not isinstance(source_value,dict) or set(source_value)!=source_fields: raise SystemExit("knowledge candidate source artifact fields drifted")
    normalized_source={key:(source_value[key].strip() if isinstance(source_value[key],str) and key!="expires_at" else source_value[key]) for key in source_fields}
    expected_source={key:completed[0][key] for key in source_fields}
    if normalized_source!=expected_source: raise SystemExit("knowledge candidate source artifact content drifted")
    for record in artifacts.values(): _require_evidence_record(record,"knowledge candidate node artifact")
    snapshot_sha=binding.get("completion_platform_snapshot_sha256")
    if re.fullmatch(r"[0-9a-f]{64}",str(snapshot_sha or "")) is None:
        raise SystemExit("knowledge candidate completion snapshot authority is invalid")
    # Legacy v2 completion bindings retain only the platform snapshot digest, not
    # a resolvable path/byte record. It remains part of completion identity but
    # cannot independently satisfy candidate evidence authority.
    allowed={str(retrospective["sha256"]),*(str(record["sha256"]) for record in artifact_set)}
    evidence=entry.get("evidence_sha256")
    if not isinstance(evidence,list) or not evidence or evidence!=sorted(set(evidence)) or not set(evidence)<=allowed:
        raise SystemExit("knowledge candidate evidence no longer matches accepted completion authority")
    terminal=max((item["node"] for item in artifact_set),default=None)
    terminal_sha=next((item["sha256"] for item in artifact_set if item["node"]==terminal),None)
    if binding.get("terminal_artifact_sha256")!=terminal_sha:
        raise SystemExit("knowledge candidate terminal artifact authority drifted")
    return completed[0]


def _promotion_expiry(entry,allow_expired=False):
    try: expiry=dt.datetime.fromisoformat(str(entry.get("expires_at","")).replace("Z","+00:00"))
    except ValueError as error: raise SystemExit("knowledge candidate expiry is invalid") from error
    if expiry.tzinfo is None: raise SystemExit("knowledge candidate expiry requires timezone")
    if not allow_expired and expiry<=dt.datetime.now(dt.timezone.utc): raise SystemExit("knowledge candidate expired before durable promotion authorization")
    return expiry


def _promotion_owner_plan(entry,source,registry_snapshot):
    try: registry=json.loads(registry_snapshot["bytes"])
    except (UnicodeError,json.JSONDecodeError) as error: raise SystemExit("knowledge registry is malformed") from error
    owners=[item for item in registry.get("entries",[]) if isinstance(item,dict) and item.get("id")==entry.get("owner_id") and item.get("status")=="active" and item.get("owners")]
    if len(owners)!=1: raise SystemExit("knowledge candidate owner is no longer active and owned")
    owner_relative=Path(str(owners[0].get("path","")))
    if owner_relative.is_absolute() or owner_relative.suffix!=".md" or any(part in {"",".",".."} for part in owner_relative.parts): raise SystemExit("knowledge registry owner path is unsafe")
    owner_path=AGENT_DIR/"project/knowledge"/owner_relative; owner_snapshot=promotion_snapshot(owner_path,"knowledge owner",1048576)
    if owner_snapshot is None: raise SystemExit("knowledge owner file is missing")
    try: owner_text=owner_snapshot["bytes"].decode("utf-8")
    except UnicodeDecodeError as error: raise SystemExit("knowledge owner file must be UTF-8") from error
    identity={"candidate_id":entry["candidate_id"],"task_generation_id":entry["task_generation_id"],"owner_id":entry["owner_id"],"owner_path":owner_relative.as_posix(),"owner_preimage_sha256":owner_snapshot["sha256"],"source":source}
    promotion_id=hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    def quoted(value): return json.dumps(str(value),ensure_ascii=False).replace("<","\u003c").replace(">","\u003e")
    block=(f"\n<!-- agent-knowledge-promotion:{promotion_id} -->\n### Promoted reusable rule {promotion_id[:16]}\n"
           f"- Rule: {quoted(entry.get('rule'))}\n- Observation: {quoted(entry.get('observation'))}\n"
           f"- Reuse scope: {quoted(entry.get('reuse_scope'))}\n- Counterexample: {quoted(entry.get('counterexample'))}\n"
           f"- Evidence SHA-256: {', '.join(entry.get('evidence_sha256',[]))}\n- Expires: {entry.get('expires_at')}\n")
    owner_after=(owner_text.rstrip()+"\n"+block).encode()
    return owner_path,owner_relative,owner_snapshot,owner_after,promotion_id


def _promotion_target_records(after_images,expected_before):
    records={}
    for path,data in after_images.items():
        relative=path.relative_to(AGENT_DIR.parent).as_posix()
        if _promotion_target(relative)!=path: raise SystemExit("knowledge promotion path normalization failed")
        records[relative]={"before_sha256":expected_before[path]["sha256"],"after_sha256":hashlib.sha256(data).hexdigest(),"after_b64":base64.b64encode(data).decode("ascii")}
    return records


def _promotion_commit_records(records,registry_sha256):
    registry_snapshot=promotion_snapshot(AGENT_DIR/"project/knowledge/registry.json","knowledge registry")
    if registry_snapshot is None or registry_snapshot["sha256"]!=registry_sha256: raise SystemExit("knowledge registry drifted during promotion commit")
    prepared=[]
    for relative,record in records.items():
        if not isinstance(record,dict) or set(record)!={"before_sha256","after_sha256","after_b64"}: raise SystemExit("knowledge promotion target record is malformed")
        path=_promotion_target(relative)
        try: after=base64.b64decode(record["after_b64"],validate=True)
        except (ValueError,TypeError) as error: raise SystemExit("knowledge promotion target payload is corrupt") from error
        if hashlib.sha256(after).hexdigest()!=record.get("after_sha256"): raise SystemExit("knowledge promotion target payload digest is corrupt")
        snapshot=promotion_snapshot(path,"knowledge promotion target")
        observed=snapshot["sha256"] if snapshot is not None else None
        if observed not in {record.get("before_sha256"),record.get("after_sha256")}:
            raise SystemExit(f"knowledge promotion target drifted during commit: {relative}")
        prepared.append((path,after,observed==record.get("after_sha256")))
    for index,(path,data,already) in enumerate(prepared):
        if not already:
            immediate=promotion_snapshot(path,"knowledge promotion target immediately before replace")
            if immediate is None or immediate["sha256"]!=records[path.relative_to(AGENT_DIR.parent).as_posix()]["before_sha256"]: raise SystemExit("knowledge promotion target changed immediately before replace")
            _promotion_atomic_write(path,data)
        canonical=promotion_snapshot(path,"knowledge promotion canonical postimage")
        if canonical is None or canonical["sha256"]!=hashlib.sha256(data).hexdigest(): raise SystemExit("knowledge promotion target namespace changed during replace")
        if os.environ.get("AGENT_WORKFLOW_PROMOTION_SELF_TEST_CRASH")==f"after-write-{index}": os._exit(97)


def recover_knowledge_promotion_transaction() -> None:
    journal_snapshot=promotion_snapshot(KNOWLEDGE_PROMOTION_JOURNAL_PATH,"knowledge promotion journal",8*1024*1024)
    if journal_snapshot is None: return
    try: journal=json.loads(journal_snapshot["bytes"])
    except (UnicodeError,json.JSONDecodeError) as error: raise SystemExit("knowledge promotion transaction journal is malformed") from error
    fields={"schema","phase","registry_sha256","candidate_id","entry","source","artifact_sha256","owner_path","owner_preimage_sha256","owner_after_b64","pending_preimage_sha256","pending_preimage_b64","prepared_decision","task_sha256","task_b64","config_sha256","config_b64","prepared_at","decision_record","targets"}
    if (not isinstance(journal,dict) or set(journal)!=fields or journal.get("schema")!="agent-knowledge-promotion-transaction/v3"
            or journal.get("phase") not in {"prepared","consuming","consumed"}
            or any(re.fullmatch(r"[0-9a-f]{64}",str(journal.get(key,""))) is None for key in ("registry_sha256","candidate_id","artifact_sha256","owner_preimage_sha256","pending_preimage_sha256","task_sha256"))
            or not str(journal.get("source","")).startswith("user:")):
        raise SystemExit("knowledge promotion transaction journal is malformed")
    try:
        task_raw=base64.b64decode(journal["task_b64"],validate=True); owner_after=base64.b64decode(journal["owner_after_b64"],validate=True); pending_before_raw=base64.b64decode(journal["pending_preimage_b64"],validate=True); config_raw=base64.b64decode(journal["config_b64"],validate=True)
        task=json.loads(task_raw); pending_before=json.loads(pending_before_raw); config=json.loads(config_raw)
    except (ValueError,TypeError,UnicodeError,json.JSONDecodeError) as error: raise SystemExit("knowledge promotion transaction payload is corrupt") from error
    if (not isinstance(task,dict) or not isinstance(pending_before,dict) or hashlib.sha256(task_raw).hexdigest()!=journal["task_sha256"]
            or hashlib.sha256(owner_after).hexdigest()!=journal["artifact_sha256"] or hashlib.sha256(pending_before_raw).hexdigest()!=journal["pending_preimage_sha256"]
            or not isinstance(config,dict) or hashlib.sha256(config_raw).hexdigest()!=journal["config_sha256"]):
        raise SystemExit("knowledge promotion transaction payload digest is corrupt")
    pending,pending_snapshot=_promotion_json(KNOWLEDGE_PENDING_PATH,"knowledge pending registry",1048576)
    base_candidates=pending_before.get("candidates"); base_promotions=pending_before.get("promotions")
    if pending_before.get("schema")!="agent-knowledge-pending/v2" or not isinstance(base_candidates,list) or not isinstance(base_promotions,list): raise SystemExit("knowledge promotion pending preimage is malformed")
    matching=[item for item in base_candidates if isinstance(item,dict) and item.get("candidate_id")==journal["candidate_id"]]
    if len(matching)!=1 or matching[0]!=journal.get("entry"): raise SystemExit("knowledge promotion journal candidate is missing, ambiguous, or drifted")
    entry=matching[0]; resolved=_promotion_task_from_archive(entry)
    resolved_raw=(json.dumps(resolved,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode())
    canonical_task=(json.dumps(task,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode())
    if resolved_raw!=canonical_task: raise SystemExit("knowledge promotion journal task differs from validated accepted authority")
    _promotion_validate_candidate(entry,task,journal["candidate_id"])
    registry_snapshot=promotion_snapshot(AGENT_DIR/"project/knowledge/registry.json","knowledge registry")
    if registry_snapshot is None or registry_snapshot["sha256"]!=journal["registry_sha256"]: raise SystemExit("knowledge registry drifted during promotion recovery")
    try: registry=json.loads(registry_snapshot["bytes"])
    except (UnicodeError,json.JSONDecodeError) as error: raise SystemExit("knowledge registry is malformed") from error
    owners=[item for item in registry.get("entries",[]) if isinstance(item,dict) and item.get("id")==entry.get("owner_id") and item.get("status")=="active" and item.get("owners")]
    if len(owners)!=1: raise SystemExit("knowledge candidate owner is no longer active and owned")
    owner_relative=Path(str(owners[0].get("path",""))); owner_path=AGENT_DIR/"project/knowledge"/owner_relative
    if owner_relative.as_posix()!=journal["owner_path"]: raise SystemExit("knowledge promotion journal owner path drifted")
    owner_snapshot=promotion_snapshot(owner_path,"knowledge owner",1048576)
    if owner_snapshot is None: raise SystemExit("knowledge owner file is missing")
    identity={"candidate_id":entry["candidate_id"],"task_generation_id":entry["task_generation_id"],"owner_id":entry["owner_id"],"owner_path":owner_relative.as_posix(),"owner_preimage_sha256":journal["owner_preimage_sha256"],"source":journal["source"]}
    promotion_id=hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    if owner_snapshot["sha256"]==journal["owner_preimage_sha256"]:
        _path,_relative,_snapshot,recomputed_after,recomputed_id=_promotion_owner_plan(entry,journal["source"],registry_snapshot)
        if recomputed_after!=owner_after or recomputed_id!=promotion_id: raise SystemExit("knowledge promotion journal no longer matches its exact owner preimage")
    elif owner_snapshot["sha256"]!=journal["artifact_sha256"] or journal["phase"]!="consumed": raise SystemExit("knowledge promotion owner drifted outside recoverable target states")
    current_config,current_config_snapshot=_promotion_json(CONFIG_PATH,"promotion config",2*1024*1024)
    if current_config_snapshot["sha256"]!=journal["config_sha256"] or current_config!=config: raise SystemExit("knowledge promotion provider configuration drifted after preparation")
    status=humandecision.status_prepared_decision(AGENT_DIR.parent.resolve(),config,task,gate="knowledge",artifact_sha256=journal["artifact_sha256"],source=journal["source"],prepared=journal["prepared_decision"])
    decision=None
    if status.get("status")=="consumed" and isinstance(status.get("record"),dict):
        if journal["phase"]=="prepared": _promotion_expiry(entry)
        decision=status["record"]
    elif status.get("status")=="unconsumed" and journal["phase"] in {"prepared","consuming"}:
        _promotion_expiry(entry)
        if pending_snapshot["sha256"]!=journal["pending_preimage_sha256"]: raise SystemExit("knowledge promotion pending authority drifted before provider consumption")
        require_promotion_snapshot(KNOWLEDGE_PENDING_PATH,pending_snapshot,"knowledge pending registry before provider consumption")
        require_promotion_snapshot(KNOWLEDGE_PROMOTION_JOURNAL_PATH,journal_snapshot,"knowledge promotion prepared journal")
        if journal["phase"]=="prepared":
            consuming={**journal,"phase":"consuming"}
            _promotion_atomic_write(KNOWLEDGE_PROMOTION_JOURNAL_PATH,(json.dumps(consuming,ensure_ascii=False,indent=2,sort_keys=True)+"\n").encode())
            journal=consuming; journal_snapshot=promotion_snapshot(KNOWLEDGE_PROMOTION_JOURNAL_PATH,"knowledge promotion consuming journal",8*1024*1024)
            if journal_snapshot is None: raise SystemExit("knowledge promotion consuming journal was not durable")
        decision_result=humandecision.consume_prepared_decision(AGENT_DIR.parent.resolve(),config,task,gate="knowledge",artifact_sha256=journal["artifact_sha256"],source=journal["source"],prepared=journal["prepared_decision"])
        if decision_result.get("status")!="consumed" or not isinstance(decision_result.get("record"),dict): raise SystemExit("provider approval was not consumed")
        decision=decision_result["record"]
        if os.environ.get("AGENT_WORKFLOW_PROMOTION_SELF_TEST_CRASH")=="after-consume": os._exit(96)
    else: raise SystemExit("knowledge promotion provider status is revoked, unknown, or inconsistent")
    if journal["phase"]=="consumed" and journal.get("decision_record")!=decision:
        raise SystemExit("knowledge promotion consumed journal decision binding drifted")
    promoted_at=journal["prepared_at"]; receipt={"promotion_id":promotion_id,"candidate_id":entry["candidate_id"],"task_generation_id":entry["task_generation_id"],"owner_id":entry["owner_id"],"owner_path":owner_path.relative_to(AGENT_DIR.parent).as_posix(),"owner_preimage_sha256":journal["owner_preimage_sha256"],"owner_postimage_sha256":journal["artifact_sha256"],"source":journal["source"],"decision_receipt":decision,"promoted_at":promoted_at}
    updated={**pending_before,"candidates":[item for item in base_candidates if item is not entry],"promotions":[*base_promotions,receipt]}
    pending_after=(json.dumps(updated,ensure_ascii=False,indent=2)+"\n").encode()
    pending_after_sha=hashlib.sha256(pending_after).hexdigest()
    if pending_snapshot["sha256"] not in {journal["pending_preimage_sha256"],pending_after_sha}: raise SystemExit("knowledge promotion pending target drifted outside recoverable states")
    records=_promotion_target_records({owner_path:owner_after,KNOWLEDGE_PENDING_PATH:pending_after},{owner_path:{"sha256":journal["owner_preimage_sha256"]},KNOWLEDGE_PENDING_PATH:{"sha256":journal["pending_preimage_sha256"]}})
    consumed={**journal,"phase":"consumed","decision_record":decision,"targets":records}
    if journal["phase"] in {"prepared","consuming"}:
        require_promotion_snapshot(KNOWLEDGE_PROMOTION_JOURNAL_PATH,journal_snapshot,"knowledge promotion prepared journal")
        _promotion_atomic_write(KNOWLEDGE_PROMOTION_JOURNAL_PATH,(json.dumps(consumed,ensure_ascii=False,indent=2,sort_keys=True)+"\n").encode())
        journal=consumed
        if os.environ.get("AGENT_WORKFLOW_PROMOTION_SELF_TEST_CRASH")=="after-consumed-journal": os._exit(96)
    elif journal.get("targets")!=records:
        raise SystemExit("knowledge promotion consumed target binding drifted")
    _promotion_commit_records(records,journal["registry_sha256"])
    final_journal=promotion_snapshot(KNOWLEDGE_PROMOTION_JOURNAL_PATH,"knowledge promotion journal",8*1024*1024)
    if final_journal is None: raise SystemExit("knowledge promotion journal disappeared before durable completion")
    _promotion_unlink(KNOWLEDGE_PROMOTION_JOURNAL_PATH,final_journal)


@contextmanager
def locked_runtime():
    try: lock_handle=boundedio.open_private_lock(RUNTIME_LOCK_PATH,label="runtime state lock")
    except RuntimeError as error: raise SystemExit(str(error)) from error
    with lock_handle as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        runtime = load_json(RUNTIME_PATH)
        yield runtime
        save_json(RUNTIME_PATH, runtime)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def load_tool_leases() -> Dict[str, object]:
    if not TOOL_LEASES_PATH.is_file():
        return {"schema": "agent-tool-leases/v1", "leases": []}
    return load_json(TOOL_LEASES_PATH)


@contextmanager
def locked_tool_leases():
    try: lock_handle=boundedio.open_private_lock(TOOL_LEASES_LOCK_PATH,label="tool lease lock")
    except RuntimeError as error: raise SystemExit(str(error)) from error
    with lock_handle as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        leases = load_tool_leases()
        yield leases
        save_json(TOOL_LEASES_PATH, leases)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def valid_file_receipt(record: object) -> bool:
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
        return False
    path = (AGENT_DIR.parent / str(record.get("path"))).resolve()
    try:
        path.relative_to(AGENT_DIR.parent.resolve())
    except ValueError:
        return False
    if not path.is_file() or path.is_symlink():
        return False
    data = boundedio.read_bytes(path,label="agent file")
    return len(data) == record.get("bytes") and hashlib.sha256(data).hexdigest() == record.get("sha256")


def update_stage_fields(fields: Dict[str, object]) -> None:
    text = boundedio.read_text(STAGE_PATH,label="stage index")
    for name, value in fields.items():
        pattern = rf"^- {re.escape(name)}:\s*.*$"
        replacement = f"- {name}: {value}"
        text, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
        if count != 1:
            raise SystemExit(f"stage index field must occur exactly once: {name}")
    atomic_write(STAGE_PATH, text)


def context_task_sha256() -> str:
    """Return the last verified canonical TASK invariant, never the TASK file hash."""
    if not CONTEXT_PATH.is_file():
        return "none"
    try:
        value = load_json(CONTEXT_PATH)
    except (OSError, ValueError, json.JSONDecodeError, SystemExit):
        raise SystemExit("context is corrupt; use contextctl repair before changing TASK state")
    digest = value.get("task_invariant_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit("context lacks a verified TASK invariant; repair it before changing TASK state")
    return digest


def sync_context(
    reason: str,
    *,
    before_task: Dict[str, object],
    after_task: Dict[str, object],
    operation: str,
    summary: str,
    source_tokens: Optional[int] = None,
    side_effects: Sequence[Tuple[Path, bytes]] = (),
) -> None:
    """Commit one field-authorized TASK -> CONTEXT transition atomically."""
    contexttx.transition_task(
        before_task,
        after_task,
        mutator="agentctl",
        operation=operation,
        reason=reason,
        summary=summary,
        source_tokens=source_tokens,
        side_effects=[(STAGE_PATH,stage_bytes(after_task)),*side_effects],
    )


class DarwinProcBSDInfo(ctypes.Structure):
    """ABI layout of Darwin's ``struct proc_bsdinfo``."""

    _fields_ = [
        ("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32), ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32), ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32), ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def native_process_identity(pid: int) -> Tuple[str, Optional[Dict[str, object]]]:
    """Return (status, identity) from the kernel, never from `ps` or `lsof`.

    Status is ``ok``, ``gone`` or ``unavailable`` so callers may discard an
    exited lsof candidate without treating an inspection failure as an exit.
    """
    if pid <= 0:
        return "gone", None
    if sys.platform == "darwin":
        try:
            libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            proc_pidinfo = libproc.proc_pidinfo
            proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
            proc_pidinfo.restype = ctypes.c_int
            info = DarwinProcBSDInfo()
            ctypes.set_errno(0)
            size = proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
        except (AttributeError, OSError):
            return "unavailable", None
        if size != ctypes.sizeof(info):
            error = ctypes.get_errno()
            return ("gone" if error in {errno.ESRCH, errno.ENOENT} else "unavailable"), None
        if int(info.pbi_pid) != pid:
            return "unavailable", None
        executable = None
        try:
            proc_pidpath = libproc.proc_pidpath
            proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
            proc_pidpath.restype = ctypes.c_int
            path_buffer = ctypes.create_string_buffer(4096)
            path_size = proc_pidpath(pid, path_buffer, len(path_buffer))
            if path_size > 0:
                executable = os.path.realpath(path_buffer.value.decode("utf-8", errors="strict"))
        except (AttributeError, OSError, UnicodeError):
            executable = None
        name = bytes(info.pbi_name).split(b"\0", 1)[0] or bytes(info.pbi_comm).split(b"\0", 1)[0]
        return "ok", {
            "pid": pid, "ppid": int(info.pbi_ppid), "pgid": int(info.pbi_pgid),
            "start_time": f"darwin:{int(info.pbi_start_tvsec)}:{int(info.pbi_start_tvusec)}",
            "command": name.decode("utf-8", errors="replace"),
            "executable": executable,
            "state": "Z" if int(info.pbi_status) == 5 else str(int(info.pbi_status)),
        }
    if sys.platform.startswith("linux"):
        try:
            with open(f"/proc/{pid}/stat","rb",buffering=0) as handle: raw_stat=handle.read(4097)
            if len(raw_stat)>4096: return "unavailable",None
            stat=raw_stat.decode("utf-8")
        except FileNotFoundError: return "gone",None
        except (OSError,UnicodeError): return "unavailable",None
        close = stat.rfind(")")
        open_ = stat.find("(")
        fields = stat[close + 2:].split() if open_ > 0 and close > open_ else []
        if len(fields) < 20:
            return "unavailable", None
        try:
            observed_pid = int(stat[:open_])
            ppid, pgid, start = int(fields[1]), int(fields[2]), int(fields[19])
        except ValueError:
            return "unavailable", None
        if observed_pid != pid:
            return "unavailable", None
        try:
            executable = os.path.realpath(os.readlink(f"/proc/{pid}/exe"))
        except OSError:
            executable = None
        return "ok", {
            "pid": pid, "ppid": ppid, "pgid": pgid,
            "start_time": f"linux:{start}", "command": stat[open_ + 1:close],
            "executable": executable,
            "state": fields[0],
        }
    return "unavailable", None


def lsof_executable() -> Optional[str]:
    """Resolve lsof only through an OS-owned, Agent-nonwritable path chain."""
    observed = [shutil.which("lsof"), "/usr/sbin/lsof", "/usr/bin/lsof"]
    seen = set()
    for raw in observed:
        if not raw:
            continue
        try:
            candidate = Path(raw).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate.name != "lsof" or not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        try:
            candidate.relative_to(AGENT_DIR.parent.resolve())
            continue
        except ValueError:
            pass
        protected = True
        for item in (candidate, *candidate.parents):
            try:
                info = item.stat()
            except OSError:
                protected = False
                break
            if info.st_uid != 0 or info.st_mode & 0o022:
                protected = False
                break
        if protected:
            return str(candidate)
    return None


def lsof_process_cwd(pid: int) -> Tuple[str, Optional[Dict[str, object]]]:
    """Read the cwd record used for path scoping; identity stays kernel-owned."""
    executable = lsof_executable()
    if executable is None:
        return "unavailable", None
    try:
        result=run_bounded_trusted_observer(
            [executable,"-n","-a","-p",str(pid),"-d","cwd","-FpcRgn"],timeout=5,output_limit=64*1024,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable", None
    if result.returncode not in {0, 1}:
        return "unavailable", None
    record: Dict[str, object] = {"pid": pid}
    observed = False
    for line in result.stdout.splitlines():
        if re.fullmatch(r"p[0-9]+", line):
            observed = int(line[1:]) == pid
        elif observed and re.fullmatch(r"R[0-9]+", line):
            record["ppid"] = int(line[1:])
        elif observed and re.fullmatch(r"g[0-9]+", line):
            record["pgid"] = int(line[1:])
        elif observed and line.startswith("c"):
            record["command"] = line[1:]
        elif observed and line.startswith("n"):
            record["cwd"] = line[1:]
    if (
        not isinstance(record.get("ppid"), int)
        or not isinstance(record.get("pgid"), int)
        or not isinstance(record.get("command"), str) or not record.get("command")
        or not isinstance(record.get("cwd"), str) or not record.get("cwd")
    ):
        return ("gone" if not observed else "unavailable"), None
    return "ok", record


def process_snapshot(pid: int) -> Optional[Dict[str, object]]:
    """Bind cwd metadata to one stable OS-native process identity."""
    before_status, before = native_process_identity(pid)
    if before_status != "ok" or before is None:
        return None
    if sys.platform.startswith("linux"):
        try:
            cwd = os.readlink(f"/proc/{pid}/cwd")
        except FileNotFoundError:
            return None
        except OSError:
            return None
        cwd_record = {"pid": pid, "ppid": before["ppid"], "pgid": before["pgid"], "cwd": cwd}
    else:
        cwd_status, cwd_record = lsof_process_cwd(pid)
        if cwd_status != "ok" or cwd_record is None:
            return None
    after_status, after = native_process_identity(pid)
    if after_status != "ok" or after is None:
        return None
    stable_keys = ("pid", "ppid", "pgid", "start_time")
    if any(before.get(key) != after.get(key) for key in stable_keys):
        return None
    if cwd_record.get("pid") != pid or cwd_record.get("ppid") != after.get("ppid") or cwd_record.get("pgid") != after.get("pgid"):
        return None
    return {**after, "cwd": str(cwd_record["cwd"])}


def _walk_ancestors() -> Tuple[Dict[int, Dict[str, object]], bool]:
    """Collect the caller chain, reporting whether every ancestor was inspectable.

    A ``gone`` ancestor is a normal boundary (the branch simply ends).  An
    ``unavailable`` ancestor (e.g. a macOS cross-uid parent that denies
    ``proc_pidinfo`` with EPERM, common inside nested sandboxes) stops that
    branch but is recorded as an incomplete walk.  Callers that only need to
    exclude the visible caller chain can use the partial result safely; callers
    that must fail closed on any unknown ancestor consume ``complete``.
    """
    result: Dict[int, Dict[str, object]] = {}
    complete = True
    pending = [os.getpid(), os.getppid()]
    while pending:
        current = pending.pop()
        for _ in range(64):
            if current <= 1 or current in result:
                break
            status, record = native_process_identity(current)
            if status == "gone":
                break
            if status != "ok" or record is None:
                # An uninspectable ancestor is outside what we can attribute;
                # stop ascending this branch but mark the chain incomplete.
                complete = False
                break
            result[current] = record
            current = int(record["ppid"])
    return result, complete


def live_ancestor_identities() -> Optional[Dict[int, Dict[str, object]]]:
    """Derive the caller chain, fail-closed when any ancestor is uninspectable.

    Kill/registration guards depend on a ``None`` here to refuse action when the
    chain cannot be fully proven, so this strict view is preserved unchanged.
    """
    result, complete = _walk_ancestors()
    return result if complete else None


def live_ancestor_pids() -> Optional[set[int]]:
    identities = live_ancestor_identities()
    return None if identities is None else set(identities)


def process_group_intersects_live_ancestors(pgid: int) -> Optional[bool]:
    """Report whether ``pgid`` is one of the caller chain's own process groups.

    Both callers (isolated-group termination and manual registration) only need
    to avoid acting on the controller's own session.  A process group is
    session- and uid-scoped, so an uninspectable cross-uid ancestor cannot share
    a PGID with the same-uid, freshly-sessioned managed or registrable group
    under consideration.  The visible chain is therefore authoritative for this
    disjointness decision, and an incomplete walk (e.g. a macOS cross-uid parent
    that denies inspection) must not permanently refuse every cleanup.
    """
    identities, _complete = _walk_ancestors()
    return any(int(item.get("pgid", 0)) == pgid for item in identities.values())


def valid_host_runner_identity_contract(value: object) -> bool:
    """Validate the provider-neutral, exact live-process exemption contract."""
    if value is None:
        return True
    if not isinstance(value, dict) or set(value) != {
        "schema", "authority", "host", "runner",
    }:
        return False
    if value.get("schema") != "agent-host-runner-identity/v1":
        return False
    authority = value.get("authority")
    if not isinstance(authority, str) or re.fullmatch(r"[a-z][a-z0-9.-]{2,63}", authority) is None:
        return False
    for key in ("host", "runner"):
        identity = value.get(key)
        if not isinstance(identity, dict) or set(identity) != {"pid", "start_time", "executable"}:
            return False
        if not isinstance(identity.get("pid"), int) or isinstance(identity.get("pid"), bool) or identity["pid"] <= 1:
            return False
        if not isinstance(identity.get("start_time"), str) or re.fullmatch(r"(?:linux:[0-9]+|darwin:[0-9]+:[0-9]+)", identity["start_time"]) is None:
            return False
        executable = identity.get("executable")
        if not isinstance(executable, str) or not Path(executable).is_absolute():
            return False
        try:
            if str(Path(executable).resolve(strict=False)) != executable:
                return False
        except (OSError, RuntimeError):
            return False
    return value["runner"]["pid"] != value["host"]["pid"]


def valid_context_transport_policy(transport: object, selected_model: object) -> bool:
    """Accept native-only state or one provenance-verified opted-in extension."""
    if isinstance(transport, dict) and transport == {"default": "native"}:
        return True
    pxpipe_transport = transport.get("pxpipe") if isinstance(transport, dict) else None
    provenance = pxpipe_transport.get("provenance") if isinstance(pxpipe_transport, dict) else None
    return (
        isinstance(transport, dict)
        and set(transport) == {"default", "pxpipe"}
        and transport.get("default") == "native"
        and isinstance(pxpipe_transport, dict)
        and set(pxpipe_transport) == {
            "enabled", "activation", "plugin_name", "plugin_version", "models",
            "primary_mode", "provider_activation", "provider_configuration",
            "provider_content_scope", "mcp_role", "selection", "content_scope",
            "session_boundary", "fallback", "provenance",
        }
        and pxpipe_transport.get("enabled") is True
        and pxpipe_transport.get("activation") == "explicit-opt-in"
        and pxpipe_transport.get("plugin_name") == "pxpipe-context"
        and pxpipe_transport.get("plugin_version") == "0.1.0+codex.20260721210500"
        and isinstance(pxpipe_transport.get("models"), list)
        and 1 <= len(pxpipe_transport.get("models", [])) <= 16
        and all(valid_model_id(model) for model in pxpipe_transport.get("models", []))
        and len(set(pxpipe_transport.get("models", []))) == len(pxpipe_transport.get("models", []))
        and selected_model in pxpipe_transport.get("models", [])
        and pxpipe_transport.get("primary_mode") == "provider-proxy"
        and pxpipe_transport.get("provider_activation") == "default-new-local-sessions"
        and pxpipe_transport.get("provider_configuration") == "user-model-provider-plus-launch-agent"
        and pxpipe_transport.get("provider_content_scope") == "whole-request-eligible-content"
        and pxpipe_transport.get("mcp_role") == "optional-cold-reference"
        and pxpipe_transport.get("selection") == "analyze-then-render"
        and pxpipe_transport.get("content_scope") == "new-cold-reference-only"
        and pxpipe_transport.get("session_boundary") == "plugin-load-requires-new-chat"
        and pxpipe_transport.get("fallback") == "native"
        and isinstance(provenance, dict)
        and set(provenance) == {"status", "manifest_sha256", "verified_by"}
        and provenance.get("status") == "verified"
        and isinstance(provenance.get("manifest_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", provenance["manifest_sha256"]) is not None
        and provenance.get("verified_by") == "installed-extension-manifest"
    )


def host_runner_peer(
    snapshot: Dict[str, object], ancestors: Dict[int, Dict[str, object]],
) -> bool:
    """Exempt only one explicitly configured host-owned runner identity.

    The default is no exemption.  Executable basenames, argv, cwd and directory
    co-location carry no authority: the configured authority must bind exact
    kernel PID/start identities and canonical executables for both runner and
    its direct host parent.
    """
    runtime_policy = load_json(CONFIG_PATH).get("runtime", {})
    contract = runtime_policy.get("host_runner_identity") if isinstance(runtime_policy, dict) else None
    if not valid_host_runner_identity_contract(contract) or contract is None:
        return False
    runner = contract["runner"]
    host = contract["host"]
    if snapshot.get("ppid") != host["pid"]:
        return False
    parent = ancestors.get(host["pid"])
    if not isinstance(parent, dict):
        return False
    return all(snapshot.get(key) == runner[key] for key in ("pid", "start_time", "executable")) and all(
        parent.get(key) == host[key] for key in ("pid", "start_time", "executable")
    )


def project_processes() -> Optional[List[Dict[str, object]]]:
    """Snapshot project-cwd processes and exclude only the live-derived caller chain."""
    root = AGENT_DIR.parent.resolve()
    executable = lsof_executable()
    if executable is None:
        return None
    try:
        probe=run_bounded_trusted_observer(
            [executable,"-n","-d","cwd","-FpcRgn"],timeout=15,
            output_limit=MAX_CONTROL_COMMAND_OUTPUT_BYTES,
        )
    except (OSError,subprocess.TimeoutExpired): return None
    output=probe.stdout
    if probe.returncode not in {0,1}:
        return None
    records: Dict[int, Dict[str, object]] = {}
    observed_pid: Optional[int] = None
    for line in output.splitlines():
        if re.fullmatch(r"p[0-9]+", line):
            observed_pid = int(line[1:])
            records.setdefault(observed_pid, {"pid": observed_pid})
        elif observed_pid is not None and re.fullmatch(r"R[0-9]+", line):
            records[observed_pid]["ppid"] = int(line[1:])
        elif observed_pid is not None and re.fullmatch(r"g[0-9]+", line):
            records[observed_pid]["pgid"] = int(line[1:])
        elif observed_pid is not None and line.startswith("c"):
            records[observed_pid]["command"] = line[1:]
        elif observed_pid is not None and line.startswith("n"):
            records[observed_pid]["cwd"] = line[1:]
    # Exclusion only removes the visible caller chain, so a partial walk is
    # safe: an uninspectable cross-uid ancestor lives outside the project root
    # and never appears in this cwd-scoped scan.  Missing an exclusion can only
    # over-report a suspicious residual, never hide one.
    ancestor_identities, _ = _walk_ancestors()
    excluded = set(ancestor_identities) | {probe.captured_observer_pid}
    snapshots: List[Dict[str, object]] = []
    for pid, raw in sorted(records.items()):
        cwd = raw.get("cwd")
        if not isinstance(cwd, str):
            continue
        try:
            Path(cwd).resolve().relative_to(root)
        except ValueError:
            continue
        if pid in excluded:
            continue
        snapshot = process_snapshot(pid)
        if snapshot is None:
            status, _ = native_process_identity(pid)
            if status == "gone":
                # lsof can retain a process that exited while its output was
                # being assembled. Only that proven transient is discardable.
                continue
            return None
        if raw.get("ppid") != snapshot.get("ppid") or raw.get("pgid") != snapshot.get("pgid"):
            return None
        if host_runner_peer(snapshot, ancestor_identities):
            continue
        try:
            same_cwd = Path(str(snapshot["cwd"])).resolve() == Path(cwd).resolve()
        except OSError:
            return None
        if not same_cwd:
            return None
        snapshots.append(snapshot)
    return snapshots


def stable_project_processes() -> Optional[List[Dict[str, object]]]:
    """Use the second complete snapshot so exited probe/transient PIDs cannot persist."""
    first = project_processes()
    if first is None:
        return None
    time.sleep(0.05)
    second = project_processes()
    return second


def process_identity(item: Dict[str, object]) -> str:
    payload = {key: item.get(key) for key in ("pid", "pgid", "start_time")}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def project_ancestor_chain(pid: int) -> List[Dict[str, object]]:
    """Capture the exact project-cwd supervisor chain for an audited tool lease."""
    root = AGENT_DIR.parent.resolve()
    chain: List[Dict[str, object]] = []
    current = pid
    seen: set[int] = set()
    for _ in range(64):
        if current <= 1 or current in seen:
            break
        seen.add(current)
        snapshot = process_snapshot(current)
        if snapshot is not None:
            try:
                Path(str(snapshot.get("cwd", ""))).resolve().relative_to(root)
            except ValueError:
                pass
            else:
                chain.append(snapshot)
        status, identity = native_process_identity(current)
        if status == "gone":
            break
        if status != "ok" or identity is None:
            # An uninspectable cross-uid ancestor sits above the project-cwd
            # supervisor chain; stop ascending but keep the visible chain rather
            # than discarding the audited lease entirely.
            break
        current = int(identity["ppid"])
    return chain


def active_agent_member(agent_id: str) -> Optional[Dict[str, object]]:
    """Return an active member only after the full v9 ledger validates."""
    if not AGENTS_PATH.is_file() or not AGENT_LEDGER_TOOL.is_file():
        return None
    try:
        before = boundedio.read_bytes(AGENTS_PATH,label="AGENTS bootstrap")
        semantic = run_bounded_command(
            [sys.executable,str(AGENT_LEDGER_TOOL),"validate"],cwd=AGENT_DIR.parent,timeout=30,
        )
        after = boundedio.read_bytes(AGENTS_PATH,label="AGENTS bootstrap")
        state = json.loads(after)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return None
    if semantic.returncode or before != after or not isinstance(state, dict) or state.get("schema") != "agent-team/v9":
        return None
    found = [item for item in state.get("members", []) if isinstance(item, dict) and item.get("id") == agent_id and item.get("status") == "active"]
    if len(found) != 1:
        return None
    item = found[0]
    try:
        config_policy = load_json(CONFIG_PATH)["agent_control"]
        deadline = dt.datetime.fromisoformat(str(item.get("deadline_at"))).astimezone(dt.timezone.utc)
        # The child cannot make progress before the platform registration/start
        # barrier is observed.  Dispatch time must never age a freshly
        # registered reviewer into a false stale state.
        latest_monitor = dt.datetime.fromisoformat(str(item.get("registration_observed_at"))).astimezone(dt.timezone.utc)
        monitors = item.get("monitor_platform_evidence")
        if not isinstance(monitors, list):
            return None
        if monitors:
            latest_record = monitors[-1]
            latest_path = (AGENT_DIR.parent / str(latest_record["path"])).resolve()
            latest_snapshot = load_json(latest_path)
            latest_monitor = dt.datetime.fromisoformat(str(latest_snapshot.get("observed_at"))).astimezone(dt.timezone.utc)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, SystemExit):
        return None
    now_utc = dt.datetime.now(dt.timezone.utc)
    maximum_gap = int(config_policy.get("status_interval_seconds", 0)) + int(config_policy.get("monitor_grace_seconds", -1))
    if (
        maximum_gap <= 0
        or maximum_gap > 60
        or deadline <= now_utc
        or (now_utc - latest_monitor).total_seconds() > maximum_gap
        or item.get("interrupt_requested_at") is not None
        or item.get("terminal_platform_evidence") is not None
        or item.get("terminal_observed_at") is not None
    ):
        return None
    return item


def active_review_agent_member(agent_id: str) -> Optional[Dict[str, object]]:
    member = active_agent_member(agent_id)
    if member is None:
        return None
    try:
        review_role_types = load_json(CONFIG_PATH)["agent_control"]["review_role_types"]
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, SystemExit):
        return None
    return member if member.get("role_type") in review_role_types else None


def audited_tool_allowances() -> Tuple[set[str], set[int], List[str]]:
    """Return exact transient-tool identities/process groups and validation errors."""
    state = load_tool_leases()
    errors: List[str] = []
    identities: set[str] = set()
    groups: set[int] = set()
    if state.get("schema") != "agent-tool-leases/v1" or not isinstance(state.get("leases"), list):
        return identities, groups, ["tool lease registry schema is invalid"]
    now_utc = dt.datetime.now(dt.timezone.utc)
    for lease in state["leases"]:
        if not isinstance(lease, dict):
            errors.append("tool lease record is invalid")
            continue
        lease_id = str(lease.get("id", "unknown"))
        try:
            deadline = dt.datetime.fromisoformat(str(lease.get("deadline_at")))
            if deadline.tzinfo is None:
                raise ValueError("timezone required")
            deadline = deadline.astimezone(dt.timezone.utc)
        except (TypeError, ValueError):
            errors.append(f"tool lease {lease_id} has an invalid deadline")
            continue
        supervisor = lease.get("supervisor")
        process = lease.get("process")
        chain = lease.get("supervisor_chain")
        if deadline <= now_utc or active_review_agent_member(str(lease.get("owner_agent_id", ""))) is None:
            errors.append(f"tool lease {lease_id} is expired or lacks an active platform-evidenced owner")
            continue
        if not isinstance(supervisor, dict) or not same_process(supervisor, process_snapshot(int(supervisor.get("pid", 0)))):
            errors.append(f"tool lease {lease_id} supervisor identity is not live")
            continue
        if not isinstance(process, dict) or process.get("scope") != "isolated_process_group" or process.get("pid") != process.get("pgid"):
            errors.append(f"tool lease {lease_id} process-group identity is invalid")
            continue
        pgid = int(process["pgid"])
        if not process_group_alive(pgid):
            errors.append(f"tool lease {lease_id} process group is no longer live")
            continue
        if not isinstance(chain, list) or not chain:
            errors.append(f"tool lease {lease_id} lacks a captured supervisor chain")
            continue
        identities.add(process_identity(supervisor))
        for item in chain:
            if isinstance(item, dict) and same_process(item, process_snapshot(int(item.get("pid", 0)))):
                identities.add(process_identity(item))
        groups.add(pgid)
    return identities, groups, errors


def capture_runtime_baseline(source: str, *, confirm_existing: bool = False) -> int:
    if not (source == "agentctl:start" or source.startswith("user:")):
        raise SystemExit("runtime baseline source must be agentctl:start or user:<decision>")
    observed = stable_project_processes()
    if observed is None:
        raise SystemExit("cannot inspect project process baseline; lsof is required")
    with locked_runtime() as runtime:
        if any(runtime.get(key) for key in ("processes", "docker_projects", "ports")):
            raise SystemExit("cannot capture a runtime baseline while registered resources remain")
        if observed and not confirm_existing:
            # Absorbing pre-existing processes into a fresh baseline would make
            # them invisible to every later assert-clean delta.  Recapturing
            # the SAME identities a previous baseline already recorded is a
            # no-op refresh and needs no new confirmation.
            baseline = runtime.get("baseline")
            previous = baseline.get("project_processes") if isinstance(baseline, dict) else None
            known = {
                process_identity(item) for item in previous if isinstance(item, dict)
            } if isinstance(previous, list) else set()
            new = [item for item in observed if process_identity(item) not in known]
            if new:
                listing = "; ".join(
                    f"pid={item.get('pid')} command={item.get('command')}" for item in new[:5]
                )
                raise SystemExit(
                    "unregistered project processes already exist and would be silently absorbed "
                    f"into the runtime baseline: {listing}; stop or register them first, or rerun "
                    "capture-runtime-baseline --source user:<decision> --confirm-existing-processes "
                    "to bless them explicitly"
                )
        runtime.clear()
        runtime.update({
            "schema": "agent-runtime/v2",
            "baseline": {
                "source": source,
                "captured_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
                "project_processes": observed,
                "confirmed_existing_processes": len(observed),
            },
            "processes": [], "docker_projects": [], "ports": [],
        })
    if observed:
        print(f"RUNTIME BASELINE WARNING: {len(observed)} pre-existing project process(es) recorded in baseline")
    print(f"RUNTIME BASELINE CAPTURED: project_processes={len(observed)}")
    return 0


def pid_alive(pid: int) -> bool:
    snapshot = process_snapshot(pid)
    return snapshot is not None and not str(snapshot["state"]).startswith("Z")


def process_group_alive(pgid: int) -> bool:
    if pgid <= 1:
        return False
    members = process_group_members(pgid)
    if members is None:
        return True  # Observation unavailable: never infer clean from a numeric PGID probe.
    return bool(members)


def process_group_members(pgid: int) -> Optional[List[int]]:
    """Return non-zombie members, or None when the platform cannot inspect them."""
    executable="/bin/ps" if Path("/bin/ps").is_file() else shutil.which("ps",path=os.defpath)
    if not executable: return None
    try:
        result=run_bounded_trusted_observer(
            [executable,"-axo","pid=,pgid=,stat="],env={"PATH":os.defpath,"LC_ALL":"C"},timeout=5,
            output_limit=MAX_CONTROL_COMMAND_OUTPUT_BYTES,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    members: List[int] = []
    for line in result.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        try:
            pid, candidate = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        if candidate == pgid and not parts[2].startswith("Z"):
            members.append(pid)
    return sorted(set(members))


def signal_process_group(pgid: int, signum: int) -> bool:
    """Numeric PGIDs are reusable and therefore never signaling authority."""
    return False


def stable_group_identities(pgid: int) -> Optional[Dict[int,str]]:
    members=process_group_members(pgid)
    if members is None: return None
    first={}
    for pid in members:
        status,identity=native_process_identity(pid)
        if status!="ok" or identity is None or int(identity.get("pgid",0))!=pgid: return None
        first[pid]=str(identity.get("start_time"))
    members_again=process_group_members(pgid)
    if members_again is None or set(members_again)!=set(first): return None
    for pid,expected in first.items():
        status,identity=native_process_identity(pid)
        if status!="ok" or identity is None or str(identity.get("start_time"))!=expected or int(identity.get("pgid",0))!=pgid: return None
    return first


def exact_identity_live(pid: int,start_time: str) -> bool:
    status,identity=native_process_identity(pid)
    return status=="ok" and identity is not None and str(identity.get("start_time"))==start_time and not str(identity.get("state","")).startswith("Z")


def signal_exact_identities(owned: Dict[int,str],signum: int) -> bool:
    ok=True
    for pid,expected in sorted(owned.items(),reverse=True):
        if not exact_identity_live(pid,expected): continue
        try:
            if sys.platform.startswith("linux"): linux_signal_identity(pid,expected,signum)
            elif sys.platform.startswith("darwin"):
                if not exact_identity_live(pid,expected): ok=False; continue
                os.kill(pid,signum)
            else: ok=False
        except ProcessLookupError: pass
        except (OSError,ProcessObservationError): ok=False
    return ok


def capture_owned_group(item: Dict[str,object]) -> bool:
    pgid=int(item.get("pgid",0)); pid=int(item.get("pid",0)); owned={}
    for value in item.get("member_identities",[]):
        if isinstance(value,dict) and isinstance(value.get("pid"),int) and isinstance(value.get("start_time"),str): owned[value["pid"]]=value["start_time"]
    status,leader=native_process_identity(pid)
    if status=="ok" and leader is not None and all(item.get(key)==leader.get(key) for key in ("pid","pgid","start_time")): owned[pid]=str(item.get("start_time"))
    if not any(exact_identity_live(member,identity) for member,identity in owned.items()): return False
    observed=stable_group_identities(pgid)
    if observed is None: return False
    owned.update(observed); item["member_identities"]=[{"pid":member,"pgid":pgid,"start_time":identity} for member,identity in sorted(owned.items())]
    return True


def terminate_isolated_group(item: Dict[str, object], timeout: int, leader: Optional[subprocess.Popen] = None) -> bool:
    """Terminate only stable PID/start identities observed in the owned group."""
    pid=int(item.get("pid",0)); pgid=int(item.get("pgid",0))
    if item.get("scope")!="isolated_process_group" or pid<=1 or pgid!=pid: return False
    if leader is not None and leader.pid!=pid: return False
    if process_group_intersects_live_ancestors(pgid) is not False: return False
    status,current=native_process_identity(pid)
    if status=="ok" and current is not None and any(item.get(key)!=current.get(key) for key in ("pid","pgid","start_time")): return False
    if status not in {"ok","gone"}: return False
    if not process_group_alive(pgid): return True
    if not capture_owned_group(item): return False
    owned={value["pid"]:value["start_time"] for value in item["member_identities"]}
    if not signal_exact_identities(owned,signal.SIGTERM): return False
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if leader is not None: leader.poll()
        capture_owned_group(item); owned={value["pid"]:value["start_time"] for value in item.get("member_identities",[])}
        if not any(exact_identity_live(member,identity) for member,identity in owned.items()): return not process_group_alive(pgid)
        time.sleep(0.05)
    if not capture_owned_group(item): return False
    owned={value["pid"]:value["start_time"] for value in item["member_identities"]}
    if not signal_exact_identities(owned,signal.SIGKILL): return False
    deadline=time.monotonic()+2
    while time.monotonic()<deadline:
        if not any(exact_identity_live(member,identity) for member,identity in owned.items()): return not process_group_alive(pgid)
        time.sleep(0.05)
    return False


def same_process(item: Dict[str, object], snapshot: Optional[Dict[str, object]]) -> bool:
    return snapshot is not None and all(
        item.get(key) == snapshot.get(key) for key in ("pid", "pgid", "start_time")
    )


def port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.25)
        return probe.connect_ex((host, port)) == 0


def tcp_listener_owners(port: int, host: str = "127.0.0.1") -> Optional[List[int]]:
    executable = lsof_executable()
    if executable is None:
        return None
    try:
        result=run_bounded_trusted_observer(
            [executable,"-nP",f"-iTCP@{host}:{port}","-sTCP:LISTEN","-Fp"],timeout=5,output_limit=64*1024,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return []
    return sorted({int(line[1:]) for line in result.stdout.splitlines() if re.fullmatch(r"p[0-9]+", line)})


def terminate_registered_process(item: Dict[str, object], timeout: int) -> bool:
    if item.get("scope") == "isolated_process_group":
        return terminate_isolated_group(item, timeout)
    pid = int(item["pid"])
    snapshot = process_snapshot(pid)
    if snapshot is None:
        status, _ = native_process_identity(pid)
        return status == "gone"
    if str(snapshot["state"]).startswith("Z"):
        return True
    if not same_process(item, snapshot):
        return False
    if not signal_exact_identities({pid:str(item.get("start_time",""))},signal.SIGTERM):
        return False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snapshot = process_snapshot(pid)
        if snapshot is None or str(snapshot["state"]).startswith("Z"):
            return True
        time.sleep(0.1)
    if not signal_exact_identities({pid:str(item.get("start_time",""))},signal.SIGKILL):
        return False
    time.sleep(0.2)
    snapshot = process_snapshot(pid)
    return snapshot is None or str(snapshot["state"]).startswith("Z")


def docker_residual(project: str) -> Optional[Dict[str, int]]:
    commands = {
        "containers": ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
        "networks": ["docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"],
        "volumes": ["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"],
    }
    result = {}
    for name, command in commands.items():
        try:
            check = run_bounded_command(command,timeout=20,output_limit=MAX_DOCKER_CONTROL_OUTPUT_BYTES)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if check.returncode:
            return None
        result[name] = len(check.stdout.splitlines())
    return result


def docker_identity_valid(item: Dict[str, object]) -> bool:
    if not isinstance(item.get("project"), str) or not isinstance(item.get("workdir"), str):
        return False
    files = item.get("files")
    if not isinstance(files, list) or not files or any(not isinstance(path, str) for path in files):
        return False
    volumes = item.get("volumes")
    if volumes is not None and (
        not isinstance(volumes, list)
        or any(not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", name) for name in volumes)
    ):
        return False
    payload = {"project": item["project"], "workdir": item["workdir"], "files": files}
    if volumes is not None:
        payload["volumes"] = volumes
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return item.get("identity_sha256") == hashlib.sha256(data).hexdigest()


def contract_values() -> Dict[str, str]:
    if not CONTRACT_PATH.is_file():
        return {}
    text = boundedio.read_text(CONTRACT_PATH,label="requirement contract")
    result: Dict[str, str] = {}
    for field in CONTRACT_FIELDS:
        matches = re.findall(rf"^- {re.escape(field)}:\s*(.*?)\s*$", text, re.MULTILINE)
        if len(matches) == 1:
            result[field] = matches[0].strip()
    return result


def contract_errors(require_approved: bool = False, expected_environment: str = "") -> List[str]:
    values = contract_values()
    errors = []
    for field in CONTRACT_FIELDS:
        value = values.get(field, "")
        if field == "Production provider target" and expected_environment in {"local", "test"} and not value:
            continue
        if not value or value.upper() == "PENDING" or "{{" in value or "<" in value:
            if field not in {"Human decisions", "Clarified"}:
                errors.append(f"requirement contract field is unresolved: {field}")
    if require_approved and values.get("Clarified") != "true":
        errors.append("requirement contract must say Clarified: true")
    if require_approved and not values.get("Human decisions", "").startswith("user:"):
        errors.append("requirement contract must record a user decision")
    environment = values.get("Target environment", "")
    if environment and environment not in {"local", "test", "production"}:
        errors.append("requirement contract Target environment is invalid")
    if expected_environment and environment != expected_environment:
        errors.append("requirement contract Target environment must match TASK.json")
    target = values.get("Production provider target", "")
    if environment == "production" and (not target or target.upper() == "PENDING" or target == "none"):
        errors.append("production requirement contract needs a configured provider target")
    if environment in {"local", "test"} and target not in {"", "none"}:
        errors.append("non-production requirement contract must set Production provider target to none")
    return errors


def contract_with_decision(source: str) -> Tuple[bytes, str]:
    text = boundedio.read_text(CONTRACT_PATH,label="requirement contract")
    for field, value in (("Human decisions", source), ("Clarified", "true")):
        text, count = re.subn(rf"^- {re.escape(field)}:\s*.*$", f"- {field}: {value}", text, count=1, flags=re.MULTILINE)
        if count != 1:
            raise SystemExit(f"requirement contract field must occur exactly once: {field}")
    data = text.encode()
    return data, hashlib.sha256(data).hexdigest()


def validate_production_provider_target(value: object, config: Dict[str, object]) -> Dict[str, object]:
    if not isinstance(value, dict) or set(value) != PRODUCTION_PROVIDER_TARGET_FIELDS:
        raise SystemExit("production provider target has invalid fields")
    checks = value.get("required_status_checks")
    reviewers = value.get("min_required_reviewers")
    patterns = config.get("branches", {}).get("production", []) if isinstance(config.get("branches"), dict) else []
    if (
        value.get("schema") != "agent-production-provider-target/v1"
        or not all(isinstance(value.get(key), str) and str(value.get(key)).strip() for key in (
            "provider", "repository", "default_branch", "test_environment", "production_environment",
        ))
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", str(value.get("repository", "")))
        or not isinstance(patterns, list)
        or not any(isinstance(pattern, str) and fnmatch.fnmatch(str(value.get("default_branch", "")), pattern) for pattern in patterns)
        or not isinstance(checks, list) or not checks or len(set(checks)) != len(checks)
        or not all(isinstance(item, str) and item.strip() for item in checks)
        or not isinstance(reviewers, int) or isinstance(reviewers, bool) or not 1 <= reviewers <= 20
    ):
        raise SystemExit("production provider target is malformed or weaker than configured production policy")
    return value


def production_target_from_contract(config: Dict[str, object], *, required: bool) -> Optional[Dict[str, object]]:
    raw = contract_values().get("Production provider target", "")
    if not required:
        if raw not in {"", "none"}:
            raise SystemExit("non-production requirement contract must not configure a production provider target")
        return None
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise SystemExit("production provider target must be canonical JSON configured during clarification") from error
    target = validate_production_provider_target(value, config)
    canonical = json.dumps(target, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if raw != canonical:
        raise SystemExit("production provider target in the requirement contract is not canonical JSON")
    return target


def command_configure_production_provider(args: argparse.Namespace) -> int:
    if not args.source.startswith("user:"):
        raise SystemExit("production provider target source must start with user:")
    task = load_json(TASK_PATH)
    config = load_json(CONFIG_PATH)
    if (
        task.get("phase") != "clarification" or task.get("status") != "waiting_human"
        or task.get("requirements_clarified") is not False
        or task.get("environment") != "production" or task.get("deployment_requested") is not True
    ):
        raise SystemExit("production provider target can be configured only for a waiting production clarification")
    requested = Path(args.target).expanduser()
    path = (AGENT_DIR.parent / requested).resolve() if not requested.is_absolute() else requested.resolve()
    try:
        path.relative_to(AGENT_DIR.parent.resolve())
    except ValueError:
        raise SystemExit("production provider target file must stay inside the project")
    if not path.is_file() or path.is_symlink():
        raise SystemExit("production provider target file is missing or unsafe")
    target = validate_production_provider_target(load_json(path), config)
    canonical = json.dumps(target, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    text = boundedio.read_text(CONTRACT_PATH,label="requirement contract")
    text, count = re.subn(
        r"^- Production provider target:\s*.*$",
        f"- Production provider target: {canonical}", text, count=1, flags=re.MULTILINE,
    )
    if count != 1:
        raise SystemExit("requirement contract Production provider target field must occur exactly once")
    atomic_write(CONTRACT_PATH, text)
    preview = text
    for field, value in (("Human decisions", args.source), ("Clarified", "true")):
        preview, changed = re.subn(
            rf"^- {re.escape(field)}:\s*.*$", f"- {field}: {value}", preview,
            count=1, flags=re.MULTILINE,
        )
        if changed != 1:
            raise SystemExit(f"requirement contract field must occur exactly once: {field}")
    digest = hashlib.sha256(preview.encode()).hexdigest()
    print(f"PRODUCTION PROVIDER TARGET CONFIGURED; REQUIREMENT APPROVAL DIGEST sha256={digest}")
    return 0


def new_contract_bytes(title: str, environment: str) -> bytes:
    return f"""# Requirement Contract

- Goal: PENDING
- Users: PENDING
- Success: PENDING
- In scope: PENDING
- Out of scope: PENDING
- Constraints: PENDING
- Data and permissions: PENDING
- Target environment: {environment}
- Context transport: native
- Acceptance: PENDING
- Provenance: user request: {title}
- Production provider target: {"PENDING" if environment == "production" else "none"}
- Human decisions: pending
- Clarified: false
""".encode()


def stage_bytes(task: Dict[str, object]) -> bytes:
    """Return the deterministic TASK projection used by workflowctl."""
    mode = str(task["mode"])
    accepted = task.get("accepted_nodes", [])
    last = max(accepted) if isinstance(accepted, list) and accepted else "none"
    gate = "required" if mode == "release" else "not_applicable"
    reason = "strict release gate is required for release mode" if mode == "release" else f"{mode} mode uses targeted acceptance and has no release live gate"
    return f"""# AI Coding Stage Index

- Pipeline version: 2.0
- Task: {task['title']}
- Task type: {task['task_type']}
- Complexity: {task['complexity']}
- Mode: {mode}
- Current node: {task.get('current_node')}
- Status: {task['status']}
- Last accepted node: {last}
- Release gate: {gate}
- Release gate reason: {reason}
- Next action: {task['next_action']}
- Updated: {task.get('updated')}

## Input provenance
- Requirement source: {task.get('requirement_source')}

## Assumptions requiring confirmation
- {task.get('open_questions') or 'None.'}

## Gate status
- Requirement clarified: {str(task.get('requirements_clarified')).lower()}

## Rollback ledger
- Entries: {len(task.get('rollback_ledger', []))}

## Canonical outputs
- `.agent/state/TASK.json`
""".encode("utf-8")


def write_stage(task: Dict[str, object], current_node: object = None, last_node: object = None, status: str = "", next_action: str = "") -> None:
    atomic_write(STAGE_PATH,stage_bytes(task).decode("utf-8"))


def branch_allowed(branch: str, patterns: List[str]) -> bool:
    return any(fnmatch.fnmatch(branch, pattern) for pattern in patterns)


def current_git_branch() -> str:
    try:
        result = run_bounded_command(
            ["git","branch","--show-current"],cwd=AGENT_DIR.parent,timeout=5,
            output_limit=64*1024,stderr_to_stdout=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def required_mode(environment: str, files: int, risk_flags: Dict[str, object], task_type: str, complexity: str) -> str:
    return workflow_state.required_mode(environment, files, risk_flags, task_type, complexity)


def usage_observer_policy(config: Dict[str, object]) -> Dict[str, object]:
    observer = config.get("agent_control", {}).get("usage_observer")
    if not isinstance(observer, dict) or set(observer) != set(USAGE_OBSERVER_POLICY):
        raise SystemExit("host usage observer policy is missing or malformed")
    if any(observer.get(key) != value for key, value in USAGE_OBSERVER_POLICY.items() if key != "signed_adapter"):
        raise SystemExit("host usage observer policy weakens fail-closed defaults")
    return observer


def parse_usage_receipt(
    path: Path, task: Dict[str, object], config: Dict[str, object], require_current: bool = True
) -> Dict[str, object]:
    try:
        data,receipt_identity=humandecision.receipt_snapshot(path)
        value=json.loads(data.decode("utf-8"))
    except (OSError,UnicodeError,json.JSONDecodeError) as error:
        raise SystemExit(f"invalid measured usage receipt: {error}")
    required = {
        "schema", "receipt_id", "provider", "authority", "model", "unit",
        "task", "observed_at", "coverage", "usage",
    }
    if set(value) != required or value.get("schema") != "agent-usage-receipt/v2":
        raise SystemExit("measured usage receipt must use the exact agent-usage-receipt/v2 schema")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", str(value.get("receipt_id", ""))):
        raise SystemExit("measured usage receipt has an invalid receipt_id")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{2,64}", str(value.get("provider", ""))):
        raise SystemExit("measured usage receipt has an invalid provider")
    task_binding = value.get("task")
    if not isinstance(task_binding, dict) or set(task_binding) != {"title", "mode"}:
        raise SystemExit("measured usage receipt task binding is invalid")
    if task_binding != {"title": task.get("title"), "mode": task.get("mode")}:
        raise SystemExit("measured usage receipt belongs to a different task or mode")
    if (
        value.get("authority") != "provider-signed-host-usage"
        or value.get("model") != config.get("agent_control", {}).get("default_model")
        or value.get("unit") != "tokens"
    ):
        raise SystemExit("measured usage receipt authority, model or unit is invalid")
    try:
        observed = dt.datetime.fromisoformat(str(value.get("observed_at", "")).replace("Z", "+00:00"))
    except ValueError:
        raise SystemExit("measured usage receipt observed_at must be ISO-8601")
    if observed.tzinfo is None:
        raise SystemExit("measured usage receipt observed_at must include a timezone")
    observer = usage_observer_policy(config)
    age = (dt.datetime.now(dt.timezone.utc) - observed.astimezone(dt.timezone.utc)).total_seconds()
    if age < -30 or (require_current and age > int(observer["max_receipt_age_seconds"])):
        raise SystemExit("measured usage receipt is stale or future-dated")
    coverage = value.get("coverage")
    if (
        not isinstance(coverage, dict)
        or set(coverage) != {"checkpoint_sequence", "checkpoint_sha256", "semantics"}
        or coverage.get("semantics") != "cumulative"
        or not isinstance(coverage.get("checkpoint_sequence"), int)
        or isinstance(coverage.get("checkpoint_sequence"), bool)
        or coverage.get("checkpoint_sequence", 0) < 1
        or re.fullmatch(r"[0-9a-f]{64}", str(coverage.get("checkpoint_sha256", ""))) is None
    ):
        raise SystemExit("measured usage receipt coverage is invalid")
    if require_current:
        context = load_json(CONTEXT_PATH)
        checkpoint = context.get("checkpoint")
        if (
            not isinstance(checkpoint, dict)
            or coverage.get("checkpoint_sequence") != checkpoint.get("sequence")
            or coverage.get("checkpoint_sha256") != hashlib.sha256(boundedio.read_bytes(CONTEXT_PATH,label="context capsule")).hexdigest()
        ):
            raise SystemExit("measured usage receipt does not cover the current checkpoint")
        checkpoint_at = dt.datetime.fromisoformat(str(checkpoint.get("updated_at", "")))
        if checkpoint_at.tzinfo is None or observed < checkpoint_at.astimezone(dt.timezone.utc):
            raise SystemExit("measured usage receipt predates the checkpoint it claims to cover")
    usage = value.get("usage")
    usage_keys = {"input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "total_tokens"}
    if not isinstance(usage, dict) or set(usage) != usage_keys:
        raise SystemExit("measured usage receipt has an invalid usage object")
    if any(not isinstance(usage[key], int) or isinstance(usage[key], bool) or usage[key] < 0 for key in usage_keys):
        raise SystemExit("measured usage receipt token values must be non-negative integers")
    if usage["total_tokens"] != usage["input_tokens"] + usage["output_tokens"]:
        raise SystemExit("measured total_tokens must equal input_tokens plus output_tokens")
    if usage["cached_input_tokens"] > usage["input_tokens"] or usage["reasoning_tokens"] > usage["output_tokens"]:
        raise SystemExit("measured usage sub-counts exceed their parent counts")
    digest = hashlib.sha256(data).hexdigest()
    expected = AGENT_DIR / "state" / "evidence" / "usage-receipts" / f"{digest}.json"
    if path.resolve() != expected.resolve():
        raise SystemExit("host usage receipt must be stored at its content-addressed evidence path")
    adapter = humandecision.adapter_path(AGENT_DIR.parent.resolve(), observer.get("signed_adapter"), required_operations=("verify-usage",))
    verified=humandecision.run_adapter(adapter,["verify-usage"],required_operations=("verify-usage",),timeout=30,receipt_raw=data)
    if verified.returncode or verified.stdout.strip() != f"VERIFIED HOST USAGE sha256={digest}":
        raise SystemExit("provider-owned host usage adapter rejected the receipt")
    after_data,after_identity=humandecision.receipt_snapshot(path)
    if after_identity!=receipt_identity or after_data!=data:
        raise SystemExit("host usage receipt changed during provider verification")
    return {
        "path": str(path.relative_to(AGENT_DIR.parent.resolve())), "sha256": digest, "bytes": len(data),
        "schema": value["schema"], "receipt_id": value["receipt_id"],
        "provider": value["provider"], "observed_at": value["observed_at"],
        "authority": value["authority"], "model": value["model"], "unit": value["unit"],
        "task": task_binding, "coverage": dict(coverage), "usage": dict(usage),
        "total_tokens": usage["total_tokens"], "semantics": "cumulative",
        "adapter_path": str(adapter), "adapter_sha256": hashlib.sha256(boundedio.read_bytes(adapter,label="provider adapter")).hexdigest(),
    }


def budget_snapshot(task: Dict[str, object], config: Dict[str, object]) -> Dict[str, object]:
    try:
        ledger = load_json(AGENTS_PATH) if AGENTS_PATH.is_file() else None
        unified = total_budget.snapshot(task, config, ledger)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise SystemExit(f"unified Token budget is invalid: {error}")
    policy = config.get("context", {})
    return {
        "state": unified["state"], "mode": unified["mode"], "budget": unified["budget"],
        "tokens": unified["root_tokens"], "reserved_reference_tokens": unified["reference_tokens"],
        "child_reserved_tokens": unified["child_reserved_tokens"],
        "child_settled_tokens": unified["child_settled_tokens"],
        "child_components": unified["child_components"],
        "consumed": unified["consumed_tokens"], "remaining": unified["remaining_tokens"],
        "over_budget": unified["over_budget_tokens"], "ratio": unified["ratio"],
        "assurance": unified["assurance"],
        "thresholds": {
            "soft": float(policy.get("soft_budget_ratio", 0.6)),
            "compact": float(policy.get("compact_budget_ratio", 0.75)),
            "hard": float(policy.get("hard_budget_ratio", 0.9)),
        },
    }


def context_usage_snapshot(task: Dict[str, object], config: Dict[str, object]) -> Dict[str, object]:
    """Return the fail-closed current-checkpoint estimate used for expansion gates."""
    invalid = {"valid": False, "state": "hard_blocked", "estimated_tokens": None}
    try:
        context = load_json(CONTEXT_PATH)
        checkpoint = context.get("checkpoint")
        freshness = context.get("usage_freshness")
        if (
            context.get("schema") != "agent-context/v2"
            or context.get("task_invariant_sha256") != contexttx.contextctl.invariant_sha256(task)
            or not isinstance(checkpoint, dict)
            or not isinstance(freshness, dict)
            or set(freshness) != {
                "schema", "checkpoint_sequence", "task_invariant_sha256", "coverage",
                "source", "estimated_tokens", "observed_at",
            }
            or freshness.get("schema") != "agent-context-usage/v1"
            or freshness.get("checkpoint_sequence") != checkpoint.get("sequence")
            or freshness.get("task_invariant_sha256") != context.get("task_invariant_sha256")
            or freshness.get("coverage") != "through-current-checkpoint"
            or freshness.get("source") != "explicit-estimate"
            or freshness.get("observed_at") != checkpoint.get("updated_at")
            or not isinstance(freshness.get("estimated_tokens"), int)
            or isinstance(freshness.get("estimated_tokens"), bool)
            or int(freshness.get("estimated_tokens", 0)) <= 0
        ):
            return invalid
        estimate = int(freshness["estimated_tokens"])
        references = task.get("loaded_references", [])
        reserved = sum(int(item.get("estimated_tokens", 0)) for item in references if isinstance(item, dict)) if isinstance(references, list) else 0
        budget = int(config.get("routing", {}).get("modes", {}).get(str(task.get("mode")), {}).get("token_budget", 0))
        if budget <= 0:
            return invalid
        ratio = (estimate + reserved) / budget
        policy = config.get("context", {})
        if ratio >= float(policy.get("hard_budget_ratio", 0.9)):
            state = "hard_blocked"
        elif ratio >= float(policy.get("compact_budget_ratio", 0.75)):
            state = "must_compact"
        elif ratio >= float(policy.get("soft_budget_ratio", 0.6)):
            state = "soft"
        else:
            state = "ok"
        return {
            "valid": True, "state": state, "estimated_tokens": estimate,
            "reserved_reference_tokens": reserved, "ratio": round(ratio, 6),
            "checkpoint_sequence": checkpoint.get("sequence"), "source": "explicit-estimate",
        }
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return invalid


def effective_budget_snapshot(task: Dict[str, object], config: Dict[str, object]) -> Dict[str, object]:
    base = budget_snapshot(task, config)
    freshness = context_usage_snapshot(task, config)
    if not freshness.get("valid"):
        return {**base, "state": "hard_blocked", "task_budget_state": base["state"], "context_usage": freshness}
    combined_task = copy.deepcopy(task)
    combined_task["tokens_used"] = max(
        int(task.get("tokens_used", 0)), int(freshness.get("estimated_tokens", 0)),
    )
    combined = budget_snapshot(combined_task, config)
    return {
        **combined,
        "task_budget_state": base["state"],
        "context_usage": freshness,
        "combined_active_root_tokens": combined_task["tokens_used"],
    }


def bounded_terminal_closure(task: Optional[Dict[str, object]]) -> bool:
    return bool(
        isinstance(task, dict)
        and task.get("status") == "ready_to_complete"
        and task.get("current_node") == 7
        and task.get("accepted_nodes") == list(range(8))
    )


def hard_repair_interval(task: Dict[str, object]) -> Optional[tuple[int, int]]:
    """Merge a contiguous hot rollback chain into one existing-scope interval."""
    rollback = task.get("rollback_ledger")
    failures = task.get("failure_ledger")
    if (
        not isinstance(rollback, list)
        or not rollback
        or not isinstance(failures, dict)
    ):
        return None
    receipts: List[Dict[str, object]] = []
    for item in reversed(rollback):
        if not isinstance(item, dict):
            break
        start, end = item.get("to"), item.get("from")
        count = failures.get(item.get("signature"))
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or not 0 < count < 3
        ):
            break
        if receipts and start != receipts[-1]["from"]:
            break
        receipts.append(item)
    if not receipts:
        return None
    return int(receipts[0]["to"]), int(receipts[-1]["from"])


def bounded_hard_repair(task: Optional[Dict[str, object]]) -> bool:
    if not isinstance(task, dict) or task.get("status") != "in_progress":
        return False
    current = task.get("current_node")
    interval = hard_repair_interval(task)
    if not isinstance(current, int) or isinstance(current, bool) or interval is None:
        return False
    start, end = interval
    return start <= current <= end


def budget_action_allowed(
    snapshot: Dict[str, object],
    action: str,
    task: Optional[Dict[str, object]] = None,
) -> bool:
    known = {
        "spawn-agent", "spawn-review-agent", "cross-review", "load-reference",
        "route-templates", "reroute-existing", "render-artifact", "finish-node",
        "acceptance", "replay", "delivery", "rollback", "return-node", "complete",
        "managed-run", "tool-run", "compact", "split", "request-decision", "cleanup", "status", "validate",
    }
    if action not in known:
        return False
    state = snapshot["state"]
    if state == "ok":
        return True
    if state == "soft":
        return action not in {"spawn-agent", "load-reference"}
    recovery = {"compact", "split", "request-decision", "cleanup", "status", "validate", "rollback", "return-node"}
    if state == "hard_blocked" and bounded_terminal_closure(task):
        # No new scope is authorized: these two actions only bind the already
        # accepted node set into its retrospective and terminal checkpoint.
        recovery.update({"render-artifact", "complete"})
    if state == "hard_blocked" and bounded_hard_repair(task):
        # return-node is only a real recovery exit if the bounded root-cause
        # repair can be executed. Keep it on the existing route and let the
        # three-strike ledger stop the third recurrence.
        recovery.update({
            "reroute-existing", "render-artifact", "finish-node",
            "acceptance", "replay", "managed-run", "tool-run",
        })
    if state == "must_compact":
        recovery.update({
            "finish-node", "acceptance", "spawn-review-agent", "cross-review", "replay",
            "delivery", "complete", "reroute-existing", "render-artifact", "managed-run", "tool-run",
        })
    return action in recovery


def verified_compact_handoff(task: Dict[str, object]) -> bool:
    try:
        result=run_bounded_command(
            [sys.executable,str(CONTEXT_TOOL),"check","--quiet"],cwd=AGENT_DIR.parent,timeout=120,
        )
        context=load_json(CONTEXT_PATH); resume=context.get("resume")
        freshness=context.get("usage_freshness",{})
        estimate=int(freshness.get("estimated_tokens",0)) if isinstance(freshness,dict) else 0
        state=contexttx.contextctl.effective_budget_state(
            load_json(CONFIG_PATH),task,estimate,
        )
        expected=contexttx.contextctl.resume_contract(
            task,contexttx.contextctl.invariant_sha256(task),state,
        )
        compaction=context.get("compaction",{}); budget=compaction.get("budget_snapshot",{}) if isinstance(compaction,dict) else {}
        return result.returncode==0 and resume==expected and isinstance(budget,dict) and budget.get("watermark")=="compact"
    except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError,subprocess.TimeoutExpired,SystemExit):
        return False


def enforce_budget_action(task: Dict[str, object], config: Dict[str, object], action: str) -> Dict[str, object]:
    snapshot = effective_budget_snapshot(task, config)
    if not budget_action_allowed(snapshot, action, task):
        raise SystemExit(
            f"budget gate blocked action={action} state={snapshot['state']}; compact, split or request a decision"
        )
    recovery={"compact","split","request-decision","cleanup","status","validate","rollback","return-node"}
    if snapshot["state"]=="must_compact" and action not in recovery and not verified_compact_handoff(task):
        raise SystemExit(f"budget gate blocked action={action} until a verified phase handoff binds the current task")
    return snapshot


def strict_bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def valid_model_id(value: object) -> bool:
    return isinstance(value,str) and value.lower() not in {"none","null","unset","unselected","default","model","model-id"} and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,127}",value) is not None


def task_skill_activation_errors(task):
    errors=[]; receipt=task.get("skill_activation")
    required={"schema","path","sha256","bytes","activation_sha256","lock_sha256","skill_ids","builtin_skill_ids"}
    if not isinstance(receipt,dict) or set(receipt)!=required or receipt.get("schema")!="agent-task-skill-activation/v2" or receipt.get("path")!=".agent/state/SKILL_ACTIVATION.json":
        return ["task Skill activation receipt is missing or invalid"]
    try: raw=_read_project_regular_file_no_links(AGENT_DIR.parent,Path(receipt["path"]),4*1024*1024)
    except SystemExit: return ["task Skill activation snapshot is missing or unsafe"]
    if len(raw)>4*1024*1024 or len(raw)!=receipt.get("bytes") or hashlib.sha256(raw).hexdigest()!=receipt.get("sha256"):
        return ["task Skill activation snapshot bytes drifted"]
    try: payload=json.loads(raw)
    except (UnicodeError,json.JSONDecodeError): return ["task Skill activation snapshot is malformed"]
    payload_required={"schema","task_generation_id","blueprint_sha256","lock_sha256","skills","builtins","activation_sha256"}
    if not isinstance(payload,dict) or set(payload)!=payload_required or payload.get("schema")!=receipt["schema"]:
        return ["task Skill activation snapshot schema is invalid"]
    unsigned={key:value for key,value in payload.items() if key!="activation_sha256"}
    activation_sha=hashlib.sha256(json.dumps(unsigned,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    if payload.get("activation_sha256")!=activation_sha or receipt.get("activation_sha256")!=activation_sha or payload.get("task_generation_id")!=task.get("task_generation_id") or payload.get("lock_sha256")!=receipt.get("lock_sha256"):
        return ["task Skill activation binding is invalid"]
    skills=payload.get("skills")
    if not isinstance(skills,list) or len(skills)>64: return ["task Skill activation set is invalid"]
    ids=[]
    for item in skills:
        if not isinstance(item,dict) or set(item)!={"id","status","bundle_sha256","matched_capabilities","documents"} or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}",str(item.get("id",""))) is None or re.fullmatch(r"[0-9a-f]{64}",str(item.get("bundle_sha256",""))) is None or item.get("status") not in {"active","deprecated"} or not isinstance(item.get("matched_capabilities"),list):
            return ["task Skill activation entry is invalid"]
        docs=item.get("documents")
        if not isinstance(docs,list) or [doc.get("path") if isinstance(doc,dict) else None for doc in docs]!=["SKILL.md","LICENSE.txt"]:
            return ["task Skill activation document set is invalid"]
        for doc in docs:
            if set(doc)!={"path","sha256","bytes","content"} or not isinstance(doc.get("content"),str): return ["task Skill activation document is invalid"]
            data=doc["content"].encode()
            if len(data)!=doc.get("bytes") or hashlib.sha256(data).hexdigest()!=doc.get("sha256"): return ["task Skill activation document bytes drifted"]
        ids.append(item["id"])
    if ids!=sorted(set(ids)) or ids!=receipt.get("skill_ids"): return ["task Skill activation identifiers drifted"]
    builtins=payload.get("builtins"); builtin_ids=[]
    if not isinstance(builtins,list) or len(builtins)>128: return ["built-in Skill activation set is invalid"]
    try: current_builtins=capture_builtin_skills()
    except (SystemExit,OSError,ValueError,TypeError): return ["built-in Skill managed inventory is missing or unsafe"]
    if builtins!=current_builtins: return ["built-in Skill activation differs from the exact managed source inventory"]
    for item in builtins:
        if not isinstance(item,dict) or set(item)!={"id","bundle_sha256","files"} or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}",str(item.get("id",""))) is None or not isinstance(item.get("files"),list) or not item["files"]:
            return ["built-in Skill activation entry is invalid"]
        records=[]
        for document in item["files"]:
            if not isinstance(document,dict) or set(document)!={"path","sha256","bytes","mode","content_base64"}: return ["built-in Skill activation file is invalid"]
            relative=Path(str(document.get("path","")))
            if relative.is_absolute() or any(part in {"",".",".."} for part in relative.parts): return ["built-in Skill activation path is unsafe"]
            try: data=base64.b64decode(document["content_base64"],validate=True)
            except (ValueError,TypeError): return ["built-in Skill activation content is invalid"]
            if len(data)!=document.get("bytes") or hashlib.sha256(data).hexdigest()!=document.get("sha256") or not isinstance(document.get("mode"),int): return ["built-in Skill activation bytes drifted"]
            try: current=_read_project_regular_file_no_links(AGENT_DIR.parent,Path(".agent/skills")/item["id"]/relative,4*1024*1024)
            except SystemExit: return ["built-in Skill source is missing or unsafe"]
            source_path=AGENT_DIR/"skills"/item["id"]/relative
            if current!=data or stat.S_IMODE(source_path.stat().st_mode)!=document["mode"]: return ["built-in Skill source differs from task activation"]
            records.append({key:document[key] for key in ("path","sha256","bytes","mode")})
        if hashlib.sha256(json.dumps(records,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()!=item.get("bundle_sha256"): return ["built-in Skill bundle binding is invalid"]
        builtin_ids.append(item["id"])
    if builtin_ids!=sorted(set(builtin_ids)) or builtin_ids!=receipt.get("builtin_skill_ids"): return ["built-in Skill activation identifiers drifted"]
    return errors


def command_verify_builtins() -> int:
    task=load_json(TASK_PATH)
    errors=task_skill_activation_errors(task)
    if errors: raise SystemExit("built-in Skill activation validation failed: "+errors[0])
    activation=load_json(AGENT_DIR/"state/SKILL_ACTIVATION.json")
    print(f"BUILTIN SKILLS VERIFIED activation_sha256={activation['activation_sha256']} count={len(activation['builtins'])}")
    return 0


def command_validate() -> int:
    config = load_json(CONFIG_PATH)
    task = load_json(TASK_PATH)
    runtime = load_json(RUNTIME_PATH)
    errors: List[str] = []
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",str(task.get("task_generation_id",""))) is None:
        errors.append("task generation identifier is missing or invalid")
    errors.extend(task_skill_activation_errors(task))
    if config.get("schema") != "agent-workflow/v2":
        errors.append("config schema must be agent-workflow/v2")
    runtime_policy=config.get("runtime")
    if not isinstance(runtime_policy,dict) or not strict_bounded_int(runtime_policy.get("term_timeout_seconds"),1,60):
        errors.append("runtime term_timeout_seconds must be an integer in 1..60")
    expected_test_modes = {
        "fast": (0, "targeted", 5, 1),
        "standard": (0, "impact", 15, 1),
        "release": (1, "impact-plus-one-full-chain", 45, 1),
    }
    configured_modes = config.get("routing", {}).get("modes", {})
    for mode_name, expected in expected_test_modes.items():
        mode_policy = configured_modes.get(mode_name, {}) if isinstance(configured_modes, dict) else {}
        observed = tuple(mode_policy.get(key) for key in (
            "clean_reruns", "test_strategy", "wall_time_minutes", "max_automatic_test_attempts",
        ))
        if observed != expected:
            errors.append(f"{mode_name} test routing policy is invalid")
    expected_testing = {
        "failure_classes": ["candidate", "test", "infrastructure"],
        "preflight_before_full_chain": True,
        "reuse_receipts_when_candidate_unchanged": True,
        "reviewers_may_rerun_full_chain": False,
        "full_chain_owner": "integrator",
        "reviewer_targeted_case_limit": 0,
        "preflight_max_seconds": 60,
        "infrastructure_failure_consumes_code_retry": False,
        "resume_from_failed_case": False,
        "max_automatic_full_chain_attempts": 1,
        "budget_registry": ".agent/state/test-budget.json",
        "budget_receipt_dir": ".agent/state/evidence/test-budgets",
        "attempt_classes": ["candidate", "test", "infrastructure"],
    }
    if config.get("testing") != expected_testing:
        errors.append("test execution, receipt reuse, preflight or retry policy is invalid")
    try:
        test_budget = load_json(TEST_BUDGET_PATH)
        if test_budget.get("schema") != "agent-test-budget/v1" or not isinstance(test_budget.get("candidates"), dict):
            raise ValueError("schema")
    except (OSError, ValueError, json.JSONDecodeError):
        errors.append("atomic candidate test budget registry is missing or invalid")
    context_policy = config.get("context", {})
    if isinstance(context_policy, dict):
        transition_increments, legacy_transition_increment = (
            total_budget.transition_increment_policy(config)
        )
        transition_configured = isinstance(
            context_policy.get(total_budget.TRANSITION_INCREMENT_KEY), dict
        ) or isinstance(
            context_policy.get(total_budget.LEGACY_TURN_OVERHEAD_KEY), dict
        )
    else:
        transition_increments, transition_configured = {}, False
        legacy_transition_increment = False
    if (
        not isinstance(context_policy, dict)
        or not isinstance(context_policy.get("max_rollback_entries"), int)
        or isinstance(context_policy.get("max_rollback_entries"), bool)
        or not 1 <= context_policy["max_rollback_entries"] <= 32
        or not isinstance(context_policy.get("max_failure_entries"), int)
        or isinstance(context_policy.get("max_failure_entries"), bool)
        or not 1 <= context_policy["max_failure_entries"] <= 64
        or not isinstance(context_policy.get("max_failure_archive_depth"), int)
        or isinstance(context_policy.get("max_failure_archive_depth"), bool)
        or not 1 <= context_policy["max_failure_archive_depth"] <= 128
    ):
        errors.append("context rollback/failure hot-state or cold-chain limits are invalid")
    if (
        not transition_configured
        or set(transition_increments) != {"fast", "standard", "release"}
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 50
            or (not legacy_transition_increment and value > 1000)
            for value in transition_increments.values()
        )
        or not (
            transition_increments.get("fast", 0)
            <= transition_increments.get("standard", 0)
            <= transition_increments.get("release", 0)
        )
    ):
        errors.append(
            "context transition token increments are missing or invalid "
            "(context.transition_token_increment; deprecated alias "
            "context.automatic_transition_token_increment)"
        )
    errors.extend(total_budget.config_budget_errors(config))
    retention = config.get("evidence_retention")
    if (
        not isinstance(retention, dict)
        or set(retention) != {
            "active_max_bytes", "min_age_hours", "min_archive_bytes", "max_archives",
            "archive_format", "preserve_referenced",
        }
        or not isinstance(retention.get("active_max_bytes"), int)
        or isinstance(retention.get("active_max_bytes"), bool)
        or not 1048576 <= retention["active_max_bytes"] <= 67108864
        or not isinstance(retention.get("min_age_hours"), int)
        or isinstance(retention.get("min_age_hours"), bool)
        or not 0 <= retention["min_age_hours"] <= 8760
        or not isinstance(retention.get("min_archive_bytes"), int)
        or isinstance(retention.get("min_archive_bytes"), bool)
        or not 0 <= retention["min_archive_bytes"] <= retention["active_max_bytes"]
        or not isinstance(retention.get("max_archives"), int)
        or isinstance(retention.get("max_archives"), bool)
        or not 1 <= retention["max_archives"] <= 256
        or retention.get("archive_format") != "deterministic-zip-deflate-v1"
        or retention.get("preserve_referenced") is not True
    ):
        errors.append("evidence retention policy is invalid")
    agent_policy = config.get("agent_control", {})
    transport = config.get("context_transport")
    selected_transport_model = agent_policy.get("default_model") if isinstance(agent_policy, dict) else None
    if not valid_context_transport_policy(transport, selected_transport_model):
        errors.append("optional context transport policy is invalid")
    selected_model=agent_policy.get("default_model") if isinstance(agent_policy,dict) else None
    inactive=task.get("status") in {"idle","accepted"}
    task_model=task.get("selected_model"); completed_model=task.get("completed_model")
    model_binding_invalid=(
        (inactive and (selected_model is not None or task_model is not None))
        or (not inactive and (not valid_model_id(selected_model) or task_model!=selected_model))
        or (task.get("status")=="accepted" and not valid_model_id(completed_model))
        or (task.get("status")!="accepted" and completed_model is not None)
    )
    if (
        not isinstance(agent_policy,dict)
        or model_binding_invalid
        or agent_policy.get("allow_model_fallback") is not False
        or agent_policy.get("context_strategy") != "long-window-capsule"
        or not strict_bounded_int(agent_policy.get("capacity_retry_limit"),0,3)
        or agent_policy.get("inherit_parent_history") is not False
        or agent_policy.get("dispatch_payload_token_limits") != {
            "fast": 0, "standard": 16000, "release": 32000,
        }
        or agent_policy.get("status_request_after_unchanged_checks") != 1
        or not isinstance(agent_policy.get("platform_observer"), dict)
        or set(agent_policy.get("platform_observer", {})) != {
            "source", "automatic_release_trust", "human_verification_required", "signed_adapter",
        }
        or agent_policy.get("platform_observer", {}).get("source") != "orchestrator-tool-transcript"
        or agent_policy.get("platform_observer", {}).get("automatic_release_trust") is not False
        or agent_policy.get("platform_observer", {}).get("human_verification_required") is not True
        or (
            agent_policy.get("platform_observer", {}).get("signed_adapter") is not None
            and not isinstance(agent_policy.get("platform_observer", {}).get("signed_adapter"), str)
        )
        or not isinstance(agent_policy.get("human_decision_observer"), dict)
        or set(agent_policy.get("human_decision_observer", {})) != set(humandecision.POLICY)
        or any(
            agent_policy.get("human_decision_observer", {}).get(key) != value
            for key, value in humandecision.POLICY.items()
            if key not in {"signed_adapter", "allow_current_chat_local_release"}
        )
        or not isinstance(
            agent_policy.get("human_decision_observer", {}).get("allow_current_chat_local_release"), bool
        )
        or not isinstance(agent_policy.get("usage_observer"), dict)
        or set(agent_policy.get("usage_observer", {})) != set(USAGE_OBSERVER_POLICY)
        or any(
            agent_policy.get("usage_observer", {}).get(key) != value
            for key, value in USAGE_OBSERVER_POLICY.items() if key != "signed_adapter"
        )
        or not isinstance(agent_policy.get("provider_preflight_observer"), dict)
        or set(agent_policy.get("provider_preflight_observer", {})) != set(PROVIDER_PREFLIGHT_OBSERVER_POLICY)
        or any(
            agent_policy.get("provider_preflight_observer", {}).get(key) != value
            for key, value in PROVIDER_PREFLIGHT_OBSERVER_POLICY.items() if key != "signed_adapter"
        )
        or not strict_bounded_int(agent_policy.get("platform_limit"),2,64)
        or not strict_bounded_int(agent_policy.get("reserve_root_slots"),1,63)
        or agent_policy.get("reserve_root_slots",64) >= agent_policy.get("platform_limit",0)
        or not strict_bounded_int(agent_policy.get("status_interval_seconds"),1,3600)
        or not strict_bounded_int(agent_policy.get("monitor_grace_seconds"),0,3600)
        or not strict_bounded_int(agent_policy.get("stall_timeout_seconds"),120,1800)
        or agent_policy.get("stall_timeout_seconds",0) <= agent_policy.get("status_interval_seconds",0) + agent_policy.get("monitor_grace_seconds",0)
        or not strict_bounded_int(agent_policy.get("max_redispatch"),0,10)
        or not strict_bounded_int(agent_policy.get("max_fork_turns"),1,20)
        or not strict_bounded_int(agent_policy.get("default_fork_turns"),0,0)
        or not strict_bounded_int(agent_policy.get("inherited_turn_estimated_tokens"),1,1000000)
        or not strict_bounded_int(agent_policy.get("child_system_tool_margin_tokens"),1,1000000)
        or not strict_bounded_int(agent_policy.get("child_output_margin_tokens"),1,1000000)
        or not strict_bounded_int(agent_policy.get("max_task_payload_input_count"),1,1024)
        or not strict_bounded_int(agent_policy.get("max_task_payload_single_bytes"),1024,10485760)
        or not strict_bounded_int(agent_policy.get("max_task_payload_total_bytes"),1024,104857600)
        or agent_policy.get("max_task_payload_total_bytes",0) < agent_policy.get("max_task_payload_single_bytes",0)
        or not strict_bounded_int(agent_policy.get("max_task_payload_estimated_tokens"),256,10000000)
        or not isinstance(agent_policy.get("scheduler"), dict)
        or set(agent_policy.get("scheduler", {})) != {"source", "signed_adapter", "provider_project_id", "provider_repository_id", "automatic_resume", "max_receipt_age_seconds"}
        or agent_policy.get("scheduler", {}).get("source") != "host-scheduler"
        or agent_policy.get("scheduler", {}).get("automatic_resume") is not False
        or any(value is not None and (not isinstance(value,str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}",value) is None) for value in (agent_policy.get("scheduler",{}).get("provider_project_id"),agent_policy.get("scheduler",{}).get("provider_repository_id")))
        or ((agent_policy.get("scheduler",{}).get("signed_adapter") is None) != (agent_policy.get("scheduler",{}).get("provider_project_id") is None or agent_policy.get("scheduler",{}).get("provider_repository_id") is None))
        or not strict_bounded_int(agent_policy.get("scheduler", {}).get("max_receipt_age_seconds"),1,3600)
    ):
        errors.append("child-agent model/context/capacity policy is invalid")
    human_observer = agent_policy.get("human_decision_observer", {})
    if isinstance(human_observer, dict) and human_observer.get("signed_adapter") is not None:
        try:
            humandecision.adapter_path(
                AGENT_DIR.parent.resolve(), human_observer.get("signed_adapter"), required_operations=("health","verify")
            )
        except (SystemExit, OSError, ValueError, TypeError) as error:
            errors.append(f"configured human decision adapter is invalid: {error}")
    usage_observer = agent_policy.get("usage_observer", {})
    if isinstance(usage_observer, dict) and usage_observer.get("signed_adapter") is not None:
        try:
            humandecision.adapter_path(AGENT_DIR.parent.resolve(), usage_observer.get("signed_adapter"), required_operations=("verify-usage",))
        except (SystemExit, OSError, ValueError, TypeError) as error:
            errors.append(f"configured host usage adapter is invalid: {error}")
    provider_observer = agent_policy.get("provider_preflight_observer", {})
    if isinstance(provider_observer, dict) and provider_observer.get("signed_adapter") is not None:
        try:
            provider_adapter = humandecision.adapter_path(AGENT_DIR.parent.resolve(), provider_observer.get("signed_adapter"), required_operations=("health-provider-preflight","verify-provider-preflight"))
            if provider_adapter.name.lower() in {
                "bash", "sh", "zsh", "fish", "env", "python", "python3", "node", "perl", "ruby", "php",
            }:
                raise SystemExit("generic interpreters are not provider preflight verifiers")
        except (SystemExit, OSError, ValueError, TypeError) as error:
            errors.append(f"configured provider preflight adapter is invalid: {error}")
    platform_observer = agent_policy.get("platform_observer", {})
    if isinstance(platform_observer, dict) and platform_observer.get("signed_adapter") is not None:
        try:
            humandecision.adapter_path(AGENT_DIR.parent.resolve(), platform_observer.get("signed_adapter"), required_operations=("verify-platform",))
        except (SystemExit, OSError, ValueError, TypeError) as error:
            errors.append(f"configured platform adapter is invalid: {error}")
    scheduler = agent_policy.get("scheduler", {})
    if isinstance(scheduler, dict) and scheduler.get("signed_adapter") is not None:
        try:
            humandecision.adapter_path(AGENT_DIR.parent.resolve(), scheduler.get("signed_adapter"), required_operations=("consume-scheduler-resume",))
        except (SystemExit, OSError, ValueError, TypeError) as error:
            errors.append(f"configured scheduler adapter is invalid: {error}")
    host_compaction = config.get("context", {}).get("host_compaction_observer", {})
    if isinstance(host_compaction, dict) and host_compaction.get("signed_adapter") is not None:
        try:
            humandecision.adapter_path(AGENT_DIR.parent.resolve(), host_compaction.get("signed_adapter"), required_operations=("verify-host-compaction",))
        except (SystemExit, OSError, ValueError, TypeError) as error:
            errors.append(f"configured host compaction adapter is invalid: {error}")
    if task.get("schema") != "agent-task/v2":
        errors.append("task schema must be agent-task/v2")
    if runtime.get("schema") != "agent-runtime/v2" or not isinstance(runtime.get("baseline"), dict):
        errors.append("runtime schema must be v2 with a captured project-process baseline")
    elif task.get("status") not in {"idle", "accepted"} and runtime["baseline"].get("source") == "template-uninitialized":
        errors.append("active task requires a captured runtime baseline")
    runtime_policy = config.get("runtime", {})
    if not isinstance(runtime_policy, dict) or not valid_host_runner_identity_contract(runtime_policy.get("host_runner_identity")):
        errors.append("host runner identity contract is invalid")
    if not isinstance(runtime_policy, dict) or runtime_policy.get("tool_leases_registry") != ".agent/state/tool-leases.json" or not TOOL_LEASES_PATH.is_file():
        errors.append("bounded foreground tool lease registry is missing or misconfigured")
    _, _, tool_lease_errors = audited_tool_allowances()
    errors.extend(tool_lease_errors)
    for relative in ("INDEX.md", "skills", "templates", "workflows", "policies", "state", "scripts", "assets", "capabilities", "knowledge"):
        if not (AGENT_DIR / relative).exists():
            errors.append(f"missing .agent/{relative}")
    if task.get("phase") not in {"clarification", "idle"} and task.get("requirements_clarified") is not True:
        errors.append("implementation is blocked until requirements_clarified=true")
    if task.get("requirements_clarified") is True and config.get("guardrails_ready") is not True:
        errors.append("project guardrails must be completed before work can leave clarification")
    if config.get("guardrails_ready") is True:
        binding=config.get("project_initialization"); guardrail_path=AGENT_DIR/"policies/PROJECT_GUARDRAILS.md"
        guardrail_data=boundedio.read_bytes(guardrail_path,label="project guardrails") if guardrail_path.is_file() else b""
        if (
            not isinstance(binding,dict) or binding.get("schema")!="agent-project-initialization/v1"
            or binding.get("guardrails_sha256")!=hashlib.sha256(guardrail_data).hexdigest()
            or binding.get("guardrails_bytes")!=len(guardrail_data)
            or not isinstance(binding.get("initialized_at"),str)
        ):
            errors.append("guardrails readiness is not atomically bound to the current policy bytes")
    unrouted_node2 = (
        task.get("requirements_clarified") is True and task.get("current_node") == 2
        and task.get("template_route") in (None,{})
        and task.get("selected_templates") == ["requirement-contract"]
        and task.get("rendered_artifacts") in ([],None)
    )
    if task.get("requirements_clarified") is True and not unrouted_node2:
        errors.extend(contract_errors(require_approved=True, expected_environment=str(task.get("environment", ""))))
        try:
            approved_target = production_target_from_contract(
                config,
                required=task.get("environment") == "production" and task.get("deployment_requested") is True,
            )
            if task.get("production_provider") != approved_target:
                errors.append("TASK production_provider differs from the human-approved requirement contract")
        except (SystemExit, OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            errors.append(f"approved production provider target is invalid: {error}")
        if CONTRACT_PATH.is_file():
            actual_contract_hash = hashlib.sha256(boundedio.read_bytes(CONTRACT_PATH,label="requirement contract")).hexdigest()
            if task.get("requirement_contract_sha256") != actual_contract_hash:
                errors.append("approved requirement contract hash does not match TASK.json")
            requirement = task.get("gate_approvals", {}).get("requirement") if isinstance(task.get("gate_approvals"), dict) else None
            if (
                not isinstance(requirement, dict)
                or requirement.get("artifact_sha256") != actual_contract_hash
                or not humandecision.reverify(
                    AGENT_DIR.parent.resolve(), config, task, gate="requirement",
                    artifact_sha256=actual_contract_hash,
                    source=str(task.get("requirement_source", "")),
                    record=requirement.get("decision_receipt"),
                )
            ):
                errors.append("requirement approval lacks a valid provider-signed human decision receipt")
    metric_keys = {"tokens", "token_source", "child_agents", "peak_children", "tool_calls", "test_runs", "test_failures", "repair_rounds", "user_corrections", "context_compactions", "references_loaded"}
    metrics = task.get("metrics")
    if not isinstance(metrics, dict) or set(metrics) != metric_keys:
        errors.append("TASK.json must contain the complete bounded cost metrics schema")
    elif any(not isinstance(metrics[key], int) or metrics[key] < 0 for key in metric_keys - {"token_source"}) or metrics["token_source"] not in {"measured", "estimated"}:
        errors.append("task cost metrics contain invalid values")
    mode = task.get("mode")
    modes = config.get("routing", {}).get("modes", {}) if isinstance(config.get("routing"), dict) else {}
    if mode not in modes:
        errors.append(f"unknown task mode: {mode}")
    else:
        mode_config = modes[mode]
        if task.get("token_budget") != mode_config.get("token_budget"):
            errors.append("task token_budget must match the active mode")
        references = task.get("loaded_references", [])
        if not isinstance(references, list) or len(references) > mode_config.get("max_loaded_references", 0):
            errors.append("loaded references exceed the active mode budget")
        tokens_used = task.get("tokens_used")
        child_agents_used = task.get("child_agents_used")
        peak_child_agents = task.get("peak_child_agents")
        if not isinstance(tokens_used, int) or tokens_used < 0:
            errors.append("recorded token use must be a non-negative observed value")
        if task.get("token_usage_source") not in {"measured", "estimated"}:
            errors.append("token_usage_source must be measured or estimated")
        if task.get("token_usage_source") == "measured":
            receipt = task.get("usage_receipt", {})
            path = (AGENT_DIR.parent / str(receipt.get("path", ""))).resolve() if isinstance(receipt, dict) else AGENT_DIR.parent / "missing"
            try:
                path.relative_to(AGENT_DIR.parent.resolve())
                parsed_receipt = parse_usage_receipt(path, task, config, require_current=False) if path.is_file() and not path.is_symlink() else None
            except (ValueError, SystemExit):
                parsed_receipt = None
            if not isinstance(receipt, dict) or parsed_receipt != receipt:
                errors.append("measured token usage lacks a valid structured platform receipt")
        usage_receipts = task.get("usage_receipts")
        if not isinstance(usage_receipts, list) or len(usage_receipts) > 8:
            errors.append("host usage receipt history must be a bounded list")
        else:
            receipt_ids = []
            for receipt in usage_receipts:
                path = (AGENT_DIR.parent / str(receipt.get("path", ""))).resolve() if isinstance(receipt, dict) else AGENT_DIR.parent / "missing"
                try:
                    path.relative_to(AGENT_DIR.parent.resolve())
                    parsed = parse_usage_receipt(path, task, config, require_current=False) if path.is_file() and not path.is_symlink() else None
                except (ValueError, SystemExit, OSError, subprocess.TimeoutExpired):
                    parsed = None
                if not isinstance(receipt, dict) or parsed != receipt:
                    errors.append("host usage receipt history contains an unverified receipt")
                    continue
                receipt_ids.append(receipt.get("receipt_id"))
            if len(receipt_ids) != len(set(receipt_ids)):
                errors.append("host usage receipt IDs must be unique")
            if usage_receipts and task.get("usage_receipt") != usage_receipts[-1]:
                errors.append("latest host usage receipt binding is stale")
        expected_budget_state = budget_snapshot(task, config)["state"]
        if task.get("budget_state") != expected_budget_state:
            errors.append("recorded budget_state differs from the computed base budget gate")
        if not isinstance(child_agents_used, int) or child_agents_used < 0:
            errors.append("child_agents_used must be a non-negative cumulative count")
        # This is a cumulative historical metric. A template migration may
        # legitimately lower the active concurrency policy below an earlier
        # observed peak. Runtime dispatch and record-usage enforce the current
        # limit; structure validation must not rewrite or reject honest history.
        if not isinstance(peak_child_agents, int) or peak_child_agents < 0:
            errors.append("peak child-agent concurrency must be a non-negative historical value")
        if isinstance(child_agents_used, int) and isinstance(peak_child_agents, int) and child_agents_used < peak_child_agents:
            errors.append("cumulative child-agent count cannot be below peak concurrency")
        references = task.get("loaded_references")
        if not isinstance(references, list):
            errors.append("loaded_references must be a list")
        else:
            root = AGENT_DIR.parent.resolve()
            for item in references:
                if not isinstance(item, dict) or set(item) != {"path", "sha256", "bytes", "estimated_tokens", "purpose", "phase"}:
                    errors.append("each loaded reference needs path, sha256, bytes, estimated_tokens, purpose and phase")
                    continue
                path = (root / str(item["path"])).resolve()
                try:
                    path.relative_to(root)
                except ValueError:
                    errors.append(f"loaded reference escapes project: {item['path']}")
                    continue
                if not path.is_file() or path.is_symlink():
                    errors.append(f"loaded reference is missing: {item['path']}")
                    continue
                data = boundedio.read_bytes(path,label="agent file")
                if hashlib.sha256(data).hexdigest() != item["sha256"] or len(data) != item["bytes"] or (len(data) + 3) // 4 != item["estimated_tokens"]:
                    errors.append(f"loaded reference metadata drifted: {item['path']}")
    environment = str(task.get("environment", ""))
    environment_policy = config.get("environments", {}).get(environment, {})
    deployment_requested = task.get("deployment_requested")
    if not isinstance(deployment_requested, bool):
        errors.append("deployment_requested must be boolean")
    elif deployment_requested and environment_policy.get("deploy_allowed") is not True:
        errors.append(f"deployment is not allowed in {environment}")
    elif environment_policy.get("deploy_required") is True and not deployment_requested:
        errors.append(f"deployment is required for {environment}")
    if environment == "production" and mode != "release":
        errors.append("production work requires release mode")
    if environment == "test" and mode == "fast":
        errors.append("test environment work requires at least standard mode")
    branch = str(task.get("branch", "unversioned"))
    if task.get("environment")=="local" and branch!="unversioned":
        actual_branch=current_git_branch(); patterns=config.get("branches",{}).get("local",[])
        if not actual_branch or actual_branch!=branch or not branch_allowed(branch,patterns): errors.append(f"branch {branch} is not allowed for local development")
    if task.get("environment") in {"test", "production"}:
        patterns = config.get("branches", {}).get(task["environment"], [])
        actual_branch = current_git_branch()
        if branch == "unversioned" or not actual_branch or actual_branch != branch or not branch_allowed(branch, patterns):
            errors.append(f"branch {branch} is not allowed for {task['environment']}")
    risk_flags = task.get("risk_flags")
    expected_risk_keys = {"deploy", "data_risk", "cross_system", "uncertain", "security", "compliance", "migration", "irreversible", "external_impact"}
    files = task.get("files")
    if not isinstance(risk_flags, dict) or set(risk_flags) != expected_risk_keys or any(not isinstance(value, bool) for value in risk_flags.values()):
        errors.append("TASK.json must record all boolean risk_flags")
    elif not isinstance(files, int) or files < 0:
        errors.append("TASK.json files must be a non-negative integer")
    else:
        minimum_mode = required_mode(str(task.get("environment")), files, risk_flags, str(task.get("task_type")), str(task.get("complexity")))
        rank = {"fast": 0, "standard": 1, "release": 2}
        if mode in rank and rank[mode] < rank[minimum_mode]:
            errors.append(f"task mode {mode} is below required minimum {minimum_mode}")
        if risk_flags["deploy"] != deployment_requested:
            errors.append("risk_flags.deploy must equal deployment_requested")
    context_check=run_bounded_command([sys.executable,str(CONTEXT_TOOL),"check","--quiet"],cwd=AGENT_DIR.parent,timeout=120)
    if context_check.returncode:
        errors.append("context capsule is stale, oversized, incomplete, or awaiting repair review")
    ledger_command = [
        sys.executable, str(AGENT_DIR / "skills" / "manage-agent-team" / "scripts" / "agentledger.py"), "validate"
    ]
    ledger_check=run_bounded_command(ledger_command,cwd=AGENT_DIR.parent,timeout=120)
    if ledger_check.returncode:
        detail = ledger_check.stdout.strip().replace("\n", " | ")[:1200]
        errors.append(
            "agent ledger is invalid or active agents remain after task completion"
            + (f": {detail}" if detail else "")
        )
    if task.get("requirements_clarified") is True:
        template_check=run_bounded_command(
            [sys.executable,str(AGENT_DIR/"scripts"/"templatectl.py"),"validate"],cwd=AGENT_DIR.parent,timeout=120,
        )
        if template_check.returncode:
            errors.append("template selection or rendered artifact state is invalid")
    elif (
        task.get("selected_templates") != ["requirement-contract"]
        or task.get("selected_capabilities") != ["core"]
        or task.get("rendered_artifacts") not in ([], None)
        or task.get("template_route") not in (None, {})
    ):
        errors.append("unclarified task may only expose the non-rendered requirement-contract template")
    workflow_check=run_bounded_command(
        [sys.executable,str(AGENT_DIR/"scripts"/"workflowctl.py"),"validate"],cwd=AGENT_DIR.parent,timeout=120,
    )
    if workflow_check.returncode:
        detail = workflow_check.stdout.strip().replace("\n", " | ")[:1200]
        errors.append(
            "node workflow state or artifact evidence is invalid"
            + (f": {detail}" if detail else "")
        )
    if not EVIDENCE_TOOL.is_file() or not EVIDENCE_INDEX_PATH.is_file():
        errors.append("evidence retention controller or index is missing")
    else:
        evidence_check=run_bounded_command(
            [sys.executable,str(EVIDENCE_TOOL),"verify","--quiet"],cwd=AGENT_DIR.parent,timeout=120,
        )
        if evidence_check.returncode:
            errors.append("evidence archive index or receipts are invalid")
    stage_contract_check=run_bounded_command(
        [sys.executable,str(AGENT_DIR/"skills"/"run-ai-coding-pipeline"/"scripts"/"validate_stage_index.py"),str(STAGE_PATH)],cwd=AGENT_DIR.parent,timeout=120,
    )
    if stage_contract_check.returncode:
        errors.append("strict stage/release-gate contract is invalid")
    delivery_check=run_bounded_command(
        [sys.executable,str(AGENT_DIR/"scripts"/"deliveryctl.py"),"validate"],cwd=AGENT_DIR.parent,timeout=120,
    )
    if delivery_check.returncode:
        errors.append("environment delivery state or immutable artifact evidence is invalid")
    stage_text = boundedio.read_text(AGENT_DIR/"state"/"STAGE_INDEX.md",label="stage index")
    stage_mode = re.findall(r"^- Mode:\s*(\S+)\s*$", stage_text, re.MULTILINE)
    stage_status = re.findall(r"^- Status:\s*(\S+)\s*$", stage_text, re.MULTILINE)
    if stage_mode != [str(mode)]:
        errors.append("stage index Mode must occur once and match TASK.json")
    if stage_status != [str(task.get("status"))]:
        errors.append("stage index Status must occur once and match TASK.json")
    root = AGENT_DIR.parent
    if (root / "skills").exists() or (root / ".ai-pipeline").exists():
        errors.append("legacy top-level skills or .ai-pipeline directory remains")
    if errors:
        print("INVALID .agent structure")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"VALID .agent structure: {AGENT_DIR}")
    return 0


def command_status() -> int:
    task = load_json(TASK_PATH)
    print(json.dumps({
        "task": task, "budget_state": effective_budget_snapshot(task, load_json(CONFIG_PATH)),
        "runtime": load_json(RUNTIME_PATH),
    }, ensure_ascii=False, indent=2))
    return 0


def command_sync_stage() -> int:
    task = load_json(TASK_PATH)
    write_stage(task)
    print("STAGE INDEX SYNCHRONIZED FROM TASK")
    return 0


def command_budget_gate(args: argparse.Namespace) -> int:
    task = load_json(TASK_PATH)
    snapshot = effective_budget_snapshot(task, load_json(CONFIG_PATH))
    allowed = budget_action_allowed(snapshot, args.action, task)
    recovery = {"compact", "split", "request-decision", "cleanup", "status", "validate", "rollback", "return-node"}
    compact_handoff_verified = None
    if allowed and snapshot["state"] == "must_compact" and args.action not in recovery:
        compact_handoff_verified = verified_compact_handoff(task)
        allowed = compact_handoff_verified
    print(json.dumps({
        **snapshot,
        "action": args.action,
        "allowed": allowed,
        "compact_handoff_verified": compact_handoff_verified,
    }, ensure_ascii=False, indent=2))
    return 0 if allowed else 2


def command_record_usage(args: argparse.Namespace) -> int:
    task = load_json(TASK_PATH)
    before_task = copy.deepcopy(task)
    config = load_json(CONFIG_PATH)
    mode_config = config["routing"]["modes"][task["mode"]]
    usage_receipt = None
    if args.source == "measured":
        if not args.receipt:
            raise SystemExit("measured usage requires a structured platform usage receipt")
        if args.tokens is not None:
            raise SystemExit("measured usage derives tokens from its receipt; do not pass --tokens")
        receipt = (AGENT_DIR.parent / args.receipt).resolve()
        try:
            receipt.relative_to(AGENT_DIR.parent.resolve())
        except ValueError:
            raise SystemExit("usage receipt escapes project")
        if not receipt.is_file() or receipt.is_symlink():
            raise SystemExit("usage receipt is missing")
        usage_receipt = parse_usage_receipt(receipt, task, config, require_current=True)
        prior = task.get("usage_receipts", [])
        if any(isinstance(item, dict) and item.get("receipt_id") == usage_receipt["receipt_id"] for item in prior):
            raise SystemExit("measured usage receipt was already recorded")
        tokens = max(int(task.get("tokens_used", 0)), int(usage_receipt["total_tokens"]))
        effective_source = "estimated"
    else:
        if args.receipt:
            raise SystemExit("estimated usage cannot attach a platform receipt")
        if args.tokens is None:
            raise SystemExit("estimated usage requires --tokens")
        tokens = int(task.get("tokens_used", 0)) + args.tokens
        effective_source = "estimated"
    children = int(task.get("child_agents_used", 0)) + args.child_agents
    peak = max(int(task.get("peak_child_agents", 0)), args.peak_child_agents)
    context_policy = config.get("context", {})
    if peak > int(mode_config["max_child_agents"]):
        raise SystemExit("peak child-agent concurrency exceeds the active mode budget")
    if children < peak:
        raise SystemExit("cumulative child-agent count cannot be below peak concurrency")
    task.update({
        "tokens_used": tokens, "token_usage_source": effective_source,
        "child_agents_used": children, "peak_child_agents": peak,
        "updated": time.strftime("%Y-%m-%d"),
    })
    if usage_receipt:
        task["usage_receipt"] = usage_receipt
        task["usage_receipts"] = [*task.get("usage_receipts", []), usage_receipt][-8:]
    task["budget_state"] = budget_snapshot(task, config)["state"]
    metrics = task.setdefault("metrics", {})
    metrics.update({"tokens": tokens, "token_source": effective_source, "child_agents": children, "peak_children": peak})
    sync_context(
        "usage-recorded", before_task=before_task, after_task=task, operation="record-usage",
        summary="recorded structured token and child-agent usage",
    )
    ratio = budget_snapshot(task, config)["ratio"]
    if ratio >= float(context_policy.get("hard_budget_ratio", 0.9)):
        print("BUDGET HARD BLOCK: usage was recorded truthfully; only recovery, cleanup or a human decision may continue")
    elif ratio >= float(context_policy.get("compact_budget_ratio", 0.75)):
        print("BUDGET COMPACT: finish the active node, compact context, and split before new scope")
    elif ratio >= float(context_policy.get("soft_budget_ratio", 0.6)):
        print("BUDGET SOFT WARNING: avoid optional references and new sub-agents")
    source_label = "provider-measured-baseline+current-checkpoint-estimate" if usage_receipt else "estimated"
    print(f"USAGE RECORDED: tokens={tokens}, child_agents={children}, peak={peak}, source={source_label}")
    return 0


def command_record_metric(args: argparse.Namespace) -> int:
    task=load_json(TASK_PATH); before_task=copy.deepcopy(task); metrics=task.get("metrics",{})
    if args.name not in {"tool_calls","test_runs","test_failures","repair_rounds","user_corrections","context_compactions","references_loaded"}:
        raise SystemExit("metric is not an incrementable counter")
    metrics[args.name]=int(metrics.get(args.name,0))+args.increment; task["metrics"]=metrics
    task["budget_state"]=budget_snapshot(task,load_json(CONFIG_PATH))["state"]
    sync_context(f"metric-{args.name}",before_task=before_task,after_task=task,operation="record-metric",summary=f"incremented bounded metric {args.name}")
    print(f"METRIC RECORDED: {args.name}={metrics[args.name]}"); return 0


def record_automatic_execution_metrics(command: Sequence[str], outcome: int, source: str) -> None:
    """Account controlled tool/test use without relying on an Agent reminder."""
    task=load_json(TASK_PATH); before=copy.deepcopy(task); metrics=task.get("metrics",{})
    metrics["tool_calls"]=int(metrics.get("tool_calls",0))+1
    test_like = any(
        token in {"pytest", "unittest"} or "test" in Path(token).name.lower()
        for token in command
    )
    if test_like:
        metrics["test_runs"]=int(metrics.get("test_runs",0))+1
        if outcome != 0: metrics["test_failures"]=int(metrics.get("test_failures",0))+1
    task["metrics"]=metrics; task["budget_state"]=budget_snapshot(task,load_json(CONFIG_PATH))["state"]
    contexttx.transition_task(
        before,task,mutator="agentctl",operation="auto-metric",
        reason=f"automatic-{source}-metric",summary=f"automatically accounted controlled {source} execution",
    )


def command_reference_load(args: argparse.Namespace) -> int:
    root = AGENT_DIR.parent.resolve()
    path = (root / args.path).resolve()
    try:
        relative = str(path.relative_to(root))
    except ValueError:
        raise SystemExit("reference path escapes project")
    if not path.is_file() or path.is_symlink():
        raise SystemExit("reference must be a real project file")
    data = boundedio.read_bytes(path,label="agent file")
    task = load_json(TASK_PATH)
    before_task = copy.deepcopy(task)
    config = load_json(CONFIG_PATH)
    enforce_budget_action(task, config, "load-reference")
    references = task.get("loaded_references", [])
    if any(isinstance(item, dict) and item.get("path") == relative for item in references):
        raise SystemExit("reference is already loaded")
    limit = config["routing"]["modes"][task["mode"]]["max_loaded_references"]
    if len(references) >= int(limit):
        raise SystemExit("reference count exceeds the active mode budget")
    candidate = {
        "path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
        "estimated_tokens": (len(data) + 3) // 4, "purpose": args.purpose, "phase": task["phase"],
    }
    probe = copy.deepcopy(task); probe["loaded_references"] = [*references, candidate]
    if budget_snapshot(probe, config)["state"] == "hard_blocked":
        raise SystemExit("reference would exceed the unified active hard watermark")
    references.append(candidate)
    task["loaded_references"] = references
    task["budget_state"] = budget_snapshot(task, config)["state"]
    sync_context("reference-loaded",before_task=before_task,after_task=task,operation="reference-load",summary=f"loaded bounded reference {relative}")
    print(f"REFERENCE LOADED: {relative}")
    return 0


def command_reference_unload(args: argparse.Namespace) -> int:
    task = load_json(TASK_PATH)
    before_task = copy.deepcopy(task)
    before = task.get("loaded_references", [])
    after = [item for item in before if not isinstance(item, dict) or item.get("path") != args.path]
    if len(after) == len(before):
        raise SystemExit("reference is not loaded")
    removed = next(item for item in before if isinstance(item, dict) and item.get("path") == args.path)
    # Unloading removes the reference from the reusable registry, not from the
    # provider's already-active context. Conservatively settle its charge into
    # root usage; only a verified host compaction may later lower that estimate.
    charge = max(0, int(removed.get("estimated_tokens", 0)))
    task["loaded_references"] = after
    task["tokens_used"] = int(task.get("tokens_used", 0)) + charge
    task["token_usage_source"] = "estimated"
    metrics = task.get("metrics", {})
    if isinstance(metrics, dict):
        metrics["tokens"] = task["tokens_used"]
        metrics["token_source"] = "estimated"
        task["metrics"] = metrics
    task["budget_state"] = budget_snapshot(task, load_json(CONFIG_PATH))["state"]
    sync_context("reference-unloaded",before_task=before_task,after_task=task,operation="reference-unload",summary=f"unloaded reference {args.path}")
    print(f"REFERENCE UNLOADED: {args.path}")
    return 0


def command_bootstrap_check() -> int:
    """Validate the template and report the next usable trust tier.

    Entering clarification creates no approved requirement and grants no
    execution or delivery authority, so a fresh project may ask questions
    before the provider adapter is configured. Every approval and later gate
    remains blocked until that provider-owned adapter is healthy.
    """
    if command_validate():
        return 1
    config = load_json(CONFIG_PATH)
    adapters = config.get("acceptance_adapters")
    if isinstance(adapters, dict):
        # `implemented: true` is a self-declaration; probe the host facts it
        # depends on and warn (never block) when they are absent.
        for name, adapter in sorted(adapters.items()):
            if not isinstance(adapter, dict) or adapter.get("implemented") is not True:
                continue
            runner = adapter.get("runner")
            runner_path = (AGENT_DIR.parent / str(runner)).resolve() if isinstance(runner, str) else None
            if runner_path is None or not runner_path.is_file():
                print(f"BOOTSTRAP WARNING: acceptance adapter {name} declares implemented=true but its runner is missing: {runner}")
            if "docker" in str(name) and shutil.which("docker") is None:
                print(f"BOOTSTRAP WARNING: acceptance adapter {name} declares implemented=true but docker is not on PATH")
            if "ios" in str(name) and shutil.which("xcodebuild") is None:
                print(f"BOOTSTRAP WARNING: acceptance adapter {name} declares implemented=true but xcodebuild is not on PATH")
    if config.get("guardrails_ready") is not True:
        print("BOOTSTRAP NOT READY: project guardrails are uninitialized")
        print("NEXT: python3 .agent/scripts/agentctl.py project-init --guardrails-file <project-guardrails.md>; then pass --model <provider/model-id> to each start")
        return 2
    observer = config.get("agent_control", {}).get("human_decision_observer", {})
    if not isinstance(observer, dict) or observer.get("signed_adapter") is None:
        print("BOOTSTRAP NOT READY: provider-owned human-decision adapter is not configured")
        print("AUTHORITATIVE GATES BLOCKED: clarification may continue, but every approval and state/gate transition requires a provider-owned receipt")
        return 2
    humandecision.health(AGENT_DIR.parent.resolve(), config)
    print("BOOTSTRAP READY: provider human-decision adapter is healthy")
    return 0


def command_project_init(args: argparse.Namespace) -> int:
    """Atomically bind completed guardrails, readiness and a fresh idle context."""
    with locked_project_init():
        return _command_project_init_locked(args)


def _command_project_init_locked(args: argparse.Namespace) -> int:
    task=load_json(TASK_PATH); config=load_json(CONFIG_PATH); agents=load_json(AGENTS_PATH)
    if task.get("status") != "idle" or task.get("requirements_clarified") is not False:
        raise SystemExit("project-init is allowed only in fresh idle unclarified state")
    if config.get("guardrails_ready") is True:
        raise SystemExit("project guardrails are already initialized")
    configured_model=config.get("agent_control",{}).get("default_model")
    if configured_model!=agents.get("default_model"):
        raise SystemExit("project-init requires config and child-Agent model authorities to agree")
    if args.default_model is not None:
        raise SystemExit("project-init cannot persist a model while idle; pass --model to each task start")
    if configured_model is not None:
        raise SystemExit("project-init requires idle model authority to remain null")
    if agents.get("members") or agents.get("prepared_dispatches"):
        raise SystemExit("project-init cannot proceed after child dispatch history exists")
    selected_model=None
    root = AGENT_DIR.parent.resolve()
    supplied = Path(args.guardrails_file)
    lexical = supplied if supplied.is_absolute() else root / supplied
    path = Path(os.path.abspath(lexical))
    try: relative = path.relative_to(root)
    except ValueError: raise SystemExit("guardrails file must stay inside the project")
    data = _read_project_regular_file_no_links(root, relative, 131072)
    if not data or len(data)>131072: raise SystemExit("guardrails file is empty or too large")
    try: text=data.decode("utf-8")
    except UnicodeError: raise SystemExit("guardrails file must be UTF-8")
    labels=(
        "Product and users:","Technology and architecture:","Writable and read-only areas:",
        "Security, privacy, compliance and performance red lines:","Build, test and lint commands:",
        "Deployment authority and rollback owner:",
    )
    if not text.startswith("# Project Guardrails\n") or re.search(r"\b(?:TODO|PENDING)\b",text,re.I):
        raise SystemExit("guardrails file is incomplete")
    for label in labels:
        if len(re.findall(rf"^- {re.escape(label)}\s*(\S.*)$",text,re.M)) != 1:
            raise SystemExit(f"guardrails require exactly one completed '{label}' fact")
    if not data.endswith(b"\n"): data += b"\n"
    initialized=dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    config["guardrails_ready"]=True
    config["project_initialization"]={
        "schema":"agent-project-initialization/v1","guardrails_sha256":hashlib.sha256(data).hexdigest(),
        "guardrails_bytes":len(data),"initialized_at":initialized,
    }
    config_bytes=(json.dumps(config,ensure_ascii=False,indent=2)+"\n").encode()
    agents_bytes=(json.dumps(agents,ensure_ascii=False,indent=2)+"\n").encode()
    policy_path=AGENT_DIR/"policies/PROJECT_GUARDRAILS.md"
    backups={CONFIG_PATH:boundedio.read_bytes(CONFIG_PATH,label="agent config"),policy_path:boundedio.read_bytes(policy_path,label="skill policy"),AGENTS_PATH:boundedio.read_bytes(AGENTS_PATH,label="AGENTS bootstrap"),CONTEXT_PATH:boundedio.read_bytes(CONTEXT_PATH,label="context capsule")}
    journal={
        "schema":"agent-project-init-transaction/v1","phase":"prepared",
        "backups":{
            str(target.relative_to(AGENT_DIR.parent)):{
                "data_b64":base64.b64encode(payload).decode("ascii"),
                "sha256":hashlib.sha256(payload).hexdigest(),"bytes":len(payload),
            }
            for target,payload in backups.items()
        },
        "committed_sha256":None,
    }
    atomic_write(PROJECT_INIT_JOURNAL_PATH,json.dumps(journal,ensure_ascii=False,indent=2)+"\n")
    _fsync_directory(PROJECT_INIT_JOURNAL_PATH.parent)
    try:
        # Publish the policy first and readiness second. Any concurrent reader
        # either sees the old valid state or a fail-closed mismatch; CONTEXT is
        # the final authoritative checkpoint.
        for target,payload in ((policy_path,data),(CONFIG_PATH,config_bytes),(AGENTS_PATH,agents_bytes)):
            atomic_write(target,payload.decode("utf-8"))
        class InitArgs: pass
        init=InitArgs(); init.transition=False; init.reset=True; init.fact=[]; init.file=[]; init.evidence=[]; init.risk=[]; init.resolve_risk=[]
        init.summary="atomically initialized project guardrails"; init.reason="project-init"; init.source_tokens=800; init.source="agentctl:project-init"
        init.request_host_compaction=False; init.host_compaction=False
        capsule=contexttx.contextctl.build_capsule(init,"verified",{},"none",None)
        atomic_write(CONTEXT_PATH,json.dumps(capsule,ensure_ascii=False,indent=2)+"\n")
        _fsync_target_parents(list(backups))
        if contexttx.contextctl.validate_context(quiet=True, ignore_checkpoint_age=True):
            raise RuntimeError("initialized context validation failed")
        journal["phase"]="committed"
        journal["committed_sha256"]={
            str(target.relative_to(AGENT_DIR.parent)):hashlib.sha256(boundedio.read_bytes(target,label="agent state target")).hexdigest()
            for target in backups
        }
        atomic_write(PROJECT_INIT_JOURNAL_PATH,json.dumps(journal,ensure_ascii=False,indent=2)+"\n")
        _fsync_directory(PROJECT_INIT_JOURNAL_PATH.parent)
    except BaseException:
        for target,payload in backups.items(): atomic_write(target,payload.decode("utf-8"))
        _fsync_target_parents(list(backups))
        PROJECT_INIT_JOURNAL_PATH.unlink(missing_ok=True)
        _fsync_directory(PROJECT_INIT_JOURNAL_PATH.parent)
        raise
    PROJECT_INIT_JOURNAL_PATH.unlink()
    _fsync_directory(PROJECT_INIT_JOURNAL_PATH.parent)
    print("PROJECT INITIALIZED: guardrails bytes, readiness and context committed atomically")
    return 0


def command_select_model(args: argparse.Namespace) -> int:
    raise SystemExit("select-model no longer persists idle authority; pass --model <model-id> to each task start")



def _content_addressed_json(directory: str, value: Dict[str, object]) -> Tuple[Path, bytes, Dict[str, object]]:
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    digest = hashlib.sha256(data).hexdigest()
    path = AGENT_DIR / "state" / "evidence" / directory / f"{digest}.json"
    return path, data, {
        "path": str(path.relative_to(AGENT_DIR.parent)), "sha256": digest, "bytes": len(data),
    }


def stored_requirement_approval_valid(task: Dict[str, object], config: Dict[str, object]) -> bool:
    """Re-validate the persisted requirement approval under the task's stored policy."""
    approvals = task.get("gate_approvals")
    requirement = approvals.get("requirement") if isinstance(approvals, dict) else None
    artifact = str(task.get("requirement_contract_sha256") or "")
    if requirement is None or re.fullmatch(r"[0-9a-f]{64}", artifact) is None:
        return False
    record = (
        requirement.get("decision_receipt")
        if task.get("decision_policy_version") == humandecision.PROVIDER_POLICY_VERSION
        and isinstance(requirement, dict)
        else requirement
    )
    return humandecision.decision_approval_valid(
        AGENT_DIR.parent.resolve(), config, task, gate="requirement",
        artifact_sha256=artifact, source=str(task.get("requirement_source", "")), record=record,
    )


def command_escalate_mode(args: argparse.Namespace) -> int:
    """Atomically add risk and/or move to a stricter mode; never downgrade."""
    task = load_json(TASK_PATH); config = load_json(CONFIG_PATH); before = copy.deepcopy(task)
    if task.get("status") in {"idle", "accepted"}:
        raise SystemExit("mode/risk can only be updated for an active task")
    try:
        risks = workflow_state.monotonic_risks(task.get("risk_flags", {}), args.new_risk or [])
        current_files = int(task.get("files", 0))
        requested_files = current_files if args.files is None else int(args.files)
        if requested_files < current_files:
            raise ValueError("declared file count cannot decrease")
        minimum = required_mode(
            str(task.get("environment")), requested_files, risks,
            str(task.get("task_type")), str(task.get("complexity")),
        )
        mode = workflow_state.escalated_mode(str(task.get("mode")), args.new_mode, minimum)
    except (TypeError, ValueError) as error:
        raise SystemExit(str(error))
    if mode == task.get("mode") and risks == task.get("risk_flags") and requested_files == int(task.get("files", 0)):
        raise SystemExit("mode/risk update is a no-op")
    if (args.source or args.human_decision_receipt) and not args.reapprove:
        raise SystemExit("--source and --human-decision-receipt are valid only with --reapprove")
    new_policy_version = humandecision.decision_policy_version(
        config, mode=mode, environment=str(task.get("environment")),
        deployment_requested=bool(task.get("deployment_requested")), risk_flags=risks,
    )
    approvals = task.get("gate_approvals")
    requirement_approval = approvals.get("requirement") if isinstance(approvals, dict) else None
    contract_hash = str(task.get("requirement_contract_sha256") or "")
    reapproval: Optional[Dict[str, object]] = None
    if task.get("requirements_clarified") is True and requirement_approval is not None:
        # The stored approval was issued under the OLD policy and routing
        # profile.  Never commit an escalation that leaves the task with an
        # approval the NEW policy will reject on every later transition.
        probe = {
            **task, "mode": mode, "risk_flags": risks, "files": requested_files,
            "decision_policy_version": new_policy_version,
        }
        if not CONTRACT_PATH.is_file() or hashlib.sha256(boundedio.read_bytes(CONTRACT_PATH,label="requirement contract")).hexdigest() != contract_hash:
            raise SystemExit("approved requirement contract bytes are missing or drifted; repair before escalating")
        if args.reapprove:
            if not str(args.source or "").startswith("user:"):
                raise SystemExit("escalate-mode --reapprove requires --source user:<decision>")
            reapproval = humandecision.record_decision_approval(
                AGENT_DIR.parent.resolve(), config, probe, gate="requirement",
                artifact_sha256=contract_hash, source=str(args.source),
                receipt=args.human_decision_receipt,
            )
        elif not stored_requirement_approval_valid(probe, config):
            remedy = (
                f"rerun with --reapprove --source user:<decision> --human-decision-receipt <path> "
                f"to re-approve the requirement under the new provider-signed policy"
                if new_policy_version == humandecision.PROVIDER_POLICY_VERSION
                else "rerun with --reapprove --source user:<decision> to re-approve the requirement under the new routing profile"
            )
            raise SystemExit(
                "mode/risk escalation would invalidate the current requirement approval under the "
                f"new decision policy (v{new_policy_version}); refusing to commit a dead state — {remedy}"
            )
    elif args.reapprove:
        raise SystemExit("--reapprove requires an approved requirement contract")
    ledger = load_json(AGENTS_PATH)
    preparations = ledger.get("prepared_dispatches", [])
    members = ledger.get("members", [])
    if not isinstance(preparations, list) or not isinstance(members, list):
        raise SystemExit(
            "agent ledger prepared_dispatches/members must be lists; refusing mode escalation"
        )
    if any(isinstance(item, dict) and (item.get("token_reservation") or {}).get("status") == "reserved" for item in preparations):
        raise SystemExit("mode escalation requires no active child Token reservation")
    if any(isinstance(item, dict) and item.get("status") == "active" for item in members):
        raise SystemExit("mode escalation requires all child Agents to reach a terminal state")
    archive_value = {
        "schema": "agent-route-archive/v1", "reason": "mode-or-risk-escalation",
        "old_mode": task.get("mode"), "new_mode": mode,
        "old_files": task.get("files"), "new_files": requested_files,
        "old_risk_flags": task.get("risk_flags"), "new_risk_flags": risks,
        "selected_templates": task.get("selected_templates"),
        "selected_capabilities": task.get("selected_capabilities"),
        "template_route": task.get("template_route"),
        "rendered_artifacts": task.get("rendered_artifacts"),
        "node_artifacts": task.get("node_artifacts"), "gate_approvals": task.get("gate_approvals"),
        "archived_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    }
    archive_path, archive_data, archive_record = _content_addressed_json("route-archives", archive_value)
    task.update({
        "mode": mode, "risk_flags": risks, "files": requested_files,
        "token_budget": int(config["routing"]["modes"][mode]["token_budget"]),
        "decision_policy_version": new_policy_version,
        "projection": workflow_state.task_projection(str(task.get("task_type")), mode),
        "selected_templates": ["requirement-contract"], "selected_capabilities": ["core"],
        "template_route": None, "rendered_artifacts": [], "current_node": 2,
        "accepted_nodes": [0, 1],
        "node_artifacts": {key: value for key, value in task.get("node_artifacts", {}).items() if key == "1"},
        "gate_approvals": {key: value for key, value in task.get("gate_approvals", {}).items() if key == "requirement"},
        "pending_gate_artifacts": {}, "status": "in_progress", "phase": "planning",
        "mode_status": "confirmed", "next_action": "reroute templates after mode/risk escalation",
        "route_archive": archive_record, "updated": time.strftime("%Y-%m-%d"),
    })
    if reapproval is not None:
        task["requirement_source"] = str(args.source)
        task["gate_approvals"] = {
            "requirement": (
                {"source": str(args.source), "artifact_sha256": contract_hash, "decision_receipt": reapproval}
                if new_policy_version == humandecision.PROVIDER_POLICY_VERSION
                else reapproval
            )
        }
    ledger["token_accounting"]["token_budget"] = task["token_budget"]
    # Advance the append hash chain exactly like agentledger.save would;
    # the journal tip is appended only after the transition commits.
    ledger_data = agents_chain_advance(ledger)
    task["budget_state"] = budget_snapshot(task, config)["state"]
    contexttx.transition_task(
        before, task, mutator="agentctl", operation="escalate-mode",
        reason="mode-risk-escalated", summary="escalated mode/risk and reopened deterministic routing",
        side_effects=[(archive_path, archive_data), (AGENTS_PATH, ledger_data)],
        evidence=[archive_record["path"]],
    )
    agents_chain_journal_append(ledger, ledger_data)
    write_stage(task)
    print(f"MODE/RISK ESCALATED: mode={mode} risks={[name for name, value in risks.items() if value]}")
    return 0


def command_reopen_clarification(args: argparse.Namespace) -> int:
    """Archive an approved contract and safely reopen a mutable Node-1 draft."""
    task = load_json(TASK_PATH); before = copy.deepcopy(task)
    if task.get("requirements_clarified") is not True or not CONTRACT_PATH.is_file():
        raise SystemExit("reopen-clarification requires an approved requirement contract")
    if not str(args.source).startswith("user:") or not str(args.reason).strip():
        raise SystemExit("reopen-clarification requires user:<source> and a non-empty reason")
    contract = boundedio.read_bytes(CONTRACT_PATH,label="requirement contract"); config=load_json(CONFIG_PATH)
    action={"schema":"agent-task-reopen-action/v1","task_generation_id":task.get("task_generation_id"),"contract_sha256":hashlib.sha256(contract).hexdigest(),"source":args.source,"reason":args.reason.strip()}
    action_sha=hashlib.sha256(json.dumps(action,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    request={"schema":"agent-human-decision-request/v1","gate":"task-reopen","artifact_sha256":action_sha,"artifact_bytes":len(json.dumps(action,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()),"source":args.source,"task_title":task.get("title"),"task_mode":task.get("mode"),"routing_profile_sha256":humandecision.routing_profile_sha256(task),"project_identity_sha256":humandecision.project_identity_sha256(AGENT_DIR.parent.resolve(),config),"task_generation_sha256":humandecision.task_generation_sha256(task),"task_generation_id":task.get("task_generation_id")}
    request["request_sha256"]=hashlib.sha256(json.dumps(request,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    if args.print_decision_request:
        if args.human_decision_receipt: raise SystemExit("--print-decision-request cannot consume a receipt")
        print(json.dumps(request,ensure_ascii=False,sort_keys=True,separators=(",",":"))); return 0
    if not args.human_decision_receipt: raise SystemExit("reopen-clarification requires a provider-signed human decision receipt")
    reopen_receipt=humandecision.verify(AGENT_DIR.parent.resolve(),config,task,gate="task-reopen",artifact_sha256=action_sha,source=args.source,receipt=args.human_decision_receipt)
    archive_value = {
        "schema": "agent-clarification-archive/v1", "source": args.source,
        "reason": args.reason.strip(),
        "archived_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "contract": {"sha256": hashlib.sha256(contract).hexdigest(), "bytes": len(contract), "utf8": contract.decode("utf-8")},
        "requirement_approval": task.get("gate_approvals", {}).get("requirement"),
        "reopen_action":action,"reopen_decision_receipt":reopen_receipt,
        "route_archive": task.get("route_archive"), "template_route": task.get("template_route"),
        "node_artifacts": task.get("node_artifacts"),
    }
    archive_path, archive_data, archive_record = _content_addressed_json("clarification-archives", archive_value)
    draft = new_contract_bytes(str(task.get("title")), str(task.get("environment")))
    task.update({
        "requirements_clarified": False, "requirement_source": "pending",
        "requirement_contract": None, "requirement_contract_sha256": None,
        "task_generation_id": "task-"+os.urandom(16).hex(),
        "primary_skill": "clarify-task", "selected_templates": ["requirement-contract"],
        "selected_capabilities": ["core"], "template_route": None, "rendered_artifacts": [],
        "status": "waiting_human", "phase": "clarification", "current_node": 1,
        "accepted_nodes": [0], "node_artifacts": {}, "gate_approvals": {},
        "pending_gate_artifacts": {}, "decision_packet": None,
        "open_questions": ["requirement contract approval"],
        "next_action": "edit and explicitly approve the reopened requirement contract",
        "mode_status": "provisional", "clarification_archive": archive_record,
        "updated": time.strftime("%Y-%m-%d"),
    })
    verification,skill_lock,captured=capture_dynamic_skill_activation()
    rebound_activation,rebound_activation_data=build_task_skill_activation(task["task_generation_id"],verification,skill_lock,captured)
    task["skill_activation"]=rebound_activation
    task["budget_state"] = budget_snapshot(task, load_json(CONFIG_PATH))["state"]
    contexttx.transition_task(
        before, task, mutator="agentctl", operation="reopen-clarification",
        reason="clarification-reopened", summary="archived the prior contract and reopened a mutable clarification draft",
        side_effects=[(archive_path, archive_data), (CONTRACT_PATH, draft),(SKILL_ACTIVATION_PATH,rebound_activation_data)],
        evidence=[archive_record["path"]],
    )
    write_stage(task)
    print(f"CLARIFICATION REOPENED: archive={archive_record['path']}")
    return 0


def _task_archive_chain_checked(head: object) -> None:
    """Fully verify the existing head chain before anchoring a new archive to it."""
    if head is None:
        return
    if evidencectl is not None:
        evidencectl.task_archive_chain(head)
        return
    # Mirror evidencectl.task_archive_chain when the controller is unavailable.
    current = head
    seen: set[str] = set()
    while current is not None:
        if (
            not isinstance(current, dict) or set(current) != TASK_ARCHIVE_HEAD_FIELDS
            or current.get("schema") != "agent-task-archive-head/v1"
            or re.fullmatch(r"[0-9a-f]{64}", str(current.get("sha256", ""))) is None
            or not isinstance(current.get("bytes"), int) or current["bytes"] < 1
            or not isinstance(current.get("total_archives"), int) or current["total_archives"] < 1
        ):
            raise SystemExit("task archive head is invalid")
        value_sha = str(current["sha256"])
        path = (AGENT_DIR.parent / str(current.get("path", ""))).resolve()
        expected = (TASK_ARCHIVE_DIR / f"{value_sha}.json").resolve()
        if path != expected or value_sha in seen or not path.is_file() or path.is_symlink():
            raise SystemExit("task archive head path is invalid or missing")
        seen.add(value_sha)
        data = boundedio.read_bytes(path,label="agent file")
        if len(data) != current["bytes"] or hashlib.sha256(data).hexdigest() != value_sha:
            raise SystemExit("task archive bytes drifted")
        try:
            payload = json.loads(data)
        except (ValueError, json.JSONDecodeError) as error:
            raise SystemExit(f"task archive payload is unreadable: {error}")
        if not isinstance(payload, dict) or payload.get("schema") not in TASK_ARCHIVE_PAYLOAD_SCHEMAS:
            raise SystemExit("task archive payload schema is invalid")
        current = payload.get("previous")


def _current_delivery_bytes() -> Optional[bytes]:
    if deliveryctl is not None:
        return deliveryctl.current_delivery_bytes()
    if not DELIVERY_PATH.is_file() or DELIVERY_PATH.is_symlink():
        return None
    return boundedio.read_bytes(DELIVERY_PATH,label="delivery state")


def _bounded_evidence_files(root: Path,max_entries: int=8192):
    stack=[root]; seen=0
    while stack:
        directory=stack.pop(); directories=[]; files=[]
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    seen+=1
                    if seen>max_entries: raise SystemExit("task evidence inventory exceeds its entry limit")
                    observed=entry.stat(follow_symlinks=False); path=Path(entry.path)
                    if stat.S_ISLNK(observed.st_mode): raise SystemExit("task evidence inventory contains a symlink")
                    item=(entry.name,path)
                    if stat.S_ISDIR(observed.st_mode): directories.append(item)
                    elif stat.S_ISREG(observed.st_mode): files.append(item)
                    else: raise SystemExit("task evidence inventory contains a special file")
        except FileNotFoundError as error: raise SystemExit("task evidence inventory changed during traversal") from error
        directories.sort(); files.sort()
        for _name,path in files: yield path
        for _name,path in reversed(directories): stack.append(path)



def _referenced_evidence_digests(texts: Sequence[str]) -> List[str]:
    """Digests of active evidence files whose literal paths appear in the archived texts."""
    evidence_dir = AGENT_DIR / "state" / "evidence"
    referenced: set[str] = set()
    if not evidence_dir.is_dir():
        return []
    total=0
    for path in _bounded_evidence_files(evidence_dir):
        relative_path=path.relative_to(AGENT_DIR.parent)
        data=_read_project_regular_file_no_links(AGENT_DIR.parent,relative_path,16*1024*1024); total+=len(data)
        if total>512*1024*1024: raise SystemExit("task evidence inventory exceeds its byte limit")
        relative=str(relative_path); digest=hashlib.sha256(data).hexdigest()
        if any(relative in text or digest in text for text in texts): referenced.add(digest)
    return sorted(referenced)


def build_task_archive(
    previous_task: Dict[str, object], *, source: str, reason: str,
    decision_receipt: Optional[Dict[str, object]], assurance: str,
) -> Tuple[Dict[str, object], Path, bytes]:
    task_bytes = boundedio.read_bytes(TASK_PATH,label="task state")
    contract_record = None
    if CONTRACT_PATH.is_file() and not CONTRACT_PATH.is_symlink():
        contract_bytes = boundedio.read_bytes(CONTRACT_PATH,label="requirement contract")
        contract_record = {
            "sha256": hashlib.sha256(contract_bytes).hexdigest(),
            "bytes": len(contract_bytes),
            "utf8": contract_bytes.decode("utf-8"),
        }
    activation_errors=task_skill_activation_errors(previous_task)
    if activation_errors: raise SystemExit(activation_errors[0])
    activation_bytes=_read_project_regular_file_no_links(AGENT_DIR.parent,Path(".agent/state/SKILL_ACTIVATION.json"),4*1024*1024)
    activation_record={"sha256":hashlib.sha256(activation_bytes).hexdigest(),"bytes":len(activation_bytes),"utf8":activation_bytes.decode("utf-8")}
    delivery_bytes = _current_delivery_bytes()
    delivery_record = None
    if delivery_bytes is not None:
        delivery_record = {
            "sha256": hashlib.sha256(delivery_bytes).hexdigest(),
            "bytes": len(delivery_bytes),
            "utf8": delivery_bytes.decode("utf-8"),
        }
    previous = previous_task.get("task_archive")
    _task_archive_chain_checked(previous)
    previous_total = previous.get("total_archives", 0) if isinstance(previous, dict) else 0
    # v2 payloads are never textually scanned: every active evidence file the
    # archived texts still reference must be digest-bound here to stay reachable.
    texts = [task_bytes.decode("utf-8"),activation_record["utf8"]]
    if contract_record is not None:
        texts.append(str(contract_record["utf8"]))
    if delivery_record is not None:
        texts.append(str(delivery_record["utf8"]))
    payload = {
        "schema": "agent-task-archive/v2",
        "archived_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "source": source,
        "reason": reason,
        "assurance": assurance,
        "decision_receipt": decision_receipt,
        "task": {
            "sha256": hashlib.sha256(task_bytes).hexdigest(),
            "bytes": len(task_bytes),
            "utf8": task_bytes.decode("utf-8"),
        },
        "requirement_contract": contract_record,
        "skill_activation":activation_record,
        "delivery": delivery_record,
        "referenced_evidence": _referenced_evidence_digests(texts),
        "previous": previous,
    }
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    digest = hashlib.sha256(data).hexdigest()
    relative = Path(".agent/state/evidence/task-archives") / f"{digest}.json"
    head = {
        "schema": "agent-task-archive-head/v1",
        "path": str(relative),
        "sha256": digest,
        "bytes": len(data),
        "total_archives": previous_total + 1,
    }
    return head, AGENT_DIR.parent / relative, data


def load_knowledge_pending() -> Dict[str, object]:
    if not KNOWLEDGE_PENDING_PATH.is_file():
        return {"schema": "agent-knowledge-pending/v2", "candidates": [], "promotions": []}
    value = load_json(KNOWLEDGE_PENDING_PATH)
    if (
        value.get("schema") != "agent-knowledge-pending/v2"
        or not isinstance(value.get("candidates"), list)
        or not isinstance(value.get("promotions"), list)
    ):
        raise SystemExit("knowledge pending registry is malformed")
    return value


def knowledge_pending_notice() -> Optional[str]:
    if not KNOWLEDGE_PENDING_PATH.is_file():
        return None
    try: pending=load_knowledge_pending()
    except SystemExit:
        return "knowledge pending registry is malformed; inspect .agent/state/knowledge-pending.json"
    count=len(pending["candidates"])
    if not count: return None
    return f"{count} evidence-bound knowledge candidate(s) await `agentctl.py promote-knowledge <candidate-id>`"


def _dynamic_skill_surface_present(path):
    if not (path.exists() or path.is_symlink()): return False
    try: metadata=os.lstat(path)
    except OSError: return True
    if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
        try:
            with os.scandir(path) as entries: return next(entries,None) is not None
        except OSError: return True
    return True


def capture_dynamic_skill_activation():
    project=AGENT_DIR/"project"; blueprint_path=project/"BLUEPRINT.json"
    if project.exists() or project.is_symlink():
        try: project_metadata=os.lstat(project)
        except OSError as error: raise SystemExit("dynamic Skill project root is unsafe") from error
        if not stat.S_ISDIR(project_metadata.st_mode) or stat.S_ISLNK(project_metadata.st_mode):
            raise SystemExit("dynamic Skill project root is unsafe")
    else:
        return {"status":"NO_DYNAMIC_SKILLS_REQUIRED","active":[],"covered_capabilities":[]},None,{}
    authority_surfaces=(
        project/"skills.lock.json",project/"skills",project/"skill-cas",project/"skill-lock-history",
        project/"skill-lifecycle.json",project/"skill-mutation-journal.json",
        project/"skill-mutation-history",project/"skill-mutation-head.json",
    )
    other_authority=any(_dynamic_skill_surface_present(path) for path in authority_surfaces)
    blueprint_present=blueprint_path.exists() or blueprint_path.is_symlink()
    if not blueprint_present and not other_authority:
        return {"status":"NO_DYNAMIC_SKILLS_REQUIRED","active":[],"covered_capabilities":[]},None,{}
    if skillctl is None:
        raise SystemExit("dynamic Skill activation verifier is unavailable")
    # An unconfirmed, structurally valid draft alone has no activation authority.
    # Quarantining an unverifiable legacy lock may therefore revoke confirmation
    # without fabricating a replacement approval. Any remaining authority surface
    # still invokes the strict verifier and fails closed.
    if blueprint_present and not other_authority:
        try: blueprint=skillctl.load_blueprint(AGENT_DIR.parent.resolve(),require_confirmed=False)
        except Exception as error:
            code=getattr(error,"code",type(error).__name__)
            raise SystemExit(f"dynamic Skill activation failed closed: {code}: {error}") from error
        if blueprint.get("status")!="confirmed":
            return {"status":"NO_DYNAMIC_SKILLS_REQUIRED","active":[],"covered_capabilities":[]},None,{}
    try:
        return skillctl.verify_activation(AGENT_DIR.parent.resolve())
    except Exception as error:
        code=getattr(error,"code",type(error).__name__)
        raise SystemExit(f"dynamic Skill activation failed closed: {code}: {error}") from error


def _strict_manifest_json(raw):
    def pairs(values):
        result={}
        for key,value in values:
            if key in result: raise ValueError("duplicate manifest key")
            result[key]=value
        return result
    try: value=json.loads(raw,object_pairs_hook=pairs)
    except (UnicodeError,json.JSONDecodeError,ValueError) as error:
        raise SystemExit("managed built-in Skill manifest is malformed") from error
    if not isinstance(value,dict): raise SystemExit("managed built-in Skill manifest is malformed")
    return value


BUILTIN_SKILL_MANIFEST_ROOT=None


def capture_builtin_skills():
    base=AGENT_DIR/"skills"
    manifest_root=Path(BUILTIN_SKILL_MANIFEST_ROOT) if BUILTIN_SKILL_MANIFEST_ROOT is not None else AGENT_DIR
    manifest_path=manifest_root/".workflow-manifest.json"
    if base.is_symlink() or not base.is_dir(): raise SystemExit("built-in Skill root is missing or unsafe")
    try: manifest_metadata=os.lstat(manifest_path)
    except OSError as error: raise SystemExit("managed built-in Skill manifest is missing or unsafe") from error
    expected_uid=os.geteuid() if hasattr(os,"geteuid") else manifest_metadata.st_uid
    if (not stat.S_ISREG(manifest_metadata.st_mode) or stat.S_ISLNK(manifest_metadata.st_mode) or manifest_metadata.st_nlink!=1
            or manifest_metadata.st_uid!=expected_uid or manifest_metadata.st_mode&(stat.S_IWGRP|stat.S_IWOTH)):
        raise SystemExit("managed built-in Skill manifest is missing, foreign-owned, or writable by another principal")
    raw=_read_project_regular_file_no_links(manifest_root,Path(".workflow-manifest.json"),4*1024*1024)
    if len(raw)>4*1024*1024: raise SystemExit("managed built-in Skill manifest exceeds its limit")
    manifest=_strict_manifest_json(raw); agent_files=manifest.get("agent_files"); agent_modes=manifest.get("agent_modes")
    if manifest.get("schema")!="agent-workflow-install/v5" or not isinstance(agent_files,dict) or not isinstance(agent_modes,dict):
        raise SystemExit("managed built-in Skill manifest schema is invalid")
    expected={name:digest for name,digest in agent_files.items() if isinstance(name,str) and name.startswith("skills/")}
    if not expected or len(expected)>4096 or set(expected)!={name for name in agent_modes if isinstance(name,str) and name.startswith("skills/")}:
        raise SystemExit("managed built-in Skill inventory is missing, oversized, or mode-unbound")
    actual=set(); stack=[base]; entries_seen=0
    while stack:
        directory=stack.pop()
        try:
            with os.scandir(directory) as iterator:
                children=[]
                for item in iterator:
                    if len(children)>=8193-entries_seen: raise SystemExit("built-in Skill topology exceeds its bounded inventory")
                    children.append(Path(item.path))
            children.sort(key=lambda item:os.fsencode(item.name),reverse=True)
        except OSError as error: raise SystemExit("built-in Skill inventory cannot be enumerated safely") from error
        for child in children:
            entries_seen+=1
            if entries_seen>8192: raise SystemExit("built-in Skill topology exceeds its bounded inventory")
            try: metadata=os.lstat(child)
            except OSError as error: raise SystemExit("built-in Skill topology changed during inventory") from error
            if stat.S_ISLNK(metadata.st_mode): raise SystemExit("built-in Skill contains a symlink")
            if stat.S_ISDIR(metadata.st_mode): stack.append(child)
            elif stat.S_ISREG(metadata.st_mode): actual.add(child.relative_to(AGENT_DIR).as_posix())
            else: raise SystemExit("built-in Skill contains a special filesystem entry")
    if actual!=set(expected):
        raise SystemExit("built-in Skill tree differs from the exact managed inventory")
    grouped={}
    for managed_name in sorted(expected):
        parts=Path(managed_name).parts
        if (len(parts)<3 or parts[0]!="skills" or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}",parts[1]) is None
                or any(part in {"",".",".."} for part in parts[2:]) or re.fullmatch(r"[0-9a-f]{64}",str(expected[managed_name])) is None):
            raise SystemExit("managed built-in Skill inventory path or digest is invalid")
        path=AGENT_DIR/managed_name; metadata=os.lstat(path)
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink!=1
                or not isinstance(agent_modes.get(managed_name),int) or stat.S_IMODE(metadata.st_mode)!=agent_modes[managed_name]):
            raise SystemExit("managed built-in Skill file type or mode drifted")
        data=_read_project_regular_file_no_links(AGENT_DIR,Path(managed_name),4*1024*1024)
        if len(data)>4*1024*1024 or hashlib.sha256(data).hexdigest()!=expected[managed_name]:
            raise SystemExit("managed built-in Skill bytes drifted")
        grouped.setdefault(parts[1],[]).append({"path":Path(*parts[2:]).as_posix(),"sha256":expected[managed_name],
            "bytes":len(data),"mode":agent_modes[managed_name],"content_base64":base64.b64encode(data).decode("ascii")})
    if len(grouped)>128: raise SystemExit("built-in Skill count exceeds activation limit")
    result=[]
    for skill_id,files in sorted(grouped.items()):
        if "SKILL.md" not in {item["path"] for item in files}: raise SystemExit("managed built-in Skill lacks SKILL.md")
        bundle=hashlib.sha256(json.dumps([{key:item[key] for key in ("path","sha256","bytes","mode")} for item in files],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
        result.append({"id":skill_id,"bundle_sha256":bundle,"files":files})
    return result



def build_task_skill_activation(task_generation_id,verification,lock,captured):
    entries={entry["id"]:entry for entry in (lock or {}).get("skills",[]) if entry.get("status") in {"active","deprecated"}}
    skills=[]
    for skill_id in verification.get("active",[]):
        entry=entries.get(skill_id); files=captured.get(skill_id)
        if entry is None or not isinstance(files,dict):
            raise SystemExit("verified dynamic Skill capture is incomplete")
        documents=[]
        for name in ("SKILL.md","LICENSE.txt"):
            raw=files.get(name)
            if not isinstance(raw,bytes): raise SystemExit("verified dynamic Skill document capture is incomplete")
            try: content=raw.decode("utf-8")
            except UnicodeDecodeError as error: raise SystemExit("verified dynamic Skill document is not UTF-8") from error
            documents.append({"path":name,"sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw),"content":content})
        skills.append({"id":skill_id,"status":entry["status"],"bundle_sha256":entry["bundle_sha256"],"matched_capabilities":entry["matched_capabilities"],"documents":documents})
    if len(skills)>64: raise SystemExit("dynamic Skill count exceeds activation limit")
    builtins=capture_builtin_skills()
    payload={"schema":"agent-task-skill-activation/v2","task_generation_id":task_generation_id,
      "blueprint_sha256":(lock or {}).get("blueprint_sha256"),"lock_sha256":(lock or {}).get("lock_sha256"),"skills":skills,"builtins":builtins}
    payload["activation_sha256"]=hashlib.sha256(json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    data=(json.dumps(payload,ensure_ascii=False,indent=2)+"\n").encode()
    if len(data)>4*1024*1024: raise SystemExit("task Skill activation exceeds its aggregate 4 MiB limit")
    receipt={"schema":payload["schema"],"path":".agent/state/SKILL_ACTIVATION.json","sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data),"activation_sha256":payload["activation_sha256"],"lock_sha256":payload["lock_sha256"],"skill_ids":[item["id"] for item in skills],"builtin_skill_ids":[item["id"] for item in builtins]}
    return receipt,data


def rebind_task_skill_activation(current_task,new_generation_id):
    errors=task_skill_activation_errors(current_task)
    if errors: raise SystemExit(errors[0])
    raw=_read_project_regular_file_no_links(AGENT_DIR.parent,Path(".agent/state/SKILL_ACTIVATION.json"),4*1024*1024)
    payload=json.loads(raw); payload["task_generation_id"]=new_generation_id; payload.pop("activation_sha256",None)
    payload["activation_sha256"]=hashlib.sha256(json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    data=(json.dumps(payload,ensure_ascii=False,indent=2)+"\n").encode()
    if len(data)>4*1024*1024: raise SystemExit("task Skill activation exceeds its aggregate 4 MiB limit")
    receipt={"schema":payload["schema"],"path":".agent/state/SKILL_ACTIVATION.json","sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data),"activation_sha256":payload["activation_sha256"],"lock_sha256":payload["lock_sha256"],"skill_ids":[item["id"] for item in payload["skills"]],"builtin_skill_ids":[item["id"] for item in payload["builtins"]]}
    return receipt,data


def command_start(args: argparse.Namespace) -> int:
    if command_validate():
        raise SystemExit("starting active work requires a valid workflow state")
    if os.environ.get("AGENT_WORKFLOW_START_SELF_TEST_STOP_AFTER_VALIDATE")=="1":
        os.kill(os.getpid(),signal.SIGSTOP)
    with locked_model_authority():
        return _command_start_locked(args)


def _command_start_locked(args: argparse.Namespace) -> int:
    config = load_json(CONFIG_PATH)
    if config.get("guardrails_ready") is not True:
        raise SystemExit("project guardrails are incomplete; run project-init before starting a task")
    previous_task = load_json(TASK_PATH) if TASK_PATH.is_file() else {}
    agents_state = load_json(AGENTS_PATH)
    skill_verification,skill_lock,skill_captured=capture_dynamic_skill_activation()
    active_replacement = previous_task.get("status") not in {"idle", "accepted"}
    current_model=config.get("agent_control",{}).get("default_model")
    if current_model!=agents_state.get("default_model"):
        raise SystemExit("starting active work requires config and child-Agent model authorities to agree")
    if previous_task.get("status") in {"idle","accepted"} and current_model is not None:
        raise SystemExit("idle model authority must be null before task start")
    if previous_task.get("status") not in {"idle","accepted"} and not valid_model_id(current_model):
        raise SystemExit("active predecessor has invalid model authority")
    selected_model=args.model
    if not valid_model_id(selected_model):
        raise SystemExit("starting active work requires --model with a safe explicit provider/model identifier")
    if active_replacement and not args.archive_active:
        raise SystemExit(
            "active task cannot be overwritten; rerun start with --archive-active, "
            "--archive-source user:<decision> and --archive-reason <reason>"
        )
    if not active_replacement and args.archive_active:
        raise SystemExit("--archive-active is valid only while replacing an unfinished task")
    if active_replacement and (
        not str(args.archive_source or "").startswith("user:")
        or not isinstance(args.archive_reason, str) or not args.archive_reason.strip()
    ):
        raise SystemExit("active task archival requires an explicit user source and non-empty reason")
    environment_policy = config["environments"][args.environment]
    if args.deploy and environment_policy.get("deploy_allowed") is not True:
        raise SystemExit(f"--deploy is not allowed for {args.environment}")
    if environment_policy.get("deploy_required") is True and not args.deploy:
        raise SystemExit(f"{args.environment} requires explicit --deploy")
    risk_flags = {
        "deploy": args.deploy, "data_risk": args.data_risk, "cross_system": args.cross_system, "uncertain": args.uncertain,
        "security": args.security, "compliance": args.compliance, "migration": args.migration,
        "irreversible": args.irreversible, "external_impact": args.external_impact,
    }
    minimum_mode = required_mode(args.environment, args.files, risk_flags, args.task_type, args.complexity)
    mode = minimum_mode if args.mode == "auto" else args.mode
    if mode not in config["routing"]["modes"]:
        raise SystemExit(f"unsupported mode: {mode}")
    rank = {"fast": 0, "standard": 1, "release": 2}
    if rank[mode] < rank[minimum_mode]:
        raise SystemExit(f"{mode} is below required minimum mode {minimum_mode} for the declared risk and environment")
    if args.environment == "production" and mode != "release":
        raise SystemExit("production environment requires release mode")
    if args.environment == "test" and mode == "fast":
        raise SystemExit("test environment requires at least standard mode")
    if previous_task.get("status") not in {"idle", None} and CONTEXT_PATH.is_file():
        try:
            previous_context = load_json(CONTEXT_PATH)
            rollover_task = copy.deepcopy(previous_task)
            rollover_task["mode"] = mode
            rollover_task["token_budget"] = config["routing"]["modes"][mode]["token_budget"]
            released_reference_tokens = sum(
                max(0, int(item.get("estimated_tokens", 0)))
                for item in previous_task.get("loaded_references", [])
                if isinstance(item, dict)
            )
            rollover_estimate = contexttx.contextctl.automatic_transition_source_tokens(
                config, previous_context, rollover_task,
            ) + released_reference_tokens
            rollover_task["loaded_references"] = []
            rollover_task["tokens_used"] = max(
                int(previous_task.get("tokens_used", 0)), rollover_estimate,
            )
            rollover_state = budget_snapshot(rollover_task, config)["state"]
        except (OSError, ValueError, TypeError, KeyError, SystemExit) as error:
            raise SystemExit(
                f"new task requires an exact rollover budget forecast: {error}"
            )
        if rollover_state in {"must_compact", "hard_blocked"}:
            raise SystemExit(
                f"new task would enter {rollover_state} at its first checkpoint; "
                "establish a verified host compaction or select an authorized "
                "higher-budget mode before starting new scope"
            )
    if agents_state.get("schema") != "agent-team/v9":
        raise SystemExit("new task requires the current agent-team/v9 ledger")
    historical_fields = ("members", "prepared_dispatches", "capacity_failures", "replay_runs")
    if any(agents_state.get(field) for field in historical_fields):
        raise SystemExit(
            "new task requires a fresh platform-empty snapshot and `agentledger.py init "
            "--archive-existing --platform-snapshot <snapshot>` before start"
        )
    accounting = agents_state.get("token_accounting")
    if (
        not isinstance(accounting, dict)
        or accounting.get("schema") != "agent-child-token-accounting/v1"
        or accounting.get("settled_tokens") != 0
    ):
        raise SystemExit("new task requires an empty child-Agent Token ledger")
    if active_replacement and not args.archive_human_decision_receipt:
        raise SystemExit("unfinished task archival requires a provider-signed human decision receipt")
    if command_cleanup():
        raise SystemExit("new task blocked because registered local runtime could not be cleaned")
    runtime_state = load_json(RUNTIME_PATH)
    if runtime_state.get("schema") != "agent-runtime/v2" or not isinstance(runtime_state.get("baseline"), dict) or runtime_state["baseline"].get("source") == "template-uninitialized":
        capture_runtime_baseline("agentctl:start")
    if command_assert_clean():
        raise SystemExit("new task blocked because the project process baseline detected a residual")
    capture_runtime_baseline("agentctl:start")
    decision_policy_version = humandecision.decision_policy_version(
        config, mode=mode, environment=args.environment,
        deployment_requested=bool(args.deploy), risk_flags=risk_flags,
    )
    node0_errors: List[str] = []
    if not args.title.strip():
        node0_errors.append("title must be non-empty")
    if args.task_type not in {"product", "release", "maintenance", "governance", "documentation"}:
        node0_errors.append(f"task_type is invalid: {args.task_type}")
    if mode not in {"fast", "standard", "release"}:
        node0_errors.append(f"mode is invalid: {mode}")
    if decision_policy_version != humandecision.PROVIDER_POLICY_VERSION:
        node0_errors.append("routing decision receipt (decision_policy_version) is missing")
    if node0_errors:
        raise SystemExit("node 0 minimal contract failed; refusing start: " + "; ".join(node0_errors))
    # Starting a task grants no implementation or delivery authority. A
    # protected task must therefore be allowed to enter clarification even
    # when the provider-owned decision adapter is not configured yet. The
    # adapter remains mandatory and fail-closed in command_approve() and all
    # later protected gates.
    actual_branch = current_git_branch()
    branch = actual_branch if args.branch == "auto" and actual_branch else ("unversioned" if args.branch == "auto" else args.branch)
    if actual_branch and branch != actual_branch:
        raise SystemExit(f"declared branch {branch} differs from Git HEAD {actual_branch}")
    if args.environment in {"test", "production"} and (not actual_branch or not branch_allowed(branch, config["branches"][args.environment])):
        raise SystemExit(f"Git HEAD branch {branch} is not allowed for {args.environment}")
    if args.environment=="local" and actual_branch and not branch_allowed(branch,config["branches"]["local"]):
        raise SystemExit(f"Git HEAD branch {branch} is not allowed for local development")
    task_archive = previous_task.get("task_archive")
    archive_side_effect: Optional[Tuple[Path, bytes]] = None
    if active_replacement:
        task_digest = hashlib.sha256(boundedio.read_bytes(TASK_PATH,label="task state")).hexdigest()
        if not args.archive_human_decision_receipt:
            raise SystemExit("unfinished task archival requires a provider-signed human decision receipt")
        archive_decision_receipt = humandecision.verify(
            AGENT_DIR.parent.resolve(), config, previous_task, gate="task-archive",
            artifact_sha256=task_digest, source=args.archive_source,
            receipt=args.archive_human_decision_receipt,
        )
        archive_assurance = "provider-signed-user-message"
        task_archive, archive_path, archive_data = build_task_archive(
            previous_task, source=args.archive_source, reason=args.archive_reason.strip(),
            decision_receipt=archive_decision_receipt, assurance=archive_assurance,
        )
        archive_side_effect = (archive_path, archive_data)
    elif previous_task.get("status") == "accepted":
        task_archive, archive_path, archive_data = build_task_archive(
            previous_task, source="workflow:accepted",
            reason="accepted task archived before starting the next requirement",
            decision_receipt=None, assurance="completed-workflow-checkpoint",
        )
        archive_side_effect = (archive_path, archive_data)
    knowledge_side_effect=None
    prior_candidates=previous_task.get("knowledge_candidates")
    if archive_side_effect is not None and isinstance(prior_candidates,list) and prior_candidates:
        pending=load_knowledge_pending(); expected={item.get("candidate_id") for item in prior_candidates if isinstance(item,dict)}
        observed={item.get("candidate_id") for item in pending["candidates"] if isinstance(item,dict) and item.get("task_generation_id")==previous_task.get("task_generation_id")}
        if not expected or not expected<=observed:
            raise SystemExit("next task blocked: completion knowledge candidates are not durably published")
    task = {
        "schema": "agent-task/v2", "title": args.title, "mode": mode,
        "task_type": args.task_type, "complexity": args.complexity, "files": args.files,
        "environment": args.environment, "deployment_requested": args.deploy, "branch": branch, "status": "waiting_human",
        "phase": "clarification", "requirements_clarified": False,
        "token_budget": config["routing"]["modes"][mode]["token_budget"], "tokens_used": 0, "token_usage_source": "estimated", "usage_receipts": [], "child_agents_used": 0, "peak_child_agents": 0,
        "budget_state": "ok",
        "risk_flags": risk_flags,
        "requirement_source": "pending", "primary_skill": "clarify-task",
        "loaded_references": [], "selected_templates": ["requirement-contract"], "selected_capabilities": ["core"], "template_route": None, "rendered_artifacts": [], "decisions": [], "open_questions": ["requirement contract approval"],
        "current_node": 1, "accepted_nodes": [0], "node_artifacts": {}, "gate_approvals": {}, "pending_gate_artifacts": {},
        "production_provider": None,
        "projection": workflow_state.task_projection(args.task_type, mode),
        "rollback_ledger": [], "rollback_archive": None,
        "failure_ledger": {}, "failure_archive": None, "mode_status": "provisional",
        "decision_policy_version": decision_policy_version,
        "selected_model": selected_model,
        "completed_model": None,
        "task_generation_id": "task-"+os.urandom(16).hex(),
        "task_archive": task_archive,
        "metrics": {"tokens": 0, "token_source": "estimated", "child_agents": 0, "peak_children": 0, "tool_calls": 0, "test_runs": 0, "test_failures": 0, "repair_rounds": 0, "user_corrections": 0, "context_compactions": 0, "references_loaded": 0},
        "next_action": "clarify and approve the requirement contract",
        "updated": time.strftime("%Y-%m-%d"),
    }
    skill_activation,skill_activation_data=build_task_skill_activation(task["task_generation_id"],skill_verification,skill_lock,skill_captured)
    task["skill_activation"]=skill_activation
    contract_data = new_contract_bytes(args.title, args.environment)
    test_budget_data = b'{\n  "schema": "agent-test-budget/v1",\n  "candidates": {}\n}\n'
    config_for_task=copy.deepcopy(config); config_for_task.setdefault("agent_control",{})["default_model"]=selected_model
    config_data=(json.dumps(config_for_task,ensure_ascii=False,indent=2)+"\n").encode()
    agents_for_task = copy.deepcopy(agents_state)
    agents_for_task["default_model"] = selected_model
    agents_for_task["epoch"] = hashlib.sha256(
        f"{AGENT_DIR.parent.resolve()}|{args.title}|{time.time_ns()}".encode()
    ).hexdigest()
    agents_for_task["token_accounting"] = {
        "schema": "agent-child-token-accounting/v1",
        "token_budget": task["token_budget"],
        "settled_tokens": 0,
    }
    agents_for_task["last_platform_snapshot"] = None
    agents_for_task["platform_empty_verified"] = False
    agents_for_task["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S+00:00",time.gmtime())
    # Advance the append hash chain exactly like agentledger.save would;
    # the journal tip is appended only after the transition commits.
    agents_data = agents_chain_advance(agents_for_task)
    sync_context(
        "new-task", before_task=previous_task, after_task=task, operation="start",
        summary="started a new task in clarification",
        side_effects=[
            (CONTRACT_PATH, contract_data), (TEST_BUDGET_PATH, test_budget_data),
            (CONFIG_PATH,config_data),(SKILL_ACTIVATION_PATH,skill_activation_data),(AGENTS_PATH, agents_data),
            *([archive_side_effect] if archive_side_effect is not None else []),
            *([knowledge_side_effect] if knowledge_side_effect is not None else []),
        ],
    )
    agents_chain_journal_append(agents_for_task, agents_data)
    delivery=run_bounded_command([sys.executable,str(AGENT_DIR/"scripts"/"deliveryctl.py"),"init"],cwd=AGENT_DIR.parent,timeout=120)
    if delivery.returncode:
        raise SystemExit("failed to initialize delivery state")
    notice = knowledge_pending_notice()
    if notice is not None:
        print(f"KNOWLEDGE PENDING: {notice}")
    print(f"STARTED {mode} task in clarification; implementation is blocked")
    return 0


def command_approve(args: argparse.Namespace) -> int:
    if not args.source.startswith("user:"):
        raise SystemExit("approval source must start with user:")
    task = load_json(TASK_PATH)
    before_task = copy.deepcopy(task)
    config = load_json(CONFIG_PATH)
    if config.get("guardrails_ready") is not True:
        raise SystemExit("project guardrails are incomplete; clarification cannot be approved")
    if task.get("phase") != "clarification" or task.get("status") != "waiting_human" or task.get("requirements_clarified") is not False:
        raise SystemExit("approval is allowed only for the active waiting clarification")
    unresolved = contract_errors(require_approved=False, expected_environment=str(task.get("environment", "")))
    if unresolved:
        raise SystemExit("requirement contract is unresolved:\n- " + "\n- ".join(unresolved))
    if any(question != "requirement contract approval" for question in task.get("open_questions", [])):
        raise SystemExit("material open questions remain")
    production_target = production_target_from_contract(
        config,
        required=task.get("environment") == "production" and task.get("deployment_requested") is True,
    )
    contract_data, contract_hash = contract_with_decision(args.source)
    if task.get("decision_policy_version") != humandecision.PROVIDER_POLICY_VERSION:
        raise SystemExit("requirement approval requires migration to the provider-owned decision policy")
    prospective_task=copy.deepcopy(task)
    prospective_task.update({"requirement_contract_sha256":contract_hash,"production_provider":production_target})
    request={
        "schema":"agent-human-decision-request/v1","gate":"requirement",
        "artifact_sha256":contract_hash,"artifact_bytes":len(contract_data),"source":args.source,
        "task_title":prospective_task.get("title"),"task_mode":prospective_task.get("mode"),
        "routing_profile_sha256":humandecision.routing_profile_sha256(prospective_task),
        "project_identity_sha256":humandecision.project_identity_sha256(AGENT_DIR.parent.resolve(),config),
        "task_generation_sha256":humandecision.task_generation_sha256(prospective_task),
        "task_generation_id":prospective_task.get("task_generation_id"),
    }
    request["request_sha256"]=hashlib.sha256(json.dumps(request,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    if args.print_decision_request:
        if args.human_decision_receipt:
            raise SystemExit("--print-decision-request cannot consume a human decision receipt")
        print(json.dumps(request,ensure_ascii=False,sort_keys=True,separators=(",",":")))
        return 0
    if not args.human_decision_receipt:
        raise SystemExit("requirement approval requires --human-decision-receipt from the configured provider-owned adapter")
    decision_receipt = humandecision.verify(
        AGENT_DIR.parent.resolve(), config, prospective_task,
        gate="requirement", artifact_sha256=contract_hash,
        source=args.source, receipt=args.human_decision_receipt,
    )
    task.update({
        "requirements_clarified": True, "requirement_source": args.source,
        "production_provider": production_target,
        "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md", "requirement_contract_sha256": contract_hash,
        "status": "in_progress", "phase": "planning", "primary_skill": "run-ai-coding-pipeline",
        "open_questions": [], "next_action": "select templates and write tests before implementation",
        "current_node": 2, "accepted_nodes": [0, 1], "mode_status": "confirmed",
        "gate_approvals": {
            **task.get("gate_approvals", {}),
            "requirement": {"source": args.source, "artifact_sha256": contract_hash, "decision_receipt": decision_receipt},
        },
        "node_artifacts": {**task.get("node_artifacts", {}), "1": {"path": ".agent/state/REQUIREMENT_CONTRACT.md", "sha256": contract_hash, "bytes": len(contract_data)}},
        "updated": time.strftime("%Y-%m-%d"),
    })
    task["budget_state"] = budget_snapshot(task, load_json(CONFIG_PATH))["state"]
    sync_context(
        "requirement-approved", before_task=before_task, after_task=task, operation="approve-requirements",
        summary="human-approved requirement contract entered planning",
        side_effects=[(CONTRACT_PATH, contract_data)],
    )
    print("REQUIREMENTS APPROVED")
    return 0


def command_promote_knowledge(args: argparse.Namespace) -> int:
    """Promote one exact accepted candidate with provider-authenticated prepared authority.

    Descriptor-relative operations provide integrity isolation for the managed tree;
    they do not confine hostile code already running as the repository owner.
    """
    if not str(args.source).startswith("user:"): raise SystemExit("knowledge promotion requires --source user:<decision>")
    with locked_knowledge_promotion():
        recover_knowledge_promotion_transaction()
        pending,pending_snapshot=_promotion_json(KNOWLEDGE_PENDING_PATH,"knowledge pending registry",1048576)
        if pending.get("schema")!="agent-knowledge-pending/v2" or not isinstance(pending.get("candidates"),list) or not isinstance(pending.get("promotions"),list): raise SystemExit("knowledge pending registry is malformed")
        matching=[entry for entry in pending["candidates"] if isinstance(entry,dict) and entry.get("candidate_id")==args.candidate_id]
        if len(matching)!=1: raise SystemExit("knowledge candidate ID is missing or ambiguous")
        entry=matching[0]; task=_promotion_task_from_archive(entry); _promotion_validate_candidate(entry,task,args.candidate_id); _promotion_expiry(entry)
        checker=run_bounded_command([sys.executable,str(AGENT_DIR/"scripts/knowledgectl.py"),"check"],cwd=AGENT_DIR.parent,timeout=120)
        if checker.returncode: raise SystemExit("knowledge promotion requires a valid project registry: "+checker.stdout.strip()[:1000])
        registry_path=AGENT_DIR/"project/knowledge/registry.json"; registry_snapshot=promotion_snapshot(registry_path,"knowledge registry")
        if registry_snapshot is None: raise SystemExit("knowledge registry is missing")
        owner_path,owner_relative,owner_snapshot,owner_after,promotion_id=_promotion_owner_plan(entry,args.source,registry_snapshot)
        if any(isinstance(item,dict) and item.get("promotion_id")==promotion_id for item in pending["promotions"]): raise SystemExit("knowledge promotion already committed")
        artifact_sha=hashlib.sha256(owner_after).hexdigest(); config,_config_snapshot=_promotion_json(CONFIG_PATH,"promotion config",2*1024*1024)
        request={"schema":"agent-human-decision-request/v1","gate":"knowledge","artifact_sha256":artifact_sha,"artifact_bytes":len(owner_after),"source":args.source,"task_title":task.get("title"),"task_mode":task.get("mode"),"routing_profile_sha256":humandecision.routing_profile_sha256(task),"project_identity_sha256":humandecision.project_identity_sha256(AGENT_DIR.parent.resolve(),config),"task_generation_sha256":humandecision.task_generation_sha256(task),"task_generation_id":task.get("task_generation_id")}
        request["request_sha256"]=hashlib.sha256(json.dumps(request,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        if args.print_decision_request:
            if args.human_decision_receipt: raise SystemExit("--print-decision-request cannot consume a receipt")
            print(json.dumps(request,ensure_ascii=False,sort_keys=True,separators=(",",":"))); return 0
        if not args.human_decision_receipt: raise SystemExit("knowledge promotion requires a provider-signed human decision receipt")
        prepared=humandecision.prepare_decision_request(AGENT_DIR.parent.resolve(),config,task,gate="knowledge",artifact_sha256=artifact_sha,source=args.source,receipt=args.human_decision_receipt,require_fresh=True)
        authenticated=humandecision.status_prepared_decision(AGENT_DIR.parent.resolve(),config,task,gate="knowledge",artifact_sha256=artifact_sha,source=args.source,prepared=prepared)
        if authenticated.get("status")!="unconsumed": raise SystemExit("knowledge promotion requires one authenticated unconsumed provider decision")
        _promotion_expiry(entry); require_promotion_snapshot(CONFIG_PATH,_config_snapshot,"promotion provider config"); require_promotion_snapshot(registry_path,registry_snapshot,"knowledge registry"); require_promotion_snapshot(owner_path,owner_snapshot,"knowledge owner"); require_promotion_snapshot(KNOWLEDGE_PENDING_PATH,pending_snapshot,"knowledge pending registry")
        task_raw=json.dumps(task,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode(); prepared_at=dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        journal={"schema":"agent-knowledge-promotion-transaction/v3","phase":"prepared","registry_sha256":registry_snapshot["sha256"],"candidate_id":entry["candidate_id"],"entry":entry,"source":args.source,"artifact_sha256":artifact_sha,"owner_path":owner_relative.as_posix(),"owner_preimage_sha256":owner_snapshot["sha256"],"owner_after_b64":base64.b64encode(owner_after).decode("ascii"),"pending_preimage_sha256":pending_snapshot["sha256"],"pending_preimage_b64":base64.b64encode(pending_snapshot["bytes"]).decode("ascii"),"prepared_decision":prepared,"task_sha256":hashlib.sha256(task_raw).hexdigest(),"task_b64":base64.b64encode(task_raw).decode("ascii"),"config_sha256":_config_snapshot["sha256"],"config_b64":base64.b64encode(_config_snapshot["bytes"]).decode("ascii"),"prepared_at":prepared_at,"decision_record":None,"targets":None}
        _promotion_atomic_write(KNOWLEDGE_PROMOTION_JOURNAL_PATH,(json.dumps(journal,ensure_ascii=False,indent=2,sort_keys=True)+"\n").encode())
        if os.environ.get("AGENT_WORKFLOW_PROMOTION_SELF_TEST_CRASH")=="after-prepared-journal": os._exit(96)
        recover_knowledge_promotion_transaction()
    remaining,_snapshot=_promotion_json(KNOWLEDGE_PENDING_PATH,"knowledge pending registry",1048576)
    print(f"KNOWLEDGE PROMOTED: registry owner {entry['owner_id']} updated; {len(remaining['candidates'])} candidate(s) remain pending")
    return 0



def validated_loopback_health_url(raw: str) -> str:
    try: parsed=urllib.parse.urlsplit(raw); port=parsed.port
    except (TypeError,ValueError) as error: raise SystemExit("managed-run health URL is invalid") from error
    if (parsed.scheme!="http" or parsed.hostname not in {"127.0.0.1","localhost","::1"}
            or parsed.username is not None or parsed.password is not None or parsed.fragment):
        raise SystemExit("managed-run health URL must be canonical loopback HTTP")
    if port is not None and not (1<=port<=65535): raise SystemExit("managed-run health URL port is invalid")
    return raw


class RejectManagedHealthRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,new_url): return None


class ManagedRunSignal(Exception):
    def __init__(self, signum: int):
        super().__init__(f"managed-run interrupted by signal {signum}")
        self.signum = signum


MAX_MANAGED_RUN_TIMEOUT_SECONDS=3600
MAX_MANAGED_RUN_OUTPUT_BYTES=4*1024*1024


def command_managed_run(args: argparse.Namespace) -> int:
    """Run one bounded launch-scoped local command and prove normal-path cleanup."""
    try: import testrun as bounded_supervisor
    except ImportError as error: raise SystemExit("managed-run bounded supervisor is unavailable") from error
    task=load_json(TASK_PATH)
    if task.get("requirements_clarified") is not True: raise SystemExit("local execution is blocked until requirements are clarified and human-approved")
    enforce_budget_action(task,load_json(CONFIG_PATH),"managed-run")
    command=list(args.command_line)
    if command and command[0]=="--": command=command[1:]
    if not command: raise SystemExit("managed-run requires a command after --")
    health_url=validated_loopback_health_url(args.health_url) if args.health_url else None
    health_opener=urllib.request.build_opener(RejectManagedHealthRedirect()) if health_url else None
    if not isinstance(args.timeout,int) or isinstance(args.timeout,bool) or not 1<=args.timeout<=MAX_MANAGED_RUN_TIMEOUT_SECONDS:
        raise SystemExit(f"managed-run timeout must be between 1 and {MAX_MANAGED_RUN_TIMEOUT_SECONDS} seconds")
    if command_assert_clean(): raise SystemExit("managed-run requires a clean runtime registry")
    previous_handlers={}
    def handle_signal(signum,_frame): raise ManagedRunSignal(signum)
    for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        previous_handlers[signum]=signal.getsignal(signum); signal.signal(signum,handle_signal)
    process=None; record=None; result=None; cleanup_proven=False; outcome=1; healthy=False
    launch_token=secrets.token_hex(16); launch_environment=dict(os.environ)
    launch_environment[bounded_supervisor.LAUNCH_TOKEN_NAME]=launch_token
    def health_complete():
        nonlocal healthy
        if health_opener is None: return False
        try:
            with health_opener.open(health_url,timeout=0.5) as response: healthy=200<=response.status<300
        except (urllib.error.URLError,TimeoutError,OSError): healthy=False
        if healthy: print(f"MANAGED RUN HEALTHY: {health_url}")
        return healthy
    try:
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL: raise SystemExit("managed-run requires default SIGCHLD ownership")
        with bounded_supervisor.child_subreaper() as boundary_supported:
            if not boundary_supported: raise SystemExit("managed-run cannot establish exact launch ownership on this host")
            process=subprocess.Popen(command,cwd=str(AGENT_DIR.parent),env=launch_environment,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,close_fds=True,bufsize=0)
            identity_status,identity=native_process_identity(process.pid)
            if identity_status!="ok" or identity is None or int(identity.get("pgid",0))!=process.pid:
                try: process.kill(); process.wait(timeout=2)
                except (OSError,subprocess.TimeoutExpired): pass
                raise SystemExit("managed command stable process identity is unavailable")
            record={key:identity[key] for key in ("pid","pgid","start_time","command")}
            record.update({"cwd":str(AGENT_DIR.parent.resolve()),"name":args.name,"kind":"managed","scope":"isolated_process_group",
                "member_identities":[{"pid":process.pid,"pgid":process.pid,"start_time":identity["start_time"]}]})
            with locked_runtime() as runtime: runtime.setdefault("processes",[]).append(record)
            result=bounded_supervisor.supervise_bounded_process(process,timeout=args.timeout,launch_token=launch_token,
                output_limit=MAX_MANAGED_RUN_OUTPUT_BYTES,grace=float(load_json(CONFIG_PATH)["runtime"]["term_timeout_seconds"]),
                completion_predicate=health_complete if health_url else None)
        cleanup_proven=bool(result["cleanup_ok"] and not result["uncertain"])
        output=result["output"].decode("utf-8",errors="replace")
        if output: sys.stdout.write(output); sys.stdout.flush()
        if result["output_limit_exceeded"]: raise SystemExit("managed command exceeded its output byte limit")
        if result["timed_out"]: raise SystemExit("managed command timed out")
        if result["residual_descendants"]: raise SystemExit("managed command detached a launch-scoped descendant")
        if result["uncertain"] or not result["cleanup_ok"]: raise SystemExit("managed-run could not prove launch-scoped cleanup")
        if health_url and not result["externally_completed"]: raise SystemExit("managed command exited before health check")
        outcome=int(result["exit_code"]); return outcome
    except ManagedRunSignal as interrupted:
        cleanup_proven=bool(getattr(interrupted,"bounded_cleanup_ok",False))
        print(f"MANAGED RUN INTERRUPTED: signal={interrupted.signum}"); return 128+interrupted.signum
    except KeyboardInterrupt as interrupted:
        cleanup_proven=bool(getattr(interrupted,"bounded_cleanup_ok",False))
        print("MANAGED RUN INTERRUPTED: keyboard"); return 130
    finally:
        if record is not None and cleanup_proven:
            with locked_runtime() as runtime:
                runtime["processes"]=[item for item in runtime.get("processes",[]) if item.get("pid")!=record["pid"]]
        for signum,handler in previous_handlers.items(): signal.signal(signum,handler)
        if record is not None:
            if not cleanup_proven: raise SystemExit("managed-run cleanup is uncertain; registry record retained")
            if command_assert_clean(): raise SystemExit("managed-run cleanup left a registered residual")
            record_automatic_execution_metrics(command,outcome,"managed-run")


def command_tool_run(args: argparse.Namespace) -> int:
    """Reject local Agent impersonation; reviewer tools belong to platform supervision."""
    raise SystemExit("tool-run is disabled because a local --agent-id cannot authenticate a platform Agent; execute reviewer tools through the platform supervisor")

def command_register_process(args: argparse.Namespace) -> int:
    snapshot = process_snapshot(args.pid)
    if args.pid <= 1 or snapshot is None or str(snapshot["state"]).startswith("Z"):
        raise SystemExit("registered PID must be a live explicit process")
    if snapshot.get("pgid") != args.pid:
        raise SystemExit("manual runtime registration requires an isolated process-group leader (pid == pgid)")
    if process_group_intersects_live_ancestors(args.pid) is not False:
        raise SystemExit("manual runtime registration cannot target the controller or its live ancestor process group")
    record = {key: snapshot[key] for key in ("pid", "pgid", "start_time", "command", "cwd")}
    record.update({"name": args.name, "kind": args.kind, "scope": "isolated_process_group"})
    with locked_runtime() as runtime:
        items = runtime.setdefault("processes", [])
        existing = next((item for item in items if isinstance(item, dict) and item.get("pid") == args.pid), None)
        if existing is not None and not same_process(existing, snapshot):
            raise SystemExit("PID is already registered with a different process identity")
        if existing is None:
            items.append(record)
    print(f"REGISTERED process {args.pid}")
    return 0


def command_register_docker(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"agent_[a-z0-9][a-z0-9_-]{4,60}", args.project):
        raise SystemExit("Docker project must be unique and start with agent_")
    workdir = Path(args.workdir).resolve()
    files = [str((workdir / raw).resolve()) for raw in (args.file or ["compose.yaml"])]
    if len(files) != len(set(files)):
        raise SystemExit("Docker Compose files must be unique")
    if not workdir.is_dir() or any(not Path(path).is_file() for path in files):
        raise SystemExit("registered Docker workdir and compose files must exist")
    volumes = sorted(set(args.volume or []))
    if any(not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", name) for name in volumes):
        raise SystemExit("declared Docker named volumes must be valid volume names")
    identity = {"project": args.project, "workdir": str(workdir), "files": files}
    if volumes:
        identity["volumes"] = volumes
    identity_payload = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    record = {
        "project": args.project, "workdir": str(workdir), "files": files,
        "identity_sha256": hashlib.sha256(identity_payload).hexdigest(),
    }
    if volumes:
        record["volumes"] = volumes
    with locked_runtime() as runtime:
        items = runtime.setdefault("docker_projects", [])
        existing = next(
            (item for item in items if isinstance(item, dict) and item.get("project") == args.project), None
        )
        if existing is not None and existing != record:
            raise SystemExit("Docker project is already registered with a different identity")
        if existing is None:
            items.append(record)
    print(f"REGISTERED docker project {args.project}")
    return 0


def command_register_port(args: argparse.Namespace) -> int:
    if not 1 <= args.port <= 65535:
        raise SystemExit("port must be between 1 and 65535")
    if args.host != "127.0.0.1":
        raise SystemExit("local runtime ports must bind explicitly to 127.0.0.1")
    with locked_runtime() as runtime:
        processes = runtime.get("processes", [])
        owner = next((item for item in processes if isinstance(item, dict) and item.get("pid") == args.pid), None)
        if owner is None:
            raise SystemExit("register the owning process before its port")
        if not same_process(owner, process_snapshot(args.pid)):
            raise SystemExit("registered process identity no longer matches the port owner")
        listener_owners = tcp_listener_owners(args.port, args.host)
        if listener_owners is None or listener_owners != [args.pid]:
            raise SystemExit(f"port listener owner mismatch: expected {args.pid}, observed {listener_owners}")
        record = {"host": args.host, "port": args.port, "protocol": "tcp", "pid": args.pid}
        items = runtime.setdefault("ports", [])
        if record not in items:
            items.append(record)
    print(f"REGISTERED port {args.port}")
    return 0


def cleanup_tool_leases(timeout: int) -> List[str]:
    failures: List[str] = []
    now_utc = dt.datetime.now(dt.timezone.utc)
    with locked_tool_leases() as state:
        if state.get("schema") != "agent-tool-leases/v1" or not isinstance(state.get("leases"), list):
            return ["tool-lease-registry:invalid"]
        retained = []
        for lease in state["leases"]:
            if not isinstance(lease, dict):
                failures.append(f"tool-lease:{lease}:invalid")
                retained.append(lease)
                continue
            lease_id = str(lease.get("id", "unknown"))
            process = lease.get("process")
            try:
                deadline = dt.datetime.fromisoformat(str(lease.get("deadline_at")))
                if deadline.tzinfo is None:
                    raise ValueError("timezone required")
                deadline = deadline.astimezone(dt.timezone.utc)
            except (TypeError, ValueError):
                deadline = now_utc - dt.timedelta(seconds=1)
            owner_active = active_review_agent_member(str(lease.get("owner_agent_id", ""))) is not None
            supervisor = lease.get("supervisor")
            supervisor_pid = supervisor.get("pid") if isinstance(supervisor, dict) else None
            try:
                supervisor_live = isinstance(supervisor, dict) and same_process(
                    supervisor, process_snapshot(int(supervisor_pid))
                )
            except (TypeError, ValueError):
                supervisor_live = False
            group_live = isinstance(process, dict) and process_group_alive(int(process.get("pgid", 0)))
            if owner_active and deadline > now_utc and group_live and supervisor_live:
                # A valid sibling review lease is supervised foreground work,
                # not a product-runtime residual.  Preserve it; its wrapper or
                # an owner/deadline failure owns exact group termination.
                retained.append(lease)
                continue
            if not isinstance(process, dict):
                # A lease without a dict process record cannot be terminated
                # exactly; keep it visible instead of silently dropping it.
                failures.append(f"tool-lease:{lease_id}:malformed-process-record")
                retained.append(lease)
                continue
            if not terminate_isolated_group(process, timeout):
                failures.append(f"tool-lease:{lease_id}:could-not-terminate-exact-group")
                retained.append(lease)
        state["leases"] = retained
    return failures


def sweep_context_authorizations() -> List[str]:
    """Remove transition authorizations stranded past their 60s validity window.

    contexttx deletes each authorization in a ``finally`` after the transition
    commits, but a hard kill between issue and commit strands the file.  Any
    record older than its validity window can never authorize anything again,
    so sweeping it here loses no live state.
    """
    warnings: List[str] = []
    if not CONTEXT_AUTH_DIR.is_dir():
        return warnings
    now = dt.datetime.now(dt.timezone.utc)
    swept=0; entries=[]
    try:
        with os.scandir(CONTEXT_AUTH_DIR) as scanner:
            for observed in scanner:
                if len(entries)>=4096:
                    warnings.append("context authorization inventory exceeds 4096 entries"); return warnings
                entries.append(Path(observed.path))
    except OSError:
        warnings.append("context authorization inventory is unreadable"); return warnings
    for entry in sorted(entries,key=lambda item:os.fsencode(item.name)):
        if not entry.is_file() or entry.is_symlink():
            continue
        issued = None
        try:
            raw=_project_regular_snapshot(entry.relative_to(AGENT_DIR.parent),"context authorization",64*1024)["bytes"]
            value=json.loads(raw.decode("utf-8"))
            if isinstance(value, dict):
                issued = dt.datetime.fromisoformat(str(value.get("issued_at", "")))
        except SystemExit:
            warnings.append(f"unsafe stranded context authorization was not swept: {entry.name}"); continue
        except (OSError,ValueError): issued=None
        if not isinstance(issued, dt.datetime) or issued.tzinfo is None:
            issued = dt.datetime.fromtimestamp(entry.stat().st_mtime, dt.timezone.utc)
        if (now - issued.astimezone(dt.timezone.utc)).total_seconds() <= CONTEXT_AUTHORIZATION_TTL_SECONDS:
            continue
        try:
            entry.unlink()
            swept += 1
        except OSError:
            warnings.append(f"could not sweep stranded context authorization: {entry.name}")
    if swept:
        _fsync_directory(CONTEXT_AUTH_DIR)
        warnings.append(f"swept {swept} stranded context authorization(s) past their 60s validity window")
    return warnings


def command_cleanup() -> int:
    config = load_json(CONFIG_PATH)
    timeout = int(config.get("runtime", {}).get("term_timeout_seconds", 8))
    failures = cleanup_tool_leases(timeout)
    with locked_runtime() as runtime:
        for item in list(runtime.get("processes", [])):
            if not isinstance(item, dict) or not isinstance(item.get("pid"), int) or not terminate_registered_process(item, timeout):
                failures.append(f"process:{item}")
        for item in list(runtime.get("docker_projects", [])):
            if not isinstance(item, dict) or not docker_identity_valid(item):
                failures.append(f"docker:{item}")
                continue
            command = ["docker", "compose"]
            for file in item["files"]:
                command.extend(["-f", str(file)])
            command.extend(["-p", str(item["project"]), "down", "--remove-orphans"])
            if item.get("volumes"):
                command.append("-v")
            try:
                down=run_bounded_command(command,cwd=str(item["workdir"]),timeout=60,output_limit=MAX_DOCKER_CONTROL_OUTPUT_BYTES)
            except (OSError, subprocess.TimeoutExpired):
                failures.append(f"docker:{item['project']}")
                continue
            residual = docker_residual(str(item["project"]))
            if down.returncode or residual is None or any(residual.values()):
                failures.append(f"docker:{item['project']}:{residual}")
        for item in runtime.get("ports", []):
            if not isinstance(item, dict) or item.get("protocol") != "tcp" or not isinstance(item.get("port"), int) or port_in_use(item["port"], str(item.get("host"))):
                failures.append(f"port:{item}:still-in-use")
        if not failures:
            baseline = runtime.get("baseline")
            runtime.clear()
            runtime.update({"schema": "agent-runtime/v2", "baseline": baseline, "processes": [], "docker_projects": [], "ports": []})
    warnings = sweep_context_authorizations()
    if EVIDENCE_TOOL.is_file() and EVIDENCE_INDEX_PATH.is_file():
        try:
            evidence_check=run_bounded_command(
                [sys.executable,str(EVIDENCE_TOOL),"verify","--deep","--quiet"],cwd=AGENT_DIR.parent,timeout=120,
            )
            if evidence_check.returncode:
                detail = evidence_check.stdout.strip().replace("\n", " | ")[:400]
                warnings.append("evidence deep verification failed" + (f": {detail}" if detail else ""))
        except subprocess.TimeoutExpired:
            warnings.append("evidence deep verification timed out after 120s")
    else:
        warnings.append("evidence controller or index is missing; deep verification skipped")
    for warning in warnings:
        print(f"CLEANUP WARNING: {warning}")
    if failures:
        print("CLEANUP FAILED")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("CLEANUP PASSED: zero registered residuals")
    return 0


def command_assert_clean() -> int:
    runtime = load_json(RUNTIME_PATH)
    errors = []
    tool_identities, tool_groups, tool_lease_errors = audited_tool_allowances()
    errors.extend(tool_lease_errors)
    baseline = runtime.get("baseline")
    if runtime.get("schema") != "agent-runtime/v2" or not isinstance(baseline, dict) or baseline.get("source") == "template-uninitialized" or not isinstance(baseline.get("project_processes"), list):
        errors.append("runtime lacks a v2 project-process baseline; capture one before execution")
    else:
        current = stable_project_processes()
        if current is None:
            errors.append("cannot inspect current project processes")
        else:
            allowed = {
                process_identity(item) for item in baseline["project_processes"] if isinstance(item, dict)
            }
            registered = {
                process_identity(item) for item in runtime.get("processes", []) if isinstance(item, dict)
            }
            unregistered = [
                item for item in current
                if process_identity(item) not in allowed | registered | tool_identities
                and int(item.get("pgid", 0)) not in tool_groups
            ]
            for item in unregistered:
                errors.append(
                    f"unregistered project process since baseline: pid={item.get('pid')} "
                    f"ppid={item.get('ppid')} pgid={item.get('pgid')} command={item.get('command')}"
                )
    for item in runtime.get("processes", []):
        if not isinstance(item, dict) or not isinstance(item.get("pid"), int):
            errors.append(f"invalid process record {item}")
            continue
        snapshot = process_snapshot(item["pid"])
        native_status, _ = native_process_identity(item["pid"])
        if snapshot is None and native_status == "gone":
            errors.append(f"stale process record {item['pid']}; run cleanup")
        elif snapshot is None:
            errors.append(f"process identity unavailable {item['pid']}; refusing cleanup")
        elif str(snapshot["state"]).startswith("Z"):
            errors.append(f"stale process record {item['pid']}; run cleanup")
        elif same_process(item, snapshot):
            errors.append(f"live registered process {item['pid']}")
        else:
            errors.append(f"process identity mismatch {item['pid']}; refusing broad cleanup")
    for item in runtime.get("docker_projects", []):
        project = item.get("project") if isinstance(item, dict) else None
        if not isinstance(item, dict) or not docker_identity_valid(item):
            errors.append(f"invalid Docker registration identity: {item}")
            continue
        residual = docker_residual(str(project)) if project else None
        if residual is None or any(residual.values()):
            errors.append(f"docker project {project}: {residual}")
        else:
            errors.append(f"stale Docker record {project}; run cleanup")
    for port in runtime.get("ports", []):
        if not isinstance(port, dict) or not isinstance(port.get("port"), int) or port_in_use(port["port"], str(port.get("host"))):
            errors.append(f"registered port is not clean: {port}")
        else:
            errors.append(f"stale port record {port}; run cleanup")
    if errors:
        print("RUNTIME NOT CLEAN")
        for error in errors:
            print(f"- {error}")
        return 1
    print("RUNTIME CLEAN")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    sub.add_parser("verify-builtins")
    sub.add_parser("status")
    sub.add_parser("sync-stage")
    sub.add_parser("bootstrap-check")
    project_init = sub.add_parser("project-init")
    project_init.add_argument("--guardrails-file", required=True)
    project_init.add_argument("--default-model")
    select_model = sub.add_parser("select-model")
    select_model.add_argument("--model", required=True)
    usage = sub.add_parser("record-usage")
    usage.add_argument("--tokens", type=nonnegative_int)
    usage.add_argument("--source", choices=("measured", "estimated"), required=True)
    usage.add_argument("--receipt")
    usage.add_argument("--child-agents", type=nonnegative_int, default=0)
    usage.add_argument("--peak-child-agents", type=nonnegative_int, default=0)
    budget = sub.add_parser("budget-gate")
    budget.add_argument("--action", required=True)
    metric=sub.add_parser("record-metric"); metric.add_argument("--name",required=True); metric.add_argument("--increment",type=nonnegative_int,default=1)
    reference = sub.add_parser("reference-load")
    reference.add_argument("--path", required=True)
    reference.add_argument("--purpose", required=True)
    unload = sub.add_parser("reference-unload")
    unload.add_argument("--path", required=True)
    start = sub.add_parser("start")
    start.add_argument("--title", required=True)
    start.add_argument("--model", required=True)
    start.add_argument("--mode", choices=("auto", "fast", "standard", "release"), default="auto")
    start.add_argument("--environment", choices=("local", "test", "production"), default="local")
    start.add_argument("--task-type", choices=("product", "release", "maintenance", "governance", "documentation"), default="product")
    # Minimal declaration by default: an undeclared task routes to fast and the
    # node-6 scope gate corrects under-declaration after the fact.
    start.add_argument("--complexity", choices=("tiny", "small", "bounded", "complex"), default="tiny")
    start.add_argument("--branch", default="auto")
    start.add_argument("--files", type=nonnegative_int, default=1)
    start.add_argument("--deploy", action="store_true")
    start.add_argument("--data-risk", action="store_true")
    start.add_argument("--cross-system", action="store_true")
    start.add_argument("--uncertain", action="store_true")
    start.add_argument("--security", action="store_true")
    start.add_argument("--compliance", action="store_true")
    start.add_argument("--migration", action="store_true")
    start.add_argument("--irreversible", action="store_true")
    start.add_argument("--external-impact", action="store_true")
    start.add_argument("--archive-active", action="store_true")
    start.add_argument("--archive-source")
    start.add_argument("--archive-reason")
    start.add_argument("--archive-human-decision-receipt")
    managed = sub.add_parser("managed-run")
    managed.add_argument("--name", required=True)
    managed.add_argument("--timeout", type=int, default=30)
    managed.add_argument("--health-url")
    managed.add_argument("command_line", nargs=argparse.REMAINDER)
    tool = sub.add_parser("tool-run",help="disabled: local Agent IDs are not authentication")
    tool.add_argument("--agent-id", required=True)
    tool.add_argument("--name", required=True)
    tool.add_argument("--timeout", type=int, default=30)
    tool.add_argument("command_line", nargs=argparse.REMAINDER)
    approve = sub.add_parser("approve-requirements")
    approve.add_argument("--source", required=True)
    approve.add_argument("--human-decision-receipt")
    approve.add_argument("--print-decision-request",action="store_true")
    for name in ("escalate-mode", "update-risk"):
        escalation = sub.add_parser(name)
        escalation.add_argument("--new-mode", choices=("fast", "standard", "release"))
        escalation.add_argument("--new-risk", action="append", choices=workflow_state.RISK_NAMES)
        escalation.add_argument("--files", type=nonnegative_int)
        escalation.add_argument("--reapprove", action="store_true")
        escalation.add_argument("--source")
        escalation.add_argument("--human-decision-receipt")
    reopen = sub.add_parser("reopen-clarification")
    reopen.add_argument("--source", required=True)
    reopen.add_argument("--reason", required=True)
    reopen.add_argument("--human-decision-receipt")
    reopen.add_argument("--print-decision-request",action="store_true")
    provider_target = sub.add_parser("configure-production-provider")
    provider_target.add_argument("--target", required=True)
    provider_target.add_argument("--source", required=True)
    process = sub.add_parser("register-process")
    process.add_argument("--pid", type=int, required=True)
    process.add_argument("--name", required=True)
    process.add_argument("--kind", default="server")
    docker = sub.add_parser("register-docker")
    docker.add_argument("--project", required=True)
    docker.add_argument("--workdir", default=".")
    docker.add_argument("--file", action="append")
    docker.add_argument("--volume", action="append")
    port = sub.add_parser("register-port")
    port.add_argument("--port", type=int, required=True)
    port.add_argument("--pid", type=int, required=True)
    port.add_argument("--host", default="127.0.0.1")
    sub.add_parser("cleanup")
    sub.add_parser("assert-clean")
    baseline = sub.add_parser("capture-runtime-baseline")
    baseline.add_argument("--source", required=True)
    baseline.add_argument("--confirm-existing-processes", action="store_true")
    promote = sub.add_parser("promote-knowledge")
    promote.add_argument("candidate_id")
    promote.add_argument("--source", required=True)
    promote.add_argument("--human-decision-receipt")
    promote.add_argument("--print-decision-request",action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    read_only={"validate","verify-builtins","status","bootstrap-check","assert-clean","budget-gate","tool-run"}
    if args.command in read_only:
        pending=[]
        if PROJECT_INIT_JOURNAL_PATH.exists(): pending.append("project-init")
        if KNOWLEDGE_PROMOTION_JOURNAL_PATH.exists(): pending.append("knowledge-promotion")
        if pending: raise SystemExit("RECOVERY REQUIRED: pending transaction(s): "+", ".join(pending))
    else:
        recover_project_init_transaction()
        if args.command!="promote-knowledge":
            with locked_knowledge_promotion():
                recover_knowledge_promotion_transaction()
    commands = {
        "validate": lambda: command_validate(), "verify-builtins": lambda: command_verify_builtins(), "status": lambda: command_status(), "sync-stage": lambda: command_sync_stage(),
        "bootstrap-check": lambda: command_bootstrap_check(),
        "project-init": lambda: command_project_init(args),
        "select-model": lambda: command_select_model(args),
        "record-usage": lambda: command_record_usage(args),
        "budget-gate": lambda: command_budget_gate(args),
        "record-metric": lambda: command_record_metric(args),
        "reference-load": lambda: command_reference_load(args), "reference-unload": lambda: command_reference_unload(args),
        "start": lambda: command_start(args), "approve-requirements": lambda: command_approve(args),
        "escalate-mode": lambda: command_escalate_mode(args),
        "update-risk": lambda: command_escalate_mode(args),
        "reopen-clarification": lambda: command_reopen_clarification(args),
        "configure-production-provider": lambda: command_configure_production_provider(args),
        "managed-run": lambda: command_managed_run(args),
        "tool-run": lambda: command_tool_run(args),
        "register-process": lambda: command_register_process(args), "register-docker": lambda: command_register_docker(args),
        "register-port": lambda: command_register_port(args),
        "cleanup": lambda: command_cleanup(), "assert-clean": lambda: command_assert_clean(),
        "capture-runtime-baseline": lambda: capture_runtime_baseline(
            args.source, confirm_existing=bool(args.confirm_existing_processes)
        ),
        "promote-knowledge": lambda: command_promote_knowledge(args),
    }
    return commands[args.command]()


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
