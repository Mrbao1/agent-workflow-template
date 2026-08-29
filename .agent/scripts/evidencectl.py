#!/usr/bin/env python3
"""Bound active evidence while preserving exact, restorable audit archives.

Task-archive format contract (reader/migrator side — the writer is
`agentctl.py build_task_archive`, owned by another workstream):

Legacy `agent-task-archive/v1` payloads embed the full archived TASK text
(`task.utf8`) and requirement-contract text. Reachability scans them
textually, so every evidence path ever mentioned in any archived TASK stays
reachable forever and eventually deadlocks compaction once active evidence
exceeds `active_max_bytes`.

`agent-task-archive/v2` payloads carry the same identity fields plus a
structured `referenced_evidence` list and are NEVER textually scanned:

    {
      "schema": "agent-task-archive/v2",
      "archived_at": <ISO-8601 str>,
      "source": <str>, "reason": <str>, "assurance": <str>,
      "decision_receipt": <object|null>,
      "task": {"sha256": <hex64>, "bytes": <int>, "utf8": <str>},
      "requirement_contract": {"sha256": <hex64>, "bytes": <int>, "utf8": <str>} | null,
      "skill_activation": {"sha256": <hex64>, "bytes": <int>, "utf8": <str>} | null,
      "delivery": {"sha256": <hex64>, "bytes": <int>, "utf8": <str>} | null,
      "referenced_evidence": [<hex64>, ...],
      "previous": <agent-task-archive-head/v1 | null>
    }

Contract rules:
- Current archives bind exact `task`, requirement, Skill activation, and delivery bytes. A migrated v1 archive uses `skill_activation: null` only when its embedded legacy task declared no activation; migration never fabricates reviewed Skill bytes.
- `referenced_evidence` holds ONLY sha256 digests of the active evidence
  files the archived text referenced at archive time — never literal paths.
  A digest protects every active evidence file whose bytes match it, exactly
  like a literal path reference would.
- Payload bytes are canonical: json.dumps(payload, sort_keys=True,
  separators=(",", ":")) + b"\\n", content-addressed at
  .agent/state/evidence/task-archives/<payload-sha256>.json.
- Head records keep schema `agent-task-archive-head/v1` with fields
  {"schema", "path", "sha256", "bytes", "total_archives"}; TASK.json
  `task_archive` stores the newest head and each payload's `previous`
  embeds the head directly below it.  `task_archive` is a capsule-bound
  TASK invariant: every head move goes through the canonical context
  transition (see commit_task_head) so the capsule is re-bound atomically.
- Reachability traverses task-archives ONLY along `previous` heads and
  `referenced_evidence` digests. v2 payload text is ignored; legacy v1
  payloads stay textually scanned (fail-safe) until rewritten.

`evidencectl.py migrate-task-archives` rewrites legacy v1 chains to v2
(content-addressed, heads re-anchored oldest-first, rewritten chain fully
verified BEFORE the TASK head pointer moves; old v1 files are left in place
as unreachable, compactable evidence).

Digest-only references protect evidence everywhere: a bare sha256 of
evidence bytes in any reference root matches like a literal path.

Reachability roots are configurable via config key `evidence.reference_roots`
(repo-relative files, directories or globs; default covers state, policies,
knowledge, capabilities, workflows, skills, templates, assets, scripts,
docs, plugins and the top-level guidance files).

Operator escape hatches (both refuse to run implicitly):
- `compact --include-task-history --source user:<decision>` deep-archives
  the task-archive head chain too; it requires a human decision record via
  humandecision using a provider-signed receipt for every task policy and
  clears the dangling TASK head. Caller text alone is never authority.
- `compact --gc-orphans` removes the unindexed archive files that `verify`
  reports (crash-leftover temporaries and unindexed ZIPs), after a full
  deep verification of the index they escaped. Orphans are evidence until
  reported; GC always lists what it removes.
"""

from pathlib import Path
import argparse
import copy
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import struct
import time
import zipfile
from typing import Dict, Iterable, List, Optional, Set, Tuple

import humandecision
from workflowlib import boundedio

try:
    import contexttx
except ImportError:  # reduced harnesses ship an evidence-only script subset
    contexttx = None


MAX_EVIDENCE_TREE_ENTRIES=32768
MAX_EVIDENCE_TREE_FILES=16384
MAX_EVIDENCE_FILE_BYTES=32*1024*1024
MAX_REFERENCE_FILE_BYTES=16*1024*1024
MAX_ARCHIVE_RECORDS=32768
MAX_TASK_ARCHIVES=256
MAX_ARCHIVE_DIRECTORY_ENTRIES=65536
MAX_ACTIVE_EVIDENCE_INPUT_BYTES=512*1024*1024
MAX_REFERENCE_INPUT_BYTES=256*1024*1024
MAX_ARCHIVED_MEMBER_BYTES=MAX_REFERENCE_FILE_BYTES
MAX_ARCHIVE_SOURCE_BYTES=MAX_ARCHIVED_MEMBER_BYTES
MAX_ARCHIVE_CONTAINER_BYTES=32*1024*1024
MAX_ARCHIVE_MANIFEST_BYTES=4*1024*1024
MAX_ARCHIVE_ENTRY_METADATA_BYTES=128
MAX_COMPACTION_SELECTED_BYTES=MAX_ARCHIVE_SOURCE_BYTES


def bounded_read(path: Path,label: str,maximum: int=MAX_EVIDENCE_FILE_BYTES) -> bytes:
    try: return boundedio.read_bytes(path,maximum=maximum,label=label)
    except RuntimeError as error: raise SystemExit(str(error)) from error


def bounded_tree(root: Path,label: str,state=None):
    state=state if state is not None else {"entries":0,"files":0}; stack=[root]
    while stack:
        directory=stack.pop()
        try:
            with os.scandir(directory) as scanner:
                batch=[]
                for entry in scanner:
                    state["entries"]+=1
                    if state["entries"]>MAX_EVIDENCE_TREE_ENTRIES: raise SystemExit(f"{label} entry limit exceeded")
                    batch.append(entry)
        except OSError as error: raise SystemExit(f"{label} traversal failed") from error
        for entry in sorted(batch,key=lambda item:os.fsencode(item.name),reverse=True):
            metadata=entry.stat(follow_symlinks=False); path=Path(entry.path)
            if stat.S_ISDIR(metadata.st_mode): stack.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                state["files"]+=1
                if state["files"]>MAX_EVIDENCE_TREE_FILES: raise SystemExit(f"{label} file limit exceeded")
            yield path,metadata


def find_agent_dir() -> Path:
    for root in (Path.cwd().resolve(), *Path.cwd().resolve().parents):
        candidate = root / ".agent"
        if candidate.is_dir():
            return candidate
    raise SystemExit(".agent directory not found")


AGENT = find_agent_dir(); ROOT = AGENT.parent.resolve(); STATE = AGENT / "state"
EVIDENCE = STATE / "evidence"; ARCHIVES = STATE / "evidence-archives"
ARCHIVE_PAGES = STATE / "evidence-archive-pages"
TASK_ARCHIVES = EVIDENCE / "task-archives"
INDEX = STATE / "EVIDENCE_INDEX.json"; CONFIG = AGENT / "config.json"
TASK = STATE / "TASK.json"
LOCK = STATE / ".evidence.lock"
SHA = re.compile(r"[0-9a-f]{64}")
INDEX_SCHEMA = "agent-evidence-index/v2"
ARCHIVE_SCHEMA = "agent-evidence-archive/v1"
HEAD_SCHEMA = "agent-evidence-archive-head/v1"
PAGE_SCHEMA = "agent-evidence-archive-page/v1"
PAGE_HEAD_SCHEMA = "agent-evidence-archive-page-head/v1"
TASK_ARCHIVE_V1 = "agent-task-archive/v1"
TASK_ARCHIVE_V2 = "agent-task-archive/v2"
TASK_ARCHIVE_HEAD_SCHEMA = "agent-task-archive-head/v1"
TASK_HISTORY_DECISION_GATE = "evidence-task-history-compaction"
ARCHIVE_FIELDS = {
    "schema", "path", "sha256", "bytes", "file_count", "source_bytes",
    "created_at", "manifest_sha256",
}
TASK_ARCHIVE_HEAD_FIELDS = {"schema", "path", "sha256", "bytes", "total_archives"}
DEFAULT_REFERENCE_ROOTS = [
    ".agent/state", ".agent/policies", ".agent/knowledge", ".agent/capabilities",
    ".agent/workflows", ".agent/skills", ".agent/templates", ".agent/assets",
    ".agent/scripts", "docs", "plugins",
    "AGENTS.md", "README.md", "CLAUDE.md", "install.py", ".agent/config.json",
]


def load_json(path: Path) -> Dict[str, object]:
    value = json.loads(bounded_read(path,"evidence JSON").decode("utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON object required: {path}")
    return value


def atomic_json(path: Path, value: Dict[str, object]) -> None:
    directory=private_directory_fd(path.parent,"evidence state",True); temporary=f".{path.name}.{secrets.token_hex(16)}"; descriptor=None
    try:
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        with os.fdopen(descriptor,"w",encoding="utf-8") as handle:
            descriptor=None; json.dump(value,handle,ensure_ascii=False,indent=2); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.rename(temporary,path.name,src_dir_fd=directory,dst_dir_fd=directory); temporary=""; os.fsync(directory)
    finally:
        if descriptor is not None: os.close(descriptor)
        if temporary:
            try: os.unlink(temporary,dir_fd=directory)
            except FileNotFoundError: pass
        os.close(directory)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def commit_task_head(before: Dict[str, object], after: Dict[str, object], *, reason: str, summary: str) -> None:
    """Move the TASK `task_archive` head through the canonical context transition.

    `task_archive` is a TASK invariant key bound by the context capsule: a
    raw rewrite leaves `contextctl check` drifted and route-resume fails
    closed until manual repair.  The field-level TRANSITION_PROFILES
    registry lives in contextctl.py (another workstream) and has no
    evidencectl profile, so this transition rides the full-invariant
    ("agentctl", "start") profile — the receipt's reason/summary record the
    real evidence operation.  Reduced harnesses without the context
    controller fall back to the plain atomic write, mirroring the
    reduced-harness pattern in agentledger.commit_registered_ledger.
    """
    if contexttx is None or not (STATE / "CONTEXT.json").is_file():
        atomic_json(TASK, after)
        return
    contexttx.transition_task(
        before, after, mutator="agentctl", operation="start",
        reason=reason, summary=summary,
    )


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def policy() -> Dict[str, object]:
    value = load_json(CONFIG).get("evidence_retention")
    if not isinstance(value, dict):
        raise SystemExit("evidence retention policy is missing")
    return value


def reference_roots() -> List[str]:
    """Reachability roots from config key `evidence.reference_roots`.

    Entries are repo-relative files, directories or glob patterns. Missing
    or malformed config falls back to the built-in default union so older
    installations keep the fail-safe coverage.
    """
    try:
        value = load_json(CONFIG).get("evidence")
    except (OSError, ValueError, json.JSONDecodeError, SystemExit):
        value = None
    roots = value.get("reference_roots") if isinstance(value, dict) else None
    if (
        isinstance(roots, list) and roots
        and all(
            isinstance(item, str) and item.strip()
            and not item.startswith("/") and ".." not in Path(item).parts
            for item in roots
        )
    ):
        return list(roots)
    return list(DEFAULT_REFERENCE_ROOTS)


def load_index() -> Dict[str, object]:
    value = load_json(INDEX)
    if set(value) != {"schema", "archives", "archive_page", "updated_at"} or value.get("schema") != INDEX_SCHEMA:
        raise SystemExit("evidence index schema is invalid")
    if not isinstance(value.get("archives"),list) or len(value["archives"])>MAX_ARCHIVE_RECORDS:
        raise SystemExit("evidence index archives must be one bounded list")
    if value.get("archive_page") is not None and not isinstance(value.get("archive_page"), dict):
        raise SystemExit("evidence index archive_page must be an object or null")
    if value.get("updated_at") is not None and not isinstance(value.get("updated_at"), str):
        raise SystemExit("evidence index updated_at is invalid")
    return value


def private_directory_fd(path: Path,label: str,create: bool=True) -> int:
    try: relative=path.relative_to(ROOT)
    except ValueError as error: raise SystemExit(f"{label} escapes the repository") from error
    if not relative.parts or any(part in {"",".",".."} for part in relative.parts): raise SystemExit(f"{label} is not lexical and safe")
    try: current=boundedio.open_nofollow(ROOT,label)
    except (OSError,RuntimeError) as error: raise SystemExit(f"{label} repository root is unsafe") from error
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    try:
        for part in relative.parts:
            try: following=os.open(part,flags,dir_fd=current)
            except FileNotFoundError:
                if not create: raise
                try: os.mkdir(part,0o700,dir_fd=current); following=os.open(part,flags,dir_fd=current)
                except OSError as error: raise SystemExit(f"{label} directory is unsafe") from error
            except OSError as error: raise SystemExit(f"{label} directory is unsafe") from error
            metadata=os.fstat(following)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=os.geteuid() or stat.S_IMODE(metadata.st_mode)&0o022:
                os.close(following); raise SystemExit(f"{label} directory is unsafe")
            os.close(current); current=following
        return current
    except BaseException:
        os.close(current); raise


def descriptor_digest(descriptor: int,maximum: int,label: str):
    opened=os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink<1 or opened.st_size<0 or opened.st_size>maximum: raise SystemExit(f"{label} is unsafe or oversized")
    identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns,opened.st_mode,opened.st_uid,opened.st_nlink)
    hasher=hashlib.sha256(); total=0; os.lseek(descriptor,0,os.SEEK_SET)
    while True:
        chunk=os.read(descriptor,min(1024*1024,maximum-total+1))
        if not chunk: break
        total+=len(chunk)
        if total>maximum: raise SystemExit(f"{label} exceeds its byte limit")
        hasher.update(chunk)
    final=os.fstat(descriptor); final_identity=(final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns,final.st_ctime_ns,final.st_mode,final.st_uid,final.st_nlink)
    if total!=opened.st_size or final_identity!=identity: raise SystemExit(f"{label} changed while hashing")
    return total,hasher.hexdigest()


def open_regular_at(directory: int,name: str,label: str) -> int:
    if not name or "/" in name or name in {".",".."}: raise SystemExit(f"{label} name is unsafe")
    try: descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
    except OSError as error: raise SystemExit(f"{label} cannot be opened safely") from error
    if not stat.S_ISREG(os.fstat(descriptor).st_mode): os.close(descriptor); raise SystemExit(f"{label} is not regular")
    return descriptor


def publish_content_addressed(directory_path: Path,name: str,data: bytes,label: str) -> None:
    directory=private_directory_fd(directory_path,label,True); temporary=f".{label.replace(' ','-')}.{secrets.token_hex(16)}"; descriptor=None
    expected=digest(data)
    try:
        try: existing=open_regular_at(directory,name,label)
        except SystemExit:
            try: os.stat(name,dir_fd=directory,follow_symlinks=False)
            except FileNotFoundError: existing=None
            else: raise
        if existing is not None:
            try:
                size,value=descriptor_digest(existing,MAX_EVIDENCE_FILE_BYTES,label)
                if size!=len(data) or value!=expected: raise SystemExit(f"{label} digest collision")
                return
            finally: os.close(existing)
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=directory)
        view=memoryview(data); offset=0
        while offset<len(view):
            written=os.write(descriptor,view[offset:])
            if written<=0: raise OSError(f"short {label} write")
            offset+=written
        os.fsync(descriptor); os.fchmod(descriptor,0o444)
        try: os.link(temporary,name,src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
        except FileExistsError:
            collision=open_regular_at(directory,name,label)
            try:
                size,value=descriptor_digest(collision,MAX_EVIDENCE_FILE_BYTES,label)
                if size!=len(data) or value!=expected: raise SystemExit(f"{label} digest collision")
            finally: os.close(collision)
        os.unlink(temporary,dir_fd=directory); temporary=""; os.fsync(directory)
    finally:
        if descriptor is not None: os.close(descriptor)
        if temporary:
            try: os.unlink(temporary,dir_fd=directory)
            except FileNotFoundError: pass
        os.close(directory)


def archive_path(record: Dict[str, object]) -> Path:
    relative=Path(str(record.get("path","")))
    expected_prefix=Path(".agent/state/evidence-archives")
    if relative.is_absolute() or relative.parent!=expected_prefix or any(part in {"",".",".."} for part in relative.parts):
        raise SystemExit("evidence archive path escapes the private archive directory")
    return ROOT/relative


def bounded_zip_entry_count(descriptor: int,size: int) -> int:
    tail_size=min(size,65557); os.lseek(descriptor,size-tail_size,os.SEEK_SET); tail=b""
    while len(tail)<tail_size:
        chunk=os.read(descriptor,tail_size-len(tail))
        if not chunk: break
        tail+=chunk
    offset=tail.rfind(b"PK\x05\x06")
    if offset<0 or offset+22>len(tail): raise SystemExit("evidence archive end record is missing")
    signature,disk,central_disk,disk_entries,total_entries,central_size,central_offset,comment_size=struct.unpack_from("<4s4H2LH",tail,offset)
    absolute_offset=size-tail_size+offset
    if signature!=b"PK\x05\x06" or disk or central_disk or disk_entries!=total_entries or total_entries==0xffff or absolute_offset+22+comment_size!=size:
        raise SystemExit("evidence archive is split, ZIP64, or malformed")
    if total_entries<1 or total_entries>MAX_EVIDENCE_TREE_FILES+1 or central_size>size or central_offset+central_size>absolute_offset:
        raise SystemExit("evidence archive entry inventory exceeds its bound")
    return total_entries


def stream_zip_member(handle,name,maximum,label,sink=None):
    info=handle.getinfo(name)
    if info.is_dir() or info.flag_bits&1 or info.file_size<0 or info.file_size>maximum: raise SystemExit(f"{label} is unsafe or oversized")
    total=0; hasher=hashlib.sha256()
    with handle.open(info,"r") as source:
        while True:
            chunk=source.read(min(1024*1024,maximum-total+1))
            if not chunk: break
            total+=len(chunk)
            if total>maximum: raise SystemExit(f"{label} exceeds its byte limit")
            hasher.update(chunk)
            if sink is not None: sink(chunk)
    if total!=info.file_size: raise SystemExit(f"{label} changed while reading")
    return total,hasher.hexdigest()


def bounded_manifest_member(handle,name,maximum,label):
    chunks=[]; total,_value=stream_zip_member(handle,name,maximum,label,chunks.append); data=b"".join(chunks)
    if len(data)!=total: raise SystemExit(f"{label} materialization drifted")
    return data


@contextlib.contextmanager
def verified_archive_zip(archive: Path,record: Dict[str,object],archive_digest: str):
    try: before=os.lstat(archive); descriptor=boundedio.open_nofollow(archive,"evidence archive")
    except (OSError,RuntimeError) as error: raise SystemExit("evidence archive cannot be opened safely") from error
    identity=lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns,item.st_mode,item.st_uid,item.st_nlink)
    opened=os.fstat(descriptor)
    try:
        if identity(before)!=identity(opened) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1 or opened.st_size!=record["bytes"]: raise SystemExit("evidence archive changed while opening")
        hasher=hashlib.sha256(); total=0; os.lseek(descriptor,0,os.SEEK_SET)
        while True:
            chunk=os.read(descriptor,min(1024*1024,MAX_ARCHIVE_CONTAINER_BYTES-total+1))
            if not chunk: break
            total+=len(chunk)
            if total>MAX_ARCHIVE_CONTAINER_BYTES: raise SystemExit("evidence archive exceeds its byte limit")
            hasher.update(chunk)
        if total!=opened.st_size or hasher.hexdigest()!=archive_digest: raise SystemExit("evidence archive bytes drifted")
        expected_count=bounded_zip_entry_count(descriptor,total); os.lseek(descriptor,0,os.SEEK_SET)
        stream=os.fdopen(os.dup(descriptor),"rb")
        try:
            with zipfile.ZipFile(stream,"r") as handle: yield handle,expected_count
        finally: stream.close()
        if identity(os.fstat(descriptor))!=identity(opened): raise SystemExit("evidence archive changed while verifying")
    finally: os.close(descriptor)


def manifest_from_archive(record: Dict[str, object],deep: bool=False):
    if set(record) != ARCHIVE_FIELDS or record.get("schema") != HEAD_SCHEMA:
        raise SystemExit("evidence archive head fields are invalid")
    archive_digest=str(record.get("sha256","")); expected=ARCHIVES/f"{archive_digest}.zip"; archive=expected
    expected_relative=str(expected.relative_to(ROOT))
    if (
        SHA.fullmatch(archive_digest) is None or record.get("path")!=expected_relative
        or not isinstance(record.get("bytes"),int) or isinstance(record.get("bytes"),bool) or not 1<=record["bytes"]<=MAX_ARCHIVE_CONTAINER_BYTES
        or not isinstance(record.get("file_count"),int) or isinstance(record.get("file_count"),bool) or not 1<=record["file_count"]<=MAX_EVIDENCE_TREE_FILES
        or not isinstance(record.get("source_bytes"),int) or isinstance(record.get("source_bytes"),bool) or not 0<=record["source_bytes"]<=MAX_ARCHIVE_SOURCE_BYTES
        or not isinstance(record.get("manifest_sha256"), str)
        or not isinstance(record.get("created_at"), str)
        or not archive.is_file() or archive.is_symlink()
    ):
        raise SystemExit("evidence archive head is invalid or missing")
    try:
        with verified_archive_zip(archive,record,archive_digest) as (handle,expected_zip_entries):
            infos=handle.infolist()
            if len(infos)!=expected_zip_entries: raise SystemExit("evidence archive central inventory drifted")
            zip_names=[info.filename for info in infos]
            if "MANIFEST.json" not in zip_names: raise SystemExit("evidence archive manifest is missing")
            manifest_bytes=bounded_manifest_member(handle,"MANIFEST.json",MAX_ARCHIVE_MANIFEST_BYTES,"evidence archive manifest")
            manifest = json.loads(manifest_bytes)
            entries = manifest.get("entries") if isinstance(manifest, dict) else None
            if (
                not isinstance(manifest, dict) or set(manifest) != {"schema", "entries"}
                or manifest.get("schema") != ARCHIVE_SCHEMA or not isinstance(entries, list)
                or digest(manifest_bytes) != record["manifest_sha256"]
                or record["file_count"] != len(entries)
                or record["source_bytes"] != sum(
                    entry.get("bytes", -1) if isinstance(entry, dict) else -1 for entry in entries
                )
            ):
                raise SystemExit("evidence archive manifest is invalid")
            names = [entry.get("path") for entry in entries if isinstance(entry, dict)]
            if len(names) != len(entries) or len(names) != len(set(names)) or names != sorted(names):
                raise SystemExit("evidence archive entry paths are invalid")
            expected_names = {"MANIFEST.json", *names}
            if len(zip_names)!=len(set(zip_names)) or set(zip_names)!=expected_names:
                raise SystemExit("evidence archive ZIP entries differ from its manifest")
            for entry in entries:
                if (
                    not isinstance(entry, dict) or set(entry) != {"path", "sha256", "bytes"}
                    or not isinstance(entry.get("path"), str)
                    or not str(entry["path"]).startswith(".agent/state/evidence/")
                    or SHA.fullmatch(str(entry.get("sha256",""))) is None
                    or not isinstance(entry.get("bytes"),int) or isinstance(entry.get("bytes"),bool) or not 0<=entry["bytes"]<=MAX_ARCHIVED_MEMBER_BYTES
                ): raise SystemExit("evidence archive entry receipt is invalid")
                relative_path=Path(entry["path"])
                if relative_path.is_absolute() or relative_path.parts[:3]!=(".agent","state","evidence") or any(part in {"",".",".."} for part in relative_path.parts):
                    raise SystemExit("evidence archive entry path is unsafe")
                if deep:
                    member_bytes,member_sha=stream_zip_member(handle,str(entry["path"]),min(MAX_ARCHIVED_MEMBER_BYTES,entry["bytes"]),"archived evidence member")
                    if member_bytes!=entry["bytes"] or member_sha!=entry["sha256"]:
                        raise SystemExit(f"archived evidence drifted: {entry['path']}")
            return manifest
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, KeyError) as error:
        raise SystemExit(f"evidence archive is unreadable: {error}")


def page_records(head: object) -> List[Dict[str, object]]:
    required = {"schema", "path", "sha256", "bytes", "total_archives", "depth"}
    chain: List[Tuple[Dict[str,object],List[Dict[str,object]]]]=[]
    current=head; seen: Set[str]=set(); record_count=0
    while current is not None:
        if len(chain)>=4096: raise SystemExit("evidence archive page chain exceeds its depth limit")
        if not isinstance(current, dict) or set(current) != required:
            raise SystemExit("evidence archive page head fields are invalid")
        value_sha = str(current.get("sha256", ""))
        relative = f".agent/state/evidence-archive-pages/{value_sha}.json"
        path = ROOT / relative
        if (
            current.get("schema") != PAGE_HEAD_SCHEMA or SHA.fullmatch(value_sha) is None
            or value_sha in seen or current.get("path") != relative
            or not isinstance(current.get("bytes"), int) or current["bytes"] < 1
            or not isinstance(current.get("total_archives"), int) or current["total_archives"] < 1
            or not isinstance(current.get("depth"), int) or current["depth"] < 1
            or not path.is_file() or path.is_symlink()
        ):
            raise SystemExit("evidence archive page head is invalid or missing")
        seen.add(value_sha); data = bounded_read(path,"evidence file")
        if len(data) != current["bytes"] or digest(data) != value_sha:
            raise SystemExit("evidence archive page bytes drifted")
        value = json.loads(data)
        records = value.get("archives") if isinstance(value, dict) else None
        previous = value.get("previous") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict) or set(value) != {"schema", "previous", "archives"}
            or value.get("schema")!=PAGE_SCHEMA or not isinstance(records,list) or not records or len(records)>MAX_ARCHIVE_RECORDS
            or any(not isinstance(record, dict) for record in records)
        ):
            raise SystemExit("evidence archive page content is invalid")
        record_count+=len(records)
        if record_count>MAX_ARCHIVE_RECORDS: raise SystemExit("evidence archive page records exceed their limit")
        chain.append((current,records)); current=previous
    flattened: List[Dict[str, object]] = []
    for depth, (page_head, records) in enumerate(reversed(chain), start=1):
        flattened.extend(records)
        if page_head["depth"] != depth or page_head["total_archives"] != len(flattened):
            raise SystemExit("evidence archive page totals or depth drifted")
    return flattened


def all_records(index: Dict[str, object]) -> List[Dict[str, object]]:
    active = index.get("archives")
    if not isinstance(active, list):
        raise SystemExit("evidence index active archives are invalid")
    return [*page_records(index.get("archive_page")), *active]


def verify_index(deep: bool = False) -> Tuple[Dict[str, object], Dict[str, List[Dict[str, object]]]]:
    index = load_index(); active = index["archives"]
    records = all_records(index)
    assert isinstance(records, list)
    if len(active) > int(policy().get("max_archives", 0)):
        raise SystemExit("evidence active archive index exceeds its configured bound")
    seen: Set[str] = set(); archived: Dict[str, List[Dict[str, object]]] = {}
    for raw in records:
        if not isinstance(raw, dict) or str(raw.get("sha256")) in seen:
            raise SystemExit("evidence archive index contains duplicate or invalid records")
        seen.add(str(raw.get("sha256")))
        manifest = manifest_from_archive(raw, deep=deep)
        for entry in manifest["entries"]:
            assert isinstance(entry, dict)
            path = str(entry["path"])
            versions = archived.setdefault(path, [])
            if entry not in versions:
                versions.append(entry)
    return index, archived


def open_archive_directory() -> Optional[int]:
    try: return private_directory_fd(ARCHIVES,"evidence archive root",False)
    except FileNotFoundError: return None


def orphan_archive_names(index: Dict[str,object],descriptor: int) -> List[str]:
    indexed={f"{record.get('sha256')}.zip" for record in all_records(index)}; names=[]; observed=0
    with os.scandir(descriptor) as entries:
        for entry in entries:
            observed+=1
            if observed>MAX_ARCHIVE_DIRECTORY_ENTRIES: raise SystemExit("evidence archive inventory exceeds its entry limit")
            if entry.name not in indexed: names.append(entry.name)
    return sorted(names,key=os.fsencode)


def orphan_archives(index: Dict[str, object]) -> List[Path]:
    descriptor=open_archive_directory()
    if descriptor is None: return []
    try: return [ARCHIVES/name for name in orphan_archive_names(index,descriptor)]
    finally: os.close(descriptor)


def publish_page(previous: object, records: List[Dict[str, object]]) -> Dict[str, object]:
    if not records:
        raise SystemExit("cannot publish an empty evidence archive page")
    prior_total = int(previous.get("total_archives", 0)) if isinstance(previous, dict) else 0
    prior_depth = int(previous.get("depth", 0)) if isinstance(previous, dict) else 0
    value = {"schema": PAGE_SCHEMA, "previous": previous, "archives": records}
    data = canonical(value); value_sha = digest(data)
    target = ARCHIVE_PAGES / f"{value_sha}.json"
    publish_content_addressed(ARCHIVE_PAGES,target.name,data,"evidence archive page")
    return {
        "schema": PAGE_HEAD_SCHEMA,
        "path": str(target.relative_to(ROOT)),
        "sha256": value_sha,
        "bytes": len(data),
        "total_archives": prior_total + len(records),
        "depth": prior_depth + 1,
    }


def evidence_files() -> Dict[str, Path]:
    evidence_directory=private_directory_fd(EVIDENCE,"active evidence root",True); os.close(evidence_directory)
    result: Dict[str, Path] = {}
    entries=list(bounded_tree(EVIDENCE,"active evidence inventory"))
    total_bytes=0
    for path,metadata in sorted(entries,key=lambda item:item[0].relative_to(EVIDENCE).as_posix().encode()):
        if stat.S_ISLNK(metadata.st_mode): raise SystemExit(f"evidence symlink is forbidden: {path.relative_to(ROOT)}")
        if stat.S_ISREG(metadata.st_mode):
            total_bytes+=metadata.st_size
            if total_bytes>MAX_ACTIVE_EVIDENCE_INPUT_BYTES: raise SystemExit("active evidence aggregate byte limit exceeded")
            result[str(path.relative_to(ROOT))]=path
        elif not stat.S_ISDIR(metadata.st_mode): raise SystemExit(f"evidence special file is forbidden: {path.relative_to(ROOT)}")
    return result


def active_bytes() -> int:
    return sum(path.stat().st_size for path in evidence_files().values())


def textual_references(path: Path, known: Set[str], digests: Dict[str, List[str]]) -> Set[str]:
    try:
        data=bounded_read(path,"reference source",MAX_REFERENCE_FILE_BYTES)
    except OSError:
        return set()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return set()
    # Match the exact known paths instead of guessing a filename grammar. This
    # is deliberately conservative and preserves Unicode, spaces, Markdown,
    # JSON strings and absolute paths containing the canonical relative path.
    strings = [text]
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        parsed = None
    stack = [parsed]
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, dict):
            stack.extend(value.keys()); stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    referenced = {relative for relative in known if any(relative in value for value in strings)}
    # Digest-only references protect evidence exactly like literal paths: any
    # standalone sha256 of the evidence bytes counts as a reference.
    for value in strings:
        for token in SHA.findall(value):
            referenced.update(digests.get(token, ()))
    return referenced


def root_reference_files() -> Iterable[Path]:
    seen: Set[Tuple[int,int]]=set(); candidates: List[Path]=[]; state={"entries":0,"files":0}
    def include(path):
        if len(candidates)>=MAX_EVIDENCE_TREE_ENTRIES: raise SystemExit("reference-root candidate limit exceeded")
        candidates.append(path)
    for entry in reference_roots():
        if any(char in entry for char in "*?["):
            if "**" in entry: raise SystemExit("recursive reference-root globs are forbidden; declare the root directory")
            for candidate in ROOT.glob(entry): include(candidate)
            continue
        base = ROOT / entry
        if base.is_dir() and not base.is_symlink():
            for candidate,_metadata in bounded_tree(base,"reference roots",state): include(candidate)
        else: include(base)
    total_bytes=0
    for path in sorted(candidates,key=lambda item:os.fsencode(str(item))):
        if not path.exists():
            continue
        if path.is_symlink():
            raise SystemExit(f"reference source symlink is forbidden: {path.relative_to(ROOT)}")
        if not path.is_file():
            continue
        # Active evidence, deep archives and the index itself never act as reference roots.
        if EVIDENCE in path.parents or ARCHIVES in path.parents or path==INDEX: continue
        metadata=os.lstat(path); identity=(metadata.st_dev,metadata.st_ino)
        if identity in seen: continue
        total_bytes+=metadata.st_size
        if total_bytes>MAX_REFERENCE_INPUT_BYTES: raise SystemExit("reference-root aggregate byte limit exceeded")
        seen.add(identity)
        yield path


def matching_receipt(path: Path, versions: Iterable[Dict[str, object]]) -> Optional[Dict[str, object]]:
    data = bounded_read(path,"evidence file"); size = len(data); value = digest(data)
    return next(
        (entry for entry in versions if entry.get("bytes") == size and entry.get("sha256") == value),
        None,
    )


def task_archive_payload(path: Path) -> Optional[Dict[str, object]]:
    """Parse a task-archive payload; None when the file is not one."""
    if TASK_ARCHIVES not in path.parents:
        return None
    try:
        value = json.loads(bounded_read(path,"evidence file"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def reachable_evidence(files: Dict[str, Path]) -> Set[str]:
    known = set(files)
    digests: Dict[str, List[str]] = {}
    for relative, path in files.items():
        digests.setdefault(digest(bounded_read(path,"evidence file")), []).append(relative)
    reachable: Set[str] = set(); queue: List[str] = []

    def absorb(reference: str) -> None:
        if reference in known and reference not in reachable:
            reachable.add(reference); queue.append(reference)

    for source in root_reference_files():
        for reference in textual_references(source, known, digests):
            absorb(reference)
    while queue:
        current = files[queue.pop()]
        payload = task_archive_payload(current)
        if isinstance(payload, dict) and payload.get("schema") == TASK_ARCHIVE_V2:
            # v2 payloads are never textually scanned (see the module
            # contract): reachability follows referenced_evidence digests and
            # the previous-head chain only.
            referenced = payload.get("referenced_evidence")
            if isinstance(referenced, list):
                for item in referenced:
                    if isinstance(item, str) and SHA.fullmatch(item):
                        for relative in digests.get(item, ()):
                            absorb(relative)
            previous = payload.get("previous")
            if isinstance(previous, dict) and isinstance(previous.get("path"), str):
                absorb(str(previous["path"]))
            continue
        # Legacy v1 task-archives (and anything unrecognized) stay textually
        # scanned as a fail-safe until migrate-task-archives rewrites them.
        for reference in textual_references(current, known, digests):
            absorb(reference)
    return reachable


def evidence_age_hours(path: Path, now_ns: int) -> float:
    stat = path.stat()
    stamps = [stat.st_mtime_ns]
    birth = getattr(stat, "st_birthtime", None)
    if birth is not None:
        stamps.append(int(birth * 1_000_000_000))
    # `cp -p` backdates mtime, so mtime alone lets a fresh copy masquerade as
    # aged evidence and bypass the protective age window. st_birthtime
    # (APFS/macOS) records real inode creation and cannot be backdated by a
    # content copy; taking the NEWEST available timestamp keeps such copies
    # protected. Residual limitation: on filesystems without st_birthtime
    # (most Linux mounts) mtime remains forgeable via `cp -p`; a complete fix
    # requires index registration timestamps.
    return (now_ns - max(stamps)) / 3_600_000_000_000


def plan(min_age_hours: int, force: bool = False, include_task_history: bool = False) -> Dict[str, object]:
    index, archived = verify_index(deep=False); files = evidence_files()
    reachable = reachable_evidence(files)
    history = {relative for relative, path in files.items() if TASK_ARCHIVES in path.parents}
    if include_task_history:
        # Operator escape hatch: task-history evidence loses its reachability
        # protection so the whole head chain can be deep-archived.
        reachable -= history
    now_ns = time.time_ns()
    recent: Set[str] = set(); duplicates: List[str] = []
    for relative, path in files.items():
        if not (include_task_history and relative in history):
            if evidence_age_hours(path, now_ns) < min_age_hours:
                recent.add(relative)
        receipt = matching_receipt(path, archived.get(relative, []))
        if receipt is not None and relative not in reachable:
            duplicates.append(relative)
    candidates = sorted(set(files) - reachable - recent - set(duplicates))
    active_bytes = sum(path.stat().st_size for path in files.values())
    candidate_bytes = sum(files[path].stat().st_size for path in candidates)
    retention = policy()
    should_archive = bool(candidates) and (
        force or include_task_history or active_bytes > int(retention["active_max_bytes"])
        or candidate_bytes >= int(retention["min_archive_bytes"])
    )
    selected=[]; selected_total=0; selected_manifest_budget=0
    if should_archive:
        for relative in candidates:
            size=files[relative].stat().st_size
            entry_budget=len(relative.encode("utf-8"))+MAX_ARCHIVE_ENTRY_METADATA_BYTES
            if selected_total+size>MAX_COMPACTION_SELECTED_BYTES or selected_manifest_budget+entry_budget>MAX_ARCHIVE_MANIFEST_BYTES: break
            selected.append(relative); selected_total+=size; selected_manifest_budget+=entry_budget
        if candidates and not selected: raise SystemExit("one evidence candidate exceeds the compaction aggregate byte limit")
    return {
        "schema": "agent-evidence-compaction-plan/v1",
        "active_files": len(files), "active_bytes": active_bytes,
        "reachable_files": len(reachable), "recent_files": len(recent),
        "archived_duplicates": duplicates,
        "candidate_files": len(candidates), "candidate_bytes": candidate_bytes,
        "selected": selected, "selected_bytes": sum(files[path].stat().st_size for path in selected),
        "archive_count": len(all_records(index)),
        "over_active_budget": active_bytes > int(retention["active_max_bytes"]),
        "task_history_files": len(history), "include_task_history": include_task_history,
    }


def zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o100444 & 0xFFFF) << 16
    return info


def stream_evidence_to_zip(path: Path,handle,name: str,maximum: int):
    try: before=os.lstat(path); descriptor=boundedio.open_nofollow(path,"active evidence")
    except (OSError,RuntimeError) as error: raise SystemExit("active evidence cannot be opened safely") from error
    identity=lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns,item.st_mode,item.st_uid,item.st_nlink)
    opened=os.fstat(descriptor); total=0; hasher=hashlib.sha256()
    try:
        if identity(before)!=identity(opened) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1 or opened.st_size>maximum: raise SystemExit("active evidence is unsafe or oversized")
        with handle.open(zip_info(name),"w") as target:
            while True:
                chunk=os.read(descriptor,min(1024*1024,maximum-total+1))
                if not chunk: break
                total+=len(chunk)
                if total>maximum: raise SystemExit("active evidence exceeds its byte limit")
                hasher.update(chunk); target.write(chunk)
        if total!=opened.st_size or identity(os.fstat(descriptor))!=identity(opened): raise SystemExit("active evidence changed while archiving")
        return total,hasher.hexdigest()
    finally: os.close(descriptor)


def publish_archive(selected: List[str], files: Dict[str, Path]) -> Dict[str, object]:
    entries=[]; directory=private_directory_fd(ARCHIVES,"evidence archive root",True)
    temporary=f".evidence-archive.{secrets.token_hex(16)}.zip"; descriptor=None
    try:
        descriptor=os.open(temporary,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=directory)
        selected_total=0
        stream=os.fdopen(os.dup(descriptor),"w+b")
        try:
            with zipfile.ZipFile(stream,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as handle:
                for relative in sorted(selected):
                    size,value=stream_evidence_to_zip(files[relative],handle,relative,MAX_ARCHIVED_MEMBER_BYTES)
                    selected_total+=size
                    if selected_total>MAX_COMPACTION_SELECTED_BYTES: raise SystemExit("compaction aggregate byte limit exceeded")
                    entries.append({"path":relative,"sha256":value,"bytes":size})
                manifest={"schema":ARCHIVE_SCHEMA,"entries":entries}; manifest_bytes=canonical(manifest)
                if len(manifest_bytes)>MAX_ARCHIVE_MANIFEST_BYTES: raise SystemExit("evidence archive manifest exceeds its byte limit")
                handle.writestr(zip_info("MANIFEST.json"),manifest_bytes)
            stream.flush()
        finally: stream.close()
        os.fsync(descriptor); archive_size,archive_digest=descriptor_digest(descriptor,MAX_ARCHIVE_CONTAINER_BYTES,"temporary evidence archive")
        target_name=f"{archive_digest}.zip"; target=ARCHIVES/target_name
        try: existing=os.open(target_name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
        except FileNotFoundError: existing=None
        except OSError as error: raise SystemExit("evidence archive digest collision") from error
        if existing is not None:
            try:
                target_size,target_digest=descriptor_digest(existing,MAX_ARCHIVE_CONTAINER_BYTES,"evidence archive target")
                if target_size!=archive_size or target_digest!=archive_digest: raise SystemExit("evidence archive digest collision")
            finally: os.close(existing)
        else:
            os.fchmod(descriptor,0o444)
            try: os.link(temporary,target_name,src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
            except FileExistsError:
                collision=open_regular_at(directory,target_name,"evidence archive target")
                try:
                    target_size,target_digest=descriptor_digest(collision,MAX_ARCHIVE_CONTAINER_BYTES,"evidence archive target")
                    if target_size!=archive_size or target_digest!=archive_digest: raise SystemExit("evidence archive digest collision")
                finally: os.close(collision)
        os.unlink(temporary,dir_fd=directory); temporary=""; os.fsync(directory)
        record={
            "schema":HEAD_SCHEMA,"path":str(target.relative_to(ROOT)),"sha256":archive_digest,"bytes":archive_size,
            "file_count":len(entries),"source_bytes":sum(entry["bytes"] for entry in entries),
            "created_at":dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),"manifest_sha256":digest(manifest_bytes),
        }
    finally:
        if descriptor is not None: os.close(descriptor)
        if temporary:
            try: os.unlink(temporary,dir_fd=directory)
            except FileNotFoundError: pass
        os.close(directory)
    manifest_from_archive(record,deep=True)
    return record


def remove_exact(relative_paths: Iterable[str], receipts: Dict[str, Dict[str, object]]) -> int:
    removed = 0
    for relative in sorted(set(relative_paths)):
        receipt=receipts.get(relative)
        if receipt is None: raise SystemExit(f"evidence removal lacks verified archive authority: {relative}")
        remove_evidence_target(relative,receipt); removed+=1
    directories=[path for path,metadata in bounded_tree(EVIDENCE,"evidence directory cleanup") if stat.S_ISDIR(metadata.st_mode)]
    for directory in sorted(directories,key=lambda item:(len(item.parts),os.fsencode(str(item))),reverse=True):
        with os.scandir(directory) as scanner: empty=next(scanner,None) is None
        if empty: directory.rmdir()
    return removed


def task_history_decision(selected: List[str], source: Optional[str], receipt: Optional[str]) -> Dict[str, object]:
    """Bind a human decision to the exact task-history compaction selection."""
    if not str(source or "").startswith("user:"):
        raise SystemExit("--include-task-history requires --source user:<decision>")
    packet = {"schema": "agent-evidence-task-history-compaction/v1", "selected": selected}
    packet_sha256 = digest(canonical(packet))
    task = load_json(TASK) if TASK.is_file() else {}
    config = load_json(CONFIG)
    if not receipt:
        raise SystemExit("task-history compaction requires a provider-signed human decision receipt")
    return humandecision.verify(
        ROOT, config, task, gate=TASK_HISTORY_DECISION_GATE,
        artifact_sha256=packet_sha256, source=str(source), receipt=receipt,
    )


def clear_compacted_task_head():
    if not TASK.is_file(): return
    before_task=load_json(TASK)
    if before_task.get("task_archive") is None: return
    after_task=copy.deepcopy(before_task); after_task["task_archive"]=None
    commit_task_head(before_task,after_task,reason="evidence-task-history-compacted",
        summary="cleared the archived task-history head after human-approved compaction")


def command_compact(args: argparse.Namespace) -> int:
    with evidence_lock_handle() as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        retention = policy()
        age = int(retention["min_age_hours"]) if args.min_age_hours is None else args.min_age_hours
        if args.gc_orphans:
            # Remove the unindexed files `verify` reports, only after a full
            # deep verification of the index they escaped. Every removal is
            # listed; --dry-run lists without touching anything.
            index, _ = verify_index(deep=True)
            descriptor=open_archive_directory()
            if descriptor is None:
                names=[]
                if args.dry_run: print(json.dumps({"schema":"agent-evidence-orphan-gc-plan/v1","orphans":[]},indent=2))
                else: print("EVIDENCE ORPHAN GC: removed=0")
                return 0
            try:
                names=orphan_archive_names(index,descriptor)
                if args.dry_run:
                    print(json.dumps({"schema":"agent-evidence-orphan-gc-plan/v1",
                        "orphans":[str((ARCHIVES/name).relative_to(ROOT)) for name in names]},ensure_ascii=False,indent=2))
                    return 0
                removed=0
                for name in names:
                    observed=os.stat(name,dir_fd=descriptor,follow_symlinks=False); relative=(ARCHIVES/name).relative_to(ROOT)
                    if stat.S_ISLNK(observed.st_mode): raise SystemExit(f"evidence orphan symlink is forbidden: {relative}")
                    if not stat.S_ISREG(observed.st_mode): print(f"EVIDENCE ORPHAN SKIPPED: {relative}"); continue
                    os.unlink(name,dir_fd=descriptor); print(f"EVIDENCE ORPHAN REMOVED: {relative}"); removed+=1
                print(f"EVIDENCE ORPHAN GC: removed={removed}"); return 0
            finally: os.close(descriptor)
        current_plan = plan(age, force=args.force, include_task_history=args.include_task_history)
        if args.dry_run:
            print(json.dumps(current_plan, ensure_ascii=False, indent=2)); return 0
        # Deep-verify every archive this run relies on BEFORE any active file
        # is removed; previously only the freshly published archive and the
        # duplicate-reconciliation path were deep-verified.
        index, archived = verify_index(deep=True); files = evidence_files()
        selected = list(current_plan["selected"])
        duplicate_paths = list(current_plan["archived_duplicates"])
        history = {relative for relative, path in files.items() if TASK_ARCHIVES in path.parents}
        history_selected = sorted((set(selected)|set(duplicate_paths)) & history)
        if history_selected and not args.include_task_history:
            raise SystemExit(
                "task-history evidence is selected for archival; rerun with "
                "--include-task-history --source user:<decision> or restore its reachability first"
            )
        if history_selected:
            decision = task_history_decision(history_selected, args.source, args.human_decision_receipt)
            print(f"TASK HISTORY DECISION: {json.dumps(decision, ensure_ascii=False, sort_keys=True)}")
        if duplicate_paths:
            if set(duplicate_paths)&set(history_selected): clear_compacted_task_head()
            duplicate_receipts: Dict[str, Dict[str, object]] = {}
            for relative in duplicate_paths:
                receipt = matching_receipt(files[relative], archived.get(relative, []))
                if receipt is None:
                    raise SystemExit(f"archived duplicate changed before reconciliation: {relative}")
                duplicate_receipts[relative] = receipt
            remove_exact(duplicate_paths, duplicate_receipts)
        if not selected:
            remaining = active_bytes()
            if remaining > int(retention["active_max_bytes"]):
                raise SystemExit(
                    "active evidence remains over budget because remaining files are referenced or inside the age window; "
                    "split/promote references, explicitly retry with --min-age-hours 0 --force, "
                    "or deep-archive task history with --include-task-history --source user:<decision>"
                )
            print(f"EVIDENCE COMPACT: no archive needed; reconciled={len(duplicate_paths)}")
            return 0
        active_records = list(index["archives"])
        page_head = index.get("archive_page")
        if len(active_records) >= int(retention["max_archives"]):
            page_head = publish_page(page_head, active_records)
            # Validate the new immutable page before it becomes the index head.
            page_records(page_head)
            active_records = []
        record = publish_archive(selected, files)
        manifest = manifest_from_archive(record, deep=True)
        updated = {
            "schema": INDEX_SCHEMA,
            "archives": [*active_records, record],
            "archive_page": page_head,
            "updated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        }
        atomic_json(INDEX, updated)
        receipts = {str(entry["path"]): entry for entry in manifest["entries"]}
        # Publication and capsule rebind precede destructive GC. A crash before
        # this point leaves only safe duplicates; a retry rebinds before removal.
        if set(selected)&set(history_selected): clear_compacted_task_head()
        removed = remove_exact(selected, receipts)
        print(
            f"EVIDENCE COMPACTED: files={removed} source_bytes={record['source_bytes']} "
            f"archive_bytes={record['bytes']} archive={record['sha256']}"
        )
        if active_bytes() > int(retention["active_max_bytes"]):
            print("EVIDENCE STILL OVER BUDGET: protected/recent active evidence requires split, promotion, an explicit age override or --include-task-history")
            return 2
        return 0


def command_verify(args: argparse.Namespace) -> int:
    index, archived = verify_index(deep=args.deep)
    orphans = orphan_archives(index)
    if not args.quiet:
        print(
            f"VALID EVIDENCE INDEX: archives={len(all_records(index))} files={len(archived)} "
            f"deep={str(args.deep).lower()} orphans={len(orphans)}"
        )
        for orphan in orphans:
            print(f"EVIDENCE ORPHAN ARCHIVE: {orphan.relative_to(ROOT)}")
    return 0


def command_status(args: argparse.Namespace) -> int:
    age = int(policy()["min_age_hours"])
    print(json.dumps(plan(age, force=False), ensure_ascii=False, indent=2)); return 0


def evidence_target_parts(relative: str):
    value=Path(relative)
    if value.is_absolute() or len(value.parts)<4 or value.parts[:3]!=(".agent","state","evidence") or any(part in {"",".",".."} for part in value.parts):
        raise SystemExit("evidence target escapes active evidence")
    return value.parts


def open_evidence_parent(relative: str,create: bool):
    parts=evidence_target_parts(relative); flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    current=os.open(ROOT,flags)
    try:
        for part in parts[:-1]:
            try: following=os.open(part,flags,dir_fd=current)
            except FileNotFoundError:
                if not create: raise
                os.mkdir(part,0o700,dir_fd=current); following=os.open(part,flags,dir_fd=current)
            metadata=os.fstat(following)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=os.geteuid() or stat.S_IMODE(metadata.st_mode)&0o022:
                os.close(following); raise SystemExit("evidence target parent is unsafe")
            os.close(current); current=following
        return current,parts[-1]
    except BaseException:
        os.close(current); raise


def bounded_descriptor_read(descriptor: int,label: str,maximum: int=MAX_EVIDENCE_FILE_BYTES):
    opened=os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1 or opened.st_size<0 or opened.st_size>maximum:
        raise SystemExit(f"{label} is unsafe or exceeds its byte limit")
    identity=(opened.st_dev,opened.st_ino,stat.S_IMODE(opened.st_mode),opened.st_nlink,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
    chunks=[]; total=0
    while True:
        chunk=os.read(descriptor,min(1024*1024,maximum-total+1))
        if not chunk: break
        chunks.append(chunk); total+=len(chunk)
        if total>maximum: raise SystemExit(f"{label} exceeds its byte limit")
    final=os.fstat(descriptor)
    final_identity=(final.st_dev,final.st_ino,stat.S_IMODE(final.st_mode),final.st_nlink,final.st_size,final.st_mtime_ns,final.st_ctime_ns)
    if final_identity!=identity or total!=opened.st_size: raise SystemExit(f"{label} changed while reading")
    return b"".join(chunks),identity


def read_evidence_target_at(parent: int,name: str):
    try: descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
    except FileNotFoundError: return None
    try: data,_identity=bounded_descriptor_read(descriptor,"evidence archive target")
    finally: os.close(descriptor)
    return data


def read_evidence_target(relative: str):
    try: parent,name=open_evidence_parent(relative,False)
    except FileNotFoundError: return None
    try: return read_evidence_target_at(parent,name)
    except OSError as error: raise SystemExit("evidence archive target is unsafe") from error
    finally: os.close(parent)


def remove_evidence_target(relative: str,receipt: Dict[str,object]) -> None:
    try: parent,name=open_evidence_parent(relative,False)
    except FileNotFoundError as error: raise SystemExit(f"evidence removal target is missing: {relative}") from error
    try:
        descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        try: data,identity=bounded_descriptor_read(descriptor,"evidence file")
        finally: os.close(descriptor)
        current=os.stat(name,dir_fd=parent,follow_symlinks=False)
        current_identity=(current.st_dev,current.st_ino,stat.S_IMODE(current.st_mode),current.st_nlink,current.st_size,current.st_mtime_ns,current.st_ctime_ns)
        if current_identity!=identity or len(data)!=receipt["bytes"] or digest(data)!=receipt["sha256"]:
            raise SystemExit(f"evidence changed before archive removal: {relative}")
        os.unlink(name,dir_fd=parent); os.fsync(parent)
        if read_evidence_target(relative) is not None: raise SystemExit(f"removed evidence target remains reachable: {relative}")
    except OSError as error: raise SystemExit(f"evidence removal target is unsafe: {relative}") from error
    finally: os.close(parent)


def evidence_target_receipt_at(parent: int,name: str):
    try: descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
    except FileNotFoundError: return None
    hasher=hashlib.sha256(); total=0
    try:
        opened=os.fstat(descriptor); identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns,opened.st_mode,opened.st_uid,opened.st_nlink)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1 or opened.st_size>MAX_ARCHIVED_MEMBER_BYTES: raise SystemExit("evidence archive target is unsafe")
        while True:
            chunk=os.read(descriptor,min(1024*1024,MAX_ARCHIVED_MEMBER_BYTES-total+1))
            if not chunk: break
            total+=len(chunk)
            if total>MAX_ARCHIVED_MEMBER_BYTES: raise SystemExit("evidence archive target exceeds its byte limit")
            hasher.update(chunk)
        final=os.fstat(descriptor); final_identity=(final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns,final.st_ctime_ns,final.st_mode,final.st_uid,final.st_nlink)
        if identity!=final_identity or total!=opened.st_size: raise SystemExit("evidence archive target changed while hashing")
        return {"bytes":total,"sha256":hasher.hexdigest()}
    finally: os.close(descriptor)


def install_archive_member(handle,entry: Dict[str,object]) -> bool:
    relative=str(entry["path"]); parent,name=open_evidence_parent(relative,True); temporary=f".{name}.{secrets.token_hex(16)}"; descriptor=None
    expected={"bytes":entry["bytes"],"sha256":entry["sha256"]}
    try:
        existing=evidence_target_receipt_at(parent,name)
        if existing is not None:
            if existing!=expected: raise SystemExit(f"restore collision: {relative}")
            return False
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=parent)
        def write_chunk(chunk):
            view=memoryview(chunk); offset=0
            while offset<len(view):
                written=os.write(descriptor,view[offset:])
                if written<=0: raise OSError("short evidence restore write")
                offset+=written
        total,value=stream_zip_member(handle,relative,min(MAX_ARCHIVED_MEMBER_BYTES,entry["bytes"]),"archived evidence member",write_chunk)
        if {"bytes":total,"sha256":value}!=expected: raise SystemExit(f"archived evidence drifted: {relative}")
        os.fsync(descriptor); os.fchmod(descriptor,0o444); os.close(descriptor); descriptor=None
        try: os.link(temporary,name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
        except FileExistsError:
            if evidence_target_receipt_at(parent,name)!=expected: raise SystemExit(f"restore collision: {relative}")
            return False
        os.unlink(temporary,dir_fd=parent); temporary=""; os.fsync(parent)
        if evidence_target_receipt_at(parent,name)!=expected: raise SystemExit("restored evidence target is not reachable through the governed hierarchy")
        return True
    finally:
        if descriptor is not None: os.close(descriptor)
        if temporary:
            try: os.unlink(temporary,dir_fd=parent)
            except FileNotFoundError: pass
        os.close(parent)


def evidence_lock_handle():
    try: return boundedio.open_private_lock(LOCK,label="evidence lock")
    except RuntimeError as error: raise SystemExit(str(error)) from error


def command_restore(args: argparse.Namespace) -> int:
    # Restore mutates active evidence and must serialize with compaction and
    # migration exactly like every other evidence write path.
    with evidence_lock_handle() as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        index, _ = verify_index(deep=True)
        selected = None
        for record in all_records(index):
            if args.archive in {record.get("path"), record.get("sha256")}:
                selected = record; break
        if not isinstance(selected, dict):
            raise SystemExit("requested evidence archive is not indexed")
        manifest=manifest_from_archive(selected,deep=True)
        entries=manifest["entries"]; restored=0
        archive_digest=str(selected["sha256"]); archive=ARCHIVES/f"{archive_digest}.zip"
        with verified_archive_zip(archive,selected,archive_digest) as (archive_handle,_entry_count):
            for entry in entries:
                relative=str(entry["path"])
                try: parent,name=open_evidence_parent(relative,False)
                except FileNotFoundError: continue
                try:
                    existing=evidence_target_receipt_at(parent,name)
                    if existing is not None and existing!={"bytes":entry["bytes"],"sha256":entry["sha256"]}: raise SystemExit(f"restore collision: {relative}")
                finally: os.close(parent)
            for entry in entries:
                if install_archive_member(archive_handle,entry): restored+=1
        print(f"EVIDENCE RESTORED: files={restored} archive={selected['sha256']}")
        return 0


def task_archive_chain(head: object) -> List[Tuple[Dict[str, object], Dict[str, object], bytes]]:
    """Load and fully verify a task-archive head chain (newest first)."""
    chain: List[Tuple[Dict[str, object], Dict[str, object], bytes]] = []
    current = head; seen: Set[str] = set()
    while current is not None:
        if len(chain)>=MAX_TASK_ARCHIVES: raise SystemExit("task archive chain exceeds its limit")
        if (
            not isinstance(current,dict) or set(current)!=TASK_ARCHIVE_HEAD_FIELDS
            or current.get("schema") != TASK_ARCHIVE_HEAD_SCHEMA
            or SHA.fullmatch(str(current.get("sha256", ""))) is None
            or not isinstance(current.get("bytes"), int) or current["bytes"] < 1
            or not isinstance(current.get("total_archives"), int) or current["total_archives"] < 1
        ):
            raise SystemExit("task archive head is invalid")
        value_sha = str(current["sha256"])
        expected=TASK_ARCHIVES/f"{value_sha}.json"; path=expected
        if current.get("path")!=str(expected.relative_to(ROOT)) or value_sha in seen or not path.is_file() or path.is_symlink():
            raise SystemExit("task archive head path is invalid or missing")
        seen.add(value_sha); data = bounded_read(path,"evidence file")
        if len(data) != current["bytes"] or digest(data) != value_sha:
            raise SystemExit("task archive bytes drifted")
        try:
            payload = json.loads(data)
        except (ValueError, json.JSONDecodeError) as error:
            raise SystemExit(f"task archive payload is unreadable: {error}")
        if not isinstance(payload, dict) or payload.get("schema") not in {TASK_ARCHIVE_V1, TASK_ARCHIVE_V2}:
            raise SystemExit("task archive payload schema is invalid")
        chain.append((current, payload, data))
        current = payload.get("previous")
    return chain


def write_task_archive(target: Path, data: bytes) -> None:
    if target.parent!=TASK_ARCHIVES: raise SystemExit("task archive target directory is invalid")
    publish_content_addressed(TASK_ARCHIVES,target.name,data,"task archive")


def command_migrate_task_archives(args: argparse.Namespace) -> int:
    """Rewrite the legacy v1 task-archive chain to v2 (content-addressed).

    Referenced evidence paths are extracted from the embedded TASK/contract
    text into `referenced_evidence` digests. Legacy payloads receive an explicit
    null Skill activation instead of fabricated reviewed bytes (only evidence still active can
    be digest-bound; already-compacted evidence needs no protection). Heads
    are re-anchored oldest-first, the rewritten chain is fully verified
    BEFORE the TASK head pointer moves, and old v1 files are left in place
    as unreachable, compactable evidence.
    """
    with evidence_lock_handle() as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        task = load_json(TASK) if TASK.is_file() else {}
        head = task.get("task_archive")
        if head is None:
            print("TASK ARCHIVE MIGRATION: no task archive head")
            return 0
        chain = task_archive_chain(head)
        files = evidence_files()
        known = set(files)
        file_digests = {relative: digest(bounded_read(path,"evidence file")) for relative, path in files.items()}
        rewritten: List[Tuple[Path, bytes]] = []
        new_head: Optional[Dict[str, object]] = None
        migrated_count = 0
        # Re-anchor oldest first so every previous pointer binds rewritten bytes.
        for old_head, payload, _ in reversed(chain):
            previous_changed = (new_head is None) != (payload.get("previous") is None) or (
                isinstance(new_head, dict) and isinstance(payload.get("previous"), dict)
                and new_head.get("sha256") != payload["previous"].get("sha256")
            )
            if (payload.get("schema") == TASK_ARCHIVE_V2 and "skill_activation" in payload
                    and "delivery" in payload and not previous_changed):
                new_head = {key: old_head[key] for key in TASK_ARCHIVE_HEAD_FIELDS}
                continue
            if payload.get("schema") == TASK_ARCHIVE_V2:
                migrated = dict(payload)
                migrated.setdefault("skill_activation",None); migrated.setdefault("delivery",None)
                migrated["previous"] = new_head
            else:
                referenced: Set[str] = set()
                texts: List[str] = []
                for field in (payload.get("task"), payload.get("requirement_contract")):
                    if isinstance(field, dict) and isinstance(field.get("utf8"), str):
                        texts.append(str(field["utf8"]))
                for relative in known:
                    if any(relative in text for text in texts):
                        referenced.add(file_digests[relative])
                migrated = {
                    "schema": TASK_ARCHIVE_V2,
                    "archived_at": payload.get("archived_at"),
                    "source": payload.get("source"),
                    "reason": payload.get("reason"),
                    "assurance": payload.get("assurance"),
                    "decision_receipt": payload.get("decision_receipt"),
                    "task": payload.get("task"),
                    "requirement_contract": payload.get("requirement_contract"),
                    "skill_activation":None,"delivery":None,
                    "referenced_evidence": sorted(referenced),
                    "previous": new_head,
                }
            data = json.dumps(migrated, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            value_sha = digest(data)
            target = TASK_ARCHIVES / f"{value_sha}.json"
            rewritten.append((target, data))
            new_head = {
                "schema": TASK_ARCHIVE_HEAD_SCHEMA,
                "path": str(target.relative_to(ROOT)),
                "sha256": value_sha,
                "bytes": len(data),
                "total_archives": old_head["total_archives"],
            }
            migrated_count += 1
        if migrated_count == 0:
            print("TASK ARCHIVE MIGRATION: chain is already v2")
            return 0
        if args.dry_run:
            print(json.dumps({
                "schema": "agent-task-archive-migration-plan/v1",
                "archives": len(chain), "rewritten": migrated_count, "new_head": new_head,
            }, ensure_ascii=False, indent=2))
            return 0
        for target, data in rewritten:
            write_task_archive(target, data)
        # Verify the rewritten chain end to end BEFORE the TASK head moves.
        task_archive_chain(new_head)
        # The head is a capsule-bound TASK invariant: move it through the
        # canonical transition so the capsule is re-bound atomically.
        after_task = copy.deepcopy(task)
        after_task["task_archive"] = new_head
        commit_task_head(
            task, after_task,
            reason="evidence-task-archives-migrated",
            summary="re-anchored the task-archive head to the rewritten v2 chain",
        )
        print(
            f"TASK ARCHIVE MIGRATED: archives={len(chain)} rewritten={migrated_count} "
            f"head={new_head['sha256']}"
        )
        return 0


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    sub = value.add_subparsers(dest="command", required=True)
    compact = sub.add_parser("compact")
    compact.add_argument("--dry-run", action="store_true")
    compact.add_argument("--force", action="store_true")
    compact.add_argument("--min-age-hours", type=int)
    compact.add_argument("--gc-orphans", action="store_true")
    compact.add_argument("--include-task-history", action="store_true")
    compact.add_argument("--source")
    compact.add_argument("--human-decision-receipt")
    verify = sub.add_parser("verify")
    verify.add_argument("--deep", action="store_true"); verify.add_argument("--quiet", action="store_true")
    sub.add_parser("status")
    restore = sub.add_parser("restore"); restore.add_argument("--archive", required=True)
    migrate = sub.add_parser("migrate-task-archives")
    migrate.add_argument("--dry-run", action="store_true")
    return value


def main() -> int:
    args = parser().parse_args()
    if getattr(args, "min_age_hours", None) is not None and args.min_age_hours < 0:
        raise SystemExit("--min-age-hours must be non-negative")
    return {
        "compact": lambda: command_compact(args), "verify": lambda: command_verify(args),
        "status": lambda: command_status(args), "restore": lambda: command_restore(args),
        "migrate-task-archives": lambda: command_migrate_task_archives(args),
    }[args.command]()


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
