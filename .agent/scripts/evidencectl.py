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
      "referenced_evidence": [<hex64>, ...],
      "previous": <agent-task-archive-head/v1 | null>
    }

Contract rules:
- `task.utf8` / `requirement_contract.utf8` remain the exact archived bytes
  (each digest-bound by its own sha256); v2 never rewrites embedded text.
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
  humandecision (provider-signed receipt for policy-v1 tasks, local
  user-message approval otherwise) and clears the dangling TASK head.
- `compact --gc-orphans` removes the unindexed archive files that `verify`
  reports (crash-leftover temporaries and unindexed ZIPs), after a full
  deep verification of the index they escaped. Orphans are evidence until
  reported; GC always lists what it removes.
"""

from pathlib import Path
import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import tempfile
import time
import zipfile
from typing import Dict, Iterable, List, Optional, Set, Tuple

import humandecision

try:
    import contexttx
except ImportError:  # reduced harnesses ship an evidence-only script subset
    contexttx = None


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
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON object required: {path}")
    return value


def atomic_json(path: Path, value: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


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
    if not isinstance(value.get("archives"), list):
        raise SystemExit("evidence index archives must be a list")
    if value.get("archive_page") is not None and not isinstance(value.get("archive_page"), dict):
        raise SystemExit("evidence index archive_page must be an object or null")
    if value.get("updated_at") is not None and not isinstance(value.get("updated_at"), str):
        raise SystemExit("evidence index updated_at is invalid")
    return value


def archive_path(record: Dict[str, object]) -> Path:
    path = (ROOT / str(record.get("path", ""))).resolve()
    try:
        path.relative_to(ARCHIVES.resolve())
    except ValueError:
        raise SystemExit("evidence archive path escapes the private archive directory")
    return path


def manifest_from_archive(record: Dict[str, object], deep: bool = False) -> Dict[str, object]:
    if set(record) != ARCHIVE_FIELDS or record.get("schema") != HEAD_SCHEMA:
        raise SystemExit("evidence archive head fields are invalid")
    archive = archive_path(record); archive_digest = str(record.get("sha256", ""))
    expected = ARCHIVES / f"{archive_digest}.zip"
    if (
        SHA.fullmatch(archive_digest) is None or archive != expected.resolve()
        or not isinstance(record.get("bytes"), int) or record["bytes"] < 1
        or not isinstance(record.get("file_count"), int) or record["file_count"] < 1
        or not isinstance(record.get("source_bytes"), int) or record["source_bytes"] < 0
        or not isinstance(record.get("manifest_sha256"), str)
        or not isinstance(record.get("created_at"), str)
        or not archive.is_file() or archive.is_symlink()
    ):
        raise SystemExit("evidence archive head is invalid or missing")
    data = archive.read_bytes()
    if len(data) != record["bytes"] or digest(data) != archive_digest:
        raise SystemExit("evidence archive bytes drifted")
    try:
        with zipfile.ZipFile(archive, "r") as handle:
            if "MANIFEST.json" not in handle.namelist():
                raise SystemExit("evidence archive manifest is missing")
            manifest_bytes = handle.read("MANIFEST.json")
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
            if set(handle.namelist()) != expected_names:
                raise SystemExit("evidence archive ZIP entries differ from its manifest")
            for entry in entries:
                if (
                    not isinstance(entry, dict) or set(entry) != {"path", "sha256", "bytes"}
                    or not isinstance(entry.get("path"), str)
                    or not str(entry["path"]).startswith(".agent/state/evidence/")
                    or SHA.fullmatch(str(entry.get("sha256", ""))) is None
                    or not isinstance(entry.get("bytes"), int) or entry["bytes"] < 0
                ):
                    raise SystemExit("evidence archive entry receipt is invalid")
                if deep:
                    member = handle.read(str(entry["path"]))
                    if len(member) != entry["bytes"] or digest(member) != entry["sha256"]:
                        raise SystemExit(f"archived evidence drifted: {entry['path']}")
            return manifest
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, KeyError) as error:
        raise SystemExit(f"evidence archive is unreadable: {error}")


def page_records(head: object) -> List[Dict[str, object]]:
    required = {"schema", "path", "sha256", "bytes", "total_archives", "depth"}
    chain: List[Tuple[Dict[str, object], List[Dict[str, object]]]] = []
    current = head; seen: Set[str] = set()
    while current is not None:
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
        seen.add(value_sha); data = path.read_bytes()
        if len(data) != current["bytes"] or digest(data) != value_sha:
            raise SystemExit("evidence archive page bytes drifted")
        value = json.loads(data)
        records = value.get("archives") if isinstance(value, dict) else None
        previous = value.get("previous") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict) or set(value) != {"schema", "previous", "archives"}
            or value.get("schema") != PAGE_SCHEMA or not isinstance(records, list) or not records
            or any(not isinstance(record, dict) for record in records)
        ):
            raise SystemExit("evidence archive page content is invalid")
        chain.append((current, records)); current = previous
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


def orphan_archives(index: Dict[str, object]) -> List[Path]:
    """Files inside the private archive directory that no index record binds.

    These are crash-leftover temporaries or unindexed ZIPs. They are still
    potential evidence, so `verify` only reports them; removal requires the
    explicit `compact --gc-orphans` operator pass.
    """
    if not ARCHIVES.is_dir():
        return []
    indexed = {f"{record.get('sha256')}.zip" for record in all_records(index)}
    return [path for path in sorted(ARCHIVES.iterdir()) if path.name not in indexed]


def publish_page(previous: object, records: List[Dict[str, object]]) -> Dict[str, object]:
    if not records:
        raise SystemExit("cannot publish an empty evidence archive page")
    prior_total = int(previous.get("total_archives", 0)) if isinstance(previous, dict) else 0
    prior_depth = int(previous.get("depth", 0)) if isinstance(previous, dict) else 0
    value = {"schema": PAGE_SCHEMA, "previous": previous, "archives": records}
    data = canonical(value); value_sha = digest(data)
    ARCHIVE_PAGES.mkdir(parents=True, exist_ok=True)
    target = ARCHIVE_PAGES / f"{value_sha}.json"
    if target.exists():
        if target.is_symlink() or target.read_bytes() != data:
            raise SystemExit("evidence archive page digest collision")
    else:
        descriptor, raw = tempfile.mkstemp(prefix=".archive-page.", dir=str(ARCHIVE_PAGES))
        temporary = Path(raw)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(data); output.flush(); os.fsync(output.fileno())
            os.replace(temporary, target); target.chmod(0o444)
        finally:
            if temporary.exists(): temporary.unlink()
    return {
        "schema": PAGE_HEAD_SCHEMA,
        "path": str(target.relative_to(ROOT)),
        "sha256": value_sha,
        "bytes": len(data),
        "total_archives": prior_total + len(records),
        "depth": prior_depth + 1,
    }


def evidence_files() -> Dict[str, Path]:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    result: Dict[str, Path] = {}
    for path in sorted(EVIDENCE.rglob("*")):
        if path.is_symlink():
            raise SystemExit(f"evidence symlink is forbidden: {path.relative_to(ROOT)}")
        if path.is_file():
            result[str(path.relative_to(ROOT))] = path
    return result


def active_bytes() -> int:
    return sum(path.stat().st_size for path in evidence_files().values())


def textual_references(path: Path, known: Set[str], digests: Dict[str, List[str]]) -> Set[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return set()
    if len(data) > 16 * 1024 * 1024:
        raise SystemExit(f"reference source is too large for safe evidence compaction: {path.relative_to(ROOT)}")
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
    seen: Set[Path] = set()
    candidates: List[Path] = []
    for entry in reference_roots():
        if any(char in entry for char in "*?["):
            candidates.extend(sorted(ROOT.glob(entry)))
            continue
        base = ROOT / entry
        if base.is_dir():
            candidates.extend(sorted(base.rglob("*")))
        else:
            candidates.append(base)
    for path in candidates:
        if not path.exists():
            continue
        if path.is_symlink():
            raise SystemExit(f"reference source symlink is forbidden: {path.relative_to(ROOT)}")
        if not path.is_file():
            continue
        resolved = path.resolve()
        # Active evidence, deep archives and the index itself never act as
        # reference roots (the evidence tree is traversed transitively).
        if EVIDENCE in resolved.parents or ARCHIVES in resolved.parents or resolved == INDEX:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        yield path


def matching_receipt(path: Path, versions: Iterable[Dict[str, object]]) -> Optional[Dict[str, object]]:
    data = path.read_bytes(); size = len(data); value = digest(data)
    return next(
        (entry for entry in versions if entry.get("bytes") == size and entry.get("sha256") == value),
        None,
    )


def task_archive_payload(path: Path) -> Optional[Dict[str, object]]:
    """Parse a task-archive payload; None when the file is not one."""
    if TASK_ARCHIVES not in path.parents:
        return None
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def reachable_evidence(files: Dict[str, Path]) -> Set[str]:
    known = set(files)
    digests: Dict[str, List[str]] = {}
    for relative, path in files.items():
        digests.setdefault(digest(path.read_bytes()), []).append(relative)
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
    selected = candidates if should_archive else []
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


def publish_archive(selected: List[str], files: Dict[str, Path]) -> Dict[str, object]:
    entries = []
    payloads: Dict[str, bytes] = {}
    for relative in sorted(selected):
        data = files[relative].read_bytes(); payloads[relative] = data
        entries.append({"path": relative, "sha256": digest(data), "bytes": len(data)})
    manifest = {"schema": ARCHIVE_SCHEMA, "entries": entries}
    manifest_bytes = canonical(manifest)
    ARCHIVES.mkdir(parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=".evidence-archive.", suffix=".zip", dir=str(ARCHIVES))
    os.close(descriptor); temporary = Path(raw)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as handle:
            handle.writestr(zip_info("MANIFEST.json"), manifest_bytes)
            for relative in sorted(payloads):
                handle.writestr(zip_info(relative), payloads[relative])
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        archive_bytes = temporary.read_bytes(); archive_digest = digest(archive_bytes)
        target = ARCHIVES / f"{archive_digest}.zip"
        if target.exists():
            if target.is_symlink() or target.read_bytes() != archive_bytes:
                raise SystemExit("evidence archive digest collision")
            temporary.unlink()
        else:
            os.replace(temporary, target); target.chmod(0o444)
        record = {
            "schema": HEAD_SCHEMA,
            "path": str(target.relative_to(ROOT)),
            "sha256": archive_digest,
            "bytes": len(archive_bytes),
            "file_count": len(entries),
            "source_bytes": sum(entry["bytes"] for entry in entries),
            "created_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "manifest_sha256": digest(manifest_bytes),
        }
        manifest_from_archive(record, deep=True)
        return record
    finally:
        if temporary.exists():
            temporary.unlink()


def remove_exact(relative_paths: Iterable[str], receipts: Dict[str, Dict[str, object]]) -> int:
    removed = 0
    for relative in sorted(set(relative_paths)):
        path = (ROOT / relative).resolve()
        try:
            path.relative_to(EVIDENCE.resolve())
        except ValueError:
            raise SystemExit("evidence removal target escapes active evidence")
        receipt = receipts.get(relative)
        if receipt is None or not path.is_file() or path.is_symlink():
            raise SystemExit(f"evidence removal lacks verified archive authority: {relative}")
        data = path.read_bytes()
        if len(data) != receipt["bytes"] or digest(data) != receipt["sha256"]:
            raise SystemExit(f"evidence changed before archive removal: {relative}")
        path.unlink(); removed += 1
    for directory in sorted((path for path in EVIDENCE.rglob("*") if path.is_dir()), reverse=True):
        if not any(directory.iterdir()):
            directory.rmdir()
    return removed


def task_history_decision(selected: List[str], source: Optional[str], receipt: Optional[str]) -> Dict[str, object]:
    """Bind a human decision to the exact task-history compaction selection."""
    if not str(source or "").startswith("user:"):
        raise SystemExit("--include-task-history requires --source user:<decision>")
    packet = {"schema": "agent-evidence-task-history-compaction/v1", "selected": selected}
    packet_sha256 = digest(canonical(packet))
    task = load_json(TASK) if TASK.is_file() else {}
    config = load_json(CONFIG)
    if task.get("decision_policy_version") == humandecision.PROVIDER_POLICY_VERSION:
        if not receipt:
            raise SystemExit("task-history compaction requires a provider-signed human decision receipt")
        return humandecision.verify(
            ROOT, config, task, gate=TASK_HISTORY_DECISION_GATE,
            artifact_sha256=packet_sha256, source=str(source), receipt=receipt,
        )
    if receipt:
        raise SystemExit("local task-history approval does not accept an unaudited provider receipt")
    # Bind the same routing profile the provider receipts bind: a local
    # approval without `task` is a 3-key record that bypasses the routing
    # profile check (see workflowctl command_approve).
    return humandecision.local_approval(str(source), packet_sha256, task)


def command_compact(args: argparse.Namespace) -> int:
    LOCK.parent.mkdir(parents=True, exist_ok=True); LOCK.touch(exist_ok=True)
    with LOCK.open("r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        retention = policy()
        age = int(retention["min_age_hours"]) if args.min_age_hours is None else args.min_age_hours
        if args.gc_orphans:
            # Remove the unindexed files `verify` reports, only after a full
            # deep verification of the index they escaped. Every removal is
            # listed; --dry-run lists without touching anything.
            index, _ = verify_index(deep=True)
            orphans = orphan_archives(index)
            if args.dry_run:
                print(json.dumps({
                    "schema": "agent-evidence-orphan-gc-plan/v1",
                    "orphans": [str(path.relative_to(ROOT)) for path in orphans],
                }, ensure_ascii=False, indent=2))
                return 0
            removed = 0
            for orphan in orphans:
                if orphan.is_symlink():
                    raise SystemExit(f"evidence orphan symlink is forbidden: {orphan.relative_to(ROOT)}")
                if not orphan.is_file():
                    print(f"EVIDENCE ORPHAN SKIPPED: {orphan.relative_to(ROOT)}")
                    continue
                print(f"EVIDENCE ORPHAN REMOVED: {orphan.relative_to(ROOT)}")
                orphan.unlink(); removed += 1
            print(f"EVIDENCE ORPHAN GC: removed={removed}")
            return 0
        current_plan = plan(age, force=args.force, include_task_history=args.include_task_history)
        if args.dry_run:
            print(json.dumps(current_plan, ensure_ascii=False, indent=2)); return 0
        # Deep-verify every archive this run relies on BEFORE any active file
        # is removed; previously only the freshly published archive and the
        # duplicate-reconciliation path were deep-verified.
        index, archived = verify_index(deep=True); files = evidence_files()
        selected = list(current_plan["selected"])
        history = {relative for relative, path in files.items() if TASK_ARCHIVES in path.parents}
        history_selected = sorted(set(selected) & history)
        if history_selected and not args.include_task_history:
            raise SystemExit(
                "task-history evidence is selected for archival; rerun with "
                "--include-task-history --source user:<decision> or restore its reachability first"
            )
        if history_selected:
            decision = task_history_decision(history_selected, args.source, args.human_decision_receipt)
            print(f"TASK HISTORY DECISION: {json.dumps(decision, ensure_ascii=False, sort_keys=True)}")
        duplicate_paths = list(current_plan["archived_duplicates"])
        if duplicate_paths:
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
        removed = remove_exact(selected, receipts)
        if history_selected and TASK.is_file():
            # The head chain now lives only inside the deep archive; drop the
            # dangling active head pointer so later archival starts fresh.
            # The head is a capsule-bound TASK invariant: move it through the
            # canonical transition so the capsule is re-bound atomically.
            before_task = load_json(TASK)
            if before_task.get("task_archive") is not None:
                after_task = copy.deepcopy(before_task)
                after_task["task_archive"] = None
                commit_task_head(
                    before_task, after_task,
                    reason="evidence-task-history-compacted",
                    summary="cleared the archived task-history head after human-approved compaction",
                )
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


def command_restore(args: argparse.Namespace) -> int:
    # Restore mutates active evidence and must serialize with compaction and
    # migration exactly like every other evidence write path.
    LOCK.parent.mkdir(parents=True, exist_ok=True); LOCK.touch(exist_ok=True)
    with LOCK.open("r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        index, _ = verify_index(deep=True)
        selected = None
        for record in all_records(index):
            if args.archive in {record.get("path"), record.get("sha256")}:
                selected = record; break
        if not isinstance(selected, dict):
            raise SystemExit("requested evidence archive is not indexed")
        manifest = manifest_from_archive(selected, deep=True); archive = archive_path(selected)
        with zipfile.ZipFile(archive, "r") as zip_handle:
            payloads = {str(entry["path"]): zip_handle.read(str(entry["path"])) for entry in manifest["entries"]}
        for relative, data in payloads.items():
            target = (ROOT / relative).resolve()
            try:
                target.relative_to(EVIDENCE.resolve())
            except ValueError:
                raise SystemExit("restore target escapes active evidence")
            if target.exists() and (target.is_symlink() or target.read_bytes() != data):
                raise SystemExit(f"restore collision: {relative}")
        restored = 0
        for relative, data in payloads.items():
            target = ROOT / relative
            if target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            descriptor, raw = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
            temporary = Path(raw)
            try:
                with os.fdopen(descriptor, "wb") as output:
                    output.write(data); output.flush(); os.fsync(output.fileno())
                os.replace(temporary, target); target.chmod(0o444); restored += 1
            finally:
                if temporary.exists(): temporary.unlink()
        print(f"EVIDENCE RESTORED: files={restored} archive={selected['sha256']}")
        return 0


def task_archive_chain(head: object) -> List[Tuple[Dict[str, object], Dict[str, object], bytes]]:
    """Load and fully verify a task-archive head chain (newest first)."""
    chain: List[Tuple[Dict[str, object], Dict[str, object], bytes]] = []
    current = head; seen: Set[str] = set()
    while current is not None:
        if (
            not isinstance(current, dict) or set(current) != TASK_ARCHIVE_HEAD_FIELDS
            or current.get("schema") != TASK_ARCHIVE_HEAD_SCHEMA
            or SHA.fullmatch(str(current.get("sha256", ""))) is None
            or not isinstance(current.get("bytes"), int) or current["bytes"] < 1
            or not isinstance(current.get("total_archives"), int) or current["total_archives"] < 1
        ):
            raise SystemExit("task archive head is invalid")
        value_sha = str(current["sha256"])
        expected = TASK_ARCHIVES / f"{value_sha}.json"
        path = (ROOT / str(current.get("path", ""))).resolve()
        if path != expected.resolve() or value_sha in seen or not path.is_file() or path.is_symlink():
            raise SystemExit("task archive head path is invalid or missing")
        seen.add(value_sha); data = path.read_bytes()
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
    TASK_ARCHIVES.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.is_symlink() or target.read_bytes() != data:
            raise SystemExit("task archive digest collision")
        return
    descriptor, raw = tempfile.mkstemp(prefix=".task-archive.", dir=str(TASK_ARCHIVES))
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, target); target.chmod(0o444)
    finally:
        if temporary.exists():
            temporary.unlink()


def command_migrate_task_archives(args: argparse.Namespace) -> int:
    """Rewrite the legacy v1 task-archive chain to v2 (content-addressed).

    Referenced evidence paths are extracted from the embedded TASK/contract
    text into `referenced_evidence` digests (only evidence still active can
    be digest-bound; already-compacted evidence needs no protection). Heads
    are re-anchored oldest-first, the rewritten chain is fully verified
    BEFORE the TASK head pointer moves, and old v1 files are left in place
    as unreachable, compactable evidence.
    """
    LOCK.parent.mkdir(parents=True, exist_ok=True); LOCK.touch(exist_ok=True)
    with LOCK.open("r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        task = load_json(TASK) if TASK.is_file() else {}
        head = task.get("task_archive")
        if head is None:
            print("TASK ARCHIVE MIGRATION: no task archive head")
            return 0
        chain = task_archive_chain(head)
        files = evidence_files()
        known = set(files)
        file_digests = {relative: digest(path.read_bytes()) for relative, path in files.items()}
        rewritten: List[Tuple[Path, bytes]] = []
        new_head: Optional[Dict[str, object]] = None
        migrated_count = 0
        # Re-anchor oldest first so every previous pointer binds rewritten bytes.
        for old_head, payload, _ in reversed(chain):
            previous_changed = (new_head is None) != (payload.get("previous") is None) or (
                isinstance(new_head, dict) and isinstance(payload.get("previous"), dict)
                and new_head.get("sha256") != payload["previous"].get("sha256")
            )
            if payload.get("schema") == TASK_ARCHIVE_V2 and not previous_changed:
                new_head = {key: old_head[key] for key in TASK_ARCHIVE_HEAD_FIELDS}
                continue
            if payload.get("schema") == TASK_ARCHIVE_V2:
                migrated = dict(payload)
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
    raise SystemExit(main())
