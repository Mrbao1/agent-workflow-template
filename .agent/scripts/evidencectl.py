#!/usr/bin/env python3
"""Bound active evidence while preserving exact, restorable audit archives."""

from pathlib import Path
import argparse
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


def find_agent_dir() -> Path:
    for root in (Path.cwd().resolve(), *Path.cwd().resolve().parents):
        candidate = root / ".agent"
        if candidate.is_dir():
            return candidate
    raise SystemExit(".agent directory not found")


AGENT = find_agent_dir(); ROOT = AGENT.parent.resolve(); STATE = AGENT / "state"
EVIDENCE = STATE / "evidence"; ARCHIVES = STATE / "evidence-archives"
ARCHIVE_PAGES = STATE / "evidence-archive-pages"
INDEX = STATE / "EVIDENCE_INDEX.json"; CONFIG = AGENT / "config.json"
LOCK = STATE / ".evidence.lock"
SHA = re.compile(r"[0-9a-f]{64}")
INDEX_SCHEMA = "agent-evidence-index/v2"
ARCHIVE_SCHEMA = "agent-evidence-archive/v1"
HEAD_SCHEMA = "agent-evidence-archive-head/v1"
PAGE_SCHEMA = "agent-evidence-archive-page/v1"
PAGE_HEAD_SCHEMA = "agent-evidence-archive-page-head/v1"
ARCHIVE_FIELDS = {
    "schema", "path", "sha256", "bytes", "file_count", "source_bytes",
    "created_at", "manifest_sha256",
}


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


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def policy() -> Dict[str, object]:
    value = load_json(CONFIG).get("evidence_retention")
    if not isinstance(value, dict):
        raise SystemExit("evidence retention policy is missing")
    return value


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


def textual_references(path: Path, known: Set[str]) -> Set[str]:
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
    return {relative for relative in known if any(relative in value for value in strings)}


def root_reference_files() -> Iterable[Path]:
    seen: Set[Path] = set()
    for base in (
        STATE, AGENT / "policies", AGENT / "knowledge", AGENT / "capabilities",
        AGENT / "workflows", ROOT / "docs",
    ):
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                raise SystemExit(f"reference source symlink is forbidden: {path.relative_to(ROOT)}")
            if not path.is_file():
                continue
            if EVIDENCE in path.parents or ARCHIVES in path.parents or path == INDEX:
                continue
            seen.add(path.resolve())
            yield path
    for path in (ROOT / "AGENTS.md", ROOT / "README.md", AGENT / "config.json"):
        if path.is_symlink():
            raise SystemExit(f"reference source symlink is forbidden: {path.relative_to(ROOT)}")
        if path.is_file() and path.resolve() not in seen:
            yield path


def matching_receipt(path: Path, versions: Iterable[Dict[str, object]]) -> Optional[Dict[str, object]]:
    data = path.read_bytes(); size = len(data); value = digest(data)
    return next(
        (entry for entry in versions if entry.get("bytes") == size and entry.get("sha256") == value),
        None,
    )


def reachable_evidence(files: Dict[str, Path]) -> Set[str]:
    known = set(files); reachable: Set[str] = set(); queue: List[str] = []
    for source in root_reference_files():
        for reference in textual_references(source, known):
            if reference not in reachable:
                reachable.add(reference); queue.append(reference)
    while queue:
        current = queue.pop()
        for reference in textual_references(files[current], known):
            if reference not in reachable:
                reachable.add(reference); queue.append(reference)
    return reachable


def plan(min_age_hours: int, force: bool = False) -> Dict[str, object]:
    index, archived = verify_index(deep=False); files = evidence_files()
    reachable = reachable_evidence(files); now_ns = time.time_ns()
    recent: Set[str] = set(); duplicates: List[str] = []
    for relative, path in files.items():
        age_hours = (now_ns - path.stat().st_mtime_ns) / 3_600_000_000_000
        if age_hours < min_age_hours:
            recent.add(relative)
        receipt = matching_receipt(path, archived.get(relative, []))
        if receipt is not None and relative not in reachable:
            duplicates.append(relative)
    candidates = sorted(set(files) - reachable - recent - set(duplicates))
    active_bytes = sum(path.stat().st_size for path in files.values())
    candidate_bytes = sum(files[path].stat().st_size for path in candidates)
    retention = policy()
    should_archive = bool(candidates) and (
        force or active_bytes > int(retention["active_max_bytes"])
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


def command_compact(args: argparse.Namespace) -> int:
    LOCK.parent.mkdir(parents=True, exist_ok=True); LOCK.touch(exist_ok=True)
    with LOCK.open("r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        retention = policy()
        age = int(retention["min_age_hours"]) if args.min_age_hours is None else args.min_age_hours
        current_plan = plan(age, force=args.force)
        if args.dry_run:
            print(json.dumps(current_plan, ensure_ascii=False, indent=2)); return 0
        index, archived = verify_index(deep=False); files = evidence_files()
        duplicate_paths = list(current_plan["archived_duplicates"])
        if duplicate_paths:
            for record in all_records(index):
                assert isinstance(record, dict); manifest_from_archive(record, deep=True)
            duplicate_receipts: Dict[str, Dict[str, object]] = {}
            for relative in duplicate_paths:
                receipt = matching_receipt(files[relative], archived.get(relative, []))
                if receipt is None:
                    raise SystemExit(f"archived duplicate changed before reconciliation: {relative}")
                duplicate_receipts[relative] = receipt
            remove_exact(duplicate_paths, duplicate_receipts)
        selected = list(current_plan["selected"])
        if not selected:
            remaining = active_bytes()
            if remaining > int(retention["active_max_bytes"]):
                raise SystemExit(
                    "active evidence remains over budget because remaining files are referenced or inside the age window; "
                    "split/promote references or explicitly retry with --min-age-hours 0 --force"
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
        print(
            f"EVIDENCE COMPACTED: files={removed} source_bytes={record['source_bytes']} "
            f"archive_bytes={record['bytes']} archive={record['sha256']}"
        )
        if active_bytes() > int(retention["active_max_bytes"]):
            print("EVIDENCE STILL OVER BUDGET: protected/recent active evidence requires split, promotion or an explicit age override")
            return 2
        return 0


def command_verify(args: argparse.Namespace) -> int:
    index, archived = verify_index(deep=args.deep)
    if not args.quiet:
        print(f"VALID EVIDENCE INDEX: archives={len(all_records(index))} files={len(archived)} deep={str(args.deep).lower()}")
    return 0


def command_status(args: argparse.Namespace) -> int:
    age = int(policy()["min_age_hours"])
    print(json.dumps(plan(age, force=False), ensure_ascii=False, indent=2)); return 0


def command_restore(args: argparse.Namespace) -> int:
    index, _ = verify_index(deep=True)
    selected = None
    for record in all_records(index):
        if args.archive in {record.get("path"), record.get("sha256")}:
            selected = record; break
    if not isinstance(selected, dict):
        raise SystemExit("requested evidence archive is not indexed")
    manifest = manifest_from_archive(selected, deep=True); archive = archive_path(selected)
    with zipfile.ZipFile(archive, "r") as handle:
        payloads = {str(entry["path"]): handle.read(str(entry["path"])) for entry in manifest["entries"]}
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


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    sub = value.add_subparsers(dest="command", required=True)
    compact = sub.add_parser("compact")
    compact.add_argument("--dry-run", action="store_true")
    compact.add_argument("--force", action="store_true")
    compact.add_argument("--min-age-hours", type=int)
    verify = sub.add_parser("verify")
    verify.add_argument("--deep", action="store_true"); verify.add_argument("--quiet", action="store_true")
    sub.add_parser("status")
    restore = sub.add_parser("restore"); restore.add_argument("--archive", required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    if getattr(args, "min_age_hours", None) is not None and args.min_age_hours < 0:
        raise SystemExit("--min-age-hours must be non-negative")
    return {
        "compact": lambda: command_compact(args), "verify": lambda: command_verify(args),
        "status": lambda: command_status(args), "restore": lambda: command_restore(args),
    }[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
