#!/usr/bin/env python3
"""Initialize, validate, compile, query, and plan a project-owned knowledge base."""
from pathlib import Path
import argparse
import json
import os
import re
import stat

from schema_validation import validate_managed_schema
from workflowlib import boundedprocess
from adaptive_common import (
    AdaptiveError, bytes_sha256, canonical_sha256, fail, load_json, print_json,
    resolve_root, safe_relative_path, write_json,
)

ENTRY_KEYS = {"id", "path", "kind", "owners", "tags", "source_globs", "status"}
KINDS = {"requirements", "architecture", "decision", "operation", "acceptance", "governance", "domain", "other"}
STATUSES = {"active", "deprecated", "superseded"}
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")


def knowledge_root(root):
    return root / ".agent/knowledge"


def registry_path(root):
    return knowledge_root(root) / "registry.json"


def bounded_strings(value, label, maximum=32):
    if not isinstance(value, list) or len(value) > maximum:
        raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", f"{label} must be a bounded list")
    cleaned = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip() or len(item.encode("utf-8")) > 256 or chr(0) in item:
            raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", f"{label}[{index}] is invalid")
        cleaned.append(item.strip())
    if len(cleaned) != len(set(cleaned)):
        raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", f"{label} contains duplicates")
    return cleaned


def safe_glob(value):
    if not isinstance(value, str) or not value or value.startswith("/") or chr(92) in value or chr(0) in value:
        raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", f"source glob is unsafe: {value!r}")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", f"source glob escapes the repository: {value!r}")
    return value


def source_glob_matches(path, pattern):
    expression = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    expression.append("(?:.*/)?")
                    index += 1
                else:
                    expression.append(".*")
                continue
            expression.append("[^/]*")
        elif char == "?":
            expression.append("[^/]")
        else:
            expression.append(re.escape(char))
        index += 1
    return re.fullmatch("".join(expression), path) is not None


def read_knowledge_file(root_path, relative, maximum_bytes=2 * 1024 * 1024):
    cursor = root_path
    try:
        root_status = cursor.lstat()
    except OSError as error:
        raise AdaptiveError("KNOWLEDGE_FILE_MISSING", f"knowledge root is missing or unsafe: {cursor}") from error
    if stat.S_ISLNK(root_status.st_mode) or not stat.S_ISDIR(root_status.st_mode):
        raise AdaptiveError("KNOWLEDGE_FILE_MISSING", f"knowledge root is missing or unsafe: {cursor}")
    parts = Path(relative).parts
    for index, part in enumerate(parts):
        cursor = cursor / part
        try:
            observed = cursor.lstat()
        except OSError as error:
            raise AdaptiveError("KNOWLEDGE_FILE_MISSING", f"knowledge entry is missing or unsafe: {relative}") from error
        if stat.S_ISLNK(observed.st_mode):
            raise AdaptiveError("KNOWLEDGE_FILE_MISSING", f"knowledge entry contains a symlink: {relative}")
        if index < len(parts) - 1 and not stat.S_ISDIR(observed.st_mode):
            raise AdaptiveError("KNOWLEDGE_FILE_MISSING", f"knowledge entry parent is unsafe: {relative}")
        if index == len(parts) - 1 and not stat.S_ISREG(observed.st_mode):
            raise AdaptiveError("KNOWLEDGE_FILE_MISSING", f"knowledge entry is not a regular file: {relative}")
    if observed.st_size > maximum_bytes:
        raise AdaptiveError("KNOWLEDGE_FILE_TOO_LARGE", f"knowledge entry exceeds {maximum_bytes} bytes: {relative}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(cursor, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino):
            raise AdaptiveError("KNOWLEDGE_FILE_CHANGED", f"knowledge entry changed during verification: {relative}")
        raw = b""
        while len(raw) <= maximum_bytes:
            chunk = os.read(descriptor, min(65536, maximum_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        if len(raw) > maximum_bytes:
            raise AdaptiveError("KNOWLEDGE_FILE_TOO_LARGE", f"knowledge entry exceeds {maximum_bytes} bytes: {relative}")
        return raw
    finally:
        os.close(descriptor)


def load_registry(root, require_files=True):
    value = load_json(registry_path(root), "knowledge registry")
    try:
        schema_errors = validate_managed_schema(value, "knowledge-registry.schema.json", "agent-knowledge-registry/v1")
    except ValueError as error:
        raise AdaptiveError("INVALID_MANAGED_SCHEMA", str(error), 3) from error
    if schema_errors:
        raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", "Knowledge registry schema validation failed: " + "; ".join(schema_errors))
    if not isinstance(value, dict) or set(value) != {"schema", "entries"} or value.get("schema") != "agent-knowledge-registry/v1":
        raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", "knowledge registry fields are invalid")
    entries = value.get("entries")
    if not isinstance(entries, list) or len(entries) > 256:
        raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", "knowledge registry entries are invalid")
    cleaned, ids, paths = [], set(), set()
    root_path = knowledge_root(root)
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", f"entry {index} fields are invalid")
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not ID_RE.fullmatch(entry_id) or entry_id in ids:
            raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", f"entry {index} ID is invalid or duplicated")
        relative = str(safe_relative_path(entry.get("path"), suffix=".md"))
        if relative in paths or relative in {"INDEX.md"}:
            raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", f"entry {index} path is duplicated or reserved")
        if entry.get("kind") not in KINDS or entry.get("status") not in STATUSES:
            raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", f"entry {index} kind or status is invalid")
        owners = bounded_strings(entry.get("owners"), f"entries[{index}].owners")
        if entry["status"] == "active" and not owners:
            raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", f"active entry {entry_id} needs an owner")
        tags = bounded_strings(entry.get("tags"), f"entries[{index}].tags")
        globs = [safe_glob(item) for item in bounded_strings(entry.get("source_globs"), f"entries[{index}].source_globs")]
        if entry["status"] == "active" and not globs:
            raise AdaptiveError("INVALID_KNOWLEDGE_REGISTRY", f"active entry {entry_id} needs source globs")
        if require_files:
            read_knowledge_file(root_path, relative)
        ids.add(entry_id); paths.add(relative)
        cleaned.append({
            "id": entry_id, "path": relative, "kind": entry["kind"], "owners": owners,
            "tags": tags, "source_globs": globs, "status": entry["status"],
        })
    return {"schema": value["schema"], "entries": sorted(cleaned, key=lambda item: item["id"])}


def command_init(root, args):
    path = registry_path(root)
    if path.exists() and not args.force:
        raise AdaptiveError("KNOWLEDGE_REGISTRY_EXISTS", f"knowledge registry already exists: {path}")
    write_json(path, {"schema": "agent-knowledge-registry/v1", "entries": []})
    print(f"KNOWLEDGE_REGISTRY_CREATED: {path}")
    return 0


def command_check(root, _args):
    registry = load_registry(root)
    print_json({"status": "valid", "entry_count": len(registry["entries"]), "registry_sha256": canonical_sha256(registry)})
    return 0


def expected_catalog(root):
    registry = load_registry(root)
    entries = []
    for entry in registry["entries"]:
        raw = read_knowledge_file(knowledge_root(root), entry["path"])
        entries.append({**entry, "bytes": len(raw), "sha256": bytes_sha256(raw)})
    payload = {"schema": "agent-knowledge-catalog/v1", "registry_sha256": canonical_sha256(registry), "entries": entries}
    return {**payload, "catalog_sha256": canonical_sha256(payload)}


def command_build(root, _args):
    catalog = expected_catalog(root)
    path = knowledge_root(root) / "catalog.json"
    write_json(path, catalog)
    print_json({"status": "built", "path": str(path), "catalog_sha256": catalog["catalog_sha256"], "entry_count": len(catalog["entries"])})
    return 0


def command_verify_catalog(root, _args):
    expected = expected_catalog(root)
    observed = load_json(knowledge_root(root) / "catalog.json", "knowledge catalog")
    if observed != expected:
        raise AdaptiveError("KNOWLEDGE_CATALOG_DRIFT", "knowledge catalog differs from the current owner files", 3)
    print_json({"status": "verified", "catalog_sha256": expected["catalog_sha256"], "entry_count": len(expected["entries"])})
    return 0


def command_plan(root, args):
    registry = load_registry(root)
    changed = []
    for value in args.changed:
        changed.append(str(safe_relative_path(value)))
    owners = {}
    unowned = []
    for path in changed:
        matched = [entry for entry in registry["entries"] if entry["status"] == "active" and any(source_glob_matches(path, pattern) for pattern in entry["source_globs"])]
        if not matched:
            unowned.append(path)
        else:
            owners[path] = [{"id": item["id"], "path": item["path"], "owners": item["owners"]} for item in matched]
    result = {"schema": "agent-knowledge-plan/v1", "changed": changed, "owners": owners, "unowned": unowned}
    print_json(result)
    return 2 if unowned else 0


def command_plan_git_diff(root, args):
    for label, value in (("base", args.base), ("head", args.head)):
        if re.fullmatch(r"[0-9a-f]{40}", value or "") is None:
            raise AdaptiveError("INVALID_GIT_DIFF", f"{label} must be a full 40-hex commit")
    import subprocess
    for label, revision in (("head", args.head), *(([] if args.base == "0" * 40 else [("base", args.base)]))):
        verified = boundedprocess.run(["git", "cat-file", "-e", f"{revision}^{{commit}}"], cwd=root,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        if verified.returncode:
            raise AdaptiveError("GIT_DIFF_FAILED", f"{label} is not an available commit object")
    if args.base == "0" * 40:
        empty_tree_result = boundedprocess.run(["git", "hash-object", "-t", "tree", "--stdin"], cwd=root, input=b"",
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        if empty_tree_result.returncode:
            raise AdaptiveError("GIT_DIFF_FAILED", "could not derive the Git empty-tree object")
        try: empty_tree = empty_tree_result.stdout.strip().decode("ascii")
        except UnicodeError as error: raise AdaptiveError("GIT_DIFF_FAILED", "Git returned a malformed empty-tree identity") from error
        if re.fullmatch(r"[0-9a-f]{40,64}", empty_tree) is None:
            raise AdaptiveError("GIT_DIFF_FAILED", "Git returned a malformed empty-tree identity")
        command = ["git", "diff", "--no-ext-diff", "--no-renames", "--ignore-submodules=none", "--name-only", "-z", empty_tree, args.head, "--"]
    else:
        command = ["git", "diff", "--no-ext-diff", "--no-renames", "--ignore-submodules=none", "--name-only", "-z", args.base, args.head, "--"]
    result = boundedprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise AdaptiveError("GIT_DIFF_FAILED", "could not derive the authoritative changed-path set")
    try:
        changed = [item.decode("utf-8") for item in result.stdout.split(bytes([0])) if item]
    except UnicodeError as error:
        raise AdaptiveError("GIT_DIFF_FAILED", "changed paths are not UTF-8") from error
    if not changed:
        print_json({"schema": "agent-knowledge-plan/v1", "changed": [], "owners": {}, "unowned": []})
        return 0
    args.changed = changed
    return command_plan(root, args)


def command_query(root, args):
    registry = load_registry(root)
    entries = registry["entries"]
    if args.id:
        entries = [item for item in entries if item["id"] == args.id]
    if args.tag:
        entries = [item for item in entries if args.tag in item["tags"]]
    if args.kind:
        entries = [item for item in entries if item["kind"] == args.kind]
    print_json({"schema": "agent-knowledge-query/v1", "entries": entries})
    return 0 if entries else 2


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--root")
    sub = value.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init"); init.add_argument("--force", action="store_true")
    sub.add_parser("check"); sub.add_parser("build"); sub.add_parser("verify-catalog")
    plan = sub.add_parser("plan"); plan.add_argument("--changed", nargs="+", required=True)
    git_plan = sub.add_parser("plan-git-diff"); git_plan.add_argument("--base", required=True); git_plan.add_argument("--head", required=True)
    query = sub.add_parser("query"); query.add_argument("--id"); query.add_argument("--tag"); query.add_argument("--kind", choices=sorted(KINDS))
    return value


def main():
    args = parser().parse_args()
    try:
        root = resolve_root(args.root, __file__)
        return {"init": command_init, "check": command_check, "build": command_build, "verify-catalog": command_verify_catalog,
                "plan": command_plan, "plan-git-diff": command_plan_git_diff, "query": command_query}[args.command](root, args)
    except Exception as error:
        return fail(error)


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
