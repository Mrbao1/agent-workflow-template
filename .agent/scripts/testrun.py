#!/usr/bin/env python3
"""Run one bounded test group and append a machine-generated hashed receipt."""

from pathlib import Path
import argparse
import contextlib
import ctypes
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
import uuid
import sys

import humandecision
from workflowlib import boundedio
from process_observation import (
    ProcessObservationError, bounded_trusted_command_output, darwin_process_snapshot,
    linux_pidfd_supported, linux_process_snapshot, linux_signal_identity,
)

def _reject_nonfinite_json(token):
    raise json.JSONDecodeError(f"non-finite JSON number is forbidden: {token}",token,0)

def strict_json_loads(raw,**kwargs):
    return json.loads(raw,parse_constant=_reject_nonfinite_json,**kwargs)

def strict_json_dumps(value,**kwargs):
    kwargs["allow_nan"]=False
    return json.dumps(value,**kwargs)



def root():
    for path in (Path.cwd().resolve(), *Path.cwd().resolve().parents):
        if (path / ".agent").is_dir():
            return path
    raise SystemExit(".agent directory not found")


ROOT = root()
CONFIG_PATH = ROOT / ".agent" / "config.json"
TASK_PATH = ROOT / ".agent" / "state" / "TASK.json"
LOCK_PATH = ROOT / ".agent" / "state" / ".test-budget.lock"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[0-9a-f]{32}$")
CASE_ID = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
REMEDIATION_SCHEMA = "agent-test-infrastructure-remediation/v1"
REMEDIATION_GATE = "test-infrastructure-remediation"
MAX_TEST_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_CONSOLE_OUTPUT_BYTES = 12 * 1024
PROCESS_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_CANDIDATE_FILE_BYTES = 256 * 1024 * 1024
MAX_CANDIDATE_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_CANDIDATE_FILES = 8192
MAX_CANDIDATE_ENTRIES = 32768
LAUNCH_TOKEN_NAME = "AGENT_TEST_LAUNCH_ID"
TEST_EXECUTION_BOUNDARY = {
    "schema": "agent-test-execution-boundary/v1",
    "mode": "disposable-exact-candidate",
    "writable_root": "disposable-candidate",
    "credentials_inherited": False,
    "filesystem_confinement": False,
    "network_confinement": False,
    "hostile_command_containment": False,
    "process_cleanup": "bounded observable cleanup; Darwin additionally fails closed on persistent same-user kernel-identity baseline deltas",
    "claim_limit": "same-UID/private copies and bounded process observation are not an OS filesystem, network, or hostile-code security boundary",
}


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def atomic(path, value):
    data=(strict_json_dumps(value,ensure_ascii=False,indent=2)+"\n").encode("utf-8")
    try: boundedio.atomic_write(path,data,mode=0o600,label="test runner state")
    except RuntimeError as error: raise SystemExit(str(error)) from error


def atomic_text(path, text):
    try: boundedio.atomic_write(path,text.encode("utf-8"),mode=0o600,label="test runner state")
    except RuntimeError as error: raise SystemExit(str(error)) from error


def atomic_bytes(path,data):
    try: boundedio.atomic_write(path,data,mode=0o600,label="test runner state")
    except RuntimeError as error: raise SystemExit(str(error)) from error


def canonical(value):
    return strict_json_dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def load_json(path):
    value = strict_json_loads(boundedio.read_text(path,label="test runner JSON"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON object required: {path}")
    return value


IGNORED_PRODUCT_PARTS = {
    ".agent", ".git", ".gradle", ".idea", ".swiftpm", ".venv", "Pods",
    "DerivedData", "__pycache__", "build", "coverage", "dist", "node_modules",
    "target", "vendor",
}
PRODUCT_MANIFESTS = {
    "Package.swift": {".swift"},
    "project.pbxproj": {".swift", ".m", ".mm", ".c", ".cc", ".cpp", ".h", ".hpp"},
    "settings.gradle": {".java", ".kt", ".kts", ".xml"},
    "settings.gradle.kts": {".java", ".kt", ".kts", ".xml"},
    "build.gradle": {".java", ".kt", ".kts", ".xml"},
    "build.gradle.kts": {".java", ".kt", ".kts", ".xml"},
    "package.json": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte", ".css", ".html"},
    "pyproject.toml": {".py", ".pyi"},
    "setup.py": {".py", ".pyi"},
    "requirements.txt": {".py", ".pyi"},
    "go.mod": {".go"},
    "Cargo.toml": {".rs"},
    "pom.xml": {".java", ".kt", ".xml"},
    "build.xml": {".java", ".kt", ".xml"},
}
COMMON_SOURCE_DIRS = {
    "Sources", "Tests", "androidTest", "api", "app", "backend", "bin", "cli",
    "cmd", "e2e", "frontend", "include", "integration", "ios", "lib", "pages",
    "public", "server", "src", "test", "tests",
}
ROOT_SOURCE_SUFFIXES = set().union(*PRODUCT_MANIFESTS.values()) | {".sh"}
PRODUCT_METADATA = {
    "Package.resolved", "Podfile", "Podfile.lock", "Cartfile", "Cartfile.resolved",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb",
    "gradle.properties", "gradlew", "gradlew.bat", "go.sum", "Cargo.lock",
    "poetry.lock", "Pipfile", "Pipfile.lock", "requirements-dev.txt",
    "Makefile", "Dockerfile", ".dockerignore", "compose.yaml", "compose.yml",
}


def _ignored_product_path(path, product_root):
    try:
        relative = path.relative_to(product_root)
    except ValueError:
        return True
    return any(part in IGNORED_PRODUCT_PARTS for part in relative.parts)


def _lexical_project_path(raw, label):
    """Resolve a configured path only after rejecting every symlink component."""
    if not isinstance(raw, str) or not raw.strip():
        raise SystemExit(f"{label} is invalid")
    path = Path(os.path.abspath(str(ROOT / raw)))
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        raise SystemExit(f"{label} escapes project")
    current = ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise SystemExit(f"{label} has a symlink component: {current.relative_to(ROOT)}")
    return path


def _safe_scope_path(raw, label):
    path = _lexical_project_path(raw, label)
    if not path.exists():
        raise SystemExit(f"{label} is missing: {raw}")
    return path


def _bounded_tree_entries(path,label,state,ignored=None):
    stack=[path]
    while stack:
        directory=stack.pop(); directories=[]; nondirectories=[]
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    state["entries"]=state.get("entries",0)+1
                    if state["entries"]>MAX_CANDIDATE_ENTRIES:
                        raise SystemExit(f"candidate discovery exceeds its {MAX_CANDIDATE_ENTRIES}-entry limit")
                    candidate=Path(entry.path)
                    if ignored is not None and ignored(candidate): continue
                    observed=entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(observed.st_mode):
                        raise SystemExit(f"{label} contains a symlink: {candidate.relative_to(ROOT)}")
                    item=(entry.name,candidate,observed)
                    if stat.S_ISDIR(observed.st_mode): directories.append(item)
                    else: nondirectories.append(item)
        except FileNotFoundError as error: raise SystemExit(f"{label} changed during traversal") from error
        except OSError as error: raise SystemExit(f"{label} cannot be enumerated") from error
        directories.sort(key=lambda item:item[0]); nondirectories.sort(key=lambda item:item[0])
        for collection in (directories,nondirectories):
            for _name,candidate,observed in collection: yield candidate,observed
        for _name,candidate,_observed in reversed(directories): stack.append(candidate)


def _files_under(path,label,state):
    observed=os.lstat(path)
    if stat.S_ISREG(observed.st_mode):
        state["entries"]=state.get("entries",0)+1
        if state["entries"]>MAX_CANDIDATE_ENTRIES: raise SystemExit("candidate discovery exceeds its entry limit")
        return [path]
    files=[]
    for item,metadata in _bounded_tree_entries(path,label,state):
        if stat.S_ISREG(metadata.st_mode) and "__pycache__" not in item.parts and item.suffix not in {".pyc",".pyo"} and item.name!=".DS_Store":
            files.append(item)
            if len(files)>MAX_CANDIDATE_FILES: raise SystemExit("candidate fingerprint scope exceeds its file limit")
    if not files: raise SystemExit(f"{label} contains no files: {path.relative_to(ROOT)}")
    return files


def governed_product_files(config):
    """Return strict configured scope plus automatically discovered product bytes.

    Configured paths are promises, not optional layout guesses.  Automatic discovery
    is rooted at scope.product_roots (default project root) and makes a manifest with
    no matching product-owned source a hard error.
    """
    scope = config.get("scope")
    if not isinstance(scope, dict):
        raise SystemExit("scope configuration is missing")
    configured = scope.get("fingerprint_paths")
    if not isinstance(configured, list) or not configured:
        raise SystemExit("candidate fingerprint paths are missing")
    files=set(); traversal_state={"entries":0}
    for raw in configured:
        path=_safe_scope_path(raw,"configured fingerprint path")
        files.update(_files_under(path,"configured fingerprint path",traversal_state))
        if len(files)>MAX_CANDIDATE_FILES: raise SystemExit("candidate fingerprint scope exceeds its file limit")

    roots_raw = scope.get("product_roots", ["."])
    if not isinstance(roots_raw, list) or not roots_raw:
        raise SystemExit("scope.product_roots must be a non-empty string array")
    product_roots = []
    for raw in roots_raw:
        product_root = _safe_scope_path(raw, "configured product root")
        if not product_root.is_dir():
            raise SystemExit(f"configured product root is not a directory: {raw}")
        product_roots.append(product_root)

    discovered_any = False
    for product_root in product_roots:
        entry_rows=list(_bounded_tree_entries(
            product_root,"product discovery",traversal_state,
            ignored=lambda item:_ignored_product_path(item,product_root),
        ))
        all_files=[item for item,metadata in entry_rows if stat.S_ISREG(metadata.st_mode)]
        manifests=[item for item in all_files if item.name in PRODUCT_MANIFESTS]
        metadata_files=[item for item in all_files if item.name in PRODUCT_METADATA]
        source_files=[item for item in all_files if item.suffix.lower() in ROOT_SOURCE_SUFFIXES]
        for manifest in manifests:
            owner=manifest.parent.parent if manifest.name=="project.pbxproj" and manifest.parent.suffix==".xcodeproj" else manifest.parent
            suffixes=PRODUCT_MANIFESTS[manifest.name]
            owned=[item for item in source_files if item!=manifest and item.suffix.lower() in suffixes and (item==owner or owner in item.parents)]
            if not owned:
                raise SystemExit(
                    "product manifest has no discoverable product-owned source: "
                    f"{manifest.relative_to(ROOT)}; add source under a common layout or list its custom path in scope.fingerprint_paths"
                )
            files.add(manifest); files.update(owned); discovered_any=True
        files.update(metadata_files)
        common_roots=[]; common_identities={}; common_spellings={}
        common_names={name.casefold() for name in COMMON_SOURCE_DIRS}
        for candidate,observed in entry_rows:
            if candidate.parent!=product_root or not stat.S_ISDIR(observed.st_mode): continue
            folded=candidate.name.casefold()
            if folded not in common_names: continue
            prior_spelling=common_spellings.get(folded)
            if prior_spelling is not None and prior_spelling.name!=candidate.name:
                raise SystemExit(f"product source roots have a cross-platform case alias: {prior_spelling.relative_to(ROOT)} and {candidate.relative_to(ROOT)}")
            identity=(observed.st_dev,observed.st_ino); prior_identity=common_identities.get(identity)
            if prior_identity is not None:
                if prior_identity!=candidate: raise SystemExit(f"product source roots are true inode aliases: {prior_identity.relative_to(ROOT)} and {candidate.relative_to(ROOT)}")
                continue
            common_spellings[folded]=candidate; common_identities[identity]=candidate; common_roots.append(candidate)
        for common_root in common_roots:
            owned=[item for item in all_files if common_root in item.parents]
            files.update(owned); discovered_any=discovered_any or bool(owned)
        root_sources=[item for item in source_files if item.parent==product_root]
        files.update(root_sources); discovered_any=discovered_any or bool(root_sources)
        if len(files)>MAX_CANDIDATE_FILES: raise SystemExit("candidate fingerprint scope exceeds its file limit")
    if not discovered_any:
        # Control-only repositories are valid only when their explicitly governed
        # paths contain real files; automatic product discovery must never silently
        # produce an empty candidate.
        if not files:
            raise SystemExit("automatic product discovery found no manifest or source")
    if len(files)>MAX_CANDIDATE_FILES: raise SystemExit("candidate fingerprint scope exceeds its file limit")
    return sorted(files)


def _acceptance_scope_path(path):
    relative=path.relative_to(ROOT)
    return not (len(relative.parts)>=2 and relative.parts[:2]==(".agent","state"))


def acceptance_candidate_files(config):
    """Return the independent exact file authority for Node-6 acceptance.

    Canonical workflow runtime state is excluded because node transitions mutate it
    after implementation; requirement and gate receipts bind that authority through
    dedicated fields instead. Everything else comes from the user-confirmed strict
    fingerprint paths plus stack-neutral product discovery.
    """
    files=[path for path in governed_product_files(config) if _acceptance_scope_path(path)]
    if not files: raise SystemExit("acceptance candidate scope contains no immutable product files")
    if len(files)>MAX_CANDIDATE_FILES: raise SystemExit("acceptance candidate scope exceeds its file limit")
    return files


def acceptance_candidate_directories(config, files=None):
    """Bind real parent and empty-directory semantics for private materialization."""
    scope=config.get("scope")
    if not isinstance(scope,dict): raise SystemExit("scope configuration is missing")
    files=list(files if files is not None else acceptance_candidate_files(config)); directories={ROOT}
    for item in files:
        current=item.parent
        while current!=ROOT:
            if _acceptance_scope_path(current): directories.add(current)
            current=current.parent
    configured=scope.get("fingerprint_paths")
    roots=scope.get("product_roots",["."])
    if not isinstance(configured,list) or not configured or not isinstance(roots,list) or not roots:
        raise SystemExit("candidate directory scope is invalid")
    traversal_state={"entries":0}
    def add_directory(item):
        if _acceptance_scope_path(item): directories.add(item)
        if len(directories)>MAX_CANDIDATE_FILES: raise SystemExit("acceptance candidate scope exceeds its directory limit")
    for raw in configured:
        configured_path=_safe_scope_path(raw,"configured fingerprint path")
        if configured_path.is_dir():
            add_directory(configured_path)
            for item,observed in _bounded_tree_entries(configured_path,"candidate directory scope",traversal_state):
                if stat.S_ISDIR(observed.st_mode): add_directory(item)
    for raw in roots:
        product_root=_safe_scope_path(raw,"configured product root")
        if not product_root.is_dir(): raise SystemExit(f"configured product root is not a directory: {raw}")
        add_directory(product_root)
        for item,observed in _bounded_tree_entries(
                product_root,"candidate directory scope",traversal_state,
                ignored=lambda candidate:_ignored_product_path(candidate,product_root)):
            if stat.S_ISDIR(observed.st_mode): add_directory(item)
    return sorted(directories,key=lambda item:(len(item.relative_to(ROOT).parts),item.relative_to(ROOT).as_posix()))


def _open_beneath_root(source,want_directory,label):
    """Open every path component with openat/O_NOFOLLOW from a real ROOT fd."""
    relative=source.relative_to(ROOT); flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)
    current=os.open(ROOT,flags|getattr(os,"O_DIRECTORY",0)); opened=None
    try:
        if not relative.parts:
            opened=os.fstat(current)
            if not want_directory or not stat.S_ISDIR(opened.st_mode): return current,opened
            return current,opened
        for index,part in enumerate(relative.parts):
            final=index==len(relative.parts)-1
            before=os.stat(part,dir_fd=current,follow_symlinks=False)
            next_flags=flags|(getattr(os,"O_DIRECTORY",0) if not final or want_directory else 0)
            descriptor=os.open(part,next_flags,dir_fd=current)
            after=os.fstat(descriptor)
            if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):
                os.close(descriptor); raise SystemExit(f"{label} changed while opening: {relative}")
            os.close(current); current=descriptor; opened=after
        return current,opened
    except Exception:
        try: os.close(current)
        except OSError: pass
        raise


def _descriptor_file_snapshot(source, label):
    """Read one root-descriptor-bound inode once for both digest and copy."""
    try: descriptor,opened=_open_beneath_root(source,False,label)
    except OSError as error: raise SystemExit(f"{label} is unavailable: {source.relative_to(ROOT)}") from error
    if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1 or opened.st_size>MAX_CANDIDATE_FILE_BYTES):
        os.close(descriptor)
        raise SystemExit(f"{label} is not one bounded single-link regular inode: {source.relative_to(ROOT)}")
    try:
        opened=os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1:
            raise SystemExit(f"{label} changed while opening: {source.relative_to(ROOT)}")
        chunks=[]; size=0
        while True:
            chunk=os.read(descriptor,min(1024*1024,MAX_CANDIDATE_FILE_BYTES+1-size))
            if not chunk: break
            chunks.append(chunk); size+=len(chunk)
            if size>MAX_CANDIDATE_FILE_BYTES:
                raise SystemExit(f"{label} exceeds its file byte limit: {source.relative_to(ROOT)}")
        closed_identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
        final=os.fstat(descriptor)
        final_identity=(final.st_dev,final.st_ino,final.st_size,final.st_mtime_ns,final.st_ctime_ns)
        if final_identity!=closed_identity:
            raise SystemExit(f"{label} changed while reading: {source.relative_to(ROOT)}")
    finally:
        os.close(descriptor)
    return b"".join(chunks),stat.S_IMODE(opened.st_mode)


def _descriptor_directory_snapshot(source,label):
    try: descriptor,opened=_open_beneath_root(source,True,label)
    except OSError as error: raise SystemExit(f"{label} is unavailable: {source.relative_to(ROOT)}") from error
    try:
        if not stat.S_ISDIR(opened.st_mode): raise SystemExit(f"{label} is not a real directory: {source.relative_to(ROOT)}")
        return stat.S_IMODE(opened.st_mode)
    finally: os.close(descriptor)


def normalized_snapshot_files(files,label="candidate snapshot",filesystem_aliases=False):
    """Collapse identical authorities and case aliases only for private materialization."""
    unique={}
    for relative,data,mode in files:
        authority=relative.as_posix()
        key=authority.casefold() if filesystem_aliases and sys.platform.startswith("darwin") else authority
        current=unique.get(key)
        if current is not None:
            if current[0].as_posix()!=authority:
                raise SystemExit(f"{label} has true filesystem-alias file authorities: {current[0].as_posix()} and {authority}")
            if current[1:]!=(data,mode): raise SystemExit(f"{label} has conflicting duplicate file authority: {authority}")
            continue
        unique[key]=(relative,data,mode)
    keys=set(unique)
    for key in keys:
        parts=Path(key).parts
        for index in range(1,len(parts)):
            if Path(*parts[:index]).as_posix() in keys:
                raise SystemExit(f"{label} has a file-prefix collision: {unique[key][0].as_posix()}")
    return [unique[key] for key in sorted(unique)]


def normalized_snapshot_directories(files,directories,label="candidate snapshot",filesystem_aliases=False):
    """Deduplicate directories and discard only revalidated stale file collisions."""
    alias=lambda value:value.casefold() if filesystem_aliases and sys.platform.startswith("darwin") else value
    file_map={alias(relative.as_posix()):(data,mode) for relative,data,mode in files}
    unique={}
    for relative,mode in directories:
        authority=relative.as_posix(); key=alias(authority)
        if key in unique:
            if unique[key][0].as_posix()!=authority:
                raise SystemExit(f"{label} has true filesystem-alias directory authorities: {unique[key][0].as_posix()} and {authority}")
            if unique[key][1]!=mode: raise SystemExit(f"{label} has conflicting duplicate directory authority: {authority}")
            continue
        unique[key]=(relative,mode)
    stale=[]
    for directory_key in unique:
        parts=Path(directory_key).parts; file_key=None
        for index in range(1,len(parts)+1):
            candidate=alias(Path(*parts[:index]).as_posix())
            if candidate in file_map: file_key=candidate; break
        if file_key is None: continue
        current_data,current_mode=_descriptor_file_snapshot(ROOT/Path(file_key),f"{label} collision revalidation")
        if (current_data,current_mode)!=file_map[file_key]:
            raise SystemExit(f"{label} has an unstable file/directory authority collision: {file_key}")
        stale.append(directory_key)
    for key in stale: del unique[key]
    return [unique[key] for key in sorted(unique,key=lambda value:(len(Path(value).parts),value))]


def capture_candidate_snapshot(config):
    """Capture all governed bytes once, plus exact private-tree modes/empty dirs."""
    governed=governed_product_files(config)
    if not governed or len(governed)>MAX_CANDIDATE_FILES:
        raise SystemExit("candidate snapshot file inventory is empty or exceeds its limit")
    files=[]; total=0
    for source in governed:
        data,mode=_descriptor_file_snapshot(source,"candidate file")
        total+=len(data)
        if total>MAX_CANDIDATE_TOTAL_BYTES: raise SystemExit("candidate snapshot exceeds its total byte limit")
        files.append((source.relative_to(ROOT),data,mode))
    files=normalized_snapshot_files(files)
    acceptance_files=[ROOT/relative for relative,_data,_mode in files if _acceptance_scope_path(ROOT/relative)]
    directories=[]
    for source in acceptance_candidate_directories(config,acceptance_files):
        mode=_descriptor_directory_snapshot(source,"candidate directory")
        directories.append((source.relative_to(ROOT),mode))
    directories=normalized_snapshot_directories(files,directories)
    return {"files":files,"directories":directories}


def acceptance_candidate_records(config,snapshot=None):
    snapshot=snapshot if snapshot is not None else capture_candidate_snapshot(config)
    records=[]
    for relative,data,mode in snapshot["files"]:
        if not _acceptance_scope_path(ROOT/relative): continue
        records.append({"path":relative.as_posix(),"sha256":hashlib.sha256(data).hexdigest(),
                        "bytes":len(data),"mode":mode})
    if not records: raise SystemExit("acceptance candidate scope contains no immutable product files")
    return records


def candidate_snapshot_matches(config,snapshot):
    try: current=capture_candidate_snapshot(config)
    except (OSError,SystemExit): return False
    if candidate_records(config,current)!=candidate_records(config,snapshot): return False
    expected_files=[item for item in snapshot["files"] if _acceptance_scope_path(ROOT/item[0])]
    current_files=[item for item in current["files"] if _acceptance_scope_path(ROOT/item[0])]
    return current_files==expected_files and current["directories"]==snapshot["directories"]


@contextlib.contextmanager
def disposable_candidate(config,snapshot=None):
    """Materialize the same descriptor-bound bytes used for the candidate digest."""
    snapshot=snapshot if snapshot is not None else capture_candidate_snapshot(config)
    files=normalized_snapshot_files(
        [item for item in snapshot["files"] if _acceptance_scope_path(ROOT/item[0])],"candidate materialization",True)
    directories=normalized_snapshot_directories(files,snapshot["directories"],"candidate materialization",True)
    with tempfile.TemporaryDirectory(prefix="agent-test-candidate-") as raw:
        workspace=Path(raw)/"candidate"; workspace.mkdir(mode=0o700); workspace=workspace.resolve()
        for relative,_mode in directories:
            if relative.parts: (workspace/relative).mkdir(parents=True,exist_ok=True,mode=0o700)
        for relative,data,mode in files:
            target=workspace/relative; target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            descriptor=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),mode)
            try:
                offset=0
                while offset<len(data): offset+=os.write(descriptor,data[offset:])
                os.fsync(descriptor); os.fchmod(descriptor,mode)
            finally: os.close(descriptor)
        for relative,mode in sorted(directories,key=lambda item:len(item[0].parts),reverse=True):
            os.chmod(workspace/relative if relative.parts else workspace,mode,follow_symlinks=False)
        yield workspace


def candidate_copy_command(command,workspace):
    rewritten=[]; compatible=True
    for index,raw in enumerate(command):
        prefix=""; path_text=raw
        if index>0 and raw.startswith("@") and len(raw)>1: prefix="@"; path_text=raw[1:]
        elif index>0 and raw.startswith("-") and "=" in raw:
            option,path_text=raw.split("=",1); prefix=option+"="
        value=Path(path_text)
        if value.is_absolute():
            lexical=Path(os.path.abspath(str(value)))
            try: relative=lexical.relative_to(ROOT)
            except ValueError: rewritten.append(raw); continue
            try: resolved=lexical.resolve(strict=True); resolved.relative_to(ROOT)
            except (OSError,ValueError): compatible=False
            target=workspace/relative
            if not target.exists(): compatible=False
            rewritten.append(prefix+str(target)); continue
        if index>0 and (ROOT/value).exists():
            target=workspace/value
            if not target.exists(): compatible=False
            rewritten.append(prefix+str(value)); continue
        if index==0 and "/" in raw and (ROOT/value).exists():
            target=workspace/value
            if not target.exists(): compatible=False
            rewritten.append(str(target)); continue
        rewritten.append(raw)
    executable=Path(command[0]).name if command else ""
    dependency_names={"npm":"node_modules","npx":"node_modules","pnpm":"node_modules","yarn":"node_modules","bun":"node_modules",
                      "gradle":".gradle","gradlew":".gradle"}
    dependency=dependency_names.get(executable)
    if dependency and (ROOT/dependency).exists() and not (workspace/dependency).exists(): compatible=False
    return rewritten,compatible


def private_test_environment(runtime):
    runtime=Path(runtime)
    directories={
        "HOME":runtime/"home","TMPDIR":runtime/"tmp","TMP":runtime/"tmp","TEMP":runtime/"tmp",
        "XDG_CONFIG_HOME":runtime/"xdg-config","XDG_CACHE_HOME":runtime/"xdg-cache","XDG_DATA_HOME":runtime/"xdg-data",
        "PYTHONPYCACHEPREFIX":runtime/"python-cache","PIP_CACHE_DIR":runtime/"pip-cache",
        "NPM_CONFIG_CACHE":runtime/"npm-cache","YARN_CACHE_FOLDER":runtime/"yarn-cache",
    }
    for path in set(directories.values()): path.mkdir(parents=True,mode=0o700)
    environment={name:str(path) for name,path in directories.items()}
    environment.update({
        "PATH":os.defpath,"LANG":"C","LC_ALL":"C","TZ":"UTC","PYTHONNOUSERSITE":"1",
        "PYTHONDONTWRITEBYTECODE":"1","GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,
        "GIT_TERMINAL_PROMPT":"0","HISTFILE":os.devnull,"NODE_REPL_HISTORY":os.devnull,"NO_COLOR":"1",
    })
    return environment


def candidate_records(config,snapshot=None):
    snapshot=snapshot if snapshot is not None else capture_candidate_snapshot(config)
    records=[]
    for relative,raw,mode in snapshot["files"]:
        data=raw
        if relative.as_posix()==".agent/config.json":
            stable_config=strict_json_loads(data.decode("utf-8"))
            control=stable_config.get("agent_control")
            if not isinstance(control,dict) or "default_model" not in control:
                raise SystemExit("candidate config lacks transient model authority")
            control["default_model"]=None
            data=canonical(stable_config)
        if relative.as_posix()==".agent/state/TASK.json":
            task=strict_json_loads(data.decode("utf-8"))
            volatile={
                "status","phase","selected_model","completed_model","tokens_used","token_usage_source","usage_receipt",
                "usage_receipts","budget_state","child_agents_used","peak_child_agents",
                "loaded_references","next_action","current_node","accepted_nodes",
                "node_artifacts","gate_approvals","pending_gate_artifacts",
                "decision_packet","selected_templates","selected_capabilities",
                "template_route","rendered_artifacts","rollback_ledger",
                "rollback_archive","failure_ledger","failure_archive",
                "retrospective","knowledge_candidates","completion_binding",
                "metrics","updated","node_artifact_capture_version","node_artifact_capture_nodes",
            }
            data=canonical({key:value for key,value in task.items() if key not in volatile})
        records.append({"kind":"file","path":relative.as_posix(),"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data),"mode":mode})
    for relative,mode in snapshot["directories"]:
        records.append({"kind":"directory","path":relative.as_posix(),"mode":mode})
    if not records: raise SystemExit("candidate fingerprint has no governed files")
    return sorted(records,key=lambda item:(str(item["path"]),str(item["kind"])))


def candidate_fingerprint(config,snapshot=None):
    return hashlib.sha256(canonical(candidate_records(config,snapshot))).hexdigest()


def test_policy(config, task):
    mode = str(task.get("mode", ""))
    mode_policy = config.get("routing", {}).get("modes", {}).get(mode, {})
    testing = config.get("testing", {})
    minutes = mode_policy.get("wall_time_minutes")
    attempts = mode_policy.get("max_automatic_test_attempts")
    if (
        mode not in {"fast", "standard", "release"}
        or minutes != {"fast": 5, "standard": 15, "release": 45}[mode]
        or attempts != 1
        or testing.get("max_automatic_full_chain_attempts") != 1
        or testing.get("infrastructure_failure_consumes_code_retry") is not False
        or testing.get("attempt_classes") != ["candidate", "test", "infrastructure"]
    ):
        raise SystemExit("test budget policy is missing or weakened")
    raw_registry = str(testing.get("budget_registry", ""))
    raw_receipts = str(testing.get("budget_receipt_dir", ""))
    registry = (ROOT / raw_registry).resolve()
    receipt_dir = (ROOT / raw_receipts).resolve()
    for path in (registry, receipt_dir):
        try:
            path.relative_to(ROOT)
        except ValueError:
            raise SystemExit("test budget state escapes project")
    return mode, int(minutes) * 60, int(attempts), registry, receipt_dir


@contextlib.contextmanager
def budget_lock():
    try: lock_handle=boundedio.open_private_lock(LOCK_PATH,label="test budget lock")
    except RuntimeError as error: raise SystemExit(str(error)) from error
    with lock_handle as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def budget_state(path):
    if not path.is_file():
        return {"schema": "agent-test-budget/v1", "candidates": {}}
    value = load_json(path)
    if value.get("schema") != "agent-test-budget/v1" or not isinstance(value.get("candidates"), dict):
        raise SystemExit("test budget registry is invalid")
    return value


def publish_budget_receipt(receipt_dir, value):
    data = canonical(value) + b"\n"
    digest = hashlib.sha256(data).hexdigest()
    path = receipt_dir / f"{digest}.json"
    if path.exists() and boundedio.read_bytes(path,label="test runner file") != data:
        raise SystemExit("test budget receipt collision")
    if not path.exists():
        atomic_text(path, data.decode("utf-8"))
    return {"path": str(path.relative_to(ROOT)), "sha256": digest, "bytes": len(data)}


def receipt_record(path):
    data = boundedio.read_bytes(path,label="test runner file")
    return {
        "path": str(path.relative_to(ROOT)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def resolve_budget_receipt(receipt_dir, raw, label):
    path = (ROOT / raw).resolve()
    try:
        path.relative_to(receipt_dir.resolve())
    except ValueError:
        raise SystemExit(f"{label} escapes the test-budget evidence directory")
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"{label} is missing or is a symlink")
    record = receipt_record(path)
    if path.name != f"{record['sha256']}.json":
        raise SystemExit(f"{label} is not stored at its content-addressed path")
    return path, record


def validate_candidate_state(candidate, mode, cap, maximum_attempts):
    if (
        candidate.get("mode") != mode
        or candidate.get("budget_seconds") != cap
        or candidate.get("max_automatic_test_attempts") != maximum_attempts
        or not isinstance(candidate.get("infrastructure_failures"), int)
        or int(candidate.get("infrastructure_failures", 0)) < 0
        or not isinstance(candidate.get("attempts"), dict)
        or not isinstance(candidate.get("active_reservations"), list)
        or not isinstance(candidate.get("infrastructure_remediations", []), list)
        or candidate.get("remediation_allowance") is not None
        and not isinstance(candidate.get("remediation_allowance"), dict)
    ):
        raise SystemExit("candidate test budget policy drifted")


def remediation_request(candidate_sha256, candidate, next_run_id, next_case):
    failure_receipt = candidate.get("latest_receipt")
    if (
        int(candidate.get("infrastructure_failures", 0)) <= 0
        or not isinstance(failure_receipt, dict)
        or set(failure_receipt) != {"path", "sha256", "bytes"}
    ):
        raise SystemExit("candidate has no unresolved runner-observed infrastructure failure")
    return {
        "schema": REMEDIATION_SCHEMA,
        "candidate_sha256": candidate_sha256,
        "failure_receipt": failure_receipt,
        "unresolved_infrastructure_failures": int(candidate["infrastructure_failures"]),
        "next_launch": {"run_id": next_run_id, "case": next_case},
        "authorization_scope": "single-test-launch",
        "code_retry_consumed": False,
    }


def validate_remediation_request(value, candidate_sha256, candidate):
    expected_keys = {
        "schema", "candidate_sha256", "failure_receipt",
        "unresolved_infrastructure_failures", "next_launch",
        "authorization_scope", "code_retry_consumed",
    }
    next_launch = value.get("next_launch") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("schema") != REMEDIATION_SCHEMA
        or value.get("candidate_sha256") != candidate_sha256
        or value.get("failure_receipt") != candidate.get("latest_receipt")
        or value.get("unresolved_infrastructure_failures") != candidate.get("infrastructure_failures")
        or value.get("authorization_scope") != "single-test-launch"
        or value.get("code_retry_consumed") is not False
        or not isinstance(next_launch, dict)
        or set(next_launch) != {"run_id", "case"}
        or RUN_ID.fullmatch(str(next_launch.get("run_id", ""))) is None
        or CASE_ID.fullmatch(str(next_launch.get("case", ""))) is None
        or next_launch.get("run_id") in candidate.get("attempts", {})
        or int(candidate.get("infrastructure_failures", 0)) <= 0
        or candidate.get("remediation_allowance") is not None
        or candidate.get("active_reservations")
    ):
        raise SystemExit("infrastructure remediation request is stale or invalid")
    return next_launch


def prepare_infrastructure_remediation(config, task, candidate_sha256, next_run_id, next_case):
    mode, cap, maximum_attempts, registry_path, receipt_dir = test_policy(config, task)
    with budget_lock():
        state = budget_state(registry_path)
        candidate = state.get("candidates", {}).get(candidate_sha256)
        if not isinstance(candidate, dict):
            raise SystemExit("candidate has no test budget state")
        validate_candidate_state(candidate, mode, cap, maximum_attempts)
        reconcile_reservations(candidate)
        request = remediation_request(candidate_sha256, candidate, next_run_id, next_case)
        # Reconciliation is committed here so a dead runner cannot be hidden by
        # repeatedly preparing an authorization request.
        atomic(registry_path, state)
    record = publish_budget_receipt(receipt_dir, request)
    print(
        "INFRASTRUCTURE REMEDIATION REQUEST "
        f"path={record['path']} sha256={record['sha256']} scope=single-test-launch"
    )
    return 0


def _load_remediation_state(config, task, candidate_sha256, request_raw):
    mode, cap, maximum_attempts, registry_path, receipt_dir = test_policy(config, task)
    request_path, request_record = resolve_budget_receipt(
        receipt_dir, request_raw, "infrastructure remediation request"
    )
    try:
        request = strict_json_loads(boundedio.read_text(request_path,label="test budget request"))
    except (OSError, ValueError) as error:
        raise SystemExit(f"infrastructure remediation request is invalid: {error}")
    with budget_lock():
        state = budget_state(registry_path)
        candidate = state.get("candidates", {}).get(candidate_sha256)
        if not isinstance(candidate, dict):
            raise SystemExit("candidate has no test budget state")
        validate_candidate_state(candidate, mode, cap, maximum_attempts)
        next_launch = validate_remediation_request(request, candidate_sha256, candidate)
    return registry_path, receipt_dir, request, request_record, next_launch


def apply_infrastructure_remediation(config, task, candidate_sha256, request_raw, source, human_receipt):
    if not isinstance(source, str) or not source.startswith("user:") or not source[5:].strip():
        raise SystemExit("infrastructure remediation source must identify an explicit user decision")
    registry_path, receipt_dir, request, request_record, next_launch = _load_remediation_state(
        config, task, candidate_sha256, request_raw
    )
    decision = humandecision.verify(
        ROOT, config, task, gate=REMEDIATION_GATE,
        artifact_sha256=request_record["sha256"], source=source,
        receipt=human_receipt, require_fresh=True,
    )
    mode, cap, maximum_attempts, _, _ = test_policy(config, task)
    with budget_lock():
        state = budget_state(registry_path)
        candidate = state.get("candidates", {}).get(candidate_sha256)
        if not isinstance(candidate, dict):
            raise SystemExit("candidate has no test budget state")
        validate_candidate_state(candidate, mode, cap, maximum_attempts)
        validate_remediation_request(request, candidate_sha256, candidate)
        applied_at = now()
        remediation = {
            "request": request_record,
            "failure_receipt": request["failure_receipt"],
            "decision_receipt": decision,
            "next_launch": next_launch,
            "applied_at": applied_at,
        }
        candidate.setdefault("infrastructure_remediations", []).append(remediation)
        candidate["infrastructure_failures"] = 0
        candidate["remediation_allowance"] = {
            "request_sha256": request_record["sha256"],
            "run_id": next_launch["run_id"], "case": next_launch["case"],
            "applied_at": applied_at,
        }
        active = sum(
            int(item.get("reserved_seconds", 0))
            for item in candidate.get("active_reservations", []) if isinstance(item, dict)
        )
        event = {
            "schema": "agent-test-budget-receipt/v1", "event": "infrastructure_remediated",
            "candidate_sha256": candidate_sha256, "mode": mode,
            "budget_seconds": cap, "consumed_seconds": candidate.get("consumed_seconds", 0),
            "reserved_seconds": active,
            "remaining_seconds": max(0, cap - int(candidate.get("consumed_seconds", 0)) - active),
            "max_automatic_test_attempts": maximum_attempts,
            "attempt_class": "infrastructure", "failure_receipt": request["failure_receipt"],
            "remediation_request": request_record, "decision_receipt": decision,
            "next_launch": next_launch, "observed_at": applied_at,
        }
        candidate["latest_receipt"] = publish_budget_receipt(receipt_dir, event)
        atomic(registry_path, state)
    print(
        "INFRASTRUCTURE REMEDIATION APPLIED "
        f"candidate={candidate_sha256} run_id={next_launch['run_id']} case={next_launch['case']}"
    )
    return 0


def process_start_identity(pid):
    try: pid=int(pid)
    except (ValueError,TypeError): return None
    try:
        snapshot=linux_process_snapshot() if sys.platform.startswith("linux") else (darwin_process_snapshot() if sys.platform=="darwin" else {})
    except ProcessObservationError: return None
    record=snapshot.get(pid)
    return record.get("start_identity") if isinstance(record,dict) else None


def reconcile_reservations(candidate):
    consumed = int(candidate.get("consumed_seconds", 0))
    retained = []
    for reservation in candidate.get("active_reservations", []):
        if (isinstance(reservation,dict) and isinstance(reservation.get("start_identity"),str)
                and process_start_identity(reservation.get("pid"))==reservation.get("start_identity")):
            retained.append(reservation)
        elif isinstance(reservation, dict):
            # A crashed runner cannot make its elapsed time trustworthy. Charge
            # the complete reservation so a crash cannot reopen the budget.
            consumed += int(reservation.get("reserved_seconds", 0))
    candidate["consumed_seconds"] = consumed
    candidate["active_reservations"] = retained


def reserve_budget(config, task, args, receipt_path, run_id, candidate_sha256, snapshot=None):
    mode, cap, maximum_attempts, registry_path, receipt_dir = test_policy(config, task)
    with budget_lock():
        if snapshot is not None and not candidate_snapshot_matches(config,snapshot):
            raise SystemExit("candidate changed before the test budget reservation")
        state = budget_state(registry_path)
        candidates = state["candidates"]
        candidate = candidates.setdefault(candidate_sha256, {
            "mode": mode,
            "budget_seconds": cap,
            "max_automatic_test_attempts": maximum_attempts,
            "consumed_seconds": 0,
            "infrastructure_failures": 0,
            "attempts": {},
            "active_reservations": [],
            "infrastructure_remediations": [],
            "remediation_allowance": None,
            "latest_receipt": None,
        })
        validate_candidate_state(candidate, mode, cap, maximum_attempts)
        reconcile_reservations(candidate)
        if int(candidate.get("infrastructure_failures", 0)) > 0:
            raise SystemExit(
                "candidate has an unresolved infrastructure failure; prepare and apply a "
                "provider-approved single-launch remediation before another test launch"
            )
        allowance = candidate.get("remediation_allowance")
        if allowance is not None and (
            set(allowance) != {"request_sha256", "run_id", "case", "applied_at"}
            or HEX64.fullmatch(str(allowance.get("request_sha256", ""))) is None
            or allowance.get("run_id") != run_id
            or allowance.get("case") != args.case
        ):
            raise SystemExit("pending infrastructure remediation is bound to a different single test launch")
        track = "code"
        attempt = candidate["attempts"].get(run_id)
        receipt_relative = str(receipt_path.relative_to(ROOT))
        if attempt is None:
            prior = [item for item in candidate["attempts"].values() if isinstance(item, dict) and item.get("track") == track]
            if len(prior) >= maximum_attempts:
                raise SystemExit(f"automatic {track} test attempt budget exhausted for this candidate")
            attempt = {
                "track": track,
                "receipt_path": receipt_relative,
                "started_at": now(),
                "cases": [],
            }
            candidate["attempts"][run_id] = attempt
        elif (
            attempt.get("track") != track
            or attempt.get("receipt_path") != receipt_relative
        ):
            raise SystemExit("run_id is already bound to a different candidate test attempt")
        if attempt.get("failure_class") is not None:
            raise SystemExit(
                "failed candidate test attempt is sealed; diagnose the failure before using a new run_id"
            )
        if args.case in attempt.get("cases", []):
            raise SystemExit("test budget already recorded this case")
        reserved = sum(int(item.get("reserved_seconds", 0)) for item in candidate["active_reservations"] if isinstance(item, dict))
        remaining = cap - int(candidate["consumed_seconds"]) - reserved
        if args.timeout > cap or args.timeout > remaining:
            raise SystemExit(f"test timeout exceeds remaining {mode} candidate budget ({max(remaining, 0)}s)")
        reservation_id = uuid.uuid4().hex; start_identity=process_start_identity(os.getpid())
        if not isinstance(start_identity,str): raise SystemExit("stable test runner process identity is unavailable")
        reservation = {
            "id": reservation_id, "pid": os.getpid(), "start_identity":start_identity, "run_id": run_id,
            "case": args.case, "reserved_seconds": args.timeout, "started_at": now(),
        }
        if allowance is not None:
            reservation["remediation_request_sha256"] = allowance["request_sha256"]
            attempt["remediation_request_sha256"] = allowance["request_sha256"]
            candidate["remediation_allowance"] = None
        candidate["active_reservations"].append(reservation)
        event = {
            "schema": "agent-test-budget-receipt/v1", "event": "reserved",
            "candidate_sha256": candidate_sha256, "mode": mode,
            "budget_seconds": cap, "consumed_seconds": candidate["consumed_seconds"],
            "reserved_seconds": reserved + args.timeout, "remaining_seconds": remaining - args.timeout,
            "max_automatic_test_attempts": maximum_attempts, "run_id": run_id,
            "attempt_class": "code", "case": args.case,
            "reservation_id": reservation_id, "observed_at": now(),
        }
        if allowance is not None:
            event["remediation_request_sha256"] = allowance["request_sha256"]
        candidate["latest_receipt"] = publish_budget_receipt(receipt_dir, event)
        atomic(registry_path, state)
    return registry_path, receipt_dir, reservation_id


def finish_budget(registry_path, receipt_dir, reservation_id, candidate_sha256, run_id, args, elapsed, exit_code, outcome, failure_class):
    with budget_lock():
        state = budget_state(registry_path)
        candidate = state.get("candidates", {}).get(candidate_sha256)
        if not isinstance(candidate, dict):
            raise SystemExit("candidate test budget disappeared during execution")
        reservations = candidate.get("active_reservations", [])
        reservation = next((item for item in reservations if isinstance(item, dict) and item.get("id") == reservation_id), None)
        if (reservation is None or reservation.get("run_id") != run_id or reservation.get("case") != args.case
            or reservation.get("pid")!=os.getpid() or reservation.get("start_identity")!=process_start_identity(os.getpid())):
            raise SystemExit("test budget reservation changed during execution")
        charged = max(1, int(math.ceil(elapsed)))
        candidate["consumed_seconds"] = int(candidate.get("consumed_seconds", 0)) + charged
        candidate["active_reservations"] = [item for item in reservations if not isinstance(item, dict) or item.get("id") != reservation_id]
        attempt = candidate.get("attempts", {}).get(run_id)
        if not isinstance(attempt, dict):
            raise SystemExit("candidate test attempt disappeared during execution")
        attempt.setdefault("cases", []).append(args.case)
        attempt["finished_at"] = now()
        attempt["failure_class"] = failure_class
        if failure_class == "infrastructure":
            attempt["track"] = "infrastructure"
            candidate["infrastructure_failures"] = int(candidate.get("infrastructure_failures", 0)) + 1
        cap = int(candidate.get("budget_seconds", 0))
        active = sum(int(item.get("reserved_seconds", 0)) for item in candidate["active_reservations"] if isinstance(item, dict))
        event = {
            "schema": "agent-test-budget-receipt/v1", "event": "finished",
            "candidate_sha256": candidate_sha256, "mode": candidate.get("mode"),
            "budget_seconds": cap, "consumed_seconds": candidate["consumed_seconds"],
            "reserved_seconds": active, "remaining_seconds": max(0, cap - int(candidate["consumed_seconds"]) - active),
            "max_automatic_test_attempts": candidate.get("max_automatic_test_attempts"),
            "run_id": run_id, "attempt_class": attempt.get("track"), "case": args.case,
            "reservation_id": reservation_id, "charged_seconds": charged,
            "exit_code": exit_code, "outcome": outcome, "failure_class": failure_class,
            "observed_at": now(),
        }
        candidate["latest_receipt"] = publish_budget_receipt(receipt_dir, event)
        atomic(registry_path, state)


def _ps_result(arguments):
    executable="/bin/ps" if Path("/bin/ps").is_file() else shutil.which("ps",path=os.defpath)
    if not executable: return None
    try: returncode,output=bounded_trusted_command_output(
        [executable,*arguments],environment={"PATH":os.defpath,"LC_ALL":"C"},timeout=2,maximum=PROCESS_SNAPSHOT_BYTES)
    except ProcessObservationError: return None
    if returncode: return None
    return output.decode("utf-8",errors="replace")


def process_snapshot():
    """Lightweight ancestry snapshot; never expands process environments."""
    if sys.platform.startswith("linux"):
        try: observed=linux_process_snapshot()
        except ProcessObservationError: return None
        return {pid:(info["ppid"],info["pgid"],info["start_identity"],info["state"]) for pid,info in observed.items()} or None
    if sys.platform.startswith("darwin"):
        try: observed=darwin_process_snapshot()
        except ProcessObservationError: return None
        return {pid:(info["ppid"],info["pgid"],info["start_identity"],info["state"]) for pid,info in observed.items()} or None
    output=_ps_result(["-axo","pid=,ppid=,pgid=,lstart=,stat="])
    if output is None: return None
    snapshot={}
    for line in output.splitlines():
        parts=line.split()
        if len(parts)<9: continue
        try: pid,parent,group=int(parts[0]),int(parts[1]),int(parts[2])
        except ValueError: continue
        snapshot[pid]=(parent,group," ".join(parts[3:8]),parts[8])
    return snapshot or None


def merge_launch_identities(known,launch_token):
    """On Darwin, perform one bounded environment scan for surviving escapes."""
    if not sys.platform.startswith("darwin"): return True
    output=_ps_result(["eww","-axo","pid=,lstart=,stat=,command="])
    if output is None: return False
    marker=f"{LAUNCH_TOKEN_NAME}={launch_token}"
    snapshot=process_snapshot()
    if snapshot is None: return False
    for line in output.splitlines():
        parts=line.split()
        if len(parts)<7 or marker not in " ".join(parts[7:]): continue
        try: pid=int(parts[0])
        except ValueError: continue
        state=parts[6]
        if pid>1 and not state.startswith("Z") and pid in snapshot:
            known.setdefault(pid,snapshot[pid][2])
    return True


def discover_descendants(root_pid,known,snapshot):
    if snapshot is None: return False
    roots={root_pid}; roots.update(pid for pid,identity in known.items() if pid in snapshot and snapshot[pid][2]==identity)
    if sys.platform.startswith("linux"):
        for pid,(parent,_group,identity,state) in snapshot.items():
            if parent==os.getpid() and pid!=root_pid and not state.startswith("Z"):
                roots.add(pid); known.setdefault(pid,identity)
    changed=True
    while changed:
        changed=False
        for pid,(parent,_group,identity,state) in snapshot.items():
            if parent in roots and pid not in roots:
                roots.add(pid)
                if pid!=root_pid and not state.startswith("Z"): known.setdefault(pid,identity)
                changed=True
    return True


def live_known(known,snapshot):
    if snapshot is None: return None
    return {pid:identity for pid,identity in known.items()
            if pid in snapshot and snapshot[pid][2]==identity and not snapshot[pid][3].startswith("Z")}


def reap_known_children(known):
    """Reap only tracked children adopted by the Linux subreaper."""
    if not sys.platform.startswith("linux"): return
    for pid in sorted(known):
        try: os.waitpid(pid,os.WNOHANG)
        except (ChildProcessError,ProcessLookupError): pass


def signal_known(known,signum,snapshot):
    if snapshot is None: return False
    ok=True
    for pid in sorted(known,reverse=True):
        if pid<=1 or pid not in snapshot or snapshot[pid][2]!=known[pid]: continue
        try:
            if sys.platform.startswith("linux"): linux_signal_identity(pid,known[pid],signum)
            elif sys.platform.startswith("darwin"):
                immediate=process_snapshot()
                if immediate is None: ok=False; continue
                if pid not in immediate or immediate[pid][2]!=known[pid]: continue
                os.kill(pid,signum)
            else: os.kill(pid,signum)
        except ProcessLookupError: pass
        except (OSError,ProcessObservationError): ok=False
    return ok


def signal_launch_group(process,known,signum,snapshot):
    """Signal only identities observed twice in an unreaped launch session."""
    if process.returncode is not None or signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL: return False
    if snapshot is None: return False
    members={pid:identity for pid,(_parent,group,identity,state) in snapshot.items() if group==process.pid and not state.startswith("Z")}
    if any(pid in known and known[pid]!=identity for pid,identity in members.items()): return False
    if not members: return True
    try:
        if any(os.getsid(pid)!=process.pid for pid in members): return False
    except (ProcessLookupError,OSError,PermissionError): return False
    immediate=process_snapshot()
    if immediate is None: return False
    current={pid:identity for pid,(_parent,group,identity,state) in immediate.items() if group==process.pid and not state.startswith("Z")}
    if current!=members: return False
    try:
        if any(os.getsid(pid)!=process.pid for pid in current): return False
    except (ProcessLookupError,OSError,PermissionError): return False
    known.update(members)
    return signal_known(members,signum,immediate)


def terminate_process_tree(process,known,grace=1.0,launch_token=None):
    """Clean exact launch identities without authorizing from a reaped numeric PID."""
    leader_anchored=process.returncode is None and signal.getsignal(signal.SIGCHLD) is signal.SIG_DFL
    uncertain=process.returncode is None and not leader_anchored
    leader_reaped=not leader_anchored; root_pid=-1 if leader_reaped else process.pid
    snapshot=process_snapshot()
    if snapshot is None: uncertain=True
    else: discover_descendants(root_pid,known,snapshot)
    if not leader_reaped and not signal_launch_group(process,known,signal.SIGTERM,snapshot):
        uncertain=True
        try: process.terminate()
        except (ProcessLookupError,PermissionError,OSError): pass
    if not signal_known(known,signal.SIGTERM,snapshot): uncertain=True
    deadline=time.monotonic()+grace
    while time.monotonic()<deadline:
        snapshot=process_snapshot()
        if snapshot is None: uncertain=True; break
        discover_descendants(root_pid,known,snapshot)
        live=live_known(known,snapshot)
        group_live=(not leader_reaped and any(group==process.pid and not state.startswith("Z")
            for _pid,(_parent,group,_identity,state) in snapshot.items()))
        if not live and not group_live: break
        time.sleep(0.05)
    for _ in range(3):
        snapshot=process_snapshot()
        if snapshot is None: uncertain=True; break
        discover_descendants(root_pid,known,snapshot)
        if not signal_known(known,signal.SIGSTOP,snapshot): uncertain=True
    if not leader_reaped and not signal_launch_group(process,known,signal.SIGKILL,snapshot):
        uncertain=True
        try: process.kill()
        except (ProcessLookupError,PermissionError,OSError): pass
    snapshot=process_snapshot()
    if snapshot is None: uncertain=True
    elif not signal_known(known,signal.SIGKILL,snapshot): uncertain=True
    if not leader_reaped:
        try: process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            uncertain=True
            if not sys.platform.startswith("darwin"):
                try: process.kill(); process.wait(timeout=2)
                except (OSError,subprocess.TimeoutExpired): pass
    reap_known_children(known)
    if not merge_launch_identities(known,launch_token): uncertain=True
    elif sys.platform.startswith("darwin"):
        escaped_snapshot=process_snapshot()
        if escaped_snapshot is None: uncertain=True
        else:
            for signum in (signal.SIGTERM,signal.SIGSTOP,signal.SIGKILL):
                if not signal_known(known,signum,escaped_snapshot): uncertain=True
                escaped_snapshot=process_snapshot()
                if escaped_snapshot is None: uncertain=True; break
    final=process_snapshot()
    if final is None: return False,True
    discover_descendants(-1,known,final)
    remaining=live_known(known,final)
    return not remaining,uncertain


class BoundedOutput:
    def __init__(self,pipe,limit=MAX_TEST_OUTPUT_BYTES):
        if not isinstance(limit,int) or isinstance(limit,bool) or limit<1: raise ValueError("output limit must be positive")
        self.pipe=pipe; self.limit=limit; self.data=bytearray(); self.exceeded=False; self.error=False
        self.thread=threading.Thread(target=self._read,name="bounded-test-output",daemon=True)
    def _read(self):
        try:
            while True:
                chunk=self.pipe.read(65536)
                if not chunk: break
                remaining=self.limit-len(self.data)
                if remaining>0: self.data.extend(chunk[:remaining])
                if len(chunk)>remaining:
                    self.exceeded=True
                    try: self.pipe.close()
                    except OSError: pass
                    break
        except (OSError,ValueError):
            if not self.exceeded: self.error=True
    def start(self): self.thread.start()
    def finish(self,timeout=2):
        self.thread.join(timeout)
        if self.thread.is_alive():
            try: self.pipe.close()
            except OSError: pass
            self.thread.join(timeout)
        return not self.thread.is_alive() and not self.error


def supervise_bounded_process(process,timeout,launch_token,output_limit=MAX_TEST_OUTPUT_BYTES,grace=5.0,completion_predicate=None):
    """Bound output and prove launch-scoped cleanup before reaping the leader."""
    if not isinstance(timeout,(int,float)) or isinstance(timeout,bool) or timeout<=0:
        raise ValueError("process timeout must be positive")
    if not isinstance(grace,(int,float)) or isinstance(grace,bool) or grace<=0:
        raise ValueError("process cleanup grace must be positive")
    if process.stdout is None: raise RuntimeError("supervised process output pipe is unavailable")
    known={}; collector=None; cleanup_ok=False; uncertain=False; timed_out=False
    output_limited=False; residual=False; leader_exited=False; externally_completed=False; leader_identity=None
    exit_code=125; started=time.monotonic()
    try:
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            raise RuntimeError("bounded supervisor requires default SIGCHLD ownership")
        collector=BoundedOutput(process.stdout,output_limit); collector.start()
        deadline=started+float(timeout)
        snapshot=process_snapshot()
        if snapshot is None: uncertain=True
        else:
            discover_descendants(process.pid,known,snapshot)
            leader=snapshot.get(process.pid)
            if leader is not None:
                leader_identity=leader[2]; known[process.pid]=leader_identity
        while not uncertain:
            if collector.exceeded: output_limited=True; break
            if completion_predicate is not None and completion_predicate(): externally_completed=True; break
            snapshot=process_snapshot()
            if snapshot is None or not discover_descendants(process.pid,known,snapshot):
                uncertain=True; break
            leader=snapshot.get(process.pid)
            if leader is not None:
                if leader_identity is None:
                    leader_identity=leader[2]; known[process.pid]=leader_identity
                elif leader[2]!=leader_identity:
                    uncertain=True; break
            if leader is None or leader[3].startswith("Z"):
                leader_exited=True; break
            if time.monotonic()>=deadline:
                timed_out=True; break
            time.sleep(0.05)
        final=None
        if not merge_launch_identities(known,launch_token): uncertain=True
        for _attempt in range(2):
            final=process_snapshot()
            if final is None or not discover_descendants(process.pid,known,final):
                uncertain=True; break
            time.sleep(0.02)
        live_result=live_known(known,final)
        if live_result is None: uncertain=True; live={}
        else: live={pid:identity for pid,identity in live_result.items() if pid!=process.pid}
        residual=bool(live)
        needs_cleanup=timed_out or output_limited or residual or uncertain or externally_completed or not leader_exited
        if needs_cleanup:
            cleaned,cleanup_uncertain=terminate_process_tree(process,known,grace=float(grace),launch_token=launch_token)
            cleanup_ok=cleaned and not cleanup_uncertain and not uncertain
        else:
            try: exit_code=int(process.wait(timeout=2))
            except subprocess.TimeoutExpired:
                uncertain=True; cleanup_ok=False
                terminate_process_tree(process,known,grace=float(grace),launch_token=launch_token)
                cleanup_ok=False
            else: cleanup_ok=True
        if externally_completed and cleanup_ok and not output_limited and not residual and not uncertain: exit_code=0
        elif process.returncode is not None and not timed_out and not output_limited and not residual and not uncertain:
            exit_code=int(process.returncode)
        drain_ok=collector.finish(timeout=2)
        if not drain_ok:
            try: terminate_process_tree(process,known,grace=float(grace),launch_token=launch_token)
            except BaseException: pass
            cleanup_ok=False; uncertain=True
        output=bytes(collector.data); output_limited=output_limited or collector.exceeded
        if output_limited or residual or uncertain or not cleanup_ok: exit_code=125
        elif timed_out: exit_code=124
        return {
            "exit_code":exit_code,"output":output,"cleanup_ok":cleanup_ok,
            "timed_out":timed_out,"output_limit_exceeded":output_limited,
            "residual_descendants":residual,"uncertain":uncertain,"externally_completed":externally_completed,
            "duration_seconds":round(time.monotonic()-started,3),
        }
    except BaseException as error:
        emergency_cleanup_ok=False
        try:
            cleaned,cleanup_uncertain=terminate_process_tree(process,known,grace=float(grace),launch_token=launch_token)
            emergency_cleanup_ok=cleaned and not cleanup_uncertain
        except BaseException:
            try:
                if process.returncode is None: process.kill()
                process.wait(timeout=2)
            except (OSError,subprocess.TimeoutExpired): pass
        if collector is not None:
            try: emergency_cleanup_ok=collector.finish(timeout=2) and emergency_cleanup_ok
            except BaseException: emergency_cleanup_ok=False
        try: setattr(error,"bounded_cleanup_ok",emergency_cleanup_ok)
        except BaseException: pass
        raise
    finally:
        if process.stdout is not None and not process.stdout.closed:
            try: process.stdout.close()
            except OSError: pass


def launch_supervised_process(command,cwd,environment):
    """Launch one supervised process; kept narrow for infrastructure fixtures."""
    return subprocess.Popen(
        command,cwd=str(cwd),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,start_new_session=True,env=environment,
        close_fds=True,bufsize=0,
    )


@contextlib.contextmanager
def child_subreaper():
    """Use Linux subreaping; macOS is tracked by the inherited launch token."""
    if not sys.platform.startswith("linux"):
        yield True
        return
    if not linux_pidfd_supported():
        yield False; return
    libc=ctypes.CDLL(None,use_errno=True); current=ctypes.c_int()
    get_child_subreaper=37; set_child_subreaper=36
    if libc.prctl(get_child_subreaper,ctypes.byref(current),0,0,0)!=0:
        yield False; return
    changed=current.value==0
    if changed and libc.prctl(set_child_subreaper,1,0,0,0)!=0:
        yield False; return
    try: yield True
    finally:
        if changed: libc.prctl(set_child_subreaper,0,0,0,0)


class Interrupted(Exception):
    def __init__(self,signum):
        self.signum=signum


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt")
    parser.add_argument("--case")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--run-id")
    parser.add_argument("--candidate-sha256")
    remediation = parser.add_mutually_exclusive_group()
    remediation.add_argument("--prepare-infrastructure-remediation", action="store_true")
    remediation.add_argument("--apply-infrastructure-remediation", action="store_true")
    parser.add_argument("--remediation-request")
    parser.add_argument("--next-run-id")
    parser.add_argument("--next-case")
    parser.add_argument("--human-decision-source")
    parser.add_argument("--human-decision-receipt")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if args.run_id is not None and RUN_ID.fullmatch(args.run_id) is None:
        raise SystemExit("run_id must be 32 lowercase hexadecimal characters")
    if args.candidate_sha256 is not None and HEX64.fullmatch(args.candidate_sha256) is None:
        raise SystemExit("candidate fingerprint must be lowercase SHA-256")
    config = load_json(CONFIG_PATH)
    task = load_json(TASK_PATH)
    exact_snapshot=capture_candidate_snapshot(config)
    candidate_sha256=candidate_fingerprint(config,exact_snapshot)
    if args.candidate_sha256 is not None and args.candidate_sha256 != candidate_sha256:
        raise SystemExit("declared candidate fingerprint differs from governed project bytes")
    if args.prepare_infrastructure_remediation:
        if command or args.receipt or args.remediation_request or args.human_decision_source or args.human_decision_receipt:
            raise SystemExit("prepare remediation does not accept a test command, receipt or decision")
        if RUN_ID.fullmatch(str(args.next_run_id or "")) is None or CASE_ID.fullmatch(str(args.next_case or "")) is None:
            raise SystemExit("prepare remediation requires a valid --next-run-id and --next-case")
        return prepare_infrastructure_remediation(
            config, task, candidate_sha256, args.next_run_id, args.next_case
        )
    if args.apply_infrastructure_remediation:
        if command or args.receipt or args.next_run_id or args.next_case:
            raise SystemExit("apply remediation accepts only its request and provider decision")
        if not args.remediation_request or not args.human_decision_source or not args.human_decision_receipt:
            raise SystemExit(
                "apply remediation requires --remediation-request, --human-decision-source "
                "and --human-decision-receipt"
            )
        return apply_infrastructure_remediation(
            config, task, candidate_sha256, args.remediation_request,
            args.human_decision_source, args.human_decision_receipt,
        )
    if any((args.remediation_request, args.next_run_id, args.next_case,
            args.human_decision_source, args.human_decision_receipt)):
        raise SystemExit("remediation-only arguments require a remediation action")
    if not args.receipt or not command:
        raise SystemExit("test --receipt and command are required")
    if args.timeout <= 0:
        raise SystemExit("test timeout must be positive")
    if CASE_ID.fullmatch(str(args.case or "")) is None:
        raise SystemExit("test case id is invalid")
    path = (ROOT / args.receipt).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError:
        raise SystemExit("receipt escapes project")
    runner = Path(__file__).resolve()
    runner_data = boundedio.read_bytes(runner,label="protected runner")
    runner_receipt = {
        "path": str(runner.relative_to(ROOT)),
        "sha256": hashlib.sha256(runner_data).hexdigest(),
        "bytes": len(runner_data),
    }
    value = strict_json_loads(boundedio.read_text(path,label="test runner JSON")) if path.is_file() else {
        "schema": "agent-test-receipt/v3", "run_id": args.run_id or uuid.uuid4().hex,
        "candidate_sha256": candidate_sha256, "runner": runner_receipt, "cases": [],
    }
    if (
        set(value) != {"schema", "run_id", "candidate_sha256", "runner", "cases"}
        or value.get("schema") != "agent-test-receipt/v3"
        or value.get("candidate_sha256") != candidate_sha256
        or value.get("runner") != runner_receipt
        or not isinstance(value.get("cases"), list)
        or (args.run_id is not None and value.get("run_id") != args.run_id)
        or any(item.get("id") == args.case for item in value.get("cases", []) if isinstance(item, dict))
    ):
        raise SystemExit("invalid receipt, stale candidate, runner drift or duplicate case")

    run_id=str(value["run_id"])
    # Compatibility is proved before consuming a bounded attempt. Dependencies
    # absent from the exact private tree are never read from writable ROOT.
    with disposable_candidate(config,exact_snapshot) as compatibility_workspace:
        _probe_command,compatible=candidate_copy_command(command,compatibility_workspace)
    if not compatible:
        raise SystemExit("test command requires paths or dependencies absent from the private candidate")
    registry_path,budget_receipt_dir,reservation_id=reserve_budget(
        config,task,args,path,run_id,candidate_sha256,exact_snapshot
    )

    output_path = path.parent / (path.stem + "-" + args.case + ".log")

    started = now()
    started_monotonic = time.monotonic()
    previous = {}

    def interrupt(signum, _frame):
        raise Interrupted(signum)

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, interrupt)
    output_bytes=b""; outcome="completed"; exit_code=1; cleanup_ok=False; output_limit=False
    execution_boundary=None
    try:
      with contextlib.ExitStack() as stack:
        workspace=stack.enter_context(disposable_candidate(config,exact_snapshot))
        runtime=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="agent-test-runtime-")))
        launch_command,compatible=candidate_copy_command(command,workspace)
        if not compatible:
            raise SystemExit("test command private-candidate compatibility changed after reservation")
        cwd=workspace
        launch_token=uuid.uuid4().hex
        launch_environment=private_test_environment(runtime)
        launch_environment[LAUNCH_TOKEN_NAME]=launch_token
        subreaper_ok=stack.enter_context(child_subreaper())
        execution_boundary=dict(TEST_EXECUTION_BOUNDARY)
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            finish_budget(registry_path,budget_receipt_dir,reservation_id,candidate_sha256,
                run_id,args,time.monotonic()-started_monotonic,126,"launch_failed","infrastructure")
            raise SystemExit("test command requires default SIGCHLD ownership for unreaped PID binding")
        try:
            process=launch_supervised_process(launch_command,cwd,launch_environment)
        except OSError as error:
            finish_budget(registry_path,budget_receipt_dir,reservation_id,candidate_sha256,
                run_id,args,time.monotonic()-started_monotonic,126,"launch_failed","infrastructure")
            raise SystemExit(f"test command could not start: {error}")
        collector=BoundedOutput(process.stdout); collector.start(); known={}; uncertain=not subreaper_ok
        deadline=time.monotonic()+args.timeout; leader_identity=None; leader_exited=False
        try:
            while outcome=="completed":
                snapshot=process_snapshot()
                if snapshot is None: uncertain=True
                else:
                    leader=snapshot.get(process.pid)
                    if leader is not None:
                        if leader_identity is None: leader_identity=leader[2]; known[process.pid]=leader_identity
                        elif leader[2]!=leader_identity:
                            uncertain=True; outcome="identity_changed"; exit_code=125; break
                    if not discover_descendants(process.pid,known,snapshot): uncertain=True
                    # Darwin libproc may omit an exited child before wait(); the
                    # default SIGCHLD disposition keeps its PID unreusable.
                    leader_exited=leader is None or leader[3].startswith("Z")
                    if leader_exited: break
                if collector.exceeded:
                    outcome="output_limit_exceeded"; exit_code=125; output_limit=True; break
                if time.monotonic()>=deadline:
                    outcome="timed_out"; exit_code=124; break
                time.sleep(0.05)
        except Interrupted as error:
            outcome="interrupted"; exit_code=128+error.signum
        final=process_snapshot()
        if final is None: uncertain=True
        else: discover_descendants(process.pid,known,final)
        if not merge_launch_identities(known,launch_token): uncertain=True
        final=process_snapshot()
        if final is None: uncertain=True; live={}
        else:
            discover_descendants(process.pid,known,final)
            live={pid:identity for pid,identity in (live_known(known,final) or {}).items() if pid!=process.pid}
        needs_cleanup=not leader_exited or bool(live) or outcome!="completed" or collector.exceeded
        if needs_cleanup:
            cleaned,cleanup_uncertain=terminate_process_tree(process,known,launch_token=launch_token)
            cleanup_ok=cleaned and not cleanup_uncertain and not uncertain
            if outcome=="completed" and process.returncode is not None: exit_code=int(process.returncode)
        else:
            try: exit_code=int(process.wait(timeout=2))
            except subprocess.TimeoutExpired:
                outcome="lifecycle_unavailable"; exit_code=125; cleanup_ok=False; uncertain=True
            else: cleanup_ok=not uncertain
        drain_ok=collector.finish()
        cleanup_ok=cleanup_ok and drain_ok
        output_bytes=bytes(collector.data)
        if live and outcome=="completed":
            outcome="residual_descendant"; exit_code=125; cleanup_ok=False
        if collector.exceeded:
            outcome="output_limit_exceeded"; exit_code=125; cleanup_ok=False
        with budget_lock():
            unchanged=candidate_snapshot_matches(config,exact_snapshot)
        if not unchanged:
            outcome="candidate_mutated"; exit_code=125; cleanup_ok=False
    finally:
        for signum, handler in previous.items(): signal.signal(signum, handler)

    atomic_bytes(output_path,output_bytes)
    output_receipt={"path":str(output_path.relative_to(ROOT)),"sha256":hashlib.sha256(output_bytes).hexdigest(),
                    "bytes":len(output_bytes),"limit_bytes":MAX_TEST_OUTPUT_BYTES,"limit_exceeded":output_limit}
    cleanup_value="passed" if cleanup_ok else "failed"
    failure_class="infrastructure" if not cleanup_ok or output_limit else ("candidate" if exit_code!=0 or outcome!="completed" else None)
    case={
        "id":args.case,"run_id":value["run_id"],"candidate_sha256":candidate_sha256,"command":command,
        "started_at":started,"finished_at":now(),"exit_code":exit_code,"outcome":outcome,"cleanup":cleanup_value,
        "execution_boundary":execution_boundary,"output":output_receipt,
    }
    case["case_sha256"]=hashlib.sha256(strict_json_dumps(case,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    value["cases"].append(case); atomic(path,value)
    finish_budget(registry_path,budget_receipt_dir,reservation_id,candidate_sha256,run_id,args,
                  time.monotonic()-started_monotonic,exit_code,outcome,failure_class)
    console=output_bytes[-MAX_CONSOLE_OUTPUT_BYTES:].decode("utf-8",errors="replace")
    if len(output_bytes)>MAX_CONSOLE_OUTPUT_BYTES: print("[bounded output tail]",flush=True)
    print(console,end="")
    print(f"TEST RECEIPT: {args.case} exit={exit_code} cleanup={cleanup_value}")
    if not cleanup_ok: return 125
    return exit_code


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
