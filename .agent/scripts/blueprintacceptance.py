#!/usr/bin/env python3
"""Plan, run, and verify a confirmed blueprint acceptance contract."""
from pathlib import Path
import argparse
import contextlib
import ctypes
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

import skillctl
import testrun as supervised_test
from process_observation import (
    ProcessObservationError, bounded_trusted_command_output, darwin_process_snapshot,
    linux_pidfd_supported, linux_process_snapshot, linux_signal_identity,
)

from adaptive_common import (
    AdaptiveError, acceptance_method, canonical_sha256, fail, load_blueprint,
    load_json, mutation_lock, record_provider_human_decision, resolve_root, safe_relative_path, utc_now,
    verify_provider_human_decision, write_json,
)

PREFLIGHT_SCHEMA = "agent-blueprint-acceptance-preflight/v4"
RECEIPT_SCHEMA = "agent-blueprint-acceptance/v4"
INTEGRATOR_SCHEMA = "agent-blueprint-integrator-evidence/v1"
HEX = set("0123456789abcdef")
LAUNCH_TOKEN_NAME = "AGENT_ACCEPTANCE_LAUNCH_ID"
PROCESS_SNAPSHOT_BYTES = 4 * 1024 * 1024
EXECUTION_BOUNDARY = {
    "schema": "agent-acceptance-execution-boundary/v1",
    "mode": "private-candidate-materialization",
    "filesystem_confinement": False,
    "network_confinement": False,
    "process_cleanup": "bounded observable ancestry/process-group/token cleanup; Linux uses subreaping and Darwin fails closed on persistent same-user kernel-identity baseline deltas",
    "authority": "confirmed-blueprint-command-under-invoking-os-account",
    "hostile_command_containment": False,
    "receipt_assurance": "reviewed exact-candidate execution and fail-closed bounded observable cleanup only",
    "claim_limit": "private reviewed-byte capture and bounded same-UID observation do not prove hostile-command containment, delegated-work absence, cgroup/container, OS filesystem, or network confinement",
}


def digest_ok(value):
    return isinstance(value, str) and len(value) == 64 and not (set(value) - HEX)


def parse_time(value, label):
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise AdaptiveError("INVALID_ACCEPTANCE_TIME", f"{label} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise AdaptiveError("INVALID_ACCEPTANCE_TIME", f"{label} timestamp lacks timezone")
    return parsed


def regular_snapshot(root,value,label,maximum=2*1024*1024):
    supplied = Path(value)
    unresolved = root / supplied if not supplied.is_absolute() else supplied
    try:
        observed = os.lstat(unresolved)
    except OSError as error:
        raise AdaptiveError("UNSAFE_ACCEPTANCE_PATH", f"{label} is unavailable") from error
    if stat.S_ISLNK(observed.st_mode):
        raise AdaptiveError("UNSAFE_ACCEPTANCE_PATH", f"{label} must not be a symlink")
    path = unresolved.resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise AdaptiveError("UNSAFE_ACCEPTANCE_PATH", f"{label} escapes the project") from error
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1 or observed.st_size > maximum:
        raise AdaptiveError("UNSAFE_ACCEPTANCE_PATH", f"{label} is not one bounded single-link regular file")
    flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino) or opened.st_nlink != 1:
            raise AdaptiveError("UNSAFE_ACCEPTANCE_PATH", f"{label} changed while opening")
        raw = b""
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(descriptor)
    if len(raw) > maximum:
        raise AdaptiveError("UNSAFE_ACCEPTANCE_PATH", f"{label} exceeds its byte limit")
    return path,str(relative),raw,stat.S_IMODE(opened.st_mode)


def regular_bytes(root,value,label,maximum=2*1024*1024):
    path,relative,raw,_=regular_snapshot(root,value,label,maximum)
    return path,relative,raw


def json_bytes(root, value, label, maximum=2 * 1024 * 1024):
    path, relative, raw = regular_bytes(root, value, label, maximum)
    try:
        parsed = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AdaptiveError("INVALID_ACCEPTANCE_JSON", f"{label} is not valid JSON") from error
    return path, relative, raw, parsed


def output_path(root, value):
    return root / safe_relative_path(value)


def candidate_manifest_path(root, supplied, claimed_sha256=None):
    task_path = root / ".agent/state/TASK.json"
    task = load_json(task_path, "workflow task") if task_path.is_file() else {}
    record = task.get("node_artifacts", {}).get("6", {}) if isinstance(task, dict) else {}
    authoritative = isinstance(record, dict) and isinstance(record.get("path"), str) and digest_ok(record.get("sha256"))
    if authoritative:
        if supplied is not None and safe_relative_path(supplied).as_posix() != safe_relative_path(record["path"]).as_posix():
            raise AdaptiveError("ACCEPTANCE_CANDIDATE_DRIFT", "candidate manifest differs from the accepted Node-6 artifact")
        if claimed_sha256 is not None and record["sha256"] != claimed_sha256:
            raise AdaptiveError("ACCEPTANCE_CANDIDATE_DRIFT", "candidate digest differs from the accepted Node-6 artifact")
        return record["path"]
    if supplied:
        return supplied
    raise AdaptiveError("CANDIDATE_MANIFEST_REQUIRED", "acceptance requires the actual Node-6 candidate manifest path")


def candidate_snapshot(root, supplied, claimed_sha256=None):
    path_value=candidate_manifest_path(root,supplied,claimed_sha256)
    _,manifest_relative,raw,value=json_bytes(root,path_value,"candidate manifest",maximum=4*1024*1024)
    digest=hashlib.sha256(raw).hexdigest()
    task_path=root/".agent/state/TASK.json"
    task=load_json(task_path,"workflow task") if task_path.is_file() else {}
    node6=task.get("node_artifacts",{}).get("6",{}) if isinstance(task,dict) else {}
    if (isinstance(node6,dict) and isinstance(node6.get("path"),str) and digest_ok(node6.get("sha256"))
            and safe_relative_path(node6["path"]).as_posix()==manifest_relative and node6["sha256"]!=digest):
        raise AdaptiveError("ACCEPTANCE_CANDIDATE_DRIFT","candidate bytes differ from the accepted Node-6 artifact digest")
    if claimed_sha256 is not None and claimed_sha256!=digest:
        raise AdaptiveError("ACCEPTANCE_CANDIDATE_DRIFT","caller candidate digest does not match actual manifest bytes")
    changes=value.get("changes") if isinstance(value,dict) else None
    snapshot=value.get("candidate_snapshot") if isinstance(value,dict) else None
    if not isinstance(changes,list) or not changes or len(changes)>1024:
        raise AdaptiveError("INVALID_CANDIDATE_MANIFEST","candidate manifest needs a bounded non-empty changes inventory")
    if not isinstance(snapshot,list) or not snapshot or len(snapshot)>8192:
        raise AdaptiveError("INVALID_CANDIDATE_MANIFEST","candidate manifest needs a bounded exact candidate_snapshot inventory")
    change_map={}; previous=None
    for index,record in enumerate(changes):
        if not isinstance(record,dict) or set(record)!={"path","sha256","bytes"}:
            raise AdaptiveError("INVALID_CANDIDATE_MANIFEST",f"candidate changes[{index}] fields are invalid")
        path=safe_relative_path(record["path"]).as_posix()
        if (path in change_map or not digest_ok(record["sha256"]) or type(record["bytes"]) is not int or record["bytes"]<0):
            raise AdaptiveError("INVALID_CANDIDATE_MANIFEST",f"candidate changes[{index}] identity is invalid")
        change_map[path]=record
    previous_inventory_root=supervised_test.ROOT
    try:
        supervised_test.ROOT=root.resolve()
        config=load_json(root/".agent/config.json","workflow configuration")
        exact_snapshot=supervised_test.capture_candidate_snapshot(config)
        governed=supervised_test.acceptance_candidate_records(config,exact_snapshot)
    except (OSError,ValueError,SystemExit) as error:
        raise AdaptiveError("INVALID_CANDIDATE_SCOPE",str(error))
    finally:
        supervised_test.ROOT=previous_inventory_root
    governed_paths={record["path"] for record in governed}
    captured_map={relative.as_posix():(content,mode) for relative,content,mode in exact_snapshot["files"]
                  if relative.as_posix() in governed_paths}
    records=[]; captured=[]; total=0
    for index,record in enumerate(snapshot):
        if not isinstance(record,dict) or set(record)!={"path","sha256","bytes","mode"}:
            raise AdaptiveError("INVALID_CANDIDATE_MANIFEST",f"candidate_snapshot[{index}] fields are invalid")
        path=safe_relative_path(record["path"]).as_posix()
        if (previous is not None and path<=previous) or not digest_ok(record["sha256"]) or type(record["bytes"]) is not int or record["bytes"]<0 or type(record["mode"]) is not int or not 0<=record["mode"]<=0o777 or record["mode"]&0o022 or not record["mode"]&0o400:
            raise AdaptiveError("INVALID_CANDIDATE_MANIFEST",f"candidate_snapshot[{index}] identity or ordering is invalid")
        previous=path
        observed=captured_map.get(path)
        if observed is None:
            raise AdaptiveError("INCOMPLETE_CANDIDATE_SNAPSHOT",f"candidate snapshot path is outside the governed inventory: {path}")
        content,observed_mode=observed; total+=len(content)
        if (total>1024*1024*1024 or observed_mode!=record["mode"] or len(content)!=record["bytes"]
                or hashlib.sha256(content).hexdigest()!=record["sha256"]):
            raise AdaptiveError("ACCEPTANCE_CANDIDATE_DRIFT",f"candidate snapshot file drifted: {path}")
        normalized={"path":path,"sha256":record["sha256"],"bytes":record["bytes"],"mode":record["mode"]}
        records.append(normalized); captured.append((path,content,record["mode"]))
    if records!=governed:
        raise AdaptiveError("INCOMPLETE_CANDIDATE_SNAPSHOT","candidate_snapshot must equal the independently governed product inventory")
    directory_records=[]; captured_directories=[]
    for directory_relative,mode in exact_snapshot["directories"]:
        path="." if not directory_relative.parts else directory_relative.as_posix()
        directory_records.append({"path":path,"mode":mode}); captured_directories.append((path,mode))
    snapshot_map={record["path"]:record for record in records}
    for path,record in change_map.items():
        bound=snapshot_map.get(path)
        if bound is None or {key:bound[key] for key in ("path","sha256","bytes")}!=record:
            raise AdaptiveError("INVALID_CANDIDATE_MANIFEST",f"changed path is absent or differs in candidate_snapshot: {path}")
    tree={"schema":"agent-acceptance-candidate-tree/v1","files":records,"directories":directory_records}
    binding={"path":manifest_relative,"sha256":digest,"bytes":len(raw),"tree_sha256":canonical_sha256(tree),
             "file_count":len(records),"directory_count":len(directory_records),"scope_sha256":canonical_sha256(config.get("scope"))}
    return binding,{"files":captured,"directories":captured_directories}


def candidate_binding(root,supplied,claimed_sha256=None):
    return candidate_snapshot(root,supplied,claimed_sha256)[0]


@contextlib.contextmanager
def materialized_candidate(captured):
    with tempfile.TemporaryDirectory(prefix="agent-acceptance-candidate-") as raw:
        workspace=Path(raw)/"candidate"; workspace.mkdir(mode=0o700); workspace=workspace.resolve()
        raw_directories=[(Path(relative),mode) for relative,mode in captured["directories"] if relative!="."]
        normalized_directories=supervised_test.normalized_snapshot_directories(
            [(Path(relative),content,mode) for relative,content,mode in captured["files"]],raw_directories,
            "blueprint candidate materialization",True)
        for relative,_mode in normalized_directories:
            (workspace/relative).mkdir(parents=True,exist_ok=True,mode=0o700)
        normalized_files=supervised_test.normalized_snapshot_files(
            [(Path(relative),content,mode) for relative,content,mode in captured["files"]],"blueprint candidate materialization",True)
        for relative,content,mode in normalized_files:
            target=workspace/relative; target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            descriptor=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),mode)
            try:
                offset=0
                while offset<len(content): offset+=os.write(descriptor,content[offset:])
                os.fsync(descriptor); os.fchmod(descriptor,mode)
            finally: os.close(descriptor)
        for relative,mode in sorted(normalized_directories,key=lambda item:len(item[0].parts),reverse=True):
            os.chmod(workspace/relative,mode,follow_symlinks=False)
        root_mode=next(mode for relative,mode in captured["directories"] if relative==".")
        os.chmod(workspace,root_mode,follow_symlinks=False)
        yield workspace


def verify_materialized_candidate(workspace,captured):
    """Recheck every bound file byte/mode and directory mode in one disposable copy."""
    expected_files={path:(content,mode) for path,content,mode in captured["files"]}
    normalized_directories=supervised_test.normalized_snapshot_directories(
        [(Path(path),content,mode) for path,(content,mode) in expected_files.items()],
        [(Path(path),mode) for path,mode in captured["directories"] if path!="."],
        "blueprint candidate verification",True)
    expected_directories={path.as_posix():mode for path,mode in normalized_directories}
    expected_directories["."]=next(mode for path,mode in captured["directories"] if path==".")
    for relative,(content,mode) in expected_files.items():
        path=workspace/safe_relative_path(relative)
        try: observed=os.lstat(path)
        except OSError as error:
            raise AdaptiveError("ACCEPTANCE_CANDIDATE_MUTATED",f"bound input disappeared: {relative}") from error
        if (not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1 or
                stat.S_IMODE(observed.st_mode)!=mode):
            raise AdaptiveError("ACCEPTANCE_CANDIDATE_MUTATED",f"bound input path or mode changed: {relative}")
        descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); digest=hashlib.sha256(); size=0
        try:
            opened=os.fstat(descriptor)
            if (opened.st_dev,opened.st_ino)!=(observed.st_dev,observed.st_ino) or opened.st_nlink!=1:
                raise AdaptiveError("ACCEPTANCE_CANDIDATE_MUTATED",f"bound input changed while opening: {relative}")
            while True:
                chunk=os.read(descriptor,1024*1024)
                if not chunk: break
                size+=len(chunk); digest.update(chunk)
        finally: os.close(descriptor)
        if size!=len(content) or digest.hexdigest()!=hashlib.sha256(content).hexdigest():
            raise AdaptiveError("ACCEPTANCE_CANDIDATE_MUTATED",f"bound input bytes changed: {relative}")
    for relative,mode in expected_directories.items():
        path=workspace if relative=="." else workspace/safe_relative_path(relative)
        try: observed=os.lstat(path)
        except OSError as error:
            raise AdaptiveError("ACCEPTANCE_CANDIDATE_MUTATED",f"bound directory disappeared: {relative}") from error
        if not stat.S_ISDIR(observed.st_mode) or stat.S_IMODE(observed.st_mode)!=mode:
            raise AdaptiveError("ACCEPTANCE_CANDIDATE_MUTATED",f"bound directory path or mode changed: {relative}")


def require_candidate_unchanged(root, binding):
    current = candidate_binding(root, binding["path"], binding["sha256"])
    if current != binding:
        raise AdaptiveError("ACCEPTANCE_CANDIDATE_DRIFT", "candidate manifest or tree changed during acceptance", 3)
    return current


def write_authority_bound_json(root, path, value, binding, blueprint_sha256):
    """Linearize receipt emission with blueprint authority and candidate bytes."""
    with mutation_lock(root):
        require_candidate_unchanged(root, binding)
        current = load_blueprint(root, require_confirmed=True)
        if current["confirmation"]["design_sha256"] != blueprint_sha256:
            raise AdaptiveError("BLUEPRINT_DRIFT", "blueprint authority changed before receipt emission", 3)
        write_json(path, value)
        try:
            require_candidate_unchanged(root, binding)
            current = load_blueprint(root, require_confirmed=True)
            if current["confirmation"]["design_sha256"] != blueprint_sha256:
                raise AdaptiveError("BLUEPRINT_DRIFT", "blueprint authority changed during receipt emission", 3)
        except Exception:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            raise


def final_authority_check(root, binding, blueprint_sha256):
    with mutation_lock(root):
        require_candidate_unchanged(root, binding)
        current = load_blueprint(root, require_confirmed=True)
        if current["confirmation"]["design_sha256"] != blueprint_sha256:
            raise AdaptiveError("BLUEPRINT_DRIFT", "blueprint authority changed before acceptance success", 3)


def acceptance_contract(blueprint):
    records = blueprint["design"]["acceptance"]
    executable_ids = {item["id"] for item in records if acceptance_method(item) == "executable"}
    commands = [item for item in blueprint["design"]["commands"] if item["stage"] in {"acceptance", "ci"}]
    covered = {value for item in commands for value in item["covers"]}
    if covered != executable_ids:
        raise AdaptiveError("INCOMPLETE_ACCEPTANCE", "executable acceptance coverage differs from the confirmed contract")
    non_executable = [{"id": item["id"], "method": acceptance_method(item)} for item in records if acceptance_method(item) != "executable"]
    return commands, non_executable


def runner_binding(root, runner):
    path, relative, raw = regular_bytes(root, runner, "blueprint runner")
    if path != (root / ".agent/project/BLUEPRINT.json").resolve():
        raise AdaptiveError("INVALID_ACCEPTANCE_RUNNER", "runner must be the authoritative project blueprint")
    return relative, hashlib.sha256(raw).hexdigest()


def verified_skills_lock(root,blueprint):
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            if skillctl.command_verify(root,None)!=0: raise AdaptiveError("INVALID_ACCEPTANCE_SKILLS","dynamic Skill verification returned failure")
    except AdaptiveError:
        raise
    except Exception as error:
        raise AdaptiveError("INVALID_ACCEPTANCE_SKILLS","dynamic Skill lock, reviewed coverage, or active bytes failed verification") from error
    path = root / ".agent/project/skills.lock.json"
    if not path.exists():
        if blueprint["design"]["capabilities"]:
            raise AdaptiveError("INVALID_ACCEPTANCE_SKILLS", "confirmed capabilities require a Skill lock")
        return None
    lock = load_json(path, "Skills lock")
    digest = lock.get("lock_sha256") if isinstance(lock, dict) else None
    if not digest_ok(digest) or lock.get("blueprint_sha256") != blueprint["confirmation"]["design_sha256"]:
        raise AdaptiveError("INVALID_ACCEPTANCE_SKILLS", "Skill lock does not bind the confirmed blueprint")
    return digest


def command_records(commands):
    return [{"id": item["id"], "argv_sha256": canonical_sha256(item["argv"]),
             "covers": item["covers"], "environment": item.get("environment", [])} for item in commands]


UNSAFE_COMMAND_ENV={"PYTHONPATH","PYTHONHOME","NODE_OPTIONS","BASH_ENV","ENV","CDPATH","RUBYOPT","PERL5OPT","GIT_CONFIG","GIT_CONFIG_GLOBAL","GIT_CONFIG_SYSTEM"}
UNSAFE_COMMAND_ENV_PREFIXES=("LD_","DYLD_")


def command_environment(command):
    environment={"PATH":os.defpath,"HOME":"<private-runtime>","TMPDIR":"<private-runtime>","XDG_CONFIG_HOME":"<private-runtime>","XDG_CACHE_HOME":"<private-runtime>",
                 "PYTHONNOUSERSITE":"1","LANG":"C","LC_ALL":"C","TZ":"UTC"}
    for name in command.get("environment",[]):
        if name=="PATH": continue
        if name in UNSAFE_COMMAND_ENV or any(name.startswith(prefix) for prefix in UNSAFE_COMMAND_ENV_PREFIXES):
            raise AdaptiveError("UNSAFE_COMMAND_ENVIRONMENT",f"command {command['id']} requested unsafe process-control environment variable {name}")
        if name not in os.environ:
            raise AdaptiveError("COMMAND_ENVIRONMENT_MISSING",f"command {command['id']} requires unavailable environment variable {name}")
        value=os.environ[name]
        path_values=[value]
        if os.pathsep in value and not value.startswith(("http://","https://")): path_values=value.split(os.pathsep)
        if any(Path(item).is_absolute() or item.startswith("file://") for item in path_values if item):
            raise AdaptiveError("UNBOUND_ACCEPTANCE_INPUT",f"command {command['id']} environment {name} references bytes outside the candidate snapshot")
        environment[name]=value
    return environment


def command_environment_sha256(command):
    return canonical_sha256(command_environment(command))


def validate_command_inputs(root,command):
    """Reject argv filesystem inputs that can resolve outside the private snapshot."""
    boundary=root.resolve()
    for index,raw in enumerate(command["argv"][1:],start=1):
        candidates=[raw]
        if raw.startswith("@") and len(raw)>1: candidates=[raw[1:]]
        elif raw.startswith("-") and "=" in raw: candidates=[raw.split("=",1)[1]]
        for value in candidates:
            if not value or value=="-": continue
            if value.startswith("file://") or Path(value).is_absolute():
                raise AdaptiveError("UNBOUND_ACCEPTANCE_INPUT",f"command {command['id']} argv[{index}] references bytes outside the candidate snapshot")
            if "/" in value:
                unresolved=boundary/value; candidate=unresolved.resolve()
                try: candidate.relative_to(boundary)
                except ValueError as error:
                    raise AdaptiveError("UNBOUND_ACCEPTANCE_INPUT",f"command {command['id']} argv[{index}] escapes the candidate snapshot") from error
                if unresolved.is_symlink() or (candidate.exists() and not (candidate.is_file() or candidate.is_dir())):
                    raise AdaptiveError("UNBOUND_ACCEPTANCE_INPUT",f"command {command['id']} argv[{index}] is not captured candidate content")
    for name in command.get("environment",[]):
        if name=="PATH" or name not in os.environ: continue
        raw=os.environ[name]; values=[raw]
        if os.pathsep in raw and not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://",raw): values=raw.split(os.pathsep)
        for value in values:
            if not value or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://",value): continue
            if value.startswith("file://"):
                raise AdaptiveError("UNBOUND_ACCEPTANCE_INPUT",f"command {command['id']} environment {name} references bytes outside the candidate snapshot")
            without_urls=re.sub(r"(?:https?|mailto|data):[^\s,;]+","",value,flags=re.I)
            fragments={value,*re.split(r"[\s,;=:'\"]+",without_urls)}
            for fragment in fragments:
                fragment=fragment.strip().lstrip("@")
                if not fragment: continue
                if Path(fragment).is_absolute():
                    raise AdaptiveError("UNBOUND_ACCEPTANCE_INPUT",f"command {command['id']} environment {name} references bytes outside the candidate snapshot")
                if "/" in fragment or fragment in {".",".."}:
                    candidate=(boundary/fragment).resolve()
                    try: candidate.relative_to(boundary)
                    except ValueError as error:
                        raise AdaptiveError("UNBOUND_ACCEPTANCE_INPUT",f"command {command['id']} environment {name} escapes the candidate snapshot") from error


def resolve_executable(root,command):
    executable=command["argv"][0]; internal=False
    if "/" in executable:
        candidate=(root/executable).resolve() if not Path(executable).is_absolute() else Path(executable).resolve()
        try: candidate.relative_to(root); internal=True
        except ValueError as error:
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"command {command['id']} executable escapes the candidate") from error
    else:
        found=shutil.which(executable,path=os.defpath)
        if found is None:
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"command {command['id']} executable is unavailable in the sealed PATH")
        candidate=Path(found).resolve()
    def safe_metadata(path,is_internal):
        try: metadata=os.lstat(path)
        except OSError as error:
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"command {command['id']} executable is unavailable") from error
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink<1 or (is_internal and metadata.st_nlink!=1)
                or metadata.st_uid not in {0,os.geteuid()} or not metadata.st_mode&0o111 or metadata.st_mode&0o022):
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"command {command['id']} executable is unsafe")
        if not is_internal:
            current=Path(path.anchor)
            for component in path.parts[1:]:
                current=current/component; observed=os.lstat(current)
                if observed.st_uid not in {0,os.geteuid()} or observed.st_mode&0o022:
                    raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"command {command['id']} executable path is unsafe")
        return metadata
    def read_bound(path,is_internal):
        before=safe_metadata(path,is_internal); descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); digest=hashlib.sha256(); prefix=b""
        try:
            opened=os.fstat(descriptor)
            if ((opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino) or opened.st_nlink<1
                    or (is_internal and opened.st_nlink!=1)):
                raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"command {command['id']} executable changed while opening")
            while True:
                chunk=os.read(descriptor,1024*1024)
                if not chunk: break
                if len(prefix)<4096: prefix=(prefix+chunk)[:4096]
                digest.update(chunk)
        finally: os.close(descriptor)
        return digest.hexdigest(),prefix
    executable_digest,prefix=read_bound(candidate,internal)
    if prefix.startswith(b"#!"):
        line=prefix.splitlines()[0]
        try: words=line[2:].decode("utf-8").strip().split()
        except UnicodeDecodeError as error:
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"command {command['id']} shebang is invalid") from error
        if len(words) not in {1,2} or not Path(words[0]).is_absolute() or Path(words[0]).name=="env":
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"command {command['id']} shebang is not a canonical interpreter")
        interpreter=Path(words[0]).resolve(strict=True); interpreter_digest,interpreter_prefix=read_bound(interpreter,False)
        if interpreter_prefix.startswith(b"#!"):
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"command {command['id']} uses a nested script interpreter")
        executable_digest=canonical_sha256({"executable_sha256":executable_digest,"shebang":line.decode("utf-8"),"interpreter_sha256":interpreter_digest})
    return str(candidate),executable_digest


EXECUTABLE_CAPTURE_MAX_BYTES=256*1024*1024


def _executable_metadata_identity(metadata):
    return (metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_nlink,metadata.st_uid,metadata.st_gid,
            metadata.st_size,metadata.st_mtime_ns,metadata.st_ctime_ns)


def _capture_reviewed_executable(path,internal,label):
    before=os.lstat(path)
    if (not stat.S_ISREG(before.st_mode) or not before.st_mode&0o111 or before.st_mode&0o022
            or before.st_uid not in {0,os.geteuid()} or before.st_size>EXECUTABLE_CAPTURE_MAX_BYTES
            or (internal and before.st_nlink!=1)):
        raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"{label} is unsafe or exceeds the capture limit")
    descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:
        opened=os.fstat(descriptor)
        if _executable_metadata_identity(opened)!=_executable_metadata_identity(before):
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"{label} changed while opening")
        chunks=[]; total=0
        while True:
            chunk=os.read(descriptor,min(1024*1024,EXECUTABLE_CAPTURE_MAX_BYTES+1-total))
            if not chunk: break
            chunks.append(chunk); total+=len(chunk)
            if total>EXECUTABLE_CAPTURE_MAX_BYTES:
                raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"{label} exceeds the capture limit")
        after=os.fstat(descriptor); named=os.lstat(path)
        if (_executable_metadata_identity(after)!=_executable_metadata_identity(before)
                or _executable_metadata_identity(named)!=_executable_metadata_identity(before)
                or total!=before.st_size):
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"{label} changed during capture")
    finally: os.close(descriptor)
    return b"".join(chunks),stat.S_IMODE(before.st_mode)


def _anonymous_executable_descriptor(content,label):
    writable,path=tempfile.mkstemp(prefix="agent-acceptance-exec-")
    readonly=None
    try:
        offset=0
        while offset<len(content): offset+=os.write(writable,content[offset:])
        os.fchmod(writable,0o500); os.fsync(writable)
        readonly=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
        captured=os.fstat(readonly)
        if (not stat.S_ISREG(captured.st_mode) or stat.S_IMODE(captured.st_mode)!=0o500
                or captured.st_size!=len(content) or captured.st_nlink!=1):
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"{label} immutable capture metadata is invalid")
        os.unlink(path); path=None; os.close(writable); writable=None
        digest=hashlib.sha256(); offset=0
        while offset<len(content):
            chunk=os.pread(readonly,min(1024*1024,len(content)-offset),offset)
            if not chunk: break
            digest.update(chunk); offset+=len(chunk)
        captured=os.fstat(readonly)
        if (offset!=len(content) or digest.hexdigest()!=hashlib.sha256(content).hexdigest()
                or captured.st_nlink!=0 or stat.S_IMODE(captured.st_mode)!=0o500):
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"{label} immutable capture bytes or mode drifted")
        fd_path=f"/dev/fd/{readonly}"
        linked=os.stat(fd_path)
        linked_identity=(linked.st_ino,linked.st_mode,linked.st_nlink,linked.st_uid,linked.st_gid,linked.st_size)
        captured_identity=(captured.st_ino,captured.st_mode,captured.st_nlink,captured.st_uid,captured.st_gid,captured.st_size)
        # Darwin's synthetic fdesc filesystem reports a different st_dev for
        # the same open file description; inode and exact metadata remain bound.
        if linked_identity!=captured_identity or (not sys.platform.startswith("darwin") and linked.st_dev!=captured.st_dev):
            raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"{label} descriptor launch path is not bound")
        result=readonly; readonly=None
        return result,fd_path
    finally:
        if path is not None:
            try: os.unlink(path)
            except FileNotFoundError: pass
        if writable is not None: os.close(writable)
        if readonly is not None: os.close(readonly)


def descriptor_exec_preexec(executable_descriptor,argv,environment):
    """Build a child-only fexecve thunk; it never reopens an executable path."""
    encoded_argv=[os.fsencode(value) for value in argv]
    encoded_environment=[os.fsencode(f"{key}={value}") for key,value in environment.items()]
    argv_array=(ctypes.c_char_p*(len(encoded_argv)+1))(*encoded_argv,None)
    environment_array=(ctypes.c_char_p*(len(encoded_environment)+1))(*encoded_environment,None)
    libc=ctypes.CDLL(None,use_errno=True); fexecve=getattr(libc,"fexecve",None)
    if fexecve is None:
        raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE","descriptor-bound fexecve is unavailable")
    fexecve.argtypes=(ctypes.c_int,ctypes.POINTER(ctypes.c_char_p),ctypes.POINTER(ctypes.c_char_p)); fexecve.restype=ctypes.c_int
    def invoke():
        fexecve(executable_descriptor,argv_array,environment_array)
        os._exit(126)
    return invoke


def _protected_executable_chain(path):
    resolved=Path(path).resolve(); cursor=resolved
    while True:
        try: metadata=os.lstat(cursor)
        except OSError: return False
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid!=0 or stat.S_IMODE(metadata.st_mode)&0o022:
            return False
        if cursor==resolved:
            restricted_system_inode=(sys.platform.startswith("darwin") and metadata.st_nlink>1
                                     and bool(getattr(metadata,"st_flags",0)&0x00080000))  # SF_RESTRICTED
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink<1 or not metadata.st_mode&0o111
                    or (metadata.st_nlink!=1 and not restricted_system_inode)): return False
        elif not stat.S_ISDIR(metadata.st_mode): return False
        if cursor.parent==cursor: return True
        cursor=cursor.parent


def _retained_protected_executable(path,expected_bytes,label):
    descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    metadata=os.fstat(descriptor); named=os.lstat(path); digest=hashlib.sha256(); offset=0
    while offset<len(expected_bytes):
        chunk=os.pread(descriptor,min(1024*1024,len(expected_bytes)-offset),offset)
        if not chunk: break
        digest.update(chunk); offset+=len(chunk)
    if (_executable_metadata_identity(metadata)!=_executable_metadata_identity(named)
            or offset!=len(expected_bytes) or digest.hexdigest()!=hashlib.sha256(expected_bytes).hexdigest()
            or not _protected_executable_chain(path)):
        os.close(descriptor); raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"{label} protected path is not stable")
    return descriptor,str(path)


def _retained_internal_executable(path,expected_bytes,label):
    descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    metadata=os.fstat(descriptor); named=os.lstat(path); digest=hashlib.sha256(); offset=0
    while offset<len(expected_bytes):
        chunk=os.pread(descriptor,min(1024*1024,len(expected_bytes)-offset),offset)
        if not chunk: break
        digest.update(chunk); offset+=len(chunk)
    if (_executable_metadata_identity(metadata)!=_executable_metadata_identity(named)
            or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1
            or not metadata.st_mode&0o111 or metadata.st_mode&0o022
            or offset!=len(expected_bytes) or digest.hexdigest()!=hashlib.sha256(expected_bytes).hexdigest()):
        os.close(descriptor); raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"{label} candidate path is not stable")
    return descriptor,str(path)


def _named_private_executable(content,directory,name,label):
    path=directory/name; writable=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o500)
    try:
        offset=0
        while offset<len(content): offset+=os.write(writable,content[offset:])
        os.fchmod(writable,0o500); os.fsync(writable)
    finally: os.close(writable)
    descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    metadata=os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 or metadata.st_size!=len(content) or stat.S_IMODE(metadata.st_mode)!=0o500:
        os.close(descriptor); raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"{label} private capture metadata is invalid")
    return descriptor,str(path)


@contextlib.contextmanager
def bound_executable_launch(root,command):
    """Retain exact reviewed launch bytes through exec on Linux and Darwin."""
    resolved,_=resolve_executable(root,command); candidate=Path(resolved)
    try: candidate.relative_to(root); internal=True
    except ValueError: internal=False
    executable_bytes,_mode=_capture_reviewed_executable(candidate,internal,f"command {command['id']} executable")
    prefix=executable_bytes[:4096]; descriptors=[]; bindings=[]; private_directory=None
    darwin=sys.platform.startswith("darwin")
    try:
        if internal:
            executable_fd,executable_path=_retained_internal_executable(candidate,executable_bytes,f"command {command['id']} executable")
            executable_kind="internal"
        elif _protected_executable_chain(candidate):
            executable_fd,executable_path=_retained_protected_executable(candidate,executable_bytes,f"command {command['id']} executable")
            executable_kind="protected"
        elif darwin:
            private_directory=Path(tempfile.mkdtemp(prefix="agent-acceptance-exec-")); private_directory.chmod(0o700)
            executable_fd,executable_path=_named_private_executable(executable_bytes,private_directory,"candidate",f"command {command['id']} executable")
            executable_kind="private"
        else:
            executable_fd,executable_path=_anonymous_executable_descriptor(executable_bytes,f"command {command['id']} executable")
            executable_kind="anonymous"
        descriptors.append(executable_fd); bindings.append((executable_fd,executable_path,executable_bytes,executable_kind))
        if prefix.startswith(b"#!"):
            line=prefix.splitlines()[0]
            try: words=line[2:].decode("utf-8").strip().split()
            except UnicodeDecodeError as error:
                raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"command {command['id']} shebang is invalid") from error
            if len(words) not in {1,2} or not Path(words[0]).is_absolute() or Path(words[0]).name=="env":
                raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"command {command['id']} shebang is not a canonical interpreter")
            interpreter=Path(words[0]).resolve(strict=True)
            interpreter_bytes,_interpreter_mode=_capture_reviewed_executable(interpreter,False,f"command {command['id']} interpreter")
            if interpreter_bytes.startswith(b"#!"):
                raise AdaptiveError("ACCEPTANCE_EXECUTABLE_UNAVAILABLE",f"command {command['id']} uses a nested script interpreter")
            if _protected_executable_chain(interpreter):
                interpreter_fd,interpreter_path=_retained_protected_executable(interpreter,interpreter_bytes,f"command {command['id']} interpreter")
                interpreter_kind="protected"
            elif darwin:
                if private_directory is None:
                    private_directory=Path(tempfile.mkdtemp(prefix="agent-acceptance-exec-")); private_directory.chmod(0o700)
                interpreter_fd,interpreter_path=_named_private_executable(interpreter_bytes,private_directory,"interpreter",f"command {command['id']} interpreter")
                interpreter_kind="private"
            else:
                interpreter_fd,interpreter_path=_anonymous_executable_descriptor(interpreter_bytes,f"command {command['id']} interpreter")
                interpreter_kind="anonymous"
            descriptors.append(interpreter_fd); bindings.append((interpreter_fd,interpreter_path,interpreter_bytes,interpreter_kind))
            digest=canonical_sha256({"executable_sha256":hashlib.sha256(executable_bytes).hexdigest(),
                                     "shebang":line.decode("utf-8"),"interpreter_sha256":hashlib.sha256(interpreter_bytes).hexdigest()})
            launch_descriptor=interpreter_fd if interpreter_kind=="anonymous" else None; launch_path=interpreter_path
            argv=[interpreter_path,*words[1:],executable_path,*command["argv"][1:]]
        else:
            launch_descriptor=executable_fd if executable_kind=="anonymous" else None; launch_path=executable_path
            digest=hashlib.sha256(executable_bytes).hexdigest(); argv=[executable_path,*command["argv"][1:]]
        if private_directory is not None: private_directory.chmod(0o500)
        def verify_capture():
            if private_directory is not None and stat.S_IMODE(os.lstat(private_directory).st_mode)!=0o500:
                raise AdaptiveError("ACCEPTANCE_EXECUTABLE_DRIFT",f"command {command['id']} private launch directory drifted")
            for descriptor,path,expected_bytes,kind in bindings:
                metadata=os.fstat(descriptor); digest_check=hashlib.sha256(); offset=0
                while offset<len(expected_bytes):
                    chunk=os.pread(descriptor,min(1024*1024,len(expected_bytes)-offset),offset)
                    if not chunk: break
                    digest_check.update(chunk); offset+=len(chunk)
                private_capture=kind=="private"
                mode_ok=(stat.S_IMODE(metadata.st_mode)==0o500 if private_capture else bool(metadata.st_mode&0o111) and not bool(metadata.st_mode&0o022))
                if offset!=len(expected_bytes) or digest_check.hexdigest()!=hashlib.sha256(expected_bytes).hexdigest() or not mode_ok:
                    raise AdaptiveError("ACCEPTANCE_EXECUTABLE_DRIFT",f"command {command['id']} retained launch bytes drifted")
                if kind=="anonymous":
                    if metadata.st_nlink!=0:
                        raise AdaptiveError("ACCEPTANCE_EXECUTABLE_DRIFT",f"command {command['id']} anonymous launch descriptor was relinked")
                    continue
                named=os.lstat(path)
                if (_executable_metadata_identity(named)!=_executable_metadata_identity(metadata)
                        or (kind=="private" and (private_directory is None or Path(path).parent!=private_directory))
                        or (kind=="protected" and not _protected_executable_chain(path))):
                    raise AdaptiveError("ACCEPTANCE_EXECUTABLE_DRIFT",f"command {command['id']} named launch path drifted")
                if kind=="internal":
                    try: Path(path).relative_to(root)
                    except ValueError as error:
                        raise AdaptiveError("ACCEPTANCE_EXECUTABLE_DRIFT",f"command {command['id']} internal launch path escaped") from error
        verify_capture()
        yield argv,digest,tuple(descriptors),launch_descriptor,launch_path,verify_capture
    finally:
        for descriptor in descriptors:
            try: os.close(descriptor)
            except OSError: pass
        if private_directory is not None:
            try: private_directory.chmod(0o700); shutil.rmtree(private_directory)
            except OSError: pass


def executable_probe(root,command):
    validate_command_inputs(root,command)
    _,digest=resolve_executable(root,command)
    return {"id":command["id"],"available":True,"resolved_sha256":digest,
            "environment_sha256":command_environment_sha256(command)}


def load_preflight(root, path, blueprint, runner_sha256, skills_lock_sha256, expected):
    _, _, _, value = json_bytes(root, path, "acceptance preflight")
    required = {"schema", "environment", "authority", "candidate_sha256", "candidate_manifest", "blueprint_sha256", "skills_lock_sha256",
                "runner_sha256", "execution_boundary", "commands", "probes", "observed_at", "expires_at", "status", "preflight_sha256"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != PREFLIGHT_SCHEMA:
        raise AdaptiveError("INVALID_ACCEPTANCE_PREFLIGHT", "preflight fields are invalid")
    payload = {key: value[key] for key in value if key != "preflight_sha256"}
    if value["preflight_sha256"] != canonical_sha256(payload):
        raise AdaptiveError("INVALID_ACCEPTANCE_PREFLIGHT", "preflight digest drifted")
    now = dt.datetime.now(dt.timezone.utc)
    observed, expires = parse_time(value["observed_at"], "preflight observed"), parse_time(value["expires_at"], "preflight expiry")
    if expires <= observed or expires - observed > dt.timedelta(hours=1) or now > expires or observed > now + dt.timedelta(minutes=1):
        raise AdaptiveError("STALE_ACCEPTANCE_PREFLIGHT", "acceptance preflight is stale or has invalid bounds")
    commands, _ = acceptance_contract(blueprint)
    if (value["status"] != "ready" or value["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"]
            or value["skills_lock_sha256"] != skills_lock_sha256 or value["runner_sha256"] != runner_sha256
            or value["execution_boundary"] != EXECUTION_BOUNDARY or value["commands"] != command_records(commands)
            or any(set(item) != {"id", "available", "resolved_sha256", "environment_sha256"} or item["available"] is not True or not digest_ok(item["resolved_sha256"]) or not digest_ok(item["environment_sha256"]) for item in value["probes"])
            or [item["id"] for item in value["probes"]] != [item["id"] for item in commands]):
        raise AdaptiveError("INVALID_ACCEPTANCE_PREFLIGHT", "preflight no longer binds verified acceptance prerequisites")
    for key in ("candidate_sha256", "candidate_manifest", "environment", "authority"):
        if value[key] != expected[key]:
            raise AdaptiveError("ACCEPTANCE_CANDIDATE_DRIFT", f"preflight {key} differs from the current release candidate")
    return value


def load_integrator(root, path, blueprint, skills_lock_sha256, expected, non_executable):
    _, relative, raw, value = json_bytes(root, path, "integrator evidence")
    required = {"schema", "candidate_sha256", "blueprint_sha256", "skills_lock_sha256", "environment", "authority",
                "integrator_id", "acceptance", "evidence", "recorded_at", "expires_at", "status", "receipt_sha256"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != INTEGRATOR_SCHEMA:
        raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", "integrator evidence fields are invalid")
    payload = {key: value[key] for key in value if key != "receipt_sha256"}
    if value["receipt_sha256"] != canonical_sha256(payload):
        raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", "integrator evidence digest drifted")
    now = dt.datetime.now(dt.timezone.utc)
    recorded, expires = parse_time(value["recorded_at"], "integrator recorded"), parse_time(value["expires_at"], "integrator expiry")
    if expires <= recorded or expires - recorded > dt.timedelta(hours=24) or now > expires or recorded > now + dt.timedelta(minutes=1):
        raise AdaptiveError("STALE_INTEGRATOR_EVIDENCE", "integrator evidence is stale or has invalid bounds")
    expected_acceptance = [{**item, "status": "passed"} for item in non_executable]
    if (value["status"] != "passed" or value["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"]
            or value["skills_lock_sha256"] != skills_lock_sha256 or value["acceptance"] != expected_acceptance
            or not isinstance(value["integrator_id"], str) or not value["integrator_id"]
            or any(value[key] != expected[key] for key in ("candidate_sha256", "environment", "authority"))):
        raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", "integrator evidence does not bind the current candidate and acceptance contract")
    evidence = value["evidence"]
    if not isinstance(evidence, list) or len(evidence) > 64:
        raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", "integrator evidence inventory is invalid")
    covered = set()
    for index, record in enumerate(evidence):
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes", "acceptance_ids"}:
            raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", f"integrator evidence[{index}] fields are invalid")
        _, evidence_relative, evidence_raw = regular_bytes(root, record["path"], f"integrator evidence[{index}]")
        ids = record["acceptance_ids"]
        if (record["path"] != evidence_relative or record["bytes"] != len(evidence_raw)
                or record["sha256"] != hashlib.sha256(evidence_raw).hexdigest()
                or not isinstance(ids, list) or not ids or len(ids) != len(set(ids))):
            raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", f"integrator evidence[{index}] bytes or coverage drifted")
        covered.update(ids)
    required_ids = {item["id"] for item in non_executable}
    if covered != required_ids or (required_ids and not evidence):
        raise AdaptiveError("INVALID_INTEGRATOR_EVIDENCE", "manual/evidence acceptance lacks exact evidence coverage")
    return relative, raw, value


def integrator_file_record(relative, raw):
    return {"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def manual_approval_action(blueprint, expected, skills_lock_sha256, preflight, integrator_relative, integrator_raw, integrator, non_executable):
    manual_ids = sorted(item["id"] for item in non_executable if item["method"] == "manual")
    evidence = [record for record in integrator["evidence"] if set(record["acceptance_ids"]) & set(manual_ids)]
    return {
        "schema": "agent-blueprint-manual-acceptance-action/v1",
        "candidate_sha256": expected["candidate_sha256"], "candidate_manifest": expected["candidate_manifest"],
        "environment": expected["environment"], "authority": expected["authority"],
        "blueprint_sha256": blueprint["confirmation"]["design_sha256"], "skills_lock_sha256": skills_lock_sha256,
        "preflight_sha256": preflight["preflight_sha256"], "integrator_evidence": integrator_file_record(integrator_relative, integrator_raw),
        "integrator_receipt_sha256": integrator["receipt_sha256"], "manual_acceptance_ids": manual_ids, "evidence": evidence,
    }


def manual_decision(root, args, action):
    if not action["manual_acceptance_ids"]:
        return None
    digest = canonical_sha256(action)
    if args.plan:
        print(json.dumps({"schema": "agent-blueprint-manual-acceptance-approval/v1", "payload": action,
                          "approval_sha256": digest, "mutation": False}, sort_keys=True))
        return "planned"
    if args.manual_approve_digest != digest:
        raise AdaptiveError("MANUAL_ACCEPTANCE_APPROVAL_REQUIRED", f"approve the exact manual acceptance action digest: {digest}")
    receipt = record_provider_human_decision(root, gate="adaptive-blueprint-manual-acceptance", artifact_sha256=digest,
                                    source=args.manual_decision_source, receipt=args.manual_decision_receipt)
    return {"action": action, "action_sha256": digest, "source": args.manual_decision_source, "receipt": receipt}


def command_preflight(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    runner_relative, runner_sha256 = runner_binding(root, args.runner)
    skills_lock_sha256 = verified_skills_lock(root, blueprint)
    commands, _ = acceptance_contract(blueprint)
    binding,captured=candidate_snapshot(root,args.candidate_manifest,args.candidate_sha256)
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "schema": PREFLIGHT_SCHEMA, "environment": args.environment, "authority": args.authority,
        "candidate_sha256": binding["sha256"], "candidate_manifest": binding,
        "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
        "skills_lock_sha256": skills_lock_sha256, "runner_sha256": runner_sha256,
        "execution_boundary": EXECUTION_BOUNDARY, "commands":command_records(commands),"probes":[],
        "observed_at": now.isoformat(), "expires_at": (now + dt.timedelta(hours=1)).isoformat(), "status": "ready",
    }
    with materialized_candidate(captured) as workspace:
        payload["probes"]=[executable_probe(workspace,item) for item in commands]
    value={**payload,"preflight_sha256":canonical_sha256(payload)}
    write_authority_bound_json(root, output_path(root, args.receipt), value, binding,
                               blueprint["confirmation"]["design_sha256"])
    print("VALID blueprint acceptance preflight")
    return 0


def command_group_exists(group_id):
    try:
        observed=linux_process_snapshot() if sys.platform.startswith("linux") else darwin_process_snapshot()
    except ProcessObservationError:
        return True  # Fail closed when exact group inventory is unavailable.
    return any(info.get("pgid")==group_id and not str(info.get("state","")).startswith("Z")
               for info in observed.values())


def signal_launch_group(process,known,requested):
    if process.returncode is not None or signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL: return False
    try:
        observed=linux_process_snapshot() if sys.platform.startswith("linux") else darwin_process_snapshot()
    except ProcessObservationError: return False
    members={pid:info["start_identity"] for pid,info in observed.items()
             if info.get("pgid")==process.pid and not str(info.get("state","")).startswith("Z")}
    if any(pid in known and known[pid]!=identity for pid,identity in members.items()): return False
    if not members: return True
    try:
        if any(os.getsid(pid)!=process.pid for pid in members): return False
    except (ProcessLookupError,OSError,PermissionError): return False
    try:
        immediate=linux_process_snapshot() if sys.platform.startswith("linux") else darwin_process_snapshot()
    except ProcessObservationError: return False
    current={pid:info["start_identity"] for pid,info in immediate.items()
             if info.get("pgid")==process.pid and not str(info.get("state","")).startswith("Z")}
    if current!=members: return False
    try:
        if any(os.getsid(pid)!=process.pid for pid in current): return False
    except (ProcessLookupError,OSError,PermissionError): return False
    known.update(members)
    normalized={pid:(info["ppid"],info["start_identity"],info["state"]) for pid,info in immediate.items()}
    return signal_known(members,requested,normalized)


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
        return {pid:(info["ppid"],info["start_identity"],info["state"]) for pid,info in observed.items()} or None
    if sys.platform.startswith("darwin"):
        try: observed=darwin_process_snapshot()
        except ProcessObservationError: return None
        return {pid:(info["ppid"],info["start_identity"],info["state"]) for pid,info in observed.items()} or None
    output=_ps_result(["-axo","pid=,ppid=,lstart=,stat="])
    if output is None: return None
    snapshot={}
    for line in output.splitlines():
        parts=line.split()
        if len(parts)<8: continue
        try: pid,parent=int(parts[0]),int(parts[1])
        except ValueError: continue
        snapshot[pid]=(parent," ".join(parts[2:7]),parts[7])
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
            known.setdefault(pid,snapshot[pid][1])
    return True


def discover_descendants(root_pid,known,snapshot):
    if snapshot is None: return False
    roots={root_pid}; roots.update(pid for pid,identity in known.items() if pid in snapshot and snapshot[pid][1]==identity)
    if sys.platform.startswith("linux"):
        for pid,(parent,identity,state) in snapshot.items():
            if parent==os.getpid() and pid!=root_pid and not state.startswith("Z"):
                roots.add(pid); known.setdefault(pid,identity)
    changed=True
    while changed:
        changed=False
        for pid,(parent,identity,state) in snapshot.items():
            if parent in roots and pid not in roots:
                roots.add(pid)
                if pid!=root_pid and not state.startswith("Z"): known.setdefault(pid,identity)
                changed=True
    return True


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
        if pid<=1 or pid not in snapshot or snapshot[pid][1]!=known[pid]: continue
        try:
            if sys.platform.startswith("linux"): linux_signal_identity(pid,known[pid],signum)
            elif sys.platform.startswith("darwin"):
                immediate=process_snapshot()
                if immediate is None or pid not in immediate or immediate[pid][1]!=known[pid]: ok=False; continue
                os.kill(pid,signum)
            else: ok=False
        except ProcessLookupError: pass
        except (OSError,ProcessObservationError): ok=False
    return ok


def monitor_and_cleanup(process,timeout,launch_token=None,subreaper_ok=True):
    """Monitor and clean exact identities while the launch PID remains unreaped."""
    if process.returncode is not None:
        return int(process.returncode),False,False,False,True
    if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
        return 125,False,False,False,True
    known={}; uncertain=not subreaper_ok; timed_out=False; deadline=time.monotonic()+timeout
    leader_identity=None
    while True:
        snapshot=process_snapshot()
        if snapshot is None: uncertain=True
        else:
            leader=snapshot.get(process.pid)
            if leader is not None:
                if leader_identity is None: leader_identity=leader[1]; known[process.pid]=leader_identity
                elif leader[1]!=leader_identity: uncertain=True; break
            if not discover_descendants(process.pid,known,snapshot): uncertain=True
            # Darwin libproc can hide an exited child before wait(); with default
            # SIGCHLD ownership and no poll/wait, that PID is still unreusable.
            if leader is None or leader[2].startswith("Z"): break
        if time.monotonic()>=deadline:
            timed_out=True; break
        time.sleep(0.05)
    final=process_snapshot()
    if final is None: uncertain=True
    else: discover_descendants(process.pid,known,final)
    if not merge_launch_identities(known,launch_token): uncertain=True
    final=process_snapshot()
    if final is None: uncertain=True
    else: discover_descendants(process.pid,known,final)
    descendants={pid:identity for pid,identity in known.items() if pid!=process.pid}
    def live(snap):
        return {pid:identity for pid,identity in descendants.items()
                if snap is not None and pid in snap and snap[pid][1]==identity and not snap[pid][2].startswith("Z")}
    group_leak=command_group_exists(process.pid)
    observed=bool(live(final)) or group_leak
    if timed_out or observed:
        if not signal_launch_group(process,known,signal.SIGTERM):
            uncertain=True
            try: process.terminate()
            except (ProcessLookupError,PermissionError): pass
        snap=process_snapshot()
        if snap is None: uncertain=True
        elif not signal_known(descendants,signal.SIGTERM,snap): uncertain=True
        term_deadline=time.monotonic()+1
        while time.monotonic()<term_deadline:
            snap=process_snapshot()
            if snap is None: uncertain=True; break
            discover_descendants(process.pid,known,snap)
            descendants.update({pid:identity for pid,identity in known.items() if pid!=process.pid})
            if not live(snap) and not command_group_exists(process.pid): break
            time.sleep(0.05)
        for _ in range(3):
            snap=process_snapshot()
            if snap is None: uncertain=True; break
            discover_descendants(process.pid,known,snap)
            descendants.update({pid:identity for pid,identity in known.items() if pid!=process.pid})
            if not signal_known(descendants,signal.SIGSTOP,snap): uncertain=True
        if not signal_launch_group(process,known,signal.SIGKILL):
            uncertain=True
            try: process.kill()
            except (ProcessLookupError,PermissionError): pass
        snap=process_snapshot()
        if snap is None: uncertain=True
        elif not signal_known(descendants,signal.SIGKILL,snap): uncertain=True
        kill_deadline=time.monotonic()+2
        while time.monotonic()<kill_deadline:
            snap=process_snapshot()
            if snap is None: uncertain=True; break
            discover_descendants(process.pid,known,snap)
            descendants.update({pid:identity for pid,identity in known.items() if pid!=process.pid})
            if not live(snap) and not command_group_exists(process.pid): break
            time.sleep(0.05)
    try: process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        uncertain=True
        try: process.kill(); process.wait(timeout=2)
        except (OSError,subprocess.TimeoutExpired): pass
    reap_known_children(known)
    if not merge_launch_identities(known,launch_token): uncertain=True
    residual_snapshot=process_snapshot()
    if residual_snapshot is None: uncertain=True; residual=True
    else:
        # The leader is now reaped: never rediscover or inspect a numeric session.
        residual=any(pid in residual_snapshot and residual_snapshot[pid][1]==identity
                     and not residual_snapshot[pid][2].startswith("Z")
                     for pid,identity in known.items() if pid!=process.pid)
    return int(process.returncode if process.returncode is not None else 125),timed_out,observed,residual,uncertain


@contextlib.contextmanager
def child_subreaper():
    """Use Linux subreaping; macOS is tracked by the inherited launch token."""
    if sys.platform.startswith("darwin"):
        # Darwin uses bounded ancestry/process-group/token observation. This is
        # functional lifecycle checking, not hostile-code containment.
        yield True; return
    if not sys.platform.startswith("linux"):
        yield False; return
    if not linux_pidfd_supported():
        yield False; return
    libc=ctypes.CDLL(None,use_errno=True); current=ctypes.c_int()
    if libc.prctl(37,ctypes.byref(current),0,0,0)!=0:
        yield False; return
    changed=current.value==0
    if changed and libc.prctl(36,1,0,0,0)!=0:
        yield False; return
    try: yield True
    finally:
        if changed: libc.prctl(36,0,0,0,0)


def execute_commands(root,blueprint,commands,expected_probes,captured=None):
    """Execute each command in a fresh exact candidate and private runtime."""
    results=[]; expected={item["id"]:item for item in expected_probes}
    for command in commands:
      candidate_context=materialized_candidate(captured) if captured is not None else contextlib.nullcontext(root)
      with candidate_context as workspace, tempfile.TemporaryDirectory(prefix="agent-acceptance-runtime-") as runtime:
        if captured is not None: verify_materialized_candidate(workspace,captured)
        validate_command_inputs(workspace,command)
        environment=command_environment(command); environment_digest=canonical_sha256(environment)
        environment={key:(runtime if value=="<private-runtime>" else value) for key,value in environment.items()}
        probe=expected.get(command["id"],{})
        if environment_digest!=probe.get("environment_sha256"):
            raise AdaptiveError("ACCEPTANCE_ENVIRONMENT_DRIFT",f"command {command['id']} requested environment differs from preflight")
        process=None; launch_token=uuid.uuid4().hex
        environment[LAUNCH_TOKEN_NAME]=launch_token
        try:
          with bound_executable_launch(workspace,command) as (argv,digest,launch_descriptors,launch_descriptor,launch_path,verify_launch_capture):
            if digest!=probe.get("resolved_sha256"):
                raise AdaptiveError("ACCEPTANCE_EXECUTABLE_DRIFT",f"command {command['id']} executable differs from preflight")
            with child_subreaper() as subreaper_ok:
              if not subreaper_ok:
                  raise AdaptiveError("ACCEPTANCE_LIFECYCLE_UNSUPPORTED",f"command {command['id']} lacks a supported bounded lifecycle observer")
              popen_options={"cwd":workspace,"shell":False,"start_new_session":True,"stdin":subprocess.DEVNULL,
                             "stdout":subprocess.DEVNULL,"stderr":subprocess.DEVNULL,"env":environment,"close_fds":True,
                             "pass_fds":launch_descriptors}
              if launch_descriptor is None:
                  popen_options["executable"]=launch_path
              else:
                  popen_options["executable"]="/bin/false"
                  popen_options["preexec_fn"]=descriptor_exec_preexec(launch_descriptor,argv,environment)
              verify_launch_capture()
              if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
                  raise AdaptiveError("ACCEPTANCE_LIFECYCLE_UNSUPPORTED",f"command {command['id']} lacks unreaped PID ownership")
              process=subprocess.Popen(argv,**popen_options)
              verify_launch_capture()
              returncode,timed_out,descendants,residual,uncertain=monitor_and_cleanup(
                  process,command["timeout_seconds"],launch_token,subreaper_ok)
        except OSError as error:
            raise AdaptiveError("ACCEPTANCE_COMMAND_FAILED",f"acceptance command could not start in private candidate materialization: {command['id']}") from error
        except BaseException:
            if process is not None and process.returncode is None: monitor_and_cleanup(process,0,launch_token)
            raise
        if captured is not None: verify_materialized_candidate(workspace,captured)
        if uncertain:
            raise AdaptiveError("ACCEPTANCE_COMMAND_FAILED",f"acceptance command descendant cleanup was uncertain: {command['id']}")
        if residual:
            raise AdaptiveError("ACCEPTANCE_COMMAND_FAILED",f"acceptance command left residual descendant processes: {command['id']}")
        if descendants:
            raise AdaptiveError("ACCEPTANCE_COMMAND_FAILED",f"acceptance command left descendant processes: {command['id']}")
        if timed_out:
            raise AdaptiveError("ACCEPTANCE_COMMAND_FAILED",f"acceptance command timed out in private candidate materialization: {command['id']}")
        record={"id":command["id"],"argv_sha256":canonical_sha256(command["argv"]),"covers":command["covers"],
                "environment":command.get("environment",[]),"exit_code":returncode}
        results.append(record)
        if returncode:
            raise AdaptiveError("ACCEPTANCE_COMMAND_FAILED",f"acceptance command failed in private candidate materialization: {command['id']}")
    return results


def command_run(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    runner_relative, runner_sha256 = runner_binding(root, args.runner)
    skills_lock_sha256 = verified_skills_lock(root, blueprint)
    binding,captured=candidate_snapshot(root,args.candidate_manifest,args.candidate_sha256)
    expected={"candidate_sha256":binding["sha256"],"candidate_manifest":binding,
                "environment": args.environment, "authority": args.authority}
    preflight = load_preflight(root, args.preflight_receipt, blueprint, runner_sha256, skills_lock_sha256, expected)
    commands, non_executable = acceptance_contract(blueprint)
    integrator_relative, integrator_raw, integrator = load_integrator(root, args.integrator_receipt, blueprint, skills_lock_sha256, expected, non_executable)
    action = manual_approval_action(blueprint, expected, skills_lock_sha256, preflight, integrator_relative, integrator_raw, integrator, non_executable)
    decision = manual_decision(root, args, action)
    if decision == "planned":
        return 0
    if args.plan:
        print(json.dumps({"schema": "agent-blueprint-manual-acceptance-approval/v1", "payload": None,
                          "approval_sha256": None, "mutation": False, "manual_approval_required": False}, sort_keys=True))
        return 0
    final_authority_check(root,binding,blueprint["confirmation"]["design_sha256"])
    results=execute_commands(root,blueprint,commands,preflight["probes"],captured=captured)
    final_authority_check(root,binding,blueprint["confirmation"]["design_sha256"])
    current_blueprint = load_blueprint(root, require_confirmed=True)
    if current_blueprint["confirmation"]["design_sha256"] != blueprint["confirmation"]["design_sha256"]:
        raise AdaptiveError("BLUEPRINT_DRIFT", "blueprint authority changed during acceptance", 3)
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "schema": RECEIPT_SCHEMA, "candidate_sha256": binding["sha256"], "candidate_manifest": binding,
        "environment": args.environment,
        "authority": args.authority, "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
        "skills_lock_sha256": skills_lock_sha256, "runner_path": runner_relative, "runner_sha256": runner_sha256,
        "preflight_path": str(safe_relative_path(args.preflight_receipt)), "preflight_sha256": preflight["preflight_sha256"],
        "integrator_path": integrator_relative, "integrator_sha256": hashlib.sha256(integrator_raw).hexdigest(),
        "integrator_evidence": integrator_file_record(integrator_relative, integrator_raw),
        "integrator_receipt_sha256": integrator["receipt_sha256"], "integrator_id": integrator["integrator_id"],
        "requires_integrator_ledger_binding": True, "manual_decision": decision,
        "execution_boundary": EXECUTION_BOUNDARY, "results": results,
        "acceptance": [{"id": item["id"], "method": acceptance_method(item), "status": "passed"} for item in blueprint["design"]["acceptance"]],
        "recorded_at": now.isoformat(), "expires_at": (now + dt.timedelta(hours=24)).isoformat(), "status": "passed",
    }
    value = {**payload, "receipt_sha256": canonical_sha256(payload)}
    write_authority_bound_json(root, output_path(root, args.receipt), value, binding,
                               blueprint["confirmation"]["design_sha256"])
    print("VALID blueprint acceptance receipt")
    return 0


def command_verify(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    runner_relative, runner_sha256 = runner_binding(root, args.runner)
    skills_lock_sha256 = verified_skills_lock(root, blueprint)
    _, _, _, value = json_bytes(root, args.receipt, "acceptance receipt")
    required = {"schema", "candidate_sha256", "candidate_manifest", "environment", "authority", "blueprint_sha256", "skills_lock_sha256",
                "runner_path", "runner_sha256", "preflight_path", "preflight_sha256", "integrator_path", "integrator_sha256",
                "integrator_evidence", "integrator_receipt_sha256", "integrator_id", "requires_integrator_ledger_binding",
                "manual_decision", "execution_boundary", "results", "acceptance", "recorded_at", "expires_at", "status", "receipt_sha256"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != RECEIPT_SCHEMA:
        raise AdaptiveError("INVALID_ACCEPTANCE_RECEIPT", "acceptance receipt fields are invalid")
    payload = {key: value[key] for key in value if key != "receipt_sha256"}
    if value["receipt_sha256"] != canonical_sha256(payload):
        raise AdaptiveError("INVALID_ACCEPTANCE_RECEIPT", "acceptance receipt digest drifted")
    claimed_candidate = args.candidate_sha256 or value["candidate_sha256"]
    supplied_manifest = args.candidate_manifest or value["candidate_manifest"].get("path")
    binding,captured=candidate_snapshot(root,supplied_manifest,claimed_candidate)
    expected_candidate=binding["sha256"]
    expected = {"candidate_sha256": expected_candidate, "candidate_manifest": binding,
                "environment": value["environment"], "authority": value["authority"]}
    preflight = load_preflight(root, value["preflight_path"], blueprint, runner_sha256, skills_lock_sha256, expected)
    commands, non_executable = acceptance_contract(blueprint)
    integrator_relative, integrator_raw, integrator = load_integrator(root, value["integrator_path"], blueprint, skills_lock_sha256, expected, non_executable)
    action = manual_approval_action(blueprint, expected, skills_lock_sha256, preflight, integrator_relative, integrator_raw, integrator, non_executable)
    manual_ids = action["manual_acceptance_ids"]
    decision = value["manual_decision"]
    if manual_ids:
        if (not isinstance(decision, dict) or set(decision) != {"action", "action_sha256", "source", "receipt"}
                or decision["action"] != action or decision["action_sha256"] != canonical_sha256(action)):
            raise AdaptiveError("INVALID_MANUAL_ACCEPTANCE_DECISION", "manual acceptance decision does not bind exact evidence")
        verify_provider_human_decision(root, gate="adaptive-blueprint-manual-acceptance", artifact_sha256=decision["action_sha256"],
                              source=decision["source"], record=decision["receipt"])
    elif decision is not None:
        raise AdaptiveError("INVALID_MANUAL_ACCEPTANCE_DECISION", "manual acceptance decision exists without manual criteria")
    expected_results = [{"id": item["id"], "argv_sha256": canonical_sha256(item["argv"]), "covers": item["covers"],
                         "environment": item.get("environment", []), "exit_code": 0} for item in commands]
    expected_acceptance = [{"id": item["id"], "method": acceptance_method(item), "status": "passed"} for item in blueprint["design"]["acceptance"]]
    now = dt.datetime.now(dt.timezone.utc)
    recorded, expires = parse_time(value["recorded_at"], "acceptance recorded"), parse_time(value["expires_at"], "acceptance expiry")
    if expires <= recorded or expires - recorded > dt.timedelta(hours=24) or now > expires or recorded > now + dt.timedelta(minutes=1):
        raise AdaptiveError("STALE_ACCEPTANCE_RECEIPT", "acceptance receipt is stale or has invalid bounds")
    if (value["status"] != "passed" or not digest_ok(value["candidate_sha256"]) or value["candidate_sha256"] != expected_candidate
            or value["candidate_manifest"] != binding
            or value["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"] or value["skills_lock_sha256"] != skills_lock_sha256
            or value["runner_path"] != runner_relative or value["runner_sha256"] != runner_sha256
            or value["preflight_sha256"] != preflight["preflight_sha256"] or value["integrator_path"] != integrator_relative
            or value["integrator_sha256"] != hashlib.sha256(integrator_raw).hexdigest()
            or value["integrator_evidence"] != integrator_file_record(integrator_relative, integrator_raw)
            or value["requires_integrator_ledger_binding"] is not True or value["execution_boundary"] != EXECUTION_BOUNDARY
            or value["integrator_receipt_sha256"] != integrator["receipt_sha256"] or value["integrator_id"] != integrator["integrator_id"]
            or value["results"] != expected_results or value["acceptance"] != expected_acceptance):
        raise AdaptiveError("INVALID_ACCEPTANCE_RECEIPT", "acceptance receipt no longer binds current candidate, commands, Skills, and evidence")
    final_authority_check(root,binding,blueprint["confirmation"]["design_sha256"])
    replayed_results=execute_commands(root,blueprint,commands,preflight["probes"],captured=captured)
    final_authority_check(root,binding,blueprint["confirmation"]["design_sha256"])
    if replayed_results != value["results"]:
        raise AdaptiveError("INVALID_ACCEPTANCE_EXECUTION", "runner-owned command replay differs from the stored result", 3)
    final_authority_check(root, binding, blueprint["confirmation"]["design_sha256"])
    print("VALID blueprint acceptance receipt")
    return 0


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--root")
    sub = value.add_subparsers(dest="command", required=True)
    preflight = sub.add_parser("preflight"); preflight.add_argument("--runner", required=True); preflight.add_argument("--receipt", required=True)
    preflight.add_argument("--environment", choices=("local", "test"), required=True); preflight.add_argument("--authority", choices=("default", "elevated", "remote-test"), required=True)
    preflight.add_argument("--candidate-sha256"); preflight.add_argument("--candidate-manifest", required=True)
    run = sub.add_parser("run"); run.add_argument("--runner", required=True); run.add_argument("--receipt", required=True)
    run.add_argument("--integrator-receipt", required=True); run.add_argument("--preflight-receipt", required=True)
    run.add_argument("--environment", choices=("local", "test"), required=True); run.add_argument("--authority", choices=("default", "elevated", "remote-test"), required=True)
    run.add_argument("--candidate-sha256"); run.add_argument("--candidate-manifest", required=True); run.add_argument("--plan", action="store_true")
    run.add_argument("--manual-approve-digest"); run.add_argument("--manual-decision-source"); run.add_argument("--manual-decision-receipt")
    verify = sub.add_parser("verify"); verify.add_argument("--runner", required=True); verify.add_argument("--receipt", required=True)
    verify.add_argument("--candidate-sha256"); verify.add_argument("--candidate-manifest")
    return value


def main():
    args = parser().parse_args()
    try:
        root = resolve_root(args.root, __file__)
        candidate = getattr(args, "candidate_sha256", None)
        if candidate is not None and not digest_ok(candidate):
            raise AdaptiveError("INVALID_CANDIDATE_DIGEST", "candidate SHA-256 must be full lowercase hex")
        return {"preflight": command_preflight, "run": command_run, "verify": command_verify}[args.command](root, args)
    except Exception as error:
        return fail(error)


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
