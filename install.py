#!/usr/bin/env python3
"""Install, check, or safely update the reusable .agent workflow."""

from pathlib import Path
import argparse, ast, contextlib, datetime as dt, hashlib, json, os, platform, re, selectors, shutil, signal, socket, stat, subprocess, sys, tempfile, threading, time, types, uuid

try:
    import fcntl
except ImportError:  # Import must remain diagnostic on unsupported hosts.
    fcntl=None

SUPPORTED_SYSTEMS={"Linux","Darwin"}
AGENT_ROOT_MODE=0o700
LOGICAL_TARGET_ROOT=None
LOGICAL_TARGET_PARENT=None
BOUND_PARENT_IDENTITY=None
BOUND_TARGET_IDENTITY=None
INSTALLER_PUBLICATION_AUTHORITY=None


def inode_identity(metadata):
    return (metadata.st_dev,metadata.st_ino)


def assert_trusted_directory_descriptor(descriptor,label):
    observed=os.fstat(descriptor)
    if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid!=os.geteuid()
            or stat.S_IMODE(observed.st_mode)&0o022):
        raise RuntimeError(f"{label} must be an owner-controlled directory with no group/other write access")
    return observed


def open_directory_chain(path):
    absolute=Path(os.path.abspath(str(path)))
    # Darwin exposes /var and /tmp as fixed root-owned aliases into /private.
    # Normalize only those OS compatibility links before the otherwise strict
    # no-follow component walk.
    if platform.system()=="Darwin" and len(absolute.parts)>1 and absolute.parts[1] in {"var","tmp"}:
        alias=Path("/")/absolute.parts[1]
        try: alias_stat=os.lstat(alias)
        except FileNotFoundError: alias_stat=None
        expected=Path("/private")/absolute.parts[1]
        if (alias_stat is not None and stat.S_ISLNK(alias_stat.st_mode) and alias_stat.st_uid==0
                and Path(os.path.realpath(str(alias)))==expected):
            absolute=expected.joinpath(*absolute.parts[2:])
    descriptor=os.open("/",os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
    try:
        for component in absolute.parts[1:]:
            try:
                child=os.open(component,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=descriptor)
            except FileNotFoundError:
                return None
            observed=os.fstat(child)
            if not stat.S_ISDIR(observed.st_mode):
                os.close(child); raise RuntimeError(f"installer parent component is not a real directory: {component}")
            os.close(descriptor); descriptor=child
        result=descriptor; descriptor=None; return result
    except OSError as error:
        raise RuntimeError(f"installer parent chain is unsafe: {absolute}") from error
    finally:
        if descriptor is not None: os.close(descriptor)


def transaction_target_root(target):
    return str(LOGICAL_TARGET_ROOT) if LOGICAL_TARGET_ROOT is not None else str(target)


def assert_namespace_binding(target=None):
    if LOGICAL_TARGET_PARENT is None or BOUND_PARENT_IDENTITY is None: return
    descriptor=open_directory_chain(LOGICAL_TARGET_PARENT)
    if descriptor is None: raise RuntimeError("installer target parent disappeared during the transaction")
    try:
        if inode_identity(os.fstat(descriptor))!=BOUND_PARENT_IDENTITY:
            raise RuntimeError("installer target parent was replaced during the transaction")
    finally: os.close(descriptor)
    if target is not None and BOUND_TARGET_IDENTITY is not None:
        try: current=os.lstat(target)
        except FileNotFoundError as error: raise RuntimeError("installer target root moved during the transaction") from error
        if not stat.S_ISDIR(current.st_mode) or inode_identity(current)!=BOUND_TARGET_IDENTITY:
            raise RuntimeError("installer target root was replaced during the transaction")

VERSION="4.0.1"
MIGRATION_VERSION=42
CANONICAL_ACCEPTANCE_ADAPTERS={
    "acceptance-workflow":{"implemented":True,"runner":".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py","receipt_schema":"workflow-release-gate/v4"},
    "acceptance-web-docker":{"implemented":True,"runner":".agent/skills/run-full-chain-acceptance/scripts/run_live_release_gate.py","receipt_schema":"acceptance-live-gate/v2"},
    "acceptance-api":{"implemented":True,"runner":".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py","receipt_schema":"local-command-release-gate/v1"},
    "acceptance-cli":{"implemented":True,"runner":".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py","receipt_schema":"local-command-release-gate/v1"},
    "acceptance-ios":{"implemented":True,"runner":".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py","receipt_schema":"local-command-release-gate/v1"},
}
MANAGED=("INDEX.md","scripts","skills","templates","workflows","assets","capabilities")
MANAGED_FILES=("knowledge/INDEX.md","LICENSE")
FRESH_STATE_RELATIVE=Path("assets")/"fresh-state"/"v1"
FRESH_STATE_REQUIRED={
    "config.json","policies/PROJECT_GUARDRAILS.md","state/TASK.json",
    "state/CONTEXT.json","state/STAGE_INDEX.md","state/REQUIREMENT_CONTRACT.md","state/SKILL_ACTIVATION.json",
    "state/agents.json","state/EVIDENCE_INDEX.json","state/delivery.json",
    "state/runtime.json","state/test-budget.json","state/tool-leases.json",
}
FRESH_STATE_ALLOWED=FRESH_STATE_REQUIRED|{
    "state/.agents.lock","state/.context.lock","state/.delivery.lock","state/.evidence.lock",
    "state/.runtime.lock","state/.task.lock","state/.template.lock","state/.test-budget.lock",
    "state/.tool-leases.lock","state/.project-init.lock","state/.scheduler-receipt-nonces.json",
}
PLUGIN_NAME="pxpipe-context"
PLUGIN_RELATIVE=Path("plugins")/PLUGIN_NAME
MARKETPLACE_RELATIVE=Path(".agents/plugins/marketplace.json")
GLOBAL_PXPIPE_INTENT_RELATIVE=Path(".agent/state/agent-global-pxpipe-retirement-intent.json")
GLOBAL_PXPIPE_RECEIPT_RELATIVE=Path(".agent/state/evidence/agent-global-pxpipe-retirement-receipt.json")
GLOBAL_PXPIPE_MAX_BYTES=2*1024*1024
GLOBAL_PXPIPE_HELPERS=("scripts/uninstall-codex-default.sh","scripts/codex-default-config.mjs")
RELEASED_PXPIPE_HELPER_SETS=(
 {"scripts/uninstall-codex-default.sh":"25762254d1bdb216d9fa502a5c45a96bed58d9226f4faf199a17a6cd56fcd9f9","scripts/codex-default-config.mjs":"8f2914b972bcb796213ee747ec74855dea83455a13aab3276d8f16eef3bb8f0a"},
 {"scripts/uninstall-codex-default.sh":"3c8d8e9fae692adb5df3ef63663b9367f216ecbbfb7628d5104f543f741d9375","scripts/codex-default-config.mjs":"593f2c7f074de7df6e7f04c351d9dd7add168a9912d23f7288f3ac1cdee62483"},
)
BOOTSTRAP_START="<!-- agent-workflow-bootstrap:start -->"
BOOTSTRAP_END="<!-- agent-workflow-bootstrap:end -->"
BOOTSTRAP_BODY="""# Agent Bootstrap

Before project work, read `.agent/INDEX.md`, `.agent/config.json`, `.agent/state/TASK.json`, `.agent/state/CONTEXT.json`, `.agent/state/SKILL_ACTIVATION.json`, and `.agent/policies/PROJECT_GUARDRAILS.md`. The guardrails are hash-bound (`project_initialization.guardrails_sha256`) and verified by bootstrap-check. Dynamic project Skills may be loaded only from the exact `SKILL.md` document bytes embedded in the task-generation-bound `SKILL_ACTIVATION.json` after `agentctl.py validate` succeeds; never load `.agent/project/skills/` directly. Built-in `.agent/skills/` may be loaded only when routed. Before starting the first task, run `python3 .agent/scripts/agentctl.py bootstrap-check`. At the start of each real host/model turn, account it exactly once with `python3 .agent/scripts/contextctl.py account-turn --turn-id <caller-stable-host-turn-id>`; retries of the same turn must reuse the same ID, and post-completion accounting must preserve the durable `complete-task` origin. Local user and current-chat evidence is advisory only and cannot authorize state or gate changes. Authoritative state and gate changes require a valid receipt from the configured provider-owned decision adapter, whose OS-protected sidecar binds the exact executable SHA-256 and protocol operations. Requirements must be clarified before design or implementation; local runtimes must be bounded and cleaned with `.agent/scripts/agentctl.py`.

After every child-agent terminal event, after every compaction, and immediately before any final reply, run `python3 .agent/scripts/workflowctl.py route-resume`. Treat that receipt as the only root-task terminal decision: when `terminal=false`, do not present the root task as complete. Repository state preserves a deterministic resume contract, but only the host scheduler can start a later model turn.
"""
CURRENT_GATE_POLICY="Local user and current-chat evidence is advisory only and cannot authorize state or gate changes. Authoritative state and gate changes require a valid receipt from the configured provider-owned decision adapter, whose OS-protected sidecar binds the exact executable SHA-256 and protocol operations."
PREVIOUS_PROVIDER_GATE_POLICY="Local user and current-chat evidence is advisory only and cannot authorize state or gate changes. Authoritative state and gate changes require a valid receipt from the configured provider-owned decision adapter."
PREVIOUS_GATE_CLAIM="Without a provider decision adapter, local non-deploy fast/standard tasks may use explicitly recorded current-chat decisions. Projects may explicitly opt local, reversible and non-external release-mode implementation into the same boundary; test, production, deploy, irreversible and external-impact gates remain blocked."
PREVIOUS_BOOTSTRAP_BODY=BOOTSTRAP_BODY.replace(CURRENT_GATE_POLICY,PREVIOUS_GATE_CLAIM)
LEGACY_BOOTSTRAP=f"{BOOTSTRAP_START}\n{PREVIOUS_BOOTSTRAP_BODY.rstrip()}\n{BOOTSTRAP_END}\n"
PREVIOUS_VERSIONED_BOOTSTRAP=f"{BOOTSTRAP_START}\n<!-- agent-workflow-bootstrap:version=2 -->\n{PREVIOUS_BOOTSTRAP_BODY.rstrip()}\n{BOOTSTRAP_END}\n"
PREVIOUS_PROVIDER_BOOTSTRAP_BODY=BOOTSTRAP_BODY.replace(CURRENT_GATE_POLICY,PREVIOUS_PROVIDER_GATE_POLICY)
PREVIOUS_PROVIDER_VERSIONED_BOOTSTRAP=f"{BOOTSTRAP_START}\n<!-- agent-workflow-bootstrap:version=3 -->\n{PREVIOUS_PROVIDER_BOOTSTRAP_BODY.rstrip()}\n{BOOTSTRAP_END}\n"
LEGACY_BOOTSTRAPS={hashlib.sha256(value.encode()).hexdigest():value for value in (LEGACY_BOOTSTRAP,PREVIOUS_VERSIONED_BOOTSTRAP,PREVIOUS_PROVIDER_VERSIONED_BOOTSTRAP)}
BOOTSTRAP_VERSION_MARKER="<!-- agent-workflow-bootstrap:version=4 -->"
BOOTSTRAP=f"{BOOTSTRAP_START}\n{BOOTSTRAP_VERSION_MARKER}\n{BOOTSTRAP_BODY.rstrip()}\n{BOOTSTRAP_END}\n"
MAX_INSTALL_TREE_ENTRIES=100000
MAX_INSTALL_TREE_FILES=65536
MAX_INSTALL_TREE_DEPTH=64
MAX_INSTALL_FILE_BYTES=16*1024*1024


def open_installer_file(path,label="installer file"):
    value=Path(path); parent=open_directory_chain(value.parent)
    if parent is None: raise RuntimeError(f"{label} parent is missing: {value}")
    try: return os.open(value.name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=parent)
    except OSError as error: raise RuntimeError(f"{label} cannot be opened safely: {value}") from error
    finally: os.close(parent)


def sha(path):
    observed=os.lstat(path)
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1 or observed.st_size>MAX_INSTALL_FILE_BYTES:
        raise RuntimeError(f"installer file is unsafe or exceeds its byte limit: {path}")
    digest=hashlib.sha256(); size=0
    descriptor=open_installer_file(path)
    try:
        opened=os.fstat(descriptor)
        identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns,opened.st_mode,opened.st_uid,opened.st_nlink)
        if identity!=(observed.st_dev,observed.st_ino,observed.st_size,observed.st_mtime_ns,observed.st_ctime_ns,observed.st_mode,observed.st_uid,observed.st_nlink): raise RuntimeError(f"installer file changed while opening: {path}")
        while True:
            chunk=os.read(descriptor,min(1024*1024,MAX_INSTALL_FILE_BYTES-size+1))
            if not chunk: break
            size+=len(chunk)
            if size>MAX_INSTALL_FILE_BYTES: raise RuntimeError(f"installer file exceeds its byte limit: {path}")
            digest.update(chunk)
        after=os.fstat(descriptor)
        if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_mode,after.st_uid,after.st_nlink)!=identity or size!=opened.st_size:
            raise RuntimeError(f"installer file changed while hashing: {path}")
    finally: os.close(descriptor)
    return digest.hexdigest()


def read_installer_bytes(path,maximum=MAX_INSTALL_FILE_BYTES,label="installer file"):
    path=Path(path); observed=os.lstat(path)
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1 or observed.st_size<0 or observed.st_size>maximum:
        raise RuntimeError(f"{label} is unsafe or exceeds its byte limit: {path}")
    descriptor=open_installer_file(path,label); chunks=[]; total=0
    try:
        opened=os.fstat(descriptor); identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns,opened.st_mode,opened.st_nlink)
        if identity!=(observed.st_dev,observed.st_ino,observed.st_size,observed.st_mtime_ns,observed.st_ctime_ns,observed.st_mode,observed.st_nlink): raise RuntimeError(f"{label} changed while opening: {path}")
        while True:
            chunk=os.read(descriptor,min(1024*1024,maximum-total+1))
            if not chunk: break
            chunks.append(chunk); total+=len(chunk)
            if total>maximum: raise RuntimeError(f"{label} exceeds its byte limit: {path}")
        after=os.fstat(descriptor)
        if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_mode,after.st_nlink)!=identity or total!=opened.st_size:
            raise RuntimeError(f"{label} changed while reading: {path}")
    finally: os.close(descriptor)
    return b"".join(chunks)


def read_installer_text(path,maximum=MAX_INSTALL_FILE_BYTES,label="installer file"):
    return read_installer_bytes(path,maximum,label).decode("utf-8")


def bounded_directory_names(directory,label,maximum):
    names=[]
    try:
        with os.scandir(directory) as scanner:
            for entry in scanner:
                if len(names)>=maximum: raise RuntimeError(f"{label} entry limit exceeded")
                names.append(entry.name)
    except OSError as error: raise RuntimeError(f"{label} inventory failed") from error
    return names


def bounded_tree_entries(root,label):
    root=Path(root); root_metadata=os.lstat(root)
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode): raise RuntimeError(f"{label} root is unsafe")
    stack=[root]; entries_seen=0; files_seen=0
    while stack:
        directory=stack.pop()
        try:
            with os.scandir(directory) as scanner:
                batch=[]
                for entry in scanner:
                    entries_seen+=1
                    if entries_seen>MAX_INSTALL_TREE_ENTRIES: raise RuntimeError(f"{label} entry limit exceeded")
                    batch.append(entry)
        except OSError as error: raise RuntimeError(f"{label} traversal failed") from error
        for entry in sorted(batch,key=lambda item:os.fsencode(item.name),reverse=True):
            try: metadata=entry.stat(follow_symlinks=False)
            except OSError as error: raise RuntimeError(f"{label} entry became unreadable: {entry.path}") from error
            path=Path(entry.path)
            if len(path.relative_to(root).parts)>MAX_INSTALL_TREE_DEPTH: raise RuntimeError(f"{label} depth limit exceeded")
            if stat.S_ISDIR(metadata.st_mode): stack.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                files_seen+=1
                if files_seen>MAX_INSTALL_TREE_FILES: raise RuntimeError(f"{label} file limit exceeded")
            yield path,metadata


def files(root):
    result={}
    for name in MANAGED:
        path=root/name
        if path.is_file(): result[name]=sha(path)
        elif path.is_dir():
            for item,metadata in bounded_tree_entries(path,"managed source inventory"):
                if stat.S_ISREG(metadata.st_mode): result[str(item.relative_to(root))]=sha(item)
                elif stat.S_ISLNK(metadata.st_mode): raise RuntimeError(f"managed source contains a symlink: {item.relative_to(root)}")
    for name in MANAGED_FILES:
        path=root/name
        if path.is_file() and not path.is_symlink(): result[name]=sha(path)
    return result


def agent_root_mode(root):
    metadata=os.lstat(root)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError("installed .agent root must be a real directory")
    return stat.S_IMODE(metadata.st_mode)


def apply_agent_root_mode(root):
    descriptor=os.open(root,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
    try: os.fchmod(descriptor,AGENT_ROOT_MODE)
    finally: os.close(descriptor)


def managed_directory_modes(root):
    result={}
    for relative in MANAGED:
        base=root/relative
        if not base.is_dir() or base.is_symlink(): continue
        result[str(base.relative_to(root))]=stat.S_IMODE(os.lstat(base).st_mode)
        for item,metadata in bounded_tree_entries(base,"managed directory modes"):
            if stat.S_ISLNK(metadata.st_mode): raise RuntimeError(f"managed directory tree contains a symlink: {item.relative_to(root)}")
            if stat.S_ISDIR(metadata.st_mode): result[str(item.relative_to(root))]=stat.S_IMODE(metadata.st_mode)
    return result


def validate_managed_directory_modes(root):
    drift=sorted(relative for relative,mode in managed_directory_modes(root).items() if mode!=0o755)
    if drift: raise RuntimeError(f"managed source directories must use canonical mode 0755: {drift}")


def apply_managed_directory_modes(root):
    flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)
    for relative in managed_directory_modes(root):
        descriptor=os.open(root/relative,flags)
        try: os.fchmod(descriptor,0o755)
        finally: os.close(descriptor)


def file_modes(root,entries):
    result={}
    for relative in entries:
        path=root/relative
        metadata=os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"managed file mode source is not regular: {relative}")
        result[relative]=stat.S_IMODE(metadata.st_mode)
    return result


def portable_file_modes(root,entries):
    # Executable intent is managed content, never mutable checkout mode bits.
    inventory_path=root/"assets/managed-executables.json"
    try: inventory=json.loads(read_installer_text(inventory_path,label="installer inventory"))
    except (OSError,UnicodeError,json.JSONDecodeError) as error:
        raise RuntimeError("managed executable inventory is missing or invalid") from error
    paths=inventory.get("paths") if isinstance(inventory,dict) else None
    if (set(inventory or {})!={"schema","paths"} or inventory.get("schema")!="agent-managed-executable-inventory/v1"
            or not isinstance(paths,list) or paths!=sorted(set(paths))):
        raise RuntimeError("managed executable inventory has invalid fields or ordering")
    executable=set()
    for raw in paths:
        if not isinstance(raw,str) or not raw or Path(raw).is_absolute() or ".." in Path(raw).parts or raw not in entries:
            raise RuntimeError(f"managed executable inventory contains an unsafe or unknown path: {raw!r}")
        executable.add(raw)
    return {relative:(0o755 if relative in executable else 0o644) for relative in entries}


def apply_file_modes(root,modes):
    for relative,mode in modes.items():
        path=root/relative
        descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
        try:
            metadata=os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(f"managed mode target is not regular: {relative}")
            os.fchmod(descriptor,mode)
        finally: os.close(descriptor)


def assert_trusted_tree_entry(path,metadata,label):
    if metadata.st_uid not in {0,os.geteuid()} or stat.S_IMODE(metadata.st_mode)&0o022:
        raise RuntimeError(f"{label} is not owner-controlled: {path}")
    if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
        raise RuntimeError(f"{label} is hard-linked outside its trusted namespace: {path}")


def validate_private_tree(root):
    """Reject links, special files, and cross-user writable private state."""
    try: root_metadata=os.lstat(root)
    except FileNotFoundError as error: raise RuntimeError(f"private .agent tree is missing or unsafe: {root}") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise RuntimeError(f"private .agent tree is missing or unsafe: {root}")
    assert_trusted_tree_entry(root,root_metadata,"private .agent root")
    for path,metadata in bounded_tree_entries(root,"private agent validation"):
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError(f"private .agent tree contains a symlink: {path.relative_to(root)}")
        if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise RuntimeError(f"private .agent tree contains a special file: {path.relative_to(root)}")
        if stat.S_ISREG(metadata.st_mode) and metadata.st_size>MAX_INSTALL_FILE_BYTES:
            raise RuntimeError(f"private .agent file exceeds its byte limit: {path.relative_to(root)}")
        assert_trusted_tree_entry(path,metadata,"private .agent entry")


PRIVATE_COPY_MAX_ENTRIES=100000
PRIVATE_COPY_MAX_BYTES=1024*1024*1024
PRIVATE_COPY_MAX_DEPTH=64


def _private_copy_identity(metadata):
    return (metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_nlink,metadata.st_uid,metadata.st_gid,
            metadata.st_size,metadata.st_mtime_ns,metadata.st_ctime_ns)


def _open_path_entry(path,flags):
    """Open one path through retained no-follow parent descriptors."""
    absolute=Path(os.path.abspath(str(path)))
    parent_descriptor=open_directory_chain(absolute.parent)
    if parent_descriptor is None:
        raise RuntimeError(f"private copy parent is unavailable: {absolute.parent}")
    try:
        descriptor=os.open(absolute.name,flags,dir_fd=parent_descriptor)
    except Exception:
        os.close(parent_descriptor); raise
    return parent_descriptor,descriptor,absolute.name


def copy_private_tree(source,destination):
    """Capture a private tree using bounded descriptor-relative no-follow I/O."""
    directory_flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)
    file_flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)
    source_parent,source_descriptor,source_name=_open_path_entry(source,directory_flags)
    destination_absolute=Path(os.path.abspath(str(destination)))
    destination_parent=open_directory_chain(destination_absolute.parent)
    if destination_parent is None:
        os.close(source_descriptor); os.close(source_parent)
        raise RuntimeError(f"private copy destination parent is unavailable: {destination_absolute.parent}")
    counters={"entries":0,"bytes":0}

    def unchanged(descriptor,before,parent_descriptor,name,label):
        opened=os.fstat(descriptor)
        try: named=os.stat(name,dir_fd=parent_descriptor,follow_symlinks=False)
        except FileNotFoundError as error: raise RuntimeError(f"{label} disappeared during private capture") from error
        expected=_private_copy_identity(before)
        if _private_copy_identity(opened)!=expected or _private_copy_identity(named)!=expected:
            raise RuntimeError(f"{label} changed during private capture")
        return opened

    def copy_directory(source_fd,destination_fd,depth,label):
        if depth>PRIVATE_COPY_MAX_DEPTH:
            raise RuntimeError("private source tree exceeds its depth limit")
        before=os.fstat(source_fd)
        if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise RuntimeError(f"{label} is not a real directory")
        assert_trusted_tree_entry(Path(label),before,"private source entry")
        names=[]
        try:
            with os.scandir(source_fd) as entries:
                for entry in entries:
                    names.append(entry.name)
                    if counters["entries"]+len(names)>PRIVATE_COPY_MAX_ENTRIES:
                        raise RuntimeError("private source tree exceeds its entry limit")
            names.sort()
        except RuntimeError: raise
        except OSError as error: raise RuntimeError(f"{label} could not be enumerated safely") from error
        for name in names:
            if not isinstance(name,str) or not name or name in {".",".."} or "/" in name:
                raise RuntimeError(f"{label} contains an unsafe entry name")
            counters["entries"]+=1
            if counters["entries"]>PRIVATE_COPY_MAX_ENTRIES:
                raise RuntimeError("private source tree exceeds its entry limit")
            entry_label=f"{label}/{name}"
            try: planned=os.stat(name,dir_fd=source_fd,follow_symlinks=False)
            except FileNotFoundError as error: raise RuntimeError(f"{entry_label} disappeared during private capture") from error
            if stat.S_ISLNK(planned.st_mode):
                raise RuntimeError(f"private source tree contains a symlink: {entry_label}")
            assert_trusted_tree_entry(Path(entry_label),planned,"private source entry")
            if stat.S_ISDIR(planned.st_mode):
                child_source=os.open(name,directory_flags,dir_fd=source_fd)
                try:
                    if _private_copy_identity(os.fstat(child_source))!=_private_copy_identity(planned):
                        raise RuntimeError(f"{entry_label} changed while opening")
                    os.mkdir(name,0o700,dir_fd=destination_fd)
                    child_destination=os.open(name,directory_flags,dir_fd=destination_fd)
                    try: copy_directory(child_source,child_destination,depth+1,entry_label)
                    finally: os.close(child_destination)
                    unchanged(child_source,planned,source_fd,name,entry_label)
                finally: os.close(child_source)
                target=os.open(name,directory_flags,dir_fd=destination_fd)
                try: os.fchmod(target,stat.S_IMODE(planned.st_mode))
                finally: os.close(target)
            elif stat.S_ISREG(planned.st_mode):
                if planned.st_nlink!=1:
                    raise RuntimeError(f"private source tree contains a hard-linked file: {entry_label}")
                child_source=os.open(name,file_flags,dir_fd=source_fd)
                try:
                    if _private_copy_identity(os.fstat(child_source))!=_private_copy_identity(planned):
                        raise RuntimeError(f"{entry_label} changed while opening")
                    child_destination=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=destination_fd)
                    try:
                        copied=0
                        while True:
                            chunk=os.read(child_source,1024*1024)
                            if not chunk: break
                            copied+=len(chunk); counters["bytes"]+=len(chunk)
                            if copied>planned.st_size or counters["bytes"]>PRIVATE_COPY_MAX_BYTES:
                                raise RuntimeError("private source tree exceeds its byte limit or changed size")
                            offset=0
                            while offset<len(chunk): offset+=os.write(child_destination,chunk[offset:])
                        if copied!=planned.st_size:
                            raise RuntimeError(f"{entry_label} changed size during private capture")
                        os.fsync(child_destination); os.fchmod(child_destination,stat.S_IMODE(planned.st_mode))
                    finally: os.close(child_destination)
                    unchanged(child_source,planned,source_fd,name,entry_label)
                finally: os.close(child_source)
            else:
                raise RuntimeError(f"private source tree contains a special file: {entry_label}")
        after=os.fstat(source_fd)
        if _private_copy_identity(after)!=_private_copy_identity(before):
            raise RuntimeError(f"{label} changed during private capture")

    created=False; created_identity=None; destination_descriptor=None
    try:
        source_before=os.fstat(source_descriptor)
        os.mkdir(destination_absolute.name,0o700,dir_fd=destination_parent); created=True
        destination_descriptor=os.open(destination_absolute.name,directory_flags,dir_fd=destination_parent)
        created_identity=inode_identity(os.fstat(destination_descriptor))
        copy_directory(source_descriptor,destination_descriptor,0,str(Path(source_name)))
        os.fchmod(destination_descriptor,stat.S_IMODE(source_before.st_mode)); os.fsync(destination_descriptor)
        unchanged(source_descriptor,source_before,source_parent,source_name,"private source root")
        named_destination=os.stat(destination_absolute.name,dir_fd=destination_parent,follow_symlinks=False)
        if inode_identity(named_destination)!=created_identity or inode_identity(os.fstat(destination_descriptor))!=created_identity:
            raise RuntimeError("private copy destination changed before handoff")
    except Exception:
        if created and created_identity is not None:
            try: named=os.stat(destination_absolute.name,dir_fd=destination_parent,follow_symlinks=False)
            except OSError: named=None
            if named is not None and inode_identity(named)==created_identity:
                try: shutil.rmtree(destination_absolute)
                except OSError: pass
        raise
    finally:
        if destination_descriptor is not None: os.close(destination_descriptor)
        os.close(destination_parent); os.close(source_descriptor); os.close(source_parent)
    final_destination=os.lstat(destination_absolute)
    if inode_identity(final_destination)!=created_identity:
        raise RuntimeError("private copy destination changed during handoff")
    validate_private_tree(destination_absolute)
    if inode_identity(os.lstat(destination_absolute))!=created_identity:
        raise RuntimeError("private copy destination changed during validation")


def validate_managed_source(root):
    """Validate only release-managed inputs; source-private state is irrelevant."""
    try: root_metadata=os.lstat(root)
    except FileNotFoundError as error: raise RuntimeError(f"managed .agent tree is missing or unsafe: {root}") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise RuntimeError(f"managed .agent tree is missing or unsafe: {root}")
    assert_trusted_tree_entry(root,root_metadata,"managed source root")
    for relative in (*MANAGED,*MANAGED_FILES):
        path=root/relative
        if not path.exists() and not path.is_symlink():
            if relative in MANAGED_FILES:
                raise RuntimeError(f"required managed source file is missing: {relative}")
            continue
        if path.is_symlink():
            raise RuntimeError(f"managed source contains a symlink: {relative}")
        assert_trusted_tree_entry(path,os.lstat(path),"managed source entry")
        if path.is_dir():
            for item,metadata in bounded_tree_entries(path,"managed source validation"):
                mode=metadata.st_mode
                if stat.S_ISLNK(mode): raise RuntimeError(f"managed source contains a symlink: {item.relative_to(root)}")
                if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise RuntimeError(f"managed source contains a special file: {item.relative_to(root)}")
                if stat.S_ISREG(mode) and metadata.st_size>MAX_INSTALL_FILE_BYTES:
                    raise RuntimeError(f"managed source file exceeds its byte limit: {item.relative_to(root)}")
                assert_trusted_tree_entry(item,metadata,"managed source entry")
        elif not path.is_file():
            raise RuntimeError(f"managed source contains a special file: {relative}")
        elif os.lstat(path).st_size>MAX_INSTALL_FILE_BYTES:
            raise RuntimeError(f"managed source file exceeds its byte limit: {relative}")


def fresh_state_seed(source):
    """Return the content-addressed release seed, never source project state."""
    root=source/FRESH_STATE_RELATIVE; manifest_path=root/"manifest.json"
    if root.is_symlink() or not root.is_dir() or manifest_path.is_symlink() or not manifest_path.is_file():
        raise RuntimeError("canonical fresh-state seed is missing or unsafe")
    try: value=json.loads(read_installer_text(manifest_path,label="installer manifest"))
    except (OSError,UnicodeError,json.JSONDecodeError) as error:
        raise RuntimeError("canonical fresh-state seed manifest is invalid") from error
    if not isinstance(value,dict) or set(value)!={"schema","seed_sha256","files"} or value.get("schema")!="agent-workflow-fresh-state-seed/v1" or not isinstance(value.get("files"),dict):
        raise RuntimeError("canonical fresh-state seed manifest has invalid fields")
    observed={}
    for item,metadata in bounded_tree_entries(root,"canonical fresh-state seed"):
        if stat.S_ISLNK(metadata.st_mode): raise RuntimeError(f"canonical fresh-state seed contains a symlink: {item.relative_to(root)}")
        if stat.S_ISDIR(metadata.st_mode): continue
        if not stat.S_ISREG(metadata.st_mode): raise RuntimeError(f"canonical fresh-state seed contains a special file: {item.relative_to(root)}")
        relative=str(item.relative_to(root))
        if relative!="manifest.json": observed[relative]=sha(item)
    if observed!=value["files"] or value.get("seed_sha256")!=tree_sha256(value["files"]):
        raise RuntimeError("canonical fresh-state seed content does not match its manifest")
    if set(observed)!=FRESH_STATE_ALLOWED:
        missing=sorted(FRESH_STATE_ALLOWED-set(observed)); extra=sorted(set(observed)-FRESH_STATE_ALLOWED)
        raise RuntimeError(f"canonical fresh-state seed inventory differs from the exact allowlist: missing={missing} extra={extra}")
    config=json.loads(read_installer_text(root/"config.json",label="installed config"))
    task=json.loads(read_installer_text(root/"state/TASK.json",label="installed task"))
    agents=json.loads(read_installer_text(root/"state/agents.json",label="installed ledger"))
    context=json.loads(read_installer_text(root/"state/CONTEXT.json",label="installed context")); checkpoint=context.get("checkpoint",{})
    usage=context.get("usage_freshness",{})
    if (checkpoint.get("sequence")!=1 or checkpoint.get("reason")!="template-genesis"
            or checkpoint.get("previous_sha256")!="none" or checkpoint.get("previous_task_invariant_sha256")!="none"
            or checkpoint.get("task_delta")!=["initial_canonical_task_state"] or usage.get("checkpoint_sequence")!=1):
        raise RuntimeError("canonical fresh-state context must be a genesis-only seed")
    if (
        config.get("project")!={"name":"__PROJECT_NAME__","type":"__PROJECT_TYPE__"}
        or config.get("guardrails_ready") is not False
        or config.get("project_initialization") is not None
        or config.get("agent_control",{}).get("default_model") is not None
        or agents.get("default_model") is not None
        or config.get("agent_control",{}).get("human_decision_observer",{}).get("signed_adapter") is not None
        or config.get("agent_control",{}).get("provider_preflight_observer",{}).get("signed_adapter") is not None
        or task.get("status")!="idle" or task.get("requirements_clarified") is not False
        or task.get("decision_policy_version")!=1
        or task.get("task_generation_id")!="idle-template-v4"
        or not existing_skill_activation_valid(root,task)
        or task.get("requirement_source")!="pending" or task.get("current_node")!="idle"
        or agents.get("schema")!="agent-team/v9"
        or any(agents.get(name)!=[] for name in ("members","prepared_dispatches","capacity_failures","replay_runs"))
        or agents.get("migration_source") is not None or agents.get("last_platform_snapshot") is not None
    ):
        raise RuntimeError("canonical fresh-state seed is not an isolated uninitialized project")
    guardrails=read_installer_text(root/"policies/PROJECT_GUARDRAILS.md",label="installed guardrails")
    if "agent-workflow-project-guardrails:v1 uninitialized" not in guardrails:
        raise RuntimeError("canonical fresh-state seed lacks the uninitialized guardrails marker")
    return root


def copy_managed_fresh_install(source,destination):
    """Build a project from managed release files plus the immutable seed."""
    destination.mkdir(mode=AGENT_ROOT_MODE,parents=True,exist_ok=False)
    apply_agent_root_mode(destination)
    for relative in MANAGED:
        origin=source/relative; target=destination/relative
        if origin.is_dir(): shutil.copytree(origin,target,symlinks=True)
        elif origin.is_file(): target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(origin,target)
    for relative in MANAGED_FILES:
        origin=source/relative
        if origin.is_file():
            target=destination/relative; target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(origin,target)
    seed=fresh_state_seed(source)
    shutil.copy2(seed/"config.json",destination/"config.json")
    shutil.copytree(seed/"policies",destination/"policies",symlinks=True)
    shutil.copytree(seed/"state",destination/"state",symlinks=True)
    (destination/"state/.scheduler-receipt-nonces.json").chmod(0o600)
    validate_private_tree(destination)
    apply_file_modes(destination,portable_file_modes(source,files(source)))
    apply_managed_directory_modes(destination)


def tree_sha256(entries):
    payload=json.dumps(entries,sort_keys=True,separators=(",",":")).encode()
    return hashlib.sha256(payload).hexdigest()


def canonical_sha256(value):
    payload=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return hashlib.sha256(payload).hexdigest()


def version_triplet(value):
    if not isinstance(value,str): return None
    if re.fullmatch(r"(?:0|[1-9][0-9]{0,9})\.(?:0|[1-9][0-9]{0,9})\.(?:0|[1-9][0-9]{0,9})",value) is None: return None
    parts=value.split(".")
    return tuple(int(part) for part in parts)


MAX_MANIFEST_NUMBER=2**31-1
RELEASED_MANIFEST_METADATA={
    "agent-workflow-install/v1":{("3.1.40",32)},
    "agent-workflow-install/v3":{("3.1.41",34)},
    "agent-workflow-install/v4":{("3.1.42",35),("3.1.43",36),("3.1.46",38),("3.1.48",39),("3.2.0",40)},
    "agent-workflow-install/v5":{("4.0.0",42),(VERSION,MIGRATION_VERSION)},
}


def validated_manifest_metadata(value,schema):
    version=value.get("version")
    parsed=version_triplet(version)
    if (parsed is None or any(component>MAX_MANIFEST_NUMBER for component in parsed)
            or parsed[0]<1 or any(str(component)!=raw for component,raw in zip(parsed,version.split(".")))):
        raise SystemExit(f"workflow install manifest version is malformed or unsupported: {version!r}")
    migration=value.get("migration_version")
    if type(migration) is not int or not 0<=migration<=MAX_MANIFEST_NUMBER:
        raise SystemExit(f"workflow install manifest migration version is missing, malformed, or out of range: {migration!r}")
    released=RELEASED_MANIFEST_METADATA.get(schema)
    if released is None or (version,migration) not in released:
        raise SystemExit(f"workflow install manifest schema/version/migration combination is not a supported release: {schema!r}/{version!r}/{migration!r}")
    return {"schema":schema,"version":version,"migration_version":migration}


def version_relation(installed,current):
    """Compare strict numeric versions and reject unknown installed syntax."""
    left,right=version_triplet(installed),version_triplet(current)
    if left is None: return "invalid_installed"
    if right is None: raise RuntimeError("template workflow version is invalid")
    if left>right: return "target_newer"
    if left<right: return "target_older"
    return "same"


def repo_plugin_files(root):
    try: root_metadata=os.lstat(root)
    except OSError as error: raise RuntimeError(f"repo plugin is missing or unsafe: {root}") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise RuntimeError(f"repo plugin is missing or unsafe: {root}")
    assert_trusted_tree_entry(root,root_metadata,"repo plugin root")
    result={}
    for item,metadata in bounded_tree_entries(root,"repo plugin"):
        if stat.S_ISLNK(metadata.st_mode): raise RuntimeError(f"repo plugin contains a symlink: {item}")
        if stat.S_ISDIR(metadata.st_mode):
            assert_trusted_tree_entry(item,metadata,"repo plugin directory")
        elif stat.S_ISREG(metadata.st_mode):
            assert_trusted_tree_entry(item,metadata,"repo plugin file")
            result[str(item.relative_to(root))]=sha(item)
        else: raise RuntimeError(f"repo plugin contains a special file: {item}")
    if not result: raise RuntimeError("repo plugin is empty")
    return result


def read_marketplace(path,required=True):
    """Read an optional marketplace through descriptor-rooted no-follow authority."""
    parent=open_directory_chain(path.parent)
    if parent is None:
        if required: raise RuntimeError(f"marketplace is missing or invalid: {path}")
        return None
    try:
        try: descriptor=os.open(path.name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0),dir_fd=parent)
        except FileNotFoundError:
            if required: raise RuntimeError(f"marketplace is missing or invalid: {path}")
            return None
        except OSError as error:
            raise RuntimeError(f"marketplace is missing or unsafe: {path}") from error
        try:
            opened=os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1 or opened.st_size>2*1024*1024
                    or opened.st_uid!=os.geteuid() or stat.S_IMODE(opened.st_mode)&0o022):
                raise RuntimeError(f"marketplace is not a bounded owner-controlled single-link regular file: {path}")
            chunks=[]; remaining=opened.st_size
            while remaining:
                chunk=os.read(descriptor,min(65536,remaining))
                if not chunk: raise RuntimeError(f"marketplace was truncated while reading: {path}")
                chunks.append(chunk); remaining-=len(chunk)
            if os.read(descriptor,1): raise RuntimeError(f"marketplace grew while reading: {path}")
            raw=b"".join(chunks)
            after=os.fstat(descriptor)
            if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,stat.S_IMODE(after.st_mode))!=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,stat.S_IMODE(opened.st_mode)):
                raise RuntimeError(f"marketplace changed while reading: {path}")
        finally: os.close(descriptor)
    finally: os.close(parent)
    try: value=json.loads(raw)
    except (UnicodeError,json.JSONDecodeError) as error: raise RuntimeError(f"marketplace is missing or invalid: {path}") from error
    if not isinstance(value,dict) or not isinstance(value.get("plugins"),list):
        raise RuntimeError(f"marketplace has no plugins list: {path}")
    if any(not isinstance(item,dict) or not isinstance(item.get("name"),str) for item in value["plugins"]):
        raise RuntimeError(f"marketplace contains an invalid plugin entry: {path}")
    return value


def named_marketplace_entry(value,name=PLUGIN_NAME,required=True):
    entries=[item for item in value["plugins"] if item.get("name")==name]
    if len(entries)>1: raise RuntimeError(f"marketplace contains duplicate {name} entries")
    if not entries:
        if required: raise RuntimeError(f"marketplace is missing {name}")
        return None
    return entries[0]


def previous_pxpipe_ownership(installed):
    if not isinstance(installed,dict): return {},None
    schema=installed.get("schema")
    if schema in {"agent-workflow-install/v2","agent-workflow-install/v3","agent-workflow-install/v4"}:
        return installed.get("repo_plugin_files",{}),installed.get("marketplace_entry",{}).get("sha256")
    if schema=="agent-workflow-install/v5":
        binding=installed.get("pxpipe",{})
        return binding.get("files",{}),binding.get("marketplace_entry_sha256")
    return {},None


def _secure_global_file(path,include_bytes=False):
    """Return an exact descriptor-relative no-follow record and optional bounded bytes."""
    path=Path(path); parent=open_directory_chain(path.parent)
    if parent is None: return ({"kind":"absent"},None) if include_bytes else {"kind":"absent"}
    try:
        try: before=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError: return ({"kind":"absent"},None) if include_bytes else {"kind":"absent"}
        if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_nlink!=1
                or before.st_uid!=os.geteuid() or stat.S_IMODE(before.st_mode)&0o022
                or before.st_size>GLOBAL_PXPIPE_MAX_BYTES):
            raise RuntimeError(f"unsafe global pxpipe artifact: {path}")
        descriptor=os.open(path.name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=parent)
        try:
            opened=os.fstat(descriptor); chunks=[]; remaining=GLOBAL_PXPIPE_MAX_BYTES+1
            while remaining:
                chunk=os.read(descriptor,min(1024*1024,remaining))
                if not chunk: break
                chunks.append(chunk); remaining-=len(chunk)
            raw=b"".join(chunks); after=os.fstat(descriptor)
        finally: os.close(descriptor)
        identity=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_mode,opened.st_uid,opened.st_nlink)
        if identity!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_mode,after.st_uid,after.st_nlink) or len(raw)!=opened.st_size:
            raise RuntimeError(f"global pxpipe artifact changed while reading: {path}")
        try: named_after=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError as error: raise RuntimeError(f"global pxpipe artifact disappeared while reading: {path}") from error
        if inode_identity(named_after)!=inode_identity(opened):
            raise RuntimeError(f"global pxpipe artifact pathname changed while reading: {path}")
        rebound=open_directory_chain(path.parent)
        if rebound is None: raise RuntimeError(f"global pxpipe parent disappeared while reading: {path}")
        try:
            if inode_identity(os.fstat(rebound))!=inode_identity(os.fstat(parent)):
                raise RuntimeError(f"global pxpipe parent changed while reading: {path}")
        finally: os.close(rebound)
        record={"kind":"present","dev":opened.st_dev,"ino":opened.st_ino,"bytes":len(raw),
                "mode":stat.S_IMODE(opened.st_mode),"uid":opened.st_uid,"sha256":hashlib.sha256(raw).hexdigest()}
        return (record,raw) if include_bytes else record
    finally: os.close(parent)


def _global_pxpipe_paths():
    home=Path(os.path.expanduser("~"))
    if not home.is_absolute(): raise RuntimeError("HOME does not resolve to an absolute path")
    state=home/".pxpipe"; label="com.pxpipe.codex-default"
    return {
        "codex_config":home/".codex/config.toml",
        "config_state":state/"codex-default.json",
        "config_backup":state/"codex-default.json.config-before",
        "dashboard_token":state/"dashboard-token",
        "ownership":state/"codex-default-install.json",
        "plist":home/"Library/LaunchAgents"/f"{label}.plist",
        "prior_plist":state/"codex-default.plist-before",
        "prior_absent":state/"codex-default.plist-absent-before",
        "recovery":state/"codex-default-uninstall-recovery.json",
        "token_staged":state/"dashboard-token.pxpipe-uninstall-staged",
        "plist_staged":home/"Library/LaunchAgents"/f"{label}.plist.pxpipe-uninstall-staged",
        "ownership_staged":state/"codex-default-install.json.pxpipe-uninstall-staged",
        "prior_plist_staged":state/"codex-default.plist-before.pxpipe-uninstall-staged",
        "prior_absent_staged":state/"codex-default.plist-absent-before.pxpipe-uninstall-staged",
    }


def _observe_pxpipe_service_absence(listener_port=None):
    # Linux has no LaunchAgent domain.  On Darwin an unreadable domain is
    # unknown, not absence.  The loopback bind independently proves no TCP
    # listener owns the retired default endpoint at this instant.
    if platform.system()=="Darwin":
        domain=f"gui/{os.geteuid()}"; label="com.pxpipe.codex-default"
        service=run_installer_command(["/bin/launchctl","print",f"{domain}/{label}"],timeout=10,output_limit=64*1024)
        if service.returncode==0: return False
        domain_probe=run_installer_command(["/bin/launchctl","print",domain],timeout=10,output_limit=16*1024*1024)
        if domain_probe.returncode!=0: raise RuntimeError("cannot observe the LaunchAgent domain")
    if listener_port is None: return True
    if type(listener_port) is not int or not 1<=listener_port<=65535: raise RuntimeError("pxpipe listener identity has an invalid port")
    probe=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        try: probe.bind(("127.0.0.1",listener_port))
        except OSError: return False
    finally: probe.close()
    return True


def _global_pxpipe_state():
    return {name:_secure_global_file(path) for name,path in _global_pxpipe_paths().items()}


def _global_pxpipe_marker_records_absent(state):
    return all(record=={"kind":"absent"} for name,record in state.items() if name!="codex_config")


def _expected_codex_config_record(record):
    if record=={"kind":"absent"}: return record
    return {"kind":"present","bytes":record["bytes"],"mode":record["mode"],"sha256":record["sha256"]}


def _validate_markerless_codex_config(record):
    observed,raw=_secure_global_file(_global_pxpipe_paths()["codex_config"],include_bytes=True)
    if observed!=record:
        raise RuntimeError("markerless global Codex config changed during pxpipe retirement planning")
    if raw is not None and re.search(rb"(?i)(?:pxpipe|127\.0\.0\.1:47821)",raw):
        raise RuntimeError("markerless Codex config still references pxpipe and cannot be retired safely")
    return _expected_codex_config_record(record)


def _expected_restored_codex_config(pre_state):
    """Authenticate the helper state and return the exact original config result."""
    paths=_global_pxpipe_paths()
    state_record,state_raw=_secure_global_file(paths["config_state"],include_bytes=True)
    backup_record,backup_raw=_secure_global_file(paths["config_backup"],include_bytes=True)
    if state_record!=pre_state["config_state"] or backup_record!=pre_state["config_backup"]:
        raise RuntimeError("global pxpipe config state changed during retirement planning")
    if state_raw is None or backup_raw is None:
        raise RuntimeError("global pxpipe config restoration evidence is incomplete")
    try: value=json.loads(state_raw)
    except (UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("global pxpipe Codex state is malformed") from error
    fields={"schema","config","backup","configExisted","beforeSha256","managedSha256","providerName","baseUrl"}
    expected_config=str(paths["codex_config"].resolve()); expected_backup=str(paths["config_backup"].resolve())
    if (not isinstance(value,dict) or set(value)!=fields or value.get("schema")!="pxpipe-codex-default/v2"
            or value.get("providerName")!="pxpipe" or value.get("config")!=expected_config
            or value.get("backup")!=expected_backup or type(value.get("configExisted")) is not bool
            or re.fullmatch(r"http://127\.0\.0\.1:(?:[1-9][0-9]{0,4})/v1",str(value.get("baseUrl",""))) is None
            or re.fullmatch(r"[0-9a-f]{64}",str(value.get("beforeSha256",""))) is None
            or re.fullmatch(r"[0-9a-f]{64}",str(value.get("managedSha256",""))) is None
            or value["beforeSha256"]!=hashlib.sha256(backup_raw).hexdigest()
            or pre_state["codex_config"].get("sha256")!=value["managedSha256"]
            or any(pre_state[name].get("mode")!=0o600 for name in ("codex_config","config_state","config_backup"))
            or (not value["configExisted"] and backup_raw!=b"")):
        raise RuntimeError("global pxpipe Codex state does not authenticate exact config restoration")
    if not 1<=int(value["baseUrl"].split(":")[2].split("/")[0])<=65535:
        raise RuntimeError("global pxpipe Codex state has an invalid loopback port")
    expected=({"kind":"present","bytes":len(backup_raw),"mode":0o600,"sha256":hashlib.sha256(backup_raw).hexdigest()}
            if value["configExisted"] else {"kind":"absent"})
    return expected,int(value["baseUrl"].split(":")[2].split("/")[0])


def _global_pxpipe_terminal_records(state,expected_codex_config):
    if not _global_pxpipe_marker_records_absent(state): return False
    current=state.get("codex_config")
    if expected_codex_config=={"kind":"absent"}: return current=={"kind":"absent"}
    return (isinstance(current,dict) and current.get("kind")=="present"
            and all(current.get(key)==expected_codex_config[key] for key in ("bytes","mode","sha256")))


def _global_pxpipe_absent(state,expected_codex_config=None,listener_port=None):
    expected=expected_codex_config if expected_codex_config is not None else _expected_codex_config_record(state["codex_config"])
    return _global_pxpipe_terminal_records(state,expected) and _observe_pxpipe_service_absence(listener_port)


def _validate_global_pxpipe_live_set(state):
    required={"codex_config","config_state","config_backup","dashboard_token","ownership","plist"}
    if any(state[name]["kind"]!="present" for name in required):
        raise RuntimeError("global pxpipe state is missing a required authenticated artifact")
    if (state["prior_plist"]["kind"]=="present") == (state["prior_absent"]["kind"]=="present"):
        raise RuntimeError("global pxpipe prior plist markers are incomplete or ambiguous")
    for name in ("recovery","token_staged","plist_staged","ownership_staged","prior_plist_staged","prior_absent_staged"):
        if state[name]["kind"]!="absent": raise RuntimeError("global pxpipe state contains an incomplete uninstall")


def _project_root_identity(target):
    observed=os.lstat(target)
    if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode): raise RuntimeError("project root identity is unsafe")
    return {"path":os.path.realpath(str(target)),"dev":observed.st_dev,"ino":observed.st_ino}




def _ensure_private_directory(path):
    path=Path(path)
    if path.exists() or path.is_symlink():
        descriptor=open_transaction_directory(path,"global pxpipe retirement evidence directory"); os.close(descriptor); return
    parent=open_transaction_directory(path.parent,"global pxpipe retirement evidence parent")
    try:
        try: os.mkdir(path.name,0o700,dir_fd=parent); os.fsync(parent)
        except FileExistsError: pass
        flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)
        child=os.open(path.name,flags,dir_fd=parent)
        try:
            observed=os.fstat(child); expected_uid=os.geteuid() if hasattr(os,"geteuid") else observed.st_uid
            if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid!=expected_uid
                    or stat.S_IMODE(observed.st_mode)&(stat.S_IWGRP|stat.S_IWOTH)):
                raise RuntimeError("global pxpipe retirement evidence directory is unsafe")
        finally: os.close(child)
    finally: os.close(parent)


def _private_json(path,value,create=False):
    path=Path(path); parent=open_transaction_directory(path.parent,"global pxpipe retirement evidence parent")
    raw=(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
    temporary=f".{path.name}.{uuid.uuid4().hex}"
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=parent)
    try:
        offset=0
        while offset<len(raw): offset+=os.write(descriptor,raw[offset:])
        os.fsync(descriptor)
    finally: os.close(descriptor)
    try:
        if create:
            os.link(temporary,path.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
            os.unlink(temporary,dir_fd=parent)
        else:
            os.replace(temporary,path.name,src_dir_fd=parent,dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try: os.unlink(temporary,dir_fd=parent)
        except FileNotFoundError: pass
        os.close(parent)


def _load_bound_private_json(path,schema):
    record=_secure_global_file(path)
    if record["kind"]!="present" or record["mode"]!=0o600: raise RuntimeError(f"missing or unsafe {schema}")
    parent=open_directory_chain(Path(path).parent)
    if parent is None: raise RuntimeError(f"missing {schema}")
    try: descriptor=os.open(Path(path).name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=parent)
    finally: os.close(parent)
    try:
        opened=os.fstat(descriptor); chunks=[]; remaining=GLOBAL_PXPIPE_MAX_BYTES+1
        while remaining:
            chunk=os.read(descriptor,min(1024*1024,remaining))
            if not chunk: break
            chunks.append(chunk); remaining-=len(chunk)
        raw=b"".join(chunks)
    finally: os.close(descriptor)
    if (opened.st_dev!=record["dev"] or opened.st_ino!=record["ino"] or len(raw)!=record["bytes"]
            or hashlib.sha256(raw).hexdigest()!=record["sha256"]):
        raise RuntimeError(f"{schema} changed during authenticated read")
    try: value=json.loads(raw)
    except (UnicodeError,json.JSONDecodeError) as error: raise RuntimeError(f"malformed {schema}") from error
    if not isinstance(value,dict) or value.get("schema")!=schema: raise RuntimeError(f"invalid {schema}")
    digest=value.get("record_sha256"); payload={key:item for key,item in value.items() if key!="record_sha256"}
    if digest!=canonical_sha256(payload): raise RuntimeError(f"unauthenticated {schema}")
    return value



def _unlink_bound_private_json(path,expected):
    snapshot=planned_path_snapshot(path,include_bytes=True); parent=open_transaction_directory(Path(path).parent,"private retirement record parent")
    try:
        try: observed=json.loads(snapshot["bytes"])
        except (UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("private retirement record changed before removal") from error
        if observed!=expected: raise RuntimeError("private retirement record changed before removal")
        temporary=f".{Path(path).name}.remove-{uuid.uuid4().hex}"
        os.replace(Path(path).name,temporary,src_dir_fd=parent,dst_dir_fd=parent)
        moved=os.stat(temporary,dir_fd=parent,follow_symlinks=False)
        if {"dev":moved.st_dev,"ino":moved.st_ino,"mode":stat.S_IFMT(moved.st_mode)}!=snapshot["identity"]:
            try: os.replace(temporary,Path(path).name,src_dir_fd=parent,dst_dir_fd=parent)
            finally: raise RuntimeError("private retirement record leaf raced during removal")
        os.unlink(temporary,dir_fd=parent); os.fsync(parent)
    finally: os.close(parent)


def _validate_global_pxpipe_snapshot(value,label):
    if not isinstance(value,dict) or set(value)!=set(_global_pxpipe_paths()):
        raise RuntimeError(f"{label} does not cover the exact global pxpipe artifact set")
    for name,record in value.items():
        if record=={"kind":"absent"}: continue
        if (not isinstance(record,dict) or set(record)!={"kind","dev","ino","bytes","mode","uid","sha256"}
                or record.get("kind")!="present"
                or any(type(record.get(key)) is not int or record[key]<0 for key in ("dev","ino","bytes","mode","uid"))
                or record["bytes"]>GLOBAL_PXPIPE_MAX_BYTES or record["mode"]>0o777
                or record["mode"]&0o022 or re.fullmatch(r"[0-9a-f]{64}",str(record.get("sha256") or "")) is None):
            raise RuntimeError(f"{label} contains an invalid exact record for {name}")
    return value


def _validate_expected_codex_config(value):
    if value=={"kind":"absent"}: return value
    if (not isinstance(value,dict) or set(value)!={"kind","bytes","mode","sha256"} or value.get("kind")!="present"
            or type(value.get("bytes")) is not int or not 0<=value["bytes"]<=GLOBAL_PXPIPE_MAX_BYTES
            or type(value.get("mode")) is not int or not 0<=value["mode"]<=0o777 or value["mode"]&0o022
            or re.fullmatch(r"[0-9a-f]{64}",str(value.get("sha256",""))) is None):
        raise RuntimeError("global pxpipe expected Codex config record is invalid")
    return value


def _validate_expected_codex_config_binding(pre_state,expected):
    if _global_pxpipe_marker_records_absent(pre_state):
        if expected!=_expected_codex_config_record(pre_state["codex_config"]):
            raise RuntimeError("global pxpipe expected unchanged Codex config differs from pre-state")
        return
    backup=pre_state.get("config_backup",{})
    if expected=={"kind":"absent"}:
        if backup.get("kind")!="present" or backup.get("bytes")!=0 or backup.get("sha256")!=hashlib.sha256(b"").hexdigest():
            raise RuntimeError("global pxpipe expected absent Codex config lacks empty original evidence")
    elif (backup.get("kind")!="present" or any(expected.get(key)!=backup.get(key) for key in ("bytes","sha256"))
          or expected.get("mode")!=0o600):
        raise RuntimeError("global pxpipe expected restored Codex config differs from captured backup")


def _validate_pxpipe_retirement_document(value,binding,kind):
    common={"schema",*binding,"pre_state","expected_codex_config","listener_port","record_sha256"}
    if kind=="intent":
        expected=common|{"phase"}; schema="agent-global-pxpipe-retirement-intent/v1"
        if set(value)!=expected or value.get("phase")!="prepared": raise RuntimeError("invalid global pxpipe retirement intent fields")
    else:
        expected=common|{"post_state","terminal"}; schema="agent-global-pxpipe-retirement-receipt/v1"
        if set(value)!=expected or value.get("terminal") is not True: raise RuntimeError("invalid global pxpipe retirement receipt fields")
        post=_validate_global_pxpipe_snapshot(value.get("post_state"),"global pxpipe retirement post-state")
        expected_config=_validate_expected_codex_config(value.get("expected_codex_config"))
        if not _global_pxpipe_terminal_records(post,expected_config): raise RuntimeError("global pxpipe retirement receipt post-state is not terminal")
    if value.get("schema")!=schema or any(value.get(key)!=item for key,item in binding.items()):
        raise RuntimeError(f"global pxpipe retirement {kind} binding mismatch")
    pre=_validate_global_pxpipe_snapshot(value.get("pre_state"),"global pxpipe retirement pre-state")
    expected_config=_validate_expected_codex_config(value.get("expected_codex_config"))
    _validate_expected_codex_config_binding(pre,expected_config)
    listener_port=value.get("listener_port")
    if (_global_pxpipe_marker_records_absent(pre) and listener_port!=47821) or (not _global_pxpipe_marker_records_absent(pre) and (type(listener_port) is not int or not 1<=listener_port<=65535)):
        raise RuntimeError("global pxpipe retirement listener port binding is invalid")
    return value


@contextlib.contextmanager
def global_pxpipe_retirement_lock():
    if fcntl is None: raise RuntimeError("global pxpipe retirement requires POSIX flock")
    state=_global_pxpipe_paths()["ownership"].parent; home=state.parent
    home_fd=open_directory_chain(home)
    if home_fd is None: raise RuntimeError("global pxpipe HOME is missing")
    state_fd=None; descriptor=None
    try:
        assert_trusted_directory_descriptor(home_fd,"global pxpipe HOME")
        flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)
        try: state_fd=os.open(state.name,flags,dir_fd=home_fd)
        except FileNotFoundError:
            os.mkdir(state.name,0o700,dir_fd=home_fd); os.fsync(home_fd); state_fd=os.open(state.name,flags,dir_fd=home_fd)
        except OSError as error: raise RuntimeError("global pxpipe lock root is unsafe") from error
        metadata=os.fstat(state_fd)
        if metadata.st_uid!=os.geteuid() or stat.S_IMODE(metadata.st_mode)!=0o700:
            raise RuntimeError("global pxpipe lock root is not owner-private")
        name=".agent-workflow-retirement.lock"
        descriptor=os.open(name,os.O_RDWR|os.O_CREAT|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=state_fd)
        observed=os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_uid!=os.geteuid() or observed.st_nlink!=1 or stat.S_IMODE(observed.st_mode)!=0o600:
            raise RuntimeError("global pxpipe retirement lock is unsafe")
        fcntl.flock(descriptor,fcntl.LOCK_EX)
        named=os.stat(name,dir_fd=state_fd,follow_symlinks=False)
        if inode_identity(named)!=inode_identity(observed): raise RuntimeError("global pxpipe retirement lock pathname changed")
        yield
    finally:
        if descriptor is not None:
            try: fcntl.flock(descriptor,fcntl.LOCK_UN)
            finally: os.close(descriptor)
        if state_fd is not None: os.close(state_fd)
        os.close(home_fd)


@contextlib.contextmanager
def sealed_pxpipe_helpers(plugin,helpers):
    directory=Path(tempfile.mkdtemp(prefix="agent-pxpipe-retirement-")); os.chmod(directory,0o700)
    try:
        for relative,digest in helpers.items():
            source=plugin/relative; record,raw=_secure_global_file(source,include_bytes=True)
            if raw is None or record.get("sha256")!=digest: raise RuntimeError(f"manifest-pinned pxpipe helper drift: {relative}")
            target=directory/Path(relative).name; descriptor=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o500 if relative.endswith(".sh") else 0o400)
            try:
                offset=0
                while offset<len(raw): offset+=os.write(descriptor,raw[offset:])
                os.fsync(descriptor)
            finally: os.close(descriptor)
            if hashlib.sha256(read_installer_bytes(target,label="installer target")).hexdigest()!=digest: raise RuntimeError("sealed pxpipe helper copy drifted")
        yield str(directory/Path(GLOBAL_PXPIPE_HELPERS[0]).name)
    finally: shutil.rmtree(directory)


def ensure_global_pxpipe_retired(target,manifest_path,installed,prior_files):
    with global_pxpipe_retirement_lock():
        return _ensure_global_pxpipe_retired_locked(target,manifest_path,installed,prior_files)


def _ensure_global_pxpipe_retired_locked(target,manifest_path,installed,prior_files):
    anchor=planned_path_snapshot(manifest_path,include_bytes=True)
    try: anchored_manifest=json.loads(anchor["bytes"])
    except (UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("authenticated pxpipe installation anchor is malformed") from error
    schema=installed.get("schema") if isinstance(installed,dict) else None; pxpipe=installed.get("pxpipe") if isinstance(installed,dict) else None
    legacy_verified=(schema in {"agent-workflow-install/v3","agent-workflow-install/v4"} and installed.get("repo_plugin_files")==prior_files
                     and isinstance(installed.get("marketplace_entry"),dict) and installed["marketplace_entry"].get("name")==PLUGIN_NAME)
    current_verified=(schema=="agent-workflow-install/v5" and isinstance(pxpipe,dict) and pxpipe.get("provenance_status")=="verified" and pxpipe.get("files")==prior_files)
    if anchored_manifest!=installed or not (legacy_verified or current_verified):
        raise RuntimeError("authenticated global pxpipe retirement requires an exact released v3/v4/v5 ownership anchor")
    helpers={name:prior_files.get(name) for name in GLOBAL_PXPIPE_HELPERS}
    if helpers not in RELEASED_PXPIPE_HELPER_SETS:
        raise RuntimeError("verified pxpipe manifest does not bind an exact released retirement helper set")
    plugin=target/PLUGIN_RELATIVE
    for name,digest in helpers.items():
        helper=plugin/name
        if _secure_global_file(helper).get("sha256")!=digest: raise RuntimeError(f"manifest-pinned pxpipe helper drift: {name}")
    binding={"project_root":_project_root_identity(target),"prior_manifest_sha256":anchor["sha256"],
             "plugin_tree_sha256":transaction_content_sha256(plugin),
             "manifest_plugin_files_sha256":canonical_sha256(prior_files),"helper_sha256":helpers}
    intent_path=target/GLOBAL_PXPIPE_INTENT_RELATIVE; receipt_path=target/GLOBAL_PXPIPE_RECEIPT_RELATIVE
    _ensure_private_directory(receipt_path.parent)
    if receipt_path.exists() or receipt_path.is_symlink():
        receipt=_validate_pxpipe_retirement_document(
            _load_bound_private_json(receipt_path,"agent-global-pxpipe-retirement-receipt/v1"),binding,"receipt")
        if receipt.get("terminal") is not True or not _global_pxpipe_absent(_global_pxpipe_state(),receipt["expected_codex_config"],receipt["listener_port"]):
            raise RuntimeError("global pxpipe retirement receipt no longer verifies terminal state")
        if intent_path.exists() or intent_path.is_symlink():
            intent=_validate_pxpipe_retirement_document(
                _load_bound_private_json(intent_path,"agent-global-pxpipe-retirement-intent/v1"),binding,"intent")
            _unlink_bound_private_json(intent_path,intent)
        return receipt
    if intent_path.exists() or intent_path.is_symlink():
        intent=_validate_pxpipe_retirement_document(
            _load_bound_private_json(intent_path,"agent-global-pxpipe-retirement-intent/v1"),binding,"intent")
        pre_state=intent["pre_state"]; expected_codex_config=intent["expected_codex_config"]; listener_port=intent["listener_port"]
    else:
        pre_state=_global_pxpipe_state()
        if _global_pxpipe_marker_records_absent(pre_state):
            expected_codex_config=_validate_markerless_codex_config(pre_state["codex_config"]); listener_port=47821
        else:
            _validate_global_pxpipe_live_set(pre_state)
            expected_codex_config,listener_port=_expected_restored_codex_config(pre_state)
        intent={"schema":"agent-global-pxpipe-retirement-intent/v1",**binding,"phase":"prepared",
                "pre_state":pre_state,"expected_codex_config":expected_codex_config,"listener_port":listener_port}
        intent["record_sha256"]=canonical_sha256(intent); _private_json(intent_path,intent,create=True)
    current=_global_pxpipe_state()
    if not _global_pxpipe_absent(current,expected_codex_config,listener_port):
        recovery=_global_pxpipe_paths()["recovery"]
        environment=dict(os.environ)
        for key in list(environment):
            if key.startswith("PXPIPE_"): environment.pop(key)
        with sealed_pxpipe_helpers(plugin,helpers) as uninstaller:
            if recovery.exists() or recovery.is_symlink():
                try: recovered=run_installer_command([uninstaller,"--recover"],env=environment,timeout=120)
                except subprocess.TimeoutExpired as error: raise RuntimeError("pinned pxpipe uninstaller recovery timed out") from error
                if recovered.returncode!=0: raise RuntimeError("pinned pxpipe uninstaller recovery failed closed: "+recovered.stderr.strip()[-2000:])
                current=_global_pxpipe_state()
            _validate_global_pxpipe_live_set(current)
            try: completed=run_installer_command([uninstaller],env=environment,timeout=120)
            except subprocess.TimeoutExpired as error: raise RuntimeError("pinned pxpipe uninstaller timed out") from error
            if completed.returncode!=0: raise RuntimeError("pinned pxpipe uninstaller failed closed: "+completed.stderr.strip()[-2000:])
    post_state=_global_pxpipe_state()
    if not _global_pxpipe_absent(post_state,expected_codex_config,listener_port): raise RuntimeError("global pxpipe retirement could not prove service/listener and exact config restoration")
    receipt={"schema":"agent-global-pxpipe-retirement-receipt/v1",**binding,"terminal":True,
             "pre_state":pre_state,"expected_codex_config":expected_codex_config,"listener_port":listener_port,"post_state":post_state}
    receipt["record_sha256"]=canonical_sha256(receipt); _private_json(receipt_path,receipt,create=True)
    intent=_validate_pxpipe_retirement_document(
        _load_bound_private_json(intent_path,"agent-global-pxpipe-retirement-intent/v1"),binding,"intent")
    _unlink_bound_private_json(intent_path,intent)
    return receipt


def exact_plugin_tree_matches(root,expected):
    max_entries=4096; max_file_bytes=16*1024*1024; max_tree_bytes=64*1024*1024; max_depth=16; max_path_bytes=4096
    if not isinstance(expected,dict) or len(expected)>max_entries: return False
    expected_directories=set()
    for relative,digest in expected.items():
        if (not isinstance(relative,str) or not relative or len(relative.encode("utf-8"))>max_path_bytes
                or Path(relative).is_absolute() or ".." in Path(relative).parts
                or not isinstance(digest,str) or re.fullmatch(r"[0-9a-f]{64}",digest) is None): return False
        parts=Path(relative).parts[:-1]
        if len(parts)>max_depth: return False
        for index in range(1,len(parts)+1): expected_directories.add(Path(*parts[:index]).as_posix())
    try: root_metadata=os.lstat(root)
    except (FileNotFoundError,OSError): return False
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode): return False
    def identity(value):
        return (value.st_dev,value.st_ino,value.st_mode,value.st_mtime_ns,value.st_ctime_ns)
    observed_files={}; observed_directories=set(); entries=0; total_bytes=0
    stack=[(Path(root),0,identity(root_metadata))]
    try:
        while stack:
            directory,depth,expected_identity=stack.pop()
            if depth>max_depth: return False
            before=os.lstat(directory)
            if identity(before)!=expected_identity or not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode): return False
            children=[]
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    entries+=1
                    if entries>max_entries: return False
                    path=directory/entry.name; relative=path.relative_to(root).as_posix()
                    if len(relative.encode("utf-8"))>max_path_bytes: return False
                    item=entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(item.st_mode) and not stat.S_ISLNK(item.st_mode):
                        observed_directories.add(relative); children.append((path,depth+1,identity(item)))
                        continue
                    if not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode) or item.st_nlink!=1 or item.st_size>max_file_bytes: return False
                    total_bytes+=item.st_size
                    if total_bytes>max_tree_bytes: return False
                    descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
                    try:
                        opened=os.fstat(descriptor)
                        if identity(opened)!=identity(item) or opened.st_nlink!=1: return False
                        digest=hashlib.sha256(); remaining=opened.st_size
                        while remaining:
                            chunk=os.read(descriptor,min(65536,remaining))
                            if not chunk: return False
                            digest.update(chunk); remaining-=len(chunk)
                        if os.read(descriptor,1): return False
                        after=os.fstat(descriptor)
                        if identity(after)!=identity(opened) or after.st_size!=opened.st_size: return False
                    finally: os.close(descriptor)
                    observed_files[relative]=digest.hexdigest()
            after=os.lstat(directory)
            if identity(after)!=identity(before): return False
            stack.extend(children)
    except (OSError,UnicodeError,ValueError): return False
    return observed_files==expected and observed_directories==expected_directories


def plan_legacy_pxpipe_cleanup(installed,target,desired_provenance,with_snapshots=False):
    if desired_provenance!="disabled": return (False,None,None,[],{}) if with_snapshots else (False,None,None,[])
    owned_files,owned_entry_digest=previous_pxpipe_ownership(installed)
    plugin_path=target/PLUGIN_RELATIVE; marketplace_path=target/MARKETPLACE_RELATIVE
    remove_plugin=False; marketplace_rewrite=None; marketplace_mode=None; conflicts=[]; snapshots={}
    plugin_exists=plugin_path.exists() or plugin_path.is_symlink()
    if plugin_exists:
        if owned_files:
            if exact_plugin_tree_matches(plugin_path,owned_files):
                remove_plugin=True
                snapshots[str(PLUGIN_RELATIVE)]={"identity":filesystem_identity(plugin_path),"sha256":transaction_content_sha256(plugin_path),"mode":stat.S_IMODE(os.lstat(plugin_path).st_mode)}
            else: conflicts.append(str(PLUGIN_RELATIVE)+" (owned tree drift)")
        else:
            # A target-local integrity document proves consistency, never installer
            # ownership. Preserve every unowned reserved tree byte-for-byte.
            conflicts.append(str(PLUGIN_RELATIVE)+" (unowned reserved path)")
    if marketplace_path.exists() or marketplace_path.is_symlink():
        # Namespace ownership/link failures are hard safety errors, not ordinary
        # content conflicts; never hide them behind a generic update-blocked result.
        marketplace_snapshot=planned_path_snapshot(marketplace_path,include_bytes=True)
        try:
            marketplace=json.loads(marketplace_snapshot["bytes"])
            if not isinstance(marketplace,dict) or not isinstance(marketplace.get("plugins"),list): raise ValueError("invalid marketplace")
            entry=named_marketplace_entry(marketplace,required=False)
        except (RuntimeError,ValueError,UnicodeError,json.JSONDecodeError):
            conflicts.append(str(MARKETPLACE_RELATIVE)+" (invalid or duplicate entry)")
        else:
            if entry is not None:
                if not isinstance(owned_entry_digest,str) or canonical_sha256(entry)!=owned_entry_digest:
                    conflicts.append(str(MARKETPLACE_RELATIVE)+" (unowned or drifted pxpipe entry)")
                else:
                    marketplace_rewrite=dict(marketplace)
                    marketplace_rewrite["plugins"]=[item for item in marketplace["plugins"] if item.get("name")!=PLUGIN_NAME]
                    marketplace_mode=marketplace_snapshot["mode"]
                    snapshots[str(MARKETPLACE_RELATIVE)]=marketplace_snapshot
    result=(remove_plugin,marketplace_rewrite,marketplace_mode,sorted(set(conflicts)))
    return (*result,snapshots) if with_snapshots else result


def optional_repo_plugin_files(root):
    """Return None only for a genuinely absent optional plugin namespace."""
    try: os.lstat(root)
    except FileNotFoundError:
        try: parent_metadata=os.lstat(root.parent)
        except FileNotFoundError: return None
        if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
            raise RuntimeError(f"repo plugin parent is unsafe: {root.parent}")
        assert_trusted_tree_entry(root.parent,parent_metadata,"repo plugin parent")
        # Recheck the leaf after validating its parent so a concurrently
        # published link/tree is never silently classified as absence.
        try: os.lstat(root)
        except FileNotFoundError: return None
    return repo_plugin_files(root)


def source_contract(source_root):
    validate_bootstrap(source_root/"AGENTS.md","AGENTS.md")
    validate_bootstrap(source_root/"CLAUDE.md","CLAUDE.md")
    validate_managed_source(source_root/".agent")
    validate_managed_directory_modes(source_root/".agent")
    fresh_state_seed(source_root/".agent")
    agent_files=files(source_root/".agent")
    agent_modes=portable_file_modes(source_root/".agent",agent_files)
    plugin_files=optional_repo_plugin_files(source_root/PLUGIN_RELATIVE)
    provenance=("disabled" if plugin_files is None else validate_repo_plugin(source_root/PLUGIN_RELATIVE,plugin_files))
    marketplace=read_marketplace(source_root/MARKETPLACE_RELATIVE,required=False)
    if marketplace is None:
        if provenance=="verified": raise RuntimeError("verified pxpipe source requires its marketplace entry")
        entry=None
    else:
        entry=named_marketplace_entry(marketplace,required=provenance=="verified")
    if plugin_files is None and entry is not None:
        raise RuntimeError("marketplace advertises an absent pxpipe plugin source")
    fresh_config=json.loads(read_installer_text(source_root/".agent/assets/fresh-state/v1/config.json",label="fresh config"))
    if fresh_config.get("context_transport")!={"default":"native"}:
        raise RuntimeError("fresh-state context transport must remain exact native-only; optional pxpipe is live opt-in only")
    if provenance!="verified":
        return agent_files,agent_modes,{},None,None,"disabled"
    entry_digest=canonical_sha256(entry)
    return agent_files,agent_modes,plugin_files,entry,entry_digest,"verified"


def atomic_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True); fd,raw=tempfile.mkstemp(prefix=f".{path.name}.",dir=str(path.parent)); temporary=Path(raw)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as handle:
            json.dump(value,handle,ensure_ascii=False,indent=2); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary,path)
    finally:
        if temporary.exists(): temporary.unlink()


def atomic_bytes(path,data):
    path.parent.mkdir(parents=True,exist_ok=True); fd,raw=tempfile.mkstemp(prefix=f".{path.name}.",dir=str(path.parent)); temporary=Path(raw)
    try:
        with os.fdopen(fd,"wb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary,path)
    finally:
        if temporary.exists(): temporary.unlink()


def validated_manifest_files(value,label):
    """Validate a bounded canonical POSIX relative-path to SHA-256 map."""
    if not isinstance(value,dict) or len(value)>20000:
        raise SystemExit(f"invalid workflow install manifest {label}")
    for relative,digest in value.items():
        if (not isinstance(relative,str) or not relative or len(relative.encode("utf-8"))>4096
                or relative.startswith("/") or "\\" in relative or "\x00" in relative):
            raise SystemExit(f"invalid workflow install manifest {label} path")
        parts=relative.split("/")
        if (any(part in {"",".",".."} or len(part.encode("utf-8"))>255 for part in parts)
                or Path(relative).as_posix()!=relative):
            raise SystemExit(f"invalid workflow install manifest {label} path")
        if not isinstance(digest,str) or re.fullmatch(r"[0-9a-f]{64}",digest) is None:
            raise SystemExit(f"invalid workflow install manifest {label} digest")
    return value


def manifest(path,required=False):
    if not path.is_file():
        if required: raise SystemExit("workflow is unmanaged: missing .workflow-manifest.json; use --adopt after verifying an exact source match")
        return None
    value=json.loads(read_installer_text(path,label="installer file"))
    schema=value.get("schema")
    if schema=="agent-workflow-install/v1":
        validated_manifest_metadata(value,schema)
        validated_manifest_files(value.get("files"),"files")
        if value.get("source_tree_sha256")!=tree_sha256(value["files"]): raise SystemExit("workflow install manifest source tree hash is invalid")
    elif schema=="agent-workflow-install/v5":
        metadata=validated_manifest_metadata(value,schema)
        if value.get("agent_root_mode")!=AGENT_ROOT_MODE: raise SystemExit("invalid workflow install root mode binding")
        validated_manifest_files(value.get("agent_files"),"agent_files")
        agent_modes=value.get("agent_modes")
        if agent_modes is not None and (
            not isinstance(agent_modes,dict) or set(agent_modes)!=set(value["agent_files"])
            or any(type(mode) is not int or not 0 <= mode <= 0o777 for mode in agent_modes.values())
        ):
            raise SystemExit("invalid workflow install managed mode binding")
        pxpipe=value.get("pxpipe")
        if not isinstance(pxpipe,dict) or set(pxpipe)!={"name","provenance_status","files","marketplace_entry_sha256"} or pxpipe.get("name")!=PLUGIN_NAME or pxpipe.get("provenance_status") not in {"verified","disabled"}:
            raise SystemExit("invalid workflow install pxpipe binding")
        validated_manifest_files(pxpipe.get("files"),"pxpipe files")
        if (pxpipe["provenance_status"]=="verified" and re.fullmatch(r"[0-9a-f]{64}",str(pxpipe.get("marketplace_entry_sha256") or "")) is None) or (pxpipe["provenance_status"]=="disabled" and (pxpipe.get("files")!={} or pxpipe.get("marketplace_entry_sha256") is not None)):
            raise SystemExit("invalid workflow install pxpipe provenance binding")
        for name in ("agents_bootstrap","claude_bootstrap"):
            bootstrap=value.get(name); expected_path="AGENTS.md" if name=="agents_bootstrap" else "CLAUDE.md"
            if not isinstance(bootstrap,dict) or set(bootstrap)!={"path","sha256"} or bootstrap.get("path")!=expected_path or not isinstance(bootstrap.get("sha256"),str) or re.fullmatch(r"[0-9a-f]{64}",bootstrap["sha256"]) is None: raise SystemExit("invalid workflow install bootstrap binding")
        payload={**metadata,"agent_root_mode":value["agent_root_mode"],"agent_files":value["agent_files"],"pxpipe":pxpipe,"agents_bootstrap_sha256":value["agents_bootstrap"]["sha256"],"claude_bootstrap_sha256":value["claude_bootstrap"]["sha256"]}
        if agent_modes is not None: payload["agent_modes"]=agent_modes
        if value.get("source_tree_sha256")!=canonical_sha256(payload): raise SystemExit("workflow install manifest source tree hash is invalid")
    elif schema in {"agent-workflow-install/v3","agent-workflow-install/v4"}:
        validated_manifest_metadata(value,schema)
        validated_manifest_files(value.get("agent_files"),"agent_files")
        validated_manifest_files(value.get("repo_plugin_files"),"repo_plugin_files")
        entry=value.get("marketplace_entry")
        if not isinstance(entry,dict) or set(entry)!={"name","sha256"} or entry.get("name")!=PLUGIN_NAME or re.fullmatch(r"[0-9a-f]{64}",str(entry.get("sha256") or "")) is None:
            raise SystemExit("invalid workflow install marketplace binding")
        payload={
            "agent_files":value["agent_files"],
            "repo_plugin_files":value["repo_plugin_files"],
            "marketplace_entry_sha256":entry["sha256"],
        }
        if schema in {"agent-workflow-install/v3","agent-workflow-install/v4"}:
            bootstrap=value.get("agents_bootstrap")
            if (
                not isinstance(bootstrap,dict) or set(bootstrap)!={"path","sha256"}
                or bootstrap.get("path")!="AGENTS.md"
                or not isinstance(bootstrap.get("sha256"),str) or len(bootstrap["sha256"])!=64
            ):
                raise SystemExit("invalid workflow install bootstrap binding")
            payload["agents_bootstrap_sha256"]=bootstrap["sha256"]
        if schema=="agent-workflow-install/v4":
            claude=value.get("claude_bootstrap")
            if (
                not isinstance(claude,dict) or set(claude)!={"path","sha256"}
                or claude.get("path")!="CLAUDE.md"
                or not isinstance(claude.get("sha256"),str) or len(claude["sha256"])!=64
            ):
                raise SystemExit("invalid workflow install bootstrap binding")
            payload["claude_bootstrap_sha256"]=claude["sha256"]
        expected=canonical_sha256(payload)
        if value.get("source_tree_sha256")!=expected: raise SystemExit("workflow install manifest source tree hash is invalid")
    else: raise SystemExit("invalid workflow install manifest")
    migration=value.get("migration_version")
    if type(migration) is not int or not 0<=migration<=MAX_MANIFEST_NUMBER:
        raise SystemExit("workflow install manifest migration version is missing, malformed, or out of range")
    return value


def installed_migration_version(installed):
    """Defensively preserve validated migration bounds at every use site."""
    value=installed.get("migration_version",0)
    if type(value) is not int or not 0<=value<=MAX_MANIFEST_NUMBER:
        raise SystemExit(f"workflow install manifest migration version is malformed or out of range: {value!r}")
    return value


def previous_agent_files(previous):
    return previous["files"] if previous.get("schema")=="agent-workflow-install/v1" else previous["agent_files"]


IDENTITY_UNSPECIFIED=object()


def plan_agent_update(wanted,wanted_modes,previous,destination,with_snapshots=False):
    previous_files=previous_agent_files(previous); current=files(destination); current_modes=file_modes(destination,current)
    conflicts=[]; writes=[]; removes=[]; snapshots={}
    for relative,digest in wanted.items():
        old=previous_files.get(relative); observed=current.get(relative)
        if observed==digest and current_modes.get(relative)==wanted_modes[relative]: continue
        if observed==digest: writes.append(relative); continue
        if observed is not None and old is not None and observed!=old: conflicts.append(relative)
        elif observed is not None and old is None: conflicts.append(relative)
        else: writes.append(relative)
    for relative,old in previous_files.items():
        if relative not in wanted and current.get(relative)==old:
            removes.append(relative); snapshots[relative]=planned_path_snapshot(destination/relative)
        elif relative not in wanted and relative in current: conflicts.append(relative)
    # Never carry target-added Python or Skill code into a migration runner.
    for relative in set(current)-set(previous_files)-set(wanted):
        if relative.startswith(("scripts/","skills/")):
            conflicts.append(relative)
    result=(sorted(set(writes)),sorted(set(removes)),sorted(set(conflicts)))
    return (*result,snapshots) if with_snapshots else result


def bootstrap_state(path,trusted_file_sha256=None):
    try: metadata=os.lstat(path)
    except FileNotFoundError: return "missing",None,None
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink!=1:
        return "conflict",None,None
    try: text=read_installer_text(path,label="installer file")
    except UnicodeError: return "conflict",None,None
    starts=text.count(BOOTSTRAP_START); ends=text.count(BOOTSTRAP_END)
    if starts==0 and ends==0: return "absent",text,None
    if starts!=1 or ends!=1: return "conflict",text,None
    begin=text.index(BOOTSTRAP_START); finish=text.index(BOOTSTRAP_END,begin)+len(BOOTSTRAP_END)
    observed=text[begin:finish]+("\n" if finish==len(text) or text[finish:finish+1]=="\n" else "")
    if observed==BOOTSTRAP: return "current",text,(begin,finish)
    legacy=hashlib.sha256(observed.encode()).hexdigest() in LEGACY_BOOTSTRAPS and LEGACY_BOOTSTRAPS[hashlib.sha256(observed.encode()).hexdigest()]==observed
    return ("previous" if legacy else "conflict"),text,(begin,finish)


def installed_bootstrap_sha256(installed,filename):
    field="agents_bootstrap" if filename=="AGENTS.md" else "claude_bootstrap"
    binding=installed.get(field) if isinstance(installed,dict) else None
    return binding.get("sha256") if isinstance(binding,dict) and binding.get("path")==filename else None


def bootstrap_state_from_snapshot(snapshot):
    if snapshot is None: return "missing",None,None
    try: text=snapshot["bytes"].decode("utf-8")
    except UnicodeError: return "conflict",None,None
    starts=text.count(BOOTSTRAP_START); ends=text.count(BOOTSTRAP_END)
    if starts==0 and ends==0: return "absent",text,None
    if starts!=1 or ends!=1: return "conflict",text,None
    begin=text.index(BOOTSTRAP_START); finish=text.index(BOOTSTRAP_END,begin)+len(BOOTSTRAP_END)
    observed=text[begin:finish]+("\n" if finish==len(text) or text[finish:finish+1]=="\n" else "")
    if observed==BOOTSTRAP: return "current",text,(begin,finish)
    legacy=hashlib.sha256(observed.encode()).hexdigest() in LEGACY_BOOTSTRAPS and LEGACY_BOOTSTRAPS[hashlib.sha256(observed.encode()).hexdigest()]==observed
    return ("previous" if legacy else "conflict"),text,(begin,finish)


def plan_bootstrap(path,filename,trusted_file_sha256=None,with_snapshot=False):
    snapshot=None
    if path.exists() or path.is_symlink(): snapshot=planned_path_snapshot(path,include_bytes=True)
    state,_,_=bootstrap_state_from_snapshot(snapshot)
    result=(False,[]) if state=="current" else ((True,[]) if state in {"missing","absent","previous"} else (False,[f"{filename}#agent-workflow-bootstrap"]))
    return (*result,snapshot) if with_snapshot else result


def render_bootstrap(path,trusted_file_sha256=None,snapshot=IDENTITY_UNSPECIFIED):
    if snapshot is IDENTITY_UNSPECIFIED:
        state,text,bounds=bootstrap_state(path,trusted_file_sha256)
    else:
        if snapshot is not None: require_planned_path(path,snapshot)
        elif path.exists() or path.is_symlink(): raise RuntimeError("planned bootstrap absence changed before staging")
        state,text,bounds=bootstrap_state_from_snapshot(snapshot)
    if state=="conflict": raise RuntimeError("managed bootstrap anchor is malformed or locally modified")
    if state=="current": return text
    if state=="missing": return BOOTSTRAP
    if state=="previous":
        begin,finish=bounds; suffix=text[finish:]
        if suffix.startswith("\n"): suffix=suffix[1:]
        return text[:begin]+BOOTSTRAP+suffix
    return text.rstrip()+"\n\n"+BOOTSTRAP


def stage_bootstrap(target,candidate_parent,filename,trusted_file_sha256=None,snapshot=IDENTITY_UNSPECIFIED):
    rendered=render_bootstrap(target/filename,trusted_file_sha256,snapshot=snapshot)
    candidate=candidate_parent/filename
    candidate.write_text(rendered,encoding="utf-8")
    return candidate


def validate_bootstrap(path,filename):
    state,_,_=bootstrap_state(path)
    if state!="current": raise RuntimeError(f"candidate {filename} lacks the canonical managed bootstrap")


def install_manifest(agent_files,agent_modes,plugin_files,entry_digest,provenance,agents_sha256,claude_sha256):
    validated_manifest_files(agent_files,"agent_files")
    validated_manifest_files(plugin_files,"pxpipe files")
    for label,value in (("AGENTS.md",agents_sha256),("CLAUDE.md",claude_sha256)):
        if not isinstance(value,str) or re.fullmatch(r"[0-9a-f]{64}",value) is None:
            raise RuntimeError(f"installed {label} SHA-256 is invalid")
    if set(agent_modes)!=set(agent_files) or any(type(mode) is not int or not 0 <= mode <= 0o777 for mode in agent_modes.values()):
        raise RuntimeError("managed file mode binding is invalid")
    if provenance not in {"verified","disabled"} or (provenance=="verified" and re.fullmatch(r"[0-9a-f]{64}",str(entry_digest or "")) is None) or (provenance=="disabled" and (plugin_files!={} or entry_digest is not None)):
        raise RuntimeError("pxpipe install provenance binding is invalid")
    pxpipe={"name":PLUGIN_NAME,"provenance_status":provenance,"files":plugin_files,"marketplace_entry_sha256":entry_digest}
    source_digest=canonical_sha256({
        "schema":"agent-workflow-install/v5","version":VERSION,"migration_version":MIGRATION_VERSION,
        "agent_root_mode":AGENT_ROOT_MODE,"agent_files":agent_files,"agent_modes":agent_modes,"pxpipe":pxpipe,
        "agents_bootstrap_sha256":agents_sha256,"claude_bootstrap_sha256":claude_sha256,
    })
    return {
        "schema":"agent-workflow-install/v5",
        "version":VERSION,
        "migration_version":MIGRATION_VERSION,
        "agent_root_mode":AGENT_ROOT_MODE,
        "source_tree_sha256":source_digest,
        "agent_files":agent_files,
        "agent_modes":agent_modes,
        "pxpipe":pxpipe,
        "agents_bootstrap":{"path":"AGENTS.md","sha256":agents_sha256},
        "claude_bootstrap":{"path":"CLAUDE.md","sha256":claude_sha256},
    }


def unlink_planned_candidate(root,relative,source_snapshot):
    parts=Path(relative).parts
    descriptor=os.open(root,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
    try:
        for component in parts[:-1]:
            child=os.open(component,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=descriptor)
            os.close(descriptor); descriptor=child
        observed=planned_path_snapshot(root/relative)
        if observed["sha256"]!=source_snapshot["sha256"] or observed["mode"]!=source_snapshot["mode"]:
            raise RuntimeError(f"staged removal does not match planned bytes and mode: {relative}")
        os.unlink(parts[-1],dir_fd=descriptor)
    finally: os.close(descriptor)


def write_managed(source,destination,writes,removes,removal_snapshots=None):
    for relative in removes:
        path=destination/relative
        if path.is_file():
            if removal_snapshots is None: path.unlink()
            else: unlink_planned_candidate(destination,relative,removal_snapshots[relative])
    for relative in writes:
        target=destination/relative; target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(source/relative,target)
    for directory in sorted((destination/name for name in MANAGED if (destination/name).is_dir()),reverse=True):
        candidates=[item for item,metadata in bounded_tree_entries(directory,"managed empty-directory cleanup") if stat.S_ISDIR(metadata.st_mode)]
        for candidate in sorted(candidates,key=lambda item:(len(item.parts),os.fsencode(str(item))),reverse=True):
            try:
                with os.scandir(candidate) as scanner: empty=next(scanner,None) is None
            except OSError as error: raise RuntimeError("managed empty-directory cleanup failed") from error
            if empty: candidate.rmdir()


def validate_repo_plugin(plugin,wanted):
    if repo_plugin_files(plugin)!=wanted: raise RuntimeError("candidate repo plugin differs from source")
    plugin_manifest_path=plugin/".codex-plugin/plugin.json"
    mcp_path=plugin/".mcp.json"
    integrity_path=plugin/"integrity.json"
    for path in (plugin_manifest_path,mcp_path,integrity_path):
        if not path.is_file() or path.is_symlink(): raise RuntimeError(f"candidate plugin metadata is missing or unsafe: {path.name}")
    try:
        plugin_manifest=json.loads(read_installer_text(plugin_manifest_path,label="plugin manifest"))
        mcp=json.loads(read_installer_text(mcp_path,label="MCP config"))
        integrity=json.loads(read_installer_text(integrity_path,label="integrity record"))
    except (UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("candidate plugin metadata is invalid JSON") from error
    if (
        plugin_manifest.get("name")!=PLUGIN_NAME
        or not isinstance(plugin_manifest.get("version"),str) or not plugin_manifest["version"]
        or plugin_manifest.get("skills")!="./skills/"
        or plugin_manifest.get("mcpServers")!="./.mcp.json"
    ): raise RuntimeError("candidate plugin manifest is invalid")
    servers=mcp.get("mcpServers") if isinstance(mcp,dict) else None
    server=servers.get(PLUGIN_NAME) if isinstance(servers,dict) else None
    if (
        not isinstance(server,dict)
        or server.get("command")!="node"
        or server.get("args")!=["./mcp/server.mjs"]
        or server.get("cwd")!="."
        or server.get("default_tools_approval_mode")!="prompt"
    ): raise RuntimeError("candidate plugin MCP contract is invalid")
    if integrity.get("schema")!="pxpipe-context-integrity/v4":
        raise RuntimeError("candidate plugin integrity metadata is not v4")
    if integrity.get("provenance_status")=="quarantined":
        quarantine_fields={
            "schema","plugin_version","provenance_status","quarantine_reason","plugin_tree_sha256",
            "pxpipe_package","pxpipe_version","source_repository","source_commit","source_tree",
            "source_package_sha256","source_lockfile","source_lockfile_sha256","esbuild_main_sha256",
            "runtime_bundle","runtime_bundle_sha256","proxy_bundle","proxy_bundle_sha256","provider_assets",
        }
        null_fields={
            "source_commit","source_tree","source_package_sha256","source_lockfile","source_lockfile_sha256",
            "esbuild_main_sha256","runtime_bundle","runtime_bundle_sha256","proxy_bundle","proxy_bundle_sha256",
        }
        if (
            set(integrity)!=quarantine_fields
            or integrity.get("plugin_version")!=plugin_manifest["version"]
            or integrity.get("pxpipe_package")!="pxpipe-proxy"
            or not isinstance(integrity.get("pxpipe_version"),str) or not integrity["pxpipe_version"]
            or integrity.get("source_repository")!="https://github.com/teamchong/pxpipe.git"
            or not isinstance(integrity.get("quarantine_reason"),str) or not integrity["quarantine_reason"].strip()
            or any(integrity.get(name) is not None for name in null_fields)
            or not isinstance(integrity.get("plugin_tree_sha256"),str)
            or re.fullmatch(r"[0-9a-f]{64}",integrity["plugin_tree_sha256"]) is None
        ):
            raise RuntimeError("candidate plugin quarantine metadata is not the exact v4 contract")
        forbidden=(plugin/"mcp/vendor/pxpipe-runtime.mjs",plugin/"proxy/vendor/pxpipe-node.mjs")
        if any(path.exists() or path.is_symlink() for path in forbidden):
            raise RuntimeError("quarantined pxpipe source contains a forbidden opaque vendor bundle")
        tree_records=[]
        plugin_entries=list(bounded_tree_entries(plugin,"candidate plugin integrity"))
        for artifact,metadata in sorted(plugin_entries,key=lambda item:item[0].relative_to(plugin).as_posix().encode()):
            if artifact==integrity_path: continue
            if stat.S_ISLNK(metadata.st_mode): raise RuntimeError("candidate plugin tree contains a symlink")
            if stat.S_ISREG(metadata.st_mode): tree_records.append([artifact.relative_to(plugin).as_posix(),sha(artifact)])
        tree_bytes=json.dumps(tree_records,separators=(",",":"),ensure_ascii=False).encode()
        if hashlib.sha256(tree_bytes).hexdigest()!=integrity["plugin_tree_sha256"]:
            raise RuntimeError("quarantined plugin tree SHA-256 does not match integrity metadata")
        expected_provider_assets={
            "scripts/codex-pxpipe.sh","scripts/codex-default-config.mjs","scripts/install-codex-default.sh",
            "scripts/uninstall-codex-default.sh","scripts/status-codex-default.sh",
        }
        provider_assets=integrity.get("provider_assets")
        if (
            not isinstance(provider_assets,dict) or set(provider_assets)!=expected_provider_assets
            or not all(isinstance(value,str) and re.fullmatch(r"[0-9a-f]{64}",value) for value in provider_assets.values())
        ):
            raise RuntimeError("quarantined plugin provider asset integrity map is invalid")
        for relative_text,expected in provider_assets.items():
            artifact=plugin/relative_text
            if not artifact.is_file() or artifact.is_symlink() or sha(artifact)!=expected:
                raise RuntimeError("quarantined plugin provider asset SHA-256 does not match integrity metadata")
        return "disabled"
    if integrity.get("provenance_status")!="verified":
        raise RuntimeError("candidate plugin provenance status is invalid")
    raise RuntimeError(
        "pxpipe verified activation is unavailable: exact upstream checkout, lockfile, toolchain, "
        "reproducible rebuild, and transitive-license review require an external trusted release process"
    )


def validate_candidate(candidate,wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,agents,claude):
    validate_private_tree(candidate)
    validate_project_guardrails(candidate)
    observed=files(candidate)
    if (observed!=wanted or file_modes(candidate,observed)!=wanted_modes or agent_root_mode(candidate)!=AGENT_ROOT_MODE
            or any(mode!=0o755 for mode in managed_directory_modes(candidate).values())):
        raise RuntimeError("candidate managed tree bytes, file modes, or directory modes differ from source")
    installed=manifest(candidate/".workflow-manifest.json",required=True)
    if installed!=install_manifest(wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,sha(agents),sha(claude)):
        raise RuntimeError("candidate install manifest is stale")
    validate_bootstrap(agents,"AGENTS.md")
    validate_bootstrap(claude,"CLAUDE.md")
    for base in (candidate/"scripts",candidate/"skills"):
        for python_file,metadata in bounded_tree_entries(base,"candidate Python validation"):
            if not stat.S_ISREG(metadata.st_mode) or python_file.suffix!=".py": continue
            try: ast.parse(read_installer_text(python_file,label="managed Python"),filename=str(python_file))
            except (SyntaxError,UnicodeError) as error: raise RuntimeError(f"candidate Python is invalid: {python_file}: {error}") from error
    template_manifest=json.loads(read_installer_text(candidate/"templates/manifest.json",label="template manifest"))
    if template_manifest.get("schema")!="agent-template-manifest/v2" or not isinstance(template_manifest.get("templates"),list): raise RuntimeError("candidate template manifest is invalid")
    ids=set()
    for item in template_manifest["templates"]:
        required={"id","path","output","renderable","depends_on","nodes","modes","capabilities","required"}
        if not isinstance(item,dict) or set(item) not in (required,required|{"authority"}) or not isinstance(item.get("id"),str) or item["id"] in ids:
            raise RuntimeError("candidate template manifest entry is invalid")
        allowed_authorities={
            "github-ci":({"github_candidate_runner","github_protected_runner","github_container","github_default_branch","blueprint_sha256"},),
            "github-test-cd":({"github_protected_runner","github_container","github_default_branch","blueprint_sha256"},),
            "github-production-cd":({"github_protected_runner","github_container","github_default_branch","blueprint_sha256"},),
            "gitlab-ci":({"gitlab_sys_platform","gitlab_image","gitlab_candidate_tags","blueprint_sha256"},),
            "gitlab-test-cd":({"gitlab_sys_platform","gitlab_image","gitlab_protected_tags","blueprint_sha256"},),
            "gitlab-production-cd":({"gitlab_sys_platform","gitlab_image","gitlab_protected_tags","blueprint_sha256"},),
        }.get(item["id"],(set(),))
        authority=item.get("authority",[])
        if not isinstance(authority,list) or len(authority)!=len(set(map(str,authority))) or set(authority) not in allowed_authorities:
            raise RuntimeError(f"candidate template blueprint authority variables are invalid: {item.get('id')} observed={authority!r}")
        ids.add(item["id"])
        source=candidate/str(item.get("path",""))
        if not source.is_file() or source.is_symlink(): raise RuntimeError(f"candidate template source missing: {item.get('path')}")
        try: source.resolve().relative_to(candidate.resolve())
        except ValueError: raise RuntimeError(f"candidate template source escapes workflow: {item.get('path')}")
        output_raw=Path(str(item.get("output","")).strip())
        output=(candidate.joinpath(*output_raw.parts[1:]) if output_raw.parts and output_raw.parts[0]==".agent" else candidate.parent/output_raw).resolve()
        if item.get("renderable") is True:
            try: output.relative_to((candidate/"state/artifacts").resolve())
            except ValueError: raise RuntimeError(f"candidate render output escapes artifact boundary: {item.get('output')}")
    if any(dependency not in ids for item in template_manifest["templates"] for dependency in item["depends_on"]):
        raise RuntimeError("candidate template dependency is unknown")


TRANSACTION_SCHEMA="agent-workflow-install-transaction/v5"
FULL_CONTENT_TRANSACTION_SCHEMA="agent-workflow-install-transaction/v4"
DIRECTORY_IDENTITY_TRANSACTION_SCHEMA="agent-workflow-install-transaction/v3"
LEGACY_TRANSACTION_SCHEMA="agent-workflow-install-transaction/v2"
OLDEST_TRANSACTION_SCHEMA="agent-workflow-install-transaction/v1"
TRANSACTION_STATES={"initializing","staging","committing","committed"}
TRANSACTION_PHASES={"prepared","backed_up","installed"}


def fsync_directory(path):
    flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)
    descriptor=os.open(str(path),flags)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def current_target_path():
    if LOGICAL_TARGET_ROOT is None or BOUND_TARGET_IDENTITY is None: return None
    return Path(LOGICAL_TARGET_ROOT.name)


def open_transaction_directory(path,label):
    value=Path(path)
    if value.is_absolute():
        descriptor=open_directory_chain(value)
        if descriptor is None: raise FileNotFoundError(str(value))
        assert_trusted_directory_descriptor(descriptor,label)
        return descriptor
    flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)
    descriptor=os.open(".",flags)
    try:
        assert_trusted_directory_descriptor(descriptor,label)
        for component in value.parts:
            if component in {"","."}: continue
            if component=="..": raise RuntimeError(f"{label} traversal may not use a parent component")
            child=os.open(component,flags,dir_fd=descriptor)
            try: assert_trusted_directory_descriptor(child,label)
            except Exception:
                os.close(child); raise
            os.close(descriptor); descriptor=child
        result=descriptor; descriptor=None; return result
    finally:
        if descriptor is not None: os.close(descriptor)


def identity_at(parent_descriptor,name):
    observed=os.stat(name,dir_fd=parent_descriptor,follow_symlinks=False)
    if stat.S_ISLNK(observed.st_mode) or not (stat.S_ISREG(observed.st_mode) or stat.S_ISDIR(observed.st_mode)):
        raise RuntimeError("transaction entry is not a regular file or directory")
    if stat.S_ISREG(observed.st_mode) and observed.st_nlink!=1:
        raise RuntimeError("transaction entry is a hard-linked regular file")
    return {"dev":observed.st_dev,"ino":observed.st_ino,"mode":stat.S_IFMT(observed.st_mode)}


def require_identity_at(parent_descriptor,name,expected,allow_absent=False):
    try: observed=identity_at(parent_descriptor,name)
    except FileNotFoundError:
        if allow_absent and expected is None: return
        raise RuntimeError("transaction entry disappeared before mutation")
    if expected is None or observed!=expected:
        raise RuntimeError("transaction entry identity changed before mutation")


def durable_replace(source,target,expected_source=IDENTITY_UNSPECIFIED,expected_target=IDENTITY_UNSPECIFIED):
    source_parent=open_transaction_directory(source.parent,"transaction source parent")
    try:
        target_parent=open_transaction_directory(target.parent,"transaction target parent")
        try:
            assert_namespace_binding(current_target_path())
            if expected_source is not IDENTITY_UNSPECIFIED:
                require_identity_at(source_parent,source.name,expected_source)
            if expected_target is not IDENTITY_UNSPECIFIED:
                require_identity_at(target_parent,target.name,expected_target,allow_absent=True)
            os.replace(source.name,target.name,src_dir_fd=source_parent,dst_dir_fd=target_parent)
            os.fsync(target_parent)
            if inode_identity(os.fstat(source_parent))!=inode_identity(os.fstat(target_parent)): os.fsync(source_parent)
            assert_namespace_binding(current_target_path())
        finally: os.close(target_parent)
    finally: os.close(source_parent)


def remove_entry_at(parent_descriptor,name,last_child=None,_state=None,_depth=0):
    _state=_state if _state is not None else {"entries":0}
    if _depth>MAX_INSTALL_TREE_DEPTH: raise RuntimeError("transaction removal depth limit exceeded")
    metadata=os.stat(name,dir_fd=parent_descriptor,follow_symlinks=False)
    if stat.S_ISDIR(metadata.st_mode):
        child=os.open(name,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=parent_descriptor)
        try:
            entries=sorted(bounded_directory_names(child,"transaction removal",MAX_INSTALL_TREE_ENTRIES-_state["entries"]+1))
            _state["entries"]+=len(entries)
            if _state["entries"]>MAX_INSTALL_TREE_ENTRIES: raise RuntimeError("transaction removal entry limit exceeded")
            if last_child is not None and last_child in entries:
                entries.remove(last_child); entries.append(last_child)
            for entry in entries:
                if entry in {".",".."}: raise RuntimeError("unsafe directory entry during removal")
                remove_entry_at(child,entry,_state=_state,_depth=_depth+1)
            os.fsync(child)
        finally: os.close(child)
        os.rmdir(name,dir_fd=parent_descriptor)
    elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        os.unlink(name,dir_fd=parent_descriptor)
    else: raise RuntimeError("refusing to remove a special transaction entry")


def durable_remove(path,expected_identity=IDENTITY_UNSPECIFIED,last_child=None):
    parent=open_transaction_directory(path.parent,"transaction removal parent")
    try:
        assert_namespace_binding(current_target_path())
        if expected_identity is not IDENTITY_UNSPECIFIED:
            require_identity_at(parent,path.name,expected_identity)
        remove_entry_at(parent,path.name,last_child=last_child)
        os.fsync(parent)
        assert_namespace_binding(current_target_path())
    finally: os.close(parent)


def durable_remove_empty_directory(path,expected_identity):
    parent=open_transaction_directory(path.parent,"transaction created-directory parent")
    try:
        assert_namespace_binding(current_target_path())
        require_identity_at(parent,path.name,expected_identity)
        os.rmdir(path.name,dir_fd=parent); os.fsync(parent)
        assert_namespace_binding(current_target_path())
    finally: os.close(parent)


def fsync_tree(root):
    if not root.is_dir() or root.is_symlink(): raise RuntimeError("transaction staging root is missing or unsafe")
    directories=[root]
    for item,metadata in bounded_tree_entries(root,"transaction staging tree"):
        if stat.S_ISLNK(metadata.st_mode): raise RuntimeError(f"transaction staging tree contains a symlink: {item}")
        if stat.S_ISDIR(metadata.st_mode): directories.append(item)
        elif stat.S_ISREG(metadata.st_mode):
            descriptor=os.open(str(item),os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
        else: raise RuntimeError(f"transaction staging tree contains a special file: {item}")
    for directory in sorted(directories,key=lambda value:len(value.parts),reverse=True): fsync_directory(directory)


def publication_lock_path(target):
    return target.parent/f".{target.name}.agent-workflow-publication.lock"


def open_publication_lock(parent_descriptor,target_name,create):
    name=f".{target_name}.agent-workflow-publication.lock"
    flags=os.O_RDWR|getattr(os,"O_NOFOLLOW",0)
    if create: flags|=os.O_CREAT
    try: descriptor=os.open(name,flags,0o600,dir_fd=parent_descriptor)
    except FileNotFoundError: return None
    observed=os.fstat(descriptor)
    if (not stat.S_ISREG(observed.st_mode) or observed.st_uid!=os.geteuid() or observed.st_nlink!=1
            or stat.S_IMODE(observed.st_mode)!=0o600):
        os.close(descriptor); raise RuntimeError("project publication lock must be a private owner-controlled 0600 regular file")
    return descriptor


def transaction_journal_path(target):
    return target.parent/f".{target.name}.agent-workflow-transaction.json"


def transaction_staging_path(target,transaction_id):
    return target.parent/f".{target.name}.agent-workflow-txn-{transaction_id}"


def transaction_targets(target):
    return {
        ".agent":target/".agent",
        str(PLUGIN_RELATIVE):target/PLUGIN_RELATIVE,
        str(MARKETPLACE_RELATIVE):target/MARKETPLACE_RELATIVE,
        "AGENTS.md":target/"AGENTS.md",
        "CLAUDE.md":target/"CLAUDE.md",
    }


def transaction_payload_digest(value):
    payload=dict(value); payload.pop("journal_sha256",None)
    return canonical_sha256(payload)


def secure_journal_stat(path):
    observed=path.lstat()
    if (not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1 or observed.st_uid!=os.geteuid()
            or stat.S_IMODE(observed.st_mode)!=0o600):
        raise RuntimeError("transaction journal is not a private, owner-controlled 0600 regular file")
    if observed.st_size>131072: raise RuntimeError("transaction journal exceeds its bounded size")
    return observed


def read_transaction_journal(target):
    path=transaction_journal_path(target)
    if not path.exists() and not path.is_symlink(): return None
    before=secure_journal_stat(path)
    descriptor=os.open(str(path),os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:
        opened=os.fstat(descriptor)
        if (opened.st_dev,opened.st_ino,opened.st_size)!=(before.st_dev,before.st_ino,before.st_size):
            raise RuntimeError("transaction journal changed while it was opened")
        raw=os.read(descriptor,131073)
        after=os.fstat(descriptor)
        if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)!=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns):
            raise RuntimeError("transaction journal changed while it was read")
    finally: os.close(descriptor)
    try: value=json.loads(raw)
    except (UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("transaction journal is invalid JSON") from error
    validate_transaction_journal(target,value)
    return value


def validate_identity(value,required):
    if value is None and not required: return
    if not isinstance(value,dict) or set(value)!={"dev","ino","mode"} or any(not isinstance(value[key],int) for key in value):
        raise RuntimeError("transaction journal contains an invalid filesystem identity")


def validate_transaction_journal(target,value):
    if not isinstance(value,dict) or value.get("schema") not in {OLDEST_TRANSACTION_SCHEMA,LEGACY_TRANSACTION_SCHEMA,DIRECTORY_IDENTITY_TRANSACTION_SCHEMA,FULL_CONTENT_TRANSACTION_SCHEMA,TRANSACTION_SCHEMA}:
        raise RuntimeError("transaction journal schema is invalid")
    if set(value)!={"schema","transaction_id","target_root","state","replacements","created_directories","journal_sha256"}:
        raise RuntimeError("transaction journal fields are invalid")
    if value.get("target_root")!=transaction_target_root(target) or value.get("state") not in TRANSACTION_STATES:
        raise RuntimeError("transaction journal target or state is invalid")
    transaction_id=value.get("transaction_id")
    if not isinstance(transaction_id,str) or re.fullmatch(r"[0-9a-f]{32}",transaction_id) is None:
        raise RuntimeError("transaction journal id is invalid")
    if value.get("journal_sha256")!=transaction_payload_digest(value):
        raise RuntimeError("transaction journal digest is invalid")
    operations=value.get("replacements")
    if not isinstance(operations,list): raise RuntimeError("transaction journal replacements are invalid")
    created=value.get("created_directories")
    allowed_directories={".","plugins",".agents",".agents/plugins"}
    if not isinstance(created,list): raise RuntimeError("transaction journal created-directory list is invalid")
    if value["schema"] in {DIRECTORY_IDENTITY_TRANSACTION_SCHEMA,TRANSACTION_SCHEMA}:
        labels=[]
        for item in created:
            if not isinstance(item,dict) or set(item)!={"path","identity"} or item.get("path") not in allowed_directories:
                raise RuntimeError("transaction journal created-directory identity is invalid")
            validate_identity(item.get("identity"),True); labels.append(item["path"])
        if len(labels)!=len(set(labels)): raise RuntimeError("transaction journal created-directory list is invalid")
    elif len(created)!=len(set(created)) or any(item not in allowed_directories for item in created):
        raise RuntimeError("transaction journal created-directory list is invalid")
    allowed=transaction_targets(target); seen=set()
    for operation in operations:
        expected_fields={"label","had_original","original_identity","candidate_identity","phase"}
        if value["schema"]!=OLDEST_TRANSACTION_SCHEMA: expected_fields.add("action")
        if value["schema"] in {FULL_CONTENT_TRANSACTION_SCHEMA,TRANSACTION_SCHEMA}: expected_fields.update({"original_content_sha256","candidate_content_sha256"})
        if value["schema"]==TRANSACTION_SCHEMA: expected_fields.add("candidate_committed_sha256")
        if not isinstance(operation,dict) or set(operation)!=expected_fields:
            raise RuntimeError("transaction journal replacement is malformed")
        label=operation.get("label")
        if label not in allowed or label in seen or not isinstance(operation.get("had_original"),bool) or operation.get("phase") not in TRANSACTION_PHASES:
            raise RuntimeError("transaction journal replacement is outside the managed whitelist")
        seen.add(label)
        action=operation.get("action","replace")
        if action not in {"replace","remove"} or (action=="remove" and not operation["had_original"]):
            raise RuntimeError("transaction journal action is invalid")
        validate_identity(operation.get("original_identity"),operation["had_original"])
        validate_identity(operation.get("candidate_identity"),action=="replace")
        if value["schema"] in {FULL_CONTENT_TRANSACTION_SCHEMA,TRANSACTION_SCHEMA}:
            fields=[("original_content_sha256",operation["had_original"]),("candidate_content_sha256",action=="replace")]
            if value["schema"]==TRANSACTION_SCHEMA: fields.append(("candidate_committed_sha256",action=="replace"))
            for field,required in fields:
                digest=operation.get(field)
                if (required and (not isinstance(digest,str) or re.fullmatch(r"[0-9a-f]{64}",digest) is None)) or (not required and digest is not None):
                    raise RuntimeError("transaction journal content digest is invalid")
    if value["state"] in {"initializing","staging"} and operations:
        raise RuntimeError("a pre-commit transaction journal cannot contain replacements")
    if value["state"] in {"committing","committed"} and not operations:
        raise RuntimeError("a commit transaction journal has no replacements")


def write_transaction_journal(target,value,create=False):
    assert_namespace_binding(current_target_path())
    path=transaction_journal_path(target); value=dict(value); value["journal_sha256"]=transaction_payload_digest(value)
    encoded=(json.dumps(value,ensure_ascii=False,indent=2)+"\n").encode()
    if create:
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)
        descriptor=os.open(str(path),flags,0o600)
        try:
            with os.fdopen(descriptor,"wb",closefd=False) as handle:
                handle.write(encoded); handle.flush(); os.fsync(descriptor)
        finally: os.close(descriptor)
        fsync_directory(path.parent)
        assert_namespace_binding(current_target_path())
        return value
    secure_journal_stat(path)
    staging=transaction_staging_path(target,value["transaction_id"])
    if not staging.is_dir() or staging.is_symlink(): raise RuntimeError("transaction staging root is unavailable for a journal update")
    descriptor,raw=tempfile.mkstemp(prefix=".journal-update-",dir=str(staging)); temporary=Path(raw)
    try:
        os.fchmod(descriptor,0o600)
        with os.fdopen(descriptor,"wb") as handle:
            handle.write(encoded); handle.flush(); os.fsync(handle.fileno())
        durable_replace(temporary,path)
    finally:
        if temporary.exists(): temporary.unlink()
    assert_namespace_binding(current_target_path())
    return value


def filesystem_identity(path):
    observed=path.lstat()
    if stat.S_ISLNK(observed.st_mode): raise RuntimeError(f"transaction target is a symlink: {path}")
    if not (stat.S_ISREG(observed.st_mode) or stat.S_ISDIR(observed.st_mode)):
        raise RuntimeError(f"transaction target is not a file or directory: {path}")
    if stat.S_ISREG(observed.st_mode) and observed.st_nlink!=1:
        raise RuntimeError(f"transaction target is a hard-linked regular file: {path}")
    return {"dev":observed.st_dev,"ino":observed.st_ino,"mode":stat.S_IFMT(observed.st_mode)}


def planned_path_snapshot(path,include_bytes=False):
    """Capture one planning authority from an opened, no-follow descriptor."""
    parent=open_transaction_directory(path.parent,"planned path parent")
    try:
        descriptor=os.open(path.name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=parent)
        try:
            opened=os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1:
                raise RuntimeError(f"planned rewrite path is not one regular file: {path}")
            digest=hashlib.sha256(); chunks=[]; remaining=opened.st_size
            while remaining:
                chunk=os.read(descriptor,min(65536,remaining))
                if not chunk: raise RuntimeError("planned rewrite path was truncated while read")
                digest.update(chunk); remaining-=len(chunk)
                if include_bytes: chunks.append(chunk)
            if os.read(descriptor,1): raise RuntimeError("planned rewrite path grew while read")
            after=os.fstat(descriptor)
            if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,stat.S_IMODE(after.st_mode))!=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,stat.S_IMODE(opened.st_mode)):
                raise RuntimeError("planned rewrite path changed while read")
            result={"identity":{"dev":opened.st_dev,"ino":opened.st_ino,"mode":stat.S_IFMT(opened.st_mode)},"sha256":digest.hexdigest(),"mode":stat.S_IMODE(opened.st_mode),"size":opened.st_size}
            if include_bytes: result["bytes"]=b"".join(chunks)
            return result
        finally: os.close(descriptor)
    finally: os.close(parent)


def require_planned_path(path,snapshot):
    observed=planned_path_snapshot(path,include_bytes=False)
    expected={key:value for key,value in snapshot.items() if key!="bytes"}
    if observed!=expected: raise RuntimeError(f"planned path changed before staging: {path}")


def transaction_content_sha256(path):
    """Hash one bounded file/directory tree without following links."""
    records=[]; totals=[0,0]
    def visit(current,relative,depth=0):
        if depth>MAX_INSTALL_TREE_DEPTH: raise RuntimeError("transaction content depth limit exceeded")
        before=os.lstat(current)
        if stat.S_ISLNK(before.st_mode):
            raise RuntimeError("transaction content contains a symlink")
        totals[0]+=1
        if totals[0]>20000: raise RuntimeError("transaction content exceeds the entry limit")
        mode=stat.S_IMODE(before.st_mode)
        if stat.S_ISREG(before.st_mode):
            if before.st_nlink!=1: raise RuntimeError("transaction content contains a hard-linked file")
            totals[1]+=before.st_size
            if totals[1]>512*1024*1024: raise RuntimeError("transaction content exceeds the byte limit")
            descriptor=os.open(str(current),os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
            try:
                opened=os.fstat(descriptor)
                if (opened.st_dev,opened.st_ino,opened.st_size)!=(before.st_dev,before.st_ino,before.st_size):
                    raise RuntimeError("transaction file changed while opening")
                digest=hashlib.sha256(); remaining=before.st_size
                while remaining:
                    chunk=os.read(descriptor,min(65536,remaining))
                    if not chunk: raise RuntimeError("transaction file was truncated while hashing")
                    digest.update(chunk); remaining-=len(chunk)
                if os.read(descriptor,1): raise RuntimeError("transaction file grew while hashing")
                after=os.fstat(descriptor)
                if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)!=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns):
                    raise RuntimeError("transaction file changed while hashing")
            finally: os.close(descriptor)
            records.append([relative,"file",mode,before.st_size,digest.hexdigest()]); return
        if not stat.S_ISDIR(before.st_mode): raise RuntimeError("transaction content contains a special file")
        names=sorted(bounded_directory_names(current,"transaction content",20001-totals[0])); records.append([relative,"directory",mode,len(names)])
        for name in names:
            if name in {".",".."} or "/" in name: raise RuntimeError("transaction content contains an unsafe name")
            visit(current/name,name if relative=="." else relative+"/"+name,depth+1)
        after=os.lstat(current)
        if (after.st_dev,after.st_ino,after.st_mtime_ns)!=(before.st_dev,before.st_ino,before.st_mtime_ns):
            raise RuntimeError("transaction directory changed while hashing")
    visit(path,".")
    return canonical_sha256(records)


def committed_content_sha256(path,label):
    if label!=".agent": return transaction_content_sha256(path)
    try:
        manifest_snapshot=planned_path_snapshot(path/".workflow-manifest.json",include_bytes=True)
    except FileNotFoundError:
        # Uninstall publishes a manifest-free private-state survivor tree. Bind
        # every remaining inode/mode/byte rather than applying install semantics.
        return transaction_content_sha256(path)
    try: installed=json.loads(manifest_snapshot["bytes"])
    except (UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("committed manifest is invalid") from error
    if not isinstance(installed,dict): raise RuntimeError("committed manifest managed binding is invalid")
    managed=previous_agent_files(installed)
    modes=installed.get("agent_modes")
    if not isinstance(managed,dict) or (modes is not None and (not isinstance(modes,dict) or set(managed)!=set(modes))):
        raise RuntimeError("committed manifest managed binding is invalid")
    records=[[".workflow-manifest.json",manifest_snapshot["sha256"],manifest_snapshot["mode"]]]
    for relative in sorted(managed):
        if not isinstance(relative,str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise RuntimeError("committed manifest contains an unsafe managed path")
        try: snapshot=planned_path_snapshot(path/relative)
        except FileNotFoundError:
            records.append([relative,"absent"]); continue
        records.append([relative,snapshot["sha256"],snapshot["mode"]])
    return canonical_sha256(records)


def content_matches(path,expected):
    try: return transaction_content_sha256(path)==expected
    except (OSError,RuntimeError): return False


def committed_content_matches(path,label,expected):
    try: return committed_content_sha256(path,label)==expected
    except (OSError,RuntimeError): return False


def identity_matches(path,expected):
    try: return filesystem_identity(path)==expected
    except (FileNotFoundError,RuntimeError): return False


def validate_transaction_ancestors(target,path,allow_missing=False):
    expected=transaction_targets(target)
    if path not in expected.values(): raise RuntimeError("transaction target is outside the managed whitelist")
    current=path.parent
    while current!=target:
        if not current.exists() and not current.is_symlink():
            if allow_missing:
                current=current.parent
                continue
            raise RuntimeError(f"transaction target ancestor is missing: {current}")
        observed=current.lstat()
        if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
            raise RuntimeError(f"transaction target ancestor is unsafe: {current}")
        if observed.st_uid!=os.geteuid() or stat.S_IMODE(observed.st_mode)&0o022:
            raise RuntimeError(f"transaction target ancestor is not owner-controlled: {current}")
        current=current.parent


def validate_staging_root(target,value,allow_missing=False,allow_initializing_marker_temp=False):
    staging=transaction_staging_path(target,value["transaction_id"])
    if not staging.exists() and not staging.is_symlink():
        if allow_missing: return staging
        raise RuntimeError("transaction staging root is missing")
    observed=staging.lstat()
    if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode) or observed.st_uid!=os.geteuid():
        raise RuntimeError("transaction staging root is unsafe")
    marker=staging/".agent-workflow-transaction-marker.json"
    if not marker.is_file() or marker.is_symlink():
        children=[]
        with os.scandir(staging) as scanner:
            for entry in scanner:
                if len(children)>=64: raise RuntimeError("transaction staging root has too many entries")
                children.append(Path(entry.path))
        if not children: return staging
        # A hard death can occur after mkstemp has created the marker's
        # private temporary file but before atomic_json renames it.  The
        # initializing journal proves that no managed target has been touched;
        # accept only those exact owner-controlled marker temporaries so the
        # next invocation can remove them and recover deterministically.
        marker_prefix=f".{marker.name}."
        if allow_initializing_marker_temp and value.get("state")=="initializing":
            for child in children:
                observed=child.lstat()
                if (
                    not child.name.startswith(marker_prefix)
                    or not stat.S_ISREG(observed.st_mode)
                    or stat.S_ISLNK(observed.st_mode)
                    or observed.st_uid!=os.geteuid()
                    or observed.st_nlink!=1
                    or observed.st_mode&0o022
                ):
                    raise RuntimeError("transaction staging contains an untrusted pre-marker object")
            return staging
        raise RuntimeError("transaction staging marker is missing or unsafe")
    try: marked=json.loads(read_installer_text(marker,label="migration marker"))
    except (OSError,UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("transaction staging marker is invalid") from error
    if marked!={"schema":value["schema"],"transaction_id":value["transaction_id"],"target_root":transaction_target_root(target)}:
        raise RuntimeError("transaction staging marker does not match the journal")
    return staging


def finish_transaction_cleanup(target,value):
    assert_namespace_binding(current_target_path())
    staging=validate_staging_root(
        target,value,allow_missing=True,
        allow_initializing_marker_temp=value.get("state")=="initializing",
    )
    if staging.exists() or staging.is_symlink():
        durable_remove(
            staging,expected_identity=filesystem_identity(staging),
            last_child=".agent-workflow-transaction-marker.json",
        )
    journal=transaction_journal_path(target)
    if journal.exists() or journal.is_symlink():
        observed=secure_journal_stat(journal)
        expected={"dev":observed.st_dev,"ino":observed.st_ino,"mode":stat.S_IFMT(observed.st_mode)}
        durable_remove(journal,expected_identity=expected)
    assert_namespace_binding(current_target_path())


def rollback_transaction(target,value):
    global BOUND_TARGET_IDENTITY
    staging=validate_staging_root(target,value)
    allowed=transaction_targets(target)
    # Validate the entire rollback graph before changing any path.  A mismatch
    # in a later operation or created directory must not leave an earlier
    # predecessor partially restored.
    for index,operation in reversed(list(enumerate(value["replacements"]))):
        target_path=allowed[operation["label"]]; candidate=staging/operation["label"]; backup=staging/"backups"/str(index)
        validate_transaction_ancestors(target,target_path,allow_missing=True)
        target_exists=target_path.exists() or target_path.is_symlink(); candidate_exists=candidate.exists() or candidate.is_symlink(); backup_exists=backup.exists() or backup.is_symlink()
        if backup_exists:
            if (not operation["had_original"] or not identity_matches(backup,operation["original_identity"])
                    or not committed_content_matches(backup,operation["label"],operation["original_content_sha256"])):
                raise RuntimeError("transaction backup does not match the recorded predecessor content")
            if target_exists and (operation.get("action","replace")=="remove" or not identity_matches(target_path,operation["candidate_identity"]) or not committed_content_matches(target_path,operation["label"],operation.get("candidate_committed_sha256",operation["candidate_content_sha256"]))):
                raise RuntimeError("transaction target changed after the interrupted install")
        elif operation["had_original"]:
            if not target_exists or not identity_matches(target_path,operation["original_identity"]) or not committed_content_matches(target_path,operation["label"],operation["original_content_sha256"]):
                raise RuntimeError("transaction predecessor is missing and no valid backup remains")
        elif target_exists and (candidate_exists or not identity_matches(target_path,operation["candidate_identity"]) or not committed_content_matches(target_path,operation["label"],operation.get("candidate_committed_sha256",operation["candidate_content_sha256"]))):
            raise RuntimeError("transaction target cannot be safely identified for rollback")
    for record in value["created_directories"]:
        relative=record if isinstance(record,str) else record["path"]
        expected=None if isinstance(record,str) else record["identity"]
        directory=target if relative=="." else target/relative
        if directory.exists() or directory.is_symlink():
            if expected is None: raise RuntimeError("created transaction directory exists without a durable identity")
            if not identity_matches(directory,expected): raise RuntimeError("created transaction directory was replaced before rollback")
    for index,operation in reversed(list(enumerate(value["replacements"]))):
        target_path=allowed[operation["label"]]; candidate=staging/operation["label"]; backup=staging/"backups"/str(index)
        # A crash is legal after the committing journal is durable but before
        # every declared parent directory has been created.  Missing ancestors
        # therefore mean this operation is untouched; any existing ancestor
        # must still be a real directory (never a symlink).
        validate_transaction_ancestors(target,target_path,allow_missing=True)
        target_exists=target_path.exists() or target_path.is_symlink()
        candidate_exists=candidate.exists() or candidate.is_symlink()
        backup_exists=backup.exists() or backup.is_symlink()
        if backup_exists:
            if (not operation["had_original"] or not identity_matches(backup,operation["original_identity"])
                    or not committed_content_matches(backup,operation["label"],operation["original_content_sha256"])):
                raise RuntimeError("transaction backup does not match the recorded predecessor content")
            if target_exists:
                if operation.get("action","replace")=="remove" or not identity_matches(target_path,operation["candidate_identity"]) or not committed_content_matches(target_path,operation["label"],operation.get("candidate_committed_sha256",operation["candidate_content_sha256"])):
                    raise RuntimeError("transaction target changed after the interrupted install")
                durable_remove(target_path,expected_identity=operation["candidate_identity"])
            target_path.parent.mkdir(parents=True,exist_ok=True); fsync_directory(target_path.parent)
            durable_replace(backup,target_path,
                            expected_source=operation["original_identity"],expected_target=None)
        elif operation["had_original"]:
            if not target_exists or not identity_matches(target_path,operation["original_identity"]) or not committed_content_matches(target_path,operation["label"],operation["original_content_sha256"]):
                raise RuntimeError("transaction predecessor is missing and no valid backup remains")
        elif target_exists:
            if candidate_exists or not identity_matches(target_path,operation["candidate_identity"]) or not committed_content_matches(target_path,operation["label"],operation.get("candidate_committed_sha256",operation["candidate_content_sha256"])):
                raise RuntimeError("transaction target cannot be safely identified for rollback")
            durable_remove(target_path,expected_identity=operation["candidate_identity"])
        if operation["had_original"]:
            if not identity_matches(target_path,operation["original_identity"]) or not committed_content_matches(target_path,operation["label"],operation["original_content_sha256"]): raise RuntimeError("transaction rollback did not restore the exact predecessor content")
        elif target_path.exists() or target_path.is_symlink(): raise RuntimeError("transaction rollback did not restore target absence")
    for record in reversed(value["created_directories"]):
        if isinstance(record,str):
            relative=record; expected=None
        else:
            relative=record["path"]; expected=record["identity"]
        directory=target if relative=="." else target/relative
        if directory.exists() or directory.is_symlink():
            if expected is None:
                raise RuntimeError("created transaction directory exists without a durable identity")
            if not identity_matches(directory,expected):
                raise RuntimeError("created transaction directory was replaced before rollback")
            if relative==".": BOUND_TARGET_IDENTITY=None
            durable_remove_empty_directory(directory,expected)
    finish_transaction_cleanup(target,value)


def recover_transaction(target):
    value=read_transaction_journal(target)
    if value is None: return False
    if value["state"] in {"initializing","staging"}:
        finish_transaction_cleanup(target,value)
    elif value["state"]=="committing":
        if value["schema"] not in {FULL_CONTENT_TRANSACTION_SCHEMA,TRANSACTION_SCHEMA}:
            raise RuntimeError("legacy transaction cannot safely roll back without full-tree content identities")
        rollback_transaction(target,value)
    else:
        staging=validate_staging_root(target,value,allow_missing=True)
        for operation in value["replacements"]:
            target_path=transaction_targets(target)[operation["label"]]
            validate_transaction_ancestors(target,target_path)
            if operation.get("action","replace")=="remove":
                if target_path.exists() or target_path.is_symlink():
                    raise RuntimeError("committed transaction removal target reappeared")
            elif (not identity_matches(target_path,operation["candidate_identity"])
                  or not committed_content_matches(target_path,operation["label"],operation.get("candidate_committed_sha256",operation["candidate_content_sha256"]))):
                raise RuntimeError("committed transaction target no longer matches its immutable candidate content")
        if staging.exists() or staging.is_symlink(): finish_transaction_cleanup(target,value)
        else:
            journal=transaction_journal_path(target); observed=secure_journal_stat(journal)
            expected={"dev":observed.st_dev,"ino":observed.st_ino,"mode":stat.S_IFMT(observed.st_mode)}
            durable_remove(journal,expected_identity=expected)
    return True


def begin_transaction(target):
    if transaction_journal_path(target).exists() or transaction_journal_path(target).is_symlink():
        raise RuntimeError("an unrecovered installer transaction already exists")
    transaction_id=uuid.uuid4().hex
    value={"schema":TRANSACTION_SCHEMA,"transaction_id":transaction_id,"target_root":transaction_target_root(target),"state":"initializing","replacements":[],"created_directories":[]}
    value=write_transaction_journal(target,value,create=True)
    staging=transaction_staging_path(target,transaction_id)
    try:
        staging.mkdir(mode=0o700); fsync_directory(staging.parent)
        if os.environ.get("AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_DURING_MARKER")=="1":
            descriptor,_raw=tempfile.mkstemp(
                prefix="..agent-workflow-transaction-marker.json.",dir=str(staging),
            )
            try:
                os.fchmod(descriptor,0o600); os.write(descriptor,b'{"partial":'); os.fsync(descriptor)
            finally: os.close(descriptor)
            fsync_directory(staging)
            os._exit(96)
        atomic_json(staging/".agent-workflow-transaction-marker.json",{
            "schema":TRANSACTION_SCHEMA,"transaction_id":transaction_id,"target_root":transaction_target_root(target),
        })
        fsync_directory(staging)
        value["state"]="staging"; write_transaction_journal(target,value)
    except Exception:
        recover_transaction(target)
        raise
    return staging


def planned_transaction_target(path):
    """Record exact namespace plus immutable managed authority."""
    try: os.lstat(path)
    except FileNotFoundError: return {"present":False}
    digest=committed_content_sha256(path,".agent") if Path(path).name==".agent" else transaction_content_sha256(path)
    return {"present":True,"identity":filesystem_identity(path),"content_sha256":digest}


def planned_transaction_target_from_snapshot(snapshot):
    if snapshot is None: return {"present":False}
    # planned_path_snapshot binds raw file bytes, while transaction recovery
    # binds the canonical transaction_content_sha256 record.
    content=canonical_sha256([[".","file",snapshot["mode"],snapshot["size"],snapshot["sha256"]]])
    return {"present":True,"identity":snapshot["identity"],"content_sha256":content}


def planned_transaction_root(path):
    """Bind root absence or directory identity without freezing project contents."""
    try: os.lstat(path)
    except FileNotFoundError: return {"present":False}
    return {"present":True,"identity":filesystem_identity(path)}


def require_planned_transaction_target(path,planned):
    if not isinstance(planned,dict) or set(planned) not in ({"present"},{"present","identity"},{"present","identity","content_sha256"}):
        raise RuntimeError("transaction target plan is malformed")
    try: os.lstat(path); present=True
    except FileNotFoundError: present=False
    if planned.get("present") is False:
        if present: raise RuntimeError(f"planned transaction target absence changed before commit: {path}")
        return
    if not present:
        raise RuntimeError(f"planned transaction target disappeared before commit: {path}")
    if not identity_matches(path,planned.get("identity")):
        raise RuntimeError(f"planned transaction target identity or content changed before commit: {path}")
    if "content_sha256" in planned and not (committed_content_matches(path,".agent",planned.get("content_sha256")) if Path(path).name==".agent" else content_matches(path,planned.get("content_sha256"))):
        raise RuntimeError(f"planned transaction target identity or content changed before commit: {path}")


def commit_transaction(target,candidate_parent,replacements,planned_targets=None,planned_root=IDENTITY_UNSPECIFIED):
    global BOUND_TARGET_IDENTITY
    journal=read_transaction_journal(target)
    if journal is None or journal["state"]!="staging": raise RuntimeError("transaction is not ready to commit")
    allowed=transaction_targets(target); operations=[]; required_directories=[]
    if planned_targets is None:
        planned_targets={label:planned_transaction_target(target_path) for label,target_path in allowed.items() if any(target_path==pair[1] for pair in replacements)}
    if planned_root is not IDENTITY_UNSPECIFIED:
        require_planned_transaction_target(target,planned_root)
    for candidate,target_path in replacements:
        labels=[label for label,expected in allowed.items() if expected==target_path]
        action="remove" if candidate is None else "replace"
        if len(labels)!=1 or (candidate is not None and candidate!=candidate_parent/labels[0]):
            raise RuntimeError("transaction replacement is outside the managed whitelist")
        if candidate is not None and (not candidate.exists() or candidate.is_symlink()):
            raise RuntimeError("transaction candidate is missing or unsafe")
        label=labels[0]
        if label not in planned_targets: raise RuntimeError(f"transaction target lacks planning authority: {label}")
        planned=planned_targets[label]; require_planned_transaction_target(target_path,planned)
        had_original=planned["present"]
        if action=="remove" and not had_original:
            raise RuntimeError("transaction removal target disappeared before commit")
        operations.append({
            "label":label,"action":action,"had_original":had_original,
            "original_identity":planned.get("identity"),
            "candidate_identity":filesystem_identity(candidate) if candidate is not None else None,
            "original_content_sha256":planned.get("content_sha256"),
            "candidate_content_sha256":transaction_content_sha256(candidate) if candidate is not None else None,
            "candidate_committed_sha256":committed_content_sha256(candidate,labels[0]) if candidate is not None else None,
            "phase":"prepared",
        })
        if action=="replace":
            current=target_path.parent
            while True:
                if not current.exists() and not current.is_symlink(): required_directories.append(current)
                if current==target: break
                current=current.parent
    # Recheck the complete plan immediately before publishing the durable
    # committing journal. durable_replace performs the final descriptor-relative
    # identity/absence CAS at each namespace mutation.
    if planned_root is not IDENTITY_UNSPECIFIED:
        require_planned_transaction_target(target,planned_root)
    for operation in operations:
        require_planned_transaction_target(allowed[operation["label"]],planned_targets[operation["label"]])
    directories=sorted(set(required_directories),key=lambda value:len(value.parts))
    directory_labels=[]
    for directory in directories:
        relative="." if directory==target else str(directory.relative_to(target))
        if relative not in {".","plugins",".agents",".agents/plugins"}:
            raise RuntimeError("transaction requires a directory outside the managed whitelist")
        directory_labels.append(relative)
    for _candidate,target_path in replacements:
        validate_transaction_ancestors(target,target_path,allow_missing=True)
    # Prebuild each minimal missing directory subtree under the private staging
    # root.  Its inode identities are durable before the committing journal is
    # published; one rename then makes each subtree visible atomically.
    directory_stage=candidate_parent/"created-directories"
    directory_stage.mkdir(mode=0o700)
    minimal_directories=[directory for directory in directories if not any(parent in set(directories) for parent in directory.parents)]
    staged_roots={}
    staged_paths={}
    for index,directory in enumerate(minimal_directories):
        staged=directory_stage/str(index); staged.mkdir(mode=0o755); os.chmod(staged,0o755)
        staged_roots[directory]=staged; staged_paths[directory]=staged
        for descendant in directories:
            if descendant!=directory and directory in descendant.parents:
                child=staged/descendant.relative_to(directory); child.mkdir(parents=True,mode=0o755); os.chmod(child,0o755)
                staged_paths[descendant]=child
    fsync_tree(candidate_parent)
    backup_root=candidate_parent/"backups"; backup_root.mkdir(parents=True,exist_ok=True); fsync_directory(candidate_parent)
    journal["state"]="committing"; journal["replacements"]=operations
    journal["created_directories"]=[
        {"path":relative,"identity":filesystem_identity(staged_paths[directory])}
        for directory,relative in zip(directories,directory_labels)
    ]
    journal=write_transaction_journal(target,journal)
    crash_after_directory=int(os.environ.get("AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_DIRECTORY","0") or "0")
    created_count=0
    for directory in minimal_directories:
        durable_replace(staged_roots[directory],directory,
                        expected_source=filesystem_identity(staged_roots[directory]),expected_target=None)
        if directory==target: BOUND_TARGET_IDENTITY=inode_identity(os.lstat(target))
        created_count+=1
        if crash_after_directory and created_count==crash_after_directory: os._exit(95)
    for _candidate,target_path in replacements: validate_transaction_ancestors(target,target_path)
    crash_after=int(os.environ.get("AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_TARGET","0") or "0")
    completed=0
    try:
        for index,operation in enumerate(operations):
            candidate=candidate_parent/operation["label"]; target_path=allowed[operation["label"]]; backup=backup_root/str(index)
            if operation["action"]=="replace":
                target_path.parent.mkdir(parents=True,exist_ok=True); fsync_directory(target_path.parent)
            if operation["had_original"]:
                if not committed_content_matches(target_path,operation["label"],operation["original_content_sha256"]): raise RuntimeError("transaction predecessor content changed before backup")
                durable_replace(target_path,backup,
                                expected_source=operation["original_identity"],expected_target=None)
                try:
                    observed_predecessor=committed_content_sha256(backup,operation["label"])
                except Exception as error:
                    # Preserve the exact inode that was moved even when a live writer
                    # prevents a stable content snapshot. Never knowingly strand the
                    # managed pathname behind the transaction journal.
                    durable_replace(backup,target_path,
                                    expected_source=operation["original_identity"],expected_target=None)
                    try:
                        operation["original_content_sha256"]=committed_content_sha256(target_path,operation["label"])
                        journal=write_transaction_journal(target,journal)
                    except Exception:
                        pass
                    raise RuntimeError("transaction predecessor could not be stably captured after backup rename; original inode was restored") from error
                if observed_predecessor!=operation["original_content_sha256"]:
                    # Bind the bytes actually moved before the next namespace
                    # transition. A crash before restoration is then recoverable.
                    operation["original_content_sha256"]=observed_predecessor
                    journal=write_transaction_journal(target,journal)
                    durable_replace(backup,target_path,
                                    expected_source=operation["original_identity"],expected_target=None)
                    raise RuntimeError("transaction predecessor content changed during backup rename; original inode was restored")
                operation["phase"]="backed_up"; journal=write_transaction_journal(target,journal)
            if operation["action"]=="replace":
                if not content_matches(candidate,operation["candidate_content_sha256"]): raise RuntimeError("transaction candidate content changed before install")
                durable_replace(candidate,target_path,
                                expected_source=operation["candidate_identity"],expected_target=None)
                if not committed_content_matches(target_path,operation["label"],operation.get("candidate_committed_sha256",operation["candidate_content_sha256"])): raise RuntimeError("transaction candidate content changed during rename")
            operation["phase"]="installed"; journal=write_transaction_journal(target,journal)
            completed+=1
            if crash_after and completed==crash_after: os._exit(97)
        journal["state"]="committed"; journal=write_transaction_journal(target,journal)
        ready=os.environ.get("AGENT_WORKFLOW_INSTALL_SELF_TEST_COMMIT_READY"); release=os.environ.get("AGENT_WORKFLOW_INSTALL_SELF_TEST_COMMIT_RELEASE")
        if ready and release:
            Path(ready).write_text("ready\n",encoding="utf-8")
            while not Path(release).exists(): time.sleep(0.01)
        if os.environ.get("AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_COMMIT")=="1": os._exit(98)
        finish_transaction_cleanup(target,journal)
    except Exception:
        current=read_transaction_journal(target)
        if current is not None and current["state"]!="committed": rollback_transaction(target,current)
        raise


def abort_transaction(target):
    value=read_transaction_journal(target)
    if value is not None:
        if value["state"]=="committing": rollback_transaction(target,value)
        elif value["state"]=="committed": finish_transaction_cleanup(target,value)
        else: finish_transaction_cleanup(target,value)


def validate_legacy_active_context(source,destination):
    """Validate the installed capsule exactly, ignoring only its age lease."""
    task=json.loads(read_installer_text(destination/"state/TASK.json",label="candidate task"))
    if task.get("status") in {"idle",None}: return
    probe="""
import copy,os,sys
sys.path.insert(0,os.environ['AGENT_WORKFLOW_TRUSTED_SCRIPTS'])
import contextctl
original=contextctl.load_json
def load(path):
    value=original(path)
    if path==contextctl.CONFIG_PATH:
        value=copy.deepcopy(value)
        value.setdefault('context',{})['max_active_checkpoint_age_minutes']=10**9
    return value
contextctl.load_json=load
raise SystemExit(contextctl.validate_context(quiet=True))
"""
    result=run_installer_command(
        [sys.executable,"-I","-B","-c",probe],cwd=destination.parent,timeout=120,env=trusted_python_env(source),
    )
    if result.returncode:
        raise RuntimeError(
            "active context has drift or corruption beyond checkpoint age; repair it before workflow update"
        )


def trusted_python_env(source):
    environment=os.environ.copy()
    for name in ("PYTHONHOME","PYTHONPATH","PYTHONSTARTUP","PYTHONINSPECT","PYTHONUSERBASE","AGENT_WORKFLOW_INHERITED_PUBLICATION_FDS"):
        environment.pop(name,None)
    environment.update({"PYTHONDONTWRITEBYTECODE":"1","PYTHONSAFEPATH":"1",
                        "AGENT_WORKFLOW_TRUSTED_SCRIPTS":str((source/"scripts").resolve())})
    return environment


def private_snapshot(root):
    snapshot={}
    entries=list(bounded_tree_entries(root,"private state snapshot"))
    for item,metadata in sorted(entries,key=lambda value:value[0].relative_to(root).as_posix().encode()):
        relative=str(item.relative_to(root))
        if stat.S_ISLNK(metadata.st_mode): snapshot[relative]=("link",os.readlink(item))
        elif stat.S_ISREG(metadata.st_mode): snapshot[relative]=("file",sha(item))
        elif stat.S_ISDIR(metadata.st_mode): snapshot[relative]=("dir",None)
        else: snapshot[relative]=("special",None)
    return snapshot


def candidate_tool(source,destination, relative, *args, expected=(0,),readonly=False):
    before=private_snapshot(destination) if readonly else None
    launcher=("import runpy,sys;trusted=sys.argv[1];script=sys.argv[2];"
              "sys.path.insert(0,trusted);sys.argv=[script,*sys.argv[3:]];runpy.run_path(script,run_name='__main__')")
    command=[sys.executable,"-I","-B","-c",launcher,str((source/"scripts").resolve()),str(source/relative),*args]
    environment=trusted_python_env(source); pass_fds=()
    if INSTALLER_PUBLICATION_AUTHORITY is not None:
        parent_fd,publication_fd=INSTALLER_PUBLICATION_AUTHORITY
        if LOGICAL_TARGET_ROOT is None: raise RuntimeError("installer publication target authority is unavailable")
        environment["AGENT_WORKFLOW_INHERITED_PUBLICATION_FDS"]=json.dumps({"schema":"agent-installer-publication-authority/v2","target":LOGICAL_TARGET_ROOT.name,"parent_fd":parent_fd,"publication_fd":publication_fd},sort_keys=True,separators=(",",":"))
        pass_fds=(parent_fd,publication_fd)
    result=run_installer_command(command,cwd=destination.parent,timeout=180,env=environment,pass_fds=pass_fds)
    if result.returncode not in expected:
        raise RuntimeError(
            f"candidate tool failed ({relative} {' '.join(args)}):\n{result.stdout.strip()}"
        )
    if readonly and private_snapshot(destination)!=before:
        raise RuntimeError(f"candidate validation mutated private state: {relative} {' '.join(args)}")
    return result.stdout


def existing_skill_activation_valid(destination,task):
    receipt=task.get("skill_activation"); path=destination/"state/SKILL_ACTIVATION.json"
    if not isinstance(receipt,dict): return False
    try: metadata=os.lstat(path)
    except FileNotFoundError: return False
    if not stat.S_ISREG(metadata.st_mode): return False
    raw=read_installer_bytes(path,label="installer file")
    if receipt.get("path")!=".agent/state/SKILL_ACTIVATION.json" or receipt.get("sha256")!=hashlib.sha256(raw).hexdigest() or receipt.get("bytes")!=len(raw): return False
    try: payload=json.loads(raw)
    except (UnicodeError,json.JSONDecodeError): return False
    unsigned={key:value for key,value in payload.items() if key!="activation_sha256"} if isinstance(payload,dict) else {}
    digest=canonical_sha256(unsigned)
    return (payload.get("schema")=="agent-task-skill-activation/v2" and payload.get("task_generation_id")==task.get("task_generation_id") and payload.get("activation_sha256")==digest and receipt.get("activation_sha256")==digest and payload.get("lock_sha256")==receipt.get("lock_sha256") and receipt.get("skill_ids")==[item.get("id") for item in payload.get("skills",[]) if isinstance(item,dict)] and receipt.get("builtin_skill_ids")==[item.get("id") for item in payload.get("builtins",[]) if isinstance(item,dict)])


def candidate_existing_skill_activation_valid(source,destination,task):
    probe="""
import json,os,sys
from pathlib import Path
sys.path.insert(0,os.environ['AGENT_WORKFLOW_TRUSTED_SCRIPTS'])
import agentctl
agentctl.AGENT_DIR=Path.cwd()/'.agent'
agentctl.BUILTIN_SKILL_MANIFEST_ROOT=Path(os.environ['AGENT_WORKFLOW_TRUSTED_SCRIPTS']).parent
raw=sys.stdin.buffer.read(16777217)
if len(raw)>16777216: raise SystemExit('task input exceeds limit')
task=json.loads(raw)
errors=agentctl.task_skill_activation_errors(task)
if errors:
    print('AGENT_SKILL_ACTIVATION_INVALID '+errors[0])
    raise SystemExit(3)
print('AGENT_SKILL_ACTIVATION_VALID')
"""
    result=run_installer_command([sys.executable,"-I","-B","-c",probe],cwd=destination.parent,input_data=json.dumps(task),timeout=180,env=trusted_python_env(source))
    return result.returncode==0 and result.stdout.strip()=="AGENT_SKILL_ACTIVATION_VALID"


def candidate_skill_activation_snapshot(source,destination,task_generation_id):
    probe="""
import base64,json,os,sys
from pathlib import Path
sys.path.insert(0,os.environ['AGENT_WORKFLOW_TRUSTED_SCRIPTS'])
import agentctl
# Execute trusted source code against the transaction candidate's private state,
# never against the installer's own source .agent tree.
agentctl.AGENT_DIR=Path.cwd()/'.agent'
agentctl.BUILTIN_SKILL_MANIFEST_ROOT=Path(os.environ['AGENT_WORKFLOW_TRUSTED_SCRIPTS']).parent
verification,lock,captured=agentctl.capture_dynamic_skill_activation()
receipt,data=agentctl.build_task_skill_activation(sys.argv[1],verification,lock,captured)
print('AGENT_SKILL_ACTIVATION '+json.dumps({'receipt':receipt,'data_b64':base64.b64encode(data).decode('ascii')},sort_keys=True,separators=(',',':')))
"""
    result=run_installer_command([sys.executable,"-I","-B","-c",probe,task_generation_id],cwd=destination.parent,timeout=180,env=trusted_python_env(source))
    if result.returncode:
        raise RuntimeError("could not verify and snapshot dynamic Skills during migration:\n"+result.stdout.strip())
    marker=next((line[len('AGENT_SKILL_ACTIVATION '):] for line in result.stdout.splitlines() if line.startswith('AGENT_SKILL_ACTIVATION ')),None)
    try:
        value=json.loads(marker); data=__import__('base64').b64decode(value['data_b64'],validate=True); receipt=value['receipt']
    except (TypeError,ValueError,KeyError,json.JSONDecodeError) as error:
        raise RuntimeError("candidate Skill activation snapshot output is invalid") from error
    if (not isinstance(receipt,dict) or receipt.get('sha256')!=hashlib.sha256(data).hexdigest() or receipt.get('bytes')!=len(data)):
        raise RuntimeError("candidate Skill activation snapshot receipt is invalid")
    return receipt,data


def initialize_fresh_context(source,destination):
    """Bind the idle seed capsule to this candidate's final private config."""
    probe="""
import argparse,hashlib,json,os,sys
sys.path.insert(0,os.environ['AGENT_WORKFLOW_TRUSTED_SCRIPTS'])
import contextctl
p=contextctl.CONTEXT_PATH
# Seed bytes are a template input, never predecessor authority for an adopter.
previous={}
args=argparse.Namespace(reason='fresh-project-seed',summary='fresh isolated idle state',source='project-init:bootstrap',source_tokens=800,fact=[],file=[],evidence=[],risk=[],resolve_risk=[],transition=False,reset=True,host_compaction=False)
capsule=contextctl.build_capsule(args,'verified',previous,'none')
contextctl.atomic_json(p,capsule)
raise SystemExit(contextctl.validate_context())
"""
    result=run_installer_command(
        [sys.executable,"-I","-B","-c",probe],cwd=destination.parent,timeout=120,env=trusted_python_env(source),
    )
    if result.returncode:
        raise RuntimeError("fresh private context initialization failed:\n"+result.stdout.strip())


def _current_provider_approvals_bound(task):
    approvals=task.get("gate_approvals",{})
    generation=task.get("task_generation_id")
    if not isinstance(approvals,dict): return False
    for gate,approval in approvals.items():
        if not isinstance(gate,str) or not isinstance(approval,dict): return False
        source=approval.get("source"); artifact=approval.get("artifact_sha256"); receipt=approval.get("decision_receipt")
        if (not isinstance(source,str) or not source.startswith("user:") or not source[5:].strip()
                or re.fullmatch(r"[0-9a-f]{64}",str(artifact or "")) is None or not isinstance(receipt,dict)):
            return False
        required={"schema","path","sha256","bytes","decision_id","authority","adapter_path","adapter_sha256","provider_consumption"}
        if (set(receipt)!=required or receipt.get("schema")!="agent-human-decision-receipt/v1"
                or receipt.get("authority")!="provider-signed-user-message"
                or re.fullmatch(r"[0-9a-f]{64}",str(receipt.get("sha256") or "")) is None
                or re.fullmatch(r"[0-9a-f]{64}",str(receipt.get("adapter_sha256") or "")) is None
                or not isinstance(receipt.get("bytes"),int) or not 0<receipt["bytes"]<=1024*1024
                or not isinstance(receipt.get("decision_id"),str) or not receipt["decision_id"]
                or not isinstance(receipt.get("path"),str) or Path(receipt["path"]).is_absolute()
                or ".." in Path(receipt["path"]).parts or not isinstance(receipt.get("adapter_path"),str)):
            return False
        consumption=receipt["provider_consumption"]
        fields={"project_identity_sha256","task_generation_sha256","task_generation_id","gate","artifact_sha256","decision_id"}
        if (not isinstance(consumption,dict) or set(consumption)!=fields|{"binding_sha256","sequence"}
                or consumption.get("task_generation_id")!=generation or consumption.get("gate")!=gate
                or consumption.get("artifact_sha256")!=artifact or consumption.get("decision_id")!=receipt["decision_id"]
                or any(re.fullmatch(r"[0-9a-f]{64}",str(consumption.get(name) or "")) is None
                       for name in ("project_identity_sha256","task_generation_sha256","binding_sha256"))
                or not isinstance(consumption.get("sequence"),int) or consumption["sequence"]<=0):
            return False
        binding={name:consumption[name] for name in fields}
        if consumption["binding_sha256"]!=canonical_sha256(binding): return False
    return True


def migrate_provider_decision_authority(destination,task,prior_migration):
    """Preserve only exact current generation-bound authority; otherwise rotate and revoke."""
    previous_policy=task.get("decision_policy_version")
    if prior_migration>=41 and previous_policy!=1:
        raise RuntimeError("current project decision_policy_version is tampered or unknown")
    approvals=task.get("gate_approvals",{})
    previous_generation_id=task.get("task_generation_id")
    generation_valid=(isinstance(previous_generation_id,str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",previous_generation_id) is not None)
    if previous_generation_id is not None and not generation_valid:
        raise RuntimeError("current task_generation_id is tampered or invalid")
    activation_path=destination/"state/SKILL_ACTIVATION.json"
    activation_declared=task.get("skill_activation") is not None
    activation_exists=activation_path.exists() or activation_path.is_symlink()
    if prior_migration>=41 and activation_declared!=activation_exists:
        raise RuntimeError("current task Skill activation receipt is incomplete or invalid")
    activation_valid=(activation_declared and activation_exists and existing_skill_activation_valid(destination,task))
    if prior_migration>=41 and activation_declared and not activation_valid:
        raise RuntimeError("current task Skill activation receipt is tampered or invalid")
    if (prior_migration>=41 and generation_valid and activation_valid
            and _current_provider_approvals_bound(task)):
        return task,False
    task["task_generation_id"]="migration-"+uuid.uuid4().hex
    task["decision_policy_version"]=1
    generation_changed=True
    # Older, incomplete, or structurally unbound authority cannot be upgraded
    # cryptographically. Rotate the generation before archiving and revoking it.
    if approvals == {} and task.get("requirements_clarified") is False:
        return task,generation_changed
    payload={
        "schema":"agent-legacy-decision-authority-archive/v1",
        "prior_migration":prior_migration,
        "decision_policy_version":previous_policy,
        "task_generation_id":previous_generation_id,
        "requirements_clarified":task.get("requirements_clarified"),
        "requirement_source":task.get("requirement_source"),
        "gate_approvals":approvals,
        "current_node":task.get("current_node"),
        "accepted_nodes":task.get("accepted_nodes"),
        "node_artifacts":task.get("node_artifacts"),
        "template_route":task.get("template_route"),
        "selected_templates":task.get("selected_templates"),
        "selected_capabilities":task.get("selected_capabilities"),
        "rendered_artifacts":task.get("rendered_artifacts"),
        "failure_escalation":task.get("failure_escalation"),
        "completion_origin":task.get("completion_origin"),
    }
    data=json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()+b"\n"
    digest=hashlib.sha256(data).hexdigest()
    archive=destination/"state/evidence/decision-archives"/f"{digest}.json"
    archive.parent.mkdir(parents=True,exist_ok=True)
    if archive.exists():
        if archive.is_symlink() or not archive.is_file() or read_installer_bytes(archive,label="installer archive")!=data:
            raise RuntimeError("legacy decision authority archive collision")
    else:
        archive.write_bytes(data)
    decisions=task.get("decisions")
    if not isinstance(decisions,list): decisions=[]; task["decisions"]=decisions
    reference=f"migration-41 archived advisory decision authority at .agent/state/evidence/decision-archives/{digest}.json sha256={digest}"
    if reference not in decisions: decisions.append(reference)
    task["gate_approvals"]={}
    task["pending_gate_artifacts"]={}
    task["requirements_clarified"]=False
    task["requirement_source"]="pending"
    if task.get("status") not in {"idle",None}:
        task["status"]="waiting_human"
        task["phase"]="clarification"
        task["primary_skill"]="clarify-task"
        task["current_node"]=1
        task["accepted_nodes"]=[0]
        task["node_artifacts"]={}
        task["template_route"]=None
        task["selected_templates"]=["requirement-contract"]
        task["selected_capabilities"]=["core"]
        task["rendered_artifacts"]=[]
        task["mode_status"]="provisional"
        task["next_action"]="obtain provider-verified approval for the preserved requirement contract"
        questions=task.get("open_questions")
        if not isinstance(questions,list): questions=[]; task["open_questions"]=questions
        question="provider-verified requirement approval"
        if question not in questions: questions.append(question)
        task.pop("decision_packet",None)
        task.pop("failure_escalation",None)
        task.pop("completion_origin",None)
    return task,True


def refresh_migrated_stage_index(source,destination):
    probe="""
import json,os,sys
sys.path.insert(0,os.environ['AGENT_WORKFLOW_TRUSTED_SCRIPTS'])
import workflowctl
task=workflowctl.load(workflowctl.TASK_PATH)
workflowctl.update_stage(task)
"""
    result=run_installer_command(
        [sys.executable,"-I","-B","-c",probe],cwd=destination.parent,timeout=120,env=trusted_python_env(source),
    )
    if result.returncode:
        raise RuntimeError("trusted migration stage-index refresh failed:\n"+result.stdout.strip())


def migrate_active_hot_state(source,destination, prior_migration):
    """Rebind migration-23 context, compact hot state, then validate in-candidate."""
    task=json.loads(read_installer_text(destination/"state/TASK.json",label="candidate task"))
    if prior_migration>=23 or task.get("status") in {"idle",None}: return
    # validate_legacy_active_context already proved the predecessor byte-for-byte
    # before candidate staging. This is a schema migration, not a human repair:
    # rebuild one ordinary verified capsule deterministically and never invent a
    # provider decision receipt.
    probe="""
import argparse,hashlib,json,os,sys
sys.path.insert(0,os.environ['AGENT_WORKFLOW_TRUSTED_SCRIPTS'])
import contextctl
from workflowlib import boundedio
p=contextctl.CONTEXT_PATH
previous=json.loads(boundedio.read_text(p,label='candidate context'))
args=argparse.Namespace(reason='migration-23-schema-rebind',summary='rebind verified active context before bounded hot-state migration',source='installer-verified-legacy-migration',source_tokens=4000,fact=[],file=[],evidence=[],risk=[],resolve_risk=[],transition=False,reset=True)
capsule=contextctl.build_capsule(args,'verified',previous,hashlib.sha256(boundedio.read_bytes(p,label='candidate context')).hexdigest())
contextctl.atomic_json(p,capsule)
raise SystemExit(contextctl.validate_context())
"""
    result=run_installer_command(
        [sys.executable,"-I","-B","-c",probe],cwd=destination.parent,timeout=120,env=trusted_python_env(source),
    )
    if result.returncode:
        raise RuntimeError("migration-23 verified context rebind failed:\n"+result.stdout.strip())
    candidate_tool(source,destination,"scripts/workflowctl.py","compact-state")
    candidate_tool(source,destination,"scripts/contextctl.py","check",readonly=True)
    candidate_tool(source,destination,"scripts/workflowctl.py","validate",readonly=True)
    candidate_tool(source,destination,"scripts/evidencectl.py","verify","--deep",readonly=True)


def migrate_active_template_state(source,destination,prior_migration):
    """Rebind unchanged generated artifacts and migrate only the known v3 runner."""
    task_path=destination/"state/TASK.json"; task=json.loads(read_installer_text(task_path,label="task state"))
    if prior_migration>=25 or task.get("status") in {"idle",None}: return
    # Migration 41 may have revoked legacy/local authority and reset this task
    # to clarification. It must not silently recreate a route before a new
    # provider-verifiable requirement approval.
    if task.get("requirements_clarified") is not True:
        return
    previous_records=task.get("rendered_artifacts")
    capabilities=task.get("selected_capabilities")
    if not isinstance(previous_records,list) or not isinstance(capabilities,list) or any(not isinstance(item,str) for item in capabilities):
        raise RuntimeError("active task template migration requires existing route capabilities and render provenance")

    # Migration 25 removes cleanup execution from the generated workflow
    # runner. Only this exact generated v3 shape is mechanically transformed;
    # any project-specific variation fails closed for human re-planning.
    runner_path=destination/"state/artifacts/04-acceptance-runner.json"
    if "acceptance-workflow" in task.get("selected_templates",[]):
        try: runner=json.loads(read_installer_text(runner_path,label="runner receipt"))
        except (OSError,UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("active workflow runner is missing or invalid") from error
        expected_cleanup=[
            {"id":"cleanup","argv":["python3",".agent/scripts/agentctl.py","cleanup"],"timeout_seconds":60},
            {"id":"assert-clean","argv":["python3",".agent/scripts/agentctl.py","assert-clean"],"timeout_seconds":60},
        ]
        if (
            not isinstance(runner,dict)
            or set(runner)!={"schema","adapter","execution_profile","preflight_commands","commands","cleanup_commands"}
            or runner.get("schema")!="acceptance-runner/v3" or runner.get("adapter")!="workflow"
            or runner.get("cleanup_commands")!=expected_cleanup
        ):
            raise RuntimeError("active workflow runner differs from the known migration-25 v3 contract")
        runner={key:value for key,value in runner.items() if key!="cleanup_commands"}; runner["schema"]="acceptance-runner/v4"
        atomic_json(runner_path,runner)

    route_args=["route"]
    # ``core`` is always selected by templatectl and is intentionally not a
    # public routing argument.  Legacy task state records it alongside the
    # user-selectable capabilities, so do not replay it explicitly.
    for capability in capabilities:
        if capability!="core": route_args.extend(["--capability",capability])
    candidate_tool(source,destination,"scripts/templatectl.py",*route_args)
    task=json.loads(read_installer_text(task_path,label="task state")); route=task.get("template_route")
    selected=task.get("selected_templates",[])
    if not isinstance(route,dict) or not isinstance(route.get("sha256"),str) or not isinstance(selected,list):
        raise RuntimeError("active template migration did not produce a bound route")
    manifest_path=destination/"templates/manifest.json"; manifest_data=read_installer_bytes(manifest_path,label="template manifest"); manifest=json.loads(manifest_data)
    entries={str(item["id"]):item for item in manifest["templates"]}
    rebound=[]
    for record in previous_records:
        if not isinstance(record,dict): raise RuntimeError("active template migration found malformed render provenance")
        template_id=str(record.get("template_id"))
        if template_id not in selected: continue
        item=entries.get(template_id)
        if not isinstance(item,dict) or item.get("renderable") is not True:
            raise RuntimeError(f"active template migration found unknown renderable: {template_id}")
        source=destination/str(item["path"]); output=destination.parent/str(item["output"])
        if not source.is_file() or source.is_symlink() or not output.is_file() or output.is_symlink():
            raise RuntimeError(f"active template migration artifact is missing or unsafe: {template_id}")
        source_data=read_installer_bytes(source,label="installer source"); output_data=read_installer_bytes(output,label="installer output")
        if template_id!="acceptance-workflow":
            if hashlib.sha256(source_data).hexdigest()!=record.get("source_sha256"):
                raise RuntimeError(f"active accepted template source changed and cannot be rebound automatically: {template_id}")
            if hashlib.sha256(output_data).hexdigest()!=record.get("sha256") or len(output_data)!=record.get("bytes"):
                raise RuntimeError(f"active accepted generated artifact drifted: {template_id}")
        rebound.append({
            "schema":"agent-template-render/v1","template_id":template_id,
            "path":str(item["output"]),"sha256":hashlib.sha256(output_data).hexdigest(),"bytes":len(output_data),
            "requirement_contract_sha256":task.get("requirement_contract_sha256"),
            "manifest_sha256":hashlib.sha256(manifest_data).hexdigest(),"route_sha256":route["sha256"],
            "source_path":str(source.relative_to(destination.parent)),
            "source_sha256":hashlib.sha256(source_data).hexdigest(),"source_bytes":len(source_data),
        })
    task["rendered_artifacts"]=rebound; atomic_json(task_path,task)
    candidate_tool(source,destination,"scripts/templatectl.py","validate",readonly=True)


def migrate_active_loaded_references(destination,prior_install,prior_migration):
    """Rebind unchanged managed references after their template bytes update."""
    task_path=destination/"state/TASK.json"; task=json.loads(read_installer_text(task_path,label="task state"))
    if prior_migration>=34 or task.get("status") in {"idle",None}: return
    records=task.get("loaded_references")
    if not isinstance(records,list):
        raise RuntimeError("active task loaded references are malformed")
    previous_files=previous_agent_files(prior_install)
    if not isinstance(previous_files,dict):
        raise RuntimeError("prior install manifest lacks managed Agent files")
    changed=False
    for record in records:
        if not isinstance(record,dict):
            raise RuntimeError("active task loaded reference is malformed")
        raw_path=record.get("path")
        if not isinstance(raw_path,str) or not raw_path.startswith(".agent/"):
            continue
        relative=raw_path[len(".agent/"):]
        prior_sha=previous_files.get(relative)
        if prior_sha is None:
            continue
        if record.get("sha256")!=prior_sha:
            raise RuntimeError(f"active managed reference differs from its installed manifest: {raw_path}")
        target=destination/relative
        if not target.is_file() or target.is_symlink():
            raise RuntimeError(f"active managed reference is missing or unsafe: {raw_path}")
        data=read_installer_bytes(target,label="installer target")
        record.update({
            "sha256":hashlib.sha256(data).hexdigest(),
            "bytes":len(data),
            "estimated_tokens":(len(data)+3)//4,
        })
        changed=True
    if changed: atomic_json(task_path,task)


def finalize_active_context_binding(source,destination,prior_migration,force=False):
    """Bind the capsule to the final post-migration task invariant."""
    task=json.loads(read_installer_text(destination/"state/TASK.json",label="candidate task"))
    if prior_migration>=MIGRATION_VERSION and not force: return
    # Earlier migration steps were individually validated before they changed
    # canonical task state.  Rebuild one ordinary verified checkpoint only
    # after every state migration has settled, preserving its facts and risks.
    same_migration_rebind=force and prior_migration>=MIGRATION_VERSION
    reason=("release-managed-policy-rebind" if same_migration_rebind else (
        "migration-34-final-state-rebind" if prior_migration<34
        else ("migration-39-budget-resume-rebind" if prior_migration<39 else ("migration-40-template-route-rebind" if prior_migration<40 else ("migration-41-provider-authority-rebind" if prior_migration<41 else "migration-42-scheduler-replay-rebind")))))
    transition_source=("installer-verified-release-policy-rebind" if same_migration_rebind else (
        "installer-verified-context-efficiency-migration" if prior_migration<34
        else ("installer-verified-budget-resume-migration" if prior_migration<39 else ("installer-verified-template-route-migration" if prior_migration<40 else ("installer-verified-provider-authority-migration" if prior_migration<41 else "installer-verified-scheduler-replay-migration")))))
    probe=f"""
import argparse,hashlib,json,os,sys
sys.path.insert(0,os.environ['AGENT_WORKFLOW_TRUSTED_SCRIPTS'])
import contextctl
from workflowlib import boundedio
p=contextctl.CONTEXT_PATH
previous=json.loads(boundedio.read_text(p,label='candidate context'))
source_tokens=max(4000,int(previous.get('compaction',{{}}).get('source_estimated_tokens',0) or 0))
args=argparse.Namespace(reason={reason!r},summary=previous.get('phase_summary','verified workflow migration'),source={transition_source!r},source_tokens=source_tokens,fact=[],file=[],evidence=[],risk=[],resolve_risk=[],transition=False,reset=False)
capsule=contextctl.build_capsule(args,'verified',previous,hashlib.sha256(boundedio.read_bytes(p,label='candidate context')).hexdigest())
contextctl.atomic_json(p,capsule)
raise SystemExit(contextctl.validate_context())
"""
    result=run_installer_command(
        [sys.executable,"-I","-B","-c",probe],cwd=destination.parent,timeout=120,env=trusted_python_env(source),
    )
    if result.returncode:
        raise RuntimeError(f"migration-{MIGRATION_VERSION} final context rebind failed:\n"+result.stdout.strip())


def migrate_delivery_state(destination,prior_migration):
    """Upgrade delivery v2 without inventing provider-owned production proof."""
    if prior_migration>=26: return
    path=destination/"state/delivery.json"
    try: state=json.loads(read_installer_text(path,label="installer file"))
    except (OSError,UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("delivery migration requires readable v2 state") from error
    if state.get("schema")=="agent-delivery/v3": return
    if state.get("schema")!="agent-delivery/v2": raise RuntimeError("delivery migration supports only agent-delivery/v2")
    status=state.get("status"); environment=state.get("environment")
    safe_statuses={"not_requested","awaiting_artifact","awaiting_test"}
    production_unapproved={"awaiting_production_approval"}
    approved_pending={"ready_to_promote"}
    historical_terminal={
        "promoted":"legacy_promoted",
        "rollback_required":"legacy_rollback_required",
        "rolled_back":"legacy_rolled_back",
    }
    legacy=None; historical_projection=False
    if environment=="production" and status in production_unapproved|approved_pending|set(historical_terminal):
        if not isinstance(state.get("artifact"),dict) or not isinstance(state.get("test_receipt"),dict):
            raise RuntimeError("production delivery migration requires the preserved artifact/test chain")
        if status in approved_pending|set(historical_terminal):
            raw_bytes=read_installer_bytes(path,label="installer file"); digest=hashlib.sha256(raw_bytes).hexdigest()
            archive=destination/"state/evidence/delivery-migration"/f"v2-{digest}.json"
            archive.parent.mkdir(parents=True,exist_ok=True)
            if archive.exists() and read_installer_bytes(archive,label="installer archive")!=raw_bytes:
                raise RuntimeError("delivery migration archive collision")
            if not archive.exists(): archive.write_bytes(raw_bytes)
            node8=destination/"state/artifacts/08-delivery.json"; node8_archive=None
            if node8.is_file() and not node8.is_symlink():
                node8_bytes=read_installer_bytes(node8,label="delivery node"); node8_digest=hashlib.sha256(node8_bytes).hexdigest()
                try: node8_value=json.loads(node8_bytes)
                except (UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("legacy Node8 receipt is invalid") from error
                if status in historical_terminal and (
                    node8_value.get("schema")!="agent-node-delivery/v2" or node8_value.get("status")!=status
                ):
                    raise RuntimeError("legacy terminal Node8 receipt does not match delivery status")
                node8_archive_path=destination/"state/evidence/delivery-migration"/f"node8-v2-{node8_digest}.json"
                if node8_archive_path.exists() and read_installer_bytes(node8_archive_path,label="delivery node archive")!=node8_bytes:
                    raise RuntimeError("legacy Node8 archive collision")
                if not node8_archive_path.exists(): node8_archive_path.write_bytes(node8_bytes)
                node8_archive={
                    "path":str(node8_archive_path.relative_to(destination.parent)),
                    "sha256":node8_digest,"bytes":len(node8_bytes),
                }
            legacy={
                "schema":"agent-delivery-migration-archive/v1",
                "previous_status":status,
                "assurance":"legacy",
                "reusable_as_release_receipt":False,
                "node8_archive":node8_archive,
                "rollback_closure":None,
                "archive":{
                    "path":str(archive.relative_to(destination.parent)),
                    "sha256":digest,
                    "bytes":len(raw_bytes),
                },
            }
        migrated_status=historical_terminal.get(status,"awaiting_provider_preflight")
        historical_projection=status in {"promoted","rolled_back"}
        state.update({
            "status":migrated_status,
            "provider_preflight":None,
            "production_approval":None,
            "deployment_attempt":None,
            "promotion_receipt":None,
            "rollback_receipt":None,
        })
    elif status in safe_statuses or environment!="production":
        state["provider_preflight"]=None
    else:
        raise RuntimeError(f"delivery migration cannot safely classify status={status}")
    state["schema"]="agent-delivery/v3"; state["legacy_production_chain"]=legacy
    state["updated_at"]=time.strftime("%Y-%m-%dT%H:%M:%S+00:00",time.gmtime())
    atomic_json(path,state)
    if historical_projection:
        node8=destination/"state/artifacts/08-delivery.json"
        state_bytes=read_installer_bytes(path,label="installer file"); artifact=state.get("artifact")
        projection={
            "schema":"agent-node-delivery/v3","status":state["status"],"environment":"production",
            "artifact_digest":artifact.get("digest") if isinstance(artifact,dict) else None,
            "legacy_assurance":"legacy","legacy_archive_sha256":legacy["archive"]["sha256"],
            "reusable_as_release_receipt":False,
            "delivery_state":{
                "path":str(path.relative_to(destination.parent)),
                "sha256":hashlib.sha256(state_bytes).hexdigest(),"bytes":len(state_bytes),
            },
        }
        atomic_json(node8,projection)
        task_path=destination/"state/TASK.json"; task=json.loads(read_installer_text(task_path,label="task state"))
        node_artifacts=task.get("node_artifacts")
        if isinstance(node_artifacts,dict) and "8" in node_artifacts:
            node8_bytes=read_installer_bytes(node8,label="delivery node")
            node_artifacts["8"]={
                "path":str(node8.relative_to(destination.parent)),
                "sha256":hashlib.sha256(node8_bytes).hexdigest(),"bytes":len(node8_bytes),
            }
            atomic_json(task_path,task)


def deep_fill(current, defaults):
    for key,value in defaults.items():
        if key not in current: current[key]=value
        elif isinstance(current[key],dict) and isinstance(value,dict): deep_fill(current[key],value)


def inside(path, boundary):
    try: path.relative_to(boundary); return True
    except ValueError: return False


def protected_external_adapter_reject_reason(adapter_owner, raw, require_executable=True):
    requested=Path(raw).expanduser()
    if not requested.is_absolute(): return f"not absolute: {raw!r}"
    try: path=requested.resolve(strict=True)
    except OSError: return f"cannot resolve: {raw!r}"
    if requested!=path: return f"resolves to a different path: {path}"
    if inside(path,adapter_owner.resolve()): return "inside the project tree"
    temporary_roots={Path(tempfile.gettempdir()).resolve(),Path("/tmp").resolve(),Path("/private/tmp").resolve(),Path("/var/tmp").resolve()}
    if any(inside(path,candidate) for candidate in temporary_roots): return "inside a temporary root"
    if not hasattr(os,"geteuid"): return "platform has no euid concept"
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode): return "not a regular file"
    if require_executable and not os.access(path,os.X_OK): return "not executable"
    current_uid=os.geteuid(); current=Path(path.anchor); chain=[current]
    for part in path.parts[1:]:
        current=current/part
        try: metadata=current.lstat()
        except OSError: return f"cannot stat chain element: {current}"
        if stat.S_ISLNK(metadata.st_mode): return f"symlink in path chain: {current}"
        chain.append(current)
    for item in chain:
        try: metadata=item.stat()
        except OSError: return f"cannot stat chain element: {item}"
        if metadata.st_uid==current_uid: return f"chain element owned by current uid {current_uid}: {item}"
        if stat.S_IMODE(metadata.st_mode)&0o022: return f"chain element group/world-writable: {item}"
        if os.access(item,os.W_OK): return f"chain element writable by current user: {item}"
    return None


def protected_external_adapter(adapter_owner, raw):
    return protected_external_adapter_reject_reason(adapter_owner, raw) is None


HUMAN_ADAPTER_METADATA_SUFFIX=".agent-workflow-adapter.json"
HUMAN_ADAPTER_METADATA_SCHEMA="agent-provider-adapter/v1"
HUMAN_ADAPTER_OPERATIONS={"health","verify","consume-scheduler-resume","verify-host-compaction","verify-usage","health-provider-preflight","verify-provider-preflight","verify-platform"}
GENERIC_ADAPTER_NAMES={"bash","sh","zsh","fish","env","python","python3","node","perl","ruby","php"}


def validate_human_adapter_metadata(target,adapter,required_operations=("health","verify")):
    metadata_path=Path(str(adapter)+HUMAN_ADAPTER_METADATA_SUFFIX)
    reject_reason=protected_external_adapter_reject_reason(target.resolve(),str(metadata_path),require_executable=False)
    if reject_reason is not None:
        raise RuntimeError(f"provider adapter metadata is missing or unsafe: {reject_reason}")
    before=os.lstat(metadata_path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>16384:
        raise RuntimeError("provider adapter metadata must be one bounded regular file")
    flags=os.O_RDONLY|(os.O_NOFOLLOW if hasattr(os,"O_NOFOLLOW") else 0)
    descriptor=os.open(metadata_path,flags)
    try:
        opened=os.fstat(descriptor)
        if (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1:
            raise RuntimeError("provider adapter metadata changed while opening")
        chunks=[]; remaining=16385
        while remaining:
            chunk=os.read(descriptor,min(4096,remaining))
            if not chunk: break
            chunks.append(chunk); remaining-=len(chunk)
        raw=b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw)>16384: raise RuntimeError("provider adapter metadata is too large")
    try: value=json.loads(raw.decode("utf-8"))
    except (UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("provider adapter metadata is not valid UTF-8 JSON") from error
    operations=value.get("operations") if isinstance(value,dict) else None
    if (
        not isinstance(value,dict)
        or set(value)!={"schema","purpose","executable_sha256","operations"}
        or value.get("schema")!=HUMAN_ADAPTER_METADATA_SCHEMA
        or value.get("purpose")!="provider-verifiable-agent-control"
        or value.get("executable_sha256")!=sha(adapter)
        or not isinstance(operations,list)
        or any(not isinstance(item,str) for item in operations)
        or operations!=sorted(set(operations))
        or any(item not in HUMAN_ADAPTER_OPERATIONS for item in operations)
        or not set(required_operations).issubset(set(operations))
    ):
        raise RuntimeError("provider adapter metadata does not bind the executable and required protocol")


def validate_installer_adapter_launcher(target,adapter):
    descriptor=os.open(adapter,os.O_RDONLY|(os.O_NOFOLLOW if hasattr(os,"O_NOFOLLOW") else 0))
    try: metadata=os.fstat(descriptor); prefix=os.read(descriptor,512)
    finally: os.close(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1:
        raise RuntimeError("provider adapter must be one protected regular executable")
    if prefix.startswith(b"#!"):
        try: parts=prefix.splitlines()[0][2:].decode("ascii").strip().split()
        except UnicodeError as error: raise RuntimeError("provider adapter shebang is invalid") from error
        if not parts or not parts[0].startswith("/") or len(parts)>2:
            raise RuntimeError("provider adapter shebang must bind one protected interpreter")
        interpreter=Path(parts[0])
        if interpreter.name=="env":
            if len(parts)!=2 or re.fullmatch(r"[A-Za-z0-9._+-]+",parts[1]) is None:
                raise RuntimeError("provider adapter env shebang is not bounded")
            interpreter=next((candidate for candidate in (Path("/usr/local/bin")/parts[1],Path("/usr/bin")/parts[1],Path("/bin")/parts[1]) if candidate.is_file()),None)
            if interpreter is None: raise RuntimeError("provider adapter env interpreter is unavailable")
        elif len(parts)!=1: raise RuntimeError("provider adapter shebang arguments are not allowed")
        reason=protected_external_adapter_reject_reason(target.resolve(),str(interpreter))
        if reason is not None: raise RuntimeError(f"provider adapter interpreter is unsafe: {reason}")


INSTALLER_ADAPTER_OUTPUT_LIMIT=262144
INSTALLER_COMMAND_OUTPUT_LIMIT=4*1024*1024
INSTALLER_COMMAND_INPUT_LIMIT=16*1024*1024


_INSTALLER_PROCESS_OBSERVER=None


def installer_process_observer():
    """Load the manifest-bound native observer without importing ambient modules."""
    global _INSTALLER_PROCESS_OBSERVER
    if _INSTALLER_PROCESS_OBSERVER is not None: return _INSTALLER_PROCESS_OBSERVER
    root=Path(__file__).resolve().parent
    module_path=root/".agent/scripts/process_observation.py"
    manifest_path=root/".agent/.workflow-manifest.json"
    try:
        module_metadata=os.lstat(module_path); manifest_metadata=os.lstat(manifest_path)
    except OSError as error:
        raise RuntimeError("installer process observer release files are unavailable") from error
    expected_uid=os.geteuid() if hasattr(os,"geteuid") else module_metadata.st_uid
    for label,metadata in (("module",module_metadata),("manifest",manifest_metadata)):
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid not in {0,expected_uid} or stat.S_IMODE(metadata.st_mode)&0o022):
            raise RuntimeError(f"installer process observer {label} identity is unsafe")
    def bounded_nofollow(path,maximum):
        descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
        try:
            opened=os.fstat(descriptor)
            before=os.lstat(path)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1
                    or (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino)):
                raise RuntimeError("installer process observer release file changed while opening")
            chunks=[]; total=0
            while True:
                chunk=os.read(descriptor,min(65536,maximum+1-total))
                if not chunk: break
                chunks.append(chunk); total+=len(chunk)
                if total>maximum: raise RuntimeError("installer process observer release file exceeds its bound")
            return b"".join(chunks)
        finally: os.close(descriptor)
    manifest_raw=bounded_nofollow(manifest_path,4*1024*1024)
    module_raw=bounded_nofollow(module_path,256*1024)
    try: manifest=json.loads(manifest_raw.decode("utf-8"))
    except (UnicodeError,json.JSONDecodeError) as error:
        raise RuntimeError("installer process observer manifest is invalid") from error
    expected=(manifest.get("agent_files",{}) if isinstance(manifest,dict) else {}).get("scripts/process_observation.py")
    if re.fullmatch(r"[0-9a-f]{64}",str(expected or "")) is None or hashlib.sha256(module_raw).hexdigest()!=expected:
        raise RuntimeError("installer process observer does not match the release manifest")
    module=types.ModuleType("_agent_installer_process_observation")
    module.__file__=str(module_path)
    exec(compile(module_raw,str(module_path),"exec"),module.__dict__)
    _INSTALLER_PROCESS_OBSERVER=module
    return module


def installer_process_snapshot():
    observer=installer_process_observer()
    try:
        records=(observer.linux_process_snapshot() if platform.system()=="Linux"
                 else observer.darwin_process_snapshot())
    except observer.ProcessObservationError as error:
        raise RuntimeError("provider adapter process identity observation is unavailable") from error
    return {pid:(int(info["ppid"]),int(info["pgid"]),str(info["start_identity"]),str(info["state"]))
            for pid,info in records.items()}


def installer_discover_descendants(root_pid,known,snapshot=None):
    snapshot=installer_process_snapshot() if snapshot is None else snapshot
    roots={root_pid}
    roots.update(pid for pid,identity in known.items()
                 if pid in snapshot and snapshot[pid][2]==identity)
    changed=True
    while changed:
        changed=False
        for pid,(parent,_group,identity,state) in snapshot.items():
            if parent in roots and pid not in roots:
                roots.add(pid)
                if pid!=root_pid and not state.startswith("Z"): known.setdefault(pid,identity)
                changed=True
    return snapshot


def installer_live_known(known,snapshot):
    return {pid:identity for pid,identity in known.items()
            if pid in snapshot and snapshot[pid][2]==identity and not snapshot[pid][3].startswith("Z")}


def installer_adapter_group_exists(process_group,snapshot=None):
    snapshot=installer_process_snapshot() if snapshot is None else snapshot
    return any(group==process_group and not state.startswith("Z")
               for _pid,(_parent,group,_identity,state) in snapshot.items())


def installer_signal_known(known,requested,snapshot):
    observer=installer_process_observer(); ok=True
    for pid in sorted(known,reverse=True):
        if pid<=1 or pid not in snapshot or snapshot[pid][2]!=known[pid]: continue
        try:
            if platform.system()=="Linux": observer.linux_signal_identity(pid,known[pid],requested)
            else:
                immediate=installer_process_snapshot()
                if pid not in immediate or immediate[pid][2]!=known[pid]: continue
                os.kill(pid,requested)
        except ProcessLookupError: pass
        except (OSError,observer.ProcessObservationError,RuntimeError): ok=False
    return ok


def installer_signal_launch_session(process,known,requested,snapshot):
    if process.returncode is not None or signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL: return False
    members={pid:identity for pid,(_parent,group,identity,state) in snapshot.items()
             if group==process.pid and not state.startswith("Z")}
    if any(pid in known and known[pid]!=identity for pid,identity in members.items()): return False
    if not members: return True
    try:
        if any(os.getsid(pid)!=process.pid for pid in members): return False
    except (ProcessLookupError,OSError,PermissionError): return False
    immediate=installer_process_snapshot()
    current={pid:identity for pid,(_parent,group,identity,state) in immediate.items()
             if group==process.pid and not state.startswith("Z")}
    if current!=members: return False
    try:
        if any(os.getsid(pid)!=process.pid for pid in current): return False
    except (ProcessLookupError,OSError,PermissionError): return False
    known.update(members)
    return installer_signal_known(members,requested,immediate)


def _drain_installer_adapter_pipe(process,output,maximum):
    if process.stdout is None: return True
    descriptor=process.stdout.fileno(); eof=False
    while True:
        try: chunk=os.read(descriptor,min(65536,max(1,maximum+1-len(output))))
        except BlockingIOError: break
        except InterruptedError: continue
        if not chunk: eof=True; break
        output.extend(chunk)
        if len(output)>maximum:
            raise RuntimeError("provider adapter output exceeds its protocol limit during cleanup")
    return eof


def stop_installer_adapter(process,output=None,maximum=INSTALLER_ADAPTER_OUTPUT_LIMIT,known=None):
    """Terminate only stable launch-session or descendant PID/start identities."""
    output=bytearray() if output is None else output; known=dict(known or {}); eof=False
    leader_anchored=process.returncode is None and signal.getsignal(signal.SIGCHLD) is signal.SIG_DFL
    root_pid=process.pid if leader_anchored else -1; cleanup_error=None
    if process.returncode is None and not leader_anchored:
        cleanup_error=RuntimeError("provider adapter unreaped PID ownership is unavailable")
    def cleanup_drain():
        nonlocal eof,cleanup_error
        try: eof=_drain_installer_adapter_pipe(process,output,maximum) or eof
        except BaseException as error:
            if cleanup_error is None: cleanup_error=error
    try:
        snapshot=installer_discover_descendants(root_pid,known)
        if leader_anchored and process.pid in snapshot: known.setdefault(process.pid,snapshot[process.pid][2])
        if leader_anchored and not installer_signal_launch_session(process,known,signal.SIGTERM,snapshot):
            cleanup_error=cleanup_error or RuntimeError("provider adapter launch session could not be identity-bound for SIGTERM")
        if not installer_signal_known(known,signal.SIGTERM,snapshot):
            cleanup_error=cleanup_error or RuntimeError("provider adapter descendants could not receive identity-bound SIGTERM")
        term_deadline=time.monotonic()+1.0
        while time.monotonic()<term_deadline:
            cleanup_drain(); snapshot=installer_discover_descendants(root_pid,known)
            live={pid:identity for pid,identity in installer_live_known(known,snapshot).items() if pid!=process.pid}
            if not live and (not leader_anchored or not installer_adapter_group_exists(process.pid,snapshot)): break
            time.sleep(0.02)
        for _ in range(3):
            snapshot=installer_discover_descendants(root_pid,known)
            if not installer_signal_known(known,signal.SIGSTOP,snapshot):
                cleanup_error=cleanup_error or RuntimeError("provider adapter descendants could not be identity-bound for SIGSTOP")
        snapshot=installer_discover_descendants(root_pid,known)
        if leader_anchored and not installer_signal_launch_session(process,known,signal.SIGKILL,snapshot):
            cleanup_error=cleanup_error or RuntimeError("provider adapter launch session could not be identity-bound for SIGKILL")
        snapshot=installer_discover_descendants(root_pid,known)
        if not installer_signal_known(known,signal.SIGKILL,snapshot):
            cleanup_error=cleanup_error or RuntimeError("provider adapter descendants could not receive identity-bound SIGKILL")
        kill_deadline=time.monotonic()+2.0; residual=True
        while time.monotonic()<kill_deadline:
            cleanup_drain(); snapshot=installer_discover_descendants(root_pid,known)
            live={pid:identity for pid,identity in installer_live_known(known,snapshot).items() if pid!=process.pid}
            residual=bool(live) or (leader_anchored and installer_adapter_group_exists(process.pid,snapshot))
            if not residual: break
            time.sleep(0.02)
        if residual:
            cleanup_error=cleanup_error or RuntimeError("provider adapter left identity-bound residual processes after SIGKILL")
        if leader_anchored:
            try: process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                try: process.kill(); process.wait(timeout=1.0)
                except (OSError,subprocess.TimeoutExpired):
                    cleanup_error=cleanup_error or RuntimeError("provider adapter leader could not be reaped")
    except BaseException as error:
        cleanup_error=cleanup_error or error
        if leader_anchored and process.returncode is None:
            try: process.kill(); process.wait(timeout=1.0)
            except (OSError,subprocess.TimeoutExpired): pass
    drain_deadline=time.monotonic()+0.5
    while not eof and time.monotonic()<drain_deadline:
        try: eof=_drain_installer_adapter_pipe(process,output,maximum) or eof
        except BaseException as error:
            cleanup_error=cleanup_error or error; break
        if not eof: time.sleep(0.01)
    try:
        final=installer_process_snapshot()
        descendants={pid:identity for pid,identity in known.items() if pid!=process.pid}
        if installer_live_known(descendants,final):
            cleanup_error=cleanup_error or RuntimeError("provider adapter identity-bound descendant remained after cleanup")
    except BaseException as error:
        cleanup_error=cleanup_error or error
    if process.returncode is None:
        cleanup_error=cleanup_error or RuntimeError("provider adapter leader was not reaped")
    if not eof:
        cleanup_error=cleanup_error or RuntimeError("provider adapter output pipe did not reach EOF; detached ownership is uncertain")
    if cleanup_error is not None: raise cleanup_error
    return bytes(output)


def bounded_installer_adapter_output(process,timeout,maximum=INSTALLER_ADAPTER_OUTPUT_LIMIT,known=None):
    if process.stdout is None: raise RuntimeError("provider adapter output pipe is unavailable")
    descriptor=process.stdout.fileno(); os.set_blocking(descriptor,False)
    selector=selectors.DefaultSelector(); selector.register(descriptor,selectors.EVENT_READ)
    output=bytearray(); deadline=time.monotonic()+timeout; eof=False; completed=False; known=dict(known or {})
    try:
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            raise RuntimeError("provider adapter requires default SIGCHLD ownership for unreaped PID binding")
        snapshot=installer_discover_descendants(process.pid,known)
        leader=snapshot.get(process.pid); leader_identity=leader[2] if leader is not None else None
        if leader_identity is not None: known[process.pid]=leader_identity
        while True:
            snapshot=installer_discover_descendants(process.pid,known)
            leader=snapshot.get(process.pid)
            if leader is not None:
                if leader_identity is None:
                    leader_identity=leader[2]; known[process.pid]=leader_identity
                elif leader[2]!=leader_identity:
                    completed=True; stop_installer_adapter(process,output,maximum,known)
                    raise RuntimeError("provider adapter leader identity changed before cleanup")
            # Darwin libproc may hide an exited-but-unreaped child. No poll/wait has
            # occurred, so an absent captured leader still retains its unreusable PID.
            exited=leader is None or leader[3].startswith("Z")
            if eof and exited: break
            remaining=deadline-time.monotonic()
            if remaining<=0:
                completed=True; stop_installer_adapter(process,output,maximum,known)
                raise subprocess.TimeoutExpired(process.args,timeout,output=bytes(output))
            events=selector.select(min(remaining,0.1))
            for key,_mask in events:
                chunk=os.read(key.fd,min(65536,max(1,maximum+1-len(output))))
                if not chunk:
                    selector.unregister(key.fd); eof=True; continue
                output.extend(chunk)
                if len(output)>maximum:
                    completed=True; stop_installer_adapter(process,output,maximum,known)
                    raise RuntimeError("provider adapter output exceeds its protocol limit")
        snapshot=installer_discover_descendants(process.pid,known)
        live={pid:identity for pid,identity in installer_live_known(known,snapshot).items() if pid!=process.pid}
        session_live={pid for pid,(_parent,group,_identity,state) in snapshot.items()
                      if pid!=process.pid and group==process.pid and not state.startswith("Z")}
        if live or session_live:
            completed=True; stop_installer_adapter(process,output,maximum,known)
            raise RuntimeError("provider adapter left a lingering identity-bound descendant process")
        process.wait(timeout=max(0.0,deadline-time.monotonic()))
        completed=True
        return bytes(output)
    except BaseException:
        if not completed: stop_installer_adapter(process,output,maximum,known)
        raise
    finally:
        selector.close()
        try: process.stdout.close()
        except OSError: pass


def run_installer_command(command,*,cwd=None,env=None,timeout=120,input_data=None,pass_fds=(),output_limit=INSTALLER_COMMAND_OUTPUT_LIMIT):
    if input_data is None: encoded=None
    elif isinstance(input_data,bytes): encoded=input_data
    elif isinstance(input_data,str): encoded=input_data.encode("utf-8")
    else: raise TypeError("installer command input must be bytes, text, or None")
    if encoded is not None and len(encoded)>INSTALLER_COMMAND_INPUT_LIMIT:
        raise RuntimeError("installer command input exceeds its byte limit")
    process=subprocess.Popen(list(command),cwd=None if cwd is None else str(cwd),env=None if env is None else dict(env),
        text=False,stdin=subprocess.PIPE if encoded is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,close_fds=True,start_new_session=True,pass_fds=tuple(pass_fds))
    write_errors=[]; writer=None
    if encoded is not None:
        def write_input():
            try:
                view=memoryview(encoded)
                while view:
                    written=process.stdin.write(view)
                    if not isinstance(written,int) or written<=0: raise OSError("installer command stdin write failed")
                    view=view[written:]
            except BrokenPipeError: pass
            except BaseException as error: write_errors.append(error)
            finally:
                try: process.stdin.close()
                except OSError: pass
        writer=threading.Thread(target=write_input,name="installer-command-stdin",daemon=True); writer.start()
    try: output=bounded_installer_adapter_output(process,timeout,maximum=output_limit)
    finally:
        if writer is not None:
            writer.join(timeout=2)
            if writer.is_alive(): raise RuntimeError("installer command stdin writer did not terminate")
    if write_errors: raise RuntimeError("installer command stdin write failed") from write_errors[0]
    decoded=output.decode("utf-8",errors="replace")
    return subprocess.CompletedProcess(list(command),process.returncode,decoded,decoded)


def run_installer_adapter(target,adapter,operation,required_operations,timeout=10):
    validate_human_adapter_metadata(target,adapter,required_operations=required_operations)
    validate_installer_adapter_launcher(target,adapter)
    before=os.lstat(adapter); digest=sha(adapter)
    with tempfile.TemporaryDirectory(prefix="agent-installer-adapter-") as raw_home:
        home=Path(raw_home); os.chmod(home,0o700)
        environment={"PATH":"/usr/local/bin:/usr/bin:/bin","HOME":str(home),"TMPDIR":str(home),"LANG":"C","LC_ALL":"C","TZ":"UTC"}
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            raise RuntimeError("provider adapter requires default SIGCHLD ownership for unreaped PID binding")
        process=subprocess.Popen([str(adapter),operation],cwd=str(home),env=environment,text=False,stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,stderr=subprocess.STDOUT,close_fds=True,start_new_session=True)
        output_bytes=bounded_installer_adapter_output(process,timeout)
        output=output_bytes.decode("utf-8",errors="replace")
        result=subprocess.CompletedProcess(process.args,process.returncode,output)
    after=os.lstat(adapter)
    if ((before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size) or digest!=sha(adapter)):
        raise RuntimeError("provider adapter changed during protected execution")
    return result


def bootstrap_human_decision_adapter(target,raw):
    guidance=(
        "fresh install requires --human-decision-adapter /absolute/provider-owned/dedicated-executable; "
        "the executable, parent chain, and <adapter>.agent-workflow-adapter.json must be OS-owned/non-writable. "
        "Metadata must use agent-provider-adapter/v1, purpose provider-verifiable-agent-control, bind the executable SHA-256, "
        "and declare sorted health+verify operations before `<adapter> health` may execute. The installer writes that "
        "canonical path to .agent/config.json agent_control.human_decision_observer.signed_adapter; "
        "generic interpreters, project-local adapters, missing metadata, and self-signed fallbacks are never accepted"
    )
    if raw is None:
        return None
    if not isinstance(raw,str) or not raw.strip():
        raise RuntimeError(guidance)
    reject_reason=protected_external_adapter_reject_reason(target.resolve(),raw)
    if reject_reason is not None:
        raise RuntimeError(guidance+f"; rejected: {reject_reason}")
    adapter=Path(raw).expanduser().resolve(strict=True)
    if adapter.name.lower() in GENERIC_ADAPTER_NAMES:
        raise RuntimeError(guidance+"; rejected: generic interpreter")
    try:
        validate_human_adapter_metadata(target,adapter)
    except RuntimeError as error:
        raise RuntimeError(guidance+f"; rejected: {error}") from error
    try:
        result=run_installer_adapter(target,adapter,"health",("health","verify"))
    except (OSError,subprocess.TimeoutExpired) as error:
        raise RuntimeError(guidance) from error
    if result.returncode:
        raise RuntimeError(guidance+f"; health failed with exit {result.returncode}")
    return str(adapter)


def bootstrap_provider_preflight_adapter(target,raw):
    if raw is None: return None
    if not isinstance(raw,str) or not raw.strip() or not protected_external_adapter(target.resolve(),raw):
        raise RuntimeError("provider preflight adapter must be an OS-owned, non-writable, non-temporary dedicated executable")
    adapter=Path(raw).expanduser().resolve(strict=True)
    if adapter.name.lower() in GENERIC_ADAPTER_NAMES:
        raise RuntimeError("provider preflight adapter cannot be a generic interpreter")
    try:
        validate_human_adapter_metadata(target,adapter,required_operations=("health-provider-preflight","verify-provider-preflight"))
    except RuntimeError as error:
        raise RuntimeError(f"provider preflight adapter protocol metadata is invalid: {error}") from error
    try:
        result=run_installer_adapter(target,adapter,"health-provider-preflight",("health-provider-preflight","verify-provider-preflight"))
    except (OSError,subprocess.TimeoutExpired) as error:
        raise RuntimeError("provider preflight adapter health check failed") from error
    if result.returncode or result.stdout.strip()!="PROVIDER PREFLIGHT ADAPTER READY":
        raise RuntimeError("provider preflight adapter health check failed")
    return str(adapter)


GUARDRAIL_FACT_LABELS=(
    "Product and users:","Technology and architecture:","Writable and read-only areas:",
    "Security, privacy, compliance and performance red lines:",
    "Build, test and lint commands:","Deployment authority and rollback owner:",
)


def project_guardrails_bytes(raw):
    if not raw: raise RuntimeError("project initialization requires --guardrails-file")
    # Keep the lexical path: resolve() would follow the very symlink this input
    # boundary must reject. Open every ancestor and the leaf descriptor-relative
    # with no-follow semantics, then bind the bounded read to the opened inode.
    path=Path(os.path.abspath(str(Path(raw).expanduser())))
    # Darwin exposes /var and /tmp as root-owned compatibility symlinks into
    # /private. Canonicalize only those fixed OS aliases; every caller-owned
    # descendant is still walked descriptor-relative with O_NOFOLLOW.
    if platform.system()=="Darwin" and len(path.parts)>1 and path.parts[1] in {"var","tmp"}:
        alias=Path("/")/path.parts[1]
        try: alias_stat=os.lstat(alias)
        except FileNotFoundError: alias_stat=None
        expected=Path("/private")/path.parts[1]
        if (alias_stat is not None and stat.S_ISLNK(alias_stat.st_mode) and alias_stat.st_uid==0
                and Path(os.path.realpath(str(alias)))==expected):
            path=expected.joinpath(*path.parts[2:])
    parent=open_directory_chain(path.parent)
    if parent is None: raise RuntimeError("project guardrails file is missing or unsafe")
    try:
        try:
            descriptor=os.open(path.name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0),dir_fd=parent)
        except OSError as error:
            raise RuntimeError("project guardrails file is missing or unsafe") from error
        try:
            opened=os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1
                    or opened.st_uid!=os.geteuid() or stat.S_IMODE(opened.st_mode)&0o022):
                raise RuntimeError("project guardrails file is not one private owner-controlled regular file")
            if opened.st_size==0 or opened.st_size>131072:
                raise RuntimeError("project guardrails file is empty or exceeds 131072 bytes")
            chunks=[]; remaining=opened.st_size
            while remaining:
                chunk=os.read(descriptor,min(65536,remaining))
                if not chunk: raise RuntimeError("project guardrails file was truncated while read")
                chunks.append(chunk); remaining-=len(chunk)
            if os.read(descriptor,1): raise RuntimeError("project guardrails file grew while read")
            after=os.fstat(descriptor)
            if (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,stat.S_IMODE(after.st_mode))!=(opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,stat.S_IMODE(opened.st_mode)):
                raise RuntimeError("project guardrails file changed while read")
            data=b"".join(chunks)
        finally: os.close(descriptor)
    finally: os.close(parent)
    try: text=data.decode("utf-8")
    except UnicodeError as error: raise RuntimeError("project guardrails file must be UTF-8") from error
    if not text.startswith("# Project Guardrails\n"):
        raise RuntimeError("project guardrails must start with '# Project Guardrails'")
    if "agent-workflow-project-guardrails:v1 uninitialized" in text or re.search(r"\b(?:TODO|PENDING)\b",text,re.IGNORECASE):
        raise RuntimeError("project guardrails still contain an uninitialized placeholder")
    for label in GUARDRAIL_FACT_LABELS:
        matches=re.findall(rf"^- {re.escape(label)}\s*(\S.*)$",text,re.MULTILINE)
        if len(matches)!=1: raise RuntimeError(f"project guardrails require exactly one completed '{label}' fact")
    return data if data.endswith(b"\n") else data+b"\n"


def bind_project_guardrails(destination,data,initialized_at=None):
    path=destination/"policies/PROJECT_GUARDRAILS.md"
    atomic_bytes(path,data)
    config_path=destination/"config.json"; config=json.loads(read_installer_text(config_path,label="installer config"))
    config["guardrails_ready"]=True
    config["project_initialization"]={
        "schema":"agent-project-initialization/v1",
        "guardrails_sha256":hashlib.sha256(data).hexdigest(),
        "guardrails_bytes":len(data),
        "initialized_at":initialized_at or dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    }
    atomic_json(config_path,config)


def validate_project_guardrails(destination,allow_legacy=False):
    config_path=destination/"config.json"; policy_path=destination/"policies/PROJECT_GUARDRAILS.md"
    config=json.loads(read_installer_text(config_path,label="installer config")); ready=config.get("guardrails_ready")
    binding=config.get("project_initialization")
    if ready is False:
        if binding is not None: raise RuntimeError("uninitialized project has a guardrails binding")
        text=read_installer_text(policy_path,label="project guardrails")
        if "agent-workflow-project-guardrails:v1 uninitialized" not in text:
            raise RuntimeError("uninitialized project guardrails differ from the canonical placeholder")
        return False
    if ready is not True: raise RuntimeError("project guardrails readiness must be Boolean")
    if binding is None and allow_legacy: return True
    data=read_installer_bytes(policy_path,label="project guardrails")
    if (
        not isinstance(binding,dict)
        or set(binding)!={"schema","guardrails_sha256","guardrails_bytes","initialized_at"}
        or binding.get("schema")!="agent-project-initialization/v1"
        or binding.get("guardrails_sha256")!=hashlib.sha256(data).hexdigest()
        or binding.get("guardrails_bytes")!=len(data)
        or not isinstance(binding.get("initialized_at"),str) or not binding["initialized_at"]
    ):
        raise RuntimeError("project guardrails readiness is not bound to the current guardrails bytes")
    return True


def validate_observer_policy(name, observed, expected, adapter_owner):
    if not isinstance(observed,dict) or set(observed)!=set(expected):
        raise RuntimeError(f"project Agent security policy has invalid keys: {name}")
    for key,value in expected.items():
        if key != "signed_adapter" and observed.get(key)!=value:
            raise RuntimeError(f"project Agent security policy differs from the canonical template: {name}.{key}")
    if name=="human_decision_observer" and observed.get("allow_current_chat_local_release") is not False:
        raise RuntimeError("project Agent security policy forbids current-chat gate authorization")
    adapter=observed.get("signed_adapter")
    if adapter is not None:
        if not isinstance(adapter,str) or not adapter.strip() or not protected_external_adapter(adapter_owner,adapter):
            raise RuntimeError(f"project Agent security policy requires an OS-owned, non-writable, non-temporary external signed_adapter: {name}")
        if name=="provider_preflight_observer" and Path(adapter).name.lower() in {"bash","sh","zsh","fish","env","python","python3","node","perl","ruby","php"}:
            raise RuntimeError("provider preflight observer requires a dedicated verifier, not a generic interpreter")


def validate_retention_policy(config):
    context=config.get("context",{}); retention=config.get("evidence_retention")
    if (
        not isinstance(context,dict)
        or not isinstance(context.get("max_rollback_entries"),int) or isinstance(context.get("max_rollback_entries"),bool)
        or not 1<=context["max_rollback_entries"]<=32
        or not isinstance(context.get("max_failure_entries"),int) or isinstance(context.get("max_failure_entries"),bool)
        or not 1<=context["max_failure_entries"]<=64
        or not isinstance(context.get("max_failure_archive_depth"),int) or isinstance(context.get("max_failure_archive_depth"),bool)
        or not 1<=context["max_failure_archive_depth"]<=128
        or not isinstance(retention,dict)
        or set(retention)!={"active_max_bytes","min_age_hours","min_archive_bytes","max_archives","archive_format","preserve_referenced"}
        or not isinstance(retention.get("active_max_bytes"),int) or isinstance(retention.get("active_max_bytes"),bool)
        or not 1048576<=retention["active_max_bytes"]<=67108864
        or not isinstance(retention.get("min_age_hours"),int) or isinstance(retention.get("min_age_hours"),bool)
        or not 0<=retention["min_age_hours"]<=8760
        or not isinstance(retention.get("min_archive_bytes"),int) or isinstance(retention.get("min_archive_bytes"),bool)
        or not 0<=retention["min_archive_bytes"]<=retention["active_max_bytes"]
        or not isinstance(retention.get("max_archives"),int) or isinstance(retention.get("max_archives"),bool)
        or not 1<=retention["max_archives"]<=256
        or retention.get("archive_format")!="deterministic-zip-deflate-v1"
        or retention.get("preserve_referenced") is not True
    ):
        raise RuntimeError("project hot-state or evidence-retention policy is invalid")


def strict_bounded_int(value,minimum,maximum):
    return type(value) is int and minimum<=value<=maximum


def valid_model_id(value):
    return isinstance(value,str) and value.lower() not in {"none","null","unset","unselected","default","model","model-id"} and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,127}",value) is not None


def validate_context_transport_policy(config,plugin_provenance,normalize_legacy_disabled=False):
    policy=config.get("context_transport")
    if policy=={"default":"native"}:
        return
    pxpipe=policy.get("pxpipe") if isinstance(policy,dict) else None
    if (
        not isinstance(policy,dict)
        or set(policy)!={"default","pxpipe"}
        or policy.get("default")!="native"
        or not isinstance(pxpipe,dict)
        or set(pxpipe)!={"enabled","activation","plugin_name","plugin_version","models","primary_mode","provider_activation","provider_configuration","provider_content_scope","mcp_role","selection","content_scope","session_boundary","fallback"}
        or not isinstance(pxpipe.get("enabled"),bool)
        or pxpipe.get("activation")!="explicit-opt-in"
        or pxpipe.get("plugin_name")!=PLUGIN_NAME
        or pxpipe.get("plugin_version")!="0.1.0+codex.20260721210500"
        or not isinstance(pxpipe.get("models"),list)
        or (pxpipe.get("enabled") is True and not 1<=len(pxpipe.get("models",[]))<=16)
        or (pxpipe.get("enabled") is False and not 0<=len(pxpipe.get("models",[]))<=16)
        or any(not valid_model_id(model) for model in pxpipe.get("models",[]))
        or len(set(pxpipe.get("models",[])))!=len(pxpipe.get("models",[]))
        or (pxpipe.get("enabled") is True and config.get("agent_control",{}).get("default_model") not in pxpipe.get("models",[]))
        or pxpipe.get("primary_mode")!="provider-proxy"
        or (pxpipe.get("provider_activation")!="task-explicit-opt-in" and not (normalize_legacy_disabled
            and pxpipe.get("enabled") is False and pxpipe.get("provider_activation")=="default-new-local-sessions"))
        or pxpipe.get("provider_configuration")!="user-model-provider-plus-launch-agent"
        or pxpipe.get("provider_content_scope")!="whole-request-eligible-content"
        or pxpipe.get("mcp_role")!="optional-cold-reference"
        or pxpipe.get("selection")!="analyze-then-render"
        or pxpipe.get("content_scope")!="new-cold-reference-only"
        or pxpipe.get("session_boundary")!="plugin-load-requires-new-chat"
        or pxpipe.get("fallback")!="native"
    ):
        raise RuntimeError("project optional context transport policy is invalid")
    if pxpipe["enabled"] is False:
        if normalize_legacy_disabled:
            config["context_transport"]={"default":"native"}
            return
        raise RuntimeError("disabled optional pxpipe transport must be fully absent")
    if plugin_provenance!="verified":
        raise RuntimeError("enabled optional pxpipe transport requires verified plugin provenance")


MAX_LEGACY_QUARANTINE_RECORDS=8192
MAX_LEGACY_QUARANTINE_BYTES=64*1024*1024
MAX_LEGACY_QUARANTINE_DEPTH=64
MAX_LEGACY_QUARANTINE_RECEIPT_BYTES=8*1024*1024


def private_namespace_records(path,base):
    records=[]; total_bytes=0
    def visit(current,depth=0):
        nonlocal total_bytes
        if depth>MAX_LEGACY_QUARANTINE_DEPTH: raise RuntimeError("legacy Skill quarantine namespace exceeds its depth limit")
        metadata=os.lstat(current)
        relative=current.relative_to(base).as_posix()
        mode=stat.S_IMODE(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError(f"legacy Skill quarantine refuses a symlink: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            records.append({"path":relative,"kind":"directory","mode":mode})
            with os.scandir(current) as iterator:
                children=[]
                for entry in iterator:
                    if len(records)+len(children)>=MAX_LEGACY_QUARANTINE_RECORDS: raise RuntimeError("legacy Skill quarantine namespace exceeds its record limit")
                    children.append(Path(entry.path))
            for child in sorted(children,key=lambda item:os.fsencode(item.name)): visit(child,depth+1)
        elif stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink!=1:
                raise RuntimeError(f"legacy Skill quarantine refuses a hardlinked file: {relative}")
            data=read_installer_bytes(current,label="current managed file"); total_bytes+=len(data)
            records.append({"path":relative,"kind":"file","mode":mode,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()})
        else:
            raise RuntimeError(f"legacy Skill quarantine refuses a special filesystem entry: {relative}")
        if len(records)>MAX_LEGACY_QUARANTINE_RECORDS or total_bytes>MAX_LEGACY_QUARANTINE_BYTES:
            raise RuntimeError("legacy Skill quarantine namespace exceeds its bounded archive limit")
    visit(path)
    return records,total_bytes


def aggregate_private_namespace_records(present,project):
    records=[]; total_bytes=0
    for item in present:
        item_records,item_bytes=private_namespace_records(item,project)
        if len(records)+len(item_records)>MAX_LEGACY_QUARANTINE_RECORDS or total_bytes+item_bytes>MAX_LEGACY_QUARANTINE_BYTES:
            raise RuntimeError("legacy Skill quarantine aggregate exceeds its archive limit")
        records.extend(item_records); total_bytes+=item_bytes
    encoded_records=json.dumps(records,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    if len(encoded_records)>MAX_LEGACY_QUARANTINE_RECEIPT_BYTES: raise RuntimeError("legacy Skill quarantine receipt exceeds its encoded limit")
    return records,total_bytes,hashlib.sha256(encoded_records).hexdigest()


def quarantine_legacy_skill_v1(destination,task):
    project=destination/"project"; lock=project/"skills.lock.json"
    if not (lock.exists() or lock.is_symlink()): return None
    metadata=os.lstat(lock)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink!=1:
        raise RuntimeError("legacy Skill lock is not a safe regular file")
    lock_bytes=read_installer_bytes(lock,label="Skill lock")
    if len(lock_bytes)>2*1024*1024:
        raise RuntimeError("legacy Skill lock exceeds its bounded migration limit")
    try: value=json.loads(lock_bytes)
    except (UnicodeDecodeError,json.JSONDecodeError) as error:
        raise RuntimeError("legacy Skill lock is malformed and cannot be safely classified") from error
    if not isinstance(value,dict) or value.get("schema")!="agent-skills-lock/v1": return None
    if task.get("status") not in {"idle",None}:
        raise RuntimeError("legacy v1 Skill authority is bound to a non-idle task; finish or explicitly abort that task before update")
    journal=project/"skill-mutation-journal.json"
    if journal.exists() or journal.is_symlink():
        raise RuntimeError("legacy Skill mutation journal must be recovered before installer quarantine")
    blueprint_path=project/"BLUEPRINT.json"; blueprint_replacement=None
    if blueprint_path.exists() or blueprint_path.is_symlink():
        blueprint_metadata=os.lstat(blueprint_path)
        if (not stat.S_ISREG(blueprint_metadata.st_mode) or stat.S_ISLNK(blueprint_metadata.st_mode)
                or blueprint_metadata.st_nlink!=1 or blueprint_metadata.st_size>2*1024*1024):
            raise RuntimeError("legacy Skill Blueprint is unsafe or oversized")
        try: blueprint_value=json.loads(read_installer_bytes(blueprint_path,label="project blueprint"))
        except (UnicodeDecodeError,json.JSONDecodeError) as error: raise RuntimeError("legacy Skill Blueprint is malformed") from error
        if not isinstance(blueprint_value,dict): raise RuntimeError("legacy Skill Blueprint must be one JSON object")
        capabilities=blueprint_value.get("design",{}).get("capabilities",[]) if isinstance(blueprint_value.get("design"),dict) else None
        if blueprint_value.get("status")=="confirmed" and isinstance(capabilities,list) and capabilities:
            # Preserve every original byte in quarantine, but only revoke the
            # confirmation in place. Do not append unbounded or fabricated
            # design guidance to the user-owned draft.
            blueprint_replacement=dict(blueprint_value); blueprint_replacement["status"]="draft"; blueprint_replacement["confirmation"]=None
    names=[
        "skills.lock.json","skills","skill-cas","skill-lock-history","skill-lifecycle.json",
        "skill-candidates.json","skill-recommendation.json",
    ]
    if blueprint_replacement is not None: names.append("BLUEPRINT.json")
    present=[project/name for name in names if (project/name).exists() or (project/name).is_symlink()]
    records,total_bytes,payload_digest=aggregate_private_namespace_records(present,project)
    if project.is_symlink() or not project.is_dir():
        raise RuntimeError("legacy Skill project namespace is not one real directory")
    quarantine_root=project/"skill-quarantine"
    if quarantine_root.exists() or quarantine_root.is_symlink():
        root_metadata=os.lstat(quarantine_root)
        if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
            raise RuntimeError("legacy Skill quarantine parent is not one real directory")
    else:
        quarantine_root.mkdir(mode=0o700)
    quarantine_root.chmod(0o700)
    quarantine=quarantine_root/f"legacy-v1-{payload_digest}"
    if quarantine.exists() or quarantine.is_symlink():
        raise RuntimeError("legacy Skill quarantine destination already exists while v1 authority remains active")
    payload=quarantine/"payload"; payload.mkdir(parents=True,mode=0o700)
    quarantine.chmod(0o700)
    for item in present: os.replace(item,payload/item.name)
    if blueprint_replacement is not None:
        atomic_json(blueprint_path,blueprint_replacement); blueprint_path.chmod(0o600)
    receipt={
        "schema":"agent-skill-v1-quarantine/v1",
        "reason":"v1-lock-lacks-complete-applicable-legal-document-proof",
        "source_lock_schema":"agent-skills-lock/v1",
        "payload_sha256":payload_digest,
        "payload_bytes":total_bytes,
        "records":records,
        "authority_converted":False,
        "legal_approval_fabricated":False,
        "blueprint_confirmation_revoked":blueprint_replacement is not None,
        "quarantined_at":dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    }
    atomic_json(quarantine/"RECEIPT.json",receipt); (quarantine/"RECEIPT.json").chmod(0o600)
    return receipt


def legacy_skill_v1_present(destination):
    path=destination/"project/skills.lock.json"
    if not (path.exists() or path.is_symlink()): return False
    metadata=os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink!=1 or metadata.st_size>2*1024*1024:
        raise RuntimeError("project Skill lock is unsafe or exceeds its bounded size")
    try: value=json.loads(read_installer_bytes(path,label="installer file"))
    except (UnicodeDecodeError,json.JSONDecodeError) as error:
        raise RuntimeError("project Skill lock is malformed") from error
    return isinstance(value,dict) and value.get("schema")=="agent-skills-lock/v1"


def prechain_skill_history_migration_required(destination):
    project=destination/"project"; history=project/"skill-mutation-history"; head=project/"skill-mutation-head.json"
    archive=project/"skill-mutation-prechain-v2"
    archive_present=archive.exists() or archive.is_symlink()
    history_present=history.exists() or history.is_symlink()
    head_present=head.exists() or head.is_symlink()
    return archive_present or (history_present and not head_present)


def retire_verified_pxpipe_policy(destination,config,prior_install):
    if config.get("context_transport")=={"default":"native"}: return None
    validate_context_transport_policy(config,"verified",normalize_legacy_disabled=False)
    policy=config["context_transport"]
    record={
        "schema":"agent-context-transport-retirement/v1",
        "reason":"template-pxpipe-source-quarantined",
        "retired_policy":policy,
        "retired_policy_sha256":canonical_sha256(policy),
        "prior_install_schema":prior_install.get("schema"),
        "prior_install_version":prior_install.get("version"),
        "prior_install_manifest_sha256":sha(destination/".workflow-manifest.json"),
        "replacement":{"default":"native"},
        "retired_at":dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    }
    digest=canonical_sha256({key:value for key,value in record.items() if key!="retired_at"})
    archive=destination/"state/evidence/context-transport-retirements"/f"{digest}.json"
    if archive.exists(): raise RuntimeError("pxpipe retirement archive collision")
    atomic_json(archive,record); archive.chmod(0o600)
    config["context_transport"]={"default":"native"}
    return record


def migrate_private(source,destination,plugin_provenance,project_root=None,idle_reseed=True,retire_pxpipe=False,policy_rebind=False):
    prior_install=manifest(destination/".workflow-manifest.json",required=True)
    prior_migration=installed_migration_version(prior_install)
    seed=fresh_state_seed(source)
    config_path=destination/"config.json"; task_path=destination/"state/TASK.json"
    config=json.loads(read_installer_text(config_path,label="installer config")); task=json.loads(read_installer_text(task_path,label="task state")); defaults=json.loads(read_installer_text(seed/"config.json",label="fresh config"))
    skill_authority_revoked=quarantine_legacy_skill_v1(destination,task) is not None
    if prechain_skill_history_migration_required(destination):
        candidate_tool(source,destination,"scripts/skillctl.py","migrate-history")
    control=config.setdefault("agent_control",{})
    control_order=list(control)
    observer_names=("platform_observer","human_decision_observer","provider_preflight_observer")
    observer_presence={name for name in observer_names if name in control}
    observer_overrides={name:control.pop(name) for name in observer_names if name in control}
    deep_fill(config,defaults)
    control=config["agent_control"]
    for name in observer_names:
        if name in observer_overrides: control[name]=observer_overrides[name]
    # Re-inserting the preserved observers must not reorder project keys: a
    # no-op migration leaves config.json byte-identical and the context
    # capsule's policy-bundle binding intact.
    config["agent_control"]={name:control[name] for name in (*control_order,*control) if name in control}
    for name,entry in list(config.get("environments",{}).items()):
        if "deploy" in entry:
            deploy=bool(entry.pop("deploy")); entry.setdefault("deploy_allowed",deploy); entry.setdefault("deploy_required",name=="production" and deploy)
    security_defaults=defaults["agent_control"]
    migration_16_policy=("status_request_after_unchanged_checks","max_task_payload_input_count","max_task_payload_single_bytes","max_task_payload_total_bytes","max_task_payload_estimated_tokens")
    if prior_migration<16:
        for name in migration_16_policy: config.setdefault("agent_control",{})[name]=security_defaults[name]
    if prior_migration<18:
        config.setdefault("agent_control",{})["stall_timeout_seconds"]=security_defaults["stall_timeout_seconds"]
    if prior_migration<19:
        config.setdefault("agent_control",{})["platform_observer"]=security_defaults["platform_observer"]
    elif "platform_observer" not in observer_presence:
        raise RuntimeError("project Agent security policy is missing after its migration boundary: platform_observer")
    if prior_migration<20:
        config.setdefault("agent_control",{})["human_decision_observer"]=security_defaults["human_decision_observer"]
    elif "human_decision_observer" not in observer_presence:
        raise RuntimeError("project Agent security policy is missing after its migration boundary: human_decision_observer")
    if prior_migration<31:
        config.setdefault("agent_control",{}).setdefault("human_decision_observer",{}).setdefault(
            "allow_current_chat_local_release",False,
        )
    if prior_migration<32:
        capsule_limits=config.setdefault("context",{}).setdefault("max_capsule_tokens",{})
        if capsule_limits.get("fast")==600:
            capsule_limits["fast"]=defaults["context"]["max_capsule_tokens"]["fast"]
    # Caller text is advisory only; migrations cannot restore legacy local gate authority.
    human_observer=config.setdefault("agent_control",{}).setdefault("human_decision_observer",{})
    if prior_migration>=31 and human_observer.get("allow_current_chat_local_release") is not False:
        raise RuntimeError("project Agent security policy was tampered after migration: allow_current_chat_local_release")
    human_observer["allow_current_chat_local_release"]=False
    if prior_migration<26:
        config.setdefault("agent_control",{})["provider_preflight_observer"]=security_defaults["provider_preflight_observer"]
    elif "provider_preflight_observer" not in observer_presence:
        raise RuntimeError("project Agent security policy is missing after its migration boundary: provider_preflight_observer")
    if prior_migration<30:
        previous_budgets={"fast":4000,"standard":12000,"release":30000}
        current_budgets={"fast":6000,"standard":20000,"release":40000}
        modes=config.setdefault("routing",{}).setdefault("modes",{})
        for mode,new_budget in current_budgets.items():
            entry=modes.setdefault(mode,{})
            if entry.get("token_budget")==previous_budgets[mode]:
                entry["token_budget"]=new_budget
    if prior_migration<35:
        previous_budgets={"fast":6000,"standard":20000,"release":40000}
        current_budgets={"fast":12000,"standard":24000,"release":48000}
        modes=config.setdefault("routing",{}).setdefault("modes",{})
        for mode,new_budget in current_budgets.items():
            entry=modes.setdefault(mode,{})
            if entry.get("token_budget")==previous_budgets[mode]:
                entry["token_budget"]=new_budget
    if prior_migration<36:
        previous_budgets={"fast":12000,"standard":24000,"release":48000}
        current_budgets={"fast":16000,"standard":48000,"release":96000}
        modes=config.setdefault("routing",{}).setdefault("modes",{})
        for mode,new_budget in current_budgets.items():
            entry=modes.setdefault(mode,{})
            if entry.get("token_budget")==previous_budgets[mode]:
                entry["token_budget"]=new_budget
        # Retire the deprecated transition-increment alias: its true
        # historical semantic was the per-TRANSITION bookkeeping increment,
        # not the per-turn overhead, so customized legacy values carry into
        # context.transition_token_increment (filled with the honest
        # 200/400/800 defaults), never into estimated_turn_overhead_tokens.
        # A mode is carried only when its legacy value differs from that
        # mode's legacy seed constant (150/300/500) — those seed constants
        # were fictional and are replaced by the honest defaults — and each
        # carried increment is clamped to the sane range [50, 1000].  The
        # carry never overwrites a project-owned transition_token_increment
        # policy.  The alias itself never survives the migration.
        context=config.setdefault("context",{})
        legacy_increment=context.get("automatic_transition_token_increment")
        legacy_seed_increment={"fast":150,"standard":300,"release":500}
        if isinstance(legacy_increment,dict):
            increment_defaults=defaults["context"].get("transition_token_increment")
            if not isinstance(increment_defaults,dict):
                increment_defaults={"fast":200,"standard":400,"release":800}
            increments=context.get("transition_token_increment")
            if increments is None:
                increments=dict(increment_defaults)
                context["transition_token_increment"]=increments
            if isinstance(increments,dict) and increments==increment_defaults:
                for mode,value in legacy_increment.items():
                    if (
                        isinstance(value,int) and not isinstance(value,bool)
                        and value!=legacy_seed_increment.get(mode)
                    ):
                        increments[mode]=min(1000,max(50,value))
        context.pop("automatic_transition_token_increment",None)
        control=config.setdefault("agent_control",{})
        if control.get("child_system_tool_margin_tokens")==1000:
            control["child_system_tool_margin_tokens"]=security_defaults["child_system_tool_margin_tokens"]
    if prior_migration<37:
        # Fill the per-transition bookkeeping increment (charged once per
        # context transition as a fixed honest estimate: fast/standard/release
        # = 200/400/800).  Migration 36 carries customized values of the
        # retired alias into this key; fill every remaining mode from the
        # seed defaults.  This step removes nothing, so projects already
        # migrated by 36 simply gain the new key.
        increment_defaults=defaults["context"].get("transition_token_increment")
        if not isinstance(increment_defaults,dict):
            increment_defaults={"fast":200,"standard":400,"release":800}
        increments=config.setdefault("context",{}).setdefault("transition_token_increment",{})
        if isinstance(increments,dict):
            for mode,value in increment_defaults.items():
                increments.setdefault(mode,value)
    if prior_migration<38:
        # v3.1.44 could carry a customized lower-mode legacy increment above
        # the next mode's default (for example 900/400/800), report a
        # successful update, and leave agentctl validation impossible. Repair
        # only invalid numeric maps: clamp every value to the supported range
        # and raise later modes to preserve fast <= standard <= release.
        increments=config.setdefault("context",{}).get("transition_token_increment")
        if (
            isinstance(increments,dict)
            and all(
                isinstance(increments.get(mode),int)
                and not isinstance(increments.get(mode),bool)
                for mode in ("fast","standard","release")
            )
        ):
            floor=50
            for mode in ("fast","standard","release"):
                normalized=min(1000,max(floor,int(increments[mode])))
                increments[mode]=normalized
                floor=normalized
    if prior_migration<21:
        for mode in ("fast", "standard", "release"):
            config.setdefault("routing",{}).setdefault("modes",{}).setdefault(mode,{}).update({
                key: value for key,value in defaults["routing"]["modes"][mode].items()
                if key in {"clean_reruns","test_strategy","wall_time_minutes","max_automatic_test_attempts"}
            })
        config["testing"]=defaults["testing"]
        config.setdefault("acceptance_adapters",{})["acceptance-workflow"]=defaults["acceptance_adapters"]["acceptance-workflow"]
    if prior_migration<22:
        for mode in ("fast","standard","release"):
            config.setdefault("routing",{}).setdefault("modes",{}).setdefault(mode,{})["max_child_agents"]=defaults["routing"]["modes"][mode]["max_child_agents"]
        config["testing"]=defaults["testing"]
        config.setdefault("context",{})["max_rollback_entries"]=defaults["context"]["max_rollback_entries"]
        fingerprint_paths=config.setdefault("scope",{}).setdefault("fingerprint_paths",[])
        for path in (".agent/scripts",".agent/skills",".agent/templates",".agent/workflows"):
            if path not in fingerprint_paths: fingerprint_paths.append(path)
        config.setdefault("acceptance_adapters",{})["acceptance-workflow"]=defaults["acceptance_adapters"]["acceptance-workflow"]
    if prior_migration<23:
        config.setdefault("context",{})["max_rollback_entries"]=defaults["context"]["max_rollback_entries"]
        config.setdefault("context",{})["max_failure_entries"]=defaults["context"]["max_failure_entries"]
        config.setdefault("context",{})["max_failure_archive_depth"]=defaults["context"]["max_failure_archive_depth"]
        config["evidence_retention"]=defaults["evidence_retention"]
    if prior_migration<24:
        config["context_transport"]=defaults["context_transport"]
    adapters=config.setdefault("acceptance_adapters",{})
    if not isinstance(adapters,dict):
        raise RuntimeError("project acceptance adapter registry must be an object")
    # Technology adapters are optional compatibility entries. A release may use
    # the generic user-confirmed blueprint acceptance contract instead.
    for name,current in adapters.items():
        if not isinstance(name,str) or not name or not isinstance(current,dict) or set(current)!={"implemented","runner","receipt_schema"}:
            raise RuntimeError(f"project acceptance adapter is invalid: {name}")
        if not isinstance(current.get("implemented"),bool) or not isinstance(current.get("runner"),str) or not current["runner"] or not isinstance(current.get("receipt_schema"),str) or not current["receipt_schema"]:
            raise RuntimeError(f"project acceptance adapter implementation contract is invalid: {name}")
        canonical = CANONICAL_ACCEPTANCE_ADAPTERS.get(name)
        if canonical is None or current != canonical:
            raise RuntimeError(f"project acceptance adapter is not a canonical digest-managed built-in: {name}")
    validate_retention_policy(config)
    if retire_pxpipe:
        retire_verified_pxpipe_policy(destination,config,prior_install)
    validate_context_transport_policy(config,plugin_provenance,normalize_legacy_disabled=True)
    config.setdefault("agent_control",{}).pop("interrupt_after_unchanged_checks",None)
    runtime_policy=config.get("runtime")
    if not isinstance(runtime_policy,dict) or not strict_bounded_int(runtime_policy.get("term_timeout_seconds"),1,60):
        raise RuntimeError("project runtime term_timeout_seconds must be an integer in 1..60")
    agent_policy=config.get("agent_control",{})
    numeric_bounds={
        "platform_limit":(2,64),"reserve_root_slots":(1,63),"max_redispatch":(0,10),
        "status_interval_seconds":(1,3600),"monitor_grace_seconds":(0,3600),"stall_timeout_seconds":(120,1800),
        "max_fork_turns":(1,20),"capacity_retry_limit":(0,3),"status_request_after_unchanged_checks":(1,100),
        "max_task_payload_input_count":(1,1024),"max_task_payload_single_bytes":(1024,10485760),
        "max_task_payload_total_bytes":(1024,104857600),"max_task_payload_estimated_tokens":(256,10000000),
    }
    selected_model=agent_policy.get("default_model"); inactive=task.get("status") in {"idle","accepted",None}
    if inactive:
        if task.get("status")=="accepted" and valid_model_id(selected_model): task.setdefault("completed_model",selected_model)
        elif task.get("status")!="accepted": task.setdefault("completed_model",None)
        task["selected_model"]=None; agent_policy["default_model"]=None
    else:
        if not valid_model_id(selected_model):
            raise RuntimeError("active task requires a valid explicit model bound at agentctl.py start --model <model-id>")
        if task.get("selected_model") not in {None,selected_model}:
            raise RuntimeError("active task model differs from preserved configuration authority")
        task["selected_model"]=selected_model; task.setdefault("completed_model",None)
    for name,(minimum,maximum) in numeric_bounds.items():
        if not strict_bounded_int(agent_policy.get(name),minimum,maximum):
            raise RuntimeError(f"project Agent numeric policy is invalid: {name}")
    if agent_policy["reserve_root_slots"]>=agent_policy["platform_limit"] or agent_policy["stall_timeout_seconds"]<=agent_policy["status_interval_seconds"]+agent_policy["monitor_grace_seconds"] or agent_policy["max_task_payload_total_bytes"]<agent_policy["max_task_payload_single_bytes"]:
        raise RuntimeError("project Agent numeric policy relationships are invalid")
    for name in ("allow_model_fallback","context_strategy","allowed_role_types","review_role_types"):
        if agent_policy.get(name)!=security_defaults.get(name):
            raise RuntimeError(f"project Agent security policy differs from the canonical template: {name}")
    adapter_owner=Path(project_root).resolve() if project_root is not None else destination.parent.resolve()
    validate_observer_policy("platform_observer",config.get("agent_control",{}).get("platform_observer"),security_defaults["platform_observer"],adapter_owner)
    validate_observer_policy("human_decision_observer",config.get("agent_control",{}).get("human_decision_observer"),security_defaults["human_decision_observer"],adapter_owner)
    validate_observer_policy("provider_preflight_observer",config.get("agent_control",{}).get("provider_preflight_observer"),security_defaults["provider_preflight_observer"],adapter_owner)
    if config.get("guardrails_ready") is True and not isinstance(config.get("project_initialization"),dict):
        guardrails_data=read_installer_bytes(destination/"policies/PROJECT_GUARDRAILS.md",label="candidate guardrails")
        config["project_initialization"]={
            "schema":"agent-project-initialization/v1",
            "guardrails_sha256":hashlib.sha256(guardrails_data).hexdigest(),
            "guardrails_bytes":len(guardrails_data),
            "initialized_at":dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        }
    atomic_json(config_path,config)
    validate_project_guardrails(destination)
    task_defaults=json.loads(read_installer_text(seed/"state/TASK.json",label="fresh task"))
    if prior_migration<40 and task.get("status") not in {"idle",None}:
        route=task.get("template_route")
        if route is None:
            pass  # Very old active tasks remain explicitly unrouted until a reviewed reroute.
        elif not isinstance(route,dict):
            raise RuntimeError("active task migration-40 requires a valid template route or null")
        elif route.get("schema")=="agent-template-route/v2":
            expected={"schema","task_type","projection","mode","capabilities","templates","requirement_contract_sha256","manifest_sha256","sha256"}
            if set(route)!=expected or route.get("sha256")!=canonical_sha256({key:route[key] for key in route if key!="sha256"}):
                raise RuntimeError("active task migration-40 requires an intact v2 route receipt")
            old_route_sha=route["sha256"]
            route_capabilities=route.get("capabilities")
            if not isinstance(route_capabilities,list) or any(not isinstance(item,str) for item in route_capabilities):
                raise RuntimeError("active task migration-40 route capabilities are invalid")
            protected=any(item=="ci-cd" or item.startswith(("provider","ci-","acceptance")) for item in route_capabilities)
            blueprint_path=destination/"project/BLUEPRINT.json"; skills_lock_path=destination/"project/skills.lock.json"
            adaptive={"blueprint_sha256":None,"skills_lock_sha256":None,"project_capabilities":[]}
            if blueprint_path.exists() or blueprint_path.is_symlink():
                blueprint_snapshot=planned_path_snapshot(blueprint_path,include_bytes=True)
                try: blueprint=json.loads(blueprint_snapshot["bytes"])
                except (UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("active route Blueprint authority is malformed") from error
                design=blueprint.get("design") if isinstance(blueprint,dict) else None
                capabilities=design.get("capabilities") if isinstance(design,dict) else None
                ids=[item.get("id") for item in capabilities] if isinstance(capabilities,list) and all(isinstance(item,dict) for item in capabilities) else None
                if blueprint.get("schema")!="agent-project-blueprint/v1" or blueprint.get("status")!="confirmed" or not isinstance(blueprint.get("confirmation"),dict) or ids!=route_capabilities:
                    raise RuntimeError("active route does not match the exact current confirmed Blueprint authority")
                adaptive["blueprint_sha256"]=blueprint_snapshot["sha256"]; adaptive["project_capabilities"]=ids
                if skills_lock_path.exists() or skills_lock_path.is_symlink(): adaptive["skills_lock_sha256"]=planned_path_snapshot(skills_lock_path)["sha256"]
            elif protected:
                raise RuntimeError("active provider/CI/acceptance route lacks confirmed Blueprint authority")
            if protected and (adaptive["blueprint_sha256"] is None or adaptive["skills_lock_sha256"] is None):
                raise RuntimeError("active provider/CI/acceptance route lacks complete Blueprint/Skill authority")
            migrated={**route,"schema":"agent-template-route/v3","adaptive_project":adaptive,"sha256":None}
            migrated["sha256"]=canonical_sha256({key:migrated[key] for key in migrated if key!="sha256"})
            task["template_route"]=migrated
            for record in task.get("rendered_artifacts",[]):
                if isinstance(record,dict) and record.get("route_sha256")==old_route_sha:
                    record["route_sha256"]=migrated["sha256"]
        elif route.get("schema")!="agent-template-route/v3":
            raise RuntimeError("active task migration-40 supports only v2/v3 route receipts")
    if task.get("status") not in {"idle",None}:
        required={"deployment_requested","current_node","accepted_nodes","node_artifacts","pending_gate_artifacts","metrics","budget_state","usage_receipts","selected_capabilities","template_route","rendered_artifacts"}
        if not required.issubset(task): raise RuntimeError("active task needs an explicit state migration before workflow update")
    else: deep_fill(task,task_defaults)
    task.setdefault("rollback_archive",None); task.setdefault("failure_archive",None); task.setdefault("task_archive",None)
    # Provider-owned receipts are the sole authoritative decision policy for every migrated task.
    task,provider_authority_revoked=migrate_provider_decision_authority(destination,task,prior_migration)
    authority_revoked=skill_authority_revoked or provider_authority_revoked
    if prior_migration<30:
        previous_budgets={"fast":4000,"standard":12000,"release":30000}
        current_budgets={"fast":6000,"standard":20000,"release":40000}
        mode=str(task.get("mode","standard"))
        if mode in previous_budgets and task.get("token_budget")==previous_budgets[mode]:
            task["token_budget"]=current_budgets[mode]
    if prior_migration<35:
        previous_budgets={"fast":6000,"standard":20000,"release":40000}
        current_budgets={"fast":12000,"standard":24000,"release":48000}
        mode=str(task.get("mode","standard"))
        if mode in previous_budgets and task.get("token_budget")==previous_budgets[mode]:
            task["token_budget"]=current_budgets[mode]
    if prior_migration<36:
        previous_budgets={"fast":12000,"standard":24000,"release":48000}
        current_budgets={"fast":16000,"standard":48000,"release":96000}
        mode=str(task.get("mode","standard"))
        if mode in previous_budgets and task.get("token_budget")==previous_budgets[mode]:
            task["token_budget"]=current_budgets[mode]
    deep_fill(task.setdefault("risk_flags",{}),task_defaults["risk_flags"])
    activation_rebound=False
    if task.get("skill_activation") is None or authority_revoked:
        activation_receipt,activation_data=candidate_skill_activation_snapshot(source,destination,task["task_generation_id"])
        task["skill_activation"]=activation_receipt; atomic_bytes(destination/"state/SKILL_ACTIVATION.json",activation_data); activation_rebound=True
    elif not existing_skill_activation_valid(destination,task):
        raise RuntimeError("current task Skill activation receipt is tampered or invalid")
    elif not candidate_existing_skill_activation_valid(source,destination,task):
        activation_receipt,activation_data=candidate_skill_activation_snapshot(source,destination,task["task_generation_id"])
        task["skill_activation"]=activation_receipt; atomic_bytes(destination/"state/SKILL_ACTIVATION.json",activation_data); activation_rebound=True
    atomic_json(task_path,task)
    for name in ("agents.json","delivery.json","runtime.json","tool-leases.json","test-budget.json","EVIDENCE_INDEX.json",".scheduler-receipt-nonces.json"):
        target=destination/"state"/name
        if not target.exists():
            if name==".scheduler-receipt-nonces.json" and prior_migration>=42:
                raise RuntimeError("scheduler nonce registry is missing; current projects cannot reset replay history")
            shutil.copy2(seed/"state"/name,target)
            if name==".scheduler-receipt-nonces.json": target.chmod(0o600)
    migrate_delivery_state(destination,prior_migration)
    migrate_active_hot_state(source,destination,prior_migration)
    migrate_active_template_state(source,destination,prior_migration)
    migrate_active_loaded_references(destination,prior_install,prior_migration)
    rebind_context=authority_revoked or activation_rebound or policy_rebind
    finalize_active_context_binding(source,destination,prior_migration,force=rebind_context)
    if prior_migration<MIGRATION_VERSION or rebind_context:
        refresh_migrated_stage_index(source,destination)
    task=json.loads(read_installer_text(task_path,label="task state"))
    agents_path=destination/"state/agents.json"; agents_state=json.loads(read_installer_text(agents_path,label="agent ledger state"))
    history_fields=("members","prepared_dispatches","capacity_failures","replay_runs")
    histories=[]
    for field in history_fields:
        value=agents_state.get(field,[])
        if not isinstance(value,list):
            raise RuntimeError(f"legacy Agent ledger {field} is malformed")
        histories.extend(value)
    if agents_state.get("schema")=="agent-team/v8":
        if histories:
            raise RuntimeError(
                "agent ledger migration 27 refuses to invent Token reservations for existing v8 history; "
                "prove the platform empty and archive the old ledger with agentledger init --archive-existing"
            )
        agents_state["schema"]="agent-team/v9"
        agents_state["token_accounting"]={
            "schema":"agent-child-token-accounting/v1",
            "token_budget":int(task.get("token_budget",0)),
            "settled_tokens":0,
        }
        agents_state["updated_at"]=time.strftime("%Y-%m-%dT%H:%M:%S+00:00",time.gmtime())
        atomic_json(agents_path,agents_state)
    elif agents_state.get("schema")!="agent-team/v9":
        raise RuntimeError("legacy Agent ledger requires an external provider-signed exact reset before workflow update; installer refuses unsigned platform-snapshot migration")
    elif not histories:
        # A history-free v9 ledger has no charges to reinterpret. Rebind its
        # empty account to the migrated task's mode budget; non-empty ledgers
        # remain fail-closed and require explicit archival.
        accounting=agents_state.get("token_accounting")
        if (
            isinstance(accounting,dict)
            and accounting.get("schema")=="agent-child-token-accounting/v1"
            and accounting.get("settled_tokens")==0
            and accounting.get("token_budget")!=task.get("token_budget")
        ):
            accounting["token_budget"]=task.get("token_budget")
            agents_state["updated_at"]=time.strftime("%Y-%m-%dT%H:%M:%S+00:00",time.gmtime())
            atomic_json(agents_path,agents_state)
    if inactive and agents_state.get("default_model") is not None:
        candidate_tool(source,destination,"skills/manage-agent-team/scripts/agentledger.py","migrate-idle-model-v4")
        candidate_tool(source,destination,"skills/manage-agent-team/scripts/agentledger.py","validate",readonly=True)
        agents_state=json.loads(read_installer_text(agents_path,label="agent ledger state"))
    ledger_security={
        "schema":"agent-team/v9",
        "default_model":config["agent_control"]["default_model"],
        "allow_model_fallback":config["agent_control"]["allow_model_fallback"],
        "context_strategy":security_defaults["context_strategy"],
        "max_fork_turns":config["agent_control"]["max_fork_turns"],
        "capacity_retry_limit":config["agent_control"]["capacity_retry_limit"],
        "reserved_root_slots":config["agent_control"]["reserve_root_slots"],
        "status_interval_seconds":config["agent_control"]["status_interval_seconds"],
        "monitor_grace_seconds":config["agent_control"]["monitor_grace_seconds"],
        "stall_timeout_seconds":config["agent_control"]["stall_timeout_seconds"],
        "allowed_role_types":security_defaults["allowed_role_types"],
        "review_role_types":security_defaults["review_role_types"],
        "status_request_after_unchanged_checks":security_defaults["status_request_after_unchanged_checks"],
        "max_redispatch":config["agent_control"]["max_redispatch"],
        "platform_observer":config["agent_control"]["platform_observer"],
        "task_payload_schema":"agent-task-payload/v2",
    }
    for name,expected in ledger_security.items():
        if agents_state.get(name)!=expected:
            raise RuntimeError(f"project Agent ledger security policy differs from the canonical template: {name}")
    accounting=agents_state.get("token_accounting")
    if (
        not isinstance(accounting,dict)
        or accounting.get("schema")!="agent-child-token-accounting/v1"
        or accounting.get("token_budget")!=task.get("token_budget")
        or not isinstance(accounting.get("settled_tokens"),int)
        or isinstance(accounting.get("settled_tokens"),bool)
        or accounting.get("settled_tokens")<0
    ):
        raise RuntimeError("project child-Agent Token accounting is invalid for the current task")
    runtime_path=destination/"state/runtime.json"; runtime=json.loads(read_installer_text(runtime_path,label="runtime state"))
    if runtime.get("schema")!="agent-runtime/v2" or not isinstance(runtime.get("baseline"),dict):
        if any(runtime.get(key) for key in ("processes","docker_projects","ports")):
            raise RuntimeError("runtime v2 migration is blocked while registered resources remain; clean them first")
        if task.get("status") not in {"idle",None}:
            raise RuntimeError("active task needs an explicit user-bound runtime baseline before workflow update")
        shutil.copy2(seed/"state/runtime.json",runtime_path)
    if task.get("status")=="idle" and (idle_reseed or prior_migration<MIGRATION_VERSION):
        shutil.copy2(seed/"state/CONTEXT.json",destination/"state/CONTEXT.json"); shutil.copy2(seed/"state/STAGE_INDEX.md",destination/"state/STAGE_INDEX.md")
        legacy=destination/"state/CONTEXT.md"
        if legacy.is_file(): legacy.unlink()
        initialize_fresh_context(source,destination)


def validate_migration_feasibility(source,destination,installed,args,retire_pxpipe=False):
    """Run the exact private-state migration against an isolated copy."""
    wanted,wanted_modes,_,_,_,plugin_provenance=source_contract(source.parent)
    writes,removes,conflicts=plan_agent_update(wanted,wanted_modes,installed,destination)
    if conflicts: raise RuntimeError("dry-run migration feasibility encountered managed conflicts")
    with tempfile.TemporaryDirectory(prefix="agent-migration-dry-run-") as raw:
        project=Path(raw)/"project"; project.mkdir(mode=0o700)
        candidate=project/".agent"; copy_private_tree(destination,candidate)
        write_managed(source,candidate,writes,removes)
        apply_file_modes(candidate,wanted_modes); apply_managed_directory_modes(candidate); apply_agent_root_mode(candidate)
        migrate_private(source,candidate,plugin_provenance,project_root=project,idle_reseed=bool(writes or removes),retire_pxpipe=retire_pxpipe,policy_rebind=bool(writes or removes))


def validate_fresh_install_feasibility(source_root,target,args,guardrails_data,wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,agents_snapshot,claude_snapshot):
    adapter_path=bootstrap_human_decision_adapter(target,args.human_decision_adapter)
    provider_adapter_path=bootstrap_provider_preflight_adapter(target,args.provider_preflight_adapter)
    with tempfile.TemporaryDirectory(prefix="agent-install-dry-run-") as raw:
        project=Path(raw)/target.name; project.mkdir(mode=0o700)
        candidate=project/".agent"; copy_managed_fresh_install(source_root/".agent",candidate)
        config_path=candidate/"config.json"; config=json.loads(read_installer_text(config_path,label="installer config"))
        config["project"]={"name":args.project_name,"type":args.project_type}; config["agent_control"]["default_model"]=None
        config["agent_control"]["human_decision_observer"]["signed_adapter"]=adapter_path
        config["agent_control"]["human_decision_observer"]["allow_current_chat_local_release"]=False
        config["agent_control"]["provider_preflight_observer"]["signed_adapter"]=provider_adapter_path; atomic_json(config_path,config)
        if guardrails_data is not None: bind_project_guardrails(candidate,guardrails_data)
        agents_path=candidate/"state/agents.json"; agents_state=json.loads(read_installer_text(agents_path,label="agent ledger state"))
        agents_state["default_model"]=None; agents_state["epoch"]="0"*64; agents_state["last_platform_snapshot"]=None
        agents_state["platform_empty_verified"]=False; agents_state["migration_source"]=None
        agents_state["updated_at"]="1970-01-01T00:00:00+00:00"; atomic_json(agents_path,agents_state)
        initialize_fresh_context(source_root/".agent",candidate)
        agents=project/"AGENTS.md"; claude=project/"CLAUDE.md"
        atomic_bytes(agents,render_bootstrap(target/"AGENTS.md",snapshot=agents_snapshot).encode())
        atomic_bytes(claude,render_bootstrap(target/"CLAUDE.md",snapshot=claude_snapshot).encode())
        atomic_json(candidate/".workflow-manifest.json",install_manifest(wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,sha(agents),sha(claude)))
        validate_candidate(candidate,wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,agents,claude)


def install(source_root,target,args):
    source=source_root/".agent"
    destination=target/".agent"
    # Make the first no-follow observation itself the durable plan. A separate
    # exists() check would leave a gap in which an interloper could appear and
    # then be mistaken for the planned predecessor.
    planned_root=planned_transaction_root(target)
    planned_targets={".agent":planned_transaction_target(destination)}
    reinstall_husk=planned_targets[".agent"]["present"]
    if reinstall_husk:
        validate_private_tree(destination)
        if (destination/".workflow-manifest.json").exists() or (destination/".workflow-manifest.json").is_symlink():
            raise SystemExit(f"existing {destination}; use --check or --update")
    guardrails_data=project_guardrails_bytes(args.guardrails_file) if args.guardrails_file else None
    wanted,wanted_modes,plugin_wanted,wanted_entry,entry_digest,plugin_provenance=source_contract(source_root)
    if reinstall_husk:
        collisions=sorted(relative for relative in wanted if (destination/relative).exists() or (destination/relative).is_symlink())
        if collisions: raise RuntimeError("private uninstall husk occupies managed reinstall paths: "+", ".join(collisions))
        if not (destination/"config.json").is_file() or (destination/"config.json").is_symlink():
            raise RuntimeError("private uninstall husk lacks supported config state")
    agents_write,agents_conflicts,agents_snapshot=plan_bootstrap(target/"AGENTS.md","AGENTS.md",with_snapshot=True)
    claude_write,claude_conflicts,claude_snapshot=plan_bootstrap(target/"CLAUDE.md","CLAUDE.md",with_snapshot=True)
    _,_,_,pxpipe_conflicts=plan_legacy_pxpipe_cleanup(None,target,plugin_provenance)
    conflicts=agents_conflicts+claude_conflicts+pxpipe_conflicts
    if conflicts:
        print("INSTALL BLOCKED: a managed bootstrap anchor or reserved pxpipe namespace conflicts")
        for item in conflicts: print(f"- {item}")
        return 2
    if args.default_model is not None:
        raise SystemExit("--default-model cannot persist idle authority; pass --model to each agentctl.py start")
    if args.dry_run:
        validate_fresh_install_feasibility(source_root,target,args,guardrails_data,wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,agents_snapshot,claude_snapshot)
        print(f"DRY RUN install {destination}"); return 0
    adapter_path=bootstrap_human_decision_adapter(target,args.human_decision_adapter)
    provider_adapter_path=bootstrap_provider_preflight_adapter(target,args.provider_preflight_adapter)
    target.parent.mkdir(parents=True,exist_ok=True)
    if agents_write: planned_targets["AGENTS.md"]=planned_transaction_target_from_snapshot(agents_snapshot)
    if claude_write: planned_targets["CLAUDE.md"]=planned_transaction_target_from_snapshot(claude_snapshot)
    candidate_parent=begin_transaction(target)
    try:
        candidate=candidate_parent/".agent"
        if reinstall_husk:
            copy_private_tree(destination,candidate); apply_agent_root_mode(candidate)
            collisions=sorted(relative for relative in wanted if (candidate/relative).exists() or (candidate/relative).is_symlink())
            if collisions: raise RuntimeError("private uninstall husk occupies managed reinstall paths: "+", ".join(collisions))
            write_managed(source,candidate,sorted(wanted),[]); apply_file_modes(candidate,wanted_modes); apply_managed_directory_modes(candidate)
            config_path=candidate/"config.json"
            if not config_path.is_file() or config_path.is_symlink(): raise RuntimeError("private uninstall husk lacks supported config state")
        else:
            copy_managed_fresh_install(source,candidate)
            config_path=candidate/"config.json"; config=json.loads(read_installer_text(config_path,label="installer config")); config["project"]={"name":args.project_name,"type":args.project_type}; config["agent_control"]["default_model"]=None; config["agent_control"]["human_decision_observer"]["signed_adapter"]=adapter_path; config["agent_control"]["human_decision_observer"]["allow_current_chat_local_release"]=False; config["agent_control"]["provider_preflight_observer"]["signed_adapter"]=provider_adapter_path; atomic_json(config_path,config)
            if guardrails_data is not None: bind_project_guardrails(candidate,guardrails_data)
            agents_path=candidate/"state/agents.json"; agents_state=json.loads(read_installer_text(agents_path,label="agent ledger state"))
            agents_state["default_model"]=None
            agents_state["epoch"]=hashlib.sha256(f"{target}|{time.time_ns()}|{uuid.uuid4().hex}".encode()).hexdigest()
            agents_state["last_platform_snapshot"]=None; agents_state["platform_empty_verified"]=False
            agents_state["migration_source"]=None; agents_state["updated_at"]=time.strftime("%Y-%m-%dT%H:%M:%S+00:00",time.gmtime())
            atomic_json(agents_path,agents_state)
            initialize_fresh_context(source,candidate)
        candidate_agents=stage_bootstrap(target,candidate_parent,"AGENTS.md",snapshot=agents_snapshot)
        candidate_claude=stage_bootstrap(target,candidate_parent,"CLAUDE.md",snapshot=claude_snapshot)
        atomic_json(candidate/".workflow-manifest.json",install_manifest(wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,sha(candidate_agents),sha(candidate_claude)))
        validate_candidate(candidate,wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,candidate_agents,candidate_claude)
        replacements=[(candidate,destination)]
        if agents_write: replacements.append((candidate_agents,target/"AGENTS.md"))
        if claude_write: replacements.append((candidate_claude,target/"CLAUDE.md"))
        commit_transaction(target,candidate_parent,replacements,planned_targets,planned_root)
    except Exception:
        abort_transaction(target)
        raise
    print(f"INSTALLED workflow {VERSION} in {target}")
    if guardrails_data is None:
        print("PROJECT INIT REQUIRED: complete project guardrails, then run `python3 .agent/scripts/agentctl.py project-init --guardrails-file <project-guardrails.md>`")
        print("BOOTSTRAP NOT READY: do not approve requirements or begin implementation before project initialization")
    else:
        print("PROJECT INITIALIZED: guardrails bytes and readiness were committed atomically")
    print("MODEL SELECTION DEFERRED: idle authority is null; pass an explicit `--model <provider/model-id>` to each task start")
    if adapter_path is None and guardrails_data is not None:
        print("LOCAL EVIDENCE ADVISORY ONLY: current-chat or other local user evidence cannot authorize state or gate changes")
        print("GATES BLOCKED: configure agent_control.human_decision_observer.signed_adapter and provide a valid provider-owned receipt")
    if guardrails_data is not None:
        print("NEXT: run `python3 .agent/scripts/agentctl.py bootstrap-check`, then start clarification")
    if provider_adapter_path is None:
        print("PRODUCTION BLOCKED: configure agent_control.provider_preflight_observer.signed_adapter before provider preflight")
    return 0


def bootstrap_without_managed_block(path):
    snapshot=planned_path_snapshot(path,include_bytes=True)
    try: text=snapshot["bytes"].decode("utf-8")
    except UnicodeError as error: raise RuntimeError(f"bootstrap is not UTF-8: {path}") from error
    starts=text.count(BOOTSTRAP_START); ends=text.count(BOOTSTRAP_END)
    if starts!=1 or ends!=1: raise RuntimeError(f"bootstrap lacks one exact managed block: {path}")
    begin=text.index(BOOTSTRAP_START); finish=text.index(BOOTSTRAP_END,begin)+len(BOOTSTRAP_END)
    block=text[begin:finish]+("\n" if text[finish:finish+1]=="\n" else "")
    digest=hashlib.sha256(block.encode()).hexdigest()
    if block!=BOOTSTRAP and LEGACY_BOOTSTRAPS.get(digest)!=block: raise RuntimeError(f"bootstrap managed block drifted: {path}")
    suffix=text[finish:]
    if suffix.startswith("\n"): suffix=suffix[1:]
    rendered=(text[:begin]+suffix).rstrip()+("\n" if (text[:begin]+suffix).strip() else "")
    return snapshot,rendered.encode()


def remove_owned_candidate_files(candidate,owned):
    validated_manifest_files(owned,"uninstall files")
    root=os.open(candidate,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
    try:
        for relative,digest in sorted(owned.items(),key=lambda item:(-len(item[0].split("/")),item[0])):
            parts=relative.split("/"); parent=os.dup(root)
            try:
                for component in parts[:-1]:
                    child=os.open(component,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=parent)
                    os.close(parent); parent=child
                name=parts[-1]; descriptor=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=parent)
                try:
                    opened=os.fstat(descriptor)
                    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1: raise RuntimeError(f"manifest-owned uninstall path drifted: {relative}")
                    content=hashlib.sha256(); remaining=opened.st_size
                    while remaining:
                        chunk=os.read(descriptor,min(65536,remaining))
                        if not chunk: raise RuntimeError(f"manifest-owned uninstall path changed: {relative}")
                        content.update(chunk); remaining-=len(chunk)
                    if os.read(descriptor,1) or content.hexdigest()!=digest: raise RuntimeError(f"manifest-owned uninstall path drifted: {relative}")
                    quarantine=f".agent-workflow-uninstall-{uuid.uuid4().hex}"
                    os.replace(name,quarantine,src_dir_fd=parent,dst_dir_fd=parent)
                    moved=os.stat(quarantine,dir_fd=parent,follow_symlinks=False)
                    if inode_identity(moved)!=inode_identity(opened):
                        try: os.replace(quarantine,name,src_dir_fd=parent,dst_dir_fd=parent)
                        finally: raise RuntimeError(f"manifest-owned uninstall leaf raced: {relative}")
                    os.unlink(quarantine,dir_fd=parent); os.fsync(parent)
                finally: os.close(descriptor)
            finally: os.close(parent)
        for relative in sorted({"/".join(name.split("/")[:-1]) for name in owned if "/" in name},key=lambda name:(-len(name.split("/")),name)):
            parts=relative.split("/"); parent=os.dup(root)
            try:
                for component in parts[:-1]:
                    child=os.open(component,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=parent)
                    os.close(parent); parent=child
                try: os.rmdir(parts[-1],dir_fd=parent); os.fsync(parent)
                except OSError: pass
            finally: os.close(parent)
    finally: os.close(root)


def uninstall_workflow(target,args):
    destination=target/".agent"; manifest_path=destination/".workflow-manifest.json"
    if not destination.is_dir() or destination.is_symlink(): raise SystemExit("target has no safe .agent workflow to uninstall")
    validate_private_tree(destination)
    if not manifest_path.is_file() or manifest_path.is_symlink():
        print("WORKFLOW UNMANAGED: no authenticated manifest; refusing uninstall"); return 2
    installed=manifest(manifest_path,required=True); owned=previous_agent_files(installed)
    snapshots={}
    conflicts=[]
    for relative,digest in owned.items():
        path=destination/relative
        try: snapshot=planned_path_snapshot(path)
        except Exception: conflicts.append(relative); continue
        if snapshot["sha256"]!=digest: conflicts.append(relative)
        else: snapshots[relative]=snapshot
    remove_plugin,marketplace_rewrite,marketplace_mode,pxpipe_conflicts,cleanup=plan_legacy_pxpipe_cleanup(installed,target,"disabled",with_snapshots=True)
    conflicts+=pxpipe_conflicts
    try: agents_snapshot,agents_post=bootstrap_without_managed_block(target/"AGENTS.md")
    except Exception as error: conflicts.append(f"AGENTS.md ({error})"); agents_snapshot=agents_post=None
    try: claude_snapshot,claude_post=bootstrap_without_managed_block(target/"CLAUDE.md")
    except Exception as error: conflicts.append(f"CLAUDE.md ({error})"); claude_snapshot=claude_post=None
    if conflicts:
        print("UNINSTALL BLOCKED: manifest-owned bytes drifted or are unsafe")
        for item in sorted(set(conflicts)): print(f"- {item}")
        return 2
    if args.dry_run:
        print(f"DRY RUN uninstall: agent_files={len(owned)} plugin={int(remove_plugin)} marketplace={int(marketplace_rewrite is not None)}")
        return 0
    prior_pxpipe_files,prior_marketplace_digest=previous_pxpipe_ownership(installed)
    retirement_receipt=None
    if remove_plugin and prior_pxpipe_files and isinstance(prior_marketplace_digest,str):
        retirement_receipt=ensure_global_pxpipe_retired(target,manifest_path,installed,prior_pxpipe_files)
    planned_root=planned_transaction_root(target); planned_targets={".agent":planned_transaction_target(destination),
        "AGENTS.md":planned_transaction_target_from_snapshot(agents_snapshot),"CLAUDE.md":planned_transaction_target_from_snapshot(claude_snapshot)}
    if marketplace_rewrite is not None: planned_targets[str(MARKETPLACE_RELATIVE)]=planned_transaction_target(target/MARKETPLACE_RELATIVE)
    if remove_plugin: planned_targets[str(PLUGIN_RELATIVE)]=planned_transaction_target(target/PLUGIN_RELATIVE)
    candidate_parent=begin_transaction(target)
    try:
        for relative,snapshot in snapshots.items(): require_planned_path(destination/relative,snapshot)
        candidate=candidate_parent/".agent"; copy_private_tree(destination,candidate)
        remove_owned_candidate_files(candidate,owned)
        candidate_manifest=candidate/".workflow-manifest.json"
        if candidate_manifest.is_symlink() or not candidate_manifest.is_file() or sha(candidate_manifest)!=sha(manifest_path): raise RuntimeError("uninstall manifest changed during staging")
        candidate_manifest.unlink()
        staged=[]
        for name,data,snapshot in (("AGENTS.md",agents_post,agents_snapshot),("CLAUDE.md",claude_post,claude_snapshot)):
            require_planned_path(target/name,snapshot); path=candidate_parent/name
            if data: atomic_bytes(path,data); os.chmod(path,snapshot["mode"]); staged.append((path,target/name))
            else: staged.append((None,target/name))
        replacements=[(candidate,destination),*staged]
        if marketplace_rewrite is not None:
            require_planned_path(target/MARKETPLACE_RELATIVE,cleanup[str(MARKETPLACE_RELATIVE)])
            staged_marketplace=candidate_parent/MARKETPLACE_RELATIVE; atomic_json(staged_marketplace,marketplace_rewrite); os.chmod(staged_marketplace,marketplace_mode)
            replacements.append((staged_marketplace,target/MARKETPLACE_RELATIVE))
        if remove_plugin:
            snapshot=cleanup[str(PLUGIN_RELATIVE)]; plugin=target/PLUGIN_RELATIVE
            if filesystem_identity(plugin)!=snapshot["identity"] or transaction_content_sha256(plugin)!=snapshot["sha256"]: raise RuntimeError("owned plugin changed before uninstall")
            if retirement_receipt is None: raise RuntimeError("pxpipe plugin removal lacks terminal global retirement receipt")
            verified=ensure_global_pxpipe_retired(target,manifest_path,installed,prior_pxpipe_files)
            if verified.get("record_sha256")!=retirement_receipt.get("record_sha256"):
                raise RuntimeError("global pxpipe retirement receipt changed before uninstall plugin deletion")
            replacements.append((None,plugin))
        commit_transaction(target,candidate_parent,replacements,planned_targets,planned_root)
    except Exception:
        abort_transaction(target); raise
    print("UNINSTALLED managed workflow bytes; preserved private/unowned .agent state and unrelated bootstrap content")
    return 0


def execute(args,source_root,target):
    source=source_root/".agent"; destination=target/".agent"
    if args.uninstall: return uninstall_workflow(target,args)
    if not args.check and not args.update and not args.adopt:
        if not args.project_name: raise SystemExit("--project-name is required for a new install")
        return install(source_root,target,args)
    if not destination.is_dir(): raise SystemExit("target has no .agent workflow; run a new install")
    validate_private_tree(destination)
    planned_destination=(planned_transaction_target(destination) if (args.adopt or args.update) and not args.dry_run else None)
    manifest_path=destination/".workflow-manifest.json"
    if args.adopt:
        if manifest_path.exists(): raise SystemExit("workflow already has an install manifest; use --check or --update")
        wanted,wanted_modes,plugin_wanted,wanted_entry,entry_digest,plugin_provenance=source_contract(source_root); observed=files(destination); observed_modes=file_modes(destination,observed)
        if (observed!=wanted or observed_modes!=wanted_modes
                or any(mode!=0o755 for mode in managed_directory_modes(destination).values())):
            missing=sorted(set(wanted)-set(observed)); extra=sorted(set(observed)-set(wanted)); changed=sorted(key for key in set(wanted)&set(observed) if wanted[key]!=observed[key] or wanted_modes[key]!=observed_modes[key])
            print("ADOPT BLOCKED: managed tree is not an exact template match")
            for label,items in (("missing",missing),("extra",extra),("changed",changed)):
                for item in items:
                    detail=(f" expected={wanted[item]} observed={observed[item]} expected_mode={oct(wanted_modes[item])} observed_mode={oct(observed_modes[item])}" if label=="changed" else "")
                    print(f"- {label}: {item}{detail}")
            return 2
        agents_write,agents_conflicts,agents_snapshot=plan_bootstrap(target/"AGENTS.md","AGENTS.md",with_snapshot=True)
        claude_write,claude_conflicts,claude_snapshot=plan_bootstrap(target/"CLAUDE.md","CLAUDE.md",with_snapshot=True)
        _,_,_,pxpipe_conflicts=plan_legacy_pxpipe_cleanup(None,target,plugin_provenance)
        adopt_conflicts=agents_conflicts+claude_conflicts+pxpipe_conflicts
        if adopt_conflicts:
            print("ADOPT BLOCKED: a managed bootstrap anchor or reserved pxpipe namespace conflicts")
            for item in adopt_conflicts: print(f"- {item}")
            return 2
        if args.dry_run: print(f"DRY RUN adopt workflow {VERSION}"); return 0
        planned_root=planned_transaction_root(target)
        planned_targets={".agent":planned_destination}
        if agents_write: planned_targets["AGENTS.md"]=planned_transaction_target_from_snapshot(agents_snapshot)
        if claude_write: planned_targets["CLAUDE.md"]=planned_transaction_target_from_snapshot(claude_snapshot)
        candidate_parent=begin_transaction(target)
        try:
            candidate=candidate_parent/".agent"; copy_private_tree(destination,candidate); apply_agent_root_mode(candidate)
            candidate_agents=stage_bootstrap(target,candidate_parent,"AGENTS.md",snapshot=agents_snapshot)
            candidate_claude=stage_bootstrap(target,candidate_parent,"CLAUDE.md",snapshot=claude_snapshot)
            atomic_json(candidate/".workflow-manifest.json",install_manifest(wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,sha(candidate_agents),sha(candidate_claude)))
            migrate_private(source,candidate,plugin_provenance,project_root=target)
            validate_candidate(candidate,wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,candidate_agents,candidate_claude)
            replacements=[(candidate,destination)]
            if agents_write: replacements.append((candidate_agents,target/"AGENTS.md"))
            if claude_write: replacements.append((candidate_claude,target/"CLAUDE.md"))
            commit_transaction(target,candidate_parent,replacements,planned_targets,planned_root)
        except Exception:
            abort_transaction(target)
            raise
        print(f"ADOPTED workflow {VERSION} in {target}"); return 0
    if not manifest_path.is_file():
        print("WORKFLOW UNMANAGED: missing .workflow-manifest.json; use --adopt only after an exact managed-tree match")
        return 2
    wanted,wanted_modes,plugin_wanted,wanted_entry,entry_digest,plugin_provenance=source_contract(source_root)
    installed=manifest(manifest_path,required=True)
    relation=version_relation(installed.get("version"),VERSION)
    if relation=="invalid_installed":
        reason=f"installed workflow version {installed.get('version')!r} is not strict numeric N.N.N"
        if args.check:
            print(f"TARGET VERSION INVALID: {reason}; install a template that recognizes this version"); return 3
        print(f"UPDATE REFUSED: {reason}; unknown versions cannot be safely upgraded or downgraded"); return 2
    if relation=="target_newer" or installed_migration_version(installed)>MIGRATION_VERSION:
        reason=(
            f"installed workflow {installed.get('version')} (migration {installed.get('migration_version')}) "
            f"is newer than template {VERSION} (migration {MIGRATION_VERSION})"
        )
        if args.check:
            print(f"TARGET NEWER: {reason}; a newer template is required"); return 3
        print(f"UPDATE REFUSED: {reason}; reverse migrations are unsupported; restore a complete older snapshot instead"); return 2
    writes,removes,conflicts,removal_snapshots=plan_agent_update(wanted,wanted_modes,installed,destination,with_snapshots=True)
    directory_mode_drift=sorted(relative for relative,mode in managed_directory_modes(destination).items() if mode!=0o755)
    if agent_root_mode(destination)!=AGENT_ROOT_MODE: directory_mode_drift.insert(0,".")
    remove_legacy_plugin,marketplace_rewrite,marketplace_mode,pxpipe_conflicts,cleanup_snapshots=plan_legacy_pxpipe_cleanup(installed,target,plugin_provenance,with_snapshots=True)
    prior_pxpipe_files,prior_marketplace_digest=previous_pxpipe_ownership(installed)
    retire_pxpipe=(
        plugin_provenance=="disabled" and remove_legacy_plugin and marketplace_rewrite is not None
        and isinstance(prior_pxpipe_files,dict) and bool(prior_pxpipe_files)
        and isinstance(prior_marketplace_digest,str) and re.fullmatch(r"[0-9a-f]{64}",prior_marketplace_digest) is not None
    )
    conflicts+=pxpipe_conflicts
    agents_trusted=installed_bootstrap_sha256(installed,"AGENTS.md")
    claude_trusted=installed_bootstrap_sha256(installed,"CLAUDE.md")
    agents_write,agents_conflicts,agents_snapshot=plan_bootstrap(target/"AGENTS.md","AGENTS.md",agents_trusted,with_snapshot=True)
    claude_write,claude_conflicts,claude_snapshot=plan_bootstrap(target/"CLAUDE.md","CLAUDE.md",claude_trusted,with_snapshot=True)
    conflicts=conflicts+agents_conflicts+claude_conflicts
    if conflicts:
        print("UPDATE BLOCKED: locally modified managed files"); [print(f"- {item}") for item in conflicts]; return 2
    if args.check:
        validate_project_guardrails(destination,allow_legacy=installed_migration_version(installed)<33)
        planned_agents_sha256=hashlib.sha256(render_bootstrap(target/"AGENTS.md",agents_trusted).encode()).hexdigest()
        planned_claude_sha256=hashlib.sha256(render_bootstrap(target/"CLAUDE.md",claude_trusted).encode()).hexdigest()
        manifest_matches_source=installed==install_manifest(wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,planned_agents_sha256,planned_claude_sha256)
        if writes or removes or directory_mode_drift or remove_legacy_plugin or marketplace_rewrite is not None or agents_write or claude_write or legacy_skill_v1_present(destination) or installed.get("version")!=VERSION or installed.get("migration_version")!=MIGRATION_VERSION or not manifest_matches_source:
            print(f"UPDATE AVAILABLE: writes={len(writes)} removes={len(removes)+int(remove_legacy_plugin)+int(marketplace_rewrite is not None)} bootstrap={int(agents_write or claude_write)} version={installed.get('version')}->{VERSION}"); return 1
        print(f"WORKFLOW CURRENT: {VERSION}"); return 0
    if ((installed_migration_version(installed)<34 or installed_migration_version(installed)>=MIGRATION_VERSION)
            and not legacy_skill_v1_present(destination)):
        validate_legacy_active_context(source,destination)
    if args.dry_run:
        validate_migration_feasibility(source,destination,installed,args,retire_pxpipe=retire_pxpipe)
        print(f"DRY RUN update: writes={len(writes)} removes={len(removes)+int(remove_legacy_plugin)+int(marketplace_rewrite is not None)} directory_modes={len(directory_mode_drift)}"); return 0
    retirement_receipt=None
    if retire_pxpipe:
        # Global user state is retired and durably receipted before the local
        # plugin that contains the pinned recovery executables can be deleted.
        retirement_receipt=ensure_global_pxpipe_retired(target,manifest_path,installed,prior_pxpipe_files)
        planned_destination=planned_transaction_target(destination)
    planned_root=planned_transaction_root(target)
    planned_targets={".agent":planned_destination}
    if agents_write: planned_targets["AGENTS.md"]=planned_transaction_target_from_snapshot(agents_snapshot)
    if claude_write: planned_targets["CLAUDE.md"]=planned_transaction_target_from_snapshot(claude_snapshot)
    if marketplace_rewrite is not None: planned_targets[str(MARKETPLACE_RELATIVE)]=planned_transaction_target(target/MARKETPLACE_RELATIVE)
    if remove_legacy_plugin: planned_targets[str(PLUGIN_RELATIVE)]=planned_transaction_target(target/PLUGIN_RELATIVE)
    candidate_parent=begin_transaction(target)
    try:
        candidate=candidate_parent/".agent"
        for relative,snapshot in removal_snapshots.items(): require_planned_path(destination/relative,snapshot)
        if str(MARKETPLACE_RELATIVE) in cleanup_snapshots: require_planned_path(target/MARKETPLACE_RELATIVE,cleanup_snapshots[str(MARKETPLACE_RELATIVE)])
        if str(PLUGIN_RELATIVE) in cleanup_snapshots:
            snapshot=cleanup_snapshots[str(PLUGIN_RELATIVE)]; path=target/PLUGIN_RELATIVE
            if filesystem_identity(path)!=snapshot["identity"] or transaction_content_sha256(path)!=snapshot["sha256"] or stat.S_IMODE(os.lstat(path).st_mode)!=snapshot["mode"]:
                raise RuntimeError("planned plugin removal changed before staging")
        copy_private_tree(destination,candidate); apply_agent_root_mode(candidate)
        candidate_agents=stage_bootstrap(target,candidate_parent,"AGENTS.md",agents_trusted,snapshot=agents_snapshot)
        candidate_claude=stage_bootstrap(target,candidate_parent,"CLAUDE.md",claude_trusted,snapshot=claude_snapshot)
        write_managed(source,candidate,writes,removes,removal_snapshots=removal_snapshots); apply_file_modes(candidate,wanted_modes); apply_managed_directory_modes(candidate); migrate_private(source,candidate,plugin_provenance,project_root=target,idle_reseed=bool(writes or removes),retire_pxpipe=retire_pxpipe,policy_rebind=bool(writes or removes))
        atomic_json(candidate/".workflow-manifest.json",install_manifest(wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,sha(candidate_agents),sha(candidate_claude)))
        validate_candidate(candidate,wanted,wanted_modes,plugin_wanted,entry_digest,plugin_provenance,candidate_agents,candidate_claude)
        replacements=[(candidate,destination)]
        if agents_write: replacements.append((candidate_agents,target/"AGENTS.md"))
        if claude_write: replacements.append((candidate_claude,target/"CLAUDE.md"))
        if marketplace_rewrite is not None:
            staged_marketplace=candidate_parent/MARKETPLACE_RELATIVE
            atomic_json(staged_marketplace,marketplace_rewrite)
            os.chmod(staged_marketplace,marketplace_mode)
            replacements.append((staged_marketplace,target/MARKETPLACE_RELATIVE))
        if remove_legacy_plugin:
            if retirement_receipt is None:
                raise RuntimeError("project pxpipe plugin deletion lacks a verified global retirement receipt")
            verified=ensure_global_pxpipe_retired(target,manifest_path,installed,prior_pxpipe_files)
            if verified.get("record_sha256")!=retirement_receipt.get("record_sha256"):
                raise RuntimeError("global pxpipe retirement receipt changed before project plugin deletion")
            replacements.append((None,target/PLUGIN_RELATIVE))
        commit_transaction(target,candidate_parent,replacements,planned_targets,planned_root)
    except Exception:
        abort_transaction(target)
        raise
    print(f"UPDATED workflow to {VERSION}; preserved config, policies, state and project files"); return 0


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("target"); parser.add_argument("--project-name","--name",dest="project_name"); parser.add_argument("--project-type","--type",dest="project_type",default="general-project"); parser.add_argument("--human-decision-adapter"); parser.add_argument("--provider-preflight-adapter"); parser.add_argument("--default-model"); parser.add_argument("--allow-current-chat-local-release",action="store_true"); parser.add_argument("--guardrails-file")
    mode=parser.add_mutually_exclusive_group(); mode.add_argument("--check",action="store_true"); mode.add_argument("--update",action="store_true"); mode.add_argument("--adopt",action="store_true"); mode.add_argument("--uninstall",action="store_true"); parser.add_argument("--dry-run",action="store_true"); args=parser.parse_args()
    if args.guardrails_file and (args.check or args.update or args.adopt or args.uninstall):
        parser.error("--guardrails-file is valid only for a new install; installed projects use agentctl.py project-init")
    if args.default_model is not None and (args.check or args.update or args.adopt or args.uninstall):
        parser.error("--default-model is unsupported because idle model authority must remain null; pass --model to each agentctl.py start")
    if args.allow_current_chat_local_release:
        parser.error("--allow-current-chat-local-release is retired; local evidence is advisory and provider-owned receipts are required")
    system=platform.system()
    if system not in SUPPORTED_SYSTEMS or fcntl is None:
        raise SystemExit(f"unsupported operating system: {system or 'unknown'}; installer supports Linux and macOS")
    global LOGICAL_TARGET_ROOT,LOGICAL_TARGET_PARENT,BOUND_PARENT_IDENTITY,BOUND_TARGET_IDENTITY,INSTALLER_PUBLICATION_AUTHORITY
    source_root=Path(__file__).resolve().parent
    supplied=Path(os.path.abspath(args.target))
    if supplied.name in {"",".",".."}: raise SystemExit("installer target must name one project directory")
    logical_parent=supplied.parent
    logical_target=logical_parent/supplied.name
    read_only=bool(args.check or args.dry_run)
    parent_descriptor=open_directory_chain(logical_parent)
    if parent_descriptor is None:
        if args.check: return execute(args,source_root,logical_target)
        raise RuntimeError("installer target parent must already exist before mutation or dry-run feasibility validation")
    original_cwd=os.open(".",os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
    LOGICAL_TARGET_ROOT=logical_target; LOGICAL_TARGET_PARENT=logical_parent
    parent_metadata=assert_trusted_directory_descriptor(parent_descriptor,"installer target parent")
    BOUND_PARENT_IDENTITY=inode_identity(parent_metadata); BOUND_TARGET_IDENTITY=None
    publication_descriptor=None
    try:
        fcntl.flock(parent_descriptor,fcntl.LOCK_EX)
        try: target_before_lock=os.stat(supplied.name,dir_fd=parent_descriptor,follow_symlinks=False)
        except FileNotFoundError: target_before_lock=None
        publication_descriptor=open_publication_lock(parent_descriptor,supplied.name,create=not read_only)
        if publication_descriptor is not None:
            fcntl.flock(publication_descriptor,fcntl.LOCK_EX)
        INSTALLER_PUBLICATION_AUTHORITY=((parent_descriptor,publication_descriptor) if not read_only and publication_descriptor is not None else None)
        os.fchdir(parent_descriptor)
        target=Path(supplied.name)
        if target.exists() or target.is_symlink():
            try:
                target_descriptor=os.open(target,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
            except OSError as error:
                raise RuntimeError("installer target must be a real directory, not a link or special file") from error
            try:
                observed=assert_trusted_directory_descriptor(target_descriptor,"installer target root")
                BOUND_TARGET_IDENTITY=inode_identity(observed)
            finally: os.close(target_descriptor)
        assert_namespace_binding(target)
        if read_only and (transaction_journal_path(target).exists() or transaction_journal_path(target).is_symlink()):
            print("RECOVERY REQUIRED: pending installer transaction; run the intended mutating command to recover")
            return 2
        if not read_only: recover_transaction(target)
        result=execute(args,source_root,target)
        assert_namespace_binding(target if BOUND_TARGET_IDENTITY is not None else None)
        return result
    finally:
        try:
            os.fchdir(original_cwd)
            if publication_descriptor is not None:
                fcntl.flock(publication_descriptor,fcntl.LOCK_UN); os.close(publication_descriptor)
            fcntl.flock(parent_descriptor,fcntl.LOCK_UN)
        finally:
            os.close(original_cwd); os.close(parent_descriptor)
            LOGICAL_TARGET_ROOT=None; LOGICAL_TARGET_PARENT=None
            BOUND_PARENT_IDENTITY=None; BOUND_TARGET_IDENTITY=None
            INSTALLER_PUBLICATION_AUTHORITY=None


if __name__=="__main__": raise SystemExit(main())
