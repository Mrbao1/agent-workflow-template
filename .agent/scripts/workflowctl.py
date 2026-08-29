#!/usr/bin/env python3
"""Execute and validate node 0-8 workflow transitions and root-cause returns."""

from pathlib import Path
import argparse
import base64
import copy
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
from typing import Dict, List, Optional, Tuple
from workflowlib import boundedio,boundedprocess

def _reject_nonfinite_json(token):
    raise json.JSONDecodeError(f"non-finite JSON number is forbidden: {token}",token,0)

def strict_json_loads(raw,**kwargs):
    return json.loads(raw,parse_constant=_reject_nonfinite_json,**kwargs)

def strict_json_dumps(value,**kwargs):
    kwargs["allow_nan"]=False
    return json.dumps(value,**kwargs)


import contexttx
import humandecision
from workflowlib import state as workflow_state
from workflowlib import budget as total_budget
from workflowlib.state import task_projection


def find_agent_dir() -> Path:
    current = Path.cwd().resolve()
    for root in (current, *current.parents):
        candidate = root / ".agent"
        if candidate.is_dir(): return candidate
    raise SystemExit(".agent directory not found")


AGENT_DIR = find_agent_dir(); ROOT = AGENT_DIR.parent.resolve()
TASK_PATH = AGENT_DIR / "state" / "TASK.json"; STAGE_PATH = AGENT_DIR / "state" / "STAGE_INDEX.md"
CONFIG_PATH=AGENT_DIR/"config.json"; AGENTS_PATH=AGENT_DIR/"state/agents.json"
PROJECT_INIT_LOCK_PATH=AGENT_DIR/"state/.project-init.lock"
AGENTS_LOCK_PATH=AGENT_DIR/"state/.agents.lock"; AGENTS_CHAIN_PATH=AGENT_DIR/"state/agents-chain.jsonl"
KNOWLEDGE_PENDING_PATH=AGENT_DIR/"state/knowledge-pending.json"
CONTEXT_TOOL = AGENT_DIR / "scripts" / "contextctl.py"
PHASES = {0:"bootstrap",1:"clarification",2:"structuring",3:"scope",4:"solution",5:"tests",6:"implementation",7:"acceptance",8:"delivery"}
GATE_NODE = {"requirement":1,"solution":4,"acceptance":7,"production":8,"knowledge":8}
NODE_TEMPLATE = {
    2:"structured-requirement",3:"deliverables",4:"solution",5:"acceptance-matrix",
    6:"node-implementation",
}


def supervised_env() -> Dict[str, str]:
    return os.environ.copy()


MAX_WORKFLOW_COMMAND_OUTPUT_BYTES=1024*1024
MAX_WORKFLOW_COMMAND_INPUT_BYTES=16*1024*1024


def run_bounded_command(command,*,cwd=ROOT,env=None,timeout=120,pass_fds=(),input_data=None,output_limit=MAX_WORKFLOW_COMMAND_OUTPUT_BYTES):
    return boundedprocess.run(command,cwd=cwd,env=env,timeout=timeout,pass_fds=pass_fds,input=input_data,text=True,output_limit=output_limit)


def load(path: Path) -> Dict[str, object]:
    value=strict_json_loads(bounded_file_text(path,"workflow JSON"))
    if not isinstance(value,dict): raise SystemExit(f"JSON object required: {path}")
    return value


def atomic(path: Path, value: Dict[str, object]) -> None:
    data=(strict_json_dumps(value,ensure_ascii=False,indent=2)+"\n").encode("utf-8")
    try: boundedio.atomic_write(path,data,mode=0o600,label="workflow state")
    except RuntimeError as error: raise SystemExit(str(error)) from error

def agents_chain_advance(ledger: Dict[str, object]) -> bytes:
    previous=bounded_file_bytes(AGENTS_PATH,"agent ledger") if AGENTS_PATH.is_file() else None; revision=ledger.get("revision")
    if revision is None: ledger["revision"]=1; ledger["prev_sha256"]=None
    else:
        if not isinstance(revision,int) or isinstance(revision,bool) or revision<1 or previous is None:
            raise SystemExit("agent ledger chain cannot advance during completion")
        ledger["revision"]=revision+1; ledger["prev_sha256"]=hashlib.sha256(previous).hexdigest()
    return (strict_json_dumps(ledger,ensure_ascii=False,indent=2)+"\n").encode()


def agents_chain_journal_data(ledger: Dict[str, object],data: bytes,prior: bytes) -> bytes:
    if len(prior)>16*1024*1024 or (prior and not prior.endswith(b"\n")):
        raise SystemExit("agent ledger chain journal is malformed or unbounded")
    entry={"revision":ledger["revision"],"prev_sha256":ledger["prev_sha256"],"file_sha256":hashlib.sha256(data).hexdigest()}
    encoded=(strict_json_dumps(entry,sort_keys=True,separators=(",",":"))+"\n").encode()
    if len(prior)+len(encoded)>16*1024*1024:
        raise SystemExit("agent ledger chain journal exceeds its completion bound")
    return prior+encoded


def agents_chain_snapshot():
    try: descriptor,relative=_open_relative_nofollow(str(AGENTS_CHAIN_PATH.relative_to(ROOT)))
    except FileNotFoundError: return False,b""
    except OSError as error: raise SystemExit("agent ledger chain journal is unsafe") from error
    try: data,_identity=_read_bounded_descriptor(descriptor,"agent ledger chain journal")
    finally: os.close(descriptor)
    return True,data


MAX_NODE_ARTIFACT_BYTES=16*1024*1024


def _open_relative_nofollow(raw: str):
    relative=Path(raw)
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise SystemExit("artifact path must be one lexical project-relative path")
    if not hasattr(os,"O_NOFOLLOW") or not hasattr(os,"O_DIRECTORY"):
        raise SystemExit("node artifact capture requires POSIX descriptor-relative no-follow support")
    current=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for index,part in enumerate(relative.parts):
            final=index==len(relative.parts)-1
            descriptor=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|(0 if final else os.O_DIRECTORY),dir_fd=current)
            os.close(current); current=descriptor
        return current,relative.as_posix()
    except BaseException:
        os.close(current); raise


def _read_bounded_descriptor(descriptor: int, label: str):
    opened=os.fstat(descriptor)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1
            or opened.st_size<0 or opened.st_size>MAX_NODE_ARTIFACT_BYTES):
        raise SystemExit(f"{label} must be one bounded single-link regular file")
    identity=(opened.st_dev,opened.st_ino,stat.S_IMODE(opened.st_mode),opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
    chunks=[]; total=0
    while True:
        chunk=os.read(descriptor,min(1024*1024,MAX_NODE_ARTIFACT_BYTES+1-total))
        if not chunk: break
        chunks.append(chunk); total+=len(chunk)
        if total>MAX_NODE_ARTIFACT_BYTES: raise SystemExit(f"{label} exceeds its byte limit")
    final=os.fstat(descriptor)
    final_identity=(final.st_dev,final.st_ino,stat.S_IMODE(final.st_mode),final.st_size,final.st_mtime_ns,final.st_ctime_ns)
    if final_identity!=identity or total!=opened.st_size:
        raise SystemExit(f"{label} changed while reading")
    return b"".join(chunks),identity


def bounded_file_bytes(path: Path,label: str) -> bytes:
    try: relative=Path(path).relative_to(ROOT).as_posix()
    except ValueError as error: raise SystemExit(f"{label} escapes project") from error
    descriptor,_relative=_open_relative_nofollow(relative)
    try: data,_identity=_read_bounded_descriptor(descriptor,label)
    finally: os.close(descriptor)
    return data


def bounded_file_text(path: Path,label: str) -> str:
    try: return bounded_file_bytes(path,label).decode("utf-8")
    except UnicodeError as error: raise SystemExit(f"{label} is not UTF-8") from error


def _node_capture_directory(create: bool):
    state,_relative=_open_relative_nofollow(".agent/state")
    try:
        state_metadata=os.fstat(state)
        if (not stat.S_ISDIR(state_metadata.st_mode) or state_metadata.st_uid!=os.geteuid()
                or stat.S_IMODE(state_metadata.st_mode)&0o022):
            raise SystemExit("node artifact state parent is unsafe")
        if create:
            try: os.mkdir("evidence",0o700,dir_fd=state)
            except FileExistsError: pass
        parent=os.open("evidence",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=state)
    finally: os.close(state)
    try:
        parent_metadata=os.fstat(parent)
        if (not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_uid!=os.geteuid()
                or stat.S_IMODE(parent_metadata.st_mode)&0o022):
            raise SystemExit("node artifact evidence parent is unsafe")
        if create:
            try: os.mkdir("node-artifact-captures",0o700,dir_fd=parent)
            except FileExistsError: pass
        descriptor=os.open("node-artifact-captures",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
    finally: os.close(parent)
    metadata=os.fstat(descriptor)
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=os.geteuid()
            or stat.S_IMODE(metadata.st_mode)&0o022):
        os.close(descriptor); raise SystemExit("node artifact capture directory is unsafe")
    return descriptor


def _seal_node_artifact(data: bytes, digest: str) -> str:
    relative=f".agent/state/evidence/node-artifact-captures/{digest}.artifact"; name=f"{digest}.artifact"
    directory=_node_capture_directory(True); flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW
    try:
        try: descriptor=os.open(name,flags,0o400,dir_fd=directory)
        except FileExistsError:
            descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
            try: observed,_identity=_read_bounded_descriptor(descriptor,"sealed node artifact")
            finally: os.close(descriptor)
            if observed!=data: raise SystemExit("sealed node artifact content-address collision")
            return relative
        try:
            view=memoryview(data)
            while view: view=view[os.write(descriptor,view):]
            os.fchmod(descriptor,0o400); os.fsync(descriptor)
        finally: os.close(descriptor)
        os.fsync(directory)
        return relative
    finally: os.close(directory)


def node_artifact(raw: str, *, seal: bool = True) -> Dict[str, object]:
    try: descriptor,relative=_open_relative_nofollow(raw)
    except OSError as error: raise SystemExit(f"artifact missing or unsafe: {raw}") from error
    try: data,identity=_read_bounded_descriptor(descriptor,"node artifact")
    finally: os.close(descriptor)
    if b"{{" in data: raise SystemExit("artifact contains unresolved template placeholders")
    digest=hashlib.sha256(data).hexdigest(); sealed_path=(
        _seal_node_artifact(data,digest) if seal else f".agent/state/evidence/node-artifact-captures/{digest}.artifact"
    )
    dev,inode,mode,size,mtime_ns,ctime_ns=identity
    capture={"schema":"agent-node-artifact-capture/v1","path":relative,"sha256":digest,"bytes":len(data),"sealed_path":sealed_path,
             "source":{"device":dev,"inode":inode,"mode":mode,"size":size,"mtime_ns":mtime_ns,"ctime_ns":ctime_ns}}
    if seal:
        prefix=f"{digest}-{hashlib.sha256(relative.encode()).hexdigest()}"
        capture_name=f"{prefix}-{canonical_sha256(capture)}.json"
        encoded=strict_json_dumps(capture,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()
        directory=_node_capture_directory(True)
        try:
            try: descriptor=os.open(capture_name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=directory)
            except FileExistsError:
                descriptor=os.open(capture_name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
                try: existing,_=_read_bounded_descriptor(descriptor,"node artifact capture record")
                finally: os.close(descriptor)
                if existing!=encoded: raise SystemExit("node artifact provenance content-address collision")
            else:
                try:
                    view=memoryview(encoded)
                    while view: view=view[os.write(descriptor,view):]
                    os.fchmod(descriptor,0o400); os.fsync(descriptor)
                finally: os.close(descriptor)
                os.fsync(directory)
        finally: os.close(directory)
    return {"path":relative,"sha256":digest,"bytes":len(data)}


def node_capture_paths(record: Dict[str,object]):
    relative=str(record.get("path","")); digest=str(record.get("sha256",""))
    prefix=f"{digest}-{hashlib.sha256(relative.encode()).hexdigest()}-"
    try: directory=_node_capture_directory(False)
    except OSError as error: raise SystemExit("node artifact capture inventory is missing or unsafe") from error
    before=os.fstat(directory); identity=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_mtime_ns,value.st_ctime_ns)
    matches=[]; observed=0
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                observed+=1
                if observed>4096: raise SystemExit("node artifact capture directory is unbounded")
                if not entry.name.startswith(prefix) or not entry.name.endswith(".json"): continue
                metadata=entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink!=1:
                    raise SystemExit("node artifact capture inventory contains an unsafe matching entry")
                matches.append(entry.name)
        after=os.fstat(directory)
    except BaseException:
        os.close(directory); raise
    if identity(after)!=identity(before):
        os.close(directory); raise SystemExit("node artifact capture inventory changed during enumeration")
    matches.sort()
    if not matches or len(matches)>64:
        os.close(directory); raise SystemExit("node artifact capture inventory is missing or unbounded")
    return directory,matches,identity(before)


def load_node_captures(record: Dict[str,object]):
    values=[]; directory,names,directory_identity=node_capture_paths(record)
    try:
        for name in names:
            descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
            try: raw,_identity=_read_bounded_descriptor(descriptor,"node artifact capture record")
            finally: os.close(descriptor)
            try: value=strict_json_loads(raw.decode("utf-8"))
            except (UnicodeError,json.JSONDecodeError) as error: raise SystemExit("node artifact capture record is invalid") from error
            if (not isinstance(value,dict) or set(value)!={"schema","path","sha256","bytes","sealed_path","source"}
                    or value.get("schema")!="agent-node-artifact-capture/v1"
                    or any(value.get(key)!=record.get(key) for key in ("path","sha256","bytes"))
                    or name.rsplit("-",1)[-1]!=canonical_sha256(value)+".json"):
                raise SystemExit("node artifact capture record does not bind the accepted record")
            values.append(value)
        after=os.fstat(directory)
        if (after.st_dev,after.st_ino,after.st_mode,after.st_mtime_ns,after.st_ctime_ns)!=directory_identity:
            raise SystemExit("node artifact capture inventory changed during loading")
    finally: os.close(directory)
    return values


def load_node_capture(record: Dict[str,object]):
    return load_node_captures(record)[0]


def node_capture_matches_source(record: Dict[str,object]) -> bool:
    try:
        captures=load_node_captures(record); descriptor,_=_open_relative_nofollow(str(record.get("path","")))
        try: data,identity=_read_bounded_descriptor(descriptor,"node artifact source revalidation")
        finally: os.close(descriptor)
        dev,inode,mode,size,mtime_ns,ctime_ns=identity
        expected_source={"device":dev,"inode":inode,"mode":mode,"size":size,"mtime_ns":mtime_ns,"ctime_ns":ctime_ns}
        return (any(capture.get("source")==expected_source for capture in captures)
                and hashlib.sha256(data).hexdigest()==record.get("sha256") and len(data)==record.get("bytes"))
    except (OSError,SystemExit,KeyError,TypeError):
        return False


def artifact(raw: str) -> Dict[str, object]:
    try: descriptor,relative=_open_relative_nofollow(raw)
    except OSError as error: raise SystemExit(f"artifact missing or unsafe: {raw}") from error
    try: data,_identity=_read_bounded_descriptor(descriptor,"workflow artifact")
    finally: os.close(descriptor)
    if b"{{" in data: raise SystemExit("artifact contains unresolved template placeholders")
    return {"path":relative,"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)}


def canonical_sha256(value: object) -> str:
    encoded=strict_json_dumps(value,ensure_ascii=False,sort_keys=True,separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def decision_packet(task: Dict[str, object], gate: str, record: Dict[str, object]) -> Dict[str, object]:
    destinations = {
        "solution": "node 5 test and acceptance planning",
        "acceptance": "node 8 delivery planning" if task.get("mode") == "release" else "retrospective and completion",
        "production": "the separately controlled node 8 production delivery step",
        "knowledge": "the separately controlled knowledge-promotion step",
    }
    questions = {
        "solution": "Approve this solution and task design?",
        "acceptance": "Accept the recorded validation result?",
        "production": "Approve the proposed production promotion decision?",
        "knowledge": "Approve promotion of the proposed reusable knowledge?",
    }

    return {
        "schema": "agent-decision-packet/v1",
        "gate": gate,
        "question": questions[gate],
        "approval_destination": destinations[gate],
        "scope_boundary": (
            "Approval records only this gate decision; it does not execute deployment "
            "or make production changes."
        ),
        "reply": "Reply approve, or reject with the requested changes.",
        "artifact": record,
    }

def _project_json(relative: str,label: str,max_bytes: int=65536):
    descriptor,normalized=_open_relative_nofollow(relative)
    try: data,_identity=_read_bounded_descriptor(descriptor,label)
    finally: os.close(descriptor)
    if len(data)>max_bytes: raise SystemExit(f"{label} exceeds {max_bytes} bytes")
    try: value=strict_json_loads(data.decode("utf-8"))
    except (UnicodeDecodeError,json.JSONDecodeError) as error: raise SystemExit(f"{label} is not strict UTF-8 JSON: {error}")
    if not isinstance(value,dict): raise SystemExit(f"{label} must be a JSON object")
    return value,{"path":normalized,"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)}


def capture_knowledge_candidates(paths,allowed_evidence):
    if not paths: return []
    registry,_record=_project_json(".agent/project/knowledge/registry.json","knowledge registry",262144)
    entries=registry.get("entries") if registry.get("schema")=="agent-knowledge-registry/v1" else None
    if not isinstance(entries,list): raise SystemExit("knowledge candidates require a valid project knowledge registry")
    owners={entry.get("id"):entry for entry in entries if isinstance(entry,dict) and entry.get("status")=="active" and isinstance(entry.get("owners"),list) and entry.get("owners")}
    captured=[]; now=dt.datetime.now(dt.timezone.utc)
    required={"schema","rule","observation","evidence_sha256","reuse_scope","counterexample","expires_at","owner_id"}
    for path in paths:
        value,source=_project_json(path,"knowledge candidate")
        if set(value)!=required or value.get("schema")!="agent-knowledge-candidate/v1": raise SystemExit("knowledge candidate fields are invalid")
        for key in ("rule","observation","reuse_scope","counterexample","owner_id"):
            if not isinstance(value.get(key),str) or not value[key].strip() or len(value[key].encode())>4096: raise SystemExit(f"knowledge candidate {key} is invalid")
        evidence=value.get("evidence_sha256")
        if not isinstance(evidence,list) or not evidence or evidence!=sorted(set(evidence)) or any(not isinstance(item,str) or re.fullmatch(r"[0-9a-f]{64}",item) is None for item in evidence) or not set(evidence)<=allowed_evidence:
            raise SystemExit("knowledge candidate evidence must be a sorted non-empty subset of accepted completion evidence")
        if value["owner_id"] not in owners: raise SystemExit("knowledge candidate must target an existing active registry owner/topic")
        try: expiry=dt.datetime.fromisoformat(value["expires_at"].replace("Z","+00:00"))
        except (ValueError,AttributeError): raise SystemExit("knowledge candidate expiry is invalid")
        if expiry.tzinfo is None or not now<expiry<=now+dt.timedelta(days=365): raise SystemExit("knowledge candidate expiry must be in the next 365 days")
        normalized={key:(value[key].strip() if isinstance(value[key],str) and key!="expires_at" else value[key]) for key in required}
        normalized["source_artifact"]=source; normalized["candidate_id"]=hashlib.sha256(strict_json_dumps(normalized,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        captured.append(normalized)
    ids=[item["candidate_id"] for item in captured]
    if len(ids)!=len(set(ids)): raise SystemExit("knowledge candidates must be supplied once")
    return sorted(captured,key=lambda item:item["candidate_id"])


def knowledge_pending_side_effect(task,candidates):
    if not candidates: return None
    if KNOWLEDGE_PENDING_PATH.exists() or KNOWLEDGE_PENDING_PATH.is_symlink():
        pending,_record=_project_json(".agent/state/knowledge-pending.json","knowledge pending registry",1048576)
        if pending.get("schema")!="agent-knowledge-pending/v2" or not isinstance(pending.get("candidates"),list) or not isinstance(pending.get("promotions"),list):
            raise SystemExit("knowledge pending registry requires explicit migration to v2")
    else: pending={"schema":"agent-knowledge-pending/v2","candidates":[],"promotions":[]}
    existing={item.get("candidate_id") for item in pending["candidates"] if isinstance(item,dict)}; recorded=dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    for candidate in candidates:
        if candidate["candidate_id"] in existing: raise SystemExit("knowledge candidate already exists")
        pending["candidates"].append({**candidate,"task_generation_id":task["task_generation_id"],"task_title":task["title"],"completion_binding_sha256":hashlib.sha256(strict_json_dumps(task["completion_binding"],sort_keys=True,separators=(",",":")).encode()).hexdigest(),"recorded_at":recorded,"status":"pending"})
    pending["candidates"]=sorted(pending["candidates"],key=lambda item:item["candidate_id"])
    return KNOWLEDGE_PENDING_PATH,(strict_json_dumps(pending,ensure_ascii=False,indent=2)+"\n").encode()


def decision_next_action(packet: Dict[str, object]) -> str:
    return (
        f"{packet['question']} If approved, advance to {packet['approval_destination']}. "
        f"{packet['scope_boundary']} {packet['reply']}"
    )


def print_decision_packet(packet: Dict[str, object]) -> None:
    artifact_record = packet["artifact"]
    assert isinstance(artifact_record, dict)
    print("DECISION REQUIRED")
    print(f"- Decide: {packet['question']}")
    print(f"- If approved: advance to {packet['approval_destination']}")
    print(f"- Boundary: {packet['scope_boundary']}")
    print(f"- Reply: {packet['reply']}")
    print(
        f"- Artifact: {artifact_record['path']} "
        f"sha256={artifact_record['sha256']}"
    )


def rollback_hot_limit() -> int:
    config = load(AGENT_DIR / "config.json")
    context = config.get("context", {})
    raw = context.get("max_rollback_entries") if isinstance(context, dict) else None
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 1:
        raise SystemExit("context.max_rollback_entries must be a positive rollback hot-state limit")
    return raw


def failure_hot_limit() -> int:
    config = load(AGENT_DIR / "config.json")
    context = config.get("context", {})
    raw = context.get("max_failure_entries") if isinstance(context, dict) else None
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 1:
        raise SystemExit("context.max_failure_entries must be a positive failure hot-state limit")
    return raw


def failure_archive_depth_limit() -> int:
    config = load(AGENT_DIR / "config.json")
    context = config.get("context", {})
    raw = context.get("max_failure_archive_depth") if isinstance(context, dict) else None
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 1:
        raise SystemExit("context.max_failure_archive_depth must be a positive cold-chain limit")
    return raw


def rollback_archive_depth_limit() -> int:
    config = load(AGENT_DIR / "config.json")
    workflow = config.get("workflow", {})
    raw = workflow.get("rollback_archive_depth_limit", 4) if isinstance(workflow, dict) else 4
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 1:
        raise SystemExit("workflow.rollback_archive_depth_limit must be a positive cold-chain limit")
    return raw


def rollback_archive_entries(task: Dict[str, object]) -> List[object]:
    """Return every archived rollback entry, oldest first, after chain validation."""
    head = task.get("rollback_archive")
    if head is None:
        return []
    errors = rollback_archive_errors(task)
    if errors:
        raise SystemExit("invalid rollback archive chain: " + "; ".join(errors))
    chain: List[List[object]] = []
    current: Optional[Dict[str, object]] = head if isinstance(head, dict) else None
    while current is not None:
        value = load(ROOT / str(current["path"]))
        entries = value.get("entries")
        if not isinstance(entries, list):
            raise SystemExit("rollback archive entries are invalid")
        chain.append(entries)
        previous = value.get("previous")
        current = previous if isinstance(previous, dict) else None
    return [entry for entries in reversed(chain) for entry in entries]


def _rollback_chain_depth(head: Dict[str, object]) -> int:
    # Node count of the archive chain; legacy heads carry no depth field, so
    # count by walking the content-addressed payloads (chain already validated).
    depth = 0; current: Optional[Dict[str, object]] = head
    while isinstance(current, dict):
        depth += 1
        digest = str(current.get("sha256", ""))
        path = ROOT / ".agent/state/evidence/rollback-archives" / f"{digest}.json"
        try:
            value = strict_json_loads(bounded_file_bytes(path,"workflow artifact"))
        except (OSError, json.JSONDecodeError):
            break
        previous = value.get("previous") if isinstance(value, dict) else None
        current = previous if isinstance(previous, dict) else None
    return depth


def compact_rollback_state(task: Dict[str, object]) -> List[Tuple[Path, bytes]]:
    ledger = task.get("rollback_ledger")
    if not isinstance(ledger, list):
        raise SystemExit("rollback_ledger must be a list")
    limit = rollback_hot_limit()
    if len(ledger) <= limit:
        return []
    archive_errors = rollback_archive_errors(task)
    if archive_errors:
        raise SystemExit("invalid rollback archive chain: " + "; ".join(archive_errors))
    previous = task.get("rollback_archive")
    if previous is not None and (
        not isinstance(previous, dict)
        or previous.get("schema") != "agent-rollback-archive-head/v1"
        or not isinstance(previous.get("total_entries"), int)
    ):
        raise SystemExit("rollback_archive head is invalid")
    evicted = ledger[:-limit]
    prior_depth = _rollback_chain_depth(previous) if isinstance(previous, dict) else 0
    snapshot = prior_depth >= rollback_archive_depth_limit() - 1
    entries = [*rollback_archive_entries(task), *evicted] if snapshot else evicted
    value = {
        "schema": "agent-rollback-archive/v1",
        "previous": None if snapshot else previous,
        "entries": entries,
    }
    data = strict_json_dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode() + b"\n"
    digest = hashlib.sha256(data).hexdigest()
    relative = f".agent/state/evidence/rollback-archives/{digest}.json"
    task["rollback_archive"] = {
        "schema": "agent-rollback-archive-head/v1",
        "path": relative,
        "sha256": digest,
        "bytes": len(data),
        "depth": 1 if snapshot else prior_depth + 1,
        "total_entries": len(evicted) + (int(previous["total_entries"]) if isinstance(previous, dict) else 0),
    }
    task["rollback_ledger"] = ledger[-limit:]
    return [(ROOT / relative, data)]


def failure_archive_counts(task: Dict[str, object]) -> Dict[str, int]:
    head = task.get("failure_archive")
    if head is None:
        return {}
    errors = failure_archive_errors(task)
    if errors:
        raise SystemExit("invalid failure archive chain: " + "; ".join(errors))
    counts: Dict[str, int] = {}
    current: Optional[Dict[str, object]] = head if isinstance(head, dict) else None
    while current is not None:
        value = load(ROOT / str(current["path"]))
        delta = value.get("counts")
        if not isinstance(delta, dict):
            raise SystemExit("failure archive counts are invalid")
        for key, count in delta.items():
            counts[str(key)] = counts.get(str(key), 0) + int(count)
        previous = value.get("previous")
        current = previous if isinstance(previous, dict) else None
    return counts


def compact_failure_state(task: Dict[str, object]) -> List[Tuple[Path, bytes]]:
    ledger = task.get("failure_ledger")
    if not isinstance(ledger, dict):
        raise SystemExit("failure_ledger must be an object")
    limit = failure_hot_limit()
    if len(ledger) <= limit:
        return []
    previous = task.get("failure_archive")
    counts = failure_archive_counts(task)
    evicted_keys = list(ledger)[:-limit]
    delta: Dict[str, int] = {}
    for signature in evicted_keys:
        delta[signature] = int(ledger[signature])
        counts[signature] = counts.get(signature, 0) + delta[signature]
    prior_depth = int(previous.get("depth", 0)) if isinstance(previous, dict) else 0
    snapshot = prior_depth >= failure_archive_depth_limit() - 1
    value = {
        "schema": "agent-failure-archive/v1",
        "previous": None if snapshot else previous,
        "counts": {
            key: (counts[key] if snapshot else delta[key])
            for key in sorted(counts if snapshot else delta)
        },
    }
    data = strict_json_dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode() + b"\n"
    digest = hashlib.sha256(data).hexdigest()
    relative = f".agent/state/evidence/failure-archives/{digest}.json"
    task["failure_archive"] = {
        "schema": "agent-failure-archive-head/v1",
        "path": relative,
        "sha256": digest,
        "bytes": len(data),
        "depth": 1 if snapshot else prior_depth + 1,
        "total_signatures": len(counts),
        "total_events": sum(counts.values()),
    }
    task["failure_ledger"] = {
        key: ledger[key] for key in list(ledger)[-limit:]
    }
    return [(ROOT / relative, data)]


def completion_checkpoint_valid(task: Dict[str, object]) -> bool:
    if not (AGENT_DIR/"state/CONTEXT.json").is_file(): return False
    context=load(AGENT_DIR/"state/CONTEXT.json"); checkpoint=context.get("checkpoint",{})
    authorization=checkpoint.get("transition_authorization",{}) if isinstance(checkpoint,dict) else {}
    completion_origin=(
        checkpoint.get("terminal_completion_origin",{})
        if isinstance(checkpoint,dict) else {}
    )
    completion_authorization=(
        completion_origin.get("transition_authorization",{})
        if (
            isinstance(completion_origin,dict)
            and set(completion_origin)=={"schema","kind","transition_authorization"}
            and completion_origin.get("schema")=="agent-terminal-completion-origin/v1"
            and completion_origin.get("kind")=="complete-task"
        ) else {}
    )
    binding=task.get("completion_binding",{})
    terminal=8 if task.get("mode")=="release" else 7
    artifact_set=[
        {"node":int(node),**record}
        for node,record in sorted(task.get("node_artifacts",{}).items(),key=lambda item:int(item[0]))
        if isinstance(record,dict)
    ] if isinstance(task.get("node_artifacts"),dict) else []
    ledger=load(AGENT_DIR/"state/agents.json") if (AGENT_DIR/"state/agents.json").is_file() else {}
    last_snapshot=ledger.get("last_platform_snapshot",{}) if isinstance(ledger,dict) else {}
    approval=task.get("gate_approvals",{}).get("acceptance",{}) if isinstance(task.get("gate_approvals"),dict) else {}
    historical_node8 = legacy_node8_archive_record(task.get("node_artifacts", {}).get("8"))
    historical_artifact_set = None
    if isinstance(historical_node8, dict):
        historical_artifact_set = [
            ({"node": 8, **historical_node8} if item.get("node") == 8 else item)
            for item in artifact_set
        ]
    artifact_binding_valid = (
        binding.get("accepted_artifact_set_sha256") == canonical_sha256(artifact_set)
        and binding.get("terminal_artifact_sha256") == task.get("node_artifacts", {}).get(str(terminal), {}).get("sha256")
    ) or (
        historical_artifact_set is not None
        and binding.get("accepted_artifact_set_sha256") == canonical_sha256(historical_artifact_set)
        and binding.get("terminal_artifact_sha256") == historical_node8.get("sha256")
    )
    legacy_binding_fields={
        "schema","accepted_artifact_set_sha256","terminal_artifact_sha256",
        "release_approval_sha256","completion_platform_snapshot_sha256",
        "completion_decision_source","completion_decision_receipt",
    }
    v2_binding_fields=legacy_binding_fields|{"completed_model","candidate_sha256"}
    binding_shape_valid=(
        (binding.get("schema")=="agent-completion-binding/v1" and set(binding)==legacy_binding_fields)
        or (
            binding.get("schema")=="agent-completion-binding/v2" and set(binding)==v2_binding_fields
            and binding.get("completed_model")==task.get("completed_model")
            and isinstance(binding.get("completed_model"),str) and bool(binding.get("completed_model"))
            and re.fullmatch(r"[0-9a-f]{64}",str(binding.get("candidate_sha256",""))) is not None
        )
    ) if isinstance(binding,dict) else False
    candidate_binding_valid=binding.get("schema")=="agent-completion-binding/v1"
    if isinstance(binding,dict) and binding.get("schema")=="agent-completion-binding/v2":
        try:
            import testrun as supervised_test
            candidate_binding_valid=supervised_test.candidate_fingerprint(load(CONFIG_PATH))==binding.get("candidate_sha256")
        except (SystemExit,OSError,UnicodeError,ValueError,TypeError,KeyError,ImportError): candidate_binding_valid=False
    binding_valid=(
        isinstance(binding,dict)
        and binding_shape_valid
        and candidate_binding_valid
        and artifact_binding_valid
        and binding.get("release_approval_sha256")==(
            canonical_sha256(approval) if task.get("mode")=="release" else None
        )
        and re.fullmatch(r"[0-9a-f]{64}",str(binding.get("completion_platform_snapshot_sha256",""))) is not None
        and (
            str(binding.get("completion_decision_source","")).startswith("user:")
            if task.get("mode")=="release" else binding.get("completion_decision_source")=="not_required"
        )
        and (
            (
                task.get("mode")=="release"
                and humandecision.reverify(
                    ROOT,load(AGENT_DIR/"config.json"),task,gate="completion",
                    artifact_sha256=str(binding.get("completion_platform_snapshot_sha256")),
                    source=str(binding.get("completion_decision_source")),
                    record=binding.get("completion_decision_receipt"),
                )
            )
            or (
                task.get("mode")!="release"
                and binding.get("completion_decision_receipt") is None
            )
        )
        and isinstance(last_snapshot,dict)
        and last_snapshot.get("sha256")==binding.get("completion_platform_snapshot_sha256")
    )
    ordinary_checkpoint = (
        any(
            isinstance(candidate, dict)
            and candidate.get("mutator") == "workflowctl"
            and candidate.get("operation") == "complete-task"
            for candidate in (authorization, completion_authorization)
        )
    )
    migration_checkpoint = (
        historical_artifact_set is not None
        and authorization is None
        and (
            (
                checkpoint.get("reason") == "migration-26-final-state-rebind"
                and context.get("compaction", {}).get("source") == "installer-verified-active-migration"
            )
            or (
                checkpoint.get("reason") == "migration-34-final-state-rebind"
                and context.get("compaction", {}).get("source") == "installer-verified-context-efficiency-migration"
            )
            or (
                checkpoint.get("reason") == "migration-39-budget-resume-rebind"
                and context.get("compaction", {}).get("source") == "installer-verified-budget-resume-migration"
            )
        )
    )
    migration_origin = (
        historical_artifact_set is not None
        and isinstance(completion_origin,dict)
        and set(completion_origin)=={"schema","kind","reason","source"}
        and completion_origin.get("schema")=="agent-terminal-completion-origin/v1"
        and completion_origin.get("kind")=="installer-migration"
        and (
            completion_origin.get("reason"),
            completion_origin.get("source"),
        ) in {
            (
                "migration-26-final-state-rebind",
                "installer-verified-active-migration",
            ),
            (
                "migration-34-final-state-rebind",
                "installer-verified-context-efficiency-migration",
            ),
            (
                "migration-39-budget-resume-rebind",
                "installer-verified-budget-resume-migration",
            ),
        }
    )
    return (
        context.get("task_invariant_sha256")==contexttx.contextctl.invariant_sha256(task)
        and (ordinary_checkpoint or migration_checkpoint or migration_origin)
        and binding_valid
    )


def release_acceptance_approval_valid(task: Dict[str, object], approval: object, record: object) -> bool:
    if not isinstance(approval,dict) or not isinstance(record,dict): return False
    path=(ROOT/str(record.get("path",""))).resolve()
    try: path.relative_to(ROOT)
    except ValueError: return False
    value=load(path) if path.is_file() and not path.is_symlink() else {}
    release_pair={"platform_transcript_verified_sha256","supervision_debt_waiver_sha256"}
    base={"source","artifact_sha256",*release_pair}
    version=task.get("decision_policy_version")
    if version!=humandecision.PROVIDER_POLICY_VERSION:
        return False
    expected_shapes={frozenset(base|{"decision_receipt"})}
    return (
        frozenset(approval) in expected_shapes
        and human_gate_approval_valid(task,"acceptance",approval,record)
        and approval.get("platform_transcript_verified_sha256")==value.get("platform_observation_set_sha256")
        and approval.get("supervision_debt_waiver_sha256")==value.get("supervision_debt_sha256")
        and re.fullmatch(r"[0-9a-f]{64}",str(approval.get("platform_transcript_verified_sha256",""))) is not None
        and re.fullmatch(r"[0-9a-f]{64}",str(approval.get("supervision_debt_waiver_sha256",""))) is not None
    )


def human_gate_approval_valid(task: Dict[str, object], gate: str, approval: object, record: object) -> bool:
    if not isinstance(approval,dict) or not isinstance(record,dict):
        return False
    source=str(approval.get("source","")); digest=str(record.get("sha256",""))
    if not source.startswith("user:") or approval.get("artifact_sha256")!=digest:
        return False
    if task.get("decision_policy_version") == humandecision.LOCAL_POLICY_VERSION:
        return False
    if task.get("decision_policy_version") != humandecision.PROVIDER_POLICY_VERSION:
        return False
    try:
        return humandecision.reverify(
            ROOT,load(AGENT_DIR/"config.json"),task,gate=gate,artifact_sha256=digest,
            source=source,record=approval.get("decision_receipt"),
        )
    except (SystemExit,OSError,ValueError,KeyError,TypeError,json.JSONDecodeError,subprocess.TimeoutExpired):
        return False


def legacy_node8_archive_record(record: object) -> Optional[Dict[str, object]]:
    """Resolve the old approved Node8 only from a non-reusable migration projection."""
    if not isinstance(record, dict):
        return None
    path = (ROOT / str(record.get("path", ""))).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError:
        return None
    if not path.is_file() or path.is_symlink():
        return None
    data = bounded_file_bytes(path,"workflow artifact")
    if record != {"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}:
        return None
    try:
        node8 = strict_json_loads(data)
        delivery = load(AGENT_DIR / "state/delivery.json")
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    legacy = delivery.get("legacy_production_chain")
    archived = legacy.get("node8_archive") if isinstance(legacy, dict) else None
    if (
        node8.get("schema") != "agent-node-delivery/v3"
        or node8.get("status") not in {"legacy_promoted", "legacy_rolled_back"}
        or node8.get("legacy_assurance") != "legacy"
        or node8.get("reusable_as_release_receipt") is not False
        or delivery.get("status") != node8.get("status")
        or not isinstance(legacy, dict) or legacy.get("assurance") != "legacy"
        or legacy.get("reusable_as_release_receipt") is not False
        or not isinstance(archived, dict)
    ):
        return None
    archived_path = (ROOT / str(archived.get("path", ""))).resolve()
    try:
        archived_path.relative_to(ROOT)
    except ValueError:
        return None
    if not archived_path.is_file() or archived_path.is_symlink():
        return None
    archived_bytes = bounded_file_bytes(archived_path,"archived workflow artifact")
    expected = {
        "path": str(archived_path.relative_to(ROOT)),
        "sha256": hashlib.sha256(archived_bytes).hexdigest(), "bytes": len(archived_bytes),
    }
    try:
        archived_value = strict_json_loads(archived_bytes)
    except (UnicodeError, json.JSONDecodeError):
        return None
    if (
        archived != expected
        or archived_value.get("schema") != "agent-node-delivery/v2"
        or archived_value.get("status") != legacy.get("previous_status")
        or archived_value.get("environment") != "production"
    ):
        return None
    return archived


def node_template(task: Dict[str, object], node: int) -> str:
    if node == 7:
        return "targeted-acceptance" if task.get("mode") == "fast" else "node-acceptance"
    return NODE_TEMPLATE.get(node, "")


def validate_provenance_bound_node_template(
    task: Dict[str, object], node: int, template_id: str,
    rendered: Dict[str, object], record: Dict[str, object],
) -> None:
    required={
        "schema","template_id","path","sha256","bytes",
        "requirement_contract_sha256","manifest_sha256","route_sha256",
        "source_path","source_sha256","source_bytes",
    }
    manifest_path=AGENT_DIR/"templates/manifest.json"
    manifest_data=bounded_file_bytes(manifest_path,"template manifest")
    manifest=strict_json_loads(manifest_data)
    templates=manifest.get("templates",[]) if isinstance(manifest,dict) else []
    entries=[item for item in templates if isinstance(item,dict) and item.get("id")==template_id]
    route=task.get("template_route")
    if (
        set(rendered)!=required
        or rendered.get("schema")!="agent-template-render/v1"
        or template_id not in task.get("selected_templates",[])
        or len(entries)!=1
        or entries[0].get("renderable") is not True
        or node not in entries[0].get("nodes",[])
        or task.get("mode") not in entries[0].get("modes",[])
        or rendered.get("path")!=entries[0].get("output")
        or rendered.get("path")!=record.get("path")
        or rendered.get("sha256")!=record.get("sha256")
        or rendered.get("bytes")!=record.get("bytes")
        or rendered.get("requirement_contract_sha256")!=task.get("requirement_contract_sha256")
        or rendered.get("manifest_sha256")!=hashlib.sha256(manifest_data).hexdigest()
        or not isinstance(route,dict)
        or rendered.get("route_sha256")!=route.get("sha256")
    ):
        raise SystemExit(f"node {node} requires current provenance-bound {template_id} render evidence")
    source=(AGENT_DIR/str(entries[0].get("path",""))).resolve()
    try: source.relative_to(AGENT_DIR)
    except ValueError: raise SystemExit(f"node {node} template source escapes .agent")
    expected_source=str(source.relative_to(ROOT))
    if (
        not source.is_file() or source.is_symlink()
        or rendered.get("source_path")!=expected_source
        or rendered.get("source_sha256")!=hashlib.sha256(bounded_file_bytes(source,"rendered template source")).hexdigest()
        or rendered.get("source_bytes")!=len(bounded_file_bytes(source,"rendered template source"))
    ):
        raise SystemExit(f"node {node} requires current provenance-bound {template_id} source evidence")


def validate_node_artifact(task: Dict[str, object], node: int, record: Dict[str, object]) -> None:
    expected=node_template(task,node)
    if expected:
        rendered=[item for item in task.get("rendered_artifacts",[]) if isinstance(item,dict) and item.get("template_id")==expected]
        if len(rendered)!=1 or rendered[0].get("path")!=record["path"] or rendered[0].get("sha256")!=record["sha256"]: raise SystemExit(f"node {node} requires the rendered {expected} artifact")
        if node in {6,7}:
            validate_provenance_bound_node_template(task,node,expected,rendered[0],record)
    elif node in {6,7,8} and not re.fullmatch(rf"\.agent/state/artifacts/{node:02d}-[A-Za-z0-9._-]+",str(record["path"])):
        raise SystemExit(f"node {node} artifact must use the canonical {node:02d}- prefix")
    if node==4 and task.get("mode")=="release": adapter(task)
    if node in {6,7,8}:
        try: capture=load_node_capture(record)
        except (OSError,SystemExit): capture=None
        raw_snapshot=capture.get("sealed_path") if isinstance(capture,dict) else record.get("path")
        try: descriptor,_relative=_open_relative_nofollow(str(raw_snapshot))
        except OSError as error: raise SystemExit("node artifact snapshot is missing or unsafe") from error
        try:
            snapshot_data,_identity=_read_bounded_descriptor(descriptor,"node artifact semantic snapshot")
            os.lseek(descriptor,0,os.SEEK_SET)
            if hashlib.sha256(snapshot_data).hexdigest()!=record.get("sha256") or len(snapshot_data)!=record.get("bytes"):
                raise SystemExit("node artifact semantic snapshot differs from its capture record")
            result=run_bounded_command([sys.executable,str(AGENT_DIR/"scripts/artifactctl.py"),"--node",str(node),"--path",str(record["path"]),"--snapshot-fd",str(descriptor)],cwd=ROOT,timeout=120,env=supervised_env(),pass_fds=(descriptor,))
        finally: os.close(descriptor)
        if result.returncode: raise SystemExit(result.stdout)


MANDATORY_SCOPE_RISK_MARKERS = {
    "security": ("segment:auth", "segment:crypto", "segment:security", "segment:secrets", "segment:iam", "suffix:.pem", "suffix:.key"),
    "migration": ("contains:migration",),
    "deploy": ("segment:deploy", "segment:deployment", "segment:ci", "segment:.circleci", "segment:.buildkite",
               "basename:.gitlab-ci.yml", "basename:jenkinsfile", "basename:azure-pipelines.yml", "basename:bitbucket-pipelines.yml",
               "contains:.github/workflows/", "contains:.gitlab/ci/"),
    "external_impact": ("segment:deploy", "segment:deployment", "segment:production", "segment:infra", "segment:ci",
                        "segment:.circleci", "segment:.buildkite", "basename:.gitlab-ci.yml", "basename:jenkinsfile",
                        "basename:azure-pipelines.yml", "basename:bitbucket-pipelines.yml",
                        "contains:.github/workflows/", "contains:.gitlab/ci/"),
}


def scope_risk_markers() -> Dict[str, Tuple[str, ...]]:
    merged = {name: list(markers) for name, markers in MANDATORY_SCOPE_RISK_MARKERS.items()}
    config = load(AGENT_DIR / "config.json")
    workflow = config.get("workflow", {})
    custom = workflow.get("actual_scope_risk_markers", {}) if isinstance(workflow, dict) else None
    if not isinstance(custom, dict):
        raise SystemExit("workflow.actual_scope_risk_markers must be an object")
    known = set(MANDATORY_SCOPE_RISK_MARKERS) | {"data_risk", "cross_system", "uncertain", "compliance"}
    for risk, markers in custom.items():
        if risk not in known or not isinstance(markers, list) or not markers or len(markers) > 64:
            raise SystemExit("workflow.actual_scope_risk_markers contains an invalid risk rule")
        for value in markers:
            if (not isinstance(value, str) or len(value) > 160
                    or not value.startswith(("segment:", "basename:", "prefix:", "suffix:", "contains:"))
                    or not value.split(":", 1)[1]):
                raise SystemExit("workflow.actual_scope_risk_markers contains an invalid path marker")
            merged.setdefault(risk, []).append(value.lower())
    return {name: tuple(dict.fromkeys(values)) for name, values in merged.items()}


def normalized_governed_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise SystemExit("node 6 change path is not canonical POSIX relative syntax")
    candidate = Path(value)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise SystemExit("node 6 change path is not canonical POSIX relative syntax")
    return "/".join(value.lower().split("/"))


def marker_matches(path: str, marker: str) -> bool:
    kind, needle = marker.split(":", 1); parts = path.split("/")
    if kind == "segment": return needle in parts
    if kind == "basename": return parts[-1] == needle
    if kind == "prefix": return path.startswith(needle)
    if kind == "suffix": return path.endswith(needle)
    return needle in path


def classify_actual_scope(paths: List[str]) -> List[str]:
    rules = scope_risk_markers(); normalized = [normalized_governed_path(path) for path in paths]
    return sorted(risk for risk, markers in rules.items()
                  if any(marker_matches(path, value) for path in normalized for value in markers))


def actual_scope_gate(task: Dict[str, object], record: Dict[str, object]) -> None:
    """Re-evaluate caller-declared scope from Node-6 governed change receipts."""
    value=load(ROOT/str(record["path"])); changes=value.get("changes")
    paths=sorted({str(item.get("path")) for item in changes if isinstance(item,dict) and item.get("path")}) if isinstance(changes,list) else []
    governed=[path for path in paths if not path.startswith(".agent/state/")]
    if not governed:
        raise SystemExit("node 6 requires at least one actual product/control-plane owned change")
    observed_risks=classify_actual_scope(governed)
    missing=[name for name in observed_risks if task.get("risk_flags",{}).get(name) is not True]
    observed_files=max(len(governed),int(task.get("files",0)))
    risks=dict(task.get("risk_flags",{})); risks.update({name:True for name in observed_risks})
    minimum=workflow_state.required_mode(str(task.get("environment")),observed_files,risks,str(task.get("task_type")),str(task.get("complexity")))
    if missing or workflow_state.MODE_RANK.get(str(task.get("mode")),-1) < workflow_state.MODE_RANK[minimum] or len(governed)>int(task.get("files",0)):
        flags=" ".join(f"--new-risk {name}" for name in missing)
        raise SystemExit(
            f"actual governed scope exceeds the declaration: files={len(governed)} minimum_mode={minimum}; "
            f"run `python3 .agent/scripts/agentctl.py escalate-mode --new-mode {minimum} --files {len(governed)} {flags} --reapprove --source user:<decision>` and reroute"
        )


def stage_side_effect(task: Dict[str, object]) -> Tuple[Path, bytes]:
    """Stage index bytes committed inside the TASK transition, never after it."""
    mode=str(task["mode"]); accepted=task.get("accepted_nodes",[]); last=max(accepted) if accepted else "none"
    gate="required" if mode=="release" else "not_applicable"
    reason="strict release gate is required for release mode" if mode=="release" else f"{mode} mode uses targeted acceptance and has no release live gate"
    return STAGE_PATH, f"""# AI Coding Stage Index

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
- Entries: {len(task.get('rollback_ledger',[]))}
## Canonical outputs
- `.agent/state/TASK.json`
""".encode("utf-8")


def update_stage(task: Dict[str, object]) -> None:
    """Compatibility shim for callers predating transactional stage commits.

    Workflow transitions commit the stage index through stage_side_effect; this
    direct write remains only for standalone tooling that renders the index
    outside a transition.
    """
    path, data = stage_side_effect(task)
    path.write_bytes(data)


def adapter(task: Dict[str, object]):
    config=load(AGENT_DIR/"config.json"); registry=config.get("acceptance_adapters",{})
    selected=[name for name in task.get("selected_templates",[]) if isinstance(registry,dict) and name in registry]
    if not selected:
        adaptive=task.get("template_route",{}).get("adaptive_project",{}) if isinstance(task.get("template_route"),dict) else {}
        digest=adaptive.get("blueprint_sha256") if isinstance(adaptive,dict) else None
        blueprint=AGENT_DIR/"project/BLUEPRINT.json"; runner=AGENT_DIR/"scripts/blueprintacceptance.py"
        if not digest or not blueprint.is_file() or blueprint.is_symlink() or not runner.is_file() or runner.is_symlink():
            raise SystemExit("release requires one legacy adapter or a confirmed blueprint acceptance contract")
        result=run_bounded_command([sys.executable,str(AGENT_DIR/"scripts/blueprintctl.py"),"--root",str(ROOT),"check","--require-confirmed","--expect-design-sha256",digest],cwd=ROOT,timeout=30,env=supervised_env())
        if result.returncode: raise SystemExit("confirmed blueprint acceptance contract is stale")
        raw=bounded_file_bytes(blueprint,"confirmed blueprint")
        return "adaptive-blueprint",{"implemented":True,"runner":str(runner.relative_to(ROOT)),"receipt_schema":"agent-blueprint-acceptance/v4"},{
            "template_id":"adaptive-blueprint","path":str(blueprint.relative_to(ROOT)),"sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw)}
    if len(selected)!=1: raise SystemExit("release selects multiple legacy acceptance adapters")
    adapter_id=selected[0]; entry=registry[adapter_id]
    if not isinstance(entry,dict) or entry.get("implemented") is not True: raise SystemExit(f"selected acceptance adapter is unavailable: {adapter_id}")
    runner=(ROOT/str(entry.get("runner",""))).resolve()
    try: runner.relative_to(ROOT)
    except ValueError: raise SystemExit("acceptance adapter runner escapes project")
    if not runner.is_file() or runner.is_symlink() or not entry.get("receipt_schema"): raise SystemExit("acceptance adapter runner/schema is unavailable")
    rendered=[item for item in task.get("rendered_artifacts",[]) if isinstance(item,dict) and item.get("template_id")==adapter_id]
    if len(rendered)!=1: raise SystemExit("selected acceptance adapter config is not rendered exactly once")
    config_record=artifact(str(rendered[0].get("path","")))
    if config_record.get("sha256")!=rendered[0].get("sha256"): raise SystemExit("selected acceptance adapter config drifted")
    return adapter_id,entry,rendered[0]


def replay_release_gate(task: Dict[str, object], acceptance_record: Dict[str, object]) -> None:
    adapter_id,entry,rendered=adapter(task); value=load(ROOT/str(acceptance_record["path"])); live=value.get("live_gate_receipt",{})
    if not isinstance(live,dict): raise SystemExit("release acceptance lacks a live gate receipt")
    live_path=(ROOT/str(live.get("path", ""))).resolve()
    try: live_path.relative_to(ROOT)
    except ValueError: raise SystemExit("release receipt escapes project")
    if not live_path.is_file() or live_path.is_symlink(): raise SystemExit("release receipt is missing")
    # Node completion is verification-only for every adapter.  The integrator
    # owns the sole `run`; this path must never start tests or execute cleanup.
    result=run_bounded_command(
        [sys.executable,str(ROOT/entry["runner"]),"verify","--runner",str(rendered["path"]),"--receipt",str(live_path.relative_to(ROOT))],
        cwd=ROOT,timeout=120,env=supervised_env(),
    )
    if result.returncode: raise SystemExit(f"registered release adapter receipt is stale or invalid for {adapter_id}:\n"+result.stdout)


def required_gate(task: Dict[str, object], node: int) -> str:
    if node==4 and task["mode"] in {"standard","release"}: return "solution"
    if node==7 and task["mode"] in {"standard","release"}: return "acceptance"
    if node==8 and task.get("environment")=="production": return "production"
    return ""


def effective_projection(task: Dict[str, object]) -> str:
    """Projection bound at task creation, falling back to the routed family."""
    raw = task.get("projection")
    if isinstance(raw, str) and raw.strip():
        return raw
    return task_projection(str(task.get("task_type")), str(task.get("mode")))


def lightweight_standard(task: Dict[str, object]) -> bool:
    return task.get("mode") == "standard" and effective_projection(task) == "lightweight"


def requirement_gate_error(task: Dict[str, object]) -> Optional[str]:
    """Single requirement-gate revalidation shared by mutations and route-resume."""
    if task.get("requirements_clarified") is not True:
        return "workflow progression is blocked until requirements are clarified and human-approved"
    source = task.get("requirement_source")
    approval = task.get("gate_approvals", {}).get("requirement") if isinstance(task.get("gate_approvals"), dict) else None
    contract_hash = str(task.get("requirement_contract_sha256", ""))
    contract = AGENT_DIR / "state" / "REQUIREMENT_CONTRACT.md"
    if (
        not str(source or "").startswith("user:")
        or task.get("decision_policy_version") != humandecision.PROVIDER_POLICY_VERSION
        or not human_gate_approval_valid(
            task,"requirement",approval,
            {"path":".agent/state/REQUIREMENT_CONTRACT.md","sha256":contract_hash,"bytes":len(bounded_file_bytes(contract,"requirement contract")) if contract.is_file() else 0},
        )
        or not re.fullmatch(r"[0-9a-f]{64}", contract_hash)
        or not contract.is_file()
        or hashlib.sha256(bounded_file_bytes(contract,"requirement contract")).hexdigest() != contract_hash
        or task.get("mode_status") != "confirmed"
    ):
        return "workflow progression lacks a valid user-bound requirement contract"
    return None


THREE_STRIKE_NEXT_ACTION = "same root cause failed three times; human decision required"


def three_strike_marker(task: Dict[str, object]) -> bool:
    """The three-strike marker is derived from invariant state, never a writable hint field."""
    return (
        task.get("status") == "waiting_human"
        and task.get("next_action") == THREE_STRIKE_NEXT_ACTION
    )


def failure_escalation_digest(task: Dict[str, object]) -> str:
    """Digest binding the escalation decision to the root-cause rollback entry."""
    ledger = task.get("rollback_ledger")
    if not isinstance(ledger, list) or not ledger or not isinstance(ledger[-1], dict):
        raise SystemExit("three-strike escalation lacks its root-cause rollback entry")
    return canonical_sha256(ledger[-1])


def failure_escalation_gate(task: Dict[str, object]) -> None:
    """Block pending escalation and revalidate a resolved decision until advance."""
    escalation = task.get("failure_escalation")
    if escalation is None and not three_strike_marker(task):
        return
    digest = failure_escalation_digest(task)
    if isinstance(escalation, dict):
        if (
            escalation.get("schema") != "agent-failure-escalation/v1"
            or escalation.get("artifact_sha256") != digest
            or escalation.get("state") not in {"pending", "resolved"}
        ):
            raise SystemExit("three-strike failure escalation state is invalid or stale")
        state = escalation.get("state")
    else:
        # Backward-compatible pending marker from pre-R4 state.
        state = "pending"
    approvals = task.get("gate_approvals", {})
    approval = approvals.get("failure-escalation") if isinstance(approvals, dict) else None
    source = str(approval.get("source", "")) if isinstance(approval, dict) else ""
    valid = isinstance(approval, dict) and humandecision.decision_approval_valid(
        ROOT, load(AGENT_DIR / "config.json"), task, gate="failure-escalation",
        artifact_sha256=digest, source=source, record=approval,
    )
    if state != "resolved" or not valid:
        raise SystemExit(
            "three-strike failure escalation requires a recorded human decision: "
            "run `python3 .agent/scripts/workflowctl.py resolve-failure --source user:<decision>`"
        )


def run_checked(command: List[str], label: str, timeout: int = 120) -> None:
    """Run a bounded mutator subprocess; failures and hangs become structured errors."""
    try:
        result=run_bounded_command(command,cwd=ROOT,timeout=timeout)
    except subprocess.TimeoutExpired:
        raise SystemExit(f"{label}: timed out after {timeout}s")
    if result.returncode:
        detail=result.stdout.strip().replace("\n"," | ")[:2000]
        raise SystemExit(label + (f": {detail}" if detail else ""))


def execution_gate(task: Dict[str, object], action: str) -> None:
    requirement_error = requirement_gate_error(task)
    if requirement_error is not None:
        raise SystemExit(requirement_error)
    current = task.get("current_node")
    accepted = task.get("accepted_nodes")
    expected = list(range(current + 1)) if isinstance(current, int) and task.get("status") == "ready_to_complete" else (list(range(current)) if isinstance(current, int) else None)
    if isinstance(current, int) and current >= 2 and accepted != expected:
        raise SystemExit("workflow sequence is discontinuous; accepted nodes must exactly precede current_node")
    try:
        result=run_bounded_command(
            [sys.executable,str(AGENT_DIR/"scripts"/"agentctl.py"),"budget-gate","--action",action],cwd=ROOT,timeout=120,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit(f"budget gate timed out before deciding {action}")
    if result.returncode:
        raise SystemExit(result.stdout.strip() or f"budget gate blocked {action}")


def command_submit(args: argparse.Namespace) -> int:
    task=load(TASK_PATH); expected=GATE_NODE[args.gate]
    if args.gate == "requirement":
        raise SystemExit("requirement approval is owned exclusively by agentctl approve-requirements")
    execution_gate(task, "request-decision")
    failure_escalation_gate(task)
    before=copy.deepcopy(task)
    if task.get("current_node")!=expected: raise SystemExit("gate is not active at the current node")
    record=artifact(args.artifact); validate_node_artifact(task,expected,record)
    approvals=task.setdefault("gate_approvals",{})
    if not isinstance(approvals,dict): raise SystemExit("gate_approvals must be an object")
    approvals.pop(args.gate,None)
    task.setdefault("pending_gate_artifacts",{})[args.gate]=record
    packet=decision_packet(task,args.gate,record)
    task.update({"status":"waiting_human","decision_packet":packet,"next_action":decision_next_action(packet)})
    contexttx.transition_task(before,task,mutator="workflowctl",operation="submit-gate",reason=f"gate-submitted-{args.gate}",summary=f"submitted exact {args.gate} artifact for human decision",side_effects=[stage_side_effect(task)])
    print_decision_packet(packet); return 0


def command_approve(args: argparse.Namespace) -> int:
    if not args.source.startswith("user:"): raise SystemExit("gate approval source must start with user:")
    task=load(TASK_PATH); expected=GATE_NODE[args.gate]
    if args.gate == "requirement":
        raise SystemExit("requirement approval is owned exclusively by agentctl approve-requirements")
    execution_gate(task, "request-decision")
    failure_escalation_gate(task)
    before=copy.deepcopy(task)
    if task.get("current_node") != expected and args.gate not in {"knowledge","production"}:
        raise SystemExit("gate is not active at the current node")
    pending=task.get("pending_gate_artifacts",{}).get(args.gate)
    if not isinstance(pending,dict) or pending.get("sha256")!=args.artifact_sha256: raise SystemExit("approval must bind the exact submitted artifact SHA-256")
    decision_policy_version = task.get("decision_policy_version")
    approval={"source":args.source,"artifact_sha256":args.artifact_sha256}
    if decision_policy_version == humandecision.PROVIDER_POLICY_VERSION:
        if not args.human_decision_receipt:
            raise SystemExit("gate approval requires a provider-signed human decision receipt")
        approval["decision_receipt"]=humandecision.verify(
            ROOT,load(AGENT_DIR/"config.json"),task,gate=args.gate,
            artifact_sha256=args.artifact_sha256,source=args.source,
            receipt=args.human_decision_receipt,
        )
    elif decision_policy_version == humandecision.LOCAL_POLICY_VERSION:
        raise SystemExit("local user-message evidence is advisory only and cannot authorize a workflow gate")
    else:
        raise SystemExit("workflow gate decision policy is unsupported")
    if args.gate=="acceptance" and task.get("mode")=="release":
        pending_path=(ROOT/str(pending.get("path",""))).resolve(); value=load(pending_path)
        observation_digest=value.get("platform_observation_set_sha256")
        debt_digest=value.get("supervision_debt_sha256")
        if (
            args.platform_transcript_verified_sha256!=observation_digest
            or args.supervision_debt_waiver_sha256!=debt_digest
            or re.fullmatch(r"[0-9a-f]{64}",str(observation_digest or "")) is None
            or re.fullmatch(r"[0-9a-f]{64}",str(debt_digest or "")) is None
        ):
            raise SystemExit("release acceptance requires explicit human transcript verification and exact supervision-debt waiver digests")
        approval.update({
            "platform_transcript_verified_sha256":args.platform_transcript_verified_sha256,
            "supervision_debt_waiver_sha256":args.supervision_debt_waiver_sha256,
        })
    elif args.platform_transcript_verified_sha256 or args.supervision_debt_waiver_sha256:
        raise SystemExit("platform/debt approval commitments apply only to release acceptance")
    approvals=task.setdefault("gate_approvals",{}); approvals[args.gate]=approval
    task.pop("decision_packet",None)
    task["status"]="in_progress"; task["next_action"]=f"advance approved node {expected}"
    contexttx.transition_task(before,task,mutator="workflowctl",operation="approve-gate",reason=f"gate-approved-{args.gate}",summary=f"recorded exact human {args.gate} decision",side_effects=[stage_side_effect(task)])
    print(f"GATE APPROVED: {args.gate}")
    return 0


def command_advance(args: argparse.Namespace) -> int:
    task=load(TASK_PATH); node=args.node
    execution_gate(task, "acceptance" if node==7 else ("delivery" if node==8 else "finish-node"))
    failure_escalation_gate(task)
    before=copy.deepcopy(task)
    projected=(
        task.get("current_node")==2 and node==6
        and (task.get("mode")=="fast" or effective_projection(task)=="lightweight")
    )
    if task.get("status") not in {"in_progress","waiting_human"} or (task.get("current_node")!=node and not projected):
        raise SystemExit("advance must match the active node")
    if node<2 or node>8: raise SystemExit("nodes 0-1 use bootstrap/requirement commands")
    record=node_artifact(args.artifact)
    if node==6: actual_scope_gate(task,record)
    validate_node_artifact(task,node,record)
    if node == 8:
        value = load(ROOT / str(record["path"]))
        if value.get("schema") == "agent-node-delivery/v3":
            raise SystemExit("historical Node8 is migration-only evidence and cannot advance a new delivery")
    gate=required_gate(task,node)
    approval=task.get("gate_approvals",{}).get(gate,{}) if gate else {}
    if gate and not human_gate_approval_valid(task,gate,approval,record):
        raise SystemExit(f"node {node} requires a human {gate} approval bound to this artifact")
    if node==7 and task.get("mode")=="release" and not release_acceptance_approval_valid(task,approval,record):
        raise SystemExit("release node 7 requires artifact-bound human transcript verification and supervision-debt waiver")
    if node==7 and task.get("mode")=="release": replay_release_gate(task,record)
    # Consume the three-strike decision on the first successful advance; the
    # marker itself clears because the transition rewrites next_action.
    task.pop("failure_escalation",None)
    if isinstance(task.get("gate_approvals"),dict): task["gate_approvals"].pop("failure-escalation",None)
    artifacts=task.setdefault("node_artifacts",{}); artifacts[str(node)]=record
    task["node_artifact_capture_version"]=1
    task["node_artifact_capture_nodes"]=sorted(set([*task.get("node_artifact_capture_nodes",[]),node]))
    additions=[2,3,4,5,6] if projected else [node]
    accepted=sorted(set([*task.setdefault("accepted_nodes",[]),*additions])); task["accepted_nodes"]=accepted
    next_node=node+1
    if task["mode"] in {"fast","standard"} and node==7:
        task.update({"current_node":7,"status":"ready_to_complete","phase":"retrospective","next_action":"render retrospective and complete task"})
    elif node==8:
        task.update({"current_node":8,"status":"ready_to_complete","phase":"retrospective","next_action":"render retrospective and complete task"})
    else:
        task.update({"current_node":next_node,"status":"in_progress","phase":PHASES[next_node],"next_action":f"complete node {next_node}: {PHASES[next_node]}"})
    contexttx.transition_task(before,task,mutator="workflowctl",operation="advance",reason=f"node-{node}-accepted",summary=f"accepted node {node} with bound evidence",side_effects=[stage_side_effect(task)])
    print(f"NODE ACCEPTED: {node} artifact={record['path']}")
    return 0


def command_return(args: argparse.Namespace) -> int:
    task=load(TASK_PATH); target=args.to
    execution_gate(task, "return-node")
    failure_escalation_gate(task)
    before=copy.deepcopy(task)
    if target<0 or target>8: raise SystemExit("return node must be 0-8")
    if target in {0,1}:
        raise SystemExit(
            "node 0/1 rollback requires `agentctl.py reopen-clarification --source user:<decision> "
            "--reason <reason>` so the old contract and approvals are archived atomically"
        )
    if task.get("current_node")!=args.from_node: raise SystemExit("from-node must equal the active current node")
    if not isinstance(task.get("current_node"),int) or target>=int(task["current_node"]): raise SystemExit("return-node must move backward to an earlier root-cause node")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}",args.issue_id): raise SystemExit("issue-id must be a stable identifier")
    signature=hashlib.sha256(f"{args.issue_id}|{args.cause_category}".encode()).hexdigest()
    failures=task.setdefault("failure_ledger",{})
    if not isinstance(failures,dict): raise SystemExit("failure_ledger must be an object")
    archived_count=failure_archive_counts(task).get(signature,0)
    hot_count=int(failures.pop(signature,0))+1
    failures[signature]=hot_count
    count=archived_count+hot_count
    if count>=3:
        task.update({
            "current_node":target,"status":"waiting_human","phase":PHASES[target],
            "next_action":THREE_STRIKE_NEXT_ACTION,
        })
    else:
        if count==2 and int(task["current_node"])>4:
            # A standard lightweight route has no node-4 solution artifact.
            # Return to node 2 so its routed node-6 implementation receipt can
            # re-accept the projected 2-6 chain instead of creating a dead end.
            target=2 if lightweight_standard(task) else 4
        task.update({"current_node":target,"status":"in_progress","phase":PHASES[target],"next_action":f"repair root cause at node {target}"})
    task.setdefault("rollback_ledger",[]).append({"from":args.from_node,"to":target,"issue_id":args.issue_id,"cause_category":args.cause_category,"subtask":args.subtask,"root_cause":args.root_cause,"change":args.change,"signature":signature,"count":count})
    if count >= 3:
        task["failure_escalation"] = {
            "schema": "agent-failure-escalation/v1",
            "state": "pending",
            "artifact_sha256": failure_escalation_digest(task),
        }
    task["accepted_nodes"]=[node for node in task.get("accepted_nodes",[]) if node<target]
    task["node_artifacts"]={key:value for key,value in task.get("node_artifacts",{}).items() if int(key)<target}
    side_effects=[*compact_rollback_state(task),*compact_failure_state(task),stage_side_effect(task)]
    contexttx.transition_task(
        before,task,mutator="workflowctl",operation="return-node",
        reason="root-cause-return",summary=f"returned to root-cause node {target}",
        side_effects=side_effects,
        # Archive heads are already integrity-bound inside the TASK invariant;
        # repeating their paths in the capsule can make fast-mode compaction
        # exceed the very budget it is meant to recover.
        evidence=[],
    )
    print(f"RETURNED TO NODE {target}: failure_count={count}")
    return 0


def command_resolve_failure(args: argparse.Namespace) -> int:
    if not args.source.startswith("user:"): raise SystemExit("failure decision source must start with user:")
    task=load(TASK_PATH)
    execution_gate(task, "request-decision")
    escalation = task.get("failure_escalation")
    if not three_strike_marker(task) and not (
        isinstance(escalation, dict) and escalation.get("state") == "pending"
    ):
        raise SystemExit("no three-strike failure escalation is pending")
    digest=failure_escalation_digest(task)
    approval=humandecision.record_decision_approval(
        ROOT,load(AGENT_DIR/"config.json"),task,gate="failure-escalation",
        artifact_sha256=digest,source=args.source,receipt=args.human_decision_receipt,
    )
    before=copy.deepcopy(task)
    approvals=task.setdefault("gate_approvals",{})
    if not isinstance(approvals,dict): raise SystemExit("gate_approvals must be an object")
    approvals["failure-escalation"]=approval
    task["failure_escalation"] = {
        "schema": "agent-failure-escalation/v1",
        "state": "resolved",
        "artifact_sha256": digest,
    }
    task["status"] = "in_progress"
    task["next_action"] = f"repair root cause at node {task.get('current_node')} and advance the repaired artifact"
    contexttx.transition_task(before,task,mutator="workflowctl",operation="resolve-failure",reason="failure-escalation-decision",summary="recorded human three-strike failure decision",side_effects=[stage_side_effect(task)])
    print("FAILURE ESCALATION RESOLVED: advance the repaired node")
    return 0


def command_compact_state() -> int:
    task=load(TASK_PATH); before=copy.deepcopy(task)
    side_effects=[*compact_rollback_state(task),*compact_failure_state(task)]
    if not side_effects:
        print(
            f"STATE ALREADY COMPACT: rollback_entries={len(task.get('rollback_ledger',[]))} "
            f"failure_entries={len(task.get('failure_ledger',{}))}"
        )
        return 0
    side_effects.append(stage_side_effect(task))
    contexttx.transition_task(
        before,task,mutator="workflowctl",operation="compact-state",
        reason="compact-workflow-hot-state",summary="archived superseded rollback and failure entries",
        side_effects=side_effects,
        evidence=[],
    )
    print(
        f"STATE COMPACTED: rollback_entries={len(task['rollback_ledger'])} "
        f"failure_entries={len(task['failure_ledger'])} "
        f"rollback_archive={(task.get('rollback_archive') or {}).get('sha256','none')} "
        f"failure_archive={(task.get('failure_archive') or {}).get('sha256','none')}"
    )
    return 0


def command_complete(args: argparse.Namespace) -> int:
    # Snapshot exact authority before validation. Nested validators legitimately
    # acquire the Agent ledger lock, so completion takes the model locks only
    # for its final compare-and-commit section.
    task_data=bounded_file_bytes(TASK_PATH,"workflow task"); config_data_before=bounded_file_bytes(CONFIG_PATH,"workflow config"); agents_data_before=bounded_file_bytes(AGENTS_PATH,"agent ledger")
    task=strict_json_loads(task_data); config=strict_json_loads(config_data_before); agents=strict_json_loads(agents_data_before)
    if not all(isinstance(value,dict) for value in (task,config,agents)):
        raise SystemExit("completion authority files must contain JSON objects")
    terminal=8 if task["mode"]=="release" else 7
    active_model=task.get("selected_model")
    if (not isinstance(active_model,str) or not active_model or config.get("agent_control",{}).get("default_model")!=active_model
            or agents.get("default_model")!=active_model):
        raise SystemExit("task completion requires exact active task/config/ledger model binding")
    execution_gate(task, "complete")
    before=copy.deepcopy(task)
    required_nodes=list(range(0,terminal+1))
    if task.get("accepted_nodes")!=required_nodes or task.get("status")!="ready_to_complete":
        raise SystemExit(f"task requires accepted node {terminal} before completion")
    full_errors=workflow_validation_errors(task,require_full=True)
    if full_errors:
        raise SystemExit("task completion full-chain validation failed:\n- " + "\n- ".join(full_errors))
    context = load(AGENT_DIR / "state/CONTEXT.json")
    open_risks = context.get("open_risks", [])
    if not isinstance(open_risks, list) or any(
        not isinstance(item, str) or not item.strip() for item in open_risks
    ):
        raise SystemExit("task completion requires a valid bounded open-risk list")
    requested_resolutions = list(dict.fromkeys(args.resolve_risk or []))
    unknown_resolutions = sorted(set(requested_resolutions) - set(open_risks))
    if unknown_resolutions:
        raise SystemExit(f"task completion cannot resolve unknown context risks: {unknown_resolutions}")
    remaining_risks = [item for item in open_risks if item not in requested_resolutions]
    if remaining_risks:
        flags = " ".join(f"--resolve-risk {strict_json_dumps(item, ensure_ascii=False)}" for item in remaining_risks)
        raise SystemExit(
            "task completion is blocked by unresolved context risks; explicitly resolve each verified risk: "
            + flags
        )
    completion_snapshot=artifact(args.platform_snapshot)
    acceptance_approval=task.get("gate_approvals",{}).get("acceptance",{}) if isinstance(task.get("gate_approvals"),dict) else {}
    completion_decision_receipt=None
    completion_decision_source="not_required"
    if task.get("mode")=="release":
        if (
            not str(args.completion_source or "").startswith("user:")
            or args.completion_platform_transcript_verified_sha256!=completion_snapshot["sha256"]
        ):
            raise SystemExit("release completion requires a human decision bound to the exact final empty platform snapshot SHA-256")
        completion_decision_source=args.completion_source
        if not args.human_decision_receipt:
            raise SystemExit("release completion requires a provider-signed human decision receipt")
        completion_decision_receipt=humandecision.verify(
            ROOT,load(AGENT_DIR/"config.json"),task,gate="completion",
            artifact_sha256=completion_snapshot["sha256"],source=args.completion_source,
            receipt=args.human_decision_receipt,
        )
    elif args.completion_source or args.completion_platform_transcript_verified_sha256 or args.human_decision_receipt:
        raise SystemExit("completion human snapshot commitments apply only to release mode")
    retro=artifact(args.retrospective); retro_text=bounded_file_text(ROOT/retro["path"],"retrospective artifact")
    retro_fields=("Result and success criteria","Wall / waiting time","Measured or estimated Tokens","References / Agent cumulative and peak","Rework / user corrections / tests / defects / blocks","What worked / failed","Knowledge candidates","Promotion decision and source")
    if any(len(re.findall(rf"^- {re.escape(field)}:\s*(.+?)\s*$",retro_text,re.MULTILINE))!=1 for field in retro_fields) or "{{" in retro_text:
        raise SystemExit("retrospective is incomplete or contains unresolved placeholders")
    ledger_command=[sys.executable,str(AGENT_DIR/"skills/manage-agent-team/scripts/agentledger.py"),"validate","--require-empty","--platform-snapshot",args.platform_snapshot]
    # Validate the workflow and ledger before the destructive cleanup so a
    # failing check never has its evidence removed first. Cleanup then runs
    # before the residual assertion, so a dirty-but-cleanable runtime is
    # cleaned instead of blocking completion; every call is bounded.
    run_checked(
        [sys.executable,str(AGENT_DIR/"scripts/agentctl.py"),"validate"],
        "task completion requires a fully valid workflow before consuming the final platform snapshot",
    )
    run_checked(ledger_command,"task completion requires an orchestrator-observed empty Agent ledger")
    # `agentledger validate --require-empty --platform-snapshot` commits the
    # exact provider-observed empty-snapshot receipt. Treat only that Agent
    # ledger postimage as expected; TASK/config authority must stay byte exact.
    if bounded_file_bytes(TASK_PATH,"workflow task")!=task_data or bounded_file_bytes(CONFIG_PATH,"workflow config")!=config_data_before:
        raise SystemExit("completion authority changed while binding the empty platform snapshot")
    agents_data_before=bounded_file_bytes(AGENTS_PATH,"agent ledger"); agents=strict_json_loads(agents_data_before)
    agents_chain_exists_before,agents_chain_data_before=agents_chain_snapshot()
    if not isinstance(agents,dict) or agents.get("default_model")!=active_model:
        raise SystemExit("empty platform verification broke active Agent model authority")
    run_checked([sys.executable,str(AGENT_DIR/"scripts/agentctl.py"),"cleanup"],"runtime cleanup failed")
    run_checked(
        [sys.executable,str(AGENT_DIR/"scripts/agentctl.py"),"assert-clean"],
        "task completion leaves runtime residuals after cleanup",
    )
    task["retrospective"]=retro
    task["completed_model"]=active_model; task["selected_model"]=None
    artifact_set=[
        {"node":int(node),**record}
        for node,record in sorted(task.get("node_artifacts",{}).items(),key=lambda item:int(item[0]))
        if isinstance(record,dict)
    ]
    allowed_knowledge_evidence={retro["sha256"],completion_snapshot["sha256"],*(record["sha256"] for record in artifact_set)}
    knowledge_candidates=capture_knowledge_candidates(args.knowledge_candidates or [],allowed_knowledge_evidence)
    task["knowledge_candidates"]=knowledge_candidates
    import testrun as supervised_test
    task["completion_binding"]={
        "schema":"agent-completion-binding/v2",
        "accepted_artifact_set_sha256":canonical_sha256(artifact_set),
        "completed_model":active_model,
        "candidate_sha256":supervised_test.candidate_fingerprint(config),
        "terminal_artifact_sha256":task.get("node_artifacts",{}).get(str(terminal),{}).get("sha256"),
        "release_approval_sha256":canonical_sha256(acceptance_approval) if task.get("mode")=="release" else None,
        "completion_platform_snapshot_sha256":completion_snapshot["sha256"],
        "completion_decision_source":completion_decision_source,
        "completion_decision_receipt":completion_decision_receipt,
    }
    task.update({"current_node":"idle","status":"accepted","phase":"idle","next_action":"start the next requirement in clarification"})
    knowledge_side_effect=knowledge_pending_side_effect(task,knowledge_candidates)
    # Match agentctl locked_model_authority ordering (project-init, Agent
    # ledger, then TASK/context inside contexttx) and reject any exact-byte
    # drift observed while the slow external validations ran.
    try:
        project_handle=boundedio.open_private_lock(PROJECT_INIT_LOCK_PATH,label="project initialization lock")
        agents_handle=boundedio.open_private_lock(AGENTS_LOCK_PATH,label="agent ledger lock")
    except RuntimeError as error: raise SystemExit(str(error)) from error
    with project_handle as project_lock:
        fcntl.flock(project_lock.fileno(),fcntl.LOCK_EX)
        with agents_handle as agents_lock:
            fcntl.flock(agents_lock.fileno(),fcntl.LOCK_EX)
            if (bounded_file_bytes(TASK_PATH,"workflow task")!=task_data or bounded_file_bytes(CONFIG_PATH,"workflow config")!=config_data_before
                    or bounded_file_bytes(AGENTS_PATH,"agent ledger")!=agents_data_before
                    or agents_chain_snapshot()!=(agents_chain_exists_before,agents_chain_data_before)):
                raise SystemExit("completion authority changed during validation; retry against the new exact state")
            idle_config=copy.deepcopy(config); idle_config.setdefault("agent_control",{})["default_model"]=None
            idle_agents=copy.deepcopy(agents); idle_agents["default_model"]=None; idle_agents["updated_at"]=dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
            agents_data=agents_chain_advance(idle_agents); config_data=(strict_json_dumps(idle_config,ensure_ascii=False,indent=2)+"\n").encode()
            agents_chain_data=agents_chain_journal_data(idle_agents,agents_data,agents_chain_data_before)
            contexttx.transition_task(
                before,task,mutator="workflowctl",operation="complete-task",
                reason="task-completed",summary="completed accepted task and bounded retrospective",
                side_effects=[stage_side_effect(task),(CONFIG_PATH,config_data),(AGENTS_PATH,agents_data),(AGENTS_CHAIN_PATH,agents_chain_data),*([knowledge_side_effect] if knowledge_side_effect else [])],resolve_risks=requested_resolutions,
            )
    print("TASK COMPLETED")
    return 0


def state_machine_errors(task: Dict[str, object]) -> List[str]:
    errors:List[str]=[]; status=task.get("status"); current=task.get("current_node")
    mode=task.get("mode"); terminal=8 if mode=="release" else 7
    accepted=task.get("accepted_nodes",[])
    decision_policy_version = task.get("decision_policy_version")
    if decision_policy_version != humandecision.PROVIDER_POLICY_VERSION:
        errors.append("workflow decision policy must be provider-verifiable policy 1; legacy local records are advisory only")
    if status=="idle":
        if current!="idle" or accepted!=[]: errors.append("idle workflow must have current_node=idle and no accepted nodes")
    elif status=="accepted":
        if current!="idle" or task.get("phase")!="idle" or accepted!=list(range(terminal+1)):
            errors.append("accepted workflow must be an explicitly completed terminal-node prefix")
        elif not completion_checkpoint_valid(task):
            errors.append("accepted workflow lacks its complete-task checkpoint")
    elif status=="ready_to_complete":
        if current!=terminal or accepted!=list(range(terminal+1)):
            errors.append("ready_to_complete must retain the fully accepted mode terminal node")
    elif status in {"in_progress","waiting_human"}:
        if not isinstance(current,int) or current<0 or current>terminal:
            errors.append("active workflow current_node is invalid")
        elif accepted!=list(range(current)):
            errors.append("active workflow accepted nodes must exactly precede current_node")
    else:
        errors.append("workflow status is invalid")
    escalation = task.get("failure_escalation")
    if escalation is not None:
        try:
            escalation_valid = (
                isinstance(escalation, dict)
                and escalation.get("schema") == "agent-failure-escalation/v1"
                and escalation.get("state") in {"pending", "resolved"}
                and escalation.get("artifact_sha256") == failure_escalation_digest(task)
            )
        except SystemExit:
            escalation_valid = False
        if not escalation_valid:
            errors.append("failure escalation record is invalid or no longer binds its rollback entry")
        elif escalation.get("state") == "pending" and not three_strike_marker(task):
            errors.append("pending failure escalation must remain at its waiting-human marker")
        elif escalation.get("state") == "resolved" and status != "in_progress":
            errors.append("resolved failure escalation must resume the repaired node in progress")
    return errors


def task_archive_errors(task: Dict[str, object]) -> List[str]:
    current = task.get("task_archive")
    if current is None:
        return []
    head_fields = {"schema", "path", "sha256", "bytes", "total_archives"}
    payload_fields = {
        "schema", "archived_at", "source", "reason", "assurance",
        "decision_receipt", "task", "requirement_contract", "previous",
    }
    # agentctl build_task_archive writes v2 payloads: the v1 identity fields
    # plus the generation-bound Skill activation, embedded delivery record, and
    # structured referenced-evidence digest list (see evidencectl.py).
    payload_v2_fields = payload_fields | {"skill_activation", "delivery", "referenced_evidence"}
    visited: set[str] = set()
    expected_total = current.get("total_archives") if isinstance(current, dict) else None
    while current is not None:
        if not isinstance(current, dict) or set(current) != head_fields:
            return ["task_archive head has invalid fields"]
        digest = str(current.get("sha256", ""))
        relative = f".agent/state/evidence/task-archives/{digest}.json"
        if (
            current.get("schema") != "agent-task-archive-head/v1"
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or digest in visited or current.get("path") != relative
            or not isinstance(current.get("bytes"), int) or current["bytes"] < 1
            or not isinstance(current.get("total_archives"), int)
            or current["total_archives"] < 1
        ):
            return ["task_archive head is not content-addressed"]
        if expected_total != current["total_archives"]:
            return ["task_archive chain count is discontinuous"]
        visited.add(digest)
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            return ["task_archive content is missing"]
        data = bounded_file_bytes(path,"workflow artifact")
        if len(data) != current["bytes"] or hashlib.sha256(data).hexdigest() != digest:
            return ["task_archive content drifted"]
        try:
            value = strict_json_loads(data)
        except json.JSONDecodeError:
            return ["task_archive content is not valid JSON"]
        if (
            not isinstance(value, dict)
            or value.get("schema") not in {"agent-task-archive/v1", "agent-task-archive/v2"}
            or set(value) != (payload_v2_fields if value.get("schema") == "agent-task-archive/v2" else payload_fields)
        ):
            return ["task_archive payload schema is invalid"]
        archived_task = value.get("task")
        contract = value.get("requirement_contract")
        if (
            not isinstance(archived_task, dict)
            or set(archived_task) != {"sha256", "bytes", "utf8"}
            or not isinstance(archived_task.get("utf8"), str)
            or len(archived_task["utf8"].encode()) != archived_task.get("bytes")
            or hashlib.sha256(archived_task["utf8"].encode()).hexdigest() != archived_task.get("sha256")
            or not isinstance(value.get("reason"), str) or not value["reason"].strip()
        ):
            return ["task_archive task bytes or reason are invalid"]
        try:
            archived_task_value = strict_json_loads(archived_task["utf8"])
            archived_at = dt.datetime.fromisoformat(str(value.get("archived_at")))
            if archived_at.tzinfo is None:
                raise ValueError("timezone required")
        except (json.JSONDecodeError, ValueError, TypeError):
            return ["task_archive task JSON or timestamp is invalid"]
        if not isinstance(archived_task_value, dict):
            return ["task_archive task JSON must be an object"]
        if archived_task_value.get("task_archive") != value.get("previous"):
            return ["task_archive chain does not match the archived task"]
        if contract is not None and (
            not isinstance(contract, dict)
            or set(contract) != {"sha256", "bytes", "utf8"}
            or not isinstance(contract.get("utf8"), str)
            or len(contract["utf8"].encode()) != contract.get("bytes")
            or hashlib.sha256(contract["utf8"].encode()).hexdigest() != contract.get("sha256")
        ):
            return ["task_archive requirement contract is invalid"]
        if value.get("schema") == "agent-task-archive/v2":
            activation=value.get("skill_activation")
            if activation is None:
                if archived_task_value.get("skill_activation") is not None:
                    return ["legacy task_archive cannot discard declared Skill activation"]
            else:
                if (not isinstance(activation,dict) or set(activation)!={"sha256","bytes","utf8"}
                        or not isinstance(activation.get("utf8"),str) or len(activation["utf8"].encode())!=activation.get("bytes")
                        or hashlib.sha256(activation["utf8"].encode()).hexdigest()!=activation.get("sha256")):
                    return ["task_archive Skill activation record is invalid"]
                try: activation_value=strict_json_loads(activation["utf8"])
                except json.JSONDecodeError: return ["task_archive Skill activation JSON is invalid"]
                schema=activation_value.get("schema") if isinstance(activation_value,dict) else None
                v2=schema=="agent-task-skill-activation/v2"
                activation_fields=({"schema","task_generation_id","blueprint_sha256","lock_sha256","skills","builtins","activation_sha256"}
                                   if v2 else {"schema","task_generation_id","blueprint_sha256","lock_sha256","skills","activation_sha256"})
                pointer_fields=({"schema","path","sha256","bytes","activation_sha256","lock_sha256","skill_ids","builtin_skill_ids"}
                                if v2 else {"schema","path","sha256","bytes","activation_sha256","lock_sha256","skill_ids"})
                pointer=archived_task_value.get("skill_activation"); skills=activation_value.get("skills") if isinstance(activation_value,dict) else None
                unsigned={key:item for key,item in activation_value.items() if key!="activation_sha256"} if isinstance(activation_value,dict) else {}
                activation_sha=hashlib.sha256(json.dumps(unsigned,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
                ids=[item.get("id") for item in skills] if isinstance(skills,list) and all(isinstance(item,dict) for item in skills) else None
                if (schema not in {"agent-task-skill-activation/v1","agent-task-skill-activation/v2"}
                        or not isinstance(activation_value,dict) or set(activation_value)!=activation_fields
                        or activation_value.get("activation_sha256")!=activation_sha
                        or activation_value.get("task_generation_id")!=archived_task_value.get("task_generation_id")
                        or not isinstance(pointer,dict) or set(pointer)!=pointer_fields
                        or pointer.get("schema")!=schema or pointer.get("path")!=".agent/state/SKILL_ACTIVATION.json"
                        or pointer.get("sha256")!=activation.get("sha256") or pointer.get("bytes")!=activation.get("bytes")
                        or pointer.get("activation_sha256")!=activation_sha or pointer.get("lock_sha256")!=activation_value.get("lock_sha256")
                        or ids is None or ids!=sorted(set(ids)) or pointer.get("skill_ids")!=ids):
                    return ["task_archive Skill activation binding is invalid"]
                if v2:
                    builtins=activation_value.get("builtins"); builtin_ids=[]
                    if not isinstance(builtins,list): return ["task_archive built-in Skill activation set is invalid"]
                    for builtin in builtins:
                        if not isinstance(builtin,dict) or set(builtin)!={"id","bundle_sha256","files"} or not isinstance(builtin.get("files"),list): return ["task_archive built-in Skill entry is invalid"]
                        records=[]
                        for document in builtin["files"]:
                            if not isinstance(document,dict) or set(document)!={"path","sha256","bytes","mode","content_base64"}: return ["task_archive built-in Skill file is invalid"]
                            try: data=base64.b64decode(document["content_base64"],validate=True)
                            except (ValueError,TypeError): return ["task_archive built-in Skill content is invalid"]
                            if len(data)!=document.get("bytes") or hashlib.sha256(data).hexdigest()!=document.get("sha256"): return ["task_archive built-in Skill bytes are invalid"]
                            records.append({key:document[key] for key in ("path","sha256","bytes","mode")})
                        if hashlib.sha256(json.dumps(records,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()!=builtin.get("bundle_sha256"): return ["task_archive built-in Skill bundle is invalid"]
                        builtin_ids.append(builtin.get("id"))
                    if builtin_ids!=sorted(set(builtin_ids)) or pointer.get("builtin_skill_ids")!=builtin_ids: return ["task_archive built-in Skill identifiers drifted"]
                for item in skills:
                    documents=item.get("documents")
                    if (set(item)!={"id","status","bundle_sha256","matched_capabilities","documents"}
                            or item.get("status") not in {"active","deprecated"} or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}",str(item.get("id",""))) is None
                            or re.fullmatch(r"[0-9a-f]{64}",str(item.get("bundle_sha256",""))) is None or not isinstance(item.get("matched_capabilities"),list)
                            or not isinstance(documents,list) or [doc.get("path") if isinstance(doc,dict) else None for doc in documents]!=["SKILL.md","LICENSE.txt"]):
                        return ["task_archive Skill activation entry is invalid"]
                    for document in documents:
                        content=document.get("content") if isinstance(document,dict) else None; data=content.encode() if isinstance(content,str) else b""
                        if (not isinstance(document,dict) or set(document)!={"path","sha256","bytes","content"} or not isinstance(content,str)
                                or len(data)!=document.get("bytes") or hashlib.sha256(data).hexdigest()!=document.get("sha256")):
                            return ["task_archive Skill activation document is invalid"]
            delivery = value.get("delivery")
            if delivery is not None and (
                not isinstance(delivery, dict)
                or set(delivery) != {"sha256", "bytes", "utf8"}
                or not isinstance(delivery.get("utf8"), str)
                or len(delivery["utf8"].encode()) != delivery.get("bytes")
                or hashlib.sha256(delivery["utf8"].encode()).hexdigest() != delivery.get("sha256")
            ):
                return ["task_archive delivery record is invalid"]
            referenced = value.get("referenced_evidence")
            if (
                not isinstance(referenced, list)
                or any(not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None for item in referenced)
            ):
                return ["task_archive referenced evidence digests are invalid"]
        assurance = value.get("assurance")
        source = str(value.get("source", ""))
        if assurance == "explicit-user-message;local-cancellation;not-provider-verified":
            if (
                not source.startswith("user:")
                or value.get("decision_receipt") is not None
                or archived_task_value.get("environment") != "local"
                or archived_task_value.get("deployment_requested") is not False
                or archived_task_value.get("status") in {"idle", "accepted"}
            ):
                return ["local task_archive decision boundary is invalid"]
        elif assurance == "completed-workflow-checkpoint":
            if source != "workflow:accepted" or archived_task_value.get("status") != "accepted" or value.get("decision_receipt") is not None:
                return ["accepted task_archive checkpoint is invalid"]
        elif assurance == "provider-signed-user-message":
            try:
                valid_provider_decision = source.startswith("user:") and humandecision.reverify(
                    ROOT, load(AGENT_DIR / "config.json"), archived_task_value,
                    gate="task-archive", artifact_sha256=str(archived_task.get("sha256")),
                    source=source, record=value.get("decision_receipt"),
                )
            except (OSError, ValueError, TypeError, SystemExit):
                valid_provider_decision = False
            if not valid_provider_decision:
                return ["protected task_archive lacks a provider decision"]
        else:
            return ["task_archive assurance is invalid"]
        current = value.get("previous")
        expected_total -= 1
    if expected_total != 0:
        return ["task_archive chain count is incomplete"]
    return []


def rollback_archive_errors(task: Dict[str, object]) -> List[str]:
    head = task.get("rollback_archive")
    if head is None:
        return []
    required = {"schema", "path", "sha256", "bytes", "depth", "total_entries"}
    legacy = required - {"depth"}  # pre-depth heads written before depth consolidation
    current = head; visited: set[str] = set()
    chain: List[Tuple[Dict[str, object], List[object], bool]] = []
    while current is not None:
        if not isinstance(current, dict) or (set(current) != required and set(current) != legacy):
            return ["rollback_archive head has invalid fields"]
        is_legacy = "depth" not in current
        digest = str(current.get("sha256", ""))
        relative = f".agent/state/evidence/rollback-archives/{digest}.json"
        if (
            current.get("schema") != "agent-rollback-archive-head/v1"
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None or digest in visited
            or current.get("path") != relative
            or not isinstance(current.get("bytes"), int) or current["bytes"] < 1
            or (not is_legacy and (
                not isinstance(current.get("depth"), int) or current["depth"] < 1
                or current["depth"] > rollback_archive_depth_limit()
            ))
            or not isinstance(current.get("total_entries"), int) or current["total_entries"] < 1
        ):
            return ["rollback_archive head is not content-addressed"]
        visited.add(digest); path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            return ["rollback_archive content is missing"]
        data = bounded_file_bytes(path,"workflow artifact")
        if len(data) != current["bytes"] or hashlib.sha256(data).hexdigest() != digest:
            return ["rollback_archive content drifted"]
        try:
            value = strict_json_loads(data)
        except json.JSONDecodeError:
            return ["rollback_archive content is not valid JSON"]
        previous = value.get("previous") if isinstance(value, dict) else None
        entries = value.get("entries") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict) or set(value) != {"schema", "previous", "entries"}
            or value.get("schema") != "agent-rollback-archive/v1"
            or not isinstance(entries, list) or not entries
        ):
            return ["rollback_archive entries or chain head is invalid"]
        chain.append((current, entries, is_legacy))
        current = previous
    cumulative = 0
    for position, (archive_head, entries, is_legacy) in enumerate(reversed(chain), start=1):
        cumulative += len(entries)
        if archive_head["total_entries"] != cumulative or (
            not is_legacy and archive_head["depth"] != position
        ):
            return ["rollback_archive cumulative totals or depth are invalid"]
    return []


def failure_archive_errors(task: Dict[str, object]) -> List[str]:
    head = task.get("failure_archive")
    if head is None:
        return []
    required = {
        "schema", "path", "sha256", "bytes", "depth", "total_signatures", "total_events",
    }
    current = head; visited: set[str] = set()
    chain: List[Tuple[Dict[str, object], Dict[str, int]]] = []
    while current is not None:
        if not isinstance(current, dict) or set(current) != required:
            return ["failure_archive head has invalid fields"]
        digest = str(current.get("sha256", ""))
        relative = f".agent/state/evidence/failure-archives/{digest}.json"
        if (
            current.get("schema") != "agent-failure-archive-head/v1"
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None or digest in visited
            or current.get("path") != relative
            or not isinstance(current.get("bytes"), int) or current["bytes"] < 1
            or not isinstance(current.get("depth"), int) or current["depth"] < 1
            or current["depth"] > failure_archive_depth_limit()
            or not isinstance(current.get("total_signatures"), int)
            or not isinstance(current.get("total_events"), int)
        ):
            return ["failure_archive head is not content-addressed"]
        visited.add(digest); path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            return ["failure_archive content is missing"]
        data = bounded_file_bytes(path,"workflow artifact")
        if len(data) != current["bytes"] or hashlib.sha256(data).hexdigest() != digest:
            return ["failure_archive content drifted"]
        try:
            value = strict_json_loads(data)
        except json.JSONDecodeError:
            return ["failure_archive content is not valid JSON"]
        previous = value.get("previous") if isinstance(value, dict) else None
        counts = value.get("counts") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict) or set(value) != {"schema", "previous", "counts"}
            or value.get("schema") != "agent-failure-archive/v1"
            or not isinstance(counts, dict)
            or any(re.fullmatch(r"[0-9a-f]{64}", str(key)) is None for key in counts)
            or any(not isinstance(count, int) or isinstance(count, bool) or count < 1 for count in counts.values())
        ):
            return ["failure_archive counts or chain head is invalid"]
        chain.append((current, {str(key): int(count) for key, count in counts.items()}))
        current = previous
    cumulative: Dict[str, int] = {}
    for position, (archive_head, delta) in enumerate(reversed(chain), start=1):
        for key, count in delta.items():
            cumulative[key] = cumulative.get(key, 0) + count
        if (
            archive_head["depth"] != position
            or archive_head["total_signatures"] != len(cumulative)
            or archive_head["total_events"] != sum(cumulative.values())
        ):
            return ["failure_archive cumulative totals or depth are invalid"]
    return []


def workflow_validation_errors(task: Dict[str, object], require_full: bool = False) -> List[str]:
    """Replay canonical state, artifact semantics, gates and stage projection without mutation."""
    errors:List[str]=[]
    required=("current_node","accepted_nodes","node_artifacts","gate_approvals","pending_gate_artifacts","rollback_ledger","rollback_archive","failure_ledger","failure_archive","mode_status")
    for key in required:
        if key not in task: errors.append(f"missing workflow state: {key}")
    accepted=task.get("accepted_nodes",[])
    if not isinstance(accepted,list) or accepted!=sorted(set(accepted)) or any(not isinstance(node,int) or node<0 or node>8 for node in accepted):
        errors.append("accepted_nodes must be unique sorted nodes 0-8")
    ledger=task.get("rollback_ledger")
    if isinstance(ledger,list) and len(ledger)>rollback_hot_limit():
        errors.append("rollback_ledger exceeds the configured hot-state limit")
    errors.extend(rollback_archive_errors(task))
    failures=task.get("failure_ledger")
    if (
        not isinstance(failures,dict) or len(failures)>failure_hot_limit()
        or any(re.fullmatch(r"[0-9a-f]{64}",str(key)) is None for key in failures)
        or any(not isinstance(count,int) or isinstance(count,bool) or count<1 for count in failures.values())
    ):
        errors.append("failure_ledger exceeds the configured hot-state limit or is invalid")
    errors.extend(failure_archive_errors(task))
    errors.extend(task_archive_errors(task))
    errors.extend(state_machine_errors(task))
    if task.get("status") in {"in_progress","ready_to_complete"}:
        # Revalidate the requirement gate with the same function the mutators
        # use, so a `continue` route never contradicts the next transition.
        requirement_error=requirement_gate_error(task)
        if requirement_error is not None:
            errors.append(requirement_error)
    artifacts=task.get("node_artifacts",{})
    if not isinstance(artifacts,dict):
        artifacts={}; errors.append("node_artifacts must be an object")
    if require_full:
        terminal=8 if task.get("mode")=="release" else 7
        if task.get("mode")=="fast":
            required_records={1,6,7}
        elif lightweight_standard(task):
            # The standard lightweight projection accepts nodes 2-6 through the
            # node 6 receipt alone; node 2 keeps its own record only when it was
            # advanced before the projection jump.
            required_records={1,6,7}|({2} if "2" in artifacts else set())
        else:
            required_records=set(range(1,terminal+1))
        observed={int(node) for node in artifacts if str(node).isdigit()}
        if observed!=required_records:
            errors.append(f"terminal workflow requires exact node artifact records {sorted(required_records)}")
    for node,record in artifacts.items():
        if not str(node).isdigit() or not isinstance(record,dict):
            errors.append("invalid node artifact record"); continue
        node_number=int(node)
        path=(ROOT/str(record.get("path",""))).resolve()
        try: path.relative_to(ROOT)
        except ValueError:
            errors.append(f"node artifact escapes project: {record.get('path')}"); continue
        if not path.is_file() or path.is_symlink():
            errors.append(f"node artifact missing: {record.get('path')}"); continue
        capture_nodes=task.get("node_artifact_capture_nodes",[])
        try:
            actual=(node_artifact(str(record.get("path","")),seal=False)
                    if node_number in capture_nodes else artifact(str(record.get("path",""))))
        except (SystemExit,OSError) as error:
            errors.append(f"node artifact capture failed: {record.get('path')}: {error}"); continue
        if record!=actual:
            errors.append(f"node artifact drifted: {record.get('path')}"); continue
        if node_number in capture_nodes and not node_capture_matches_source(record):
            errors.append(f"node artifact capture identity drifted: {record.get('path')}"); continue
        # `complete-task` already revalidated every semantic artifact before it
        # atomically wrote the completion checkpoint and cleared active model
        # authority. Accepted history is thereafter validated by exact bytes +
        # that checkpoint; replaying live validators against the intentionally
        # idle config/ledger would substitute a different candidate authority.
        if task.get("status")!="accepted":
            try:
                validate_node_artifact(task,node_number,actual)
            except (SystemExit,subprocess.TimeoutExpired) as error:
                errors.append(f"node {node} semantic artifact validation failed: {error}")
    if task.get("mode") in {"standard","release"}:
        # The lightweight standard projection has no node 4 solution gate; the
        # release projection stays full through "lightweight-release".
        gate_nodes=((7,"acceptance"),) if lightweight_standard(task) else ((4,"solution"),(7,"acceptance"))
        for node,gate in gate_nodes:
            approval=task.get("gate_approvals",{}).get(gate,{}) if isinstance(task.get("gate_approvals"),dict) else {}
            record=artifacts.get(str(node),{})
            if node in accepted and not human_gate_approval_valid(task,gate,approval,record):
                errors.append(f"{task.get('mode')} node {node} lacks artifact-bound human {gate} approval")
            if node==7 and node in accepted and task.get("mode")=="release" and not release_acceptance_approval_valid(task,approval,record):
                errors.append("release node 7 lacks explicit transcript verification and supervision-debt waiver")
    if task.get("environment")=="production" and 8 in accepted:
        approval=task.get("gate_approvals",{}).get("production",{}) if isinstance(task.get("gate_approvals"),dict) else {}
        record=artifacts.get("8",{})
        approval_record = legacy_node8_archive_record(record) if task.get("status") == "accepted" else None
        if not human_gate_approval_valid(task,"production",approval,approval_record or record):
            errors.append("production node 8 lacks artifact-bound human production approval")
    stage_validator=AGENT_DIR/"skills/run-ai-coding-pipeline/scripts/validate_stage_index.py"
    if not stage_validator.is_file() or not STAGE_PATH.is_file():
        errors.append("stage index validator or stage index is missing")
    else:
        try:
            stage=run_bounded_command([sys.executable,str(stage_validator),str(STAGE_PATH)],cwd=ROOT,timeout=120)
            if stage.returncode: errors.append("stage index drifted from canonical TASK state")
        except subprocess.TimeoutExpired:
            errors.append("stage index validation timed out")
    if require_full and task.get("status")!="accepted":
        try:
            template=run_bounded_command([sys.executable,str(AGENT_DIR/"scripts/templatectl.py"),"validate"],cwd=ROOT,timeout=120)
            if template.returncode: errors.append("terminal workflow template state is invalid")
        except subprocess.TimeoutExpired:
            errors.append("terminal workflow template validation timed out")
        try:
            delivery=run_bounded_command([sys.executable,str(AGENT_DIR/"scripts/deliveryctl.py"),"validate"],cwd=ROOT,timeout=120)
            if delivery.returncode: errors.append("terminal workflow delivery state is invalid")
        except subprocess.TimeoutExpired:
            errors.append("terminal workflow delivery validation timed out")
    return errors


SCHEDULER_NONCE_PATH = AGENT_DIR / "state" / ".scheduler-receipt-nonces.json"
SCHEDULER_NONCE_LOCK = AGENT_DIR / "state" / ".scheduler-receipt-nonces.lock"


def consumed_scheduler_nonces() -> Dict[str, str]:
    """Load the initialized nonce registry; loss/corruption must never reset replay history."""
    try:
        before=os.lstat(SCHEDULER_NONCE_PATH)
    except OSError as error:
        raise SystemExit("scheduler nonce registry is missing; restore or reinitialize the workflow") from error
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.geteuid()
            or stat.S_IMODE(before.st_mode)&0o022 or before.st_size>humandecision.MAX_RECEIPT_BYTES):
        raise SystemExit("scheduler nonce registry is unsafe")
    try:
        raw_bytes,identity=humandecision.receipt_snapshot(SCHEDULER_NONCE_PATH)
        after=os.lstat(SCHEDULER_NONCE_PATH)
        if identity!=(after.st_dev,after.st_ino) or after.st_mtime_ns!=before.st_mtime_ns or after.st_size!=before.st_size:
            raise SystemExit("scheduler nonce registry changed while reading")
        value=strict_json_loads(raw_bytes.decode("utf-8"))
    except (OSError,UnicodeError,ValueError) as error:
        raise SystemExit("scheduler nonce registry is unreadable or malformed") from error
    if (not isinstance(value,dict) or set(value)!={"schema","nonces"}
            or value.get("schema")!="agent-scheduler-receipt-nonces/v1" or not isinstance(value.get("nonces"),dict)):
        raise SystemExit("scheduler nonce registry has invalid fields")
    now=dt.datetime.now(dt.timezone.utc); live: Dict[str,str]={}
    for nonce,expiry in value["nonces"].items():
        if not isinstance(nonce,str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,256}",nonce) or not isinstance(expiry,str):
            raise SystemExit("scheduler nonce registry contains an invalid entry")
        try: observed=dt.datetime.fromisoformat(expiry.replace("Z","+00:00"))
        except ValueError as error: raise SystemExit("scheduler nonce registry contains an invalid expiry") from error
        if observed.tzinfo is None: raise SystemExit("scheduler nonce registry expiry lacks timezone")
        if observed.astimezone(dt.timezone.utc)>now: live[nonce]=expiry
    return live


def record_scheduler_nonce(nonce: str, expiry: dt.datetime) -> None:
    """Consume a verified scheduler nonce, pruning expired entries atomically."""
    live = consumed_scheduler_nonces()
    live[nonce] = expiry.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat()
    data=(strict_json_dumps({"schema":"agent-scheduler-receipt-nonces/v1","nonces":live},ensure_ascii=False,sort_keys=True)+"\n").encode("utf-8")
    try: boundedio.atomic_write(SCHEDULER_NONCE_PATH,data,mode=0o600,label="scheduler nonce registry")
    except RuntimeError as error: raise SystemExit(str(error)) from error


def consume_scheduler_nonce(nonce: str, expiry: dt.datetime) -> None:
    """Record a provider-consumed nonce in the local fail-closed audit cache.

    The protected provider adapter is the non-rollbackable replay authority.
    This owner-private registry is defense in depth and detects local damage;
    its lock still serializes audit-cache updates from concurrent resumptions.
    """
    try: lock_handle=boundedio.open_private_lock(SCHEDULER_NONCE_LOCK,label="scheduler nonce lock")
    except RuntimeError as error: raise SystemExit(str(error)) from error
    with lock_handle as handle:
        fcntl.flock(handle.fileno(),fcntl.LOCK_EX)
        if nonce in consumed_scheduler_nonces(): raise SystemExit("scheduler receipt nonce was already consumed")
        record_scheduler_nonce(nonce,expiry)


def verified_scheduler_resume(raw: Optional[str], cursor: str, task: Dict[str, object], config: Dict[str, object]) -> bool:
    if not raw:
        return False
    agent_control = config.get("agent_control", {})
    scheduler = agent_control.get("scheduler", {}) if isinstance(agent_control, dict) else {}
    if not isinstance(scheduler, dict):
        scheduler = {}
    adapter = humandecision.try_adapter_path(
        ROOT, scheduler.get("signed_adapter"), required_operations=("consume-scheduler-resume",),
    )
    if adapter is None:
        raise SystemExit("host scheduler resume adapter is not configured")
    path = (ROOT / raw).resolve()
    try: path.relative_to(ROOT)
    except ValueError: raise SystemExit("scheduler receipt escapes project")
    if not path.is_file() or path.is_symlink(): raise SystemExit("scheduler receipt is missing or unsafe")
    receipt_data,receipt_identity=humandecision.receipt_snapshot(path)
    try: value=strict_json_loads(receipt_data.decode("utf-8"))
    except (UnicodeError,json.JSONDecodeError) as error: raise SystemExit("scheduler receipt is not valid UTF-8 JSON") from error
    required = {"schema", "resume_cursor", "task_invariant_sha256", "observed_at", "scheduler_id", "nonce",
                "provider_project_id", "provider_repository_id", "task_generation_id"}
    provider_ids=(value.get("provider_project_id"),value.get("provider_repository_id"),value.get("task_generation_id")) if isinstance(value,dict) else ()
    trusted_ids=(scheduler.get("provider_project_id"),scheduler.get("provider_repository_id"),task.get("task_generation_id"))
    if (not isinstance(value,dict) or set(value) != required or value.get("schema") != "host-scheduler-resume/v2"
            or value.get("resume_cursor") != cursor
            or value.get("task_invariant_sha256") != contexttx.contextctl.invariant_sha256(task)
            or not str(value.get("scheduler_id", "")).strip()
            or not isinstance(value.get("nonce"),str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,256}",value["nonce"])
            or provider_ids!=trusted_ids
            or any(not isinstance(item,str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}",item) is None for item in provider_ids)):
        raise SystemExit("scheduler receipt does not bind the current cursor and provider-issued project/repository/task generation identities")
    try: observed = dt.datetime.fromisoformat(str(value.get("observed_at", "")).replace("Z", "+00:00"))
    except ValueError: raise SystemExit("scheduler receipt timestamp is invalid")
    if observed.tzinfo is None: raise SystemExit("scheduler receipt timestamp lacks timezone")
    age = (dt.datetime.now(dt.timezone.utc) - observed.astimezone(dt.timezone.utc)).total_seconds()
    raw_maximum = scheduler.get("max_receipt_age_seconds", 300)
    maximum = raw_maximum if isinstance(raw_maximum, int) and not isinstance(raw_maximum, bool) and raw_maximum > 0 else 300
    if age < -30 or age > maximum: raise SystemExit("scheduler receipt is stale or future-dated")
    nonce = str(value["nonce"])
    if nonce in consumed_scheduler_nonces():
        raise SystemExit("scheduler receipt nonce was already consumed")
    digest=hashlib.sha256(receipt_data).hexdigest()
    # Replay authority lives outside the rollbackable project state. The
    # protected provider adapter must verify and atomically consume this nonce
    # in one operation backed by its own monotonic durable store.
    result=humandecision.run_adapter(adapter,["consume-scheduler-resume"],required_operations=("consume-scheduler-resume",),timeout=30,receipt_raw=receipt_data)
    consume_binding={key:value[key] for key in ("provider_project_id","provider_repository_id","task_generation_id","scheduler_id","nonce")}
    binding_digest=canonical_sha256(consume_binding)
    expected_prefix=f"CONSUMED SCHEDULER RESUME sha256={digest} binding-sha256={binding_digest} sequence="
    sequence_text=result.stdout.strip()[len(expected_prefix):] if result.stdout.strip().startswith(expected_prefix) else ""
    if result.returncode or not sequence_text.isdigit() or int(sequence_text)<=0:
        raise SystemExit("host scheduler adapter rejected or did not atomically consume the resume receipt")
    after_data,after_identity=humandecision.receipt_snapshot(path)
    if after_identity!=receipt_identity or after_data!=receipt_data:
        raise SystemExit("scheduler receipt changed during provider verification")
    consume_scheduler_nonce(nonce, observed.astimezone(dt.timezone.utc) + dt.timedelta(seconds=maximum))
    return True


def terminal_binding_error() -> Optional[str]:
    """Read-only ledger/runtime proof required before a terminal route receipt."""
    checks = (
        (
            [sys.executable, str(AGENT_DIR/"skills/manage-agent-team/scripts/agentledger.py"), "validate", "--require-empty"],
            "Agent ledger empty-state validation",
        ),
        (
            [sys.executable, str(AGENT_DIR/"scripts/agentctl.py"), "assert-clean"],
            "runtime residual check",
        ),
    )
    for command, label in checks:
        try:
            result=run_bounded_command(command,cwd=ROOT,timeout=30)
        except subprocess.TimeoutExpired:
            return f"{label} timed out"
        if result.returncode:
            detail = result.stdout.strip().replace("\n", " | ")[:500]
            return label + (f" failed: {detail}" if detail else " failed")
    return None


def transition_journal_recovery() -> Optional[str]:
    """Concrete recovery command for a leftover transition journal, or None."""
    try:
        status = contexttx.transition_journal_status()
    except (OSError, ValueError, TypeError) as error:
        return f"inspect .agent/state/.context-transition-journal.json manually: {error}"
    if status is None:
        return None
    state = str(status.get("state", "")) if isinstance(status, dict) else ""
    if state == "interrupted":
        return "python3 .agent/scripts/contextctl.py journal --restore"
    if state in {"committed", "rolled_back"}:
        return "python3 .agent/scripts/contextctl.py journal --discard"
    return str(status.get("recovery") or "inspect .agent/state/.context-transition-journal.json manually") if isinstance(status, dict) else "inspect .agent/state/.context-transition-journal.json manually"


def _command_route_resume_locked(args: Optional[argparse.Namespace] = None) -> int:
    task=load(TASK_PATH)
    context=load(AGENT_DIR/"state/CONTEXT.json")
    cursor=canonical_sha256({
        "task": contexttx.contextctl.invariant_sha256(task),
        "checkpoint": (context.get("checkpoint") or {}).get("sequence"),
        "next_action": task.get("next_action"),
    })
    if args is not None and getattr(args,"after_cursor",None) not in {None,cursor}:
        raise SystemExit("resume cursor is stale; run route-resume without --after-cursor to obtain the current command")
    try:
        context_result=run_bounded_command([sys.executable,str(CONTEXT_TOOL),"check","--quiet"],cwd=ROOT,timeout=120)
        context_invalid = context_result.returncode != 0
    except subprocess.TimeoutExpired:
        context_invalid = True
    config=load(AGENT_DIR/"config.json")
    errors=workflow_validation_errors(task,require_full=task.get("status") in {"ready_to_complete","accepted"})
    if context_invalid: errors.append("context capsule is invalid or stale")
    recovery=transition_journal_recovery()
    if recovery is not None:
        errors.append(f"interrupted context transition requires recovery: run `{recovery}`")
    effective_budget_state="hard_blocked"
    try:
        active=copy.deepcopy(task); freshness=context.get("usage_freshness",{})
        active["tokens_used"]=max(int(task.get("tokens_used",0)),int(freshness.get("estimated_tokens",0)))
        ledger_path=AGENT_DIR/"state/agents.json"; ledger=load(ledger_path) if ledger_path.is_file() else None
        effective_budget_state=str(total_budget.snapshot(active,config,ledger)["state"])
    except (ValueError,TypeError,OSError,KeyError,SystemExit):
        errors.append("effective unified Token budget is invalid")
    effective_next_action=contexttx.contextctl.resume_next_action(task,effective_budget_state)
    terminal_closure=(
        task.get("status")=="ready_to_complete"
        and task.get("current_node")==7
        and task.get("accepted_nodes")==list(range(8))
    )
    hard_repair=contexttx.contextctl.bounded_hard_repair(task)
    action="continue"; terminal=False; control="resume-current-node"; cleanup=None
    if errors:
        action="waiting_human"; control="repair-context-or-workflow-state"
    elif task.get("status")=="accepted":
        action="complete"; terminal=True; control="explicit-complete-task-checkpoint"
        if effective_budget_state in {"must_compact","hard_blocked"}:
            control="explicit-complete-task-checkpoint;budget-recovery-before-next-task"
        binding_error=terminal_binding_error()
        if binding_error is not None:
            terminal=False; action="waiting_human"; control="cleanup-agent-ledger-and-runtime"
            cleanup="python3 .agent/scripts/agentctl.py cleanup"
            errors.append(f"terminal route requires an empty verified Agent ledger and clean runtime: {binding_error}")
    elif task.get("status")=="idle":
        action="waiting_human"; control="clarify-next-requirement"
    elif effective_budget_state=="hard_blocked" and terminal_closure:
        control="bounded-terminal-closure"
    elif effective_budget_state=="hard_blocked" and hard_repair:
        control="bounded-root-cause-repair"
    elif task.get("status")=="waiting_human" or effective_budget_state=="hard_blocked":
        action="waiting_human"; control="human-decision-required"
    elif effective_budget_state=="must_compact":
        resume=context.get("resume",{})
        expected_resume=contexttx.contextctl.resume_contract(
            task,
            contexttx.contextctl.invariant_sha256(task),
            effective_budget_state,
        )
        if resume != expected_resume:
            action="compact"; control="create-verified-compact-handoff"
        else:
            control="verified-phase-handoff-resume"
    scheduler_available=False; scheduler_error=None
    if not terminal and action=="continue":
        try:
            scheduler_available=verified_scheduler_resume(getattr(args,"scheduler_receipt",None) if args is not None else None,cursor,task,config)
        except (SystemExit,subprocess.TimeoutExpired,OSError,ValueError) as error:
            scheduler_error=str(error)
    resume_command=None
    if not terminal and action=="continue" and not scheduler_available:
        action="waiting_host_resume"; control="scheduler-unavailable-manual-resume"
        resume_command=f"HOST RESUME REQUIRED: cursor={cursor} node={task.get('current_node')} next={task.get('next_action')}"
    receipt={
        "schema":"agent-workflow-route/v2","terminal":terminal,"action":action,
        "status":task.get("status"),"current_node":task.get("current_node"),
        "next_action":effective_next_action,"budget_state":effective_budget_state,
        "control":control,"errors":errors,"scheduler_available":scheduler_available,
        "scheduler_error":scheduler_error,"recovery":recovery,"cleanup":cleanup,
        "resume_cursor":cursor,"resume_command":resume_command,
    }
    print(strict_json_dumps(receipt,ensure_ascii=False,sort_keys=True,separators=(",",":")))
    return 1 if errors else 0


def command_route_resume(args: Optional[argparse.Namespace] = None) -> int:
    """Linearize cursor validation and irreversible provider nonce consumption.

    Every canonical TASK/CONTEXT transition uses contexttx.TASK_LOCK. Holding the
    same lock through receipt emission prevents a provider-consumed nonce from
    authorizing a cursor that a concurrent transition has already revoked.
    """
    lock_path=contexttx.TASK_LOCK
    try: lock_handle=boundedio.open_private_lock(lock_path,label="task transition lock")
    except RuntimeError as error: raise SystemExit(str(error)) from error
    with lock_handle as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
        return _command_route_resume_locked(args)


def command_validate() -> int:
    task=load(TASK_PATH); errors=workflow_validation_errors(task,require_full=task.get("status") in {"ready_to_complete","accepted"})
    accepted=task.get("accepted_nodes",[])
    if errors:
        print("INVALID WORKFLOW STATE")
        for error in errors: print(f"- {error}")
        return 1
    print(f"VALID WORKFLOW STATE: current={task.get('current_node')} accepted={accepted}")
    return 0


def main() -> int:
    parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="command",required=True)
    submit=sub.add_parser("submit-gate"); submit.add_argument("--gate",choices=tuple(GATE_NODE),required=True); submit.add_argument("--artifact",required=True)
    approve=sub.add_parser("approve-gate"); approve.add_argument("--gate",choices=tuple(GATE_NODE),required=True); approve.add_argument("--source",required=True); approve.add_argument("--artifact-sha256",required=True); approve.add_argument("--human-decision-receipt"); approve.add_argument("--platform-transcript-verified-sha256"); approve.add_argument("--supervision-debt-waiver-sha256")
    advance=sub.add_parser("advance"); advance.add_argument("--node",type=int,required=True); advance.add_argument("--artifact",required=True)
    back=sub.add_parser("return-node"); back.add_argument("--from-node",type=int,required=True); back.add_argument("--to",type=int,required=True); back.add_argument("--issue-id",required=True); back.add_argument("--cause-category",choices=("requirements","provenance","scope","solution","tests","implementation","acceptance","runtime","delivery","agent-control"),required=True); back.add_argument("--subtask",required=True); back.add_argument("--root-cause",required=True); back.add_argument("--change",required=True)
    resolve=sub.add_parser("resolve-failure"); resolve.add_argument("--source",required=True); resolve.add_argument("--human-decision-receipt")
    complete=sub.add_parser("complete-task"); complete.add_argument("--retrospective",required=True); complete.add_argument("--knowledge-candidate-file","--knowledge-candidates",dest="knowledge_candidates",action="append"); complete.add_argument("--resolve-risk",action="append"); complete.add_argument("--platform-snapshot",required=True); complete.add_argument("--completion-source"); complete.add_argument("--completion-platform-transcript-verified-sha256"); complete.add_argument("--human-decision-receipt")
    sub.add_parser("compact-state")
    resume=sub.add_parser("route-resume"); resume.add_argument("--after-cursor"); resume.add_argument("--scheduler-receipt")
    sub.add_parser("validate")
    args=parser.parse_args()
    return {"submit-gate":lambda:command_submit(args),"approve-gate":lambda:command_approve(args),"advance":lambda:command_advance(args),"return-node":lambda:command_return(args),"resolve-failure":lambda:command_resolve_failure(args),"complete-task":lambda:command_complete(args),"compact-state":command_compact_state,"route-resume":lambda:command_route_resume(args),"validate":command_validate}[args.command]()


if __name__=="__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
