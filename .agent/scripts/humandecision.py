#!/usr/bin/env python3
"""Verify provider-owned human decision receipts without trusting caller labels."""

from pathlib import Path
import base64
import datetime as dt
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Dict, Optional

from process_observation import (ProcessObservationError,darwin_process_group_snapshot,darwin_process_snapshot,linux_process_group_snapshot,linux_process_snapshot,linux_signal_identity)
from workflowlib import boundedio,boundedprocess

def _reject_nonfinite_json(token):
    raise json.JSONDecodeError(f"non-finite JSON number is forbidden: {token}",token,0)

def strict_json_loads(raw,**kwargs):
    return json.loads(raw,parse_constant=_reject_nonfinite_json,**kwargs)

def strict_json_dumps(value,**kwargs):
    kwargs["allow_nan"]=False
    return json.dumps(value,**kwargs)



SCHEMA = "agent-human-decision/v1"
PROVIDER_POLICY_VERSION = 1
LOCAL_POLICY_VERSION = 2
LOCAL_ASSURANCE = "explicit-user-message;local-advisory;not-authoritative"
POLICY = {
    "source": "orchestrator-user-message",
    "automatic_gate_trust": False,
    "human_verification_required": True,
    "allow_current_chat_local_release": False,
    "signed_adapter": None,
    "max_receipt_age_seconds": 900,
}
FIELDS = {
    "schema", "decision_id", "gate", "decision", "artifact_sha256", "source",
    "task_title", "task_mode", "routing_profile_sha256", "project_identity_sha256", "task_generation_sha256", "task_generation_id",
    "observed_at", "authority",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DECISION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MAX_RECEIPT_BYTES = 262144
MAX_ADAPTER_METADATA_BYTES = 16384
MAX_ADAPTER_OUTPUT_BYTES = 262144
ADAPTER_METADATA_SUFFIX = ".agent-workflow-adapter.json"
ADAPTER_METADATA_SCHEMA = "agent-provider-adapter/v1"
ADAPTER_OPERATIONS = {
    "health", "verify", "consume-human-decision", "status-human-decision",
    "consume-scheduler-resume", "verify-host-compaction", "verify-usage",
    "health-provider-preflight", "verify-provider-preflight", "verify-platform",
}


def canonical(value: object) -> bytes:
    return strict_json_dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha256(path: Path) -> str:
    return boundedio.sha256(path,label="human-decision artifact")


def receipt_snapshot(path: Path):
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_RECEIPT_BYTES:
        raise SystemExit("human decision receipt must be one bounded regular file")
    flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or
                not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1):
            raise SystemExit("human decision receipt changed while opening")
        chunks = []
        remaining = MAX_RECEIPT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk); remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_RECEIPT_BYTES:
            raise SystemExit("human decision receipt is too large")
        return raw, (opened.st_dev, opened.st_ino)
    finally:
        os.close(descriptor)


def repository_identity(root: Path) -> Dict[str,object]:
    resolved=root.resolve(); root_stat=os.lstat(resolved)
    if not stat.S_ISDIR(root_stat.st_mode): raise SystemExit("human decision project root is not a directory")
    git_entry=resolved/".git"; git_identity=None
    try: git_stat=os.lstat(git_entry)
    except FileNotFoundError: pass
    else:
        if stat.S_ISLNK(git_stat.st_mode): raise SystemExit("human decision repository metadata cannot be a symlink")
        base={"dev":git_stat.st_dev,"ino":git_stat.st_ino,"mode":stat.S_IFMT(git_stat.st_mode)}
        if stat.S_ISDIR(git_stat.st_mode): git_identity={**base,"kind":"directory"}
        elif stat.S_ISREG(git_stat.st_mode) and git_stat.st_nlink==1 and git_stat.st_size<=4096:
            raw,identity=receipt_snapshot(git_entry)
            try: text=raw.decode("utf-8")
            except UnicodeDecodeError as error: raise SystemExit("Git worktree metadata is not UTF-8") from error
            match=re.fullmatch(r"gitdir: ([^\r\n]+)\n?",text)
            if not match: raise SystemExit("Git worktree metadata is malformed")
            target=Path(match.group(1)); target=target if target.is_absolute() else git_entry.parent/target
            target=Path(os.path.abspath(str(target)))
            try: target_stat=os.lstat(target)
            except FileNotFoundError as error: raise SystemExit("Git worktree metadata target is missing") from error
            if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISDIR(target_stat.st_mode):
                raise SystemExit("Git worktree metadata target is not a no-follow directory")
            git_identity={**base,"kind":"gitdir-file","content_sha256":hashlib.sha256(raw).hexdigest(),
                "target":{"path":str(target),"dev":target_stat.st_dev,"ino":target_stat.st_ino,"mode":stat.S_IFMT(target_stat.st_mode)}}
        else: raise SystemExit("human decision repository metadata is unsafe")
    executable=shutil.which("git",path=os.defpath); origin_sha256=None
    if executable:
        try: result=boundedprocess.run([executable,"-C",str(resolved),"config","--get","remote.origin.url"],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=10,env={"PATH":os.defpath,"LANG":"C","LC_ALL":"C"})
        except (OSError,subprocess.SubprocessError): result=None
        if result is not None and result.returncode==0:
            candidate=result.stdout.strip()
            if candidate and "\n" not in candidate and "\r" not in candidate and len(candidate)<=2048:
                origin_sha256=hashlib.sha256(candidate.encode()).hexdigest()
    return {"root":{"path":str(resolved),"dev":root_stat.st_dev,"ino":root_stat.st_ino,"mode":stat.S_IFMT(root_stat.st_mode)},
        "git_entry":git_identity,"origin_sha256":origin_sha256}


def project_identity_sha256(root: Path,config: Dict[str,object]) -> str:
    initialization=config.get("project_initialization") if isinstance(config,dict) else None
    identity={"repository":repository_identity(root),"project":config.get("project") if isinstance(config,dict) else None,
              "project_initialization":initialization if isinstance(initialization,dict) else None}
    return hashlib.sha256(canonical(identity)).hexdigest()


def task_generation_sha256(task: Dict[str,object]) -> str:
    identity={key:task.get(key) for key in ("task_generation_id","title","mode","task_type","requirement_contract_sha256","files","environment","deployment_requested","branch","task_archive")}
    return hashlib.sha256(canonical(identity)).hexdigest()


def routing_profile_sha256(task: Dict[str, object]) -> str:
    profile = {
        key: task.get(key)
        for key in (
            "task_type", "complexity", "mode", "files", "environment",
            "deployment_requested", "branch", "risk_flags",
        )
    }
    return hashlib.sha256(canonical(profile)).hexdigest()


def policy(config: Dict[str, object]) -> Dict[str, object]:
    control = config.get("agent_control", {})
    observed = control.get("human_decision_observer") if isinstance(control, dict) else None
    if not isinstance(observed, dict) or set(observed) != set(POLICY):
        raise SystemExit("human decision observer policy is missing or malformed")
    for key, expected in POLICY.items():
        if key == "signed_adapter":
            continue
        if observed.get(key) != expected:
            raise SystemExit("human decision observer policy weakens the fail-closed defaults")
    return observed


def decision_policy_version(
    config: Dict[str, object], *, mode: str, environment: str,
    deployment_requested: bool, risk_flags: Optional[Dict[str, object]] = None,
) -> int:
    """Select the sole authoritative provider-receipt gate policy.

    Task classification may still retain caller text as advisory context, but
    neither local mode nor a low-risk route changes who can authorize a gate.
    Keeping this choice independent of adapter availability lets a task begin
    clarification before the host integration is configured while ensuring it
    cannot cross a human gate until that provider integration exists.
    """
    policy(config)  # Validate the configured observer shape before routing.
    return PROVIDER_POLICY_VERSION


def local_approval(source: str, artifact_sha256: str, task: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    """Construct a legacy advisory record for archive/migration tests, never authority."""
    if not source.startswith("user:") or HEX64.fullmatch(artifact_sha256) is None:
        raise SystemExit("local human decision must bind a user source and exact artifact SHA-256")
    approval: Dict[str, object] = {
        "source": source,
        "artifact_sha256": artifact_sha256,
        "assurance": LOCAL_ASSURANCE,
    }
    if task is not None:
        # Bind the routing profile so archived advisory data remains attributable
        # to its historical task even though it can never authorize a gate.
        approval["routing_profile_sha256"] = routing_profile_sha256(task)
    return approval


def local_advisory_valid(
    task: Dict[str, object], approval: object, *, source: str,
    artifact_sha256: str, config: Optional[Dict[str, object]] = None,
) -> bool:
    risks = task.get("risk_flags")
    if not (
        task.get("decision_policy_version") == LOCAL_POLICY_VERSION
        and task.get("environment") == "local"
        and task.get("mode") in {"fast", "standard", "release"}
        and task.get("deployment_requested") is False
        and isinstance(risks, dict)
        and not any(risks.get(name) is True for name in {"deploy", "irreversible", "external_impact"})
        and isinstance(approval, dict)
        and approval.get("source") == source
        and approval.get("artifact_sha256") == artifact_sha256
        and approval.get("assurance") == LOCAL_ASSURANCE
        and source.startswith("user:")
        and HEX64.fullmatch(artifact_sha256) is not None
    ):
        return False
    # Accepted key shapes (all built on the base triple):
    # - base only: legacy record predating the routing-profile binding. Every
    #   last historical local-approval producer passed the task and bound the
    #   profile, so a 3-key record can only come from older code. Records carry
    #   no timestamp or schema version, so no cheaper cutoff exists; the
    #   window stays open only for those genuinely legacy records.
    # - base + routing_profile_sha256: later historical bound record.
    # - base + release pair: legacy release acceptance approval recorded by
    #   workflowctl approve-gate before the routing-profile binding existed.
    # - base + release pair + routing_profile_sha256: later historical release
    #   advisory record under the retired local boundary. The release digests are
    #   bound to the accepted artifact by workflowctl.release_acceptance_approval_valid;
    #   here their shape is re-validated the same way as the base digest.
    base = {"source", "artifact_sha256", "assurance"}
    release_pair = {"platform_transcript_verified_sha256", "supervision_debt_waiver_sha256"}
    extra = set(approval) - base
    if extra - {"routing_profile_sha256"} - release_pair:
        return False
    release_keys = extra & release_pair
    if release_keys not in (set(), release_pair):
        return False  # transcript/debt commitments are recorded atomically, never partially
    if "routing_profile_sha256" in extra:
        if approval.get("routing_profile_sha256") != routing_profile_sha256(task):
            return False
    if any(HEX64.fullmatch(str(approval.get(name, ""))) is None for name in release_keys):
        return False
    if task.get("mode") == "release" and config is not None:
        # Archive-shape validation also reflects configuration tightening: a
        # historical release advisory from the retired local boundary is not
        # even structurally current once that legacy flag is withdrawn.
        try:
            observed = policy(config)
        except SystemExit:
            return False
        if observed.get("allow_current_chat_local_release") is not True:
            return False
    return True


def local_approval_valid(
    task: Dict[str, object], approval: object, *, source: str,
    artifact_sha256: str, config: Optional[Dict[str, object]] = None,
) -> bool:
    """Deprecated authorization hook: local evidence is never gate authority."""
    return False


def resolve_receipt(root: Path, raw: str) -> Path:
    path = (root / raw).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        raise SystemExit("human decision receipt escapes the project evidence boundary")
    if not path.is_file() or path.is_symlink():
        raise SystemExit("human decision receipt is missing or is a symlink")
    return path


def inside(path: Path, boundary: Path) -> bool:
    try:
        path.relative_to(boundary)
        return True
    except ValueError:
        return False


def protected_path_chain(path: Path) -> bool:
    """Require an OS ownership boundary the current Agent cannot create."""
    if not hasattr(os, "geteuid"):
        return False
    current_uid = os.geteuid()
    current = Path(path.anchor)
    chain = [current]
    for part in path.parts[1:]:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError:
            return False
        if stat.S_ISLNK(metadata.st_mode):
            return False
        chain.append(current)
    for item in chain:
        try:
            metadata = item.stat()
        except OSError:
            return False
        if (
            metadata.st_uid == current_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or os.access(item, os.W_OK)
        ):
            return False
    return True


def verify_adapter_metadata(path: Path, required_operations) -> None:
    metadata_path = Path(str(path) + ADAPTER_METADATA_SUFFIX)
    try:
        canonical_metadata = metadata_path.resolve(strict=True)
    except OSError:
        raise SystemExit("provider adapter is missing its OS-protected protocol metadata")
    if canonical_metadata != metadata_path or not protected_path_chain(metadata_path):
        raise SystemExit("provider adapter metadata must be canonical, OS-owned and non-writable by the Agent")
    before = os.lstat(metadata_path)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size > MAX_ADAPTER_METADATA_BYTES):
        raise SystemExit("provider adapter metadata must be one bounded regular file")
    flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
    descriptor = os.open(metadata_path, flags)
    try:
        opened = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1):
            raise SystemExit("provider adapter metadata changed while opening")
        chunks = []
        remaining = MAX_ADAPTER_METADATA_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_ADAPTER_METADATA_BYTES:
            raise SystemExit("provider adapter metadata is too large")
    finally:
        os.close(descriptor)
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise SystemExit("provider adapter metadata is not valid UTF-8 JSON")
    operations = value.get("operations") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "purpose", "executable_sha256", "operations"}
        or value.get("schema") != ADAPTER_METADATA_SCHEMA
        or value.get("purpose") != "provider-verifiable-agent-control"
        or value.get("executable_sha256") != sha256(path)
        or not isinstance(operations, list)
        or any(not isinstance(item, str) for item in operations)
        or operations != sorted(set(operations))
        or any(item not in ADAPTER_OPERATIONS for item in operations)
        or not set(required_operations).issubset(set(operations))
    ):
        raise SystemExit("provider adapter metadata does not bind the executable and required protocol")


def validate_adapter_launcher(path: Path) -> None:
    flags=os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os,"O_NOFOLLOW") else 0)
    descriptor=os.open(path,flags)
    try:
        metadata=os.fstat(descriptor); prefix=os.read(descriptor,512)
    finally: os.close(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1:
        raise SystemExit("provider adapter must be one protected regular executable")
    if prefix.startswith(b"#!"):
        first=prefix.splitlines()[0][2:].decode("ascii",errors="strict").strip(); parts=first.split()
        if not parts or not parts[0].startswith("/") or len(parts)>2:
            raise SystemExit("provider adapter shebang must bind one protected interpreter")
        interpreter=Path(parts[0])
        if interpreter.name=="env":
            if len(parts)!=2 or re.fullmatch(r"[A-Za-z0-9._+-]+",parts[1]) is None:
                raise SystemExit("provider adapter env shebang is not a bounded interpreter lookup")
            resolved=next((candidate for candidate in (Path("/usr/local/bin")/parts[1],Path("/usr/bin")/parts[1],Path("/bin")/parts[1]) if candidate.is_file()),None)
            if resolved is None: raise SystemExit("provider adapter env interpreter is unavailable on the sealed PATH")
            interpreter=resolved
        elif len(parts)!=1:
            raise SystemExit("provider adapter shebang arguments are not allowed")
        try: canonical=interpreter.resolve(strict=True)
        except OSError as error: raise SystemExit("provider adapter interpreter is unavailable") from error
        if canonical!=interpreter or not protected_path_chain(interpreter):
            raise SystemExit("provider adapter interpreter must be canonical, OS-protected, and non-agent-writable")
        observed=os.lstat(interpreter)
        if not stat.S_ISREG(observed.st_mode) or not os.access(interpreter,os.X_OK):
            raise SystemExit("provider adapter interpreter is not an executable regular file")
def adapter_snapshot():
    try: return linux_process_snapshot() if sys.platform.startswith("linux") else darwin_process_snapshot()
    except ProcessObservationError: return None


def native_adapter_snapshot():
    """Retry the kernel-native observer directly after wrapper-level failure."""
    try:
        if sys.platform.startswith("linux"): return linux_process_snapshot()
        if sys.platform.startswith("darwin"): return darwin_process_snapshot()
    except ProcessObservationError:
        pass
    return None


def targeted_adapter_group_snapshot(group_id: int):
    try:
        if sys.platform.startswith("linux"): return linux_process_group_snapshot(group_id)
        if sys.platform.startswith("darwin"): return darwin_process_group_snapshot(group_id)
    except ProcessObservationError:
        pass
    return None


def observe_adapter_group_native(group_id: int,known: Dict[int,str]) -> bool:
    """Capture stable same-session members individually; never signal a numeric group."""
    for _attempt in range(3):
        first=targeted_adapter_group_snapshot(group_id)
        if first is None: return False
        members={pid:info for pid,info in first.items() if info.get("pgid")==group_id and info.get("sid",group_id)==group_id and not str(info.get("state","")).startswith("Z")}
        time.sleep(0.01)
        second=targeted_adapter_group_snapshot(group_id)
        if second is None: return False
        stable={pid:info for pid,info in second.items() if pid in members and info.get("pgid")==group_id and info.get("sid",group_id)==group_id and info.get("start_identity")==members[pid].get("start_identity") and not str(info.get("state","")).startswith("Z")}
        if set(stable)==set(members):
            known.update({pid:str(info["start_identity"]) for pid,info in stable.items()})
            return True
    return False


def cleanup_adapter_after_observer_failure(process: subprocess.Popen,known: Dict[int,str],reaped: bool) -> None:
    """Best-effort exact-member cleanup while an unreaped leader still anchors its session."""
    if not reaped:
        snapshot=native_adapter_snapshot()
        if snapshot is not None: observe_adapter_descendants(process.pid,known,snapshot)
        observe_adapter_group_native(process.pid,known)
    signal_adapter_identities(known,signal.SIGTERM)
    deadline=time.monotonic()+0.5
    while not reaped and time.monotonic()<deadline:
        observe_adapter_group_native(process.pid,known)
        signal_adapter_identities(known,signal.SIGTERM)
        time.sleep(0.02)
    signal_adapter_identities(known,signal.SIGKILL)
    for _attempt in range(3):
        if not reaped: observe_adapter_group_native(process.pid,known)
        signal_adapter_identities(known,signal.SIGKILL)
        time.sleep(0.01)


def adapter_group_exists(group_id: int,snapshot=None) -> bool:
    snapshot=adapter_snapshot() if snapshot is None else snapshot
    if snapshot is None: return True
    return any(info.get("pgid")==group_id and not str(info.get("state","")).startswith("Z")
               for info in snapshot.values())


def observe_adapter_group(group_id: int,known: Dict[int,str]) -> bool:
    for attempt in range(3):
        snapshot=adapter_snapshot()
        if snapshot is None: return False
        members={pid:info for pid,info in snapshot.items()
                 if info.get("pgid")==group_id and not str(info.get("state","")).startswith("Z")}
        if any(pid in known and known[pid]!=info.get("start_identity") for pid,info in members.items()): return False
        try:
            if any(os.getsid(pid)!=group_id for pid in members): return False
        except (ProcessLookupError,OSError,PermissionError):
            if attempt<2: time.sleep(0.01); continue
            return False
        immediate=adapter_snapshot()
        if immediate is None: return False
        current={pid:info for pid,info in immediate.items()
                 if info.get("pgid")==group_id and not str(info.get("state","")).startswith("Z")}
        current_identities={pid:str(info.get("start_identity")) for pid,info in current.items()}
        member_identities={pid:str(info.get("start_identity")) for pid,info in members.items()}
        if any(member_identities.get(pid,known.get(pid))!=identity for pid,identity in current_identities.items()):
            if attempt<2: time.sleep(0.01); continue
            return False
        try:
            if any(os.getsid(pid)!=group_id for pid in current): return False
        except (ProcessLookupError,OSError,PermissionError):
            if attempt<2: time.sleep(0.01); continue
            return False
        known.update({pid:str(info["start_identity"]) for pid,info in current.items()}); return True
    return False


def observe_adapter_descendants(root_pid: int,known: Dict[int,str],snapshot=None) -> bool:
    snapshot=adapter_snapshot() if snapshot is None else snapshot
    if snapshot is None: return False
    roots={root_pid}; roots.update(pid for pid,identity in known.items()
                                 if pid in snapshot and snapshot[pid].get("start_identity")==identity)
    changed=True
    while changed:
        changed=False
        for pid,info in snapshot.items():
            if info.get("ppid") in roots and pid not in roots:
                roots.add(pid)
                if pid!=root_pid and not str(info.get("state","")).startswith("Z"):
                    known.setdefault(pid,str(info["start_identity"]))
                changed=True
    return True


def signal_adapter_identities(known: Dict[int,str],signum: int) -> bool:
    ok=True
    for pid,identity in sorted(known.items(),reverse=True):
        try:
            if sys.platform.startswith("linux"): linux_signal_identity(pid,identity,signum)
            elif sys.platform.startswith("darwin"):
                immediate=darwin_process_snapshot(); current=immediate.get(pid)
                if current is None or current.get("start_identity")!=identity: continue
                os.kill(pid,signum)
            else: return False
        except ProcessLookupError: pass
        except (OSError,ProcessObservationError): ok=False
    return ok


def stop_adapter_process(process: subprocess.Popen,known: Dict[int,str]) -> bool:
    reaped=process.returncode is not None
    try:
        return _stop_adapter_process_observed(process,known,reaped)
    finally:
        if process.returncode is None:
            try: process.terminate()
            except (OSError,ProcessLookupError): pass
            try: process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                try: process.kill()
                except (OSError,ProcessLookupError): pass
                try: process.wait(timeout=2)
                except subprocess.TimeoutExpired: pass


def _stop_adapter_process_observed(process: subprocess.Popen,known: Dict[int,str],reaped: bool) -> bool:
    snapshot=adapter_snapshot()
    if snapshot is None:
        cleanup_adapter_after_observer_failure(process,known,reaped)
        return False
    if not reaped:
        if not observe_adapter_descendants(process.pid,known,snapshot): return False
        if not observe_adapter_group(process.pid,known): return False
    if not signal_adapter_identities(known,signal.SIGTERM): return False
    deadline=time.monotonic()+2.0
    while time.monotonic()<deadline:
        snapshot=adapter_snapshot()
        if snapshot is None or not observe_adapter_descendants(process.pid,known,snapshot): return False
        if not reaped and not observe_adapter_group(process.pid,known): return False
        live={pid for pid,identity in known.items() if pid!=process.pid and pid in snapshot
              and snapshot[pid].get("start_identity")==identity and not str(snapshot[pid].get("state","")).startswith("Z")}
        if not live and (reaped or not adapter_group_exists(process.pid,snapshot)): break
        time.sleep(0.02)
    for _ in range(3):
        snapshot=adapter_snapshot()
        if snapshot is None or not observe_adapter_descendants(process.pid,known,snapshot): return False
        if not signal_adapter_identities(known,signal.SIGSTOP): return False
    if not reaped and not observe_adapter_group(process.pid,known): return False
    if not signal_adapter_identities(known,signal.SIGKILL): return False
    kill_deadline=time.monotonic()+2.0
    residual=True
    while time.monotonic()<kill_deadline:
        snapshot=adapter_snapshot()
        if snapshot is None: return False
        live={pid for pid,identity in known.items() if pid!=process.pid and pid in snapshot
              and snapshot[pid].get("start_identity")==identity and not str(snapshot[pid].get("state","")).startswith("Z")}
        residual=bool(live) or (not reaped and adapter_group_exists(process.pid,snapshot))
        if not residual: break
        time.sleep(0.02)
    if residual: return False
    if not reaped:
        try: process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=2)
    final=adapter_snapshot()
    if final is None: return False
    return not any(pid in final and final[pid].get("start_identity")==identity
                   and not str(final[pid].get("state","")).startswith("Z")
                   for pid,identity in known.items() if pid!=process.pid)


def run_adapter(adapter: Path, arguments, *, required_operations, timeout: int, receipt_raw: Optional[bytes] = None, receipt_option: str = "--receipt") -> subprocess.CompletedProcess:
    verify_adapter_metadata(adapter,required_operations)
    validate_adapter_launcher(adapter)
    before=os.lstat(adapter); before_sha=sha256(adapter)
    with tempfile.TemporaryDirectory(prefix="agent-provider-adapter-") as raw_home:
        home=Path(raw_home); os.chmod(home,0o700)
        command=[str(adapter),*arguments]
        if receipt_raw is not None:
            receipt_path=home/"receipt.json"
            flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|(os.O_NOFOLLOW if hasattr(os,"O_NOFOLLOW") else 0)
            descriptor=os.open(receipt_path,flags,0o600)
            try:
                os.write(descriptor,receipt_raw); os.fsync(descriptor)
            finally: os.close(descriptor)
            command=[str(adapter),*arguments,receipt_option,str(receipt_path)]
        environment={"PATH":"/usr/local/bin:/usr/bin:/bin","HOME":str(home),"TMPDIR":str(home),"LANG":"C","LC_ALL":"C","TZ":"UTC"}
        process=None; output_stream=None; known={}
        try:
            if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
                raise SystemExit("provider adapter requires default SIGCHLD ownership for unreaped PID binding")
            process=subprocess.Popen(command,cwd=str(home),env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,close_fds=True,start_new_session=True)
            output_stream=process.stdout
            if output_stream is None: raise SystemExit("provider adapter output pipe is unavailable")
            snapshot=adapter_snapshot()
            if snapshot is None: raise SystemExit("provider adapter leader identity observation is unavailable")
            leader=snapshot.get(process.pid)
            leader_identity=str(leader["start_identity"]) if leader is not None else None
            if leader_identity is not None: known[process.pid]=leader_identity
            selector=selectors.DefaultSelector(); selector.register(output_stream,selectors.EVENT_READ)
            deadline=time.monotonic()+timeout; chunks=[]; total=0; eof=False
            try:
                while True:
                    snapshot=adapter_snapshot()
                    if (snapshot is None or not observe_adapter_descendants(process.pid,known,snapshot)
                            or not observe_adapter_group(process.pid,known)):
                        raise SystemExit("provider adapter process identity observation is unavailable")
                    leader=snapshot.get(process.pid)
                    if leader is not None:
                        observed_identity=str(leader.get("start_identity"))
                        if leader_identity is None:
                            leader_identity=observed_identity; known[process.pid]=observed_identity
                        elif observed_identity!=leader_identity:
                            raise SystemExit("provider adapter leader identity changed before cleanup")
                    # Darwin libproc may omit an exited child before wait(); without
                    # poll/wait, its captured PID is still unreaped and cannot be reused.
                    exited=leader is None or str(leader.get("state","")).startswith("Z")
                    if eof and exited: break
                    remaining=deadline-time.monotonic()
                    if remaining<=0:
                        raise SystemExit("provider adapter timed out during protected execution")
                    events=selector.select(min(remaining,0.1)) if not eof else []
                    for key,_mask in events:
                        chunk=os.read(key.fileobj.fileno(),min(65536,MAX_ADAPTER_OUTPUT_BYTES+1-total))
                        if not chunk:
                            selector.unregister(key.fileobj); eof=True; continue
                        chunks.append(chunk); total+=len(chunk)
                        if total>MAX_ADAPTER_OUTPUT_BYTES:
                            raise SystemExit("provider adapter output exceeds its bounded protocol limit")
                    if eof and not exited: time.sleep(min(remaining,0.02))
                snapshot=adapter_snapshot()
                if snapshot is None or not observe_adapter_descendants(process.pid,known,snapshot):
                    raise SystemExit("provider adapter final process identity observation is unavailable")
                live={pid for pid,identity in known.items() if pid!=process.pid and pid in snapshot
                      and snapshot[pid].get("start_identity")==identity and not str(snapshot[pid].get("state","")).startswith("Z")}
                if live or adapter_group_exists(process.pid,snapshot):
                    raise SystemExit("provider adapter left descendant processes after leader exit")
                remaining=deadline-time.monotonic()
                if remaining<=0: raise SystemExit("provider adapter timed out during protected execution")
                returncode=process.wait(timeout=remaining)
            finally:
                selector.close()
            raw_output=b"".join(chunks)
            result=subprocess.CompletedProcess(command,returncode,raw_output.decode("utf-8",errors="replace"))
        except BaseException as error:
            if process is not None and not stop_adapter_process(process,known):
                raise SystemExit(f"{error}; provider adapter cleanup could not prove exact process identity termination") from error
            raise
        finally:
            if output_stream is not None: output_stream.close()
    after=os.lstat(adapter)
    if ((before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size)
            or before_sha!=sha256(adapter)):
        raise SystemExit("provider adapter changed during protected execution")
    return result


def adapter_path(root: Path, raw: object, required_operations=("health", "verify")) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise SystemExit("human gate is blocked until a provider-owned signed decision adapter is configured")
    requested = Path(raw).expanduser()
    if not requested.is_absolute():
        raise SystemExit("human decision adapter must be an absolute host-provisioned executable")
    try:
        path = requested.resolve(strict=True)
    except OSError:
        raise SystemExit("configured human decision adapter is unavailable")
    if requested != path:
        raise SystemExit("human decision adapter path must be canonical and contain no symlink or traversal")
    if inside(path, root.resolve()):
        raise SystemExit("human decision adapter must be provider-owned and outside the project workspace")
    temporary_roots = {
        Path(tempfile.gettempdir()).resolve(), Path("/tmp").resolve(),
        Path("/private/tmp").resolve(), Path("/var/tmp").resolve(),
    }
    if any(inside(path, candidate) for candidate in temporary_roots):
        raise SystemExit("human decision adapter cannot reside in an Agent-writable temporary boundary")
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode) or not os.access(path, os.X_OK):
        raise SystemExit("configured human decision adapter is unavailable or not executable")
    if not protected_path_chain(path):
        raise SystemExit("human decision adapter and every parent must be OS-owned and non-writable by the Agent")
    verify_adapter_metadata(path, required_operations)
    validate_adapter_launcher(path)
    return path


def try_adapter_path(root: Path, raw: object, required_operations=("health", "verify")) -> Optional[Path]:
    """Resolve a configured adapter path, or return None when none is configured.

    Unlike adapter_path this does not raise for an unconfigured (null or blank)
    adapter, so callers can probe availability; a configured but invalid
    adapter still fails closed through adapter_path.
    """
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    return adapter_path(root, raw, required_operations=required_operations)


def health(root: Path, config: Dict[str, object]) -> Dict[str, object]:
    """Fail before task mutation unless the provider decision boundary is live."""
    active_policy = policy(config)
    adapter = adapter_path(root, active_policy.get("signed_adapter"))
    try:
        result = run_adapter(adapter,["health"],required_operations=("health","verify"),timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit("provider-owned human decision adapter health check failed") from error
    if result.returncode:
        raise SystemExit(
            f"provider-owned human decision adapter health check failed: exit={result.returncode}"
        )
    return {
        "adapter_path": str(adapter),
        "adapter_sha256": sha256(adapter),
        "health": "passed",
    }


def parse_receipt(path: Path, task: Dict[str, object], gate: str, artifact_sha256: str, source: str, maximum_age: int, raw: Optional[bytes] = None) -> Dict[str, object]:
    content = raw if raw is not None else receipt_snapshot(path)[0]
    value = strict_json_loads(content.decode("utf-8"))
    if not isinstance(value, dict) or set(value) != FIELDS or value.get("schema") != SCHEMA:
        raise SystemExit("human decision receipt schema or fields are invalid")
    if (
        value.get("gate") != gate
        or value.get("decision") != "approved"
        or value.get("artifact_sha256") != artifact_sha256
        or value.get("source") != source
        or value.get("task_title") != task.get("title")
        or value.get("task_mode") != task.get("mode")
        or DECISION_ID.fullmatch(str(task.get("task_generation_id",""))) is None
        or value.get("task_generation_id") != task.get("task_generation_id")
        or value.get("routing_profile_sha256") != routing_profile_sha256(task)
        or value.get("authority") != "provider-signed-user-message"
        or not isinstance(value.get("decision_id"), str)
        or DECISION_ID.fullmatch(str(value.get("decision_id"))) is None
        or HEX64.fullmatch(str(artifact_sha256)) is None
        or HEX64.fullmatch(str(value.get("project_identity_sha256"))) is None
        or HEX64.fullmatch(str(value.get("task_generation_sha256"))) is None
        or not isinstance(value.get("task_generation_id"),str)
        or DECISION_ID.fullmatch(value.get("task_generation_id")) is None
    ):
        raise SystemExit("human decision receipt does not bind the active gate, task and artifact")
    try:
        observed = dt.datetime.fromisoformat(str(value.get("observed_at", "")).replace("Z", "+00:00"))
    except ValueError:
        raise SystemExit("human decision observed_at must be ISO-8601")
    if observed.tzinfo is None:
        raise SystemExit("human decision observed_at must include a timezone")
    age = (dt.datetime.now(dt.timezone.utc) - observed.astimezone(dt.timezone.utc)).total_seconds()
    if age < -30 or (maximum_age > 0 and age > maximum_age):
        raise SystemExit("human decision receipt is stale or future-dated")
    return value


def _decision_consumption(value: Dict[str, object]) -> Dict[str, object]:
    binding = {
        "project_identity_sha256": value["project_identity_sha256"],
        "task_generation_sha256": value["task_generation_sha256"],
        "task_generation_id": value["task_generation_id"],
        "gate": value["gate"],
        "artifact_sha256": value["artifact_sha256"],
        "decision_id": value["decision_id"],
    }
    return {"binding_sha256": hashlib.sha256(canonical(binding)).hexdigest(), **binding}

PREPARED_DECISION_FIELDS={
    "schema","path","raw_base64","sha256","bytes","decision_id","authority",
    "adapter_path","adapter_sha256","binding","binding_sha256","record","request_sha256",
}


def _prepared_request_payload(root,config,task,*,gate,artifact_sha256,source,path,raw,require_fresh):
    if task.get("decision_policy_version")!=PROVIDER_POLICY_VERSION:
        raise SystemExit("provider receipt cannot authorize a legacy or unsupported decision policy")
    active_policy=policy(config)
    value=parse_receipt(path,task,gate,artifact_sha256,source,
        int(active_policy.get("max_receipt_age_seconds",0)) if require_fresh else 0,raw=raw)
    if (value.get("project_identity_sha256")!=project_identity_sha256(root,config)
            or value.get("task_generation_sha256")!=task_generation_sha256(task)):
        raise SystemExit("human decision receipt belongs to another project or task generation")
    operations=("consume-human-decision","status-human-decision")
    adapter=adapter_path(root,active_policy.get("signed_adapter"),required_operations=operations)
    digest=hashlib.sha256(raw).hexdigest(); consumption=_decision_consumption(value)
    relative=str(path.relative_to(root.resolve()))
    record={"schema":SCHEMA,"path":relative,"sha256":digest,"bytes":len(raw),
            "decision_id":value["decision_id"],"authority":value["authority"],
            "adapter_path":str(adapter),"adapter_sha256":sha256(adapter)}
    request={"schema":"agent-human-decision-consumption-request/v1","path":relative,
             "raw_base64":base64.b64encode(raw).decode("ascii"),"sha256":digest,"bytes":len(raw),
             "decision_id":value["decision_id"],"authority":value["authority"],
             "adapter_path":str(adapter),"adapter_sha256":sha256(adapter),
             "binding":{key:consumption[key] for key in consumption if key!="binding_sha256"},
             "binding_sha256":consumption["binding_sha256"],"record":record}
    return {**request,"request_sha256":hashlib.sha256(canonical(request)).hexdigest()}


def prepare_decision_request(root:Path,config:Dict[str,object],task:Dict[str,object],*,gate:str,artifact_sha256:str,source:str,receipt:str,require_fresh:bool=True)->Dict[str,object]:
    path=resolve_receipt(root,receipt); raw,_identity=receipt_snapshot(path)
    return _prepared_request_payload(root,config,task,gate=gate,artifact_sha256=artifact_sha256,
        source=source,path=path,raw=raw,require_fresh=require_fresh)


def _validate_prepared_request(root,config,task,prepared,*,gate,artifact_sha256,source,require_fresh):
    if not isinstance(prepared,dict) or set(prepared)!=PREPARED_DECISION_FIELDS:
        raise SystemExit("prepared human decision request fields are invalid")
    unsigned={key:prepared[key] for key in prepared if key!="request_sha256"}
    if prepared.get("schema")!="agent-human-decision-consumption-request/v1" or prepared.get("request_sha256")!=hashlib.sha256(canonical(unsigned)).hexdigest():
        raise SystemExit("prepared human decision request digest is invalid")
    encoded=prepared.get("raw_base64")
    if not isinstance(encoded,str): raise SystemExit("prepared human decision receipt encoding is invalid")
    try: raw=base64.b64decode(encoded.encode("ascii"),validate=True)
    except (ValueError,UnicodeError) as error: raise SystemExit("prepared human decision receipt encoding is invalid") from error
    if base64.b64encode(raw).decode("ascii")!=encoded or len(raw)>MAX_RECEIPT_BYTES:
        raise SystemExit("prepared human decision receipt is noncanonical or oversized")
    relative=prepared.get("path")
    if not isinstance(relative,str): raise SystemExit("prepared human decision path is invalid")
    path=(root/relative).resolve()
    try: path.relative_to(root.resolve())
    except ValueError as error: raise SystemExit("prepared human decision path escapes the project") from error
    rebuilt=_prepared_request_payload(root,config,task,gate=gate,artifact_sha256=artifact_sha256,
        source=source,path=path,raw=raw,require_fresh=require_fresh)
    if rebuilt!=prepared: raise SystemExit("prepared human decision request no longer binds the active authority")
    return raw,Path(str(prepared["adapter_path"])),prepared["record"],prepared["binding"]


def _run_prepared_decision(root,config,task,prepared,*,gate,artifact_sha256,source,operation,require_fresh,path_must_match):
    raw,adapter,record,binding=_validate_prepared_request(root,config,task,prepared,gate=gate,
        artifact_sha256=artifact_sha256,source=source,require_fresh=require_fresh)
    if path_must_match:
        path=root/str(prepared["path"])
        current,_identity=receipt_snapshot(path)
        if current!=raw: raise SystemExit("human decision receipt changed after durable preparation")
    operations=("consume-human-decision","status-human-decision")
    result=run_adapter(adapter,[operation],required_operations=operations,timeout=30,receipt_raw=raw)
    digest=str(prepared["sha256"]); binding_sha=str(prepared["binding_sha256"]); output=result.stdout.strip()
    prefixes={
        "consumed":f"CONSUMED HUMAN DECISION sha256={digest} binding-sha256={binding_sha} sequence=",
        "active":f"ACTIVE HUMAN DECISION sha256={digest} binding-sha256={binding_sha} sequence=",
        "unconsumed":f"UNCONSUMED HUMAN DECISION sha256={digest} binding-sha256={binding_sha} sequence=",
        "revoked":f"REVOKED HUMAN DECISION sha256={digest} binding-sha256={binding_sha} sequence=",
    }
    observed=None; sequence=None
    for status,prefix in prefixes.items():
        if output.startswith(prefix):
            text=output[len(prefix):]
            if text.isdigit(): observed=status; sequence=int(text)
            break
    allowed={"consume-human-decision":{"consumed"},"status-human-decision":{"active","unconsumed","revoked"}}[operation]
    if result.returncode or observed not in allowed or sequence is None or (observed=="unconsumed")!=(sequence==0) or (observed!="unconsumed" and sequence<=0):
        raise SystemExit("provider-owned human decision adapter returned unknown exact approval status")
    authorization={"kind":"provider-human-decision","status":"consumed" if observed in {"consumed","active"} else observed,
                   "sequence":sequence,"binding_sha256":binding_sha,"receipt_sha256":digest,
                   "confirmed_via":operation,"recorded_at":dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()}
    if observed in {"consumed","active"}:
        consumption={"binding_sha256":binding_sha,**binding,"sequence":sequence}
        return {"status":"consumed","record":{**record,"provider_consumption":consumption},"authorization":authorization}
    return {"status":observed,"record":None,"authorization":authorization}


def consume_prepared_decision(root:Path,config:Dict[str,object],task:Dict[str,object],*,gate:str,artifact_sha256:str,source:str,prepared:Dict[str,object]):
    return _run_prepared_decision(root,config,task,prepared,gate=gate,artifact_sha256=artifact_sha256,
        source=source,operation="consume-human-decision",require_fresh=True,path_must_match=True)


def status_prepared_decision(root:Path,config:Dict[str,object],task:Dict[str,object],*,gate:str,artifact_sha256:str,source:str,prepared:Dict[str,object]):
    return _run_prepared_decision(root,config,task,prepared,gate=gate,artifact_sha256=artifact_sha256,
        source=source,operation="status-human-decision",require_fresh=False,path_must_match=False)


def verify(root:Path,config:Dict[str,object],task:Dict[str,object],*,gate:str,artifact_sha256:str,source:str,receipt:str,require_fresh:bool=True,consume:bool=True)->Dict[str,object]:
    prepared=prepare_decision_request(root,config,task,gate=gate,artifact_sha256=artifact_sha256,
        source=source,receipt=receipt,require_fresh=require_fresh)
    result=(consume_prepared_decision if consume else status_prepared_decision)(root,config,task,
        gate=gate,artifact_sha256=artifact_sha256,source=source,prepared=prepared)
    if result.get("status")!="consumed" or not isinstance(result.get("record"),dict):
        raise SystemExit("provider-owned human decision approval is not consumed and active")
    return result["record"]


def reverify(root: Path, config: Dict[str, object], task: Dict[str, object], *, gate: str, artifact_sha256: str, source: str, record: object) -> bool:
    if not isinstance(record, dict) or not isinstance(record.get("path"), str):
        return False
    try:
        return record == verify(
            root, config, task, gate=gate, artifact_sha256=artifact_sha256,
            source=source, receipt=str(record["path"]), require_fresh=False, consume=False,
        )
    except (SystemExit, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return False


def record_decision_approval(
    root: Path, config: Dict[str, object], task: Dict[str, object], *,
    gate: str, artifact_sha256: str, source: str, receipt: Optional[str] = None,
) -> Dict[str, object]:
    """Record authoritative gate approval under the stored decision policy.

    Provider policy requires a receipt for the exact gate and artifact. Local
    policy is deliberately advisory-only and therefore cannot produce a gate
    approval record.
    """
    if task.get("decision_policy_version") != PROVIDER_POLICY_VERSION:
        # Legacy/current-chat labels may be retained by callers as advisory
        # context, but no non-provider policy can authorize a gate.
        raise SystemExit(
            f"gate {gate} requires provider policy 1; local user-message evidence is advisory only"
        )
    if not receipt:
        raise SystemExit(f"gate {gate} approval requires a provider-signed human decision receipt")
    return verify(root, config, task, gate=gate, artifact_sha256=artifact_sha256, source=source, receipt=receipt)


def decision_approval_valid(
    root: Path, config: Dict[str, object], task: Dict[str, object], *,
    gate: str, artifact_sha256: str, source: str, record: object,
) -> bool:
    """Re-validate provider authority; local advisory records always fail closed."""
    version = task.get("decision_policy_version")
    if version == LOCAL_POLICY_VERSION:
        return False
    if version == PROVIDER_POLICY_VERSION:
        return reverify(root, config, task, gate=gate, artifact_sha256=artifact_sha256, source=source, record=record)
    return False
