#!/usr/bin/env python3
"""Bounded self-suite entry across isolated install contexts.

The default run covers idle-source. --full covers idle-source, polluted-source,
and installed-project. --context selects one or more contexts, which lets CI
parallelize context x shard without dropping coverage. Every child receives a
minimal environment and a private HOME/XDG/Git/Python cache root.
"""

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid


SELF_TESTS = (
    ".agent/scripts/self_test_adaptive_workflow.py",
    ".agent/scripts/self_test_budget_context_gates.py",
    ".agent/scripts/self_test_control_gates.py",
    ".agent/scripts/self_test_security_control_plane.py",
    ".agent/scripts/self_test_schema_contracts.py",
    ".agent/scripts/self_test_evidence_retention.py",
    ".agent/scripts/self_test_hardening_core.py",
    ".agent/scripts/self_test_local_decision_archive.py",
    ".agent/scripts/self_test_neutrality_contracts.py",
    ".agent/scripts/self_test_plugin_install_lifecycle.py",
    ".agent/scripts/self_test_runner_trust.py",
    ".agent/scripts/self_test_template_lifecycle.py",
    ".agent/scripts/self_test_templatectl.py",
    ".agent/skills/deliver-environments/scripts/self_test_delivery.py",
    ".agent/skills/deliver-environments/scripts/self_test_delivery_migration.py",
    ".agent/skills/manage-agent-team/scripts/self_test_agentledger.py",
    ".agent/skills/manage-local-runtime/scripts/self_test_docker_http.py",
    ".agent/skills/manage-local-runtime/scripts/self_test_managed_run.py",
    ".agent/skills/manage-task-context/scripts/self_test_context.py",
    ".agent/skills/run-ai-coding-pipeline/scripts/self_test_stage_index.py",
    ".agent/skills/run-ai-coding-pipeline/scripts/self_test_workflow.py",
    ".agent/skills/run-full-chain-acceptance/scripts/self_test_acceptance_runtime.py",
    ".agent/skills/run-full-chain-acceptance/scripts/self_test_gate.py",
    ".agent/skills/run-full-chain-acceptance/scripts/self_test_product_fingerprint.py",
    ".agent/skills/run-full-chain-acceptance/scripts/self_test_workflow_release_gate.py",
)

DARWIN_PROCESS_OBSERVER_TESTS = {
    ".agent/scripts/self_test_adaptive_workflow.py",
    ".agent/scripts/self_test_security_control_plane.py",
    ".agent/scripts/self_test_runner_trust.py",
    ".agent/skills/manage-local-runtime/scripts/self_test_managed_run.py",
    "ci-hardening",
}

SELF_TEST_ARGUMENTS = {
    ".agent/scripts/self_test_template_lifecycle.py": ("--template-root", "."),
}

ALL_CONTEXTS = ("idle-source", "polluted-source", "installed-project")
DEFAULT_CONTEXTS = ("idle-source",)
SKIP_EXIT_CODE = 77
TERM_GRACE_SECONDS = 1.0
MAX_CAPTURE_BYTES = 12000
ROOT_DOCUMENTATION_FILES = {
    "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md", "LICENSE", "LICENSE.txt",
}
SAFE_HOST_ENVIRONMENT = (
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
    "LANG", "LC_ALL", "LC_CTYPE", "TZ",
)

SOURCE_CHECKS = (
    ("ci-hardening", ("tests/test_ci_hardening.py",)),
    ("freshness", ("tests/check_freshness.py",)),
    ("install-lifecycle", ("tests/test_install_lifecycle.py", "--template-root", ".")),
    ("pxpipe-global-retirement", ("tests/test_pxpipe_global_retirement.py",)),
    ("pxpipe-integrity", ("plugins/pxpipe-context/scripts/verify-integrity.mjs", "--allow-quarantined")),
    ("pxpipe-self-test", ("plugins/pxpipe-context/scripts/self-test.mjs",)),
    ("pxpipe-dashboard-auth", ("plugins/pxpipe-context/scripts/dashboard-auth-self-test.mjs",)),
    ("pxpipe-provider-integration", ("plugins/pxpipe-context/scripts/provider-integration-self-test.mjs",)),
)


class RunFailure(RuntimeError):
    def __init__(self, record):
        super().__init__(json.dumps(record, ensure_ascii=False))
        self.record = record


def output_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def safe_label(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "-" for char in value)[-80:] or "check"


ORIGINAL_TOOL_PATH=os.environ.get("PATH","")

TRUSTED_TOOL_NAMES=(
    "awk","bash","basename","cat","chmod","cp","curl","cut","date","dirname","docker","env","find","git","grep","head","id",
    "kill","launchctl","ln","lsof","mkdir","mktemp","mv","node","openssl","printf","ps","pwd","python3","readlink","rm",
    "sed","sh","sleep","sort","stat","tail","tee","touch","tr","uname","wc","xargs",
)


def trusted_absolute_tool(requested):
    try: resolved=Path(requested).resolve(strict=True)
    except OSError: return None
    try:
        metadata=os.lstat(resolved)
        if not metadata.st_mode&0o111 or not resolved.is_file() or resolved.is_symlink(): return None
        current=Path(resolved.anchor)
        for component in resolved.parts[1:]:
            current=current/component; observed=os.lstat(current)
            if observed.st_uid not in {0,os.geteuid()} or observed.st_mode&0o022: return None
    except OSError: return None
    return resolved


def trusted_tool_path(name):
    directories=[]
    # The CI-selected PATH is the toolchain authority (setup-node/.ci-bin).
    # Each selected executable still must pass owner-chain checks and digest sealing.
    for value in (ORIGINAL_TOOL_PATH,os.defpath):
        for item in value.split(os.pathsep):
            if item and item not in directories: directories.append(item)
    for directory in directories:
        candidate=Path(directory)/name
        if candidate.exists() or candidate.is_symlink():
            resolved=trusted_absolute_tool(candidate)
            if resolved is not None: return resolved
    return None


TOOL_SEALS=None
TOOL_SEAL_LOCK=threading.Lock()
MAX_TOOL_BYTES=256*1024*1024


def bounded_file_sha256(path,maximum=MAX_TOOL_BYTES):
    digest=hashlib.sha256(); size=0
    descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:
        while True:
            chunk=os.read(descriptor,65536)
            if not chunk: break
            size+=len(chunk)
            if size>maximum: raise RuntimeError(f"trusted tool exceeds its byte limit: {path}")
            digest.update(chunk)
    finally: os.close(descriptor)
    return digest.hexdigest()


def seal_tool(path):
    metadata=os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode): raise RuntimeError(f"trusted tool is not regular: {path}")
    return {"path":str(path),"dev":metadata.st_dev,"ino":metadata.st_ino,"size":metadata.st_size,
            "mode":stat.S_IFMT(metadata.st_mode),"uid":metadata.st_uid,"nlink":metadata.st_nlink,
            "mtime_ns":metadata.st_mtime_ns,"ctime_ns":metadata.st_ctime_ns,"sha256":bounded_file_sha256(path)}


def tool_is_os_protected(path):
    if os.geteuid()==0: return False
    current=Path(path.anchor)
    try:
        for component in path.parts[1:]:
            current=current/component; observed=os.lstat(current)
            if observed.st_uid!=0 or observed.st_mode&0o022: return False
    except OSError: return False
    return True


def initialize_tool_seals():
    global TOOL_SEALS
    if TOOL_SEALS is not None: return TOOL_SEALS
    with TOOL_SEAL_LOCK:
        if TOOL_SEALS is not None: return TOOL_SEALS
        seals={}
        for name in TRUSTED_TOOL_NAMES:
            resolved=trusted_tool_path(name)
            if resolved is not None: seals[name]=seal_tool(resolved)
        canonical_python=trusted_absolute_tool(sys.executable)
        if canonical_python is None: raise RuntimeError("current Python interpreter is not owner-controlled")
        python_seal=seal_tool(canonical_python); seals["python"]=python_seal; seals["python3"]=python_seal
        TOOL_SEALS=seals
    return TOOL_SEALS


def revalidate_tool_seal(seal,with_digest=False):
    observed=os.lstat(seal["path"])
    current=(observed.st_dev,observed.st_ino,observed.st_size,stat.S_IFMT(observed.st_mode),observed.st_uid,
             observed.st_nlink,observed.st_mtime_ns,observed.st_ctime_ns)
    expected=tuple(seal[key] for key in ("dev","ino","size","mode","uid","nlink","mtime_ns","ctime_ns"))
    if current!=expected or not stat.S_ISREG(observed.st_mode): raise RuntimeError(f"trusted tool identity changed: {seal['path']}")
    if with_digest and bounded_file_sha256(seal["path"])!=seal["sha256"]:
        raise RuntimeError(f"trusted tool content changed: {seal['path']}")


def private_tool_launcher(name,seal,python_path):
    return f'''#!{python_path}
import hashlib,os,stat,sys,tempfile
SOURCE={seal["path"]!r}
EXPECTED={seal!r}
LIMIT={MAX_TOOL_BYTES}
root=os.path.dirname(os.path.abspath(sys.argv[0])); cache=os.path.join(root,".sealed-{name}")
def metadata_ok(value):
 return (value.st_dev,value.st_ino,value.st_size,stat.S_IFMT(value.st_mode),value.st_uid,value.st_nlink,value.st_mtime_ns,value.st_ctime_ns)==tuple(EXPECTED[key] for key in ("dev","ino","size","mode","uid","nlink","mtime_ns","ctime_ns")) and stat.S_ISREG(value.st_mode)
if not os.path.exists(cache):
 source=os.open(SOURCE,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); before=os.fstat(source)
 if not metadata_ok(before): raise SystemExit("sealed tool identity changed before copy")
 temporary_descriptor,temporary=tempfile.mkstemp(prefix=".tool-copy-",dir=root); digest=hashlib.sha256(); size=0
 try:
  os.fchmod(temporary_descriptor,0o500)
  while True:
   chunk=os.read(source,65536)
   if not chunk: break
   size+=len(chunk)
   if size>LIMIT: raise RuntimeError("sealed tool exceeds copy limit")
   digest.update(chunk); os.write(temporary_descriptor,chunk)
  os.fsync(temporary_descriptor)
  if not metadata_ok(os.fstat(source)) or digest.hexdigest()!=EXPECTED["sha256"]: raise RuntimeError("sealed tool changed during copy")
  os.replace(temporary,cache); temporary=None
 finally:
  os.close(source); os.close(temporary_descriptor)
  if temporary is not None:
   try: os.unlink(temporary)
   except FileNotFoundError: pass
os.execve(cache,[SOURCE,*sys.argv[1:]],os.environ)
'''


def private_tool_path(root):
    directory=root/"tools"; directory.mkdir(mode=0o700,exist_ok=True)
    seals=initialize_tool_seals(); python_path=seals["python3"]["path"]
    for name,seal in sorted(seals.items()):
        target=directory/name
        if target.exists() or target.is_symlink(): continue
        revalidate_tool_seal(seal,with_digest=tool_is_os_protected(Path(seal["path"])))
        if tool_is_os_protected(Path(seal["path"])):
            target.symlink_to(seal["path"])
        else:
            target.write_text(private_tool_launcher(name,seal,python_path),encoding="utf-8"); target.chmod(0o500)
    return directory


def child_environment(root: Path) -> dict:
    """Return a minimal environment with no inherited credentials or trust roots."""
    root.mkdir(parents=True, exist_ok=True)
    home = root / "home"
    config = root / "xdg-config"
    cache = root / "xdg-cache"
    data = root / "xdg-data"
    pycache = root / "pycache"
    temp = root / "tmp"
    for path in (home, config, cache, data, pycache, temp):
        path.mkdir(parents=True, exist_ok=True)
    env={key:os.environ[key] for key in SAFE_HOST_ENVIRONMENT if os.environ.get(key)}
    env["PATH"]=str(private_tool_path(root))
    env.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(config),
        "XDG_CACHE_HOME": str(cache),
        "XDG_DATA_HOME": str(data),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": str(pycache),
        "TMPDIR": str(temp),
        "TMP": str(temp),
        "TEMP": str(temp),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "Agent Workflow Self-Test",
        "GIT_AUTHOR_EMAIL": "self-test@example.invalid",
        "GIT_COMMITTER_NAME": "Agent Workflow Self-Test",
        "GIT_COMMITTER_EMAIL": "self-test@example.invalid",
        "NO_COLOR": "1",
    })
    return env


_SUPERVISED_RUNTIME=None


def supervised_runtime():
    """Load the exact staged identity-aware lifecycle implementation lazily."""
    global _SUPERVISED_RUNTIME
    expected=(Path(__file__).resolve().parents[1]/".agent/scripts/testrun.py").resolve()
    scripts=str(expected.parent)
    if scripts not in sys.path: sys.path.insert(0,scripts)
    if _SUPERVISED_RUNTIME is None:
        import testrun as runtime
        if Path(runtime.__file__).resolve()!=expected:
            raise RuntimeError("protected runner loaded a non-staged lifecycle implementation")
        _SUPERVISED_RUNTIME=runtime
    return _SUPERVISED_RUNTIME


def process_snapshot():
    snapshot=supervised_runtime().process_snapshot()
    if snapshot is None: raise RuntimeError("protected process identity observation is unavailable")
    return snapshot


def process_group_exists(group_id: int) -> bool:
    return any(group==group_id and not state.startswith("Z")
               for _pid,(_parent,group,_identity,state) in process_snapshot().items())


def discover_descendants(root_pid,known):
    snapshot=process_snapshot()
    if not supervised_runtime().discover_descendants(root_pid,known,snapshot):
        raise RuntimeError("protected descendant identity observation is unavailable")
    return snapshot


def terminate_process_group(process,seed_known=None,launch_token=None) -> None:
    """Terminate only twice-observed PID/start identities attributable to this launch."""
    cleaned,uncertain=supervised_runtime().terminate_process_tree(
        process,dict(seed_known or {}),grace=TERM_GRACE_SECONDS,launch_token=launch_token)
    if not cleaned or uncertain:
        raise RuntimeError("protected test process cleanup could not be identity-bound")


def decode_bounded_tail(data: bytes, maximum=MAX_CAPTURE_BYTES) -> str:
    """Decode a raw tail while keeping its UTF-8 representation byte-bounded."""
    text = data[-maximum:].decode("utf-8", errors="replace")
    if len(text.encode("utf-8")) <= maximum:
        return text
    low, high = 0, len(text)
    while low < high:
        middle = (low + high) // 2
        if len(text[middle:].encode("utf-8")) <= maximum:
            high = middle
        else:
            low = middle + 1
    return text[low:]


def run(command, cwd, timeout=900, expected=(0,), label=None):
    """Run one command with isolated state while streaming bounded progress."""
    started = time.monotonic()
    requested_command=list(command)
    display = safe_label(label or Path(str(requested_command[0])).name)
    print(f"[{display}] START", flush=True)
    with tempfile.TemporaryDirectory(prefix=f"agent-workflow-{display}-") as raw_env:
        env = child_environment(Path(raw_env)); launch_command=list(requested_command)
        runtime=supervised_runtime(); launch_token=uuid.uuid4().hex
        env[runtime.LAUNCH_TOKEN_NAME]=launch_token
        try: requested_executable=Path(str(launch_command[0])).resolve(strict=True)
        except OSError: requested_executable=None
        canonical_python=Path(initialize_tool_seals()["python3"]["path"])
        if requested_executable==canonical_python:
            launch_command[0]=str(Path(env["PATH"])/"python3")
        if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
            raise RuntimeError("protected runner requires default SIGCHLD ownership for unreaped PID binding")
        process = subprocess.Popen(
            launch_command, cwd=str(cwd), env=env, start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
        )
        output_parts = deque(maxlen=3)
        output_bytes = 0

        def consume_output():
            nonlocal output_bytes
            assert process.stdout is not None
            while True:
                chunk = process.stdout.read(4096)
                if not chunk:
                    break
                output_bytes += len(chunk)
                output_parts.append(chunk)

        reader=None; known_descendants={}
        try:
            reader=threading.Thread(target=consume_output,name=f"output-{display}",daemon=True)
            reader.start()
            initial_snapshot=discover_descendants(process.pid,known_descendants)
            leader=initial_snapshot.get(process.pid); leader_identity=leader[2] if leader is not None else None
            if leader_identity is not None: known_descendants[process.pid]=leader_identity
            timed_out=False; residual=False; cleanup_failed=False
            deadline=time.monotonic()+timeout
            while True:
                snapshot=discover_descendants(process.pid,known_descendants)
                leader=snapshot.get(process.pid)
                if leader is not None:
                    if leader_identity is None:
                        leader_identity=leader[2]; known_descendants[process.pid]=leader_identity
                    elif leader[2]!=leader_identity:
                        cleanup_failed=True; residual=True
                        break
                # Darwin libproc can hide an exited child before wait(); the PID remains
                # unreusable because this runner has deliberately not polled or reaped it.
                if leader is None or leader[3].startswith("Z"): break
                if time.monotonic()>=deadline:
                    timed_out=True; break
                time.sleep(0.05)
            if timed_out:
                print(f"[{display}] TIMEOUT after {timeout}s; terminating launch identities",flush=True)
                try: terminate_process_group(process,known_descendants,launch_token)
                except RuntimeError: cleanup_failed=True
            else:
                if not runtime.merge_launch_identities(known_descendants,launch_token): cleanup_failed=True
                snapshot=discover_descendants(process.pid,known_descendants)
                live_descendants={pid:identity for pid,identity in known_descendants.items()
                                  if pid!=process.pid and pid in snapshot
                                  and snapshot[pid][2]==identity and not snapshot[pid][3].startswith("Z")}
                session_live={pid for pid,(_parent,group,_identity,state) in snapshot.items()
                              if pid!=process.pid and group==process.pid and not state.startswith("Z")}
                if live_descendants or session_live or cleanup_failed:
                    residual=True
                    print(f"[{display}] RESIDUAL descendants={sorted(set(live_descendants)|session_live)}; terminating and failing",flush=True)
                    try: terminate_process_group(process,known_descendants,launch_token)
                    except RuntimeError: cleanup_failed=True
                else:
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        residual=True; cleanup_failed=True
            reader.join(timeout=5)
            if reader.is_alive():
                residual=True; cleanup_failed=True
                if process.stdout is not None: process.stdout.close()
                reader.join(timeout=2)
            if process.stdout is not None and not process.stdout.closed:
                process.stdout.close()
            if process.returncode is None:
                try: process.wait(timeout=1)
                except subprocess.TimeoutExpired: cleanup_failed=True
            exit_code=124 if timed_out and not cleanup_failed else (125 if residual or cleanup_failed else int(process.returncode))
            if residual or cleanup_failed: output_parts.append(b"test left live or unattributed descendant processes; identity-scoped cleanup failed closed\n")
            output = decode_bounded_tail(b"".join(output_parts))
        except BaseException:
            try: terminate_process_group(process,known_descendants,launch_token)
            except BaseException: pass
            if process.stdout is not None and not process.stdout.closed:
                try: process.stdout.close()
                except OSError: pass
            if reader is not None: reader.join(timeout=2)
            raise
    elapsed = round(time.monotonic() - started, 3)
    print(f"[{display}] END exit={exit_code} seconds={elapsed:.3f}", flush=True)
    record = {
        "command": requested_command,
        "cwd": str(cwd),
        "exit_code": exit_code,
        "seconds": elapsed,
        "output_bytes": output_bytes,
        "output_truncated": output_bytes > MAX_CAPTURE_BYTES,
        "output": output,
    }
    if exit_code not in expected:
        raise RunFailure(record)
    return record


def execute(name, command, cwd, timeout):
    """Run one check, preserving an explicit skip instead of calling it pass."""
    try:
        record = run(command, cwd, timeout=timeout, expected=(0, SKIP_EXIT_CODE), label=name)
        status = "skip" if record["exit_code"] == SKIP_EXIT_CODE else "pass"
        return {"name": name, "status": status, **record}
    except RunFailure as error:
        status = "timeout" if error.record["exit_code"] == 124 else "fail"
        return {"name": name, "status": status, **error.record}


MAX_INDEX_BYTES=4*1024*1024
MAX_INDEX_PATHS=10000
MAX_FIXTURE_FILE_BYTES=32*1024*1024
MAX_FIXTURE_TOTAL_BYTES=512*1024*1024


def staged_entries(source: Path) -> list:
    """Return exact stage-0 regular-file identities from the Git index."""
    with tempfile.TemporaryDirectory(prefix="agent-workflow-git-env-") as raw_env:
        result=subprocess.Popen(
            ["git","ls-files","-z","--stage"],cwd=source,
            env=child_environment(Path(raw_env)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        )
        output=result.stdout.read(MAX_INDEX_BYTES+1) if result.stdout is not None else b""
        if len(output)>MAX_INDEX_BYTES:
            terminate_process_group(result); raise RuntimeError("Git index inventory exceeds its byte limit")
        stderr=result.stderr.read(MAX_CAPTURE_BYTES+1) if result.stderr is not None else b""
        if result.stdout is not None: result.stdout.close()
        if result.stderr is not None: result.stderr.close()
        status=result.wait()
    if status!=0: raise RuntimeError(f"Git index inventory failed: {decode_bounded_tail(stderr)}")
    entries=[]
    for raw in output.split(b"\0"):
        if not raw: continue
        try: header,path_raw=raw.split(b"\t",1); mode_raw,oid_raw,stage_raw=header.split(b" ",2)
        except ValueError as error: raise RuntimeError("Git index inventory record is malformed") from error
        try:
            mode=mode_raw.decode("ascii"); oid=oid_raw.decode("ascii"); stage=stage_raw.decode("ascii"); text=path_raw.decode("utf-8","strict")
        except UnicodeError as error: raise RuntimeError("Git index inventory is not canonical UTF-8/ASCII") from error
        relative=PurePosixPath(text)
        if relative.is_absolute() or any(part in {"",".",".."} for part in relative.parts):
            raise RuntimeError(f"unsafe staged path: {text!r}")
        if stage!="0": raise RuntimeError(f"unmerged staged Git entry: {text!r}")
        if mode not in {"100644","100755"}: raise RuntimeError(f"unsupported staged Git mode {mode!r}: {text!r}")
        if not oid or any(char not in "0123456789abcdef" for char in oid):
            raise RuntimeError(f"invalid staged Git object identity: {text!r}")
        entries.append((Path(*relative.parts),mode,oid))
        if len(entries)>MAX_INDEX_PATHS: raise RuntimeError("Git index inventory exceeds its path limit")
    if len({relative.as_posix() for relative,_mode,_oid in entries})!=len(entries):
        raise RuntimeError("Git index inventory contains duplicate paths")
    return sorted(entries,key=lambda item:item[0].as_posix())


def staged_index_digest(entries) -> str:
    inventory=[[relative.as_posix(),mode,oid] for relative,mode,oid in entries]
    return hashlib.sha256(json.dumps(inventory,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()


def materialize_staged_tree(source: Path,target: Path,entries=None) -> None:
    target.mkdir(mode=0o700,parents=True,exist_ok=False); total=0
    entries=staged_entries(source) if entries is None else entries
    raw_git_env=tempfile.mkdtemp(prefix="agent-workflow-git-materialize-")
    try:
        git_env=child_environment(Path(raw_git_env))
        for relative,mode,oid in entries:
            destination=target/relative; destination.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
            descriptor=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
            process=subprocess.Popen(["git","cat-file","blob",oid],cwd=source,env=git_env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            digest=hashlib.sha256(); size=0
            try:
                with os.fdopen(descriptor,"wb") as handle:
                    while True:
                        chunk=process.stdout.read(65536) if process.stdout is not None else b""
                        if not chunk: break
                        size+=len(chunk); total+=len(chunk)
                        if size>MAX_FIXTURE_FILE_BYTES or total>MAX_FIXTURE_TOTAL_BYTES:
                            terminate_process_group(process); raise RuntimeError("staged fixture content exceeds its byte limits")
                        digest.update(chunk); handle.write(chunk)
                    handle.flush(); os.fsync(handle.fileno())
                stderr=process.stderr.read(MAX_CAPTURE_BYTES+1) if process.stderr is not None else b""
                if process.wait()!=0: raise RuntimeError(f"staged Git blob materialization failed: {decode_bounded_tail(stderr)}")
                # Git validates the opaque object id while streaming the blob;
                # repositories may use SHA-1 or SHA-256 object formats.
                digest.hexdigest()
                os.chmod(destination,0o755 if mode=="100755" else 0o644)
            finally:
                if process.returncode is None: terminate_process_group(process)
                if process.stdout is not None: process.stdout.close()
                if process.stderr is not None: process.stderr.close()
        private_nonce=target/".agent/state/.scheduler-receipt-nonces.json"
        if private_nonce.is_file(): private_nonce.chmod(0o600)
    except Exception:
        shutil.rmtree(target,ignore_errors=True); raise
    finally: shutil.rmtree(raw_git_env,ignore_errors=True)


def staged_tree_digest(root: Path,entries) -> str:
    expected={relative.as_posix():(mode,oid) for relative,mode,oid in entries}
    observed={}
    for candidate in root.rglob("*"):
        metadata=os.lstat(candidate)
        if stat.S_ISDIR(metadata.st_mode): continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1:
            raise RuntimeError("staged materialization contains a non-regular file")
        relative=candidate.relative_to(root).as_posix(); mode="100755" if metadata.st_mode&0o111 else "100644"
        if relative not in expected or mode!=expected[relative][0]:
            raise RuntimeError(f"staged materialization mode/path differs from index: {relative}")
        observed[relative]=[mode,metadata.st_size,bounded_file_sha256(candidate)]
    if set(observed)!=set(expected): raise RuntimeError("staged materialization file set differs from Git index")
    return hashlib.sha256(json.dumps([[name,*observed[name]] for name in sorted(observed)],separators=(",",":"),ensure_ascii=False).encode()).hexdigest()


def untracked_fixture_inputs(source: Path) -> list:
    """Return non-ignored untracked inputs that a fixture would silently omit."""
    with tempfile.TemporaryDirectory(prefix="agent-workflow-git-env-") as raw_env:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--others", "--exclude-standard"], cwd=source,
            env=child_environment(Path(raw_env)),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
    roots = {".agent", "plugins", "tests"}
    candidates = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        text = raw.decode("utf-8", errors="strict")
        relative = PurePosixPath(text)
        is_root_fixture_input = len(relative.parts) == 1 and text not in ROOT_DOCUMENTATION_FILES
        if relative.parts and (relative.parts[0] in roots or is_root_fixture_input):
            candidates.append(text)
    return sorted(candidates)


def copy_project_without_agent(source: Path,target: Path,staged=False) -> None:
    if not staged:
        if not (source/".git").is_dir(): raise RuntimeError("fixture source must be a Git worktree or an explicitly staged snapshot")
        omitted=untracked_fixture_inputs(source)
        if omitted:
            raise RuntimeError("fixture would omit non-ignored untracked source files; stage or remove them first: "+", ".join(omitted))
        with tempfile.TemporaryDirectory(prefix="agent-workflow-project-stage-") as raw:
            snapshot=Path(raw)/"source"; materialize_staged_tree(source,snapshot)
            copy_project_without_agent(snapshot,target,staged=True)
        return
    target.mkdir(mode=0o755,parents=True,exist_ok=False)
    for candidate in sorted(source.rglob("*")):
        relative=candidate.relative_to(source)
        if not relative.parts or relative.parts[0] in {".agent",".git",".idea","outputs"}: continue
        if relative.parts[:2] == ("plugins", "pxpipe-context"): continue
        metadata=os.lstat(candidate)
        if stat.S_ISDIR(metadata.st_mode):
            (target/relative).mkdir(mode=0o755,parents=True,exist_ok=True); continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1:
            raise RuntimeError(f"staged fixture input must be one regular file: {relative.as_posix()}")
        destination=target/relative; destination.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        shutil.copyfile(candidate,destination); destination.chmod(0o755 if metadata.st_mode&0o111 else 0o644)


def guardrails(path: Path) -> None:
    path.write_text("""# Project Guardrails

## Required project facts
- Product and users: Disposable full-suite fixture for workflow maintainers.
- Technology and architecture: Python, JSON, Markdown, and optional Node.js plugin controls.
- Writable and read-only areas: The temporary fixture is writable and the source template is read-only.
- Security, privacy, compliance and performance red lines: No credentials, network, deployment, or external effects.
- Build, test and lint commands: Run tests/run_all.py with bounded subprocess timeouts.
- Deployment authority and rollback owner: Deployment is forbidden and the fixture owner controls rollback.

## Universal project constraints
- Remain local, bounded, reversible, isolated, and zero-residual.
""", encoding="utf-8")


def make_context(source: Path, workspace: Path, name: str) -> Path:
    target = workspace / name
    copy_project_without_agent(source,target,staged=True)
    run(
        [sys.executable, str(source / "install.py"), str(target), "--project-name", name],
        source, label=f"install-{name}",
    )
    if name == "polluted-source":
        evidence = target / ".agent/state/evidence/polluted"
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "sentinel.txt").write_text("PRIVATE_SOURCE_POLLUTION\n", encoding="utf-8")
        return target
    if name == "installed-project":
        policy = target / "fixture-guardrails.md"
        guardrails(policy)
        run(
            [sys.executable, ".agent/scripts/agentctl.py", "project-init", "--guardrails-file", policy.name],
            target, label=f"project-init-{name}",
        )
    return target


def assert_self_test_inventory(root: Path) -> None:
    discovered = {
        path.relative_to(root).as_posix()
        for path in root.glob(".agent/**/self_test_*.py")
    }
    expected = set(SELF_TESTS)
    if discovered != expected:
        raise RuntimeError(json.dumps({
            "error": "Python self-test inventory drift",
            "root": str(root),
            "missing": sorted(expected - discovered),
            "unexpected": sorted(discovered - expected),
        }, ensure_ascii=False))


def self_test_command(relative: str):
    return [sys.executable, relative, *SELF_TEST_ARGUMENTS.get(relative, ())]


def source_check_command(entry):
    name, arguments = entry
    if arguments[0].endswith(".py"):
        return name, [sys.executable, *arguments]
    return name, ["node", *arguments]


def source_runtime_control_command():
    script="""
import subprocess,sys
commands=(
    ("capture-runtime-baseline","capture-runtime-baseline","--source","user:full-suite-source-control","--confirm-existing-processes"),
    ("cleanup","cleanup"),
    ("assert-clean","assert-clean"),
)
for label,*arguments in commands:
    result=subprocess.run([sys.executable,".agent/scripts/agentctl.py",*arguments],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
    if result.returncode:
        print(f"{label} failed\\n{result.stdout}")
        raise SystemExit(result.returncode)
print("SOURCE RUNTIME CONTROL PASS")
"""
    return [sys.executable,"-c",script]


def parse_shard(text: str):
    try:
        k_text, n_text = text.split("/", 1)
        k, n = int(k_text), int(n_text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid shard {text!r}: expected K/N with integer K and N")
    if n < 1 or not 1 <= k <= n:
        raise argparse.ArgumentTypeError(f"invalid shard {text!r}: expected 1 <= K <= N")
    return (k, n)


def resolve_only(names) -> list:
    by_basename = {}
    for relative in SELF_TESTS:
        by_basename.setdefault(Path(relative).name, relative)
        by_basename.setdefault(Path(relative).stem, relative)
    wanted = set()
    unknown = []
    for name in names:
        if name in SELF_TESTS:
            wanted.add(name)
        elif name in by_basename:
            wanted.add(by_basename[name])
        else:
            unknown.append(name)
    if unknown:
        raise SystemExit(
            "unknown self-test name(s): {}\nregistered tests:\n  {}".format(
                ", ".join(unknown), "\n  ".join(SELF_TESTS),
            )
        )
    return [relative for relative in SELF_TESTS if relative in wanted]


def select_tests(shard, only) -> list:
    tests = list(SELF_TESTS)
    if shard:
        k, n = shard
        tests = [test for index, test in enumerate(tests) if index % n == k - 1]
    if only:
        wanted = set(resolve_only(only))
        tests = [test for test in tests if test in wanted]
    return tests


def run_batch(context,items,cwd,timeout,jobs,isolate=False):
    """Run deterministically; concurrent mutators receive private context copies."""
    with tempfile.TemporaryDirectory(prefix=f"agent-workflow-batch-{safe_label(context)}-") as raw:
        executions=[]
        for index,(name,command) in enumerate(items):
            execution_root=cwd
            if isolate:
                execution_root=Path(raw)/str(index)
                shutil.copytree(cwd,execution_root,symlinks=False)
            executions.append((name,command,execution_root))
        # Darwin PID/start observation and individual signaling are intentionally
        # exercised without sibling matrix load, so lifecycle evidence stays isolated.
        exclusive=({name for name,_command,_root in executions} if sys.platform.startswith("darwin") else set())
        parallel=[(index,item) for index,item in enumerate(executions) if item[0] not in exclusive]
        serial=[(index,item) for index,item in enumerate(executions) if item[0] in exclusive]
        indexed={}
        with ThreadPoolExecutor(max_workers=max(1,jobs)) as pool:
            futures=[(index,pool.submit(execute,name,command,execution_root,timeout))
                     for index,(name,command,execution_root) in parallel]
            for index,future in futures: indexed[index]=future.result()
        # Never create sibling matrix processes while Darwin lifecycle observers run.
        for index,(name,command,execution_root) in serial:
            indexed[index]=execute(name,command,execution_root,timeout)
        results=[indexed[index] for index in range(len(executions))]
    for result in results: result["context"]=context
    return results


def print_failures(records) -> None:
    for record in records:
        if record["status"] in {"pass", "skip"}:
            continue
        print(
            f"--- FAIL {record['context']} :: {record['name']} "
            f"({record['status']}, exit={record['exit_code']}, {record['seconds']:.1f}s) ---"
        )
        tail = output_text(record.get("output"))[-4000:]
        if tail.strip():
            print(tail)
        print("---")


def classify_skips(records, allowed_skips):
    allowed = set(allowed_skips)
    for record in records:
        if record["status"] == "skip":
            record["skip_disposition"] = "allowed-n/a" if record["name"] in allowed else "unapproved"


def result_counts(records, fail_on_skip=False):
    counts = {status: sum(record["status"] == status for record in records) for status in ("pass", "skip", "fail", "timeout")}
    counts["allowed_skip"] = sum(
        record["status"] == "skip" and record.get("skip_disposition") == "allowed-n/a" for record in records
    )
    counts["unapproved_skip"] = counts["skip"] - counts["allowed_skip"]
    failures = counts["fail"] + counts["timeout"] + (counts["unapproved_skip"] if fail_on_skip else 0)
    return counts, failures


def print_summary(records, wall_seconds, fail_on_skip=False) -> int:
    width = max((len(Path(record["name"]).name) for record in records), default=4)
    print("\ncontext            {:<{w}}  result   seconds".format("test", w=width))
    for record in records:
        print(
            "{:<18} {:<{w}}  {:<8} {:>7.1f}".format(
                record["context"], Path(record["name"]).name,
                record["status"], record["seconds"], w=width,
            )
        )
    counts, failures = result_counts(records, fail_on_skip=fail_on_skip)
    print(
        f"\ntotal={len(records)} passed={counts['pass']} skipped={counts['skip']} "
        f"allowed_n_a={counts['allowed_skip']} unapproved_skip={counts['unapproved_skip']} "
        f"failed={counts['fail']} timed_out={counts['timeout']} wall={wall_seconds:.1f}s"
    )
    if fail_on_skip and counts["unapproved_skip"]:
        print("required capability failure: --fail-on-skip rejects every skip not named by --allow-skip")
    return failures


def resolve_contexts(args):
    if args.full and args.context:
        raise SystemExit("--full and --context are mutually exclusive")
    if args.full:
        return ALL_CONTEXTS
    if args.context:
        return tuple(dict.fromkeys(args.context))
    return DEFAULT_CONTEXTS


def validate_required_commands(commands) -> None:
    missing=sorted(command for command in commands if trusted_tool_path(command) is None)
    if missing:
        raise SystemExit(f"required command(s) unavailable: {', '.join(missing)}")


def default_report_path(contexts, shard):
    context_label="-".join(contexts)
    shard_label=f"-shard-{shard[0]}-of-{shard[1]}" if shard else ""
    return Path("outputs")/f"full-suite-{context_label}{shard_label}.json"


@contextlib.contextmanager
def owned_staged_workspace(workspace):
    workspace=Path(workspace).resolve()
    temporary_root=Path(tempfile.gettempdir()).resolve()
    try: before=os.lstat(workspace)
    except OSError as error: raise RuntimeError("staged self-suite workspace is missing or unsafe") from error
    expected_uid=os.geteuid() if hasattr(os,"geteuid") else before.st_uid
    if (workspace.parent!=temporary_root or not workspace.name.startswith("agent-workflow-self-suite-")
            or not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid!=expected_uid or stat.S_IMODE(before.st_mode)!=0o700):
        raise RuntimeError("staged self-suite workspace ownership is invalid")
    flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)
    descriptor=os.open(workspace,flags)
    opened=os.fstat(descriptor)
    if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):
        os.close(descriptor)
        raise RuntimeError("staged self-suite workspace changed during ownership capture")
    try:
        yield str(workspace)
    finally:
        try: current=os.lstat(workspace)
        except OSError as error:
            os.close(descriptor)
            raise RuntimeError("staged self-suite workspace disappeared before cleanup") from error
        stable=(stat.S_ISDIR(current.st_mode) and not stat.S_ISLNK(current.st_mode)
                and (current.st_dev,current.st_ino)==(opened.st_dev,opened.st_ino)
                and current.st_uid==expected_uid)
        os.close(descriptor)
        if not stable:
            raise RuntimeError("staged self-suite workspace identity changed before cleanup")
        shutil.rmtree(workspace)


def staged_child_environment(workspace,staged_root,source,index_digest,tree_digest,launcher_digest,index_count,tool_path):
    """Build an allowlisted re-exec environment from already bound values only."""
    return {
        "PATH":tool_path,"LANG":"C","LC_ALL":"C","TZ":"UTC",
        "PYTHONDONTWRITEBYTECODE":"1","PYTHONNOUSERSITE":"1",
        "TMPDIR":str(workspace.parent),"TMP":str(workspace.parent),"TEMP":str(workspace.parent),
        "AGENT_RUN_ALL_STAGED_ROOT":str(staged_root),"AGENT_RUN_ALL_ORIGINAL_ROOT":str(source),
        "AGENT_RUN_ALL_INDEX_SHA256":index_digest,"AGENT_RUN_ALL_INDEX_COUNT":str(index_count),
        "AGENT_RUN_ALL_LAUNCHER_SHA256":launcher_digest,"AGENT_RUN_ALL_TREE_SHA256":tree_digest,
    }


def staged_reexec(source):
    if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
        raise RuntimeError("protected runner requires default SIGCHLD ownership before staged materialization")
    marker=os.environ.get("AGENT_RUN_ALL_STAGED_ROOT")
    if marker:
        staged_root=Path(marker).resolve(); original=Path(os.environ.get("AGENT_RUN_ALL_ORIGINAL_ROOT","")).resolve()
        launcher=(staged_root/"tests/run_all.py").resolve(); expected=os.environ.get("AGENT_RUN_ALL_LAUNCHER_SHA256","")
        index_sha=os.environ.get("AGENT_RUN_ALL_INDEX_SHA256",""); count=os.environ.get("AGENT_RUN_ALL_INDEX_COUNT",""); tree_sha=os.environ.get("AGENT_RUN_ALL_TREE_SHA256","")
        metadata=os.lstat(staged_root); launch_metadata=os.lstat(launcher)
        if (__file__ and Path(__file__).resolve()!=launcher or metadata.st_uid!=(os.geteuid() if hasattr(os,"geteuid") else metadata.st_uid)
                or stat.S_IMODE(metadata.st_mode)!=0o700 or not stat.S_ISREG(launch_metadata.st_mode)
                or bounded_file_sha256(launcher)!=expected or re.fullmatch(r"[0-9a-f]{64}",index_sha) is None
                or re.fullmatch(r"[0-9a-f]{64}",tree_sha) is None or not count.isdigit() or int(count)<1 or not original.is_dir()):
            raise RuntimeError("staged self-suite re-exec binding is invalid")
        entries=staged_entries(original)
        if len(entries)!=int(count) or staged_index_digest(entries)!=index_sha:
            raise RuntimeError("original Git index differs from staged self-suite binding")
        with tempfile.TemporaryDirectory(prefix="agent-workflow-staged-verifier-") as raw:
            verifier=Path(raw)/"source"; materialize_staged_tree(original,verifier,entries); expected_tree=staged_tree_digest(verifier,entries)
        if expected_tree!=tree_sha or staged_tree_digest(staged_root,entries)!=tree_sha:
            raise RuntimeError("staged self-suite bytes differ from the exact Git index objects")
        return staged_root,original,index_sha,expected,tree_sha,int(count),staged_root.parent
    omitted=untracked_fixture_inputs(source)
    if omitted: raise RuntimeError("fixture would omit non-ignored untracked source files; stage or remove them first: "+", ".join(omitted))
    workspace=Path(tempfile.mkdtemp(prefix="agent-workflow-self-suite-")); os.chmod(workspace,0o700)
    try:
        entries=staged_entries(source); index_sha=staged_index_digest(entries); staged_root=workspace/"staged-source"
        materialize_staged_tree(source,staged_root,entries); tree_sha=staged_tree_digest(staged_root,entries)
        if staged_index_digest(staged_entries(source))!=index_sha: raise RuntimeError("Git index changed during staged materialization")
        launcher=staged_root/"tests/run_all.py"; launcher_sha=bounded_file_sha256(launcher)
        seals=initialize_tool_seals(); tool_directories=[]
        for name in (*TRUSTED_TOOL_NAMES,"python3"):
            details=seals.get(name); directory=str(Path(details["path"]).parent) if details is not None else None
            if directory and directory not in tool_directories: tool_directories.append(directory)
        for directory in os.defpath.split(os.pathsep):
            if directory and directory not in tool_directories: tool_directories.append(directory)
        tool_path=os.pathsep.join(tool_directories)
        environment=staged_child_environment(
            workspace,staged_root,source,index_sha,tree_sha,launcher_sha,len(entries),tool_path)
        python=seals["python3"]["path"]
        os.execve(python,[python,str(launcher),*sys.argv[1:]],environment)
    except BaseException:
        shutil.rmtree(workspace,ignore_errors=True); raise
    raise RuntimeError("staged self-suite re-exec unexpectedly returned")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template-root", default=".")
    parser.add_argument("--report", default=None)
    parser.add_argument("--shard", type=parse_shard, default=None, metavar="K/N")
    parser.add_argument("--only", nargs="+", default=None, metavar="NAME")
    parser.add_argument("--test-timeout", type=int, default=300, metavar="SECONDS")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--context", action="append", choices=ALL_CONTEXTS)
    parser.add_argument("--require-command", action="append", default=[])
    parser.add_argument("--fail-on-skip", action="store_true")
    parser.add_argument("--allow-skip", action="append", default=[], choices=SELF_TESTS,
                        help="exact registered self-test that is an audited not-applicable case")
    parser.add_argument("-j", "--jobs", type=int, default=4, metavar="N")
    args = parser.parse_args()
    if args.test_timeout < 1 or args.jobs < 1:
        parser.error("--test-timeout and --jobs must be positive")

    contexts = resolve_contexts(args)
    validate_required_commands(args.require_command)
    if args.report is None:
        args.report = default_report_path(contexts, args.shard)

    started = time.monotonic()
    requested_source = Path(args.template_root).resolve()
    source,original_source,index_sha,launcher_sha,tree_sha,index_count,workspace_root=staged_reexec(requested_source)
    report = (original_source / args.report).resolve()
    tests = select_tests(args.shard, args.only)
    if not tests:
        raise SystemExit("self-test selection is empty; refusing green zero-test evidence")

    records = []
    with owned_staged_workspace(workspace_root) as raw:
        workspace = Path(raw)
        assert_self_test_inventory(source)
        for name in contexts:
            print(f"== context {name}: {len(tests)} self-tests (jobs={args.jobs}, timeout={args.test_timeout}s) ==", flush=True)
            try:
                context = make_context(source, workspace, name)
            except Exception as error:
                if isinstance(error, RunFailure):
                    detail = error.record
                else:
                    detail = {
                        "command": [], "cwd": str(source), "exit_code": 1,
                        "seconds": 0.0, "output": str(error),
                    }
                records.append({"context": name, "name": "install-context", "status": "fail", **detail})
                continue
            context_records = []
            baseline = execute(
                "capture-runtime-baseline",
                [sys.executable, ".agent/scripts/agentctl.py", "capture-runtime-baseline", "--source", "user:full-suite-controller"],
                context, timeout=60,
            )
            baseline["context"] = name
            context_records.append(baseline)
            try:
                assert_self_test_inventory(context)
            except RuntimeError as error:
                context_records.append({
                    "context": name, "name": "self-test-inventory", "status": "fail",
                    "command": [], "cwd": str(context), "exit_code": 1,
                    "seconds": 0.0, "output": str(error),
                })
            if name == "polluted-source":
                for control, command in (
                    ("agent-state-validation", [sys.executable, ".agent/scripts/agentctl.py", "validate"]),
                    ("context-validation", [sys.executable, ".agent/scripts/contextctl.py", "check"]),
                ):
                    row = execute(control, command, context, timeout=args.test_timeout)
                    row["context"] = name
                    context_records.append(row)
            context_records.extend(run_batch(
                name,
                [(relative, self_test_command(relative)) for relative in tests],
                context,timeout=args.test_timeout,jobs=args.jobs,isolate=True,
            ))
            for control, command in (
                ("cleanup", [sys.executable, ".agent/scripts/agentctl.py", "cleanup"]),
                ("assert-clean", [sys.executable, ".agent/scripts/agentctl.py", "assert-clean"]),
            ):
                row = execute(control, command, context, timeout=60)
                row["context"] = name
                context_records.append(row)
            print_failures(context_records)
            records.extend(context_records)

        source_checks_selected = args.shard is None or args.shard[0] == 1
        source_checks_owned = "idle-source" in contexts
        if source_checks_selected and source_checks_owned:
            print(f"== context source: {len(SOURCE_CHECKS)} source-level checks ==", flush=True)
            source_records = run_batch(
                "source", [source_check_command(entry) for entry in SOURCE_CHECKS],
                source,timeout=args.test_timeout,jobs=1,isolate=True,
            )
            source_records.extend(run_batch(
                "source", [("source-runtime-control", source_runtime_control_command())],
                source,timeout=180,jobs=1,isolate=True,
            ))
            print_failures(source_records)
            records.extend(source_records)

    wall_seconds = time.monotonic() - started
    classify_skips(records, args.allow_skip)
    failures = print_summary(records, wall_seconds, fail_on_skip=args.fail_on_skip)
    counts, _ = result_counts(records, fail_on_skip=args.fail_on_skip)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({
        "schema": "agent-workflow-full-suite/v3",
        "staged_index_sha256": index_sha,
        "staged_index_entries": index_count,
        "staged_launcher_sha256": launcher_sha,
        "staged_tree_sha256": tree_sha,
        "status": "failed" if failures else "passed",
        "contexts": list(contexts),
        "shard": f"{args.shard[0]}/{args.shard[1]}" if args.shard else None,
        "jobs": args.jobs,
        "test_timeout": args.test_timeout,
        "fail_on_skip": args.fail_on_skip,
        "allowed_skips": sorted(args.allow_skip),
        "required_commands": args.require_command,
        "counts": counts,
        "wall_seconds": round(wall_seconds, 3),
        "runs": records,
    }, ensure_ascii=False, indent=2) + "\n")
    try:
        display_report = report.relative_to(original_source)
    except ValueError:
        display_report = report
    if failures:
        print(f"SELF SUITE FAIL: failures={failures} runs={len(records)} report={display_report}")
        return 1
    print(f"SELF SUITE PASS: runs={len(records)} report={display_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
