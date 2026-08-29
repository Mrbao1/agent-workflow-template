#!/usr/bin/env python3
"""Hostile and race regressions for adaptive security authority."""
from pathlib import Path
from types import SimpleNamespace
import copy
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parents[1]
sys.path.insert(0, str(SCRIPTS))
import adaptive_common
import agentctl
import blueprintacceptance
import blueprintctl
import humandecision
import skillctl
import testrun as supervised_test
import workflowctl


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def process_is_live(pid):
    snapshot=blueprintacceptance.process_snapshot()
    if snapshot is not None:
        record=snapshot.get(pid)
        return record is not None and not str(record[2]).startswith("Z")
    try: os.kill(pid,0); return True
    except ProcessLookupError: return False


def blueprint(command=None):
    value = blueprintctl.empty_blueprint()
    value["design"].update({
        "goals": ["prove authority"],
        "architecture": ["isolated fixture"],
        "capabilities": [{"id": "authority", "description": "provider authority"}],
        "constraints": ["no forged local evidence"],
        "acceptance": [{"id": "authority-proof", "criterion": "provider authority is enforced", "method": "manual"}],
        "commands": [] if command is None else [command],
    })
    return value


def confirmed(command):
    value = blueprint(command)
    digest = adaptive_common.canonical_sha256(value["design"])
    value.update({"status": "confirmed", "confirmation": {
        "source": "user:provider-observed", "design_sha256": digest,
        "confirmed_at": "2026-01-01T00:00:00+00:00", "decision_receipt": {"provider": "fixture"},
    }})
    return value


# Caller labels alone must never confirm an authoritative blueprint.
with tempfile.TemporaryDirectory(prefix="blueprint-authority-") as raw:
    root = Path(raw)
    shutil.copytree(ROOT / ".agent/assets/fresh-state/v1/state", root / ".agent/state")
    shutil.copy2(ROOT / ".agent/assets/fresh-state/v1/config.json", root / ".agent/config.json")
    write_json(root / ".agent/project/BLUEPRINT.json", blueprint())
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "blueprintctl.py"), "--root", str(root), "confirm",
         "--source", "user:forged-local-label"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode == 0 or "host/provider-verifiable receipt" not in result.stdout:
        raise AssertionError(f"receipt-less blueprint confirmation did not fail closed: {result.stdout}")
    if json.loads((root / ".agent/project/BLUEPRINT.json").read_text())["status"] != "draft":
        raise AssertionError("failed confirmation mutated blueprint authority")


# Local evidence remains explicitly advisory and can never validate a gate.
config = json.loads((ROOT / ".agent/assets/fresh-state/v1/config.json").read_text())
task = json.loads((ROOT / ".agent/assets/fresh-state/v1/state/TASK.json").read_text())
task.update({"decision_policy_version": humandecision.LOCAL_POLICY_VERSION, "environment": "local",
             "mode": "standard", "deployment_requested": False})
task["risk_flags"] = {name: False for name in task["risk_flags"]}
digest = "a" * 64
advisory = humandecision.local_approval("user:advisory", digest, task)
if "not-authoritative" not in advisory["assurance"] or not humandecision.local_advisory_valid(
        task, advisory, source="user:advisory", artifact_sha256=digest, config=config):
    raise AssertionError("local evidence is not a valid, visibly non-authoritative advisory")
if humandecision.local_approval_valid(task, advisory, source="user:advisory", artifact_sha256=digest, config=config):
    raise AssertionError("legacy local approval hook still authorizes advisory evidence")
try:
    humandecision.record_decision_approval(ROOT, config, task, gate="requirement", artifact_sha256=digest,
                                           source="user:forged", receipt=None)
except SystemExit as error:
    if "advisory only" not in str(error):
        raise
else:
    raise AssertionError("local evidence authorized a workflow gate")
if humandecision.decision_approval_valid(ROOT, config, task, gate="requirement", artifact_sha256=digest,
                                         source="user:advisory", record=advisory):
    raise AssertionError("local advisory revalidated as gate authority")
security_risks = dict(task["risk_flags"]); security_risks["security"] = True
for risks in ({name: False for name in task["risk_flags"]}, security_risks):
    if humandecision.decision_policy_version(config, mode="standard", environment="local",
            deployment_requested=False, risk_flags=risks) != humandecision.PROVIDER_POLICY_VERSION:
        raise AssertionError("task routing did not retain sole provider authority")
weakened = json.loads(json.dumps(config))
weakened["agent_control"]["human_decision_observer"]["allow_current_chat_local_release"] = True
try:
    humandecision.policy(weakened)
except SystemExit:
    pass
else:
    raise AssertionError("retired local-release authorization option was accepted")
for generic_adapter in ("/bin/sh", "/usr/bin/env"):
    if not Path(generic_adapter).exists():
        continue
    try:
        humandecision.adapter_path(ROOT, generic_adapter)
    except SystemExit:
        pass
    else:
        raise AssertionError(f"generic interpreter was accepted as a provider adapter: {generic_adapter}")
with tempfile.TemporaryDirectory(prefix="adapter-metadata-") as raw:
    adapter = Path(raw).resolve() / "provider-adapter"
    adapter.write_bytes(b"dedicated provider adapter fixture")
    metadata = Path(str(adapter) + humandecision.ADAPTER_METADATA_SUFFIX)
    value = {"schema": humandecision.ADAPTER_METADATA_SCHEMA,
             "purpose": "provider-verifiable-agent-control",
             "executable_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
             "operations": ["health", "verify"]}
    write_json(metadata, value)
    original_protection = humandecision.protected_path_chain
    humandecision.protected_path_chain = lambda _path: True
    humandecision.verify_adapter_metadata(adapter, ("health", "verify"))
    value["executable_sha256"] = "0" * 64
    write_json(metadata, value)
    try:
        humandecision.verify_adapter_metadata(adapter, ("health", "verify"))
    except SystemExit:
        pass
    else:
        raise AssertionError("adapter metadata accepted an executable digest mismatch")
    humandecision.protected_path_chain = original_protection


with tempfile.TemporaryDirectory(prefix="adapter-execution-") as raw:
    adapter_root=Path(raw); adapter=adapter_root/"provider-adapter"; child_pid_path=adapter_root/"child.pid"
    original_metadata,original_launcher=humandecision.verify_adapter_metadata,humandecision.validate_adapter_launcher
    humandecision.verify_adapter_metadata=lambda *_args,**_kwargs:None; humandecision.validate_adapter_launcher=lambda *_args,**_kwargs:None
    poisoned={"PYTHONPATH":"/poison","NODE_OPTIONS":"--require=/poison","LD_PRELOAD":"/poison","GIT_CONFIG_GLOBAL":"/poison"}
    old_environment={name:os.environ.get(name) for name in poisoned}; os.environ.update(poisoned)
    try:
        adapter.write_text("#!/bin/sh\nfor n in PYTHONPATH NODE_OPTIONS LD_PRELOAD GIT_CONFIG_GLOBAL; do eval 'v=$'\"$n\"; test -z \"$v\" || exit 41; done\nprintf clean\n",encoding="utf-8"); adapter.chmod(0o700)
        result=humandecision.run_adapter(adapter,["health"],required_operations=("health",),timeout=2)
        if result.returncode!=0 or result.stdout.strip()!="clean": raise AssertionError("provider adapter inherited poisoned host process-control state")
        adapter.write_text(f"#!/bin/sh\nhead -c {humandecision.MAX_ADAPTER_OUTPUT_BYTES} /dev/zero\n",encoding="utf-8"); adapter.chmod(0o700)
        exact=humandecision.run_adapter(adapter,["health"],required_operations=("health",),timeout=2)
        if exact.returncode!=0 or len(exact.stdout)!=humandecision.MAX_ADAPTER_OUTPUT_BYTES:
            raise AssertionError("exact bounded provider adapter output was rejected")
        adapter.write_text(f"#!/bin/sh\nhead -c {humandecision.MAX_ADAPTER_OUTPUT_BYTES+1} /dev/zero\n",encoding="utf-8"); adapter.chmod(0o700)
        try: humandecision.run_adapter(adapter,["health"],required_operations=("health",),timeout=2)
        except SystemExit as error:
            if "output exceeds" not in str(error): raise
        else: raise AssertionError("overflowing provider adapter output was accepted")
        adapter.write_text(f"#!/bin/sh\nsleep 30 >/dev/null 2>&1 &\necho $! > {str(child_pid_path)!s}\nprintf clean\nexit 0\n",encoding="utf-8"); adapter.chmod(0o700)
        try: humandecision.run_adapter(adapter,["health"],required_operations=("health",),timeout=2)
        except SystemExit as error:
            if "descendant" not in str(error): raise
        else: raise AssertionError("successful provider adapter left a surviving descendant")
        successful_child=int(child_pid_path.read_text(encoding="utf-8"))
        for _ in range(40):
            if not process_is_live(successful_child): break
            time.sleep(.05)
        else: raise AssertionError("successful provider adapter descendant survived cleanup")
        adapter.write_text(f"#!/bin/sh\nsleep 30 &\necho $! > {str(child_pid_path)!s}\nsleep 30\n",encoding="utf-8"); adapter.chmod(0o700)
        try: humandecision.run_adapter(adapter,["health"],required_operations=("health",),timeout=1)
        except SystemExit as error:
            if "timed out" not in str(error): raise
        else: raise AssertionError("timed-out provider adapter was accepted")
        child_pid=int(child_pid_path.read_text(encoding="utf-8"))
        for _ in range(40):
            if not process_is_live(child_pid): break
            time.sleep(.05)
        else: raise AssertionError("timed-out provider adapter descendant survived cleanup")
    finally:
        for name,value in old_environment.items():
            if value is None: os.environ.pop(name,None)
            else: os.environ[name]=value
        humandecision.verify_adapter_metadata,humandecision.validate_adapter_launcher=original_metadata,original_launcher

# run-command holds the shared lock through launch completion; revocation cannot interleave.
with tempfile.TemporaryDirectory(prefix="decision-replay-") as raw:
    replay_root=Path(raw); project_a=replay_root/"project-a"; project_b=replay_root/"project-b"
    for project in (project_a,project_b): (project/".agent/state/evidence").mkdir(parents=True)
    config_a={"project":"fixture","project_initialization":{"guardrails_sha256":"a"*64}}
    config_b={"project":"fixture","project_initialization":{"guardrails_sha256":"a"*64}}
    task_a={"title":"generation-a","mode":"standard","decision_policy_version":1,"task_type":"feature","requirement_contract_sha256":"b"*64,
            "task_generation_id":"provider-generation-a","files":[],"environment":"local","deployment_requested":False,"branch":"fix/a","task_archive":None,"risk_flags":[]}
    task_b={**task_a,"title":"generation-b","task_generation_id":"provider-generation-b"}; artifact="c"*64; source="user:replay-fixture"
    receipt={"schema":humandecision.SCHEMA,"decision_id":"decision-replay-a","gate":"requirement","decision":"approved",
             "artifact_sha256":artifact,"source":source,"task_title":task_a["title"],"task_mode":task_a["mode"],
             "routing_profile_sha256":humandecision.routing_profile_sha256(task_a),
             "project_identity_sha256":humandecision.project_identity_sha256(project_a,config_a),
             "task_generation_sha256":humandecision.task_generation_sha256(task_a),"task_generation_id":"provider-generation-a",
             "observed_at":dt.datetime.now(dt.timezone.utc).isoformat(),"authority":"provider-signed-user-message"}
    receipt_path=project_a/".agent/state/evidence/decision.json"; write_json(receipt_path,receipt)
    original_policy,original_adapter,original_run=humandecision.policy,humandecision.adapter_path,humandecision.run_adapter
    humandecision.policy=lambda _config:{"signed_adapter":"fixture","max_receipt_age_seconds":900}
    humandecision.adapter_path=lambda *_args,**_kwargs:Path(shutil.which("true") or "/usr/bin/true")
    consumed=set()
    def decision_adapter(_adapter,arguments,**kwargs):
        raw=kwargs["receipt_raw"]; value=json.loads(raw); binding=humandecision._decision_consumption(value)
        operation=arguments[0]; key=binding["binding_sha256"]
        if operation=="consume-human-decision":
            if key in consumed: return subprocess.CompletedProcess([],1,"")
            consumed.add(key); status="CONSUMED"
        elif operation=="status-human-decision" and key in consumed: status="ACTIVE"
        else: return subprocess.CompletedProcess([],1,"")
        output=(f"{status} HUMAN DECISION sha256={hashlib.sha256(raw).hexdigest()} "
                f"binding-sha256={key} sequence=1\n")
        return subprocess.CompletedProcess([],0,output)
    humandecision.run_adapter=decision_adapter
    try:
        first=humandecision.verify(project_a,config_a,task_a,gate="requirement",artifact_sha256=artifact,source=source,receipt=".agent/state/evidence/decision.json")
        for other_root,other_config,other_task in ((project_a,config_a,task_b),(project_b,config_b,task_a)):
            if other_root==project_b: shutil.copy2(receipt_path,project_b/".agent/state/evidence/decision.json")
            try: humandecision.verify(other_root,other_config,other_task,gate="requirement",artifact_sha256=artifact,source=source,receipt=".agent/state/evidence/decision.json")
            except SystemExit: pass
            else: raise AssertionError("provider decision replay crossed its project or task generation")
        try: humandecision.verify(project_a,config_a,task_a,gate="requirement",artifact_sha256=artifact,source=source,receipt=".agent/state/evidence/decision.json")
        except SystemExit: pass
        else: raise AssertionError("provider decision was consumed more than once")
        if not humandecision.reverify(project_a,config_a,task_a,gate="requirement",artifact_sha256=artifact,source=source,record=first):
            raise AssertionError("consumed exact same-gate receipt status did not revalidate deterministically")
    finally:
        humandecision.policy,humandecision.adapter_path,humandecision.run_adapter=original_policy,original_adapter,original_run

with tempfile.TemporaryDirectory(prefix="blueprint-race-") as raw:
    root = Path(raw); (root / ".agent/project").mkdir(parents=True)
    command = {"id": "race", "argv": ["python3", "-c", "pass"], "stage": "ci",
               "timeout_seconds": 30, "covers": [], "environment": []}
    authority = confirmed(command)
    original_load, original_popen, original_stop, original_snapshot, original_argv = blueprintctl.load_blueprint, blueprintctl.subprocess.Popen, blueprintctl.stop_process_group, blueprintctl.testrun.process_snapshot, sys.argv[:]
    started, release, contender_acquired = threading.Event(), threading.Event(), threading.Event()
    class FakeProcess:
        pid = 4242
        def __init__(self): self.returncode=None
    blueprintctl.load_blueprint = lambda *_args, **_kwargs: copy.deepcopy(authority)
    blueprintctl.subprocess.Popen = lambda *_args, **_kwargs: FakeProcess()
    def fake_process_snapshot():
        started.set()
        return {} if release.is_set() else {4242:(1,4242,"fixture-start","R")}
    blueprintctl.testrun.process_snapshot=fake_process_snapshot
    def fake_stop(process,*_args,**_kwargs): process.returncode=0
    blueprintctl.stop_process_group = fake_stop
    sys.argv = ["blueprintctl.py", "--root", str(root), "run-command", "--id", "race", "--stage", "ci"]
    result = []
    runner = threading.Thread(target=lambda: result.append(blueprintctl.main()), daemon=True); runner.start()
    if not started.wait(2): raise AssertionError("command did not reach its launch linearization point")
    def contend():
        with adaptive_common.mutation_lock(root): contender_acquired.set()
    contender = threading.Thread(target=contend, daemon=True); contender.start(); time.sleep(0.15)
    if contender_acquired.is_set(): raise AssertionError("revocation lock interleaved with active command")
    release.set(); runner.join(3); contender.join(3)
    if result != [0] or not contender_acquired.is_set(): raise AssertionError("serialized command/revocation ordering failed")
    blueprintctl.load_blueprint, blueprintctl.subprocess.Popen, blueprintctl.stop_process_group, blueprintctl.testrun.process_snapshot, sys.argv = original_load, original_popen, original_stop, original_snapshot, original_argv


# A final in-lock re-read must reject authority drift before Popen.
with tempfile.TemporaryDirectory(prefix="blueprint-drift-") as raw:
    root = Path(raw); (root / ".agent/project").mkdir(parents=True)
    command = {"id": "drift", "argv": ["python3", "-c", "pass"], "stage": "ci",
               "timeout_seconds": 30, "covers": [], "environment": []}
    first = confirmed(command); second = copy.deepcopy(first); second["design"]["commands"][0]["argv"] = ["python3", "-c", "raise SystemExit(9)"]
    loads = iter([first, second]); launched = []
    original_load, original_popen, original_argv = blueprintctl.load_blueprint, blueprintctl.subprocess.Popen, sys.argv[:]
    blueprintctl.load_blueprint = lambda *_args, **_kwargs: copy.deepcopy(next(loads))
    blueprintctl.subprocess.Popen = lambda *_args, **_kwargs: launched.append(True)
    sys.argv = ["blueprintctl.py", "--root", str(root), "run-command", "--id", "drift", "--stage", "ci"]
    if blueprintctl.main() == 0 or launched:
        raise AssertionError("stale command authority reached Popen")
    blueprintctl.load_blueprint, blueprintctl.subprocess.Popen, sys.argv = original_load, original_popen, original_argv


# Candidate identity is the actual manifest bytes plus every listed file byte.
with tempfile.TemporaryDirectory(prefix="acceptance-process-") as raw:
    process_root=Path(raw).resolve()
    env_script=process_root/"env-script"; env_script.write_text("#!/usr/bin/env python3\n",encoding="utf-8"); env_script.chmod(0o700)
    env_command={"id":"env-shebang","argv":["./env-script"],"timeout_seconds":2,"covers":[],"environment":[]}
    try: blueprintacceptance.executable_probe(process_root,env_command)
    except adaptive_common.AdaptiveError as error:
        if error.code!="ACCEPTANCE_EXECUTABLE_UNAVAILABLE": raise
    else: raise AssertionError("environment-resolved shebang escaped executable byte binding")
    with tempfile.TemporaryDirectory(prefix="mutable-external-helper-") as external_raw:
        external_helper=Path(external_raw)/"helper.py"; external_helper.write_text("raise SystemExit(0)\n",encoding="utf-8")
        for external_argv in (["python3",str(external_helper)],["python3",f"--config={external_helper}"]):
            external_command={"id":"external-input","argv":external_argv,"timeout_seconds":2,"covers":[],"environment":[]}
            try: blueprintacceptance.executable_probe(process_root,external_command)
            except adaptive_common.AdaptiveError as error:
                if error.code!="UNBOUND_ACCEPTANCE_INPUT": raise
            else: raise AssertionError("acceptance command referenced mutable bytes outside its candidate snapshot")
    drift_script=process_root/"drift-script"; drift_script.write_text("#!/bin/sh\nexit 0\n",encoding="utf-8"); drift_script.chmod(0o700)
    drift_command={"id":"drift","argv":["./drift-script"],"timeout_seconds":2,"covers":[],"environment":[]}
    drift_probe=blueprintacceptance.executable_probe(process_root,drift_command)
    drift_script.write_text("#!/bin/sh\nexit 7\n",encoding="utf-8"); drift_script.chmod(0o700)
    try: blueprintacceptance.execute_commands(process_root,{},[drift_command],[drift_probe])
    except adaptive_common.AdaptiveError as error:
        if error.code!="ACCEPTANCE_EXECUTABLE_DRIFT": raise
    else: raise AssertionError("acceptance executable drift was not rejected before execution")
    leak_script=process_root/"leak-script"; leak_script.write_text(
        "#!/bin/sh\nsleep 30 &\necho $! > leaked.pid\nexit 0\n",encoding="utf-8"); leak_script.chmod(0o700)
    leak_command={"id":"leak","argv":["./leak-script"],"timeout_seconds":2,"covers":[],"environment":[]}
    leak_probe=blueprintacceptance.executable_probe(process_root,leak_command)
    try: blueprintacceptance.execute_commands(process_root,{},[leak_command],[leak_probe])
    except adaptive_common.AdaptiveError as error:
        if error.code!="ACCEPTANCE_COMMAND_FAILED" or "descendant" not in str(error): raise
    else: raise AssertionError("successful acceptance command left a descendant")
    leaked_pid=int((process_root/"leaked.pid").read_text(encoding="utf-8"))
    for _ in range(40):
        if not process_is_live(leaked_pid): break
        time.sleep(.05)
    else: raise AssertionError("acceptance descendant survived process-group cleanup")

    detached_script=process_root/"detached.py"
    detached_script.write_text("import os,signal,subprocess,sys,time\nchild=subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)'],preexec_fn=os.setsid)\nopen('detached.pid','w').write(str(child.pid))\ntime.sleep(.3)\n",encoding="utf-8")
    detached_command={"id":"detached","argv":["python3","detached.py"],"timeout_seconds":2,"covers":[],"environment":[]}
    detached_probe=blueprintacceptance.executable_probe(process_root,detached_command)
    try: blueprintacceptance.execute_commands(process_root,{},[detached_command],[detached_probe])
    except adaptive_common.AdaptiveError as error:
        if error.code!="ACCEPTANCE_COMMAND_FAILED" or "descendant" not in str(error): raise
    else: raise AssertionError("direct setsid escape was accepted")
    detached_pid=int((process_root/"detached.pid").read_text(encoding="utf-8"))
    for _ in range(40):
        if not process_is_live(detached_pid): break
        time.sleep(.05)
    else: raise AssertionError("direct setsid descendant survived identity-bound cleanup")

    first=b"#!/bin/sh\nprintf created > unbound.marker\nprintf private > \"$HOME/private.marker\"\n"
    second=b"#!/bin/sh\ntest ! -e unbound.marker && test ! -e \"$HOME/private.marker\"\n"
    captured={"files":[("first",first,493),("second",second,493)],"directories":[(".",0o700)]}
    probes=[]
    for command in ({"id":"first","argv":["./first"],"timeout_seconds":2,"covers":[],"environment":[]},
                    {"id":"second","argv":["./second"],"timeout_seconds":2,"covers":[],"environment":[]}):
        with blueprintacceptance.materialized_candidate(captured) as workspace:
            probes.append(blueprintacceptance.executable_probe(workspace,command))
    blueprintacceptance.execute_commands(process_root,{},[
        {"id":"first","argv":["./first"],"timeout_seconds":2,"covers":[],"environment":[]},
        {"id":"second","argv":["./second"],"timeout_seconds":2,"covers":[],"environment":[]},
    ],probes,captured=captured)

# The general test runner constructs an empty-base environment: secrets and interpreter/shell injection never inherit.
with tempfile.TemporaryDirectory(prefix="testrun-env-") as raw:
    poisoned={"SECRET_TOKEN":"exfiltrate","PYTHONPATH":"/tmp/inject","PYTHONINSPECT":"1","NODE_OPTIONS":"--require=/tmp/pwn",
              "BASH_ENV":"/tmp/pwn","ENV":"/tmp/pwn","LD_PRELOAD":"/tmp/pwn","DYLD_INSERT_LIBRARIES":"/tmp/pwn"}
    previous={name:os.environ.get(name) for name in poisoned}; os.environ.update(poisoned)
    try: child=supervised_test.private_test_environment(Path(raw))
    finally:
        for name,value in previous.items():
            if value is None: os.environ.pop(name,None)
            else: os.environ[name]=value
    if any(name in child for name in poisoned): raise AssertionError("secret or process-control environment reached test child")
    if child.get("PATH")!=os.defpath or child.get("HOME")==os.environ.get("HOME"):
        raise AssertionError("test child did not receive sealed PATH and private HOME")
    for name in ("HOME","TMPDIR","XDG_CONFIG_HOME","XDG_CACHE_HOME","XDG_DATA_HOME"):
        path=Path(child[name])
        if not path.is_dir() or path.is_symlink() or (path.stat().st_mode&0o777)!=0o700:
            raise AssertionError(f"test child {name} is not a private directory")
    probe=subprocess.run([sys.executable,"-c","import os,sys; sys.exit(any(n in os.environ for n in sys.argv[1:]))",*poisoned],
                         env=child,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if probe.returncode: raise AssertionError("negative environment exfiltration child observed a poisoned variable")

# Bounded raw output never retains more than the configured cap.
producer=subprocess.Popen([sys.executable,"-c",f"import os; os.write(1,b'x'*({supervised_test.MAX_TEST_OUTPUT_BYTES}+65536))"],
                          stdout=subprocess.PIPE,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,start_new_session=True)
collector=supervised_test.BoundedOutput(producer.stdout); collector.start(); producer.wait(timeout=10)
if not collector.finish() or not collector.exceeded or len(collector.data)!=supervised_test.MAX_TEST_OUTPUT_BYTES:
    raise AssertionError("testrun output collection was not fail-closed and bounded")

# The testrun identity monitor kills a directly observed setsid descendant without PID-reuse signaling.
with tempfile.TemporaryDirectory(prefix="testrun-descendant-") as raw:
    pid_path=Path(raw)/"pid"
    source=("import os,subprocess,sys,time\n"
            f"p=subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)'],preexec_fn=os.setsid)\n"
            f"open({str(pid_path)!r},'w').write(str(p.pid))\ntime.sleep(30)\n")
    process=subprocess.Popen([sys.executable,"-c",source],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL,start_new_session=True)
    known={}; deadline=time.monotonic()+2
    while time.monotonic()<deadline and not pid_path.exists():
        snapshot=supervised_test.process_snapshot()
        if snapshot is not None:
            if process.pid in snapshot: known.setdefault(process.pid,snapshot[process.pid][2])
            supervised_test.discover_descendants(process.pid,known,snapshot)
        time.sleep(.02)
    if not pid_path.exists(): raise AssertionError("testrun setsid fixture did not start")
    child_pid=int(pid_path.read_text())
    cleaned,uncertain=supervised_test.terminate_process_tree(process,known)
    if not cleaned or uncertain: raise AssertionError("testrun detached descendant cleanup was uncertain")
    if process_is_live(child_pid): raise AssertionError("testrun direct setsid descendant survived cleanup")

with tempfile.TemporaryDirectory(prefix="candidate-manifest-") as raw:
    root = Path(raw).resolve(); payload = root / "dist/app.bin"; payload.parent.mkdir(parents=True); payload.write_bytes(b"release-v1")
    record = {"path": "dist/app.bin", "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(), "bytes": payload.stat().st_size}
    (root/".agent").mkdir(); (root/"candidate-scope").mkdir()
    write_json(root/".agent/config.json",{"scope":{"fingerprint_paths":["dist/app.bin"],"product_roots":["candidate-scope"]}})
    manifest=root/"candidate.json"; write_json(manifest,{"schema":"fixture/v1","changes":[record],"candidate_snapshot":[{**record,"mode":420}]})
    binding = blueprintacceptance.candidate_binding(root, "candidate.json")
    if binding["sha256"] != hashlib.sha256(manifest.read_bytes()).hexdigest() or binding["file_count"] != 1:
        raise AssertionError("candidate identity was not derived from actual manifest bytes")
    (root / ".agent/project").mkdir(parents=True)
    original_load, original_write = blueprintacceptance.load_blueprint, blueprintacceptance.write_json
    authority = confirmed(None)
    blueprintacceptance.load_blueprint = lambda *_args, **_kwargs: copy.deepcopy(authority)
    def racing_write(path, value):
        original_write(path, value); payload.write_bytes(b"raced-after-write")
    blueprintacceptance.write_json = racing_write
    receipt_path = root / "preflight.json"
    try:
        blueprintacceptance.write_authority_bound_json(root, receipt_path, {"status": "ready"}, binding,
                                                       authority["confirmation"]["design_sha256"])
    except adaptive_common.AdaptiveError:
        pass
    else:
        raise AssertionError("candidate drift during receipt emission was accepted")
    if receipt_path.exists():
        raise AssertionError("stale raced receipt remained usable")
    blueprintacceptance.load_blueprint, blueprintacceptance.write_json = original_load, original_write
    payload.write_bytes(b"release-v1")
    try: blueprintacceptance.candidate_binding(root, "candidate.json", "0" * 64)
    except adaptive_common.AdaptiveError: pass
    else: raise AssertionError("bare caller digest substituted candidate identity")
    payload.write_bytes(b"release-v2")
    try: blueprintacceptance.require_candidate_unchanged(root, binding)
    except adaptive_common.AdaptiveError: pass
    else: raise AssertionError("listed candidate file drift was accepted")
    payload.unlink(); payload.symlink_to(manifest)
    try: blueprintacceptance.candidate_binding(root, "candidate.json")
    except adaptive_common.AdaptiveError: pass
    else: raise AssertionError("candidate symlink was accepted")


# Mandatory nested risks and additive custom rules are fail-closed.
with tempfile.TemporaryDirectory(prefix="scope-risk-") as raw:
    agent = Path(raw) / ".agent"; agent.mkdir(); write_json(agent / "config.json", {"workflow": {}})
    original_agent,original_root=workflowctl.AGENT_DIR,workflowctl.ROOT
    workflowctl.AGENT_DIR=agent; workflowctl.ROOT=Path(raw)
    try:
        observed=set(workflowctl.classify_actual_scope([
            "packages/app/security/policy.py","services/api/deploy/job.yml","packages/app/ci/build.yml",
            "nested/.github/workflows/build.yml","nested/.gitlab/ci/test.yml","nested/.circleci/config.yml",
            "nested/Jenkinsfile","nested/azure-pipelines.yml",".gitlab-ci.yml",
        ]))
        if not {"security","deploy","external_impact"}.issubset(observed): raise AssertionError(f"nested mandatory risks were missed: {observed}")
        write_json(agent/"config.json",{"workflow":{"actual_scope_risk_markers":{"compliance":["basename:regulated.json"]}}})
        if "compliance" not in workflowctl.classify_actual_scope(["deep/path/regulated.json"]): raise AssertionError("custom additive risk marker was ignored")
        write_json(agent/"config.json",{"workflow":{"actual_scope_risk_markers":{"unknown":["segment:x"]}}})
        try: workflowctl.classify_actual_scope(["src/x/file.py"])
        except SystemExit: pass
        else: raise AssertionError("unknown scope risk configuration did not fail closed")
    finally: workflowctl.AGENT_DIR,workflowctl.ROOT=original_agent,original_root

# Built-in Skill activation embeds only manifest-owned bytes and its producer
# cannot exceed the same count/aggregate bounds enforced by validation.
def activation_fixture(root,skills):
    agent=root/".agent"; files={}; modes={}
    for skill_id,content in skills.items():
        path=agent/"skills"/skill_id/"SKILL.md"; path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(content); path.chmod(0o644); relative=f"skills/{skill_id}/SKILL.md"
        files[relative]=hashlib.sha256(content).hexdigest(); modes[relative]=0o644
    (agent/"project").mkdir(parents=True,exist_ok=True)
    (agent/".workflow-manifest.json").write_text(json.dumps({"schema":"agent-workflow-install/v5","agent_files":files,"agent_modes":modes}),encoding="utf-8")
    return agent

original_agent_dir=agentctl.AGENT_DIR
try:
    with tempfile.TemporaryDirectory(prefix="builtin-activation-") as raw:
        root=Path(raw); agentctl.AGENT_DIR=activation_fixture(root,{"managed-skill":b"# Managed\n"})
        captured=agentctl.capture_builtin_skills()
        if [item["id"] for item in captured]!=["managed-skill"]: raise AssertionError("managed built-in Skill was not captured")
        hidden=agentctl.AGENT_DIR/"skills/managed-skill/.env"; hidden.write_text("SECRET=must-not-archive\n",encoding="utf-8")
        try: agentctl.capture_builtin_skills()
        except SystemExit: pass
        else: raise AssertionError("untracked hidden credential entered built-in activation")
        hidden.unlink()
        outside=root/"outside-secret"; outside.write_text("credential bytes",encoding="utf-8")
        managed=agentctl.AGENT_DIR/"skills/managed-skill/SKILL.md"; managed.unlink(); os.link(outside,managed)
        try: agentctl.capture_builtin_skills()
        except SystemExit: pass
        else: raise AssertionError("hardlinked external file entered built-in activation")
    with tempfile.TemporaryDirectory(prefix="builtin-count-") as raw:
        root=Path(raw); skills={f"skill-{index:03d}":b"# Skill\n" for index in range(128)}
        agentctl.AGENT_DIR=activation_fixture(root,skills); agentctl.capture_builtin_skills()
        extra=agentctl.AGENT_DIR/"skills/skill-128/SKILL.md"; extra.parent.mkdir(); extra.write_bytes(b"# Extra\n"); extra.chmod(0o644)
        manifest=json.loads((agentctl.AGENT_DIR/".workflow-manifest.json").read_text()); relative="skills/skill-128/SKILL.md"
        manifest["agent_files"][relative]=hashlib.sha256(extra.read_bytes()).hexdigest(); manifest["agent_modes"][relative]=0o644
        (agentctl.AGENT_DIR/".workflow-manifest.json").write_text(json.dumps(manifest),encoding="utf-8")
        try: agentctl.capture_builtin_skills()
        except SystemExit: pass
        else: raise AssertionError("129 built-in Skills exceeded the validator without producer rejection")
    with tempfile.TemporaryDirectory(prefix="builtin-size-") as raw:
        root=Path(raw); agentctl.AGENT_DIR=activation_fixture(root,{"large-skill":b"x"*(3200*1024)})
        try: agentctl.build_task_skill_activation("size-generation",{"active":[]},None,{})
        except SystemExit as error:
            if "aggregate 4 MiB" not in str(error): raise
        else: raise AssertionError("activation producer emitted a snapshot rejected by its 4 MiB validator")
    for relative,is_directory in (("skill-mutation-head.json",False),("skill-mutation-history",True),
                                  ("skill-lifecycle.json",False),("skill-cas",True)):
        with tempfile.TemporaryDirectory(prefix="orphan-skill-authority-") as raw:
            root=Path(raw); agentctl.AGENT_DIR=root/".agent"; project=agentctl.AGENT_DIR/"project"; project.mkdir(parents=True)
            surface=project/relative
            if is_directory: surface.mkdir(); (surface/"orphan").write_text("{}\n",encoding="utf-8")
            else: surface.write_text("{}\n",encoding="utf-8")
            try: agentctl.capture_dynamic_skill_activation()
            except SystemExit: pass
            else: raise AssertionError(f"orphan dynamic Skill authority was treated as absent: {relative}")
finally:
    agentctl.AGENT_DIR=original_agent_dir


# Immutable historical task archives retain exact activation-v1 facts without
# fabricating the built-in byte authority introduced by activation v2.
with tempfile.TemporaryDirectory(prefix="legacy-activation-archive-") as raw:
    root=Path(raw); archive_dir=root/".agent/state/evidence/task-archives"; archive_dir.mkdir(parents=True)
    activation={"schema":"agent-task-skill-activation/v1","task_generation_id":"legacy-generation",
        "blueprint_sha256":None,"lock_sha256":None,"skills":[]}
    activation["activation_sha256"]=hashlib.sha256(json.dumps(activation,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    activation_data=(json.dumps(activation,ensure_ascii=False,indent=2)+"\n").encode()
    pointer={"schema":activation["schema"],"path":".agent/state/SKILL_ACTIVATION.json",
        "sha256":hashlib.sha256(activation_data).hexdigest(),"bytes":len(activation_data),
        "activation_sha256":activation["activation_sha256"],"lock_sha256":None,"skill_ids":[]}
    archived_task={"task_generation_id":"legacy-generation","status":"accepted","task_archive":None,"skill_activation":pointer}
    archived_task_data=json.dumps(archived_task,sort_keys=True,separators=(",",":"),ensure_ascii=False)
    payload={"schema":"agent-task-archive/v2","archived_at":"2026-01-01T00:00:00+00:00","source":"workflow:accepted",
        "reason":"historical activation v1 fixture","assurance":"completed-workflow-checkpoint","decision_receipt":None,
        "task":{"sha256":hashlib.sha256(archived_task_data.encode()).hexdigest(),"bytes":len(archived_task_data.encode()),"utf8":archived_task_data},
        "requirement_contract":None,"previous":None,
        "skill_activation":{"sha256":hashlib.sha256(activation_data).hexdigest(),"bytes":len(activation_data),"utf8":activation_data.decode()},
        "delivery":None,"referenced_evidence":[]}
    payload_data=(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode(); digest=hashlib.sha256(payload_data).hexdigest()
    (archive_dir/f"{digest}.json").write_bytes(payload_data)
    head={"schema":"agent-task-archive-head/v1","path":f".agent/state/evidence/task-archives/{digest}.json",
        "sha256":digest,"bytes":len(payload_data),"total_archives":1}
    original_root,original_workflow_agent=workflowctl.ROOT,workflowctl.AGENT_DIR
    workflowctl.ROOT=root; workflowctl.AGENT_DIR=root/".agent"
    shutil.copy2(ROOT/".agent/config.json",root/".agent/config.json")
    try:
        if workflowctl.task_archive_errors({"task_archive":head}): raise AssertionError("exact historical activation-v1 archive was rejected")
        tampered=json.loads(activation_data); tampered["builtins"]=[]
        tampered_data=(json.dumps(tampered,ensure_ascii=False,indent=2)+"\n").encode(); payload["skill_activation"]={"sha256":hashlib.sha256(tampered_data).hexdigest(),"bytes":len(tampered_data),"utf8":tampered_data.decode()}
        bad_data=(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode(); bad_digest=hashlib.sha256(bad_data).hexdigest(); (archive_dir/f"{bad_digest}.json").write_bytes(bad_data)
        bad_head={**head,"path":f".agent/state/evidence/task-archives/{bad_digest}.json","sha256":bad_digest,"bytes":len(bad_data)}
        if not workflowctl.task_archive_errors({"task_archive":bad_head}): raise AssertionError("activation-v1 archive fabricated built-in authority")
    finally: workflowctl.ROOT,workflowctl.AGENT_DIR=original_root,original_workflow_agent


# Emergency Skill quarantine changes urgency but never bypasses provider authority.
with tempfile.TemporaryDirectory(prefix="skill-emergency-authority-") as raw:
    root=Path(raw); lifecycle=root/".agent/project/skill-lifecycle.json"
    event={"action":"quarantine","decision":{"gate":"adaptive-skill-quarantine","source":"security:incident-42",
        "action_sha256":"d"*64,"receipt":{"provider":"bound"},"assurance":"provider-authenticated-emergency-containment"}}
    write_json(lifecycle,{"schema":"agent-skill-lifecycle/v1","events":[event]})
    original_verify=skillctl.verify_human_decision; calls=[]
    def emergency_verify(_root,**kwargs):
        calls.append(kwargs)
        if kwargs.get("record")!={"provider":"bound"}: raise adaptive_common.AdaptiveError("INVALID_HUMAN_DECISION","forged emergency receipt",3)
        return kwargs["record"]
    skillctl.verify_human_decision=emergency_verify
    try:
        skillctl.load_lifecycle(root)
        if len(calls)!=1 or calls[0].get("source")!="security:incident-42": raise AssertionError("emergency quarantine skipped provider decision revalidation")
        forged=copy.deepcopy(event); forged["decision"]["receipt"]={"provider":"forged"}
        write_json(lifecycle,{"schema":"agent-skill-lifecycle/v1","events":[forged]})
        try: skillctl.load_lifecycle(root)
        except adaptive_common.AdaptiveError: pass
        else: raise AssertionError("forged emergency quarantine receipt was accepted")
    finally: skillctl.verify_human_decision=original_verify


# Protected Skill mutation history rejects truncation, forks, and stale heads.
with tempfile.TemporaryDirectory(prefix="skill-mutation-chain-") as raw:
    root=Path(raw); history=root/".agent/project/skill-mutation-history"; history.mkdir(parents=True)
    first={"phase":"published","chain_sequence":1,"previous_journal_sha256":"none","journal_id":"1"*64,"journal_sha256":"a"*64}
    second={"phase":"published","chain_sequence":2,"previous_journal_sha256":first["journal_sha256"],"journal_id":"2"*64,"journal_sha256":"b"*64}
    records={first["journal_id"]+".json":first,second["journal_id"]+".json":second}
    for name in records: (history/name).write_text("{}\n",encoding="utf-8"); (history/name).chmod(0o600)
    original_history_reader=skillctl._mutation_history_value
    skillctl._mutation_history_value=lambda _fd,name:copy.deepcopy(records[name])
    try:
        skillctl.write_mutation_head(root,second)
        if skillctl.mutation_history_chain(root)!=[first,second]: raise AssertionError("valid Skill mutation chain was rejected")
        (history/(first["journal_id"]+".json")).unlink()
        try: skillctl.mutation_history_chain(root)
        except adaptive_common.AdaptiveError: pass
        else: raise AssertionError("truncated Skill mutation chain was accepted")
        (history/(first["journal_id"]+".json")).write_text("{}\n",encoding="utf-8"); (history/(first["journal_id"]+".json")).chmod(0o600)
        records[second["journal_id"]+".json"]={**second,"previous_journal_sha256":"c"*64}
        try: skillctl.mutation_history_chain(root)
        except adaptive_common.AdaptiveError: pass
        else: raise AssertionError("forked Skill mutation predecessor was accepted")
        records[second["journal_id"]+".json"]=second
        skillctl.write_mutation_head(root,first)
        try: skillctl.mutation_history_chain(root)
        except adaptive_common.AdaptiveError: pass
        else: raise AssertionError("stale Skill mutation head was accepted")
        skillctl.write_mutation_head(root,second)
        if skillctl.mutation_history_chain(root)!=[first,second]: raise AssertionError("monotonic Skill mutation head recovery failed")
    finally:
        skillctl._mutation_history_value=original_history_reader

print("SECURITY CONTROL-PLANE SELF-TEST PASSED")
