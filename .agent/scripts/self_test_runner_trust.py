#!/usr/bin/env python3
"""Focused regressions for exact snapshots, private execution, and daemon cleanup."""
from pathlib import Path
from types import SimpleNamespace
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time

SCRIPTS=Path(__file__).resolve().parent
sys.path.insert(0,str(SCRIPTS))
# blueprintacceptance only needs skillctl when full CLI Skill verification runs.
sys.modules.setdefault("skillctl",SimpleNamespace())
import testrun
import blueprintacceptance
import process_observation


def write_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2)+"\n",encoding="utf-8")


def alive(pid):
    if sys.platform.startswith("linux"):
        try:
            raw=(Path("/proc")/str(pid)/"stat").read_bytes()
        except FileNotFoundError:
            return False
        except OSError:
            pass
        else:
            close=raw.rfind(b")")
            if close >= 0 and raw[close+2:close+3] in {b"Z",b"X"}:
                return False
    try: os.kill(pid,0); return True
    except ProcessLookupError: return False
    except PermissionError: return True


def wait_dead(pid):
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        if not alive(pid): return
        time.sleep(.02)
    raise AssertionError(f"escaped process survived cleanup: {pid}")


def darwin_unknown_group_signal_case():
    process=SimpleNamespace(pid=10,returncode=None); calls=[]; original_platform=sys.platform
    original_test_snapshot=testrun.process_snapshot; original_kill=os.kill
    original_acceptance_snapshot=blueprintacceptance.darwin_process_snapshot
    try:
        sys.platform="darwin"
        test_snapshot={10:(1,10,"darwin:leader","R"),11:(1,10,"darwin:unknown","R")}
        testrun.process_snapshot=lambda:test_snapshot; testrun.os.kill=lambda pid,sig:calls.append((pid,sig))
        if testrun.signal_launch_group(process,{10:"darwin:leader"},signal.SIGTERM,test_snapshot):
            raise AssertionError("testrun accepted an unknown Darwin group member")
        raw={10:{"pid":10,"ppid":1,"pgid":10,"uid":os.geteuid(),"state":"R","start_identity":"darwin:leader","command":"x"},
             11:{"pid":11,"ppid":1,"pgid":10,"uid":os.geteuid(),"state":"R","start_identity":"darwin:unknown","command":"x"}}
        blueprintacceptance.darwin_process_snapshot=lambda:raw
        if blueprintacceptance.signal_launch_group(process,{10:"darwin:leader"},signal.SIGTERM):
            raise AssertionError("acceptance accepted an unknown Darwin group member")
        if calls: raise AssertionError(f"unknown Darwin group was signaled: {calls}")
    finally:
        sys.platform=original_platform; testrun.process_snapshot=original_test_snapshot; testrun.os.kill=original_kill
        blueprintacceptance.darwin_process_snapshot=original_acceptance_snapshot


def reaped_identifier_reuse_case():
    process=SimpleNamespace(pid=10,returncode=0); calls=[]; original_platform=sys.platform
    original_snapshot=testrun.process_snapshot; original_merge=testrun.merge_launch_identities
    original_reap=testrun.reap_known_children; original_kill=os.kill
    original_acceptance_snapshot=blueprintacceptance.darwin_process_snapshot
    reused={10:(1,10,"darwin:reused","R"),11:(10,10,"darwin:unrelated-child","R")}
    raw={pid:{"pid":pid,"ppid":row[0],"pgid":row[1],"sid":10,"uid":os.geteuid(),"state":row[3],"start_identity":row[2],"command":"x"}
         for pid,row in reused.items()}
    try:
        sys.platform="darwin"; testrun.process_snapshot=lambda:reused
        testrun.merge_launch_identities=lambda _known,_token:True; testrun.reap_known_children=lambda _known:None
        testrun.os.kill=lambda pid,signum:calls.append((pid,signum))
        cleaned,uncertain=testrun.terminate_process_tree(process,{10:"darwin:original"})
        if not cleaned or uncertain or calls:
            raise AssertionError(f"reaped PID/session reuse authorized signaling: {cleaned=} {uncertain=} {calls=}")
        blueprintacceptance.darwin_process_snapshot=lambda:raw
        if blueprintacceptance.signal_launch_group(process,{10:"darwin:original"},signal.SIGTERM):
            raise AssertionError("Blueprint cleanup accepted a reaped launch-session identifier")
        if calls: raise AssertionError(f"Blueprint reaped identifier reuse was signaled: {calls}")
    finally:
        sys.platform=original_platform; testrun.process_snapshot=original_snapshot
        testrun.merge_launch_identities=original_merge; testrun.reap_known_children=original_reap
        testrun.os.kill=original_kill; blueprintacceptance.darwin_process_snapshot=original_acceptance_snapshot


def bounded_candidate_traversal_case():
    with tempfile.TemporaryDirectory(prefix="runner-bounded-tree-") as raw:
        root=Path(raw); governed=root/"governed"; governed.mkdir()
        for index in range(4): (governed/f"entry-{index}.txt").write_text("x",encoding="utf-8")
        old_root=testrun.ROOT; old_limit=testrun.MAX_CANDIDATE_ENTRIES
        try:
            testrun.ROOT=root; testrun.MAX_CANDIDATE_ENTRIES=3
            config={"scope":{"fingerprint_paths":["governed"],"product_roots":["."]}}
            try: testrun.governed_product_files(config)
            except SystemExit as error:
                if "entry limit" not in str(error) and "3-entry limit" not in str(error): raise
            else: raise AssertionError("candidate traversal materialized entries beyond its configured limit")
        finally: testrun.MAX_CANDIDATE_ENTRIES=old_limit; testrun.ROOT=old_root



def snapshot_race_case():
    with tempfile.TemporaryDirectory(prefix="runner-snapshot-race-") as raw:
        root=Path(raw); source=root/"source.txt"; source.write_bytes(b"hash-A\n")
        empty=root/"empty"; empty.mkdir(); empty.chmod(0o711)
        config={"scope":{"fingerprint_paths":["source.txt"],"product_roots":["."]}}
        old_root=testrun.ROOT; original=testrun._descriptor_file_snapshot; swapped={"done":False}
        try:
            testrun.ROOT=root
            def swap_after_descriptor_read(path,label):
                result=original(path,label)
                if path==source and not swapped["done"]:
                    source.write_bytes(b"copy-B\n"); swapped["done"]=True
                return result
            testrun._descriptor_file_snapshot=swap_after_descriptor_read
            snapshot=testrun.capture_candidate_snapshot(config)
            digest=testrun.candidate_fingerprint(config,snapshot)
            with testrun.disposable_candidate(config,snapshot) as workspace:
                assert (workspace/"source.txt").read_bytes()==b"hash-A\n"
                assert (workspace/"empty").is_dir()
                assert (workspace/"empty").stat().st_mode&0o777==0o711
            source.write_bytes(b"hash-A\n")
            assert testrun.candidate_fingerprint(config,snapshot)==digest
        finally:
            testrun._descriptor_file_snapshot=original; testrun.ROOT=old_root


def assert_no_case_or_inode_aliases(snapshot,label):
    for kind,items in (("file",snapshot["files"]),("directory",snapshot["directories"])):
        folded={}; identities={}
        for item in items:
            relative=item[0]; key=relative.as_posix().casefold()
            if key in folded and folded[key]!=relative.as_posix():
                raise AssertionError(f"{label} has {kind} case aliases: {folded[key]} and {relative.as_posix()}")
            folded[key]=relative.as_posix()
            path=testrun.ROOT/relative; metadata=os.lstat(path); identity=(metadata.st_dev,metadata.st_ino)
            prior=identities.get(identity)
            if prior is not None and prior.casefold()==relative.as_posix().casefold() and prior!=relative.as_posix():
                raise AssertionError(f"{label} has {kind} same-inode aliases: {prior} and {relative.as_posix()}")
            identities[identity]=relative.as_posix()


def current_snapshot_inventory_case():
    config=json.loads(testrun.CONFIG_PATH.read_text(encoding="utf-8"))
    snapshot=testrun.capture_candidate_snapshot(config)
    assert_no_case_or_inode_aliases(snapshot,"current candidate snapshot")
    current_files={path.as_posix() for path,_data,_mode in snapshot["files"]}
    current_directories={path.as_posix() for path,_mode in snapshot["directories"]}
    assert not ({"Tests/check_freshness.py","tests/check_freshness.py"}<=current_files),current_files
    assert not ({"Tests","tests"}<=current_directories),current_directories
    processes=blueprintacceptance.process_snapshot(); assert processes is not None and os.getpid() in processes,processes
    identity=processes[os.getpid()][1]
    if sys.platform.startswith("linux"):
        assert identity.startswith("linux:") and process_observation.linux_pidfd_supported(),identity
    elif sys.platform.startswith("darwin"):
        assert identity.startswith("darwin:"),identity


def case_alias_materialization_case():
    with tempfile.TemporaryDirectory(prefix="runner-source-spelling-") as raw:
        root=Path(raw); source=root/"tests"; source.mkdir(); (source/"check_freshness.py").write_text("same\n")
        config={"scope":{"fingerprint_paths":["tests"],"product_roots":["."]}}
        old_root=testrun.ROOT
        try:
            testrun.ROOT=root
            original_platform=testrun.sys.platform
            try:
                testrun.sys.platform="darwin"; darwin_snapshot=testrun.capture_candidate_snapshot(config)
                testrun.sys.platform="linux"; linux_snapshot=testrun.capture_candidate_snapshot(config)
            finally: testrun.sys.platform=original_platform
            darwin_inventory=testrun.acceptance_candidate_records(config,darwin_snapshot)
            linux_inventory=testrun.acceptance_candidate_records(config,linux_snapshot)
            assert darwin_inventory==linux_inventory,(darwin_inventory,linux_inventory)
            snapshot=testrun.capture_candidate_snapshot(config)
            assert_no_case_or_inode_aliases(snapshot,"fixture candidate snapshot")
            file_paths=[path.as_posix() for path,_data,_mode in snapshot["files"]]
            directory_paths=[path.as_posix() for path,_mode in snapshot["directories"]]
            assert file_paths==["tests/check_freshness.py"],file_paths
            assert "tests" in directory_paths and "Tests" not in directory_paths,directory_paths
            with testrun.disposable_candidate(config,snapshot) as workspace:
                assert (workspace/"tests/check_freshness.py").read_text()=="same\n"
            alias={"files":[("Tests/check_freshness.py",b"same\n",420),("tests/check_freshness.py",b"same\n",420)],
                   "directories":[(".",0o700),("Tests",0o755),("tests",0o755)]}
            if sys.platform.startswith("darwin"):
                try:
                    with blueprintacceptance.materialized_candidate(alias): pass
                except SystemExit as error: assert "true filesystem-alias" in str(error)
                else: raise AssertionError("blueprint materialization accepted true case aliases")
            else:
                with blueprintacceptance.materialized_candidate(alias) as workspace:
                    assert (workspace/"Tests/check_freshness.py").is_file()
                    assert (workspace/"tests/check_freshness.py").is_file()
        finally: testrun.ROOT=old_root


def normalized_state_case():
    with tempfile.TemporaryDirectory(prefix="runner-normalized-state-") as raw:
        root=Path(raw); task=root/".agent/state/TASK.json"
        write_json(task,{"title":"same","status":"one","metrics":{"turns":1},"updated":"one"})
        config={"scope":{"fingerprint_paths":[".agent/state/TASK.json"],"product_roots":["."]}}
        old_root=testrun.ROOT
        try:
            testrun.ROOT=root; snapshot=testrun.capture_candidate_snapshot(config)
            write_json(task,{"title":"same","status":"two","metrics":{"turns":2},"updated":"two"})
            assert testrun.candidate_snapshot_matches(config,snapshot), "volatile TASK fields changed candidate semantics"
        finally: testrun.ROOT=old_root


def private_dependency_case():
    with tempfile.TemporaryDirectory(prefix="runner-private-dependency-") as raw:
        root=Path(raw); (root/"source.txt").write_text("candidate\n",encoding="utf-8")
        (root/"node_modules").mkdir()
        config={"scope":{"fingerprint_paths":["source.txt"],"product_roots":["."]}}
        old_root=testrun.ROOT
        try:
            testrun.ROOT=root; snapshot=testrun.capture_candidate_snapshot(config)
            with testrun.disposable_candidate(config,snapshot) as workspace:
                _command,compatible=testrun.candidate_copy_command(["npm","test"],workspace)
                outside=Path(raw).parent/"runner-outside-tool"; outside.write_text("outside",encoding="utf-8")
                link=root/"project-tool"; link.symlink_to(outside)
                _command,symlink_compatible=testrun.candidate_copy_command([str(link)],workspace)
                link.unlink(); outside.unlink()
            assert compatible is False, "authoritative node_modules unexpectedly authorized private execution"
            assert symlink_compatible is False, "project-local absolute symlink escaped private execution"
        finally: testrun.ROOT=old_root


def descriptor_launch_case():
    with tempfile.TemporaryDirectory(prefix="runner-fd-launch-") as raw:
        root=Path(raw).resolve(); script=root/"acceptance.sh"
        script.write_bytes(b"#!/bin/sh\nprintf 'reviewed-A\\n'\n"); script.chmod(0o755)
        command={"id":"fd-launch","argv":["./acceptance.sh"],"environment":[],"timeout_seconds":5,"covers":[]}
        _resolved,expected=blueprintacceptance.resolve_executable(root,command)
        with blueprintacceptance.bound_executable_launch(root,command) as (_argv,digest,_descriptors,_launch_descriptor,_launch_path,verify_capture):
            replacement=root/"replacement.sh"; replacement.write_bytes(b"#!/bin/sh\nprintf 'swapped-B\\n'\n"); replacement.chmod(0o755)
            os.replace(replacement,script)
            assert digest==expected,"descriptor launch digest differed from reviewed preflight bytes"
            try: verify_capture()
            except blueprintacceptance.AdaptiveError as error:
                assert error.code=="ACCEPTANCE_EXECUTABLE_DRIFT",error
            else: raise AssertionError("canonical executable path replacement did not fail closed")
        script.write_bytes(b"#!/bin/sh\nprintf 'reviewed-A\\n'\n"); script.chmod(0o755)
        probe=blueprintacceptance.executable_probe(root,command)
        results=blueprintacceptance.execute_commands(root,{},[command],[probe])
        assert len(results)==1,results
        if sys.platform.startswith("darwin"):
            script.write_bytes(b"#!/bin/sh\nexit 0\n"); script.chmod(0o755)
            probe=blueprintacceptance.executable_probe(root,command)
            results=blueprintacceptance.execute_commands(root,{},[command],[probe])
            assert len(results)==1,results


def canonical_internal_semantics_case():
    with tempfile.TemporaryDirectory(prefix="runner-canonical-path-") as raw:
        root=Path(raw).resolve(); tools=root/"tools"; tools.mkdir()
        sibling=tools/"sibling.txt"; sibling.write_text("bound-sibling\n",encoding="utf-8")
        executable=tools/"check.py"
        executable.write_text(
            f"#!{sys.executable}\n"
            "from pathlib import Path\nimport sys\n"
            "path=Path(__file__).resolve()\n"
            "valid=Path(sys.argv[0]).resolve()==path and (path.parent/'sibling.txt').read_text()=='bound-sibling\\n'\n"
            "raise SystemExit(0 if valid else 9)\n",encoding="utf-8")
        executable.chmod(0o500)
        command={"id":"canonical-internal","argv":["tools/check.py"],"covers":[],"environment":[],"timeout_seconds":5}
        probe=blueprintacceptance.executable_probe(root,command)
        results=blueprintacceptance.execute_commands(root,{},[command],[probe])
        assert results[0]["exit_code"]==0,results


def lifecycle_case():
    joined="import os,time; p=os.fork(); (time.sleep(.25),os._exit(0)) if p==0 else os.waitpid(p,0)"
    token="1"*32; env={"PATH":os.defpath,"LC_ALL":"C",blueprintacceptance.LAUNCH_TOKEN_NAME:token}
    original_ps=blueprintacceptance._ps_result; scan_arguments=[]
    def counted_ps(arguments): scan_arguments.append(tuple(arguments)); return original_ps(arguments)
    blueprintacceptance._ps_result=counted_ps; scan_started=time.monotonic()
    try:
        with blueprintacceptance.child_subreaper() as supported:
            process=subprocess.Popen([sys.executable,"-c",joined],start_new_session=True,env=env,
                                     stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            code,timed_out,leak,residual,uncertain=blueprintacceptance.monitor_and_cleanup(process,5,token,supported)
    finally: blueprintacceptance._ps_result=original_ps
    scan_elapsed=time.monotonic()-scan_started
    environment_scans=sum(1 for arguments in scan_arguments if "eww" in arguments)
    lightweight_scans=len(scan_arguments)-environment_scans
    if sys.platform.startswith("darwin"):
        assert environment_scans<=2 and lightweight_scans==0, scan_arguments
    elif sys.platform.startswith("linux"):
        assert environment_scans==0 and lightweight_scans==0, scan_arguments
    else:
        assert environment_scans<=2 and lightweight_scans>=2, scan_arguments
    assert scan_elapsed<3, f"bounded process monitoring took {scan_elapsed:.3f}s"
    assert (code,timed_out,leak,residual,uncertain)==(0,False,False,False,False), (code,timed_out,leak,residual,uncertain)

    original_merge=blueprintacceptance.merge_launch_identities
    blueprintacceptance.merge_launch_identities=lambda _known,_token: False
    try:
        process=subprocess.Popen([sys.executable,"-c","pass"],start_new_session=True,env=env,
                                 stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        _code,_timed_out,_leak,_residual,scan_uncertain=blueprintacceptance.monitor_and_cleanup(process,5,token,True)
    finally: blueprintacceptance.merge_launch_identities=original_merge
    assert scan_uncertain, "unavailable final Darwin identity scan did not fail closed"

    original_snapshot=blueprintacceptance.process_snapshot
    blueprintacceptance.process_snapshot=lambda: None
    uncertain_process=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"],start_new_session=True,
                                       stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        uncertain_result=blueprintacceptance.monitor_and_cleanup(uncertain_process,0.05,"4"*32,True)
    finally: blueprintacceptance.process_snapshot=original_snapshot
    assert uncertain_result[3:] == (True,True),uncertain_result
    assert uncertain_process.poll() is not None,"uncertain observation left the directly owned leader unreaped"

    with tempfile.TemporaryDirectory(prefix="runner-daemon-escape-") as raw:
        pid_path=Path(raw)/"daemon.pid"
        daemon=textwrap.dedent("""
            import os,signal,sys,time
            if os.fork(): os._exit(0)
            os.setsid()
            if os.fork(): os._exit(0)
            signal.signal(signal.SIGTERM,signal.SIG_IGN)
            if len(sys.argv)>2:
                code="import os,signal,sys,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);open(sys.argv[1],'w').write(str(os.getpid()));time.sleep(30)"
                os.execve(sys.executable,[sys.executable,'-c',code,sys.argv[1]],{})
            open(sys.argv[1],'w').write(str(os.getpid()))
            time.sleep(30)
        """)
        token="2"*32; env={"PATH":os.defpath,"LC_ALL":"C",blueprintacceptance.LAUNCH_TOKEN_NAME:token}
        with blueprintacceptance.child_subreaper() as supported:
            process=subprocess.Popen([sys.executable,"-c",daemon,str(pid_path),"clear-token"],start_new_session=True,env=env,
                                     stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            deadline=time.monotonic()+2
            while time.monotonic()<deadline:
                published=pid_path.read_text().strip() if pid_path.exists() else ""
                if published.isdigit(): break
                time.sleep(.01)
            assert published.isdigit(), "daemon fixture did not publish a PID"
            daemon_pid=int(published)
            # Darwin deliberately exercises the already-reaped fail-closed path;
            # Linux leaves the leader unreaped so subreaper cleanup stays bound.
            if sys.platform.startswith("darwin"):
                process.wait(timeout=2)
            code,timed_out,leak,residual,uncertain=blueprintacceptance.monitor_and_cleanup(
                process,5,token,supported)
        if sys.platform.startswith("darwin"):
            assert (code,timed_out,leak,residual,uncertain)==(0,False,False,False,True)
            assert alive(daemon_pid), "reaped launch observer signaled an unattributed tokenless process"
            assert blueprintacceptance.EXECUTION_BOUNDARY["hostile_command_containment"] is False
            os.kill(daemon_pid,signal.SIGKILL)
        else:
            assert leak or residual or uncertain, (code,timed_out,leak,residual,uncertain)
        wait_dead(daemon_pid)

    with tempfile.TemporaryDirectory(prefix="testrun-daemon-escape-") as raw:
        pid_path=Path(raw)/"daemon.pid"; token="3"*32
        env={"PATH":os.defpath,"LC_ALL":"C",testrun.LAUNCH_TOKEN_NAME:token}
        with testrun.child_subreaper() as supported:
            process=subprocess.Popen([sys.executable,"-c",daemon,str(pid_path),"clear-token"],start_new_session=True,env=env,
                                     stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+2
            while time.monotonic()<deadline:
                published=pid_path.read_text().strip() if pid_path.exists() else ""
                if published.isdigit(): break
                time.sleep(.01)
            assert published.isdigit(), "testrun daemon fixture did not publish a PID"
            daemon_pid=int(published); process.wait(timeout=2)
            known={}; snapshot=testrun.process_snapshot()
            assert snapshot is not None and testrun.discover_descendants(process.pid,known,snapshot)
            assert testrun.merge_launch_identities(known,token)
            if not sys.platform.startswith("darwin"):
                assert daemon_pid in known, "Linux subreaping did not find the detached daemon"
            cleaned,uncertain=testrun.terminate_process_tree(process,known,launch_token=token)
        if sys.platform.startswith("darwin"):
            assert cleaned and not uncertain and alive(daemon_pid), "launch-scoped cleanup claimed or signaled an unattributed process"
            os.kill(daemon_pid,signal.SIGKILL)
        else:
            assert supported and cleaned and not uncertain, (supported,cleaned,uncertain)
        wait_dead(daemon_pid)


def bounded_observer_output_case():
    import process_observation
    started=time.monotonic()
    try:
        process_observation.bounded_trusted_command_output(
            [sys.executable,"-c","import os;os.write(1,b'x'*8192)"],environment={"PATH":os.defpath,"LC_ALL":"C"},timeout=2,maximum=1024)
    except process_observation.ProcessObservationError as error:
        assert "output limit" in str(error),error
    else: raise AssertionError("trusted process observer buffered output beyond its limit")
    assert time.monotonic()-started<10


def main():
    current_snapshot_inventory_case(); bounded_candidate_traversal_case(); bounded_observer_output_case(); darwin_unknown_group_signal_case(); reaped_identifier_reuse_case(); snapshot_race_case(); case_alias_materialization_case(); normalized_state_case(); private_dependency_case(); descriptor_launch_case(); canonical_internal_semantics_case(); lifecycle_case()
    print("PASS: descriptor-bound snapshot and launch, private dependency refusal, bounded launch-scoped monitoring")
    return 0


if __name__=="__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
