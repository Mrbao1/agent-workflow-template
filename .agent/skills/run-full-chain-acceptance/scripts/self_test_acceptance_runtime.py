#!/usr/bin/env python3
"""Bounded regressions for acceptance-client termination and pipe draining."""

from pathlib import Path
import http.server
import importlib.util
import os
import signal
import threading
import sys
import tempfile
import time


SOURCE = Path(__file__).with_name("run_acceptance_runtime.py").resolve()


def load_runtime():
    spec = importlib.util.spec_from_file_location("acceptance_runtime_under_test", SOURCE)
    if spec is None or spec.loader is None:
        raise AssertionError("acceptance runtime module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bounded_command_output(runtime) -> None:
    runtime.COMMAND_OUTPUT_LIMIT_BYTES=1024; runtime.CLIENT_OUTPUT_LIMIT_BYTES=1024
    started=time.monotonic()
    try: runtime.run([sys.executable,"-c","import os;os.write(1,b'x'*8192)"],2,dict(os.environ))
    except RuntimeError as error:
        if "output exceeded" not in str(error): raise
    else: raise AssertionError("Docker/build command output limit was not enforced")
    if time.monotonic()-started>10: raise AssertionError("command output limit did not fail within its bound")
    client=runtime.run_client([sys.executable,"-c","import os;os.write(1,b'y'*8192)"],2,dict(os.environ))
    if client["exit_code"]!=125 or not client["output_limit_exceeded"] or len(client["raw_output"].encode())>1024:
        raise AssertionError("real client output limit was not bounded and failed closed")
    previous=os.environ.get("GITHUB_TOKEN"); os.environ["GITHUB_TOKEN"]="poison-secret"
    try: sanitized=runtime.run_client([sys.executable,"-c","import os;print('GITHUB_TOKEN' in os.environ)"],2,dict(os.environ))
    finally:
        if previous is None: os.environ.pop("GITHUB_TOKEN",None)
        else: os.environ["GITHUB_TOKEN"]=previous
    if sanitized["exit_code"]!=0 or sanitized["raw_output"].strip()!="False":
        raise AssertionError("real client inherited an ambient credential")


class HttpFixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302 if self.path=="/redirect" else 200)
        if self.path=="/redirect": self.send_header("Location","http://example.invalid/")
        self.end_headers()
        try:
            if self.path=="/large": self.wfile.write(b'x'*8192)
            elif self.path=="/trickle":
                for _index in range(100): self.wfile.write(b'x'); self.wfile.flush(); time.sleep(0.05)
            else: self.wfile.write(b'ok')
        except (BrokenPipeError,ConnectionResetError): pass
    def log_message(self,*_args): pass


def bounded_inventory(runtime) -> None:
    with tempfile.TemporaryDirectory(prefix="bounded-inventory-") as raw:
        root=Path(raw)
        for index in range(4): (root/f"entry-{index}").write_text("x",encoding="utf-8")
        previous=runtime.MAX_INVENTORY_ENTRIES; runtime.MAX_INVENTORY_ENTRIES=3
        try:
            try: list(runtime.bounded_tree_entries(root,{"count":0},"fixture inventory"))
            except RuntimeError as error:
                if "exceeds 3 entries" not in str(error): raise
            else: raise AssertionError("directory entries were materialized beyond their configured limit")
        finally: runtime.MAX_INVENTORY_ENTRIES=previous
        outside=root/"outside"; outside.mkdir(); (outside/"secret").write_text("secret",encoding="utf-8")
        link=root/"link"
        try: link.symlink_to(outside,target_is_directory=True)
        except (OSError,NotImplementedError): pass
        else:
            try: runtime.reject_symlink_components(link/"secret",root,"fixture fingerprint")
            except RuntimeError as error:
                if "symlink component" not in str(error): raise
            else: raise AssertionError("workspace fingerprint followed a parent symlink")



def bounded_http(runtime) -> None:
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),HttpFixture)
    thread=threading.Thread(target=server.serve_forever,name="bounded-http-fixture",daemon=True); thread.start()
    base=f"http://127.0.0.1:{server.server_port}"
    if not runtime.same_http_origin(base+"/",base+"/asset.js") or runtime.same_http_origin(base+"/",f"http://127.0.0.1:{server.server_port+1}/asset.js"):
        raise AssertionError("web baseline same-origin asset policy drifted")
    try:
        runtime.HTTP_BODY_LIMIT_BYTES=1024
        try: runtime.fetch(base+"/large")
        except RuntimeError as error:
            if "byte limit" not in str(error): raise
        else: raise AssertionError("oversized HTTP body was accepted")
        runtime.HTTP_TOTAL_TIMEOUT_SECONDS=0.2; started=time.monotonic()
        try: runtime.fetch(base+"/trickle")
        except TimeoutError: pass
        else: raise AssertionError("trickle HTTP body evaded the total deadline")
        if time.monotonic()-started>2: raise AssertionError("HTTP total deadline was not bounded")
        runtime.HTTP_TOTAL_TIMEOUT_SECONDS=2
        try: runtime.fetch(base+"/redirect")
        except OSError: pass
        else: raise AssertionError("acceptance HTTP fetch followed a redirect")
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)



def complete_docker_cleanup(runtime) -> None:
    calls=[]; image_queries=0; volume_queries=0
    def fake_run(command,_timeout,_environment):
        nonlocal image_queries,volume_queries
        calls.append(list(command))
        if command[:4]==["docker","image","ls","-q"]:
            image_queries+=1; return "sha256:candidate\n" if image_queries==1 else ""
        if command[:4]==["docker","volume","ls","-q"]:
            volume_queries+=1; return "agent_acceptance_fixture_data\n" if volume_queries==1 else ""
        return ""
    original=runtime.run; runtime.run=fake_run
    try: result=runtime.cleanup_acceptance_resources(["docker","compose","-p","agent_acceptance_fixture"],"agent_acceptance_fixture","app:acceptance-exact",{})
    finally: runtime.run=original
    if result["cleanup"]!={"containers":0,"networks":0,"volumes":0,"images":0}: raise AssertionError(result)
    if ["docker","compose","-p","agent_acceptance_fixture","down","--remove-orphans","--volumes"] not in calls:
        raise AssertionError("acceptance cleanup did not remove exact project volumes")
    if ["docker","image","rm","--force","app:acceptance-exact"] not in calls:
        raise AssertionError("acceptance cleanup did not remove the exact candidate image")
    if ["docker","volume","rm","--force","agent_acceptance_fixture_data"] not in calls: raise AssertionError("acceptance cleanup did not remove a labeled residual volume")
    if not any(command[:3]==["docker","volume","ls"] for command in calls): raise AssertionError("acceptance cleanup did not verify volume residuals")


def cleanup_continues_after_failure(runtime) -> None:
    calls=[]; queries={"container":0,"volume":0,"image":0}
    def fake_run(command,_timeout,_environment):
        calls.append(list(command))
        if command[:3]==["docker","ps","-aq"]:
            queries["container"]+=1; return "abcdef123456\n" if queries["container"]==1 else ""
        if command[:4]==["docker","volume","ls","-q"]:
            queries["volume"]+=1; return "agent_acceptance_failure_data\n" if queries["volume"]==1 else ""
        if command[:4]==["docker","image","ls","-q"]:
            queries["image"]+=1; return "sha256:candidate\n" if queries["image"]==1 else ""
        if command==["docker","rm","--force","abcdef123456"]: raise RuntimeError("fixture container removal failed")
        return ""
    original=runtime.run; runtime.run=fake_run
    try: result=runtime.cleanup_acceptance_resources(["docker","compose","-p","agent_acceptance_failure"],"agent_acceptance_failure","app:acceptance-failure",{})
    finally: runtime.run=original
    if not result.get("cleanup_errors"): raise AssertionError("cleanup removal failure was not recorded")
    if ["docker","volume","rm","--force","agent_acceptance_failure_data"] not in calls: raise AssertionError("volume cleanup stopped after container failure")
    if ["docker","image","rm","--force","app:acceptance-failure"] not in calls: raise AssertionError("image cleanup stopped after container failure")


def escaped_stdout_pipe(runtime) -> None:
    with tempfile.TemporaryDirectory(prefix="acceptance-runtime-pipe-") as raw_root:
        root=Path(raw_root); child_pid_path=root/"escaped.pid"; helper=root/"escape_stdout.py"
        helper.write_text("""#!/usr/bin/env python3
import os,sys,time
pid=os.fork()
if pid==0:
 os.setsid(); open(sys.argv[1],"w").write(str(os.getpid())); time.sleep(30); os._exit(0)
print("real-partial-output",flush=True); os._exit(0)
""",encoding="utf-8")
        runtime.PROCESS_CLEANUP_GRACE_SECONDS=0.2; started=time.monotonic()
        result=runtime.run_client([sys.executable,str(helper),str(child_pid_path)],0.2,dict(os.environ))
        elapsed=time.monotonic()-started
        if elapsed>15: raise AssertionError(f"escaped stdout fixture exceeded its hard bound: {elapsed:.3f}s")
        leaked=False
        if child_pid_path.exists():
            child_pid=int(child_pid_path.read_text(encoding="utf-8"))
            try: os.kill(child_pid,0); leaked=True
            except ProcessLookupError: pass
            if leaked:
                try: os.kill(child_pid,signal.SIGKILL)
                except ProcessLookupError: pass
        if leaked: raise AssertionError("escaped token-bound client child remained alive")
        if result["exit_code"]!=125 or result["process_cleanup"]!={"remaining":0}:
            raise AssertionError("escaped inherited stdout was not cleaned as bounded infrastructure failure")
        if "real-partial-output" not in result["raw_output"]:
            raise AssertionError("real subprocess partial output was lost")



def exact_candidate_image_binding(runtime) -> None:
    candidate="sha256:"+"a"*64; prebuilt="sha256:"+"b"*64
    containers=[{"service":"app","image":candidate,"published_ports":[]},{"service":"db","image":prebuilt,"published_ports":[]}]
    selected,services=runtime.exact_candidate_service_binding(containers,candidate,["app"])
    if services!=["app"] or len(selected)!=1: raise AssertionError("exact loaded candidate service was not selected")
    try: runtime.exact_candidate_service_binding([containers[1]],candidate,["app"])
    except RuntimeError as error:
        if "exact loaded candidate image" not in str(error): raise
    else: raise AssertionError("an unrelated prebuilt Compose service satisfied candidate execution")
    try: runtime.exact_candidate_service_binding(containers,candidate,["frontend"])
    except RuntimeError as error:
        if "user-governed" not in str(error): raise
    else: raise AssertionError("candidate-selected dummy service replaced the governed application service")
    try: runtime.exact_candidate_service_binding([containers[0],dict(containers[0])],candidate,["app"])
    except RuntimeError: pass
    else: raise AssertionError("duplicate candidate service identities were accepted")


def main() -> int:
    runtime=load_runtime(); bounded_command_output(runtime)
    runtime=load_runtime(); bounded_inventory(runtime); bounded_http(runtime); complete_docker_cleanup(runtime); cleanup_continues_after_failure(runtime); exact_candidate_image_binding(runtime)
    runtime=load_runtime(); escaped_stdout_pipe(runtime)
    print("PASS: acceptance bytes/deadlines, exact built image, Docker resources and escaped-child cleanup are enforced")
    return 0


if __name__ == "__main__":
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"scripts"))
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
