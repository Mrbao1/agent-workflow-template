#!/usr/bin/env python3
"""Build, start, enforce, probe, and always clean a Docker Compose runtime."""

from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
from typing import Dict, List, Set

sys.path.insert(0, str((Path.cwd() / ".agent/scripts").resolve()))
import testrun as supervised_test
from adaptive_common import AdaptiveError,load_blueprint
from workflowlib import boundedio


COMMAND_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024
CLIENT_OUTPUT_LIMIT_BYTES = 1024 * 1024
PROCESS_CLEANUP_GRACE_SECONDS = 5.0
HTTP_BODY_LIMIT_BYTES = 1024 * 1024
HTTP_TOTAL_TIMEOUT_SECONDS = 15.0
SAFE_CLIENT_ENVIRONMENT = ("PATH","LANG","LC_ALL","LC_CTYPE","TZ","TMPDIR","TMP","TEMP","TERM","AGENT_IMAGE")


def client_environment(source: Dict[str,str]) -> Dict[str,str]:
    result={key:source[key] for key in SAFE_CLIENT_ENVIRONMENT if key in source}
    result.setdefault("PATH",os.defpath); result.setdefault("LANG","C"); result.setdefault("LC_ALL","C")
    return result


def supervised_command(command: List[str], timeout: int, env: Dict[str, str], output_limit: int) -> Dict[str, object]:
    launch_token=uuid.uuid4().hex; launch_env=dict(env or {})
    launch_env[supervised_test.LAUNCH_TOKEN_NAME]=launch_token
    if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
        raise RuntimeError("acceptance runtime requires default SIGCHLD ownership")
    with supervised_test.child_subreaper() as boundary_supported:
        if not boundary_supported:
            raise RuntimeError("acceptance runtime cannot establish its process supervision boundary")
        process=subprocess.Popen(
            command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,
            start_new_session=True,env=launch_env,close_fds=True,bufsize=0,
        )
        return supervised_test.supervise_bounded_process(
            process,timeout,launch_token,output_limit=output_limit,grace=PROCESS_CLEANUP_GRACE_SECONDS)


def run(command: List[str], timeout: int, env: Dict[str, str] = None) -> str:
    result=supervised_command(command,timeout,env or dict(os.environ),COMMAND_OUTPUT_LIMIT_BYTES)
    output=bytes(result["output"]); text=output.decode("utf-8",errors="replace")
    if result["output_limit_exceeded"]:
        raise RuntimeError(f"command output exceeded {COMMAND_OUTPUT_LIMIT_BYTES} bytes: {' '.join(command)}")
    if not result["cleanup_ok"]:
        raise RuntimeError(f"command cleanup could not be proved: {' '.join(command)}")
    if result["exit_code"]:
        raise RuntimeError(f"command failed ({result['exit_code']}): {' '.join(command)}\n{text}")
    return text.strip()


def compact(output: str, lines: int = 80) -> Dict[str, object]:
    rows = output.splitlines()
    return {"sha256": hashlib.sha256(output.encode()).hexdigest(), "line_count": len(rows), "tail": rows[-lines:]}


def run_client(command: List[str], timeout: int, env: Dict[str, str]) -> Dict[str, object]:
    result=supervised_command(command,timeout,client_environment(env),CLIENT_OUTPUT_LIMIT_BYTES)
    output=bytes(result["output"]); text=output.decode("utf-8",errors="replace")
    return {
        "command":command,"exit_code":int(result["exit_code"]),"raw_output":text,
        "output_limit_exceeded":bool(result["output_limit_exceeded"]),
        "process_cleanup":{"remaining":0 if result["cleanup_ok"] else -1},
    }


def agent_config() -> Dict[str, object]:
    root=Path.cwd().resolve(); path=Path(os.path.abspath(".agent/config.json"))
    if not path.is_file(): return {}
    reject_symlink_components(path,root,"agent configuration")
    try:
        value=json.loads(bounded_regular_bytes(path,1024*1024).decode("utf-8"))
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def isolated_environment() -> Dict[str, str]:
    blocked = {
        "DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
        "BUILDX_BUILDER",
    }
    return {
        key: value for key, value in os.environ.items()
        if not key.startswith("COMPOSE_") and key not in blocked
    }


def docker_context_roots() -> List[Path]:
    if not any(Path(name).is_file() for name in ("compose.yaml","compose.yml")): return []
    raw=run(["docker","compose","config","--format","json"],30,isolated_environment())
    try: value=json.loads(raw)
    except ValueError as error: raise RuntimeError("resolved Compose configuration is not JSON") from error
    services=value.get("services") if isinstance(value,dict) else None
    if not isinstance(services,dict): raise RuntimeError("resolved Compose services are invalid")
    contexts=set()
    for service in services.values():
        build=service.get("build") if isinstance(service,dict) else None
        if build is None: continue
        context=build if isinstance(build,str) else build.get("context") if isinstance(build,dict) else None
        if not isinstance(context,str) or not context.strip() or "://" in context or context.startswith("git@"):
            raise RuntimeError("acceptance requires every Docker build context to be one local project directory")
        candidate=Path(context); candidate=candidate if candidate.is_absolute() else Path.cwd()/candidate
        candidate=Path(os.path.abspath(str(candidate)))
        try: candidate.relative_to(Path.cwd().resolve())
        except ValueError: raise RuntimeError("Docker build context escapes the governed project")
        current=Path.cwd().resolve()
        for part in candidate.relative_to(current).parts:
            current=current/part
            if current.is_symlink(): raise RuntimeError("Docker build context has a symlink component")
        if not candidate.is_dir(): raise RuntimeError("Docker build context is not a directory")
        contexts.add(candidate)
    return sorted(contexts)


MAX_INVENTORY_ENTRIES = 100000
MAX_INVENTORY_BYTES = 512 * 1024 * 1024


def bounded_regular_digest(path: Path,expected,byte_limit: int) -> str:
    if byte_limit<0: raise RuntimeError("acceptance file inventory exceeds its byte limit")
    observed=os.lstat(path); identity=lambda value:(value.st_dev,value.st_ino,value.st_size,stat.S_IFMT(value.st_mode),value.st_mtime_ns,value.st_ctime_ns)
    if not stat.S_ISREG(observed.st_mode) or identity(observed)!=identity(expected) or observed.st_size>byte_limit:
        raise RuntimeError("acceptance file identity or size changed before hashing")
    return boundedio.sha256(path,maximum=byte_limit,label="acceptance source file")


def bounded_regular_bytes(path: Path,byte_limit: int) -> bytes:
    return boundedio.read_bytes(path,maximum=byte_limit,label="acceptance control file")


def reject_symlink_components(path: Path, root: Path, label: str) -> Path:
    try: relative=path.relative_to(root)
    except ValueError: raise RuntimeError(f"{label} escapes the project")
    current=root
    for part in relative.parts:
        current=current/part
        try: observed=os.lstat(current)
        except FileNotFoundError: return relative
        if stat.S_ISLNK(observed.st_mode): raise RuntimeError(f"{label} has a symlink component")
    return relative



def bounded_tree_entries(root: Path, state: Dict[str,int], label: str):
    stack=[root]
    while stack:
        directory=stack.pop(); directories=[]; nondirectories=[]
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    state["count"]=state.get("count",0)+1
                    if state["count"]>MAX_INVENTORY_ENTRIES:
                        raise RuntimeError(f"{label} exceeds {MAX_INVENTORY_ENTRIES} entries")
                    observed=entry.stat(follow_symlinks=False); item=(entry.name,Path(entry.path),observed)
                    if stat.S_ISDIR(observed.st_mode): directories.append(item)
                    else: nondirectories.append(item)
        except FileNotFoundError as error: raise RuntimeError(f"{label} changed during traversal") from error
        directories.sort(key=lambda item:item[0]); nondirectories.sort(key=lambda item:item[0])
        for collection in (directories,nondirectories):
            for _name,path,observed in collection: yield path,observed
        for _name,path,_observed in reversed(directories): stack.append(path)


def docker_context_manifest() -> List[Dict[str,object]]:
    records=[]; total=0; root=Path.cwd().resolve(); state={"count":0}
    for context in docker_context_roots():
        for path,observed in bounded_tree_entries(context,state,"Docker build-context inventory"):
            relative=path.relative_to(root).as_posix(); mode=stat.S_IMODE(observed.st_mode)
            if stat.S_ISREG(observed.st_mode):
                if observed.st_size>MAX_INVENTORY_BYTES-total: raise RuntimeError("Docker build-context inventory exceeds 512 MiB")
                value=bounded_regular_digest(path,observed,MAX_INVENTORY_BYTES-total); total+=observed.st_size; kind="file"
            elif stat.S_ISDIR(observed.st_mode): value=hashlib.sha256(b"directory").hexdigest(); kind="directory"
            elif stat.S_ISLNK(observed.st_mode): value=hashlib.sha256(os.readlink(path).encode()).hexdigest(); kind="symlink"
            else: raise RuntimeError(f"Docker build context contains a special file: {relative}")
            records.append({"path":relative,"sha256":value,"kind":kind,"mode":mode})
    return records


def workspace_fingerprint() -> Dict[str, object]:
    configured=agent_config().get("scope",{})
    paths=configured.get("fingerprint_paths",[]) if isinstance(configured,dict) else []
    if not isinstance(paths,list) or not paths:
        paths=["src","public","docker","tests","e2e","integration","Dockerfile",".dockerignore","compose.yaml","package.json","package-lock.json",".agent/config.json",".agent/acceptance-client.json"]
    root=Path.cwd().resolve(); combined={record["path"]:record for record in docker_context_manifest()}
    total=0; state={"count":0}
    def include(path: Path, observed) -> None:
        nonlocal total
        if not stat.S_ISREG(observed.st_mode): return
        if observed.st_size>MAX_INVENTORY_BYTES-total: raise RuntimeError("workspace fingerprint exceeds its byte limit")
        relative=Path(os.path.abspath(str(path))).relative_to(root).as_posix()
        value=bounded_regular_digest(path,observed,MAX_INVENTORY_BYTES-total); total+=observed.st_size
        combined[relative]={"path":relative,"sha256":value,"kind":"file","mode":stat.S_IMODE(observed.st_mode)}
    for raw in paths:
        candidate=Path(str(raw)); candidate=candidate if candidate.is_absolute() else root/candidate
        candidate=Path(os.path.abspath(str(candidate)))
        reject_symlink_components(candidate,root,"workspace fingerprint path")
        try: observed=os.lstat(candidate)
        except FileNotFoundError: continue
        if stat.S_ISREG(observed.st_mode):
            state["count"]+=1
            if state["count"]>MAX_INVENTORY_ENTRIES: raise RuntimeError("workspace fingerprint exceeds its entry limit")
            include(candidate,observed); continue
        if not stat.S_ISDIR(observed.st_mode): continue
        for path,entry_stat in bounded_tree_entries(candidate,state,"workspace fingerprint"):
            include(path,entry_stat)
    manifest=sorted(combined.values(),key=lambda item:(str(item["path"]),str(item["kind"])))
    encoded=json.dumps(manifest,sort_keys=True,separators=(",",":")).encode()
    return {"sha256":hashlib.sha256(encoded).hexdigest(),"files":manifest}



class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,new_url):
        return None


def same_http_origin(base_url: str, candidate_url: str) -> bool:
    try: base=urllib.parse.urlsplit(base_url); candidate=urllib.parse.urlsplit(candidate_url); base_port=base.port; candidate_port=candidate.port
    except ValueError: return False
    return (
        base.scheme==candidate.scheme=="http" and base.hostname==candidate.hostname
        and base_port==candidate_port and candidate.username is None and candidate.password is None
        and not candidate.fragment
    )


def fetch(url: str) -> Dict[str, object]:
    parsed=urllib.parse.urlsplit(url)
    if (parsed.scheme!="http" or parsed.hostname not in {"127.0.0.1","localhost","::1"}
            or parsed.username is not None or parsed.password is not None or parsed.fragment):
        raise RuntimeError("acceptance HTTP fetch must target a canonical loopback HTTP URL")
    if threading.current_thread() is not threading.main_thread() or not hasattr(signal,"setitimer"):
        raise RuntimeError("acceptance HTTP total-deadline enforcement is unavailable")
    previous_timer=signal.getitimer(signal.ITIMER_REAL)
    if previous_timer[0]>0 or previous_timer[1]>0:
        raise RuntimeError("acceptance HTTP fetch refuses to replace an active process timer")
    previous_handler=signal.getsignal(signal.SIGALRM)
    def deadline(_signum,_frame): raise TimeoutError("acceptance HTTP fetch exceeded its total deadline")
    signal.signal(signal.SIGALRM,deadline); signal.setitimer(signal.ITIMER_REAL,HTTP_TOTAL_TIMEOUT_SECONDS)
    try:
        opener=urllib.request.build_opener(RejectRedirect())
        request=urllib.request.Request(url,headers={"Connection":"close"})
        with opener.open(request,timeout=HTTP_TOTAL_TIMEOUT_SECONDS) as response:
            body=response.read(HTTP_BODY_LIMIT_BYTES+1)
            if len(body)>HTTP_BODY_LIMIT_BYTES:
                raise RuntimeError("acceptance HTTP body exceeds its byte limit")
            return {
                "url":url,"status":response.status,
                "headers":{key.lower():value for key,value in response.headers.items()},
                "body":body.decode(errors="replace"),
            }
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,previous_handler)


def docker_namespace_inventory(project_name: str,image_tag: str,runtime_env: Dict[str,str]):
    commands={
        "containers":["docker","ps","-aq","--filter",f"label=com.docker.compose.project={project_name}"],
        "networks":["docker","network","ls","-q","--filter",f"label=com.docker.compose.project={project_name}"],
        "volumes":["docker","volume","ls","-q","--filter",f"label=com.docker.compose.project={project_name}"],
        "images":["docker","image","ls","-q","--filter",f"reference={image_tag}"],
    }; observed={}
    for kind,command in commands.items():
        values=[line.strip() for line in run(command,30,runtime_env).splitlines() if line.strip()]
        if len(values)>256: raise RuntimeError(f"acceptance Docker {kind} inventory exceeds 256 entries")
        observed[kind]=values
    return observed


def cleanup_acceptance_resources(compose: List[str],project_name: str,image_tag: str,runtime_env: Dict[str,str]):
    result={}; errors=[]
    try: result["cleanup_command"]=compact(run(compose+["down","--remove-orphans","--volumes"],60,runtime_env))
    except (RuntimeError,subprocess.TimeoutExpired,OSError) as error: errors.append("compose down: "+str(error))
    try: owned=docker_namespace_inventory(project_name,image_tag,runtime_env)
    except (RuntimeError,subprocess.TimeoutExpired,OSError) as error:
        owned={"containers":[],"networks":[],"volumes":[],"images":[]}; errors.append("owned resource inventory: "+str(error))
    removals={"containers":(["docker","rm","--force"],r"[0-9a-f]{12,64}"),"networks":(["docker","network","rm"],r"[0-9a-f]{12,64}"),"volumes":(["docker","volume","rm","--force"],r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")}
    for kind in ("containers","networks","volumes"):
        prefix,pattern=removals[kind]
        for identity in owned[kind]:
            try:
                if re.fullmatch(pattern,identity) is None: raise RuntimeError(f"unsafe Docker {kind} cleanup identity")
                run(prefix+[identity],60,runtime_env)
            except (RuntimeError,subprocess.TimeoutExpired,OSError) as error: errors.append(f"{kind} removal {identity!r}: {error}")
    if owned["images"]:
        try: result["image_cleanup"]=compact(run(["docker","image","rm","--force",image_tag],60,runtime_env))
        except (RuntimeError,subprocess.TimeoutExpired,OSError) as error: errors.append("candidate image removal: "+str(error))
    try: residual={kind:len(values) for kind,values in docker_namespace_inventory(project_name,image_tag,runtime_env).items()}
    except (RuntimeError,subprocess.TimeoutExpired,OSError) as error:
        residual={"containers":1,"networks":1,"volumes":1,"images":1}; errors.append("residual observation: "+str(error))
    result["cleanup"]=residual
    if errors: result["cleanup_errors"]=errors
    return result


def exact_candidate_service_binding(containers,loaded_image_id,expected_services):
    if not isinstance(loaded_image_id,str) or re.fullmatch(r"sha256:[0-9a-f]{64}",loaded_image_id) is None:
        raise RuntimeError("candidate image has no canonical loaded identity")
    candidate=[item for item in containers if isinstance(item,dict) and item.get("image")==loaded_image_id]
    services=sorted({item.get("service") for item in candidate if isinstance(item.get("service"),str) and item.get("service")})
    if not services or len(services)!=len(candidate):
        raise RuntimeError("compose must run at least one uniquely named service from the exact loaded candidate image")
    if services!=expected_services:
        raise RuntimeError("exact loaded candidate services differ from the user-governed application service set")
    return candidate,services


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--health-url", required=True)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--web-baseline", action="store_true")
    parser.add_argument("--client-command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if not re.fullmatch(r"agent_acceptance_[a-z0-9][a-z0-9_-]{3,55}", args.project_name):
        print(json.dumps({"status": "failed", "error": "project-name must be unique and start with agent_acceptance_"}))
        return 1
    try:
        blueprint=load_blueprint(Path.cwd(),require_confirmed=True)
        application_services=blueprint["design"].get("application_services")
        blueprint_sha256=blueprint["confirmation"]["design_sha256"]
    except (AdaptiveError,OSError,KeyError,TypeError,ValueError,SystemExit) as error:
        print(json.dumps({"status":"failed","error":f"confirmed Blueprint application-service authority is unavailable: {error}"}))
        return 1
    if (not isinstance(application_services,list) or not 1<=len(application_services)<=16
            or application_services!=sorted(set(application_services))
            or any(re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}",service) is None for service in application_services)):
        print(json.dumps({"status":"failed","error":"confirmed Blueprint must bind an exact non-empty Compose application_services set"}))
        return 1

    compose = ["docker", "compose", "-p", args.project_name]
    evidence: Dict[str, object] = {
        "schema": "run_acceptance_runtime/v2", "tool": "run_acceptance_runtime",
        "tool_sha256": bounded_regular_digest(Path(__file__),os.lstat(Path(__file__)),16*1024*1024),
        "project": args.project_name, "health_url": args.health_url, "blueprint_sha256": blueprint_sha256,
        "application_services": application_services,
        "candidate_sha256": supervised_test.candidate_fingerprint(agent_config()),
        "source": workspace_fingerprint(),
    }
    runtime_env = isolated_environment()
    project_name = str(agent_config().get("project", {}).get("name", "agent-project")) if isinstance(agent_config().get("project"), dict) else "agent-project"
    image_name = re.sub(r"[^a-z0-9_.-]+", "-", project_name.lower()).strip("-._") or "agent-project"
    project_tag=hashlib.sha256(args.project_name.encode("utf-8")).hexdigest()[:12]
    runtime_env["AGENT_IMAGE"] = f"{image_name}:acceptance-{evidence['source']['sha256'][:16]}-{project_tag}"
    evidence["image_tag"] = runtime_env["AGENT_IMAGE"]
    exit_code=0; cleanup_authorized=False
    try:
        evidence["docker"]=run(["docker","version","--format","{{.Server.Version}}"],30,runtime_env)
        evidence["compose"]=run(["docker","compose","version","--short"],30,runtime_env)
        preexisting=docker_namespace_inventory(args.project_name,runtime_env["AGENT_IMAGE"],runtime_env)
        evidence["namespace_preflight"]={kind:len(values) for kind,values in preexisting.items()}
        if any(preexisting.values()): raise RuntimeError("acceptance Docker namespace is not clean and cannot be claimed")
        cleanup_authorized=True
        resolved = run(compose + ["config"], 30, runtime_env)
        evidence["resolved_compose"] = compact(resolved)
        with tempfile.TemporaryDirectory(prefix=f"{args.project_name}_image_") as image_dir:
            archive = str(Path(image_dir) / "image.oci.tar")
            build = [
                "docker", "buildx", "build", "--pull", "--provenance=false", "--sbom=false",
                "--build-arg", "SOURCE_DATE_EPOCH=0",
                "--output", f"type=oci,dest={archive},rewrite-timestamp=true,name={runtime_env['AGENT_IMAGE']}",
            ]
            if args.no_cache:
                build.append("--no-cache")
            build.append(".")
            build_output = run(build, args.timeout, runtime_env)
            load_output = run(["docker", "load", "-i", archive], args.timeout, runtime_env)
            loaded_ids=run(["docker","image","ls","-q","--filter",f"reference={runtime_env['AGENT_IMAGE']}"],30,runtime_env).splitlines()
            if len(set(loaded_ids))!=1: raise RuntimeError("candidate image load did not produce one exact image")
            loaded_image_id=run(["docker","image","inspect",runtime_env["AGENT_IMAGE"],"--format","{{.Id}}"],30,runtime_env)
            if re.fullmatch(r"sha256:[0-9a-f]{64}",loaded_image_id) is None: raise RuntimeError("candidate image has no canonical loaded identity")
            evidence["loaded_image_id"]=loaded_image_id
            evidence["build"] = compact(build_output + "\n" + load_output)
        evidence["up"] = compact(run(compose + ["up", "-d", "--force-recreate", "--wait", "--wait-timeout", str(args.timeout)], args.timeout, runtime_env))

        expected_images: Set[str] = {
            value if value.startswith("sha256:") else f"sha256:{value}"
            for value in run(compose + ["images", "-q"], 30, runtime_env).splitlines()
        }
        container_ids = run(compose + ["ps", "-q"], 30, runtime_env).splitlines()
        if not container_ids:
            raise RuntimeError("compose started no containers")
        containers = []
        for container_id in container_ids:
            data = json.loads(run(["docker", "inspect", container_id, "--format", "{{json .}}"], 30, runtime_env))
            host = data["HostConfig"]
            state = data["State"]
            health = state.get("Health", {}).get("Status", "none")
            published_ports = [
                {"container_port": container_port, "host_ip": binding.get("HostIp", ""), "host_port": binding.get("HostPort", "")}
                for container_port, values in data["NetworkSettings"].get("Ports", {}).items() if values
                for binding in values
            ]
            bindings = [binding["host_ip"] for binding in published_ports]
            normalized_image = run(["docker", "image", "inspect", data["Image"], "--format", "{{.Id}}"], 30, runtime_env)
            item = {
                "id": data["Id"], "service": (data["Config"].get("Labels") or {}).get("com.docker.compose.service", ""),
                "image_ref": data["Image"], "image": normalized_image, "status": state["Status"], "health": health,
                "user": data["Config"].get("User", ""), "readonly_rootfs": host.get("ReadonlyRootfs", False),
                "cap_drop": host.get("CapDrop") or [], "security_opt": host.get("SecurityOpt") or [],
                "tmpfs": host.get("Tmpfs") or {}, "host_ips": bindings,
                "published_ports": published_ports,
            }
            containers.append(item)
            if item["image"] not in expected_images:
                raise RuntimeError("running container image differs from resolved compose image")
            if item["status"] != "running" or item["health"] != "healthy":
                raise RuntimeError("every declared service must be running and healthy")
            if item["user"] in ("", "0", "root") or not item["readonly_rootfs"]:
                raise RuntimeError("containers must run non-root with a read-only root filesystem")
            if "ALL" not in item["cap_drop"] or "no-new-privileges:true" not in item["security_opt"]:
                raise RuntimeError("containers must drop all capabilities and enable no-new-privileges")
            if "/tmp" not in item["tmpfs"]:
                raise RuntimeError("containers must use an explicit test-only /tmp tmpfs")
            if bindings and any(ip not in {"127.0.0.1", "::1"} for ip in bindings):
                raise RuntimeError("published acceptance ports must bind only to loopback")
        evidence["containers"] = containers
        candidate_containers,candidate_services=exact_candidate_service_binding(containers,evidence.get("loaded_image_id"),application_services)
        evidence["candidate_services"]=candidate_services

        parsed_health = urllib.parse.urlsplit(args.health_url)
        health_port = str(parsed_health.port or (80 if parsed_health.scheme == "http" else 443))
        published = [port for item in candidate_containers for port in item["published_ports"]]
        if parsed_health.scheme != "http" or parsed_health.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed_health.path != "/healthz" or not any(port["host_port"] == health_port and port["host_ip"] in {"127.0.0.1", "::1"} for port in published):
            raise RuntimeError("health URL must target the inspected container's published loopback /healthz port")
        health_result = fetch(args.health_url)
        evidence["health"] = {key: value for key, value in health_result.items() if key != "body"}
        evidence["health"]["body"] = health_result["body"][:200]
        if health_result["status"] != 200 or not health_result["headers"].get("content-type", "").startswith("text/plain"):
            raise RuntimeError("health endpoint must return 200 text/plain")

        if args.web_baseline:
            parsed = urllib.parse.urlsplit(args.health_url)
            root_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
            root = fetch(root_url)
            required_headers = {"content-security-policy", "referrer-policy", "x-content-type-options", "x-frame-options"}
            if root["status"] != 200 or not required_headers.issubset(root["headers"]):
                raise RuntimeError("web baseline requires root 200 and security headers")
            script=re.search(r'<script[^>]+src="([^"]+)"',root["body"])
            asset_url=urllib.parse.urljoin(root_url,script.group(1)) if script else ""
            if (not asset_url or not same_http_origin(root_url,asset_url)
                    or fetch(asset_url)["status"]!=200):
                raise RuntimeError("web baseline requires one same-origin loadable script asset")
            deep = fetch(urllib.parse.urljoin(root_url, "__acceptance__/deep/link"))
            if deep["status"] != 200 or deep["body"] != root["body"]:
                raise RuntimeError("web baseline requires SPA fallback")
            evidence["web_baseline"] = {"root": 200, "asset": 200, "spa": 200, "security_headers": sorted(required_headers)}

        if args.client_command:
            client = run_client(args.client_command, args.timeout, runtime_env)
            evidence["client"] = {"command": args.client_command, "exit_code": client["exit_code"], "output": compact(str(client["raw_output"])), "process_cleanup": client["process_cleanup"], "output_limit_exceeded": client["output_limit_exceeded"]}
            try:
                receipt = json.loads(str(client["raw_output"]))
            except ValueError:
                receipt = None
            evidence["client"]["receipt"] = receipt if isinstance(receipt, dict) else None
            if client["exit_code"]:
                raise RuntimeError("real client command failed")

        logs = run(compose + ["logs", "--no-color", "--tail", "200"], 30, runtime_env)
        evidence["logs"] = compact(logs)
        if re.search(r"\[(emerg|alert|crit|error)\]|\b(fatal|panic|unhandled)\b", logs, re.IGNORECASE):
            raise RuntimeError("container logs contain error-level entries")
        final_source = workspace_fingerprint()
        evidence["source_after"] = {"sha256": final_source["sha256"], "file_count": len(final_source["files"])}
        if final_source["sha256"] != evidence["source"]["sha256"]:
            raise RuntimeError("workspace changed during runtime acceptance")
        evidence["status"] = "passed"
    except (RuntimeError, subprocess.TimeoutExpired, OSError, ValueError) as error:
        evidence["status"] = "failed"
        evidence["error"] = str(error)
        exit_code = 1
    finally:
        if cleanup_authorized:
            try:
                cleanup_result=cleanup_acceptance_resources(compose,args.project_name,runtime_env["AGENT_IMAGE"],runtime_env)
                evidence.update(cleanup_result)
                if cleanup_result.get("cleanup_errors") or any(cleanup_result["cleanup"].values()):
                    raise RuntimeError("acceptance Docker cleanup was incomplete: "+json.dumps({"errors":cleanup_result.get("cleanup_errors",[]),"residual":cleanup_result["cleanup"]},sort_keys=True))
            except (RuntimeError,subprocess.TimeoutExpired,OSError) as error:
                evidence["cleanup_error"]=str(error); evidence["status"]="failed"; exit_code=1
        else:
            evidence["cleanup"]={"containers":0,"networks":0,"volumes":0,"images":0}
            evidence["cleanup_skipped"]="namespace authority was not acquired"

    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"scripts"))
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
