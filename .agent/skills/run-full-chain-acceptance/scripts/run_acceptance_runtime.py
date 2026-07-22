#!/usr/bin/env python3
"""Build, start, enforce, probe, and always clean a Docker Compose runtime."""

from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from typing import Dict, List, Set

sys.path.insert(0, str((Path.cwd() / ".agent/scripts").resolve()))
import testrun as supervised_test


CLIENT_TERM_DRAIN_SECONDS = 5
CLIENT_KILL_DRAIN_SECONDS = 2
CLIENT_REAP_SECONDS = 1


def run(command: List[str], timeout: int, env: Dict[str, str] = None) -> str:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=env)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}")
    return result.stdout.strip()


def compact(output: str, lines: int = 80) -> Dict[str, object]:
    rows = output.splitlines()
    return {"sha256": hashlib.sha256(output.encode()).hexdigest(), "line_count": len(rows), "tail": rows[-lines:]}


def terminate_process_group(pgid: int) -> bool:
    def exists():
        try:
            result = subprocess.run(["ps", "-axo", "pgid="], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode:
            return None
        return any(value.strip().isdigit() and int(value.strip()) == pgid for value in result.stdout.splitlines())

    state = exists()
    if state is False:
        return True
    if state is None:
        return False
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    for _ in range(30):
        state = exists()
        if state is False:
            return True
        if state is None:
            return False
        time.sleep(0.1)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    for _ in range(30):
        state = exists()
        if state is False:
            return True
        if state is None:
            return False
        time.sleep(0.1)
    return exists() is False


def output_text(raw: object) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def merge_output(previous: str, observed: object) -> str:
    """Merge TimeoutExpired.output without duplicating communicate's prefix."""
    current = output_text(observed)
    if current.startswith(previous):
        return current
    if previous.endswith(current):
        return previous
    return previous + current


def close_output_pipe(process: subprocess.Popen) -> None:
    if process.stdout is not None and not process.stdout.closed:
        try:
            process.stdout.close()
        except OSError:
            pass


def run_client(command: List[str], timeout: int, env: Dict[str, str]) -> Dict[str, object]:
    process = subprocess.Popen(
        command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True, env=env,
    )
    output = ""
    pipe_drained = True
    try:
        output, _ = process.communicate(timeout=timeout)
        code = process.returncode
    except subprocess.TimeoutExpired as error:
        output = merge_output(output, error.output)
        code = 124
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
        try:
            remaining, _ = process.communicate(timeout=CLIENT_TERM_DRAIN_SECONDS)
            output = merge_output(output, remaining)
        except subprocess.TimeoutExpired as error:
            output = merge_output(output, error.output)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                remaining, _ = process.communicate(timeout=CLIENT_KILL_DRAIN_SECONDS)
                output = merge_output(output, remaining)
            except subprocess.TimeoutExpired as final_error:
                output = merge_output(output, final_error.output)
                pipe_drained = False
                close_output_pipe(process)
    finally:
        cleaned = terminate_process_group(process.pid) and pipe_drained
        if process.poll() is None:
            try:
                process.wait(timeout=CLIENT_REAP_SECONDS)
            except subprocess.TimeoutExpired:
                cleaned = False
                close_output_pipe(process)
    return {"command": command, "exit_code": code if cleaned else 125, "raw_output": output, "process_cleanup": {"remaining": 0 if cleaned else -1}}


def agent_config() -> Dict[str, object]:
    path = Path(".agent/config.json")
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
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


def workspace_fingerprint() -> Dict[str, object]:
    configured = agent_config().get("scope", {})
    paths = configured.get("fingerprint_paths", []) if isinstance(configured, dict) else []
    if not isinstance(paths, list) or not paths:
        paths = ["src", "public", "docker", "tests", "e2e", "integration", "Dockerfile", "compose.yaml", "package.json", "package-lock.json", ".agent/config.json", ".agent/acceptance-client.json"]
    files = []
    for raw in paths:
        path = Path(str(raw))
        if path.is_dir():
            files.extend(item for item in path.rglob("*") if item.is_file() and not item.is_symlink())
        elif path.is_file() and not path.is_symlink():
            files.append(path)
    manifest = []
    for path in sorted(set(path for path in files if path.is_file())):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest.append({"path": str(path), "sha256": digest})
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "files": manifest}


def fetch(url: str) -> Dict[str, object]:
    with urllib.request.urlopen(url, timeout=15) as response:
        return {
            "url": url, "status": response.status,
            "headers": {key.lower(): value for key, value in response.headers.items()},
            "body": response.read().decode(errors="replace"),
        }


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

    compose = ["docker", "compose", "-p", args.project_name]
    evidence: Dict[str, object] = {
        "schema": "run_acceptance_runtime/v1", "tool": "run_acceptance_runtime",
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "project": args.project_name, "health_url": args.health_url,
        "candidate_sha256": supervised_test.candidate_fingerprint(agent_config()),
        "source": workspace_fingerprint(),
    }
    runtime_env = isolated_environment()
    project_name = str(agent_config().get("project", {}).get("name", "agent-project")) if isinstance(agent_config().get("project"), dict) else "agent-project"
    image_name = re.sub(r"[^a-z0-9_.-]+", "-", project_name.lower()).strip("-._") or "agent-project"
    runtime_env["AGENT_IMAGE"] = f"{image_name}:acceptance-{evidence['source']['sha256'][:16]}"
    evidence["image_tag"] = runtime_env["AGENT_IMAGE"]
    exit_code = 0
    try:
        evidence["docker"] = run(["docker", "version", "--format", "{{.Server.Version}}"], 30, runtime_env)
        evidence["compose"] = run(["docker", "compose", "version", "--short"], 30, runtime_env)
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
                "id": data["Id"], "image_ref": data["Image"], "image": normalized_image, "status": state["Status"], "health": health,
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

        parsed_health = urllib.parse.urlsplit(args.health_url)
        health_port = str(parsed_health.port or (80 if parsed_health.scheme == "http" else 443))
        published = [port for item in containers for port in item["published_ports"]]
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
            script = re.search(r'<script[^>]+src="([^"]+)"', root["body"])
            if not script or fetch(urllib.parse.urljoin(root_url, script.group(1)))["status"] != 200:
                raise RuntimeError("web baseline requires a loadable script asset")
            deep = fetch(urllib.parse.urljoin(root_url, "__acceptance__/deep/link"))
            if deep["status"] != 200 or deep["body"] != root["body"]:
                raise RuntimeError("web baseline requires SPA fallback")
            evidence["web_baseline"] = {"root": 200, "asset": 200, "spa": 200, "security_headers": sorted(required_headers)}

        if args.client_command:
            client = run_client(args.client_command, args.timeout, runtime_env)
            evidence["client"] = {"command": args.client_command, "exit_code": client["exit_code"], "output": compact(str(client["raw_output"])), "process_cleanup": client["process_cleanup"]}
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
        try:
            evidence["cleanup_command"] = compact(run(compose + ["down", "--remove-orphans"], 60, runtime_env))
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
            evidence["cleanup_error"] = str(error)
            evidence["status"] = "failed"
            exit_code = 1
        try:
            residual_containers = run(["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={args.project_name}"], 30, runtime_env).splitlines()
            residual_networks = run(["docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={args.project_name}"], 30, runtime_env).splitlines()
            evidence["cleanup"] = {"containers": len(residual_containers), "networks": len(residual_networks)}
            if residual_containers or residual_networks:
                exit_code = 1
                evidence["status"] = "failed"
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
            evidence["cleanup_error"] = str(error)
            evidence["status"] = "failed"
            exit_code = 1

    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
