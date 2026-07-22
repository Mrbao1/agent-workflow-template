#!/usr/bin/env python3
"""Build, serve and tear down the project through an isolated Compose HTTP path."""

from pathlib import Path
import os, socket, subprocess, time, urllib.request, uuid

ROOT=Path(__file__).resolve().parents[4]
if not (ROOT/"compose.yaml").is_file():
    print("DOCKER HTTP SELF-TEST SKIPPED: project has no compose.yaml")
    raise SystemExit(0)
project="agent_http_"+uuid.uuid4().hex[:12]
with socket.socket() as probe: probe.bind(("127.0.0.1",0)); port=probe.getsockname()[1]
env={**os.environ,"AGENT_ACCEPTANCE_PORT":str(port)}; command=["docker","compose","-f","compose.yaml","-p",project]
try:
    subprocess.run([*command,"up","-d","--build","--wait"],cwd=ROOT,env=env,check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180)
    deadline=time.monotonic()+30; body=b""
    while time.monotonic()<deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/",timeout=2) as response: body=response.read(); status=response.status
            if status==200 and b"<html" in body.lower(): break
        except Exception: time.sleep(.25)
    else: raise SystemExit("Docker HTTP path did not become healthy")
finally:
    subprocess.run([*command,"down","--remove-orphans"],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90)
residual=subprocess.run(["docker","ps","-aq","--filter",f"label=com.docker.compose.project={project}"],text=True,stdout=subprocess.PIPE,check=True)
if residual.stdout.strip(): raise SystemExit("Docker container residual remains")
print("DOCKER HTTP SELF-TEST PASSED")
