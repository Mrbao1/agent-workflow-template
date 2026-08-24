#!/usr/bin/env python3
"""Install, check, or safely update the reusable .agent workflow."""

from pathlib import Path
import argparse, ast, datetime as dt, fcntl, hashlib, json, os, re, shutil, stat, subprocess, sys, tempfile, time, uuid

VERSION="3.2.0"
MIGRATION_VERSION=40
CANONICAL_ACCEPTANCE_ADAPTERS={
    "acceptance-workflow":{"implemented":True,"runner":".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py","receipt_schema":"workflow-release-gate/v4"},
    "acceptance-web-docker":{"implemented":True,"runner":".agent/skills/run-full-chain-acceptance/scripts/run_live_release_gate.py","receipt_schema":"acceptance-live-gate/v2"},
    "acceptance-api":{"implemented":True,"runner":".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py","receipt_schema":"local-command-release-gate/v1"},
    "acceptance-cli":{"implemented":True,"runner":".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py","receipt_schema":"local-command-release-gate/v1"},
    "acceptance-ios":{"implemented":True,"runner":".agent/skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py","receipt_schema":"local-command-release-gate/v1"},
}
MANAGED=("INDEX.md","scripts","skills","templates","workflows","assets","capabilities")
MANAGED_FILES=("knowledge/INDEX.md",)
FRESH_STATE_RELATIVE=Path("assets")/"fresh-state"/"v1"
FRESH_STATE_REQUIRED={
    "config.json","policies/PROJECT_GUARDRAILS.md","state/TASK.json",
    "state/CONTEXT.json","state/STAGE_INDEX.md","state/REQUIREMENT_CONTRACT.md",
    "state/agents.json","state/EVIDENCE_INDEX.json","state/delivery.json",
    "state/runtime.json","state/test-budget.json","state/tool-leases.json",
}
FRESH_STATE_ALLOWED=FRESH_STATE_REQUIRED|{
    "state/.agents.lock","state/.context.lock","state/.delivery.lock","state/.evidence.lock",
    "state/.runtime.lock","state/.task.lock","state/.template.lock","state/.test-budget.lock",
    "state/.tool-leases.lock","state/.project-init.lock",
}
PLUGIN_NAME="pxpipe-context"
PLUGIN_RELATIVE=Path("plugins")/PLUGIN_NAME
MARKETPLACE_RELATIVE=Path(".agents/plugins/marketplace.json")
BOOTSTRAP_START="<!-- agent-workflow-bootstrap:start -->"
BOOTSTRAP_END="<!-- agent-workflow-bootstrap:end -->"
BOOTSTRAP_BODY="""# Agent Bootstrap

Before project work, read `.agent/INDEX.md`, `.agent/config.json`, `.agent/state/TASK.json`, `.agent/state/CONTEXT.json`, and `.agent/policies/PROJECT_GUARDRAILS.md`. The guardrails are hash-bound (`project_initialization.guardrails_sha256`) and verified by bootstrap-check. Load `.agent/skills/` only when routed. Before starting the first task, run `python3 .agent/scripts/agentctl.py bootstrap-check`. At the start of each real host/model turn, account it exactly once with `python3 .agent/scripts/contextctl.py account-turn --turn-id <caller-stable-host-turn-id>`; retries of the same turn must reuse the same ID, and post-completion accounting must preserve the durable `complete-task` origin. Without a provider decision adapter, local non-deploy fast/standard tasks may use explicitly recorded current-chat decisions. Projects may explicitly opt local, reversible and non-external release-mode implementation into the same boundary; test, production, deploy, irreversible and external-impact gates remain blocked. Requirements must be clarified before design or implementation; local runtimes must be bounded and cleaned with `.agent/scripts/agentctl.py`.

After every child-agent terminal event, after every compaction, and immediately before any final reply, run `python3 .agent/scripts/workflowctl.py route-resume`. Treat that receipt as the only root-task terminal decision: when `terminal=false`, do not present the root task as complete. Repository state preserves a deterministic resume contract, but only the host scheduler can start a later model turn.
"""
BOOTSTRAP=f"{BOOTSTRAP_START}\n{BOOTSTRAP_BODY.rstrip()}\n{BOOTSTRAP_END}\n"
def sha(path):
    digest=hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda:handle.read(1024*1024),b""): digest.update(chunk)
    return digest.hexdigest()


def files(root):
    result={}
    for name in MANAGED:
        path=root/name
        if path.is_file(): result[name]=sha(path)
        elif path.is_dir():
            for item in sorted(path.rglob("*")):
                if item.is_file() and not item.is_symlink(): result[str(item.relative_to(root))]=sha(item)
    for name in MANAGED_FILES:
        path=root/name
        if path.is_file() and not path.is_symlink(): result[name]=sha(path)
    return result


def validate_private_tree(root):
    """Reject links in a private workflow tree without following them."""
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError(f"private .agent tree is missing or unsafe: {root}")
    for directory,dirnames,filenames in os.walk(root,topdown=True,followlinks=False):
        base=Path(directory)
        for name in dirnames+filenames:
            path=base/name
            if path.is_symlink():
                raise RuntimeError(f"private .agent tree contains a symlink: {path.relative_to(root)}")


def copy_private_tree(source,destination):
    # Preserve links so staging can reject them.  The default copytree mode
    # dereferences links and could import bytes from outside the project.
    shutil.copytree(source,destination,symlinks=True)
    validate_private_tree(destination)


def validate_managed_source(root):
    """Validate only release-managed inputs; source-private state is irrelevant."""
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError(f"managed .agent tree is missing or unsafe: {root}")
    for relative in (*MANAGED,*MANAGED_FILES):
        path=root/relative
        if not path.exists() and not path.is_symlink():
            continue
        if path.is_symlink():
            raise RuntimeError(f"managed source contains a symlink: {relative}")
        if path.is_dir():
            for directory,dirnames,filenames in os.walk(path,topdown=True,followlinks=False):
                base=Path(directory)
                for name in dirnames+filenames:
                    item=base/name
                    if item.is_symlink():
                        raise RuntimeError(f"managed source contains a symlink: {item.relative_to(root)}")
                    mode=item.stat().st_mode
                    if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                        raise RuntimeError(f"managed source contains a special file: {item.relative_to(root)}")
        elif not path.is_file():
            raise RuntimeError(f"managed source contains a special file: {relative}")


def fresh_state_seed(source):
    """Return the content-addressed release seed, never source project state."""
    root=source/FRESH_STATE_RELATIVE; manifest_path=root/"manifest.json"
    if root.is_symlink() or not root.is_dir() or manifest_path.is_symlink() or not manifest_path.is_file():
        raise RuntimeError("canonical fresh-state seed is missing or unsafe")
    try: value=json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError,UnicodeError,json.JSONDecodeError) as error:
        raise RuntimeError("canonical fresh-state seed manifest is invalid") from error
    if not isinstance(value,dict) or set(value)!={"schema","seed_sha256","files"} or value.get("schema")!="agent-workflow-fresh-state-seed/v1" or not isinstance(value.get("files"),dict):
        raise RuntimeError("canonical fresh-state seed manifest has invalid fields")
    observed={}
    for item in sorted(root.rglob("*")):
        if item.is_symlink(): raise RuntimeError(f"canonical fresh-state seed contains a symlink: {item.relative_to(root)}")
        if item.is_dir(): continue
        if not item.is_file(): raise RuntimeError(f"canonical fresh-state seed contains a special file: {item.relative_to(root)}")
        relative=str(item.relative_to(root))
        if relative!="manifest.json": observed[relative]=sha(item)
    if observed!=value["files"] or value.get("seed_sha256")!=tree_sha256(value["files"]):
        raise RuntimeError("canonical fresh-state seed content does not match its manifest")
    if set(observed)!=FRESH_STATE_ALLOWED:
        missing=sorted(FRESH_STATE_ALLOWED-set(observed)); extra=sorted(set(observed)-FRESH_STATE_ALLOWED)
        raise RuntimeError(f"canonical fresh-state seed inventory differs from the exact allowlist: missing={missing} extra={extra}")
    config=json.loads((root/"config.json").read_text(encoding="utf-8"))
    task=json.loads((root/"state/TASK.json").read_text(encoding="utf-8"))
    agents=json.loads((root/"state/agents.json").read_text(encoding="utf-8"))
    if (
        config.get("project")!={"name":"__PROJECT_NAME__","type":"__PROJECT_TYPE__"}
        or config.get("guardrails_ready") is not False
        or config.get("project_initialization") is not None
        or config.get("agent_control",{}).get("human_decision_observer",{}).get("signed_adapter") is not None
        or config.get("agent_control",{}).get("provider_preflight_observer",{}).get("signed_adapter") is not None
        or task.get("status")!="idle" or task.get("requirements_clarified") is not False
        or task.get("requirement_source")!="pending" or task.get("current_node")!="idle"
        or agents.get("schema")!="agent-team/v9"
        or any(agents.get(name)!=[] for name in ("members","prepared_dispatches","capacity_failures","replay_runs"))
        or agents.get("migration_source") is not None or agents.get("last_platform_snapshot") is not None
    ):
        raise RuntimeError("canonical fresh-state seed is not an isolated uninitialized project")
    guardrails=(root/"policies/PROJECT_GUARDRAILS.md").read_text(encoding="utf-8")
    if "agent-workflow-project-guardrails:v1 uninitialized" not in guardrails:
        raise RuntimeError("canonical fresh-state seed lacks the uninitialized guardrails marker")
    return root


def copy_managed_fresh_install(source,destination):
    """Build a project from managed release files plus the immutable seed."""
    destination.mkdir(parents=True,exist_ok=False)
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
    validate_private_tree(destination)


def tree_sha256(entries):
    payload=json.dumps(entries,sort_keys=True,separators=(",",":")).encode()
    return hashlib.sha256(payload).hexdigest()


def canonical_sha256(value):
    payload=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return hashlib.sha256(payload).hexdigest()


def version_triplet(value):
    if not isinstance(value,str): return None
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",value) is None: return None
    parts=value.split(".")
    return tuple(int(part) for part in parts)


def version_relation(installed,current):
    """Compare strict numeric versions and reject unknown installed syntax."""
    left,right=version_triplet(installed),version_triplet(current)
    if left is None: return "invalid_installed"
    if right is None: raise RuntimeError("template workflow version is invalid")
    if left>right: return "target_newer"
    if left<right: return "target_older"
    return "same"


def repo_plugin_files(root):
    if not root.is_dir() or root.is_symlink(): raise RuntimeError(f"repo plugin is missing or unsafe: {root}")
    result={}
    for item in sorted(root.rglob("*")):
        if item.is_symlink(): raise RuntimeError(f"repo plugin contains a symlink: {item}")
        if item.is_file(): result[str(item.relative_to(root))]=sha(item)
    if not result: raise RuntimeError("repo plugin is empty")
    return result


def read_marketplace(path):
    try: value=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as error: raise RuntimeError(f"marketplace is missing or invalid: {path}") from error
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


def source_contract(source_root):
    validate_bootstrap(source_root/"AGENTS.md","AGENTS.md")
    validate_bootstrap(source_root/"CLAUDE.md","CLAUDE.md")
    validate_managed_source(source_root/".agent")
    fresh_state_seed(source_root/".agent")
    agent_files=files(source_root/".agent")
    plugin_files=repo_plugin_files(source_root/PLUGIN_RELATIVE)
    validate_repo_plugin(source_root/PLUGIN_RELATIVE,plugin_files)
    marketplace=read_marketplace(source_root/MARKETPLACE_RELATIVE)
    entry=named_marketplace_entry(marketplace)
    entry_digest=canonical_sha256(entry)
    return agent_files,plugin_files,entry,entry_digest


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


def manifest(path,required=False):
    if not path.is_file():
        if required: raise SystemExit("workflow is unmanaged: missing .workflow-manifest.json; use --adopt after verifying an exact source match")
        return None
    value=json.loads(path.read_text(encoding="utf-8"))
    schema=value.get("schema")
    if schema=="agent-workflow-install/v1":
        if not isinstance(value.get("files"),dict): raise SystemExit("invalid workflow install manifest")
        if value.get("source_tree_sha256")!=tree_sha256(value["files"]): raise SystemExit("workflow install manifest source tree hash is invalid")
    elif schema in {"agent-workflow-install/v2","agent-workflow-install/v3","agent-workflow-install/v4"}:
        if not isinstance(value.get("agent_files"),dict) or not isinstance(value.get("repo_plugin_files"),dict):
            raise SystemExit("invalid workflow install manifest")
        entry=value.get("marketplace_entry")
        if not isinstance(entry,dict) or set(entry)!={"name","sha256"} or entry.get("name")!=PLUGIN_NAME or not isinstance(entry.get("sha256"),str):
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
    if not isinstance(value.get("migration_version"),int): raise SystemExit("workflow install manifest migration version is missing or malformed")
    return value


def installed_migration_version(installed):
    """Defensive guard for every int(migration_version) use site.

    manifest() already rejects non-integer values, but a malformed manifest
    must never surface as an uncaught ValueError traceback downstream.
    """
    value=installed.get("migration_version",0)
    if isinstance(value,bool) or not isinstance(value,int):
        try: return int(str(value).strip())
        except (TypeError,ValueError): raise SystemExit(f"workflow install manifest migration version is malformed: {value!r}")
    return value


def previous_agent_files(previous):
    return previous["files"] if previous.get("schema")=="agent-workflow-install/v1" else previous["agent_files"]


def plan_agent_update(wanted,previous,destination):
    previous_files=previous_agent_files(previous); current=files(destination)
    conflicts=[]; writes=[]; removes=[]
    for relative,digest in wanted.items():
        old=previous_files.get(relative); observed=current.get(relative)
        if observed==digest: continue
        if observed is not None and old is not None and observed!=old: conflicts.append(relative)
        elif observed is not None and old is None: conflicts.append(relative)
        else: writes.append(relative)
    for relative,old in previous_files.items():
        if relative not in wanted and current.get(relative)==old: removes.append(relative)
        elif relative not in wanted and relative in current: conflicts.append(relative)
    return sorted(set(writes)),sorted(set(removes)),sorted(set(conflicts))


def bootstrap_state(path):
    if not path.exists() and not path.is_symlink(): return "missing",None
    if path.is_symlink() or not path.is_file(): return "conflict",None
    try: text=path.read_text(encoding="utf-8")
    except UnicodeError: return "conflict",None
    starts=text.count(BOOTSTRAP_START); ends=text.count(BOOTSTRAP_END)
    if starts==0 and ends==0: return "absent",text
    if starts!=1 or ends!=1: return "conflict",text
    begin=text.index(BOOTSTRAP_START); finish=text.index(BOOTSTRAP_END,begin)+len(BOOTSTRAP_END)
    observed=text[begin:finish]+("\n" if finish==len(text) or text[finish:finish+1]=="\n" else "")
    return ("current" if observed==BOOTSTRAP else "conflict"),text


def plan_bootstrap(path,filename):
    state,_=bootstrap_state(path)
    if state=="current": return False,[]
    if state in {"missing","absent"}: return True,[]
    return False,[f"{filename}#agent-workflow-bootstrap"]


def render_bootstrap(path):
    state,text=bootstrap_state(path)
    if state=="conflict": raise RuntimeError("managed bootstrap anchor is malformed or locally modified")
    if state=="current": return text
    if state=="missing": return BOOTSTRAP
    return text.rstrip()+"\n\n"+BOOTSTRAP


def stage_bootstrap(target,candidate_parent,filename):
    rendered=render_bootstrap(target/filename)
    candidate=candidate_parent/filename
    candidate.write_text(rendered,encoding="utf-8")
    return candidate


def validate_bootstrap(path,filename):
    state,_=bootstrap_state(path)
    if state!="current": raise RuntimeError(f"candidate {filename} lacks the canonical managed bootstrap")


def install_manifest(agent_files,plugin_files,entry_digest,agents_sha256,claude_sha256):
    for label,value in (("AGENTS.md",agents_sha256),("CLAUDE.md",claude_sha256)):
        if not isinstance(value,str) or re.fullmatch(r"[0-9a-f]{64}",value) is None:
            raise RuntimeError(f"installed {label} SHA-256 is invalid")
    source_digest=canonical_sha256({
        "agent_files":agent_files,
        "repo_plugin_files":plugin_files,
        "marketplace_entry_sha256":entry_digest,
        "agents_bootstrap_sha256":agents_sha256,
        "claude_bootstrap_sha256":claude_sha256,
    })
    return {
        "schema":"agent-workflow-install/v4",
        "version":VERSION,
        "migration_version":MIGRATION_VERSION,
        "source_tree_sha256":source_digest,
        "agent_files":agent_files,
        "repo_plugin_files":plugin_files,
        "marketplace_entry":{"name":PLUGIN_NAME,"sha256":entry_digest},
        "agents_bootstrap":{"path":"AGENTS.md","sha256":agents_sha256},
        "claude_bootstrap":{"path":"CLAUDE.md","sha256":claude_sha256},
    }


def write_managed(source,destination,writes,removes):
    for relative in removes:
        path=destination/relative
        if path.is_file(): path.unlink()
    for relative in writes:
        target=destination/relative; target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(source/relative,target)
    for directory in sorted((destination/name for name in MANAGED if (destination/name).is_dir()),reverse=True):
        for candidate in sorted(directory.rglob("*"),reverse=True):
                if candidate.is_dir() and not any(candidate.iterdir()): candidate.rmdir()


def validate_repo_plugin(plugin,wanted):
    if repo_plugin_files(plugin)!=wanted: raise RuntimeError("candidate repo plugin differs from source")
    plugin_manifest_path=plugin/".codex-plugin/plugin.json"
    mcp_path=plugin/".mcp.json"
    integrity_path=plugin/"integrity.json"
    for path in (plugin_manifest_path,mcp_path,integrity_path):
        if not path.is_file() or path.is_symlink(): raise RuntimeError(f"candidate plugin metadata is missing or unsafe: {path.name}")
    try:
        plugin_manifest=json.loads(plugin_manifest_path.read_text(encoding="utf-8"))
        mcp=json.loads(mcp_path.read_text(encoding="utf-8"))
        integrity=json.loads(integrity_path.read_text(encoding="utf-8"))
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
    if integrity.get("schema")!="pxpipe-context-integrity/v3" or integrity.get("plugin_version")!=plugin_manifest["version"]:
        raise RuntimeError("candidate plugin integrity metadata is invalid")
    integrity_files=(
        ("runtime_bundle","runtime_bundle_sha256","runtime"),
        ("proxy_bundle","proxy_bundle_sha256","proxy bundle"),
    )
    for path_field,digest_field,label in integrity_files:
        relative=Path(str(integrity.get(path_field,"")).strip())
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise RuntimeError(f"candidate plugin {label} path is unsafe")
        artifact=(plugin/relative).resolve()
        try: artifact.relative_to(plugin.resolve())
        except ValueError as error: raise RuntimeError(f"candidate plugin {label} escapes plugin root") from error
        expected=integrity.get(digest_field)
        if not artifact.is_file() or artifact.is_symlink() or not isinstance(expected,str) or sha(artifact)!=expected:
            raise RuntimeError(f"candidate plugin {label} SHA-256 does not match integrity metadata")
    expected_provider_assets={
        "scripts/codex-pxpipe.sh",
        "scripts/codex-default-config.mjs",
        "scripts/install-codex-default.sh",
        "scripts/uninstall-codex-default.sh",
        "scripts/status-codex-default.sh",
    }
    provider_assets=integrity.get("provider_assets")
    if not isinstance(provider_assets,dict) or set(provider_assets)!=expected_provider_assets:
        raise RuntimeError("candidate plugin provider asset integrity map is invalid")
    for relative_text,expected in provider_assets.items():
        relative=Path(relative_text)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise RuntimeError("candidate plugin provider asset path is unsafe")
        artifact=(plugin/relative).resolve()
        try: artifact.relative_to(plugin.resolve())
        except ValueError as error: raise RuntimeError("candidate plugin provider asset escapes plugin root") from error
        if not artifact.is_file() or artifact.is_symlink() or not isinstance(expected,str) or sha(artifact)!=expected:
            raise RuntimeError("candidate plugin provider asset SHA-256 does not match integrity metadata")
    server_script=plugin/"mcp/server.mjs"
    if not server_script.is_file() or server_script.is_symlink(): raise RuntimeError("candidate plugin MCP server is missing")


def validate_candidate(candidate,wanted,plugin_wanted,entry_digest,agents,claude):
    validate_private_tree(candidate)
    validate_project_guardrails(candidate)
    observed=files(candidate)
    if observed!=wanted: raise RuntimeError("candidate managed tree differs from source")
    installed=manifest(candidate/".workflow-manifest.json",required=True)
    if installed!=install_manifest(wanted,plugin_wanted,entry_digest,sha(agents),sha(claude)):
        raise RuntimeError("candidate install manifest is stale")
    validate_bootstrap(agents,"AGENTS.md")
    validate_bootstrap(claude,"CLAUDE.md")
    for base in (candidate/"scripts",candidate/"skills"):
        for python_file in base.rglob("*.py"):
            try: ast.parse(python_file.read_text(encoding="utf-8"),filename=str(python_file))
            except (SyntaxError,UnicodeError) as error: raise RuntimeError(f"candidate Python is invalid: {python_file}: {error}") from error
    template_manifest=json.loads((candidate/"templates/manifest.json").read_text(encoding="utf-8"))
    if template_manifest.get("schema")!="agent-template-manifest/v2" or not isinstance(template_manifest.get("templates"),list): raise RuntimeError("candidate template manifest is invalid")
    ids=set()
    for item in template_manifest["templates"]:
        required={"id","path","output","renderable","depends_on","nodes","modes","capabilities","required"}
        if not isinstance(item,dict) or set(item)!=required or not isinstance(item.get("id"),str) or item["id"] in ids:
            raise RuntimeError("candidate template manifest entry is invalid")
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


def remove_path(path):
    if path.is_symlink() or path.is_file(): path.unlink()
    elif path.is_dir(): shutil.rmtree(path)


TRANSACTION_SCHEMA="agent-workflow-install-transaction/v1"
TRANSACTION_STATES={"initializing","staging","committing","committed"}
TRANSACTION_PHASES={"prepared","backed_up","installed"}


def fsync_directory(path):
    flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)
    descriptor=os.open(str(path),flags)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def durable_replace(source,target):
    source_parent=source.parent; target_parent=target.parent
    os.replace(source,target)
    fsync_directory(target_parent)
    if source_parent!=target_parent: fsync_directory(source_parent)


def durable_remove(path):
    parent=path.parent
    remove_path(path)
    fsync_directory(parent)


def fsync_tree(root):
    if not root.is_dir() or root.is_symlink(): raise RuntimeError("transaction staging root is missing or unsafe")
    directories=[root]
    for item in root.rglob("*"):
        if item.is_symlink(): raise RuntimeError(f"transaction staging tree contains a symlink: {item}")
        if item.is_dir(): directories.append(item)
        elif item.is_file():
            descriptor=os.open(str(item),os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
        else: raise RuntimeError(f"transaction staging tree contains a special file: {item}")
    for directory in sorted(directories,key=lambda value:len(value.parts),reverse=True): fsync_directory(directory)


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
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1 or observed.st_uid!=os.getuid() or observed.st_mode&0o022:
        raise RuntimeError("transaction journal is not a private, owner-controlled regular file")
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
    if not isinstance(value,dict) or value.get("schema")!=TRANSACTION_SCHEMA:
        raise RuntimeError("transaction journal schema is invalid")
    if set(value)!={"schema","transaction_id","target_root","state","replacements","created_directories","journal_sha256"}:
        raise RuntimeError("transaction journal fields are invalid")
    if value.get("target_root")!=str(target) or value.get("state") not in TRANSACTION_STATES:
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
    if not isinstance(created,list) or len(created)!=len(set(created)) or any(item not in allowed_directories for item in created):
        raise RuntimeError("transaction journal created-directory list is invalid")
    allowed=transaction_targets(target); seen=set()
    for operation in operations:
        if not isinstance(operation,dict) or set(operation)!={"label","had_original","original_identity","candidate_identity","phase"}:
            raise RuntimeError("transaction journal replacement is malformed")
        label=operation.get("label")
        if label not in allowed or label in seen or not isinstance(operation.get("had_original"),bool) or operation.get("phase") not in TRANSACTION_PHASES:
            raise RuntimeError("transaction journal replacement is outside the managed whitelist")
        seen.add(label)
        validate_identity(operation.get("original_identity"),operation["had_original"])
        validate_identity(operation.get("candidate_identity"),True)
    if value["state"] in {"initializing","staging"} and operations:
        raise RuntimeError("a pre-commit transaction journal cannot contain replacements")
    if value["state"] in {"committing","committed"} and not operations:
        raise RuntimeError("a commit transaction journal has no replacements")


def write_transaction_journal(target,value,create=False):
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
    return value


def filesystem_identity(path):
    observed=path.lstat()
    if stat.S_ISLNK(observed.st_mode): raise RuntimeError(f"transaction target is a symlink: {path}")
    if not (stat.S_ISREG(observed.st_mode) or stat.S_ISDIR(observed.st_mode)):
        raise RuntimeError(f"transaction target is not a file or directory: {path}")
    return {"dev":observed.st_dev,"ino":observed.st_ino,"mode":stat.S_IFMT(observed.st_mode)}


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
        current=current.parent


def validate_staging_root(target,value,allow_missing=False,allow_initializing_marker_temp=False):
    staging=transaction_staging_path(target,value["transaction_id"])
    if not staging.exists() and not staging.is_symlink():
        if allow_missing: return staging
        raise RuntimeError("transaction staging root is missing")
    observed=staging.lstat()
    if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode) or observed.st_uid!=os.getuid():
        raise RuntimeError("transaction staging root is unsafe")
    marker=staging/".agent-workflow-transaction-marker.json"
    if not marker.is_file() or marker.is_symlink():
        children=list(staging.iterdir())
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
                    or observed.st_uid!=os.getuid()
                    or observed.st_nlink!=1
                    or observed.st_mode&0o022
                ):
                    raise RuntimeError("transaction staging contains an untrusted pre-marker object")
            return staging
        raise RuntimeError("transaction staging marker is missing or unsafe")
    try: marked=json.loads(marker.read_text(encoding="utf-8"))
    except (OSError,UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("transaction staging marker is invalid") from error
    if marked!={"schema":TRANSACTION_SCHEMA,"transaction_id":value["transaction_id"],"target_root":str(target)}:
        raise RuntimeError("transaction staging marker does not match the journal")
    return staging


def finish_transaction_cleanup(target,value):
    staging=validate_staging_root(
        target,value,allow_missing=True,
        allow_initializing_marker_temp=value.get("state")=="initializing",
    )
    if staging.exists() or staging.is_symlink():
        marker=staging/".agent-workflow-transaction-marker.json"
        for child in list(staging.iterdir()):
            if child==marker: continue
            remove_path(child); fsync_directory(staging)
        if marker.exists() or marker.is_symlink(): marker.unlink(); fsync_directory(staging)
        staging.rmdir(); fsync_directory(staging.parent)
    journal=transaction_journal_path(target)
    if journal.exists() or journal.is_symlink():
        secure_journal_stat(journal); journal.unlink(); fsync_directory(journal.parent)


def rollback_transaction(target,value):
    staging=validate_staging_root(target,value)
    allowed=transaction_targets(target)
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
            if not operation["had_original"] or not identity_matches(backup,operation["original_identity"]):
                raise RuntimeError("transaction backup does not match the recorded predecessor")
            if target_exists:
                if not identity_matches(target_path,operation["candidate_identity"]):
                    raise RuntimeError("transaction target changed after the interrupted install")
                durable_remove(target_path)
            target_path.parent.mkdir(parents=True,exist_ok=True); fsync_directory(target_path.parent)
            durable_replace(backup,target_path)
        elif operation["had_original"]:
            if not target_exists or not identity_matches(target_path,operation["original_identity"]):
                raise RuntimeError("transaction predecessor is missing and no valid backup remains")
        elif target_exists:
            if candidate_exists or not identity_matches(target_path,operation["candidate_identity"]):
                raise RuntimeError("transaction target cannot be safely identified for rollback")
            durable_remove(target_path)
        if operation["had_original"]:
            if not identity_matches(target_path,operation["original_identity"]): raise RuntimeError("transaction rollback did not restore the predecessor")
        elif target_path.exists() or target_path.is_symlink(): raise RuntimeError("transaction rollback did not restore target absence")
    for relative in reversed(value["created_directories"]):
        directory=target if relative=="." else target/relative
        if directory.is_dir() and not directory.is_symlink():
            try: directory.rmdir()
            except OSError: pass
            else: fsync_directory(directory.parent)
    finish_transaction_cleanup(target,value)


def recover_transaction(target):
    value=read_transaction_journal(target)
    if value is None: return False
    if value["state"] in {"initializing","staging"}:
        finish_transaction_cleanup(target,value)
    elif value["state"]=="committing": rollback_transaction(target,value)
    else:
        staging=validate_staging_root(target,value,allow_missing=True)
        for operation in value["replacements"]:
            target_path=transaction_targets(target)[operation["label"]]
            validate_transaction_ancestors(target,target_path)
            if not identity_matches(target_path,operation["candidate_identity"]):
                raise RuntimeError("committed transaction target no longer matches its candidate")
        if staging.exists() or staging.is_symlink(): finish_transaction_cleanup(target,value)
        else:
            journal=transaction_journal_path(target); secure_journal_stat(journal); journal.unlink(); fsync_directory(journal.parent)
    return True


def begin_transaction(target):
    if transaction_journal_path(target).exists() or transaction_journal_path(target).is_symlink():
        raise RuntimeError("an unrecovered installer transaction already exists")
    transaction_id=uuid.uuid4().hex
    value={"schema":TRANSACTION_SCHEMA,"transaction_id":transaction_id,"target_root":str(target),"state":"initializing","replacements":[],"created_directories":[]}
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
            "schema":TRANSACTION_SCHEMA,"transaction_id":transaction_id,"target_root":str(target),
        })
        fsync_directory(staging)
        value["state"]="staging"; write_transaction_journal(target,value)
    except Exception:
        recover_transaction(target)
        raise
    return staging


def commit_transaction(target,candidate_parent,replacements):
    journal=read_transaction_journal(target)
    if journal is None or journal["state"]!="staging": raise RuntimeError("transaction is not ready to commit")
    allowed=transaction_targets(target); operations=[]; required_directories=[]
    for candidate,target_path in replacements:
        labels=[label for label,expected in allowed.items() if expected==target_path]
        if len(labels)!=1 or candidate!=candidate_parent/labels[0]: raise RuntimeError("transaction replacement is outside the managed whitelist")
        if not candidate.exists() or candidate.is_symlink(): raise RuntimeError("transaction candidate is missing or unsafe")
        had_original=target_path.exists() or target_path.is_symlink()
        operations.append({
            "label":labels[0],"had_original":had_original,
            "original_identity":filesystem_identity(target_path) if had_original else None,
            "candidate_identity":filesystem_identity(candidate),"phase":"prepared",
        })
        current=target_path.parent
        while True:
            if not current.exists() and not current.is_symlink(): required_directories.append(current)
            if current==target: break
            current=current.parent
    directory_labels=[]
    for directory in sorted(set(required_directories),key=lambda value:len(value.parts)):
        relative="." if directory==target else str(directory.relative_to(target))
        if relative not in {".","plugins",".agents",".agents/plugins"}:
            raise RuntimeError("transaction requires a directory outside the managed whitelist")
        directory_labels.append(relative)
    fsync_tree(candidate_parent)
    backup_root=candidate_parent/"backups"; backup_root.mkdir(parents=True,exist_ok=True); fsync_directory(candidate_parent)
    journal["state"]="committing"; journal["replacements"]=operations; journal["created_directories"]=directory_labels; journal=write_transaction_journal(target,journal)
    crash_after_directory=int(os.environ.get("AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_DIRECTORY","0") or "0")
    created_count=0
    for relative in directory_labels:
        directory=target if relative=="." else target/relative
        directory.mkdir(); fsync_directory(directory.parent)
        created_count+=1
        if crash_after_directory and created_count==crash_after_directory: os._exit(95)
    for _candidate,target_path in replacements: validate_transaction_ancestors(target,target_path)
    crash_after=int(os.environ.get("AGENT_WORKFLOW_INSTALL_SELF_TEST_CRASH_AFTER_TARGET","0") or "0")
    completed=0
    try:
        for index,operation in enumerate(operations):
            candidate=candidate_parent/operation["label"]; target_path=allowed[operation["label"]]; backup=backup_root/str(index)
            target_path.parent.mkdir(parents=True,exist_ok=True); fsync_directory(target_path.parent)
            if operation["had_original"]:
                durable_replace(target_path,backup)
                operation["phase"]="backed_up"; journal=write_transaction_journal(target,journal)
            durable_replace(candidate,target_path)
            operation["phase"]="installed"; journal=write_transaction_journal(target,journal)
            completed+=1
            if crash_after and completed==crash_after: os._exit(97)
        journal["state"]="committed"; journal=write_transaction_journal(target,journal)
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


def validate_legacy_active_context(destination):
    """Validate the installed capsule exactly, ignoring only its age lease."""
    task=json.loads((destination/"state/TASK.json").read_text(encoding="utf-8"))
    if task.get("status") in {"idle",None}: return
    probe="""
import copy,sys
sys.path.insert(0,'.agent/scripts')
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
    result=subprocess.run(
        [sys.executable,"-c",probe],cwd=str(destination.parent),text=True,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120,
        env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"},
    )
    if result.returncode:
        raise RuntimeError(
            "active context has drift or corruption beyond checkpoint age; repair it before workflow update"
        )


def candidate_tool(destination, relative, *args, expected=(0,)):
    command=[sys.executable,str(destination/relative),*args]
    result=subprocess.run(
        command,cwd=str(destination.parent),text=True,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180,
    )
    if result.returncode not in expected:
        raise RuntimeError(
            f"candidate tool failed ({relative} {' '.join(args)}):\n{result.stdout.strip()}"
        )
    return result.stdout


def initialize_fresh_context(destination):
    """Bind the idle seed capsule to this candidate's final private config."""
    probe="""
import argparse,hashlib,json,sys
sys.path.insert(0,'.agent/scripts')
import contextctl
p=contextctl.CONTEXT_PATH
previous=json.loads(p.read_text(encoding='utf-8'))
args=argparse.Namespace(reason='fresh-project-seed',summary='fresh isolated idle state',source='project-init:bootstrap',source_tokens=800,fact=[],file=[],evidence=[],risk=[],resolve_risk=[],transition=False,reset=True,host_compaction=False)
capsule=contextctl.build_capsule(args,'verified',previous,hashlib.sha256(p.read_bytes()).hexdigest())
contextctl.atomic_json(p,capsule)
raise SystemExit(contextctl.validate_context())
"""
    result=subprocess.run(
        [sys.executable,"-c",probe],cwd=str(destination.parent),text=True,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120,
        env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"},
    )
    if result.returncode:
        raise RuntimeError("fresh private context initialization failed:\n"+result.stdout.strip())


def migrate_active_hot_state(destination, prior_migration):
    """Rebind migration-23 context, compact hot state, then validate in-candidate."""
    task=json.loads((destination/"state/TASK.json").read_text(encoding="utf-8"))
    if prior_migration>=23 or task.get("status") in {"idle",None}: return
    # validate_legacy_active_context already proved the predecessor byte-for-byte
    # before candidate staging. This is a schema migration, not a human repair:
    # rebuild one ordinary verified capsule deterministically and never invent a
    # provider decision receipt.
    probe="""
import argparse,hashlib,json,sys
sys.path.insert(0,'.agent/scripts')
import contextctl
p=contextctl.CONTEXT_PATH
previous=json.loads(p.read_text(encoding='utf-8'))
args=argparse.Namespace(reason='migration-23-schema-rebind',summary='rebind verified active context before bounded hot-state migration',source='installer-verified-legacy-migration',source_tokens=4000,fact=[],file=[],evidence=[],risk=[],resolve_risk=[],transition=False,reset=True)
capsule=contextctl.build_capsule(args,'verified',previous,hashlib.sha256(p.read_bytes()).hexdigest())
contextctl.atomic_json(p,capsule)
raise SystemExit(contextctl.validate_context())
"""
    result=subprocess.run(
        [sys.executable,"-c",probe],cwd=str(destination.parent),text=True,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120,
    )
    if result.returncode:
        raise RuntimeError("migration-23 verified context rebind failed:\n"+result.stdout.strip())
    candidate_tool(destination,"scripts/workflowctl.py","compact-state")
    candidate_tool(destination,"scripts/contextctl.py","check")
    candidate_tool(destination,"scripts/workflowctl.py","validate")
    candidate_tool(destination,"scripts/evidencectl.py","verify","--deep")


def migrate_active_template_state(destination,prior_migration):
    """Rebind unchanged generated artifacts and migrate only the known v3 runner."""
    task_path=destination/"state/TASK.json"; task=json.loads(task_path.read_text(encoding="utf-8"))
    if prior_migration>=25 or task.get("status") in {"idle",None}: return
    previous_records=task.get("rendered_artifacts")
    capabilities=task.get("selected_capabilities")
    if not isinstance(previous_records,list) or not isinstance(capabilities,list) or any(not isinstance(item,str) for item in capabilities):
        raise RuntimeError("active task template migration requires existing route capabilities and render provenance")

    # Migration 25 removes cleanup execution from the generated workflow
    # runner. Only this exact generated v3 shape is mechanically transformed;
    # any project-specific variation fails closed for human re-planning.
    runner_path=destination/"state/artifacts/04-acceptance-runner.json"
    if "acceptance-workflow" in task.get("selected_templates",[]):
        try: runner=json.loads(runner_path.read_text(encoding="utf-8"))
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
    candidate_tool(destination,"scripts/templatectl.py",*route_args)
    task=json.loads(task_path.read_text(encoding="utf-8")); route=task.get("template_route")
    selected=task.get("selected_templates",[])
    if not isinstance(route,dict) or not isinstance(route.get("sha256"),str) or not isinstance(selected,list):
        raise RuntimeError("active template migration did not produce a bound route")
    manifest_path=destination/"templates/manifest.json"; manifest_data=manifest_path.read_bytes(); manifest=json.loads(manifest_data)
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
        source_data=source.read_bytes(); output_data=output.read_bytes()
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
    candidate_tool(destination,"scripts/templatectl.py","validate")


def migrate_active_loaded_references(destination,prior_install,prior_migration):
    """Rebind unchanged managed references after their template bytes update."""
    task_path=destination/"state/TASK.json"; task=json.loads(task_path.read_text(encoding="utf-8"))
    if prior_migration>=34 or task.get("status") in {"idle",None}: return
    records=task.get("loaded_references")
    if not isinstance(records,list):
        raise RuntimeError("active task loaded references are malformed")
    previous_files=prior_install.get("agent_files")
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
        data=target.read_bytes()
        record.update({
            "sha256":hashlib.sha256(data).hexdigest(),
            "bytes":len(data),
            "estimated_tokens":(len(data)+3)//4,
        })
        changed=True
    if changed: atomic_json(task_path,task)


def finalize_active_context_binding(destination,prior_migration):
    """Bind the capsule to the final post-migration task invariant."""
    task=json.loads((destination/"state/TASK.json").read_text(encoding="utf-8"))
    if prior_migration>=MIGRATION_VERSION: return
    # Earlier migration steps were individually validated before they changed
    # canonical task state.  Rebuild one ordinary verified checkpoint only
    # after every state migration has settled, preserving its facts and risks.
    reason=(
        "migration-34-final-state-rebind"
        if prior_migration<34
        else ("migration-39-budget-resume-rebind" if prior_migration<39 else "migration-40-template-route-rebind")
    )
    source=(
        "installer-verified-context-efficiency-migration"
        if prior_migration<34
        else ("installer-verified-budget-resume-migration" if prior_migration<39 else "installer-verified-template-route-migration")
    )
    probe=f"""
import argparse,hashlib,json,sys
sys.path.insert(0,'.agent/scripts')
import contextctl
p=contextctl.CONTEXT_PATH
previous=json.loads(p.read_text(encoding='utf-8'))
source_tokens=max(4000,int(previous.get('compaction',{{}}).get('source_estimated_tokens',0) or 0))
args=argparse.Namespace(reason={reason!r},summary=previous.get('phase_summary','verified workflow migration'),source={source!r},source_tokens=source_tokens,fact=[],file=[],evidence=[],risk=[],resolve_risk=[],transition=False,reset=False)
capsule=contextctl.build_capsule(args,'verified',previous,hashlib.sha256(p.read_bytes()).hexdigest())
contextctl.atomic_json(p,capsule)
raise SystemExit(contextctl.validate_context())
"""
    result=subprocess.run(
        [sys.executable,"-c",probe],cwd=str(destination.parent),text=True,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120,
    )
    if result.returncode:
        raise RuntimeError(f"migration-{MIGRATION_VERSION} final context rebind failed:\n"+result.stdout.strip())


def migrate_delivery_state(destination,prior_migration):
    """Upgrade delivery v2 without inventing provider-owned production proof."""
    if prior_migration>=26: return
    path=destination/"state/delivery.json"
    try: state=json.loads(path.read_text(encoding="utf-8"))
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
            raw_bytes=path.read_bytes(); digest=hashlib.sha256(raw_bytes).hexdigest()
            archive=destination/"state/evidence/delivery-migration"/f"v2-{digest}.json"
            archive.parent.mkdir(parents=True,exist_ok=True)
            if archive.exists() and archive.read_bytes()!=raw_bytes:
                raise RuntimeError("delivery migration archive collision")
            if not archive.exists(): archive.write_bytes(raw_bytes)
            node8=destination/"state/artifacts/08-delivery.json"; node8_archive=None
            if node8.is_file() and not node8.is_symlink():
                node8_bytes=node8.read_bytes(); node8_digest=hashlib.sha256(node8_bytes).hexdigest()
                try: node8_value=json.loads(node8_bytes)
                except (UnicodeError,json.JSONDecodeError) as error: raise RuntimeError("legacy Node8 receipt is invalid") from error
                if status in historical_terminal and (
                    node8_value.get("schema")!="agent-node-delivery/v2" or node8_value.get("status")!=status
                ):
                    raise RuntimeError("legacy terminal Node8 receipt does not match delivery status")
                node8_archive_path=destination/"state/evidence/delivery-migration"/f"node8-v2-{node8_digest}.json"
                if node8_archive_path.exists() and node8_archive_path.read_bytes()!=node8_bytes:
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
        state_bytes=path.read_bytes(); artifact=state.get("artifact")
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
        task_path=destination/"state/TASK.json"; task=json.loads(task_path.read_text(encoding="utf-8"))
        node_artifacts=task.get("node_artifacts")
        if isinstance(node_artifacts,dict) and "8" in node_artifacts:
            node8_bytes=node8.read_bytes()
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


def protected_external_adapter_reject_reason(adapter_owner, raw):
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
    if not os.access(path,os.X_OK): return "not executable"
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


def bootstrap_human_decision_adapter(target,raw):
    guidance=(
        "fresh install requires --human-decision-adapter /absolute/provider-owned/executable; "
        "the executable and parent chain must be OS-owned/non-writable and `<adapter> health` "
        "must exit 0. The installer writes that canonical path to "
        ".agent/config.json agent_control.human_decision_observer.signed_adapter; "
        "a project-local or self-signed fallback is never accepted"
    )
    if raw is None:
        return None
    if not isinstance(raw,str) or not raw.strip():
        raise RuntimeError(guidance)
    reject_reason=protected_external_adapter_reject_reason(target.resolve(),raw)
    if reject_reason is not None:
        raise RuntimeError(guidance+f"; rejected: {reject_reason}")
    adapter=Path(raw).expanduser().resolve(strict=True)
    try:
        result=subprocess.run(
            [str(adapter),"health"],cwd=str(Path.cwd()),text=True,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=10,
        )
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
    if adapter.name.lower() in {"bash","sh","zsh","fish","env","python","python3","node","perl","ruby","php"}:
        raise RuntimeError("provider preflight adapter cannot be a generic interpreter")
    try:
        result=subprocess.run(
            [str(adapter),"health-provider-preflight"],cwd=str(Path.cwd()),text=True,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=10,
        )
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
    path=Path(raw).expanduser().resolve()
    if not path.is_file() or path.is_symlink(): raise RuntimeError("project guardrails file is missing or unsafe")
    data=path.read_bytes()
    if not data or len(data)>131072: raise RuntimeError("project guardrails file is empty or exceeds 131072 bytes")
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
    config_path=destination/"config.json"; config=json.loads(config_path.read_text(encoding="utf-8"))
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
    config=json.loads(config_path.read_text(encoding="utf-8")); ready=config.get("guardrails_ready")
    binding=config.get("project_initialization")
    if ready is False:
        if binding is not None: raise RuntimeError("uninitialized project has a guardrails binding")
        text=policy_path.read_text(encoding="utf-8")
        if "agent-workflow-project-guardrails:v1 uninitialized" not in text:
            raise RuntimeError("uninitialized project guardrails differ from the canonical placeholder")
        return False
    if ready is not True: raise RuntimeError("project guardrails readiness must be Boolean")
    if binding is None and allow_legacy: return True
    data=policy_path.read_bytes()
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
        if key not in {"signed_adapter","allow_current_chat_local_release"} and observed.get(key)!=value:
            raise RuntimeError(f"project Agent security policy differs from the canonical template: {name}.{key}")
    if name=="human_decision_observer" and not isinstance(observed.get("allow_current_chat_local_release"),bool):
        raise RuntimeError("project Agent security policy requires a Boolean current-chat local-release opt-in")
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


def validate_context_transport_policy(config):
    policy=config.get("context_transport")
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
        or pxpipe.get("models")!=["gpt-5.6-sol"]
        or pxpipe.get("primary_mode")!="provider-proxy"
        or pxpipe.get("provider_activation")!="default-new-local-sessions"
        or pxpipe.get("provider_configuration")!="user-model-provider-plus-launch-agent"
        or pxpipe.get("provider_content_scope")!="whole-request-eligible-content"
        or pxpipe.get("mcp_role")!="optional-cold-reference"
        or pxpipe.get("selection")!="analyze-then-render"
        or pxpipe.get("content_scope")!="new-cold-reference-only"
        or pxpipe.get("session_boundary")!="plugin-load-requires-new-chat"
        or pxpipe.get("fallback")!="native"
    ):
        raise RuntimeError("project optional context transport policy is invalid")


def fresh_empty_platform_snapshot(raw):
    if not raw: raise RuntimeError("legacy Agent ledger migration requires --agent-platform-snapshot with a fresh platform-empty v3 proof")
    path=Path(raw).resolve()
    if not path.is_file() or path.is_symlink(): raise RuntimeError("Agent platform snapshot is missing or unsafe")
    data=path.read_bytes(); value=json.loads(data)
    if not isinstance(value,dict) or set(value)!={"schema","observed_at","members"} or value.get("schema")!="agent-platform-snapshot/v3" or value.get("members")!=[]:
        raise RuntimeError("Agent migration snapshot must be an exact empty agent-platform-snapshot/v3")
    try:
        observed=dt.datetime.fromisoformat(str(value.get("observed_at")))
        if observed.tzinfo is None: raise ValueError
        age=(dt.datetime.now(dt.timezone.utc)-observed.astimezone(dt.timezone.utc)).total_seconds()
    except (TypeError,ValueError) as error: raise RuntimeError("Agent migration snapshot time is invalid") from error
    if age < -5 or age > 300: raise RuntimeError("Agent migration snapshot is stale or from the future")
    return data,hashlib.sha256(data).hexdigest()


def migrate_private(source,destination,agent_platform_snapshot=None,project_root=None,allow_current_chat_local_release=False,idle_reseed=True):
    prior_install=manifest(destination/".workflow-manifest.json",required=True)
    prior_migration=installed_migration_version(prior_install)
    seed=fresh_state_seed(source)
    config_path=destination/"config.json"; task_path=destination/"state/TASK.json"
    config=json.loads(config_path.read_text(encoding="utf-8")); defaults=json.loads((seed/"config.json").read_text(encoding="utf-8"))
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
    if allow_current_chat_local_release:
        config.setdefault("agent_control",{}).setdefault("human_decision_observer",{})[
            "allow_current_chat_local_release"
        ]=True
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
    validate_context_transport_policy(config)
    config.setdefault("agent_control",{}).pop("interrupt_after_unchanged_checks",None)
    for name in ("default_model","allow_model_fallback","context_strategy","max_fork_turns","capacity_retry_limit","reserve_root_slots","max_redispatch","status_interval_seconds","monitor_grace_seconds","stall_timeout_seconds","allowed_role_types","review_role_types",*migration_16_policy):
        if config.get("agent_control",{}).get(name)!=security_defaults.get(name):
            raise RuntimeError(f"project Agent security policy differs from the canonical template: {name}")
    adapter_owner=Path(project_root).resolve() if project_root is not None else destination.parent.resolve()
    validate_observer_policy("platform_observer",config.get("agent_control",{}).get("platform_observer"),security_defaults["platform_observer"],adapter_owner)
    validate_observer_policy("human_decision_observer",config.get("agent_control",{}).get("human_decision_observer"),security_defaults["human_decision_observer"],adapter_owner)
    validate_observer_policy("provider_preflight_observer",config.get("agent_control",{}).get("provider_preflight_observer"),security_defaults["provider_preflight_observer"],adapter_owner)
    if config.get("guardrails_ready") is True and not isinstance(config.get("project_initialization"),dict):
        guardrails_data=(destination/"policies/PROJECT_GUARDRAILS.md").read_bytes()
        config["project_initialization"]={
            "schema":"agent-project-initialization/v1",
            "guardrails_sha256":hashlib.sha256(guardrails_data).hexdigest(),
            "guardrails_bytes":len(guardrails_data),
            "initialized_at":dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        }
    atomic_json(config_path,config)
    validate_project_guardrails(destination)
    task=json.loads(task_path.read_text(encoding="utf-8")); task_defaults=json.loads((seed/"state/TASK.json").read_text(encoding="utf-8"))
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
            migrated={**route,"schema":"agent-template-route/v3","adaptive_project":{"blueprint_sha256":None,"skills_lock_sha256":None,"project_capabilities":[]},"sha256":None}
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
    if prior_migration<28 and task.get("status") in {"idle",None}:
        task["decision_policy_version"]=2
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
    if (
        prior_migration<31
        and config.get("agent_control",{}).get("human_decision_observer",{}).get("allow_current_chat_local_release") is True
        and task.get("requirements_clarified") is False
        and task.get("environment")=="local"
        and task.get("deployment_requested") is False
        and not any(task["risk_flags"].get(name) is True for name in ("deploy","irreversible","external_impact"))
    ):
        task["decision_policy_version"]=2
    atomic_json(task_path,task)
    for name in ("agents.json","delivery.json","runtime.json","tool-leases.json","test-budget.json","EVIDENCE_INDEX.json"):
        target=destination/"state"/name
        if not target.exists(): shutil.copy2(seed/"state"/name,target)
    migrate_delivery_state(destination,prior_migration)
    migrate_active_hot_state(destination,prior_migration)
    migrate_active_template_state(destination,prior_migration)
    migrate_active_loaded_references(destination,prior_install,prior_migration)
    finalize_active_context_binding(destination,prior_migration)
    task=json.loads(task_path.read_text(encoding="utf-8"))
    agents_path=destination/"state/agents.json"; agents_state=json.loads(agents_path.read_text(encoding="utf-8"))
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
        if histories:
            raise RuntimeError("agent ledger migration refuses to invent v9 platform-assurance, Token-accounting, supervision-debt, implementation-author or replay semantics for existing history; prove the platform empty, archive the old ledger, and run agentledger init --archive-existing")
        platform_bytes,platform_digest=fresh_empty_platform_snapshot(agent_platform_snapshot)
        legacy_bytes=agents_path.read_bytes(); legacy_digest=hashlib.sha256(legacy_bytes).hexdigest()
        archive=destination/"state/evidence"/f"agent-ledger-migration-{legacy_digest[:16]}.json"
        archive.parent.mkdir(parents=True,exist_ok=True)
        if archive.exists() and archive.read_bytes()!=legacy_bytes:
            raise RuntimeError("agent ledger migration archive path collision")
        if not archive.exists(): archive.write_bytes(legacy_bytes)
        platform_internal=destination/"state/evidence/platform-snapshots"/f"{platform_digest}.json"
        platform_internal.parent.mkdir(parents=True,exist_ok=True)
        if platform_internal.exists() and platform_internal.read_bytes()!=platform_bytes:
            raise RuntimeError("Agent platform snapshot digest collision")
        if not platform_internal.exists(): platform_internal.write_bytes(platform_bytes)
        platform_internal.chmod(0o444)
        migrated=json.loads((seed/"state/agents.json").read_text(encoding="utf-8"))
        migrated["migration_source"]={
            "path":str(Path(".agent/state/evidence")/archive.name),
            "sha256":legacy_digest,
            "bytes":len(legacy_bytes),
        }
        migrated["epoch"]=hashlib.sha256(f"{destination}|{time.time_ns()}|{uuid.uuid4().hex}".encode()).hexdigest()
        migrated["last_platform_snapshot"]={
            "path":str(Path(".agent/state/evidence/platform-snapshots")/platform_internal.name),
            "sha256":platform_digest,
            "bytes":len(platform_bytes),
        }
        migrated["platform_empty_verified"]=False
        migrated["updated_at"]=time.strftime("%Y-%m-%dT%H:%M:%S+00:00",time.gmtime())
        atomic_json(agents_path,migrated)
        agents_state=migrated
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
    ledger_security={
        "schema":"agent-team/v9",
        "default_model":security_defaults["default_model"],
        "allow_model_fallback":security_defaults["allow_model_fallback"],
        "context_strategy":security_defaults["context_strategy"],
        "max_fork_turns":security_defaults["max_fork_turns"],
        "capacity_retry_limit":security_defaults["capacity_retry_limit"],
        "reserved_root_slots":security_defaults["reserve_root_slots"],
        "status_interval_seconds":security_defaults["status_interval_seconds"],
        "monitor_grace_seconds":security_defaults["monitor_grace_seconds"],
        "stall_timeout_seconds":security_defaults["stall_timeout_seconds"],
        "allowed_role_types":security_defaults["allowed_role_types"],
        "review_role_types":security_defaults["review_role_types"],
        "status_request_after_unchanged_checks":security_defaults["status_request_after_unchanged_checks"],
        "max_redispatch":security_defaults["max_redispatch"],
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
    runtime_path=destination/"state/runtime.json"; runtime=json.loads(runtime_path.read_text(encoding="utf-8"))
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
        initialize_fresh_context(destination)


def install(source_root,target,args):
    source=source_root/".agent"
    destination=target/".agent"
    if destination.exists() or destination.is_symlink(): raise SystemExit(f"existing {destination}; use --check or --update")
    adapter_path=bootstrap_human_decision_adapter(target,args.human_decision_adapter)
    provider_adapter_path=bootstrap_provider_preflight_adapter(target,args.provider_preflight_adapter)
    guardrails_data=project_guardrails_bytes(args.guardrails_file) if args.guardrails_file else None
    wanted,plugin_wanted,wanted_entry,entry_digest=source_contract(source_root)
    agents_write,agents_conflicts=plan_bootstrap(target/"AGENTS.md","AGENTS.md")
    claude_write,claude_conflicts=plan_bootstrap(target/"CLAUDE.md","CLAUDE.md")
    conflicts=agents_conflicts+claude_conflicts
    if conflicts:
        print("INSTALL BLOCKED: a managed bootstrap anchor is locally modified")
        for item in conflicts: print(f"- {item}")
        return 2
    if args.dry_run: print(f"DRY RUN install {destination}"); return 0
    target.parent.mkdir(parents=True,exist_ok=True)
    candidate_parent=begin_transaction(target)
    try:
        candidate=candidate_parent/".agent"
        copy_managed_fresh_install(source,candidate)
        config_path=candidate/"config.json"; config=json.loads(config_path.read_text(encoding="utf-8")); config["project"]={"name":args.project_name,"type":args.project_type}; config["agent_control"]["human_decision_observer"]["signed_adapter"]=adapter_path; config["agent_control"]["human_decision_observer"]["allow_current_chat_local_release"]=bool(args.allow_current_chat_local_release); config["agent_control"]["provider_preflight_observer"]["signed_adapter"]=provider_adapter_path; atomic_json(config_path,config)
        if guardrails_data is not None: bind_project_guardrails(candidate,guardrails_data)
        agents_path=candidate/"state/agents.json"; agents_state=json.loads(agents_path.read_text(encoding="utf-8"))
        agents_state["epoch"]=hashlib.sha256(f"{target}|{time.time_ns()}|{uuid.uuid4().hex}".encode()).hexdigest()
        agents_state["last_platform_snapshot"]=None; agents_state["platform_empty_verified"]=False
        agents_state["migration_source"]=None; agents_state["updated_at"]=time.strftime("%Y-%m-%dT%H:%M:%S+00:00",time.gmtime())
        atomic_json(agents_path,agents_state)
        initialize_fresh_context(candidate)
        candidate_agents=stage_bootstrap(target,candidate_parent,"AGENTS.md")
        candidate_claude=stage_bootstrap(target,candidate_parent,"CLAUDE.md")
        atomic_json(candidate/".workflow-manifest.json",install_manifest(wanted,plugin_wanted,entry_digest,sha(candidate_agents),sha(candidate_claude)))
        validate_candidate(candidate,wanted,plugin_wanted,entry_digest,candidate_agents,candidate_claude)
        replacements=[(candidate,destination)]
        if agents_write: replacements.append((candidate_agents,target/"AGENTS.md"))
        if claude_write: replacements.append((candidate_claude,target/"CLAUDE.md"))
        commit_transaction(target,candidate_parent,replacements)
    except Exception:
        abort_transaction(target)
        raise
    print(f"INSTALLED workflow {VERSION} in {target}")
    if guardrails_data is None:
        print("PROJECT INIT REQUIRED: complete project guardrails, then run `python3 .agent/scripts/agentctl.py project-init --guardrails-file <project-guardrails.md>`")
        print("BOOTSTRAP NOT READY: do not approve requirements or begin implementation before project initialization")
    else:
        print("PROJECT INITIALIZED: guardrails bytes and readiness were committed atomically")
    if adapter_path is None and guardrails_data is not None:
        if args.allow_current_chat_local_release:
            print("NEXT: current Codex chat may approve local non-deploy, reversible and non-external work, including release-mode implementation")
            print("PROTECTED GATES BLOCKED: configure agent_control.human_decision_observer.signed_adapter for test, production, deploy, irreversible or external-impact routes")
        else:
            print("NEXT: local non-deploy fast/standard tasks may use explicit current-chat user decisions")
            print("PROTECTED GATES BLOCKED: configure agent_control.human_decision_observer.signed_adapter for release, test, production or deploy routes")
    elif guardrails_data is not None:
        print("NEXT: run `python3 .agent/scripts/agentctl.py bootstrap-check`, then start clarification")
    if guardrails_data is not None and adapter_path is None:
        print("NEXT: run `python3 .agent/scripts/agentctl.py bootstrap-check`, then start clarification")
    if provider_adapter_path is None:
        print("PRODUCTION BLOCKED: configure agent_control.provider_preflight_observer.signed_adapter before provider preflight")
    return 0


def execute(args,source_root,target):
    source=source_root/".agent"; destination=target/".agent"
    if not args.check and not args.update and not args.adopt:
        if not args.project_name: raise SystemExit("--project-name is required for a new install")
        return install(source_root,target,args)
    if not destination.is_dir(): raise SystemExit("target has no .agent workflow; run a new install")
    validate_private_tree(destination)
    manifest_path=destination/".workflow-manifest.json"
    if args.adopt:
        if manifest_path.exists(): raise SystemExit("workflow already has an install manifest; use --check or --update")
        wanted,plugin_wanted,wanted_entry,entry_digest=source_contract(source_root); observed=files(destination)
        if observed!=wanted:
            missing=sorted(set(wanted)-set(observed)); extra=sorted(set(observed)-set(wanted)); changed=sorted(key for key in set(wanted)&set(observed) if wanted[key]!=observed[key])
            print("ADOPT BLOCKED: managed tree is not an exact template match")
            for label,items in (("missing",missing),("extra",extra),("changed",changed)):
                for item in items: print(f"- {label}: {item}")
            return 2
        agents_write,agents_conflicts=plan_bootstrap(target/"AGENTS.md","AGENTS.md")
        claude_write,claude_conflicts=plan_bootstrap(target/"CLAUDE.md","CLAUDE.md")
        adopt_conflicts=agents_conflicts+claude_conflicts
        if adopt_conflicts:
            print("ADOPT BLOCKED: a managed bootstrap anchor is locally modified")
            for item in adopt_conflicts: print(f"- {item}")
            return 2
        if args.dry_run: print(f"DRY RUN adopt workflow {VERSION}"); return 0
        candidate_parent=begin_transaction(target)
        try:
            candidate=candidate_parent/".agent"; copy_private_tree(destination,candidate)
            candidate_agents=stage_bootstrap(target,candidate_parent,"AGENTS.md")
            candidate_claude=stage_bootstrap(target,candidate_parent,"CLAUDE.md")
            atomic_json(candidate/".workflow-manifest.json",install_manifest(wanted,plugin_wanted,entry_digest,sha(candidate_agents),sha(candidate_claude)))
            migrate_private(source,candidate,args.agent_platform_snapshot,project_root=target,allow_current_chat_local_release=args.allow_current_chat_local_release)
            validate_candidate(candidate,wanted,plugin_wanted,entry_digest,candidate_agents,candidate_claude)
            replacements=[(candidate,destination)]
            if agents_write: replacements.append((candidate_agents,target/"AGENTS.md"))
            if claude_write: replacements.append((candidate_claude,target/"CLAUDE.md"))
            commit_transaction(target,candidate_parent,replacements)
        except Exception:
            abort_transaction(target)
            raise
        print(f"ADOPTED workflow {VERSION} in {target}"); return 0
    if not manifest_path.is_file():
        print("WORKFLOW UNMANAGED: missing .workflow-manifest.json; use --adopt only after an exact managed-tree match")
        return 2
    wanted,plugin_wanted,wanted_entry,entry_digest=source_contract(source_root)
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
    writes,removes,conflicts=plan_agent_update(wanted,installed,destination)
    agents_write,agents_conflicts=plan_bootstrap(target/"AGENTS.md","AGENTS.md")
    claude_write,claude_conflicts=plan_bootstrap(target/"CLAUDE.md","CLAUDE.md")
    conflicts=conflicts+agents_conflicts+claude_conflicts
    if conflicts:
        print("UPDATE BLOCKED: locally modified managed files"); [print(f"- {item}") for item in conflicts]; return 2
    if args.check:
        validate_project_guardrails(destination,allow_legacy=installed_migration_version(installed)<33)
        planned_agents_sha256=hashlib.sha256(render_bootstrap(target/"AGENTS.md").encode()).hexdigest()
        planned_claude_sha256=hashlib.sha256(render_bootstrap(target/"CLAUDE.md").encode()).hexdigest()
        manifest_matches_source=installed==install_manifest(wanted,plugin_wanted,entry_digest,planned_agents_sha256,planned_claude_sha256)
        if writes or removes or agents_write or claude_write or installed.get("version")!=VERSION or installed.get("migration_version")!=MIGRATION_VERSION or not manifest_matches_source:
            print(f"UPDATE AVAILABLE: writes={len(writes)} removes={len(removes)} bootstrap={int(agents_write or claude_write)} version={installed.get('version')}->{VERSION}"); return 1
        print(f"WORKFLOW CURRENT: {VERSION}"); return 0
    if installed_migration_version(installed)<34:
        validate_legacy_active_context(destination)
    if args.dry_run: print(f"DRY RUN update: writes={len(writes)} removes={len(removes)}"); return 0
    candidate_parent=begin_transaction(target)
    try:
        candidate=candidate_parent/".agent"
        copy_private_tree(destination,candidate)
        candidate_agents=stage_bootstrap(target,candidate_parent,"AGENTS.md")
        candidate_claude=stage_bootstrap(target,candidate_parent,"CLAUDE.md")
        write_managed(source,candidate,writes,removes); migrate_private(source,candidate,args.agent_platform_snapshot,project_root=target,allow_current_chat_local_release=args.allow_current_chat_local_release,idle_reseed=bool(writes or removes))
        atomic_json(candidate/".workflow-manifest.json",install_manifest(wanted,plugin_wanted,entry_digest,sha(candidate_agents),sha(candidate_claude)))
        validate_candidate(candidate,wanted,plugin_wanted,entry_digest,candidate_agents,candidate_claude)
        replacements=[(candidate,destination)]
        if agents_write: replacements.append((candidate_agents,target/"AGENTS.md"))
        if claude_write: replacements.append((candidate_claude,target/"CLAUDE.md"))
        commit_transaction(target,candidate_parent,replacements)
    except Exception:
        abort_transaction(target)
        raise
    print(f"UPDATED workflow to {VERSION}; preserved config, policies, state and project files"); return 0


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("target"); parser.add_argument("--project-name","--name",dest="project_name"); parser.add_argument("--project-type","--type",dest="project_type",default="general-project"); parser.add_argument("--agent-platform-snapshot"); parser.add_argument("--human-decision-adapter"); parser.add_argument("--provider-preflight-adapter"); parser.add_argument("--allow-current-chat-local-release",action="store_true"); parser.add_argument("--allow-downgrade",action="store_true"); parser.add_argument("--guardrails-file")
    mode=parser.add_mutually_exclusive_group(); mode.add_argument("--check",action="store_true"); mode.add_argument("--update",action="store_true"); mode.add_argument("--adopt",action="store_true"); parser.add_argument("--dry-run",action="store_true"); args=parser.parse_args()
    if args.guardrails_file and (args.check or args.update or args.adopt):
        parser.error("--guardrails-file is valid only for a new install; installed projects use agentctl.py project-init")
    if args.allow_downgrade and not args.update:
        parser.error("--allow-downgrade is valid only with --update")
    source_root=Path(__file__).resolve().parent; target=Path(args.target).resolve()
    if not args.check and not args.dry_run:
        target.parent.mkdir(parents=True,exist_ok=True)
    if not target.parent.is_dir():
        # Read-only modes against a missing location hold no transaction to recover.
        return execute(args,source_root,target)
    lock_descriptor=os.open(str(target.parent),os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
    try:
        fcntl.flock(lock_descriptor,fcntl.LOCK_EX)
        recover_transaction(target)
        return execute(args,source_root,target)
    finally:
        try: fcntl.flock(lock_descriptor,fcntl.LOCK_UN)
        finally: os.close(lock_descriptor)


if __name__=="__main__": raise SystemExit(main())
