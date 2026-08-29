#!/usr/bin/env python3
"""Disposable requirement and token control-plane attacks."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types



if (__name__=="__main__" and not globals().get("_PUBLICATION_SELF_TEST_REENTRY")
        and os.environ.get("AGENT_WORKFLOW_FOCUSED_PROMOTION_TEST")!="1"):
    import runpy
    from workflowlib.publication import discover_project_root,run_cli
    def _publication_self_test():
        runpy.run_path(__file__,run_name="__main__",init_globals={"_PUBLICATION_SELF_TEST_REENTRY":True})
        return 0
    raise SystemExit(run_cli(discover_project_root(),_publication_self_test))

SOURCE = Path(__file__).resolve().parents[1]
BASE_PYTHONPATH = os.environ.get("PYTHONPATH", "")
sys.path.insert(0, str(SOURCE / "scripts"))
import providerctl as PROVIDERCTL
import humandecision as HUMANDECISION


def provider_approval(source: str, artifact_sha256: str, gate: str = "requirement") -> dict:
    return {
        "source": source,
        "artifact_sha256": artifact_sha256,
        "decision_receipt": {
            "gate": gate,
            "source": source,
            "artifact_sha256": artifact_sha256,
            "authority": "provider-signed-user-message",
        },
    }


def install_provider_reverify(root: Path) -> None:
    site = root / "test-provider-site"
    site.mkdir(exist_ok=True)
    (site / "sitecustomize.py").write_text(
        "import hashlib,json,sys\nfrom pathlib import Path\n"
        "sys.path.insert(0,str(Path.cwd()/'.agent/scripts'))\n"
        "import humandecision\n"
        "def _verify(root,config,task,*,gate,artifact_sha256,source,receipt,require_fresh=True):\n"
        " path=(Path(root)/receipt).resolve();raw=path.read_bytes()\n"
        " if json.loads(raw)!={'test_provider_receipt':True}: raise SystemExit('test provider rejected receipt')\n"
        " return {'schema':'agent-human-decision-receipt/v1','path':str(path.relative_to(Path(root).resolve())),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'decision_id':'test-provider-decision','authority':'provider-signed-user-message','adapter_path':'/test/provider/decision-adapter','adapter_sha256':'a'*64}\n"
        "def _reverify(root,config,task,*,gate,artifact_sha256,source,record):\n"
        " if not isinstance(record,dict): return False\n"
        " if record.get('gate') is not None: return record.get('gate')==gate and record.get('artifact_sha256')==artifact_sha256 and record.get('source')==source and record.get('authority')=='provider-signed-user-message'\n"
        " try: return record==_verify(root,config,task,gate=gate,artifact_sha256=artifact_sha256,source=source,receipt=record.get('path',''),require_fresh=False)\n"
        " except Exception: return False\n"
        "humandecision.verify=_verify\nhumandecision.reverify=_reverify\n",
        encoding="utf-8",
    )
    os.environ["PYTHONPATH"] = str(site) + (os.pathsep + BASE_PYTHONPATH if BASE_PYTHONPATH else "")


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run(root: Path, tool: str, *args: str, expected: int = 0, env=None) -> str:
    result = subprocess.run(
        [sys.executable, f".agent/scripts/{tool}.py", *args], cwd=root, env=env,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode != expected:
        raise AssertionError(f"{tool} {args}: expected {expected}, got {result.returncode}\n{result.stdout}")
    return result.stdout


def promotion_security_focus() -> None:
    fixture = r'''import base64,datetime as dt,hashlib,json,os,shutil,sys,tempfile,types
from pathlib import Path
SOURCE=Path(os.environ["PROMOTION_SOURCE"]); case=os.environ["PROMOTION_CASE"]
with tempfile.TemporaryDirectory(prefix="promotion-focus-") as raw:
 root=Path(raw); shutil.copytree(SOURCE/"scripts",root/".agent/scripts"); (root/".agent/state").mkdir(); (root/".agent/project/knowledge").mkdir(parents=True)
 os.chdir(root); sys.path.insert(0,str(root/".agent/scripts")); import agentctl
 agentctl.workflow_validator.task_archive_errors=lambda current:(["forged archive chain"] if case=="invalid-archive" else [])
 agentctl.workflow_validator.completion_checkpoint_valid=lambda task:(case!="invalid-completion")
 owner=root/".agent/project/knowledge/topic.md"; owner.write_text("# Topic\n",encoding="utf-8")
 registry={"schema":"agent-knowledge-registry/v1","entries":[{"id":"topic","path":"topic.md","kind":"other","owners":["owner"],"tags":[],"source_globs":["src/**"],"status":"active"}]}
 registry_path=root/".agent/project/knowledge/registry.json"; registry_path.write_text(json.dumps(registry)+"\n",encoding="utf-8")
 evidence=root/"evidence.txt"; evidence.write_text("e",encoding="utf-8"); evidence_sha=hashlib.sha256(evidence.read_bytes()).hexdigest(); evidence_record={"path":"evidence.txt","sha256":evidence_sha,"bytes":1}
 expiry=(dt.datetime.now(dt.timezone.utc)+(dt.timedelta(seconds=-1) if case=="expiry" else dt.timedelta(hours=1))).isoformat()
 candidate_value={"schema":"agent-knowledge-candidate/v1","rule":"pin exact evidence","observation":"drift was observed","evidence_sha256":["b"*64] if case=="platform-only" else [evidence_sha],"reuse_scope":"promotion tests","counterexample":"unrelated evidence","expires_at":expiry,"owner_id":"topic"}
 candidate_file=root/"candidate.json"; candidate_file.write_text(json.dumps(candidate_value),encoding="utf-8"); source_record={"path":"candidate.json","sha256":hashlib.sha256(candidate_file.read_bytes()).hexdigest(),"bytes":len(candidate_file.read_bytes())}
 candidate={**candidate_value,"source_artifact":source_record}; candidate_id=hashlib.sha256(json.dumps(candidate,sort_keys=True,separators=(",",":")).encode()).hexdigest(); candidate["candidate_id"]=candidate_id
 artifact_set=[{"node":1,**evidence_record}]; accepted_sha=hashlib.sha256(json.dumps(artifact_set,sort_keys=True,separators=(",",":")).encode()).hexdigest()
 binding={"schema":"agent-completion-binding/v2","accepted_artifact_set_sha256":accepted_sha,"completed_model":"model","candidate_sha256":"a"*64,"terminal_artifact_sha256":evidence_sha,"release_approval_sha256":None,"completion_platform_snapshot_sha256":"b"*64,"completion_decision_source":"not_required","completion_decision_receipt":None}
 task={"status":"accepted","task_generation_id":"generation-a","title":"task a","mode":"fast","task_type":"maintenance","files":1,"environment":"local","deployment_requested":False,"branch":"fixture","decision_policy_version":1,"risk_flags":{},"knowledge_candidates":[candidate],"completion_binding":binding,"node_artifacts":{"1":evidence_record},"retrospective":evidence_record,"task_archive":None}
 task_path=root/".agent/state/TASK.json"; task_path.write_text(json.dumps(task)+"\n",encoding="utf-8"); (root/".agent/config.json").write_text("{}\n",encoding="utf-8")
 entry={**candidate,"task_generation_id":"generation-a","task_title":"task a","completion_binding_sha256":hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(",",":")).encode()).hexdigest(),"recorded_at":dt.datetime.now(dt.timezone.utc).isoformat(),"status":"pending"}
 pending={"schema":"agent-knowledge-pending/v2","candidates":[entry],"promotions":[]}; pending_path=root/".agent/state/knowledge-pending.json"; pending_path.write_text(json.dumps(pending)+"\n",encoding="utf-8")
 if case=="archive":
  archived_raw=task_path.read_bytes(); payload={"schema":"agent-task-archive/v2","task":{"sha256":hashlib.sha256(archived_raw).hexdigest(),"bytes":len(archived_raw),"utf8":archived_raw.decode()},"previous":None}
  payload_raw=(json.dumps(payload,sort_keys=True,separators=(",",":"))+"\n").encode(); digest=hashlib.sha256(payload_raw).hexdigest(); archive=root/f".agent/state/evidence/task-archives/{digest}.json"; archive.parent.mkdir(parents=True); archive.write_bytes(payload_raw)
  newer={**task,"status":"clarifying","task_generation_id":"generation-b","title":"task b","knowledge_candidates":[],"task_archive":{"schema":"agent-task-archive-head/v1","path":f".agent/state/evidence/task-archives/{digest}.json","sha256":digest,"bytes":len(payload_raw),"total_archives":1}}
  task_path.write_text(json.dumps(newer)+"\n",encoding="utf-8")
 state={"consumed":False,"count":0}; agentctl.subprocess.run=lambda *a,**k:types.SimpleNamespace(returncode=0,stdout="")
 agentctl.humandecision.prepare_decision_request=lambda *a,**k:{"prepared":True,"artifact":k["artifact_sha256"]}
 def status(*a,**k):
  if case=="owner-drift" and not state.get("drifted"): owner.write_text("drift\n",encoding="utf-8"); state["drifted"]=True
  if case=="registry-drift" and not state.get("drifted"): registry_path.write_text("{}\n",encoding="utf-8"); state["drifted"]=True
  if case=="config-drift" and not state.get("drifted"): (root/".agent/config.json").write_text('{"drift":true}\n',encoding="utf-8"); state["drifted"]=True
  assert k["prepared"].get("artifact")==k["artifact_sha256"] and k["source"]=="user:test" and k["gate"]=="knowledge"
  return {"status":"consumed","record":{"provider":"ok"}} if state["consumed"] else {"status":"unconsumed","record":None}
 def consume(*a,**k): state["consumed"]=True; state["count"]+=1; return {"status":"consumed","record":{"provider":"ok"}}
 agentctl.humandecision.status_prepared_decision=status; agentctl.humandecision.consume_prepared_decision=consume
 agentctl.humandecision.routing_profile_sha256=lambda task:"c"*64; agentctl.humandecision.project_identity_sha256=lambda root,config:"d"*64; agentctl.humandecision.task_generation_sha256=lambda task:"e"*64
 args=types.SimpleNamespace(source="user:test",candidate_id=candidate_id,print_decision_request=False,human_decision_receipt="receipt")
 before_owner=owner.read_bytes(); before_pending=pending_path.read_bytes()
 if case in {"forged","symlink-journal"}:
  class Crash(Exception): pass
  agentctl.os._exit=lambda code:(_ for _ in ()).throw(Crash(code)); os.environ["AGENT_WORKFLOW_PROMOTION_SELF_TEST_CRASH"]="after-prepared-journal"
  try: agentctl.command_promote_knowledge(args)
  except Crash: pass
  os.environ.pop("AGENT_WORKFLOW_PROMOTION_SELF_TEST_CRASH",None); journal=agentctl.KNOWLEDGE_PROMOTION_JOURNAL_PATH
  if case=="forged":
   value=json.loads(journal.read_text()); forged=b"forged owner\n"; value["owner_after_b64"]=base64.b64encode(forged).decode(); value["artifact_sha256"]=hashlib.sha256(forged).hexdigest(); journal.write_text(json.dumps(value)+"\n")
  else:
   external=root/"external-journal"; journal.replace(external); journal.symlink_to(external)
  try: agentctl.recover_knowledge_promotion_transaction(); raise AssertionError("forged journal was accepted")
  except (SystemExit,OSError): pass
  assert owner.read_bytes()==before_owner and pending_path.read_bytes()==before_pending and state["count"]==0
 elif case in {"lock-symlink","lock-hardlink"}:
  outside=root/"outside-lock"; outside.write_text("sentinel")
  lock=agentctl.KNOWLEDGE_PROMOTION_LOCK_PATH
  if case=="lock-symlink": lock.symlink_to(outside)
  else: os.link(outside,lock)
  try:
   with agentctl.locked_knowledge_promotion(): pass
   raise AssertionError("unsafe lock was accepted")
  except (SystemExit,OSError): pass
  assert outside.read_text()=="sentinel" and owner.read_bytes()==before_owner and pending_path.read_bytes()==before_pending
 elif case=="parent-swap":
  external=root/"external"; external.mkdir(); original=agentctl.os.rename; swapped={"done":False}
  def racing(src,dst,*a,**kw):
   if not swapped["done"] and dst=="topic.md":
    managed=root/".agent/project/knowledge"; held=root/".agent/project/knowledge-held"; original(managed,held); managed.symlink_to(external,target_is_directory=True); swapped["done"]=True
   return original(src,dst,*a,**kw)
  agentctl.os.rename=racing
  try: agentctl.command_promote_knowledge(args); raise AssertionError("parent swap reported a successful promotion")
  except (SystemExit,OSError): pass
  held=root/".agent/project/knowledge-held/topic.md"
  assert swapped["done"] and state["count"]==1 and agentctl.KNOWLEDGE_PROMOTION_JOURNAL_PATH.exists()
  assert not (external/"topic.md").exists() and held.exists()
 elif case in {"crash-consume","crash-write-0","crash-write-1"}:
  class Crash(Exception): pass
  hook={"crash-consume":"after-consume","crash-write-0":"after-write-0","crash-write-1":"after-write-1"}[case]
  agentctl.os._exit=lambda code:(_ for _ in ()).throw(Crash(code)); os.environ["AGENT_WORKFLOW_PROMOTION_SELF_TEST_CRASH"]=hook
  try: agentctl.command_promote_knowledge(args)
  except Crash: pass
  assert state["count"]==1 and agentctl.KNOWLEDGE_PROMOTION_JOURNAL_PATH.exists()
  if case=="crash-consume": assert owner.read_bytes()==before_owner
  os.environ.pop("AGENT_WORKFLOW_PROMOTION_SELF_TEST_CRASH",None); agentctl.recover_knowledge_promotion_transaction()
  assert state["count"]==1 and not agentctl.KNOWLEDGE_PROMOTION_JOURNAL_PATH.exists() and not json.loads(pending_path.read_text())["candidates"]
 elif case in {"expiry","evidence-drift","owner-drift","registry-drift","config-drift","platform-only","invalid-archive","invalid-completion"}:
  if case=="evidence-drift": evidence.write_text("changed",encoding="utf-8")
  try: agentctl.command_promote_knowledge(args); raise AssertionError(f"{case} was accepted")
  except SystemExit: pass
  assert state["count"]==0 and pending_path.read_bytes()==before_pending and not agentctl.KNOWLEDGE_PROMOTION_JOURNAL_PATH.exists()
  if case!="owner-drift": assert owner.read_bytes()==before_owner
 else:
  agentctl.command_promote_knowledge(args); assert state["count"]==1 and not json.loads(pending_path.read_text())["candidates"] and not agentctl.KNOWLEDGE_PROMOTION_JOURNAL_PATH.exists()
'''
    cases=("success","archive","expiry","evidence-drift","owner-drift","registry-drift","config-drift","platform-only","invalid-archive","invalid-completion","forged","symlink-journal","lock-symlink","lock-hardlink","parent-swap","crash-consume","crash-write-0","crash-write-1")
    for case in cases:
        env={**os.environ,"PROMOTION_SOURCE":str(SOURCE),"PROMOTION_CASE":case}
        result=subprocess.run([sys.executable,"-c",fixture],env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
        if result.returncode:
            raise AssertionError(f"promotion security case {case} failed:\n{result.stdout}")


if os.environ.get("AGENT_WORKFLOW_FOCUSED_PROMOTION_TEST")=="1":
    promotion_security_focus()
    print("FOCUSED KNOWLEDGE PROMOTION SECURITY SELF-TEST PASSED")
    raise SystemExit(0)


def tree_digest(root: Path):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in root.rglob("*") if path.is_file() and not path.is_symlink()}


def copy_policy_runtime(root: Path, scripts: Path) -> None:
    shutil.copytree(SOURCE / "scripts/workflowlib", scripts / "workflowlib", dirs_exist_ok=True)
    if not (scripts/"testrun.py").exists(): shutil.copy2(SOURCE/"scripts/testrun.py",scripts/"testrun.py")
    shutil.copy2(SOURCE / "INDEX.md", root / ".agent/INDEX.md")
    shutil.copytree(SOURCE / "workflows", root / ".agent/workflows", dirs_exist_ok=True)
    shutil.copytree(SOURCE / "templates", root / ".agent/templates", dirs_exist_ok=True)
    shutil.copytree(SOURCE / "policies", root / ".agent/policies", dirs_exist_ok=True)
    shutil.copytree(SOURCE / "skills/run-ai-coding-pipeline", root / ".agent/skills/run-ai-coding-pipeline", dirs_exist_ok=True)
    shutil.copytree(SOURCE / "skills/clarify-task", root / ".agent/skills/clarify-task", dirs_exist_ok=True)


with tempfile.TemporaryDirectory(prefix="agentctl-context-transport-") as raw:
    root = Path(raw)
    shutil.copytree(SOURCE, root / ".agent", symlinks=True)
    seed = root / ".agent/assets/fresh-state/v1"
    shutil.rmtree(root / ".agent/state")
    shutil.rmtree(root / ".agent/policies")
    shutil.copytree(seed / "state", root / ".agent/state")
    shutil.copytree(seed / "policies", root / ".agent/policies")
    shutil.copy2(seed / "config.json", root / ".agent/config.json")
    subprocess.run(["git","init","-q"],cwd=root,check=True)
    subprocess.run(["git","checkout","-q","-b","fix/workflow-hardening"],cwd=root,check=True)
    run(root, "agentctl", "validate")
    pre_init_paths=(root/".agent/config.json",root/".agent/policies/PROJECT_GUARDRAILS.md",root/".agent/state/CONTEXT.json",
        root/".agent/state/STAGE_INDEX.md",root/".agent/state/TASK.json",root/".agent/state/SKILL_ACTIVATION.json")
    pre_init_bytes={path:path.read_bytes() for path in pre_init_paths}
    guardrails=root/"project-guardrails.md"
    guardrails.write_text("# Project Guardrails\n\n## Required project facts\n\n"
        "- Product and users: Disposable control-gate fixture.\n"
        "- Technology and architecture: Python workflow controls and JSON state.\n"
        "- Writable and read-only areas: The fixture is writable; external paths are read-only.\n"
        "- Security, privacy, compliance and performance red lines: No credentials or external effects.\n"
        "- Build, test and lint commands: Run the control-gate self-test.\n"
        "- Deployment authority and rollback owner: No deployment; the fixture owner rolls back.\n",encoding="utf-8")
    run(root,"agentctl","project-init","--guardrails-file",guardrails.name)
    before_skill_start={path:path.read_bytes() for path in (root/".agent/state/TASK.json",root/".agent/state/SKILL_ACTIVATION.json")}
    orphan=root/".agent/project/skills/orphan"; orphan.mkdir(parents=True)
    rejected_start=run(root,"agentctl","start","--model","provider-neutral/model.fixture","--title","orphan Skill must fail",expected=1)
    if "dynamic Skill activation failed closed" not in rejected_start or any(path.read_bytes()!=data for path,data in before_skill_start.items()):
        raise AssertionError("task start did not reject an unverified dynamic Skill surface before mutation")
    shutil.rmtree(root/".agent/project")
    for path,data in pre_init_bytes.items(): path.write_bytes(data)
    config_path = root / ".agent/config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if config.get("context_transport") != {"default": "native"}:
        raise AssertionError("fresh context transport is not native-only")
    config["context_transport"]["pxpipe"] = {"selection": "render-without-analysis"}
    write(config_path, config)
    output = run(root, "agentctl", "validate", expected=1)
    if "optional context transport policy is invalid" not in output:
        raise AssertionError(f"agentctl rejected the invalid plugin policy for the wrong reason:\n{output}")

    # The child-charge margins keep a positive floor: a zero margin would
    # silently weaken the child-charge invariant, so validate must reject it.
    # Each case starts from the pristine seed config so failures stay
    # attributable to the margin under test.
    seed_config_bytes = (seed / "config.json").read_bytes()
    for margin_key in (
        "inherited_turn_estimated_tokens", "child_system_tool_margin_tokens", "child_output_margin_tokens",
    ):
        broken = json.loads(seed_config_bytes)
        broken["agent_control"][margin_key] = 0
        write(config_path, broken)
        output = run(root, "agentctl", "validate", expected=1)
        if "child-agent model/context/capacity policy is invalid" not in output:
            raise AssertionError(f"zero {margin_key} did not fail the positive margin floor:\n{output}")
    for section,key,bad,expected_message in (
        ("agent_control","platform_limit",True,"child-agent model/context/capacity policy is invalid"),
        ("agent_control","status_interval_seconds","30","child-agent model/context/capacity policy is invalid"),
        ("agent_control","max_fork_turns",True,"child-agent model/context/capacity policy is invalid"),
        ("runtime","term_timeout_seconds","8","runtime term_timeout_seconds"),
        ("agent_control","default_model","bad model\n","child-agent model/context/capacity policy is invalid"),
    ):
        broken=json.loads(seed_config_bytes); broken[section][key]=bad; write(config_path,broken)
        output=run(root,"agentctl","validate",expected=1)
        if expected_message not in output or "Traceback" in output:
            raise AssertionError(f"malformed {section}.{key} did not fail cleanly:\n{output}")
    probe=subprocess.run([sys.executable,"-c","import sys;sys.path.insert(0,'.agent/scripts');import agentctl;assert agentctl.valid_model_id('provider-neutral/model-v1');assert not agentctl.valid_model_id('bad model');assert not agentctl.strict_bounded_int(True,1,3)"],cwd=root)
    if probe.returncode: raise AssertionError("host/model or strict integer helper rejected valid boundaries")

    # A positive margin passes the floor: the edited config drifts the capsule,
    # but the margin check itself must not fire.
    restored = json.loads(seed_config_bytes)
    restored["agent_control"]["child_output_margin_tokens"] = 1
    write(config_path, restored)
    output = run(root, "agentctl", "validate", expected=1)
    if "child-agent model/context/capacity policy is invalid" in output:
        raise AssertionError(f"a positive margin tripped the floor:\n{output}")
    config_path.write_bytes(seed_config_bytes)
    run(root, "agentctl", "validate")


with tempfile.TemporaryDirectory(prefix="provider-authority-proof-") as raw:
    root = Path(raw)
    (root / ".agent").mkdir()
    write(root / ".agent/config.json", {
        "agent_control": {"provider_preflight_observer": {
            "source": "provider-read-only-api", "automatic_release_trust": False,
            "provider_verification_required": True, "signed_adapter": "/protected/provider-adapter",
            "max_receipt_age_seconds": 300,
        }}
    })

    def authority_environment(provider: str) -> dict:
        receipt = {
            "schema": "agent-provider-authority-proof/v3", "receipt_id": "control-proof-123",
            "candidate_revision":"d"*40,"candidate_tree":"e"*40,
            "authority": "provider-authenticated-protected-adapter", "provider": provider,
            "project_id": "71", "repository_host": "code.example", "repository": "neutral/repository",
            "authority_kind": ("github-external-workflow" if provider == "github" else "gitlab-pipeline-execution-policy"),
            "immutable_authority_ref": (
                "security/authority/.github/workflows/verify.yml@" + "a" * 40
                if provider == "github" else "policy/release-authority@" + "a" * 40
            ),
            "effective_config_sha256": "b" * 64, "effective_config_bytes": 4096,
            "collision_result": {"status": "clear", "evidence_sha256": "c" * 64},
            "producer_identity": {"subject": "provider/security-authority", "issuer": "https://provider.example", "provider_actor_id": "88"},
            "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        }
        return {
            "AGENT_PROVIDER_AUTHORITY_RECEIPT_JSON": json.dumps(receipt, sort_keys=True, separators=(",", ":")),
            "AGENT_PROVIDER_PROJECT_ID": "71", "AGENT_PROVIDER_REPOSITORY_HOST": "code.example", "AGENT_PROVIDER_REPOSITORY": "neutral/repository",
        }

    original_adapter = PROVIDERCTL._provider_authority_adapter
    original_run_adapter = PROVIDERCTL.humandecision.run_adapter
    original_candidate_identity=PROVIDERCTL._current_candidate_git_identity
    original_trusted_repository=PROVIDERCTL.trusted_git_repository
    try:
        PROVIDERCTL.trusted_git_repository=lambda _root:{"host":"code.example","repository":"neutral/repository"}
        PROVIDERCTL._current_candidate_git_identity=lambda *_a,**_k:{"candidate_revision":"d"*40,"candidate_tree":"e"*40}
        PROVIDERCTL._provider_authority_adapter = lambda _root: Path("/protected/provider-adapter")
        def verified_adapter(_adapter, _arguments, *, receipt_raw=None, **_kwargs):
            return types.SimpleNamespace(
                returncode=0,
                stdout="VERIFIED PROVIDER PREFLIGHT sha256=" + hashlib.sha256(receipt_raw).hexdigest() + "\n",
            )
        PROVIDERCTL.humandecision.run_adapter = verified_adapter
        for provider, validator in (
            ("github", PROVIDERCTL.validate_github_external_authority_environment),
            ("gitlab", PROVIDERCTL.validate_gitlab_external_authority_environment),
        ):
            environment = authority_environment(provider)
            validator(environment, root=root)
            spoofed = dict(environment); spoofed["AGENT_PROVIDER_PROJECT_ID"] = "72"
            try:
                validator(spoofed, root=root)
            except PROVIDERCTL.AdaptiveError as error:
                if error.code != "PROVIDER_EXTERNAL_AUTHORITY_UNVERIFIED":
                    raise AssertionError(f"{provider} spoof failed for the wrong reason: {error}")
            else:
                raise AssertionError(f"{provider} project-identity spoof became authority")
        legacy = {
            "AGENT_GITHUB_AUTHORITY_MODE": "immutable-external-workflow",
            "AGENT_GITHUB_AUTHORITY_REPOSITORY_ID": "71",
            "AGENT_GITHUB_AUTHORITY_WORKFLOW_REF": "security/authority/.github/workflows/verify.yml@" + "a" * 40,
            "AGENT_GITHUB_RULESET_RECEIPT_SHA256": "b" * 64,
            "AGENT_GITHUB_VERIFIER_CONFIG_SHA256": "c" * 64,
        }
        try:
            PROVIDERCTL.validate_github_external_authority_environment(legacy, root=root)
        except PROVIDERCTL.AdaptiveError as error:
            if error.code != "PROVIDER_EXTERNAL_AUTHORITY_UNVERIFIED":
                raise AssertionError(f"legacy metadata failed for the wrong reason: {error}")
        else:
            raise AssertionError("regex-shaped caller metadata became provider authority")
        rejected = authority_environment("github")
        PROVIDERCTL.humandecision.run_adapter = lambda *_args, **_kwargs: types.SimpleNamespace(returncode=1, stdout="REJECTED\n")
        try:
            PROVIDERCTL.validate_github_external_authority_environment(rejected, root=root)
        except PROVIDERCTL.AdaptiveError as error:
            if error.code != "PROVIDER_EXTERNAL_AUTHORITY_UNVERIFIED":
                raise AssertionError(f"adapter rejection failed for the wrong reason: {error}")
        else:
            raise AssertionError("protected adapter rejection became VERIFIED provider authority")
    finally:
        PROVIDERCTL._provider_authority_adapter = original_adapter
        PROVIDERCTL.humandecision.run_adapter = original_run_adapter
        PROVIDERCTL._current_candidate_git_identity=original_candidate_identity
        PROVIDERCTL.trusted_git_repository=original_trusted_repository


with tempfile.TemporaryDirectory(prefix="control-gates-") as raw:
    root = Path(raw)
    scripts = root / ".agent/scripts"
    state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in (
        "agentctl.py", "contextctl.py", "contexttx.py", "workflowctl.py",
        "artifactctl.py", "humandecision.py", "process_observation.py", "testrun.py",
    ):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    shutil.copytree(SOURCE / "scripts/workflowlib", scripts / "workflowlib")
    shutil.copy2(SOURCE / "INDEX.md", root / ".agent/INDEX.md")
    shutil.copytree(SOURCE / "workflows", root / ".agent/workflows")
    shutil.copytree(SOURCE / "templates", root / ".agent/templates")
    shutil.copytree(SOURCE / "policies", root / ".agent/policies")
    shutil.copytree(SOURCE / "skills/run-ai-coding-pipeline", root / ".agent/skills/run-ai-coding-pipeline")
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    install_provider_reverify(root)
    contract = "# Requirement Contract\n\n- Human decisions: user:fixture\n- Clarified: true\n"
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    digest = hashlib.sha256(contract.encode()).hexdigest()
    task = {
        "schema": "agent-task/v2", "title": "control fixture", "task_type": "maintenance",
        "complexity": "bounded", "mode": "release", "files": 1, "environment": "local",
        "deployment_requested": False, "branch": "unversioned", "status": "in_progress",
        "phase": "implementation", "requirements_clarified": True,
        "requirement_source": "user:fixture", "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
        "requirement_contract_sha256": digest, "primary_skill": "run-ai-coding-pipeline",
        "decision_policy_version": 1,
        "task_generation_id": "fixture-task-generation",
        "risk_flags": {key: False for key in ("deploy", "data_risk", "cross_system", "uncertain", "security", "compliance", "migration", "irreversible", "external_impact")},
        "token_budget": 96000, "tokens_used": 79200, "token_usage_source": "estimated",
        "usage_receipts": [], "budget_state": "must_compact", "child_agents_used": 0,
        "peak_child_agents": 0, "loaded_references": [], "selected_templates": ["requirement-contract"],
        "selected_capabilities": ["core"], "template_route": None, "rendered_artifacts": [],
        "decisions": [], "open_questions": [], "next_action": "finish implementation",
        "current_node": 6, "accepted_nodes": list(range(6)), "node_artifacts": {},
        "gate_approvals": {"requirement": provider_approval("user:fixture", digest)}, "pending_gate_artifacts": {},
        "rollback_ledger": [], "rollback_archive": None,
        "failure_ledger": {}, "failure_archive": None, "mode_status": "confirmed",
        "metrics": {"tokens": 79200, "token_source": "estimated", "child_agents": 0, "peak_children": 0,
                    "tool_calls": 0, "test_runs": 0, "test_failures": 0, "repair_rounds": 0,
                    "user_corrections": 0, "context_compactions": 0, "references_loaded": 0},
        "updated": "2026-07-17",
    }
    write(state / "TASK.json", task)
    run(root, "contextctl", "sync", "--reason", "fixture", "--summary", "control fixture", "--source-tokens", "1600")

    run(root, "agentctl", "budget-gate", "--action", "unknown-typo", expected=2)
    run(root, "agentctl", "budget-gate", "--action", "route-templates", expected=2)
    pristine_context=(state/"CONTEXT.json").read_bytes()
    missing_handoff=json.loads(pristine_context); missing_handoff.pop("resume")
    write(state/"CONTEXT.json",missing_handoff)
    run(root,"agentctl","budget-gate","--action","finish-node",expected=2)
    (state/"CONTEXT.json").write_bytes(pristine_context)
    run(root, "agentctl", "budget-gate", "--action", "finish-node")
    run(root, "agentctl", "budget-gate", "--action", "spawn-review-agent")

    # Observed/estimated usage is never discarded merely because it crossed the
    # hard watermark; it is recorded and all expansion is then blocked.
    run(root, "agentctl", "record-usage", "--tokens", "7200", "--source", "estimated")
    hard = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if hard["tokens_used"] != 86400 or hard["budget_state"] != "hard_blocked":
        raise AssertionError("hard-watermark usage was not recorded truthfully")
    run(root, "agentctl", "budget-gate", "--action", "finish-node", expected=2)
    run(root, "agentctl", "budget-gate", "--action", "rollback")

    before = (state / "TASK.json").read_bytes()
    run(root, "workflowctl", "advance", "--node", "6", "--artifact", "missing.json", expected=1)
    if (state / "TASK.json").read_bytes() != before:
        raise AssertionError("hard-blocked workflow advance mutated TASK")

    # Local execution is a later-phase mutator and cannot be used while the
    # requirement contract is unclarified.
    hard["requirements_clarified"] = False
    hard["requirement_source"] = "pending"
    write(state / "TASK.json", hard)
    run(root, "agentctl", "managed-run", "--name", "forbidden", "--timeout", "1", "--", "/usr/bin/true", expected=1)

with tempfile.TemporaryDirectory(prefix="human-decision-v1-") as raw:
    root = Path(raw)
    scripts = root / ".agent/scripts"
    state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in ("agentctl.py", "contextctl.py", "contexttx.py", "humandecision.py", "process_observation.py", "testrun.py"):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    copy_policy_runtime(root, scripts)
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    fixture_config = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))
    fixture_config["guardrails_ready"] = True
    fixture_config["agent_control"]["human_decision_observer"]["allow_current_chat_local_release"] = False
    write(root / ".agent/config.json", fixture_config)
    contract = """# Requirement Contract

- Goal: verify provider-owned human approval
- Users: workflow maintainers
- Success: unsigned approval is rejected
- In scope: requirement approval gate
- Out of scope: implementation
- Constraints: no external effects
- Data and permissions: fixture data only
- Target environment: local
- Acceptance: fail closed without a signed receipt
- Provenance: user fixture
- Human decisions: pending
- Clarified: false
"""
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    task = {
        "schema": "agent-task/v2", "title": "human decision v1 fixture",
        "task_type": "governance", "complexity": "bounded", "mode": "release",
        "task_generation_id":"forged-task-generation",
        "files": 1, "environment": "local", "deployment_requested": False,
        "branch": "unversioned", "status": "waiting_human", "phase": "clarification",
        "requirements_clarified": False, "requirement_source": "pending",
        "primary_skill": "clarify-task", "decision_policy_version": 1,
        "risk_flags": {key: False for key in (
            "deploy", "data_risk", "cross_system", "uncertain", "security",
            "compliance", "migration", "irreversible", "external_impact",
        )},
        "token_budget": 96000, "tokens_used": 0, "token_usage_source": "estimated",
        "usage_receipts": [], "budget_state": "ok", "child_agents_used": 0,
        "peak_child_agents": 0, "loaded_references": [],
        "selected_templates": ["requirement-contract"], "selected_capabilities": ["core"],
        "template_route": None, "rendered_artifacts": [], "decisions": [],
        "open_questions": ["requirement contract approval"],
        "next_action": "approve requirement contract", "current_node": 1,
        "accepted_nodes": [0], "node_artifacts": {}, "gate_approvals": {},
        "pending_gate_artifacts": {}, "rollback_ledger": [], "rollback_archive": None,
        "failure_ledger": {}, "failure_archive": None,
        "mode_status": "provisional",
        "metrics": {
            "tokens": 0, "token_source": "estimated", "child_agents": 0,
            "peak_children": 0, "tool_calls": 0, "test_runs": 0,
            "test_failures": 0, "repair_rounds": 0, "user_corrections": 0,
            "context_compactions": 0, "references_loaded": 0,
        },
        "updated": "2026-07-18",
    }
    write(state / "TASK.json", task)
    run(
        root, "contextctl", "sync", "--reason", "fixture",
        "--summary", "unsigned human decision fixture", "--source-tokens", "1200",
    )
    before_task = (state / "TASK.json").read_bytes()
    before_contract = (state / "REQUIREMENT_CONTRACT.md").read_bytes()
    failure = run(
        root, "agentctl", "approve-requirements", "--source", "user:fixture",
        expected=1,
    )
    if "requires --human-decision-receipt" not in failure:
        raise AssertionError(f"v1 requirement gate failed for the wrong reason:\n{failure}")
    if (state / "TASK.json").read_bytes() != before_task or (state / "REQUIREMENT_CONTRACT.md").read_bytes() != before_contract:
        raise AssertionError("rejected unsigned v1 requirement approval mutated authoritative state")
    forged_provider_dir = Path(tempfile.mkdtemp(prefix="forged-human-provider-"))
    forged_adapter = forged_provider_dir / "verify-human-decision.py"
    forged_adapter.write_text("""#!/usr/bin/env python3
import hashlib, pathlib, sys
receipt = pathlib.Path(sys.argv[sys.argv.index('--receipt') + 1])
print('VERIFIED HUMAN DECISION sha256=' + hashlib.sha256(receipt.read_bytes()).hexdigest())
""", encoding="utf-8")
    forged_adapter.chmod(0o755)
    fixture_config["agent_control"]["human_decision_observer"]["signed_adapter"] = str(forged_adapter.resolve())
    write(root / ".agent/config.json", fixture_config)
    approved_contract = contract.replace("- Human decisions: pending", "- Human decisions: user:fixture").replace(
        "- Clarified: false", "- Clarified: true",
    )
    approved_sha = hashlib.sha256(approved_contract.encode()).hexdigest()
    routing_sha=HUMANDECISION.routing_profile_sha256(task)
    project_sha=HUMANDECISION.project_identity_sha256(root,fixture_config)
    prospective_task={**task,"requirement_contract_sha256":approved_sha}
    generation_sha=HUMANDECISION.task_generation_sha256(prospective_task)
    forged_receipt = ".agent/state/evidence/forged-human-decision.json"
    write(root / forged_receipt, {
        "schema": "agent-human-decision/v1", "decision_id": "forged-temp-adapter",
        "gate": "requirement", "decision": "approved", "artifact_sha256": approved_sha,
        "source": "user:fixture", "task_title": task["title"], "task_mode": task["mode"],
        "routing_profile_sha256":routing_sha,"project_identity_sha256":project_sha,"task_generation_sha256":generation_sha,
        "task_generation_id":task["task_generation_id"],
        "observed_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "authority": "provider-signed-user-message",
    })
    forged_failure = run(
        root, "agentctl", "approve-requirements", "--source", "user:fixture",
        "--human-decision-receipt", forged_receipt, expected=1,
    )
    if "temporary boundary" not in forged_failure:
        raise AssertionError(f"Agent-created external adapter failed for the wrong reason:\n{forged_failure}")
    if (state / "TASK.json").read_bytes() != before_task or (state / "REQUIREMENT_CONTRACT.md").read_bytes() != before_contract:
        raise AssertionError("forged temporary adapter mutated or approved the v1 requirement gate")
    shutil.rmtree(forged_provider_dir)

with tempfile.TemporaryDirectory(prefix="human-decision-provider-only-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in ("agentctl.py", "contextctl.py", "contexttx.py", "humandecision.py", "process_observation.py", "testrun.py"):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    copy_policy_runtime(root, scripts)
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    fixture_config = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))
    fixture_config["guardrails_ready"] = True
    fixture_config["agent_control"]["human_decision_observer"]["allow_current_chat_local_release"] = False
    write(root / ".agent/config.json", fixture_config)
    contract = """# Requirement Contract

- Goal: verify provider-owned human approval
- Users: workflow maintainers
- Success: approval binds the routing profile
- In scope: requirement approval gate
- Out of scope: implementation
- Constraints: no external effects
- Data and permissions: fixture data only
- Target environment: local
- Acceptance: provider receipt validates under its routing profile
- Provenance: user fixture
- Human decisions: pending
- Clarified: false
"""
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    task = {
        "schema": "agent-task/v2", "title": "human decision v2 fixture",
        "task_type": "governance", "complexity": "bounded", "mode": "standard",
        "task_generation_id":"provider-task-generation",
        "files": 1, "environment": "local", "deployment_requested": False,
        "branch": "unversioned", "status": "waiting_human", "phase": "clarification",
        "requirements_clarified": False, "requirement_source": "pending",
        "primary_skill": "clarify-task", "decision_policy_version": 1,
        "risk_flags": {key: False for key in (
            "deploy", "data_risk", "cross_system", "uncertain", "security",
            "compliance", "migration", "irreversible", "external_impact",
        )},
        "token_budget": 48000, "tokens_used": 0, "token_usage_source": "estimated",
        "usage_receipts": [], "budget_state": "ok", "child_agents_used": 0,
        "peak_child_agents": 0, "loaded_references": [],
        "selected_templates": ["requirement-contract"], "selected_capabilities": ["core"],
        "template_route": None, "rendered_artifacts": [], "decisions": [],
        "open_questions": ["requirement contract approval"],
        "next_action": "approve requirement contract", "current_node": 1,
        "accepted_nodes": [0], "node_artifacts": {}, "gate_approvals": {},
        "pending_gate_artifacts": {}, "rollback_ledger": [], "rollback_archive": None,
        "failure_ledger": {}, "failure_archive": None,
        "mode_status": "provisional",
        "metrics": {
            "tokens": 0, "token_source": "estimated", "child_agents": 0,
            "peak_children": 0, "tool_calls": 0, "test_runs": 0,
            "test_failures": 0, "repair_rounds": 0, "user_corrections": 0,
            "context_compactions": 0, "references_loaded": 0,
        },
        "updated": "2026-07-30",
    }
    write(state / "TASK.json", task)
    run(
        root, "contextctl", "sync", "--reason", "fixture",
        "--summary", "local human decision fixture", "--source-tokens", "1200",
    )
    bootstrap_probe = subprocess.run(
        [sys.executable, "-c", (
            "import runpy,sys;sys.path.insert(0,'.agent/scripts');import agentctl;"
            "agentctl.command_validate=lambda:0;"
            "raise SystemExit(agentctl.command_bootstrap_check())"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    bootstrap = bootstrap_probe.stdout
    if (
        bootstrap_probe.returncode != 2
        or "BOOTSTRAP NOT READY: provider-owned human-decision adapter is not configured" not in bootstrap
        or "AUTHORITATIVE GATES BLOCKED" not in bootstrap
        or "LOCAL READY" in bootstrap
    ):
        raise AssertionError(f"adapterless bootstrap did not remain provider-gate blocked:\n{bootstrap}")
    (state / ".knowledge-promotion.lock").touch()
    def approval_authority_bytes():
        return {path.name: path.read_bytes() for path in (
            state / "TASK.json", state / "CONTEXT.json",
            state / "REQUIREMENT_CONTRACT.md",
        )}
    before_approval = approval_authority_bytes()
    request=json.loads(run(root,"agentctl","approve-requirements","--source","user:fixture","--print-decision-request"))
    if request.get("schema")!="agent-human-decision-request/v1" or request.get("task_generation_id")!=task["task_generation_id"] or approval_authority_bytes()!=before_approval:
        raise AssertionError("prospective requirement decision request mutated state or lost generation identity")
    missing = run(root, "agentctl", "approve-requirements", "--source", "user:fixture", expected=1)
    if "requires --human-decision-receipt" not in missing or approval_authority_bytes() != before_approval:
        raise AssertionError(f"provider-policy approval did not fail immutably without a provider receipt:\n{missing}")
    forged_local = ".agent/state/forged-local-approval.json"
    write(root / forged_local, {
        "source": "user:fixture", "artifact_sha256": "0" * 64,
        "assurance": "explicit-user-message;local-advisory;not-authoritative",
    })
    before_forged = approval_authority_bytes()
    forged = run(
        root, "agentctl", "approve-requirements", "--source", "user:fixture",
        "--human-decision-receipt", forged_local, expected=1,
    )
    if "human decision receipt" not in forged or approval_authority_bytes() != before_forged:
        raise AssertionError(f"forged local evidence did not fail immutably at the provider boundary:\n{forged}")
    provider_receipt = ".agent/state/test-provider-receipt.json"
    write(root / provider_receipt, {"test_only": "provider-owned adapter input"})
    provider_wrapper = r"""
import runpy, sys
from pathlib import Path
target = sys.argv[1]
sys.path.insert(0, str(Path(target).resolve().parent))
import humandecision

def provider_verify(*_args, receipt=None, gate=None, artifact_sha256=None, source=None, **_kwargs):
    return {"schema": "agent-human-decision/v1", "path": str(receipt),
            "sha256": "f" * 64, "bytes": 1, "decision_id": "self-test-provider",
            "authority": "provider-signed-user-message", "adapter_path": "/self-test/provider",
            "adapter_sha256": "e" * 64, "gate": gate,
            "artifact_sha256": artifact_sha256, "source": source}

def provider_reverify(*_args, gate=None, artifact_sha256=None, source=None, record=None, **_kwargs):
    try:
        return record == provider_verify(receipt=record.get("path"), gate=gate, artifact_sha256=artifact_sha256, source=source)
    except BaseException:
        return False

humandecision.verify = provider_verify
humandecision.reverify = provider_reverify
sys.argv = [target, *sys.argv[2:]]
runpy.run_path(target, run_name="__main__")
"""
    approved = subprocess.run(
        [sys.executable, "-c", provider_wrapper, str(scripts / "agentctl.py"),
         "approve-requirements", "--source", "user:fixture",
         "--human-decision-receipt", provider_receipt],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if approved.returncode or "REQUIREMENTS APPROVED" not in approved.stdout:
        raise AssertionError(f"test-only provider receipt was not accepted (exit={approved.returncode}):\n{approved.stdout}")
    approved_task = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    approval = approved_task.get("gate_approvals", {}).get("requirement")
    if (
        approved_task.get("decision_policy_version") != 1
        or request.get("task_generation_sha256") != PROVIDERCTL.humandecision.task_generation_sha256(approved_task)
        or request.get("artifact_sha256") != approved_task.get("requirement_contract_sha256")
        or not isinstance(approval, dict)
        or approval.get("source") != "user:fixture"
        or approval.get("artifact_sha256") != approved_task.get("requirement_contract_sha256")
        or approval.get("decision_receipt", {}).get("authority") != "provider-signed-user-message"
    ):
        raise AssertionError("provider approval was not stored in the uniform authoritative receipt shape")

with tempfile.TemporaryDirectory(prefix="workflow-hot-state-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in (
        "agentctl.py", "artifactctl.py", "contextctl.py", "contexttx.py",
        "humandecision.py", "process_observation.py", "testrun.py", "workflowctl.py",
    ):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    copy_policy_runtime(root, scripts)
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    install_provider_reverify(root)
    fixture_config = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))
    fixture_config["agent_control"]["human_decision_observer"]["allow_current_chat_local_release"] = False
    fixture_config.setdefault("context", {})["max_rollback_entries"] = 2
    fixture_config.setdefault("context", {})["max_failure_entries"] = 2
    fixture_config.setdefault("context", {})["max_failure_archive_depth"] = 2
    write(root / ".agent/config.json", fixture_config)
    contract = "# Requirement Contract\n\n- Human decisions: user:fixture\n- Clarified: true\n"
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    contract_sha = hashlib.sha256(contract.encode()).hexdigest()
    solution_path = state / "artifacts/04-solution.md"
    solution_path.parent.mkdir(parents=True)
    solution_path.write_text("# Approved candidate solution\n", encoding="utf-8")
    solution_sha = hashlib.sha256(solution_path.read_bytes()).hexdigest()
    task = {
        "schema": "agent-task/v2", "title": "decision and hot-state fixture",
        "task_type": "maintenance", "complexity": "bounded", "mode": "standard",
        "files": 1, "environment": "local", "deployment_requested": False,
        "branch": "unversioned", "status": "in_progress", "phase": "tests",
        "requirements_clarified": True, "requirement_source": "user:fixture",
        "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
        "requirement_contract_sha256": contract_sha, "primary_skill": "run-ai-coding-pipeline",
        "decision_policy_version": 1,
        "task_generation_id": "fixture-task-generation",
        "risk_flags": {key: False for key in (
            "deploy", "data_risk", "cross_system", "uncertain", "security",
            "compliance", "migration", "irreversible", "external_impact",
        )},
        "token_budget": 48000, "tokens_used": 0, "token_usage_source": "estimated",
        "usage_receipts": [], "budget_state": "ok", "child_agents_used": 0,
        "peak_child_agents": 0, "loaded_references": [], "selected_templates": ["solution"],
        "selected_capabilities": ["core"], "template_route": None,
        "rendered_artifacts": [{
            "template_id": "solution", "path": ".agent/state/artifacts/04-solution.md",
            "sha256": solution_sha, "bytes": len(solution_path.read_bytes()),
        }],
        "decisions": [], "open_questions": [], "next_action": "test rollback",
        "current_node": 5, "accepted_nodes": [0, 1, 2, 3, 4], "node_artifacts": {},
        "gate_approvals": {"requirement": provider_approval("user:fixture", contract_sha), "solution": {
            "source": "user:old", "artifact_sha256": "0" * 64,
        }},
        "pending_gate_artifacts": {},
        "rollback_ledger": [{"sequence": number} for number in range(5)],
        "rollback_archive": None,
        "failure_ledger": {
            hashlib.sha256("archived-repeat|tests".encode()).hexdigest(): 2,
            **{hashlib.sha256(f"old-failure-{number}".encode()).hexdigest(): 1 for number in range(4)},
        },
        "failure_archive": None, "mode_status": "confirmed", "metrics": {},
    }
    write(state / "TASK.json", task)
    run(root, "contextctl", "sync", "--reason", "fixture", "--summary", "hot state fixture", "--source-tokens", "1200")
    compact_output = run(root, "workflowctl", "compact-state")
    compacted = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    head = compacted.get("rollback_archive", {})
    archive = root / str(head.get("path", ""))
    failure_head = compacted.get("failure_archive", {})
    if len(compacted["rollback_ledger"]) != 2 or head.get("total_entries") != 3:
        raise AssertionError("compact-state did not bound rollback hot state")
    if len(compacted["failure_ledger"]) != 2 or failure_head.get("total_signatures") != 3 or failure_head.get("total_events") != 4:
        raise AssertionError("compact-state did not bound failure hot state")
    if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != head.get("sha256"):
        raise AssertionError("compact-state did not publish content-addressed archive evidence")
    if "STATE COMPACTED" not in compact_output:
        raise AssertionError("compact-state did not report its archive head")
    before_noop = (state / "TASK.json").read_bytes()
    run(root, "workflowctl", "compact-state")
    if (state / "TASK.json").read_bytes() != before_noop:
        raise AssertionError("compact-state no-op rewrote canonical TASK")
    run(
        root, "workflowctl", "return-node", "--from-node", "5", "--to", "4",
        "--issue-id", "fixture-return", "--cause-category", "tests",
        "--subtask", "hot-state", "--root-cause", "fixture root cause",
        "--change", "fixture repair",
    )
    returned = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if len(returned["rollback_ledger"]) != 2 or returned["rollback_archive"].get("total_entries") != 4:
        raise AssertionError("return-node did not automatically compact and chain rollback history")
    if (
        len(returned["failure_ledger"]) != 2
        or returned["failure_archive"].get("total_signatures") != 4
        or returned["failure_archive"].get("depth") != 1
    ):
        raise AssertionError("return-node did not automatically compact failure history")
    submitted = run(
        root, "workflowctl", "submit-gate", "--gate", "solution",
        "--artifact", ".agent/state/artifacts/04-solution.md",
    )
    decided = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    packet = decided.get("decision_packet", {})
    if "solution" in decided["gate_approvals"]:
        raise AssertionError("submit-gate retained a stale approval for the resubmitted gate")
    if (
        packet.get("schema") != "agent-decision-packet/v1"
        or packet.get("approval_destination") != "node 5 test and acceptance planning"
        or "does not execute deployment" not in str(packet.get("scope_boundary"))
        or "does not execute deployment" not in decided["next_action"]
        or "DECISION REQUIRED" not in submitted
        or "advance to node 5" not in submitted
    ):
        raise AssertionError("submit-gate did not publish a readable bounded decision packet")
    run(
        root, "workflowctl", "return-node", "--from-node", "4", "--to", "3",
        "--issue-id", "archived-repeat", "--cause-category", "tests",
        "--subtask", "archived-count", "--root-cause", "same archived root cause",
        "--change", "request human decision",
    )
    repeated = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if repeated.get("status") != "waiting_human" or "three times" not in repeated.get("next_action", ""):
        raise AssertionError("archived failure count did not preserve the third-failure human gate")
    if repeated.get("accepted_nodes") != list(range(int(repeated["current_node"]))):
        raise AssertionError("third-failure waiting_human state is not a valid node prefix")
    state_probe = subprocess.run(
        [sys.executable, "-c", (
            "import json,sys;sys.path.insert(0,'.agent/scripts');import workflowctl;"
            "t=json.load(open('.agent/state/TASK.json'));"
            "e=workflowctl.state_machine_errors(t);print('\\n'.join(e));raise SystemExit(bool(e))"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if state_probe.returncode:
        raise AssertionError(f"third-failure state machine is invalid:\n{state_probe.stdout}")

with tempfile.TemporaryDirectory(prefix="fast-route-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in ("agentctl.py", "adaptive_common.py", "schema_validation.py", "skillctl.py", "contextctl.py", "contexttx.py", "templatectl.py", "humandecision.py", "process_observation.py", "testrun.py", "workflowctl.py"):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    copy_policy_runtime(root, scripts)
    shutil.copytree(SOURCE / "assets", root / ".agent/assets")
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    install_provider_reverify(root)
    contract = "# Requirement Contract\n\n- Human decisions: user:fixture\n- Clarified: true\n"
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    digest = hashlib.sha256(contract.encode()).hexdigest()
    fast = {
        "schema": "agent-task/v2", "title": "fast route", "task_type": "maintenance", "complexity": "tiny",
        "mode": "fast", "files": 1, "environment": "local", "deployment_requested": False,
        "branch": "unversioned", "status": "in_progress", "phase": "planning",
        "requirements_clarified": True, "requirement_source": "user:fixture",
        "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md", "requirement_contract_sha256": digest,
        "decision_policy_version": 1,
        "task_generation_id": "fixture-task-generation",
        "token_budget": 16000, "tokens_used": 0, "token_usage_source": "estimated", "usage_receipts": [],
        "budget_state": "ok", "child_agents_used": 0, "peak_child_agents": 0,
        "loaded_references": [], "selected_templates": ["requirement-contract"], "selected_capabilities": ["core"],
        "template_route": None, "rendered_artifacts": [], "decisions": [], "open_questions": [],
        "next_action": "route fast templates", "current_node": 2, "accepted_nodes": [0, 1],
        "node_artifacts": {}, "gate_approvals": {"requirement": provider_approval("user:fixture", digest)}, "pending_gate_artifacts": {},
        "rollback_ledger": [], "rollback_archive": None,
        "failure_ledger": {}, "failure_archive": None, "mode_status": "confirmed", "metrics": {},
    }
    write(state / "TASK.json", fast)
    run(root, "contextctl", "sync", "--reason", "fast", "--summary", "fast route fixture", "--source-tokens", "1400")
    run(root, "templatectl", "route")
    routed = json.loads((state / "TASK.json").read_text(encoding="utf-8"))["selected_templates"]
    expected = [
        "requirement-contract", "fast-projection", "node-implementation",
        "targeted-acceptance", "retrospective",
    ]
    if routed != expected or any(item in routed for item in ("task-plan", "acceptance-matrix", "node-acceptance")):
        raise AssertionError(f"fast route is still heavy or dependency-invalid: {routed}")

ESCALATION_RISKS = {key: False for key in (
    "deploy", "data_risk", "cross_system", "uncertain", "security",
    "compliance", "migration", "irreversible", "external_impact",
)}


def escalation_task(contract_sha: str) -> dict:
    return {
        "schema": "agent-task/v2", "title": "escalation fixture", "task_type": "maintenance",
        "complexity": "tiny", "mode": "fast", "files": 1, "environment": "local",
        "deployment_requested": False, "branch": "unversioned", "status": "in_progress",
        "phase": "planning", "requirements_clarified": True, "requirement_source": "user:fixture",
        "requirement_contract": ".agent/state/REQUIREMENT_CONTRACT.md",
        "requirement_contract_sha256": contract_sha, "primary_skill": "run-ai-coding-pipeline",
        "risk_flags": dict(ESCALATION_RISKS), "decision_policy_version": 1,
        "token_budget": 16000, "tokens_used": 0, "token_usage_source": "estimated",
        "usage_receipts": [], "budget_state": "ok", "child_agents_used": 0,
        "peak_child_agents": 0, "loaded_references": [],
        "selected_templates": ["requirement-contract"], "selected_capabilities": ["core"],
        "template_route": None, "rendered_artifacts": [], "decisions": [], "open_questions": [],
        "next_action": "route templates", "current_node": 2, "accepted_nodes": [0, 1],
        "node_artifacts": {}, "gate_approvals": {}, "pending_gate_artifacts": {},
        "rollback_ledger": [], "rollback_archive": None,
        "failure_ledger": {}, "failure_archive": None, "mode_status": "confirmed",
        "projection": "lightweight", "metrics": {}, "updated": "2026-07-30",
    }


with tempfile.TemporaryDirectory(prefix="escalate-policy-flip-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    # testrun.py is imported by agentledger, which the ledger-chain seeding uses.
    for name in ("agentctl.py", "contextctl.py", "contexttx.py", "humandecision.py", "process_observation.py", "testrun.py"):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    copy_policy_runtime(root, scripts)
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    escalation_config=json.loads((root/".agent/config.json").read_text(encoding="utf-8"))
    escalation_config["agent_control"]["human_decision_observer"]["allow_current_chat_local_release"]=False
    write(root/".agent/config.json",escalation_config)
    shutil.copy2(SOURCE / "assets/fresh-state/v1/state/agents.json", state / "agents.json")
    shutil.copytree(SOURCE / "skills/manage-agent-team", root / ".agent/skills/manage-agent-team")
    # Seed a chain-upgraded ledger through agentledger's own save: escalation
    # must advance the same append hash chain, never strand its tip.
    chain_seed = subprocess.run(
        [sys.executable, "-c", (
            "import sys;sys.path.insert(0,'.agent/scripts');"
            "sys.path.insert(0,'.agent/skills/manage-agent-team/scripts');"
            "import agentledger;"
            "agentledger.save(agentledger.load(agentledger.STATE));"
            "print('LEDGER CHAIN SEEDED')"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if chain_seed.returncode or "LEDGER CHAIN SEEDED" not in chain_seed.stdout:
        raise AssertionError(f"could not seed a chain-upgraded ledger:\n{chain_seed.stdout}")
    contract = "# Requirement Contract\n\n- Human decisions: user:fixture\n- Clarified: true\n"
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    contract_sha = hashlib.sha256(contract.encode()).hexdigest()
    write(state / "TASK.json", escalation_task(contract_sha))
    # Bind the requirement approval to the current routing profile via the real helper.
    bind = subprocess.run(
        [sys.executable, "-c", (
            "import json;"
            "p='.agent/state/TASK.json';t=json.load(open(p));"
            "t['gate_approvals']={'requirement':{'source':'user:fixture',"
            "'artifact_sha256':t['requirement_contract_sha256'],'decision_receipt':"
            "{'authority':'provider-signed-user-message','decision_id':'fixture-old'}}};"
            "json.dump(t,open(p,'w'),ensure_ascii=False,indent=2)"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if bind.returncode:
        raise AssertionError(f"could not bind the prior provider approval fixture:\n{bind.stdout}")
    run(root, "contextctl", "sync", "--reason", "fixture", "--summary", "escalation fixture", "--source-tokens", "1200")

    # A routing-profile-changing escalation must refuse to strand the old approval.
    before_task = (state / "TASK.json").read_bytes()
    refusal = run(root, "agentctl", "escalate-mode", "--new-mode", "standard", expected=1)
    if "would invalidate the current requirement approval" not in refusal or "--reapprove --source user:<decision>" not in refusal:
        raise AssertionError(f"profile-changing escalation refused for the wrong reason:\n{refusal}")
    if (state / "TASK.json").read_bytes() != before_task:
        raise AssertionError("a refused escalation mutated TASK")
    misuse = run(root, "agentctl", "escalate-mode", "--new-mode", "standard", "--source", "user:fixture", expected=1)
    if "valid only with --reapprove" not in misuse:
        raise AssertionError(f"--source without --reapprove failed for the wrong reason:\n{misuse}")

    before_reapprove = (state / "TASK.json").read_bytes()
    missing_receipt = run(
        root, "agentctl", "escalate-mode", "--new-mode", "standard", "--reapprove",
        "--source", "user:escalated", expected=1,
    )
    if "provider-signed human decision receipt" not in missing_receipt:
        raise AssertionError(f"escalation reapproval failed for the wrong reason:\n{missing_receipt}")
    if (state / "TASK.json").read_bytes() != before_reapprove:
        raise AssertionError("failed escalation reapproval mutated TASK")


with tempfile.TemporaryDirectory(prefix="task-archive-v2-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in (
        "agentctl.py", "contextctl.py", "contexttx.py",
        "humandecision.py", "process_observation.py", "testrun.py", "deliveryctl.py", "evidencectl.py",
    ):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    shutil.copytree(SOURCE / "scripts/workflowlib", scripts / "workflowlib")
    shutil.copytree(SOURCE / "skills", root / ".agent/skills")
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    shutil.copy2(SOURCE / ".workflow-manifest.json", root / ".agent/.workflow-manifest.json")
    (state / "evidence").mkdir()
    (state / "evidence/referenced-note.txt").write_text("referenced evidence bytes\n", encoding="utf-8")
    (state / "evidence/unreferenced-note.txt").write_text("unreferenced evidence bytes\n", encoding="utf-8")
    contract = "# Requirement Contract\n\n- Human decisions: user:fixture\n- Clarified: true\n"
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    (state / "delivery.json").write_text('{"schema":"agent-delivery/v3","epochs":[]}\n', encoding="utf-8")
    seed_task=json.loads((SOURCE/"assets/fresh-state/v1/state/TASK.json").read_text(encoding="utf-8"))
    shutil.copy2(SOURCE/"assets/fresh-state/v1/state/SKILL_ACTIVATION.json",state/"SKILL_ACTIVATION.json")
    (state/"SKILL_ACTIVATION.json").chmod(0o600)
    write(state / "TASK.json", {
        "schema": "agent-task/v2",
        "title": "archive fixture referencing .agent/state/evidence/referenced-note.txt",
        "task_archive": None, "status": "accepted",
        "task_generation_id":seed_task["task_generation_id"],"skill_activation":seed_task["skill_activation"],
    })
    archive_probe = subprocess.run(
        [sys.executable, "-c", (
            "import hashlib,json,sys;sys.path.insert(0,'.agent/scripts');"
            "import agentctl,evidencectl;"
            "state=agentctl.AGENT_DIR/'state';"
            "task_bytes=(state/'TASK.json').read_bytes();"
            "contract_bytes=(state/'REQUIREMENT_CONTRACT.md').read_bytes();"
            "delivery_bytes=(state/'delivery.json').read_bytes();"
            "ref=hashlib.sha256((state/'evidence/referenced-note.txt').read_bytes()).hexdigest();"
            "unref=hashlib.sha256((state/'evidence/unreferenced-note.txt').read_bytes()).hexdigest();"
            "previous=json.loads(task_bytes);"
            "head1,path1,data1=agentctl.build_task_archive(previous,source='user:fixture',reason='first',decision_receipt=None,assurance='test');"
            "path1.parent.mkdir(parents=True,exist_ok=True);path1.write_bytes(data1);"
            "p1=json.loads(data1);"
            "assert p1['schema']=='agent-task-archive/v2',p1['schema'];"
            "assert p1['task']=={'sha256':hashlib.sha256(task_bytes).hexdigest(),'bytes':len(task_bytes),'utf8':task_bytes.decode('utf-8')},'task bytes not embedded exactly';"
            "assert p1['requirement_contract']=={'sha256':hashlib.sha256(contract_bytes).hexdigest(),'bytes':len(contract_bytes),'utf8':contract_bytes.decode('utf-8')},'contract bytes not embedded exactly';"
            "assert p1['delivery']=={'sha256':hashlib.sha256(delivery_bytes).hexdigest(),'bytes':len(delivery_bytes),'utf8':delivery_bytes.decode('utf-8')},'delivery bytes not embedded exactly';"
            "assert p1['referenced_evidence']==[ref],p1['referenced_evidence'];"
            "assert unref not in p1['referenced_evidence'];"
            "assert p1['previous'] is None;"
            "assert data1==json.dumps(p1,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()+b'\\n','payload bytes are not canonical';"
            "assert head1=={'schema':'agent-task-archive-head/v1','path':str(path1.relative_to(agentctl.AGENT_DIR.parent)),'sha256':hashlib.sha256(data1).hexdigest(),'bytes':len(data1),'total_archives':1},head1;"
            "head2,path2,data2=agentctl.build_task_archive({**previous,'task_archive':head1},source='user:fixture',reason='second',decision_receipt=None,assurance='test');"
            "path2.write_bytes(data2);p2=json.loads(data2);"
            "assert p2['previous']==head1 and head2['total_archives']==2,'chain head not anchored';"
            "chain=evidencectl.task_archive_chain(head2);"
            "assert len(chain)==2 and all(item[1]['schema']=='agent-task-archive/v2' for item in chain),'evidencectl rejected the v2 chain';"
            "(state/'REQUIREMENT_CONTRACT.md').unlink();"
            "head3,path3,data3=agentctl.build_task_archive({**previous,'task_archive':head2},source='s',reason='r',decision_receipt=None,assurance='a');"
            "assert json.loads(data3)['requirement_contract'] is None,'missing contract must archive as null';"
            "print('TASK ARCHIVE V2 PROBE OK')"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if archive_probe.returncode or "TASK ARCHIVE V2 PROBE OK" not in archive_probe.stdout:
        raise AssertionError(f"task-archive v2 writer contract violated:\n{archive_probe.stdout}")

with tempfile.TemporaryDirectory(prefix="evidence-capsule-transition-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in ("contextctl.py", "contexttx.py", "humandecision.py", "process_observation.py", "evidencectl.py"):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    copy_policy_runtime(root, scripts)
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    install_provider_reverify(root)
    shutil.copy2(SOURCE / "assets/fresh-state/v1/state/agents.json", state / "agents.json")
    shutil.copy2(SOURCE / "assets/fresh-state/v1/state/EVIDENCE_INDEX.json", state / "EVIDENCE_INDEX.json")
    (state / "evidence/task-archives").mkdir(parents=True)
    contract = "# Requirement Contract\n\n- Human decisions: user:fixture\n- Clarified: true\n"
    (state / "REQUIREMENT_CONTRACT.md").write_text(contract, encoding="utf-8")
    contract_sha = hashlib.sha256(contract.encode()).hexdigest()

    def write_chain_archive(payload: dict, total: int) -> dict:
        data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        value_sha = hashlib.sha256(data).hexdigest()
        path = state / "evidence/task-archives" / f"{value_sha}.json"
        path.write_bytes(data)
        return {
            "schema": "agent-task-archive-head/v1", "path": str(path.relative_to(root)),
            "sha256": value_sha, "bytes": len(data), "total_archives": total,
        }

    def legacy_payload(utf8: str, previous: object) -> dict:
        return {
            "schema": "agent-task-archive/v1", "archived_at": "2026-01-01T00:00:00+00:00",
            "source": "workflow:accepted", "reason": "self-test", "assurance": "self-test",
            "decision_receipt": None,
            "task": {"sha256": "0" * 64, "bytes": len(utf8.encode()), "utf8": utf8},
            "requirement_contract": None, "previous": previous,
        }

    head1 = write_chain_archive(legacy_payload("archived task one", None), 1)
    head2 = write_chain_archive(legacy_payload("archived task two", head1), 2)
    capsule_task = escalation_task(contract_sha)
    capsule_task["task_archive"] = head2
    write(state / "TASK.json", capsule_task)
    run(root, "contextctl", "sync", "--reason", "fixture", "--summary", "capsule fixture", "--source-tokens", "1200")

    # migrate-task-archives moves the capsule-bound TASK head through the
    # canonical transition: the capsule must still verify afterwards.
    migrated = run(root, "evidencectl", "migrate-task-archives")
    if "TASK ARCHIVE MIGRATED" not in migrated:
        raise AssertionError(f"migration did not run in the capsule fixture:\n{migrated}")
    new_head = json.loads((state / "TASK.json").read_text(encoding="utf-8"))["task_archive"]
    if not isinstance(new_head, dict) or new_head["sha256"] == head2["sha256"]:
        raise AssertionError("migration did not re-anchor the TASK head to the rewritten chain")
    run(root, "contextctl", "check")

    # compact --include-task-history drops the dangling head through the same
    # canonical transition, but only with a provider-verifiable decision.
    history_receipt = state / "test-task-history-receipt.json"
    write(history_receipt, {"test_provider_receipt": True})
    compacted = run(
        root, "evidencectl", "compact", "--include-task-history",
        "--source", "user:fixture-history", "--force", "--min-age-hours", "0",
        "--human-decision-receipt", str(history_receipt.relative_to(root)),
    )
    if "EVIDENCE COMPACTED" not in compacted:
        raise AssertionError(f"task-history compaction did not run in the capsule fixture:\n{compacted}")
    if json.loads((state / "TASK.json").read_text(encoding="utf-8")).get("task_archive") is not None:
        raise AssertionError("task-history compaction did not clear the dangling TASK head")
    # The decision record must retain the immutable provider receipt identity;
    # local/current-chat text is never emitted as compaction authority.
    decision_line = next(
        (line for line in compacted.splitlines() if line.startswith("TASK HISTORY DECISION: ")), None,
    )
    if decision_line is None:
        raise AssertionError(f"task-history compaction did not record a provider decision:\n{compacted}")
    decision = json.loads(decision_line.split(": ", 1)[1])
    receipt_bytes = history_receipt.read_bytes()
    if (
        set(decision) != {
            "schema", "path", "sha256", "bytes", "decision_id", "authority",
            "adapter_path", "adapter_sha256",
        }
        or decision.get("authority") != "provider-signed-user-message"
        or decision.get("sha256") != hashlib.sha256(receipt_bytes).hexdigest()
        or decision.get("bytes") != len(receipt_bytes)
        or root / str(decision.get("path")) != history_receipt
    ):
        raise AssertionError(f"task-history decision did not preserve provider receipt identity: {decision}")
    run(root, "contextctl", "check")

with tempfile.TemporaryDirectory(prefix="cleanup-leases-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in ("agentctl.py", "contextctl.py", "contexttx.py", "humandecision.py", "process_observation.py", "testrun.py", "evidencectl.py"):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    shutil.copytree(SOURCE / "scripts/workflowlib", scripts / "workflowlib")
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    shutil.copy2(SOURCE / "assets/fresh-state/v1/state/agents.json", state / "agents.json")
    shutil.copy2(SOURCE / "assets/fresh-state/v1/state/EVIDENCE_INDEX.json", state / "EVIDENCE_INDEX.json")
    write(state / "runtime.json", {
        "schema": "agent-runtime/v2",
        "baseline": {"source": "user:fixture", "captured_at": "2026-07-30T00:00:00+00:00", "project_processes": []},
        "processes": [], "docker_projects": [], "ports": [],
    })
    now = dt.datetime.now(dt.timezone.utc)
    past = (now - dt.timedelta(minutes=10)).replace(microsecond=0).isoformat()
    auth_dir = state / ".context-authorizations"
    auth_dir.mkdir()
    write(auth_dir / "stale.json", {"issued_at": past})
    write(auth_dir / "fresh.json", {"issued_at": now.replace(microsecond=0).isoformat()})
    write(state / "tool-leases.json", {
        "schema": "agent-tool-leases/v1",
        "leases": [{
            "id": "malformed", "owner_agent_id": "nobody", "name": "malformed",
            "started_at": past, "deadline_at": past, "supervisor": None,
            "process": "not-a-dict", "command": ["true"],
            "policy": "bounded-platform-review-tool/v1",
        }],
    })
    # A lease without a dict process record is retained and reported, never dropped.
    failed = run(root, "agentctl", "cleanup", expected=1)
    if "malformed-process-record" not in failed or "CLEANUP FAILED" not in failed:
        raise AssertionError(f"cleanup did not report the malformed tool lease:\n{failed}")
    retained = json.loads((state / "tool-leases.json").read_text(encoding="utf-8"))["leases"]
    if len(retained) != 1 or retained[0].get("id") != "malformed":
        raise AssertionError(f"cleanup silently dropped the malformed tool lease: {retained}")
    # Stranded context authorizations past their validity window are swept; fresh stay.
    if "swept 1 stranded context authorization(s)" not in failed:
        raise AssertionError(f"cleanup did not report the stranded authorization sweep:\n{failed}")
    if (auth_dir / "stale.json").exists() or not (auth_dir / "fresh.json").is_file():
        raise AssertionError("context authorization sweep removed the wrong records")
    write(state / "tool-leases.json", {"schema": "agent-tool-leases/v1", "leases": []})
    passed = run(root, "agentctl", "cleanup")
    if "CLEANUP PASSED" not in passed or "deep verification skipped" in passed:
        raise AssertionError(f"cleanup did not pass with a wired deep evidence verification:\n{passed}")

    # Supervisor liveness is part of lease retention: a live, fresh, owned lease
    # survives; the same lease with a dead supervisor is reaped exactly.
    lease_probe_script = root / "lease_probe.py"
    lease_probe_script.write_text(
        """import datetime as dt
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, ".agent/scripts")
import agentctl

now = dt.datetime.now(dt.timezone.utc)
future = (now + dt.timedelta(minutes=10)).replace(microsecond=0).isoformat()
started = now.replace(microsecond=0).isoformat()
kept = subprocess.Popen(["sleep", "30"], start_new_session=True)
reaped = subprocess.Popen(["sleep", "30"], start_new_session=True)


def lease(lease_id, process):
    snap = None
    for _ in range(50):
        snap = agentctl.process_snapshot(process.pid)
        if snap is not None:
            break
        if process.poll() is not None:
            break
        time.sleep(0.02)
    assert snap is not None, f"could not snapshot leased process {process.pid}"
    record = {key: snap[key] for key in ("pid", "pgid", "start_time", "command", "cwd")}
    record.update({"name": lease_id, "kind": "foreground-tool", "scope": "isolated_process_group"})
    supervisor = agentctl.process_snapshot(os.getpid()) if lease_id == "kept" else {
        "pid": 999999, "pgid": 999999, "start_time": 1,
        "command": "dead-supervisor", "cwd": record["cwd"],
    }
    return {
        "id": lease_id, "owner_agent_id": "owner", "name": lease_id,
        "started_at": started, "deadline_at": future,
        "supervisor": supervisor, "supervisor_chain": [],
        "process": record, "command": ["sleep", "30"],
        "policy": "bounded-platform-review-tool/v1",
    }


try:
    agentctl.TOOL_LEASES_PATH.write_text(json.dumps({
        "schema": "agent-tool-leases/v1",
        "leases": [lease("kept", kept), lease("reaped", reaped)],
    }, indent=2) + "\\n", encoding="utf-8")
    # The owner check is exercised elsewhere; here every lease is owner-active so
    # only supervisor/group/deadline liveness decides retention.
    agentctl.active_review_agent_member = lambda agent_id: {"id": agent_id}
    failures = agentctl.cleanup_tool_leases(5)
    remaining = [item["id"] for item in json.loads(agentctl.TOOL_LEASES_PATH.read_text())["leases"]]
    assert failures == [], failures
    assert remaining == ["kept"], remaining
    assert not agentctl.process_group_alive(reaped.pid), "dead-supervisor lease group survived"
    assert agentctl.process_group_alive(kept.pid), "live-supervisor lease group was killed"
    print("LEASE SUPERVISOR PROBE OK")
finally:
    for process in (kept, reaped):
        try:
            process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
""",
        encoding="utf-8",
    )
    lease_probe = subprocess.run(
        [sys.executable, str(lease_probe_script)], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if lease_probe.returncode or "LEASE SUPERVISOR PROBE OK" not in lease_probe.stdout:
        raise AssertionError(f"tool-lease supervisor reaping is broken:\n{lease_probe.stdout}")

    # Docker residuals include named volumes: declared volumes force `down -v`
    # and leftover named volumes fail assert-clean.
    fakebin = root / "fakebin"
    fakebin.mkdir()
    docker_log = root / "docker.log"
    (fakebin / "docker").write_text(
        "#!/bin/bash\n"
        f"echo \"$*\" >> {docker_log}\n"
        "if [ \"$1\" = \"volume\" ] && [ \"$FAKE_DOCKER_VOLUME_RESIDUAL\" = \"1\" ]; then\n"
        "  echo leftover-volume\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    (fakebin / "docker").chmod(0o755)
    (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    run(
        root, "agentctl", "register-docker", "--project", "agent_fixture1",
        "--workdir", ".", "--file", "compose.yaml", "--volume", "datavol",
    )
    # Single-character volume names are valid Docker names and must register.
    run(
        root, "agentctl", "register-docker", "--project", "agent_fixture9",
        "--workdir", ".", "--file", "compose.yaml", "--volume", "a",
    )
    original_path = os.environ["PATH"]
    os.environ["PATH"] = f"{fakebin}:{original_path}"
    try:
        run(root, "agentctl", "cleanup")
        log_lines = docker_log.read_text(encoding="utf-8").splitlines()
        if not any("compose" in line and "-p agent_fixture1 down --remove-orphans -v" in line for line in log_lines):
            raise AssertionError(f"declared volumes did not force compose down -v:\n{log_lines}")
        if not any(line.startswith("volume ls") for line in log_lines):
            raise AssertionError(f"docker residual check does not count named volumes:\n{log_lines}")
        run(
            root, "agentctl", "register-docker", "--project", "agent_fixture1",
            "--workdir", ".", "--file", "compose.yaml", "--volume", "datavol",
        )
        os.environ["FAKE_DOCKER_VOLUME_RESIDUAL"] = "1"
        residual = run(root, "agentctl", "assert-clean", expected=1)
        if "agent_fixture1" not in residual or "volume" not in residual:
            raise AssertionError(f"assert-clean ignored a leftover named volume:\n{residual}")
        del os.environ["FAKE_DOCKER_VOLUME_RESIDUAL"]
        run(root, "agentctl", "cleanup")
    finally:
        os.environ["PATH"] = original_path
        os.environ.pop("FAKE_DOCKER_VOLUME_RESIDUAL", None)

    # Capturing a baseline over pre-existing unregistered processes requires an
    # explicit confirmation flag so leaks cannot become invisible.
    sleeper = subprocess.Popen(["sleep", "30"], cwd=root)
    try:
        baseline_refusal = run(
            root, "agentctl", "capture-runtime-baseline", "--source", "user:fixture", expected=1,
        )
        if "unregistered project processes already exist" not in baseline_refusal or "--confirm-existing-processes" not in baseline_refusal:
            raise AssertionError(f"baseline capture absorbed a pre-existing process:\n{baseline_refusal}")
        confirmed = run(
            root, "agentctl", "capture-runtime-baseline",
            "--source", "user:fixture", "--confirm-existing-processes",
        )
        if "RUNTIME BASELINE WARNING" not in confirmed:
            raise AssertionError(f"confirmed baseline capture did not warn:\n{confirmed}")
    finally:
        sleeper.kill()
        sleeper.wait()


with tempfile.TemporaryDirectory(prefix="knowledge-loop-") as raw:
    root = Path(raw); scripts = root / ".agent/scripts"; state = root / ".agent/state"
    scripts.mkdir(parents=True); state.mkdir(parents=True)
    for name in ("agentctl.py", "contextctl.py", "contexttx.py", "humandecision.py", "process_observation.py", "testrun.py"):
        shutil.copy2(SOURCE / "scripts" / name, scripts / name)
    shutil.copytree(SOURCE / "scripts/workflowlib", scripts / "workflowlib")
    shutil.copy2(SOURCE / "config.json", root / ".agent/config.json")
    write(state / "knowledge-pending.json", {
        "schema":"agent-knowledge-pending/v2",
        "candidates":[{"schema":"agent-knowledge-candidate/v1","candidate_id":"a"*64,
          "task_generation_id":"fixture-generation","completion_binding_sha256":"b"*64,
          "rule":"pin exact dependencies","observation":"unbounded resolution drifted",
          "evidence_sha256":["c"*64],"reuse_scope":"dependency resolution",
          "counterexample":"local path dependency","expires_at":"2099-01-01T00:00:00+00:00","owner_id":"dependency-policy"}],
        "promotions":[],
    })
    probe=subprocess.run([sys.executable,"-c",(
        "import sys;sys.path.insert(0,'.agent/scripts');import agentctl;"
        "p=agentctl.load_knowledge_pending();assert p['schema']=='agent-knowledge-pending/v2';"
        "assert 'evidence-bound knowledge candidate(s)' in agentctl.knowledge_pending_notice();"
        "print('STRUCTURED KNOWLEDGE PENDING OK')")],cwd=root,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if probe.returncode or "STRUCTURED KNOWLEDGE PENDING OK" not in probe.stdout:
        raise AssertionError(f"structured knowledge pending registry is broken:\n{probe.stdout}")
    bad_source=run(root,"agentctl","promote-knowledge","a"*64,"--source","bogus",expected=1)
    if "user:" not in bad_source: raise AssertionError(f"promotion without a human source failed incorrectly:\n{bad_source}")



with tempfile.TemporaryDirectory(prefix="bootstrap-adapters-") as raw:
    root = Path(raw)
    shutil.copytree(SOURCE, root / ".agent", symlinks=True)
    seed = root / ".agent/assets/fresh-state/v1"
    shutil.rmtree(root / ".agent/state")
    shutil.rmtree(root / ".agent/policies")
    shutil.copytree(seed / "state", root / ".agent/state")
    shutil.copytree(seed / "policies", root / ".agent/policies")
    shutil.copy2(seed / "config.json", root / ".agent/config.json")
    install_provider_reverify(root)
    config = json.loads((root / ".agent/config.json").read_text(encoding="utf-8"))
    config["acceptance_adapters"] = {
        "acceptance-web-docker": {"implemented": True, "runner": ".agent/scripts/missing-docker-runner.py"},
        "acceptance-ios": {"implemented": True, "runner": ".agent/scripts/missing-ios-runner.py"},
        "acceptance-cli": {"implemented": False, "runner": ".agent/scripts/missing-cli-runner.py"},
    }
    write(root / ".agent/config.json", config)
    # Editing config is policy-bundle drift under the bound capsule; re-bind the
    # seeded checkpoint through the fail-closed provider-approved repair path.
    run(root, "contextctl", "repair", "--reason", "fixture config", "--summary", "fixture config", "--source-tokens", "800", expected=1)
    repair_receipt = root / ".agent/state/test-context-repair-receipt.json"
    write(repair_receipt, {"test_provider_receipt": True})
    run(
        root, "contextctl", "approve-repair", "--source", "user:fixture",
        "--human-decision-receipt", str(repair_receipt.relative_to(root)),
    )
    # Guardrails stay uninitialized in the seed: warnings are non-fatal and the
    # check still reports its usual next-step exit.
    output = run(root, "agentctl", "bootstrap-check", expected=2)
    if "acceptance-web-docker declares implemented=true but its runner is missing" not in output:
        raise AssertionError(f"bootstrap-check did not probe the declared docker runner:\n{output}")
    if "acceptance-ios declares implemented=true but its runner is missing" not in output:
        raise AssertionError(f"bootstrap-check did not probe the declared ios runner:\n{output}")
    if "missing-cli-runner" in output:
        raise AssertionError(f"bootstrap-check probed an adapter not declared implemented:\n{output}")
    if shutil.which("docker") is None and "docker is not on PATH" not in output:
        raise AssertionError(f"bootstrap-check missed the absent docker host prerequisite:\n{output}")
    if shutil.which("xcodebuild") is None and "xcodebuild is not on PATH" not in output:
        raise AssertionError(f"bootstrap-check missed the absent xcodebuild host prerequisite:\n{output}")

with tempfile.TemporaryDirectory(prefix="start-node0-") as raw:
    root = Path(raw)
    shutil.copytree(SOURCE, root / ".agent", symlinks=True)
    seed = root / ".agent/assets/fresh-state/v1"
    shutil.rmtree(root / ".agent/state")
    shutil.rmtree(root / ".agent/policies")
    shutil.copytree(seed / "state", root / ".agent/state")
    shutil.copytree(seed / "policies", root / ".agent/policies")
    shutil.copy2(seed / "config.json", root / ".agent/config.json")
    state = root / ".agent/state"
    install_provider_reverify(root); write(state/"archive-receipt.json",{"test_provider_receipt":True})
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "checkout", "-q", "-b", "fix/node0-fixture"], cwd=root, check=True)
    # Idle initialized state remains neutral, but active work requires an explicit host selection.
    missing_model = run(root, "agentctl", "start", "--title", "model selection fixture", expected=2)
    if "--model" not in missing_model:
        raise AssertionError(f"start without a selected model failed for the wrong reason:\n{missing_model}")
    if json.loads((state / "TASK.json").read_text(encoding="utf-8")).get("status") != "idle":
        raise AssertionError("a model-less refused start mutated the idle TASK")
    selected = run(root, "agentctl", "select-model", "--model", "provider-neutral/model-v1",expected=1)
    if "pass --model <model-id> to each task start" not in selected:
        raise AssertionError(f"idle model persistence failed for the wrong reason:\n{selected}")
    selected_config=json.loads((root/".agent/config.json").read_text(encoding="utf-8")); selected_agents=json.loads((state/"agents.json").read_text(encoding="utf-8"))
    if selected_config["agent_control"].get("default_model") is not None or selected_agents.get("default_model") is not None:
        raise AssertionError("idle model authorities did not remain null")

    start_guardrails=root/"project-guardrails.md"
    start_guardrails.write_text("# Project Guardrails\n\n## Required project facts\n\n"
        "- Product and users: Disposable node-zero fixture.\n"
        "- Technology and architecture: Python workflow controls and JSON state.\n"
        "- Writable and read-only areas: The fixture is writable; external paths are read-only.\n"
        "- Security, privacy, compliance and performance red lines: No credentials or external effects.\n"
        "- Build, test and lint commands: Run the control-gate self-test.\n"
        "- Deployment authority and rollback owner: No deployment; the fixture owner rolls back.\n",encoding="utf-8")
    run(root,"agentctl","project-init","--guardrails-file",start_guardrails.name)

    # Seed a chain-upgraded ledger through agentledger's own save: every start
    # rewrites agents.json and must advance the same append hash chain.
    chain_seed = subprocess.run(
        [sys.executable, "-c", (
            "import sys;sys.path.insert(0,'.agent/scripts');"
            "sys.path.insert(0,'.agent/skills/manage-agent-team/scripts');"
            "import agentledger;"
            "agentledger.save(agentledger.load(agentledger.STATE));"
            "print('LEDGER CHAIN SEEDED')"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if chain_seed.returncode or "LEDGER CHAIN SEEDED" not in chain_seed.stdout:
        raise AssertionError(f"could not seed a chain-upgraded ledger:\n{chain_seed.stdout}")

    def assert_ledger_chain(expected_revision: int) -> None:
        ledger = json.loads((state / "agents.json").read_text(encoding="utf-8"))
        if ledger.get("revision") != expected_revision:
            raise AssertionError(f"start did not advance the ledger chain to revision {expected_revision}: {ledger.get('revision')}")
        probe = subprocess.run(
            [sys.executable, "-c", (
                "import sys;sys.path.insert(0,'.agent/scripts');"
                "sys.path.insert(0,'.agent/skills/manage-agent-team/scripts');"
                "import agentledger;"
                "errors=agentledger.ledger_chain_errors(agentledger.load(agentledger.STATE));"
                "assert not errors,errors;"
                "print('LEDGER CHAIN OK')"
            )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        if probe.returncode or "LEDGER CHAIN OK" not in probe.stdout:
            raise AssertionError(f"start stranded the agent ledger append chain:\n{probe.stdout}")

    # Node 0's minimal contract refuses a task without a usable title after a valid model selection.
    refusal = run(
        root, "agentctl", "start", "--model", "provider-neutral/model-v1", "--title", "", "--mode", "fast", "--environment", "local",
        "--task-type", "maintenance", "--complexity", "tiny", "--files", "1", expected=1,
    )
    if "node 0 minimal contract failed" not in refusal:
        raise AssertionError(f"start without the node-0 contract failed for the wrong reason:\n{refusal}")
    if json.loads((state / "TASK.json").read_text(encoding="utf-8")).get("status") != "idle":
        raise AssertionError("a refused start mutated the idle TASK")
    # A pending knowledge registry is surfaced at every start.
    (state / "evidence").mkdir()
    (state / "evidence/fixture-note.txt").write_text("archive reachability fixture\n", encoding="utf-8")
    write(state / "knowledge-pending.json", {
        "schema": "agent-knowledge-pending/v2",
        "candidates": [{"candidate_id": "f"*64, "task_generation_id":"older", "status":"pending"}],
        "promotions": [],
    })
    started = run(
        root, "agentctl", "start", "--model", "provider-neutral/model-v1",
        "--title", "first fixture uses .agent/state/evidence/fixture-note.txt",
        "--mode", "fast", "--environment", "local", "--task-type", "maintenance",
        "--complexity", "tiny", "--files", "1",
    )
    if "STARTED fast task in clarification" not in started:
        raise AssertionError(f"fresh start failed:\n{started}")
    if "KNOWLEDGE PENDING" not in started or "promote-knowledge" not in started:
        raise AssertionError(f"start did not surface the pending knowledge candidates:\n{started}")
    first = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if first.get("projection") != "lightweight" or first.get("decision_policy_version") != 1:
        raise AssertionError(f"start did not persist the routing projection: {first.get('projection')}")
    assert_ledger_chain(2)
    first_task_bytes = (state / "TASK.json").read_bytes()
    first_activation_bytes=(state/"SKILL_ACTIVATION.json").read_bytes()
    first_delivery_bytes = (state / "delivery.json").read_bytes()

    # Replacing an active task archives it as a byte-exact task-archive/v2 payload
    # with the delivery state and digest-bound evidence references embedded.
    rotated = run(
        root, "agentctl", "start", "--model", "provider-neutral/model-v2", "--title", "second fixture",
        "--mode", "fast", "--environment", "local", "--task-type", "governance",
        "--complexity", "tiny", "--files", "1",
        "--archive-active", "--archive-source", "user:rotate", "--archive-reason", "rotate fixture",
        "--archive-human-decision-receipt", ".agent/state/archive-receipt.json",
    )
    if "STARTED fast task in clarification" not in rotated:
        raise AssertionError(f"archiving start failed:\n{rotated}")
    second = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    head = second.get("task_archive", {})
    archive = root / str(head.get("path", ""))
    if (
        head.get("schema") != "agent-task-archive-head/v1"
        or head.get("total_archives") != 1
        or not archive.is_file()
        or hashlib.sha256(archive.read_bytes()).hexdigest() != head.get("sha256")
        or len(archive.read_bytes()) != head.get("bytes")
    ):
        raise AssertionError(f"archiving start did not anchor a verified v2 head: {head}")
    payload = json.loads(archive.read_bytes())
    referenced_sha = hashlib.sha256((state / "evidence/fixture-note.txt").read_bytes()).hexdigest()
    if (
        payload.get("schema") != "agent-task-archive/v2"
        or payload.get("source") != "user:rotate"
        or payload.get("reason") != "rotate fixture"
        or payload.get("previous") is not None
        or payload.get("task", {}).get("utf8") != first_task_bytes.decode("utf-8")
        or payload.get("task", {}).get("sha256") != hashlib.sha256(first_task_bytes).hexdigest()
        or payload.get("skill_activation",{}).get("utf8")!=first_activation_bytes.decode("utf-8")
        or payload.get("skill_activation",{}).get("sha256")!=hashlib.sha256(first_activation_bytes).hexdigest()
    ):
        raise AssertionError(f"task archive payload is not the byte-exact v2 contract: {sorted(payload)}")
    delivery = payload.get("delivery")
    if (
        not isinstance(delivery, dict)
        or delivery.get("utf8") != first_delivery_bytes.decode("utf-8")
        or delivery.get("sha256") != hashlib.sha256(first_delivery_bytes).hexdigest()
    ):
        raise AssertionError(f"task archive did not embed the exact delivery bytes: {delivery}")
    if referenced_sha not in payload.get("referenced_evidence", []):
        raise AssertionError(f"task archive lost the referenced evidence digest: {payload.get('referenced_evidence')}")
    if second.get("projection") != "lightweight":
        raise AssertionError(f"archiving start persisted a wrong projection: {second.get('projection')}")
    assert_ledger_chain(3)
    chain_probe = subprocess.run(
        [sys.executable, "-c", (
            "import json,sys;sys.path.insert(0,'.agent/scripts');import evidencectl;"
            "head=json.load(open('.agent/state/TASK.json'))['task_archive'];"
            "chain=evidencectl.task_archive_chain(head);"
            "assert len(chain)==1 and chain[0][1]['schema']=='agent-task-archive/v2';"
            "print('START ARCHIVE CHAIN OK')"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if chain_probe.returncode or "START ARCHIVE CHAIN OK" not in chain_probe.stdout:
        raise AssertionError(f"evidencectl rejected the start-produced v2 archive chain:\n{chain_probe.stdout}")

with tempfile.TemporaryDirectory(prefix="start-defaults-") as raw:
    root = Path(raw)
    shutil.copytree(SOURCE, root / ".agent", symlinks=True)
    seed = root / ".agent/assets/fresh-state/v1"
    shutil.rmtree(root / ".agent/state")
    shutil.rmtree(root / ".agent/policies")
    shutil.copytree(seed / "state", root / ".agent/state")
    shutil.copytree(seed / "policies", root / ".agent/policies")
    shutil.copy2(seed / "config.json", root / ".agent/config.json")
    state = root / ".agent/state"
    install_provider_reverify(root); write(state/"archive-receipt.json",{"test_provider_receipt":True})
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "checkout", "-q", "-b", "fix/defaults-fixture"], cwd=root, check=True)
    defaults_guardrails=root/"project-guardrails.md"
    defaults_guardrails.write_text("# Project Guardrails\n\n## Required project facts\n\n"
        "- Product and users: Disposable start-defaults fixture.\n"
        "- Technology and architecture: Python workflow controls and JSON state.\n"
        "- Writable and read-only areas: The fixture is writable; external paths are read-only.\n"
        "- Security, privacy, compliance and performance red lines: No credentials or external effects.\n"
        "- Build, test and lint commands: Run the control-gate self-test.\n"
        "- Deployment authority and rollback owner: No deployment; the fixture owner rolls back.\n",encoding="utf-8")
    run(root,"agentctl","project-init","--guardrails-file",defaults_guardrails.name)
    # A bare start declares nothing: the minimal defaults must route it to fast,
    # leaving the node-6 scope gate as the post-hoc corrector for under-declaration.
    started = run(root, "agentctl", "start", "--model", "provider-neutral/model.fixture", "--title", "bare start defaults fixture")
    if "STARTED fast task in clarification" not in started:
        raise AssertionError(f"bare start did not route to fast:\n{started}")
    task = json.loads((state / "TASK.json").read_text(encoding="utf-8"))
    if (
        task.get("mode") != "fast"
        or task.get("complexity") != "tiny"
        or task.get("files") != 1
        or task.get("decision_policy_version") != 1
    ):
        raise AssertionError(f"bare start persisted wrong routing defaults: {task.get('mode')}/{task.get('complexity')}/{task.get('files')}")
    # Explicit declarations are unchanged: bounded complexity with 3 files still
    # routes to standard on the exact same command surface.
    rotated = run(
        root, "agentctl", "start", "--model", "provider-neutral/model-v2", "--title", "declared standard fixture",
        "--complexity", "bounded", "--files", "3",
        "--archive-active", "--archive-source", "user:rotate", "--archive-reason", "defaults fixture",
        "--archive-human-decision-receipt", ".agent/state/archive-receipt.json",
    )
    if "STARTED standard task in clarification" not in rotated:
        raise AssertionError(f"explicitly declared start did not route to standard:\n{rotated}")

print(
    "CONTROL GATES SELF-TEST PASSED: budget routing, clarification, signed v1 human decisions, "
    "escalation re-approval, task-archive v2, cleanup/lease/docker/baseline hygiene, "
    "knowledge promotion, adapter probes, node-0 start contracts and fast start defaults"
)
