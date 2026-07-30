#!/usr/bin/env python3
"""Bounded adversarial fixtures for the v3 delivery/provider production gate."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from typing import Optional


AGENT_SOURCE = Path(__file__).resolve().parents[3]
DELIVERY_SOURCE = AGENT_SOURCE / "scripts/deliveryctl.py"
HUMAN_DECISION_SOURCE = AGENT_SOURCE / "scripts/humandecision.py"


def invoke(root: Path, *args: str, expected: int = 0, provider_harness: bool = False) -> subprocess.CompletedProcess:
    command = root / ("provider-harness.py" if provider_harness else ".agent/scripts/deliveryctl.py")
    result = subprocess.run(
        [sys.executable, str(command), *args], cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15,
    )
    if result.returncode != expected:
        raise AssertionError(f"{args}: expected {expected}, got {result.returncode}\n{result.stdout}")
    return result


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def canonical(value: object) -> str:
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def current_state(root: Path) -> dict:
    return json.loads((root / ".agent/state/delivery.json").read_text(encoding="utf-8"))


def assert_state_unchanged(root: Path, before: bytes, label: str) -> None:
    if (root / ".agent/state/delivery.json").read_bytes() != before:
        raise AssertionError(f"rejected {label} mutated delivery state")


def provider_receipt(root: Path, target: dict, *, observed_at: Optional[str] = None) -> dict:
    state = current_state(root)
    artifact, test = state["artifact"], state["test_receipt"]
    candidate = {
        "digest": artifact["digest"],
        "source_branch": artifact["source_branch"],
        "source_revision": artifact["source_revision"],
        "build_run_id": artifact["build_run_id"],
    }
    summary = {
        "digest": test["digest"],
        "source_revision": test["source_revision"],
        "build_run_id": test["build_run_id"],
        "run_id": test["run_id"],
        "result": test["result"],
        "branch": test["branch"],
        "runner_sha256": test["runner"]["sha256"],
        "evidence_sha256": test["evidence"]["sha256"],
    }
    revision = artifact["source_revision"]
    return {
        "schema": "provider-production-preflight/v1",
        "receipt_id": "provider-observation-123",
        "authority": "provider-signed-read-only-observer",
        "provider": target["provider"],
        "repository": target["repository"],
        "default_branch": target["default_branch"],
        "effective_protection": {
            "source": "ruleset", "enforced": True,
            "required_status_checks": list(target["required_status_checks"]),
            "pull_request_reviews": {
                "required": True,
                "required_approving_review_count": target["min_required_reviewers"],
            },
            "force_push_allowed": False, "deletion_allowed": False,
        },
        "environments": {
            "test": {"name": target["test_environment"]},
            "production": {
                "name": target["production_environment"],
                "required_reviewers": ["release-owner", "security-owner"],
                "prevent_self_review": True,
            },
        },
        "candidate": candidate,
        "candidate_revision": revision,
        "default_branch_reachability": {
            "branch": target["default_branch"], "candidate_revision": revision,
            "relation": "merge-commit", "verified": True,
            "evidence_url": "https://provider.example/reachability/123",
            "evidence_sha256": "a" * 64,
        },
        "required_check_runs": [
            {
                "name": name, "commit_sha": revision, "status": "completed",
                "conclusion": "success", "run_id": f"run-{index + 1}",
                "url": f"https://provider.example/checks/{index + 1}",
                "evidence_sha256": hashlib.sha256(name.encode()).hexdigest(),
            }
            for index, name in enumerate(target["required_status_checks"])
        ],
        "test_summary": summary,
        "observed_at": observed_at or dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    }


with tempfile.TemporaryDirectory(prefix="delivery-v3-test-") as raw:
    root = Path(raw)
    scripts = root / ".agent/scripts"
    scripts.mkdir(parents=True)
    (root / ".agent/state").mkdir()
    shutil.copy2(DELIVERY_SOURCE, scripts / "deliveryctl.py")
    shutil.copy2(HUMAN_DECISION_SOURCE, scripts / "humandecision.py")
    (scripts / "agentctl.py").write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")
    (root / "artifact.bin").write_bytes(b"immutable candidate")
    (root / "test-evidence.txt").write_text("passed", encoding="utf-8")
    (root / "deploy-evidence.txt").write_text("healthy", encoding="utf-8")
    (root / "runner.py").write_text("print('independent test')\n", encoding="utf-8")

    verifier = root / ".agent/provider-preflight-verifier"
    verifier.write_text(
        "#!/usr/bin/env python3\n"
        "import hashlib, pathlib, sys\n"
        "data=pathlib.Path(sys.argv[-1]).read_bytes()\n"
        "print('VERIFIED PROVIDER PREFLIGHT sha256='+hashlib.sha256(data).hexdigest())\n",
        encoding="utf-8",
    )
    verifier.chmod(0o755)
    (root / "provider-harness.py").write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "import sys\n"
        "sys.path.insert(0, str(Path('.agent/scripts').resolve()))\n"
        "import deliveryctl\n"
        "deliveryctl.provider_adapter_path=lambda: Path('.agent/provider-preflight-verifier').resolve()\n"
        "def verify(root, config, task, *, gate, artifact_sha256, source, receipt):\n"
        "    value=deliveryctl.load((Path(root)/receipt).resolve())\n"
        "    if value != {'gate':gate,'artifact_sha256':artifact_sha256,'source':source}:\n"
        "        raise SystemExit('fixture human-decision adapter rejected packet binding')\n"
        "    return value\n"
        "def reverify(root, config, task, *, gate, artifact_sha256, source, record):\n"
        "    if gate == 'requirement': return True\n"
        "    return record == {'gate':gate,'artifact_sha256':artifact_sha256,'source':source}\n"
        "deliveryctl.humandecision.verify=verify\n"
        "deliveryctl.humandecision.reverify=reverify\n"
        "raise SystemExit(deliveryctl.main())\n",
        encoding="utf-8",
    )
    write_json(root / ".agent/config.json", {
        "branches": {
            "local": ["feature/*", "fix/*", "chore/*"],
            "test": ["develop", "test/*", "release/*"],
            "production": ["main"],
        },
        "agent_control": {
            "provider_preflight_observer": {
                "source": "provider-read-only-api",
                "automatic_release_trust": False,
                "provider_verification_required": True,
                "signed_adapter": str(verifier.resolve()),
                "max_receipt_age_seconds": 300,
            }
        },
    })

    digest = "sha256:" + hashlib.sha256(b"immutable candidate").hexdigest()
    revision = "a" * 40
    artifact_args = (
        "--path", "artifact.bin", "--digest", digest, "--built-by", "ci:builder",
        "--source-branch", "test/candidate", "--source-revision", revision,
        "--build-run-id", "build-123",
    )
    test_args = (
        "--digest", digest, "--result", "passed", "--evidence", "test-evidence.txt",
        "--tested-environment", "test", "--branch", "test/candidate",
        "--run-id", "test-123", "--reviewer", "independent:reviewer", "--runner", "runner.py",
    )

    # Test delivery remains lightweight: no provider receipt, adapter or human production decision.
    test_task = {
        "environment": "test", "deployment_requested": True,
        "requirements_clarified": True, "requirement_source": "user:fixture",
        "accepted_nodes": list(range(8)),
    }
    write_json(root / ".agent/state/TASK.json", test_task)
    invoke(root, "init")
    invoke(root, "record-artifact", *artifact_args)
    invoke(root, "accept-test", *test_args)
    if current_state(root)["status"] != "ready_to_promote":
        raise AssertionError("test delivery was incorrectly burdened by the production provider gate")
    invoke(root, "promote", "--digest", digest, "--evidence", "deploy-evidence.txt")
    invoke(root, "validate")

    target = {
        "schema": "agent-production-provider-target/v1",
        "provider": "github", "repository": "example/repository", "default_branch": "main",
        "test_environment": "test", "production_environment": "production",
        "required_status_checks": ["build", "test"], "min_required_reviewers": 2,
    }
    canonical_target = json.dumps(target, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    contract = root / ".agent/state/REQUIREMENT_CONTRACT.md"
    contract.write_text("# Approved requirements\n\n- Production provider target: " + canonical_target + "\n", encoding="utf-8")
    production_task = {
        "environment": "production", "deployment_requested": True,
        "requirements_clarified": True, "requirement_source": "user:fixture",
        "accepted_nodes": list(range(8)), "production_provider": target,
        "requirement_contract_sha256": hashlib.sha256(contract.read_bytes()).hexdigest(),
    }
    write_json(root / ".agent/state/TASK.json", production_task)
    invoke(root, "init")
    invoke(root, "record-artifact", *artifact_args)
    invoke(root, "accept-test", *test_args)
    state_path = root / ".agent/state/delivery.json"

    missing_before = state_path.read_bytes()
    invoke(root, "record-provider-preflight", "--receipt", ".agent/state/evidence/provider-preflight/missing.json", expected=1)
    assert_state_unchanged(root, missing_before, "missing provider preflight")

    receipt_path = root / ".agent/state/evidence/provider-preflight/receipt.json"
    valid_receipt = provider_receipt(root, target)
    write_json(receipt_path, valid_receipt)

    # A caller-authored project-local verifier is rejected by the real trust boundary.
    untrusted_before = state_path.read_bytes()
    rejected = invoke(
        root, "record-provider-preflight", "--receipt", str(receipt_path.relative_to(root)), expected=1,
    )
    if "OS-protected host provider adapter" not in rejected.stdout:
        raise AssertionError(f"caller verifier failed for the wrong reason:\n{rejected.stdout}")
    assert_state_unchanged(root, untrusted_before, "caller-owned provider verifier")

    forged = dict(valid_receipt)
    forged["authority"] = "caller-asserted-provider"
    write_json(receipt_path, forged)
    forged_before = state_path.read_bytes()
    invoke(
        root, "record-provider-preflight", "--receipt", str(receipt_path.relative_to(root)),
        expected=1, provider_harness=True,
    )
    assert_state_unchanged(root, forged_before, "forged provider authority")

    wrong_check = json.loads(json.dumps(valid_receipt))
    wrong_check["required_check_runs"][0]["commit_sha"] = "b" * 40
    write_json(receipt_path, wrong_check)
    check_before = state_path.read_bytes()
    invoke(
        root, "record-provider-preflight", "--receipt", str(receipt_path.relative_to(root)),
        expected=1, provider_harness=True,
    )
    assert_state_unchanged(root, check_before, "check run from another revision")

    expired_time = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=301)).replace(microsecond=0).isoformat()
    expired = provider_receipt(root, target, observed_at=expired_time)
    write_json(receipt_path, expired)
    expired_before = state_path.read_bytes()
    invoke(
        root, "record-provider-preflight", "--receipt", str(receipt_path.relative_to(root)),
        expected=1, provider_harness=True,
    )
    assert_state_unchanged(root, expired_before, "expired provider observation")

    valid_receipt = provider_receipt(root, target)
    write_json(receipt_path, valid_receipt)
    valid_bytes = receipt_path.read_bytes()
    invoke(
        root, "record-provider-preflight", "--receipt", str(receipt_path.relative_to(root)),
        provider_harness=True,
    )
    if current_state(root)["status"] != "awaiting_production_approval":
        raise AssertionError("valid provider preflight did not advance to human production approval")

    receipt_path.write_bytes(valid_bytes + b" \n")
    drift_before = state_path.read_bytes()
    invoke(root, "approve-production", "--source", "user:release-owner", expected=1, provider_harness=True)
    assert_state_unchanged(root, drift_before, "drifted provider receipt")
    receipt_path.write_bytes(valid_bytes)

    # Policy v1 must sign the complete deployment packet SHA, not only artifact bytes/digest.
    production_task = json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    production_task["decision_policy_version"] = 1
    production_task["gate_approvals"] = {
        "requirement": {
            "artifact_sha256": production_task["requirement_contract_sha256"],
            "decision_receipt": {"fixture": "provider-signed-requirement"},
        }
    }
    write_json(root / ".agent/state/TASK.json", production_task)
    state = current_state(root)
    artifact, test, provider = state["artifact"], state["test_receipt"], state["provider_preflight"]
    packet = {
        "schema": "agent-production-deployment-decision/v1",
        "artifact_digest": artifact["digest"], "candidate_revision": artifact["source_revision"],
        "candidate_sha256": canonical({
            "digest": artifact["digest"], "source_branch": artifact["source_branch"],
            "source_revision": artifact["source_revision"], "build_run_id": artifact["build_run_id"],
        }),
        "provider": target["provider"], "repository": target["repository"],
        "default_branch": target["default_branch"],
        "production_environment": target["production_environment"],
        "provider_preflight_sha256": provider["sha256"],
        "test_summary_sha256": provider["test_summary_sha256"],
    }
    source = "user:release-owner"
    wrong_decision = root / "artifact-only-decision.json"
    write_json(wrong_decision, {
        "gate": "production-delivery", "artifact_sha256": artifact["sha256"], "source": source,
    })
    unsigned_before = state_path.read_bytes()
    invoke(
        root, "approve-production", "--source", source,
        "--human-decision-receipt", str(wrong_decision.relative_to(root)),
        expected=1, provider_harness=True,
    )
    assert_state_unchanged(root, unsigned_before, "artifact-only production decision")
    packet_decision = root / "packet-decision.json"
    write_json(packet_decision, {
        "gate": "production-delivery", "artifact_sha256": canonical(packet), "source": source,
    })
    invoke(
        root, "approve-production", "--source", source,
        "--human-decision-receipt", str(packet_decision.relative_to(root)), provider_harness=True,
    )
    approved = current_state(root)
    packet = approved["production_approval"]["decision_packet"]
    expected_packet_keys = {
        "schema", "artifact_digest", "candidate_revision", "candidate_sha256", "provider",
        "repository", "default_branch", "production_environment", "provider_preflight_sha256",
        "test_summary_sha256",
    }
    if set(packet) != expected_packet_keys or approved["production_approval"]["decision_packet_sha256"] != canonical(packet):
        raise AssertionError("production approval did not bind the complete content-addressed decision packet")

    valid_approved = state_path.read_bytes()
    tampered = current_state(root)
    tampered["production_approval"]["decision_packet"]["repository"] = "attacker/repository"
    write_json(state_path, tampered)
    tamper_before = state_path.read_bytes()
    invoke(
        root, "promote", "--digest", digest, "--evidence", "deploy-evidence.txt",
        expected=1, provider_harness=True,
    )
    assert_state_unchanged(root, tamper_before, "tampered production decision packet")
    state_path.write_bytes(valid_approved)

    invoke(
        root, "promote", "--digest", digest, "--evidence", "deploy-evidence.txt",
        provider_harness=True,
    )
    invoke(root, "validate", provider_harness=True)

# Clarification has a sanctioned, digest-producing provider-target entry point;
# production setup never requires editing TASK by hand.
with tempfile.TemporaryDirectory(prefix="production-target-config-") as raw:
    root = Path(raw)
    scripts = root / ".agent/scripts"
    scripts.mkdir(parents=True)
    for name in ("agentctl.py", "contexttx.py", "contextctl.py", "humandecision.py"):
        shutil.copy2(AGENT_SOURCE / "scripts" / name, scripts / name)
    shutil.copytree(AGENT_SOURCE / "scripts/workflowlib", scripts / "workflowlib")
    target = {
        "schema": "agent-production-provider-target/v1", "provider": "github",
        "repository": "example/repository", "default_branch": "main",
        "test_environment": "test", "production_environment": "production",
        "required_status_checks": ["build", "test"], "min_required_reviewers": 2,
    }
    write_json(root / "provider-target.json", target)
    write_json(root / ".agent/config.json", {
        "branches": {"local": ["feature/*"], "test": ["test/*"], "production": ["main"]}
    })
    write_json(root / ".agent/state/TASK.json", {
        "phase": "clarification", "status": "waiting_human", "requirements_clarified": False,
        "environment": "production", "deployment_requested": True,
    })
    contract_path = root / ".agent/state/REQUIREMENT_CONTRACT.md"
    contract_path.write_text(
        "# Requirement Contract\n\n"
        "- Goal: release\n- Users: users\n- Success: healthy\n- In scope: release\n"
        "- Out of scope: none\n- Constraints: protected\n- Data and permissions: least privilege\n"
        "- Target environment: production\n- Acceptance: passed\n- Provenance: user request\n"
        "- Production provider target: PENDING\n- Human decisions: pending\n- Clarified: false\n",
        encoding="utf-8",
    )
    configured = subprocess.run(
        [
            sys.executable, str(scripts / "agentctl.py"), "configure-production-provider",
            "--target", "provider-target.json", "--source", "user:release-owner",
        ],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15,
    )
    canonical_target = json.dumps(target, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if (
        configured.returncode != 0 or "REQUIREMENT APPROVAL DIGEST sha256=" not in configured.stdout
        or f"- Production provider target: {canonical_target}" not in contract_path.read_text(encoding="utf-8")
        or "production_provider" in json.loads((root / ".agent/state/TASK.json").read_text(encoding="utf-8"))
    ):
        raise AssertionError(f"sanctioned production target configuration failed:\n{configured.stdout}")

# Full sanctioned path: editable draft → exact policy-v1 approval → strict context/structure validation.
with tempfile.TemporaryDirectory(prefix="production-target-approval-") as raw:
    root = Path(raw)
    shutil.copytree(AGENT_SOURCE, root / ".agent")
    subprocess.run(["git", "init", "-b", "main"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    config_path = root / ".agent/config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    fixture_guardrails = """# Project Guardrails

- Product and users: Disposable production-delivery fixture for maintainers.
- Technology and architecture: Python, JSON, and Markdown control-plane fixture.
- Writable and read-only areas: Only the disposable fixture is writable.
- Security, privacy, compliance and performance red lines: No real provider or deployment effects.
- Build, test and lint commands: Run only this bounded self-test.
- Deployment authority and rollback owner: Deployment is simulated; the fixture owns rollback.
""".encode()
    (root / ".agent/policies/PROJECT_GUARDRAILS.md").write_bytes(fixture_guardrails)
    config["guardrails_ready"] = True
    config["project_initialization"] = {
        "schema": "agent-project-initialization/v1",
        "guardrails_sha256": hashlib.sha256(fixture_guardrails).hexdigest(),
        "guardrails_bytes": len(fixture_guardrails),
        "initialized_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    }
    write_json(config_path, config)
    task_path = root / ".agent/state/TASK.json"
    task = json.loads(task_path.read_text(encoding="utf-8"))
    task.update({
        "title": "production target approval fixture", "mode": "release", "environment": "production",
        "deployment_requested": True, "branch": "main", "status": "waiting_human", "phase": "clarification",
        "requirements_clarified": False, "requirement_source": "pending", "production_provider": None,
        "token_budget": config["routing"]["modes"]["release"]["token_budget"],
        "primary_skill": "clarify-task", "selected_templates": ["requirement-contract"],
        "selected_capabilities": ["core"], "template_route": None, "rendered_artifacts": [],
        "open_questions": ["requirement contract approval"], "current_node": 1, "accepted_nodes": [0],
        "node_artifacts": {}, "gate_approvals": {}, "pending_gate_artifacts": {},
        "mode_status": "provisional", "next_action": "clarify and approve the requirement contract",
    })
    task["risk_flags"]["deploy"] = True
    task["decision_policy_version"] = 1
    write_json(task_path, task)
    agents_path = root / ".agent/state/agents.json"
    agents = json.loads(agents_path.read_text(encoding="utf-8"))
    agents["token_accounting"]["token_budget"] = task["token_budget"]
    write_json(agents_path, agents)
    contract_path = root / ".agent/state/REQUIREMENT_CONTRACT.md"
    contract_path.write_text(
        "# Requirement Contract\n\n- Goal: release safely\n- Users: production users\n"
        "- Success: healthy exact release\n- In scope: release\n- Out of scope: policy changes\n"
        "- Constraints: protected production\n- Data and permissions: least privilege\n"
        "- Target environment: production\n- Context transport: native\n- Acceptance: full gate\n"
        "- Provenance: user request\n- Production provider target: PENDING\n"
        "- Human decisions: pending\n- Clarified: false\n",
        encoding="utf-8",
    )
    runtime_path = root / ".agent/state/runtime.json"
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    runtime["baseline"] = {"source": "fixture", "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "project_processes": []}
    write_json(runtime_path, runtime)
    seed = subprocess.run(
        [sys.executable, "-c", (
            "import argparse,hashlib,json,sys;sys.path.insert(0,'.agent/scripts');import contextctl;"
            "p=contextctl.CONTEXT_PATH;args=argparse.Namespace(reason='fixture',summary='waiting production clarification',"
            "source='fixture',source_tokens=4000,fact=[],file=[],evidence=[],risk=[],resolve_risk=[],transition=False,reset=False);"
            "value=contextctl.build_capsule(args,'verified',{},'none');contextctl.atomic_json(p,value);"
            "raise SystemExit(contextctl.validate_context())"
        )], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )
    if seed.returncode:
        raise AssertionError(f"failed to seed draft context:\n{seed.stdout}")
    target = {
        "schema": "agent-production-provider-target/v1", "provider": "github",
        "repository": "example/repository", "default_branch": "main",
        "test_environment": "test", "production_environment": "production",
        "required_status_checks": ["build", "test"], "min_required_reviewers": 2,
    }
    write_json(root / "provider-target.json", target)
    configured = subprocess.run(
        [sys.executable, ".agent/scripts/agentctl.py", "configure-production-provider",
         "--target", "provider-target.json", "--source", "user:release-owner"],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )
    context_check = subprocess.run(
        [sys.executable, ".agent/scripts/contextctl.py", "check"], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )
    if configured.returncode or context_check.returncode:
        raise AssertionError(f"draft target drifted context:\n{configured.stdout}\n{context_check.stdout}")
    approval_sha = configured.stdout.strip().split("sha256=")[-1]
    harness = root / "approve-harness.py"
    harness.write_text(
        "from pathlib import Path\nimport argparse,json,sys\nsys.path.insert(0,'.agent/scripts')\nimport agentctl\n"
        "def verify(root,config,task,*,gate,artifact_sha256,source,receipt):\n"
        " value=json.loads((Path(root)/receipt).read_text())\n"
        " if value!={'gate':gate,'artifact_sha256':artifact_sha256,'source':source}: raise SystemExit('signed approval mismatch')\n"
        " return value\n"
        "agentctl.humandecision.verify=verify\n"
        "args=argparse.Namespace(source='user:release-owner',human_decision_receipt=sys.argv[1])\n"
        "raise SystemExit(agentctl.command_approve(args))\n",
        encoding="utf-8",
    )
    wrong = root / "wrong-requirement-decision.json"
    write_json(wrong, {"gate": "requirement", "artifact_sha256": "0" * 64, "source": "user:release-owner"})
    before = (task_path.read_bytes(), contract_path.read_bytes(), (root / ".agent/state/CONTEXT.json").read_bytes())
    rejected = subprocess.run([sys.executable, str(harness), wrong.name], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    after = (task_path.read_bytes(), contract_path.read_bytes(), (root / ".agent/state/CONTEXT.json").read_bytes())
    if rejected.returncode == 0 or after != before:
        raise AssertionError("wrong requirement decision did not roll back TASK/CONTRACT/CONTEXT exactly")
    correct = root / "correct-requirement-decision.json"
    write_json(correct, {"gate": "requirement", "artifact_sha256": approval_sha, "source": "user:release-owner"})
    approved = subprocess.run([sys.executable, str(harness), correct.name], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    routed = subprocess.run(
        [sys.executable, ".agent/scripts/templatectl.py", "route", "--capability", "delivery", "--capability", "ci-provider-github", "--capability", "acceptance-workflow"],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )
    delivery_init = subprocess.run(
        [sys.executable, ".agent/scripts/deliveryctl.py", "init"], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )
    # agentctl validate re-runs `workflowctl.py validate` as a subprocess, and
    # the requirement-gate revalidation performs a genuine provider reverify.
    # A sandbox cannot provision an OS-owned decision adapter, so the harness
    # executes that one subprocess in-process with the provider boundary
    # stubbed; every other controller still runs as a real subprocess.
    validated = root / "validate-harness.py"
    validated.write_text(
        "import sys,types;sys.path.insert(0,'.agent/scripts')\n"
        "import agentctl,humandecision,workflowctl\n"
        "humandecision.reverify=lambda *a,**k: True\n"
        "real_run=agentctl.subprocess.run\n"
        "def patched(command,**kwargs):\n"
        "    if any(str(item).endswith('workflowctl.py') for item in command):\n"
        "        rc=workflowctl.command_validate()\n"
        "        return types.SimpleNamespace(returncode=rc,stdout='')\n"
        "    return real_run(command,**kwargs)\n"
        "agentctl.subprocess.run=patched\n"
        "raise SystemExit(agentctl.command_validate())\n",
        encoding="utf-8",
    )
    context_check = subprocess.run([sys.executable, ".agent/scripts/contextctl.py", "check"], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    structure = subprocess.run([sys.executable, str(validated)], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    approved_task = json.loads(task_path.read_text(encoding="utf-8"))
    if (
        approved.returncode or routed.returncode or delivery_init.returncode or context_check.returncode or structure.returncode
        or approved_task.get("production_provider") != target
        or approved_task.get("requirement_contract_sha256") != hashlib.sha256(contract_path.read_bytes()).hexdigest()
    ):
        raise AssertionError(f"sanctioned signed approval path failed:\n{approved.stdout}\n{routed.stdout}\n{delivery_init.stdout}\n{context_check.stdout}\n{structure.stdout}")

print("DELIVERY V3 SELF-TEST PASSED: lightweight test flow and fail-closed provider production gate")
