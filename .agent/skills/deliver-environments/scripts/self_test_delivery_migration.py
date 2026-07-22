#!/usr/bin/env python3
"""Migration-26 fixtures: lossless idle and historical production terminal closure."""

from pathlib import Path
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile


SOURCE_ROOT = Path(__file__).resolve().parents[4]
INSTALLER = SOURCE_ROOT / "install.py"
AGENT_SOURCE = SOURCE_ROOT / ".agent"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def receipt(root: Path, relative: str) -> dict:
    data = (root / relative).read_bytes()
    return {"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def invoke(root: Path, tool: str, *args: str, expected: int = 0, harness: bool = False) -> subprocess.CompletedProcess:
    script = root / ".agent/scripts/delivery-harness.py" if harness else root / f".agent/scripts/{tool}.py"
    result = subprocess.run(
        [sys.executable, str(script), *args], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )
    if result.returncode != expected:
        raise AssertionError(f"{tool} {args}: expected {expected}, got {result.returncode}\n{result.stdout}")
    return result


spec = importlib.util.spec_from_file_location("delivery_migration_installer", INSTALLER)
installer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(installer)


with tempfile.TemporaryDirectory(prefix="delivery-migration-26-") as raw:
    sandbox = Path(raw)

    idle_root = sandbox / "idle"
    idle_agent = idle_root / ".agent"
    write_json(idle_agent / "state/delivery.json", {
        "schema": "agent-delivery/v2", "environment": "local", "deployment_requested": False,
        "status": "not_requested", "artifact": None, "test_receipt": None,
        "production_approval": None, "deployment_attempt": None, "promotion_receipt": None,
        "rollback_receipt": None, "updated_at": "2026-01-01T00:00:00+00:00",
    })
    write_json(idle_agent / "state/TASK.json", {"status": "idle", "node_artifacts": {}})
    installer.migrate_delivery_state(idle_agent, 25)
    idle = json.loads((idle_agent / "state/delivery.json").read_text(encoding="utf-8"))
    if (
        idle.get("schema") != "agent-delivery/v3" or idle.get("status") != "not_requested"
        or idle.get("provider_preflight") is not None or idle.get("legacy_production_chain") is not None
    ):
        raise AssertionError("migration 25→26 did not preserve idle delivery semantics")

    for old_status, new_status in (
        ("promoted", "legacy_promoted"),
        ("rolled_back", "legacy_rolled_back"),
        ("rollback_required", "legacy_rollback_required"),
    ):
        root = sandbox / old_status
        agent = root / ".agent"
        (agent / "scripts").mkdir(parents=True)
        for name in ("deliveryctl.py", "artifactctl.py", "humandecision.py", "testrun.py"):
            shutil.copy2(AGENT_SOURCE / "scripts" / name, agent / "scripts" / name)
        shutil.copytree(AGENT_SOURCE / "scripts/workflowlib", agent / "scripts/workflowlib")
        (agent / "scripts/delivery-harness.py").write_text(
            "#!/usr/bin/env python3\nfrom pathlib import Path\nimport sys\n"
            "sys.path.insert(0,str(Path('.agent/scripts').resolve()))\nimport deliveryctl\n"
            "def verify(root,config,task,*,gate,artifact_sha256,source,receipt):\n"
            " value=deliveryctl.load((Path(root)/receipt).resolve())\n"
            " if value!={'gate':gate,'artifact_sha256':artifact_sha256,'source':source}: raise SystemExit('fixture decision rejected')\n"
            " return value\n"
            "def reverify(root,config,task,*,gate,artifact_sha256,source,record):\n"
            " return gate=='requirement' or record=={'gate':gate,'artifact_sha256':artifact_sha256,'source':source}\n"
            "deliveryctl.humandecision.verify=verify\ndeliveryctl.humandecision.reverify=reverify\n"
            "raise SystemExit(deliveryctl.main())\n",
            encoding="utf-8",
        )
        (agent / "scripts/agentctl.py").write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")
        (root / "artifact.bin").write_bytes(b"legacy immutable artifact")
        (root / "runner.py").write_text("print('legacy independent test')\n", encoding="utf-8")
        (root / "test-evidence.txt").write_text("passed", encoding="utf-8")
        (root / "deploy-evidence.txt").write_text("legacy deployment", encoding="utf-8")
        (root / "rollback-evidence.txt").write_text("legacy rollback", encoding="utf-8")
        (root / "health-evidence.txt").write_text("healthy", encoding="utf-8")
        (root / "restored.bin").write_bytes(b"restored")
        artifact_file = receipt(root, "artifact.bin")
        digest = "sha256:" + artifact_file["sha256"]
        artifact = {
            **artifact_file, "digest": digest, "built_by": "ci:legacy", "source_branch": "main",
            "source_revision": "a" * 40, "build_run_id": "build-legacy", "recorded_at": "2026-01-01T00:00:00+00:00",
        }
        test = {
            "schema": "agent-delivery-test-receipt/v1", "digest": digest, "result": "passed",
            "tested_environment": "test", "branch": "test/legacy", "source_revision": "a" * 40,
            "build_run_id": "build-legacy", "run_id": "test-legacy", "reviewer": "independent:legacy",
            "runner": receipt(root, "runner.py"), "evidence": receipt(root, "test-evidence.txt"),
            "recorded_at": "2026-01-01T00:00:00+00:00",
        }
        attempt_result = "failed" if old_status == "rollback_required" else "passed"
        attempt = {
            "schema": "agent-deployment-attempt/v1", "digest": digest, "environment": "production",
            "source_revision": "a" * 40, "build_run_id": "build-legacy", "test_run_id": "test-legacy",
            "result": attempt_result, "evidence": receipt(root, "deploy-evidence.txt"),
            "recorded_at": "2026-01-01T00:00:00+00:00",
        }
        promotion = None if old_status == "rollback_required" else {
            "schema": "agent-promotion-receipt/v1", "digest": digest, "environment": "production",
            "source_revision": "a" * 40, "deployment_attempt_sha256": "b" * 64,
            "evidence": receipt(root, "deploy-evidence.txt"), "recorded_at": "2026-01-01T00:00:00+00:00",
        }
        rollback = None
        if old_status == "rolled_back":
            restored = receipt(root, "restored.bin")
            rollback = {
                "schema": "agent-rollback-receipt/v1", "reason": "legacy", "failed_digest": digest,
                "restored_digest": "sha256:" + restored["sha256"], "restored_artifact": restored,
                "rollback_evidence": receipt(root, "rollback-evidence.txt"),
                "health_evidence": receipt(root, "health-evidence.txt"),
                "deployment_attempt": attempt, "recorded_at": "2026-01-01T00:00:00+00:00",
            }
        old_state = {
            "schema": "agent-delivery/v2", "environment": "production", "deployment_requested": True,
            "status": old_status, "artifact": artifact, "test_receipt": test,
            "production_approval": {"source": "user:legacy", "digest": digest, "test_run_id": "test-legacy"},
            "deployment_attempt": attempt, "promotion_receipt": promotion,
            "rollback_receipt": rollback, "updated_at": "2026-01-01T00:00:00+00:00",
        }
        state_path = agent / "state/delivery.json"
        write_json(state_path, old_state)
        old_state_bytes = state_path.read_bytes()
        node8_path = agent / "state/artifacts/08-delivery.json"
        old_node8_bytes = None
        node_artifacts = {}
        if old_status != "rollback_required":
            old_node8 = {
                "schema": "agent-node-delivery/v2", "status": old_status, "environment": "production",
                "artifact_digest": digest, "promotion_receipt_sha256": "c" * 64,
                "rollback_receipt_sha256": "d" * 64 if rollback else None,
                "delivery_state": receipt(root, ".agent/state/delivery.json"),
            }
            write_json(node8_path, old_node8)
            old_node8_bytes = node8_path.read_bytes()
            node_artifacts = {"8": receipt(root, ".agent/state/artifacts/08-delivery.json")}
        write_json(agent / "state/TASK.json", {
            "environment": "production", "deployment_requested": True,
            "status": "in_progress" if old_status == "rollback_required" else "accepted",
            "requirements_clarified": True, "requirement_source": "user:legacy",
            "accepted_nodes": list(range(8)) if old_status == "rollback_required" else list(range(9)),
            "node_artifacts": node_artifacts,
        })
        write_json(agent / "config.json", {
            "branches": {"local": ["feature/*"], "test": ["test/*"], "production": ["main"]},
            "agent_control": {
                "provider_preflight_observer": {
                    "source": "provider-read-only-api", "automatic_release_trust": False,
                    "provider_verification_required": True, "signed_adapter": None,
                    "max_receipt_age_seconds": 300,
                }
            },
        })

        installer.migrate_delivery_state(agent, 25)
        migrated = json.loads(state_path.read_text(encoding="utf-8"))
        legacy = migrated["legacy_production_chain"]
        archive = root / legacy["archive"]["path"]
        node8_archive = root / legacy["node8_archive"]["path"] if legacy["node8_archive"] is not None else None
        if (
            migrated["status"] != new_status or legacy["assurance"] != "legacy"
            or legacy["reusable_as_release_receipt"] is not False
            or archive.read_bytes() != old_state_bytes
            or (node8_archive.read_bytes() if node8_archive is not None else None) != old_node8_bytes
            or any(migrated[key] is not None for key in (
                "provider_preflight", "production_approval", "deployment_attempt", "promotion_receipt", "rollback_receipt",
            ))
        ):
            raise AssertionError(f"{old_status} migration was not lossless historical-only")
        if old_status != "rollback_required":
            projection = json.loads(node8_path.read_text(encoding="utf-8"))
            if (
                projection.get("schema") != "agent-node-delivery/v3" or projection.get("status") != new_status
                or projection.get("legacy_archive_sha256") != legacy["archive"]["sha256"]
                or projection.get("reusable_as_release_receipt") is not False
            ):
                raise AssertionError(f"{old_status} migration did not create a non-reusable historical Node8")
        elif node8_path.exists():
            raise AssertionError("rollback_required migration incorrectly created a terminal Node8")
        migrated_task = json.loads((agent / "state/TASK.json").read_text(encoding="utf-8"))
        if old_status != "rollback_required" and migrated_task["node_artifacts"]["8"] != receipt(root, ".agent/state/artifacts/08-delivery.json"):
            raise AssertionError("accepted legacy TASK did not rebind its historical Node8 receipt")

        before_promote = state_path.read_bytes()
        before_evidence = (root / "deploy-evidence.txt").read_bytes()
        invoke(root, "deliveryctl", "promote", "--digest", digest, "--evidence", "deploy-evidence.txt", expected=1)
        if state_path.read_bytes() != before_promote or (root / "deploy-evidence.txt").read_bytes() != before_evidence:
            raise AssertionError(f"{old_status} historical migration caused a promotion side effect")
        invoke(root, "deliveryctl", "validate")
        if old_status == "rollback_required":
            blocked_snapshot = state_path.read_bytes()
            invoke(root, "deliveryctl", "snapshot-node8", expected=1)
            if state_path.read_bytes() != blocked_snapshot or node8_path.exists():
                raise AssertionError("unclosed legacy rollback became terminal or mutated delivery state")
            restored_digest = "sha256:" + hashlib.sha256((root / "restored.bin").read_bytes()).hexdigest()
            policy_task = json.loads((agent / "state/TASK.json").read_text(encoding="utf-8"))
            policy_task["decision_policy_version"] = 1
            contract_path = agent / "state/REQUIREMENT_CONTRACT.md"
            contract_path.write_text("# Approved legacy recovery requirement\n", encoding="utf-8")
            contract_sha = hashlib.sha256(contract_path.read_bytes()).hexdigest()
            policy_task["requirement_contract_sha256"] = contract_sha
            policy_task["gate_approvals"] = {
                "requirement": {"artifact_sha256": contract_sha, "decision_receipt": {"fixture": True}}
            }
            write_json(agent / "state/TASK.json", policy_task)
            source = "user:release-owner"
            base_closure_args = (
                "record-legacy-rollback-closure", "--reason", "external recovery verified", "--source", source,
                "--evidence", "rollback-evidence.txt", "--health-evidence", "health-evidence.txt",
                "--failed-digest", digest, "--restored-digest", restored_digest,
                "--restored-artifact", "restored.bin",
            )
            wrong_decision = root / "wrong-closure-decision.json"
            write_json(wrong_decision, {
                "gate": "legacy-rollback-closure", "artifact_sha256": artifact["sha256"], "source": source,
            })
            unsigned_before = state_path.read_bytes()
            invoke(root, "deliveryctl", *base_closure_args, expected=1, harness=True)
            invoke(
                root, "deliveryctl", *base_closure_args,
                "--human-decision-receipt", str(wrong_decision.relative_to(root)), expected=1, harness=True,
            )
            if state_path.read_bytes() != unsigned_before:
                raise AssertionError("unsigned/wrong-packet legacy rollback closure mutated delivery state")
            closure_packet = {
                "schema": "agent-legacy-rollback-decision/v1",
                "reason": "external recovery verified",
                "legacy_archive_sha256": legacy["archive"]["sha256"],
                "failed_digest": digest, "restored_digest": restored_digest,
                "restored_artifact_sha256": hashlib.sha256((root / "restored.bin").read_bytes()).hexdigest(),
                "rollback_evidence_sha256": hashlib.sha256((root / "rollback-evidence.txt").read_bytes()).hexdigest(),
                "health_evidence_sha256": hashlib.sha256((root / "health-evidence.txt").read_bytes()).hexdigest(),
            }
            correct_decision = root / "correct-closure-decision.json"
            write_json(correct_decision, {
                "gate": "legacy-rollback-closure",
                "artifact_sha256": hashlib.sha256(json.dumps(
                    closure_packet, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                ).encode()).hexdigest(),
                "source": source,
            })
            invoke(
                root, "deliveryctl", *base_closure_args,
                "--human-decision-receipt", str(correct_decision.relative_to(root)), harness=True,
            )
            closed = json.loads(state_path.read_text(encoding="utf-8"))
            if closed.get("status") != "legacy_rolled_back" or not isinstance(closed["legacy_production_chain"].get("rollback_closure"), dict):
                raise AssertionError("evidence-bound legacy rollback closure did not reach historical rolled_back")
            invoke(root, "deliveryctl", "validate", harness=True)
            invoke(root, "deliveryctl", "snapshot-node8", harness=True)
        else:
            invoke(root, "deliveryctl", "snapshot-node8")
            invoke(root, "artifactctl", "--node", "8", "--path", ".agent/state/artifacts/08-delivery.json")

print("DELIVERY MIGRATION-26 SELF-TEST PASSED: lossless terminals + signed rollback closure")
