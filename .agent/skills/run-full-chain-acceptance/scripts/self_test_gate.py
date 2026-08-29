#!/usr/bin/env python3
"""Run positive and adversarial fixtures against the acceptance report gate."""

from pathlib import Path
import copy
import hashlib
import json
import subprocess
import sys
import tempfile


VALIDATOR = Path(__file__).with_name("validate_acceptance_report.py").resolve()
LANES = (
    "happy-path", "alternative-path", "validation", "boundary", "interruption-recovery",
    "concurrency-idempotency", "persistence-data-integrity", "accessibility", "privacy-security",
    "compatibility-responsive", "regression-operations",
)
FINGERPRINT = ""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def run_gate(root: Path) -> int:
    return subprocess.run([sys.executable, str(VALIDATOR), "report.md"], cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).returncode


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="acceptance-gate-") as raw_root:
        root = Path(raw_root)
        (root / ".agent").mkdir()
        write_json(root / ".agent/config.json", {
            "routing": {"modes": {"release": {"clean_reruns": 1}}}
        })
        for path, content in {
            "src/app.js": "app", "tests/e2e.js": "test", "package.json": "{}",
            "Dockerfile": "FROM scratch", "spec.md": "# requirement-a\n# requirement-b\n",
        }.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        fingerprint = root / "fingerprint.sha256"
        fingerprint.write_text("".join(
            f"{digest(root / path)}  {path}\n" for path in ("src/app.js", "tests/e2e.js", "package.json", "Dockerfile", "spec.md")
        ), encoding="utf-8")
        tested = digest(fingerprint)

        roles = {
            "implementer": "/agent/impl#build", "adversarial": "/agent/adversarial#review",
            "cross": "/agent/cross#review", "integrator": "/agent/integrator#replay",
        }
        lanes = []
        for lane in LANES:
            if lane == "boundary":
                lanes.append({"id": lane, "status": "covered", "cases": ["CASE-A"]})
            elif lane == "happy-path":
                lanes.append({"id": lane, "status": "covered", "cases": ["CASE-B"]})
            else:
                lanes.append({"id": lane, "status": "not_applicable", "reason": "fixture scope", "approver": "user:fixture"})
        plan = {
            "requirements": [
                {"id": "REQ-A", "source": {"file": "spec.md", "anchor": "requirement-a"}, "delivery": "boundary"},
                {"id": "REQ-B", "source": {"file": "spec.md", "anchor": "requirement-b"}, "delivery": "happy"},
            ],
            "scope": {
                "source_roots": ["src"], "test_roots": ["tests"], "config_files": ["package.json"],
                "container_files": ["Dockerfile"], "requirement_files": ["spec.md"], "exclude_paths": [],
            },
            "lanes": lanes,
            "adjacencies": [{"case_a": "CASE-A", "case_b": "CASE-B", "controlled_field": "amount_class", "source": {"file": "spec.md", "anchor": "requirement-b"}}],
            "agents": {
                "platform_limit": 4, "max_active_children": 3, "peak_active_children": 3,
                "root_slot_reserved": True,
                "assignments": [{"role": role, "agent": agent, "read_only": role != "implementer"} for role, agent in roles.items()],
                "events": [
                    {"sequence": index, "timestamp": f"2026-07-17T00:00:{index:02d}Z", "role": role, "phase": phase, "action": action, "fingerprint": tested}
                    for index, (role, phase, action) in enumerate([
                        ("implementer", "candidate", "started"), ("implementer", "candidate", "status_check"), ("implementer", "candidate", "finished"),
                        ("adversarial", "adversarial", "started"), ("adversarial", "adversarial", "status_check"), ("adversarial", "adversarial", "finished"),
                        ("cross", "cross", "started"), ("cross", "cross", "status_check"), ("cross", "cross", "finished"),
                        ("integrator", "integrator", "started"), ("integrator", "integrator", "status_check"), ("integrator", "integrator", "finished"),
                    ], start=1)
                ],
            },
        }
        write_json(root / "plan.json", plan)
        blueprint_design={
            "goals":["Exercise the exact user-required application"],"architecture":[],"technology_choices":[],
            "capabilities":[],"constraints":[],"acceptance":[{"id":"exact-runtime","criterion":"Run the exact application service"}],
            "commands":[{"id":"run-acceptance","argv":["python3","tests/e2e.js"],"stage":"acceptance","timeout_seconds":30,"covers":["exact-runtime"],"environment":["PATH"]}],
            "providers":[],"application_services":["app"],
        }
        blueprint_sha256=hashlib.sha256(json.dumps(blueprint_design,sort_keys=True,separators=(",", ":")).encode()).hexdigest()
        (root/".agent/project").mkdir()
        write_json(root/".agent/project/BLUEPRINT.json",{
            "schema":"agent-project-blueprint/v1","status":"confirmed","design":blueprint_design,"suggestions":[],
            "confirmation":{"source":"user:fixture","design_sha256":blueprint_sha256,"confirmed_at":"2026-07-17T00:00:00Z","decision_receipt":{}},
        })

        common = {
            "tested_fingerprint": tested, "environment": "fixture", "precondition": "clean",
            "expected": "pass", "actual": "pass", "assertions": [{"name": "ui", "passed": True}, {"name": "storage", "passed": True}],
            "command": "fixture", "exit_code": 0, "timestamp": "2026-07-17T00:00:00Z",
            "observed_layers": ["ui", "storage"], "data_flow_steps": ["input", "persist"], "risk": "high",
            "execution_run_ids": ["RUN-A"],
        }
        case_a = dict(common, case_id="CASE-A", requirement_id="REQ-A", reviewer_agent=roles["adversarial"], lane="boundary", user_role="cautious", review_type="adversarial", attack_types=["boundary", "fault"], fault_injection="invalid boundary value", scenario_vector={"flow": "capture-confirm", "state": "review", "input_shape": "expense", "amount_class": "boundary"})
        case_b = dict(common, case_id="CASE-B", requirement_id="REQ-B", reviewer_agent=roles["cross"], lane="happy-path", user_role="first-time", review_type="cross", derivation_source={"file": "spec.md", "anchor": "requirement-b"}, adjacent_case="CASE-A", controlled_field="amount_class", scenario_vector={"flow": "capture-confirm", "state": "review", "input_shape": "expense", "amount_class": "normal"})
        write_json(root / "case-a.json", case_a)
        write_json(root / "case-b.json", case_b)
        image_digest = "sha256:" + "a" * 64
        candidate_sha256 = "f" * 64
        runtime_source = [{"path": path, "sha256": digest(root / path)} for path in ("src/app.js", "package.json", "Dockerfile")]
        for suffix in ("A",):
            runtime_id = f"acceptance_fixture_{suffix.lower()}"
            write_json(root / f"runtime-{suffix.lower()}.json", {
                "schema": "run_acceptance_runtime/v2", "tool": "run_acceptance_runtime",
                "tool_sha256": digest(VALIDATOR.with_name("run_acceptance_runtime.py")),
                "candidate_sha256": candidate_sha256, "blueprint_sha256": blueprint_sha256,
                "project": runtime_id, "status": "passed", "source": {"sha256": "fixture", "files": runtime_source},
                "source_after": {"sha256": "fixture"},
                "loaded_image_id": image_digest, "application_services": ["app"], "candidate_services": ["app"],
                "containers": [{"service": "app", "status": "running", "health": "healthy", "image": image_digest}],
                "docker": "fixture", "compose": "fixture",
                "resolved_compose": {"sha256": "d" * 64, "line_count": 1, "tail": ["fixture"]},
                "build": {"sha256": "d" * 64, "line_count": 1, "tail": ["fixture"]},
                "up": {"sha256": "d" * 64, "line_count": 1, "tail": ["fixture"]},
                "health": {"status": 200},
                "client": {
                    "command": ["fixture-client", "tests/e2e.js", suffix], "exit_code": 0,
                    "output": {"sha256": "b" * 64},
                    "process_cleanup": {"remaining": 0}, "output_limit_exceeded": False,
                    "receipt": {"schema": "acceptance-client/v1", "passed": True, "fresh_state_token": f"fresh-{suffix}", "state_reset": {"performed": True, "residual": 0}, "case_ids": ["CASE-A", "CASE-B"], "assertions": [{"case_id": "CASE-A", "name": "boundary persists", "passed": True}, {"case_id": "CASE-B", "name": "happy path persists", "passed": True}]},
                },
                "logs": {"sha256": "d" * 64, "line_count": 1, "tail": ["fixture"]},
                "namespace_preflight":{"containers":0,"networks":0,"volumes":0,"images":0},
                "cleanup_command": {"sha256": "c" * 64, "line_count": 1, "tail": ["fixture"]}, "cleanup": {"containers": 0, "networks": 0, "volumes": 0, "images": 0},
            })
            write_json(root / f"run-{suffix.lower()}.json", {
                "run_id": f"RUN-{suffix}", "tested_fingerprint": tested, "candidate_sha256": candidate_sha256, "fresh_state": True, "fresh_state_token": f"fresh-{suffix}",
                "reviewer_agent": roles["integrator"], "cases": ["CASE-A", "CASE-B"], "new_defects": 0,
                "command": ["fixture-client", "tests/e2e.js", suffix], "exit_code": 0, "timestamp": f"2026-07-17T00:0{1 if suffix == 'B' else 0}:00Z",
                "runtime_id": runtime_id, "image_digest": image_digest,
                "state_reset_evidence": {"command": "reset fixture", "exit_code": 0, "residual": 0, "token": f"fresh-{suffix}"},
                "runtime_evidence": f"runtime-{suffix.lower()}.json",
                "runtime_evidence_sha256": digest(root / f"runtime-{suffix.lower()}.json"),
            })

        report = f"""# Fixture

- Tested fingerprint: {tested}
- Fingerprint manifest: fingerprint.sha256
- Fingerprint manifest SHA-256: {tested}
- Acceptance plan: plan.json
- Acceptance plan SHA-256: {digest(root / 'plan.json')}
- Runtime: fixture
- Implementer agent: {roles['implementer']}
- Adversarial reviewer agent: {roles['adversarial']}
- Cross reviewer agent: {roles['cross']}
- Integrator agent: {roles['integrator']}
- Requirements: 2
- Requirement coverage: 100%
- Mandatory cases: 2
- Passed: 2
- Failed: 0
- Blocked: 0
- P0: 0
- P1: 0
- P2: 0
- P3: 0
- P3 disposition: none
- Clean full-chain reruns: 1
- AI recommendation: release
- Human decision: approved
- Human decision source: user:fixture

## Traceability
Plan-backed requirements and cases.
## Runtime evidence
Fresh fixture runtime.
## Scenario results
- Case: CASE-A | Requirement: REQ-A | Status: Pass | Evidence: case-a.json | SHA-256: {digest(root / 'case-a.json')}
- Case: CASE-B | Requirement: REQ-B | Status: Pass | Evidence: case-b.json | SHA-256: {digest(root / 'case-b.json')}
## Adversarial review
Boundary and fault attacks.
## Cross-review
Authoritative adjacent-case review.
## Defects and retest
- Rerun: RUN-A | Evidence: run-a.json | SHA-256: {digest(root / 'run-a.json')}
## Residual risks
Fixture only.
"""
        (root / "report.md").write_text(report, encoding="utf-8")
        if run_gate(root) != 0:
            print("FAIL: valid fixture was rejected")
            return 1

        attacks = {
            "zero-cases": ("- Mandatory cases: 2", "- Mandatory cases: 0"),
            "same-agent": (f"- Cross reviewer agent: {roles['cross']}", "- Cross reviewer agent: /agent/impl#cross"),
            "pending-human": ("- Human decision: approved", "- Human decision: pending"),
            "tampered-hash": (digest(root / "case-a.json"), "0" * 64),
            "missing-rerun-case": ("\"cases\":[\"CASE-A\",\"CASE-B\"]", "\"cases\":[\"CASE-A\"]"),
        }
        original_report = report
        original_run = (root / "run-a.json").read_text(encoding="utf-8")
        for name, (old, new) in attacks.items():
            if name == "missing-rerun-case":
                (root / "run-a.json").write_text(original_run.replace(old, new), encoding="utf-8")
            else:
                (root / "report.md").write_text(original_report.replace(old, new), encoding="utf-8")
            if run_gate(root) == 0:
                print(f"FAIL: adversarial fixture passed: {name}")
                return 1
            (root / "report.md").write_text(original_report, encoding="utf-8")
            (root / "run-a.json").write_text(original_run, encoding="utf-8")

        semantic_attacks = []
        value = copy.deepcopy(case_a); value["lane"] = "happy-path"; semantic_attacks.append(("mismatched-lane", "case-a.json", value))
        value = copy.deepcopy(plan); value["requirements"][0]["source"]["anchor"] = "missing-anchor"; semantic_attacks.append(("fake-requirement-source", "plan.json", value))
        value = copy.deepcopy(plan); value["requirements"][0]["source"]["anchor"] = "#"; semantic_attacks.append(("empty-normalized-anchor", "plan.json", value))
        value = copy.deepcopy(plan); value["scope"]["exclude_paths"] = [
            {"path": "src/app.js", "reason": "fixture attack", "approver": "user:fixture"},
            {"path": "tests/e2e.js", "reason": "fixture attack", "approver": "user:fixture"},
        ]; semantic_attacks.append(("exclude-all-roots", "plan.json", value))
        value = copy.deepcopy(plan); value["scope"]["source_roots"] = [".."]; semantic_attacks.append(("escape-root", "plan.json", value))
        value = copy.deepcopy(case_a); value["attack_types"] = ["foo", "bar"]; semantic_attacks.append(("arbitrary-attacks", "case-a.json", value))
        value = copy.deepcopy(case_b); value["adjacent_case"] = "CASE-B"; semantic_attacks.append(("self-adjacent", "case-b.json", value))
        value = copy.deepcopy(case_b); value["derivation_source"] = {"file": "spec.md", "anchor": "missing"}; semantic_attacks.append(("fake-cross-source", "case-b.json", value))
        value = copy.deepcopy(case_b); value["derivation_source"] = {"file": "spec.md", "anchor": "requirement-a"}; semantic_attacks.append(("cross-source-from-other-requirement", "case-b.json", value))
        value = copy.deepcopy(case_b); value["controlled_field"] = "flow"; semantic_attacks.append(("fake-adjacency", "case-b.json", value))
        value = copy.deepcopy(case_b); value["scenario_vector"]["flow"] = "other-flow"; semantic_attacks.append(("multi-variable-adjacency", "case-b.json", value))
        value = copy.deepcopy(case_b); value["scenario_vector"]["flow"] = " "; semantic_attacks.append(("empty-adjacency-invariant", "case-b.json", value))
        value = copy.deepcopy(plan); value["agents"]["events"][3]["role"] = "cross"; semantic_attacks.append(("out-of-order-ledger", "plan.json", value))
        value = copy.deepcopy(plan); value["agents"]["events"][2], value["agents"]["events"][3] = value["agents"]["events"][3], value["agents"]["events"][2]; value["agents"]["events"][2]["sequence"] = 3; value["agents"]["events"][3]["sequence"] = 4; semantic_attacks.append(("interleaved-phases", "plan.json", value))
        value = copy.deepcopy(plan); value["agents"]["events"][0]["action"] = "finished"; value["agents"]["events"][2]["action"] = "started"; semantic_attacks.append(("reversed-phase-actions", "plan.json", value))
        value = json.loads(original_run); value["fresh_state"] = False; semantic_attacks.append(("fake-fresh", "run-a.json", value))
        value = json.loads(original_run); value["image_digest"] = "sha256:short"; semantic_attacks.append(("short-digest", "run-a.json", value))
        value = json.loads(original_run); value["cases"].append(value["cases"][0]); semantic_attacks.append(("duplicate-rerun-case", "run-a.json", value))
        value = copy.deepcopy(case_b); value["execution_run_ids"].append(value["execution_run_ids"][0]); semantic_attacks.append(("duplicate-execution-run-id", "case-b.json", value))

        originals = {name: (root / name).read_bytes() for name in ("plan.json", "case-a.json", "case-b.json", "run-a.json")}
        for name, filename, value in semantic_attacks:
            target = root / filename
            old_hash = hashlib.sha256(originals[filename]).hexdigest()
            write_json(target, value)
            mutated_report = original_report.replace(old_hash, digest(target))
            (root / "report.md").write_text(mutated_report, encoding="utf-8")
            if run_gate(root) == 0:
                print(f"FAIL: semantic adversarial fixture passed: {name}")
                return 1
            target.write_bytes(originals[filename])
            (root / "report.md").write_text(original_report, encoding="utf-8")

        runtime_original = json.loads((root / "runtime-a.json").read_text(encoding="utf-8"))
        run_original = json.loads(original_run)
        original_run_hash = hashlib.sha256(original_run.encode()).hexdigest()
        runtime_attacks = []
        value = copy.deepcopy(runtime_original); del value["client"]["command"]; runtime_attacks.append(("missing-client-command", value))
        value = copy.deepcopy(runtime_original); value["client"]["receipt"] = None; runtime_attacks.append(("missing-client-receipt", value))
        value = copy.deepcopy(runtime_original); value["client"]["receipt"]["assertions"] = [{"name": "generic", "passed": True}, {"name": "generic two", "passed": True}]; runtime_attacks.append(("receipt-without-case-assertions", value))
        value = copy.deepcopy(runtime_original); value["client"]["receipt"]["assertions"][0]["name"] = "   "; runtime_attacks.append(("receipt-whitespace-assertion", value))
        value = copy.deepcopy(runtime_original); value["client"]["receipt"]["case_ids"].append(value["client"]["receipt"]["case_ids"][0]); runtime_attacks.append(("duplicate-client-case-id", value))
        value = copy.deepcopy(runtime_original); value["client"]["process_cleanup"] = {"remaining": 1}; runtime_attacks.append(("client-process-residual", value))
        value = copy.deepcopy(runtime_original); value["client"]["output_limit_exceeded"] = True; runtime_attacks.append(("client-output-truncated", value))
        value = copy.deepcopy(runtime_original); value["client"]["command"] = ["fixture-client"]; runtime_attacks.append(("client-without-fingerprinted-test", value))
        value = copy.deepcopy(runtime_original); value["containers"] = [1]; runtime_attacks.append(("non-object-container", value))
        value = copy.deepcopy(runtime_original); value["loaded_image_id"] = "sha256:"+"b"*64; runtime_attacks.append(("loaded-image-substitution", value))
        value = copy.deepcopy(runtime_original); value["blueprint_sha256"] = "e"*64; runtime_attacks.append(("blueprint-authority-substitution", value))
        value = copy.deepcopy(runtime_original); value["candidate_services"] = []; runtime_attacks.append(("missing-candidate-service", value))
        value = copy.deepcopy(runtime_original); value["application_services"] = ["dummy"]; runtime_attacks.append(("governed-service-substitution", value))
        value = copy.deepcopy(runtime_original); value["containers"][0]["image"] = "sha256:"+"b"*64; runtime_attacks.append(("prebuilt-service-substitution", value))
        value = copy.deepcopy(runtime_original); value["health"] = {}; runtime_attacks.append(("missing-runtime-health", value))
        value = copy.deepcopy(runtime_original); value["source_after"]["sha256"] = "different"; runtime_attacks.append(("runtime-source-changed", value))
        value = copy.deepcopy(runtime_original); value["candidate_sha256"] = "e" * 64; runtime_attacks.append(("stale-runtime-candidate", value))
        for name, runtime_value in runtime_attacks:
            write_json(root / "runtime-a.json", runtime_value)
            run_value = copy.deepcopy(run_original)
            run_value["runtime_evidence_sha256"] = digest(root / "runtime-a.json")
            write_json(root / "run-a.json", run_value)
            mutated_report = original_report.replace(original_run_hash, digest(root / "run-a.json"))
            (root / "report.md").write_text(mutated_report, encoding="utf-8")
            if run_gate(root) == 0:
                print(f"FAIL: runtime adversarial fixture passed: {name}")
                return 1
        write_json(root / "runtime-a.json", runtime_original)
        (root / "run-a.json").write_text(original_run, encoding="utf-8")
        (root / "report.md").write_text(original_report, encoding="utf-8")

        print(f"PASS: acceptance gate positive fixture and {len(attacks) + len(semantic_attacks) + len(runtime_attacks)} adversarial fixtures")
        return 0


if __name__ == "__main__":
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"scripts"))
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
