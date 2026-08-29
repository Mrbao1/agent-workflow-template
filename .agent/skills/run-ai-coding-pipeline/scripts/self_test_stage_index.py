#!/usr/bin/env python3
"""Prove STAGE_INDEX is a read-only, deterministic TASK projection."""

from pathlib import Path
import copy
import json
import subprocess
import sys
import tempfile


VALIDATOR = Path(__file__).with_name("validate_stage_index.py").resolve()


def stage(task: dict[str, object]) -> str:
    accepted = task["accepted_nodes"]
    last = max(accepted) if accepted else "none"
    mode = str(task["mode"])
    gate = "required" if mode == "release" else "not_applicable"
    reason = "strict release gate is required for release mode" if mode == "release" else f"{mode} mode uses targeted acceptance and has no release live gate"
    return f"""# AI Coding Stage Index

- Pipeline version: 2.0
- Task: {task['title']}
- Task type: {task['task_type']}
- Complexity: {task['complexity']}
- Mode: {mode}
- Current node: {task['current_node']}
- Status: {task['status']}
- Last accepted node: {last}
- Release gate: {gate}
- Release gate reason: {reason}
- Next action: {task['next_action']}
- Updated: {task['updated']}

## Input provenance

- Requirement source: {task['requirement_source']}

## Assumptions requiring confirmation

- None.

## Gate status

- Requirement clarified: {str(task['requirements_clarified']).lower()}

## Rollback ledger

- Entries: {len(task['rollback_ledger'])}

## Canonical outputs

- `.agent/state/TASK.json`
"""


def valid(stage_path: Path, task_path: Path) -> bool:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(stage_path), "--task", str(task_path)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    ).returncode == 0


def main() -> int:
    task: dict[str, object] = {
        "schema": "agent-task/v2", "title": "fixture", "task_type": "maintenance",
        "complexity": "bounded", "mode": "standard", "current_node": "idle", "status": "accepted",
        "accepted_nodes": list(range(8)), "next_action": "start the next requirement in clarification",
        "updated": "2026-07-17", "requirement_source": "user:fixture", "requirements_clarified": True,
        "rollback_ledger": [], "node_artifacts": {}, "open_questions": [], "gate_approvals": {},
    }
    with tempfile.TemporaryDirectory(prefix="stage-index-") as raw:
        root = Path(raw)
        stage_path, task_path = root / "STAGE_INDEX.md", root / "TASK.json"
        task_path.write_text(json.dumps(task), encoding="utf-8")
        stage_path.write_text(stage(task), encoding="utf-8")
        if not valid(stage_path, task_path):
            print("FAIL: valid TASK projection was rejected")
            return 1

        attacks = {
            "detached-status": stage(task).replace("- Status: accepted", "- Status: in_progress"),
            "detached-current": stage(task).replace("- Current node: idle", "- Current node: 7"),
            "detached-last": stage(task).replace("- Last accepted node: 7", "- Last accepted node: 6"),
            "detached-next": stage(task).replace("start the next requirement", "silently deploy"),
            "duplicate-status": stage(task).replace("- Status: accepted", "- Status: accepted\n- Status: accepted"),
            "comment-heading": stage(task).replace("## Gate status", "<!-- ## Gate status -->"),
        }
        for name, body in attacks.items():
            stage_path.write_text(body, encoding="utf-8")
            if valid(stage_path, task_path):
                print(f"FAIL: detached stage passed: {name}")
                return 1

        # TASK changes invalidate the old projection even if STAGE itself is untouched.
        stage_path.write_text(stage(task), encoding="utf-8")
        drifted = copy.deepcopy(task)
        drifted["status"] = "in_progress"
        drifted["current_node"] = 7
        drifted["next_action"] = "accept"
        task_path.write_text(json.dumps(drifted), encoding="utf-8")
        if valid(stage_path, task_path):
            print("FAIL: a TASK mutation did not invalidate STAGE")
            return 1

        # Release validation is structural and must not execute a heavy live gate.
        release = copy.deepcopy(task)
        release.update({"mode": "release", "status": "in_progress", "current_node": 6,
                        "accepted_nodes": list(range(6)), "next_action": "complete node 6"})
        task_path.write_text(json.dumps(release), encoding="utf-8")
        stage_path.write_text(stage(release), encoding="utf-8")
        if not valid(stage_path, task_path):
            print("FAIL: release TASK projection was rejected without a live replay")
            return 1

    print(f"PASS: TASK-derived stage projection and {len(attacks) + 2} drift attacks")
    return 0


if __name__ == "__main__":
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"scripts"))
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
