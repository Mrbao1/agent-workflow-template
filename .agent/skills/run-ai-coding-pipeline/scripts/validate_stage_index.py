#!/usr/bin/env python3
"""Validate STAGE_INDEX as a bounded projection of canonical TASK.json."""

from pathlib import Path
import argparse
import json
import re
from typing import Dict, List


FIELDS = ("Pipeline version", "Task", "Task type", "Complexity", "Mode", "Current node", "Status",
          "Last accepted node", "Release gate", "Release gate reason", "Next action", "Updated")
HEADINGS = ("Input provenance", "Assumptions requiring confirmation", "Gate status", "Rollback ledger", "Canonical outputs")


def occurrences(text: str, field: str) -> List[str]:
    return [value.strip(" `") for value in re.findall(rf"^- {re.escape(field)}:\s*(.+?)\s*$", text, re.MULTILINE)]


def nonempty(text: str, heading: str) -> bool:
    match = re.search(rf"^## {re.escape(heading)}\s*$\n(?P<body>.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    return bool(match and re.sub(r"<!--.*?-->|```.*?```", "", match.group("body"), flags=re.DOTALL).strip())


def expected(task: Dict[str, object]) -> Dict[str, str]:
    accepted = task.get("accepted_nodes", [])
    last = str(max(accepted)) if isinstance(accepted, list) and accepted else "none"
    mode = str(task.get("mode"))
    gate = "required" if mode == "release" else "not_applicable"
    reason = "strict release gate is required for release mode" if mode == "release" else f"{mode} mode uses targeted acceptance and has no release live gate"
    return {"Pipeline version": "2.0", "Task": str(task.get("title")), "Task type": str(task.get("task_type")),
            "Complexity": str(task.get("complexity")), "Mode": mode, "Current node": str(task.get("current_node")),
            "Status": str(task.get("status")), "Last accepted node": last, "Release gate": gate,
            "Release gate reason": reason, "Next action": str(task.get("next_action")), "Updated": str(task.get("updated"))}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("stage", nargs="?", default=".agent/state/STAGE_INDEX.md"); parser.add_argument("--task")
    args = parser.parse_args(); stage = Path(args.stage); task_path = Path(args.task) if args.task else stage.with_name("TASK.json")
    if not stage.is_file() or not task_path.is_file():
        print("INVALID stage index\n- stage or canonical task is missing"); return 1
    text = stage.read_text(encoding="utf-8"); task = json.loads(task_path.read_text(encoding="utf-8")); errors: List[str] = []
    values: Dict[str, str] = {}
    for field in FIELDS:
        found = occurrences(text, field); values[field] = found[0] if found else ""
        if len(found) != 1: errors.append(f"field must occur exactly once: {field}")
    for heading in HEADINGS:
        if not nonempty(text, heading): errors.append(f"missing or empty heading: ## {heading}")
    for field, value in expected(task).items():
        if values.get(field) != value: errors.append(f"{field} drifted from TASK.json")
    accepted = task.get("accepted_nodes", [])
    if not isinstance(accepted, list) or accepted != sorted(set(accepted)): errors.append("TASK accepted_nodes is invalid")
    if errors:
        print("INVALID stage index")
        for error in errors: print(f"- {error}")
        return 1
    print(f"VALID TASK-derived stage index: {stage}"); return 0


if __name__ == "__main__": raise SystemExit(main())
