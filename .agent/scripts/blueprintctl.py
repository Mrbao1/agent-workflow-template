#!/usr/bin/env python3
"""Manage the user-authored project design that gates adaptive Skill selection."""
from pathlib import Path
import argparse
import os
import signal
import subprocess
import time
import uuid

import testrun
from adaptive_common import (
    AdaptiveError, blueprint_path, canonical_sha256, fail, load_blueprint, load_json,
    mutation_lock, print_json, record_provider_human_decision, resolve_root, utc_now, validate_blueprint, validate_design, write_json,
)


def empty_blueprint():
    return {
        "schema": "agent-project-blueprint/v1",
        "status": "draft",
        "design": {
            "goals": [],
            "architecture": [],
            "technology_choices": [],
            "capabilities": [],
            "constraints": [],
            "acceptance": [],
            "commands": [],
            "providers": [],
        },
        "suggestions": [],
        "confirmation": None,
    }


def explicit_user_source(value):
    if not isinstance(value, str) or not value.startswith("user:") or not value[5:].strip():
        raise AdaptiveError("USER_CONFIRMATION_REQUIRED", "source must be an explicit user:<decision> record")
    return value


def command_init(root, args):
    path = blueprint_path(root)
    if path.exists():
        existing = load_blueprint(root)
        if not args.force or existing["status"] == "confirmed":
            raise AdaptiveError("BLUEPRINT_EXISTS", f"blueprint already exists: {path}; reopen a confirmed blueprint before replacement")
    write_json(path, empty_blueprint())
    print(f"BLUEPRINT_DRAFT_CREATED: {path}")
    return 0


def command_import(root, args):
    target = blueprint_path(root)
    if target.exists() and load_blueprint(root)["status"] == "confirmed":
        raise AdaptiveError("BLUEPRINT_EXISTS", "reopen the confirmed blueprint before importing a draft")
    value = validate_blueprint(load_json(Path(args.input).resolve(), "blueprint import"))
    if value["status"] != "draft":
        raise AdaptiveError("INVALID_BLUEPRINT", "import accepts an unconfirmed draft only")
    write_json(blueprint_path(root), value)
    print("BLUEPRINT_DRAFT_IMPORTED")
    return 0


def command_check(root, args):
    value = load_blueprint(root, require_confirmed=args.require_confirmed)
    if args.expect_design_sha256 and (value["status"] != "confirmed" or value["confirmation"]["design_sha256"] != args.expect_design_sha256):
        raise AdaptiveError("BLUEPRINT_EXPECTATION_MISMATCH", "blueprint does not match the expected confirmed design")
    design_sha = canonical_sha256(value["design"])
    print_json({
        "schema": "agent-project-blueprint-status/v1",
        "status": value["status"],
        "design_sha256": design_sha,
        "confirmed": value["status"] == "confirmed",
        "technology_choice_count": len(value["design"]["technology_choices"]),
        "capability_count": len(value["design"]["capabilities"]),
        "command_count": len(value["design"]["commands"]),
        "suggestions_are_authority": False,
    })
    return 0


def command_confirm(root, args):
    source = explicit_user_source(args.source)
    value = load_blueprint(root)
    if value["status"] != "draft":
        raise AdaptiveError("BLUEPRINT_ALREADY_CONFIRMED", "reopen before replacing a confirmed design")
    design = validate_design(value["design"], require_material=True)
    design_sha256 = canonical_sha256(design)
    decision_receipt = record_provider_human_decision(
        root, gate="adaptive-blueprint-confirm", artifact_sha256=design_sha256,
        source=source, receipt=args.human_decision_receipt,
    )
    confirmed = {
        "schema": value["schema"],
        "status": "confirmed",
        "design": design,
        "suggestions": value["suggestions"],
        "confirmation": {
            "source": source,
            "design_sha256": design_sha256,
            "confirmed_at": utc_now(),
            "decision_receipt": decision_receipt,
        },
    }
    validate_blueprint(confirmed, require_confirmed=True)
    write_json(blueprint_path(root), confirmed)
    print(f"BLUEPRINT_CONFIRMED: sha256={confirmed['confirmation']['design_sha256']}")
    return 0


def command_reopen(root, args):
    source = explicit_user_source(args.source)
    value = load_blueprint(root, require_confirmed=True)
    action = {"action": "reopen-blueprint", "design_sha256": value["confirmation"]["design_sha256"], "source": source}
    action_sha256 = canonical_sha256(action)
    decision_receipt = record_provider_human_decision(
        root, gate="adaptive-blueprint-reopen", artifact_sha256=action_sha256,
        source=source, receipt=args.human_decision_receipt,
    )
    history = root / ".agent/project/blueprint-history" / f"{value['confirmation']['design_sha256']}.json"
    if not history.exists():
        write_json(history, value)
    events_path = root / ".agent/project/blueprint-events.json"
    events = load_json(events_path, "blueprint events") if events_path.exists() else {"schema": "agent-blueprint-events/v1", "events": []}
    if not isinstance(events, dict) or set(events) != {"schema", "events"} or events.get("schema") != "agent-blueprint-events/v1" or not isinstance(events.get("events"), list) or len(events["events"]) > 256:
        raise AdaptiveError("INVALID_BLUEPRINT_EVENTS", "blueprint event ledger is invalid", 3)
    events["events"].append({**action, "action_sha256": action_sha256, "decision_receipt": decision_receipt, "recorded_at": utc_now()})
    draft = {
        "schema": value["schema"], "status": "draft", "design": value["design"],
        "suggestions": value["suggestions"], "confirmation": None,
    }
    write_json(events_path, events)
    write_json(blueprint_path(root), draft)
    print("BLUEPRINT_REOPENED: dynamic Skills are inactive until the revised design is confirmed")
    return 0


def command_show(root, _args):
    print_json(load_blueprint(root))
    return 0


def stop_process_group(process,known,launch_token):
    cleaned,uncertain=testrun.terminate_process_tree(
        process,known,grace=2.0,launch_token=launch_token)
    if not cleaned or uncertain: raise AdaptiveError("COMMAND_CLEANUP_UNCERTAIN","could not prove exact Blueprint command process cleanup",3)


def command_run(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    if args.expect_design_sha256 and blueprint["confirmation"]["design_sha256"] != args.expect_design_sha256:
        raise AdaptiveError("BLUEPRINT_EXPECTATION_MISMATCH", "command does not match the expected confirmed design")
    command = next((item for item in blueprint["design"]["commands"] if item["id"] == args.id), None)
    if command is None:
        raise AdaptiveError("UNKNOWN_COMMAND", f"confirmed blueprint has no command {args.id!r}")
    if args.stage and command["stage"] != args.stage:
        raise AdaptiveError("COMMAND_STAGE_MISMATCH", f"command {args.id!r} is not in stage {args.stage!r}")
    # Re-read under the shared mutation lock immediately before launch.
    current = load_blueprint(root, require_confirmed=True)
    if (current["confirmation"]["design_sha256"] != blueprint["confirmation"]["design_sha256"]
            or next((item for item in current["design"]["commands"] if item["id"] == args.id), None) != command):
        raise AdaptiveError("BLUEPRINT_DRIFT", "confirmed blueprint changed before command launch", 3)
    environment = {"PATH": os.defpath}
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    for name in command.get("environment", []):
        if name not in os.environ:
            raise AdaptiveError("COMMAND_ENVIRONMENT_MISSING", f"command {args.id!r} requires unavailable environment variable {name}")
        environment[name] = os.environ[name]
    launch_token=uuid.uuid4().hex; environment[testrun.LAUNCH_TOKEN_NAME]=launch_token
    if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
        raise AdaptiveError("COMMAND_PROCESS_OBSERVER_UNAVAILABLE","default SIGCHLD ownership is required",3)
    try:
        process = subprocess.Popen(command["argv"], cwd=root, shell=False, start_new_session=True,
                                   stdin=subprocess.DEVNULL, env=environment)
    except OSError as error:
        raise AdaptiveError("COMMAND_START_FAILED", f"could not start {args.id!r}: {error}") from error
    known={}; deadline=time.monotonic()+command["timeout_seconds"]; cleanup_attempted=False
    timed_out=False; leader_identity=None
    try:
        while True:
            snapshot=testrun.process_snapshot()
            if snapshot is None: raise AdaptiveError("COMMAND_PROCESS_OBSERVER_UNAVAILABLE","process identity snapshot failed",3)
            leader=snapshot.get(process.pid)
            if leader is not None:
                if leader_identity is None: leader_identity=leader[2]; known[process.pid]=leader_identity
                elif leader[2]!=leader_identity: raise AdaptiveError("COMMAND_PROCESS_OBSERVER_UNAVAILABLE","leader identity changed",3)
            testrun.discover_descendants(process.pid,known,snapshot)
            if leader is None or leader[3].startswith("Z"): break
            if time.monotonic()>=deadline: timed_out=True; break
            time.sleep(0.05)
        cleanup_attempted=True; stop_process_group(process,known,launch_token)
        return_code=int(process.returncode if process.returncode is not None else 125)
    except BaseException:
        if not cleanup_attempted: stop_process_group(process,known,launch_token)
        raise
    if timed_out:
        print(f"BLUEPRINT_COMMAND_TIMEOUT: id={args.id} timeout={command['timeout_seconds']}")
        return 124
    print(f"BLUEPRINT_COMMAND_FINISHED: id={args.id} exit={return_code}")
    return return_code


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--root")
    sub = value.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init"); init.add_argument("--force", action="store_true")
    imported = sub.add_parser("import"); imported.add_argument("--input", required=True)
    check = sub.add_parser("check"); check.add_argument("--require-confirmed", action="store_true"); check.add_argument("--expect-design-sha256")
    confirm = sub.add_parser("confirm"); confirm.add_argument("--source", required=True); confirm.add_argument("--human-decision-receipt")
    reopen = sub.add_parser("reopen"); reopen.add_argument("--source", required=True); reopen.add_argument("--human-decision-receipt")
    sub.add_parser("show")
    run = sub.add_parser("run-command"); run.add_argument("--id", required=True); run.add_argument("--stage", choices=("design", "development", "acceptance", "ci")); run.add_argument("--expect-design-sha256")
    return value


def main():
    args = parser().parse_args()
    try:
        root = resolve_root(args.root, __file__)
        handlers = {
            "init": command_init, "import": command_import, "check": command_check,
            "confirm": command_confirm, "reopen": command_reopen, "show": command_show,
            "run-command": command_run,
        }
        if args.command in {"init", "import", "confirm", "reopen", "run-command"}:
            with mutation_lock(root):
                return handlers[args.command](root, args)
        return handlers[args.command](root, args)
    except Exception as error:
        return fail(error)


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
