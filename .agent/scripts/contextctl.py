#!/usr/bin/env python3
"""Create and validate one bounded, integrity-linked task context capsule."""

from pathlib import Path
import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
from typing import Dict, List, Optional, Tuple

def _reject_nonfinite_json(token):
    raise json.JSONDecodeError(f"non-finite JSON number is forbidden: {token}",token,0)

def strict_json_loads(raw,**kwargs):
    return json.loads(raw,parse_constant=_reject_nonfinite_json,**kwargs)

def strict_json_dumps(value,**kwargs):
    kwargs["allow_nan"]=False
    return json.dumps(value,**kwargs)


import humandecision
from workflowlib import boundedio
from workflowlib import budget as total_budget

# Capture handoff arrival before imports/validation can queue behind loaded -jN hosts.
# The 60-second TTL still applies to producer-to-consumer process startup.
PROCESS_STARTED_AT = dt.datetime.now(dt.timezone.utc)


def find_agent_dir() -> Path:
    current = Path.cwd().resolve()
    for root in (current, *current.parents):
        candidate = root / ".agent"
        if candidate.is_dir():
            return candidate
    raise SystemExit(".agent directory not found")


AGENT_DIR = find_agent_dir()
ROOT = AGENT_DIR.parent.resolve()
CONFIG_PATH = AGENT_DIR / "config.json"
TASK_PATH = AGENT_DIR / "state" / "TASK.json"
CONTRACT_PATH = AGENT_DIR / "state" / "REQUIREMENT_CONTRACT.md"
CONTEXT_PATH = AGENT_DIR / "state" / "CONTEXT.json"
LOCK_PATH = AGENT_DIR / "state" / ".context.lock"
AUTH_DIR = AGENT_DIR / "state" / ".context-authorizations"
LIST_FIELDS = ("confirmed_facts", "decisions", "open_questions", "changed_files", "evidence", "open_risks")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UNAPPROVED_CONTRACT_BINDING = "unapproved-draft"
TURN_ACCOUNTING_SCHEMA = "agent-context-turn-accounting/v1"
MAX_ACCOUNTED_TURN_IDS = 64

# This snapshot binds the enumerated canonical TASK fields: scope, routing,
# evidence, gates, rollback behavior, resource budgets and completion
# semantics.  "projection" is bound only when the field is present on TASK, so
# capsules sealed before the field existed keep their historical digests.
# Top-level fields outside this list are NOT integrity-bound: a canonical
# transition commits them wholesale and records their changed field names in
# the transition authorization receipt for audit (see authorization_receipt).
TASK_INVARIANT_KEYS = (
    "schema",
    "task_generation_id",
    "selected_model",
    "completed_model",
    "title",
    "task_type",
    "complexity",
    "mode",
    "files",
    "environment",
    "deployment_requested",
    "branch",
    "status",
    "phase",
    "requirements_clarified",
    "requirement_source",
    "requirement_contract",
    "requirement_contract_sha256",
    "primary_skill",
    "skill_activation",
    "risk_flags",
    "token_budget",
    "tokens_used",
    "token_usage_source",
    "usage_receipt",
    "usage_receipts",
    "budget_state",
    "child_agents_used",
    "peak_child_agents",
    "loaded_references",
    "selected_templates",
    "selected_capabilities",
    "template_route",
    "rendered_artifacts",
    "decisions",
    "open_questions",
    "next_action",
    "current_node",
    "accepted_nodes",
    "node_artifacts",
    "gate_approvals",
    "pending_gate_artifacts",
    "decision_packet",
    "rollback_ledger",
    "rollback_archive",
    "failure_ledger",
    "failure_archive",
    "failure_escalation",
    "mode_status",
    "decision_policy_version",
    "projection",
    "task_archive",
    "metrics",
    "retrospective",
    "knowledge_candidates",
    "completion_binding",
    "route_archive",
    "clarification_archive",
    "updated",
)

# Canonical mutators may change only these top-level TASK invariants in one
# transition.  A context transition without one of these field-level profiles
# is rejected even when the caller knows the previous public checkpoint hash.
TRANSITION_PROFILES = {
    ("agentctl", "start"): set(TASK_INVARIANT_KEYS),
    ("agentctl", "approve-requirements"): {
        "requirements_clarified", "requirement_source", "requirement_contract",
        "requirement_contract_sha256", "status", "phase", "primary_skill",
        "open_questions", "next_action", "current_node", "accepted_nodes",
        "mode_status", "gate_approvals", "node_artifacts", "budget_state", "updated",
    },
    ("agentctl", "record-usage"): {
        "tokens_used", "token_usage_source", "usage_receipt", "usage_receipts",
        "budget_state", "child_agents_used", "peak_child_agents", "metrics", "updated",
    },
    ("agentctl", "record-metric"): {"metrics", "budget_state"},
    ("agentctl", "auto-metric"): {"metrics", "budget_state"},
    ("agentledger", "register"): {
        "child_agents_used", "peak_child_agents", "metrics", "budget_state", "updated",
    },
    ("agentctl", "reference-load"): {"loaded_references", "budget_state"},
    ("agentctl", "reference-unload"): {
        "loaded_references", "tokens_used", "token_usage_source", "metrics", "budget_state",
    },
    ("agentctl", "escalate-mode"): {
        "mode", "risk_flags", "files", "token_budget", "decision_policy_version",
        "projection", "requirement_source",
        "selected_templates", "selected_capabilities", "template_route",
        "rendered_artifacts", "current_node", "accepted_nodes", "node_artifacts",
        "gate_approvals", "pending_gate_artifacts", "status", "phase",
        "mode_status", "next_action", "route_archive", "budget_state", "updated",
    },
    ("agentctl", "reopen-clarification"): {
        "requirements_clarified", "requirement_source", "requirement_contract",
        "requirement_contract_sha256", "task_generation_id", "primary_skill", "skill_activation", "selected_templates",
        "selected_capabilities", "template_route", "rendered_artifacts", "status",
        "phase", "current_node", "accepted_nodes", "node_artifacts", "gate_approvals",
        "pending_gate_artifacts", "decision_packet", "open_questions", "next_action",
        "mode_status", "clarification_archive", "budget_state", "updated",
    },
    ("templatectl", "route"): {
        "selected_templates", "selected_capabilities", "template_route", "rendered_artifacts",
        "next_action",
    },
    ("templatectl", "render"): {"rendered_artifacts"},
    ("workflowctl", "submit-gate"): {
        "pending_gate_artifacts", "gate_approvals", "decision_packet", "status", "next_action",
    },
    ("workflowctl", "approve-gate"): {
        "gate_approvals", "decision_packet", "status", "next_action",
    },
    ("workflowctl", "advance"): {
        "node_artifacts", "accepted_nodes", "current_node", "status", "phase", "next_action",
        "failure_escalation", "gate_approvals",
    },
    ("workflowctl", "return-node"): {
        "current_node", "status", "phase", "next_action", "accepted_nodes",
        "node_artifacts", "rollback_ledger", "rollback_archive", "failure_ledger",
        "failure_archive", "failure_escalation",
    },
    ("workflowctl", "resolve-failure"): {
        "gate_approvals", "failure_escalation", "status", "next_action",
    },
    ("workflowctl", "compact-state"): {
        "rollback_ledger", "rollback_archive", "failure_ledger", "failure_archive",
    },
    ("workflowctl", "complete-task"): {
        "retrospective", "knowledge_candidates", "current_node", "status", "phase", "next_action",
        "completion_binding", "selected_model", "completed_model",
    },
}


def load_json(path: Path) -> Dict[str, object]:
    value = strict_json_loads(boundedio.read_text(path,label="context JSON"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON object required: {path}")
    return value


def atomic_json(path: Path, value: Dict[str, object]) -> None:
    data=(strict_json_dumps(value,ensure_ascii=False,indent=2)+"\n").encode("utf-8")
    try: boundedio.atomic_write(path,data,mode=0o600,label="context capsule")
    except RuntimeError as error: raise SystemExit(str(error)) from error


def contract_sha256() -> str:
    return hashlib.sha256(boundedio.read_bytes(CONTRACT_PATH,label="requirement contract")).hexdigest() if CONTRACT_PATH.is_file() else "missing"


def governed_contract_binding(task: Dict[str, object]) -> str:
    """Bind approved bytes exactly while treating clarification text as a draft.

    Before the human requirement gate, the single contract file is expected to
    change repeatedly.  Its bytes have no decision authority and therefore must
    not make an otherwise valid context capsule drift.  The approval transition
    flips requirements_clarified and atomically installs the final bytes, at
    which point their SHA-256 becomes strict canonical state.
    """
    if task.get("requirements_clarified") is not True:
        return UNAPPROVED_CONTRACT_BINDING
    return contract_sha256()


def task_invariant(task: Dict[str, object]) -> Dict[str, object]:
    snapshot = {key: copy.deepcopy(task.get(key)) for key in TASK_INVARIANT_KEYS if key != "projection"}
    if "projection" in task:
        snapshot["projection"] = copy.deepcopy(task.get("projection"))
    return snapshot


def object_sha256(value: object) -> str:
    encoded = strict_json_dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


MAX_POLICY_ENTRIES=32768
MAX_POLICY_FILES=8192
MAX_POLICY_FILE_BYTES=16*1024*1024


def bounded_policy_tree(base: Path,label: str,state):
    stack=[base]
    while stack:
        directory=stack.pop()
        with os.scandir(directory) as scanner:
            batch=[]
            for entry in scanner:
                state["entries"]+=1
                if state["entries"]>MAX_POLICY_ENTRIES: raise SystemExit(f"{label} entry limit exceeded")
                batch.append(entry)
        for entry in sorted(batch,key=lambda item:os.fsencode(item.name),reverse=True):
            metadata=entry.stat(follow_symlinks=False); path=Path(entry.path)
            if stat.S_ISLNK(metadata.st_mode): raise SystemExit(f"{label} contains a symlink: {path.relative_to(ROOT)}")
            if stat.S_ISDIR(metadata.st_mode): stack.append(path); continue
            if not stat.S_ISREG(metadata.st_mode): raise SystemExit(f"{label} contains a special file: {path.relative_to(ROOT)}")
            state["files"]+=1
            if state["files"]>MAX_POLICY_FILES: raise SystemExit(f"{label} file limit exceeded")
            yield path


def bounded_policy_digest(path: Path) -> str:
    try: return boundedio.sha256(path,maximum=MAX_POLICY_FILE_BYTES,label="policy bundle file")
    except RuntimeError as error: raise SystemExit(str(error)) from error


POLICY_BUNDLE_VERSION = "policy-bundle/v2"
LEGACY_POLICY_BUNDLE_VERSION = "policy-bundle/v1"


def policy_bundle_sha256(task: Dict[str, object], version: str = POLICY_BUNDLE_VERSION) -> str:
    """Bind the active checkpoint to config, index, workflow and Skill rules.

    policy-bundle/v2 additionally binds the enforcement code
    (`.agent/scripts/**.py`, the primary skill's `scripts/**` and
    `references/**`) and `policies/PROJECT_GUARDRAILS.md`, so editing a script
    or the guardrails is policy drift, not a silent change.  Missing or
    symlinked bundle files fail closed in every version.
    """
    if version not in {POLICY_BUNDLE_VERSION, LEGACY_POLICY_BUNDLE_VERSION}:
        raise SystemExit(f"unknown policy bundle version: {version}")
    paths=[CONFIG_PATH,AGENT_DIR/"INDEX.md",AGENT_DIR/"templates/manifest.json"]
    primary=str(task.get("primary_skill","")); traversal={"entries":0,"files":0}
    if primary: paths.append(AGENT_DIR/"skills"/primary/"SKILL.md")
    workflows=AGENT_DIR/"workflows"
    paths.extend(sorted(bounded_policy_tree(workflows,"workflow policy inventory",traversal),key=lambda path:path.relative_to(workflows).as_posix().encode()))
    if version==POLICY_BUNDLE_VERSION:
        paths.append(AGENT_DIR/"policies"/"PROJECT_GUARDRAILS.md")
        scripts=AGENT_DIR/"scripts"
        script_files=[path for path in bounded_policy_tree(scripts,"script policy inventory",traversal) if path.suffix==".py"]
        paths.extend(sorted(script_files,key=lambda path:path.relative_to(scripts).as_posix().encode()))
        if primary:
            for name in ("scripts","references"):
                base=AGENT_DIR/"skills"/primary/name
                if base.is_dir() and not base.is_symlink():
                    paths.extend(sorted(bounded_policy_tree(base,f"primary Skill {name} inventory",traversal),key=lambda path:path.relative_to(base).as_posix().encode()))
    entries = []
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"policy bundle file is missing or unsafe: {path.relative_to(ROOT)}")
        entries.append({"path":str(path.relative_to(ROOT)),"sha256":bounded_policy_digest(path)})
    if version == LEGACY_POLICY_BUNDLE_VERSION:
        return object_sha256(entries)
    return object_sha256({"version": version, "files": entries})


def invariant_sha256(task: Dict[str, object]) -> str:
    return object_sha256(task_invariant(task))


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def normalized_token_estimate(value: Dict[str, object]) -> int:
    clone = copy.deepcopy(value)
    compaction = clone.get("compaction")
    if isinstance(compaction, dict):
        for key in (
            "source_estimated_tokens", "capsule_estimated_tokens",
            "tokens_removed", "capsule_reduction_tokens", "compression_ratio",
        ):
            compaction[key] = 0
    integrity = clone.get("integrity")
    if isinstance(integrity, dict):
        integrity["content_sha256"] = "0" * 64
    encoded = strict_json_dumps(clone, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return (len(encoded) + 3) // 4


def content_sha256(value: Dict[str, object]) -> str:
    clone = copy.deepcopy(value)
    integrity = clone.get("integrity")
    if isinstance(integrity, dict):
        integrity["content_sha256"] = "0" * 64
    return object_sha256(clone)


def authorization_receipt(
    raw: str,
    args: argparse.Namespace,
    previous: Dict[str, object],
    current_task: Dict[str, object],
) -> Tuple[Dict[str, object], Dict[str, object]]:
    path = (ROOT / raw).resolve()
    try:
        path.relative_to(AUTH_DIR.resolve())
    except ValueError:
        raise SystemExit("context transition authorization must stay in the private authorization directory")
    if not path.is_file() or path.is_symlink():
        raise SystemExit("context transition authorization is missing or is a symlink")
    value = load_json(path)
    required = {
        "schema", "mutator", "operation", "reason", "issued_at", "from_task_sha256",
        "to_task_sha256", "changed_fields", "before_task", "after_task",
    }
    if set(value) != required or value.get("schema") != "agent-context-transition-authorization/v1":
        raise SystemExit("context transition authorization schema is invalid")
    try:
        issued = dt.datetime.fromisoformat(str(value.get("issued_at")))
        if issued.tzinfo is None:
            raise ValueError("timezone required")
        issued_utc=issued.astimezone(dt.timezone.utc)
        now=dt.datetime.now(dt.timezone.utc)
        # A contextctl child normally starts after contexttx sealed the receipt.
        # Measure freshness at that handoff boundary, not after slow policy/hash
        # validation.  Direct in-process callers that predate the receipt retain
        # validation-time freshness, so this cannot extend a pre-created lease.
        observed=PROCESS_STARTED_AT if PROCESS_STARTED_AT>=issued_utc else now
        age=(observed-issued_utc).total_seconds()
        if age < -5 or age > 60:
            raise ValueError("authorization is stale")
    except (TypeError, ValueError):
        raise SystemExit("context transition authorization timestamp is invalid or stale")
    before, after = value.get("before_task"), value.get("after_task")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise SystemExit("context transition authorization lacks before/after TASK states")
    before_hash, after_hash = invariant_sha256(before), invariant_sha256(after)
    expected_from = str(previous.get("task_invariant_sha256", ""))
    if (
        value.get("reason") != args.reason
        or value.get("from_task_sha256") != before_hash
        or value.get("to_task_sha256") != after_hash
        or before_hash != expected_from
        or after_hash != invariant_sha256(current_task)
        or task_invariant(after) != task_invariant(current_task)
    ):
        raise SystemExit("context transition authorization does not bind the exact old/new canonical TASK")
    actual = sorted(
        key for key in TASK_INVARIANT_KEYS
        if task_invariant(before).get(key) != task_invariant(after).get(key)
    )
    if not actual or value.get("changed_fields") != actual:
        raise SystemExit("context transition authorization changed-field receipt is stale")
    profile = (str(value.get("mutator")), str(value.get("operation")))
    allowed = TRANSITION_PROFILES.get(profile)
    if allowed is None or not set(actual).issubset(allowed):
        raise SystemExit(f"context transition fields exceed canonical mutator profile {profile}: {actual}")
    # Non-invariant top-level changes are committed wholesale by the canonical
    # mutator; record their field names for audit without blocking them.
    non_invariant = sorted(
        key for key in set(before) | set(after)
        if key not in TASK_INVARIANT_KEYS and before.get(key) != after.get(key)
    )
    receipt = {
        "schema": value["schema"],
        "mutator": profile[0],
        "operation": profile[1],
        "changed_fields": actual,
        "non_invariant_changed_fields": non_invariant,
        "receipt_sha256": hashlib.sha256(boundedio.read_bytes(path,label="context receipt")).hexdigest(),
    }
    return receipt, before


def list_value(value: object) -> List[str]:
    if not isinstance(value, list):
        return []
    return list(dict.fromkeys(str(item).strip() for item in value if isinstance(item, str) and item.strip()))


def safe_previous() -> Tuple[Dict[str, object], str]:
    if not CONTEXT_PATH.is_file():
        return {}, "none"
    digest = hashlib.sha256(boundedio.read_bytes(CONTEXT_PATH,label="context capsule")).hexdigest()
    try:
        return load_json(CONTEXT_PATH), digest
    except (OSError, ValueError, SystemExit):
        return {}, digest


def budget_snapshot(config: Dict[str, object], task: Dict[str, object], current_estimate: int = 0) -> Dict[str, object]:
    policy = config.get("context", {}) if isinstance(config.get("context"), dict) else {}
    active_task = copy.deepcopy(task)
    used = int(task.get("tokens_used", 0)) if isinstance(task.get("tokens_used"), int) else 0
    active_task["tokens_used"] = max(used, int(current_estimate))
    ledger_path = AGENT_DIR / "state/agents.json"
    ledger = load_json(ledger_path) if ledger_path.is_file() else None
    try: unified = total_budget.snapshot(active_task, config, ledger, active_window_estimate=current_estimate)
    except ValueError as error: raise SystemExit(str(error))
    consumed = int(unified["consumed_tokens"]); budget = int(unified["budget"])
    ratio = consumed / budget if budget > 0 else 0.0
    if ratio >= float(policy.get("hard_budget_ratio", 0.9)):
        watermark = "hard"
    elif ratio >= float(policy.get("compact_budget_ratio", 0.75)):
        watermark = "compact"
    elif ratio >= float(policy.get("soft_budget_ratio", 0.6)):
        watermark = "soft"
    else:
        watermark = "normal"
    return {
        "task_tokens_used": used,
        "current_checkpoint_estimated_tokens": int(current_estimate),
        "task_token_budget": budget,
        "usage_source": task.get("token_usage_source"),
        "reserved_reference_tokens": unified["reference_tokens"],
        "child_reserved_tokens": unified["child_reserved_tokens"],
        "child_settled_tokens": unified["child_settled_tokens"],
        "consumed_tokens": consumed,
        "budget_ratio": round(ratio, 4),
        "watermark": watermark,
        "assurance": unified["assurance"],
    }


def automatic_transition_source_tokens(
    config: Dict[str, object],
    previous: Dict[str, object],
    task: Dict[str, object],
    requested: Optional[int] = None,
) -> int:
    """Return the minimum honest active-window estimate for a canonical transition.

    A canonical transition adds bounded control-plane bookkeeping to the same
    active context; it is not evidence that the host replayed a whole turn or
    that the session was compacted. Therefore its estimate advances by
    ``context.transition_token_increment[mode]``. The deprecated
    ``context.automatic_transition_token_increment`` alias keeps its exact
    legacy arithmetic. Cumulative provider usage receipts remain exclusively
    in TASK's cumulative-cost account: they do not measure the active window,
    and their latest delta must never be replayed at multiple transitions.
    Real host turns are charged independently by ``account-turn``. Only a
    verified host-compaction handshake may establish a lower active-context
    baseline.
    """
    mode = str(task.get("mode", ""))
    try:
        increment = total_budget.transition_increment_estimate(config, mode)
    except ValueError as error:
        raise SystemExit(
            f"context transition increment is unusable: {error} "
            f"(configure context.transition_token_increment; "
            f"deprecated alias context.automatic_transition_token_increment)"
        )
    freshness = previous.get("usage_freshness")
    prior = freshness.get("estimated_tokens") if isinstance(freshness, dict) else None
    if not isinstance(prior, int) or isinstance(prior, bool) or prior <= 0:
        raise SystemExit("verified previous context lacks a positive active-window usage estimate")
    floor = prior + increment
    if requested is None:
        return floor
    if not isinstance(requested, int) or isinstance(requested, bool) or requested <= 0:
        raise SystemExit("requested context source-token estimate must be positive")
    return max(floor, requested)


def effective_budget_state(
    config: Dict[str, object], task: Dict[str, object], current_estimate: int
) -> str:
    """Map the checkpoint's unified watermark to the public routing state."""
    watermark = str(budget_snapshot(config, task, current_estimate).get("watermark", "hard"))
    return {
        "normal": "ok",
        "soft": "soft",
        "compact": "must_compact",
        "hard": "hard_blocked",
    }.get(watermark, "hard_blocked")


def hard_repair_interval(task: Dict[str, object]) -> Optional[Tuple[int, int]]:
    """Merge adjacent hot return receipts without widening beyond their route."""
    rollback = task.get("rollback_ledger")
    failures = task.get("failure_ledger")
    if (
        not isinstance(rollback, list)
        or not rollback
        or not isinstance(failures, dict)
    ):
        return None
    receipts: List[Dict[str, object]] = []
    for item in reversed(rollback):
        if not isinstance(item, dict):
            break
        start, end = item.get("to"), item.get("from")
        count = failures.get(item.get("signature"))
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or not 0 < count < 3
        ):
            break
        if receipts and start != receipts[-1]["from"]:
            break
        receipts.append(item)
    if not receipts:
        return None
    return int(receipts[0]["to"]), int(receipts[-1]["from"])


def bounded_hard_repair(task: Dict[str, object]) -> bool:
    current = task.get("current_node")
    interval = hard_repair_interval(task)
    return bool(
        task.get("status") == "in_progress"
        and isinstance(current, int)
        and not isinstance(current, bool)
        and interval is not None
        and interval[0] <= current <= interval[1]
    )


def resume_next_action(task: Dict[str, object], budget_state: str) -> object:
    """Return an executable next step for this checkpoint, not stale TASK prose."""
    terminal = task.get("status") == "accepted" and task.get("current_node") == "idle"
    terminal_closure = (
        task.get("status") == "ready_to_complete"
        and task.get("current_node") == 7
        and task.get("accepted_nodes") == list(range(8))
    )
    if terminal and budget_state in {"must_compact", "hard_blocked"}:
        return (
            "before starting another requirement, establish a verified host compaction "
            "or select an authorized higher-budget mode"
        )
    if (
        budget_state == "hard_blocked"
        and not terminal_closure
        and not bounded_hard_repair(task)
    ):
        return (
            "use rollback, return-node, cleanup or an explicit human decision; "
            "do not continue or expand scope"
        )
    return task.get("next_action")


def resume_contract(
    task: Dict[str, object],
    snapshot_sha256: str,
    budget_state: Optional[str] = None,
) -> Dict[str, object]:
    status=task.get("status"); current=task.get("current_node")
    terminal=status=="accepted" and current=="idle"
    terminal_closure = (
        status == "ready_to_complete"
        and current == 7
        and task.get("accepted_nodes") == list(range(8))
    )
    hard_repair = bounded_hard_repair(task)
    effective_state = str(budget_state or task.get("budget_state") or "hard_blocked")
    if terminal:
        action="complete"
    elif status in {"idle","waiting_human"} or (
        effective_state=="hard_blocked" and not terminal_closure and not hard_repair
    ):
        action="waiting_human"
    else:
        action="continue"
    return {
        "schema":"agent-context-resume/v1","task_status":status,"current_node":current,
        "next_action":resume_next_action(task, effective_state),"budget_state":effective_state,
        "terminal":terminal,"resume_action":action,"task_invariant_sha256":snapshot_sha256,
    }


def turn_accounting_value(previous: Dict[str, object]) -> Dict[str, object]:
    value = previous.get("turn_accounting")
    if not isinstance(value, dict):
        return {
            "schema": TURN_ACCOUNTING_SCHEMA,
            "applied_turn_ids_sha256": [],
            "turns_accounted": 0,
            "estimated_tokens_charged": 0,
        }
    return copy.deepcopy(value)


def turn_accounting_errors(context: Dict[str, object]) -> List[str]:
    value = context.get("turn_accounting")
    if value is None:
        # Legacy capsules are upgraded by their next sync/transition.
        return []
    required = {
        "schema", "applied_turn_ids_sha256", "turns_accounted",
        "estimated_tokens_charged",
    }
    ids = value.get("applied_turn_ids_sha256") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema") != TURN_ACCOUNTING_SCHEMA
        or not isinstance(ids, list)
        or len(ids) > MAX_ACCOUNTED_TURN_IDS
        or len(ids) != len(set(ids))
        or any(not isinstance(item, str) or HEX64.fullmatch(item) is None for item in ids)
        or value.get("turns_accounted") != len(ids)
        or not isinstance(value.get("estimated_tokens_charged"), int)
        or isinstance(value.get("estimated_tokens_charged"), bool)
        or int(value.get("estimated_tokens_charged", -1)) < 0
    ):
        return ["host-turn accounting record is malformed or unbounded"]
    return []


def terminal_completion_origin(context: Dict[str, object]) -> Dict[str, object]:
    """Return exact durable terminal provenance for post-completion accounting."""
    checkpoint = context.get("checkpoint")
    compaction = context.get("compaction")
    if not isinstance(checkpoint, dict) or not isinstance(compaction, dict):
        raise SystemExit("accepted task host-turn accounting lacks terminal checkpoint records")
    origin = checkpoint.get("terminal_completion_origin")
    current_authorization = checkpoint.get("transition_authorization")
    if origin is None and (
        isinstance(current_authorization, dict)
        and current_authorization.get("mutator") == "workflowctl"
        and current_authorization.get("operation") == "complete-task"
    ):
        origin = {
            "schema": "agent-terminal-completion-origin/v1",
            "kind": "complete-task",
            "transition_authorization": copy.deepcopy(current_authorization),
        }
    elif origin is None and (
        checkpoint.get("reason") in {
            "migration-26-final-state-rebind",
            "migration-34-final-state-rebind",
            "migration-39-budget-resume-rebind",
        }
        and compaction.get("source") in {
            "installer-verified-active-migration",
            "installer-verified-context-efficiency-migration",
            "installer-verified-budget-resume-migration",
        }
    ):
        origin = {
            "schema": "agent-terminal-completion-origin/v1",
            "kind": "installer-migration",
            "reason": checkpoint.get("reason"),
            "source": compaction.get("source"),
        }
    ordinary_origin = (
        isinstance(origin, dict)
        and set(origin) == {"schema", "kind", "transition_authorization"}
        and origin.get("schema") == "agent-terminal-completion-origin/v1"
        and origin.get("kind") == "complete-task"
        and isinstance(origin.get("transition_authorization"), dict)
        and origin["transition_authorization"].get("mutator") == "workflowctl"
        and origin["transition_authorization"].get("operation") == "complete-task"
    )
    migration_origin = (
        isinstance(origin, dict)
        and set(origin) == {"schema", "kind", "reason", "source"}
        and origin.get("schema") == "agent-terminal-completion-origin/v1"
        and origin.get("kind") == "installer-migration"
        and (origin.get("reason"), origin.get("source")) in {
            (
                "migration-26-final-state-rebind",
                "installer-verified-active-migration",
            ),
            (
                "migration-34-final-state-rebind",
                "installer-verified-context-efficiency-migration",
            ),
            (
                "migration-39-budget-resume-rebind",
                "installer-verified-budget-resume-migration",
            ),
        }
    )
    if not (ordinary_origin or migration_origin):
        raise SystemExit(
            "accepted task host-turn accounting requires durable terminal completion provenance"
        )
    assert isinstance(origin, dict)
    return copy.deepcopy(origin)


def update_compaction_metrics(
    compaction: Dict[str, object],
    capsule_estimate: int,
    *,
    host_tokens_removed: Optional[int] = None,
) -> None:
    source = int(compaction.get("source_estimated_tokens", 0))
    already_separated = "capsule_reduction_tokens" in compaction
    compaction["capsule_estimated_tokens"] = capsule_estimate
    compaction["capsule_reduction_tokens"] = source - capsule_estimate
    if host_tokens_removed is not None:
        compaction["tokens_removed"] = host_tokens_removed
    elif not already_separated:
        compaction["tokens_removed"] = 0
    compaction["compression_ratio"] = round(source / max(capsule_estimate, 1), 2)


def build_capsule(
    args: argparse.Namespace,
    integrity_status: str,
    previous: Dict[str, object],
    previous_file_sha256: str,
    transition_authorization: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    config = load_json(CONFIG_PATH)
    task = load_json(TASK_PATH)
    previous_checkpoint = previous.get("checkpoint") if isinstance(previous.get("checkpoint"), dict) else {}
    sequence = int(previous_checkpoint.get("sequence", 0)) + 1
    checkpoint_at = now()

    if args.transition or args.reset:
        facts = list_value(args.fact)
        changed_files = list_value(args.file)
        evidence = list_value(args.evidence)
    else:
        facts = list_value(previous.get("confirmed_facts")) + list_value(args.fact)
        changed_files = list_value(previous.get("changed_files")) + list_value(args.file)
        evidence = list_value(previous.get("evidence")) + list_value(args.evidence)

    previous_risks = list_value(previous.get("open_risks"))
    resolutions = list_value(args.resolve_risk)
    unknown_resolutions = sorted(set(resolutions) - set(previous_risks))
    if unknown_resolutions:
        raise SystemExit(f"cannot resolve unknown context risks: {unknown_resolutions}")
    risks = [item for item in previous_risks if item not in resolutions] + list_value(args.risk)
    facts.extend(
        [
            f"requirement_source={task.get('requirement_source', 'pending')}",
            f"requirements_clarified={str(task.get('requirements_clarified', False)).lower()}",
            f"environment={task.get('environment', 'local')}",
        ]
    )
    summary = str(args.summary or previous.get("phase_summary", "")).strip()
    if not summary:
        raise SystemExit("a non-empty --summary is required for initial sync, transition and repair")

    snapshot_sha256 = invariant_sha256(task)
    previous_task_sha256 = str(previous.get("task_invariant_sha256", "none")) if previous else "none"
    capsule: Dict[str, object] = {
        "schema": "agent-context/v2",
        "policy_bundle_version": POLICY_BUNDLE_VERSION,
        "policy_bundle_sha256": policy_bundle_sha256(task),
        "task_title": task.get("title"),
        "phase": task.get("phase"),
        "mode": task.get("mode"),
        "task_invariant_sha256": snapshot_sha256,
        "requirement_contract_sha256": governed_contract_binding(task),
        "phase_summary": summary,
        "confirmed_facts": list_value(facts),
        "decisions": list_value(task.get("decisions")),
        "open_questions": list_value(task.get("open_questions")),
        "changed_files": list_value(changed_files),
        "evidence": list_value(evidence),
        "open_risks": list_value(risks),
        "next_action": task.get("next_action"),
        "resume": resume_contract(
            task,
            snapshot_sha256,
            effective_budget_state(config, task, int(args.source_tokens)),
        ),
        "checkpoint": {
            "sequence": sequence,
            "reason": args.reason,
            "updated_at": checkpoint_at,
            "previous_sha256": previous_file_sha256,
            "previous_task_invariant_sha256": previous_task_sha256,
            "task_delta": (
                transition_authorization["changed_fields"]
                if transition_authorization is not None
                else (["canonical_task_state"] if previous else ["initial_canonical_task_state"])
            ),
            "transition_authorization": transition_authorization,
        },
        "usage_freshness": {
            "schema": "agent-context-usage/v1",
            "checkpoint_sequence": sequence,
            "task_invariant_sha256": snapshot_sha256,
            "coverage": "through-current-checkpoint",
            "source": "explicit-estimate",
            "estimated_tokens": int(args.source_tokens),
            "observed_at": checkpoint_at,
        },
        "turn_accounting": turn_accounting_value(previous),
        "compaction": {
            "source_estimated_tokens": int(args.source_tokens),
            "capsule_estimated_tokens": 0,
            "tokens_removed": 0,
            "capsule_reduction_tokens": 0,
            "compression_ratio": 0,
            "method": "explicit-estimate/v1",
            "reason": args.reason,
            "source": args.source,
            "budget_snapshot": budget_snapshot(config, task, int(args.source_tokens)),
        },
        "integrity": {
            "status": integrity_status,
            "verified_at": now(),
            "source": args.source,
            "content_sha256": "0" * 64,
        },
    }
    previous_resume = previous.get("resume") if isinstance(previous, dict) else None
    if (
        task.get("status") == "accepted"
        and isinstance(previous_resume, dict)
        and previous_resume.get("terminal") is True
    ):
        # Plain refreshes, installer rebinds and reviewed repairs occur after
        # the canonical complete-task transition. Preserve that exact origin
        # just as account-turn does, otherwise any post-completion sync would
        # silently reopen the terminal route.
        capsule["checkpoint"]["terminal_completion_origin"] = (  # type: ignore[index]
            terminal_completion_origin(previous)
        )
    if getattr(args, "request_host_compaction", False):
        capsule["host_compaction"] = {
            "schema": "agent-host-compaction-state/v1", "state": "awaiting_host_compaction",
            "history": ["handoff_written"], "receipt": None,
        }
    elif getattr(args, "host_compaction", False):
        capsule["host_compaction"] = {
            "schema": "agent-host-compaction-state/v1", "state": "resumed",
            "history": ["handoff_written", "awaiting_host_compaction", "resumed"],
            "receipt": getattr(args, "verified_host_compaction_receipt", None),
        }
    elif isinstance(previous.get("host_compaction"), dict) and not getattr(args, "reset", False):
        capsule["host_compaction"] = copy.deepcopy(previous["host_compaction"])
    estimated = normalized_token_estimate(capsule)
    if int(args.source_tokens) < estimated:
        raise SystemExit(
            f"source token estimate {args.source_tokens} is below the bounded capsule estimate {estimated}; "
            "provide an honest pre-compaction estimate"
        )
    compaction = capsule["compaction"]
    assert isinstance(compaction, dict)
    host_removed = None
    verified_host = getattr(args, "verified_host_compaction_receipt", None)
    if isinstance(verified_host, dict):
        before_tokens = verified_host.get("from_estimated_tokens")
        after_tokens = verified_host.get("to_estimated_tokens")
        if isinstance(before_tokens, int) and isinstance(after_tokens, int):
            host_removed = before_tokens - after_tokens
    elif isinstance(previous.get("host_compaction"), dict):
        previous_receipt = previous["host_compaction"].get("receipt")
        if isinstance(previous_receipt, dict):
            before_tokens = previous_receipt.get("from_estimated_tokens")
            after_tokens = previous_receipt.get("to_estimated_tokens")
            if not isinstance(before_tokens, int) or not isinstance(after_tokens, int):
                try:
                    legacy_receipt = load_json(ROOT / str(previous_receipt.get("path", "")))
                    before_tokens = legacy_receipt.get("from_estimated_tokens")
                    after_tokens = legacy_receipt.get("to_estimated_tokens")
                except (OSError, ValueError, SystemExit, json.JSONDecodeError):
                    before_tokens = after_tokens = None
            if isinstance(before_tokens, int) and isinstance(after_tokens, int):
                host_removed = before_tokens - after_tokens
    update_compaction_metrics(compaction, estimated, host_tokens_removed=host_removed)
    capsule["integrity"]["content_sha256"] = content_sha256(capsule)  # type: ignore[index]
    return capsule


def internal_compaction_errors(context: Dict[str, object]) -> List[str]:
    errors: List[str] = []
    compaction = context.get("compaction")
    estimate = normalized_token_estimate(context)
    required = {
        "source_estimated_tokens",
        "capsule_estimated_tokens",
        "tokens_removed",
        "compression_ratio",
        "method",
        "reason",
        "source",
        "budget_snapshot",
    }
    if not isinstance(compaction, dict) or not required.issubset(compaction):
        return ["stored compaction evidence is incomplete"]
    source = compaction.get("source_estimated_tokens")
    if not isinstance(source, int) or source < estimate:
        errors.append("stored source token estimate is below capsule size")
    if compaction.get("capsule_estimated_tokens") != estimate:
        errors.append("stored capsule token estimate is stale")
    capsule_reduction = compaction.get("capsule_reduction_tokens")
    if capsule_reduction is None:
        # Legacy v2 records used tokens_removed for the theoretical difference
        # between active-window source and serialized capsule size.
        if isinstance(source, int) and compaction.get("tokens_removed") != source - estimate:
            errors.append("stored legacy removed-token evidence is stale")
    else:
        if capsule_reduction != source - estimate:
            errors.append("stored capsule-reduction evidence is stale")
        removed = compaction.get("tokens_removed")
        if not isinstance(removed, int) or isinstance(removed, bool) or removed < 0:
            errors.append("stored host-token removal evidence is invalid")
        host = context.get("host_compaction")
        if removed and (
            not isinstance(host, dict)
            or host.get("state") != "resumed"
            or not isinstance(host.get("receipt"), dict)
        ):
            errors.append("unverified checkpoint cannot claim host tokens were removed")
    if compaction.get("method") != "explicit-estimate/v1" or not str(compaction.get("reason", "")).strip():
        errors.append("stored compaction method or reason is invalid")
    expected_ratio = round(source / max(estimate, 1), 2) if isinstance(source, int) else None
    if compaction.get("compression_ratio") != expected_ratio:
        errors.append("stored compression ratio is stale")
    host = context.get("host_compaction")
    if host is not None:
        if not isinstance(host, dict) or host.get("schema") != "agent-host-compaction-state/v1" or host.get("state") not in {"awaiting_host_compaction", "resumed"}:
            errors.append("host compaction state is invalid")
        elif host.get("state") == "awaiting_host_compaction" and (host.get("history") != ["handoff_written"] or host.get("receipt") is not None):
            errors.append("host compaction handoff state is invalid")
        elif host.get("state") == "resumed":
            record = host.get("receipt")
            if host.get("history") != ["handoff_written", "awaiting_host_compaction", "resumed"] or not isinstance(record, dict):
                errors.append("host compaction resumed state lacks a verified receipt")
            else:
                try:
                    receipt_value = load_json(ROOT / str(record.get("path", "")))
                    verified = verify_host_compaction_receipt(
                        str(record.get("path", "")), load_json(TASK_PATH),
                        int(receipt_value.get("from_estimated_tokens", -1)),
                        int(receipt_value.get("to_estimated_tokens", -1)), require_fresh=False,
                        expected_task_invariant_sha256=str(record.get("task_invariant_sha256", "")),
                    )
                    legacy_verified = {
                        key: value for key, value in verified.items()
                        if key not in {"from_estimated_tokens", "to_estimated_tokens"}
                    }
                    if record != verified and record != legacy_verified:
                        errors.append("stored host compaction receipt or adapter provenance drifted")
                    elif (
                        compaction.get("capsule_reduction_tokens") is not None
                        and compaction.get("tokens_removed")
                        != int(verified["from_estimated_tokens"]) - int(verified["to_estimated_tokens"])
                    ):
                        errors.append("stored host-token removal amount differs from its verified receipt")
                except (OSError, ValueError, TypeError, SystemExit, json.JSONDecodeError):
                    errors.append("stored host compaction receipt cannot be durably reverified")
    abort = compaction.get("host_compaction_abort")
    if abort is not None:
        # Revalidate the stored abort approval with the same discipline as
        # repair_approval_errors: the event is only trustworthy while its
        # human decision still verifies under the task's decision policy.
        if (
            not isinstance(abort, dict)
            or abort.get("event") != "aborted"
            or not str(abort.get("source", "")).startswith("user:")
            or HEX64.fullmatch(str(abort.get("aborted_capsule_sha256", ""))) is None
        ):
            errors.append("stored host compaction abort record is invalid")
        else:
            try:
                abort_approval_valid = humandecision.decision_approval_valid(
                    ROOT, load_json(CONFIG_PATH), load_json(TASK_PATH),
                    gate="context-abort-host-compaction",
                    artifact_sha256=str(abort["aborted_capsule_sha256"]),
                    source=str(abort["source"]), record=abort.get("approval"),
                )
            except (OSError, ValueError, TypeError, SystemExit, json.JSONDecodeError):
                abort_approval_valid = False
            if not abort_approval_valid:
                errors.append("stored host compaction abort lacks a valid human decision approval")
    return errors


def handoff_artifact_present(previous: Dict[str, object], task: Dict[str, object]) -> bool:
    """The recorded handoff must be a real artifact, not a fabricated label.

    Entering ``awaiting_host_compaction`` claims ``handoff_written``; that is
    only honest when the verified previous capsule carries an
    ``agent-context-resume/v1`` contract bound to the current TASK invariant.
    """
    if not CONTEXT_PATH.is_file() or CONTEXT_PATH.is_symlink():
        return False
    resume = previous.get("resume") if isinstance(previous, dict) else None
    return (
        isinstance(resume, dict)
        and resume.get("schema") == "agent-context-resume/v1"
        and resume.get("task_invariant_sha256") == invariant_sha256(task)
    )


def verify_host_compaction_receipt(raw: str, task: Dict[str, object],
                                   from_tokens: int, to_tokens: int,
                                   *, require_fresh: bool = True,
                                   expected_task_invariant_sha256: Optional[str] = None) -> Dict[str, object]:
    config = load_json(CONFIG_PATH)
    observer = config.get("context", {}).get("host_compaction_observer", {})
    adapter_raw = observer.get("signed_adapter") if isinstance(observer, dict) else None
    if not isinstance(adapter_raw, str) or not adapter_raw:
        raise SystemExit("host compaction is unsupported until context.host_compaction_observer.signed_adapter is configured")
    adapter = humandecision.adapter_path(
        ROOT, adapter_raw, required_operations=("verify-host-compaction",),
    )
    path = (ROOT / raw).resolve()
    try: path.relative_to(ROOT)
    except ValueError: raise SystemExit("host compaction receipt escapes project")
    if not path.is_file() or path.is_symlink(): raise SystemExit("host compaction receipt is missing or unsafe")
    receipt_data,receipt_identity=humandecision.receipt_snapshot(path)
    try: value=strict_json_loads(receipt_data.decode("utf-8"))
    except (UnicodeError,json.JSONDecodeError) as error: raise SystemExit("host compaction receipt is not valid UTF-8 JSON") from error
    required = {"schema", "task_invariant_sha256", "from_estimated_tokens", "to_estimated_tokens", "observed_at", "host_id", "nonce"}
    if (
        set(value) != required or value.get("schema") != "host-compaction-receipt/v1"
        or value.get("task_invariant_sha256") != (
            expected_task_invariant_sha256
            if expected_task_invariant_sha256 is not None
            else invariant_sha256(task)
        )
        or value.get("from_estimated_tokens") != from_tokens or value.get("to_estimated_tokens") != to_tokens
        or not str(value.get("host_id", "")).strip() or not str(value.get("nonce", "")).strip()
    ):
        raise SystemExit("host compaction receipt does not bind the active-window transition")
    try: observed = dt.datetime.fromisoformat(str(value.get("observed_at", "")).replace("Z", "+00:00"))
    except ValueError: raise SystemExit("host compaction receipt timestamp is invalid")
    if observed.tzinfo is None: raise SystemExit("host compaction receipt timestamp lacks timezone")
    if require_fresh:
        age = (dt.datetime.now(dt.timezone.utc) - observed.astimezone(dt.timezone.utc)).total_seconds()
        maximum = int(observer.get("max_receipt_age_seconds", 300))
        if age < -30 or age > maximum:
            raise SystemExit("host compaction receipt is stale or future-dated")
    digest=hashlib.sha256(receipt_data).hexdigest()
    result=humandecision.run_adapter(adapter,["verify-host-compaction"],required_operations=("verify-host-compaction",),timeout=30,receipt_raw=receipt_data)
    if result.returncode or result.stdout.strip() != f"VERIFIED HOST COMPACTION sha256={digest}":
        raise SystemExit("host compaction adapter rejected the receipt")
    after_data,after_identity=humandecision.receipt_snapshot(path)
    if after_identity!=receipt_identity or after_data!=receipt_data:
        raise SystemExit("host compaction receipt changed during provider verification")
    return {
        "path": str(path.relative_to(ROOT)), "sha256": digest, "bytes": len(receipt_data),
        "task_invariant_sha256": value["task_invariant_sha256"],
        "from_estimated_tokens": value["from_estimated_tokens"],
        "to_estimated_tokens": value["to_estimated_tokens"],
        "host_id": value["host_id"], "observed_at": value["observed_at"],
        "adapter_path": str(adapter), "adapter_sha256": hashlib.sha256(boundedio.read_bytes(adapter,label="context adapter")).hexdigest(),
    }


def usage_freshness_errors(context: Dict[str, object]) -> List[str]:
    freshness = context.get("usage_freshness")
    checkpoint = context.get("checkpoint")
    compaction = context.get("compaction")
    required = {
        "schema", "checkpoint_sequence", "task_invariant_sha256", "coverage",
        "source", "estimated_tokens", "observed_at",
    }
    if not isinstance(freshness, dict) or set(freshness) != required:
        return ["current-checkpoint usage freshness receipt is missing or malformed"]
    if (
        freshness.get("schema") != "agent-context-usage/v1"
        or freshness.get("coverage") != "through-current-checkpoint"
        or freshness.get("source") != "explicit-estimate"
        or not isinstance(checkpoint, dict)
        or freshness.get("checkpoint_sequence") != checkpoint.get("sequence")
        or freshness.get("task_invariant_sha256") != context.get("task_invariant_sha256")
        or freshness.get("observed_at") != checkpoint.get("updated_at")
        or not isinstance(freshness.get("estimated_tokens"), int)
        or isinstance(freshness.get("estimated_tokens"), bool)
        or int(freshness.get("estimated_tokens", 0)) <= 0
        or not isinstance(compaction, dict)
        or freshness.get("estimated_tokens") != compaction.get("source_estimated_tokens")
    ):
        return ["current-checkpoint usage freshness receipt does not bind this checkpoint and explicit estimate"]
    try:
        observed = dt.datetime.fromisoformat(str(freshness.get("observed_at")))
        if observed.tzinfo is None:
            raise ValueError("timezone required")
    except (TypeError, ValueError):
        return ["current-checkpoint usage freshness timestamp is invalid"]
    return []


def repair_approval_errors(
    context: Dict[str, object], config: Dict[str, object], task: Dict[str, object]
) -> List[str]:
    integrity = context.get("integrity")
    if not isinstance(integrity, dict):
        return ["context integrity record is invalid"]
    base = {"status", "verified_at", "source", "content_sha256"}
    repair = base | {"repair_capsule_sha256", "repair_approval"}
    if integrity.get("status") == "needs_review":
        return [] if set(integrity) == base else ["unreviewed repair contains invalid approval fields"]
    if set(integrity) == base:
        return []
    if set(integrity) != repair or HEX64.fullmatch(str(integrity.get("repair_capsule_sha256", ""))) is None:
        return ["reviewed repair lacks an exact repair-capsule approval binding"]
    if not humandecision.decision_approval_valid(
        ROOT, config, task, gate="context-repair",
        artifact_sha256=str(integrity["repair_capsule_sha256"]),
        source=str(integrity.get("source", "")), record=integrity.get("repair_approval"),
    ):
        return ["reviewed repair lacks a valid human decision approval"]
    return []


def stored_capsule_errors(task: Optional[Dict[str, object]] = None) -> List[str]:
    """Check capsule integrity against its own bound snapshot before a transition."""
    try:
        context = load_json(CONTEXT_PATH)
    except (OSError, ValueError, SystemExit) as error:
        return [str(error)]
    errors: List[str] = []
    if context.get("schema") != "agent-context/v2":
        errors.append("stored schema is invalid")
    if not isinstance(context.get("task_invariant_sha256"), str) or not HEX64.fullmatch(str(context.get("task_invariant_sha256"))):
        errors.append("stored TASK invariant binding is invalid")
    if not isinstance(context.get("phase_summary"), str) or not str(context.get("phase_summary")).strip():
        errors.append("stored phase summary is invalid")
    resume=context.get("resume")
    if (
        not isinstance(resume,dict)
        or resume.get("schema")!="agent-context-resume/v1"
        or resume.get("task_invariant_sha256")!=context.get("task_invariant_sha256")
        or not isinstance(resume.get("terminal"),bool)
        or resume.get("resume_action") not in {"continue","waiting_human","complete"}
    ):
        errors.append("stored resume contract is invalid")
    for field in LIST_FIELDS:
        values = context.get(field)
        if not isinstance(values, list) or any(not isinstance(item, str) or not item.strip() for item in values):
            errors.append(f"stored {field} is invalid")
    if not context.get("confirmed_facts"):
        errors.append("stored confirmed_facts are empty")
    checkpoint = context.get("checkpoint")
    if (
        not isinstance(checkpoint, dict)
        or not isinstance(checkpoint.get("sequence"), int)
        or checkpoint["sequence"] < 1
        or not isinstance(checkpoint.get("previous_sha256"), str)
        or not isinstance(checkpoint.get("task_delta"), list)
    ):
        errors.append("stored checkpoint is invalid")
    integrity = context.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("status") != "verified":
        errors.append("stored capsule is not verified")
    elif integrity.get("content_sha256") != content_sha256(context):
        errors.append("stored capsule content hash is invalid")
    errors.extend(internal_compaction_errors(context))
    errors.extend(usage_freshness_errors(context))
    errors.extend(turn_accounting_errors(context))
    try:
        approval_task = task if task is not None else load_json(TASK_PATH)
        errors.extend(repair_approval_errors(context, load_json(CONFIG_PATH), approval_task))
    except (OSError, ValueError, SystemExit, json.JSONDecodeError):
        errors.append("stored repair approval could not be reverified")
    return errors


def legacy_usage_upgrade_allowed(context: Dict[str, object]) -> bool:
    """Permit one integrity-preserving v2 -> freshness migration, and nothing else."""
    task = load_json(TASK_PATH)
    errors = stored_capsule_errors()
    if errors != ["current-checkpoint usage freshness receipt is missing or malformed"]:
        return False
    compaction = context.get("compaction")
    snapshot = compaction.get("budget_snapshot") if isinstance(compaction, dict) else None
    # Compare on the stored snapshot's own basis: recompute what the current
    # code would record for this TASK/config with the stored checkpoint
    # estimate, rather than against a zero-estimate snapshot that can never
    # match a real legacy capsule.
    estimate = snapshot.get("current_checkpoint_estimated_tokens") if isinstance(snapshot, dict) else None
    if not isinstance(estimate, int) or isinstance(estimate, bool) or estimate < 0:
        return False
    expected = budget_snapshot(load_json(CONFIG_PATH), task, estimate)
    return bool(
        context.get("task_invariant_sha256") == invariant_sha256(task)
        and context.get("requirement_contract_sha256") == governed_contract_binding(task)
        and context.get("resume") == resume_contract(task, invariant_sha256(task))
        and snapshot == expected
    )


def validate_context(quiet: bool = False, ignore_checkpoint_age: bool = False) -> int:
    config = load_json(CONFIG_PATH)
    task = load_json(TASK_PATH)
    errors: List[str] = []
    try:
        context = load_json(CONTEXT_PATH)
    except (OSError, ValueError, SystemExit) as error:
        if not quiet:
            print(f"INVALID context capsule\n- {error}")
        return 1
    policy = config.get("context", {}) if isinstance(config.get("context"), dict) else {}
    # A config whose budget arithmetic lets one permitted operation cross the
    # hard watermark is invalid for every capsule under it.
    errors.extend(total_budget.config_budget_errors(config))
    mode_policy = policy.get("max_capsule_tokens", {}) if isinstance(policy.get("max_capsule_tokens"), dict) else {}
    if context.get("schema") != "agent-context/v2":
        errors.append("schema must be agent-context/v2")
    freshness_for_resume = context.get("usage_freshness")
    resume_estimate = (
        freshness_for_resume.get("estimated_tokens")
        if isinstance(freshness_for_resume, dict)
        else None
    )
    resume_state = (
        effective_budget_state(config, task, int(resume_estimate))
        if isinstance(resume_estimate, int) and not isinstance(resume_estimate, bool)
        else "hard_blocked"
    )
    expected_resume = resume_contract(task, invariant_sha256(task), resume_state)
    legacy_resume = resume_contract(task, invariant_sha256(task))
    exact = {
        "task_title": task.get("title"),
        "phase": task.get("phase"),
        "mode": task.get("mode"),
        "task_invariant_sha256": invariant_sha256(task),
        "requirement_contract_sha256": governed_contract_binding(task),
        "decisions": list_value(task.get("decisions")),
        "open_questions": list_value(task.get("open_questions")),
        "next_action": task.get("next_action"),
    }
    for key, expected in exact.items():
        if context.get(key) != expected:
            errors.append(f"{key} drifted from canonical task/contract state")
    stored_resume = context.get("resume")
    # A pre-fix capsule may still carry TASK's base budget state. It is
    # accepted only as a one-transition compatibility value; every new
    # sync/account-turn writes the checkpoint-effective state.
    if stored_resume != expected_resume and stored_resume != legacy_resume:
        errors.append("resume drifted from canonical task/checkpoint state")
    bundle_version = context.get("policy_bundle_version", LEGACY_POLICY_BUNDLE_VERSION)
    if bundle_version == POLICY_BUNDLE_VERSION:
        if context.get("policy_bundle_sha256") != policy_bundle_sha256(task):
            errors.append("policy_bundle_sha256 drifted from canonical task/contract state")
    elif (
        bundle_version == LEGACY_POLICY_BUNDLE_VERSION
        and context.get("policy_bundle_sha256") == policy_bundle_sha256(task, LEGACY_POLICY_BUNDLE_VERSION)
    ):
        # One-shot migration window: an otherwise exact policy-bundle/v1
        # capsule stays valid and is upgraded to policy-bundle/v2 (which also
        # binds enforcement code and guardrails) by the next sync.
        pass
    else:
        errors.append("policy_bundle_sha256 drifted from canonical task/contract state")
    if task.get("requirements_clarified") is True and task.get("requirement_contract_sha256") != contract_sha256():
        errors.append("TASK requirement contract binding differs from the governed contract bytes")
    if not isinstance(context.get("phase_summary"), str) or not str(context.get("phase_summary")).strip():
        errors.append("phase_summary must be non-empty")
    for field in LIST_FIELDS:
        values = context.get(field)
        if not isinstance(values, list) or any(not isinstance(item, str) or not item.strip() for item in values):
            errors.append(f"{field} must be a list of non-empty strings")
        elif len(values) > int(policy.get("max_list_items", 30)):
            errors.append(f"{field} exceeds its item budget")
        if field in {"changed_files", "evidence"} and isinstance(values, list):
            for raw in values:
                path = (ROOT / str(raw)).resolve()
                try:
                    path.relative_to(ROOT)
                except ValueError:
                    errors.append(f"{field} path escapes project: {raw}")
                    continue
                if not path.is_file() or path.is_symlink():
                    errors.append(f"{field} path is missing: {raw}")
    if task.get("status") == "accepted" and context.get("open_risks") != []:
        errors.append("accepted terminal context must not retain unresolved risks")
    if not context.get("confirmed_facts"):
        errors.append("confirmed_facts cannot be empty")
    encoded = boundedio.read_bytes(CONTEXT_PATH,label="context capsule")
    if len(encoded) > int(policy.get("max_bytes", 8192)):
        errors.append("context capsule exceeds byte budget")
    estimate = normalized_token_estimate(context)
    errors.extend(internal_compaction_errors(context))
    errors.extend(usage_freshness_errors(context))
    errors.extend(turn_accounting_errors(context))
    compaction = context.get("compaction")
    checkpoint_estimate = int(compaction.get("source_estimated_tokens", 0)) if isinstance(compaction, dict) else 0
    if isinstance(compaction, dict) and compaction.get("budget_snapshot") != budget_snapshot(config, task, checkpoint_estimate):
        errors.append("context budget snapshot drifted from TASK/config state")
    limit = int(mode_policy.get(str(task.get("mode")), 1800))
    if estimate > limit:
        errors.append(f"context capsule exceeds {task.get('mode')} token budget")
    integrity = context.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("status") != "verified":
        errors.append("context repair requires explicit review before work continues")
    elif integrity.get("content_sha256") != content_sha256(context):
        errors.append("context capsule content hash is invalid")
    errors.extend(repair_approval_errors(context, config, task))
    checkpoint = context.get("checkpoint")
    if (
        not isinstance(checkpoint, dict)
        or not isinstance(checkpoint.get("sequence"), int)
        or checkpoint["sequence"] < 1
        or not isinstance(checkpoint.get("previous_sha256"), str)
        or not isinstance(checkpoint.get("previous_task_invariant_sha256"), str)
        or not isinstance(checkpoint.get("task_delta"), list)
    ):
        errors.append("checkpoint sequence/linkage is invalid")
    if (
        not ignore_checkpoint_age
        and task.get("status") in {"in_progress", "waiting_human", "ready_to_complete"}
        and isinstance(checkpoint, dict)
    ):
        try:
            updated = dt.datetime.fromisoformat(str(checkpoint.get("updated_at")))
            if updated.tzinfo is None:
                raise ValueError("timezone required")
            age = (dt.datetime.now(dt.timezone.utc) - updated).total_seconds() / 60
            if age > int(policy.get("max_active_checkpoint_age_minutes", 45)):
                errors.append("active context checkpoint is stale; compact before continuing")
        except (TypeError, ValueError):
            errors.append("checkpoint updated_at is invalid")
    if errors:
        if not quiet:
            print("INVALID context capsule")
            for error in errors:
                print(f"- {error}")
        return 1
    if not quiet:
        print(f"VALID context capsule: {estimate}/{limit} estimated tokens")
    return 0


def abort_host_compaction(args: argparse.Namespace) -> int:
    """Abandon a pending host-compaction wait under human decision authority.

    The bounded inverse of ``sync --request-host-compaction``: valid only
    while the capsule awaits a host receipt, it clears the awaiting state,
    preserves every checkpoint value and records the aborted event together
    with its approval in the capsule compaction block. Every authoritative
    abort uses provider policy v1 and requires a provider-signed receipt;
    local/current-chat text alone is advisory.
    """
    if not args.source.startswith("user:"):
        raise SystemExit("abort approval source must start with user:")
    context = load_json(CONTEXT_PATH)
    host = context.get("host_compaction")
    if not isinstance(host, dict) or host.get("state") != "awaiting_host_compaction":
        raise SystemExit("abort-host-compaction is valid only while a host compaction is awaited")
    task = load_json(TASK_PATH)
    config = load_json(CONFIG_PATH)
    capsule_sha256 = hashlib.sha256(boundedio.read_bytes(CONTEXT_PATH,label="context capsule")).hexdigest()
    approval = humandecision.record_decision_approval(
        ROOT, config, task, gate="context-abort-host-compaction",
        artifact_sha256=capsule_sha256, source=args.source,
        receipt=args.human_decision_receipt,
    )
    compaction = context.get("compaction")
    integrity = context.get("integrity")
    if not isinstance(compaction, dict) or not isinstance(integrity, dict) or integrity.get("status") != "verified":
        raise SystemExit("awaiting capsule is not a verified compaction record; use repair --reset")
    context.pop("host_compaction", None)
    compaction["host_compaction_abort"] = {
        "event": "aborted",
        "aborted_at": now(),
        "source": args.source,
        "aborted_capsule_sha256": capsule_sha256,
        "approval": approval,
    }
    estimated = normalized_token_estimate(context)
    if int(compaction.get("source_estimated_tokens", 0)) < estimated:
        raise SystemExit("aborted capsule exceeds its source estimate; use repair --reset")
    update_compaction_metrics(compaction, estimated)
    integrity["verified_at"] = now()
    integrity["content_sha256"] = "0" * 64
    integrity["content_sha256"] = content_sha256(context)
    atomic_json(CONTEXT_PATH, context)
    result = validate_context(ignore_checkpoint_age=True)
    if result == 0:
        print("HOST COMPACTION ABORTED: awaiting state cleared; renew the checkpoint with a plain sync before continuing")
    return result


def account_host_turn(args: argparse.Namespace) -> int:
    """Charge one real host/model turn exactly once by caller-stable identity."""
    if not isinstance(args.turn_id, str) or not args.turn_id.strip():
        raise SystemExit("--turn-id must be a non-empty caller-stable host turn identity")
    if len(args.turn_id.encode("utf-8")) > 256:
        raise SystemExit("--turn-id exceeds the bounded 256-byte identity limit")
    if validate_context(quiet=True, ignore_checkpoint_age=True) != 0:
        raise SystemExit("host turn accounting requires an exact verified context checkpoint")
    context = load_json(CONTEXT_PATH)
    host = context.get("host_compaction")
    if isinstance(host, dict) and host.get("state") == "awaiting_host_compaction":
        raise SystemExit("host turn accounting is paused while host compaction awaits its receipt")
    accounting = turn_accounting_value(context)
    errors = turn_accounting_errors({**context, "turn_accounting": accounting})
    if errors:
        raise SystemExit(errors[0])
    digest = hashlib.sha256(args.turn_id.encode("utf-8")).hexdigest()
    applied = accounting["applied_turn_ids_sha256"]
    assert isinstance(applied, list)
    if digest in applied:
        print(f"HOST TURN ALREADY ACCOUNTED: sha256={digest}")
        return 0
    if len(applied) >= MAX_ACCOUNTED_TURN_IDS:
        raise SystemExit(
            "host turn identity ledger is full; establish a verified host compaction "
            "or split into a fresh project session before continuing"
        )
    task = load_json(TASK_PATH)
    config = load_json(CONFIG_PATH)
    try:
        overhead = total_budget.turn_overhead_estimate(config, str(task.get("mode", "")))
    except ValueError as error:
        raise SystemExit(str(error))
    freshness = context.get("usage_freshness")
    checkpoint = context.get("checkpoint")
    compaction = context.get("compaction")
    integrity = context.get("integrity")
    if not all(isinstance(value, dict) for value in (freshness, checkpoint, compaction, integrity)):
        raise SystemExit("host turn accounting requires complete context checkpoint records")
    prior = int(freshness["estimated_tokens"])  # type: ignore[index]
    timestamp = now()
    previous_file_sha256 = hashlib.sha256(boundedio.read_bytes(CONTEXT_PATH,label="context capsule")).hexdigest()
    applied.append(digest)
    accounting["turns_accounted"] = len(applied)
    accounting["estimated_tokens_charged"] = int(accounting["estimated_tokens_charged"]) + overhead
    context["turn_accounting"] = accounting
    checkpoint["sequence"] = int(checkpoint["sequence"]) + 1  # type: ignore[index]
    checkpoint["reason"] = "host-turn-accounted"
    checkpoint["updated_at"] = timestamp
    checkpoint["previous_sha256"] = previous_file_sha256
    checkpoint["previous_task_invariant_sha256"] = invariant_sha256(task)
    checkpoint["task_delta"] = ["turn_accounting"]
    # A completed task can receive later host/model turns (for example, the
    # maintainer's next review request) without ceasing to be terminal. Keep
    # the exact complete-task transition receipt as immutable provenance while
    # this accounting checkpoint becomes the current checkpoint. Subsequent
    # task transitions build a new capsule and naturally discard the marker.
    if task.get("status") == "accepted":
        checkpoint["terminal_completion_origin"] = terminal_completion_origin(context)
    else:
        checkpoint.pop("terminal_completion_origin", None)
    checkpoint["transition_authorization"] = None
    new_source = prior + overhead
    freshness["checkpoint_sequence"] = checkpoint["sequence"]  # type: ignore[index]
    freshness["task_invariant_sha256"] = invariant_sha256(task)
    freshness["estimated_tokens"] = new_source
    freshness["observed_at"] = timestamp
    context["resume"] = resume_contract(
        task,
        invariant_sha256(task),
        effective_budget_state(config, task, new_source),
    )
    compaction["source_estimated_tokens"] = new_source
    compaction["reason"] = "host-turn-accounted"
    compaction["source"] = f"host-turn:{digest}"
    compaction["budget_snapshot"] = budget_snapshot(config, task, new_source)
    integrity["verified_at"] = timestamp
    # A reviewed repair keeps its human-decision source because the stored
    # approval is revalidated against that exact source on every checkpoint.
    # The host-turn provenance is independently recorded in compaction.source.
    if "repair_approval" not in integrity:
        integrity["source"] = f"host-turn:{digest}"
    integrity["content_sha256"] = "0" * 64
    estimated = normalized_token_estimate(context)
    if new_source < estimated:
        raise SystemExit("host turn estimate is below the expanded bounded capsule size")
    update_compaction_metrics(compaction, estimated)
    integrity["content_sha256"] = content_sha256(context)
    atomic_json(CONTEXT_PATH, context)
    result = validate_context(ignore_checkpoint_age=True)
    if result == 0:
        print(f"HOST TURN ACCOUNTED: sha256={digest} overhead={overhead}")
    return result


def _main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("--quiet", action="store_true")
    for name in ("sync", "repair"):
        command = sub.add_parser(name)
        command.add_argument("--source-tokens", type=int, required=True)
        command.add_argument("--reason", required=True)
        command.add_argument("--summary")
        command.add_argument("--source", default="agent:contextctl")
        command.add_argument("--fact", action="append")
        command.add_argument("--file", action="append")
        command.add_argument("--evidence", action="append")
        command.add_argument("--risk", action="append")
        command.add_argument("--resolve-risk", action="append")
        command.add_argument("--reset", action="store_true")
        command.add_argument("--transition", action="store_true")
        command.add_argument("--from-task-sha256")
        command.add_argument("--authorization")
        command.add_argument("--host-compaction", action="store_true")
        command.add_argument("--host-compaction-receipt")
        command.add_argument("--request-host-compaction", action="store_true")
    approve = sub.add_parser("approve-repair")
    approve.add_argument("--source", required=True)
    approve.add_argument("--human-decision-receipt")
    abort = sub.add_parser("abort-host-compaction")
    abort.add_argument("--source", required=True)
    abort.add_argument("--human-decision-receipt")
    account_turn = sub.add_parser("account-turn")
    account_turn.add_argument("--turn-id", required=True)
    journal = sub.add_parser("journal")
    journal.add_argument("--restore", action="store_true")
    journal.add_argument("--discard", action="store_true")
    args = parser.parse_args()
    if args.command == "check":
        return validate_context(args.quiet)
    if args.command == "journal":
        import contexttx
        if args.restore and args.discard:
            raise SystemExit("journal --restore and --discard are distinct actions")
        if args.restore:
            status: Optional[Dict[str, object]] = contexttx.restore_transition_journal()
        elif args.discard:
            contexttx.discard_transition_journal()
            status = None
        else:
            status = contexttx.transition_journal_status()
        if status is None:
            status = {
                "schema": "agent-context-transition-journal-status/v1",
                "state": "none",
                "recovery": "no interrupted context transition",
            }
            print(strict_json_dumps(status, ensure_ascii=False, indent=2))
            return 0
        print(strict_json_dumps(status, ensure_ascii=False, indent=2))
        return 0 if status.get("state") == "restored" else 1
    if args.command == "abort-host-compaction":
        return abort_host_compaction(args)
    if args.command == "account-turn":
        return account_host_turn(args)
    if args.command == "approve-repair":
        if not args.source.startswith("user:"):
            raise SystemExit("repair approval source must start with user:")
        context = load_json(CONTEXT_PATH)
        if not isinstance(context.get("integrity"), dict) or context["integrity"].get("status") != "needs_review":
            raise SystemExit("no repaired context is waiting for review")
        repair_capsule_sha256 = hashlib.sha256(boundedio.read_bytes(CONTEXT_PATH,label="context capsule")).hexdigest()
        approval = humandecision.record_decision_approval(
            ROOT, load_json(CONFIG_PATH), load_json(TASK_PATH), gate="context-repair",
            artifact_sha256=repair_capsule_sha256, source=args.source,
            receipt=args.human_decision_receipt,
        )
        context["integrity"] = {
            "status": "verified",
            "verified_at": now(),
            "source": args.source,
            "repair_capsule_sha256": repair_capsule_sha256,
            "repair_approval": approval,
            "content_sha256": "0" * 64,
        }
        estimated = normalized_token_estimate(context)
        compaction = context.get("compaction")
        if not isinstance(compaction, dict) or int(compaction.get("source_estimated_tokens", 0)) < estimated:
            raise SystemExit("repair review changed capsule size beyond its source estimate; repair again")
        update_compaction_metrics(compaction, estimated)
        context["integrity"]["content_sha256"] = content_sha256(context)
        atomic_json(CONTEXT_PATH, context)
        return validate_context()

    if args.source_tokens <= 0:
        raise SystemExit("--source-tokens must be a positive explicit pre-compaction estimate")
    if args.command == "repair" and args.host_compaction:
        raise SystemExit("repair cannot claim a host compaction; repair and active-window reset are separate controls")
    if args.command == "sync" and args.reset:
        raise SystemExit("sync --reset is forbidden; use a bound transition or fail-closed repair")
    previous, previous_file_sha256 = safe_previous()
    if args.command == "repair" and previous:
        prior_freshness = previous.get("usage_freshness")
        prior_estimate = (
            prior_freshness.get("estimated_tokens")
            if isinstance(prior_freshness, dict)
            else None
        )
        if (
            isinstance(prior_estimate, int)
            and not isinstance(prior_estimate, bool)
            and args.source_tokens < prior_estimate
        ):
            raise SystemExit(
                "context repair cannot lower the active-window estimate; "
                "only a verified host compaction may establish a lower value"
            )
    pending_host = previous.get("host_compaction") if isinstance(previous, dict) else None
    if (
        isinstance(pending_host, dict)
        and pending_host.get("state") == "awaiting_host_compaction"
        and not args.host_compaction
        and not (args.command == "repair" and args.reset)
    ):
        raise SystemExit(
            "context and TASK transitions are paused until the pending host compaction is resumed "
            "with a verified receipt, abandoned with abort-host-compaction, or rebuilt with repair --reset"
        )
    transition_authorization: Optional[Dict[str, object]] = None
    if args.command == "sync" and CONTEXT_PATH.is_file():
        if args.transition:
            if args.host_compaction:
                raise SystemExit("a canonical TASK transition cannot also claim a host context compaction")
            expected = previous.get("task_invariant_sha256")
            if not args.from_task_sha256 or args.from_task_sha256 != expected or not HEX64.fullmatch(args.from_task_sha256):
                raise SystemExit("transition must bind --from-task-sha256 to the verified previous capsule")
            if invariant_sha256(load_json(TASK_PATH)) == expected:
                raise SystemExit("--transition requires an actual canonical TASK state change; use plain sync for compaction")
            if not args.authorization:
                raise SystemExit("transition requires a fresh field-level authorization from a canonical TASK mutator")
            transition_authorization, before_task = authorization_receipt(
                args.authorization, args, previous, load_json(TASK_PATH)
            )
            errors = stored_capsule_errors(before_task)
            if errors:
                raise SystemExit("context drift or corruption detected; use repair instead of overwriting evidence:\n- " + "\n- ".join(errors))
            minimum_source_tokens = automatic_transition_source_tokens(
                load_json(CONFIG_PATH), previous, load_json(TASK_PATH)
            )
            if args.source_tokens < minimum_source_tokens:
                raise SystemExit(
                    "canonical context transition estimate cannot decrease or stand still: "
                    f"received {args.source_tokens}, requires at least {minimum_source_tokens}"
                )
        else:
            if args.from_task_sha256 or args.authorization:
                raise SystemExit("--from-task-sha256/--authorization are valid only with --transition")
            # A capsule that is otherwise exact may be refreshed after its
            # checkpoint-age lease expires. Drift, corruption, oversize state,
            # or an unreviewed repair still fail closed and require repair.
            if (
                validate_context(quiet=True, ignore_checkpoint_age=True) != 0
                and not legacy_usage_upgrade_allowed(previous)
            ):
                raise SystemExit("context drift or corruption detected; use a bound transition or repair")
            prior_freshness = previous.get("usage_freshness")
            prior_estimate = (
                prior_freshness.get("estimated_tokens")
                if isinstance(prior_freshness, dict) else None
            )
            if args.request_host_compaction and args.host_compaction:
                raise SystemExit("request and resume host compaction are distinct transitions")
            if args.request_host_compaction and isinstance(previous.get("host_compaction"), dict) and previous["host_compaction"].get("state") == "awaiting_host_compaction":
                raise SystemExit("host compaction is already awaiting a host receipt")
            if args.request_host_compaction:
                # Entering the awaiting state without a configured observer
                # adapter is a one-way deadlock: the only resume path requires
                # a receipt the host can never verify.
                observer = load_json(CONFIG_PATH).get("context", {})
                observer = observer.get("host_compaction_observer", {}) if isinstance(observer, dict) else {}
                adapter_raw = observer.get("signed_adapter") if isinstance(observer, dict) else None
                if not isinstance(adapter_raw, str) or not adapter_raw.strip():
                    raise SystemExit(
                        "host compaction is unsupported until context.host_compaction_observer.signed_adapter "
                        "is configured; requesting the awaiting state without it would be unrecoverable"
                    )
                humandecision.adapter_path(
                    ROOT, adapter_raw, required_operations=("verify-host-compaction",),
                )
                if not handoff_artifact_present(previous, load_json(TASK_PATH)):
                    raise SystemExit(
                        "host compaction request requires a written compact handoff: the verified capsule "
                        "must carry an agent-context-resume/v1 contract bound to the current TASK"
                    )
            if isinstance(prior_estimate, int) and args.source_tokens < prior_estimate:
                if not args.host_compaction:
                    raise SystemExit(
                        "plain context refresh cannot lower the active-window estimate; "
                        "use --host-compaction only after an actual host context compaction"
                    )
                if not str(args.source).startswith("host:"):
                    raise SystemExit("--host-compaction requires an explicit host:* source")
                host_state = previous.get("host_compaction")
                if not isinstance(host_state, dict) or host_state.get("state") != "awaiting_host_compaction":
                    raise SystemExit("host compaction must follow a handoff_written -> awaiting_host_compaction transition")
                if not args.host_compaction_receipt:
                    raise SystemExit("--host-compaction requires --host-compaction-receipt")
                args.verified_host_compaction_receipt = verify_host_compaction_receipt(
                    args.host_compaction_receipt, load_json(TASK_PATH), prior_estimate, args.source_tokens,
                )
            elif args.host_compaction:
                raise SystemExit("--host-compaction must establish a strictly lower active-window estimate")
    elif args.command == "sync" and args.transition:
        raise SystemExit("initial context creation must use plain sync, not transition")
    elif args.command == "sync" and args.host_compaction:
        raise SystemExit("initial context creation cannot claim a host compaction")
    elif args.command == "sync" and args.request_host_compaction:
        raise SystemExit("initial context creation cannot request a host compaction; no handoff has been written")

    integrity_status = "needs_review" if args.command == "repair" else "verified"
    context = build_capsule(
        args, integrity_status, previous, previous_file_sha256, transition_authorization
    )
    atomic_json(CONTEXT_PATH, context)
    if args.command == "repair":
        print("CONTEXT REPAIRED: review is required before work continues")
        return 1
    return validate_context()


def main() -> int:
    try: lock_handle=boundedio.open_private_lock(LOCK_PATH,label="context capsule lock")
    except RuntimeError as error: raise SystemExit(str(error)) from error
    with lock_handle as handle:
        fcntl.flock(handle.fileno(),fcntl.LOCK_EX)
        return _main()


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
