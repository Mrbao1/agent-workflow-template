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
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple

import humandecision
from workflowlib import budget as total_budget


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

# This snapshot binds the enumerated canonical TASK fields: scope, routing,
# evidence, gates, rollback behavior, resource budgets and completion
# semantics.  "projection" is bound only when the field is present on TASK, so
# capsules sealed before the field existed keep their historical digests.
# Top-level fields outside this list are NOT integrity-bound: a canonical
# transition commits them wholesale and records their changed field names in
# the transition authorization receipt for audit (see authorization_receipt).
TASK_INVARIANT_KEYS = (
    "schema",
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
        "requirement_contract_sha256", "primary_skill", "selected_templates",
        "selected_capabilities", "template_route", "rendered_artifacts", "status",
        "phase", "current_node", "accepted_nodes", "node_artifacts", "gate_approvals",
        "pending_gate_artifacts", "decision_packet", "open_questions", "next_action",
        "mode_status", "clarification_archive", "budget_state", "updated",
    },
    ("templatectl", "route"): {
        "selected_templates", "selected_capabilities", "template_route", "rendered_artifacts",
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
    },
    ("workflowctl", "return-node"): {
        "current_node", "status", "phase", "next_action", "accepted_nodes",
        "node_artifacts", "rollback_ledger", "rollback_archive", "failure_ledger",
        "failure_archive",
    },
    ("workflowctl", "compact-state"): {
        "rollback_ledger", "rollback_archive", "failure_ledger", "failure_archive",
    },
    ("workflowctl", "complete-task"): {
        "retrospective", "knowledge_candidates", "current_node", "status", "phase", "next_action",
        "completion_binding",
    },
}


def load_json(path: Path) -> Dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON object required: {path}")
    return value


def atomic_json(path: Path, value: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def contract_sha256() -> str:
    return hashlib.sha256(CONTRACT_PATH.read_bytes()).hexdigest() if CONTRACT_PATH.is_file() else "missing"


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
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


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
    paths = [CONFIG_PATH, AGENT_DIR / "INDEX.md", AGENT_DIR / "templates/manifest.json"]
    primary = str(task.get("primary_skill", ""))
    if primary:
        paths.append(AGENT_DIR / "skills" / primary / "SKILL.md")
    paths.extend(sorted((AGENT_DIR / "workflows").glob("*.md")))
    if version == POLICY_BUNDLE_VERSION:
        paths.append(AGENT_DIR / "policies" / "PROJECT_GUARDRAILS.md")
        paths.extend(sorted((AGENT_DIR / "scripts").rglob("*.py")))
        if primary:
            for name in ("scripts", "references"):
                base = AGENT_DIR / "skills" / primary / name
                if base.is_dir():
                    paths.extend(sorted(path for path in base.rglob("*") if not path.is_dir()))
    entries = []
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"policy bundle file is missing or unsafe: {path.relative_to(ROOT)}")
        entries.append({"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
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
        for key in ("source_estimated_tokens", "capsule_estimated_tokens", "tokens_removed", "compression_ratio"):
            compaction[key] = 0
    integrity = clone.get("integrity")
    if isinstance(integrity, dict):
        integrity["content_sha256"] = "0" * 64
    encoded = json.dumps(clone, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
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
) -> Dict[str, object]:
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
        age = (dt.datetime.now(dt.timezone.utc) - issued.astimezone(dt.timezone.utc)).total_seconds()
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
    return {
        "schema": value["schema"],
        "mutator": profile[0],
        "operation": profile[1],
        "changed_fields": actual,
        "non_invariant_changed_fields": non_invariant,
        "receipt_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def list_value(value: object) -> List[str]:
    if not isinstance(value, list):
        return []
    return list(dict.fromkeys(str(item).strip() for item in value if isinstance(item, str) and item.strip()))


def safe_previous() -> Tuple[Dict[str, object], str]:
    if not CONTEXT_PATH.is_file():
        return {}, "none"
    digest = hashlib.sha256(CONTEXT_PATH.read_bytes()).hexdigest()
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

    A canonical transition adds control-plane work to the same active context;
    it is not evidence that the session was compacted.  Therefore its estimate
    must advance from the prior checkpoint.  The per-transition floor is the
    estimated per-turn host overhead (``context.estimated_turn_overhead_tokens``
    — system-prompt replay plus turn cost) plus the inherited host context
    charged per root turn; the deprecated
    ``context.automatic_transition_token_increment`` alias keeps its exact
    legacy arithmetic.  When two provider-observed cumulative usage receipts
    exist, their measured delta is preferred over the estimate.  A
    provider-verified cumulative measurement remains in TASK.tokens_used for
    the independent cost gate; it is not an active-window measurement and must
    not undo a real compaction. Only an explicit plain ``sync`` (the real
    compaction path) may establish a lower active-context baseline.
    """
    mode = str(task.get("mode", ""))
    measured = total_budget.measured_turn_delta(task)
    if measured is not None:
        increment = measured
    else:
        try:
            increment = total_budget.transition_overhead_estimate(config, mode)
        except ValueError as error:
            raise SystemExit(
                f"context turn-overhead estimate is unusable: {error} "
                f"(configure context.estimated_turn_overhead_tokens; "
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


def resume_contract(task: Dict[str, object], snapshot_sha256: str) -> Dict[str, object]:
    status=task.get("status"); current=task.get("current_node")
    terminal=status=="accepted" and current=="idle"
    if terminal:
        action="complete"
    elif status in {"idle","waiting_human"} or task.get("budget_state")=="hard_blocked":
        action="waiting_human"
    else:
        action="continue"
    return {
        "schema":"agent-context-resume/v1","task_status":status,"current_node":current,
        "next_action":task.get("next_action"),"budget_state":task.get("budget_state"),
        "terminal":terminal,"resume_action":action,"task_invariant_sha256":snapshot_sha256,
    }


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
        "resume": resume_contract(task, snapshot_sha256),
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
        "compaction": {
            "source_estimated_tokens": int(args.source_tokens),
            "capsule_estimated_tokens": 0,
            "tokens_removed": 0,
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
    compaction["capsule_estimated_tokens"] = estimated
    compaction["tokens_removed"] = int(args.source_tokens) - estimated
    compaction["compression_ratio"] = round(int(args.source_tokens) / max(estimated, 1), 2)
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
    if isinstance(source, int) and compaction.get("tokens_removed") != source - estimate:
        errors.append("stored removed-token evidence is stale")
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
                    if verified != record:
                        errors.append("stored host compaction receipt or adapter provenance drifted")
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
    adapter = humandecision.adapter_path(ROOT, adapter_raw)
    path = (ROOT / raw).resolve()
    try: path.relative_to(ROOT)
    except ValueError: raise SystemExit("host compaction receipt escapes project")
    if not path.is_file() or path.is_symlink(): raise SystemExit("host compaction receipt is missing or unsafe")
    value = load_json(path)
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
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    result = subprocess.run(
        [str(adapter), "verify-host-compaction", "--receipt", str(path)], cwd=str(ROOT), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
    )
    if result.returncode or result.stdout.strip() != f"VERIFIED HOST COMPACTION sha256={digest}":
        raise SystemExit("host compaction adapter rejected the receipt")
    return {
        "path": str(path.relative_to(ROOT)), "sha256": digest, "bytes": path.stat().st_size,
        "task_invariant_sha256": value["task_invariant_sha256"],
        "host_id": value["host_id"], "observed_at": value["observed_at"],
        "adapter_path": str(adapter), "adapter_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
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


def stored_capsule_errors() -> List[str]:
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
    try:
        errors.extend(repair_approval_errors(context, load_json(CONFIG_PATH), load_json(TASK_PATH)))
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
    exact = {
        "task_title": task.get("title"),
        "phase": task.get("phase"),
        "mode": task.get("mode"),
        "task_invariant_sha256": invariant_sha256(task),
        "requirement_contract_sha256": governed_contract_binding(task),
        "decisions": list_value(task.get("decisions")),
        "open_questions": list_value(task.get("open_questions")),
        "next_action": task.get("next_action"),
        "resume": resume_contract(task, invariant_sha256(task)),
    }
    for key, expected in exact.items():
        if context.get(key) != expected:
            errors.append(f"{key} drifted from canonical task/contract state")
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
    if not context.get("confirmed_facts"):
        errors.append("confirmed_facts cannot be empty")
    encoded = CONTEXT_PATH.read_bytes()
    if len(encoded) > int(policy.get("max_bytes", 8192)):
        errors.append("context capsule exceeds byte budget")
    estimate = normalized_token_estimate(context)
    errors.extend(internal_compaction_errors(context))
    errors.extend(usage_freshness_errors(context))
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
    with its approval in the capsule compaction block.  Approval routing
    matches repair: policy-v2 local tasks use a bound local approval,
    protected routes require a provider-signed receipt.
    """
    if not args.source.startswith("user:"):
        raise SystemExit("abort approval source must start with user:")
    context = load_json(CONTEXT_PATH)
    host = context.get("host_compaction")
    if not isinstance(host, dict) or host.get("state") != "awaiting_host_compaction":
        raise SystemExit("abort-host-compaction is valid only while a host compaction is awaited")
    task = load_json(TASK_PATH)
    config = load_json(CONFIG_PATH)
    capsule_sha256 = hashlib.sha256(CONTEXT_PATH.read_bytes()).hexdigest()
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
    compaction["capsule_estimated_tokens"] = estimated
    compaction["tokens_removed"] = int(compaction["source_estimated_tokens"]) - estimated
    compaction["compression_ratio"] = round(int(compaction["source_estimated_tokens"]) / max(estimated, 1), 2)
    integrity["verified_at"] = now()
    integrity["content_sha256"] = "0" * 64
    integrity["content_sha256"] = content_sha256(context)
    atomic_json(CONTEXT_PATH, context)
    result = validate_context(ignore_checkpoint_age=True)
    if result == 0:
        print("HOST COMPACTION ABORTED: awaiting state cleared; renew the checkpoint with a plain sync before continuing")
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
            print(json.dumps(status, ensure_ascii=False, indent=2))
            return 0
        print(json.dumps(status, ensure_ascii=False, indent=2))
        return 0 if status.get("state") == "restored" else 1
    if args.command == "abort-host-compaction":
        return abort_host_compaction(args)
    if args.command == "approve-repair":
        if not args.source.startswith("user:"):
            raise SystemExit("repair approval source must start with user:")
        context = load_json(CONTEXT_PATH)
        if not isinstance(context.get("integrity"), dict) or context["integrity"].get("status") != "needs_review":
            raise SystemExit("no repaired context is waiting for review")
        repair_capsule_sha256 = hashlib.sha256(CONTEXT_PATH.read_bytes()).hexdigest()
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
        compaction["capsule_estimated_tokens"] = estimated
        compaction["tokens_removed"] = int(compaction["source_estimated_tokens"]) - estimated
        compaction["compression_ratio"] = round(int(compaction["source_estimated_tokens"]) / max(estimated, 1), 2)
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
            errors = stored_capsule_errors()
            if errors:
                raise SystemExit("context drift or corruption detected; use repair instead of overwriting evidence:\n- " + "\n- ".join(errors))
            expected = previous.get("task_invariant_sha256")
            if not args.from_task_sha256 or args.from_task_sha256 != expected or not HEX64.fullmatch(args.from_task_sha256):
                raise SystemExit("transition must bind --from-task-sha256 to the verified previous capsule")
            if invariant_sha256(load_json(TASK_PATH)) == expected:
                raise SystemExit("--transition requires an actual canonical TASK state change; use plain sync for compaction")
            if not args.authorization:
                raise SystemExit("transition requires a fresh field-level authorization from a canonical TASK mutator")
            transition_authorization = authorization_receipt(
                args.authorization, args, previous, load_json(TASK_PATH)
            )
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
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOCK_PATH.touch(exist_ok=True)
    with LOCK_PATH.open("r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return _main()


if __name__ == "__main__":
    raise SystemExit(main())
