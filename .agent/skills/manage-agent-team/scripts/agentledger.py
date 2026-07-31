#!/usr/bin/env python3
"""Locked, platform-snapshot-driven ledger for bounded child-agent work."""

from pathlib import Path
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Set, Tuple


def find_agent_dir() -> Path:
    for root in (Path.cwd().resolve(), *Path.cwd().resolve().parents):
        if (root / ".agent").is_dir():
            return root / ".agent"
    raise SystemExit(".agent directory not found")


AGENT = find_agent_dir(); ROOT = AGENT.parent.resolve()
sys.path.insert(0, str(AGENT / "scripts"))
from workflowlib import budget as unified_budget
import humandecision
import testrun as supervised_test
STATE = AGENT / "state/agents.json"; CONFIG = AGENT / "config.json"; TASK = AGENT / "state/TASK.json"
LOCK = AGENT / "state/.agents.lock"; ACTIVE = "active"; TERMINAL = {"completed", "interrupted", "errored", "expired", "lost"}
CHAIN_JOURNAL = AGENT / "state/agents-chain.jsonl"
SHA = re.compile(r"[0-9a-f]{64}")
SCHEMA = "agent-team/v9"
TOKEN_ACCOUNTING_SCHEMA = "agent-child-token-accounting/v1"
TOKEN_CHARGE_SCHEMA = "agent-child-token-charge/v1"
PLATFORM_SCHEMA = "agent-platform-snapshot/v3"
HANDOFF_SCHEMA = "agent-handoff-envelope/v3"
TASK_PAYLOAD_SCHEMA = "agent-task-payload/v2"
TASK_PAYLOAD_DRAFT_SCHEMA = "agent-task-payload-draft/v1"
TERMINAL_MARKER_SCHEMA = "agent-terminal-marker/v6"
REVIEW_ATTESTATION_SCHEMA = "agent-review-attestation/v2"
LEGACY_REVIEW_ATTESTATION_SCHEMA = "agent-review-attestation/v1"
IMPLEMENTATION_ATTESTATION_SCHEMA = "agent-implementation-attestation/v1"
NODE6_ARTIFACT_PATH = ".agent/state/artifacts/06-implementation.json"
REPLAY_PLAN_SCHEMA = "agent-replay-plan/v1"
REPLAY_OBSERVATION_SCHEMA = "agent-replay-observation/v1"
REVIEW_VERDICT_LINE = re.compile(r"^VERDICT (PASS|FAIL) P0=([0-9]+) P1=([0-9]+) P2=([0-9]+)$")
REVIEW_ATTESTATION_PREFIX = "ATTESTATION "
SCENARIO_RECEIPT_PREFIX = "SCENARIO_RECEIPT "
SCENARIO_RECEIPT_SCHEMA = "agent-role-scenario-receipt/v1"
REVIEW_CHAIN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
RUN_ID = re.compile(r"[0-9a-f]{32}")
TIMESTAMP_SKEW_SECONDS = 5
WATCHDOG_MAX_DELAY_SECONDS = 60
PREPARED_DISPATCH_TTL_SECONDS = 300
# Register/dispatch enforces PREPARED_DISPATCH_TTL_SECONDS; validate only
# warns past that TTL so a slow-but-legitimate dispatch does not close every
# validate caller, and fails hard only past this much larger bound.
PREPARED_DISPATCH_VALIDATE_EXPIRY_SECONDS = 3600
LOST_OBSERVATION_THRESHOLD = 3
LEDGER_FORCE_ARCHIVE_SCHEMA = "agent-ledger-force-archive/v1"
CANONICAL_ROLE_TYPES = (
    "worker", "researcher", "documentation-worker", "implementer",
    "reviewer", "adversarial", "cross", "integrator",
)
CANONICAL_REVIEW_ROLE_TYPES = ("reviewer", "adversarial", "cross", "integrator")
FORMAL_REVIEW_ROLE_TYPES = ("adversarial", "cross", "integrator")
CROSS_REVIEW_LENSES = (
    "product", "architecture", "qa", "security", "operations",
    "ai-workflow-new-project-adopter",
)
PLATFORM_ACTIVE = {"active", "running", "pending", "working", "waiting"}
PLATFORM_TERMINAL = {
    "completed": {"completed", "finished", "done"},
    "interrupted": {"interrupted", "cancelled", "canceled", "stopped"},
    "errored": {"errored", "error", "failed"},
    "expired": {
        "completed", "finished", "done", "interrupted", "cancelled", "canceled",
        "stopped", "errored", "error", "failed",
    },
}


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(value: dt.datetime) -> str:
    return value.isoformat()


def parse(value: object) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(dt.timezone.utc)


def integer(value: object, default: int = -1) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load(path: Path) -> Dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON object required: {path}")
    return value


def ledger_bytes(value: Dict[str, object]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def chain_upgrade(value: Dict[str, object], previous: Optional[bytes]) -> None:
    """Advance the append hash chain; a legacy ledger restarts at genesis once."""
    revision = value.get("revision")
    if revision is None:
        value["revision"] = 1
        value["prev_sha256"] = None
        return
    if not isinstance(revision, int) or revision < 1:
        raise SystemExit("agent ledger chain revision is invalid")
    if previous is None:
        raise SystemExit("agent ledger chain continuity is lost: state file is missing")
    value["revision"] = revision + 1
    value["prev_sha256"] = hashlib.sha256(previous).hexdigest()


def chain_journal_append(value: Dict[str, object], data: bytes) -> None:
    entry = {
        "revision": value["revision"], "prev_sha256": value["prev_sha256"],
        "file_sha256": hashlib.sha256(data).hexdigest(),
    }
    with CHAIN_JOURNAL.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush(); os.fsync(handle.fileno())


def save(value: Dict[str, object]) -> None:
    chain_upgrade(value, STATE.read_bytes() if STATE.is_file() else None)
    data = ledger_bytes(value)
    descriptor, raw = tempfile.mkstemp(prefix=".agents.", dir=str(STATE.parent))
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, STATE)
    finally:
        if temporary.exists():
            temporary.unlink()
    chain_journal_append(value, data)


def commit_registered_ledger(state: Dict[str, object]) -> None:
    """Atomically commit ledger registration and TASK child metrics."""
    if not (AGENT / "state/CONTEXT.json").is_file():
        # Reduced unit harnesses without the canonical context controller can
        # exercise ledger semantics, but installed projects always take the
        # atomic TASK/context/ledger path below.
        save(state)
        return
    import contexttx
    before = load(TASK); after = json.loads(json.dumps(before))
    after["child_agents_used"] = integer(before.get("child_agents_used"), 0) + 1
    after["peak_child_agents"] = max(integer(before.get("peak_child_agents"), 0), len(active(state)))
    metrics = after.setdefault("metrics", {})
    metrics["child_agents"] = after["child_agents_used"]
    metrics["peak_children"] = after["peak_child_agents"]
    try: after["budget_state"] = unified_budget.snapshot(after, load(CONFIG), state)["state"]
    except ValueError as error: raise SystemExit(str(error))
    after["updated"] = now().date().isoformat()
    chain_upgrade(state, STATE.read_bytes() if STATE.is_file() else None)
    data = ledger_bytes(state)
    contexttx.transition_task(
        before, after, mutator="agentledger", operation="register",
        reason="agent-registered", summary="automatically accounted a registered child Agent",
        side_effects=[(STATE, data)],
    )
    chain_journal_append(state, data)


def active(state: Dict[str, object]) -> List[Dict[str, object]]:
    return [item for item in state.get("members", []) if isinstance(item, dict) and item.get("status") == ACTIVE]


def member(state: Dict[str, object], agent_id: str) -> Dict[str, object]:
    found = [item for item in state.get("members", []) if isinstance(item, dict) and item.get("id") == agent_id]
    if len(found) != 1:
        raise SystemExit(f"agent must occur exactly once: {agent_id}")
    return found[0]


def mode_limit() -> int:
    config, task = load(CONFIG), load(TASK)
    return int(config["routing"]["modes"][task["mode"]]["max_child_agents"])


def required_clean_replays() -> int:
    value = integer(load(CONFIG).get("routing", {}).get("modes", {}).get("release", {}).get("clean_reruns"))
    if value != 1:
        raise SystemExit("release clean replay policy must be exactly one")
    return value


def current_candidate_sha256() -> str:
    """Use the canonical governed-product fingerprint, never a review payload hash."""
    return supervised_test.candidate_fingerprint(load(CONFIG))


def policy() -> Dict[str, object]:
    return load(CONFIG)["agent_control"]


def platform_observer_policy() -> Dict[str, object]:
    """Expose local-manual assurance or a configured provider adapter."""
    value = policy().get("platform_observer")
    required = {
        "source", "automatic_release_trust", "human_verification_required", "signed_adapter",
    }
    if (
        not isinstance(value, dict) or set(value) != required
        or value.get("source") != "orchestrator-tool-transcript"
        or value.get("automatic_release_trust") is not False
        or value.get("human_verification_required") is not True
        or (value.get("signed_adapter") is not None and not isinstance(value.get("signed_adapter"), str))
    ):
        raise SystemExit(
            "platform observer must disclose human transcript verification; "
            "release trust requires a provider-owned signed adapter"
        )
    return dict(value)


def task_payload_limits() -> Dict[str, int]:
    """Return the canonical executable input/context budget."""
    config = policy()
    limits = {
        "max_input_count": integer(config.get("max_task_payload_input_count")),
        "max_single_bytes": integer(config.get("max_task_payload_single_bytes")),
        "max_total_bytes": integer(config.get("max_task_payload_total_bytes")),
        "max_estimated_tokens": integer(config.get("max_task_payload_estimated_tokens")),
    }
    if (
        limits["max_input_count"] < 1 or limits["max_input_count"] > 64
        or limits["max_single_bytes"] < 1
        or limits["max_total_bytes"] < limits["max_single_bytes"]
        or limits["max_estimated_tokens"] < 1
    ):
        raise SystemExit("task payload budget policy is invalid")
    return limits


def dispatch_context_policy() -> Dict[str, object]:
    """Return the fail-closed policy for new child prompts.

    Historical ledger entries may retain a non-zero fork window for audit
    replay, but every new dispatch is capsule/payload complete and therefore
    must not duplicate parent-chat turns.
    """
    config = policy()
    limits = config.get("dispatch_payload_token_limits")
    expected_modes = {"fast", "standard", "release"}
    if (
        config.get("inherit_parent_history") is not False
        or not isinstance(limits, dict)
        or set(limits) != expected_modes
        or any(
            not isinstance(limits.get(mode), int)
            or isinstance(limits.get(mode), bool)
            or int(limits.get(mode, -1)) < 0
            for mode in expected_modes
        )
        or int(limits.get("fast", -1)) != 0
        or int(limits.get("standard", 0)) < 1000
        or int(limits.get("release", 0)) < int(limits.get("standard", 0))
        or int(limits.get("release", 0)) > integer(config.get("max_task_payload_estimated_tokens"), 0)
    ):
        raise SystemExit("new-dispatch context policy is missing or malformed")
    return {
        "inherit_parent_history": False,
        "payload_token_limits": {mode: int(limits[mode]) for mode in sorted(expected_modes)},
    }


def require_dispatch_fork(fork_turns: int) -> Dict[str, object]:
    """Reject a new host dispatch before it can publish any evidence."""
    active = dispatch_context_policy()
    if fork_turns != 0:
        raise SystemExit(
            "new Agent dispatch must use fork_turns=0; seal the complete bounded context in the task payload"
        )
    return active


def require_dispatch_context(fork_turns: int, estimated_tokens: int) -> None:
    """Reject duplicated chat history and over-broad sealed child context."""
    active = require_dispatch_fork(fork_turns)
    mode = str(load(TASK).get("mode"))
    limits = active["payload_token_limits"]
    limit = int(limits.get(mode, -1)) if isinstance(limits, dict) else -1
    if estimated_tokens < 1 or limit < 1 or estimated_tokens > limit:
        raise SystemExit(
            f"task payload estimate {estimated_tokens} exceeds the {mode} new-dispatch limit {max(limit, 0)}"
        )


def task_payload_semantic_bytes(objective: object, constraints: object,
                                acceptance: object) -> int:
    """Count the reusable prompt text as well as referenced artifact bytes."""
    value = {
        "objective": objective,
        "shared_constraints": constraints,
        "acceptance_criteria": acceptance,
    }
    return len(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8"))


def task_payload_metrics(sizes: List[int], semantic_bytes: int = 0) -> Dict[str, int]:
    total = sum(sizes)
    return {
        "input_count": len(sizes),
        "max_single_bytes": max(sizes, default=0),
        "total_bytes": total,
        "estimated_tokens": (total + max(0, semantic_bytes) + 3) // 4,
    }


def task_payload_within_limits(sizes: List[int], semantic_bytes: int = 0) -> bool:
    try:
        limits = task_payload_limits()
    except SystemExit:
        return False
    metrics = task_payload_metrics(sizes, semantic_bytes)
    return (
        metrics["input_count"] <= limits["max_input_count"]
        and metrics["max_single_bytes"] <= limits["max_single_bytes"]
        and metrics["total_bytes"] <= limits["max_total_bytes"]
        and metrics["estimated_tokens"] <= limits["max_estimated_tokens"]
    )


def mode_token_budget() -> Tuple[int, int]:
    """Return the mode budget and root-recorded usage without touching context."""
    config, task = load(CONFIG), load(TASK)
    mode = task.get("mode")
    try:
        budget = int(config["routing"]["modes"][mode]["token_budget"])
        declared = int(task["token_budget"])
        used = int(task["tokens_used"])
    except (KeyError, TypeError, ValueError):
        raise SystemExit("task/mode token budget is invalid")
    if budget < 1 or declared != budget or used < 0:
        raise SystemExit("task token budget must equal the current mode and usage must be non-negative")
    return budget, used


def token_reservations(state: Dict[str, object]) -> List[Dict[str, object]]:
    reservations: List[Dict[str, object]] = []
    for preparation in state.get("prepared_dispatches", []):
        if isinstance(preparation, dict) and isinstance(preparation.get("token_reservation"), dict):
            reservations.append(preparation["token_reservation"])
    return reservations


def token_budget_snapshot(state: Dict[str, object]) -> Dict[str, int]:
    """Return the same total account exposed by agentctl status/budget-gate."""
    budget, root_used = mode_token_budget()
    accounting = state.get("token_accounting")
    if (
        not isinstance(accounting, dict)
        or accounting.get("schema") != TOKEN_ACCOUNTING_SCHEMA
        or accounting.get("token_budget") != budget
    ):
        raise SystemExit("child token accounting is missing or differs from the current mode")
    reservations = token_reservations(state)
    settled_payload = sum(
        integer(item.get("estimated_tokens"), 0)
        for item in reservations if item.get("status") == "settled"
    )
    if accounting.get("settled_tokens") != settled_payload:
        raise SystemExit("child token accounting total differs from settled reservations")
    try:
        total = unified_budget.snapshot(load(TASK), load(CONFIG), state)
    except ValueError as error:
        raise SystemExit(str(error))
    return {
        "budget": budget, "root_used": root_used,
        "references": int(total["reference_tokens"]),
        "reserved": int(total["child_reserved_tokens"]),
        "settled": int(total["child_settled_tokens"]),
        "consumed": int(total["consumed_tokens"]),
        "remaining": int(total["remaining_tokens"]),
        "over_budget": int(total["over_budget_tokens"]),
    }


def require_payload_token_budget(state: Dict[str, object], estimated_tokens: int,
                                 fork_turns: Optional[int] = None) -> None:
    if fork_turns is None:
        fork_turns = integer(policy().get("default_fork_turns"), 0)
    require_dispatch_context(fork_turns, estimated_tokens)
    additional = {
        "fork_turns": fork_turns,
        "token_reservation": {"status": "reserved", "estimated_tokens": estimated_tokens},
    }
    try:
        total = unified_budget.snapshot(load(TASK), load(CONFIG), state, additional_child=additional)
    except ValueError as error:
        raise SystemExit(str(error))
    snapshot = token_budget_snapshot(state)
    requested = estimated_tokens + fork_turns * integer(policy().get("inherited_turn_estimated_tokens"), 800) + integer(policy().get("child_system_tool_margin_tokens"), 4000) + integer(policy().get("child_output_margin_tokens"), 2000)
    if estimated_tokens < 1 or int(total["over_budget_tokens"]) > 0:
        raise SystemExit(
            "task payload exceeds the current mode remaining token budget: "
            + json.dumps({**snapshot, "requested": requested, "fork_turns": fork_turns}, sort_keys=True, separators=(",", ":"))
        )


def token_reservation_id(state: Dict[str, object], agent_id: str,
                         payload_sha256: str, estimated_tokens: int) -> str:
    return hashlib.sha256(
        f"{state.get('epoch')}|{agent_id}|{payload_sha256}|{estimated_tokens}".encode()
    ).hexdigest()


def settle_token_reservation(state: Dict[str, object], item: Dict[str, object],
                             terminal_status: str, terminal_observed_at: str) -> Dict[str, object]:
    """Settle one prepare-time reservation exactly once using immutable event bytes."""
    matches = [
        preparation for preparation in state.get("prepared_dispatches", [])
        if isinstance(preparation, dict) and preparation.get("id") == item.get("id")
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("token_reservation"), dict):
        raise SystemExit("terminal Agent lacks its unique token reservation")
    reservation = matches[0]["token_reservation"]
    if reservation.get("id") != item.get("token_reservation_id"):
        raise SystemExit("member token reservation differs from preparation")
    value = {
        "schema": TOKEN_CHARGE_SCHEMA,
        "ledger_epoch": state.get("epoch"),
        "reservation_id": reservation.get("id"),
        "agent_id": item.get("id"),
        "root_task_id": item.get("root_task_id"),
        "task_payload_sha256": item.get("task_payload_sha256"),
        "estimated_tokens": reservation.get("estimated_tokens"),
        "terminal_status": terminal_status,
        "terminal_observed_at": terminal_observed_at,
    }
    receipt = publish_generated_blob(value, "agent-token-charges", ".json", "agent-token-charge")
    if reservation.get("status") == "settled":
        if reservation.get("charge_receipt") != receipt:
            raise SystemExit("settled child token charge differs from its immutable receipt")
        return receipt
    if reservation.get("status") != "reserved":
        raise SystemExit("only a reserved child token charge can settle")
    reservation.update({
        "status": "settled", "closed_at": terminal_observed_at,
        "charge_receipt": receipt,
    })
    accounting = state.get("token_accounting")
    if not isinstance(accounting, dict):
        raise SystemExit("child token accounting is missing")
    accounting["settled_tokens"] = integer(accounting.get("settled_tokens"), 0) + integer(
        reservation.get("estimated_tokens"), 0
    )
    return receipt


def token_charge_from_receipt(record: object) -> Optional[Dict[str, object]]:
    if not content_addressed_receipt(record, "agent-token-charges", ".json"):
        return None
    try:
        value = load(ROOT / str(record["path"]))
    except (OSError, ValueError, json.JSONDecodeError, TypeError, KeyError, SystemExit):
        return None
    required = {
        "schema", "ledger_epoch", "reservation_id", "agent_id", "root_task_id",
        "task_payload_sha256", "estimated_tokens", "terminal_status", "terminal_observed_at",
    }
    if (
        set(value) != required
        or value.get("schema") != TOKEN_CHARGE_SCHEMA
        or not SHA.fullmatch(str(value.get("ledger_epoch", "")))
        or not SHA.fullmatch(str(value.get("reservation_id", "")))
        or not SHA.fullmatch(str(value.get("task_payload_sha256", "")))
        or integer(value.get("estimated_tokens")) < 1
        or value.get("terminal_status") not in TERMINAL
    ):
        return None
    try:
        parse(value.get("terminal_observed_at"))
    except (TypeError, ValueError):
        return None
    return value


def release_token_reservation(state: Dict[str, object], item: Dict[str, object],
                              closed_at: str) -> None:
    """Release the prepare-time reservation of a lost child (mirrors cancel-prepare)."""
    matches = [
        preparation for preparation in state.get("prepared_dispatches", [])
        if isinstance(preparation, dict) and preparation.get("id") == item.get("id")
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("token_reservation"), dict):
        raise SystemExit("lost Agent lacks its unique token reservation")
    reservation = matches[0]["token_reservation"]
    if reservation.get("id") != item.get("token_reservation_id"):
        raise SystemExit("member token reservation differs from preparation")
    if reservation.get("status") == "released":
        if reservation.get("closed_at") != closed_at or reservation.get("charge_receipt") is not None:
            raise SystemExit("released child token reservation differs from the lost settlement")
        return
    if reservation.get("status") != "reserved":
        raise SystemExit("only a reserved child token reservation can be released")
    reservation.update({"status": "released", "closed_at": closed_at, "charge_receipt": None})


def lost_decision_binding(state: Dict[str, object], agent_id: str) -> str:
    return hashlib.sha256(f"agent-lost|{state.get('epoch')}|{agent_id}".encode()).hexdigest()


def require_sha(value: str, label: str = "progress hash") -> None:
    if not SHA.fullmatch(value):
        raise SystemExit(f"{label} must be lowercase SHA-256")


def evidence(raw: str) -> Dict[str, object]:
    path = (ROOT / raw).resolve()
    try:
        relative = str(path.relative_to(ROOT))
    except ValueError:
        raise SystemExit("evidence path escapes project")
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"evidence is missing: {relative}")
    data = path.read_bytes()
    return {"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def immutable_platform_evidence(raw: str) -> Tuple[Path, Dict[str, object]]:
    """Ingest a caller-owned snapshot into an immutable, content-addressed store.

    Callers commonly reuse a filename such as ``running.json`` for polling.  A
    ledger receipt must never point at that mutable path, otherwise the next
    poll destroys the historical proof.  The ledger lock serializes writers;
    the hard-link publish prevents an existing digest path from being replaced.
    """
    source_record = evidence(raw)
    source = ROOT / str(source_record["path"])
    data = source.read_bytes()
    digest = str(source_record["sha256"])
    directory = AGENT / "state/evidence/platform-snapshots"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{digest}.json"
    if os.path.lexists(target):
        if target.is_symlink() or not target.is_file() or target.read_bytes() != data:
            raise SystemExit(f"immutable platform snapshot collision or mutation: {target.relative_to(ROOT)}")
    else:
        descriptor, raw_temporary = tempfile.mkstemp(prefix=".platform-snapshot.", dir=str(directory))
        temporary = Path(raw_temporary)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data); handle.flush(); os.fsync(handle.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                if target.is_symlink() or not target.is_file() or target.read_bytes() != data:
                    raise SystemExit(f"immutable platform snapshot collision or mutation: {target.relative_to(ROOT)}")
            if target.is_file() and not target.is_symlink():
                target.chmod(0o444)
        finally:
            if temporary.exists():
                temporary.unlink()
    record = {"path": str(target.relative_to(ROOT)), "sha256": digest, "bytes": len(data)}
    return target, record


def immutable_blob_evidence(raw: str, directory_name: str, suffix: str, prefix: str) -> Dict[str, object]:
    """Copy caller bytes into a content-addressed immutable store."""
    source_record = evidence(raw)
    source = ROOT / str(source_record["path"])
    data = source.read_bytes()
    digest = str(source_record["sha256"])
    directory = AGENT / f"state/evidence/{directory_name}"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{digest}{suffix}"
    if os.path.lexists(target):
        if target.is_symlink() or not target.is_file() or target.read_bytes() != data:
            raise SystemExit(f"immutable {prefix} collision or mutation: {target.relative_to(ROOT)}")
    else:
        descriptor, raw_temporary = tempfile.mkstemp(prefix=f".{prefix}.", dir=str(directory))
        temporary = Path(raw_temporary)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data); handle.flush(); os.fsync(handle.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                if target.is_symlink() or not target.is_file() or target.read_bytes() != data:
                    raise SystemExit(f"immutable {prefix} collision or mutation: {target.relative_to(ROOT)}")
            if target.is_file() and not target.is_symlink():
                target.chmod(0o444)
        finally:
            if temporary.exists():
                temporary.unlink()
    return {"path": str(target.relative_to(ROOT)), "sha256": digest, "bytes": len(data)}


def immutable_task_payload_evidence(raw: str) -> Dict[str, object]:
    """Preserve the reusable bounded task/context payload."""
    return immutable_blob_evidence(raw, "agent-task-payloads", ".ctx", "agent-task-payload")


def immutable_input_artifact_evidence(raw: str) -> Dict[str, object]:
    """Seal one readable source file into the child-review input store."""
    source = evidence(raw)
    sealed = immutable_blob_evidence(raw, "agent-input-artifacts", ".blob", "agent-input-artifact")
    return {"label": source["path"], **sealed}


def input_artifact_receipt(record: object) -> bool:
    return (
        isinstance(record, dict)
        and set(record) == {"label", "path", "sha256", "bytes"}
        and safe_contract_path(record.get("label")) == record.get("label")
        and content_addressed_receipt(
            {key: record.get(key) for key in ("path", "sha256", "bytes")},
            "agent-input-artifacts", ".blob",
        )
    )


def result_evidence_receipt(record: object) -> bool:
    return (
        isinstance(record, dict)
        and set(record) == {"source_path", "path", "sha256", "bytes"}
        and safe_contract_path(record.get("source_path")) == record.get("source_path")
        and content_addressed_receipt(
            {key: record.get(key) for key in ("path", "sha256", "bytes")},
            "agent-result-evidence", ".result",
        )
    )


def immutable_result_evidence(raw: str) -> Dict[str, object]:
    """Preserve final reviewer-authored report bytes separately from live progress."""
    source = evidence(raw)
    sealed = immutable_blob_evidence(raw, "agent-result-evidence", ".result", "agent-result-evidence")
    return {"source_path": source["path"], **sealed}


def publish_generated_blob(value: Dict[str, object], directory_name: str,
                           suffix: str, prefix: str) -> Dict[str, object]:
    """Publish ledger-authored JSON bytes without trusting a caller timestamp."""
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    digest = hashlib.sha256(data).hexdigest()
    directory = AGENT / f"state/evidence/{directory_name}"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{digest}{suffix}"
    if os.path.lexists(target):
        if target.is_symlink() or not target.is_file() or target.read_bytes() != data:
            raise SystemExit(f"immutable {prefix} collision or mutation")
    else:
        descriptor, raw = tempfile.mkstemp(prefix=f".{prefix}.", dir=str(directory))
        temporary = Path(raw)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data); handle.flush(); os.fsync(handle.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                if target.is_symlink() or not target.is_file() or target.read_bytes() != data:
                    raise SystemExit(f"immutable {prefix} collision or mutation")
            target.chmod(0o444)
        finally:
            if temporary.exists(): temporary.unlink()
    return {"path": str(target.relative_to(ROOT)), "sha256": digest, "bytes": len(data)}


def review_verdict_from_result(record: object) -> Optional[Dict[str, object]]:
    """Derive the only review verdict accepted by finish and node 7."""
    if not result_evidence_receipt(record):
        return None
    try:
        data = (ROOT / str(record["path"])).read_bytes()
        text = data.decode("utf-8")
    except (OSError, UnicodeDecodeError, TypeError, KeyError):
        return None
    lines = text.splitlines()
    match = REVIEW_VERDICT_LINE.fullmatch(lines[0] if lines else "")
    if match is None:
        return None
    status = match.group(1); counts = [int(match.group(index)) for index in (2, 3, 4)]
    if any(value > 9999 for value in counts):
        return None
    if (status == "PASS") != (sum(counts) == 0):
        return None
    return {
        "status": status, "p0": counts[0], "p1": counts[1], "p2": counts[2],
        "report_sha256": record["sha256"],
    }


def review_attestation_from_result(record: object) -> Optional[Dict[str, object]]:
    """Parse the exact canonical second report line; prose never grants authority."""
    if not result_evidence_receipt(record):
        return None
    try:
        lines = (ROOT / str(record["path"])).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError, TypeError, KeyError):
        return None
    if len(lines) < 2 or not lines[1].startswith(REVIEW_ATTESTATION_PREFIX):
        return None
    raw = lines[1][len(REVIEW_ATTESTATION_PREFIX):]
    try:
        value = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    required = {
        "schema", "role_type", "review_chain_id", "review_subject_sha256",
        "predecessor_result_sha256", "lenses", "clean_replays",
    }
    if value.get("schema") == REVIEW_ATTESTATION_SCHEMA:
        required.add("targeted_cases")
    if (
        not isinstance(value, dict) or set(value) != required
        or value.get("schema") not in {REVIEW_ATTESTATION_SCHEMA, LEGACY_REVIEW_ATTESTATION_SCHEMA}
        or raw != json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    ):
        return None
    return value


def valid_targeted_cases(attestation: Dict[str, object], role_type: object) -> bool:
    """Reject self-reported Cases until envelope+runner+Agent receipts are bound.

    A reviewer-authored string list cannot prove who ran a command or which
    controlled runner produced it.  Empty is the only fail-closed declaration;
    the configured limit remains a ceiling for a future receipt-backed schema.
    """
    if attestation.get("schema") == LEGACY_REVIEW_ATTESTATION_SCHEMA:
        return True
    cases = attestation.get("targeted_cases")
    try:
        limit = int(load(CONFIG)["testing"]["reviewer_targeted_case_limit"])
    except (KeyError, TypeError, ValueError):
        return False
    if (
        not isinstance(cases, list) or limit < 0 or len(cases) > limit
        or len(cases) != len(set(cases))
        or any(not isinstance(case, str) or not case or len(case) > 128 for case in cases)
    ):
        return False
    return not cases


def cross_scenario_from_result(record: object, item: Dict[str, object]) \
        -> Optional[Tuple[Dict[str, object], str]]:
    """Validate the cross-owned six-role receipt before cross can become PASS."""
    if not result_evidence_receipt(record):
        return None
    try:
        lines = (ROOT / str(record["path"])).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError, TypeError, KeyError):
        return None
    if len(lines) < 3 or not lines[2].startswith(SCENARIO_RECEIPT_PREFIX):
        return None
    raw = lines[2][len(SCENARIO_RECEIPT_PREFIX):]
    try:
        value = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    required = {
        "schema", "review_chain_id", "review_subject_sha256", "reviewer_agent_id", "scenarios",
    }
    if (
        not isinstance(value, dict) or set(value) != required
        or value.get("schema") != SCENARIO_RECEIPT_SCHEMA
        or raw != json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        or value.get("review_chain_id") != item.get("review_chain_id")
        or value.get("review_subject_sha256") != item.get("review_subject_sha256")
        or value.get("reviewer_agent_id") != item.get("id")
    ):
        return None
    scenarios = value.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != len(CROSS_REVIEW_LENSES):
        return None
    scenario_ids: Set[str] = set()
    for index, scenario in enumerate(scenarios):
        required_scenario = {"id", "lens", "requirement_ids", "assertions", "evidence", "result"}
        if not isinstance(scenario, dict) or set(scenario) != required_scenario:
            return None
        scenario_id = scenario.get("id")
        if (
            not isinstance(scenario_id, str)
            or REVIEW_CHAIN_ID.fullmatch(scenario_id) is None
            or scenario_id in scenario_ids
            or scenario.get("lens") != CROSS_REVIEW_LENSES[index]
            or scenario.get("result") != "passed"
        ):
            return None
        scenario_ids.add(scenario_id)
        for field in ("requirement_ids", "assertions"):
            values = scenario.get(field)
            if (
                not isinstance(values, list) or not values or len(values) > 64
                or len(values) != len(set(values))
                or any(not isinstance(entry, str) or not entry or len(entry) > 500 for entry in values)
            ):
                return None
        scenario_evidence = scenario.get("evidence")
        if not isinstance(scenario_evidence, list) or not scenario_evidence or len(scenario_evidence) > 32:
            return None
        identities: Set[Tuple[object, object]] = set()
        for evidence_record in scenario_evidence:
            identity = (
                evidence_record.get("path") if isinstance(evidence_record, dict) else None,
                evidence_record.get("sha256") if isinstance(evidence_record, dict) else None,
            )
            if identity in identities or not content_addressed_receipt(
                evidence_record, "scenario-evidence", ".evidence",
            ):
                return None
            identities.add(identity)
    return value, hashlib.sha256(raw.encode()).hexdigest()


def clean_replay_run_id(record: object, registered_at: dt.datetime,
                        terminal_at: dt.datetime) -> Optional[str]:
    """Accept only a successful, internally consistent full test-run receipt."""
    if not result_evidence_receipt(record):
        return None
    try:
        value = load(ROOT / str(record["path"]))
    except (OSError, ValueError, json.JSONDecodeError, TypeError, SystemExit):
        return None
    candidate_sha256 = current_candidate_sha256()
    if set(value) != {"schema", "run_id", "candidate_sha256", "runner", "cases"}:
        return None
    run_id = value.get("run_id")
    runner = value.get("runner")
    cases = value.get("cases")
    if (
        value.get("schema") != "agent-test-receipt/v3"
        or value.get("candidate_sha256") != candidate_sha256
        or not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{32}", run_id) is None
        or not isinstance(cases, list) or not cases
        or not valid_receipt(runner) or runner.get("path") != ".agent/scripts/testrun.py"
    ):
        return None
    case_ids: Set[str] = set()
    for case in cases:
        case_id = case.get("id") if isinstance(case, dict) else None
        required = {
            "id", "run_id", "candidate_sha256", "command", "started_at", "finished_at", "exit_code",
            "outcome", "cleanup", "output", "case_sha256",
        }
        if (
            not isinstance(case, dict) or set(case) != required
            or not isinstance(case_id, str) or not case_id or case_id in case_ids
            or case.get("run_id") != run_id or case.get("candidate_sha256") != candidate_sha256
            or case.get("exit_code") != 0
            or case.get("outcome") != "completed" or case.get("cleanup") != "passed"
            or not isinstance(case.get("command"), list) or not case.get("command")
            or any(not isinstance(part, str) or not part for part in case.get("command", []))
            or not valid_receipt(case.get("output"))
        ):
            return None
        try:
            case_started = parse(case.get("started_at"))
            case_finished = parse(case.get("finished_at"))
            if (
                case_finished < case_started
                or case_started < registered_at - dt.timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
                or case_finished > terminal_at + dt.timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
            ):
                return None
        except (TypeError, ValueError):
            return None
        unsigned = {key: value for key, value in case.items() if key != "case_sha256"}
        if case.get("case_sha256") != hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest():
            return None
        case_ids.add(case_id)
    return run_id


def attestation_receipt(record: Dict[str, object]) -> Dict[str, object]:
    return {key: record[key] for key in ("source_path", "sha256", "bytes")}


def replay_plan(record: object) -> Optional[Dict[str, object]]:
    if not content_addressed_receipt(record, "agent-replay-plans", ".json"):
        return None
    try:
        value = load(ROOT / str(record["path"]))
    except (OSError, ValueError, json.JSONDecodeError, TypeError, SystemExit):
        return None
    if set(value) != {"schema", "run_id", "receipt_path", "cases"} or value.get("schema") != REPLAY_PLAN_SCHEMA:
        return None
    if RUN_ID.fullmatch(str(value.get("run_id", ""))) is None or safe_contract_path(value.get("receipt_path")) != value.get("receipt_path"):
        return None
    cases = value.get("cases")
    if not isinstance(cases, list) or not cases:
        return None
    ids: Set[str] = set(); outputs: Set[str] = set()
    required = {
        "id", "command", "timeout_seconds", "expected_exit_code", "expected_outcome",
        "expected_cleanup", "expected_output_path",
    }
    for case in cases:
        if not isinstance(case, dict) or set(case) != required:
            return None
        case_id = case.get("id"); command = case.get("command"); output = case.get("expected_output_path")
        if (
            not isinstance(case_id, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", case_id) is None
            or case_id in ids or not isinstance(command, list) or not command
            or any(not isinstance(part, str) or not part for part in command) or "-c" in command
            or not isinstance(case.get("timeout_seconds"), int) or not 1 <= int(case["timeout_seconds"]) <= 1800
            or case.get("expected_exit_code") != 0 or case.get("expected_outcome") != "completed"
            or case.get("expected_cleanup") != "passed"
            or safe_contract_path(output) != output or output in outputs
        ):
            return None
        ids.add(case_id); outputs.add(str(output))
    return value


def replay_plan_output_paths_match_runner(plan: Dict[str, object]) -> bool:
    """The managed runner deterministically derives every output from receipt stem + case ID."""
    receipt = Path(str(plan.get("receipt_path", "")))
    cases = plan.get("cases")
    return isinstance(cases, list) and all(
        isinstance(case, dict)
        and case.get("expected_output_path") == str(
            receipt.with_name(receipt.stem + "-" + str(case.get("id")) + ".log")
        )
        for case in cases
    )


def current_node6_replay_contract(item: Dict[str, object]) \
        -> Optional[Tuple[Dict[str, object], Dict[str, object], List[Dict[str, object]]]]:
    """Bind a replay suite to the current accepted Node 6 and its sealed review input."""
    try:
        task = load(TASK)
    except (OSError, ValueError, json.JSONDecodeError, SystemExit):
        return None
    artifacts = task.get("node_artifacts")
    accepted = task.get("accepted_nodes")
    node6_record = artifacts.get("6") if isinstance(artifacts, dict) else None
    if not isinstance(accepted, list) or 6 not in accepted or not valid_receipt(node6_record):
        return None
    payload = reusable_task_payload(item.get("task_payload_evidence"))
    if payload is None:
        return None
    matching_inputs = [
        record for record in payload.get("input_artifacts", [])
        if isinstance(record, dict)
        and record.get("label") == node6_record.get("path")
        and record.get("sha256") == node6_record.get("sha256")
        and record.get("bytes") == node6_record.get("bytes")
    ]
    if len(matching_inputs) != 1 or not content_addressed_receipt(
        {key: matching_inputs[0].get(key) for key in ("path", "sha256", "bytes")},
        "agent-input-artifacts", ".blob",
    ):
        return None
    try:
        node6 = load(ROOT / str(node6_record["path"]))
    except (OSError, ValueError, json.JSONDecodeError, TypeError, SystemExit):
        return None
    checks = node6.get("checks")
    if (
        node6.get("schema") != "agent-node-implementation/v3"
        or node6.get("status") != "verified"
        or not isinstance(checks, list) or not checks
    ):
        return None
    normalized: List[Dict[str, object]] = []; ids: Set[str] = set()
    for check in checks:
        check_id = check.get("id") if isinstance(check, dict) else None
        command = check.get("command") if isinstance(check, dict) else None
        if (
            not isinstance(check_id, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", check_id) is None
            or check_id in ids or not isinstance(command, list) or not command
            or any(not isinstance(part, str) or not part for part in command)
            or check.get("exit_code") != 0
        ):
            return None
        ids.add(check_id); normalized.append({"id": check_id, "command": command})
    return dict(node6_record), dict(matching_inputs[0]), normalized


def sealed_node6_replay_contract(run: Dict[str, object], item: Dict[str, object]) \
        -> Optional[Tuple[Dict[str, object], Dict[str, object], List[Dict[str, object]]]]:
    """Replay historical run provenance from its immutable Node 6 input, not mutable current state."""
    node6_record = run.get("node6_task_receipt")
    input_record = run.get("node6_input_evidence")
    if (
        not isinstance(node6_record, dict) or set(node6_record) != {"path", "sha256", "bytes"}
        or safe_contract_path(node6_record.get("path")) != node6_record.get("path")
        or not isinstance(input_record, dict)
        or set(input_record) != {"label", "path", "sha256", "bytes"}
        or input_record.get("label") != node6_record.get("path")
        or input_record.get("sha256") != node6_record.get("sha256")
        or input_record.get("bytes") != node6_record.get("bytes")
        or not content_addressed_receipt(
            {key: input_record.get(key) for key in ("path", "sha256", "bytes")},
            "agent-input-artifacts", ".blob",
        )
    ):
        return None
    payload = reusable_task_payload(item.get("task_payload_evidence"))
    if payload is None or len([
        candidate for candidate in payload.get("input_artifacts", [])
        if isinstance(candidate, dict) and candidate == input_record
    ]) != 1:
        return None
    try:
        node6 = load(ROOT / str(input_record["path"]))
    except (OSError, ValueError, json.JSONDecodeError, TypeError, SystemExit):
        return None
    checks = node6.get("checks")
    if (
        node6.get("schema") != "agent-node-implementation/v3"
        or node6.get("status") != "verified" or not isinstance(checks, list) or not checks
    ):
        return None
    normalized: List[Dict[str, object]] = []; ids: Set[str] = set()
    for check in checks:
        check_id = check.get("id") if isinstance(check, dict) else None
        command = check.get("command") if isinstance(check, dict) else None
        if (
            not isinstance(check_id, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", check_id) is None
            or check_id in ids or not isinstance(command, list) or not command
            or any(not isinstance(part, str) or not part for part in command)
            or check.get("exit_code") != 0
        ):
            return None
        ids.add(check_id); normalized.append({"id": check_id, "command": command})
    return dict(node6_record), dict(input_record), normalized


def replay_plan_matches_node6(plan: Dict[str, object], checks: List[Dict[str, object]]) -> bool:
    return [
        {"id": case.get("id"), "command": case.get("command")}
        for case in plan.get("cases", []) if isinstance(case, dict)
    ] == checks


def replay_run_authority(state: Dict[str, object], item: Dict[str, object], record: Dict[str, object],
                         terminal_at: dt.datetime) -> Optional[str]:
    """Validate one runner/ledger-authored replay authority against final immutable bytes."""
    runs = state.get("replay_runs")
    if not isinstance(runs, list):
        return None
    matches = [run for run in runs if isinstance(run, dict) and run.get("final_receipt_sha256") == record.get("sha256")]
    if len(matches) != 1:
        return None
    run = matches[0]
    plan = replay_plan(run.get("plan_evidence"))
    node6_contract = current_node6_replay_contract(item)
    final = run.get("final_receipt_evidence")
    record_is_final = (
        isinstance(record, dict) and set(record) == {"source_path", "path", "sha256", "bytes"}
        and record.get("source_path") == run.get("receipt_path")
        and (
            result_evidence_receipt(record)
            or content_addressed_receipt({key: record.get(key) for key in ("path", "sha256", "bytes")},
                                         "agent-replay-receipts", ".receipt")
        )
    )
    if (
        plan is None or node6_contract is None or not replay_plan_matches_node6(plan, node6_contract[2])
        or run.get("node6_task_receipt") != node6_contract[0]
        or run.get("node6_input_evidence") != node6_contract[1]
        or run.get("status") != "completed"
        or run.get("integrator_id") != item.get("id")
        or run.get("review_chain_id") != item.get("review_chain_id")
        or run.get("review_subject_sha256") != item.get("review_subject_sha256")
        or run.get("candidate_sha256") != current_candidate_sha256()
        or run.get("receipt_path") != record.get("source_path")
        or not record_is_final
        or not content_addressed_receipt(final, "agent-replay-receipts", ".receipt")
        or (final or {}).get("sha256") != record.get("sha256")
        or run.get("final_receipt_sha256") != record.get("sha256")
        or plan.get("run_id") != run.get("run_id")
    ):
        return None
    try:
        registered = parse(item.get("registration_observed_at"))
        prepared = parse(run.get("prepared_at")); completed = parse(run.get("completed_at"))
        if prepared < registered - dt.timedelta(seconds=TIMESTAMP_SKEW_SECONDS) or completed > terminal_at + dt.timedelta(seconds=TIMESTAMP_SKEW_SECONDS):
            return None
    except (TypeError, ValueError):
        return None
    cases = run.get("cases")
    if not isinstance(cases, list) or len(cases) != len(plan["cases"]):
        return None
    receipt_value = load(ROOT / str(final["path"]))
    if (
        set(receipt_value) != {"schema", "run_id", "candidate_sha256", "runner", "cases"}
        or receipt_value.get("schema") != "agent-test-receipt/v3"
        or receipt_value.get("run_id") != run.get("run_id")
        or receipt_value.get("candidate_sha256") != run.get("candidate_sha256")
        or receipt_value.get("runner") != run.get("runner_evidence")
    ):
        return None
    prior_sha: Optional[str] = None; built_cases: List[Dict[str, object]] = []
    for index, (authority, expected) in enumerate(zip(cases, plan["cases"])):
        if not isinstance(authority, dict) or set(authority) != {"id", "claim_id", "start", "finish", "case"} or authority.get("id") != expected.get("id"):
            return None
        start_record, finish_record, case = authority.get("start"), authority.get("finish"), authority.get("case")
        if (
            not content_addressed_receipt(start_record, "agent-replay-observations", ".json")
            or not content_addressed_receipt(finish_record, "agent-replay-observations", ".json")
            or not isinstance(case, dict)
        ):
            return None
        start_value = load(ROOT / str(start_record["path"])); finish_value = load(ROOT / str(finish_record["path"]))
        common = {
            "authority_id": run.get("authority_id"), "integrator_id": item.get("id"),
            "review_chain_id": item.get("review_chain_id"), "review_subject_sha256": item.get("review_subject_sha256"),
            "run_id": run.get("run_id"), "case_id": expected.get("id"), "sequence": index,
            "claim_id": authority.get("claim_id"),
            "runner_sha256": (run.get("runner_evidence") or {}).get("sha256"),
            "plan_sha256": (run.get("plan_evidence") or {}).get("sha256"),
        }
        if (
            start_value.get("schema") != REPLAY_OBSERVATION_SCHEMA or start_value.get("event") != "start"
            or any(start_value.get(key) != value for key, value in common.items())
            or start_value.get("previous_observation_sha256") != prior_sha
            or start_value.get("command") != expected.get("command")
            or start_value.get("timeout_seconds") != expected.get("timeout_seconds")
            or start_value.get("output_path") != expected.get("expected_output_path")
            or finish_value.get("schema") != REPLAY_OBSERVATION_SCHEMA or finish_value.get("event") != "finish"
            or any(finish_value.get(key) != value for key, value in common.items())
            or finish_value.get("previous_observation_sha256") != start_record.get("sha256")
            or finish_value.get("output") != case.get("output")
            or finish_value.get("exit_code") != case.get("exit_code")
            or finish_value.get("outcome") != case.get("outcome")
            or finish_value.get("cleanup") != case.get("cleanup")
        ):
            return None
        try:
            started = parse(start_value.get("observed_at")); finished = parse(finish_value.get("observed_at"))
            if (
                finished < started or started < registered - dt.timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
                or started < prepared or finished > terminal_at + dt.timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
            ):
                return None
        except (TypeError, ValueError):
            return None
        required_case = {
            "id", "run_id", "candidate_sha256", "command", "started_at", "finished_at",
            "exit_code", "outcome", "cleanup", "output", "case_sha256",
        }
        if (
            set(case) != required_case
            or case.get("id") != expected.get("id") or case.get("run_id") != run.get("run_id")
            or case.get("candidate_sha256") != run.get("candidate_sha256")
            or case.get("command") != expected.get("command")
            or case.get("started_at") != start_value.get("observed_at")
            or case.get("finished_at") != finish_value.get("observed_at")
            or case.get("exit_code") != expected.get("expected_exit_code")
            or case.get("outcome") != expected.get("expected_outcome")
            or case.get("cleanup") != expected.get("expected_cleanup")
            or not content_addressed_receipt(case.get("output"), "agent-replay-outputs", ".log")
        ):
            return None
        unsigned = {key: value for key, value in case.items() if key != "case_sha256"}
        if case.get("case_sha256") != hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest():
            return None
        built_cases.append(case); prior_sha = finish_record.get("sha256")
    if receipt_value.get("cases") != built_cases or run.get("last_observation_sha256") != prior_sha:
        return None
    return str(run.get("run_id")) if RUN_ID.fullmatch(str(run.get("run_id", ""))) else None


def review_result_contract(item: Dict[str, object], records: List[Dict[str, object]],
                           state: Optional[Dict[str, object]] = None,
                           terminal_observed: Optional[dt.datetime] = None,
                           require_current_schema: bool = False) \
        -> Optional[Tuple[Dict[str, object], Dict[str, object]]]:
    """Replay a report, its role attestation and any integrator clean reruns."""
    report_path = item.get("result_report_path")
    reports = [record for record in records if record.get("source_path") == report_path]
    if len(reports) != 1:
        return None
    report = reports[0]
    verdict = review_verdict_from_result(report)
    attestation = review_attestation_from_result(report)
    if verdict is None or attestation is None:
        return None
    role_type = item.get("role_type")
    expected_chain = item.get("review_chain_id")
    expected_subject = item.get("review_subject_sha256")
    expected_predecessor = item.get("predecessor_result_sha256")
    if (
        (require_current_schema and attestation.get("schema") != REVIEW_ATTESTATION_SCHEMA)
        or attestation.get("role_type") != role_type
        or attestation.get("review_chain_id") != expected_chain
        or attestation.get("review_subject_sha256") != expected_subject
        or attestation.get("predecessor_result_sha256") != expected_predecessor
        or not valid_targeted_cases(attestation, role_type)
    ):
        return None
    lenses = attestation.get("lenses")
    clean_replays = attestation.get("clean_replays")
    if not isinstance(lenses, list) or not isinstance(clean_replays, list):
        return None
    if role_type == "cross":
        if (
            lenses != list(CROSS_REVIEW_LENSES) or clean_replays
            or cross_scenario_from_result(report, item) is None
        ):
            return None
    elif role_type == "integrator":
        owned_runs = [
            run for run in (state or {}).get("replay_runs", [])
            if isinstance(run, dict) and run.get("integrator_id") == item.get("id")
        ]
        # Keep historical two-run receipts valid, while new preparation authority
        # is capped by the current one-run policy.
        if len(owned_runs) not in {1, 2} or any(run.get("status") != "completed" for run in owned_runs):
            return None
        try:
            registered_at = parse(item.get("registration_observed_at"))
            terminal_at = terminal_observed or parse(item.get("terminal_observed_at"))
        except (TypeError, ValueError):
            return None
        replay_records = sorted(
            [record for record in records if record is not report],
            key=lambda record: str(record.get("source_path")),
        )
        expected_replays = [attestation_receipt(record) for record in replay_records]
        run_ids = [replay_run_authority(state or {}, item, record, terminal_at) for record in replay_records]
        if (
            lenses or len(replay_records) != len(owned_runs) or clean_replays != expected_replays
            or any(run_id is None for run_id in run_ids) or len(set(run_ids)) != len(owned_runs)
        ):
            return None
    elif lenses or clean_replays or len(records) != 1:
        return None
    if role_type != "integrator" and len(records) != 1:
        return None
    return verdict, attestation


def implementation_result_contract(item: Dict[str, object], records: List[Dict[str, object]],
                                   state: Dict[str, object], *, require_current: bool = True) \
        -> Optional[Dict[str, object]]:
    """Derive an implementer result from its sealed candidate.

    Finish authority additionally requires that candidate to still be the live
    Node 6 artifact. Historical validation deliberately does not: a controlled
    rollback must preserve an earlier terminal attestation without making the
    append-only ledger impossible to validate.
    """
    if len(records) != 1 or not result_evidence_receipt(records[0]):
        return None
    source_path = records[0].get("source_path")
    if (
        not isinstance(source_path, str)
        or re.fullmatch(r"\.agent/state/evidence/implementation-attestation-[A-Za-z0-9._-]+\.json", source_path) is None
    ):
        return None
    try:
        attestation = load(ROOT / str(records[0]["path"]))
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError, TypeError, SystemExit):
        return None
    required = {
        "schema", "agent_id", "root_task_id", "candidate_review_subject_sha256",
        "requirement_contract_sha256", "node6_artifact", "changes", "checks",
    }
    payload = reusable_task_payload(item.get("task_payload_evidence"))
    if payload is None:
        return None
    node6_inputs = [
        receipt for receipt in payload.get("input_artifacts", [])
        if isinstance(receipt, dict) and receipt.get("label") == NODE6_ARTIFACT_PATH
    ]
    if len(node6_inputs) != 1:
        return None
    sealed_node6 = node6_inputs[0]
    try:
        node6_data = (ROOT / str(sealed_node6["path"])).read_bytes()
        node6 = json.loads(node6_data.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError, TypeError, KeyError):
        return None
    expected_node6 = {
        "path": NODE6_ARTIFACT_PATH,
        "sha256": hashlib.sha256(node6_data).hexdigest(),
        "bytes": len(node6_data),
    }
    if (
        sealed_node6.get("sha256") != expected_node6["sha256"]
        or sealed_node6.get("bytes") != expected_node6["bytes"]
    ):
        return None
    if require_current:
        try:
            current_data = (ROOT / NODE6_ARTIFACT_PATH).read_bytes()
        except OSError:
            return None
        current_receipt = {
            "path": NODE6_ARTIFACT_PATH,
            "sha256": hashlib.sha256(current_data).hexdigest(),
            "bytes": len(current_data),
        }
        if current_receipt != expected_node6:
            return None
    initial_agent_id = item.get("id")
    if integer(item.get("redispatch_count")) == 1:
        sources = [
            source for source in state.get("members", [])
            if isinstance(source, dict) and source.get("redispatched_to") == item.get("id")
        ]
        if len(sources) != 1:
            return None
        initial_agent_id = sources[0].get("id")
    if (
        set(attestation) != required
        or attestation.get("schema") != IMPLEMENTATION_ATTESTATION_SCHEMA
        or attestation.get("agent_id") != item.get("id")
        or attestation.get("root_task_id") != item.get("root_task_id")
        or attestation.get("candidate_review_subject_sha256") != item.get("task_payload_sha256")
        or node6.get("schema") != "agent-node-implementation/v3"
        or node6.get("status") != "verified"
        or node6.get("implementer_agent_id") != initial_agent_id
        or attestation.get("requirement_contract_sha256") != node6.get("requirement_contract_sha256")
        or attestation.get("node6_artifact") != expected_node6
        or attestation.get("changes") != node6.get("changes")
        or attestation.get("checks") != node6.get("checks")
    ):
        return None
    return attestation


def review_conclusion(verdict: Dict[str, object]) -> str:
    return f"{verdict['status']} P0={verdict['p0']} P1={verdict['p1']} P2={verdict['p2']}"


def review_final_message(verdict: Dict[str, object]) -> str:
    return f"FINAL_RESULT {review_conclusion(verdict)} report_sha256={verdict['report_sha256']}"


def reusable_task_payload(record: object) -> Optional[Dict[str, object]]:
    """Accept only dispatch-invariant task semantics; the envelope owns dispatch data."""
    if not content_addressed_receipt(record, "agent-task-payloads", ".ctx"):
        return None
    try:
        value = load(ROOT / str(record["path"]))
    except (OSError, ValueError, json.JSONDecodeError, TypeError, SystemExit):
        return None
    required = {
        "schema", "objective", "input_artifacts", "shared_constraints", "acceptance_criteria",
        "estimated_tokens",
    }
    if set(value) != required or value.get("schema") != TASK_PAYLOAD_SCHEMA:
        return None
    objective = value.get("objective")
    input_artifacts = value.get("input_artifacts")
    groups = (value.get("shared_constraints"), value.get("acceptance_criteria"))
    if not isinstance(objective, str) or not objective.strip() or len(objective) > 2000:
        return None
    if (
        not isinstance(input_artifacts, list) or not input_artifacts
        or any(not input_artifact_receipt(item) for item in input_artifacts)
        or len({str(item.get("label")) for item in input_artifacts if isinstance(item, dict)}) != len(input_artifacts)
        or len({str(item.get("path")) for item in input_artifacts if isinstance(item, dict)}) != len(input_artifacts)
        or not task_payload_within_limits(
            [integer(item.get("bytes")) for item in input_artifacts if isinstance(item, dict)],
            task_payload_semantic_bytes(objective, *groups),
        )
    ):
        return None
    for group in groups:
        if (
            not isinstance(group, list) or not group or len(group) != len(set(group))
            or any(not isinstance(item, str) or not item.strip() or len(item) > 2000 for item in group)
        ):
            return None
    metrics = task_payload_metrics(
        [integer(item.get("bytes")) for item in input_artifacts if isinstance(item, dict)],
        task_payload_semantic_bytes(objective, *groups),
    )
    if value.get("estimated_tokens") != metrics["estimated_tokens"]:
        return None
    return value


PAYLOAD_CONTROL_TEXT = re.compile(
    r"\b(?:agent|root)[ _-]*id\b|\brole[ _-]*type\b|\bmodel\b|\bfork(?:[ _-]*turns?)?\b|"
    r"\b(?:start(?:ed)?|deadline)[ _-]*(?:at|time)\b|\bredispatch(?:[ _-]*count)?\b|"
    r"\b(?:report|output)[ _-]*path\b|\b(?:allowed|forbidden)[ _-]*(?:evidence|actions?)\b|"
    r"\bstart[ _-]*barrier\b|\bledger[ _-]*registered\b",
    re.IGNORECASE,
)


def payload_dispatch_conflicts(payload: Dict[str, object], envelope: Dict[str, object]) -> bool:
    """Reject dispatch control smuggled through otherwise schema-valid free text."""
    text = "\n".join([
        str(payload.get("objective", "")),
        *[str(item) for item in payload.get("shared_constraints", [])],
        *[str(item) for item in payload.get("acceptance_criteria", [])],
    ])
    lowered = text.lower()
    if "/" in text or "\\" in text or PAYLOAD_CONTROL_TEXT.search(text):
        return True
    # Role names such as "adversarial" and "cross" are task semantics shared by
    # every reviewer, not dispatch identity.  Structural role controls (for
    # example ``role_type``) remain blocked by PAYLOAD_CONTROL_TEXT above.
    literals = [
        envelope.get("agent_id"), envelope.get("root_task_id"),
        envelope.get("model"), envelope.get("started_at"), envelope.get("deadline_at"),
        envelope.get("start_barrier"), *envelope.get("allowed_evidence_paths", []),
        *envelope.get("forbidden_actions", []),
    ]
    for item in literals:
        if not isinstance(item, str) or len(item.strip()) < 4:
            continue
        literal = item.strip().lower()
        if any(character in literal for character in "/\\.:@"):
            if literal in lowered:
                return True
        elif re.search(rf"(?<![a-z0-9_-]){re.escape(literal)}(?![a-z0-9_-])", lowered):
            return True
    return False


def immutable_handoff_envelope_evidence(raw: str) -> Dict[str, object]:
    """Preserve the exact machine-readable per-dispatch spawn message."""
    return immutable_blob_evidence(raw, "agent-handoff-envelopes", ".json", "agent-handoff-envelope")


def safe_contract_path(raw: object) -> Optional[str]:
    if not isinstance(raw, str) or not raw or Path(raw).is_absolute():
        return None
    path = (ROOT / raw).resolve()
    try:
        relative = str(path.relative_to(ROOT))
    except ValueError:
        return None
    return relative if relative == raw else None


def command_seal_payload(args: argparse.Namespace) -> int:
    """Turn path labels into immutable bytes before an envelope can reference the payload."""
    draft_record = evidence(args.draft)
    draft = load(ROOT / str(draft_record["path"]))
    required = {"schema", "objective", "input_artifacts", "shared_constraints", "acceptance_criteria"}
    inputs = draft.get("input_artifacts")
    groups = (draft.get("shared_constraints"), draft.get("acceptance_criteria"))
    if (
        set(draft) != required or draft.get("schema") != TASK_PAYLOAD_DRAFT_SCHEMA
        or not isinstance(draft.get("objective"), str) or not str(draft.get("objective")).strip()
        or not isinstance(inputs, list) or not inputs or len(inputs) != len(set(inputs))
        or any(safe_contract_path(item) != item for item in inputs)
        or any(not isinstance(group, list) or not group or len(group) != len(set(group)) for group in groups)
        or any(not isinstance(item, str) or not item.strip() or len(item) > 2000 for group in groups for item in group)
    ):
        raise SystemExit("task payload draft is invalid")
    text = "\n".join([str(draft["objective"]), *draft["shared_constraints"], *draft["acceptance_criteria"]])
    if "/" in text or "\\" in text or PAYLOAD_CONTROL_TEXT.search(text):
        raise SystemExit("task payload draft contains dispatch control or path-like free text")
    source_sizes: List[int] = []
    for raw_input in inputs:
        source = ROOT / str(raw_input)
        if source.is_symlink() or not source.is_file():
            raise SystemExit("task payload input must be a regular non-symlink file")
        source_sizes.append(source.stat().st_size)
    semantic_bytes = task_payload_semantic_bytes(draft["objective"], *groups)
    if not task_payload_within_limits(source_sizes, semantic_bytes):
        metrics = task_payload_metrics(source_sizes, semantic_bytes)
        raise SystemExit(
            "task payload exceeds count, single-file, total-byte or estimated-token budget: "
            + json.dumps(metrics, sort_keys=True, separators=(",", ":"))
        )
    metrics = task_payload_metrics(source_sizes, semantic_bytes)
    # Sealing is not a reservation, but it must already fit the live budget.
    # Prepare repeats this check while holding the ledger lock and reserves it.
    require_payload_token_budget(load(STATE), metrics["estimated_tokens"])
    sealed = {
        "schema": TASK_PAYLOAD_SCHEMA,
        "objective": draft["objective"],
        "input_artifacts": [immutable_input_artifact_evidence(item) for item in inputs],
        "shared_constraints": draft["shared_constraints"],
        "acceptance_criteria": draft["acceptance_criteria"],
        "estimated_tokens": metrics["estimated_tokens"],
    }
    output = (ROOT / args.output).resolve()
    try:
        output.relative_to(ROOT)
    except ValueError:
        raise SystemExit("sealed task payload output escapes project")
    data = (json.dumps(sealed, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if os.path.lexists(output) and (output.is_symlink() or not output.is_file() or output.read_bytes() != data):
        raise SystemExit("sealed task payload output already exists with different bytes")
    if not output.exists():
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, raw = tempfile.mkstemp(prefix=".sealed-task-payload.", dir=str(output.parent))
        temporary = Path(raw)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data); handle.flush(); os.fsync(handle.fileno())
            os.replace(temporary, output)
        finally:
            if temporary.exists(): temporary.unlink()
    print(f"SEALED TASK PAYLOAD: {output.relative_to(ROOT)} sha256={hashlib.sha256(data).hexdigest()}")
    return 0


def execution_profile_contract(value: object, candidate_sha256: object) -> Optional[Dict[str, object]]:
    if not isinstance(value, dict) or set(value) != {
        "environment", "authority", "capabilities", "preflight_receipt",
    }:
        return None
    environment = value.get("environment")
    authority = value.get("authority")
    capabilities = value.get("capabilities")
    receipt = value.get("preflight_receipt")
    if (
        environment not in {"local", "test"}
        or authority not in {"default", "elevated", "remote-test"}
        or not isinstance(capabilities, list) or not capabilities
        or len(capabilities) != len(set(capabilities))
        or any(not isinstance(item, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", item) for item in capabilities)
        or not valid_receipt(receipt)
    ):
        return None
    try:
        preflight = load(ROOT / str(receipt["path"]))
    except (OSError, ValueError, json.JSONDecodeError, TypeError, SystemExit):
        return None
    checks = preflight.get("checks")
    required = {
        "schema", "environment", "authority", "candidate_sha256", "observed_at",
        "expires_at", "status", "capabilities", "checks",
    }
    if (
        set(preflight) != required
        or preflight.get("schema") != "agent-execution-preflight/v1"
        or preflight.get("environment") != environment
        or preflight.get("authority") != authority
        or preflight.get("candidate_sha256") != candidate_sha256
        or preflight.get("status") != "passed"
        or preflight.get("capabilities") != capabilities
        or not isinstance(checks, list) or len(checks) != len(capabilities)
        or [item.get("capability") for item in checks if isinstance(item, dict)] != capabilities
        or any(
            not isinstance(item, dict)
            or set(item) != {"capability", "status", "evidence"}
            or item.get("status") != "passed"
            or not isinstance(item.get("evidence"), str) or not item.get("evidence")
            for item in checks
        )
    ):
        return None
    try:
        if parse(preflight.get("expires_at")) <= parse(preflight.get("observed_at")):
            return None
    except (TypeError, ValueError):
        return None
    return value


def handoff_envelope(record: object) -> Optional[Dict[str, object]]:
    if not content_addressed_receipt(record, "agent-handoff-envelopes", ".json"):
        return None
    try:
        value = load(ROOT / str(record["path"]))
    except (OSError, ValueError, json.JSONDecodeError, TypeError, SystemExit):
        return None
    required = {
        "schema", "ledger_epoch", "agent_id", "root_task_id", "role_type", "model", "fork_turns",
        "started_at", "deadline_at", "redispatch_count", "task_payload_path", "task_payload_sha256",
        "allowed_evidence_paths", "forbidden_actions", "start_barrier", "review_chain_id",
        "review_subject_sha256", "predecessor_result_sha256", "result_report_path",
    }
    if frozenset(value) not in {frozenset(required), frozenset(required | {"execution_profile"})} or value.get("schema") != HANDOFF_SCHEMA:
        return None
    allowed = value.get("allowed_evidence_paths")
    forbidden = value.get("forbidden_actions")
    role_type = value.get("role_type")
    chain_id = value.get("review_chain_id")
    subject = value.get("review_subject_sha256")
    predecessor = value.get("predecessor_result_sha256")
    report_path = value.get("result_report_path")
    if (
        not isinstance(allowed, list) or not allowed or len(allowed) != len(set(allowed))
        or any(safe_contract_path(item) is None for item in allowed)
        or not isinstance(forbidden, list) or not forbidden or len(forbidden) != len(set(forbidden))
        or any(not isinstance(item, str) or not item.strip() for item in forbidden)
        or value.get("start_barrier") != "LEDGER_REGISTERED"
    ):
        return None
    if role_type in CANONICAL_REVIEW_ROLE_TYPES:
        if (
            not SHA.fullmatch(str(subject or "")) or subject != value.get("task_payload_sha256")
            or safe_contract_path(report_path) != report_path or report_path not in allowed
        ):
            return None
        if role_type in FORMAL_REVIEW_ROLE_TYPES:
            if not isinstance(chain_id, str) or REVIEW_CHAIN_ID.fullmatch(chain_id) is None:
                return None
        elif chain_id is not None:
            return None
        if role_type in {"cross", "integrator"}:
            if not SHA.fullmatch(str(predecessor or "")):
                return None
        elif predecessor is not None:
            return None
    elif any(item is not None for item in (chain_id, subject, predecessor, report_path)):
        return None
    if (
        "execution_profile" in value
        and execution_profile_contract(value.get("execution_profile"), current_candidate_sha256()) is None
    ):
        return None
    return value


def envelope_contract_matches(value: Dict[str, object], expected: Dict[str, object],
                              payload_record: Dict[str, object]) -> bool:
    payload = reusable_task_payload(payload_record)
    return (
        payload is not None
        and not payload_dispatch_conflicts(payload, value)
        and value.get("ledger_epoch") == expected.get("ledger_epoch")
        and value.get("agent_id") == expected.get("agent_id")
        and value.get("root_task_id") == expected.get("root_task_id")
        and value.get("role_type") == expected.get("role_type")
        and value.get("model") == expected.get("model")
        and value.get("fork_turns") == expected.get("fork_turns")
        and value.get("started_at") == expected.get("started_at")
        and value.get("deadline_at") == expected.get("deadline_at")
        and value.get("redispatch_count") == expected.get("redispatch_count")
        and value.get("task_payload_sha256") == payload_record.get("sha256")
        and value.get("task_payload_path") == payload_record.get("path")
        and all(
            key not in expected or value.get(key) == expected.get(key)
            for key in (
                "review_chain_id", "review_subject_sha256",
                "predecessor_result_sha256", "result_report_path",
            )
        )
        and not {
            str(item.get("label")) for item in payload.get("input_artifacts", []) if isinstance(item, dict)
        }.intersection(value.get("allowed_evidence_paths", []))
        and (
            value.get("role_type") not in CANONICAL_REVIEW_ROLE_TYPES
            or {"approve-node7", "modify-managed-files"}.issubset(set(value.get("forbidden_actions", [])))
        )
    )


def immutable_capacity_evidence(raw: str) -> Dict[str, object]:
    """Preserve each pre-registration capacity error before a retry overwrites it."""
    source_record = evidence(raw)
    source = ROOT / str(source_record["path"])
    data = source.read_bytes()
    digest = str(source_record["sha256"])
    directory = AGENT / "state/evidence/capacity-failures"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{digest}.err"
    if os.path.lexists(target):
        if target.is_symlink() or not target.is_file() or target.read_bytes() != data:
            raise SystemExit(f"immutable capacity evidence collision or mutation: {target.relative_to(ROOT)}")
    else:
        descriptor, raw_temporary = tempfile.mkstemp(prefix=".capacity-failure.", dir=str(directory))
        temporary = Path(raw_temporary)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data); handle.flush(); os.fsync(handle.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                if target.is_symlink() or not target.is_file() or target.read_bytes() != data:
                    raise SystemExit(f"immutable capacity evidence collision or mutation: {target.relative_to(ROOT)}")
            if target.is_file() and not target.is_symlink():
                target.chmod(0o444)
        finally:
            if temporary.exists():
                temporary.unlink()
    return {"path": str(target.relative_to(ROOT)), "sha256": digest, "bytes": len(data)}


def valid_receipt(record: object) -> bool:
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
        return False
    path = (ROOT / str(record["path"])).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError:
        return False
    return path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"] and len(path.read_bytes()) == record["bytes"]


def content_addressed_receipt(record: object, directory: str, suffix: str) -> bool:
    if not valid_receipt(record) or not isinstance(record, dict):
        return False
    return record.get("path") == f".agent/state/evidence/{directory}/{record.get('sha256')}{suffix}"


def receipt_platform_snapshot(record: object) -> Optional[Dict[str, object]]:
    """Read an immutable historical platform snapshot without a freshness check."""
    if not valid_receipt(record):
        return None
    try:
        value = load(ROOT / str(record["path"]))
    except (OSError, ValueError, json.JSONDecodeError, TypeError):
        return None
    if value.get("schema") != PLATFORM_SCHEMA or not isinstance(value.get("members"), list):
        return None
    try:
        parse(value.get("observed_at"))
    except (ValueError, TypeError):
        return None
    return value


def receipt_platform_member(record: object, agent_id: str) -> Optional[Dict[str, object]]:
    """Read historical platform member semantics without applying freshness."""
    value = receipt_platform_snapshot(record)
    if value is None:
        return None
    found = [item for item in value["members"] if isinstance(item, dict) and item.get("id") == agent_id]
    return found[0] if len(found) == 1 else None


def receipt_observed_at(record: object) -> Optional[dt.datetime]:
    value = receipt_platform_snapshot(record)
    if value is None:
        return None
    try:
        return parse(value.get("observed_at"))
    except (ValueError, TypeError):
        return None


def completion_contract_errors(item: Dict[str, object], terminal_observed: dt.datetime,
                               interval: int, monitor_grace: int, stall_timeout: int,
                               terminal_record: Optional[Dict[str, object]] = None) -> List[str]:
    """Replay the immutable monitoring chain for a successful completion."""
    errors: List[str] = []
    try:
        started = parse(item.get("started_at")); deadline = parse(item.get("deadline_at"))
    except (ValueError, TypeError):
        return ["invalid start/deadline timestamp"]
    if terminal_observed < started - dt.timedelta(seconds=TIMESTAMP_SKEW_SECONDS):
        errors.append("terminal observation predates registration")
    if terminal_observed > deadline:
        errors.append("terminal observation is after deadline")
    if item.get("interrupt_requested_at") is not None:
        errors.append("completion followed an interrupt request")
    if item.get("stall_violation_at") is not None:
        errors.append("child message stall timeout was previously violated")
    try:
        previous = parse(item.get("registration_observed_at"))
    except (ValueError, TypeError):
        errors.append("invalid registration observation timestamp")
        previous = started
    registered = receipt_platform_member(item.get("registration_platform_evidence"), str(item.get("id")))
    progress_cursor = integer((registered or {}).get("message_cursor"), 0)
    last_progress_observed = previous
    monitors = item.get("monitor_platform_evidence", [])
    if not isinstance(monitors, list):
        return [*errors, "monitor evidence chain is invalid"]
    for record in monitors:
        observed = receipt_observed_at(record)
        monitored = receipt_platform_member(record, str(item.get("id")))
        if observed is None:
            errors.append("monitor evidence cannot be replayed")
            continue
        gap = (observed - previous).total_seconds()
        if gap < 0:
            errors.append("monitor observations are not monotonic")
        if observed > previous:
            previous = observed
        cursor = integer((monitored or {}).get("message_cursor"), -1)
        if cursor > progress_cursor:
            progress_cursor = cursor; last_progress_observed = observed
        elif (observed - last_progress_observed).total_seconds() > stall_timeout:
            errors.append("child message stall timeout was exceeded")
    final_gap = (terminal_observed - previous).total_seconds()
    if final_gap < -TIMESTAMP_SKEW_SECONDS:
        errors.append("terminal observation predates latest monitor")
    terminal_member = receipt_platform_member(
        terminal_record if terminal_record is not None else item.get("terminal_platform_evidence"),
        str(item.get("id")),
    )
    terminal_cursor = integer((terminal_member or {}).get("message_cursor"), -1)
    if terminal_cursor < progress_cursor:
        errors.append("terminal message cursor regressed")
    elif terminal_cursor > progress_cursor:
        last_progress_observed = terminal_observed
    elif (terminal_observed - last_progress_observed).total_seconds() > stall_timeout:
        errors.append("child message stall timeout was exceeded")
    return sorted(set(errors))


def platform_snapshot(raw: str) -> Tuple[Dict[str, object], Dict[str, object], Dict[str, Dict[str, object]]]:
    path, record = immutable_platform_evidence(raw)
    value = load(path)
    if value.get("schema") != PLATFORM_SCHEMA or not isinstance(value.get("members"), list):
        raise SystemExit("platform snapshot schema is invalid")
    try:
        observed = parse(value.get("observed_at"))
    except (ValueError, TypeError):
        raise SystemExit("platform snapshot observed_at is invalid")
    age = (now() - observed).total_seconds()
    if age < -5 or age > 300:
        raise SystemExit("platform snapshot is stale or from the future")
    observer = platform_observer_policy(); adapter = observer.get("signed_adapter")
    mode = load(TASK).get("mode")
    if mode == "release" and not adapter:
        raise SystemExit("release platform observation requires agent_control.platform_observer.signed_adapter")
    if adapter:
        adapter = humandecision.adapter_path(ROOT, adapter)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result = subprocess.run(
            [str(adapter), "verify-platform", "--snapshot", str(path)], cwd=str(ROOT), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )
        if result.returncode or result.stdout.strip() != f"VERIFIED PLATFORM SNAPSHOT sha256={digest}":
            raise SystemExit("provider platform adapter rejected the snapshot")
    members: Dict[str, Dict[str, object]] = {}
    for item in value["members"]:
        required = {
            "id", "status", "ledger_epoch", "root_task_id", "role_type", "started_at", "deadline_at",
            "redispatch_count", "model", "fork_turns", "task_payload_sha256", "handoff_envelope_sha256",
            "message_cursor",
        }
        if not isinstance(item, dict) or not required.issubset(item) or set(item) - {
            "id", "status", "role_type", "model", "fork_turns", "task_payload_sha256", "handoff_envelope_sha256",
            "ledger_epoch", "root_task_id", "started_at", "deadline_at", "redispatch_count",
            "message_cursor", "message_sha256", "message_kind",
        }:
            raise SystemExit("platform snapshot member is invalid")
        agent_id, status, cursor = item.get("id"), str(item.get("status", "")).lower(), item.get("message_cursor")
        if not isinstance(agent_id, str) or not agent_id or agent_id in members or not isinstance(cursor, int) or cursor < 0:
            raise SystemExit("platform snapshot identity/cursor is invalid")
        if status not in PLATFORM_ACTIVE and not any(status in values for values in PLATFORM_TERMINAL.values()):
            raise SystemExit(f"unknown platform status: {status}")
        message_hash = item.get("message_sha256")
        if message_hash is not None and not SHA.fullmatch(str(message_hash)):
            raise SystemExit("platform message hash is invalid")
        if item.get("model") != policy().get("default_model"):
            raise SystemExit("platform snapshot model differs from configured default")
        if item.get("role_type") not in policy().get("allowed_role_types", []):
            raise SystemExit("platform snapshot role type is not canonical")
        if not SHA.fullmatch(str(item.get("ledger_epoch", ""))) or not str(item.get("root_task_id", "")):
            raise SystemExit("platform snapshot task/epoch binding is invalid")
        try:
            if parse(item.get("deadline_at")) <= parse(item.get("started_at")) or int(item.get("redispatch_count", -1)) < 0:
                raise ValueError
        except (TypeError, ValueError):
            raise SystemExit("platform snapshot schedule/redispatch binding is invalid")
        if integer(item.get("fork_turns"), -1) < 0 or integer(item.get("fork_turns"), -1) > integer(policy().get("max_fork_turns"), -1):
            raise SystemExit("platform snapshot fork window is outside configured bounds")
        if not SHA.fullmatch(str(item.get("task_payload_sha256", ""))):
            raise SystemExit("platform task payload hash is invalid")
        if not SHA.fullmatch(str(item.get("handoff_envelope_sha256", ""))):
            raise SystemExit("platform handoff envelope hash is invalid")
        members[agent_id] = item
    return value, record, members


def active_platform_ids(members: Dict[str, Dict[str, object]]) -> Set[str]:
    return {agent_id for agent_id, item in members.items() if str(item.get("status", "")).lower() in PLATFORM_ACTIVE}


def platform_contract_matches(observed: Dict[str, object], item: Dict[str, object], state: Dict[str, object]) -> bool:
    """Bind every platform observation to the immutable registration contract."""
    return (
        observed.get("ledger_epoch") == state.get("epoch")
        and observed.get("root_task_id") == item.get("root_task_id")
        and observed.get("role_type") == item.get("role_type")
        and observed.get("started_at") == item.get("started_at")
        and observed.get("deadline_at") == item.get("deadline_at")
        and observed.get("redispatch_count") == item.get("redispatch_count")
        and observed.get("model") == item.get("model")
        and observed.get("fork_turns") == item.get("fork_turns")
        and observed.get("task_payload_sha256") == item.get("task_payload_sha256")
        and observed.get("handoff_envelope_sha256") == item.get("handoff_envelope_sha256")
    )


def terminal_marker_path(state: Dict[str, object], agent_id: str) -> Path:
    identity = hashlib.sha256(agent_id.encode()).hexdigest()
    return AGENT / "state/evidence/agent-terminal-markers" / str(state.get("epoch")) / f"{identity}.json"


def publish_terminal_marker(state: Dict[str, object], item: Dict[str, object], status: str,
                            terminal_record: Dict[str, object], observed_at: str,
                            finished_at: str, conclusion: str, result_evidence: List[Dict[str, object]],
                            review_verdict: Optional[Dict[str, object]],
                            review_attestation: Optional[Dict[str, object]], final_cursor: int,
                            final_message_sha256: Optional[str]) -> None:
    """Publish the complete reviewer result before the editable ledger changes."""
    marker = terminal_marker_path(state, str(item["id"]))
    marker.parent.mkdir(parents=True, exist_ok=True)
    value = {
        "schema": TERMINAL_MARKER_SCHEMA, "ledger_epoch": state.get("epoch"),
        "agent_id": item.get("id"), "terminal_status": status,
        "task_payload_sha256": item.get("task_payload_sha256"),
        "handoff_envelope_sha256": item.get("handoff_envelope_sha256"),
        "review_chain_id": item.get("review_chain_id"),
        "review_subject_sha256": item.get("review_subject_sha256"),
        "predecessor_result_sha256": item.get("predecessor_result_sha256"),
        "result_report_path": item.get("result_report_path"),
        "terminal_platform_evidence": terminal_record, "terminal_observed_at": observed_at,
        "finished_at": finished_at, "conclusion": conclusion,
        "result_evidence": result_evidence,
        "review_verdict": review_verdict,
        "review_attestation": review_attestation,
        "monitoring_violation_at": item.get("monitoring_violation_at"),
        "stall_violation_at": item.get("stall_violation_at"),
        "final_message_cursor": final_cursor,
        "final_message_sha256": final_message_sha256,
    }
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if os.path.lexists(marker):
        if marker.is_symlink() or not marker.is_file() or marker.read_bytes() != data:
            raise SystemExit("terminal marker collision or attempted terminal rewrite")
        return
    descriptor, raw = tempfile.mkstemp(prefix=".terminal-marker.", dir=str(marker.parent))
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        try:
            os.link(temporary, marker)
        except FileExistsError:
            if marker.is_symlink() or not marker.is_file() or marker.read_bytes() != data:
                raise SystemExit("terminal marker collision or attempted terminal rewrite")
        marker.chmod(0o444)
    finally:
        if temporary.exists(): temporary.unlink()


def read_terminal_marker(state: Dict[str, object], item: Dict[str, object]) -> Optional[Dict[str, object]]:
    marker = terminal_marker_path(state, str(item.get("id")))
    if not marker.is_file() or marker.is_symlink():
        return None
    try:
        value = load(marker)
    except (OSError, ValueError, json.JSONDecodeError, SystemExit):
        return {"invalid": True}
    return value


def orphan_terminal_marker_errors(state: Dict[str, object]) -> List[str]:
    """Reverse marker check: every current-epoch marker needs its member record."""
    directory = AGENT / "state/evidence/agent-terminal-markers" / str(state.get("epoch"))
    if not directory.exists():
        return []
    if directory.is_symlink() or not directory.is_dir():
        return ["terminal marker epoch path is not a real directory"]
    member_ids = {
        str(item.get("id")) for item in state.get("members", []) if isinstance(item, dict)
    }
    errors = []
    for marker in sorted(directory.iterdir()):
        if marker.is_symlink() or not marker.is_file() or marker.suffix != ".json":
            errors.append(f"terminal marker entry is not a regular marker file: {marker.name}")
            continue
        identity = marker.stem
        matched = [
            agent_id for agent_id in member_ids
            if hashlib.sha256(agent_id.encode()).hexdigest() == identity
        ]
        if SHA.fullmatch(identity) is None or len(matched) != 1:
            errors.append(f"orphan terminal marker lacks its ledger member: {marker.name}")
    return errors


def ledger_chain_errors(state: Dict[str, object]) -> List[str]:
    """Verify the append hash chain back to the current epoch genesis.

    A legacy ledger without chain fields is accepted once; the next save
    upgrades it to revision 1.  Once upgraded, any break fails closed.
    """
    revision = state.get("revision")
    if revision is None:
        return []
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        return ["agent ledger chain revision is invalid"]
    previous = state.get("prev_sha256")
    if revision == 1:
        if previous is not None:
            return ["agent ledger chain genesis must not reference a predecessor"]
    elif not isinstance(previous, str) or SHA.fullmatch(previous) is None:
        return ["agent ledger chain predecessor hash is invalid"]
    try:
        lines = CHAIN_JOURNAL.read_text(encoding="utf-8").splitlines() if CHAIN_JOURNAL.is_file() else []
    except OSError:
        lines = []
    entries: List[object] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except ValueError:
            return ["agent ledger chain journal is unreadable"]
    if not entries:
        return ["agent ledger chain journal is missing for an upgraded ledger"]
    tip = entries[-1]
    canonical = hashlib.sha256(ledger_bytes(state)).hexdigest()
    if (
        not isinstance(tip, dict)
        or tip.get("revision") != revision
        or tip.get("prev_sha256") != previous
        or tip.get("file_sha256") != canonical
    ):
        return [
            "agent ledger content differs from its append chain tip; "
            "restore the ledger or re-initialize with init --archive-existing"
        ]
    index = len(entries) - 1
    while True:
        entry = entries[index]
        if (
            not isinstance(entry, dict)
            or set(entry) != {"revision", "prev_sha256", "file_sha256"}
            or not isinstance(entry.get("revision"), int)
            or entry["revision"] < 1
            or (
                SHA.fullmatch(str(entry.get("file_sha256") or "")) is None
            )
        ):
            return ["agent ledger chain journal entry is invalid"]
        if entry["revision"] == 1:
            if entry.get("prev_sha256") is not None:
                return ["agent ledger chain genesis must not reference a predecessor"]
            return []
        if index == 0:
            return ["agent ledger chain does not reach the epoch genesis"]
        prior = entries[index - 1]
        if (
            not isinstance(prior, dict)
            or entry.get("prev_sha256") != prior.get("file_sha256")
            or entry.get("revision") != (prior.get("revision") if isinstance(prior.get("revision"), int) else -1) + 1
        ):
            return ["agent ledger append hash chain is broken"]
        index -= 1


def command_init(args: argparse.Namespace) -> int:
    if not args.platform_snapshot:
        raise SystemExit("initialization requires a fresh platform snapshot")
    _, snapshot_record, platform = platform_snapshot(args.platform_snapshot)
    if active_platform_ids(platform):
        raise SystemExit("cannot initialize while platform reports active child agents")
    migration_source = None
    if args.force and not args.archive_existing:
        raise SystemExit("--force only applies to init --archive-existing")
    if not args.force and (args.force_reason or args.source or args.receipt):
        raise SystemExit("--force-reason/--source/--receipt require --force")
    if STATE.is_file():
        existing = load(STATE)
        non_terminal = [
            item for item in existing.get("members", [])
            if isinstance(item, dict) and item.get("status") not in TERMINAL
        ]
        if non_terminal and not args.archive_existing:
            raise SystemExit("cannot initialize over active ledger members without an explicit audited migration")
        if non_terminal and not args.force:
            raise SystemExit(
                "cannot archive-reset a ledger with non-terminal members; close every child first, "
                "or pass --force --force-reason <why> --source user:<message> to bind a human decision "
                "(gate ledger-force-reset)"
            )
        if args.archive_existing:
            data = STATE.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            payload = data
            if args.force:
                if not args.force_reason or not args.force_reason.strip():
                    raise SystemExit("forced ledger reset requires an explicit --force-reason")
                if not args.source:
                    raise SystemExit("forced ledger reset requires --source user:<message> or a provider receipt")
                approval = humandecision.record_decision_approval(
                    ROOT, load(CONFIG), load(TASK), gate="ledger-force-reset",
                    artifact_sha256=digest, source=args.source, receipt=args.receipt,
                )
                envelope = {
                    "schema": LEDGER_FORCE_ARCHIVE_SCHEMA, "archived_at": iso(now()),
                    "force_reason": args.force_reason.strip(),
                    "ledger_sha256": digest, "ledger_bytes": len(data),
                    "decision": {
                        "gate": "ledger-force-reset", "artifact_sha256": digest,
                        "source": args.source, "approval": approval,
                    },
                    "ledger": json.loads(data.decode("utf-8")),
                }
                payload = (json.dumps(envelope, ensure_ascii=False, indent=2) + "\n").encode()
            archive = AGENT / "state" / "evidence" / f"agent-ledger-archive-{digest[:16]}.json"
            archive.parent.mkdir(parents=True, exist_ok=True)
            if archive.exists():
                if not args.force and archive.read_bytes() != data:
                    raise SystemExit("ledger migration archive path collision")
                if args.force:
                    try:
                        prior = load(archive)
                    except SystemExit:
                        raise SystemExit("ledger migration archive path collision")
                    if prior.get("schema") != LEDGER_FORCE_ARCHIVE_SCHEMA or prior.get("ledger_sha256") != digest:
                        raise SystemExit("ledger migration archive path collision")
            if not archive.exists():
                descriptor, raw = tempfile.mkstemp(prefix=".agent-ledger-archive.", dir=str(archive.parent))
                temporary = Path(raw)
                try:
                    with os.fdopen(descriptor, "wb") as handle:
                        handle.write(payload); handle.flush(); os.fsync(handle.fileno())
                    os.replace(temporary, archive)
                finally:
                    if temporary.exists(): temporary.unlink()
            final = archive.read_bytes()
            migration_source = {
                "path": str(archive.relative_to(ROOT)),
                "sha256": hashlib.sha256(final).hexdigest(), "bytes": len(final),
            }
    config = policy()
    if config.get("allowed_role_types") != list(CANONICAL_ROLE_TYPES):
        raise SystemExit("agent role policy must equal the canonical role types")
    if config.get("review_role_types") != list(CANONICAL_REVIEW_ROLE_TYPES):
        raise SystemExit("review role policy must equal the canonical review role types")
    interval = int(config.get("status_interval_seconds", 0))
    monitor_grace = int(config.get("monitor_grace_seconds", -1))
    if interval <= 0 or monitor_grace < 0 or interval + monitor_grace > 60:
        raise SystemExit("supervisor polling target plus grace must be positive and no greater than 60 seconds")
    status_after = int(config.get("status_request_after_unchanged_checks", 0))
    if status_after < 1 or status_after > 10:
        raise SystemExit("status request threshold is invalid")
    stall_timeout = int(config.get("stall_timeout_seconds", 0))
    if stall_timeout < 120 or stall_timeout > 1800 or stall_timeout <= interval + monitor_grace:
        raise SystemExit("stall timeout must be bounded to 120-1800 seconds and exceed the monitor gap")
    token_budget, _ = mode_token_budget()
    value: Dict[str, object] = {
        "schema": SCHEMA, "platform_limit": int(config["platform_limit"]),
        "default_model": str(config["default_model"]),
        "allow_model_fallback": bool(config["allow_model_fallback"]),
        "context_strategy": str(config["context_strategy"]),
        "max_fork_turns": int(config["max_fork_turns"]),
        "capacity_retry_limit": int(config["capacity_retry_limit"]),
        "task_payload_limits": task_payload_limits(),
        "reserved_root_slots": int(config["reserve_root_slots"]),
        "status_interval_seconds": int(config["status_interval_seconds"]),
        "monitor_grace_seconds": monitor_grace,
        "stall_timeout_seconds": stall_timeout,
        "allowed_role_types": list(config["allowed_role_types"]),
        "review_role_types": list(config["review_role_types"]),
        "status_request_after_unchanged_checks": int(config["status_request_after_unchanged_checks"]),
        "max_redispatch": int(config["max_redispatch"]),
        "platform_observer": platform_observer_policy(),
        "epoch": hashlib.sha256(f"{load(TASK).get('title')}|{iso(now())}".encode()).hexdigest(),
        "members": [], "prepared_dispatches": [], "capacity_failures": [], "replay_runs": [],
        "token_accounting": {
            "schema": TOKEN_ACCOUNTING_SCHEMA,
            "token_budget": token_budget,
            "settled_tokens": 0,
        },
        "task_payload_schema": TASK_PAYLOAD_SCHEMA,
        "last_platform_snapshot": snapshot_record, "platform_empty_verified": True,
        "migration_source": migration_source, "updated_at": iso(now()),
    }
    save(value); print("AGENT LEDGER INITIALIZED"); return 0


def completed_zero_pass(item: Dict[str, object]) -> bool:
    verdict = item.get("review_verdict")
    return (
        item.get("status") == "completed" and isinstance(verdict, dict)
        and verdict.get("status") == "PASS"
        and all(verdict.get(key) == 0 for key in ("p0", "p1", "p2"))
        and SHA.fullmatch(str(verdict.get("report_sha256", ""))) is not None
    )


def committed_review_result(state: Dict[str, object], item: Dict[str, object],
                            expected_status: str) -> bool:
    """Prove one terminal reviewer verdict from every immutable commitment."""
    verdict_value = item.get("review_verdict")
    if (
        item.get("status") != "completed" or not isinstance(verdict_value, dict)
        or verdict_value.get("status") != expected_status
        or not all(isinstance(verdict_value.get(key), int) and verdict_value.get(key) >= 0
                   for key in ("p0", "p1", "p2"))
        or SHA.fullmatch(str(verdict_value.get("report_sha256", ""))) is None
        or (expected_status == "PASS" and any(verdict_value.get(key) != 0 for key in ("p0", "p1", "p2")))
        or (expected_status == "FAIL" and all(verdict_value.get(key) == 0 for key in ("p0", "p1", "p2")))
    ):
        return False
    records = item.get("result_evidence")
    contract = review_result_contract(item, records, state) if isinstance(records, list) else None
    marker = read_terminal_marker(state, item)
    terminal_record = item.get("terminal_platform_evidence")
    terminal_snapshot = receipt_platform_snapshot(terminal_record)
    terminal_member = receipt_platform_member(terminal_record, str(item.get("id")))
    if contract is None or marker is None or marker.get("invalid") is True:
        return False
    verdict, attestation = contract
    if (
        verdict != item.get("review_verdict") or attestation != item.get("review_attestation")
        or marker.get("schema") != TERMINAL_MARKER_SCHEMA
        or marker.get("ledger_epoch") != state.get("epoch")
        or marker.get("agent_id") != item.get("id") or marker.get("terminal_status") != "completed"
        or marker.get("task_payload_sha256") != item.get("task_payload_sha256")
        or marker.get("handoff_envelope_sha256") != item.get("handoff_envelope_sha256")
        or marker.get("review_chain_id") != item.get("review_chain_id")
        or marker.get("review_subject_sha256") != item.get("review_subject_sha256")
        or marker.get("predecessor_result_sha256") != item.get("predecessor_result_sha256")
        or marker.get("result_report_path") != item.get("result_report_path")
        or marker.get("result_evidence") != records or marker.get("review_verdict") != verdict
        or marker.get("review_attestation") != attestation
        or marker.get("monitoring_violation_at") != item.get("monitoring_violation_at")
        or marker.get("stall_violation_at") != item.get("stall_violation_at")
        or marker.get("terminal_platform_evidence") != terminal_record
        or marker.get("terminal_observed_at") != item.get("terminal_observed_at")
        or marker.get("final_message_sha256") != item.get("last_platform_message_sha256")
        or item.get("last_platform_message_sha256") != hashlib.sha256(review_final_message(verdict).encode()).hexdigest()
        or terminal_snapshot is None or terminal_member is None
        or str(terminal_member.get("status", "")).lower() not in PLATFORM_TERMINAL["completed"]
        or not platform_contract_matches(terminal_member, item, state)
    ):
        return False
    try:
        terminal_observed = parse(terminal_snapshot.get("observed_at"))
        return (
            item.get("terminal_observed_at") == iso(terminal_observed)
            and not completion_contract_errors(
                item, terminal_observed, int(state.get("status_interval_seconds", 0)),
                int(state.get("monitor_grace_seconds", 0)), int(state.get("stall_timeout_seconds", 0)),
            )
        )
    except (TypeError, ValueError):
        return False


def committed_zero_pass(state: Dict[str, object], item: Dict[str, object]) -> bool:
    """Prove a zero-finding predecessor from immutable commitments."""
    return completed_zero_pass(item) and committed_review_result(state, item, "PASS")


def committed_review_fail(state: Dict[str, object], item: Dict[str, object]) -> bool:
    """Prove a reviewer-authored FAIL that may receive the one controlled retry."""
    return committed_review_result(state, item, "FAIL")


def formal_review_chain_ids(state: Dict[str, object], root_task_id: object,
                            review_subject_sha256: object) -> Set[str]:
    """Return every non-cancelled chain ever used for one root and subject."""
    records: List[Dict[str, object]] = [
        item for item in state.get("members", []) if isinstance(item, dict)
    ]
    records.extend(
        item for item in state.get("prepared_dispatches", [])
        if isinstance(item, dict) and item.get("cancelled_at") is None
    )
    return {
        str(item.get("review_chain_id")) for item in records
        if item.get("role_type") in FORMAL_REVIEW_ROLE_TYPES
        and item.get("root_task_id") == root_task_id
        and item.get("review_subject_sha256") == review_subject_sha256
        and isinstance(item.get("review_chain_id"), str)
    }


def require_single_formal_review_chain(state: Dict[str, object],
                                       envelope: Dict[str, object]) -> None:
    """Prevent a new chain ID from laundering a prior attempt or supervision debt."""
    if envelope.get("role_type") not in FORMAL_REVIEW_ROLE_TYPES:
        return
    chain_ids = formal_review_chain_ids(
        state, envelope.get("root_task_id"), envelope.get("review_subject_sha256"),
    )
    if chain_ids and chain_ids != {str(envelope.get("review_chain_id"))}:
        raise SystemExit(
            "one root task and review subject must retain one formal review chain; "
            "retry the failed role in the existing chain"
        )


def require_formal_review_predecessor(state: Dict[str, object], envelope: Dict[str, object]) -> None:
    """Reject a formal successor until one immutable zero-finding predecessor exists."""
    role_type = envelope.get("role_type")
    if role_type not in FORMAL_REVIEW_ROLE_TYPES:
        return
    chain_id = envelope.get("review_chain_id")
    subject = envelope.get("review_subject_sha256")
    same_chain = [
        item for item in state.get("members", [])
        if isinstance(item, dict) and item.get("review_chain_id") == chain_id
    ]
    if any(item.get("review_subject_sha256") != subject for item in same_chain):
        raise SystemExit("formal review chain cannot mix task payload subjects")
    prior_same_role = [item for item in same_chain if item.get("role_type") == role_type]
    if integer(envelope.get("redispatch_count")) == 0 and prior_same_role:
        raise SystemExit("formal review role was already dispatched in this review chain")
    if integer(envelope.get("redispatch_count")) == 1 and (
        len(prior_same_role) != 1
        or (
            prior_same_role[0].get("status") not in {"interrupted", "errored", "expired"}
            and not committed_review_fail(state, prior_same_role[0])
        )
        or integer(prior_same_role[0].get("redispatch_count")) != 0
    ):
        raise SystemExit("formal review redispatch lacks one failed predecessor attempt")
    if role_type == "adversarial":
        if envelope.get("predecessor_result_sha256") is not None:
            raise SystemExit("adversarial review cannot claim a predecessor")
        if any(item.get("role_type") in {"cross", "integrator"} for item in same_chain):
            raise SystemExit("adversarial review cannot start after a successor in the same chain")
        return
    predecessor_role = "adversarial" if role_type == "cross" else "cross"
    predecessors = [
        item for item in same_chain
        if item.get("role_type") == predecessor_role and committed_zero_pass(state, item)
    ]
    if len(predecessors) != 1:
        raise SystemExit(f"{role_type} review requires one completed zero-finding PASS {predecessor_role} predecessor")
    predecessor = predecessors[0]
    predecessor_sha = (predecessor.get("review_verdict") or {}).get("report_sha256")
    if envelope.get("predecessor_result_sha256") != predecessor_sha:
        raise SystemExit(f"{role_type} review predecessor report digest is invalid")
    try:
        predecessor_terminal = parse(predecessor.get("terminal_observed_at"))
        if parse(envelope.get("started_at")) < predecessor_terminal or now() < predecessor_terminal:
            raise SystemExit("formal review roles overlap; successor starts before predecessor terminal observation")
    except (TypeError, ValueError):
        raise SystemExit("formal review predecessor chronology is invalid")
    if role_type == "integrator":
        adversarial = [
            item for item in same_chain
            if item.get("role_type") == "adversarial" and committed_zero_pass(state, item)
        ]
        if len(adversarial) != 1:
            raise SystemExit("integrator review requires the same chain's completed adversarial PASS")
        if predecessor.get("predecessor_result_sha256") != (adversarial[0].get("review_verdict") or {}).get("report_sha256"):
            raise SystemExit("integrator review chain is not linked adversarial to cross")


def command_prepare(args: argparse.Namespace) -> int:
    """Publish payload/envelope before spawn and reserve one bounded child slot."""
    state = load(STATE)
    if state.get("task_payload_limits") != task_payload_limits():
        raise SystemExit("ledger task payload limits differ from config")
    prepared = state.setdefault("prepared_dispatches", [])
    if not isinstance(prepared, list):
        raise SystemExit("prepared dispatch registry is invalid")
    prior_preparations = [
        item for item in prepared if isinstance(item, dict) and item.get("id") == args.id
    ]
    if len(prior_preparations) > 1:
        raise SystemExit("canonical dispatch ID occurs more than once")
    if any(isinstance(item, dict) and item.get("id") == args.id for item in state.get("members", [])):
        raise SystemExit("canonical agent ID already exists")
    root_id = args.root_task_id or args.id
    if args.role_type not in state.get("allowed_role_types", []):
        raise SystemExit(f"unknown canonical role type: {args.role_type}")
    configured_model = str(policy().get("default_model", ""))
    if args.model != configured_model:
        raise SystemExit(f"agent model must equal configured default: {configured_model}")
    configured_fork = int(policy().get("max_fork_turns", 0))
    if args.fork_turns < 0 or args.fork_turns > configured_fork:
        raise SystemExit(f"agent fork window must stay within 0..{configured_fork}")
    # A preparation written before the no-history policy may retain a non-zero
    # fork for audit and exact command replay.  Reject it before publishing any
    # evidence only when this ID would create a genuinely new dispatch.
    if not prior_preparations:
        require_dispatch_fork(args.fork_turns)
    if args.redispatch_count < 0 or args.redispatch_count > int(state.get("max_redispatch", -1)):
        raise SystemExit("prepared redispatch count is invalid")
    payload_record = immutable_task_payload_evidence(args.task_payload)
    payload = reusable_task_payload(payload_record)
    if payload is None:
        raise SystemExit("reusable task payload must match exact sealed agent-task-payload/v2 and contain no dispatch fields")
    estimated_tokens = integer(payload.get("estimated_tokens"))
    envelope_record = immutable_handoff_envelope_evidence(args.handoff_envelope)
    envelope = handoff_envelope(envelope_record)
    if envelope is None:
        raise SystemExit("per-dispatch handoff envelope is invalid")
    if not prior_preparations and args.role_type == "integrator":
        execution_profile = execution_profile_contract(
            envelope.get("execution_profile"), current_candidate_sha256()
        )
        if execution_profile is None:
            raise SystemExit("integrator dispatch requires a candidate-bound execution profile and passed preflight")
        preflight = load(ROOT / str(execution_profile["preflight_receipt"]["path"]))
        try:
            observed = parse(preflight.get("observed_at")); expires = parse(preflight.get("expires_at"))
        except (TypeError, ValueError):
            raise SystemExit("integrator execution preflight timestamps are invalid")
        if observed > now() + dt.timedelta(seconds=TIMESTAMP_SKEW_SECONDS) or now() > expires or expires - observed > dt.timedelta(minutes=15):
            raise SystemExit("integrator execution preflight is stale, future or overlong")
    try:
        started = parse(envelope.get("started_at")); deadline = parse(envelope.get("deadline_at"))
    except (TypeError, ValueError):
        raise SystemExit("prepared dispatch schedule is invalid")
    duration = (deadline - started).total_seconds()
    age = (now() - started).total_seconds()
    if (
        duration < 60 or duration > 7200 or duration % 60 != 0
        or (not prior_preparations and (age < -5 or age > 300 or deadline <= now()))
    ):
        raise SystemExit("prepared dispatch schedule is stale, future or outside 1-120 minutes")
    expected_contract = {
        "ledger_epoch": state.get("epoch"), "agent_id": args.id, "root_task_id": root_id,
        "role_type": args.role_type, "model": args.model, "fork_turns": args.fork_turns,
        "started_at": iso(started), "deadline_at": iso(deadline), "redispatch_count": args.redispatch_count,
    }
    if not envelope_contract_matches(envelope, expected_contract, payload_record):
        raise SystemExit("per-dispatch handoff envelope differs from the prepare contract")
    if prior_preparations:
        prior = prior_preparations[0]
        reservation = prior.get("token_reservation")
        if (
            prior.get("root_task_id") != root_id
            or prior.get("role_type") != args.role_type
            or prior.get("model") != args.model
            or prior.get("fork_turns") != args.fork_turns
            or prior.get("redispatch_count") != args.redispatch_count
            or prior.get("task_payload_evidence") != payload_record
            or prior.get("handoff_envelope_evidence") != envelope_record
            or not isinstance(reservation, dict)
            or reservation.get("estimated_tokens") != estimated_tokens
        ):
            raise SystemExit("canonical dispatch ID was already prepared with different bytes or controls")
        if prior.get("consumed_at") is None and prior.get("cancelled_at") is None and reservation.get("status") == "reserved":
            print(f"AGENT DISPATCH ALREADY PREPARED: {args.id}")
            try:
                prior_expiry = min(
                    parse(prior.get("deadline_at")),
                    parse(prior.get("prepared_at"))
                    + dt.timedelta(seconds=PREPARED_DISPATCH_TTL_SECONDS),
                )
            except (TypeError, ValueError):
                prior_expiry = None
            if prior_expiry is None or now() >= prior_expiry:
                # Register will hard-reject this preparation; surface the
                # release cursor here so idempotent re-entry is not a dead end.
                print(
                    f"prepared dispatch is past the register TTL: {args.id}; "
                    f"release it before re-registering: agentledger.py cancel-prepare --id {args.id}"
                )
            return 0
        raise SystemExit("canonical dispatch ID is already closed")
    require_dispatch_context(args.fork_turns, estimated_tokens)
    if not state.get("members") and state.get("platform_empty_verified") is not True:
        raise SystemExit(
            "first dispatch for this task requires `agentledger.py init --platform-snapshot <fresh-empty-snapshot>`"
        )
    cap = min(mode_limit(), int(state["platform_limit"]) - int(state["reserved_root_slots"]))
    pending = [item for item in prepared if isinstance(item, dict) and item.get("consumed_at") is None and item.get("cancelled_at") is None]
    if len(active(state)) + len(pending) >= cap:
        raise SystemExit("agent concurrency cap reached; root slot is reserved")
    require_single_formal_review_chain(state, envelope)
    require_formal_review_predecessor(state, envelope)
    # A completed implementation may need one final read-only authorship
    # attestation after the compact watermark. Classify only that tightly
    # constrained dispatch as acceptance work; an implementer that may still
    # edit managed files remains new scope and stays blocked.
    allowed_paths = list(envelope["allowed_evidence_paths"])
    forbidden_actions = set(envelope["forbidden_actions"])
    attestation_only_implementer = (
        args.role_type == "implementer"
        and len(allowed_paths) == 1
        and re.fullmatch(
            r"\.agent/state/evidence/implementation-attestation-[A-Za-z0-9._-]+\.json",
            allowed_paths[0],
        ) is not None
        and {"approve-node7", "modify-managed-files"}.issubset(forbidden_actions)
    )
    action = "spawn-review-agent" if (
        args.role_type in state.get("review_role_types", []) or attestation_only_implementer
    ) else "spawn-agent"
    budget = subprocess.run(
        [sys.executable, str(AGENT / "scripts" / "agentctl.py"), "budget-gate", "--action", action],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    if budget.returncode:
        raise SystemExit(budget.stdout.strip() or f"budget gate blocked {action}")
    require_payload_token_budget(state, estimated_tokens, args.fork_turns)
    capacity_failures = [
        item for item in state.get("capacity_failures", [])
        if isinstance(item, dict) and item.get("root_task_id") == root_id
    ]
    if len(capacity_failures) > int(state["capacity_retry_limit"]):
        raise SystemExit("same-model capacity retry was already exhausted for this root task")
    reserved_at = iso(now())
    reservation_id = token_reservation_id(
        state, args.id, str(payload_record["sha256"]), estimated_tokens,
    )
    prepared.append({
        "id": args.id, "root_task_id": root_id, "role_type": args.role_type,
        "model": args.model, "fork_turns": args.fork_turns, "started_at": iso(started),
        "deadline_at": iso(deadline), "redispatch_count": args.redispatch_count,
        "task_payload_sha256": payload_record["sha256"], "task_payload_evidence": payload_record,
        "handoff_envelope_sha256": envelope_record["sha256"], "handoff_envelope_evidence": envelope_record,
        "allowed_evidence_paths": list(envelope["allowed_evidence_paths"]),
        "forbidden_actions": list(envelope["forbidden_actions"]),
        "review_chain_id": envelope["review_chain_id"],
        "review_subject_sha256": envelope["review_subject_sha256"],
        "predecessor_result_sha256": envelope["predecessor_result_sha256"],
        "result_report_path": envelope["result_report_path"],
        "token_reservation": {
            "id": reservation_id,
            "estimated_tokens": estimated_tokens,
            "status": "reserved",
            "reserved_at": reserved_at,
            "closed_at": None,
            "charge_receipt": None,
        },
        "prepared_at": reserved_at, "consumed_at": None, "cancelled_at": None,
    })
    state["updated_at"] = iso(now()); save(state)
    print(f"AGENT DISPATCH PREPARED: {args.id}")
    print(f"TASK PAYLOAD: {payload_record['path']} sha256={payload_record['sha256']}")
    print(f"SPAWN ENVELOPE: {envelope_record['path']} sha256={envelope_record['sha256']}")
    return 0


def command_cancel_prepare(args: argparse.Namespace) -> int:
    state = load(STATE)
    registry = state.get("prepared_dispatches", [])
    matches = [item for item in registry if isinstance(item, dict) and item.get("id") == args.id]
    if len(matches) == 1 and matches[0].get("cancelled_at") is not None:
        print(f"AGENT DISPATCH ALREADY CANCELLED: {args.id}")
        return 0
    if len(matches) != 1 or matches[0].get("consumed_at") is not None:
        raise SystemExit("only one unconsumed prepared dispatch can be cancelled")
    if any(isinstance(item, dict) and item.get("id") == args.id for item in state.get("members", [])):
        raise SystemExit("registered dispatch cannot be cancelled")
    reservation = matches[0].get("token_reservation")
    if not isinstance(reservation, dict) or reservation.get("status") != "reserved":
        raise SystemExit("prepared dispatch lacks a releasable token reservation")
    cancelled_at = iso(now())
    matches[0]["cancelled_at"] = cancelled_at
    reservation.update({"status": "released", "closed_at": cancelled_at, "charge_receipt": None})
    state["updated_at"] = iso(now()); save(state)
    print(f"AGENT DISPATCH CANCELLED: {args.id}"); return 0


def register(state: Dict[str, object], args: argparse.Namespace, redispatch_count: int = 0,
             root_task_id: Optional[str] = None) -> int:
    if not args.platform_snapshot:
        raise SystemExit("agent registration requires a fresh platform snapshot taken after spawn")
    require_sha(args.progress_hash)
    if any(item.get("id") == args.id for item in state.get("members", []) if isinstance(item, dict)):
        raise SystemExit("canonical agent ID already exists")
    if not 1 <= args.deadline_minutes <= 120:
        raise SystemExit("deadline must be 1-120 minutes")
    maximum_fork_turns = int(policy().get("max_fork_turns", 0))
    if args.fork_turns < 0 or args.fork_turns > maximum_fork_turns:
        raise SystemExit(f"agent fork window must stay within 0..{maximum_fork_turns}")
    root_id = root_task_id or args.root_task_id or args.id
    prepared = [
        item for item in state.get("prepared_dispatches", [])
        if isinstance(item, dict) and item.get("id") == args.id
        and item.get("consumed_at") is None and item.get("cancelled_at") is None
    ]
    if len(prepared) != 1:
        raise SystemExit("agent registration requires one unconsumed pre-spawn preparation")
    preparation = prepared[0]
    try:
        register_expiry = min(
            parse(preparation.get("deadline_at")),
            parse(preparation.get("prepared_at"))
            + dt.timedelta(seconds=PREPARED_DISPATCH_TTL_SECONDS),
        )
    except (TypeError, ValueError):
        # Shape errors are not expiry; still fail closed, but say what is
        # actually wrong with the preparation.
        raise SystemExit(f"prepared dispatch has invalid timestamps: {args.id}")
    if now() >= register_expiry:
        raise SystemExit(
            f"prepared dispatch expired: {args.id}; "
            f"release it before re-preparing: agentledger.py cancel-prepare --id {args.id}"
        )
    reservation = preparation.get("token_reservation")
    if (
        preparation.get("root_task_id") != root_id
        or preparation.get("role_type") != args.role_type
        or preparation.get("model") != args.model
        or preparation.get("fork_turns") != args.fork_turns
        or preparation.get("redispatch_count") != redispatch_count
        or not isinstance(reservation, dict)
        or reservation.get("status") != "reserved"
    ):
        raise SystemExit("agent registration differs from its pre-spawn preparation")
    snapshot_value, snapshot_record, platform = platform_snapshot(args.platform_snapshot)
    registration_observed = parse(snapshot_value["observed_at"])
    payload_record = immutable_task_payload_evidence(args.task_payload)
    if reusable_task_payload(payload_record) is None:
        raise SystemExit("reusable task payload must match exact sealed agent-task-payload/v2 and contain no dispatch fields")
    envelope_record = immutable_handoff_envelope_evidence(args.handoff_envelope)
    envelope = handoff_envelope(envelope_record)
    try:
        started = parse(envelope.get("started_at") if envelope else None)
        deadline = parse(envelope.get("deadline_at") if envelope else None)
    except (ValueError, TypeError):
        raise SystemExit("per-dispatch handoff envelope schedule is invalid")
    if (
        (deadline - started).total_seconds() != args.deadline_minutes * 60
        or registration_observed < started - dt.timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
        or registration_observed > deadline
    ):
        raise SystemExit("platform registration observation is outside the prepared dispatch window")
    if payload_record != preparation.get("task_payload_evidence") or envelope_record != preparation.get("handoff_envelope_evidence"):
        raise SystemExit("registration payload/envelope bytes differ from pre-spawn preparation")
    expected_contract = {
        "ledger_epoch": state.get("epoch"), "agent_id": args.id, "root_task_id": root_id,
        "role_type": args.role_type, "model": args.model, "fork_turns": args.fork_turns,
        "started_at": iso(started), "deadline_at": iso(deadline), "redispatch_count": redispatch_count,
        "review_chain_id": preparation.get("review_chain_id"),
        "review_subject_sha256": preparation.get("review_subject_sha256"),
        "predecessor_result_sha256": preparation.get("predecessor_result_sha256"),
        "result_report_path": preparation.get("result_report_path"),
    }
    if envelope is None or not envelope_contract_matches(envelope, expected_contract, payload_record):
        raise SystemExit("per-dispatch handoff envelope differs from the registration contract")
    require_formal_review_predecessor(state, envelope)
    if iso(started) != preparation.get("started_at") or iso(deadline) != preparation.get("deadline_at"):
        raise SystemExit("platform registration schedule differs from pre-spawn preparation")
    observed = active_platform_ids(platform)
    expected = {str(item["id"]) for item in active(state)} | {args.id}
    platform_item = platform.get(args.id)
    if observed != expected or not platform_item or str(platform_item.get("status", "")).lower() not in PLATFORM_ACTIVE:
        raise SystemExit(f"registration platform mismatch: expected={sorted(expected)} observed={sorted(observed)}")
    expected_model = str(policy().get("default_model", ""))
    if not expected_model or args.model != expected_model or platform_item.get("model") != expected_model:
        raise SystemExit(f"agent model must be platform-bound to configured default: {expected_model}")
    if platform_item.get("fork_turns") != args.fork_turns:
        raise SystemExit("agent fork window differs from the platform spawn receipt")
    if platform_item.get("role_type") != args.role_type:
        raise SystemExit("agent role type differs from the platform spawn receipt")
    if platform_item.get("task_payload_sha256") != payload_record.get("sha256"):
        raise SystemExit("agent task payload differs from the platform spawn receipt")
    if platform_item.get("handoff_envelope_sha256") != envelope_record.get("sha256"):
        raise SystemExit("agent handoff envelope differs from the platform spawn receipt")
    if (
        platform_item.get("ledger_epoch") != state.get("epoch")
        or platform_item.get("root_task_id") != root_id
        or platform_item.get("started_at") != iso(started)
        or platform_item.get("deadline_at") != iso(deadline)
        or platform_item.get("redispatch_count") != redispatch_count
    ):
        raise SystemExit("agent registration contract differs from the platform spawn receipt")
    for existing in active(state):
        if not platform_contract_matches(platform[str(existing["id"])], existing, state):
            raise SystemExit(f"existing platform contract drifted for {existing['id']}")
    if args.role_type not in state.get("allowed_role_types", []):
        raise SystemExit(f"unknown canonical role type: {args.role_type}")
    state["members"].append({
        "id": args.id, "root_task_id": root_id, "role_type": args.role_type,
        "role": args.role, "task": args.task, "model": args.model,
        "fork_turns": args.fork_turns, "context_strategy": str(policy()["context_strategy"]),
        "task_payload_sha256": payload_record["sha256"], "task_payload_evidence": payload_record,
        "payload_estimated_tokens": (preparation.get("token_reservation") or {}).get("estimated_tokens"),
        "token_reservation_id": (preparation.get("token_reservation") or {}).get("id"),
        "handoff_envelope_sha256": envelope_record["sha256"], "handoff_envelope_evidence": envelope_record,
        "allowed_evidence_paths": list(envelope["allowed_evidence_paths"]),
        "forbidden_actions": list(envelope["forbidden_actions"]),
        "review_chain_id": envelope["review_chain_id"],
        "review_subject_sha256": envelope["review_subject_sha256"],
        "predecessor_result_sha256": envelope["predecessor_result_sha256"],
        "result_report_path": envelope["result_report_path"], "status": ACTIVE,
        "started_at": iso(started), "deadline_at": iso(deadline),
        "last_progress_at": iso(registration_observed), "last_check_at": None, "progress_hash": args.progress_hash,
        "platform_cursor": int(platform_item.get("message_cursor", 0)), "last_platform_message_sha256": platform_item.get("message_sha256"),
        "progress_observed": False, "unchanged_checks": 0, "redispatch_count": redispatch_count,
        "redispatched_to": None, "evidence": [], "registration_platform_evidence": snapshot_record,
        "result_evidence": [], "review_verdict": None, "review_attestation": None,
        "registration_observed_at": iso(registration_observed),
        "monitor_platform_evidence": [], "monitoring_violation_at": None,
        "stall_violation_at": None,
        "interrupt_requested_at": None, "interrupt_reason": None,
        "terminal_platform_evidence": None, "terminal_observed_at": None,
    })
    preparation["consumed_at"] = iso(now())
    state["last_platform_snapshot"] = snapshot_record; state["platform_empty_verified"] = False; state["updated_at"] = iso(now()); commit_registered_ledger(state)
    print(f"AGENT REGISTERED: {args.id}"); return 0


def command_register(args: argparse.Namespace) -> int:
    state = load(STATE)
    existing = [
        item for item in state.get("members", [])
        if isinstance(item, dict) and item.get("id") == args.id
    ]
    if len(existing) == 1:
        item = existing[0]
        payload_record = immutable_task_payload_evidence(args.task_payload)
        envelope_record = immutable_handoff_envelope_evidence(args.handoff_envelope)
        root_id = args.root_task_id or args.id
        try:
            duration_minutes = int((parse(item.get("deadline_at")) - parse(item.get("started_at"))).total_seconds() // 60)
        except (TypeError, ValueError):
            duration_minutes = -1
        if (
            item.get("root_task_id") == root_id
            and item.get("role_type") == args.role_type
            and item.get("role") == args.role
            and item.get("task") == args.task
            and item.get("model") == args.model
            and item.get("fork_turns") == args.fork_turns
            and item.get("task_payload_evidence") == payload_record
            and item.get("handoff_envelope_evidence") == envelope_record
            and duration_minutes == args.deadline_minutes
        ):
            print(f"AGENT ALREADY REGISTERED: {args.id}")
            return 0
        raise SystemExit("canonical agent ID was already registered with a different contract")
    return register(state, args)


def managed_runner_receipt() -> Dict[str, object]:
    return evidence(".agent/scripts/testrun.py")


def replay_run(state: Dict[str, object], integrator_id: str, run_id: str) -> Dict[str, object]:
    found = [
        item for item in state.get("replay_runs", [])
        if isinstance(item, dict) and item.get("integrator_id") == integrator_id and item.get("run_id") == run_id
    ]
    if len(found) != 1:
        raise SystemExit("replay run must be pre-registered exactly once")
    return found[0]


def command_replay_prepare(args: argparse.Namespace) -> int:
    state = load(STATE); item = member(state, args.integrator_id)
    if item.get("status") != ACTIVE or item.get("role_type") != "integrator":
        raise SystemExit("clean replay preparation requires one active integrator")
    source_plan = evidence(args.plan)
    sealed_plan = immutable_blob_evidence(args.plan, "agent-replay-plans", ".json", "agent-replay-plan")
    plan = replay_plan(sealed_plan)
    if plan is None or not replay_plan_output_paths_match_runner(plan):
        raise SystemExit("clean replay plan is invalid")
    node6_contract = current_node6_replay_contract(item)
    if node6_contract is None or not replay_plan_matches_node6(plan, node6_contract[2]):
        raise SystemExit("clean replay plan must exactly reproduce the current sealed Node 6 checks")
    node6_task_receipt, node6_input_evidence, _ = node6_contract
    if plan.get("receipt_path") not in set(item.get("allowed_evidence_paths", [])):
        raise SystemExit("clean replay receipt is outside the integrator envelope allowlist")
    receipt_path = ROOT / str(plan["receipt_path"])
    if os.path.lexists(receipt_path):
        raise SystemExit("clean replay receipt path must be fresh")
    runs = state.setdefault("replay_runs", [])
    if not isinstance(runs, list):
        raise SystemExit("replay run registry is invalid")
    if len([run for run in runs if isinstance(run, dict) and run.get("integrator_id") == item.get("id")]) >= required_clean_replays():
        raise SystemExit("integrator clean replay authority is exactly one pre-registered run")
    if any(isinstance(run, dict) and run.get("run_id") == plan.get("run_id") for run in runs):
        raise SystemExit("clean replay run ID was already registered")
    runner = managed_runner_receipt(); prepared_at = iso(now())
    candidate_sha256 = current_candidate_sha256()
    authority_id = hashlib.sha256(json.dumps({
        "epoch": state.get("epoch"), "integrator_id": item.get("id"),
        "review_chain_id": item.get("review_chain_id"),
        "review_subject_sha256": item.get("review_subject_sha256"),
        "candidate_sha256": candidate_sha256,
        "run_id": plan.get("run_id"), "plan_sha256": sealed_plan.get("sha256"),
        "runner_sha256": runner.get("sha256"), "prepared_at": prepared_at,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    runs.append({
        "authority_id": authority_id, "integrator_id": item.get("id"),
        "review_chain_id": item.get("review_chain_id"),
        "review_subject_sha256": item.get("review_subject_sha256"),
        "candidate_sha256": candidate_sha256,
        "run_id": plan.get("run_id"), "receipt_path": plan.get("receipt_path"),
        "source_plan": source_plan, "plan_evidence": sealed_plan, "runner_evidence": runner,
        "node6_task_receipt": node6_task_receipt, "node6_input_evidence": node6_input_evidence,
        "prepared_at": prepared_at, "status": "prepared",
        "cases": [{"id": case["id"], "claim_id": None, "start": None, "finish": None, "case": None} for case in plan["cases"]],
        "last_observation_sha256": None, "completed_at": None,
        "final_receipt_sha256": None, "final_receipt_evidence": None, "failure_reason": None,
    })
    state["updated_at"] = iso(now()); save(state)
    print(f"REPLAY PREPARED: {plan['run_id']} authority={authority_id}")
    return 0


def abort_pending_replays_for_terminal(state: Dict[str, object], integrator_id: str,
                                       completed_at: str, reconciliation: bool = False) -> int:
    """Close every unfinished prepared run when its integrator becomes terminal."""
    runs = state.get("replay_runs")
    if not isinstance(runs, list):
        raise SystemExit("replay run registry is invalid")
    count = 0
    for run in runs:
        if (
            not isinstance(run, dict) or run.get("integrator_id") != integrator_id
            or run.get("status") != "prepared"
        ):
            continue
        cases = run.get("cases")
        if not isinstance(cases, list):
            raise SystemExit("prepared replay case registry is invalid")
        unfinished_claim = any(
            isinstance(case, dict) and case.get("start") is not None and case.get("finish") is None
            for case in cases
        )
        run.update({
            "status": "aborted", "completed_at": completed_at,
            "failure_reason": (
                "orphaned-executing-claim" if unfinished_claim
                else "terminal-owner-reconciled" if reconciliation
                else "integrator-terminal-before-replay"
            ),
            "final_receipt_sha256": None, "final_receipt_evidence": None,
        })
        count += 1
    return count


def command_replay_reconcile_terminal(args: argparse.Namespace) -> int:
    """Repair only a legacy terminal integrator whose never-finished runs stayed prepared."""
    state = load(STATE); item = member(state, args.integrator_id)
    if (
        item.get("role_type") != "integrator"
        or item.get("status") not in {"interrupted", "errored", "expired"}
        or not valid_receipt(item.get("terminal_platform_evidence"))
    ):
        raise SystemExit("replay reconciliation requires one observed non-successful terminal integrator")
    try:
        parse(item.get("terminal_observed_at")); parse(item.get("finished_at"))
    except (TypeError, ValueError):
        raise SystemExit("terminal integrator timestamps are invalid")
    reconciled_at = iso(now())
    count = abort_pending_replays_for_terminal(state, str(item["id"]), reconciled_at, reconciliation=True)
    if count == 0:
        raise SystemExit("terminal integrator has no prepared replay to reconcile")
    state["updated_at"] = reconciled_at; save(state)
    print(f"REPLAY TERMINAL RECONCILED: {item['id']} aborted={count}")
    return 0


def replay_observation(run: Dict[str, object], expected: Dict[str, object], sequence: int,
                       event: str, observed_at: str, claim_id: str,
                       output: Optional[Dict[str, object]] = None,
                       execution: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    value: Dict[str, object] = {
        "schema": REPLAY_OBSERVATION_SCHEMA, "event": event,
        "authority_id": run.get("authority_id"), "integrator_id": run.get("integrator_id"),
        "review_chain_id": run.get("review_chain_id"),
        "review_subject_sha256": run.get("review_subject_sha256"),
        "run_id": run.get("run_id"), "case_id": expected.get("id"), "sequence": sequence,
        "claim_id": claim_id,
        "runner_sha256": (run.get("runner_evidence") or {}).get("sha256"),
        "plan_sha256": (run.get("plan_evidence") or {}).get("sha256"),
        "previous_observation_sha256": run.get("last_observation_sha256"),
        "observed_at": observed_at,
    }
    if event == "finish":
        value["output"] = output
    if execution:
        value.update(execution or {})
    return publish_generated_blob(value, "agent-replay-observations", ".json", "agent-replay-observation")


def write_replay_receipt(run: Dict[str, object], cases: List[Dict[str, object]]) -> None:
    receipt_path = ROOT / str(run["receipt_path"]); receipt_path.parent.mkdir(parents=True, exist_ok=True)
    value = {
        "schema": "agent-test-receipt/v3", "run_id": run["run_id"],
        "candidate_sha256": run["candidate_sha256"],
        "runner": run["runner_evidence"], "cases": [case["case"] for case in cases if case.get("case") is not None],
    }
    data = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    descriptor, raw = tempfile.mkstemp(prefix=f".{receipt_path.name}.", dir=str(receipt_path.parent))
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, receipt_path)
    finally:
        if temporary.exists(): temporary.unlink()


def replay_execute_claim(integrator_id: str, run_id: str) -> Optional[Dict[str, object]]:
    """Short locked phase: authorize exactly the next Node 6 case and persist its start."""
    with LOCK.open("r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        state = load(STATE); item = member(state, integrator_id); run = replay_run(state, integrator_id, run_id)
        plan = replay_plan(run.get("plan_evidence")); cases = run.get("cases")
        contract = current_node6_replay_contract(item)
        try:
            supervision_valid = (
                now() <= parse(item.get("deadline_at"))
                and item.get("interrupt_requested_at") is None
                and item.get("stall_violation_at") is None
            )
        except (TypeError, ValueError):
            supervision_valid = False
        if (
            item.get("status") != ACTIVE or item.get("role_type") != "integrator"
            or run.get("status") != "prepared" or plan is None or not isinstance(cases, list)
            or contract is None or not replay_plan_matches_node6(plan, contract[2])
            or run.get("node6_task_receipt") != contract[0]
            or run.get("node6_input_evidence") != contract[1]
            or run.get("candidate_sha256") != current_candidate_sha256()
            or managed_runner_receipt() != run.get("runner_evidence")
        ):
            raise SystemExit("replay execute authority or current Node 6 binding drifted")
        if not supervision_valid:
            aborted_at = iso(now())
            run.update({"status": "aborted", "completed_at": aborted_at,
                        "failure_reason": "supervision-window-closed"})
            state["updated_at"] = aborted_at; save(state)
            raise SystemExit("replay execution is aborted because the integrator supervision window closed")
        executing = [case for case in cases if isinstance(case, dict) and case.get("start") is not None and case.get("finish") is None]
        if executing:
            aborted_at = iso(now())
            run.update({"status": "aborted", "completed_at": aborted_at,
                        "failure_reason": "orphaned-executing-claim"})
            state["updated_at"] = aborted_at; save(state)
            raise SystemExit("replay orphaned claim was preserved as an aborted authority")
        pending = [index for index, case in enumerate(cases) if isinstance(case, dict) and case.get("start") is None]
        if not pending:
            return None
        index = pending[0]; authority = cases[index]; expected = plan["cases"][index]
        if any(isinstance(case, dict) and case.get("finish") is None for case in cases[:index]):
            raise SystemExit("replay cases cannot skip pre-registered order")
        claimed_at = iso(now())
        claim_id = hashlib.sha256(
            f"{run['authority_id']}|{expected['id']}|{claimed_at}|{os.urandom(32).hex()}".encode()
        ).hexdigest()
        start = replay_observation(
            run, expected, index, "start", claimed_at, claim_id,
            execution={
                "command": expected["command"], "timeout_seconds": expected["timeout_seconds"],
                "output_path": expected["expected_output_path"],
            },
        )
        authority.update({"claim_id": claim_id, "start": start})
        run["last_observation_sha256"] = start["sha256"]
        state["updated_at"] = claimed_at; save(state)
        return {
            "index": index, "claim_id": claim_id, "case_id": expected["id"],
            "command": expected["command"], "timeout_seconds": expected["timeout_seconds"],
            "receipt_path": run["receipt_path"], "runner": run["runner_evidence"],
            "candidate_sha256": run["candidate_sha256"],
        }


def replay_execute_commit(integrator_id: str, run_id: str, claim: Dict[str, object]) -> Tuple[bool, bool]:
    """Short locked phase: consume only the exact ledger-launched testrun result."""
    with LOCK.open("r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        state = load(STATE); item = member(state, integrator_id); run = replay_run(state, integrator_id, run_id)
        plan = replay_plan(run.get("plan_evidence")); cases = run.get("cases")
        index = integer(claim.get("index"))
        try:
            supervision_valid = (
                now() <= parse(item.get("deadline_at"))
                and item.get("interrupt_requested_at") is None
                and item.get("stall_violation_at") is None
            )
        except (TypeError, ValueError):
            supervision_valid = False
        if (
            item.get("status") != ACTIVE or run.get("status") != "prepared"
            or plan is None or not isinstance(cases, list) or not 0 <= index < len(cases)
            or run.get("candidate_sha256") != current_candidate_sha256()
            or managed_runner_receipt() != run.get("runner_evidence")
        ):
            raise SystemExit("replay execution changed before result commit")
        if not supervision_valid:
            aborted_at = iso(now())
            run.update({"status": "aborted", "completed_at": aborted_at,
                        "failure_reason": "supervision-window-closed"})
            state["updated_at"] = aborted_at; save(state)
            raise SystemExit("replay result cannot commit after the supervision window closed")
        authority = cases[index]; expected = plan["cases"][index]
        if (
            not isinstance(authority, dict) or authority.get("claim_id") != claim.get("claim_id")
            or authority.get("start") is None or authority.get("finish") is not None
        ):
            raise SystemExit("replay execution claim is no longer unique and active")
        try:
            provisional = load(ROOT / str(run["receipt_path"]))
        except (OSError, ValueError, json.JSONDecodeError, TypeError, SystemExit):
            raise SystemExit("managed testrun did not produce its provisional result")
        provisional_cases = provisional.get("cases")
        if (
            set(provisional) != {"schema", "run_id", "candidate_sha256", "runner", "cases"}
            or provisional.get("schema") != "agent-test-receipt/v3"
            or provisional.get("run_id") != run_id or provisional.get("runner") != run.get("runner_evidence")
            or provisional.get("candidate_sha256") != run.get("candidate_sha256")
            or not isinstance(provisional_cases, list) or len(provisional_cases) != index + 1
            or any(provisional_cases[position] != cases[position].get("case") for position in range(index))
        ):
            raise SystemExit("managed testrun receipt differs from prior replay authority")
        observed_case = provisional_cases[index]
        required_case = {
            "id", "run_id", "candidate_sha256", "command", "started_at", "finished_at", "exit_code",
            "outcome", "cleanup", "output", "case_sha256",
        }
        if (
            not isinstance(observed_case, dict) or set(observed_case) != required_case
            or observed_case.get("id") != expected.get("id") or observed_case.get("run_id") != run_id
            or observed_case.get("candidate_sha256") != run.get("candidate_sha256")
            or observed_case.get("command") != expected.get("command")
            or not valid_receipt(observed_case.get("output"))
            or (observed_case.get("output") or {}).get("path") != expected.get("expected_output_path")
        ):
            raise SystemExit("managed testrun result does not match the exact planned invocation")
        unsigned = {key: value for key, value in observed_case.items() if key != "case_sha256"}
        if observed_case.get("case_sha256") != hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest():
            raise SystemExit("managed testrun result hash is invalid")
        output = immutable_blob_evidence(
            str(expected["expected_output_path"]), "agent-replay-outputs", ".log", "agent-replay-output"
        )
        finished_at = iso(now())
        finish = replay_observation(
            run, expected, index, "finish", finished_at, str(claim["claim_id"]), output,
            execution={
                "exit_code": observed_case.get("exit_code"), "outcome": observed_case.get("outcome"),
                "cleanup": observed_case.get("cleanup"),
            },
        )
        start_value = load(ROOT / str(authority["start"]["path"]))
        case = {
            "id": expected["id"], "run_id": run_id,
            "candidate_sha256": run["candidate_sha256"], "command": expected["command"],
            "started_at": start_value["observed_at"], "finished_at": finished_at,
            "exit_code": observed_case.get("exit_code"), "outcome": observed_case.get("outcome"),
            "cleanup": observed_case.get("cleanup"), "output": output,
        }
        case["case_sha256"] = hashlib.sha256(
            json.dumps(case, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        authority.update({"finish": finish, "case": case}); run["last_observation_sha256"] = finish["sha256"]
        passed = (
            observed_case.get("exit_code") == expected.get("expected_exit_code")
            and observed_case.get("outcome") == expected.get("expected_outcome")
            and observed_case.get("cleanup") == expected.get("expected_cleanup")
        )
        write_replay_receipt(run, cases)
        completed = all(isinstance(candidate, dict) and candidate.get("finish") is not None for candidate in cases)
        if not passed or completed:
            final = immutable_blob_evidence(
                str(run["receipt_path"]), "agent-replay-receipts", ".receipt", "agent-replay-receipt"
            )
            run.update({
                "status": "completed" if passed else "failed", "completed_at": finished_at,
                "final_receipt_sha256": final["sha256"], "final_receipt_evidence": final,
                "failure_reason": None if passed else "test-result-mismatch",
            })
        state["updated_at"] = finished_at; save(state)
        return passed, completed


def command_replay_execute(args: argparse.Namespace) -> int:
    while True:
        claim = replay_execute_claim(args.integrator_id, args.run_id)
        if claim is None:
            print(f"REPLAY COMPLETED: {args.run_id}")
            return 0
        runner = ROOT / str(claim["runner"]["path"])
        invocation = [
            sys.executable, str(runner), "--receipt", str(claim["receipt_path"]),
            "--run-id", args.run_id, "--case", str(claim["case_id"]),
            "--candidate-sha256", str(claim["candidate_sha256"]),
            "--timeout", str(claim["timeout_seconds"]), "--", *claim["command"],
        ]
        try:
            result = subprocess.run(
                invocation, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=int(claim["timeout_seconds"]) + 15,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            with LOCK.open("r+") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                state = load(STATE); run = replay_run(state, args.integrator_id, args.run_id)
                if run.get("status") == "prepared":
                    aborted_at = iso(now())
                    run.update({"status": "aborted", "completed_at": aborted_at,
                                "failure_reason": "runner-launch-or-timeout"})
                    state["updated_at"] = aborted_at; save(state)
            print(f"REPLAY EXECUTION ABORTED: {args.run_id}/{claim['case_id']}: {error}")
            return 1
        try:
            passed, completed = replay_execute_commit(args.integrator_id, args.run_id, claim)
        except SystemExit as error:
            with LOCK.open("r+") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                state = load(STATE); run = replay_run(state, args.integrator_id, args.run_id)
                if run.get("status") == "prepared":
                    aborted_at = iso(now())
                    run.update({"status": "aborted", "completed_at": aborted_at,
                                "failure_reason": "runner-result-unreadable"})
                    state["updated_at"] = aborted_at; save(state)
            print(result.stdout, end="")
            raise SystemExit(f"managed replay result rejected: {error}")
        print(result.stdout, end="")
        if not passed or result.returncode != 0:
            print(f"REPLAY FAILED: {args.run_id}/{claim['case_id']}")
            return 1
        if completed:
            print(f"REPLAY COMPLETED: {args.run_id}")
            return 0


def command_capacity_failure(args: argparse.Namespace) -> int:
    """Record pre-registration spawn capacity failures and bound retries."""
    state = load(STATE); configured = str(policy().get("default_model", ""))
    if args.model != configured:
        raise SystemExit(f"capacity retry cannot change model; required: {configured}")
    if not args.root_task_id or not args.attempt_id:
        raise SystemExit("capacity failure requires stable root-task-id and unique attempt-id")
    attempts = state.setdefault("capacity_failures", [])
    if not isinstance(attempts, list):
        raise SystemExit("capacity failure registry is invalid")
    if any(isinstance(item, dict) and item.get("attempt_id") == args.attempt_id for item in attempts):
        raise SystemExit("capacity attempt ID already exists")
    prior = [item for item in attempts if isinstance(item, dict) and item.get("root_task_id") == args.root_task_id]
    maximum_failures = int(state["capacity_retry_limit"]) + 1
    if len(prior) >= maximum_failures:
        raise SystemExit("same-model capacity retry is exhausted; stop dispatching")
    record = immutable_capacity_evidence(args.evidence)
    attempts.append({
        "attempt_id": args.attempt_id, "root_task_id": args.root_task_id, "model": args.model,
        "failed_at": iso(now()), "error_evidence": record,
    })
    state["updated_at"] = iso(now()); save(state)
    count = len(prior) + 1
    if count <= int(state["capacity_retry_limit"]):
        print(f"SAME-MODEL CAPACITY RETRY ALLOWED: {count}/{state['capacity_retry_limit']}")
        return 0
    print("CAPACITY RETRY EXHAUSTED: stop without model fallback")
    return 3


def command_heartbeat(args: argparse.Namespace) -> int:
    require_sha(args.progress_hash); state = load(STATE); item = member(state, args.id)
    if item["status"] != ACTIVE:
        raise SystemExit("heartbeat requires active agent")
    if not args.evidence:
        raise SystemExit("heartbeat requires verified evidence; message-only progress comes from check snapshots")
    observed = now()
    try:
        progress_gap = (observed - parse(item["last_progress_at"])).total_seconds()
        overdue = observed > parse(item["deadline_at"])
    except (KeyError, TypeError, ValueError):
        raise SystemExit("heartbeat cannot replay the active progress window")
    permanent_violation = item.get("stall_violation_at") is not None
    if progress_gap > int(state["stall_timeout_seconds"]) or overdue or permanent_violation:
        if progress_gap > int(state["stall_timeout_seconds"]):
            item["stall_violation_at"] = item.get("stall_violation_at") or iso(observed)
        item["interrupt_requested_at"] = item.get("interrupt_requested_at") or iso(observed)
        if overdue:
            item["interrupt_reason"] = "deadline"
        else:
            item["interrupt_reason"] = item.get("interrupt_reason") or "stall-timeout"
        state["updated_at"] = iso(observed); save(state)
        raise SystemExit("late evidence heartbeat cannot recover a violated supervision window")
    records = [evidence(raw) for raw in args.evidence]
    aggregate = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if args.progress_hash != aggregate or args.progress_hash == item["progress_hash"]:
        raise SystemExit("progress hash must equal new evidence receipt aggregate")
    item["progress_hash"] = args.progress_hash
    known = {(entry["path"], entry["sha256"]) for entry in item["evidence"]}
    item["evidence"].extend(entry for entry in records if (entry["path"], entry["sha256"]) not in known)
    item.update({"last_progress_at": iso(observed), "last_check_at": iso(observed), "progress_observed": True, "unchanged_checks": 0,
                 "interrupt_requested_at": None, "interrupt_reason": None})
    state["updated_at"] = iso(observed); save(state); print(f"EVIDENCE HEARTBEAT: {args.id}"); return 0


def note_platform_presence(state: Dict[str, object], platform: Dict[str, Dict[str, object]],
                           snapshot_record: Dict[str, object]) -> List[str]:
    """Update per-member missing-observation counters from one fresh snapshot.

    Presence with any platform status resets the counter; full absence counts
    one consecutive missing observation per distinct snapshot.
    """
    snapshot_sha = str(snapshot_record.get("sha256"))
    lost_candidates = []
    for item in active(state):
        agent_id = str(item["id"])
        if agent_id in platform:
            item["missing_observations"] = 0
            item["missing_snapshot_sha256"] = None
            continue
        if item.get("missing_snapshot_sha256") != snapshot_sha:
            item["missing_observations"] = integer(item.get("missing_observations"), 0) + 1
            item["missing_snapshot_sha256"] = snapshot_sha
        if integer(item.get("missing_observations"), 0) >= LOST_OBSERVATION_THRESHOLD:
            lost_candidates.append(agent_id)
    return sorted(lost_candidates)


def command_check(args: argparse.Namespace) -> int:
    if not args.platform_snapshot:
        raise SystemExit("check requires a fresh platform snapshot")
    state = load(STATE); snapshot_value, snapshot_record, platform = platform_snapshot(args.platform_snapshot)
    registry = {str(item["id"]) for item in active(state)}; observed = active_platform_ids(platform)
    lost_candidates = note_platform_presence(state, platform, snapshot_record)
    if observed != registry:
        state["last_platform_snapshot"] = snapshot_record
        state["updated_at"] = iso(now()); save(state)
        print(f"PLATFORM MISMATCH: registry={sorted(registry)} platform={sorted(observed)}")
        for agent_id in lost_candidates:
            print(
                f"LOST EXIT AVAILABLE: {agent_id} "
                f"(finish --id {agent_id} --status lost --lost --conclusion <bounded-loss-summary> "
                "--platform-snapshot <fresh-agent-platform-snapshot-v3.json>)"
            )
        return 4
    observed_at = parse(snapshot_value["observed_at"]); current = now(); action = 0
    interval = int(state["status_interval_seconds"])
    maximum_gap = interval + int(state["monitor_grace_seconds"])
    for item in active(state):
        observed_item = platform[item["id"]]; cursor = int(observed_item["message_cursor"])
        prior_progress_at = parse(item["last_progress_at"])
        progress_gap = (observed_at - prior_progress_at).total_seconds()
        if not platform_contract_matches(observed_item, item, state):
            raise SystemExit(f"platform registration contract drifted for {item['id']}")
        if cursor < int(item["platform_cursor"]):
            raise SystemExit(f"platform cursor regressed for {item['id']}")
        cursor_advanced = cursor > int(item["platform_cursor"])
        monitors = item.get("monitor_platform_evidence")
        if not isinstance(monitors, list):
            raise SystemExit(f"monitor evidence chain is invalid for {item['id']}")
        previous = parse(item["registration_observed_at"])
        if monitors:
            prior_observed = receipt_observed_at(monitors[-1])
            if prior_observed is None:
                raise SystemExit(f"prior monitor evidence drifted for {item['id']}")
            previous = prior_observed
        if observed_at < previous:
            raise SystemExit(f"platform observation time regressed for {item['id']}")
        duplicate = any(
            isinstance(record, dict) and record.get("sha256") == snapshot_record.get("sha256")
            for record in monitors
        )
        gap = (observed_at - previous).total_seconds()
        if not duplicate:
            monitors.append(snapshot_record)
            if gap > maximum_gap:
                item["monitoring_violation_at"] = item.get("monitoring_violation_at") or iso(observed_at)
        if cursor_advanced:
            message_hash = observed_item.get("message_sha256")
            if not SHA.fullmatch(str(message_hash or "")):
                raise SystemExit(f"new platform cursor lacks a message hash for {item['id']}")
            item.update({"platform_cursor": cursor, "last_platform_message_sha256": message_hash,
                         "last_progress_at": iso(observed_at), "last_check_at": iso(observed_at),
                         "progress_observed": True, "unchanged_checks": 0})
            if item.get("stall_violation_at") is None:
                item.update({"interrupt_requested_at": None, "interrupt_reason": None})
        else:
            last_check = item.get("last_check_at")
            eligible = last_check is None or (observed_at - parse(last_check)).total_seconds() >= interval
            if eligible:
                item["last_check_at"] = iso(observed_at); item["progress_observed"] = False
                item["unchanged_checks"] = int(item["unchanged_checks"]) + 1
        stalled = (
            not cursor_advanced
            and progress_gap > int(state["stall_timeout_seconds"])
        ) or item.get("stall_violation_at") is not None
        if current > parse(item["deadline_at"]) or stalled:
            if stalled:
                item["stall_violation_at"] = item.get("stall_violation_at") or iso(observed_at)
            item["interrupt_requested_at"] = item.get("interrupt_requested_at") or iso(current)
            if current > parse(item["deadline_at"]):
                item["interrupt_reason"] = "deadline"
            else:
                item["interrupt_reason"] = "stall-timeout"
            print(f"INTERRUPT REQUIRED: {item['id']} (orchestrator must call the platform interrupt tool and then finish with terminal proof)"); action = max(action, 3)
        elif int(item["unchanged_checks"]) >= int(state["status_request_after_unchanged_checks"]):
            print(f"REQUEST STATUS: {item['id']}"); action = max(action, 2)
    state["last_platform_snapshot"] = snapshot_record; state["platform_empty_verified"] = not registry
    state["updated_at"] = iso(current); save(state)
    if not action:
        print(f"AGENT TEAM HEALTHY: active={len(registry)}")
    return action


def command_finish(args: argparse.Namespace) -> int:
    if not args.lost and (args.source or args.receipt):
        raise SystemExit("--source/--receipt require finish --lost")
    state = load(STATE); item = member(state, args.id)
    if item.get("status") in TERMINAL:
        requested = sorted(
            [evidence(raw) for raw in (args.evidence or [])],
            key=lambda record: str(record["path"]),
        )
        existing = sorted([
            {
                "path": record.get("source_path"),
                "sha256": record.get("sha256"),
                "bytes": record.get("bytes"),
            }
            for record in item.get("result_evidence", []) if isinstance(record, dict)
        ], key=lambda record: str(record["path"]))
        if (
            item.get("status") == args.status
            and item.get("conclusion") == args.conclusion.strip()
            and requested == existing
        ):
            print(f"AGENT ALREADY FINISHED: {args.id} {args.status}")
            return 0
        raise SystemExit("terminal Agent cannot be rewritten with a different finish contract")
    if args.lost or args.status == "lost":
        if not args.lost or args.status != "lost":
            raise SystemExit("lost status requires finish --lost with --status lost")
        if not args.platform_snapshot:
            raise SystemExit("finish --lost requires a fresh platform snapshot proving absence")
        if item["status"] != ACTIVE:
            raise SystemExit("finish requires active agent")
        snapshot_value, snapshot_record, platform = platform_snapshot(args.platform_snapshot)
        if args.id in platform:
            raise SystemExit("finish --lost requires the Agent to be absent from the fresh platform snapshot")
        terminal_observed = parse(snapshot_value["observed_at"])
        approval = None
        if integer(item.get("missing_observations"), 0) < LOST_OBSERVATION_THRESHOLD:
            if not args.source:
                raise SystemExit(
                    f"finish --lost requires {LOST_OBSERVATION_THRESHOLD} consecutive missing platform observations "
                    "or --source user:<message> to bind a human decision (gate agent-lost)"
                )
            approval = humandecision.record_decision_approval(
                ROOT, load(CONFIG), load(TASK), gate="agent-lost",
                artifact_sha256=lost_decision_binding(state, args.id),
                source=args.source, receipt=args.receipt,
            )
        conclusion = args.conclusion.strip()
        if not conclusion or len(conclusion) > 4000:
            raise SystemExit("finish conclusion must be non-empty and bounded")
        records = sorted(
            [immutable_result_evidence(raw) for raw in (args.evidence or [])],
            key=lambda record: str(record["source_path"]),
        )
        if len({str(record["source_path"]) for record in records}) != len(records):
            raise SystemExit("finish evidence paths must be unique")
        allowed = set(item.get("allowed_evidence_paths", []))
        if any(record.get("source_path") not in allowed for record in records):
            raise SystemExit("finish evidence is outside the per-dispatch envelope allowlist")
        prior_observed = parse(item["registration_observed_at"])
        monitors = item.get("monitor_platform_evidence", [])
        if isinstance(monitors, list) and monitors:
            latest_monitor = receipt_observed_at(monitors[-1])
            if latest_monitor is not None:
                prior_observed = latest_monitor
        maximum_gap = int(state["status_interval_seconds"]) + int(state["monitor_grace_seconds"])
        if (terminal_observed - prior_observed).total_seconds() > maximum_gap:
            item["monitoring_violation_at"] = item.get("monitoring_violation_at") or iso(terminal_observed)
        finished_at = iso(terminal_observed)
        if item.get("role_type") == "integrator":
            abort_pending_replays_for_terminal(state, str(item["id"]), finished_at)
        release_token_reservation(state, item, finished_at)
        publish_terminal_marker(
            state, item, "lost", snapshot_record, finished_at, finished_at,
            conclusion, records, None, None,
            int(item["platform_cursor"]), item.get("last_platform_message_sha256"),
        )
        item.update({"status": "lost", "finished_at": finished_at, "conclusion": conclusion,
                     "progress_observed": False,
                     "terminal_platform_evidence": snapshot_record,
                     "terminal_observed_at": finished_at, "result_evidence": records,
                     "review_verdict": None, "review_attestation": None,
                     "lost_decision": approval})
        state["last_platform_snapshot"] = snapshot_record; state["platform_empty_verified"] = False
        state["updated_at"] = iso(now()); save(state); print(f"AGENT FINISHED: {args.id} lost"); return 0
    if not args.platform_snapshot:
        raise SystemExit("finish requires platform terminal evidence")
    if item["status"] != ACTIVE:
        raise SystemExit("finish requires active agent")
    snapshot_value, snapshot_record, platform = platform_snapshot(args.platform_snapshot)
    terminal_observed = parse(snapshot_value["observed_at"])
    observed = platform.get(args.id)
    if not observed or str(observed.get("status", "")).lower() not in PLATFORM_TERMINAL[args.status]:
        raise SystemExit("finish status is not proven by the platform snapshot")
    if not platform_contract_matches(observed, item, state):
        raise SystemExit("finish platform registration contract differs from registration")
    if int(observed.get("message_cursor", 0)) < int(item["platform_cursor"]):
        raise SystemExit("terminal snapshot cursor regressed")
    prior_observed = parse(item["registration_observed_at"])
    monitors = item.get("monitor_platform_evidence", [])
    if isinstance(monitors, list) and monitors:
        latest_monitor = receipt_observed_at(monitors[-1])
        if latest_monitor is not None:
            prior_observed = latest_monitor
    maximum_gap = int(state["status_interval_seconds"]) + int(state["monitor_grace_seconds"])
    if (terminal_observed - prior_observed).total_seconds() > maximum_gap:
        item["monitoring_violation_at"] = item.get("monitoring_violation_at") or iso(terminal_observed)
    contract_errors = completion_contract_errors(
        item, terminal_observed, int(state["status_interval_seconds"]), int(state["monitor_grace_seconds"]),
        int(state["stall_timeout_seconds"]), snapshot_record,
    )
    if args.status == "completed" and contract_errors:
        raise SystemExit("completion contract failed; close as expired: " + "; ".join(contract_errors))
    if args.status == "expired" and not contract_errors:
        raise SystemExit("expired status requires a deadline, child stall or interrupt violation")
    if args.status == "expired" and any("stall timeout" in error for error in contract_errors):
        item["stall_violation_at"] = item.get("stall_violation_at") or iso(terminal_observed)
    conclusion = args.conclusion.strip()
    if not conclusion or len(conclusion) > 4000:
        raise SystemExit("finish conclusion must be non-empty and bounded")
    records = sorted(
        [immutable_result_evidence(raw) for raw in (args.evidence or [])],
        key=lambda record: str(record["source_path"]),
    )
    if len({str(record["source_path"]) for record in records}) != len(records):
        raise SystemExit("finish evidence paths must be unique")
    allowed = set(item.get("allowed_evidence_paths", []))
    if any(record.get("source_path") not in allowed for record in records):
        raise SystemExit("finish evidence is outside the per-dispatch envelope allowlist")
    is_completed_review = args.status == "completed" and item.get("role_type") in state.get("review_role_types", [])
    is_completed_implementer = args.status == "completed" and item.get("role_type") == "implementer"
    final_cursor = int(observed.get("message_cursor", 0))
    final_message_sha256 = observed.get("message_sha256")
    if final_cursor > 0 and not SHA.fullmatch(str(final_message_sha256 or "")):
        raise SystemExit("terminal result with messages requires the final platform message digest")
    review_contract = review_result_contract(
        item, records, state, terminal_observed, require_current_schema=True,
    ) if is_completed_review else None
    implementation_contract = implementation_result_contract(item, records, state) if is_completed_implementer else None
    review_verdict = review_contract[0] if review_contract is not None else None
    review_attestation = review_contract[1] if review_contract is not None else None
    if is_completed_review:
        if review_verdict is None or review_attestation is None:
            raise SystemExit("completed review lacks a valid report attestation, role lenses or clean replay evidence")
        expected_conclusion = review_conclusion(review_verdict)
        expected_message_sha256 = hashlib.sha256(review_final_message(review_verdict).encode()).hexdigest()
        if conclusion != expected_conclusion:
            raise SystemExit("finish conclusion differs from the reviewer-authored report verdict")
        if final_message_sha256 != expected_message_sha256:
            raise SystemExit("terminal platform message does not commit the reviewer-authored verdict and report")
    if is_completed_implementer and implementation_contract is None:
        raise SystemExit("completed implementer lacks the exact current-candidate implementation attestation")
    finished_at = iso(terminal_observed)
    if item.get("role_type") == "integrator" and args.status != "completed":
        abort_pending_replays_for_terminal(state, str(item["id"]), finished_at)
    settle_token_reservation(state, item, args.status, iso(terminal_observed))
    publish_terminal_marker(
        state, item, args.status, snapshot_record, iso(terminal_observed), finished_at,
        conclusion, records, review_verdict, review_attestation, final_cursor, final_message_sha256,
    )
    item.update({"status": args.status, "finished_at": finished_at, "conclusion": conclusion,
                 "platform_cursor": final_cursor, "last_platform_message_sha256": final_message_sha256,
                 "progress_observed": False,
                 "terminal_platform_evidence": snapshot_record,
                 "terminal_observed_at": iso(terminal_observed), "result_evidence": records,
                 "review_verdict": review_verdict, "review_attestation": review_attestation})
    state["last_platform_snapshot"] = snapshot_record; state["platform_empty_verified"] = False
    state["updated_at"] = iso(now()); save(state); print(f"AGENT FINISHED: {args.id} {args.status}"); return 0


def command_redispatch(args: argparse.Namespace) -> int:
    state = load(STATE); old = member(state, args.from_id)
    controlled_review_retry = (
        old.get("role_type") in FORMAL_REVIEW_ROLE_TYPES
        and committed_review_fail(state, old)
    )
    if (
        old["status"] not in {"interrupted", "errored", "expired"}
        and not controlled_review_retry
    ) or not valid_receipt(old.get("terminal_platform_evidence")):
        raise SystemExit(
            "redispatch requires an orchestrator-observed interrupted, errored or expired source, "
            "or one immutable formal-review FAIL"
        )
    if old.get("redispatched_to"):
        raise SystemExit("source agent was already redispatched")
    count = int(old["redispatch_count"]) + 1
    if count > int(state["max_redispatch"]):
        raise SystemExit("root task already used its single redispatch")
    # Mutate only the in-memory transaction.  register() performs the single
    # atomic save after every new-agent check passes; a failed registration
    # therefore does not consume the one allowed redispatch.
    old["redispatched_to"] = args.to_id
    args.id, args.role_type, args.role, args.task = args.to_id, old["role_type"], old["role"], old["task"]
    args.model = old["model"]
    # A redispatch is a new host child even when its source predates the
    # no-history policy.  Keep the source's historical fork value immutable,
    # but bind the replacement preparation/envelope/platform receipt to zero.
    args.fork_turns = 0
    args.task_payload = old["task_payload_evidence"]["path"]
    args.progress_hash, args.platform_cursor = hashlib.sha256(b"redispatch").hexdigest(), 0
    return register(state, args, count, old["root_task_id"])


def formal_review_chain_errors(state: Dict[str, object]) -> List[str]:
    """Replay formal-chain subject, predecessor and non-overlap semantics."""
    errors: List[str] = []
    members = [
        item for item in state.get("members", [])
        if isinstance(item, dict) and item.get("role_type") in FORMAL_REVIEW_ROLE_TYPES
    ]
    preparations = {
        str(item.get("id")): item for item in state.get("prepared_dispatches", [])
        if isinstance(item, dict)
    }
    chains: Dict[str, List[Dict[str, object]]] = {}
    for item in members:
        chain_id = item.get("review_chain_id")
        if not isinstance(chain_id, str) or REVIEW_CHAIN_ID.fullmatch(chain_id) is None:
            errors.append(f"formal review has invalid chain ID: {item.get('id')}")
            continue
        if item.get("review_subject_sha256") != item.get("task_payload_sha256"):
            errors.append(f"formal review subject differs from its sealed payload: {item.get('id')}")
        chains.setdefault(chain_id, []).append(item)
    root_subject_chains: Dict[Tuple[object, object], Set[str]] = {}
    for item in [
        *members,
        *[
            entry for entry in state.get("prepared_dispatches", [])
            if isinstance(entry, dict)
            and entry.get("role_type") in FORMAL_REVIEW_ROLE_TYPES
            and entry.get("cancelled_at") is None
        ],
    ]:
        key = (item.get("root_task_id"), item.get("review_subject_sha256"))
        chain_id = item.get("review_chain_id")
        if isinstance(chain_id, str):
            root_subject_chains.setdefault(key, set()).add(chain_id)
    for key, chain_ids in root_subject_chains.items():
        if len(chain_ids) > 1:
            errors.append(
                "formal review root/subject uses multiple chains: "
                f"{key[0]}:{key[1]}"
            )
    for chain_id, chain in chains.items():
        if len({item.get("review_subject_sha256") for item in chain}) != 1:
            errors.append(f"formal review chain mixes subjects: {chain_id}")
        if len({item.get("root_task_id") for item in chain}) != 1:
            errors.append(f"formal review chain mixes root tasks: {chain_id}")
        passed_by_role: Dict[str, List[Dict[str, object]]] = {
            role: [item for item in chain if item.get("role_type") == role and committed_zero_pass(state, item)]
            for role in FORMAL_REVIEW_ROLE_TYPES
        }
        for role, passed in passed_by_role.items():
            if len(passed) > 1:
                errors.append(f"formal review chain has duplicate completed PASS {role}: {chain_id}")
            attempts = [item for item in chain if item.get("role_type") == role]
            if (
                len([item for item in attempts if integer(item.get("redispatch_count")) == 0]) > 1
                or len([item for item in attempts if integer(item.get("redispatch_count")) == 1]) > 1
                or len(attempts) > 2
            ):
                errors.append(f"formal review chain has duplicate/non-bounded {role} dispatches: {chain_id}")
            completed_attempts = [item for item in attempts if item.get("status") == "completed"]
            if len(completed_attempts) == 2 and (
                not committed_review_fail(state, min(completed_attempts, key=lambda item: integer(item.get("redispatch_count"))))
                or not committed_zero_pass(state, max(completed_attempts, key=lambda item: integer(item.get("redispatch_count"))))
            ):
                errors.append(f"formal review controlled retry is not FAIL then PASS: {chain_id}:{role}")
        adversarial = passed_by_role["adversarial"]
        cross = passed_by_role["cross"]
        for successor in [item for item in chain if item.get("role_type") in {"cross", "integrator"}]:
            predecessor_role = "adversarial" if successor.get("role_type") == "cross" else "cross"
            candidates = passed_by_role[predecessor_role]
            if len(candidates) != 1:
                errors.append(f"formal review successor lacks completed PASS {predecessor_role}: {successor.get('id')}")
                continue
            predecessor = candidates[0]
            predecessor_sha = (predecessor.get("review_verdict") or {}).get("report_sha256")
            if successor.get("predecessor_result_sha256") != predecessor_sha:
                errors.append(f"formal review predecessor digest differs: {successor.get('id')}")
            preparation = preparations.get(str(successor.get("id")), {})
            try:
                predecessor_terminal = parse(predecessor.get("terminal_observed_at"))
                successor_times = [
                    parse(successor.get("started_at")),
                    parse(successor.get("registration_observed_at")),
                    parse(preparation.get("prepared_at")),
                ]
                if any(moment < predecessor_terminal for moment in successor_times):
                    errors.append(f"formal review roles overlap or are temporally reversed: {successor.get('id')}")
            except (TypeError, ValueError):
                errors.append(f"formal review chronology is invalid: {successor.get('id')}")
            if successor.get("role_type") == "integrator":
                if len(adversarial) != 1 or not committed_zero_pass(state, adversarial[0]):
                    errors.append(f"integrator lacks completed PASS adversarial ancestor: {successor.get('id')}")
                elif predecessor.get("predecessor_result_sha256") != (adversarial[0].get("review_verdict") or {}).get("report_sha256"):
                    errors.append(f"integrator chain skips adversarial report: {successor.get('id')}")
        if cross and (len(adversarial) != 1 or not committed_zero_pass(state, adversarial[0])):
            errors.append(f"cross review exists without one accepted adversarial predecessor: {chain_id}")
        if any(item.get("role_type") == "integrator" for item in chain) and len(cross) != 1:
            errors.append(f"integrator exists without one accepted cross predecessor: {chain_id}")
    return sorted(set(errors))


def replay_run_registry_errors(state: Dict[str, object]) -> List[str]:
    """Replay every prepared/completed clean-run authority, including partial active runs."""
    errors: List[str] = []
    runs = state.get("replay_runs")
    if not isinstance(runs, list):
        return ["replay run registry is invalid"]
    members = {str(item.get("id")): item for item in state.get("members", []) if isinstance(item, dict)}
    authority_ids: List[object] = []; run_ids: List[object] = []; receipt_paths: List[object] = []
    required = {
        "authority_id", "integrator_id", "review_chain_id", "review_subject_sha256",
        "candidate_sha256", "run_id",
        "receipt_path", "source_plan", "plan_evidence", "runner_evidence", "prepared_at", "status",
        "cases", "last_observation_sha256", "completed_at", "final_receipt_sha256",
        "final_receipt_evidence", "node6_task_receipt", "node6_input_evidence", "failure_reason",
    }
    for run in runs:
        if not isinstance(run, dict) or set(run) != required:
            errors.append("replay run fields are invalid"); continue
        authority_ids.append(run.get("authority_id")); run_ids.append(run.get("run_id")); receipt_paths.append(run.get("receipt_path"))
        item = members.get(str(run.get("integrator_id"))); plan = replay_plan(run.get("plan_evidence"))
        node6_contract = sealed_node6_replay_contract(run, item) if item is not None else None
        if (
            SHA.fullmatch(str(run.get("authority_id", ""))) is None
            or RUN_ID.fullmatch(str(run.get("run_id", ""))) is None
            or item is None or item.get("role_type") != "integrator"
            or run.get("review_chain_id") != item.get("review_chain_id")
            or run.get("review_subject_sha256") != item.get("review_subject_sha256")
            or run.get("candidate_sha256") != current_candidate_sha256()
            or not valid_receipt(run.get("source_plan")) or plan is None
            or (run.get("status") != "aborted" and not replay_plan_output_paths_match_runner(plan))
            or plan.get("run_id") != run.get("run_id") or plan.get("receipt_path") != run.get("receipt_path")
            or not valid_receipt(run.get("runner_evidence"))
            or run.get("runner_evidence") != managed_runner_receipt()
            or node6_contract is None or not replay_plan_matches_node6(plan, node6_contract[2])
            or run.get("node6_task_receipt") != node6_contract[0]
            or run.get("node6_input_evidence") != node6_contract[1]
        ):
            errors.append(f"replay run provenance drifted: {run.get('run_id')}")
            continue
        try:
            prepared = parse(run.get("prepared_at")); registered = parse(item.get("registration_observed_at"))
            if prepared < registered - dt.timedelta(seconds=TIMESTAMP_SKEW_SECONDS):
                errors.append(f"replay run predates integrator registration: {run.get('run_id')}")
        except (TypeError, ValueError):
            errors.append(f"replay run timestamps are invalid: {run.get('run_id')}")
            continue
        cases = run.get("cases")
        if not isinstance(cases, list) or [case.get("id") for case in cases if isinstance(case, dict)] != [case["id"] for case in plan["cases"]]:
            errors.append(f"replay cases differ from plan: {run.get('run_id')}"); continue
        seen_unstarted = False; previous_sha: Optional[str] = None
        result_mismatch = False; unfinished_claim = False; finished_cases: List[Dict[str, object]] = []
        for index, (authority, expected) in enumerate(zip(cases, plan["cases"])):
            if not isinstance(authority, dict) or set(authority) != {"id", "claim_id", "start", "finish", "case"}:
                errors.append(f"replay case authority is invalid: {run.get('run_id')}/{index}"); continue
            start, finish, case, claim_id = authority.get("start"), authority.get("finish"), authority.get("case"), authority.get("claim_id")
            if start is None:
                seen_unstarted = True
                if claim_id is not None or finish is not None or case is not None:
                    errors.append(f"replay case finishes without start: {run.get('run_id')}/{index}")
                continue
            if SHA.fullmatch(str(claim_id or "")) is None:
                errors.append(f"replay executing claim is invalid: {run.get('run_id')}/{index}")
            if seen_unstarted:
                errors.append(f"replay cases did not execute in plan order: {run.get('run_id')}/{index}")
            if not content_addressed_receipt(start, "agent-replay-observations", ".json"):
                errors.append(f"replay start observation drifted: {run.get('run_id')}/{index}"); continue
            start_value = load(ROOT / str(start["path"]))
            if (
                start_value.get("schema") != REPLAY_OBSERVATION_SCHEMA or start_value.get("event") != "start"
                or start_value.get("authority_id") != run.get("authority_id")
                or start_value.get("integrator_id") != run.get("integrator_id")
                or start_value.get("review_chain_id") != run.get("review_chain_id")
                or start_value.get("review_subject_sha256") != run.get("review_subject_sha256")
                or start_value.get("run_id") != run.get("run_id") or start_value.get("claim_id") != claim_id
                or start_value.get("case_id") != expected.get("id") or start_value.get("sequence") != index
                or start_value.get("runner_sha256") != (run.get("runner_evidence") or {}).get("sha256")
                or start_value.get("plan_sha256") != (run.get("plan_evidence") or {}).get("sha256")
                or start_value.get("previous_observation_sha256") != previous_sha
                or start_value.get("command") != expected.get("command")
                or start_value.get("timeout_seconds") != expected.get("timeout_seconds")
                or start_value.get("output_path") != expected.get("expected_output_path")
            ):
                errors.append(f"replay start authority differs from plan: {run.get('run_id')}/{index}")
            previous_sha = start.get("sha256")
            if finish is None:
                unfinished_claim = True
                if case is not None: errors.append(f"replay partial case has forged result: {run.get('run_id')}/{index}")
                continue
            if not content_addressed_receipt(finish, "agent-replay-observations", ".json") or not isinstance(case, dict):
                errors.append(f"replay finish authority drifted: {run.get('run_id')}/{index}"); continue
            finish_value = load(ROOT / str(finish["path"]))
            required_case = {
                "id", "run_id", "candidate_sha256", "command", "started_at", "finished_at",
                "exit_code", "outcome", "cleanup", "output", "case_sha256",
            }
            if (
                finish_value.get("schema") != REPLAY_OBSERVATION_SCHEMA or finish_value.get("event") != "finish"
                or finish_value.get("authority_id") != run.get("authority_id")
                or finish_value.get("integrator_id") != run.get("integrator_id")
                or finish_value.get("review_chain_id") != run.get("review_chain_id")
                or finish_value.get("review_subject_sha256") != run.get("review_subject_sha256")
                or finish_value.get("run_id") != run.get("run_id") or finish_value.get("claim_id") != claim_id
                or finish_value.get("case_id") != expected.get("id") or finish_value.get("sequence") != index
                or finish_value.get("runner_sha256") != (run.get("runner_evidence") or {}).get("sha256")
                or finish_value.get("plan_sha256") != (run.get("plan_evidence") or {}).get("sha256")
                or finish_value.get("previous_observation_sha256") != previous_sha
                or finish_value.get("output") != case.get("output")
                or finish_value.get("exit_code") != case.get("exit_code")
                or finish_value.get("outcome") != case.get("outcome")
                or finish_value.get("cleanup") != case.get("cleanup")
                or set(case) != required_case
                or case.get("id") != expected.get("id") or case.get("run_id") != run.get("run_id")
                or case.get("candidate_sha256") != run.get("candidate_sha256")
                or case.get("command") != expected.get("command")
                or not content_addressed_receipt(case.get("output"), "agent-replay-outputs", ".log")
            ):
                errors.append(f"replay output chain drifted: {run.get('run_id')}/{index}")
            if (
                case.get("exit_code") != expected.get("expected_exit_code")
                or case.get("outcome") != expected.get("expected_outcome")
                or case.get("cleanup") != expected.get("expected_cleanup")
            ):
                result_mismatch = True
            unsigned = {key: value for key, value in case.items() if key != "case_sha256"}
            if case.get("case_sha256") != hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest():
                errors.append(f"replay case hash drifted: {run.get('run_id')}/{index}")
            finished_cases.append(case)
            previous_sha = finish.get("sha256")
        if run.get("last_observation_sha256") != previous_sha:
            errors.append(f"replay observation tail drifted: {run.get('run_id')}")
        if run.get("status") == "completed":
            final = run.get("final_receipt_evidence")
            try:
                receipt_value = load(ROOT / str(final["path"])) if content_addressed_receipt(final, "agent-replay-receipts", ".receipt") else {}
                parse(run.get("completed_at"))
            except (OSError, ValueError, json.JSONDecodeError, TypeError, KeyError, SystemExit):
                receipt_value = {}
            if (
                run.get("failure_reason") is not None or result_mismatch or unfinished_claim
                or (final or {}).get("sha256") != run.get("final_receipt_sha256")
                or set(receipt_value) != {"schema", "run_id", "candidate_sha256", "runner", "cases"}
                or receipt_value.get("schema") != "agent-test-receipt/v3"
                or receipt_value.get("run_id") != run.get("run_id")
                or receipt_value.get("candidate_sha256") != run.get("candidate_sha256")
                or receipt_value.get("runner") != run.get("runner_evidence")
                or receipt_value.get("cases") != finished_cases
            ):
                errors.append(f"completed replay authority is invalid: {run.get('run_id')}")
        elif run.get("status") == "prepared":
            if item.get("status") != ACTIVE or run.get("failure_reason") is not None or run.get("completed_at") is not None or run.get("final_receipt_evidence") is not None or run.get("final_receipt_sha256") is not None:
                errors.append(f"prepared replay is not owned by an active integrator: {run.get('run_id')}")
        elif run.get("status") == "failed":
            final = run.get("final_receipt_evidence")
            try:
                receipt_value = load(ROOT / str(final["path"])) if content_addressed_receipt(final, "agent-replay-receipts", ".receipt") else {}
                parse(run.get("completed_at"))
            except (OSError, ValueError, json.JSONDecodeError, TypeError, KeyError, SystemExit):
                receipt_value = {}
            if (
                run.get("failure_reason") != "test-result-mismatch" or not result_mismatch or unfinished_claim
                or (final or {}).get("sha256") != run.get("final_receipt_sha256")
                or set(receipt_value) != {"schema", "run_id", "candidate_sha256", "runner", "cases"}
                or receipt_value.get("schema") != "agent-test-receipt/v3"
                or receipt_value.get("run_id") != run.get("run_id")
                or receipt_value.get("candidate_sha256") != run.get("candidate_sha256")
                or receipt_value.get("runner") != run.get("runner_evidence")
                or receipt_value.get("cases") != finished_cases
            ):
                errors.append(f"failed replay authority is invalid: {run.get('run_id')}")
        elif run.get("status") == "aborted":
            try:
                parse(run.get("completed_at"))
            except (TypeError, ValueError):
                errors.append(f"aborted replay timestamp is invalid: {run.get('run_id')}")
            if (
                run.get("failure_reason") not in {
                    "supervision-window-closed", "orphaned-executing-claim",
                    "runner-launch-or-timeout", "runner-result-unreadable",
                    "integrator-terminal-before-replay", "terminal-owner-reconciled",
                }
                or run.get("final_receipt_evidence") is not None or run.get("final_receipt_sha256") is not None
                or result_mismatch
            ):
                errors.append(f"aborted replay authority is invalid: {run.get('run_id')}")
        else:
            errors.append(f"replay run status is invalid: {run.get('run_id')}")
    if len(authority_ids) != len(set(authority_ids)) or len(run_ids) != len(set(run_ids)) or len(receipt_paths) != len(set(receipt_paths)):
        errors.append("replay authority, run ID and receipt path must be globally unique")
    return sorted(set(errors))


def command_validate(args: argparse.Namespace) -> int:
    state = load(STATE); config = policy(); errors: List[str] = []; warnings: List[str] = []
    try:
        dispatch_context_policy()
    except SystemExit as error:
        errors.append(str(error))
    if state.get("schema") != SCHEMA: errors.append("invalid schema")
    if state.get("task_payload_schema") != TASK_PAYLOAD_SCHEMA: errors.append("invalid reusable task payload schema policy")
    errors.extend(ledger_chain_errors(state))
    try:
        if state.get("task_payload_limits") != task_payload_limits():
            errors.append("ledger task payload limits differ from config")
    except SystemExit as error:
        errors.append(str(error))
    try:
        token_budget_snapshot(state)
    except SystemExit as error:
        errors.append(str(error))
    accounting = state.get("token_accounting")
    if not isinstance(accounting, dict) or set(accounting) != {
        "schema", "token_budget", "settled_tokens",
    }:
        errors.append("child token accounting fields are invalid")
    if (
        state.get("default_model") != config.get("default_model")
        or state.get("allow_model_fallback") is not False
        or config.get("allow_model_fallback") is not False
        or state.get("context_strategy") != config.get("context_strategy")
        or state.get("max_fork_turns") != config.get("max_fork_turns")
        or state.get("capacity_retry_limit") != config.get("capacity_retry_limit")
    ):
        errors.append("ledger model/context/capacity policy differs from config")
    if state.get("migration_source") is not None and not valid_receipt(state.get("migration_source")):
        errors.append("ledger migration archive evidence drifted")
    try:
        if state.get("platform_observer") != platform_observer_policy():
            errors.append("ledger platform observer assurance differs from config")
    except SystemExit as error:
        errors.append(str(error))
    pairs = (("platform_limit", "platform_limit"), ("reserved_root_slots", "reserve_root_slots"),
             ("status_interval_seconds", "status_interval_seconds"),
             ("monitor_grace_seconds", "monitor_grace_seconds"),
             ("stall_timeout_seconds", "stall_timeout_seconds"),
             ("allowed_role_types", "allowed_role_types"),
             ("review_role_types", "review_role_types"),
             ("status_request_after_unchanged_checks", "status_request_after_unchanged_checks"),
             ("max_redispatch", "max_redispatch"))
    if any(state.get(key) != config.get(config_key) for key, config_key in pairs): errors.append("ledger policy differs from config")
    if config.get("allowed_role_types") != list(CANONICAL_ROLE_TYPES) or config.get("review_role_types") != list(CANONICAL_REVIEW_ROLE_TYPES):
        errors.append("config role policy differs from the canonical role types")
    try:
        if int(state.get("status_interval_seconds", 0)) <= 0 or int(state.get("monitor_grace_seconds", -1)) < 0 or int(state.get("status_interval_seconds", 0)) + int(state.get("monitor_grace_seconds", -1)) > 60:
            errors.append("supervisor polling target plus grace exceeds 60 seconds")
        if (
            int(state.get("stall_timeout_seconds", 0)) < 120
            or int(state.get("stall_timeout_seconds", 0)) > 1800
            or int(state.get("stall_timeout_seconds", 0))
            <= int(state.get("status_interval_seconds", 0)) + int(state.get("monitor_grace_seconds", 0))
        ):
            errors.append("stall timeout policy is invalid")
        if not 1 <= int(state.get("status_request_after_unchanged_checks", 0)) <= 10:
            errors.append("status request threshold is invalid")
    except (TypeError, ValueError):
        errors.append("supervisor polling policy is invalid")
    preparation_ids: List[object] = []
    preparations = state.get("prepared_dispatches", [])
    if not isinstance(preparations, list):
        errors.append("prepared dispatch registry is invalid"); preparations = []
    preparation_required = {
        "id", "root_task_id", "role_type", "model", "fork_turns", "started_at", "deadline_at",
        "redispatch_count", "task_payload_sha256", "task_payload_evidence", "handoff_envelope_sha256",
        "handoff_envelope_evidence", "allowed_evidence_paths", "forbidden_actions", "prepared_at",
        "consumed_at", "cancelled_at", "review_chain_id", "review_subject_sha256",
        "predecessor_result_sha256", "result_report_path", "token_reservation",
    }
    for preparation in preparations:
        if not isinstance(preparation, dict) or set(preparation) != preparation_required:
            errors.append("prepared dispatch fields are invalid"); continue
        preparation_ids.append(preparation.get("id"))
        payload_record = preparation.get("task_payload_evidence")
        payload = reusable_task_payload(payload_record)
        envelope = handoff_envelope(preparation.get("handoff_envelope_evidence"))
        reservation = preparation.get("token_reservation")
        expected = {
            "ledger_epoch": state.get("epoch"), "agent_id": preparation.get("id"),
            "root_task_id": preparation.get("root_task_id"), "role_type": preparation.get("role_type"),
            "model": preparation.get("model"), "fork_turns": preparation.get("fork_turns"),
            "started_at": preparation.get("started_at"), "deadline_at": preparation.get("deadline_at"),
            "redispatch_count": preparation.get("redispatch_count"),
            "review_chain_id": preparation.get("review_chain_id"),
            "review_subject_sha256": preparation.get("review_subject_sha256"),
            "predecessor_result_sha256": preparation.get("predecessor_result_sha256"),
            "result_report_path": preparation.get("result_report_path"),
        }
        if (
            preparation.get("role_type") not in state.get("allowed_role_types", [])
            or preparation.get("model") != config.get("default_model")
            or integer(preparation.get("fork_turns"), -1) < 0
            or integer(preparation.get("fork_turns"), -1) > integer(config.get("max_fork_turns"), -1)
            or payload is None
            or preparation.get("task_payload_sha256") != (payload_record or {}).get("sha256")
            or envelope is None
            or preparation.get("handoff_envelope_sha256") != (preparation.get("handoff_envelope_evidence") or {}).get("sha256")
            or not envelope_contract_matches(envelope, expected, payload_record or {})
            or preparation.get("allowed_evidence_paths") != envelope.get("allowed_evidence_paths")
            or preparation.get("forbidden_actions") != envelope.get("forbidden_actions")
        ):
            errors.append(f"prepared dispatch provenance drifted: {preparation.get('id')}")
        elif preparation.get("role_type") in FORMAL_REVIEW_ROLE_TYPES:
            try:
                require_formal_review_predecessor(state, envelope)
            except SystemExit as error:
                # A consumed preparation is replayed against terminal history below;
                # the current completed member of the same role is excluded there.
                if preparation.get("consumed_at") is None:
                    errors.append(f"prepared formal review chain is invalid: {preparation.get('id')}: {error}")
        try:
            parse(preparation.get("prepared_at"))
            duration = (parse(preparation.get("deadline_at")) - parse(preparation.get("started_at"))).total_seconds()
            if duration < 60 or duration > 7200 or duration % 60 != 0: raise ValueError
        except (TypeError, ValueError):
            errors.append(f"prepared dispatch timestamps are invalid: {preparation.get('id')}")
        consumed, cancelled = preparation.get("consumed_at"), preparation.get("cancelled_at")
        if consumed is not None and cancelled is not None:
            errors.append(f"prepared dispatch is both consumed and cancelled: {preparation.get('id')}")
        for timestamp, label in ((consumed, "consumed"), (cancelled, "cancelled")):
            if timestamp is not None:
                try: parse(timestamp)
                except (TypeError, ValueError): errors.append(f"prepared dispatch {label} time is invalid: {preparation.get('id')}")
        if consumed is None and cancelled is None:
            try:
                prepared_at = parse(preparation.get("prepared_at"))
                expiry = min(
                    parse(preparation.get("deadline_at")),
                    prepared_at + dt.timedelta(seconds=PREPARED_DISPATCH_TTL_SECONDS),
                )
                if now() >= expiry:
                    # The TTL is enforced at register/dispatch time.  Validate
                    # only warns here so a slow-but-legitimate dispatch does
                    # not close every validate caller; it fails hard only past
                    # the much larger validate expiry bound.
                    warnings.append(
                        f"prepared dispatch pending past register TTL: {preparation.get('id')}; "
                        f"register will reject it; release it with: agentledger.py cancel-prepare --id {preparation.get('id')}"
                    )
                hard_expiry = min(
                    parse(preparation.get("deadline_at")),
                    prepared_at + dt.timedelta(seconds=PREPARED_DISPATCH_VALIDATE_EXPIRY_SECONDS),
                )
                if now() >= hard_expiry:
                    errors.append(
                        f"prepared dispatch expired: {preparation.get('id')}; "
                        f"release it before revalidation: agentledger.py cancel-prepare --id {preparation.get('id')}"
                    )
            except (TypeError, ValueError):
                pass  # timestamp shape errors are already reported above
        reservation_required = {
            "id", "estimated_tokens", "status", "reserved_at", "closed_at", "charge_receipt",
        }
        expected_reservation_id = token_reservation_id(
            state, str(preparation.get("id")), str(preparation.get("task_payload_sha256")),
            integer((payload or {}).get("estimated_tokens")),
        )
        if (
            not isinstance(reservation, dict) or set(reservation) != reservation_required
            or reservation.get("id") != expected_reservation_id
            or reservation.get("estimated_tokens") != (payload or {}).get("estimated_tokens")
            or reservation.get("status") not in {"reserved", "released", "settled"}
        ):
            errors.append(f"prepared dispatch token reservation is invalid: {preparation.get('id')}")
        else:
            try:
                parse(reservation.get("reserved_at"))
            except (TypeError, ValueError):
                errors.append(f"prepared dispatch token reservation time is invalid: {preparation.get('id')}")
            if reservation.get("status") == "reserved":
                if reservation.get("closed_at") is not None or reservation.get("charge_receipt") is not None or cancelled is not None:
                    errors.append(f"open token reservation has terminal data: {preparation.get('id')}")
            elif reservation.get("status") == "released":
                lost_settlement = consumed is not None and any(
                    isinstance(entry, dict) and entry.get("id") == preparation.get("id")
                    and entry.get("status") == "lost"
                    and entry.get("terminal_observed_at") == reservation.get("closed_at")
                    for entry in state.get("members", [])
                )
                cancelled_release = consumed is None and reservation.get("closed_at") == cancelled
                if reservation.get("charge_receipt") is not None or not (cancelled_release or lost_settlement):
                    errors.append(f"released token reservation is not a cancel or lost settlement: {preparation.get('id')}")
            else:
                charge = token_charge_from_receipt(reservation.get("charge_receipt"))
                if (
                    charge is None
                    or charge.get("ledger_epoch") != state.get("epoch")
                    or charge.get("reservation_id") != reservation.get("id")
                    or charge.get("agent_id") != preparation.get("id")
                    or charge.get("root_task_id") != preparation.get("root_task_id")
                    or charge.get("task_payload_sha256") != preparation.get("task_payload_sha256")
                    or charge.get("estimated_tokens") != reservation.get("estimated_tokens")
                    or charge.get("terminal_observed_at") != reservation.get("closed_at")
                ):
                    errors.append(f"settled token reservation lacks its bound charge receipt: {preparation.get('id')}")
    if len(preparation_ids) != len(set(preparation_ids)):
        errors.append("duplicate prepared dispatch IDs")
    ids = []
    capacity_attempt_ids: List[object] = []
    capacity_counts: Dict[str, int] = {}
    for attempt in state.get("capacity_failures", []):
        if not isinstance(attempt, dict):
            errors.append("capacity failure must be object"); continue
        capacity_attempt_ids.append(attempt.get("attempt_id"))
        root_id = str(attempt.get("root_task_id", "")); capacity_counts[root_id] = capacity_counts.get(root_id, 0) + 1
        if not attempt.get("attempt_id") or not root_id or attempt.get("model") != config.get("default_model"):
            errors.append("capacity failure identity/model is invalid")
        if not content_addressed_receipt(attempt.get("error_evidence"), "capacity-failures", ".err"):
            errors.append(f"capacity failure evidence drifted: {attempt.get('attempt_id')}")
        try:
            parse(attempt.get("failed_at"))
        except (ValueError, TypeError):
            errors.append(f"capacity failure timestamp is invalid: {attempt.get('attempt_id')}")
    if len(capacity_attempt_ids) != len(set(capacity_attempt_ids)):
        errors.append("duplicate capacity attempt IDs")
    if any(count > int(state.get("capacity_retry_limit", -1)) + 1 for count in capacity_counts.values()):
        errors.append("capacity retry limit exceeded")
    required = {"id", "root_task_id", "role_type", "role", "task", "model", "fork_turns", "context_strategy",
                "task_payload_sha256", "task_payload_evidence", "handoff_envelope_sha256", "handoff_envelope_evidence",
                "payload_estimated_tokens", "token_reservation_id",
                "allowed_evidence_paths", "forbidden_actions", "review_chain_id", "review_subject_sha256",
                "predecessor_result_sha256", "result_report_path", "status", "started_at", "deadline_at", "last_progress_at",
                "last_check_at", "progress_hash", "platform_cursor", "last_platform_message_sha256", "progress_observed",
                "unchanged_checks", "redispatch_count", "redispatched_to", "evidence", "result_evidence", "review_verdict",
                "review_attestation", "registration_platform_evidence",
                "registration_observed_at", "monitor_platform_evidence", "monitoring_violation_at",
                "stall_violation_at",
                "interrupt_requested_at", "interrupt_reason", "terminal_platform_evidence", "terminal_observed_at"}
    for item in state.get("members", []):
        if not isinstance(item, dict): errors.append("member must be object"); continue
        ids.append(item.get("id"))
        matching_preparations = [entry for entry in preparations if isinstance(entry, dict) and entry.get("id") == item.get("id")]
        if (
            len(matching_preparations) != 1
            or matching_preparations[0].get("consumed_at") is None
            or matching_preparations[0].get("cancelled_at") is not None
            or matching_preparations[0].get("task_payload_sha256") != item.get("task_payload_sha256")
            or matching_preparations[0].get("handoff_envelope_sha256") != item.get("handoff_envelope_sha256")
            or (matching_preparations[0].get("token_reservation") or {}).get("id") != item.get("token_reservation_id")
            or (matching_preparations[0].get("token_reservation") or {}).get("estimated_tokens") != item.get("payload_estimated_tokens")
            or any(
                matching_preparations[0].get(key) != item.get(key)
                for key in (
                    "review_chain_id", "review_subject_sha256",
                    "predecessor_result_sha256", "result_report_path",
                )
            )
        ):
            errors.append(f"member lacks its consumed pre-spawn preparation: {item.get('id')}")
        if not required.issubset(item): errors.append(f"member fields incomplete: {item.get('id')}")
        if item.get("role_type") not in state.get("allowed_role_types", []): errors.append(f"invalid canonical role type: {item.get('id')}")
        if item.get("status") not in {ACTIVE, *TERMINAL}: errors.append(f"invalid member status: {item.get('id')}")
        reservation = matching_preparations[0].get("token_reservation") if len(matching_preparations) == 1 else None
        if isinstance(reservation, dict):
            if item.get("status") == ACTIVE and reservation.get("status") != "reserved":
                errors.append(f"active Agent token reservation is not open: {item.get('id')}")
            if item.get("status") in TERMINAL:
                if item.get("status") == "lost":
                    if (
                        reservation.get("status") != "released"
                        or reservation.get("charge_receipt") is not None
                        or reservation.get("closed_at") != item.get("terminal_observed_at")
                    ):
                        errors.append(f"lost Agent token reservation is not released: {item.get('id')}")
                else:
                    charge = token_charge_from_receipt(reservation.get("charge_receipt"))
                    if (
                        reservation.get("status") != "settled" or charge is None
                        or charge.get("terminal_status") != item.get("status")
                        or charge.get("terminal_observed_at") != item.get("terminal_observed_at")
                    ):
                        errors.append(f"terminal Agent token charge is not settled: {item.get('id')}")
        if item.get("model") != config.get("default_model"): errors.append(f"member model differs from configured default: {item.get('id')}")
        if integer(item.get("fork_turns"), -1) < 0 or integer(item.get("fork_turns"), -1) > integer(config.get("max_fork_turns"), -1): errors.append(f"member fork window is outside configured bounds: {item.get('id')}")
        if item.get("context_strategy") != config.get("context_strategy"): errors.append(f"member context strategy differs from config: {item.get('id')}")
        if not SHA.fullmatch(str(item.get("task_payload_sha256", ""))): errors.append(f"invalid task payload hash: {item.get('id')}")
        if not content_addressed_receipt(item.get("task_payload_evidence"), "agent-task-payloads", ".ctx") or item.get("task_payload_sha256") != (item.get("task_payload_evidence") or {}).get("sha256"):
            errors.append(f"task payload evidence drifted: {item.get('id')}")
        payload = reusable_task_payload(item.get("task_payload_evidence"))
        if (
            payload is None
            or item.get("payload_estimated_tokens") != payload.get("estimated_tokens")
            or not SHA.fullmatch(str(item.get("token_reservation_id", "")))
        ):
            errors.append(f"member token reservation binding drifted: {item.get('id')}")
        if not SHA.fullmatch(str(item.get("handoff_envelope_sha256", ""))): errors.append(f"invalid handoff envelope hash: {item.get('id')}")
        envelope = handoff_envelope(item.get("handoff_envelope_evidence"))
        expected_envelope = {
            "ledger_epoch": state.get("epoch"), "agent_id": item.get("id"), "root_task_id": item.get("root_task_id"),
            "role_type": item.get("role_type"), "model": item.get("model"), "fork_turns": item.get("fork_turns"),
            "started_at": item.get("started_at"), "deadline_at": item.get("deadline_at"),
            "redispatch_count": item.get("redispatch_count"),
            "review_chain_id": item.get("review_chain_id"),
            "review_subject_sha256": item.get("review_subject_sha256"),
            "predecessor_result_sha256": item.get("predecessor_result_sha256"),
            "result_report_path": item.get("result_report_path"),
        }
        if (
            envelope is None
            or item.get("handoff_envelope_sha256") != (item.get("handoff_envelope_evidence") or {}).get("sha256")
            or not envelope_contract_matches(envelope, expected_envelope, item.get("task_payload_evidence") or {})
            or item.get("allowed_evidence_paths") != envelope.get("allowed_evidence_paths")
            or item.get("forbidden_actions") != envelope.get("forbidden_actions")
        ):
            errors.append(f"handoff envelope contract drifted: {item.get('id')}")
        if not SHA.fullmatch(str(item.get("progress_hash", ""))): errors.append(f"invalid progress hash: {item.get('id')}")
        try:
            duration = (parse(item["deadline_at"]) - parse(item["started_at"])).total_seconds()
            if duration < 60 or duration > 7200 or duration % 60 != 0: errors.append(f"invalid deadline: {item.get('id')}")
        except (KeyError, ValueError, TypeError): errors.append(f"invalid timestamp: {item.get('id')}")
        allowed_paths = set(item.get("allowed_evidence_paths", [])) if isinstance(item.get("allowed_evidence_paths"), list) else set()
        for record in item.get("evidence", []):
            if not valid_receipt(record): errors.append(f"evidence drifted: {item.get('id')}")
            elif record.get("path") not in allowed_paths: errors.append(f"evidence violates handoff allowlist: {item.get('id')}")
        result_records = item.get("result_evidence")
        if not isinstance(result_records, list):
            errors.append(f"result evidence is invalid: {item.get('id')}")
            result_records = []
        for record in result_records:
            if not result_evidence_receipt(record): errors.append(f"result evidence drifted: {item.get('id')}")
            elif record.get("source_path") not in allowed_paths: errors.append(f"result evidence violates handoff allowlist: {item.get('id')}")
        if item.get("status") == ACTIVE and result_records:
            errors.append(f"active Agent has terminal result evidence: {item.get('id')}")
        is_completed_review = item.get("status") == "completed" and item.get("role_type") in state.get("review_role_types", [])
        is_completed_implementer = item.get("status") == "completed" and item.get("role_type") == "implementer"
        if is_completed_review:
            derived_contract = review_result_contract(item, result_records, state)
            derived_verdict = derived_contract[0] if derived_contract is not None else None
            derived_attestation = derived_contract[1] if derived_contract is not None else None
            if (
                derived_verdict is None
                or item.get("review_verdict") != derived_verdict
                or item.get("review_attestation") != derived_attestation
                or item.get("conclusion") != review_conclusion(derived_verdict)
                or item.get("last_platform_message_sha256") != hashlib.sha256(review_final_message(derived_verdict).encode()).hexdigest()
            ):
                errors.append(f"completed review lacks its reviewer-authored verdict commitment: {item.get('id')}")
        elif item.get("review_verdict") is not None or item.get("review_attestation") is not None:
            errors.append(f"non-review terminal state has a review verdict/attestation: {item.get('id')}")
        if is_completed_implementer and implementation_result_contract(
            item, result_records, state, require_current=False,
        ) is None:
            errors.append(f"completed implementer lacks its exact implementation attestation: {item.get('id')}")
        registration_snapshot = None; registered = None
        if not content_addressed_receipt(item.get("registration_platform_evidence"), "platform-snapshots", ".json"):
            errors.append(f"registration lacks platform evidence: {item.get('id')}")
        else:
            registration_snapshot = receipt_platform_snapshot(item.get("registration_platform_evidence"))
            registered = receipt_platform_member(item.get("registration_platform_evidence"), str(item.get("id")))
            if (
                registration_snapshot is None
                or registered is None
                or str(registered.get("status", "")).lower() not in PLATFORM_ACTIVE
                or not platform_contract_matches(registered, item, state)
                or iso(parse(registration_snapshot.get("observed_at"))) != item.get("registration_observed_at")
                or parse(item.get("registration_observed_at")) < parse(item.get("started_at")) - dt.timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
                or parse(item.get("registration_observed_at")) > parse(item.get("deadline_at"))
            ):
                errors.append(f"registration platform semantics differ from ledger: {item.get('id')}")
        monitors = item.get("monitor_platform_evidence")
        prior_observed = parse(item.get("registration_observed_at"))
        prior_cursor = int(registered.get("message_cursor", 0)) if isinstance(registered, dict) else 0
        first_monitor_gap_at: Optional[str] = None
        if not isinstance(monitors, list):
            errors.append(f"monitor evidence chain is invalid: {item.get('id')}")
            monitors = []
        for record in monitors:
            if not content_addressed_receipt(record, "platform-snapshots", ".json"):
                errors.append(f"monitor evidence drifted: {item.get('id')}"); continue
            monitor_snapshot = receipt_platform_snapshot(record)
            monitored = receipt_platform_member(record, str(item.get("id")))
            if monitor_snapshot is None or monitored is None:
                errors.append(f"monitor platform semantics are missing: {item.get('id')}"); continue
            monitor_observed = parse(monitor_snapshot.get("observed_at"))
            monitor_cursor = monitored.get("message_cursor")
            gap = (monitor_observed - prior_observed).total_seconds()
            if gap < 0:
                errors.append(f"monitor timestamps regressed: {item.get('id')}")
            if gap > int(state.get("status_interval_seconds", 0)) + int(state.get("monitor_grace_seconds", 0)):
                first_monitor_gap_at = first_monitor_gap_at or iso(monitor_observed)
            if (
                str(monitored.get("status", "")).lower() not in PLATFORM_ACTIVE
                or not platform_contract_matches(monitored, item, state)
                or not isinstance(monitor_cursor, int)
                or int(monitor_cursor or 0) < prior_cursor
            ):
                errors.append(f"monitor platform semantics differ from ledger: {item.get('id')}")
            if monitor_observed > prior_observed:
                prior_observed = monitor_observed
            if isinstance(monitor_cursor, int):
                prior_cursor = monitor_cursor
        if item.get("status") in TERMINAL:
            terminal_snapshot = receipt_platform_snapshot(item.get("terminal_platform_evidence"))
            if terminal_snapshot is not None:
                terminal_observed_for_gap = parse(terminal_snapshot.get("observed_at"))
                if terminal_observed_for_gap > prior_observed and (
                    terminal_observed_for_gap - prior_observed
                ).total_seconds() > int(state.get("status_interval_seconds", 0)) + int(state.get("monitor_grace_seconds", 0)):
                    first_monitor_gap_at = first_monitor_gap_at or iso(terminal_observed_for_gap)
        if item.get("monitoring_violation_at") != first_monitor_gap_at:
            errors.append(f"first monitoring violation timestamp differs from immutable evidence: {item.get('id')}")
        if item.get("stall_violation_at") is not None:
            try:
                parse(item.get("stall_violation_at"))
            except (ValueError, TypeError):
                errors.append(f"stall violation timestamp is invalid: {item.get('id')}")
        marker = read_terminal_marker(state, item)
        if item.get("status") == ACTIVE and marker is not None:
            errors.append(f"terminal Agent was reactivated: {item.get('id')}")
        if item.get("status") in TERMINAL:
            if marker is None or marker.get("invalid") is True:
                errors.append(f"terminal status lacks its immutable epoch marker: {item.get('id')}")
            elif (
                set(marker) != {
                    "schema", "ledger_epoch", "agent_id", "terminal_status", "task_payload_sha256",
                    "handoff_envelope_sha256", "review_chain_id", "review_subject_sha256",
                    "predecessor_result_sha256", "result_report_path", "terminal_platform_evidence",
                    "terminal_observed_at", "finished_at", "conclusion", "result_evidence",
                    "review_verdict", "review_attestation", "final_message_cursor", "final_message_sha256",
                    "monitoring_violation_at", "stall_violation_at",
                }
                or marker.get("schema") != TERMINAL_MARKER_SCHEMA
                or marker.get("ledger_epoch") != state.get("epoch")
                or marker.get("agent_id") != item.get("id")
                or marker.get("terminal_status") != item.get("status")
                or marker.get("task_payload_sha256") != item.get("task_payload_sha256")
                or marker.get("handoff_envelope_sha256") != item.get("handoff_envelope_sha256")
                or marker.get("review_chain_id") != item.get("review_chain_id")
                or marker.get("review_subject_sha256") != item.get("review_subject_sha256")
                or marker.get("predecessor_result_sha256") != item.get("predecessor_result_sha256")
                or marker.get("result_report_path") != item.get("result_report_path")
                or marker.get("terminal_platform_evidence") != item.get("terminal_platform_evidence")
                or marker.get("terminal_observed_at") != item.get("terminal_observed_at")
                or marker.get("finished_at") != item.get("finished_at")
                or marker.get("conclusion") != item.get("conclusion")
                or marker.get("result_evidence") != item.get("result_evidence")
                or marker.get("review_verdict") != item.get("review_verdict")
                or marker.get("review_attestation") != item.get("review_attestation")
                or marker.get("monitoring_violation_at") != item.get("monitoring_violation_at")
                or marker.get("stall_violation_at") != item.get("stall_violation_at")
                or marker.get("final_message_cursor") != item.get("platform_cursor")
                or marker.get("final_message_sha256") != item.get("last_platform_message_sha256")
            ):
                errors.append(f"terminal marker differs from ledger: {item.get('id')}")
            if not str(item.get("conclusion", "")).strip() or item.get("finished_at") is None:
                errors.append(f"terminal member fields are incomplete: {item.get('id')}")
            else:
                try: parse(item.get("finished_at"))
                except (ValueError, TypeError): errors.append(f"terminal finish timestamp is invalid: {item.get('id')}")
        if item.get("status") == "lost":
            decision = item.get("lost_decision")
            if integer(item.get("missing_observations"), 0) < LOST_OBSERVATION_THRESHOLD:
                try:
                    decision_valid = isinstance(decision, dict) and humandecision.decision_approval_valid(
                        ROOT, load(CONFIG), load(TASK), gate="agent-lost",
                        artifact_sha256=lost_decision_binding(state, str(item.get("id"))),
                        source=str(decision.get("source", "")), record=decision,
                    )
                except SystemExit:
                    decision_valid = False
                if not decision_valid:
                    errors.append(f"lost Agent lacks its missing-observation proof or human decision: {item.get('id')}")
            elif decision is not None and not isinstance(decision, dict):
                errors.append(f"lost Agent decision record is invalid: {item.get('id')}")
        if item.get("status") in TERMINAL and not content_addressed_receipt(item.get("terminal_platform_evidence"), "platform-snapshots", ".json"):
            errors.append(f"terminal status lacks platform evidence: {item.get('id')}")
        elif item.get("status") == "lost":
            lost_snapshot = receipt_platform_snapshot(item.get("terminal_platform_evidence"))
            if (
                lost_snapshot is None
                or receipt_platform_member(item.get("terminal_platform_evidence"), str(item.get("id"))) is not None
            ):
                errors.append(f"lost Agent terminal evidence does not prove platform absence: {item.get('id')}")
            elif item.get("terminal_observed_at") != iso(parse(lost_snapshot.get("observed_at"))):
                errors.append(f"terminal observation timestamp differs from receipt: {item.get('id')}")
        elif item.get("status") in TERMINAL:
            terminal_snapshot = receipt_platform_snapshot(item.get("terminal_platform_evidence"))
            terminal = receipt_platform_member(item.get("terminal_platform_evidence"), str(item.get("id")))
            if (
                terminal_snapshot is None
                or terminal is None
                or str(terminal.get("status", "")).lower() not in PLATFORM_TERMINAL[str(item.get("status"))]
                or not platform_contract_matches(terminal, item, state)
                or not isinstance(terminal.get("message_cursor"), int)
                or int(terminal.get("message_cursor", -1)) != int(item.get("platform_cursor", 0))
                or terminal.get("message_sha256") != item.get("last_platform_message_sha256")
            ):
                errors.append(f"terminal platform semantics differ from ledger: {item.get('id')}")
            else:
                terminal_observed = parse(terminal_snapshot.get("observed_at"))
                if item.get("terminal_observed_at") != iso(terminal_observed):
                    errors.append(f"terminal observation timestamp differs from receipt: {item.get('id')}")
                contract_errors = completion_contract_errors(
                    item, terminal_observed, int(state.get("status_interval_seconds", 0)), int(state.get("monitor_grace_seconds", 0)),
                    int(state.get("stall_timeout_seconds", 0)),
                )
                if item.get("status") == "completed" and contract_errors:
                    errors.append(f"completed Agent violated deadline/monitoring contract: {item.get('id')}")
                if item.get("status") == "expired" and not contract_errors:
                    errors.append(f"expired Agent has no deadline/monitoring violation: {item.get('id')}")
        elif item.get("terminal_observed_at") is not None:
            errors.append(f"active Agent has terminal observation time: {item.get('id')}")
    errors.extend(formal_review_chain_errors(state))
    errors.extend(replay_run_registry_errors(state))
    errors.extend(orphan_terminal_marker_errors(state))
    member_map = {str(item.get("id")): item for item in state.get("members", []) if isinstance(item, dict)}
    for item in member_map.values():
        try:
            redispatch_count = int(item.get("redispatch_count", -1))
        except (TypeError, ValueError):
            errors.append(f"invalid redispatch count: {item.get('id')}"); continue
        if redispatch_count < 0 or redispatch_count > int(state.get("max_redispatch", -1)):
            errors.append(f"invalid redispatch count: {item.get('id')}")
        sources = [source for source in member_map.values() if source.get("redispatched_to") == item.get("id")]
        if redispatch_count == 0 and sources:
            errors.append(f"initial Agent has a redispatch source: {item.get('id')}")
        source_retryable = len(sources) == 1 and (
            sources[0].get("status") in {"interrupted", "errored", "expired"}
            or (
                sources[0].get("role_type") in FORMAL_REVIEW_ROLE_TYPES
                and committed_review_fail(state, sources[0])
            )
        )
        if redispatch_count > 0 and (
            len(sources) != 1
            or sources[0].get("root_task_id") != item.get("root_task_id")
            or integer(sources[0].get("redispatch_count")) + 1 != redispatch_count
            or not source_retryable
            or sources[0].get("task_payload_sha256") != item.get("task_payload_sha256")
            or sources[0].get("handoff_envelope_sha256") == item.get("handoff_envelope_sha256")
            or any(
                sources[0].get(key) != item.get(key)
                for key in ("review_chain_id", "review_subject_sha256", "predecessor_result_sha256")
            )
        ):
            errors.append(f"redispatch relationship is invalid: {item.get('id')}")
        target_id = item.get("redispatched_to")
        if target_id is not None:
            target = member_map.get(str(target_id))
            item_retryable = (
                item.get("status") in {"interrupted", "errored", "expired"}
                or (
                    item.get("role_type") in FORMAL_REVIEW_ROLE_TYPES
                    and committed_review_fail(state, item)
                )
            )
            if (
                target is None
                or target.get("root_task_id") != item.get("root_task_id")
                or integer(target.get("redispatch_count")) != redispatch_count + 1
                or not item_retryable
                or target.get("task_payload_sha256") != item.get("task_payload_sha256")
                or target.get("handoff_envelope_sha256") == item.get("handoff_envelope_sha256")
                or any(
                    target.get(key) != item.get(key)
                    for key in ("review_chain_id", "review_subject_sha256", "predecessor_result_sha256")
                )
            ):
                errors.append(f"redispatch target is invalid: {item.get('id')}")
    if len(ids) != len(set(ids)): errors.append("duplicate canonical IDs")
    pending_preparations = [item for item in preparations if isinstance(item, dict) and item.get("consumed_at") is None and item.get("cancelled_at") is None]
    if len(active(state)) + len(pending_preparations) > min(mode_limit(), int(state.get("platform_limit", 0)) - int(state.get("reserved_root_slots", 1))): errors.append("active/prepared agents exceed cap")
    if load(TASK).get("status") in {"idle", "accepted"} and (active(state) or pending_preparations):
        errors.append("terminal/idle task cannot retain active or prepared child agents")
    pending_empty_snapshot: Optional[Dict[str, object]] = None
    if args.require_empty:
        if active(state): errors.append("active agents remain")
        if pending_preparations: errors.append("unconsumed prepared dispatches remain")
        if args.platform_snapshot:
            try:
                _, record, platform = platform_snapshot(args.platform_snapshot)
                if active_platform_ids(platform): errors.append("platform still reports active agents")
                else:
                    pending_empty_snapshot = record
            except SystemExit as error:
                errors.append(str(error))
        empty_verified = state.get("platform_empty_verified") is True
        empty_receipt = state.get("last_platform_snapshot")
        if pending_empty_snapshot is not None:
            empty_verified = True; empty_receipt = pending_empty_snapshot
        if not empty_verified or not valid_receipt(empty_receipt):
            errors.append("empty ledger lacks a fresh platform empty-state proof")
    for warning in warnings: print(f"WARNING: {warning}")
    if errors:
        print("INVALID AGENT LEDGER")
        for error in errors: print(f"- {error}")
        return 1
    if pending_empty_snapshot is not None:
        state["last_platform_snapshot"] = pending_empty_snapshot
        state["platform_empty_verified"] = True
        state["updated_at"] = iso(now())
        save(state)
    print(f"VALID AGENT LEDGER: active={len(active(state))}"); return 0


def command_watchdog_plan(args: argparse.Namespace) -> int:
    """Emit one bounded foreground supervision plan without claiming platform truth."""
    state = load(STATE); generated = now()
    active_members = sorted(active(state), key=lambda item: str(item.get("id")))
    pending_preparations = sorted(
        [
            item for item in state.get("prepared_dispatches", [])
            if isinstance(item, dict)
            and item.get("consumed_at") is None and item.get("cancelled_at") is None
        ],
        key=lambda item: str(item.get("id")),
    )
    capacity_limit = min(
        mode_limit(),
        int(state.get("platform_limit", 0)) - int(state.get("reserved_root_slots", 1)),
    )
    occupied = len(active_members) + len(pending_preparations)
    actions: List[Dict[str, object]] = []
    due_times: List[dt.datetime] = []
    scheduled_cancel: Set[str] = set()

    for preparation in pending_preparations:
        preparation_id = str(preparation.get("id"))
        try:
            expiry = min(
                parse(preparation.get("deadline_at")),
                parse(preparation.get("prepared_at"))
                + dt.timedelta(seconds=PREPARED_DISPATCH_TTL_SECONDS),
            )
            due_times.append(expiry)
            if generated >= expiry:
                scheduled_cancel.add(preparation_id)
                actions.append({
                    "action": "cancel-prepare", "id": preparation_id,
                    "reason": "prepared-dispatch-expired", "execute_by": iso(generated),
                    "command": f"agentledger.py cancel-prepare --id {preparation_id}",
                })
        except (TypeError, ValueError):
            scheduled_cancel.add(preparation_id)
            actions.append({
                "action": "cancel-prepare", "id": preparation_id,
                "reason": "prepared-dispatch-time-invalid", "execute_by": iso(generated),
                "command": f"agentledger.py cancel-prepare --id {preparation_id}",
            })

    excess_after_expiry = max(0, occupied - len(scheduled_cancel) - capacity_limit)
    if excess_after_expiry:
        cancellable = sorted(
            [item for item in pending_preparations if str(item.get("id")) not in scheduled_cancel],
            key=lambda item: str(item.get("prepared_at", "")), reverse=True,
        )
        for preparation in cancellable[:excess_after_expiry]:
            preparation_id = str(preparation.get("id"))
            scheduled_cancel.add(preparation_id)
            actions.append({
                "action": "cancel-prepare", "id": preparation_id,
                "reason": "capacity-excess", "execute_by": iso(generated),
                "command": f"agentledger.py cancel-prepare --id {preparation_id}",
            })
        unresolved_excess = max(0, excess_after_expiry - len(cancellable[:excess_after_expiry]))
        if unresolved_excess:
            actions.append({
                "action": "platform-capacity-reconcile", "reason": "active-agents-exceed-capacity",
                "excess": unresolved_excess,
                "active_ids": [str(item.get("id")) for item in active_members],
                "requires_human_target_selection": True,
            })

    if active_members:
        actions.insert(0, {
            "action": "platform-list", "reason": "refresh-real-platform-state",
            "execute_by": iso(generated + dt.timedelta(seconds=WATCHDOG_MAX_DELAY_SECONDS)),
            "host_operation": "collaboration.list_agents",
        })
    maximum_gap = min(
        WATCHDOG_MAX_DELAY_SECONDS,
        int(state.get("status_interval_seconds", 0)) + int(state.get("monitor_grace_seconds", 0)),
    )
    for item in active_members:
        agent_id = str(item.get("id"))
        missing = integer(item.get("missing_observations"), 0)
        if missing >= LOST_OBSERVATION_THRESHOLD:
            actions.append({
                "action": "finish-lost", "id": agent_id,
                "reason": "missing-platform-observations", "missing_observations": missing,
                "command": (
                    f"agentledger.py finish --id {agent_id} --status lost --lost "
                    "--conclusion <bounded-loss-summary> "
                    "--platform-snapshot <fresh-agent-platform-snapshot-v3.json>"
                ),
            })
            continue
        try:
            latest_observed = parse(item.get("registration_observed_at"))
            monitors = item.get("monitor_platform_evidence", [])
            if isinstance(monitors, list) and monitors:
                observed = receipt_observed_at(monitors[-1])
                if observed is None:
                    raise ValueError("invalid monitor observation")
                latest_observed = observed
            due_times.append(latest_observed + dt.timedelta(seconds=maximum_gap))
            deadline = parse(item.get("deadline_at"))
            due_times.append(deadline)
        except (TypeError, ValueError):
            actions.append({
                "action": "platform-interrupt", "id": agent_id,
                "reason": "invalid-supervision-clock", "host_operation": "collaboration.interrupt_agent",
                "requires_real_platform_confirmation": True,
            })
            continue
        interrupt_reason = item.get("interrupt_reason")
        if item.get("interrupt_requested_at") is not None:
            reason = str(interrupt_reason or "ledger-interrupt-requested")
        elif item.get("stall_violation_at") is not None:
            reason = "observed-stall-timeout"
        elif generated > deadline:
            reason = "deadline-exceeded"
        else:
            reason = ""
        if reason:
            actions.append({
                "action": "platform-interrupt", "id": agent_id, "reason": reason,
                "host_operation": "collaboration.interrupt_agent",
                "requires_real_platform_confirmation": True,
            })
        elif integer(item.get("unchanged_checks"), 0) >= int(
            state.get("status_request_after_unchanged_checks", 1)
        ):
            actions.append({
                "action": "request-status", "id": agent_id,
                "reason": "elapsed-unchanged-check", "host_operation": "collaboration.send_message",
            })
    if active_members:
        actions.append({
            "action": "submit-platform-snapshot", "reason": "reconcile-ledger-with-real-platform",
            "command": "agentledger.py check --platform-snapshot <fresh-agent-platform-snapshot-v3.json>",
            "requires_real_platform_snapshot": True,
        })

    scheduler_required = bool(active_members or pending_preparations)
    if scheduler_required:
        due_times.append(generated + dt.timedelta(seconds=WATCHDOG_MAX_DELAY_SECONDS))
    next_due = max(generated, min(due_times)) if due_times else None
    result = {
        "schema": "agent-watchdog-plan/v1", "generated_at": iso(generated),
        "foreground_one_shot": True, "background_process_started": False,
        "platform_authority": False, "terminal": False,
        "terminal_reason": "agent ledger has no main-task completion authority",
        "main_task_status": load(TASK).get("status"),
        "active_ids": [str(item.get("id")) for item in active_members],
        "prepared_ids": [str(item.get("id")) for item in pending_preparations],
        "capacity": {
            "active": len(active_members), "prepared": len(pending_preparations),
            "occupied": occupied, "limit": capacity_limit,
            "over_by": max(0, occupied - capacity_limit),
        },
        "host_scheduler": {
            "required": scheduler_required,
            "max_delay_seconds": WATCHDOG_MAX_DELAY_SECONDS if scheduler_required else None,
            "next_check_due_at": iso(next_due) if next_due is not None else None,
            "must_use_real_platform_tools": True,
            "required_sequence": [
                "call collaboration.list_agents",
                "execute listed collaboration.interrupt_agent actions when present",
                "materialize one fresh agent-platform-snapshot/v3",
                "run agentledger.py check with that snapshot",
            ] if scheduler_required else [],
        },
        "bounds": {
            "single_foreground_invocation": True, "persistent_loop": False,
            "max_actions": len(active_members) + len(pending_preparations) + 3,
        },
        "actions": actions,
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(); sub = value.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init"); init.add_argument("--platform-snapshot"); init.add_argument("--archive-existing", action="store_true")
    init.add_argument("--force", action="store_true"); init.add_argument("--force-reason"); init.add_argument("--source"); init.add_argument("--receipt")
    seal = sub.add_parser("seal-payload"); seal.add_argument("--draft", required=True); seal.add_argument("--output", required=True)
    prepare = sub.add_parser("prepare"); prepare.add_argument("--id", required=True); prepare.add_argument("--root-task-id"); prepare.add_argument("--role-type", choices=CANONICAL_ROLE_TYPES, required=True); prepare.add_argument("--model", required=True); prepare.add_argument("--fork-turns", type=int, required=True); prepare.add_argument("--redispatch-count", type=int, default=0); prepare.add_argument("--task-payload", required=True); prepare.add_argument("--handoff-envelope", required=True)
    cancel = sub.add_parser("cancel-prepare"); cancel.add_argument("--id", required=True)
    register_p = sub.add_parser("register"); register_p.add_argument("--id", required=True); register_p.add_argument("--root-task-id"); register_p.add_argument("--role-type", choices=CANONICAL_ROLE_TYPES, required=True); register_p.add_argument("--role", required=True); register_p.add_argument("--task", required=True); register_p.add_argument("--model", required=True); register_p.add_argument("--fork-turns", type=int, required=True); register_p.add_argument("--task-payload", required=True); register_p.add_argument("--handoff-envelope", required=True); register_p.add_argument("--deadline-minutes", type=int, required=True); register_p.add_argument("--progress-hash", required=True); register_p.add_argument("--platform-cursor", type=int, default=0); register_p.add_argument("--platform-snapshot")
    capacity = sub.add_parser("capacity-failure"); capacity.add_argument("--root-task-id", required=True); capacity.add_argument("--attempt-id", required=True); capacity.add_argument("--model", required=True); capacity.add_argument("--evidence", required=True)
    heartbeat = sub.add_parser("heartbeat"); heartbeat.add_argument("--id", required=True); heartbeat.add_argument("--progress-hash", required=True); heartbeat.add_argument("--evidence", action="append")
    replay_prepare = sub.add_parser("replay-prepare"); replay_prepare.add_argument("--integrator-id", required=True); replay_prepare.add_argument("--plan", required=True)
    replay_execute = sub.add_parser("replay-execute"); replay_execute.add_argument("--integrator-id", required=True); replay_execute.add_argument("--run-id", required=True)
    replay_reconcile = sub.add_parser("replay-reconcile-terminal"); replay_reconcile.add_argument("--integrator-id", required=True)
    check = sub.add_parser("check"); check.add_argument("--platform-snapshot")
    finish = sub.add_parser("finish"); finish.add_argument("--id", required=True); finish.add_argument("--status", choices=tuple(sorted(TERMINAL)), required=True); finish.add_argument("--conclusion", required=True); finish.add_argument("--evidence", action="append"); finish.add_argument("--platform-snapshot")
    finish.add_argument("--lost", action="store_true"); finish.add_argument("--source"); finish.add_argument("--receipt")
    redispatch = sub.add_parser("redispatch"); redispatch.add_argument("--from-id", required=True); redispatch.add_argument("--to-id", required=True); redispatch.add_argument("--handoff-envelope", required=True); redispatch.add_argument("--deadline-minutes", type=int, required=True); redispatch.add_argument("--platform-snapshot")
    validate = sub.add_parser("validate"); validate.add_argument("--require-empty", action="store_true"); validate.add_argument("--platform-snapshot")
    sub.add_parser("watchdog-plan")
    return value


def main() -> int:
    args = parser().parse_args(); LOCK.touch(exist_ok=True)
    if args.command == "replay-execute":
        return command_replay_execute(args)
    with LOCK.open("r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return {"init": command_init, "seal-payload": command_seal_payload, "prepare": command_prepare, "cancel-prepare": command_cancel_prepare,
                "register": command_register, "capacity-failure": command_capacity_failure, "heartbeat": command_heartbeat,
                "replay-prepare": command_replay_prepare, "replay-reconcile-terminal": command_replay_reconcile_terminal,
                "check": command_check, "finish": command_finish, "redispatch": command_redispatch,
                "validate": command_validate, "watchdog-plan": command_watchdog_plan}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
