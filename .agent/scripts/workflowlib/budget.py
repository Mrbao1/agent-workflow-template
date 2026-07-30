"""Unified, non-negative workflow Token accounting.

This module deliberately separates assurance from arithmetic.  Without a
verified host usage adapter the result is a conservative best-effort estimate,
not a provider billing limit.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple


# Honest per-turn host-overhead defaults: the measured bootstrap of this
# governance stack costs ~6.7k tokens before any business file is read, so a
# mid-task turn (host system-prompt replay + capsule + tool definitions) is
# multi-thousand tokens, not 150/300/500.  Hosts calibrate these per provider.
DEFAULT_TURN_OVERHEAD_TOKENS = {"fast": 2000, "standard": 3000, "release": 4000}
DEFAULT_DISPATCH_PAYLOAD_LIMITS = {"fast": 0, "standard": 16000, "release": 32000}
DEFAULT_CHILD_SYSTEM_TOOL_MARGIN = 4000
DEFAULT_CHILD_OUTPUT_MARGIN = 2000
DEFAULT_INHERITED_TURN_TOKENS = 800
TURN_OVERHEAD_KEY = "estimated_turn_overhead_tokens"
LEGACY_TURN_OVERHEAD_KEY = "automatic_transition_token_increment"


def _integer(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, parsed)


def _child_components(config: Dict[str, object], preparation: Dict[str, object]) -> Dict[str, int]:
    policy = config.get("agent_control", {})
    if not isinstance(policy, dict):
        policy = {}
    reservation = preparation.get("token_reservation", {})
    if not isinstance(reservation, dict):
        reservation = {}
    sealed = _integer(reservation.get("estimated_tokens"))
    fork_turns = _integer(preparation.get("fork_turns"))
    inherited = fork_turns * _integer(policy.get("inherited_turn_estimated_tokens"), DEFAULT_INHERITED_TURN_TOKENS)
    system_tool = _integer(policy.get("child_system_tool_margin_tokens"), DEFAULT_CHILD_SYSTEM_TOOL_MARGIN)
    output = _integer(policy.get("child_output_margin_tokens"), DEFAULT_CHILD_OUTPUT_MARGIN)
    return {
        "sealed_input": sealed,
        "inherited_fork": inherited,
        "system_tool_margin": system_tool,
        "output_margin": output,
        "total": sealed + inherited + system_tool + output,
    }


def turn_overhead_policy(config: Dict[str, object]) -> Tuple[Dict[str, object], bool]:
    """Resolve the per-mode turn-overhead map; the bool marks the legacy alias.

    ``context.estimated_turn_overhead_tokens`` is the honest per-turn host
    overhead (system-prompt replay + turn cost).  The deprecated
    ``context.automatic_transition_token_increment`` alias keeps legacy
    configs working with their exact legacy arithmetic (no inherited-turn
    surcharge); the new key activates the full per-turn model.
    """
    context = config.get("context", {}) if isinstance(config.get("context"), dict) else {}
    configured = context.get(TURN_OVERHEAD_KEY)
    if isinstance(configured, dict):
        return configured, False
    if configured is not None:
        return {}, False
    legacy = context.get(LEGACY_TURN_OVERHEAD_KEY)
    if isinstance(legacy, dict):
        return legacy, True
    return dict(DEFAULT_TURN_OVERHEAD_TOKENS), False


def transition_overhead_estimate(config: Dict[str, object], mode: str) -> int:
    """Estimated tokens one recorded root transition adds to the active window.

    Under the current key this is the per-turn host overhead plus the
    inherited host context charged per root turn
    (``agent_control.inherited_turn_estimated_tokens``, the same quantity
    charged per fork turn at child dispatch).
    """
    overheads, legacy = turn_overhead_policy(config)
    increment = overheads.get(mode)
    if not isinstance(increment, int) or isinstance(increment, bool) or increment <= 0:
        raise ValueError(f"estimated turn overhead is invalid for mode {mode}")
    if legacy:
        return increment
    agent = config.get("agent_control", {}) if isinstance(config.get("agent_control"), dict) else {}
    return increment + _integer(agent.get("inherited_turn_estimated_tokens"), DEFAULT_INHERITED_TURN_TOKENS)


def measured_turn_delta(task: Dict[str, object]) -> Optional[int]:
    """Provider-observed growth between the two latest usage receipts, if any.

    Cumulative receipts cannot replace the active-window estimate, but the
    delta between two provider-observed cumulative measurements is real
    per-period growth and is preferred over the configured turn estimate.
    """
    receipts = task.get("usage_receipts")
    latest = receipts[-2:] if isinstance(receipts, list) else []
    if len(latest) != 2 or not all(isinstance(item, dict) for item in latest):
        return None
    totals = [item.get("total_tokens") for item in latest]
    if not all(isinstance(total, int) and not isinstance(total, bool) for total in totals):
        return None
    delta = int(totals[1]) - int(totals[0])
    return delta if delta > 0 else None


def config_budget_errors(config: Dict[str, object]) -> List[str]:
    """Fail-closed arithmetic invariant for the unified token budget.

    For every configured mode, one fully-charged permitted child plus the
    recorded baseline overhead must stay below the hard watermark, otherwise
    a legitimate operation deterministically crosses the line::

        max_child_charge(mode) = dispatch_payload_limit(mode)
                                 + child_system_tool_margin + child_output_margin
        baseline_overhead(mode) = bootstrap_overhead + turn_overhead(mode)
                                  + inherited_turn (current key only)
        require charge + baseline < hard_budget_ratio * token_budget(mode)

    Modes with a zero payload limit permit no children and charge zero.
    Configs using the deprecated increment alias keep their legacy arithmetic
    (no bootstrap default, no inherited surcharge) so existing installs are
    not rejected retroactively; the honest baseline applies to current keys.
    """
    errors: List[str] = []
    routing = config.get("routing", {}) if isinstance(config.get("routing"), dict) else {}
    modes = routing.get("modes", {}) if isinstance(routing.get("modes"), dict) else {}
    context = config.get("context", {}) if isinstance(config.get("context"), dict) else {}
    agent = config.get("agent_control", {}) if isinstance(config.get("agent_control"), dict) else {}
    try:
        hard_ratio = float(context.get("hard_budget_ratio", .9))
    except (TypeError, ValueError):
        return ["context.hard_budget_ratio must be a number"]
    bootstrap_raw = context.get("bootstrap_overhead_tokens")
    if bootstrap_raw is not None and (
        not isinstance(bootstrap_raw, int) or isinstance(bootstrap_raw, bool) or bootstrap_raw < 0
    ):
        errors.append("context.bootstrap_overhead_tokens must be a non-negative integer")
    bootstrap = _integer(bootstrap_raw, 0)
    overheads, legacy = turn_overhead_policy(config)
    if not overheads and context.get(TURN_OVERHEAD_KEY) is not None:
        errors.append(f"context.{TURN_OVERHEAD_KEY} must be a per-mode object of positive integers")
    limits = agent.get("dispatch_payload_token_limits")
    limits = limits if isinstance(limits, dict) else DEFAULT_DISPATCH_PAYLOAD_LIMITS
    system_margin = _integer(agent.get("child_system_tool_margin_tokens"), DEFAULT_CHILD_SYSTEM_TOOL_MARGIN)
    output_margin = _integer(agent.get("child_output_margin_tokens"), DEFAULT_CHILD_OUTPUT_MARGIN)
    inherited = 0 if legacy else _integer(agent.get("inherited_turn_estimated_tokens"), DEFAULT_INHERITED_TURN_TOKENS)
    turn_key = LEGACY_TURN_OVERHEAD_KEY if legacy else TURN_OVERHEAD_KEY
    for mode in sorted(modes):
        mode_policy = modes.get(mode)
        budget = _integer(mode_policy.get("token_budget")) if isinstance(mode_policy, dict) else 0
        if budget <= 0:
            errors.append(f"routing.modes.{mode}.token_budget must be a positive integer")
            continue
        turn = overheads.get(mode)
        if not isinstance(turn, int) or isinstance(turn, bool) or turn <= 0:
            errors.append(f"context.{turn_key}.{mode} must be a positive integer")
            continue
        payload = _integer(limits.get(mode), 0)
        charge = payload + system_margin + output_margin if payload > 0 else 0
        baseline = bootstrap + turn + inherited
        limit = hard_ratio * budget
        if charge + baseline >= limit:
            inherited_clause = (
                f" + agent_control.inherited_turn_estimated_tokens ({inherited})" if not legacy else ""
            )
            errors.append(
                f"{mode} budget arithmetic lets one permitted operation cross the hard watermark: "
                f"agent_control.dispatch_payload_token_limits.{mode} ({payload})"
                f" + agent_control.child_system_tool_margin_tokens ({system_margin})"
                f" + agent_control.child_output_margin_tokens ({output_margin})"
                f" + context.bootstrap_overhead_tokens ({bootstrap})"
                f" + context.{turn_key}.{mode} ({turn}){inherited_clause}"
                f" = {charge + baseline} must stay below"
                f" context.hard_budget_ratio ({hard_ratio:g}) x routing.modes.{mode}.token_budget ({budget})"
                f" = {limit:g}"
            )
    return errors


def snapshot(task: Dict[str, object], config: Dict[str, object],
             ledger: Optional[Dict[str, object]] = None,
             *, active_window_estimate: Optional[int] = None,
             additional_child: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    mode = str(task.get("mode", ""))
    modes = config.get("routing", {}).get("modes", {}) if isinstance(config.get("routing"), dict) else {}
    mode_policy = modes.get(mode, {}) if isinstance(modes, dict) else {}
    budget = _integer(mode_policy.get("token_budget")) if isinstance(mode_policy, dict) else 0
    declared = _integer(task.get("token_budget"))
    if budget <= 0 or declared != budget:
        raise ValueError("task token budget must equal the active mode budget")
    declared_root = _integer(task.get("tokens_used"))
    active_window = (
        _integer(active_window_estimate)
        if active_window_estimate is not None
        else 0
    )
    # Startup reading is charged once per task as a floor on root consumption:
    # measured or declared usage above it already contains it, so it is never
    # added twice.  Legacy configs without the key keep a zero floor.
    context_policy = config.get("context", {}) if isinstance(config.get("context"), dict) else {}
    bootstrap = _integer(context_policy.get("bootstrap_overhead_tokens"), 0)
    # The active provider context is part of root consumption, not a separate
    # additive charge.  Use the larger of cumulative root usage and the honest
    # active-window estimate, then add references and child reservations.
    root = max(declared_root, active_window, bootstrap)
    references = task.get("loaded_references", [])
    reference_tokens = sum(
        _integer(item.get("estimated_tokens")) for item in references if isinstance(item, dict)
    ) if isinstance(references, list) else 0
    reserved = settled = 0
    child_breakdown = {"sealed_input": 0, "inherited_fork": 0, "system_tool_margin": 0, "output_margin": 0}
    preparations = ledger.get("prepared_dispatches", []) if isinstance(ledger, dict) else []
    if not isinstance(preparations, list):
        raise ValueError("prepared dispatch registry must be a list")
    for preparation in preparations:
        if not isinstance(preparation, dict):
            continue
        reservation = preparation.get("token_reservation")
        if not isinstance(reservation, dict) or reservation.get("status") not in {"reserved", "settled"}:
            continue
        parts = _child_components(config, preparation)
        for key in child_breakdown:
            child_breakdown[key] += parts[key]
        if reservation.get("status") == "reserved":
            reserved += parts["total"]
        else:
            settled += parts["total"]
    if additional_child is not None:
        parts = _child_components(config, additional_child)
        reserved += parts["total"]
        for key in child_breakdown:
            child_breakdown[key] += parts[key]
    total = root + reference_tokens + reserved + settled
    policy = config.get("context", {}) if isinstance(config.get("context"), dict) else {}
    ratio = total / budget
    if ratio >= float(policy.get("hard_budget_ratio", .9)):
        state = "hard_blocked"
    elif ratio >= float(policy.get("compact_budget_ratio", .75)):
        state = "must_compact"
    elif ratio >= float(policy.get("soft_budget_ratio", .6)):
        state = "soft"
    else:
        state = "ok"
    adapter = config.get("agent_control", {}).get("usage_observer", {}) if isinstance(config.get("agent_control"), dict) else {}
    signed = adapter.get("signed_adapter") if isinstance(adapter, dict) else None
    source = str(task.get("token_usage_source", "estimated"))
    # TASK records usage receipts as a plural history; the latest entry is the
    # current measurement.  The singular field is a legacy fallback only.
    receipts = task.get("usage_receipts")
    latest = receipts[-1] if isinstance(receipts, list) and receipts else task.get("usage_receipt")
    usage_receipt = latest if isinstance(latest, dict) else None
    verified = (
        bool(signed) and source == "measured" and usage_receipt is not None
        and isinstance(usage_receipt.get("sha256"), str)
        and usage_receipt.get("semantics") == "cumulative"
    )
    estimate_policy = config.get("token_estimation", {})
    error_ratio = float(estimate_policy.get("max_error_ratio", .35)) if isinstance(estimate_policy, dict) else .35
    return {
        "schema": "agent-total-token-budget/v1",
        "mode": mode,
        "budget": budget,
        "root_tokens": root,
        "declared_root_tokens": declared_root,
        "bootstrap_overhead_tokens": bootstrap,
        "reference_tokens": reference_tokens,
        "child_reserved_tokens": reserved,
        "child_settled_tokens": settled,
        "child_components": child_breakdown,
        "consumed_tokens": total,
        "remaining_tokens": max(0, budget - total),
        "over_budget_tokens": max(0, total - budget),
        "ratio": round(ratio, 6),
        "state": state,
        "active_window_estimate": active_window if active_window_estimate is not None else None,
        "assurance": {
            "level": "provider-observed-measurement" if verified else "best-effort-estimate",
            # Observation is not provider-side enforcement; this controller
            # never claims a hard billing cap from a measurement adapter.
            "hard_billing_limit": False,
            "unmetered_direct_reads_possible": True,
            "estimated_max_error_ratio": 0.0 if verified else error_ratio,
        },
    }
