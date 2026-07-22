"""Unified, non-negative workflow Token accounting.

This module deliberately separates assurance from arithmetic.  Without a
verified host usage adapter the result is a conservative best-effort estimate,
not a provider billing limit.
"""

from __future__ import annotations

from typing import Dict, Optional


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
    inherited = fork_turns * _integer(policy.get("inherited_turn_estimated_tokens"), 800)
    system_tool = _integer(policy.get("child_system_tool_margin_tokens"), 1000)
    output = _integer(policy.get("child_output_margin_tokens"), 2000)
    return {
        "sealed_input": sealed,
        "inherited_fork": inherited,
        "system_tool_margin": system_tool,
        "output_margin": output,
        "total": sealed + inherited + system_tool + output,
    }


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
    # The active provider context is part of root consumption, not a separate
    # additive charge.  Use the larger of cumulative root usage and the honest
    # active-window estimate, then add references and child reservations.
    root = max(declared_root, active_window)
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
    usage_receipt = task.get("usage_receipt")
    verified = (
        bool(signed) and source == "measured" and isinstance(usage_receipt, dict)
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
