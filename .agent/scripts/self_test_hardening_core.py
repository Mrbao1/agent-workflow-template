#!/usr/bin/env python3
"""Focused regressions for unified budget and pure state routing."""

from pathlib import Path
import copy
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workflowlib import budget, state


def fixture():
    config = {
        "routing": {"modes": {name: {"token_budget": value} for name, value in {
            "fast": 6000, "standard": 20000, "release": 40000,
        }.items()}},
        "context": {"soft_budget_ratio": .6, "compact_budget_ratio": .75, "hard_budget_ratio": .9},
        "agent_control": {
            "inherited_turn_estimated_tokens": 800, "child_system_tool_margin_tokens": 1000,
            "child_output_margin_tokens": 2000,
            "usage_observer": {"signed_adapter": None},
        },
        "token_estimation": {"max_error_ratio": .35},
    }
    task = {
        "mode": "fast", "token_budget": 6000, "tokens_used": 1000,
        "token_usage_source": "estimated",
        "loaded_references": [{"estimated_tokens": 500}],
    }
    return config, task


def main() -> int:
    config, task = fixture()
    ledger = {"prepared_dispatches": [{
        "fork_turns": 0,
        "token_reservation": {"status": "reserved", "estimated_tokens": 1200},
    }]}
    value = budget.snapshot(task, config, ledger)
    assert value["consumed_tokens"] == 5700 and value["state"] == "hard_blocked"
    assert value["child_components"] == {
        "sealed_input": 1200, "inherited_fork": 0,
        "system_tool_margin": 1000, "output_margin": 2000,
    }
    assert value["assurance"]["hard_billing_limit"] is False
    assert value["assurance"]["unmetered_direct_reads_possible"] is True

    long_fork = copy.deepcopy(ledger); long_fork["prepared_dispatches"][0]["fork_turns"] = 10
    long_value = budget.snapshot(task, config, long_fork)
    assert long_value["over_budget_tokens"] > 0
    assert long_value["child_components"]["inherited_fork"] == 8000
    assert long_value["consumed_tokens"] - value["consumed_tokens"] == 8000

    recent_task = {**task, "mode": "standard", "token_budget": 20000, "tokens_used": 0, "loaded_references": []}
    recent = {"prepared_dispatches": [{
        "fork_turns": 0,
        "token_reservation": {"status": "reserved", "estimated_tokens": 11885},
    }]}
    recent_value = budget.snapshot(recent_task, config, recent)
    assert recent_value["child_reserved_tokens"] == 14885
    assert recent_value["child_components"] == {
        "sealed_input": 11885, "inherited_fork": 0,
        "system_tool_margin": 1000, "output_margin": 2000,
    }
    recent["prepared_dispatches"][0]["fork_turns"] = 10
    historical_value = budget.snapshot(recent_task, config, recent)
    assert historical_value["child_reserved_tokens"] == 22885
    assert historical_value["child_reserved_tokens"] - recent_value["child_reserved_tokens"] == 8000
    small = copy.deepcopy(ledger); small["prepared_dispatches"][0]["token_reservation"]["estimated_tokens"] = 1
    assert budget.snapshot(task, config, small)["consumed_tokens"] < value["consumed_tokens"]
    active = budget.snapshot(task, config, ledger, active_window_estimate=2200)
    assert active["root_tokens"] == 2200
    assert active["consumed_tokens"] == value["consumed_tokens"] + 1200
    assert active["child_reserved_tokens"] == value["child_reserved_tokens"]

    risks = state.monotonic_risks({name: False for name in state.RISK_NAMES}, ["migration"])
    assert state.required_mode("local", 1, risks, "maintenance", "tiny") == "release"
    assert state.escalated_mode("fast", None, "standard") == "standard"
    try:
        state.escalated_mode("release", "fast", "fast")
    except ValueError as error:
        assert "downgrade" in str(error)
    else:
        raise AssertionError("mode downgrade was accepted")
    assert state.task_projection("governance", "standard") == "lightweight"
    assert state.task_projection("product", "standard") == "product"
    print(json.dumps({"status": "passed", "cases": 10}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
