#!/usr/bin/env python3
"""Focused regressions for unified budget and pure state routing."""

from pathlib import Path
import ast
import copy
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workflowlib import budget, state

PUBLICATION_ENTRYPOINTS = {
    "scripts/agentctl.py",
    "scripts/artifactctl.py",
    "scripts/blueprintacceptance.py",
    "scripts/blueprintctl.py",
    "scripts/contextctl.py",
    "scripts/deliveryctl.py",
    "scripts/evidencectl.py",
    "scripts/evolutionctl.py",
    "scripts/knowledgectl.py",
    "scripts/providerctl.py",
    "scripts/self_test_adaptive_workflow.py",
    "scripts/self_test_budget_context_gates.py",
    "scripts/self_test_control_gates.py",
    "scripts/self_test_evidence_retention.py",
    "scripts/self_test_hardening_core.py",
    "scripts/self_test_local_decision_archive.py",
    "scripts/self_test_neutrality_contracts.py",
    "scripts/self_test_plugin_install_lifecycle.py",
    "scripts/self_test_runner_trust.py",
    "scripts/self_test_schema_contracts.py",
    "scripts/self_test_template_lifecycle.py",
    "scripts/self_test_templatectl.py",
    "scripts/skillctl.py",
    "scripts/templatectl.py",
    "scripts/testrun.py",
    "scripts/workflowctl.py",
    "skills/manage-agent-team/scripts/agentledger.py",
    "skills/manage-task-context/scripts/self_test_context.py",
    "skills/run-ai-coding-pipeline/scripts/self_test_stage_index.py",
    "skills/run-ai-coding-pipeline/scripts/validate_stage_index.py",
    "skills/run-full-chain-acceptance/scripts/preflight_environment.py",
    "skills/run-full-chain-acceptance/scripts/run_acceptance_runtime.py",
    "skills/run-full-chain-acceptance/scripts/run_live_release_gate.py",
    "skills/run-full-chain-acceptance/scripts/run_workflow_release_gate.py",
    "skills/run-full-chain-acceptance/scripts/self_test_acceptance_runtime.py",
    "skills/run-full-chain-acceptance/scripts/self_test_gate.py",
    "skills/run-full-chain-acceptance/scripts/self_test_product_fingerprint.py",
    "skills/run-full-chain-acceptance/scripts/self_test_workflow_release_gate.py",
    "skills/run-full-chain-acceptance/scripts/validate_acceptance_report.py",
}


def main_guard(node):
    if not isinstance(node,ast.If): return False
    for comparison in (item for item in ast.walk(node.test) if isinstance(item,ast.Compare)):
        values=[comparison.left,*comparison.comparators]
        if (any(isinstance(value,ast.Name) and value.id=="__name__" for value in values)
                and any(isinstance(value,ast.Constant) and value.value=="__main__" for value in values)):
            return True
    return False


def publication_entrypoint_contract():
    agent_root=Path(__file__).resolve().parents[1]
    candidates=[*(agent_root/"scripts").glob("*.py"),*(agent_root/"skills").glob("*/scripts/*.py")]
    discovered=set()
    for path in candidates:
        tree=ast.parse(path.read_text(encoding="utf-8"),filename=str(path))
        guards=[node for node in tree.body if main_guard(node)]
        if not guards: continue
        relative=path.relative_to(agent_root).as_posix(); discovered.add(relative)
        assert any(isinstance(node,ast.ImportFrom) and node.module=="workflowlib.publication"
                   for node in ast.walk(tree)), relative
        assert any(isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="run_cli"
                   for guard in guards for node in ast.walk(guard)), relative
    assert discovered==PUBLICATION_ENTRYPOINTS,(sorted(discovered-PUBLICATION_ENTRYPOINTS),sorted(PUBLICATION_ENTRYPOINTS-discovered))


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
    publication_entrypoint_contract()
    print(json.dumps({"status": "passed", "cases": 11}, sort_keys=True))
    return 0


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
