"""Pure state-machine helpers.

Keep mode/risk transitions here so the CLI, validation and tests use one
definition rather than subtly different copies.
"""

from __future__ import annotations

from typing import Dict, Iterable, Optional


MODES = ("fast", "standard", "release")
MODE_RANK = {name: index for index, name in enumerate(MODES)}
RISK_NAMES = (
    "deploy", "data_risk", "cross_system", "uncertain", "security",
    "compliance", "migration", "irreversible", "external_impact",
)
RELEASE_RISKS = set(RISK_NAMES) - {"uncertain"}


def required_mode(environment: str, files: int, risk_flags: Dict[str, object],
                  task_type: str, complexity: str) -> str:
    if task_type == "release" or environment == "production" or any(
        risk_flags.get(name) is True for name in RELEASE_RISKS
    ):
        return "release"
    if complexity == "complex" or environment == "test" or risk_flags.get("uncertain") is True or files > 2:
        return "standard"
    return "fast"


def monotonic_risks(current: Dict[str, object], additions: Iterable[str]) -> Dict[str, bool]:
    unknown = sorted(set(additions) - set(RISK_NAMES))
    if unknown:
        raise ValueError(f"unknown risk flags: {unknown}")
    result = {name: current.get(name) is True for name in RISK_NAMES}
    for name in additions:
        result[name] = True
    return result


def escalated_mode(current: str, requested: Optional[str], minimum: str) -> str:
    if current not in MODE_RANK or minimum not in MODE_RANK:
        raise ValueError("invalid workflow mode")
    target = requested or minimum
    if target not in MODE_RANK:
        raise ValueError(f"invalid workflow mode: {target}")
    target = MODES[max(MODE_RANK[target], MODE_RANK[minimum])]
    if MODE_RANK[target] < MODE_RANK[current]:
        raise ValueError("mode downgrade is forbidden")
    return target


def task_projection(task_type: str, mode: str) -> str:
    """Return the canonical task-type projection family."""
    if task_type in {"governance", "documentation", "maintenance"}:
        return "lightweight-release" if mode == "release" else "lightweight"
    return "product"
