#!/usr/bin/env python3
"""Verify provider-owned human decision receipts without trusting caller labels."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from typing import Dict, Optional


SCHEMA = "agent-human-decision/v1"
PROVIDER_POLICY_VERSION = 1
LOCAL_POLICY_VERSION = 2
LOCAL_ASSURANCE = "explicit-user-message;local-only;not-provider-verified"
POLICY = {
    "source": "orchestrator-user-message",
    "automatic_gate_trust": False,
    "human_verification_required": True,
    "allow_current_chat_local_release": False,
    "signed_adapter": None,
    "max_receipt_age_seconds": 900,
}
FIELDS = {
    "schema", "decision_id", "gate", "decision", "artifact_sha256", "source",
    "task_title", "task_mode", "routing_profile_sha256", "observed_at", "authority",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def routing_profile_sha256(task: Dict[str, object]) -> str:
    profile = {
        key: task.get(key)
        for key in (
            "task_type", "complexity", "mode", "files", "environment",
            "deployment_requested", "branch", "risk_flags",
        )
    }
    return hashlib.sha256(canonical(profile)).hexdigest()


def policy(config: Dict[str, object]) -> Dict[str, object]:
    control = config.get("agent_control", {})
    observed = control.get("human_decision_observer") if isinstance(control, dict) else None
    if not isinstance(observed, dict) or set(observed) != set(POLICY):
        raise SystemExit("human decision observer policy is missing or malformed")
    for key, expected in POLICY.items():
        if key in {"signed_adapter", "allow_current_chat_local_release"}:
            continue
        if observed.get(key) != expected:
            raise SystemExit("human decision observer policy weakens the fail-closed defaults")
    return observed


def decision_policy_version(
    config: Dict[str, object], *, mode: str, environment: str,
    deployment_requested: bool, risk_flags: Optional[Dict[str, object]] = None,
) -> int:
    """Select the strongest usable gate without blocking reversible local work.

    A configured provider adapter is always preferred. Without one, local
    fast/standard work keeps the lower-assurance conversation boundary. A
    project may explicitly opt release-mode local implementation into that
    boundary. Test, production, deploy, irreversible and external-impact
    routes stay fail-closed.
    """
    observed = policy(config)
    if observed.get("signed_adapter") is not None:
        return PROVIDER_POLICY_VERSION
    risks = risk_flags if isinstance(risk_flags, dict) else {}
    protected_effect = any(risks.get(name) is True for name in ("deploy", "irreversible", "external_impact"))
    local_mode_allowed = mode in {"fast", "standard"} or (
        mode == "release" and observed.get("allow_current_chat_local_release") is True
    )
    if environment == "local" and local_mode_allowed and not deployment_requested and not protected_effect:
        return LOCAL_POLICY_VERSION
    return PROVIDER_POLICY_VERSION


def local_approval(source: str, artifact_sha256: str, task: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    if not source.startswith("user:") or HEX64.fullmatch(artifact_sha256) is None:
        raise SystemExit("local human decision must bind a user source and exact artifact SHA-256")
    approval: Dict[str, object] = {
        "source": source,
        "artifact_sha256": artifact_sha256,
        "assurance": LOCAL_ASSURANCE,
    }
    if task is not None:
        # Bind the same routing profile the provider receipts bind, so a local
        # approval cannot be replayed against a rerouted or escalated task.
        approval["routing_profile_sha256"] = routing_profile_sha256(task)
    return approval


def local_approval_valid(
    task: Dict[str, object], approval: object, *, source: str,
    artifact_sha256: str, config: Optional[Dict[str, object]] = None,
) -> bool:
    risks = task.get("risk_flags")
    if not (
        task.get("decision_policy_version") == LOCAL_POLICY_VERSION
        and task.get("environment") == "local"
        and task.get("mode") in {"fast", "standard", "release"}
        and task.get("deployment_requested") is False
        and isinstance(risks, dict)
        and not any(risks.get(name) is True for name in {"deploy", "irreversible", "external_impact"})
        and isinstance(approval, dict)
        and approval.get("source") == source
        and approval.get("artifact_sha256") == artifact_sha256
        and approval.get("assurance") == LOCAL_ASSURANCE
        and source.startswith("user:")
        and HEX64.fullmatch(artifact_sha256) is not None
    ):
        return False
    # Accepted key shapes (all built on the base triple):
    # - base only: legacy record predating the routing-profile binding. Every
    #   current local-approval producer passes the task and binds the profile,
    #   so a 3-key record can only come from pre-binding code. Records carry
    #   no timestamp or schema version, so no cheaper cutoff exists; the
    #   window stays open only for those genuinely legacy records.
    # - base + routing_profile_sha256: current bound record.
    # - base + release pair: legacy release acceptance approval recorded by
    #   workflowctl approve-gate before the routing-profile binding existed.
    # - base + release pair + routing_profile_sha256: current release
    #   acceptance approval under the local boundary. The release digests are
    #   bound to the accepted artifact by workflowctl.release_acceptance_approval_valid;
    #   here their shape is re-validated the same way as the base digest.
    base = {"source", "artifact_sha256", "assurance"}
    release_pair = {"platform_transcript_verified_sha256", "supervision_debt_waiver_sha256"}
    extra = set(approval) - base
    if extra - {"routing_profile_sha256"} - release_pair:
        return False
    release_keys = extra & release_pair
    if release_keys not in (set(), release_pair):
        return False  # transcript/debt commitments are recorded atomically, never partially
    if "routing_profile_sha256" in extra:
        if approval.get("routing_profile_sha256") != routing_profile_sha256(task):
            return False
    if any(HEX64.fullmatch(str(approval.get(name, ""))) is None for name in release_keys):
        return False
    if task.get("mode") == "release" and config is not None:
        # Config tightening is retroactive: a release task that was approved
        # under a formerly permissive local boundary loses that approval once
        # the project withdraws allow_current_chat_local_release.
        try:
            observed = policy(config)
        except SystemExit:
            return False
        if observed.get("allow_current_chat_local_release") is not True:
            return False
    return True


def resolve_receipt(root: Path, raw: str) -> Path:
    path = (root / raw).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        raise SystemExit("human decision receipt escapes the project evidence boundary")
    if not path.is_file() or path.is_symlink():
        raise SystemExit("human decision receipt is missing or is a symlink")
    return path


def inside(path: Path, boundary: Path) -> bool:
    try:
        path.relative_to(boundary)
        return True
    except ValueError:
        return False


def protected_path_chain(path: Path) -> bool:
    """Require an OS ownership boundary the current Agent cannot create."""
    if not hasattr(os, "geteuid"):
        return False
    current_uid = os.geteuid()
    current = Path(path.anchor)
    chain = [current]
    for part in path.parts[1:]:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError:
            return False
        if stat.S_ISLNK(metadata.st_mode):
            return False
        chain.append(current)
    for item in chain:
        try:
            metadata = item.stat()
        except OSError:
            return False
        if (
            metadata.st_uid == current_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or os.access(item, os.W_OK)
        ):
            return False
    return True


def adapter_path(root: Path, raw: object) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise SystemExit("human gate is blocked until a provider-owned signed decision adapter is configured")
    requested = Path(raw).expanduser()
    if not requested.is_absolute():
        raise SystemExit("human decision adapter must be an absolute host-provisioned executable")
    try:
        path = requested.resolve(strict=True)
    except OSError:
        raise SystemExit("configured human decision adapter is unavailable")
    if requested != path:
        raise SystemExit("human decision adapter path must be canonical and contain no symlink or traversal")
    if inside(path, root.resolve()):
        raise SystemExit("human decision adapter must be provider-owned and outside the project workspace")
    temporary_roots = {
        Path(tempfile.gettempdir()).resolve(), Path("/tmp").resolve(),
        Path("/private/tmp").resolve(), Path("/var/tmp").resolve(),
    }
    if any(inside(path, candidate) for candidate in temporary_roots):
        raise SystemExit("human decision adapter cannot reside in an Agent-writable temporary boundary")
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode) or not os.access(path, os.X_OK):
        raise SystemExit("configured human decision adapter is unavailable or not executable")
    if not protected_path_chain(path):
        raise SystemExit("human decision adapter and every parent must be OS-owned and non-writable by the Agent")
    return path


def try_adapter_path(root: Path, raw: object) -> Optional[Path]:
    """Resolve a configured adapter path, or return None when none is configured.

    Unlike adapter_path this does not raise for an unconfigured (null or blank)
    adapter, so callers can probe availability; a configured but invalid
    adapter still fails closed through adapter_path.
    """
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    return adapter_path(root, raw)


def health(root: Path, config: Dict[str, object]) -> Dict[str, object]:
    """Fail before task mutation unless the provider decision boundary is live."""
    active_policy = policy(config)
    adapter = adapter_path(root, active_policy.get("signed_adapter"))
    try:
        result = subprocess.run(
            [str(adapter), "health"], cwd=str(root), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit("provider-owned human decision adapter health check failed") from error
    if result.returncode:
        raise SystemExit(
            f"provider-owned human decision adapter health check failed: exit={result.returncode}"
        )
    return {
        "adapter_path": str(adapter),
        "adapter_sha256": sha256(adapter),
        "health": "passed",
    }


def parse_receipt(path: Path, task: Dict[str, object], gate: str, artifact_sha256: str, source: str, maximum_age: int) -> Dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != FIELDS or value.get("schema") != SCHEMA:
        raise SystemExit("human decision receipt schema or fields are invalid")
    if (
        value.get("gate") != gate
        or value.get("decision") != "approved"
        or value.get("artifact_sha256") != artifact_sha256
        or value.get("source") != source
        or value.get("task_title") != task.get("title")
        or value.get("task_mode") != task.get("mode")
        or value.get("routing_profile_sha256") != routing_profile_sha256(task)
        or value.get("authority") != "provider-signed-user-message"
        or not isinstance(value.get("decision_id"), str)
        or not str(value.get("decision_id")).strip()
        or HEX64.fullmatch(str(artifact_sha256)) is None
    ):
        raise SystemExit("human decision receipt does not bind the active gate, task and artifact")
    try:
        observed = dt.datetime.fromisoformat(str(value.get("observed_at", "")).replace("Z", "+00:00"))
    except ValueError:
        raise SystemExit("human decision observed_at must be ISO-8601")
    if observed.tzinfo is None:
        raise SystemExit("human decision observed_at must include a timezone")
    age = (dt.datetime.now(dt.timezone.utc) - observed.astimezone(dt.timezone.utc)).total_seconds()
    if age < -30 or (maximum_age > 0 and age > maximum_age):
        raise SystemExit("human decision receipt is stale or future-dated")
    return value


def verify(root: Path, config: Dict[str, object], task: Dict[str, object], *, gate: str, artifact_sha256: str, source: str, receipt: str, require_fresh: bool = True) -> Dict[str, object]:
    active_policy = policy(config)
    path = resolve_receipt(root, receipt)
    value = parse_receipt(
        path, task, gate, artifact_sha256, source,
        int(active_policy.get("max_receipt_age_seconds", 0)) if require_fresh else 0,
    )
    adapter = adapter_path(root, active_policy.get("signed_adapter"))
    digest = sha256(path)
    result = subprocess.run(
        [str(adapter), "verify", "--receipt", str(path)], cwd=str(root),
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
    )
    if result.returncode or result.stdout.strip() != f"VERIFIED HUMAN DECISION sha256={digest}":
        raise SystemExit("provider-owned human decision adapter rejected the receipt")
    return {
        "schema": SCHEMA,
        "path": str(path.relative_to(root.resolve())),
        "sha256": digest,
        "bytes": len(path.read_bytes()),
        "decision_id": value["decision_id"],
        "authority": value["authority"],
        "adapter_path": str(adapter),
        "adapter_sha256": sha256(adapter),
    }


def reverify(root: Path, config: Dict[str, object], task: Dict[str, object], *, gate: str, artifact_sha256: str, source: str, record: object) -> bool:
    if not isinstance(record, dict) or not isinstance(record.get("path"), str):
        return False
    try:
        return record == verify(
            root, config, task, gate=gate, artifact_sha256=artifact_sha256,
            source=source, receipt=str(record["path"]), require_fresh=False,
        )
    except (SystemExit, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return False


def record_decision_approval(
    root: Path, config: Dict[str, object], task: Dict[str, object], *,
    gate: str, artifact_sha256: str, source: str, receipt: Optional[str] = None,
) -> Dict[str, object]:
    """Record a fresh human decision under the task's stored decision policy.

    This is the single approval routing shared by every human gate: a task on
    the policy-v2 local boundary accepts a bound local user-message approval,
    while every other route requires a provider-signed receipt for the exact
    gate and artifact.  Returns the approval record to store alongside the
    artifact; raises SystemExit with an actionable message on any violation.
    """
    if task.get("decision_policy_version") == LOCAL_POLICY_VERSION:
        if receipt:
            raise SystemExit("local user-message approval does not accept an unaudited provider receipt")
        approval = local_approval(source, artifact_sha256, task)
        if not local_approval_valid(task, approval, source=source, artifact_sha256=artifact_sha256, config=config):
            raise SystemExit(
                f"local approval for gate {gate} is outside the current local decision boundary; "
                "re-approve the task under the active policy or configure a provider adapter"
            )
        return approval
    if not receipt:
        raise SystemExit(f"gate {gate} approval requires a provider-signed human decision receipt")
    return verify(root, config, task, gate=gate, artifact_sha256=artifact_sha256, source=source, receipt=receipt)


def decision_approval_valid(
    root: Path, config: Dict[str, object], task: Dict[str, object], *,
    gate: str, artifact_sha256: str, source: str, record: object,
) -> bool:
    """Re-validate a stored human-decision approval under the task's decision policy.

    Mirror of record_decision_approval for persisted records: policy-v2 local
    tasks re-check the local approval (including the routing-profile binding
    and retroactive config tightening for release mode), provider-routed tasks
    re-verify the signed receipt, and any other stored policy version fails
    closed.
    """
    version = task.get("decision_policy_version")
    if version == LOCAL_POLICY_VERSION:
        return local_approval_valid(task, record, source=source, artifact_sha256=artifact_sha256, config=config)
    if version == PROVIDER_POLICY_VERSION:
        return reverify(root, config, task, gate=gate, artifact_sha256=artifact_sha256, source=source, record=record)
    return False
