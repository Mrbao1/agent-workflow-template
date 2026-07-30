#!/usr/bin/env python3
"""Locked, digest-bound artifact promotion receipts for local, test and production."""

from pathlib import Path
import argparse
import datetime as dt
import fcntl
import fnmatch
import hashlib
import json
import os
import re
import tempfile
import subprocess
import sys
from typing import Dict, List, Optional

import humandecision


def find_agent_dir() -> Path:
    for root in (Path.cwd().resolve(), *Path.cwd().resolve().parents):
        if (root / ".agent").is_dir():
            return root / ".agent"
    raise SystemExit(".agent directory not found")


AGENT = find_agent_dir()
ROOT = AGENT.parent.resolve()
STATE = AGENT / "state" / "delivery.json"
NODE8 = AGENT / "state" / "artifacts" / "08-delivery.json"
TASK = AGENT / "state" / "TASK.json"
CONFIG = AGENT / "config.json"
CONTRACT = AGENT / "state" / "REQUIREMENT_CONTRACT.md"
LOCK = AGENT / "state" / ".delivery.lock"
DELIVERY_ARCHIVES = AGENT / "state" / "evidence" / "delivery-archives"
DELIVERY_RECEIPT_FIELDS = (
    "artifact", "test_receipt", "provider_preflight", "production_approval",
    "deployment_attempt", "promotion_receipt", "rollback_receipt", "legacy_production_chain",
)
DELIVERY_CHAIN_LIMIT = 256
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
PROVIDER_RECEIPT_SCHEMA = "provider-production-preflight/v1"
PROVIDER_RECORD_SCHEMA = "agent-provider-preflight-record/v1"
PROVIDER_RECEIPT_FIELDS = {
    "schema", "receipt_id", "authority", "provider", "repository", "default_branch",
    "effective_protection", "environments", "candidate", "candidate_revision",
    "default_branch_reachability", "required_check_runs", "test_summary", "observed_at",
}
PROVIDER_TARGET_FIELDS = {
    "schema", "provider", "repository", "default_branch", "test_environment",
    "production_environment", "required_status_checks", "min_required_reviewers",
}


def load(path: Path) -> Dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON object required: {path}")
    return value


def save(value: Dict[str, object], target: Path = STATE) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def canonical_sha256(value: object) -> Optional[str]:
    if value is None:
        return None
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def file_receipt(raw: str, label: str = "receipt file") -> Dict[str, object]:
    path = (ROOT / raw).resolve()
    try:
        relative = str(path.relative_to(ROOT))
    except ValueError:
        raise SystemExit(f"{label} escapes project")
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"{label} missing: {relative}")
    data = path.read_bytes()
    return {"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def valid_file_receipt(value: object) -> bool:
    if not isinstance(value, dict) or not {"path", "sha256", "bytes"}.issubset(value):
        return False
    path = (ROOT / str(value.get("path", ""))).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError:
        return False
    if not path.is_file() or path.is_symlink():
        return False
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest() == value.get("sha256") and len(data) == value.get("bytes")


def require_digest(raw: str, label: str) -> str:
    if not isinstance(raw, str) or not raw.startswith("sha256:") or not HEX64.fullmatch(raw[7:]):
        raise SystemExit(f"{label} must be sha256:<64 lowercase hex>")
    return raw


def branch_patterns(environment: str) -> List[str]:
    defaults = {
        "local": ["feature/*", "fix/*", "chore/*"],
        "test": ["develop", "test/*", "release/*"],
        "production": ["main"],
    }
    if not CONFIG.is_file():
        return defaults[environment]
    try:
        value = load(CONFIG).get("branches", {})
    except (OSError, ValueError, json.JSONDecodeError, SystemExit):
        return defaults[environment]
    patterns = value.get(environment) if isinstance(value, dict) else None
    return list(patterns) if isinstance(patterns, list) and all(isinstance(item, str) for item in patterns) else defaults[environment]


def branch_allowed(branch: str, environment: str) -> bool:
    return any(fnmatch.fnmatch(branch, pattern) for pattern in branch_patterns(environment))


def require_status(state: Dict[str, object], expected: str) -> None:
    if state.get("status") != expected:
        raise SystemExit(f"delivery transition requires status={expected}, observed={state.get('status')}")


def execution_gate(action: str) -> Dict[str, object]:
    task = load(TASK)
    source = task.get("requirement_source")
    requirement = task.get("gate_approvals", {}).get("requirement") if isinstance(task.get("gate_approvals"), dict) else None
    accepted = task.get("accepted_nodes", [])
    if task.get("requirements_clarified") is not True or not str(source or "").startswith("user:"):
        raise SystemExit("delivery is blocked until requirements are clarified and human-approved")
    if task.get("decision_policy_version") == 1:
        contract = AGENT / "state/REQUIREMENT_CONTRACT.md"
        contract_sha = hashlib.sha256(contract.read_bytes()).hexdigest() if contract.is_file() else ""
        if (
            not isinstance(requirement, dict)
            or requirement.get("artifact_sha256") != contract_sha
            or not humandecision.reverify(
                ROOT, load(CONFIG), task, gate="requirement", artifact_sha256=contract_sha,
                source=str(source), record=requirement.get("decision_receipt"),
            )
        ):
            raise SystemExit("delivery lacks a provider-signed human requirement decision")
    if not isinstance(accepted, list) or 7 not in accepted:
        raise SystemExit("delivery is blocked until full-chain acceptance has passed")
    result = subprocess.run(
        [sys.executable, str(AGENT / "scripts" / "agentctl.py"), "budget-gate", "--action", action],
        cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode:
        raise SystemExit(result.stdout.strip() or f"budget gate blocked {action}")
    return task


def production_provider_target(task: Dict[str, object]) -> Dict[str, object]:
    value = task.get("production_provider")
    if not isinstance(value, dict) or set(value) != PROVIDER_TARGET_FIELDS:
        raise SystemExit("production requires an approved production_provider target in TASK")
    checks = value.get("required_status_checks")
    reviewers = value.get("min_required_reviewers")
    if (
        value.get("schema") != "agent-production-provider-target/v1"
        or not all(str(value.get(key, "")).strip() for key in (
            "provider", "repository", "default_branch", "test_environment", "production_environment",
        ))
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", str(value.get("repository", "")))
        or not branch_allowed(str(value.get("default_branch", "")), "production")
        or not isinstance(checks, list) or not checks
        or len(set(checks)) != len(checks)
        or not all(isinstance(item, str) and item.strip() for item in checks)
        or not isinstance(reviewers, int) or isinstance(reviewers, bool) or reviewers < 1 or reviewers > 20
    ):
        raise SystemExit("production_provider target is malformed or weaker than the production contract")
    if not CONTRACT.is_file() or CONTRACT.is_symlink():
        raise SystemExit("production provider target requires the approved requirement contract")
    contract_bytes = CONTRACT.read_bytes()
    if hashlib.sha256(contract_bytes).hexdigest() != task.get("requirement_contract_sha256"):
        raise SystemExit("production provider target is not bound to the approved requirement contract")
    prefix = "- Production provider target: "
    canonical_target = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    matches = [line for line in contract_bytes.decode("utf-8").splitlines() if line.startswith(prefix)]
    if matches != [prefix + canonical_target]:
        raise SystemExit("approved requirement contract must contain one exact canonical production provider target")
    return value


def candidate_summary(artifact: Dict[str, object]) -> Dict[str, object]:
    return {
        "digest": artifact.get("digest"),
        "source_branch": artifact.get("source_branch"),
        "source_revision": artifact.get("source_revision"),
        "build_run_id": artifact.get("build_run_id"),
    }


def test_summary(test: Dict[str, object]) -> Dict[str, object]:
    runner = test.get("runner") if isinstance(test.get("runner"), dict) else {}
    evidence = test.get("evidence") if isinstance(test.get("evidence"), dict) else {}
    return {
        "digest": test.get("digest"),
        "source_revision": test.get("source_revision"),
        "build_run_id": test.get("build_run_id"),
        "run_id": test.get("run_id"),
        "result": test.get("result"),
        "branch": test.get("branch"),
        "runner_sha256": runner.get("sha256"),
        "evidence_sha256": evidence.get("sha256"),
    }


def provider_observer_policy() -> Dict[str, object]:
    config = load(CONFIG)
    control = config.get("agent_control")
    observer = control.get("provider_preflight_observer") if isinstance(control, dict) else None
    expected = {
        "source", "automatic_release_trust", "provider_verification_required",
        "signed_adapter", "max_receipt_age_seconds",
    }
    if (
        not isinstance(observer, dict) or set(observer) != expected
        or observer.get("source") != "provider-read-only-api"
        or observer.get("automatic_release_trust") is not False
        or observer.get("provider_verification_required") is not True
        or observer.get("max_receipt_age_seconds") != 300
    ):
        raise SystemExit("provider preflight observer policy is missing or weakens fail-closed defaults")
    return observer


def provider_adapter_path() -> Path:
    observer = provider_observer_policy()
    try:
        adapter = humandecision.adapter_path(ROOT, observer.get("signed_adapter"))
    except SystemExit as error:
        raise SystemExit("production preflight requires an OS-protected host provider adapter") from error
    if adapter.name.lower() in {
        "bash", "sh", "zsh", "fish", "env", "python", "python3", "node", "perl", "ruby", "php",
    }:
        raise SystemExit("provider preflight adapter must be a dedicated verifier, not a generic interpreter")
    return adapter


def provider_receipt_file(raw: str) -> tuple[Path, Dict[str, object]]:
    path = (ROOT / raw).resolve()
    boundary = (AGENT / "state" / "evidence" / "provider-preflight").resolve()
    try:
        relative = str(path.relative_to(ROOT))
        path.relative_to(boundary)
    except ValueError:
        raise SystemExit("provider preflight receipt escapes its evidence boundary")
    if not path.is_file() or path.is_symlink():
        raise SystemExit("provider preflight receipt is missing or is a symlink")
    data = path.read_bytes()
    return path, {"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def parse_provider_preflight(
    value: object, task: Dict[str, object], artifact: Dict[str, object], test: Dict[str, object],
    *, require_fresh: bool,
) -> Dict[str, object]:
    target = production_provider_target(task)
    if not isinstance(value, dict) or set(value) != PROVIDER_RECEIPT_FIELDS:
        raise SystemExit("provider preflight receipt schema or fields are invalid")
    protection = value.get("effective_protection")
    environments = value.get("environments")
    test_environment = environments.get("test") if isinstance(environments, dict) else None
    production_environment = environments.get("production") if isinstance(environments, dict) else None
    reachability = value.get("default_branch_reachability")
    check_runs = value.get("required_check_runs")
    required_checks = protection.get("required_status_checks") if isinstance(protection, dict) else None
    reviews = protection.get("pull_request_reviews") if isinstance(protection, dict) else None
    required_reviewers = production_environment.get("required_reviewers") if isinstance(production_environment, dict) else None
    if (
        value.get("schema") != PROVIDER_RECEIPT_SCHEMA
        or value.get("authority") != "provider-signed-read-only-observer"
        or not isinstance(value.get("receipt_id"), str) or not str(value.get("receipt_id", "")).strip()
        or value.get("provider") != target.get("provider")
        or value.get("repository") != target.get("repository")
        or value.get("default_branch") != target.get("default_branch")
        or value.get("candidate_revision") != artifact.get("source_revision")
        or not isinstance(reachability, dict)
        or set(reachability) != {
            "branch", "candidate_revision", "relation", "verified", "evidence_url", "evidence_sha256",
        }
        or reachability.get("branch") != target.get("default_branch")
        or reachability.get("candidate_revision") != artifact.get("source_revision")
        or reachability.get("relation") not in {"head", "merge-commit"}
        or reachability.get("verified") is not True
        or not re.fullmatch(r"https://[^\s]+", str(reachability.get("evidence_url", "")))
        or not HEX64.fullmatch(str(reachability.get("evidence_sha256", "")))
        or not isinstance(check_runs, list) or not check_runs
        or len({item.get("name") for item in check_runs if isinstance(item, dict)}) != len(check_runs)
        or len({item.get("run_id") for item in check_runs if isinstance(item, dict)}) != len(check_runs)
        or not set(target["required_status_checks"]).issubset({
            item.get("name") for item in check_runs if isinstance(item, dict)
        })
        or any(
            not isinstance(item, dict)
            or set(item) != {"name", "commit_sha", "status", "conclusion", "run_id", "url", "evidence_sha256"}
            or not isinstance(item.get("name"), str) or not item.get("name", "").strip()
            or item.get("commit_sha") != artifact.get("source_revision")
            or item.get("status") != "completed" or item.get("conclusion") != "success"
            or not RUN_ID.fullmatch(str(item.get("run_id", "")))
            or not re.fullmatch(r"https://[^\s]+", str(item.get("url", "")))
            or not HEX64.fullmatch(str(item.get("evidence_sha256", "")))
            for item in check_runs
        )
        or not isinstance(protection, dict)
        or set(protection) != {
            "source", "enforced", "required_status_checks", "pull_request_reviews",
            "force_push_allowed", "deletion_allowed",
        }
        or protection.get("source") not in {"branch-protection", "ruleset"}
        or protection.get("enforced") is not True
        or not isinstance(required_checks, list)
        or not set(target["required_status_checks"]).issubset(required_checks)
        or len(set(required_checks)) != len(required_checks)
        or not all(isinstance(item, str) and item.strip() for item in required_checks)
        or not isinstance(reviews, dict)
        or set(reviews) != {"required", "required_approving_review_count"}
        or reviews.get("required") is not True
        or not isinstance(reviews.get("required_approving_review_count"), int)
        or isinstance(reviews.get("required_approving_review_count"), bool)
        or reviews.get("required_approving_review_count", 0) < target["min_required_reviewers"]
        or protection.get("force_push_allowed") is not False
        or protection.get("deletion_allowed") is not False
        or not isinstance(environments, dict) or set(environments) != {"test", "production"}
        or not isinstance(test_environment, dict) or set(test_environment) != {"name"}
        or test_environment.get("name") != target.get("test_environment")
        or not isinstance(production_environment, dict)
        or set(production_environment) != {"name", "required_reviewers", "prevent_self_review"}
        or production_environment.get("name") != target.get("production_environment")
        or production_environment.get("prevent_self_review") is not True
        or not isinstance(required_reviewers, list)
        or len(required_reviewers) < target["min_required_reviewers"]
        or len(set(required_reviewers)) != len(required_reviewers)
        or not all(isinstance(item, str) and item.strip() for item in required_reviewers)
        or value.get("candidate") != candidate_summary(artifact)
        or value.get("test_summary") != test_summary(test)
    ):
        raise SystemExit("provider preflight does not prove the approved repository, controls, environments and current candidate")
    try:
        observed = dt.datetime.fromisoformat(str(value.get("observed_at", "")).replace("Z", "+00:00"))
    except ValueError:
        raise SystemExit("provider preflight observed_at must be ISO-8601")
    if observed.tzinfo is None:
        raise SystemExit("provider preflight observed_at must include a timezone")
    age = (dt.datetime.now(dt.timezone.utc) - observed.astimezone(dt.timezone.utc)).total_seconds()
    maximum_age = int(provider_observer_policy().get("max_receipt_age_seconds", 0))
    if age < -30 or (require_fresh and age > maximum_age):
        raise SystemExit("provider preflight receipt is stale or future-dated")
    return value


def verify_provider_preflight(
    raw: str, task: Dict[str, object], artifact: Dict[str, object], test: Dict[str, object],
    *, require_fresh: bool = True,
) -> Dict[str, object]:
    if (
        not valid_file_receipt(artifact)
        or artifact.get("digest") != test.get("digest")
        or test.get("result") != "passed"
        or not valid_file_receipt(test.get("runner"))
        or not valid_file_receipt(test.get("evidence"))
    ):
        raise SystemExit("provider preflight requires the current byte-valid artifact and test evidence")
    path, receipt = provider_receipt_file(raw)
    value = parse_provider_preflight(load(path), task, artifact, test, require_fresh=require_fresh)
    adapter = provider_adapter_path()
    result = subprocess.run(
        [str(adapter), "verify-provider-preflight", "--receipt", str(path)],
        cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
    )
    if result.returncode or result.stdout.strip() != f"VERIFIED PROVIDER PREFLIGHT sha256={receipt['sha256']}":
        raise SystemExit("host provider adapter rejected the production preflight receipt")
    return {
        "schema": PROVIDER_RECORD_SCHEMA,
        **receipt,
        "receipt_id": value["receipt_id"],
        "authority": value["authority"],
        "provider": value["provider"],
        "repository": value["repository"],
        "default_branch": value["default_branch"],
        "observed_at": value["observed_at"],
        "candidate_sha256": canonical_sha256(value["candidate"]),
        "test_summary_sha256": canonical_sha256(value["test_summary"]),
        "adapter_path": str(adapter),
        "adapter_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
    }


def reverify_provider_preflight(
    record: object, task: Dict[str, object], artifact: Dict[str, object], test: Dict[str, object],
    *, require_fresh: bool,
) -> bool:
    if not isinstance(record, dict) or set(record) != {
        "schema", "path", "sha256", "bytes", "receipt_id", "authority", "provider",
        "repository", "default_branch", "observed_at", "candidate_sha256",
        "test_summary_sha256", "adapter_path", "adapter_sha256",
    }:
        return False
    try:
        expected = verify_provider_preflight(
            str(record.get("path", "")), task, artifact, test, require_fresh=require_fresh,
        )
    except (SystemExit, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return False
    return expected == record


def deployment_decision_packet(
    task: Dict[str, object], artifact: Dict[str, object], test: Dict[str, object], provider: Dict[str, object],
) -> Dict[str, object]:
    target = production_provider_target(task)
    return {
        "schema": "agent-production-deployment-decision/v1",
        "artifact_digest": artifact.get("digest"),
        "candidate_revision": artifact.get("source_revision"),
        "candidate_sha256": canonical_sha256(candidate_summary(artifact)),
        "provider": target.get("provider"),
        "repository": target.get("repository"),
        "default_branch": target.get("default_branch"),
        "production_environment": target.get("production_environment"),
        "provider_preflight_sha256": provider.get("sha256"),
        "test_summary_sha256": canonical_sha256(test_summary(test)),
    }


def current_delivery_bytes() -> Optional[bytes]:
    """Exact current delivery.json bytes for task-archive inclusion.

    Exported for `agentctl.py build_task_archive` (another workstream): bind
    the returned bytes with sha256 in the task-archive head. Returns None
    when no delivery state exists yet. Read-only.
    """
    if not STATE.is_file() or STATE.is_symlink():
        return None
    return STATE.read_bytes()


def delivery_state_empty(value: object) -> bool:
    """True when a reset loses nothing: no receipts and a pre-artifact status."""
    return (
        isinstance(value, dict)
        and value.get("status") in {"not_requested", "awaiting_artifact"}
        and all(value.get(field) is None for field in DELIVERY_RECEIPT_FIELDS)
    )


def archive_delivery_state(raw: bytes) -> Dict[str, object]:
    """Content-address the exact prior delivery.json bytes into evidence."""
    value_sha = hashlib.sha256(raw).hexdigest()
    DELIVERY_ARCHIVES.mkdir(parents=True, exist_ok=True)
    target = DELIVERY_ARCHIVES / f"{value_sha}.json"
    if target.exists():
        if target.is_symlink() or target.read_bytes() != raw:
            raise SystemExit("delivery state archive digest collision")
    else:
        descriptor, temp_raw = tempfile.mkstemp(prefix=".delivery-archive.", dir=str(DELIVERY_ARCHIVES))
        temporary = Path(temp_raw)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(raw); output.flush(); os.fsync(output.fileno())
            os.replace(temporary, target); target.chmod(0o444)
        finally:
            if temporary.exists():
                temporary.unlink()
    return {"path": str(target.relative_to(ROOT)), "sha256": value_sha, "bytes": len(raw)}


def delivery_chain_errors(state: Dict[str, object]) -> List[str]:
    """Verify the epoch/previous_head hash chain across `init` resets.

    Every reset of a non-empty state archives the exact prior bytes under
    evidence/delivery-archives/ and links the fresh state to that receipt.
    Legacy states (neither epoch nor previous_head) predate the chain and
    are accepted as chain-terminal.
    """
    epoch = state.get("epoch")
    head = state.get("previous_head")
    if epoch is None and head is None:
        return []
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        return ["delivery epoch is invalid"]
    errors: List[str] = []
    seen = set()
    current_epoch = epoch
    depth = 0
    while head is not None:
        depth += 1
        if depth > DELIVERY_CHAIN_LIMIT:
            errors.append("delivery archive chain exceeds its depth bound")
            break
        if not isinstance(head, dict) or set(head) != {"path", "sha256", "bytes"}:
            errors.append("delivery archive head fields are invalid")
            break
        value_sha = str(head.get("sha256", ""))
        expected = DELIVERY_ARCHIVES / f"{value_sha}.json"
        path = (ROOT / str(head.get("path", ""))).resolve()
        if (
            not HEX64.fullmatch(value_sha) or path != expected.resolve()
            or not isinstance(head.get("bytes"), int) or head["bytes"] < 1
            or value_sha in seen or not path.is_file() or path.is_symlink()
        ):
            errors.append("delivery archive head is invalid or missing")
            break
        seen.add(value_sha)
        data = path.read_bytes()
        if len(data) != head["bytes"] or hashlib.sha256(data).hexdigest() != value_sha:
            errors.append("delivery archive bytes drifted")
            break
        try:
            archived = json.loads(data)
        except (ValueError, json.JSONDecodeError):
            archived = None
        if not isinstance(archived, dict) or archived.get("schema") not in {"agent-delivery/v2", "agent-delivery/v3"}:
            errors.append("delivery archive content is not a delivery state")
            break
        archived_epoch = archived.get("epoch")
        if archived_epoch is None and archived.get("previous_head") is None:
            archived_epoch = 1  # legacy archived state predating the chain
        if archived_epoch != current_epoch - 1:
            errors.append("delivery archive chain is not continuous across resets")
            break
        current_epoch -= 1
        head = archived.get("previous_head")
    if head is None and current_epoch != 1 and not errors:
        errors.append("delivery archive chain does not terminate at the first epoch")
    return errors


def command_init(_: argparse.Namespace) -> int:
    task = load(TASK)
    status = "awaiting_artifact" if task.get("deployment_requested") else "not_requested"
    epoch, previous_head = 1, None
    if STATE.is_file() and not STATE.is_symlink():
        raw = STATE.read_bytes()
        try:
            current = json.loads(raw)
        except (ValueError, json.JSONDecodeError):
            current = None
        old_epoch = current.get("epoch") if isinstance(current, dict) else None
        if not isinstance(old_epoch, int) or isinstance(old_epoch, bool) or old_epoch < 1:
            old_epoch = 1
        if delivery_state_empty(current):
            # Empty/fresh states carry no receipts worth archiving; keep the
            # established chain so a later archival still links across resets.
            epoch = old_epoch
            head = current.get("previous_head") if isinstance(current, dict) else None
            previous_head = head if isinstance(head, dict) else None
        else:
            # A non-empty delivery state is audit evidence: archive its exact
            # bytes BEFORE resetting, and refuse to reset when archival fails.
            previous_head = archive_delivery_state(raw)
            epoch = old_epoch + 1
    save({
        "schema": "agent-delivery/v3",
        "environment": task.get("environment"),
        "deployment_requested": task.get("deployment_requested"),
        "status": status,
        "artifact": None,
        "test_receipt": None,
        "provider_preflight": None,
        "production_approval": None,
        "deployment_attempt": None,
        "promotion_receipt": None,
        "rollback_receipt": None,
        "legacy_production_chain": None,
        "epoch": epoch,
        "previous_head": previous_head,
        "updated_at": timestamp(),
    })
    print(f"DELIVERY INITIALIZED: {status}")
    return 0


def command_artifact(args: argparse.Namespace) -> int:
    execution_gate("delivery")
    state = load(STATE)
    require_status(state, "awaiting_artifact")
    digest = require_digest(args.digest, "artifact digest")
    receipt = file_receipt(args.path, "artifact")
    if digest != "sha256:" + str(receipt["sha256"]):
        raise SystemExit("artifact digest must equal the recorded artifact bytes")
    if not args.built_by or not RUN_ID.fullmatch(args.build_run_id) or not REVISION.fullmatch(args.source_revision):
        raise SystemExit("artifact requires builder, source revision and build run ID provenance")
    if not (branch_allowed(args.source_branch, "test") or branch_allowed(args.source_branch, "production")):
        raise SystemExit("artifact source branch is not an allowed test or production branch")
    receipt.update({
        "digest": digest,
        "built_by": args.built_by,
        "source_branch": args.source_branch,
        "source_revision": args.source_revision,
        "build_run_id": args.build_run_id,
        "recorded_at": timestamp(),
    })
    state.update({"artifact": receipt, "status": "awaiting_test", "updated_at": timestamp()})
    save(state)
    print("ARTIFACT RECORDED")
    return 0


def command_test(args: argparse.Namespace) -> int:
    execution_gate("delivery")
    state = load(STATE)
    require_status(state, "awaiting_test")
    artifact = state.get("artifact")
    if not isinstance(artifact, dict) or artifact.get("digest") != require_digest(args.digest, "test digest"):
        raise SystemExit("test receipt must bind the recorded artifact digest")
    if args.result != "passed" or args.tested_environment != "test":
        raise SystemExit("only an independently passed test-environment receipt can advance delivery")
    if not args.branch or not branch_allowed(args.branch, "test"):
        raise SystemExit("test receipt branch does not match configured test branch patterns")
    if not RUN_ID.fullmatch(args.run_id):
        raise SystemExit("test receipt has an invalid run ID")
    reviewer = args.reviewer.strip()
    if not reviewer or reviewer.startswith(("implementer:", "self:", "agent:self")) or reviewer == artifact.get("built_by"):
        raise SystemExit("test receipt requires an independent reviewer identity")
    runner = file_receipt(args.runner, "test runner")
    evidence = file_receipt(args.evidence, "test evidence")
    test_receipt = {
        "schema": "agent-delivery-test-receipt/v1",
        "digest": args.digest,
        "result": "passed",
        "tested_environment": "test",
        "branch": args.branch,
        "source_revision": artifact.get("source_revision"),
        "build_run_id": artifact.get("build_run_id"),
        "run_id": args.run_id,
        "reviewer": reviewer,
        "runner": runner,
        "evidence": evidence,
        "recorded_at": timestamp(),
    }
    status = "awaiting_provider_preflight" if state.get("environment") == "production" else "ready_to_promote"
    state.update({"test_receipt": test_receipt, "status": status, "updated_at": timestamp()})
    save(state)
    print("TEST RECEIPT ACCEPTED")
    return 0


def command_provider_preflight(args: argparse.Namespace) -> int:
    task = execution_gate("delivery")
    state = load(STATE)
    require_status(state, "awaiting_provider_preflight")
    if state.get("environment") != "production":
        raise SystemExit("provider preflight is a production-only transition")
    artifact, test = state.get("artifact"), state.get("test_receipt")
    if not isinstance(artifact, dict) or not isinstance(test, dict):
        raise SystemExit("provider preflight requires the exact tested candidate")
    record = verify_provider_preflight(args.receipt, task, artifact, test, require_fresh=True)
    state.update({
        "provider_preflight": record,
        "status": "awaiting_production_approval",
        "updated_at": timestamp(),
    })
    save(state)
    print("PROVIDER PREFLIGHT ACCEPTED")
    return 0


def command_approve(args: argparse.Namespace) -> int:
    task = execution_gate("request-decision")
    if not args.source.startswith("user:"):
        raise SystemExit("production approval source must start with user:")
    state = load(STATE)
    require_status(state, "awaiting_production_approval")
    if state.get("environment") != "production" or not state.get("test_receipt"):
        raise SystemExit("production approval requires a production target and passed test receipt")
    artifact, test, provider = state.get("artifact"), state.get("test_receipt"), state.get("provider_preflight")
    if (
        not isinstance(artifact, dict) or not isinstance(test, dict)
        or not reverify_provider_preflight(provider, task, artifact, test, require_fresh=True)
    ):
        raise SystemExit("production approval requires a fresh provider-owned preflight for the tested candidate")
    decision_receipt = None
    decision_packet = deployment_decision_packet(task, artifact, test, provider)
    decision_packet_sha256 = canonical_sha256(decision_packet)
    if task.get("decision_policy_version") == 1:
        if not args.human_decision_receipt:
            raise SystemExit("production approval requires a provider-signed human decision receipt")
        decision_receipt = humandecision.verify(
            ROOT, load(CONFIG), task, gate="production-delivery",
            artifact_sha256=decision_packet_sha256, source=args.source,
            receipt=args.human_decision_receipt,
        )
    state.update({
        "production_approval": {
            "source": args.source,
            "digest": artifact["digest"],
            "test_run_id": test["run_id"],
            "candidate_sha256": canonical_sha256(candidate_summary(artifact)),
            "test_summary_sha256": canonical_sha256(test_summary(test)),
            "provider_preflight_sha256": provider["sha256"],
            "decision_packet": decision_packet,
            "decision_packet_sha256": decision_packet_sha256,
            "decision_receipt": decision_receipt,
            "recorded_at": timestamp(),
        },
        "status": "ready_to_promote",
        "updated_at": timestamp(),
    })
    save(state)
    print("PRODUCTION APPROVED")
    return 0


def command_promote(args: argparse.Namespace) -> int:
    execution_gate("delivery")
    state = load(STATE)
    require_status(state, "ready_to_promote")
    artifact, test = state.get("artifact"), state.get("test_receipt")
    digest = require_digest(args.digest, "promotion digest")
    if not isinstance(artifact, dict) or not isinstance(test, dict) or artifact.get("digest") != test.get("digest") or digest != artifact.get("digest"):
        raise SystemExit("promotion digest differs from the independently tested digest")
    if state.get("environment") == "production":
        approval = state.get("production_approval")
        provider = state.get("provider_preflight")
        task = load(TASK)
        expected_packet = deployment_decision_packet(task, artifact, test, provider) if isinstance(provider, dict) else None
        signed_decision_valid = task.get("decision_policy_version") != 1
        if task.get("decision_policy_version") == 1 and isinstance(approval, dict) and expected_packet is not None:
            signed_decision_valid = humandecision.reverify(
                ROOT, load(CONFIG), task, gate="production-delivery",
                artifact_sha256=str(canonical_sha256(expected_packet)),
                source=str(approval.get("source", "")), record=approval.get("decision_receipt"),
            )
        if (
            not isinstance(approval, dict) or approval.get("digest") != digest
            or not str(approval.get("source", "")).startswith("user:")
            or not reverify_provider_preflight(provider, task, artifact, test, require_fresh=True)
            or approval.get("provider_preflight_sha256") != provider.get("sha256")
            or approval.get("candidate_sha256") != canonical_sha256(candidate_summary(artifact))
            or approval.get("test_summary_sha256") != canonical_sha256(test_summary(test))
            or approval.get("decision_packet") != expected_packet
            or approval.get("decision_packet_sha256") != canonical_sha256(expected_packet)
            or not signed_decision_valid
        ):
            raise SystemExit("production promotion requires digest-bound human approval")
    evidence = file_receipt(args.evidence, "deployment evidence")
    attempt = {
        "schema": "agent-deployment-attempt/v1",
        "digest": digest,
        "environment": state.get("environment"),
        "source_revision": artifact.get("source_revision"),
        "build_run_id": artifact.get("build_run_id"),
        "test_run_id": test.get("run_id"),
        "result": args.result,
        "evidence": evidence,
        "recorded_at": timestamp(),
    }
    state["deployment_attempt"] = attempt
    if args.result == "passed":
        state["promotion_receipt"] = {
            "schema": "agent-promotion-receipt/v1",
            "digest": digest,
            "environment": state.get("environment"),
            "source_revision": artifact.get("source_revision"),
            "deployment_attempt_sha256": hashlib.sha256(json.dumps(attempt, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "evidence": evidence,
            "recorded_at": timestamp(),
        }
        state["status"] = "promoted"
        print("ARTIFACT PROMOTED")
    else:
        state["status"] = "rollback_required"
        print("DEPLOYMENT FAILED: ROLLBACK REQUIRED")
    state["updated_at"] = timestamp()
    save(state)
    return 0 if args.result == "passed" else 2


def command_rollback(args: argparse.Namespace) -> int:
    execution_gate("rollback")
    state = load(STATE)
    if state.get("status") not in {"promoted", "rollback_required"}:
        raise SystemExit("rollback requires a promoted or failed-deployment state")
    artifact = state.get("artifact")
    if not isinstance(artifact, dict) or args.failed_digest != artifact.get("digest"):
        raise SystemExit("rollback must bind the attempted artifact digest")
    restored_digest = require_digest(args.restored_digest, "restored digest")
    restored = file_receipt(args.restored_artifact, "restored artifact")
    if restored_digest != "sha256:" + str(restored["sha256"]):
        raise SystemExit("restored digest must equal the restored artifact bytes")
    rollback = {
        "schema": "agent-rollback-receipt/v1",
        "reason": args.reason,
        "failed_digest": args.failed_digest,
        "restored_digest": restored_digest,
        "restored_artifact": restored,
        "rollback_evidence": file_receipt(args.evidence, "rollback evidence"),
        "health_evidence": file_receipt(args.health_evidence, "restored health evidence"),
        "deployment_attempt": state.get("deployment_attempt"),
        "recorded_at": timestamp(),
    }
    state.update({"rollback_receipt": rollback, "status": "rolled_back", "updated_at": timestamp()})
    save(state)
    print("ROLLBACK RECORDED")
    return 0


def command_legacy_rollback_closure(args: argparse.Namespace) -> int:
    """Record externally completed recovery for a migrated v2 failed deployment."""
    task = execution_gate("rollback")
    if not args.source.startswith("user:"):
        raise SystemExit("legacy rollback closure requires an explicit user decision source")
    state = load(STATE)
    require_status(state, "legacy_rollback_required")
    artifact = state.get("artifact")
    legacy = state.get("legacy_production_chain")
    if (
        not isinstance(artifact, dict) or args.failed_digest != artifact.get("digest")
        or not isinstance(legacy, dict) or legacy.get("previous_status") != "rollback_required"
        or legacy.get("rollback_closure") is not None
    ):
        raise SystemExit("legacy rollback closure must bind the archived failed production attempt")
    restored_digest = require_digest(args.restored_digest, "restored digest")
    restored = file_receipt(args.restored_artifact, "restored artifact")
    if restored_digest != "sha256:" + str(restored["sha256"]):
        raise SystemExit("restored digest must equal the restored artifact bytes")
    rollback_evidence = file_receipt(args.evidence, "legacy rollback evidence")
    health_evidence = file_receipt(args.health_evidence, "legacy restored health evidence")
    packet = {
        "schema": "agent-legacy-rollback-decision/v1",
        "reason": args.reason,
        "legacy_archive_sha256": legacy.get("archive", {}).get("sha256") if isinstance(legacy.get("archive"), dict) else None,
        "failed_digest": args.failed_digest,
        "restored_digest": restored_digest,
        "restored_artifact_sha256": restored.get("sha256"),
        "rollback_evidence_sha256": rollback_evidence.get("sha256"),
        "health_evidence_sha256": health_evidence.get("sha256"),
    }
    packet_sha256 = canonical_sha256(packet)
    decision_receipt = None
    if task.get("decision_policy_version") == 1:
        if not args.human_decision_receipt:
            raise SystemExit("legacy rollback closure requires a provider-signed human decision receipt")
        decision_receipt = humandecision.verify(
            ROOT, load(CONFIG), task, gate="legacy-rollback-closure",
            artifact_sha256=str(packet_sha256), source=args.source, receipt=args.human_decision_receipt,
        )
    legacy["rollback_closure"] = {
        "schema": "agent-legacy-rollback-closure/v1",
        "source": args.source,
        "reason": args.reason,
        "failed_digest": args.failed_digest,
        "restored_digest": restored_digest,
        "restored_artifact": restored,
        "rollback_evidence": rollback_evidence,
        "health_evidence": health_evidence,
        "decision_packet": packet,
        "decision_packet_sha256": packet_sha256,
        "decision_receipt": decision_receipt,
        "recorded_at": timestamp(),
    }
    state.update({"legacy_production_chain": legacy, "status": "legacy_rolled_back", "updated_at": timestamp()})
    save(state)
    print("LEGACY ROLLBACK CLOSURE RECORDED")
    return 0


def command_validate(_: argparse.Namespace) -> int:
    task, state = load(TASK), load(STATE)
    errors: List[str] = []
    if state.get("schema") != "agent-delivery/v3":
        errors.append("invalid schema")
    base_fields = {
        "schema", "environment", "deployment_requested", "status", "artifact", "test_receipt",
        "provider_preflight", "production_approval", "deployment_attempt", "promotion_receipt",
        "rollback_receipt", "legacy_production_chain", "updated_at",
    }
    if set(state) not in (base_fields, base_fields | {"epoch", "previous_head"}):
        errors.append("delivery state fields are invalid")
    errors.extend(delivery_chain_errors(state))
    if state.get("environment") != task.get("environment") or state.get("deployment_requested") != task.get("deployment_requested"):
        errors.append("delivery state differs from task target")
    allowed = {
        "not_requested", "awaiting_artifact", "awaiting_test", "awaiting_provider_preflight",
        "awaiting_production_approval", "ready_to_promote", "promoted", "rollback_required", "rolled_back",
        "legacy_promoted", "legacy_rollback_required", "legacy_rolled_back",
    }
    status = state.get("status")
    if status not in allowed:
        errors.append("unknown delivery status")
    artifact = state.get("artifact")
    test = state.get("test_receipt")
    provider = state.get("provider_preflight")
    approval = state.get("production_approval")
    attempt = state.get("deployment_attempt")
    promotion = state.get("promotion_receipt")
    rollback = state.get("rollback_receipt")
    legacy = state.get("legacy_production_chain")
    if not task.get("deployment_requested"):
        if status != "not_requested" or any(item is not None for item in (artifact, test, provider, approval, attempt, promotion, rollback, legacy)):
            errors.append("non-deployment task must stay receipt-free and not_requested")
    elif status == "awaiting_artifact" and any(item is not None for item in (artifact, test, provider, approval, attempt, promotion, rollback)):
        errors.append("awaiting_artifact must not contain receipts")
    if status == "awaiting_test" and (not artifact or any(item is not None for item in (test, provider, approval, attempt, promotion, rollback))):
        errors.append("awaiting_test requires only an artifact")
    if status == "awaiting_provider_preflight" and (
        state.get("environment") != "production" or not artifact or not test
        or any(item is not None for item in (provider, approval, attempt, promotion, rollback))
    ):
        errors.append("awaiting_provider_preflight requires only the tested production candidate")
    if status == "awaiting_production_approval" and (
        state.get("environment") != "production" or not artifact or not test or not provider
        or any(item is not None for item in (approval, attempt, promotion, rollback))
    ):
        errors.append("awaiting_production_approval requires a provider-preflighted tested candidate")
    if status == "ready_to_promote" and (not artifact or not test or attempt is not None or promotion is not None or rollback is not None):
        errors.append("ready_to_promote requires an undeployed tested candidate")
    if status == "ready_to_promote" and state.get("environment") == "production" and (not provider or not approval):
        errors.append("production ready_to_promote requires provider preflight and human approval")
    if status == "ready_to_promote" and state.get("environment") != "production" and (provider is not None or approval is not None):
        errors.append("non-production ready_to_promote must not contain production gates")
    if status == "promoted" and (not artifact or not test or not attempt or not promotion or rollback is not None):
        errors.append("promoted state lacks its complete attestation chain")
    if status == "rollback_required" and (not artifact or not test or not attempt or promotion is not None or rollback is not None):
        errors.append("rollback_required must retain the failed attempt without a success receipt")
    if status == "rolled_back" and (not artifact or not test or not attempt or not rollback):
        errors.append("rolled_back state lacks artifact, test, attempt or rollback evidence")
    if status in {"legacy_promoted", "legacy_rollback_required", "legacy_rolled_back"} and (
        state.get("environment") != "production" or not artifact or not test
        or any(item is not None for item in (provider, approval, attempt, promotion, rollback))
        or not legacy
    ):
        errors.append("legacy production history must be archived and operationally receipt-free")
    if isinstance(artifact, dict):
        if not valid_file_receipt(artifact) or artifact.get("digest") != "sha256:" + str(artifact.get("sha256", "")):
            errors.append("artifact bytes/digest drifted")
        if (
            not str(artifact.get("built_by", "")).strip()
            or not (
                branch_allowed(str(artifact.get("source_branch", "")), "test")
                or branch_allowed(str(artifact.get("source_branch", "")), "production")
            )
            or not REVISION.fullmatch(str(artifact.get("source_revision", "")))
            or not RUN_ID.fullmatch(str(artifact.get("build_run_id", "")))
        ):
            errors.append("artifact source/build provenance is invalid")
    if isinstance(test, dict):
        if test.get("schema") != "agent-delivery-test-receipt/v1" or test.get("result") != "passed" or test.get("tested_environment") != "test":
            errors.append("test receipt schema/result/environment is invalid")
        if not branch_allowed(str(test.get("branch", "")), "test") or not valid_file_receipt(test.get("runner")) or not valid_file_receipt(test.get("evidence")):
            errors.append("test branch, runner or evidence drifted")
        if isinstance(artifact, dict) and any(test.get(key) != artifact.get(key) for key in ("digest", "source_revision", "build_run_id")):
            errors.append("test receipt is not bound to the built artifact")
    if isinstance(provider, dict):
        if (
            state.get("environment") != "production"
            or not isinstance(artifact, dict) or not isinstance(test, dict)
            or not reverify_provider_preflight(
                provider, task, artifact, test,
                require_fresh=status in {"awaiting_production_approval", "ready_to_promote"},
            )
        ):
            errors.append("provider preflight authority, content, freshness or candidate binding is invalid")
    elif state.get("environment") == "production" and status in {
        "awaiting_production_approval", "ready_to_promote", "promoted", "rollback_required", "rolled_back",
    }:
        errors.append("production state lacks its provider-owned preflight")
    if legacy is not None:
        archive = legacy.get("archive") if isinstance(legacy, dict) else None
        if (
            state.get("environment") != "production"
            or not isinstance(legacy, dict)
            or set(legacy) != {
                "schema", "previous_status", "assurance", "reusable_as_release_receipt", "archive",
                "node8_archive", "rollback_closure",
            }
            or legacy.get("schema") != "agent-delivery-migration-archive/v1"
            or legacy.get("previous_status") not in {"ready_to_promote", "promoted", "rollback_required", "rolled_back"}
            or legacy.get("assurance") != "legacy"
            or legacy.get("reusable_as_release_receipt") is not False
            or not valid_file_receipt(archive)
            or (legacy.get("node8_archive") is not None and not valid_file_receipt(legacy.get("node8_archive")))
        ):
            errors.append("legacy production delivery chain archive is invalid")
        elif isinstance(archive, dict):
            try:
                archived = load(ROOT / str(archive.get("path", "")))
            except (OSError, ValueError, json.JSONDecodeError, SystemExit):
                archived = {}
            if (
                archived.get("schema") != "agent-delivery/v2"
                or archived.get("status") != legacy.get("previous_status")
                or archived.get("artifact") != artifact
                or archived.get("test_receipt") != test
            ):
                errors.append("legacy production archive does not preserve the artifact/test chain")
        expected_legacy_status = {
            "promoted": "legacy_promoted",
            "rollback_required": (
                "legacy_rolled_back" if isinstance(legacy, dict) and legacy.get("rollback_closure") is not None
                else "legacy_rollback_required"
            ),
            "rolled_back": "legacy_rolled_back",
        }.get(legacy.get("previous_status")) if isinstance(legacy, dict) else None
        if expected_legacy_status is not None and status != expected_legacy_status:
            errors.append("terminal legacy production history cannot re-enter an operational delivery state")
        closure = legacy.get("rollback_closure") if isinstance(legacy, dict) else None
        if closure is not None:
            if (
                legacy.get("previous_status") != "rollback_required"
                or not isinstance(closure, dict)
                or set(closure) != {
                    "schema", "source", "reason", "failed_digest", "restored_digest", "restored_artifact",
                    "rollback_evidence", "health_evidence", "decision_packet", "decision_packet_sha256",
                    "decision_receipt", "recorded_at",
                }
                or closure.get("schema") != "agent-legacy-rollback-closure/v1"
                or not str(closure.get("source", "")).startswith("user:")
                or closure.get("failed_digest") != (artifact or {}).get("digest")
                or not valid_file_receipt(closure.get("restored_artifact"))
                or not valid_file_receipt(closure.get("rollback_evidence"))
                or not valid_file_receipt(closure.get("health_evidence"))
                or closure.get("restored_digest") != "sha256:" + str((closure.get("restored_artifact") or {}).get("sha256", ""))
            ):
                errors.append("legacy rollback closure is invalid or not bound to the archived failed attempt")
            else:
                expected_packet = {
                    "schema": "agent-legacy-rollback-decision/v1",
                    "reason": closure.get("reason"),
                    "legacy_archive_sha256": archive.get("sha256") if isinstance(archive, dict) else None,
                    "failed_digest": closure.get("failed_digest"),
                    "restored_digest": closure.get("restored_digest"),
                    "restored_artifact_sha256": (closure.get("restored_artifact") or {}).get("sha256"),
                    "rollback_evidence_sha256": (closure.get("rollback_evidence") or {}).get("sha256"),
                    "health_evidence_sha256": (closure.get("health_evidence") or {}).get("sha256"),
                }
                if (
                    closure.get("decision_packet") != expected_packet
                    or closure.get("decision_packet_sha256") != canonical_sha256(expected_packet)
                    or (
                        task.get("decision_policy_version") == 1
                        and not humandecision.reverify(
                            ROOT, load(CONFIG), task, gate="legacy-rollback-closure",
                            artifact_sha256=str(canonical_sha256(expected_packet)),
                            source=str(closure.get("source", "")), record=closure.get("decision_receipt"),
                        )
                    )
                ):
                    errors.append("legacy rollback closure lacks its exact human-approved recovery packet")
    if isinstance(approval, dict):
        signed_decision_valid = True
        expected_packet = (
            deployment_decision_packet(task, artifact, test, provider)
            if isinstance(artifact, dict) and isinstance(test, dict) and isinstance(provider, dict)
            else None
        )
        if task.get("decision_policy_version") == 1 and expected_packet is not None:
            signed_decision_valid = humandecision.reverify(
                ROOT, load(CONFIG), task, gate="production-delivery",
                artifact_sha256=str(canonical_sha256(expected_packet)),
                source=str(approval.get("source", "")), record=approval.get("decision_receipt"),
            )
        if (
            state.get("environment") != "production"
            or not str(approval.get("source", "")).startswith("user:")
            or approval.get("digest") != (artifact or {}).get("digest")
            or approval.get("test_run_id") != (test or {}).get("run_id")
            or approval.get("candidate_sha256") != canonical_sha256(candidate_summary(artifact or {}))
            or approval.get("test_summary_sha256") != canonical_sha256(test_summary(test or {}))
            or approval.get("provider_preflight_sha256") != (provider or {}).get("sha256")
            or approval.get("decision_packet") != expected_packet
            or approval.get("decision_packet_sha256") != canonical_sha256(expected_packet)
            or not signed_decision_valid
        ):
            errors.append("production approval is not bound to the tested artifact")
    if state.get("environment") == "production" and status in {"ready_to_promote", "promoted", "rollback_required", "rolled_back"}:
        if (
            not isinstance(approval, dict)
            or not str(approval.get("source", "")).startswith("user:")
            or approval.get("digest") != (artifact or {}).get("digest")
            or approval.get("provider_preflight_sha256") != (provider or {}).get("sha256")
        ):
            errors.append("production lacks digest-bound human approval")
    if isinstance(attempt, dict):
        if (
            attempt.get("schema") != "agent-deployment-attempt/v1"
            or attempt.get("digest") != (artifact or {}).get("digest")
            or attempt.get("environment") != state.get("environment")
            or attempt.get("source_revision") != (artifact or {}).get("source_revision")
            or attempt.get("build_run_id") != (artifact or {}).get("build_run_id")
            or attempt.get("test_run_id") != (test or {}).get("run_id")
            or attempt.get("result") not in {"passed", "failed"}
            or not valid_file_receipt(attempt.get("evidence"))
        ):
            errors.append("deployment attempt provenance drifted")
        if status == "promoted" and attempt.get("result") != "passed":
            errors.append("promoted does not bind a passed deployment attempt")
        if status == "rollback_required" and attempt.get("result") != "failed":
            errors.append("rollback_required does not bind a failed attempt")
    if isinstance(promotion, dict):
        if (
            promotion.get("schema") != "agent-promotion-receipt/v1"
            or promotion.get("digest") != (artifact or {}).get("digest")
            or promotion.get("environment") != state.get("environment")
            or promotion.get("source_revision") != (artifact or {}).get("source_revision")
            or promotion.get("deployment_attempt_sha256") != canonical_sha256(attempt)
            or not isinstance(attempt, dict)
            or attempt.get("result") != "passed"
            or not valid_file_receipt(promotion.get("evidence"))
        ):
            errors.append("promotion receipt drifted")
    if isinstance(rollback, dict):
        if rollback.get("schema") != "agent-rollback-receipt/v1" or rollback.get("failed_digest") != (artifact or {}).get("digest"):
            errors.append("rollback does not bind the failed artifact")
        for key in ("restored_artifact", "rollback_evidence", "health_evidence"):
            if not valid_file_receipt(rollback.get(key)):
                errors.append(f"rollback nested {key} drifted")
        restored = rollback.get("restored_artifact")
        if isinstance(restored, dict) and rollback.get("restored_digest") != "sha256:" + str(restored.get("sha256", "")):
            errors.append("rollback restored digest differs from restored bytes")
        if rollback.get("deployment_attempt") != attempt:
            errors.append("rollback receipt does not embed the exact deployment attempt")
    if status == "rolled_back" and isinstance(attempt, dict):
        if attempt.get("result") == "passed" and not isinstance(promotion, dict):
            errors.append("rollback after a passed deployment must retain its promotion receipt")
        if attempt.get("result") == "failed" and promotion is not None:
            errors.append("rollback after a failed deployment cannot contain a promotion receipt")
    if errors:
        print("INVALID DELIVERY STATE")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"VALID DELIVERY STATE: {status}")
    return 0


def command_snapshot_node8(_: argparse.Namespace) -> int:
    """Emit the terminal Node8 projection from the validated current delivery state."""
    if command_validate(argparse.Namespace()) != 0:
        raise SystemExit("Node8 snapshot requires a valid delivery state")
    state = load(STATE)
    status = state.get("status")
    legacy_statuses = {"legacy_promoted", "legacy_rolled_back"}
    if status not in {"not_requested", "promoted", "rolled_back"} | legacy_statuses:
        raise SystemExit(f"Node8 snapshot requires a terminal delivery status, observed={status}")
    artifact = state.get("artifact")
    if status in legacy_statuses:
        legacy = state.get("legacy_production_chain")
        archive = legacy.get("archive") if isinstance(legacy, dict) else None
        if not isinstance(archive, dict):
            raise SystemExit("historical Node8 snapshot requires the exact legacy delivery archive")
        value = {
            "schema": "agent-node-delivery/v3", "status": status,
            "environment": state.get("environment"),
            "artifact_digest": artifact.get("digest") if isinstance(artifact, dict) else None,
            "legacy_assurance": "legacy", "legacy_archive_sha256": archive.get("sha256"),
            "reusable_as_release_receipt": False,
            "delivery_state": file_receipt(str(STATE.relative_to(ROOT)), "delivery state"),
        }
    else:
        value = {
            "schema": "agent-node-delivery/v2", "status": status,
            "environment": state.get("environment"),
            "artifact_digest": artifact.get("digest") if isinstance(artifact, dict) else None,
            "promotion_receipt_sha256": canonical_sha256(state.get("promotion_receipt")),
            "rollback_receipt_sha256": canonical_sha256(state.get("rollback_receipt")),
            "delivery_state": file_receipt(str(STATE.relative_to(ROOT)), "delivery state"),
        }
    save(value, NODE8)
    print(f"NODE 8 DELIVERY SNAPSHOT: {NODE8.relative_to(ROOT)}")
    return 0


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    sub = value.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    artifact = sub.add_parser("record-artifact")
    artifact.add_argument("--path", required=True)
    artifact.add_argument("--digest", required=True)
    artifact.add_argument("--built-by", required=True)
    artifact.add_argument("--source-branch", required=True)
    artifact.add_argument("--source-revision", required=True)
    artifact.add_argument("--build-run-id", required=True)
    test = sub.add_parser("accept-test")
    test.add_argument("--digest", required=True)
    test.add_argument("--result", choices=("passed", "failed"), required=True)
    test.add_argument("--evidence", required=True)
    test.add_argument("--tested-environment", required=True)
    test.add_argument("--branch", required=True)
    test.add_argument("--run-id", required=True)
    test.add_argument("--reviewer", required=True)
    test.add_argument("--runner", required=True)
    provider = sub.add_parser("record-provider-preflight")
    provider.add_argument("--receipt", required=True)
    approve = sub.add_parser("approve-production")
    approve.add_argument("--source", required=True)
    approve.add_argument("--human-decision-receipt")
    promote = sub.add_parser("promote")
    promote.add_argument("--digest", required=True)
    promote.add_argument("--evidence", required=True)
    promote.add_argument("--result", choices=("passed", "failed"), default="passed")
    rollback = sub.add_parser("rollback")
    rollback.add_argument("--reason", required=True)
    rollback.add_argument("--evidence", required=True)
    rollback.add_argument("--health-evidence", required=True)
    rollback.add_argument("--failed-digest", required=True)
    rollback.add_argument("--restored-digest", required=True)
    rollback.add_argument("--restored-artifact", required=True)
    legacy_rollback = sub.add_parser("record-legacy-rollback-closure")
    legacy_rollback.add_argument("--reason", required=True)
    legacy_rollback.add_argument("--evidence", required=True)
    legacy_rollback.add_argument("--health-evidence", required=True)
    legacy_rollback.add_argument("--failed-digest", required=True)
    legacy_rollback.add_argument("--restored-digest", required=True)
    legacy_rollback.add_argument("--restored-artifact", required=True)
    legacy_rollback.add_argument("--source", required=True)
    legacy_rollback.add_argument("--human-decision-receipt")
    sub.add_parser("validate")
    sub.add_parser("snapshot-node8")
    return value


def main() -> int:
    args = parser().parse_args()
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    LOCK.touch(exist_ok=True)
    with LOCK.open("r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return {
            "init": command_init,
            "record-artifact": command_artifact,
            "accept-test": command_test,
            "record-provider-preflight": command_provider_preflight,
            "approve-production": command_approve,
            "promote": command_promote,
            "rollback": command_rollback,
            "record-legacy-rollback-closure": command_legacy_rollback_closure,
            "validate": command_validate,
            "snapshot-node8": command_snapshot_node8,
        }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
