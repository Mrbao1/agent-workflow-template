#!/usr/bin/env python3
"""Run one bounded test group and append a machine-generated hashed receipt."""

from pathlib import Path
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import tempfile
import time
import uuid
import sys

import humandecision


def root():
    for path in (Path.cwd().resolve(), *Path.cwd().resolve().parents):
        if (path / ".agent").is_dir():
            return path
    raise SystemExit(".agent directory not found")


ROOT = root()
CONFIG_PATH = ROOT / ".agent" / "config.json"
TASK_PATH = ROOT / ".agent" / "state" / "TASK.json"
LOCK_PATH = ROOT / ".agent" / "state" / ".test-budget.lock"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[0-9a-f]{32}$")
CASE_ID = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
REMEDIATION_SCHEMA = "agent-test-infrastructure-remediation/v1"
REMEDIATION_GATE = "test-infrastructure-remediation"
PIPE_DRAIN_TIMEOUT_SECONDS = 1.0


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def atomic_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def load_json(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON object required: {path}")
    return value


IGNORED_PRODUCT_PARTS = {
    ".agent", ".git", ".gradle", ".idea", ".swiftpm", ".venv", "Pods",
    "DerivedData", "__pycache__", "build", "coverage", "dist", "node_modules",
    "target", "vendor",
}
PRODUCT_MANIFESTS = {
    "Package.swift": {".swift"},
    "project.pbxproj": {".swift", ".m", ".mm", ".c", ".cc", ".cpp", ".h", ".hpp"},
    "settings.gradle": {".java", ".kt", ".kts", ".xml"},
    "settings.gradle.kts": {".java", ".kt", ".kts", ".xml"},
    "build.gradle": {".java", ".kt", ".kts", ".xml"},
    "build.gradle.kts": {".java", ".kt", ".kts", ".xml"},
    "package.json": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte", ".css", ".html"},
    "pyproject.toml": {".py", ".pyi"},
    "setup.py": {".py", ".pyi"},
    "requirements.txt": {".py", ".pyi"},
    "go.mod": {".go"},
    "Cargo.toml": {".rs"},
    "pom.xml": {".java", ".kt", ".xml"},
    "build.xml": {".java", ".kt", ".xml"},
}
COMMON_SOURCE_DIRS = {
    "Sources", "Tests", "androidTest", "api", "app", "backend", "bin", "cli",
    "cmd", "e2e", "frontend", "include", "integration", "ios", "lib", "pages",
    "public", "server", "src", "test", "tests",
}
ROOT_SOURCE_SUFFIXES = set().union(*PRODUCT_MANIFESTS.values()) | {".sh"}
PRODUCT_METADATA = {
    "Package.resolved", "Podfile", "Podfile.lock", "Cartfile", "Cartfile.resolved",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb",
    "gradle.properties", "gradlew", "gradlew.bat", "go.sum", "Cargo.lock",
    "poetry.lock", "Pipfile", "Pipfile.lock", "requirements-dev.txt",
    "Makefile", "Dockerfile", "compose.yaml", "compose.yml",
}


def _ignored_product_path(path, product_root):
    try:
        relative = path.relative_to(product_root)
    except ValueError:
        return True
    return any(part in IGNORED_PRODUCT_PARTS for part in relative.parts)


def _lexical_project_path(raw, label):
    """Resolve a configured path only after rejecting every symlink component."""
    if not isinstance(raw, str) or not raw.strip():
        raise SystemExit(f"{label} is invalid")
    path = Path(os.path.abspath(str(ROOT / raw)))
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        raise SystemExit(f"{label} escapes project")
    current = ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise SystemExit(f"{label} has a symlink component: {current.relative_to(ROOT)}")
    return path


def _safe_scope_path(raw, label):
    path = _lexical_project_path(raw, label)
    if not path.exists():
        raise SystemExit(f"{label} is missing: {raw}")
    return path


def _files_under(path, label):
    if path.is_file():
        return [path]
    files = []
    for item in sorted(path.rglob("*")):
        if item.is_symlink():
            raise SystemExit(f"{label} contains a symlink: {item.relative_to(ROOT)}")
        if item.is_file() and "__pycache__" not in item.parts and item.suffix not in {".pyc", ".pyo"} and item.name != ".DS_Store":
            files.append(item)
    if not files:
        raise SystemExit(f"{label} contains no files: {path.relative_to(ROOT)}")
    return files


def governed_product_files(config):
    """Return strict configured scope plus automatically discovered product bytes.

    Configured paths are promises, not optional layout guesses.  Automatic discovery
    is rooted at scope.product_roots (default project root) and makes a manifest with
    no matching product-owned source a hard error.
    """
    scope = config.get("scope")
    if not isinstance(scope, dict):
        raise SystemExit("scope configuration is missing")
    configured = scope.get("fingerprint_paths")
    if not isinstance(configured, list) or not configured:
        raise SystemExit("candidate fingerprint paths are missing")
    files = set()
    for raw in configured:
        path = _safe_scope_path(raw, "configured fingerprint path")
        files.update(_files_under(path, "configured fingerprint path"))

    roots_raw = scope.get("product_roots", ["."])
    if not isinstance(roots_raw, list) or not roots_raw:
        raise SystemExit("scope.product_roots must be a non-empty string array")
    product_roots = []
    for raw in roots_raw:
        product_root = _safe_scope_path(raw, "configured product root")
        if not product_root.is_dir():
            raise SystemExit(f"configured product root is not a directory: {raw}")
        product_roots.append(product_root)

    discovered_any = False
    for product_root in product_roots:
        manifests = []
        source_files = []
        metadata = []
        for item in sorted(product_root.rglob("*")):
            if _ignored_product_path(item, product_root):
                continue
            if item.is_symlink():
                raise SystemExit(f"product discovery contains a symlink: {item.relative_to(ROOT)}")
            if not item.is_file():
                continue
            if item.name in PRODUCT_MANIFESTS:
                manifests.append(item)
            if item.name in PRODUCT_METADATA:
                metadata.append(item)
            if item.suffix.lower() in ROOT_SOURCE_SUFFIXES:
                source_files.append(item)
        for manifest in manifests:
            owner = manifest.parent.parent if manifest.name == "project.pbxproj" and manifest.parent.suffix == ".xcodeproj" else manifest.parent
            suffixes = PRODUCT_MANIFESTS[manifest.name]
            owned = [
                item for item in source_files
                if item != manifest and item.suffix.lower() in suffixes and (item == owner or owner in item.parents)
            ]
            if not owned:
                raise SystemExit(
                    "product manifest has no discoverable product-owned source: "
                    f"{manifest.relative_to(ROOT)}; add source under a common layout or list its custom path in scope.fingerprint_paths"
                )
            files.add(manifest)
            files.update(owned)
            discovered_any = True
        files.update(metadata)
        common_roots = []
        for name in COMMON_SOURCE_DIRS:
            candidate = product_root / name
            if candidate.is_symlink():
                raise SystemExit(f"product source root is a symlink: {candidate.relative_to(ROOT)}")
            if candidate.is_dir():
                common_roots.append(candidate)
        for common_root in common_roots:
            owned = []
            for item in sorted(common_root.rglob("*")):
                if item.is_symlink():
                    raise SystemExit(f"product source root contains a symlink: {item.relative_to(ROOT)}")
                if item.is_file() and not _ignored_product_path(item, product_root):
                    owned.append(item)
            files.update(owned)
            discovered_any = discovered_any or bool(owned)
        root_sources = [item for item in source_files if item.parent == product_root]
        files.update(root_sources)
        discovered_any = discovered_any or bool(root_sources)
    if not discovered_any:
        # Control-only repositories are valid only when their explicitly governed
        # paths contain real files; automatic product discovery must never silently
        # produce an empty candidate.
        if not files:
            raise SystemExit("automatic product discovery found no manifest or source")
    return sorted(files)


def candidate_records(config):
    records = []
    for item in governed_product_files(config):
        data = item.read_bytes()
        if str(item.relative_to(ROOT)) == ".agent/state/TASK.json":
            task = json.loads(data.decode("utf-8"))
            volatile = {
                "status", "phase", "tokens_used", "token_usage_source", "usage_receipt",
                "usage_receipts", "budget_state", "child_agents_used", "peak_child_agents",
                "loaded_references", "next_action", "current_node", "accepted_nodes",
                "node_artifacts", "gate_approvals", "pending_gate_artifacts",
                "decision_packet", "selected_templates", "selected_capabilities",
                "template_route", "rendered_artifacts", "rollback_ledger",
                "rollback_archive", "failure_ledger", "failure_archive",
                "retrospective", "knowledge_candidates", "completion_binding",
                "metrics", "updated",
            }
            data = canonical({key: value for key, value in task.items() if key not in volatile})
        records.append({
            "path": str(item.relative_to(ROOT)),
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        })
    if not records:
        raise SystemExit("candidate fingerprint has no governed files")
    return records


def candidate_fingerprint(config):
    return hashlib.sha256(canonical(candidate_records(config))).hexdigest()


def test_policy(config, task):
    mode = str(task.get("mode", ""))
    mode_policy = config.get("routing", {}).get("modes", {}).get(mode, {})
    testing = config.get("testing", {})
    minutes = mode_policy.get("wall_time_minutes")
    attempts = mode_policy.get("max_automatic_test_attempts")
    if (
        mode not in {"fast", "standard", "release"}
        or minutes != {"fast": 5, "standard": 15, "release": 45}[mode]
        or attempts != 1
        or testing.get("max_automatic_full_chain_attempts") != 1
        or testing.get("infrastructure_failure_consumes_code_retry") is not False
        or testing.get("attempt_classes") != ["candidate", "test", "infrastructure"]
    ):
        raise SystemExit("test budget policy is missing or weakened")
    raw_registry = str(testing.get("budget_registry", ""))
    raw_receipts = str(testing.get("budget_receipt_dir", ""))
    registry = (ROOT / raw_registry).resolve()
    receipt_dir = (ROOT / raw_receipts).resolve()
    for path in (registry, receipt_dir):
        try:
            path.relative_to(ROOT)
        except ValueError:
            raise SystemExit("test budget state escapes project")
    return mode, int(minutes) * 60, int(attempts), registry, receipt_dir


@contextlib.contextmanager
def budget_lock():
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOCK_PATH.touch(exist_ok=True)
    with LOCK_PATH.open("r+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def budget_state(path):
    if not path.is_file():
        return {"schema": "agent-test-budget/v1", "candidates": {}}
    value = load_json(path)
    if value.get("schema") != "agent-test-budget/v1" or not isinstance(value.get("candidates"), dict):
        raise SystemExit("test budget registry is invalid")
    return value


def publish_budget_receipt(receipt_dir, value):
    data = canonical(value) + b"\n"
    digest = hashlib.sha256(data).hexdigest()
    path = receipt_dir / f"{digest}.json"
    if path.exists() and path.read_bytes() != data:
        raise SystemExit("test budget receipt collision")
    if not path.exists():
        atomic_text(path, data.decode("utf-8"))
    return {"path": str(path.relative_to(ROOT)), "sha256": digest, "bytes": len(data)}


def receipt_record(path):
    data = path.read_bytes()
    return {
        "path": str(path.relative_to(ROOT)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def resolve_budget_receipt(receipt_dir, raw, label):
    path = (ROOT / raw).resolve()
    try:
        path.relative_to(receipt_dir.resolve())
    except ValueError:
        raise SystemExit(f"{label} escapes the test-budget evidence directory")
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"{label} is missing or is a symlink")
    record = receipt_record(path)
    if path.name != f"{record['sha256']}.json":
        raise SystemExit(f"{label} is not stored at its content-addressed path")
    return path, record


def validate_candidate_state(candidate, mode, cap, maximum_attempts):
    if (
        candidate.get("mode") != mode
        or candidate.get("budget_seconds") != cap
        or candidate.get("max_automatic_test_attempts") != maximum_attempts
        or not isinstance(candidate.get("infrastructure_failures"), int)
        or int(candidate.get("infrastructure_failures", 0)) < 0
        or not isinstance(candidate.get("attempts"), dict)
        or not isinstance(candidate.get("active_reservations"), list)
        or not isinstance(candidate.get("infrastructure_remediations", []), list)
        or candidate.get("remediation_allowance") is not None
        and not isinstance(candidate.get("remediation_allowance"), dict)
    ):
        raise SystemExit("candidate test budget policy drifted")


def remediation_request(candidate_sha256, candidate, next_run_id, next_case):
    failure_receipt = candidate.get("latest_receipt")
    if (
        int(candidate.get("infrastructure_failures", 0)) <= 0
        or not isinstance(failure_receipt, dict)
        or set(failure_receipt) != {"path", "sha256", "bytes"}
    ):
        raise SystemExit("candidate has no unresolved runner-observed infrastructure failure")
    return {
        "schema": REMEDIATION_SCHEMA,
        "candidate_sha256": candidate_sha256,
        "failure_receipt": failure_receipt,
        "unresolved_infrastructure_failures": int(candidate["infrastructure_failures"]),
        "next_launch": {"run_id": next_run_id, "case": next_case},
        "authorization_scope": "single-test-launch",
        "code_retry_consumed": False,
    }


def validate_remediation_request(value, candidate_sha256, candidate):
    expected_keys = {
        "schema", "candidate_sha256", "failure_receipt",
        "unresolved_infrastructure_failures", "next_launch",
        "authorization_scope", "code_retry_consumed",
    }
    next_launch = value.get("next_launch") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("schema") != REMEDIATION_SCHEMA
        or value.get("candidate_sha256") != candidate_sha256
        or value.get("failure_receipt") != candidate.get("latest_receipt")
        or value.get("unresolved_infrastructure_failures") != candidate.get("infrastructure_failures")
        or value.get("authorization_scope") != "single-test-launch"
        or value.get("code_retry_consumed") is not False
        or not isinstance(next_launch, dict)
        or set(next_launch) != {"run_id", "case"}
        or RUN_ID.fullmatch(str(next_launch.get("run_id", ""))) is None
        or CASE_ID.fullmatch(str(next_launch.get("case", ""))) is None
        or next_launch.get("run_id") in candidate.get("attempts", {})
        or int(candidate.get("infrastructure_failures", 0)) <= 0
        or candidate.get("remediation_allowance") is not None
        or candidate.get("active_reservations")
    ):
        raise SystemExit("infrastructure remediation request is stale or invalid")
    return next_launch


def prepare_infrastructure_remediation(config, task, candidate_sha256, next_run_id, next_case):
    mode, cap, maximum_attempts, registry_path, receipt_dir = test_policy(config, task)
    with budget_lock():
        state = budget_state(registry_path)
        candidate = state.get("candidates", {}).get(candidate_sha256)
        if not isinstance(candidate, dict):
            raise SystemExit("candidate has no test budget state")
        validate_candidate_state(candidate, mode, cap, maximum_attempts)
        reconcile_reservations(candidate)
        request = remediation_request(candidate_sha256, candidate, next_run_id, next_case)
        # Reconciliation is committed here so a dead runner cannot be hidden by
        # repeatedly preparing an authorization request.
        atomic(registry_path, state)
    record = publish_budget_receipt(receipt_dir, request)
    print(
        "INFRASTRUCTURE REMEDIATION REQUEST "
        f"path={record['path']} sha256={record['sha256']} scope=single-test-launch"
    )
    return 0


def _load_remediation_state(config, task, candidate_sha256, request_raw):
    mode, cap, maximum_attempts, registry_path, receipt_dir = test_policy(config, task)
    request_path, request_record = resolve_budget_receipt(
        receipt_dir, request_raw, "infrastructure remediation request"
    )
    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SystemExit(f"infrastructure remediation request is invalid: {error}")
    with budget_lock():
        state = budget_state(registry_path)
        candidate = state.get("candidates", {}).get(candidate_sha256)
        if not isinstance(candidate, dict):
            raise SystemExit("candidate has no test budget state")
        validate_candidate_state(candidate, mode, cap, maximum_attempts)
        next_launch = validate_remediation_request(request, candidate_sha256, candidate)
    return registry_path, receipt_dir, request, request_record, next_launch


def apply_infrastructure_remediation(config, task, candidate_sha256, request_raw, source, human_receipt):
    if not isinstance(source, str) or not source.startswith("user:") or not source[5:].strip():
        raise SystemExit("infrastructure remediation source must identify an explicit user decision")
    registry_path, receipt_dir, request, request_record, next_launch = _load_remediation_state(
        config, task, candidate_sha256, request_raw
    )
    decision = humandecision.verify(
        ROOT, config, task, gate=REMEDIATION_GATE,
        artifact_sha256=request_record["sha256"], source=source,
        receipt=human_receipt, require_fresh=True,
    )
    mode, cap, maximum_attempts, _, _ = test_policy(config, task)
    with budget_lock():
        state = budget_state(registry_path)
        candidate = state.get("candidates", {}).get(candidate_sha256)
        if not isinstance(candidate, dict):
            raise SystemExit("candidate has no test budget state")
        validate_candidate_state(candidate, mode, cap, maximum_attempts)
        validate_remediation_request(request, candidate_sha256, candidate)
        applied_at = now()
        remediation = {
            "request": request_record,
            "failure_receipt": request["failure_receipt"],
            "decision_receipt": decision,
            "next_launch": next_launch,
            "applied_at": applied_at,
        }
        candidate.setdefault("infrastructure_remediations", []).append(remediation)
        candidate["infrastructure_failures"] = 0
        candidate["remediation_allowance"] = {
            "request_sha256": request_record["sha256"],
            "run_id": next_launch["run_id"], "case": next_launch["case"],
            "applied_at": applied_at,
        }
        active = sum(
            int(item.get("reserved_seconds", 0))
            for item in candidate.get("active_reservations", []) if isinstance(item, dict)
        )
        event = {
            "schema": "agent-test-budget-receipt/v1", "event": "infrastructure_remediated",
            "candidate_sha256": candidate_sha256, "mode": mode,
            "budget_seconds": cap, "consumed_seconds": candidate.get("consumed_seconds", 0),
            "reserved_seconds": active,
            "remaining_seconds": max(0, cap - int(candidate.get("consumed_seconds", 0)) - active),
            "max_automatic_test_attempts": maximum_attempts,
            "attempt_class": "infrastructure", "failure_receipt": request["failure_receipt"],
            "remediation_request": request_record, "decision_receipt": decision,
            "next_launch": next_launch, "observed_at": applied_at,
        }
        candidate["latest_receipt"] = publish_budget_receipt(receipt_dir, event)
        atomic(registry_path, state)
    print(
        "INFRASTRUCTURE REMEDIATION APPLIED "
        f"candidate={candidate_sha256} run_id={next_launch['run_id']} case={next_launch['case']}"
    )
    return 0


def live_pid(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except (ProcessLookupError, ValueError, TypeError):
        return False
    except PermissionError:
        return True


def reconcile_reservations(candidate):
    consumed = int(candidate.get("consumed_seconds", 0))
    retained = []
    for reservation in candidate.get("active_reservations", []):
        if isinstance(reservation, dict) and live_pid(reservation.get("pid")):
            retained.append(reservation)
        elif isinstance(reservation, dict):
            # A crashed runner cannot make its elapsed time trustworthy. Charge
            # the complete reservation so a crash cannot reopen the budget.
            consumed += int(reservation.get("reserved_seconds", 0))
    candidate["consumed_seconds"] = consumed
    candidate["active_reservations"] = retained


def reserve_budget(config, task, args, receipt_path, run_id, candidate_sha256):
    mode, cap, maximum_attempts, registry_path, receipt_dir = test_policy(config, task)
    with budget_lock():
        state = budget_state(registry_path)
        candidates = state["candidates"]
        candidate = candidates.setdefault(candidate_sha256, {
            "mode": mode,
            "budget_seconds": cap,
            "max_automatic_test_attempts": maximum_attempts,
            "consumed_seconds": 0,
            "infrastructure_failures": 0,
            "attempts": {},
            "active_reservations": [],
            "infrastructure_remediations": [],
            "remediation_allowance": None,
            "latest_receipt": None,
        })
        validate_candidate_state(candidate, mode, cap, maximum_attempts)
        reconcile_reservations(candidate)
        if int(candidate.get("infrastructure_failures", 0)) > 0:
            raise SystemExit(
                "candidate has an unresolved infrastructure failure; prepare and apply a "
                "provider-approved single-launch remediation before another test launch"
            )
        allowance = candidate.get("remediation_allowance")
        if allowance is not None and (
            set(allowance) != {"request_sha256", "run_id", "case", "applied_at"}
            or HEX64.fullmatch(str(allowance.get("request_sha256", ""))) is None
            or allowance.get("run_id") != run_id
            or allowance.get("case") != args.case
        ):
            raise SystemExit("pending infrastructure remediation is bound to a different single test launch")
        track = "code"
        attempt = candidate["attempts"].get(run_id)
        receipt_relative = str(receipt_path.relative_to(ROOT))
        if attempt is None:
            prior = [item for item in candidate["attempts"].values() if isinstance(item, dict) and item.get("track") == track]
            if len(prior) >= maximum_attempts:
                raise SystemExit(f"automatic {track} test attempt budget exhausted for this candidate")
            attempt = {
                "track": track,
                "receipt_path": receipt_relative,
                "started_at": now(),
                "cases": [],
            }
            candidate["attempts"][run_id] = attempt
        elif (
            attempt.get("track") != track
            or attempt.get("receipt_path") != receipt_relative
        ):
            raise SystemExit("run_id is already bound to a different candidate test attempt")
        if attempt.get("failure_class") is not None:
            raise SystemExit(
                "failed candidate test attempt is sealed; diagnose the failure before using a new run_id"
            )
        if args.case in attempt.get("cases", []):
            raise SystemExit("test budget already recorded this case")
        reserved = sum(int(item.get("reserved_seconds", 0)) for item in candidate["active_reservations"] if isinstance(item, dict))
        remaining = cap - int(candidate["consumed_seconds"]) - reserved
        if args.timeout > cap or args.timeout > remaining:
            raise SystemExit(f"test timeout exceeds remaining {mode} candidate budget ({max(remaining, 0)}s)")
        reservation_id = uuid.uuid4().hex
        reservation = {
            "id": reservation_id, "pid": os.getpid(), "run_id": run_id,
            "case": args.case, "reserved_seconds": args.timeout, "started_at": now(),
        }
        if allowance is not None:
            reservation["remediation_request_sha256"] = allowance["request_sha256"]
            attempt["remediation_request_sha256"] = allowance["request_sha256"]
            candidate["remediation_allowance"] = None
        candidate["active_reservations"].append(reservation)
        event = {
            "schema": "agent-test-budget-receipt/v1", "event": "reserved",
            "candidate_sha256": candidate_sha256, "mode": mode,
            "budget_seconds": cap, "consumed_seconds": candidate["consumed_seconds"],
            "reserved_seconds": reserved + args.timeout, "remaining_seconds": remaining - args.timeout,
            "max_automatic_test_attempts": maximum_attempts, "run_id": run_id,
            "attempt_class": "code", "case": args.case,
            "reservation_id": reservation_id, "observed_at": now(),
        }
        if allowance is not None:
            event["remediation_request_sha256"] = allowance["request_sha256"]
        candidate["latest_receipt"] = publish_budget_receipt(receipt_dir, event)
        atomic(registry_path, state)
    return registry_path, receipt_dir, reservation_id


def finish_budget(registry_path, receipt_dir, reservation_id, candidate_sha256, run_id, args, elapsed, exit_code, outcome, failure_class):
    with budget_lock():
        state = budget_state(registry_path)
        candidate = state.get("candidates", {}).get(candidate_sha256)
        if not isinstance(candidate, dict):
            raise SystemExit("candidate test budget disappeared during execution")
        reservations = candidate.get("active_reservations", [])
        reservation = next((item for item in reservations if isinstance(item, dict) and item.get("id") == reservation_id), None)
        if reservation is None or reservation.get("run_id") != run_id or reservation.get("case") != args.case:
            raise SystemExit("test budget reservation changed during execution")
        charged = max(1, int(math.ceil(elapsed)))
        candidate["consumed_seconds"] = int(candidate.get("consumed_seconds", 0)) + charged
        candidate["active_reservations"] = [item for item in reservations if not isinstance(item, dict) or item.get("id") != reservation_id]
        attempt = candidate.get("attempts", {}).get(run_id)
        if not isinstance(attempt, dict):
            raise SystemExit("candidate test attempt disappeared during execution")
        attempt.setdefault("cases", []).append(args.case)
        attempt["finished_at"] = now()
        attempt["failure_class"] = failure_class
        if failure_class == "infrastructure":
            attempt["track"] = "infrastructure"
            candidate["infrastructure_failures"] = int(candidate.get("infrastructure_failures", 0)) + 1
        cap = int(candidate.get("budget_seconds", 0))
        active = sum(int(item.get("reserved_seconds", 0)) for item in candidate["active_reservations"] if isinstance(item, dict))
        event = {
            "schema": "agent-test-budget-receipt/v1", "event": "finished",
            "candidate_sha256": candidate_sha256, "mode": candidate.get("mode"),
            "budget_seconds": cap, "consumed_seconds": candidate["consumed_seconds"],
            "reserved_seconds": active, "remaining_seconds": max(0, cap - int(candidate["consumed_seconds"]) - active),
            "max_automatic_test_attempts": candidate.get("max_automatic_test_attempts"),
            "run_id": run_id, "attempt_class": attempt.get("track"), "case": args.case,
            "reservation_id": reservation_id, "charged_seconds": charged,
            "exit_code": exit_code, "outcome": outcome, "failure_class": failure_class,
            "observed_at": now(),
        }
        candidate["latest_receipt"] = publish_budget_receipt(receipt_dir, event)
        atomic(registry_path, state)


def group_alive(pgid):
    members = group_members(pgid)
    if members is not None:
        return bool(members)
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def group_members(pgid):
    try:
        result = subprocess.run(
            ["ps", "-axo", "pid=,pgid=,stat="], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    members = []
    for line in result.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        try:
            pid, candidate = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        if candidate == pgid and not parts[2].startswith("Z"):
            members.append(pid)
    return sorted(set(members))


def signal_group(pgid, signum):
    try:
        os.killpg(pgid, signum)
        return True
    except ProcessLookupError:
        return True
    except PermissionError:
        members = group_members(pgid)
        if members is None:
            return False
        ok = True
        for pid in members:
            try:
                os.kill(pid, signum)
            except ProcessLookupError:
                continue
            except OSError:
                ok = False
        return ok
    except OSError:
        return False


def terminate_group(process, grace=2.0):
    pgid = process.pid
    if pgid <= 1:
        return False
    if group_alive(pgid):
        if not signal_group(pgid, signal.SIGTERM):
            return False
        deadline = time.monotonic() + grace
        while group_alive(pgid) and time.monotonic() < deadline:
            process.poll()  # reap an exited leader so orphaned descendants can be reaped too
            time.sleep(0.05)
    if group_alive(pgid):
        if not signal_group(pgid, signal.SIGKILL):
            return False
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        return False
    deadline = time.monotonic() + 2
    while group_alive(pgid) and time.monotonic() < deadline:
        process.poll()
        time.sleep(0.05)
    return not group_alive(pgid)


def merge_output(previous, observed):
    previous = previous or b""
    observed = observed or b""
    if observed.startswith(previous):
        return observed
    if previous.endswith(observed):
        return previous
    return previous + observed


def bounded_pipe_drain(process, previous, timeout=PIPE_DRAIN_TIMEOUT_SECONDS):
    """Collect final output without ever waiting indefinitely on an inherited pipe."""
    try:
        observed, _ = process.communicate(timeout=timeout)
        return merge_output(previous, observed), True
    except subprocess.TimeoutExpired as error:
        output = merge_output(previous, error.output)
        if process.stdout is not None and not process.stdout.closed:
            try:
                process.stdout.close()
            except OSError:
                pass
        return output, False


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt")
    parser.add_argument("--case")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--run-id")
    parser.add_argument("--candidate-sha256")
    remediation = parser.add_mutually_exclusive_group()
    remediation.add_argument("--prepare-infrastructure-remediation", action="store_true")
    remediation.add_argument("--apply-infrastructure-remediation", action="store_true")
    parser.add_argument("--remediation-request")
    parser.add_argument("--next-run-id")
    parser.add_argument("--next-case")
    parser.add_argument("--human-decision-source")
    parser.add_argument("--human-decision-receipt")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if args.run_id is not None and RUN_ID.fullmatch(args.run_id) is None:
        raise SystemExit("run_id must be 32 lowercase hexadecimal characters")
    if args.candidate_sha256 is not None and HEX64.fullmatch(args.candidate_sha256) is None:
        raise SystemExit("candidate fingerprint must be lowercase SHA-256")
    config = load_json(CONFIG_PATH)
    task = load_json(TASK_PATH)
    candidate_sha256 = candidate_fingerprint(config)
    if args.candidate_sha256 is not None and args.candidate_sha256 != candidate_sha256:
        raise SystemExit("declared candidate fingerprint differs from governed project bytes")
    if args.prepare_infrastructure_remediation:
        if command or args.receipt or args.remediation_request or args.human_decision_source or args.human_decision_receipt:
            raise SystemExit("prepare remediation does not accept a test command, receipt or decision")
        if RUN_ID.fullmatch(str(args.next_run_id or "")) is None or CASE_ID.fullmatch(str(args.next_case or "")) is None:
            raise SystemExit("prepare remediation requires a valid --next-run-id and --next-case")
        return prepare_infrastructure_remediation(
            config, task, candidate_sha256, args.next_run_id, args.next_case
        )
    if args.apply_infrastructure_remediation:
        if command or args.receipt or args.next_run_id or args.next_case:
            raise SystemExit("apply remediation accepts only its request and provider decision")
        if not args.remediation_request or not args.human_decision_source or not args.human_decision_receipt:
            raise SystemExit(
                "apply remediation requires --remediation-request, --human-decision-source "
                "and --human-decision-receipt"
            )
        return apply_infrastructure_remediation(
            config, task, candidate_sha256, args.remediation_request,
            args.human_decision_source, args.human_decision_receipt,
        )
    if any((args.remediation_request, args.next_run_id, args.next_case,
            args.human_decision_source, args.human_decision_receipt)):
        raise SystemExit("remediation-only arguments require a remediation action")
    if not args.receipt or not command:
        raise SystemExit("test --receipt and command are required")
    if args.timeout <= 0:
        raise SystemExit("test timeout must be positive")
    if CASE_ID.fullmatch(str(args.case or "")) is None:
        raise SystemExit("test case id is invalid")
    path = (ROOT / args.receipt).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError:
        raise SystemExit("receipt escapes project")
    runner = Path(__file__).resolve()
    runner_data = runner.read_bytes()
    runner_receipt = {
        "path": str(runner.relative_to(ROOT)),
        "sha256": hashlib.sha256(runner_data).hexdigest(),
        "bytes": len(runner_data),
    }
    value = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {
        "schema": "agent-test-receipt/v3", "run_id": args.run_id or uuid.uuid4().hex,
        "candidate_sha256": candidate_sha256, "runner": runner_receipt, "cases": [],
    }
    if (
        set(value) != {"schema", "run_id", "candidate_sha256", "runner", "cases"}
        or value.get("schema") != "agent-test-receipt/v3"
        or value.get("candidate_sha256") != candidate_sha256
        or value.get("runner") != runner_receipt
        or not isinstance(value.get("cases"), list)
        or (args.run_id is not None and value.get("run_id") != args.run_id)
        or any(item.get("id") == args.case for item in value.get("cases", []) if isinstance(item, dict))
    ):
        raise SystemExit("invalid receipt, stale candidate, runner drift or duplicate case")

    run_id = str(value["run_id"])
    registry_path, budget_receipt_dir, reservation_id = reserve_budget(
        config, task, args, path, run_id, candidate_sha256
    )

    output_path = path.parent / (path.stem + "-" + args.case + ".log")

    started = now()
    started_monotonic = time.monotonic()
    command_env = os.environ.copy()
    try:
        process = subprocess.Popen(
            command, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True, env=command_env,
        )
    except OSError as error:
        finish_budget(
            registry_path, budget_receipt_dir, reservation_id, candidate_sha256,
            run_id, args, time.monotonic() - started_monotonic, 126,
            "launch_failed", "infrastructure",
        )
        raise SystemExit(f"test command could not start: {error}")
    previous = {}

    def interrupt(signum, _frame):
        raise Interrupted(signum)

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, interrupt)
    output_bytes = b""
    outcome = "completed"
    exit_code = 1
    cleanup_ok = False
    try:
        try:
            output_bytes, _ = process.communicate(timeout=args.timeout)
            exit_code = int(process.returncode)
        except subprocess.TimeoutExpired as error:
            output_bytes = merge_output(output_bytes, error.output)
            outcome = "timed_out"
            exit_code = 124
        except Interrupted as error:
            outcome = "interrupted"
            exit_code = 128 + error.signum
        finally:
            cleanup_ok = terminate_group(process)
            output_bytes, drain_ok = bounded_pipe_drain(process, output_bytes)
            cleanup_ok = cleanup_ok and drain_ok
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)

    output = output_bytes.decode("utf-8", errors="replace")
    encoded = output.encode()
    atomic_text(output_path, output)
    output_receipt = {
        "path": str(output_path.relative_to(ROOT)),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "bytes": len(encoded),
    }
    cleanup_value = "passed" if cleanup_ok else "failed"
    failure_class = None
    if not cleanup_ok:
        failure_class = "infrastructure"
    elif exit_code != 0 or outcome != "completed":
        failure_class = "candidate"
    case = {
        "id": args.case, "run_id": value["run_id"], "candidate_sha256": candidate_sha256,
        "command": command,
        "started_at": started, "finished_at": now(), "exit_code": exit_code,
        "outcome": outcome, "cleanup": cleanup_value,
        "output": output_receipt,
    }
    case["case_sha256"] = hashlib.sha256(
        json.dumps(case, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    value["cases"].append(case)
    atomic(path, value)
    finish_budget(
        registry_path, budget_receipt_dir, reservation_id, candidate_sha256,
        run_id, args, time.monotonic() - started_monotonic, exit_code, outcome,
        failure_class,
    )
    print(output, end="")
    print(f"TEST RECEIPT: {args.case} exit={exit_code} cleanup={cleanup_value}")
    if not cleanup_ok:
        return 125
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
