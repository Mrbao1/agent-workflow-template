#!/usr/bin/env python3
"""Emit provider-neutral Issue/change and CI templates from a confirmed user blueprint."""
from pathlib import Path, PurePosixPath
import argparse
import ctypes
import errno
import json
import os
import platform
import secrets
import stat

from adaptive_common import (
    AdaptiveError, bytes_sha256, canonical_sha256, fail, load_blueprint, load_json,
    mutation_lock, print_json, record_human_decision, resolve_root, verify_human_decision, write_json,
)

CHECKOUT_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


def yaml_scalar(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def design_artifact(blueprint, provider):
    design = blueprint["design"]
    payload = {"schema": "agent-provider-confirmed-design/v1", "provider": provider,
               "design_sha256": canonical_sha256(design), "design": design}
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def workflow_commands(blueprint):
    return [item for item in blueprint["design"]["commands"] if item["stage"] in {"acceptance", "ci"}]


def common_checks(blueprint, commands, provider):
    digest = blueprint["confirmation"]["design_sha256"]
    lines = [
        f"python3 .agent/scripts/blueprintctl.py check --require-confirmed --expect-design-sha256 {digest}",
        "python3 .agent/scripts/skillctl.py verify",
        "python3 .agent/scripts/knowledgectl.py check",
        "python3 .agent/scripts/knowledgectl.py verify-catalog",
        f"python3 .agent/scripts/providerctl.py verify --provider {provider}",
    ]
    lines.extend(f"python3 .agent/scripts/blueprintctl.py run-command --id {item['id']} --expect-design-sha256 {digest}" for item in commands)
    return lines


def confirmed_design_markdown(blueprint):
    design = blueprint["design"]
    lines = ["<!-- Generated from the confirmed blueprint; do not hand-edit this block. -->", "## Goals"]
    lines += [f"- {item}" for item in design["goals"]] or ["- (explicitly empty)"]
    lines += ["", "## Architecture"] + ([f"- {item}" for item in design["architecture"]] or ["- (explicitly empty)"])
    lines += ["", "## Technology choices"] + ([f"- {item['name']}: {item['reason']}" for item in design["technology_choices"]] or ["- (explicitly empty)"])
    lines += ["", "## Capabilities"] + ([f"- {item['id']}: {item['description']}" for item in design["capabilities"]] or ["- (explicitly empty)"])
    command_by_acceptance = {item["id"]: [] for item in design["acceptance"]}
    for command in design["commands"]:
        for acceptance_id in command["covers"]:
            command_by_acceptance[acceptance_id].append(command["id"])
    lines += ["", "## Acceptance"]
    for item in design["acceptance"]:
        method = item.get("method", "executable")
        commands = ", ".join(command_by_acceptance[item["id"]]) or "human/integrator evidence"
        lines.append(f"- {item['id']} [{method}]: {item['criterion']} (evidence: {commands})")
    lines += ["", "## Constraints"] + ([f"- {item}" for item in design["constraints"]] or ["- (explicitly empty)"])
    lines += ["", "## Commands"] + ([f"- {item['id']} [{item['stage']}]: argv={json.dumps(item['argv'], ensure_ascii=False)}; timeout={item['timeout_seconds']}; covers={json.dumps(item['covers'], ensure_ascii=False)}; environment={json.dumps(item.get('environment', []), ensure_ascii=False)}" for item in design["commands"]] or ["- (explicitly empty)"])
    lines += ["", "## Providers"] + ([f"- {json.dumps(item, ensure_ascii=False, sort_keys=True)}" for item in design["providers"]] or ["- (explicitly empty)"])
    lines += ["", "## Canonical full design JSON", "`" * 3 + "json", json.dumps(design, ensure_ascii=False, indent=2, sort_keys=True), "`" * 3,
              "<!-- End generated blueprint block. -->"]
    return "\n".join(lines)


def gitlab_files(blueprint):
    digest = blueprint["confirmation"]["design_sha256"]
    commands = workflow_commands(blueprint)
    provider = next(item for item in blueprint["design"]["providers"] if item["id"] == "gitlab")
    ci = ["stages:", "  - agent-verify", "", "agent-workflow-verify:", "  stage: agent-verify"]
    if provider["image"]:
        ci.append(f"  image: {yaml_scalar(provider['image'])}")
    if provider["tags"]:
        ci.extend(["  tags:", *[f"    - {yaml_scalar(tag)}" for tag in provider["tags"]]])
    ci.extend([
        "  timeout: 45m", "  variables:", "    PYTHONDONTWRITEBYTECODE: \"1\"", "    GIT_DEPTH: \"0\"", "  script:",
        *["    - " + line for line in common_checks(blueprint, commands, "gitlab")],
        '    - python3 .agent/scripts/knowledgectl.py plan-git-diff --base "${CI_MERGE_REQUEST_DIFF_BASE_SHA:-$CI_COMMIT_BEFORE_SHA}" --head "$CI_COMMIT_SHA"',
        "  artifacts:", "    when: always", "    expire_in: 14 days", "    paths:",
        "      - .agent/knowledge/catalog.json", "      - .agent/project/skills.lock.json", "  rules:",
        "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'",
        "    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'", "",
    ])
    issue = f"""# Context

<!-- Describe the problem and users. Do not let the Agent choose architecture or technology here. -->

# User-confirmed design

- Blueprint SHA-256: {digest}

{confirmed_design_markdown(blueprint)}

# Scope

## In

## Out

# Acceptance

# Knowledge owners

# Security / migration / rollback
"""
    merge = f"""# Change summary

# Confirmed design

Blueprint SHA-256: {digest}

{confirmed_design_markdown(blueprint)}

# Skill selection

- Recommendation SHA-256:
- Locked commits and licenses:
- Hard-gate result:

# Knowledge and Issue trace

# Verification

# Review and rollback
"""
    return {
        ".gitlab-ci.yml": "\n".join(ci),
        ".gitlab/issue_templates/Feature.md": issue,
        ".gitlab/merge_request_templates/Default.md": merge,
        ".agent/provider-design/gitlab.json": design_artifact(blueprint, "gitlab"),
    }


def github_files(blueprint):
    digest = blueprint["confirmation"]["design_sha256"]
    commands = workflow_commands(blueprint)
    provider = next(item for item in blueprint["design"]["providers"] if item["id"] == "github")
    steps = [
        "      - name: Verify confirmed project blueprint",
        f"        run: python3 .agent/scripts/blueprintctl.py check --require-confirmed --expect-design-sha256 {digest}",
        "      - name: Verify locked dynamic Skills",
        "        run: python3 .agent/scripts/skillctl.py verify",
        "      - name: Verify generated provider authority",
        "        run: python3 .agent/scripts/providerctl.py verify --provider github",
        "      - name: Verify and compile project knowledge",
        "        run: |",
        "          python3 .agent/scripts/knowledgectl.py check",
        "          python3 .agent/scripts/knowledgectl.py verify-catalog",
        "      - name: Verify changed-path knowledge ownership",
        "        env:",
        "          BASE_SHA: ${{ github.event.pull_request.base.sha || github.event.before }}",
        "          HEAD_SHA: ${{ github.sha }}",
        '        run: python3 .agent/scripts/knowledgectl.py plan-git-diff --base "$BASE_SHA" --head "$HEAD_SHA"',
    ]
    for command in commands:
        steps.extend([
            f"      - name: Run confirmed command {command['id']}",
            f"        run: python3 .agent/scripts/blueprintctl.py run-command --id {command['id']} --expect-design-sha256 {digest}",
        ])
    runs_on = yaml_scalar(provider["runner"])
    job = [
        "name: agent-workflow-verify", "", "on:", "  pull_request:", "  push:", "",
        "permissions:", "  contents: read", "", "jobs:", "  verify:", f"    runs-on: {runs_on}",
    ]
    if provider["container_image"]:
        job.extend(["    container:", f"      image: {yaml_scalar(provider['container_image'])}"])
    job.extend([
        "    timeout-minutes: 45", "    steps:", f"      - uses: actions/checkout@{CHECKOUT_SHA}",
        "        with:", "          fetch-depth: 0", *steps, "",
    ])
    workflow = "\n".join(job)
    issue = f"""---
name: Feature
about: User-designed change routed by the adaptive workflow
---

# Context

# User-confirmed design

- Blueprint SHA-256: {digest}

{confirmed_design_markdown(blueprint)}

# Scope

# Acceptance

# Knowledge owners

# Security / migration / rollback
"""
    pull = f"""# Change summary

# Confirmed design

Blueprint SHA-256: {digest}

{confirmed_design_markdown(blueprint)}

# Skill selection

- Recommendation SHA-256:
- Locked commits and licenses:
- Hard-gate result:

# Knowledge and Issue trace

# Verification

# Review and rollback
"""
    return {
        ".github/workflows/agent-verify.yml": workflow,
        ".github/ISSUE_TEMPLATE/feature.md": issue,
        ".github/pull_request_template.md": pull,
        ".agent/provider-design/github.json": design_artifact(blueprint, "github"),
    }


PROVIDER_TARGET_MAX_BYTES = 2 * 1024 * 1024
PROVIDER_JOURNAL_RELATIVE = Path(".agent/project/provider-mutation-journal.json")
PROVIDER_JOURNAL_SCHEMA = "agent-provider-mutation-journal/v1"
_PROVIDER_STAGE_PREFIX = ".provider-stage-"
_PROVIDER_QUARANTINE_PREFIX = ".provider-quarantine-"
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _safe_provider_relative(relative):
    path = PurePosixPath(str(relative))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise AdaptiveError("UNSAFE_PROVIDER_TARGET", f"unsafe provider-relative path: {relative!r}")
    return path


def _output_root_relative(root, raw):
    requested = Path(raw).expanduser()
    candidate = (requested if requested.is_absolute() else root / requested).resolve(strict=False)
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise AdaptiveError("UNSAFE_OUTPUT_ROOT", "provider templates must stay inside the project root") from error
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise AdaptiveError("UNSAFE_OUTPUT_ROOT", "provider output root is not canonical")
    return "." if not relative.parts else PurePosixPath(*relative.parts).as_posix()


def _open_directory_chain(root_fd, parts, create=False):
    descriptor = os.dup(root_fd)
    try:
        for part in parts:
            try:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    os.close(descriptor)
                    return None
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                except FileExistsError:
                    pass
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as error:
                raise AdaptiveError("UNSAFE_OUTPUT_ROOT", f"provider directory ancestor {part!r} is unsafe") from error
            opened = os.fstat(child)
            if not stat.S_ISDIR(opened.st_mode):
                os.close(child)
                raise AdaptiveError("UNSAFE_OUTPUT_ROOT", f"provider directory ancestor {part!r} is not a directory")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _open_output_root(root, relative, create=False):
    root_fd = os.open(root, _DIRECTORY_FLAGS)
    try:
        parts = () if relative == "." else PurePosixPath(relative).parts
        return _open_directory_chain(root_fd, parts, create=create)
    finally:
        os.close(root_fd)


def _assert_output_binding(root, relative, held_fd):
    fresh_fd = _open_output_root(root, relative, create=False)
    if fresh_fd is None:
        raise AdaptiveError("PROVIDER_OUTPUT_ROOT_DRIFT", "provider output root disappeared during the operation")
    try:
        held = os.fstat(held_fd); fresh = os.fstat(fresh_fd)
        if (held.st_dev, held.st_ino) != (fresh.st_dev, fresh.st_ino):
            raise AdaptiveError("PROVIDER_OUTPUT_ROOT_DRIFT", "provider output root binding changed during the operation")
    finally:
        os.close(fresh_fd)


def _open_target_parent(output_fd, relative, create=False):
    safe = _safe_provider_relative(relative)
    parent = _open_directory_chain(output_fd, safe.parts[:-1], create=create)
    return parent, safe.name


def _read_open_descriptor(descriptor, label):
    opened = os.fstat(descriptor)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
            or opened.st_size > PROVIDER_TARGET_MAX_BYTES):
        raise AdaptiveError("UNSAFE_PROVIDER_TARGET", f"{label} is not one bounded single-link regular file")
    chunks = []
    remaining = PROVIDER_TARGET_MAX_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    final = os.fstat(descriptor)
    if (len(raw) > PROVIDER_TARGET_MAX_BYTES
            or (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)):
        raise AdaptiveError("UNSAFE_PROVIDER_TARGET", f"{label} changed while reading")
    return {
        "exists": True, "dev": opened.st_dev, "ino": opened.st_ino,
        "mode": stat.S_IMODE(opened.st_mode), "bytes": len(raw),
        "sha256": bytes_sha256(raw), "raw": raw,
    }


def _snapshot_at(parent_fd, name, label):
    flags = os.O_RDONLY | _FILE_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        return {"exists": False}
    except OSError as error:
        raise AdaptiveError("UNSAFE_PROVIDER_TARGET", f"{label} cannot be opened safely") from error
    try:
        return _read_open_descriptor(descriptor, label)
    finally:
        os.close(descriptor)


def provider_target_snapshot(output_fd, relative, label=None):
    """Descriptor-rooted snapshot used by planning, commit and verification."""
    if output_fd is None:
        return {"exists": False}
    parent_fd, name = _open_target_parent(output_fd, relative, create=False)
    if parent_fd is None:
        return {"exists": False}
    try:
        return _snapshot_at(parent_fd, name, label or str(relative))
    finally:
        os.close(parent_fd)


def _directory_identity(descriptor):
    observed = os.fstat(descriptor)
    if not stat.S_ISDIR(observed.st_mode):
        raise AdaptiveError("UNSAFE_OUTPUT_ROOT", "provider directory descriptor is not a directory")
    return {"dev": observed.st_dev, "ino": observed.st_ino}


def _assert_directory_identity(descriptor, expected, label):
    if _directory_identity(descriptor) != expected:
        raise AdaptiveError("PROVIDER_DIRECTORY_IDENTITY_DRIFT", f"provider directory identity changed: {label}")


def _record_snapshot(snapshot):
    if not snapshot.get("exists"):
        return {"exists": False}
    return {
        "exists": True, "mode": snapshot["mode"], "bytes": snapshot["bytes"],
        "sha256": snapshot["sha256"],
    }


def _snapshot_matches_record(snapshot, record):
    if bool(snapshot.get("exists")) != bool(record.get("exists")):
        return False
    if not record.get("exists"):
        return True
    return all(snapshot.get(key) == record.get(key) for key in ("mode", "bytes", "sha256"))


def _snapshot_matches_snapshot(observed, expected):
    if bool(observed.get("exists")) != bool(expected.get("exists")):
        return False
    if not expected.get("exists"):
        return True
    return all(observed.get(key) == expected.get(key) for key in ("dev", "ino", "mode", "bytes", "sha256"))


def _libc_rename(source_fd, source_name, target_fd, target_name, operation):
    libc = ctypes.CDLL(None, use_errno=True)
    system = platform.system()
    if system == "Linux" and hasattr(libc, "renameat2"):
        function = libc.renameat2
        flag = 2 if operation == "exchange" else 1
    elif system == "Darwin" and hasattr(libc, "renameatx_np"):
        function = libc.renameatx_np
        flag = 2 if operation == "exchange" else 4
    else:
        raise AdaptiveError("PROVIDER_ATOMICITY_UNAVAILABLE", "this host lacks an approved atomic provider rename primitive")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = function(source_fd, os.fsencode(source_name), target_fd, os.fsencode(target_name), flag)
    if result != 0:
        error_number = ctypes.get_errno()
        if operation == "noreplace" and error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise AdaptiveError("PROVIDER_TARGET_DRIFT", f"provider target appeared before atomic commit: {target_name}")
        if error_number in {errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL}:
            raise AdaptiveError("PROVIDER_ATOMICITY_UNAVAILABLE", "filesystem lacks the required atomic provider rename semantics")
        raise OSError(error_number, os.strerror(error_number), target_name)


def atomic_provider_exchange(parent_fd, staged_name, target_name):
    _libc_rename(parent_fd, staged_name, parent_fd, target_name, "exchange")
    os.fsync(parent_fd)


def atomic_provider_noreplace(parent_fd, source_name, target_name):
    _libc_rename(parent_fd, source_name, parent_fd, target_name, "noreplace")
    os.fsync(parent_fd)


def _write_stage(parent_fd, name, raw, mode=0o644):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW
    try:
        descriptor = os.open(name, flags, mode, dir_fd=parent_fd)
    except OSError as error:
        raise AdaptiveError("PROVIDER_STAGE_FAILED", f"cannot create provider stage {name}") from error
    try:
        view = memoryview(raw)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except BaseException:
        try:
            os.close(descriptor)
        finally:
            try:
                os.unlink(name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    else:
        os.close(descriptor)
    observed = _snapshot_at(parent_fd, name, f"provider stage {name}")
    expected = {"exists": True, "mode": mode, "bytes": len(raw), "sha256": bytes_sha256(raw)}
    if not _snapshot_matches_record(observed, expected):
        raise AdaptiveError("PROVIDER_STAGE_FAILED", f"provider stage {name} changed after fsync")
    os.fsync(parent_fd)


def _remove_name_if_record(parent_fd, name, expected):
    observed = _snapshot_at(parent_fd, name, f"provider transaction-owned file {name}")
    if not _snapshot_matches_record(observed, expected):
        return False
    quarantine = _PROVIDER_QUARANTINE_PREFIX + secrets.token_hex(16)
    try:
        atomic_provider_noreplace(parent_fd, name, quarantine)
    except AdaptiveError as error:
        if error.code == "PROVIDER_TARGET_DRIFT":
            return False
        raise
    moved = _snapshot_at(parent_fd, quarantine, f"provider quarantine {quarantine}")
    if not _snapshot_matches_record(moved, expected):
        try:
            atomic_provider_noreplace(parent_fd, quarantine, name)
        except BaseException as restore_error:
            raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"cannot restore raced provider file {name}") from restore_error
        return False
    os.unlink(quarantine, dir_fd=parent_fd)
    os.fsync(parent_fd)
    return True


def _journal_path(root):
    return root / PROVIDER_JOURNAL_RELATIVE


def _journal_digest(value):
    return canonical_sha256({key: item for key, item in value.items() if key != "journal_sha256"})


def _write_journal(root, value):
    payload = {key: item for key, item in value.items() if key != "journal_sha256"}
    payload["journal_sha256"] = canonical_sha256(payload)
    write_json(_journal_path(root), payload)
    value.clear(); value.update(payload)


def _validate_journal_item(item):
    if not isinstance(item, dict) or set(item) != {"path", "stage", "parent_identity", "expected", "generated", "state"}:
        raise AdaptiveError("INVALID_PROVIDER_JOURNAL", "provider journal item fields are invalid")
    _safe_provider_relative(item["path"])
    identity = item["parent_identity"]
    if (not isinstance(identity, dict) or set(identity) != {"dev", "ino"}
            or not all(isinstance(identity[key], int) and identity[key] >= 0 for key in ("dev", "ino"))):
        raise AdaptiveError("INVALID_PROVIDER_JOURNAL", "provider journal parent identity is invalid")
    stage_suffix = item.get("stage", "")[len(_PROVIDER_STAGE_PREFIX):] if isinstance(item.get("stage"), str) else ""
    if (not isinstance(item.get("stage"), str) or "/" in item["stage"]
            or not item["stage"].startswith(_PROVIDER_STAGE_PREFIX)
            or len(stage_suffix) != 32 or any(character not in "0123456789abcdef" for character in stage_suffix)):
        raise AdaptiveError("INVALID_PROVIDER_JOURNAL", "provider journal stage name is invalid")
    if item["state"] not in {"prepared", "committed"}:
        raise AdaptiveError("INVALID_PROVIDER_JOURNAL", "provider journal item state is invalid")
    for key in ("expected", "generated"):
        record = item[key]
        if not isinstance(record, dict) or record.get("exists") not in {True, False}:
            raise AdaptiveError("INVALID_PROVIDER_JOURNAL", "provider journal snapshot is invalid")
        if record["exists"]:
            if (set(record) != {"exists", "mode", "bytes", "sha256"}
                    or not isinstance(record["mode"], int) or not isinstance(record["bytes"], int)
                    or record["bytes"] < 0 or record["bytes"] > PROVIDER_TARGET_MAX_BYTES
                    or not isinstance(record["sha256"], str) or len(record["sha256"]) != 64
                    or any(character not in "0123456789abcdef" for character in record["sha256"])):
                raise AdaptiveError("INVALID_PROVIDER_JOURNAL", "provider journal file identity is invalid")
        elif set(record) != {"exists"}:
            raise AdaptiveError("INVALID_PROVIDER_JOURNAL", "absent provider snapshot has extra fields")
    if not item["generated"]["exists"] or item["generated"]["mode"] != 0o644:
        raise AdaptiveError("INVALID_PROVIDER_JOURNAL", "provider journal generated identity is invalid")


def _load_journal(root, required=False):
    path = _journal_path(root)
    if not path.exists():
        if required:
            raise AdaptiveError("PROVIDER_TRANSACTION_NOT_FOUND", "no provider mutation journal exists")
        return None
    value = load_json(path, "provider mutation journal")
    if (not isinstance(value, dict)
            or set(value) != {"schema", "transaction_id", "provider", "output_root", "output_identity", "items", "journal_sha256"}
            or value.get("schema") != PROVIDER_JOURNAL_SCHEMA
            or value.get("provider") not in {"github", "gitlab"}
            or not isinstance(value.get("transaction_id"), str) or len(value["transaction_id"]) != 32
            or any(character not in "0123456789abcdef" for character in value["transaction_id"])
            or not isinstance(value.get("output_root"), str)
            or not isinstance(value.get("items"), list) or not value["items"]
            or value.get("journal_sha256") != _journal_digest(value)):
        raise AdaptiveError("INVALID_PROVIDER_JOURNAL", "provider mutation journal is invalid or tampered")
    if value["output_root"] != ".":
        _safe_provider_relative(value["output_root"])
    output_identity = value["output_identity"]
    if (not isinstance(output_identity, dict) or set(output_identity) != {"dev", "ino"}
            or not all(isinstance(output_identity[key], int) and output_identity[key] >= 0 for key in ("dev", "ino"))):
        raise AdaptiveError("INVALID_PROVIDER_JOURNAL", "provider journal output identity is invalid")
    paths = []
    for item in value["items"]:
        _validate_journal_item(item); paths.append(item["path"])
    if len(paths) != len(set(paths)):
        raise AdaptiveError("INVALID_PROVIDER_JOURNAL", "provider mutation journal repeats a target")
    return value


def _delete_journal(root):
    path = _journal_path(root)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    descriptor = os.open(path.parent, _DIRECTORY_FLAGS)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _recover_existing_item(parent_fd, name, stage, expected, generated):
    target_snapshot = _snapshot_at(parent_fd, name, f"provider recovery target {name}")
    stage_snapshot = _snapshot_at(parent_fd, stage, f"provider recovery stage {stage}")
    if _snapshot_matches_record(target_snapshot, generated) and stage_snapshot.get("exists"):
        # The stage is the predecessor actually displaced by the atomic exchange.
        # It may differ from the approved snapshot when a writer raced the commit;
        # restoring those actual bytes is still the only ownership-safe rollback.
        expected_target = target_snapshot
        candidate = stage_snapshot
        for _ in range(8):
            atomic_provider_exchange(parent_fd, stage, name)
            restored = _snapshot_at(parent_fd, name, f"restored provider target {name}")
            displaced = _snapshot_at(parent_fd, stage, f"restored provider stage {stage}")
            if not _snapshot_matches_snapshot(restored, candidate):
                if _remove_name_if_record(parent_fd, stage, _record_snapshot(displaced)):
                    return
                break
            if _snapshot_matches_snapshot(displaced, expected_target):
                if _remove_name_if_record(parent_fd, stage, _record_snapshot(displaced)):
                    return
                break
            expected_target = restored
            candidate = displaced
        raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"provider recovery remained contested at {name}")
    if _snapshot_matches_record(stage_snapshot, generated) and not _snapshot_matches_record(target_snapshot, generated):
        if not _remove_name_if_record(parent_fd, stage, generated):
            raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"provider recovery stage changed at {stage}")
        return
    if not stage_snapshot.get("exists") and not _snapshot_matches_record(target_snapshot, generated):
        # No transaction-owned generated bytes remain at either pathname. A
        # concurrent target is authoritative and must be preserved.
        return
    raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"concurrent bytes prevent provider recovery at {name}")


def _recover_absent_item(parent_fd, name, stage, generated):
    target_snapshot = _snapshot_at(parent_fd, name, f"provider recovery target {name}")
    stage_snapshot = _snapshot_at(parent_fd, stage, f"provider recovery stage {stage}")
    if _snapshot_matches_record(target_snapshot, generated):
        if not _remove_name_if_record(parent_fd, name, generated):
            raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"provider recovery target changed at {name}")
    elif target_snapshot.get("exists"):
        # A third party replaced or created the path. Preserve it; the transaction owns no current bytes.
        pass
    if _snapshot_matches_record(stage_snapshot, generated):
        if not _remove_name_if_record(parent_fd, stage, generated):
            raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"provider recovery stage changed at {stage}")
    elif stage_snapshot.get("exists"):
        raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"unknown bytes occupy provider stage {stage}")


def _recover_provider_transaction_locked(root, required=False):
    journal = _load_journal(root, required=required)
    if journal is None:
        return None
    output_fd = _open_output_root(root, journal["output_root"], create=False)
    if output_fd is None:
        raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", "journal output root disappeared")
    try:
        _assert_directory_identity(output_fd, journal["output_identity"], "output root")
        # Validate the complete namespace before the first recovery mutation.
        validated_parents = []
        for item in journal["items"]:
            parent_fd, _ = _open_target_parent(output_fd, item["path"], create=False)
            if parent_fd is None:
                raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"provider parent disappeared for {item['path']}")
            try:
                _assert_directory_identity(parent_fd, item["parent_identity"], item["path"])
            finally:
                os.close(parent_fd)
            validated_parents.append(item["path"])
        for item in reversed(journal["items"]):
            parent_fd, name = _open_target_parent(output_fd, item["path"], create=False)
            if parent_fd is None:
                if item["expected"].get("exists"):
                    raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"provider parent disappeared for {item['path']}")
                continue
            try:
                _assert_directory_identity(parent_fd, item["parent_identity"], item["path"] )
                if item["expected"].get("exists"):
                    _recover_existing_item(parent_fd, name, item["stage"], item["expected"], item["generated"])
                else:
                    _recover_absent_item(parent_fd, name, item["stage"], item["generated"])
            finally:
                os.close(parent_fd)
    finally:
        os.close(output_fd)
    _delete_journal(root)
    return {"provider": journal["provider"], "transaction_id": journal["transaction_id"]}


def command_recover(root, args):
    with mutation_lock(root):
        result = _recover_provider_transaction_locked(root, required=True)
    print_json({"status": "PROVIDER_TRANSACTION_RECOVERED", **result})
    return 0


def _commit_existing(parent_fd, name, stage, expected, generated):
    atomic_provider_exchange(parent_fd, stage, name)
    actual_predecessor = _snapshot_at(parent_fd, stage, f"displaced provider predecessor {name}")
    current = _snapshot_at(parent_fd, name, f"committed provider target {name}")
    if _snapshot_matches_snapshot(actual_predecessor, expected) and _snapshot_matches_record(current, generated):
        return
    # Restore exactly what the atomic exchange displaced, but only while the target is still ours.
    if _snapshot_matches_record(current, generated) and actual_predecessor.get("exists"):
        atomic_provider_exchange(parent_fd, stage, name)
        restored = _snapshot_at(parent_fd, name, f"restored raced provider target {name}")
        owned_stage = _snapshot_at(parent_fd, stage, f"restored provider generated stage {stage}")
        if not _snapshot_matches_snapshot(restored, actual_predecessor):
            # A post-exchange writer already owns the pathname. Preserve it and
            # leave the displaced bytes staged for visible recovery.
            raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"provider target raced during restoration: {name}")
        if not _snapshot_matches_record(owned_stage, generated):
            # The restoration exchange captured a later concurrent writer in the
            # stage. Move the newest captured bytes back to their pathname. If a
            # still later writer races an attempt, carry that newly displaced
            # snapshot forward. The loop is bounded; failure retains the journal.
            expected_target = restored
            candidate = owned_stage
            for _ in range(8):
                atomic_provider_exchange(parent_fd, stage, name)
                current_target = _snapshot_at(parent_fd, name, f"compensated provider target {name}")
                displaced_again = _snapshot_at(parent_fd, stage, f"compensated provider stage {stage}")
                if not _snapshot_matches_snapshot(current_target, candidate):
                    # A writer changed the target after the exchange; it is already
                    # at the authoritative pathname. Remove only the older staged
                    # bytes that this transaction just displaced.
                    if _remove_name_if_record(parent_fd, stage, _record_snapshot(displaced_again)):
                        raise AdaptiveError("PROVIDER_TARGET_DRIFT", f"provider target changed during compensation: {name}")
                    break
                if _snapshot_matches_snapshot(displaced_again, expected_target):
                    if _remove_name_if_record(parent_fd, stage, _record_snapshot(displaced_again)):
                        raise AdaptiveError("PROVIDER_TARGET_DRIFT", f"provider predecessor changed before atomic commit: {name}")
                    break
                expected_target = current_target
                candidate = displaced_again
            raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"provider restoration compensation remained contested: {name}")
        # The stage again holds generated bytes; journal recovery removes it and
        # rolls back any earlier committed items without touching the raced target.
        raise AdaptiveError("PROVIDER_TARGET_DRIFT", f"provider predecessor changed before atomic commit: {name}")
    raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"concurrent bytes replaced transaction-owned provider target: {name}")


def _prepare_transaction(root, output_fd, provider, output_root_relative, prepared, predecessors):
    items = []
    for relative, raw in sorted(prepared.items()):
        parent_fd, name = _open_target_parent(output_fd, relative, create=True)
        try:
            parent_identity = _directory_identity(parent_fd)
            stage = _PROVIDER_STAGE_PREFIX + secrets.token_hex(16)
            _write_stage(parent_fd, stage, raw, 0o644)
        finally:
            os.close(parent_fd)
        items.append({
            "path": relative, "stage": stage, "parent_identity": parent_identity,
            "expected": _record_snapshot(predecessors[relative]),
            "generated": {"exists": True, "mode": 0o644, "bytes": len(raw), "sha256": bytes_sha256(raw)},
            "state": "prepared",
        })
    journal = {
        "schema": PROVIDER_JOURNAL_SCHEMA, "transaction_id": secrets.token_hex(16),
        "provider": provider, "output_root": output_root_relative,
        "output_identity": _directory_identity(output_fd), "items": items,
    }
    _write_journal(root, journal)
    return journal


def _apply_transaction(root, output_fd, journal, predecessors):
    try:
        for item in journal["items"]:
            parent_fd, name = _open_target_parent(output_fd, item["path"], create=False)
            if parent_fd is None:
                raise AdaptiveError("PROVIDER_TARGET_DRIFT", f"provider parent disappeared: {item['path']}")
            try:
                if item["expected"].get("exists"):
                    _commit_existing(parent_fd, name, item["stage"], predecessors[item["path"]], item["generated"])
                else:
                    atomic_provider_noreplace(parent_fd, item["stage"], name)
                committed = _snapshot_at(parent_fd, name, f"committed provider target {item['path']}")
                if not _snapshot_matches_record(committed, item["generated"]):
                    raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", f"provider target changed after commit: {item['path']}")
            finally:
                os.close(parent_fd)
            item["state"] = "committed"
            _write_journal(root, journal)
        # Keep the journal authoritative until one final descriptor-rooted pass
        # proves every target and every parent still belongs to this transaction.
        _assert_output_binding(root, journal["output_root"], output_fd)
        _assert_directory_identity(output_fd, journal["output_identity"], "output root")
        for item in journal["items"]:
            parent_fd, name = _open_target_parent(output_fd, item["path"], create=False)
            if parent_fd is None:
                raise AdaptiveError("PROVIDER_TRANSACTION_FINALIZE_BLOCKED", f"provider parent disappeared: {item['path']}")
            try:
                _assert_directory_identity(parent_fd, item["parent_identity"], item["path"])
                final_snapshot = _snapshot_at(parent_fd, name, f"final provider target {item['path']}")
                if not _snapshot_matches_record(final_snapshot, item["generated"]):
                    raise AdaptiveError("PROVIDER_TRANSACTION_FINALIZE_BLOCKED", f"provider target changed before finalization: {item['path']}")
            finally:
                os.close(parent_fd)
    except BaseException as original:
        try:
            _recover_provider_transaction_locked(root, required=True)
        except BaseException as recovery_error:
            if isinstance(recovery_error, AdaptiveError):
                raise recovery_error from original
            raise AdaptiveError("PROVIDER_TRANSACTION_ROLLBACK_BLOCKED", "provider rollback failed after interrupted mutation") from recovery_error
        raise
    # Every official target is now one coherent generated set. Remove the durable
    # journal first: a crash before this point rolls back; a crash after it leaves
    # only unreferenced hidden predecessor stages, never a mixed provider set.
    _delete_journal(root)
    for item in journal["items"]:
        if not item["expected"].get("exists"):
            continue
        parent_fd, _ = _open_target_parent(output_fd, item["path"], create=False)
        try:
            _remove_name_if_record(parent_fd, item["stage"], item["expected"])
        finally:
            os.close(parent_fd)


def _command_emit_locked(root, args):
    if _load_journal(root) is not None:
        raise AdaptiveError("PROVIDER_RECOVERY_REQUIRED", "an interrupted provider mutation exists; run providerctl.py recover")
    blueprint = load_blueprint(root, require_confirmed=True)
    if args.provider not in {item["id"] for item in blueprint["design"]["providers"]}:
        raise AdaptiveError("PROVIDER_NOT_CONFIRMED", f"provider {args.provider!r} is not in the user-confirmed blueprint")
    output_relative = _output_root_relative(root, args.output_root)
    output_fd = _open_output_root(root, output_relative, create=False)
    try:
        files = gitlab_files(blueprint) if args.provider == "gitlab" else github_files(blueprint)
        prepared = {}
        for relative, content in sorted(files.items()):
            raw = content.encode("utf-8")
            prepared[relative] = raw if raw.endswith(bytes([10])) else raw + bytes([10])
        provider_config = next(item for item in blueprint["design"]["providers"] if item["id"] == args.provider)
        trace_payload = {
            "schema": "agent-provider-trace/v2", "provider": args.provider,
            "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
            "design_sha256": canonical_sha256(blueprint["design"]),
            "provider_config_sha256": canonical_sha256(provider_config),
            "commands": [{"id": item["id"], "stage": item["stage"], "covers": item["covers"],
                          "environment": item.get("environment", []), "argv_sha256": canonical_sha256(item["argv"])}
                         for item in workflow_commands(blueprint)],
            "generated_files": [{"path": name, "sha256": bytes_sha256(raw)} for name, raw in sorted(prepared.items())],
        }
        trace_relative = f".agent/provider-trace/{args.provider}.json"
        predecessors = {}
        existing = []
        for relative in sorted([*prepared, trace_relative]):
            snapshot = provider_target_snapshot(output_fd, relative, f"provider predecessor {relative}")
            predecessors[relative] = snapshot
            if snapshot["exists"]:
                existing.append({"path": relative, "sha256": snapshot["sha256"]})
        trace_payload["predecessor_inventory"] = existing
        if existing and not args.force:
            raise AdaptiveError("PROVIDER_TEMPLATE_EXISTS", "refusing to overwrite provider files; plan and approve a force action after review")
        overwrite_action = {
            "schema": "agent-provider-overwrite-action/v2", "provider": args.provider,
            "blueprint_sha256": blueprint["confirmation"]["design_sha256"], "output_root": output_relative,
            "existing": existing, "proposed_trace_sha256": canonical_sha256(trace_payload),
        }
        overwrite_sha256 = canonical_sha256(overwrite_action)
        if args.plan_overwrite:
            print_json({"mutation": False, "payload": overwrite_action,
                        "approval_sha256": overwrite_sha256 if existing else None,
                        "approval_required": bool(existing)})
            return 0
        decision = None
        if existing:
            if args.approve_digest != overwrite_sha256 or not args.source:
                raise AdaptiveError("PROVIDER_OVERWRITE_APPROVAL_REQUIRED", f"approve the exact provider overwrite digest: {overwrite_sha256}")
            receipt = record_human_decision(root, gate="adaptive-provider-overwrite", artifact_sha256=overwrite_sha256,
                                            source=args.source, receipt=args.human_decision_receipt)
            decision = {"source": args.source, "action_sha256": overwrite_sha256,
                        "action": overwrite_action, "receipt": receipt}
        committed_trace = {**trace_payload, "overwrite_decision": decision}
        trace = {**committed_trace, "trace_sha256": canonical_sha256(committed_trace)}
        prepared[trace_relative] = (json.dumps(trace, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    finally:
        if output_fd is not None:
            os.close(output_fd)
    output_fd = _open_output_root(root, output_relative, create=True)
    try:
        journal = _prepare_transaction(root, output_fd, args.provider, output_relative, prepared, predecessors)
        _apply_transaction(root, output_fd, journal, predecessors)
    finally:
        os.close(output_fd)
    written = [{"path": relative, "sha256": bytes_sha256(raw)} for relative, raw in sorted(prepared.items())]
    print_json({"schema": "agent-provider-template-result/v1", "provider": args.provider,
                "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
                "trace_sha256": trace["trace_sha256"], "files": written})
    return 0


def command_emit(root, args):
    with mutation_lock(root):
        return _command_emit_locked(root, args)


def _command_verify_locked(root, args):
    if _load_journal(root) is not None:
        raise AdaptiveError("PROVIDER_RECOVERY_REQUIRED", "provider verification is blocked by an interrupted mutation; run recover")
    blueprint = load_blueprint(root, require_confirmed=True)
    provider_config = next((item for item in blueprint["design"]["providers"] if item["id"] == args.provider), None)
    if provider_config is None:
        raise AdaptiveError("PROVIDER_NOT_CONFIRMED", f"provider {args.provider!r} is not in the confirmed blueprint")
    output_relative = _output_root_relative(root, args.output_root)
    output_fd = _open_output_root(root, output_relative, create=False)
    if output_fd is None:
        raise AdaptiveError("PROVIDER_TRACE_MISSING", "provider output root is missing")
    try:
        trace_relative = f".agent/provider-trace/{args.provider}.json"
        trace_snapshot = provider_target_snapshot(output_fd, trace_relative, "provider trace")
        if not trace_snapshot.get("exists") or trace_snapshot.get("mode") != 0o644:
            raise AdaptiveError("PROVIDER_TRACE_MISSING", "provider trace is missing or has an unsafe mode")
        try:
            trace = json.loads(trace_snapshot["raw"])
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AdaptiveError("INVALID_PROVIDER_TRACE", "provider trace is invalid JSON") from error
        required_trace_fields = {"schema", "provider", "blueprint_sha256", "design_sha256",
                                 "provider_config_sha256", "commands", "generated_files",
                                 "predecessor_inventory", "overwrite_decision", "trace_sha256"}
        if not isinstance(trace, dict) or set(trace) != required_trace_fields:
            raise AdaptiveError("INVALID_PROVIDER_TRACE", "provider trace fields are invalid")
        committed = {key: value for key, value in trace.items() if key != "trace_sha256"}
        if (trace.get("schema") != "agent-provider-trace/v2" or trace.get("provider") != args.provider
                or trace.get("trace_sha256") != canonical_sha256(committed)):
            raise AdaptiveError("INVALID_PROVIDER_TRACE", "provider trace digest or schema is invalid")
        if (trace.get("blueprint_sha256") != blueprint["confirmation"]["design_sha256"]
                or trace.get("design_sha256") != canonical_sha256(blueprint["design"])
                or trace.get("provider_config_sha256") != canonical_sha256(provider_config)):
            raise AdaptiveError("STALE_PROVIDER_TRACE", "provider trace is stale for the confirmed design")
        expected_commands = [{"id": item["id"], "stage": item["stage"], "covers": item["covers"],
                              "environment": item.get("environment", []),
                              "argv_sha256": canonical_sha256(item["argv"])}
                             for item in workflow_commands(blueprint)]
        if trace.get("commands") != expected_commands:
            raise AdaptiveError("INVALID_PROVIDER_TRACE", "provider command trace is invalid")
        expected_files = gitlab_files(blueprint) if args.provider == "gitlab" else github_files(blueprint)
        expected = {}
        for relative, content in expected_files.items():
            raw = content.encode("utf-8"); expected[relative] = raw if raw.endswith(bytes([10])) else raw + bytes([10])
        expected_inventory = [{"path": name, "sha256": bytes_sha256(raw)} for name, raw in sorted(expected.items())]
        if trace.get("generated_files") != expected_inventory:
            raise AdaptiveError("INVALID_PROVIDER_TRACE", "provider generated-file inventory is invalid")
        for relative, raw in expected.items():
            snapshot = provider_target_snapshot(output_fd, relative, f"generated provider file {relative}")
            if (not snapshot.get("exists") or snapshot["raw"] != raw
                    or snapshot["mode"] != 0o644):
                raise AdaptiveError("PROVIDER_OUTPUT_DRIFT", f"provider file drifted: {relative}")
    finally:
        os.close(output_fd)
    predecessor_inventory = trace.get("predecessor_inventory")
    allowed_predecessors = set(expected) | {trace_relative}
    if (not isinstance(predecessor_inventory, list)
            or predecessor_inventory != sorted(predecessor_inventory, key=lambda item: item.get("path", "") if isinstance(item, dict) else "")
            or len({item.get("path") for item in predecessor_inventory if isinstance(item, dict)}) != len(predecessor_inventory)
            or any(not isinstance(item, dict) or set(item) != {"path", "sha256"}
                   or item["path"] not in allowed_predecessors
                   or not isinstance(item["sha256"], str) or len(item["sha256"]) != 64
                   or any(character not in "0123456789abcdef" for character in item["sha256"])
                   for item in predecessor_inventory)):
        raise AdaptiveError("INVALID_PROVIDER_TRACE", "provider predecessor inventory is invalid")
    decision = trace.get("overwrite_decision")
    if predecessor_inventory:
        if not isinstance(decision, dict) or set(decision) != {"source", "action_sha256", "action", "receipt"}:
            raise AdaptiveError("INVALID_PROVIDER_TRACE", "provider overwrite decision is missing")
        action = decision["action"]
        if (not isinstance(decision["source"], str) or not decision["source"]
                or not isinstance(decision["action_sha256"], str)
                or not isinstance(action, dict)
                or set(action) != {"schema", "provider", "blueprint_sha256", "output_root", "existing", "proposed_trace_sha256"}
                or decision["action_sha256"] != canonical_sha256(action)
                or action.get("schema") != "agent-provider-overwrite-action/v2"
                or action.get("provider") != args.provider
                or action.get("blueprint_sha256") != trace["blueprint_sha256"]
                or action.get("output_root") != output_relative
                or action.get("existing") != predecessor_inventory
                or action.get("proposed_trace_sha256") != canonical_sha256({
                    key: value for key, value in trace.items()
                    if key not in {"overwrite_decision", "trace_sha256"}
                })):
            raise AdaptiveError("INVALID_PROVIDER_TRACE", "provider overwrite decision does not bind this trace and predecessor")
        verify_human_decision(root, gate="adaptive-provider-overwrite", artifact_sha256=decision["action_sha256"],
                              source=decision["source"], record=decision["receipt"])
    elif decision is not None:
        raise AdaptiveError("INVALID_PROVIDER_TRACE", "provider overwrite decision exists without predecessor output")
    print_json({"status": "PROVIDER_TRACE_VERIFIED", "provider": args.provider,
                "trace_sha256": trace["trace_sha256"]})
    return 0


def command_verify(root, args):
    with mutation_lock(root):
        return _command_verify_locked(root, args)


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--root")
    sub = value.add_subparsers(dest="command", required=True)
    emit = sub.add_parser("emit")
    emit.add_argument("--provider", choices=("github", "gitlab"), required=True)
    emit.add_argument("--output-root", default=".")
    emit.add_argument("--force", action="store_true"); emit.add_argument("--plan-overwrite", action="store_true")
    emit.add_argument("--approve-digest"); emit.add_argument("--source"); emit.add_argument("--human-decision-receipt")
    verify = sub.add_parser("verify"); verify.add_argument("--provider", choices=("github", "gitlab"), required=True); verify.add_argument("--output-root", default=".")
    sub.add_parser("recover")
    return value


def main():
    args = parser().parse_args()
    try:
        root = resolve_root(args.root, __file__)
        if args.command == "emit":
            return command_emit(root, args)
        if args.command == "verify":
            return command_verify(root, args)
        return command_recover(root, args)
    except Exception as error:
        return fail(error)


if __name__ == "__main__":
    raise SystemExit(main())
