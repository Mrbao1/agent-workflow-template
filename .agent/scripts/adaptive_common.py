#!/usr/bin/env python3
"""Deterministic helpers for user-confirmed adaptive workflow controls."""
from pathlib import Path, PurePosixPath
from contextlib import contextmanager
import datetime as dt
import hashlib
import json
import os
import re
import stat
import tempfile

import humandecision

MAX_JSON_BYTES = 2 * 1024 * 1024
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
SHELLS = {"sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}
CONTROL_TOKENS = {"&&", "||", ";", "|", ">", ">>", "<"}
DESIGN_KEYS = {
    "goals", "architecture", "technology_choices", "capabilities", "constraints",
    "acceptance", "commands", "providers",
}


class AdaptiveError(RuntimeError):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


def utc_now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_sha256(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def bytes_sha256(value):
    return hashlib.sha256(value).hexdigest()


def default_root(script_file):
    return Path(script_file).resolve().parents[2]


def resolve_root(value, script_file):
    root = Path(value).expanduser().resolve() if value else default_root(script_file)
    if root.is_symlink() or not root.is_dir():
        raise AdaptiveError("INVALID_ROOT", f"project root is missing or unsafe: {root}")
    return root


def ensure_real_directory(path):
    missing = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    if cursor.is_symlink() or not cursor.is_dir():
        raise AdaptiveError("UNSAFE_PATH", f"directory ancestor is unsafe: {cursor}")
    for item in reversed(missing):
        item.mkdir(mode=0o700)
    cursor = path
    while True:
        mode = cursor.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise AdaptiveError("UNSAFE_PATH", f"directory is unsafe: {cursor}")
        if cursor.parent == cursor:
            break
        if cursor.name == ".agent" or cursor == path.anchor:
            break
        cursor = cursor.parent


def atomic_write_bytes(path, data, mode=0o600):
    path = Path(path)
    ensure_real_directory(path.parent)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise AdaptiveError("UNSAFE_PATH", f"target is not a regular file: {path}")
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def write_json(path, value):
    atomic_write_bytes(path, json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + bytes([10]))


def load_json(path, label="JSON", maximum=MAX_JSON_BYTES):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AdaptiveError("MISSING_FILE", f"{label} is missing or unsafe: {path}")
    size = path.stat().st_size
    if size > maximum:
        raise AdaptiveError("FILE_TOO_LARGE", f"{label} exceeds {maximum} bytes")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AdaptiveError("INVALID_JSON", f"{label} is not valid UTF-8 JSON: {error}") from error


@contextmanager
def mutation_lock(root):
    project = Path(root) / ".agent/project"
    ensure_real_directory(project)
    path = project / ".mutation.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise AdaptiveError("MUTATION_LOCK_UNSAFE", f"cannot open adaptive mutation lock: {error}", 3) from error
    try:
        observed = os.lstat(path); opened = os.fstat(descriptor)
        if (not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1 or
                (observed.st_dev, observed.st_ino) != (opened.st_dev, opened.st_ino)):
            raise AdaptiveError("MUTATION_LOCK_UNSAFE", "adaptive mutation lock is not one real regular file", 3)
        try:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except (ImportError, OSError) as error:
            raise AdaptiveError("MUTATION_LOCK_UNAVAILABLE", "host cannot provide an exclusive adaptive mutation lock", 3) from error
        yield
    finally:
        try:
            if 'fcntl' in locals():
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def decision_context(root):
    config = load_json(Path(root) / ".agent/config.json", "workflow config")
    task = load_json(Path(root) / ".agent/state/TASK.json", "workflow task")
    return config, task


def record_human_decision(root, *, gate, artifact_sha256, source, receipt=None):
    config, task = decision_context(root)
    try:
        return humandecision.record_decision_approval(
            Path(root), config, task, gate=gate, artifact_sha256=artifact_sha256,
            source=source, receipt=receipt,
        )
    except SystemExit as error:
        raise AdaptiveError("HUMAN_DECISION_REQUIRED", str(error)) from error


def verify_human_decision(root, *, gate, artifact_sha256, source, record):
    config, task = decision_context(root)
    if not humandecision.decision_approval_valid(
        Path(root), config, task, gate=gate, artifact_sha256=artifact_sha256,
        source=source, record=record,
    ):
        raise AdaptiveError("INVALID_HUMAN_DECISION", f"stored human decision is invalid for gate {gate}", 3)
    return record


def record_provider_human_decision(root, *, gate, artifact_sha256, source, receipt=None):
    if not receipt:
        raise AdaptiveError("HUMAN_DECISION_REQUIRED", f"gate {gate} requires a host/provider-verifiable receipt", 2)
    config, task = decision_context(root)
    try:
        return humandecision.verify(
            Path(root), config, task, gate=gate, artifact_sha256=artifact_sha256,
            source=source, receipt=receipt,
        )
    except SystemExit as error:
        raise AdaptiveError("HUMAN_DECISION_REQUIRED", str(error)) from error


def verify_provider_human_decision(root, *, gate, artifact_sha256, source, record):
    config, task = decision_context(root)
    if not humandecision.reverify(
        Path(root), config, task, gate=gate, artifact_sha256=artifact_sha256,
        source=source, record=record,
    ):
        raise AdaptiveError("INVALID_HUMAN_DECISION", f"stored provider decision is invalid for gate {gate}", 3)
    return record


def safe_relative_path(value, *, suffix=None):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
        raise AdaptiveError("UNSAFE_PATH", "path must be a non-empty bounded string")
    if chr(92) in value or any(ord(char) < 32 for char in value):
        raise AdaptiveError("UNSAFE_PATH", f"path contains forbidden characters: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AdaptiveError("UNSAFE_PATH", f"path escapes its root: {value!r}")
    if suffix and not value.lower().endswith(suffix.lower()):
        raise AdaptiveError("UNSAFE_PATH", f"path must end with {suffix}: {value!r}")
    return path


def clean_string(value, label, *, maximum=2048):
    if not isinstance(value, str) or not value.strip():
        raise AdaptiveError("INVALID_BLUEPRINT", f"{label} must be a non-empty string")
    value = value.strip()
    if len(value.encode("utf-8")) > maximum or any(ord(char) == 0 for char in value):
        raise AdaptiveError("INVALID_BLUEPRINT", f"{label} exceeds its safe bound")
    return value


def clean_string_list(value, label, *, required=False, maximum_items=32):
    if not isinstance(value, list) or len(value) > maximum_items:
        raise AdaptiveError("INVALID_BLUEPRINT", f"{label} must be a bounded list")
    cleaned = [clean_string(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if required and not cleaned:
        raise AdaptiveError("INVALID_BLUEPRINT", f"{label} requires a user decision")
    if len(cleaned) != len(set(cleaned)):
        raise AdaptiveError("INVALID_BLUEPRINT", f"{label} contains duplicates")
    return cleaned


def validate_id_records(value, label, text_key, *, required=False):
    if not isinstance(value, list) or len(value) > 64:
        raise AdaptiveError("INVALID_BLUEPRINT", f"{label} must be a bounded list")
    records = []
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != {"id", text_key} or not ID_RE.fullmatch(str(item.get("id", ""))):
            raise AdaptiveError("INVALID_BLUEPRINT", f"{label}[{index}] fields or ID are invalid")
        records.append({"id": item["id"], text_key: clean_string(item[text_key], f"{label}[{index}].{text_key}")})
    if required and not records:
        raise AdaptiveError("INVALID_BLUEPRINT", f"{label} requires a user decision")
    ids = [item["id"] for item in records]
    if len(ids) != len(set(ids)):
        raise AdaptiveError("INVALID_BLUEPRINT", f"{label} contains duplicate IDs")
    return records


def validate_acceptance_records(value, *, required=False):
    if not isinstance(value, list) or len(value) > 64:
        raise AdaptiveError("INVALID_BLUEPRINT", "acceptance must be a bounded list")
    records = []
    for index, item in enumerate(value):
        base = {"id", "criterion"}
        if not isinstance(item, dict) or set(item) not in {frozenset(base), frozenset(base | {"method"})} or not ID_RE.fullmatch(str(item.get("id", ""))):
            raise AdaptiveError("INVALID_BLUEPRINT", f"acceptance[{index}] fields or ID are invalid")
        method = item.get("method", "executable")
        if method not in {"executable", "evidence", "manual"}:
            raise AdaptiveError("INVALID_BLUEPRINT", f"acceptance[{index}].method is invalid")
        record = {"id": item["id"], "criterion": clean_string(item["criterion"], f"acceptance[{index}].criterion")}
        if "method" in item:
            record["method"] = method
        records.append(record)
    if required and not records:
        raise AdaptiveError("INVALID_BLUEPRINT", "acceptance requires a user decision")
    ids = [item["id"] for item in records]
    if len(ids) != len(set(ids)):
        raise AdaptiveError("INVALID_BLUEPRINT", "acceptance contains duplicate IDs")
    return records


def acceptance_method(record):
    return record.get("method", "executable")


def validate_command(value, index):
    required = {"id", "argv", "stage", "timeout_seconds", "covers"}
    if not isinstance(value, dict) or set(value) not in {frozenset(required), frozenset(required | {"environment"})}:
        raise AdaptiveError("INVALID_BLUEPRINT", f"commands[{index}] fields are invalid")
    command_id = value.get("id")
    if not isinstance(command_id, str) or not ID_RE.fullmatch(command_id):
        raise AdaptiveError("INVALID_BLUEPRINT", f"commands[{index}].id is invalid")
    argv = value.get("argv")
    if not isinstance(argv, list) or not 1 <= len(argv) <= 64:
        raise AdaptiveError("INVALID_BLUEPRINT", f"commands[{index}].argv is invalid")
    argv = [clean_string(item, f"commands[{index}].argv", maximum=1024) for item in argv]
    executable = Path(argv[0]).name.lower()
    if executable in SHELLS or any(Path(item).name.lower() in SHELLS for item in argv) or any(item in CONTROL_TOKENS for item in argv):
        raise AdaptiveError("INVALID_BLUEPRINT", f"commands[{index}] may not invoke a shell or control token")
    stage = value.get("stage")
    if stage not in {"design", "development", "acceptance", "ci"}:
        raise AdaptiveError("INVALID_BLUEPRINT", f"commands[{index}].stage is invalid")
    timeout = value.get("timeout_seconds")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 3600:
        raise AdaptiveError("INVALID_BLUEPRINT", f"commands[{index}].timeout_seconds is invalid")
    covers = clean_string_list(value.get("covers"), f"commands[{index}].covers", maximum_items=64)
    if any(not ID_RE.fullmatch(item) for item in covers):
        raise AdaptiveError("INVALID_BLUEPRINT", f"commands[{index}].covers contains an invalid acceptance ID")
    environment = clean_string_list(value.get("environment", []), f"commands[{index}].environment", maximum_items=32)
    if any(re.fullmatch(r"[A-Z_][A-Z0-9_]{0,63}", item) is None for item in environment):
        raise AdaptiveError("INVALID_BLUEPRINT", f"commands[{index}].environment contains an invalid variable name")
    result = {"id": command_id, "argv": argv, "stage": stage, "timeout_seconds": timeout, "covers": covers}
    if "environment" in value:
        result["environment"] = environment
    return result


def safe_ci_scalar(value, label, *, nullable=False):
    if nullable and value is None:
        return None
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,255}", value) is None:
        raise AdaptiveError("INVALID_BLUEPRINT", f"{label} is not a safe CI scalar")
    return value


def pinned_ci_image(value, label, *, nullable=False):
    value = safe_ci_scalar(value, label, nullable=nullable)
    if value is None:
        return None
    if re.search(r"@sha256:[0-9a-f]{64}$", value) is None:
        raise AdaptiveError("INVALID_BLUEPRINT", f"{label} must use an immutable @sha256 image digest")
    return value


def validate_providers(value):
    if not isinstance(value, list) or len(value) > 2:
        raise AdaptiveError("INVALID_BLUEPRINT", "providers must be a bounded user-supplied list")
    providers = []
    for index, provider in enumerate(value):
        if not isinstance(provider, dict) or provider.get("id") not in {"github", "gitlab"}:
            raise AdaptiveError("INVALID_BLUEPRINT", f"providers[{index}] identity is invalid")
        if provider["id"] == "github":
            if set(provider) != {"id", "runner", "container_image"}:
                raise AdaptiveError("INVALID_BLUEPRINT", f"providers[{index}] GitHub fields are invalid")
            runner = provider["runner"]
            if isinstance(runner, list):
                if not 1 <= len(runner) <= 8 or len(runner) != len(set(runner)):
                    raise AdaptiveError("INVALID_BLUEPRINT", f"providers[{index}].runner labels are invalid")
                runner = [safe_ci_scalar(item, f"providers[{index}].runner") for item in runner]
            else:
                runner = safe_ci_scalar(runner, f"providers[{index}].runner")
            providers.append({"id": "github", "runner": runner,
                              "container_image": pinned_ci_image(provider["container_image"], f"providers[{index}].container_image", nullable=True)})
        else:
            if set(provider) != {"id", "image", "tags"}:
                raise AdaptiveError("INVALID_BLUEPRINT", f"providers[{index}] GitLab fields are invalid")
            tags = clean_string_list(provider["tags"], f"providers[{index}].tags", maximum_items=16)
            if any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tag) is None for tag in tags):
                raise AdaptiveError("INVALID_BLUEPRINT", f"providers[{index}].tags contains an invalid tag")
            providers.append({"id": "gitlab", "image": pinned_ci_image(provider["image"], f"providers[{index}].image", nullable=True), "tags": tags})
    ids = [item["id"] for item in providers]
    if len(ids) != len(set(ids)):
        raise AdaptiveError("INVALID_BLUEPRINT", "providers contains duplicate IDs")
    return providers


def validate_design(value, *, require_material=False):
    if not isinstance(value, dict) or set(value) != DESIGN_KEYS:
        raise AdaptiveError("INVALID_BLUEPRINT", "design fields are invalid")
    design = {
        "goals": clean_string_list(value["goals"], "goals", required=require_material),
        "architecture": clean_string_list(value["architecture"], "architecture"),
        "capabilities": validate_id_records(value["capabilities"], "capabilities", "description"),
        "constraints": clean_string_list(value["constraints"], "constraints"),
        "acceptance": validate_acceptance_records(value["acceptance"], required=require_material),
    }
    choices = value.get("technology_choices")
    if not isinstance(choices, list) or len(choices) > 32:
        raise AdaptiveError("INVALID_BLUEPRINT", "technology_choices must be a bounded user-supplied list")
    design["technology_choices"] = []
    for index, choice in enumerate(choices):
        if not isinstance(choice, dict) or set(choice) != {"name", "reason"}:
            raise AdaptiveError("INVALID_BLUEPRINT", f"technology_choices[{index}] fields are invalid")
        design["technology_choices"].append({
            "name": clean_string(choice["name"], f"technology_choices[{index}].name", maximum=256),
            "reason": clean_string(choice["reason"], f"technology_choices[{index}].reason"),
        })
    names = [item["name"].casefold() for item in design["technology_choices"]]
    if len(names) != len(set(names)):
        raise AdaptiveError("INVALID_BLUEPRINT", "technology_choices contain duplicate names")
    commands = value.get("commands")
    if not isinstance(commands, list) or len(commands) > 32:
        raise AdaptiveError("INVALID_BLUEPRINT", "commands must be a bounded list")
    design["commands"] = [validate_command(item, index) for index, item in enumerate(commands)]
    ids = [item["id"] for item in design["commands"]]
    if len(ids) != len(set(ids)):
        raise AdaptiveError("INVALID_BLUEPRINT", "commands contain duplicate IDs")
    acceptance_ids = {item["id"] for item in design["acceptance"]}
    executable_ids = {item["id"] for item in design["acceptance"] if acceptance_method(item) == "executable"}
    for command in design["commands"]:
        unknown = set(command["covers"]) - executable_ids
        if unknown:
            raise AdaptiveError("INVALID_BLUEPRINT", f"command {command['id']} covers non-executable or unknown acceptance IDs: {sorted(unknown)}")
        if command["covers"] and command["stage"] not in {"acceptance", "ci"}:
            raise AdaptiveError("INVALID_BLUEPRINT", f"command {command['id']} may cover acceptance only in acceptance or ci stage")
    covered = {item for command in design["commands"] if command["stage"] in {"acceptance", "ci"} for item in command["covers"]}
    if require_material and covered != executable_ids:
        raise AdaptiveError("INVALID_BLUEPRINT", f"executable acceptance coverage is incomplete: missing={sorted(executable_ids-covered)} extra={sorted(covered-executable_ids)}")
    design["providers"] = validate_providers(value.get("providers"))
    return design


def validate_blueprint(value, *, require_confirmed=False):
    if not isinstance(value, dict) or set(value) != {"schema", "status", "design", "suggestions", "confirmation"}:
        raise AdaptiveError("INVALID_BLUEPRINT", "blueprint fields are invalid")
    if value.get("schema") != "agent-project-blueprint/v1" or value.get("status") not in {"draft", "confirmed"}:
        raise AdaptiveError("INVALID_BLUEPRINT", "blueprint schema or status is invalid")
    design = validate_design(value.get("design"), require_material=value.get("status") == "confirmed")
    suggestions = value.get("suggestions")
    if not isinstance(suggestions, list) or len(suggestions) > 32:
        raise AdaptiveError("INVALID_BLUEPRINT", "suggestions must be a bounded non-authoritative list")
    cleaned_suggestions = []
    for index, item in enumerate(suggestions):
        if not isinstance(item, dict) or set(item) != {"value", "evidence"}:
            raise AdaptiveError("INVALID_BLUEPRINT", f"suggestions[{index}] fields are invalid")
        cleaned_suggestions.append({
            "value": clean_string(item["value"], f"suggestions[{index}].value"),
            "evidence": clean_string(item["evidence"], f"suggestions[{index}].evidence"),
        })
    confirmation = value.get("confirmation")
    if value["status"] == "draft":
        if confirmation is not None:
            raise AdaptiveError("INVALID_BLUEPRINT", "draft blueprint may not carry confirmation")
    else:
        required = {"source", "design_sha256", "confirmed_at", "decision_receipt"}
        if not isinstance(confirmation, dict) or set(confirmation) != required:
            raise AdaptiveError("INVALID_BLUEPRINT", "confirmed blueprint receipt fields are invalid")
        if not isinstance(confirmation.get("source"), str) or not confirmation["source"].startswith("user:"):
            raise AdaptiveError("INVALID_BLUEPRINT", "blueprint confirmation must come from an explicit user decision")
        if not SHA256_RE.fullmatch(str(confirmation.get("design_sha256", ""))) or not isinstance(confirmation.get("decision_receipt"), dict):
            raise AdaptiveError("INVALID_BLUEPRINT", "blueprint confirmation digest or decision receipt is invalid")
        if confirmation["design_sha256"] != canonical_sha256(design):
            raise AdaptiveError("BLUEPRINT_DRIFT", "confirmed blueprint design changed after user approval")
        clean_string(confirmation.get("confirmed_at"), "confirmation.confirmed_at", maximum=64)
    if require_confirmed and value["status"] != "confirmed":
        raise AdaptiveError("BLUEPRINT_NOT_CONFIRMED", "Skill and template selection waits for explicit user design confirmation")
    return {
        "schema": value["schema"], "status": value["status"], "design": design,
        "suggestions": cleaned_suggestions, "confirmation": confirmation,
    }


def blueprint_path(root):
    return Path(root) / ".agent/project/BLUEPRINT.json"


def load_blueprint(root, *, require_confirmed=False):
    value = validate_blueprint(load_json(blueprint_path(root), "project blueprint"), require_confirmed=require_confirmed)
    if value["status"] == "confirmed":
        confirmation = value["confirmation"]
        verify_human_decision(
            root, gate="adaptive-blueprint-confirm", artifact_sha256=confirmation["design_sha256"],
            source=confirmation["source"], record=confirmation["decision_receipt"],
        )
    return value


def print_json(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def fail(error):
    if isinstance(error, AdaptiveError):
        print(f"{error.code}: {error}")
        return error.exit_code
    print(f"INTERNAL_ERROR: {error}")
    return 1
