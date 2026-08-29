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
import uuid

import humandecision
from workflowlib import boundedio
from schema_validation import strict_json_dumps, strict_json_loads, validate_managed_schema

MAX_JSON_BYTES = 2 * 1024 * 1024
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
CI_IMAGE_RE = re.compile(r"(?:[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?/)?(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:[0-9a-f]{64}")
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
    return strict_json_dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_sha256(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def bytes_sha256(value):
    return hashlib.sha256(value).hexdigest()


def default_root(script_file):
    return Path(script_file).resolve().parents[2]


def resolve_root(value, script_file):
    lexical = Path(value).expanduser().absolute() if value else default_root(script_file)
    try:
        observed = os.lstat(lexical)
    except OSError as error:
        raise AdaptiveError("INVALID_ROOT", f"project root is missing or unsafe: {lexical}") from error
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
        raise AdaptiveError("INVALID_ROOT", f"project root is missing or unsafe: {lexical}")
    root = lexical.resolve()
    return root


def ensure_real_directory(path):
    governed = ".agent" in Path(path).parts
    governed_root = next((ancestor.parent for ancestor in [Path(path), *Path(path).parents]
                            if ancestor.name == ".agent"), None)
    missing = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    if cursor.is_symlink() or not cursor.is_dir():
        raise AdaptiveError("UNSAFE_PATH", f"directory ancestor is unsafe: {cursor}")
    if governed:
        probe = cursor
        while True:
            metadata = probe.lstat()
            expected_uid = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
            if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != expected_uid
                    or stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)):
                raise AdaptiveError("UNSAFE_PATH", f"directory ancestor ownership or mode is unsafe: {probe}")
            if probe == governed_root or probe.parent == probe:
                break
            probe = probe.parent
    for item in reversed(missing):
        item.mkdir(mode=0o700)
    cursor = path
    while True:
        metadata = cursor.lstat()
        mode = metadata.st_mode
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
        if (stat.S_ISLNK(mode) or not stat.S_ISDIR(mode) or (governed and (
                metadata.st_uid != expected_uid or stat.S_IMODE(mode) & (stat.S_IWGRP | stat.S_IWOTH)))):
            raise AdaptiveError("UNSAFE_PATH", f"directory ownership or mode is unsafe: {cursor}")
        if cursor.parent == cursor:
            break
        if (governed and cursor == governed_root) or cursor == path.anchor:
            break
        cursor = cursor.parent


def _open_governed_parent(path):
    path = Path(path)
    agent = next((ancestor for ancestor in [path, *path.parents] if ancestor.name == ".agent"), None)
    if agent is None or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise AdaptiveError("UNSAFE_PATH", f"governed path cannot be opened safely: {path}")
    root = agent.parent
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(root, flags)
    expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.fstat(descriptor).st_uid
    try:
        for component in path.parent.relative_to(root).parts:
            metadata = os.fstat(descriptor)
            if (metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)):
                raise AdaptiveError("UNSAFE_PATH", f"governed parent is unsafe: {path.parent}")
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def atomic_write_bytes(path, data, mode=0o600):
    path = Path(path)
    ensure_real_directory(path.parent)
    if ".agent" in path.parts:
        directory = _open_governed_parent(path)
        temporary = f".{path.name}.{uuid.uuid4().hex}"
        handle = None
        try:
            expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.fstat(directory).st_uid
            try:
                existing = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None and (not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1
                    or existing.st_uid != expected_uid or stat.S_IMODE(existing.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)):
                raise AdaptiveError("UNSAFE_PATH", f"target is not one owned regular file: {path}")
            handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=directory)
            os.fchmod(handle, mode)
            view = memoryview(data)
            while view:
                view = view[os.write(handle, view):]
            os.fsync(handle); os.close(handle); handle = None
            os.rename(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            if handle is not None: os.close(handle)
            try: os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError: pass
            os.close(directory)
        return
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise AdaptiveError("UNSAFE_PATH", f"target is not a regular file: {path}")
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb", closefd=True) as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try: os.unlink(temporary)
        except FileNotFoundError: pass


def write_json(path, value):
    atomic_write_bytes(path, strict_json_dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + bytes([10]))


def durable_unlink(path):
    path=Path(path); directory=_open_governed_parent(path)
    try:
        observed=os.stat(path.name,dir_fd=directory,follow_symlinks=False)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1:
            raise AdaptiveError("UNSAFE_PATH",f"durable unlink target is unsafe: {path}",3)
        os.unlink(path.name,dir_fd=directory); os.fsync(directory)
    finally: os.close(directory)


def durable_rename(source,destination):
    source=Path(source); destination=Path(destination)
    source_directory=_open_governed_parent(source); destination_directory=_open_governed_parent(destination)
    try:
        observed=os.stat(source.name,dir_fd=source_directory,follow_symlinks=False)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1:
            raise AdaptiveError("UNSAFE_PATH",f"durable rename source is unsafe: {source}",3)
        try: existing=os.stat(destination.name,dir_fd=destination_directory,follow_symlinks=False)
        except FileNotFoundError: existing=None
        if existing is not None:
            raise AdaptiveError("UNSAFE_PATH",f"durable rename destination already exists: {destination}",3)
        os.rename(source.name,destination.name,src_dir_fd=source_directory,dst_dir_fd=destination_directory)
        os.fsync(destination_directory)
        if (os.fstat(source_directory).st_dev,os.fstat(source_directory).st_ino)!=(os.fstat(destination_directory).st_dev,os.fstat(destination_directory).st_ino):
            os.fsync(source_directory)
    finally:
        os.close(destination_directory); os.close(source_directory)


def load_json(path, label="JSON", maximum=MAX_JSON_BYTES):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise AdaptiveError("MISSING_FILE", f"{label} is missing or unsafe: {path}")
    size = path.stat().st_size
    if size > maximum:
        raise AdaptiveError("FILE_TOO_LARGE", f"{label} exceeds {maximum} bytes")
    try:
        return strict_json_loads(boundedio.read_text(path,maximum=MAX_JSON_BYTES,label="adaptive JSON"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AdaptiveError("INVALID_JSON", f"{label} is not valid UTF-8 JSON: {error}") from error


@contextmanager
def mutation_lock(root):
    project = Path(root) / ".agent/project"
    ensure_real_directory(project)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise AdaptiveError("MUTATION_LOCK_UNAVAILABLE", "host cannot provide no-follow descriptor locks", 3)
    directory = os.open(project, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        directory_stat = os.fstat(directory)
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else directory_stat.st_uid
        if (not stat.S_ISDIR(directory_stat.st_mode) or directory_stat.st_uid != expected_uid
                or stat.S_IMODE(directory_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)):
            raise AdaptiveError("MUTATION_LOCK_UNSAFE", "adaptive mutation lock parent is unsafe", 3)
        descriptor = os.open(".mutation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except (ImportError, OSError) as error:
            raise AdaptiveError("MUTATION_LOCK_UNAVAILABLE", "host cannot provide an exclusive adaptive mutation lock", 3) from error
        opened = os.fstat(descriptor)
        observed = os.stat(".mutation.lock", dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_uid != expected_uid
                or stat.S_IMODE(opened.st_mode) != 0o600
                or (observed.st_dev, observed.st_ino) != (opened.st_dev, opened.st_ino)):
            raise AdaptiveError("MUTATION_LOCK_UNSAFE", "adaptive mutation lock is not one owned mode-0600 regular file", 3)
        yield
        # Revalidate after the protected mutation so replacing the lock pathname
        # cannot create two independent lock domains.
        observed = os.stat(".mutation.lock", dir_fd=directory, follow_symlinks=False)
        if (observed.st_dev, observed.st_ino) != (opened.st_dev, opened.st_ino):
            raise AdaptiveError("MUTATION_LOCK_UNSAFE", "adaptive mutation lock pathname changed while held", 3)
    except OSError as error:
        raise AdaptiveError("MUTATION_LOCK_UNSAFE", f"cannot use adaptive mutation lock safely: {error}", 3) from error
    finally:
        if descriptor is not None:
            try:
                if 'fcntl' in locals():
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        os.close(directory)


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


def prepare_provider_human_decision(root, *, gate, artifact_sha256, source, receipt=None):
    if not receipt:
        raise AdaptiveError("HUMAN_DECISION_REQUIRED", f"gate {gate} requires a host/provider-verifiable receipt", 2)
    config,task=decision_context(root)
    try:
        return humandecision.prepare_decision_request(Path(root),config,task,gate=gate,
            artifact_sha256=artifact_sha256,source=source,receipt=receipt)
    except SystemExit as error:
        raise AdaptiveError("HUMAN_DECISION_REQUIRED",str(error)) from error


def consume_prepared_provider_human_decision(root, *, gate, artifact_sha256, source, prepared):
    config,task=decision_context(root)
    try:
        return humandecision.consume_prepared_decision(Path(root),config,task,gate=gate,
            artifact_sha256=artifact_sha256,source=source,prepared=prepared)
    except SystemExit as error:
        raise AdaptiveError("HUMAN_DECISION_STATUS_UNKNOWN",str(error),3) from error


def status_prepared_provider_human_decision(root, *, gate, artifact_sha256, source, prepared):
    config,task=decision_context(root)
    try:
        return humandecision.status_prepared_decision(Path(root),config,task,gate=gate,
            artifact_sha256=artifact_sha256,source=source,prepared=prepared)
    except SystemExit as error:
        raise AdaptiveError("HUMAN_DECISION_STATUS_UNKNOWN",str(error),3) from error


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
    if CI_IMAGE_RE.fullmatch(value) is None:
        raise AdaptiveError("INVALID_BLUEPRINT", f"{label} must be a canonical lowercase immutable @sha256 image reference")
    return value


def validate_providers(value):
    if not isinstance(value, list) or len(value) > 16:
        raise AdaptiveError("INVALID_BLUEPRINT", "providers must be a bounded user-supplied list")
    providers = []
    for index, provider in enumerate(value):
        if not isinstance(provider, dict) or not isinstance(provider.get("id"), str) or ID_RE.fullmatch(provider["id"]) is None:
            raise AdaptiveError("INVALID_BLUEPRINT", f"providers[{index}] identity is invalid")
        if provider["id"] == "github":
            required={"id","runner","protected_runner","candidate_ephemeral","protected_ephemeral","protected_isolated","container_image","default_branch"}
            if set(provider) not in (required,required|{"host"}) or any(provider.get(key) is not True for key in ("candidate_ephemeral","protected_ephemeral","protected_isolated")):
                raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}] GitHub fields or ephemeral isolation authority are invalid")
            def github_runner(field):
                runner=provider[field]
                if isinstance(runner,list):
                    if not 1<=len(runner)<=8 or len(runner)!=len(set(runner)): raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}].{field} labels are invalid")
                    runner=[safe_ci_scalar(item,f"providers[{index}].{field}") for item in runner]
                else: runner=safe_ci_scalar(runner,f"providers[{index}].{field}")
                labels=runner if isinstance(runner,list) else [runner]
                if any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,255}",label) is None for label in labels): raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}].{field} labels are invalid")
                normalized={label.casefold() for label in labels}
                if any(re.search(r"(?:^|[-_.])windows(?:$|[-_.])|^windows-|^win32$",label) for label in normalized): raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}].{field} selects unsupported native Windows")
                if not any(label in {"linux","macos"} or label.startswith(("ubuntu-","macos-")) for label in normalized): raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}].{field} must explicitly select Linux or macOS POSIX")
                return runner,normalized
            runner,candidate_labels=github_runner("runner"); protected_runner,protected_labels=github_runner("protected_runner")
            if "self-hosted" in candidate_labels|protected_labels and (candidate_labels==protected_labels or not candidate_labels-protected_labels or not protected_labels-candidate_labels):
                raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}] self-hosted candidate and protected pools need distinct authority labels")
            branch=clean_string(provider["default_branch"],f"providers[{index}].default_branch",maximum=128)
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}",branch) is None or ".." in branch or "//" in branch or branch.endswith("/"): raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}].default_branch is invalid")
            container_image=pinned_ci_image(provider["container_image"],f"providers[{index}].container_image",nullable=True)
            if container_image is not None and any(label=="macos" or label.startswith("macos-") for label in candidate_labels|protected_labels): raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}] cannot combine a GitHub macOS runner with a container image")
            normalized={"id":"github","runner":runner,"protected_runner":protected_runner,"candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True,"container_image":container_image,"default_branch":branch}
            if "host" in provider:
                host=clean_string(provider["host"],f"providers[{index}].host",maximum=256)
                if re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*(?::[0-9]{1,5})?",host) is None: raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}].host is invalid")
                normalized["host"]=host
            providers.append(normalized)
        elif provider["id"] == "gitlab":
            required={"id","platform","image","tags","protected_tags","candidate_ephemeral","protected_ephemeral","protected_isolated"}
            if set(provider)!=required or any(provider.get(key) is not True for key in ("candidate_ephemeral","protected_ephemeral","protected_isolated")): raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}] GitLab fields or ephemeral isolation authority are invalid")
            platform=provider["platform"]
            if platform not in {"linux","macos"}: raise AdaptiveError("UNSUPPORTED_PROVIDER_PLATFORM",f"providers[{index}] must explicitly select Linux or macOS POSIX")
            tags=clean_string_list(provider["tags"],f"providers[{index}].tags",maximum_items=16)
            protected_tags=clean_string_list(provider["protected_tags"],f"providers[{index}].protected_tags",maximum_items=16)
            if (not tags or not protected_tags or len(tags)!=len(set(tags)) or len(protected_tags)!=len(set(protected_tags))
                    or any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",tag) is None for tag in tags+protected_tags)):
                raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}] GitLab runner tags are invalid")
            candidate_set={tag.casefold() for tag in tags}; protected_set={tag.casefold() for tag in protected_tags}
            if candidate_set==protected_set or not candidate_set-protected_set or not protected_set-candidate_set: raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}] candidate and protected GitLab pools need distinct authority tags")
            if any(re.search(r"(?:^|[-_.])windows(?:$|[-_.])|^windows-|^win32$",tag) for tag in candidate_set|protected_set): raise AdaptiveError("UNSUPPORTED_PROVIDER_PLATFORM",f"providers[{index}] selects unsupported native Windows runner tags")
            image=pinned_ci_image(provider["image"],f"providers[{index}].image",nullable=True)
            if platform=="macos" and image is not None: raise AdaptiveError("UNSUPPORTED_PROVIDER_PLATFORM",f"providers[{index}] cannot combine a GitLab macOS runner with a container image")
            providers.append({"id":"gitlab","platform":platform,"image":image,"tags":tags,"protected_tags":protected_tags,"candidate_ephemeral":True,"protected_ephemeral":True,"protected_isolated":True})
        else:
            if set(provider) not in ({"id","kind","configuration"},{"id","kind","configuration","discovery_aliases"}) or ID_RE.fullmatch(str(provider.get("kind", ""))) is None:
                raise AdaptiveError("INVALID_BLUEPRINT", f"providers[{index}] generic fields are invalid")
            configuration = provider["configuration"]
            if not isinstance(configuration, list) or len(configuration) > 32:
                raise AdaptiveError("INVALID_BLUEPRINT", f"providers[{index}].configuration is invalid")
            normalized = []
            for setting_index, setting in enumerate(configuration):
                if not isinstance(setting, dict) or set(setting) != {"key", "value"} or ID_RE.fullmatch(str(setting.get("key", ""))) is None:
                    raise AdaptiveError("INVALID_BLUEPRINT", f"providers[{index}].configuration[{setting_index}] is invalid")
                if re.search(r"(?i)(?:token|secret|password|credential|private|api[._-]?key|auth)",setting["key"]):
                    raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}].configuration[{setting_index}] may not store secret-bearing settings; use runtime secret injection")
                public_value=clean_string(setting.get("value"),f"providers[{index}].configuration[{setting_index}].value",maximum=512)
                if re.search(r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:ghp|glpat|github_pat)_[A-Za-z0-9_-]{12,}|[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@)",public_value):
                    raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}].configuration[{setting_index}] contains credential-like content")
                normalized.append({"key":setting["key"],"value":public_value})
            keys = [item["key"] for item in normalized]
            if len(keys) != len(set(keys)):
                raise AdaptiveError("INVALID_BLUEPRINT", f"providers[{index}].configuration contains duplicate keys")
            normalized_provider={"id":provider["id"],"kind":provider["kind"],"configuration":normalized}
            if "discovery_aliases" in provider:
                aliases=clean_string_list(provider["discovery_aliases"],f"providers[{index}].discovery_aliases",maximum_items=8)
                if any(len(alias)>64 or re.fullmatch(r"[a-z0-9][a-z0-9 +._-]{0,63}",alias) is None for alias in aliases):
                    raise AdaptiveError("INVALID_BLUEPRINT",f"providers[{index}].discovery_aliases must be explicit public search phrases")
                normalized_provider["discovery_aliases"]=aliases
            providers.append(normalized_provider)
    ids = [item["id"] for item in providers]
    if len(ids) != len(set(ids)):
        raise AdaptiveError("INVALID_BLUEPRINT", "providers contains duplicate IDs")
    return providers


def validate_design(value, *, require_material=False):
    allowed_keys=DESIGN_KEYS|{"application_services"}
    if not isinstance(value, dict) or set(value) not in (DESIGN_KEYS,allowed_keys):
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
    if "application_services" in value:
        services=value["application_services"]
        if (not isinstance(services,list) or not 1<=len(services)<=16 or len(services)!=len(set(services))
                or any(not isinstance(service,str) or re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}",service) is None for service in services)):
            raise AdaptiveError("INVALID_BLUEPRINT","application_services must be an exact non-empty user-confirmed Compose service set")
        design["application_services"]=sorted(services)
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
    try:
        schema_errors = validate_managed_schema(value, "project-blueprint.schema.json", "agent-project-blueprint/v1")
    except ValueError as error:
        raise AdaptiveError("INVALID_MANAGED_SCHEMA", str(error), 3) from error
    if schema_errors:
        raise AdaptiveError("INVALID_BLUEPRINT", "Blueprint schema validation failed: " + "; ".join(schema_errors))
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
            raise AdaptiveError("INVALID_BLUEPRINT", "blueprint confirmation must identify a provider-observed user decision")
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
        verify_provider_human_decision(
            root, gate="adaptive-blueprint-confirm", artifact_sha256=confirmation["design_sha256"],
            source=confirmation["source"], record=confirmation["decision_receipt"],
        )
    return value


def print_json(value):
    print(strict_json_dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def fail(error):
    if isinstance(error, AdaptiveError):
        print(f"{error.code}: {error}")
        return error.exit_code
    print(f"INTERNAL_ERROR: {error}")
    return 1
