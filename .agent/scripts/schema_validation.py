#!/usr/bin/env python3
"""Bounded JSON Schema 2020-12 subset used by managed Agent contracts."""
from pathlib import Path
import datetime as dt
import json
import math
import re
from workflowlib import boundedio

MAX_SCHEMA_BYTES = 512 * 1024
MAX_ERRORS = 32
def _reject_nonfinite(token):
    raise json.JSONDecodeError(f"non-finite JSON number is forbidden: {token}", token, 0)


def strict_json_loads(raw, **kwargs):
    """Parse standards-compliant JSON and reject NaN/Infinity at every boundary."""
    if "parse_constant" in kwargs:
        raise TypeError("parse_constant override is forbidden")
    return json.loads(raw, parse_constant=_reject_nonfinite, **kwargs)


def strict_json_dumps(value, **kwargs):
    """Serialize canonical/managed JSON without Python non-finite extensions."""
    if kwargs.get("allow_nan") is True:
        raise ValueError("allow_nan=True is forbidden")
    kwargs["allow_nan"] = False
    return json.dumps(value, **kwargs)


SUPPORTED = {
    "$schema", "$id", "$defs", "$ref", "title", "type", "const", "enum", "oneOf",
    "allOf", "if", "then", "properties", "required", "additionalProperties",
    "items", "minItems", "maxItems", "uniqueItems", "minLength", "maxLength",
    "pattern", "minimum", "maximum", "format", "minProperties", "maxProperties",
}

def _schema_file(name):
    if not isinstance(name, str) or re.fullmatch(r"[a-z0-9-]+\.schema\.json", name) is None:
        raise ValueError("invalid managed schema name")
    path = Path(__file__).resolve().parent.parent / "assets" / "schemas" / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"managed schema is missing or unsafe: {name}")
    try: raw=boundedio.read_bytes(path,maximum=MAX_SCHEMA_BYTES,label=f"managed schema {name}")
    except RuntimeError as error: raise ValueError(str(error)) from error
    if bytes([0]) in raw:
        raise ValueError(f"managed schema is oversized or invalid: {name}")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"managed schema is not valid UTF-8 JSON: {name}") from error
    if not isinstance(value, dict):
        raise ValueError(f"managed schema root is not an object: {name}")
    return value

def _json_identity(value):
    try:
        return strict_json_dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return repr(value)

def _type_matches(value, expected):
    if expected == "object": return isinstance(value, dict)
    if expected == "array": return isinstance(value, list)
    if expected == "string": return isinstance(value, str)
    if expected == "integer": return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number": return (
        isinstance(value, (int, float)) and not isinstance(value, bool)
        and (not isinstance(value, float) or math.isfinite(value))
    )
    if expected == "boolean": return isinstance(value, bool)
    if expected == "null": return value is None
    raise ValueError(f"unsupported schema type: {expected}")

def _resolve_ref(root, reference):
    if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
        raise ValueError(f"unsupported schema reference: {reference!r}")
    name = reference[len("#/$defs/"): ]
    definitions = root.get("$defs")
    if not isinstance(definitions, dict) or name not in definitions or not isinstance(definitions[name], dict):
        raise ValueError(f"unresolved schema reference: {reference}")
    return definitions[name]

def _check_schema(schema, root, location="$", depth=0, reference_stack=frozenset()):
    if depth > 64: raise ValueError(f"schema nesting exceeds limit at {location}")
    if not isinstance(schema, dict): raise ValueError(f"schema node at {location} is not an object")
    unknown = set(schema) - SUPPORTED
    if unknown: raise ValueError(f"unsupported schema keywords at {location}: {sorted(unknown)}")
    if "$ref" in schema:
        reference = schema["$ref"]
        if reference in reference_stack: raise ValueError(f"schema reference cycle at {location}")
        _check_schema(_resolve_ref(root, reference), root, location + ".$ref", depth + 1, reference_stack | {reference})
    for key in ("oneOf", "allOf"):
        if key in schema:
            if not isinstance(schema[key], list) or not schema[key]: raise ValueError(f"{key} at {location} is invalid")
            for index, child in enumerate(schema[key]): _check_schema(child, root, f"{location}.{key}[{index}]", depth + 1, reference_stack)
    for key in ("if", "then", "items"):
        if key in schema: _check_schema(schema[key], root, f"{location}.{key}", depth + 1, reference_stack)
    for key in ("properties", "$defs"):
        if key in schema:
            if not isinstance(schema[key], dict): raise ValueError(f"{key} at {location} is invalid")
            for name, child in schema[key].items(): _check_schema(child, root, f"{location}.{key}.{name}", depth + 1, reference_stack)
    if "pattern" in schema:
        try: re.compile(schema["pattern"])
        except (TypeError, re.error) as error: raise ValueError(f"invalid pattern at {location}") from error
    if "format" in schema and schema["format"] != "date-time": raise ValueError(f"unsupported format at {location}")


def _date_time(value):
    if not isinstance(value, str): return False
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None

def _validate(instance, schema, root, location, errors):
    if len(errors) >= MAX_ERRORS: return
    if not isinstance(schema, dict): raise ValueError(f"schema node at {location} is not an object")
    unknown = set(schema) - SUPPORTED
    if unknown: raise ValueError(f"unsupported schema keywords at {location}: {sorted(unknown)}")
    if "$ref" in schema:
        _validate(instance, _resolve_ref(root, schema["$ref"]), root, location, errors)
        return
    if "const" in schema and instance != schema["const"]: errors.append(f"{location}: const mismatch")
    if "enum" in schema and instance not in schema["enum"]: errors.append(f"{location}: value is outside enum")
    expected = schema.get("type")
    if expected is not None:
        if not isinstance(expected, str): raise ValueError(f"schema type at {location} must be a string")
        if not _type_matches(instance, expected):
            errors.append(f"{location}: expected {expected}")
            return
    if "oneOf" in schema:
        variants = schema["oneOf"]
        if not isinstance(variants, list) or not variants: raise ValueError(f"oneOf at {location} is invalid")
        matched = 0
        for variant in variants:
            branch = []
            _validate(instance, variant, root, location, branch)
            if not branch: matched += 1
        if matched != 1: errors.append(f"{location}: expected exactly one oneOf branch, matched {matched}")
    for child in schema.get("allOf", []): _validate(instance, child, root, location, errors)
    if "if" in schema:
        condition = []
        _validate(instance, schema["if"], root, location, condition)
        if not condition and "then" in schema: _validate(instance, schema["then"], root, location, errors)
    if isinstance(instance, dict):
        if "minProperties" in schema and len(instance) < schema["minProperties"]: errors.append(f"{location}: too few properties")
        if "maxProperties" in schema and len(instance) > schema["maxProperties"]: errors.append(f"{location}: too many properties")
        required = schema.get("required", [])
        if not isinstance(required, list) or any(not isinstance(item, str) for item in required): raise ValueError(f"required at {location} is invalid")
        for key in required:
            if key not in instance: errors.append(f"{location}: missing required property {key}")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict): raise ValueError(f"properties at {location} is invalid")
        if schema.get("additionalProperties") is False:
            for key in sorted(set(instance) - set(properties)): errors.append(f"{location}: unexpected property {key}")
        for key, child in properties.items():
            if key in instance: _validate(instance[key], child, root, f"{location}.{key}", errors)
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]: errors.append(f"{location}: too few items")
        if "maxItems" in schema and len(instance) > schema["maxItems"]: errors.append(f"{location}: too many items")
        if schema.get("uniqueItems") is True:
            identities = [_json_identity(item) for item in instance]
            if len(identities) != len(set(identities)): errors.append(f"{location}: items are not unique")
        if "items" in schema:
            for index, item in enumerate(instance): _validate(item, schema["items"], root, f"{location}[{index}]", errors)
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]: errors.append(f"{location}: string is too short")
        if "maxLength" in schema and len(instance) > schema["maxLength"]: errors.append(f"{location}: string is too long")
        if "pattern" in schema and re.search(schema["pattern"], instance) is None: errors.append(f"{location}: pattern mismatch")
        if schema.get("format") == "date-time" and not _date_time(instance): errors.append(f"{location}: invalid date-time")
        elif "format" in schema and schema["format"] != "date-time": raise ValueError(f"unsupported format at {location}")
    if isinstance(instance, float) and not math.isfinite(instance):
        errors.append(f"{location}: non-finite number is forbidden")
        return
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]: errors.append(f"{location}: below minimum")
        if "maximum" in schema and instance > schema["maximum"]: errors.append(f"{location}: above maximum")

def validate_managed_schema(instance, name, expected_id):
    schema = _schema_file(name)
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" or schema.get("$id") != expected_id:
        raise ValueError(f"managed schema identity drifted: {name}")
    _check_schema(schema, schema)
    errors = []
    _validate(instance, schema, schema, "$", errors)
    return errors[:MAX_ERRORS]
