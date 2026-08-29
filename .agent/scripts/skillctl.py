#!/usr/bin/env python3
"""Discover, score, lock, install, verify, update, retire, and roll back content-only Skills."""
from pathlib import Path
from contextlib import contextmanager
from urllib import error as urlerror, parse as urlparse, request as urlrequest
import argparse
import base64
import datetime as dt
import json
import math
import os
import re
import shutil
import signal
import stat
import sys
import threading
import time
import tempfile
import uuid

from schema_validation import validate_managed_schema
from workflowlib import boundedio
from adaptive_common import (
    AdaptiveError, COMMIT_RE, ID_RE, SHA256_RE, atomic_write_bytes, bytes_sha256,
    canonical_sha256, consume_prepared_provider_human_decision, durable_rename, durable_unlink,
    ensure_real_directory, fail, load_blueprint, load_json, mutation_lock,
    prepare_provider_human_decision, print_json, record_human_decision, resolve_root, safe_relative_path,
    status_prepared_provider_human_decision, utc_now, verify_human_decision, write_json,
)

DEFAULT_POLICY_RELATIVE = Path(".agent/assets/policies/skill-policy.json")
POLICY_KEYS = {
    "schema", "allowed_hosts", "offline_content_catalogs", "allowed_licenses", "minimum_score", "maximum_candidates",
    "maximum_skill_bytes", "maximum_license_bytes", "github_request_budget", "maximum_recommendation_age_hours",
    "minimum_evolution_samples", "minimum_evolution_success_rate", "weights",
}
WEIGHT_KEYS = {"relevance", "quality", "maintenance", "security", "trust", "license"}
REPOSITORY_KEYS = {
    "host", "owner", "name", "repository_id", "owner_type", "archived", "fork", "stars", "pushed_at",
}
CANDIDATE_KEYS = {"id", "repository", "commit", "path", "content", "license"}
LICENSE_KEYS = {"spdx", "path", "content", "documents"}
LICENSE_DOCUMENT_KEYS = {"path", "kind", "content"}
LICENSE_BASENAME_RE = re.compile(r"(?i)^(LICENSE|COPYING|NOTICE)(?:[._-][A-Za-z0-9._-]+)?$")
SUPPORTED_STRICT_LICENSES = {"MIT"}
BUILTIN_SKILL_AUTHORIZED_CAPABILITIES={
    "ci-provider-github","ci-provider-gitlab","delivery","multi-agent","context-transport-pxpipe",
    "acceptance-web-docker","acceptance-api","acceptance-cli","acceptance-ios","acceptance-workflow",
}
HARD_PATTERNS = (
    ("pipe-to-shell", re.compile(r"curl[^\n|]{0,240}\|\s*(?:sh|bash|zsh)", re.I)),
    ("destructive-delete", re.compile(r"\brm\s+-rf\b", re.I)),
    ("credential-file", re.compile(r"(?:\.ssh/id_|/etc/(?:shadow|passwd))", re.I)),
    ("secret-enumeration", re.compile(r"\b(?:printenv|env)\s+(?:GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|AWS_SECRET_ACCESS_KEY)\b", re.I)),
    ("privilege-escalation", re.compile(r"\bsudo\s+", re.I)),
    ("unsupported-external-assets",re.compile(r"(?:\]\((?!#|data:)[^)]+\)|^\s*\[[^]\r\n]+\]:\s*(?!<?(?:#|data:))\S+|\b(?:src|href)\s*=\s*[\"'](?!#|data:)[^\"']+|(?:^|[\s`])(?:references|scripts|assets)/)",re.I|re.M)),
    ("mutable-network-resource",re.compile(r"(?:https?|ftp|git|ssh)://|\bgit@[^\s:]+:|\bwww\.",re.I)),
    ("runtime-acquisition",re.compile(r"\b(?:curl|wget|git\s+(?:clone|pull|fetch)|pip(?:3)?\s+install|python(?:3)?\s+-m\s+pip\s+install|npm\s+(?:install|i|exec)|npx|pnpm\s+(?:add|install|dlx)|yarn\s+(?:add|install|dlx)|bun\s+(?:add|install|x)|go\s+(?:get|install)|cargo\s+install|gem\s+install|brew\s+install)\b",re.I)),
    ("prose-runtime-acquisition",re.compile(r"\b(?:download|fetch|retrieve|clone|pull|acquire|install)\b.{0,100}\b(?:tool|script|binary|package|dependency|repository|repo|artifact|plugin|extension|latest|release)\b|\b(?:tool|script|binary|package|dependency|repository|repo|artifact|plugin|extension)\b.{0,100}\b(?:download|fetch|retrieve|clone|pull|acquire|install|from the (?:web|internet))\b",re.I|re.S)),
)
WARNING_PATTERNS = (
    ("instruction-override", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions", re.I)),
    ("credential-request", re.compile(r"(?:show|print|upload|send|exfiltrate).{0,80}(?:token|password|secret|private key)", re.I)),
    ("disable-controls", re.compile(r"(?:disable|bypass|skip).{0,60}(?:security|policy|approval|test)", re.I)),
)


def require_finite_json(value, label="Skill JSON"):
    """Reject non-finite JSON numbers before scoring, hashing, or persistence."""
    if isinstance(value, float) and not math.isfinite(value):
        raise AdaptiveError("NON_FINITE_SKILL_JSON", f"{label} contains NaN or Infinity")
    if isinstance(value, list):
        for item in value:
            require_finite_json(item, label)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AdaptiveError("INVALID_SKILL_JSON", f"{label} contains a non-string object key")
            require_finite_json(item, label)
    return value


def skill_load_json(path, label):
    return require_finite_json(load_json(path, label), label)


def strict_json_loads(raw, label):
    try:
        value = json.loads(raw, parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise AdaptiveError("INVALID_SKILL_JSON", f"{label} is not strict finite JSON") from error
    return require_finite_json(value, label)


def policy_path(root):
    return root / ".agent/project/skill-policy.json"


def load_policy(root):
    project_policy = policy_path(root)
    path = project_policy if project_policy.exists() else root / DEFAULT_POLICY_RELATIVE
    value = skill_load_json(path, "Skill policy")
    configured_licenses = value.get("allowed_licenses") if isinstance(value, dict) else None
    if isinstance(configured_licenses, list):
        unsupported_licenses = sorted({item for item in configured_licenses if isinstance(item, str)} - SUPPORTED_STRICT_LICENSES)
        if unsupported_licenses:
            raise AdaptiveError("INVALID_SKILL_POLICY", f"allowed_licenses contains unsupported strict classifier IDs: {unsupported_licenses}")
    try:
        schema_errors = validate_managed_schema(value, "skill-policy.schema.json", "agent-skill-policy/v1")
    except ValueError as error:
        raise AdaptiveError("INVALID_MANAGED_SCHEMA", str(error), 3) from error
    if schema_errors:
        raise AdaptiveError("INVALID_SKILL_POLICY", "Skill policy schema validation failed: " + "; ".join(schema_errors))
    if not isinstance(value, dict) or set(value) != POLICY_KEYS or value.get("schema") != "agent-skill-policy/v1":
        raise AdaptiveError("INVALID_SKILL_POLICY", "Skill policy fields are invalid")
    if not isinstance(value["allowed_hosts"], list) or not value["allowed_hosts"]:
        raise AdaptiveError("INVALID_SKILL_POLICY", "allowed_hosts must be a non-empty list")
    catalogs=value["offline_content_catalogs"]
    if (not isinstance(catalogs,list) or len(catalogs)>32 or len({item.get("id") for item in catalogs if isinstance(item,dict)})!=len(catalogs)
            or any(not isinstance(item,dict) or set(item)!={"id","candidate_set_sha256"}
                   or ID_RE.fullmatch(str(item.get("id",""))) is None or SHA256_RE.fullmatch(str(item.get("candidate_set_sha256",""))) is None for item in catalogs)):
        raise AdaptiveError("INVALID_SKILL_POLICY","offline_content_catalogs must be an exact bounded catalog allowlist")
    if not isinstance(value["allowed_licenses"], list) or not value["allowed_licenses"]:
        raise AdaptiveError("INVALID_SKILL_POLICY", "allowed_licenses must be a non-empty list")
    if (not isinstance(value["minimum_score"], (int, float)) or isinstance(value["minimum_score"], bool)
            or not math.isfinite(value["minimum_score"]) or not 0 <= value["minimum_score"] <= 100):
        raise AdaptiveError("INVALID_SKILL_POLICY", "minimum_score must be 0-100")
    for key, lower, upper in (
        ("maximum_candidates", 1, 100), ("maximum_skill_bytes", 1024, 1048576),
        ("maximum_license_bytes", 128, 524288), ("github_request_budget", 1, 100),
        ("maximum_recommendation_age_hours", 1, 24 * 365), ("minimum_evolution_samples", 3, 100),
    ):
        if not isinstance(value[key], int) or isinstance(value[key], bool) or not lower <= value[key] <= upper:
            raise AdaptiveError("INVALID_SKILL_POLICY", f"{key} is outside its safe bound")
    if (not isinstance(value["minimum_evolution_success_rate"], (int, float)) or isinstance(value["minimum_evolution_success_rate"], bool)
            or not math.isfinite(value["minimum_evolution_success_rate"]) or not 0 <= value["minimum_evolution_success_rate"] <= 1):
        raise AdaptiveError("INVALID_SKILL_POLICY", "minimum_evolution_success_rate must be 0-1")
    weights = value.get("weights")
    if not isinstance(weights, dict) or set(weights) != WEIGHT_KEYS:
        raise AdaptiveError("INVALID_SKILL_POLICY", "scoring weights are invalid")
    if (any(not isinstance(item, (int, float)) or isinstance(item, bool) or not math.isfinite(item) or item < 0
            for item in weights.values()) or not math.isfinite(sum(weights.values()))
            or abs(sum(weights.values()) - 1.0) > 0.000001):
        raise AdaptiveError("INVALID_SKILL_POLICY", "scoring weights must be non-negative and sum to one")
    return value


def token_set(text):
    words = re.findall(r"[a-z0-9][a-z0-9+.#_-]{1,63}|[\u3400-\u9fff]{2,}", str(text).casefold())
    stop = {"the", "and", "for", "with", "from", "this", "that", "user", "skill", "agent", "use", "project"}
    return {word for word in words if word not in stop}


def phrase_fit(items, candidate_tokens):
    if not items:
        return 0.0
    values = []
    for item in items:
        tokens = token_set(item)
        values.append(len(tokens & candidate_tokens) / len(tokens) if tokens else 0.0)
    return sum(values) / len(values)


def parse_frontmatter(content):
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, ["missing-frontmatter"]
    closing = next((index for index in range(1, min(len(lines), 65)) if lines[index].strip() == "---"), None)
    if closing is None:
        return None, ["unterminated-frontmatter"]
    values = {}
    for line in lines[1:closing]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            return None, ["complex-frontmatter"]
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}", key) or not value:
            return None, ["invalid-frontmatter"]
        values[key] = value
    if not values.get("name") or not values.get("description"):
        return None, ["missing-name-or-description"]
    return values, []


def clean_candidate_container(value, policy, blueprint):
    try:
        schema_errors = validate_managed_schema(value, "skill-candidates.schema.json", "agent-skill-candidates/v2")
    except ValueError as error:
        raise AdaptiveError("INVALID_MANAGED_SCHEMA", str(error), 3) from error
    if schema_errors:
        raise AdaptiveError("INVALID_CANDIDATES", "Skill candidates schema validation failed: " + "; ".join(schema_errors))
    if not isinstance(value, dict) or set(value) != {"schema", "provenance", "candidates"} or value.get("schema") != "agent-skill-candidates/v2":
        raise AdaptiveError("INVALID_CANDIDATES", "candidate document fields are invalid")
    candidates = value.get("candidates")
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= policy["maximum_candidates"]:
        raise AdaptiveError("INVALID_CANDIDATES", "candidate count is outside policy")
    ids = [item.get("id") for item in candidates if isinstance(item, dict)]
    if len(ids) != len(candidates) or len(ids) != len(set(ids)):
        raise AdaptiveError("INVALID_CANDIDATES", "candidate IDs are missing or duplicated")
    provenance = value.get("provenance")
    fields = {"mode", "source", "blueprint_sha256", "query", "requests", "observed_at", "candidate_set_sha256"}
    query = provenance.get("query") if isinstance(provenance, dict) else None
    query_invalid = query is not None and (
        not isinstance(query, list) or not query or len(query) > policy["github_request_budget"]
        or any(not isinstance(item, str) or not item or len(item) > 240 for item in query)
    )
    if (not isinstance(provenance, dict) or set(provenance) != fields or
            provenance.get("mode") not in {"github-api", "offline-user-reviewed"} or
            not isinstance(provenance.get("source"), str) or not provenance["source"] or len(provenance["source"]) > 256 or
            provenance.get("blueprint_sha256") != blueprint["confirmation"]["design_sha256"] or
            provenance.get("candidate_set_sha256") != canonical_sha256(candidates) or
            not isinstance(provenance.get("requests"), int) or isinstance(provenance.get("requests"), bool) or not 0 <= provenance["requests"] <= policy["github_request_budget"] or
            query_invalid):
        raise AdaptiveError("INVALID_CANDIDATE_PROVENANCE", "candidate provenance fields or binding are invalid")
    try:
        observed = dt.datetime.fromisoformat(str(provenance["observed_at"]).replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise AdaptiveError("INVALID_CANDIDATE_PROVENANCE", "candidate provenance timestamp is invalid") from error
    age = (dt.datetime.now(dt.timezone.utc) - observed).total_seconds() / 3600.0 if observed.tzinfo else float("inf")
    if age < -1 or age > policy["maximum_recommendation_age_hours"]:
        raise AdaptiveError("STALE_CANDIDATE_PROVENANCE", "candidate provenance is outside policy freshness")
    if provenance["mode"] == "github-api" and (provenance["source"] != "api.github.com" or not provenance["query"] or provenance["requests"] < len(provenance["query"])):
        raise AdaptiveError("INVALID_CANDIDATE_PROVENANCE", "GitHub candidate provenance is incomplete")
    if provenance["mode"] == "offline-user-reviewed":
        if provenance["query"] is not None or provenance["requests"] != 0:
            raise AdaptiveError("INVALID_CANDIDATE_PROVENANCE", "offline candidate provenance must not claim network evidence")
    return candidates, provenance


def provider_skill_phrases(design):
    phrases=[]
    for provider in design.get("providers", []):
        # Structural identifiers aid local scoring only. Outbound discovery uses
        # provider_discovery_phrases and never sends these private matching fields.
        parts=[str(provider.get("id", ""))]
        kind=provider.get("kind")
        if isinstance(kind,str): parts.append(kind)
        configuration=provider.get("configuration", [])
        if isinstance(configuration,list):
            parts.extend(item.get("key", "") for item in configuration if isinstance(item,dict))
        phrase=" ".join(part for part in parts if part)
        if phrase: phrases.append(phrase)
    return phrases


def provider_discovery_phrases(design):
    phrases=[]
    for provider in design.get("providers",[]):
        if provider.get("id") in {"github","gitlab"}: phrases.append(str(provider["id"]))
        else:
            aliases=provider.get("discovery_aliases",[])
            if isinstance(aliases,list): phrases.extend(aliases)
    return phrases


def provider_specific_tokens(provider):
    generic={"provider","source","control","workflow","service","custom","generic","self","hosted","git"}
    return (token_set(str(provider.get("id","")))|token_set(str(provider.get("kind",""))))-generic


def stable_technology_coverage_id(name):
    slug=re.sub(r"[^a-z0-9+._-]+","-",str(name).casefold()).strip("-._")
    if not slug: slug=bytes_sha256(str(name).encode("utf-8"))[:16]
    return f"technology:{slug[:80]}"


def routing_units(blueprint):
    """Return bounded, deduplicated units for every Skill-routing Blueprint dimension."""
    design=blueprint["design"]; units=[]
    def add(identifier,phrase,dimension,discovery_phrase=None,required=True):
        phrase=str(phrase).strip(); discovery_phrase=str(discovery_phrase if discovery_phrase is not None else phrase).strip()
        if not phrase: return
        existing=next((item for item in units if item["id"]==identifier),None)
        if existing is not None:
            if (existing["phrase"]!=phrase or existing["dimension"]!=dimension
                    or existing["discovery_phrase"]!=discovery_phrase or existing["required"]!=required):
                raise AdaptiveError("AMBIGUOUS_SKILL_COVERAGE",f"coverage ID collision: {identifier}")
            return
        if len(units)>=128: raise AdaptiveError("SKILL_COVERAGE_LIMIT","confirmed Blueprint exceeds 128 routing units")
        units.append({"id":identifier,"dimension":dimension,"phrase":phrase,
                      "discovery_phrase":discovery_phrase,"required":required})
    for item in design.get("capabilities",[]): add(item["id"],item["id"]+" "+item["description"],"capability")
    for item in design.get("technology_choices",[]): add(stable_technology_coverage_id(item["name"]),item["name"]+" "+item["reason"],"technology",required=False)
    for provider in design.get("providers",[]):
        add(provider_coverage_id(provider)," ".join(provider_skill_phrases({"providers":[provider]})),"provider",
            " ".join(provider_discovery_phrases({"providers":[provider]})),required=False)
    for dimension,key,prefix in (("goal","goals","goal"),("architecture","architecture","architecture"),("constraint","constraints","constraint")):
        for value in design.get(key,[]):
            add(f"{prefix}:{bytes_sha256(str(value).encode('utf-8'))[:16]}",value,dimension,required=False)
    for item in design.get("acceptance",[]):
        add(f"acceptance:{item['id']}",item["id"]+" "+item["criterion"],"acceptance",required=False)
    return sorted(units,key=lambda item:item["id"])


def routing_unit_fit(unit,tokens):
    identifier_tokens=token_set(unit["id"])
    if unit["dimension"] in {"capability","acceptance"} and identifier_tokens and identifier_tokens<=tokens:
        return 1.0
    return phrase_fit([unit["phrase"]],tokens)


def candidate_assessment(candidate, blueprint, policy, now=None, *, trusted_repository_metadata=True):
    failures, warnings = [], []
    if not isinstance(candidate, dict) or set(candidate) != CANDIDATE_KEYS:
        return {"id": str(candidate.get("id", "invalid")) if isinstance(candidate, dict) else "invalid",
                "eligible": False, "score": 0.0, "confidence": 0.0,
                "breakdown": {key: 0.0 for key in WEIGHT_KEYS}, "coverage_scores": {},
                "unit_scores": {}, "eligible_coverage": [], "approvable_coverage": [],
                "hard_failures": ["invalid-candidate-fields"], "warnings": [],
                "candidate_sha256": canonical_sha256(candidate)}
    candidate_id = candidate.get("id")
    if not isinstance(candidate_id, str) or not ID_RE.fullmatch(candidate_id):
        failures.append("invalid-id")
    repository = candidate.get("repository")
    if not isinstance(repository, dict) or set(repository) != REPOSITORY_KEYS:
        failures.append("invalid-repository-metadata")
        repository = {}
    else:
        if repository.get("host") not in policy["allowed_hosts"]:
            failures.append("host-not-allowed")
        if not isinstance(repository.get("repository_id"), int) or repository["repository_id"] <= 0:
            failures.append("missing-numeric-repository-id")
        if (not all(isinstance(repository.get(key), str) and repository[key] for key in ("owner", "name", "owner_type", "pushed_at"))
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", str(repository.get("owner", "")))
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", str(repository.get("name", "")))):
            failures.append("invalid-repository-identity")
        if repository.get("archived") is not False:
            failures.append("archived-repository")
        if not isinstance(repository.get("fork"), bool) or not isinstance(repository.get("stars"), int) or repository.get("stars", -1) < 0:
            failures.append("invalid-repository-quality-evidence")
    commit = candidate.get("commit")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        failures.append("commit-must-be-full-40-hex")
    try:
        safe_relative_path(candidate.get("path"), suffix="SKILL.md")
    except AdaptiveError:
        failures.append("unsafe-skill-path")
    content = candidate.get("content")
    if not isinstance(content, str) or not content or len(content.encode("utf-8", errors="ignore")) > policy["maximum_skill_bytes"] or chr(0) in str(content):
        failures.append("invalid-skill-content")
        content = ""
    frontmatter, frontmatter_failures = parse_frontmatter(content)
    failures.extend(frontmatter_failures)
    license_value = candidate.get("license")
    if not isinstance(license_value, dict):
        license_value = {}
    validate_license_set(license_value, candidate.get("path"), policy, failures)
    relative_assets = relative_asset_references(content)
    if relative_assets:
        failures.append("unavailable-relative-assets")
    for code, pattern in HARD_PATTERNS:
        if pattern.search(content):
            failures.append(code)
    for code, pattern in WARNING_PATTERNS:
        if pattern.search(content):
            warnings.append(code)
    if len(warnings) >= 2:
        failures.append("multiple-prompt-risk-signals")

    candidate_tokens = token_set(content)
    units=routing_units(blueprint)
    coverage_scores={item["id"]:round(routing_unit_fit(item,candidate_tokens),6) for item in units}
    # A correct narrow Skill is scored against the unit it actually covers, not
    # averaged down by unrelated confirmed dimensions. Set selection below owns breadth.
    relevance=max(coverage_scores.values(),default=0.0)
    lower = content.casefold()
    quality_signals = [
        frontmatter is not None,
        "## when to use" in lower or "## use" in lower,
        "## workflow" in lower or "## process" in lower,
        "## constraints" in lower or "## safety" in lower,
        "## verification" in lower or "## test" in lower,
        bool(re.search(r"(?m)^\s*1\.\s+", content)),
    ]
    quality = sum(1.0 for item in quality_signals if item) / len(quality_signals)
    current = now or dt.datetime.now(dt.timezone.utc)
    maintenance = 0.0
    try:
        pushed = dt.datetime.fromisoformat(str(repository.get("pushed_at", "")).replace("Z", "+00:00"))
        days = (current - pushed).total_seconds() / 86400.0
        if days < -1:
            failures.append("future-maintenance-date")
        else:
            maintenance = math.exp(-max(0.0, days) / 365.0)
    except (TypeError, ValueError):
        warnings.append("missing-maintenance-date")
    if not trusted_repository_metadata:
        maintenance = 0.5
    security = max(0.0, 1.0 - 0.2 * len(warnings)) if not failures else 0.0
    if not trusted_repository_metadata:
        warnings.append("offline-repository-metadata-unverified")
    owner_score = 0.7 if repository.get("owner_type") == "Organization" else 0.45
    popularity = min(0.3, math.log10(1 + max(0, int(repository.get("stars", 0)))) / 15.0)
    trust = min(1.0, owner_score + popularity - (0.1 if repository.get("fork") else 0.0)) if trusted_repository_metadata else 0.5
    license_score = 1.0 if license_value.get("spdx") in policy["allowed_licenses"] else 0.0
    breakdown = {
        "relevance": round(relevance, 6), "quality": round(quality, 6),
        "maintenance": round(maintenance, 6), "security": round(security, 6),
        "trust": round(trust, 6), "license": round(license_score, 6),
    }
    coverage_signals = [
        bool(repository.get("repository_id")), bool(repository.get("pushed_at")),
        bool(commit and isinstance(commit, str) and COMMIT_RE.fullmatch(commit)),
        bool(frontmatter), bool(license_value.get("content")),
    ]
    confidence = sum(1.0 for item in coverage_signals if item) / len(coverage_signals)
    unit_scores={}
    for identifier,fit in coverage_scores.items():
        unit_breakdown={**breakdown,"relevance":fit}
        unit_base=100.0*sum(policy["weights"][key]*unit_breakdown[key] for key in WEIGHT_KEYS)
        unit_scores[identifier]=round(unit_base*(0.70+0.30*confidence),3) if not failures else 0.0
    score=max(unit_scores.values(),default=0.0)
    eligible_coverage=sorted(identifier for identifier,fit in coverage_scores.items()
                             if fit>=0.5 and unit_scores[identifier]>=policy["minimum_score"] and not failures)
    mandatory={item["id"] for item in units if item["required"]}
    approvable_coverage=sorted(mandatory&set(eligible_coverage))
    eligible=bool(eligible_coverage)
    if not failures and score < policy["minimum_score"]:
        warnings.append("score-below-threshold")
    if not failures and relevance <= 0:
        warnings.append("no-confirmed-design-match")
    return {
        "id": candidate_id if isinstance(candidate_id, str) else "invalid",
        "eligible": eligible, "score": score, "confidence": round(confidence, 3),
        "breakdown":breakdown,"coverage_scores":coverage_scores,"unit_scores":unit_scores,
        "eligible_coverage":eligible_coverage,"approvable_coverage":approvable_coverage,
        "hard_failures":sorted(set(failures)),"warnings":sorted(set(warnings)),
        "candidate_sha256": canonical_sha256(candidate),
    }


EXACT_COVER_MAX_STATES=1000000


def exact_optimal_cover(required,eligible):
    """Return a proven minimum-cardinality cover or fail before approximating."""
    units=sorted(required)
    if not units: return [],set()
    positions={unit:index for index,unit in enumerate(units)}; full=(1<<len(units))-1
    normalized=[]
    for item in eligible:
        coverage=sorted(set(item.get("suggested_capabilities",[]))&set(units)); mask=0
        for unit in coverage: mask|=1<<positions[unit]
        if mask:
            strength=sum(float(item.get("unit_scores",{}).get(unit,0.0)) for unit in coverage)
            normalized.append((mask,item,strength))
    union=0
    for mask,_item,_strength in normalized: union|=mask
    missing={unit for unit,index in positions.items() if not union&(1<<index)}
    if missing: return [],missing
    # Two equal coverage masks can never both occur in a minimum cover. Retain
    # the stronger deterministic representative before exact enumeration.
    by_mask={}
    for mask,item,strength in normalized:
        rank=(-strength,-float(item["score"]),-float(item["confidence"]),item["candidate_sha256"],item["id"])
        if mask not in by_mask or rank<by_mask[mask][0]: by_mask[mask]=(rank,item)
    candidates=[(mask,value[1]) for mask,value in sorted(by_mask.items(),key=lambda pair:(pair[1][1]["candidate_sha256"],pair[1][1]["id"]))]
    count=len(candidates); suffix=[0]*(count+1)
    for index in range(count-1,-1,-1): suffix[index]=suffix[index+1]|candidates[index][0]
    maximum=max(bin(mask).count("1") for mask,_item in candidates)
    lower=(len(units)+maximum-1)//maximum; states=0
    for size in range(lower,count+1):
        best=None
        def visit(start,picks,mask,chosen):
            nonlocal states,best
            states+=1
            if states>EXACT_COVER_MAX_STATES:
                raise SystemExit("exact Skill cover exceeded its bounded search state limit; narrow the confirmed capabilities or candidate catalog")
            if picks==0:
                if mask!=full: return
                items=[candidates[index][1] for index in chosen]
                strength=sum(max(float(item.get("unit_scores",{}).get(unit,0.0)) for item in items) for unit in units)
                rank=(-strength,-sum(float(item["score"]) for item in items),-sum(float(item["confidence"]) for item in items),tuple(sorted((item["candidate_sha256"],item["id"]) for item in items)))
                if best is None or rank<best[0]: best=(rank,items)
                return
            if count-start<picks or (mask|suffix[start])!=full: return
            uncovered=full&~mask; max_new=max((bin(candidate_mask&uncovered).count("1") for candidate_mask,_item in candidates[start:]),default=0)
            if max_new==0 or (bin(uncovered).count("1")+max_new-1)//max_new>picks: return
            for index in range(start,count-picks+1):
                candidate_mask=candidates[index][0]
                if candidate_mask&~mask: visit(index+1,picks-1,mask|candidate_mask,chosen+(index,))
        visit(0,size,0,())
        if best is not None:
            return [item["id"] for item in sorted(best[1],key=lambda item:(item["candidate_sha256"],item["id"]))],set()
    return [],set(units)


def report_payload(blueprint, policy, assessments, provenance):
    eligible = [item for item in assessments if item["eligible"]]
    eligible.sort(key=lambda item: (-item["score"], -item["confidence"], item["candidate_sha256"], item["id"]))
    ordered = sorted(assessments, key=lambda item: (not item["eligible"], -item["score"], item["id"], item["candidate_sha256"]))
    required=required_skill_coverage(blueprint); selected,uncovered=exact_optimal_cover(required,eligible)
    return {
        "schema": "agent-skill-recommendation/v1",
        "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
        "policy_sha256": canonical_sha256(policy),
        "minimum_score": policy["minimum_score"], "candidate_provenance": provenance,
        "required_coverage":sorted(required),"uncovered_coverage":sorted(uncovered),
        "candidates": ordered,"recommended_ids":selected,
        "recommended_id": selected[0] if selected else None,
    }


def build_report(blueprint, policy, candidates, provenance):
    generated_at = utc_now()
    generated = dt.datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    scoring_time = generated.replace(hour=0, minute=0, second=0, microsecond=0)
    # Candidate documents are caller-writable, including github-api labels.
    # Repository quality metadata remains neutral until install re-fetches it.
    assessments = [candidate_assessment(item, blueprint, policy, now=scoring_time, trusted_repository_metadata=False) for item in candidates]
    for assessment, candidate in zip(assessments, candidates):
        assessment["suggested_capabilities"]=list(assessment.get("approvable_coverage",[]))
    payload = report_payload(blueprint, policy, assessments, provenance)
    expires_at = (generated + dt.timedelta(hours=policy["maximum_recommendation_age_hours"])).isoformat()
    report = {**payload, "generated_at": generated_at, "expires_at": expires_at,
              "recommendation_sha256": canonical_sha256(payload)}
    return {**report, "report_sha256": canonical_sha256(report)}


def load_report(path):
    value = skill_load_json(path, "Skill recommendation")
    expected = {
        "schema", "blueprint_sha256", "policy_sha256", "minimum_score", "candidate_provenance", "candidates",
        "required_coverage", "uncovered_coverage", "recommended_ids", "recommended_id",
        "generated_at", "expires_at", "recommendation_sha256", "report_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != "agent-skill-recommendation/v1":
        raise AdaptiveError("INVALID_RECOMMENDATION", "recommendation fields are invalid")
    payload = {key: value[key] for key in value if key not in {"generated_at", "expires_at", "recommendation_sha256", "report_sha256"}}
    if canonical_sha256(payload) != value.get("recommendation_sha256"):
        raise AdaptiveError("INVALID_RECOMMENDATION", "recommendation digest is invalid")
    report = {key: value[key] for key in value if key != "report_sha256"}
    if canonical_sha256(report) != value.get("report_sha256"):
        raise AdaptiveError("INVALID_RECOMMENDATION", "recommendation report digest is invalid")
    return value


def validate_report_context(report, blueprint, policy, *, require_fresh=True):
    if report["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"] or report["policy_sha256"] != canonical_sha256(policy):
        raise AdaptiveError("STALE_RECOMMENDATION", "recommendation does not bind the current confirmed design and policy")
    expected=report_payload(blueprint,policy,report["candidates"],report["candidate_provenance"])
    for key in ("required_coverage","uncovered_coverage","recommended_ids","recommended_id"):
        if report.get(key)!=expected[key]:
            raise AdaptiveError("INVALID_RECOMMENDATION","recommended Skill covering set or exact Blueprint coverage drifted")
    if require_fresh:
        try:
            generated = dt.datetime.fromisoformat(report["generated_at"].replace("Z", "+00:00"))
            expires = dt.datetime.fromisoformat(report["expires_at"].replace("Z", "+00:00"))
            expected_expires = generated + dt.timedelta(hours=policy["maximum_recommendation_age_hours"])
            if expires != expected_expires:
                raise ValueError("report expiry does not match policy")
            age_hours = (dt.datetime.now(dt.timezone.utc) - generated).total_seconds() / 3600.0
        except (AttributeError, TypeError, ValueError) as error:
            raise AdaptiveError("INVALID_RECOMMENDATION", "recommendation time is invalid") from error
        if age_hours < -1 or age_hours > policy["maximum_recommendation_age_hours"]:
            raise AdaptiveError("STALE_RECOMMENDATION", "recommendation evidence is outside the configured freshness window")
    return report


GITHUB_TOTAL_DEADLINE_SECONDS=25.0


class GitHubTotalDeadlineExpired(TimeoutError): pass


@contextmanager
def github_io_deadline(seconds):
    if threading.current_thread() is not threading.main_thread():
        raise AdaptiveError("GITHUB_DEADLINE_UNAVAILABLE","GitHub total deadline requires the main thread",4)
    if not hasattr(signal,"setitimer") or not hasattr(signal,"ITIMER_REAL"):
        raise AdaptiveError("GITHUB_DEADLINE_UNAVAILABLE","GitHub total deadline is unavailable on this host",4)
    existing=signal.getitimer(signal.ITIMER_REAL)
    if existing!=(0.0,0.0):
        raise AdaptiveError("GITHUB_DEADLINE_UNAVAILABLE","an ambient real-time timer prevents isolated GitHub deadline ownership",4)
    previous=signal.getsignal(signal.SIGALRM)
    def expired(_signum,_frame): raise GitHubTotalDeadlineExpired("GitHub total deadline expired")
    signal.signal(signal.SIGALRM,expired); signal.setitimer(signal.ITIMER_REAL,max(0.001,float(seconds)))
    try: yield
    finally:
        signal.setitimer(signal.ITIMER_REAL,0); signal.signal(signal.SIGALRM,previous)


class StrictGitHubRedirectHandler(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        target = urlparse.urlparse(new_url)
        if target.scheme != "https" or target.hostname != "api.github.com" or target.port not in {None, 443}:
            raise AdaptiveError("GITHUB_REDIRECT_REJECTED", "GitHub redirected outside api.github.com", 4)
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


class GitHubClient:
    def __init__(self, budget):
        self.budget = budget
        self.requests = 0
        self.token = os.environ.get("GITHUB_TOKEN")
        if self.token is not None and (not self.token.strip() or any(ord(char) < 33 for char in self.token)):
            raise AdaptiveError("INVALID_GITHUB_TOKEN", "GITHUB_TOKEN is blank or malformed; no fallback is allowed")
        self.opener = urlrequest.build_opener(StrictGitHubRedirectHandler())
        self.response_cache = {}

    def get(self, path, maximum=4 * 1024 * 1024):
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or chr(0) in path:
            raise AdaptiveError("INVALID_GITHUB_PATH", "GitHub API path is invalid", 4)
        cached = self.response_cache.get(path)
        if cached is not None:
            raw = cached
            if len(raw) > maximum:
                raise AdaptiveError("GITHUB_RESPONSE_TOO_LARGE", "cached GitHub response exceeded its byte budget", 4)
            return strict_json_loads(raw.decode("utf-8"), "cached GitHub response")
        url = "https://api.github.com" + path
        headers = {
            "Accept": "application/vnd.github+json", "User-Agent": "agent-workflow-template/skillctl",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token.strip()
        request = urlrequest.Request(url, headers=headers, method="GET")
        raw=None; last_error=None; deadline=time.monotonic()+GITHUB_TOTAL_DEADLINE_SECONDS
        for attempt in range(2):
            if self.requests >= self.budget:
                if last_error is not None:
                    raise AdaptiveError("GITHUB_NETWORK_ERROR", f"GitHub transient failure exhausted request budget; requests={self.requests}", 4) from last_error
                raise AdaptiveError("GITHUB_BUDGET_EXHAUSTED", f"GitHub request budget {self.budget} exhausted", 4)
            self.requests += 1
            remaining=deadline-time.monotonic()
            if remaining<=0: raise AdaptiveError("GITHUB_TOTAL_DEADLINE","GitHub request exceeded its total deadline",4)
            try:
                with github_io_deadline(remaining):
                    with self.opener.open(request,timeout=min(12.0,remaining)) as response:
                        final=urlparse.urlparse(response.geturl())
                        if final.scheme!="https" or final.hostname!="api.github.com" or final.port not in {None,443}:
                            raise AdaptiveError("GITHUB_REDIRECT_REJECTED","GitHub redirected outside api.github.com",4)
                        raw=response.read(maximum+1)
                        if len(raw)>maximum:
                            raise AdaptiveError("GITHUB_RESPONSE_TOO_LARGE","GitHub response exceeded its byte budget",4)
                break
            except GitHubTotalDeadlineExpired as error:
                raise AdaptiveError("GITHUB_TOTAL_DEADLINE","GitHub request exceeded its total deadline",4) from error
            except urlerror.HTTPError as error:
                remaining = error.headers.get("X-RateLimit-Remaining") if error.headers else None
                if error.code in {502, 503, 504} and attempt == 0:
                    last_error = error
                    continue
                code = "GITHUB_RATE_LIMITED" if error.code in {403, 429} and remaining == "0" else "GITHUB_HTTP_ERROR"
                raise AdaptiveError(code, f"GitHub request failed with HTTP {error.code}; requests={self.requests}", 4) from error
            except (urlerror.URLError, TimeoutError) as error:
                if attempt == 0:
                    last_error = error
                    continue
                raise AdaptiveError("GITHUB_NETWORK_ERROR", f"GitHub request failed after bounded retry; requests={self.requests}", 4) from error
        if raw is None:
            raise AdaptiveError("GITHUB_NETWORK_ERROR", f"GitHub request failed; requests={self.requests}", 4)
        try:
            value = strict_json_loads(raw.decode("utf-8"), "GitHub response")
        except (UnicodeError, json.JSONDecodeError) as error:
            raise AdaptiveError("GITHUB_INVALID_JSON", "GitHub returned invalid JSON", 4) from error
        self.response_cache[path] = raw
        return value


def decode_blob(value, maximum, label):
    if not isinstance(value, dict) or value.get("encoding") != "base64" or not isinstance(value.get("content"), str):
        raise AdaptiveError("GITHUB_INVALID_BLOB", f"{label} blob response is invalid", 4)
    try:
        encoded = re.sub(r"[\t\n\r ]+", "", value["content"])
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise AdaptiveError("GITHUB_INVALID_BLOB", f"{label} is not valid base64", 4) from error
    if len(raw) > maximum or bytes([0]) in raw:
        raise AdaptiveError("GITHUB_INVALID_BLOB", f"{label} exceeds policy or contains NUL", 4)
    try:
        return raw.decode("utf-8")
    except UnicodeError as error:
        raise AdaptiveError("GITHUB_INVALID_BLOB", f"{label} is not UTF-8 text", 4) from error


def detect_license(content):
    """Conservatively recognize only a complete, unmodified MIT grant.

    Keyword/sub-string fingerprints are not license evidence: an otherwise valid
    license followed by a field-of-use restriction or dual-license condition must
    remain NOASSERTION. Other SPDX IDs stay conservative until an equally strict
    complete-text validator is implemented.
    """
    if not isinstance(content, str) or chr(0) in content:
        return "NOASSERTION"
    if content.startswith("\ufeff"):
        content = content[1:]
    if "\ufeff" in content:
        return "NOASSERTION"
    lines = [line.strip() for line in content.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    lines = [line for line in lines if line]
    if lines and lines[0].casefold() == "mit license":
        lines.pop(0)
    copyright_lines = []
    while lines and lines[0].casefold().startswith("copyright"):
        copyright_lines.append(lines.pop(0))
    legal_notice_terms = re.compile(r"\b(?:license|spdx|apache|gpl|mpl|bsd|isc|dual|restrict(?:ion)?|prohibit(?:ed)?|commercial use|personal use|use only|only|redistribution|additional terms?|provided that)\b", re.I)
    if (not copyright_lines or any(len(line) > 300 or legal_notice_terms.search(line) or not re.fullmatch(
            r"Copyright(?: \(c\)| ©)?[ A-Za-z0-9.,_()@/+&:'-]+", line, re.I)
            for line in copyright_lines)):
        return "NOASSERTION"
    normalized = " ".join(" ".join(lines).casefold().split())
    mit_body = " ".join("""Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.""".casefold().split())
    return "MIT" if normalized == mit_body else "NOASSERTION"


def legal_document_kind(path):
    match = LICENSE_BASENAME_RE.fullmatch(Path(path).name)
    if not match:
        return None
    return "notice" if match.group(1).casefold() == "notice" else "license"


def applicable_legal_paths(skill_path, blobs):
    """Resolve all direct legal terms from the Skill directory through repository root."""
    safe_relative_path(skill_path, suffix="SKILL.md")
    parent = Path(skill_path).parent
    ancestors = [Path()] if str(parent) == "." else [parent, *parent.parents]
    records = []
    for ancestor in ancestors:
        prefix = "" if str(ancestor) == "." else ancestor.as_posix() + "/"
        scoped = []
        for candidate in blobs:
            if not isinstance(candidate, str) or not candidate.startswith(prefix):
                continue
            remainder = candidate[len(prefix):]
            if "/" in remainder:
                continue
            kind = legal_document_kind(candidate)
            if kind:
                scoped.append((candidate, kind))
        for kind in ("license", "notice"):
            matches = sorted(path for path, value_kind in scoped if value_kind == kind)
            if len(matches) > 1:
                raise AdaptiveError("AMBIGUOUS_SKILL_LICENSE",
                    f"multiple {kind} documents apply at package boundary {prefix or '/'}: {matches}", 4)
            if matches:
                records.append((matches[0], kind))
    if not any(kind == "license" for _, kind in records):
        raise AdaptiveError("SKILL_LICENSE_MISSING", f"no applicable LICENSE/COPYING exists for {skill_path}", 4)
    return records


def notice_is_unrestricted(content):
    """Accept only narrowly provable copyright attribution, never prose terms."""
    if not isinstance(content, str) or not content.strip() or chr(0) in content or "\ufeff" in content:
        return False
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    copyright_line = re.compile(
        r"^(?:(?:SPDX-FileCopyrightText|Copyright(?: \(c\))?)\s*[: ]\s*|©\s*)"
        r"(?:19|20)[0-9]{2}(?:-(?:19|20)[0-9]{2})?(?:,?\s+)(?:[A-Za-z0-9][A-Za-z0-9 .,&()'/_+-]{0,200})$",
        re.I,
    )
    return bool(lines) and all(copyright_line.fullmatch(line) for line in lines)


def canonical_license_content(documents):
    if len(documents) == 1:
        return documents[0]["content"]
    parts = []
    for item in documents:
        body = item["content"]
        parts.append(f"===== {item['kind'].upper()}: {item['path']} =====\n{body.rstrip()}\n")
    return "\n".join(parts)


def validate_license_set(license_value, skill_path, policy, failures=None):
    target = failures if failures is not None else []
    if not isinstance(license_value, dict) or set(license_value) != LICENSE_KEYS:
        target.append("invalid-license-record")
        return []
    documents = license_value.get("documents")
    if not isinstance(documents, list) or not documents:
        target.append("invalid-license-documents")
        return []
    normalized = []
    seen = set()
    total = 0
    for item in documents:
        if not isinstance(item, dict) or set(item) != LICENSE_DOCUMENT_KEYS:
            target.append("invalid-license-document")
            continue
        path, kind, content = item.get("path"), item.get("kind"), item.get("content")
        try:
            safe_relative_path(path)
        except AdaptiveError:
            target.append("unsafe-license-path"); continue
        expected_kind = legal_document_kind(path)
        if kind != expected_kind or path in seen:
            target.append("invalid-license-document-set"); continue
        seen.add(path)
        raw = content.encode("utf-8", errors="ignore") if isinstance(content, str) else b""
        total += len(raw)
        if not isinstance(content, str) or not content or chr(0) in content:
            target.append("invalid-license-content"); continue
        if kind == "license" and detect_license(content) != "MIT":
            target.append("license-text-spdx-mismatch")
        if kind == "notice" and not notice_is_unrestricted(content):
            target.append("notice-additional-restrictions")
        normalized.append({"path": path, "kind": kind, "content": content})
    if total > policy["maximum_license_bytes"]:
        target.append("invalid-license-content")
    try:
        expected_paths = applicable_legal_paths(skill_path, {item["path"]: {} for item in normalized})
    except AdaptiveError:
        target.append("invalid-license-document-set")
        expected_paths = []
    if [(item["path"], item["kind"]) for item in normalized] != expected_paths:
        target.append("invalid-license-document-set")
    if normalized and (license_value.get("path") != normalized[0]["path"]
            or license_value.get("content") != canonical_license_content(normalized)):
        target.append("license-set-aggregate-mismatch")
    if license_value.get("spdx") not in policy["allowed_licenses"]:
        target.append("license-not-allowed")
    return normalized


def relative_asset_references(content):
    """Return relative references that content-only activation cannot provide."""
    if not isinstance(content, str):
        return ["<invalid-content>"]
    patterns = (
        re.compile(r"\]\((?!https?://|mailto:|#|data:)([^)]+)\)", re.I),
        re.compile(r"^\s*\[[^]\r\n]+\]:\s*<?(?!https?://|mailto:|#|data:)([^>\s]+)>?", re.I | re.M),
        re.compile(r'''\b(?:src|href|data|poster|srcset)\s*=\s*["'](?!https?://|mailto:|#|data:)([^"']+)''', re.I),
        re.compile(r'''\b(?:src|href|data|poster|srcset)\s*=\s*(?!["']|https?://|mailto:|#|data:)([^\s>]+)''', re.I),
        re.compile(r'''\burl\(\s*["']?(?!https?://|data:|#)([^)"']+)["']?\s*\)''', re.I),
        re.compile(r'''`((?:\./)?(?:references|scripts|assets)/[^`]+)`''', re.I),
        re.compile(r'''(?:^|\s)((?:\./)?(?:references|scripts|assets)/[^\s)>,;]+)''', re.I | re.M),
    )
    values = []
    for pattern in patterns:
        values.extend(match.group(1).strip() for match in pattern.finditer(content))
    return sorted(set(value for value in values if value))


def discovery_queries(blueprint):
    authoritative=[item["discovery_phrase"] for item in routing_units(blueprint)]
    queries = []
    suffix = " in:name,description,readme"
    for value in authoritative:
        terms = sorted(token_set(value))[:5]
        term_text = " ".join(terms) if terms else str(value).strip()
        prefix = "\"agent skill\" "
        query = prefix + term_text[:240 - len(prefix) - len(suffix)] + suffix
        queries.append(query)
    return list(dict.fromkeys(queries))


def unique_candidate_id(path, frontmatter, used):
    raw = (frontmatter or {}).get("name") or Path(path).parent.name or "skill"
    value = re.sub(r"[^a-z0-9._-]+", "-", raw.casefold()).strip("-._")[:64] or "skill"
    if not ID_RE.fullmatch(value):
        value = "skill-" + bytes_sha256(path.encode())[:12]
    base, counter = value, 2
    while value in used:
        suffix = f"-{counter}"; value = base[:64-len(suffix)] + suffix; counter += 1
    used.add(value)
    return value


def discover_github(blueprint, policy, maximum_repositories):
    queries = discovery_queries(blueprint)
    if not queries:
        raise AdaptiveError("NO_DISCOVERY_TERMS", "confirmed design has no usable Skill discovery terms")
    inspection_limit = min(maximum_repositories, policy["maximum_candidates"])
    required_budget = len(queries) + (inspection_limit * 2)
    if required_budget > policy["github_request_budget"]:
        raise AdaptiveError(
            "GITHUB_BUDGET_INSUFFICIENT",
            f"GitHub request budget {policy['github_request_budget']} cannot cover "
            f"{len(queries)} required search queries plus {inspection_limit * 2} branch/tree inspection requests",
            4,
        )
    client = GitHubClient(policy["github_request_budget"])
    result_lists = []
    for query in queries:
        search = client.get("/search/repositories?" + urlparse.urlencode({"q": query, "per_page": inspection_limit, "page": 1}))
        items = search.get("items") if isinstance(search, dict) else None
        if not isinstance(items, list):
            raise AdaptiveError("GITHUB_SEARCH_INVALID", "GitHub repository search result is invalid", 4)
        result_lists.append(items)
    ranked_repositories, repository_ids = [], set()
    for query_index, items in enumerate(result_lists):
        valid = [item for item in items if isinstance(item, dict) and isinstance(item.get("id"), int)]
        if not valid:
            raise AdaptiveError("GITHUB_QUERY_COVERAGE_INCOMPLETE", f"confirmed query unit {query_index} returned no inspectable repository", 4)
        if any(item["id"] in repository_ids for item in valid):
            continue
        representative = valid[0]
        if len(ranked_repositories) >= inspection_limit:
            raise AdaptiveError(
                "GITHUB_REPOSITORY_LIMIT_INSUFFICIENT",
                f"repository inspection limit {inspection_limit} cannot cover every confirmed query unit",
                4,
            )
        repository_ids.add(representative["id"]); ranked_repositories.append(representative)
    maximum_rank = max((len(items) for items in result_lists), default=0)
    for rank in range(maximum_rank):
        for items in result_lists:
            if rank >= len(items):
                continue
            repository = items[rank]
            repository_id = repository.get("id") if isinstance(repository, dict) else None
            if not isinstance(repository_id, int) or repository_id in repository_ids:
                continue
            repository_ids.add(repository_id)
            ranked_repositories.append(repository)
            if len(ranked_repositories) >= inspection_limit:
                break
        if len(ranked_repositories) >= inspection_limit:
            break
    candidates, used, inspected = [], set(), []
    design_tokens = set().union(*(token_set(value) for value in (
        blueprint["design"]["goals"] + blueprint["design"]["architecture"]
        + [item["name"] for item in blueprint["design"]["technology_choices"]]
        + [item["id"] + " " + item["description"] for item in blueprint["design"]["capabilities"]]
    )))
    for repository in ranked_repositories:
        full_name = repository.get("full_name")
        default_branch = repository.get("default_branch")
        if (not isinstance(full_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name)
                or not isinstance(default_branch, str) or not default_branch or len(default_branch) > 255):
            continue
        owner, name = full_name.split("/", 1)
        branch = client.get(f"/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/branches/{urlparse.quote(default_branch, safe='')}")
        commit = ((branch.get("commit") or {}).get("sha")) if isinstance(branch, dict) else None
        if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
            continue
        tree = client.get(f"/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/git/trees/{commit}?recursive=1")
        if not isinstance(tree, dict) or tree.get("truncated") is True or not isinstance(tree.get("tree"), list):
            continue
        blobs = {}
        for item in tree["tree"]:
            if not isinstance(item, dict) or item.get("type") != "blob":
                continue
            blob_path, blob_sha = item.get("path"), item.get("sha")
            if not isinstance(blob_path, str) or not isinstance(blob_sha, str) or not COMMIT_RE.fullmatch(blob_sha):
                continue
            try:
                safe_relative_path(blob_path)
            except AdaptiveError:
                continue
            if blob_path in blobs:
                raise AdaptiveError("GITHUB_TREE_DUPLICATE_PATH", f"GitHub tree repeats path {blob_path}", 4)
            blobs[blob_path] = item
        skill_paths = [value for value in blobs if Path(value).name == "SKILL.md"
                       and blobs[value].get("mode") == "100644"]
        skill_paths.sort(key=lambda value: (-len(token_set(value) & design_tokens), value))
        if not skill_paths:
            continue
        inspected.append({
            "repository": repository, "owner": owner, "name": name, "commit": commit,
            "blobs": blobs, "skill_paths": skill_paths, "license_cache": {},
        })
    maximum_path_rank = max((len(item["skill_paths"]) for item in inspected), default=0)
    planned_work = []
    planned_legal_urls = set()
    for path_rank in range(maximum_path_rank):
        for item in inspected:
            if len(planned_work) >= policy["maximum_candidates"] or path_rank >= len(item["skill_paths"]):
                continue
            skill_path = item["skill_paths"][path_rank]
            try:
                legal_paths = applicable_legal_paths(skill_path, item["blobs"])
            except AdaptiveError:
                continue
            if any(item["blobs"][legal_path].get("mode") != "100644" for legal_path, _ in legal_paths):
                continue
            planned_work.append((item["repository"].get("id"), skill_path))
            planned_legal_urls.update((item["repository"].get("id"), legal_path) for legal_path, _ in legal_paths)
    required_remaining = len(planned_work) + len(planned_legal_urls)
    if client.requests + required_remaining > client.budget:
        raise AdaptiveError("GITHUB_BUDGET_INSUFFICIENT",
            f"GitHub request budget {client.budget} cannot cover {client.requests} completed search/tree requests "
            f"plus {len(planned_work)} Skill blobs and {len(planned_legal_urls)} unique applicable legal blobs", 4)
    planned_work = set(planned_work)
    budget_exhausted = False
    for path_rank in range(maximum_path_rank):
        for item in inspected:
            if len(candidates) >= policy["maximum_candidates"]:
                break
            if path_rank >= len(item["skill_paths"]):
                continue
            if client.requests >= client.budget:
                budget_exhausted = True
                break
            skill_path = item["skill_paths"][path_rank]
            if (item["repository"].get("id"), skill_path) not in planned_work:
                continue
            blob = client.get(f"/repos/{urlparse.quote(item['owner'])}/{urlparse.quote(item['name'])}/git/blobs/{item['blobs'][skill_path]['sha']}")
            content = decode_blob(blob, policy["maximum_skill_bytes"], "Skill")
            try:
                legal_paths = applicable_legal_paths(skill_path, item["blobs"])
            except AdaptiveError:
                continue
            if any(item["blobs"][legal_path].get("mode") != "100644" for legal_path, _ in legal_paths):
                continue
            cache_key = tuple(legal_paths)
            documents = item["license_cache"].get(cache_key)
            if documents is None:
                documents = []
                total_license_bytes = 0
                for legal_path, kind in legal_paths:
                    legal_blob = client.get(f"/repos/{urlparse.quote(item['owner'])}/{urlparse.quote(item['name'])}/git/blobs/{item['blobs'][legal_path]['sha']}")
                    legal_content = decode_blob(legal_blob, policy["maximum_license_bytes"], kind)
                    total_license_bytes += len(legal_content.encode("utf-8"))
                    if total_license_bytes > policy["maximum_license_bytes"]:
                        documents = []
                        break
                    if ((kind == "license" and detect_license(legal_content) != "MIT")
                            or (kind == "notice" and not notice_is_unrestricted(legal_content))):
                        documents = []
                        break
                    documents.append({"path": legal_path, "kind": kind, "content": legal_content})
                item["license_cache"][cache_key] = documents
            if not documents:
                continue
            frontmatter, _ = parse_frontmatter(content)
            repository = item["repository"]
            aggregate = canonical_license_content(documents)
            candidates.append({
                "id": unique_candidate_id(skill_path, frontmatter, used),
                "repository": {"host": "github.com", "owner": item["owner"], "name": item["name"],
                    "repository_id": repository.get("id"), "owner_type": (repository.get("owner") or {}).get("type"),
                    "archived": repository.get("archived"), "fork": repository.get("fork"),
                    "stars": repository.get("stargazers_count"), "pushed_at": repository.get("pushed_at")},
                "commit": item["commit"], "path": skill_path, "content": content,
                "license": {"spdx": "MIT", "path": documents[0]["path"], "content": aggregate,
                            "documents": documents},
            })
        if len(candidates) >= policy["maximum_candidates"] or budget_exhausted:
            break
    if not candidates:
        raise AdaptiveError("NO_GITHUB_SKILLS_FOUND", f"no bounded GitHub candidates found; requests={client.requests}", 4)
    provenance = {"mode": "github-api", "source": "api.github.com",
        "blueprint_sha256": blueprint["confirmation"]["design_sha256"], "query": queries,
        "requests": client.requests, "observed_at": utc_now(), "candidate_set_sha256": canonical_sha256(candidates)}
    return {"schema": "agent-skill-candidates/v2", "provenance": provenance, "candidates": candidates}, client.requests, queries


def source_pin_for_candidate(candidate, provenance, policy, *, client_factory=GitHubClient):
    """Bind approval to one immutable source bundle.

    Caller-authored provenance never authenticates GitHub. github-api mode is
    accepted only after this process re-fetches repository identity and the
    exact commit/tree/blob bytes through the pinned HTTPS API client. Offline
    mode records the same complete pin but explicitly claims no GitHub
    authenticity.
    """
    require_finite_json(candidate, "Skill candidate")
    repository = candidate["repository"]
    skill_raw = candidate["content"].encode("utf-8")
    license_raw = candidate["license"]["content"].encode("utf-8")
    license_documents = candidate["license"].get("documents", [])
    license_failures = []
    validate_license_set(candidate["license"], candidate["path"], policy, license_failures)
    if license_failures:
        raise AdaptiveError("INVALID_SKILL_LICENSE_SET", f"legal document set is invalid: {sorted(set(license_failures))}")
    evidence = None
    authenticity = "offline-user-reviewed-no-source-host-authenticity"
    repository_metadata = dict(repository)
    if provenance["mode"] == "github-api":
        client = client_factory(policy["github_request_budget"])
        repository_api = client.get(f"/repositories/{repository['repository_id']}")
        if not isinstance(repository_api, dict):
            raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "repository identity response is invalid", 4)
        full_name = repository_api.get("full_name")
        expected_full_name = f"{repository['owner']}/{repository['name']}"
        owner_api = repository_api.get("owner") if isinstance(repository_api.get("owner"), dict) else {}
        trusted_metadata = {
            "host": "github.com", "owner": owner_api.get("login"),
            "name": repository_api.get("name"), "repository_id": repository_api.get("id"),
            "owner_type": owner_api.get("type"),
            "archived": repository_api.get("archived"), "fork": repository_api.get("fork"),
            "stars": repository_api.get("stargazers_count"), "pushed_at": repository_api.get("pushed_at"),
        }
        immutable_repository_fields=("host","owner","name","repository_id","owner_type","archived","fork")
        if (full_name != expected_full_name or any(trusted_metadata[key]!=repository[key] for key in immutable_repository_fields)
                or trusted_metadata["archived"] is not False):
            raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "caller repository identity differs from authenticated GitHub identity", 4)
        owner = urlparse.quote(repository["owner"], safe="")
        name = urlparse.quote(repository["name"], safe="")
        commit_api = client.get(f"/repos/{owner}/{name}/git/commits/{candidate['commit']}")
        commit_sha = commit_api.get("sha") if isinstance(commit_api, dict) else None
        commit_tree = commit_api.get("tree") if isinstance(commit_api, dict) and isinstance(commit_api.get("tree"), dict) else {}
        tree_sha = commit_tree.get("sha")
        if commit_sha != candidate["commit"] or not isinstance(tree_sha, str) or not COMMIT_RE.fullmatch(tree_sha):
            raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "immutable commit could not be authenticated", 4)
        tree_api = client.get(f"/repos/{owner}/{name}/git/trees/{tree_sha}?recursive=1")
        if not isinstance(tree_api, dict) or tree_api.get("truncated") is True or not isinstance(tree_api.get("tree"), list):
            raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "immutable source tree is incomplete", 4)
        blobs = {}
        for item in tree_api["tree"]:
            if not isinstance(item, dict) or item.get("type") != "blob":
                continue
            path = item.get("path")
            if path in blobs:
                raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "immutable source tree repeats a path", 4)
            blobs[path] = item
        skill_item = blobs.get(candidate["path"])
        if (not isinstance(skill_item, dict) or skill_item.get("mode") != "100644"
                or not COMMIT_RE.fullmatch(str(skill_item.get("sha", "")))):
            raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "reviewed Skill is unavailable at the immutable commit", 4)
        try:
            trusted_paths = applicable_legal_paths(candidate["path"], blobs)
        except AdaptiveError as error:
            raise AdaptiveError("GITHUB_SOURCE_MISMATCH", str(error), 4) from error
        declared_paths = [(item.get("path"), item.get("kind")) for item in license_documents if isinstance(item, dict)]
        required_blob_requests = 1 + len(trusted_paths)
        if client.requests + required_blob_requests > client.budget:
            raise AdaptiveError("GITHUB_BUDGET_INSUFFICIENT",
                f"GitHub request budget {client.budget} cannot authenticate one Skill and {len(trusted_paths)} legal blobs after immutable tree inspection", 4)
        if declared_paths != trusted_paths:
            raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "reviewed legal document set is incomplete or ambiguous", 4)
        skill_blob = client.get(f"/repos/{owner}/{name}/git/blobs/{skill_item.get('sha')}")
        if not isinstance(skill_blob, dict) or skill_blob.get("sha") != skill_item.get("sha"):
            raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "GitHub Skill blob identity differs from the immutable tree", 4)
        trusted_skill = decode_blob(skill_blob, policy["maximum_skill_bytes"], "Skill")
        trusted_documents = []
        license_blob_shas = []
        for declared, (legal_path, kind) in zip(license_documents, trusted_paths):
            legal_item = blobs.get(legal_path)
            if (not isinstance(legal_item, dict) or legal_item.get("mode") != "100644"
                    or not COMMIT_RE.fullmatch(str(legal_item.get("sha", "")))):
                raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "reviewed legal document is not a regular immutable blob", 4)
            legal_blob = client.get(f"/repos/{owner}/{name}/git/blobs/{legal_item.get('sha')}")
            if not isinstance(legal_blob, dict) or legal_blob.get("sha") != legal_item.get("sha"):
                raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "GitHub legal blob identity differs from the immutable tree", 4)
            trusted_content = decode_blob(legal_blob, policy["maximum_license_bytes"], kind)
            if trusted_content != declared.get("content"):
                raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "reviewed legal bytes differ from immutable GitHub blobs", 4)
            if ((kind == "license" and detect_license(trusted_content) != "MIT")
                    or (kind == "notice" and not notice_is_unrestricted(trusted_content))):
                raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "reviewed legal terms are conflicting or restrictive", 4)
            trusted_documents.append({"path": legal_path, "kind": kind, "content": trusted_content})
            license_blob_shas.append({"path": legal_path, "sha": legal_item.get("sha")})
        if trusted_skill.encode("utf-8") != skill_raw or canonical_license_content(trusted_documents).encode("utf-8") != license_raw:
            raise AdaptiveError("GITHUB_SOURCE_MISMATCH", "reviewed aggregate bytes differ from immutable GitHub blobs", 4)
        authenticity = "github-api-refetched-immutable"
        evidence = {
            "api_host": "api.github.com", "repository_id": repository_api["id"],
            "commit_sha": commit_sha, "tree_sha": tree_sha,
            "skill_blob_sha": skill_item.get("sha"), "license_blob_shas": license_blob_shas,
            "observed_repository_metadata_sha256": canonical_sha256(trusted_metadata), "requests": client.requests,
        }
    return {
        "schema": "agent-skill-source-pin/v2", "authenticity": authenticity,
        "repository": repository_metadata, "commit": candidate["commit"], "path": candidate["path"],
        "skill": {"source_path": candidate["path"], "sha256": bytes_sha256(skill_raw), "bytes": len(skill_raw)},
        "license": {"spdx": candidate["license"]["spdx"], "classifier": "strict-license-set/v2",
                    "sha256": bytes_sha256(license_raw), "bytes": len(license_raw),
                    "documents": [{"source_path": item["path"], "kind": item["kind"],
                        "classifier": "strict-mit-text/v1" if item["kind"] == "license" else "unrestricted-notice/v1",
                        "sha256": bytes_sha256(item["content"].encode("utf-8")),
                        "bytes": len(item["content"].encode("utf-8"))} for item in license_documents]},
        "relative_assets": relative_asset_references(candidate["content"]),
        "authenticated_evidence": evidence,
    }


def project_path(root, name):
    return root / ".agent/project" / name


def lock_path(root):
    return project_path(root, "skills.lock.json")


def empty_lock(blueprint, policy):
    value = {
        "schema": "agent-skills-lock/v2", "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
        "policy_sha256": canonical_sha256(policy), "skills": [], "lock_sha256": None,
    }
    value["lock_sha256"] = canonical_sha256(lock_payload(value))
    return value


def lock_payload(value):
    return {key: value[key] for key in value if key != "lock_sha256"}


def validate_lock(value):
    if isinstance(value, dict) and value.get("schema") == "agent-skills-lock/v1":
        raise AdaptiveError("SKILL_LOCK_MIGRATION_REQUIRED",
            "v1 locks do not bind complete applicable legal-document sets; quarantine them and re-discover/re-review every Skill before creating a v2 lock", 3)
    if not isinstance(value, dict) or set(value) != {"schema", "blueprint_sha256", "policy_sha256", "skills", "lock_sha256"}:
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill lock fields are invalid", 3)
    if value.get("schema") != "agent-skills-lock/v2" or not SHA256_RE.fullmatch(str(value.get("blueprint_sha256", ""))) or not SHA256_RE.fullmatch(str(value.get("policy_sha256", ""))):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill lock identity is invalid", 3)
    if not isinstance(value.get("skills"), list) or len(value["skills"]) > 64:
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill lock inventory is invalid", 3)
    if value.get("lock_sha256") != canonical_sha256(lock_payload(value)):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill lock digest drifted", 3)
    ids = [item.get("id") for item in value["skills"] if isinstance(item, dict)]
    if len(ids) != len(value["skills"]) or len(ids) != len(set(ids)):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill lock IDs are invalid", 3)
    return value


def load_lock(root, blueprint, policy, required=False):
    path = lock_path(root)
    if not path.exists():
        if required:
            raise AdaptiveError("SKILL_LOCK_MISSING", "no dynamic Skill lock exists", 3)
        return empty_lock(blueprint, policy)
    value = validate_lock(skill_load_json(path, "Skill lock"))
    for entry in value["skills"]:
        verify_entry(root, entry)
    return value


def archive_lock(root, value):
    if not value.get("skills"):
        return
    digest = value.get("lock_sha256") or canonical_sha256(lock_payload(value))
    path = project_path(root, f"skill-lock-history/{digest}.json")
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or skill_load_json(path,"Skill lock history")!=value:
            raise AdaptiveError("SKILL_LOCK_HISTORY_COLLISION","existing Skill lock history bytes or value differ",3)
    else:
        write_json(path,value)


def finalize_lock(value):
    value={**value,"skills":sorted(value["skills"],key=lambda item:item["id"]),"lock_sha256":None}
    return {**value,"lock_sha256":canonical_sha256(lock_payload(value))}


def write_lock(root, previous, value):
    archive_lock(root, previous)
    value=finalize_lock(value)
    write_json(lock_path(root), value)
    return value


def _storage_project_root(path):
    cursor = Path(path)
    while cursor.parent != cursor:
        if cursor.name == "project" and cursor.parent.name == ".agent":
            return cursor.parent.parent
        cursor = cursor.parent
    raise AdaptiveError("UNSAFE_SKILL_STORAGE", f"Skill storage is outside .agent/project: {path}", 3)


def _open_storage_chain(path):
    """Open every component from the project root without following links."""
    path = Path(path)
    project_root = _storage_project_root(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(project_root, flags)
    try:
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.fstat(descriptor).st_uid
        components = path.relative_to(project_root).parts
        for component in components:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != expected_uid
                    or stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)):
                raise AdaptiveError("UNSAFE_SKILL_STORAGE", f"Skill storage ancestry is unsafe: {path}", 3)
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != expected_uid
                or stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)):
            raise AdaptiveError("UNSAFE_SKILL_STORAGE", f"Skill storage is unsafe: {path}", 3)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise
def capture_exact_bundle(path, files):
    """Capture one exact bundle through a pinned no-follow directory descriptor."""
    path = Path(path)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        return None
    try:
        expected = sorted(record["path"] for record in files)
        if expected != ["LICENSE.txt", "SKILL.md"] or any(
                set(record) != {"path", "bytes", "sha256", "mode"} or record["mode"] != "100600"
                or not isinstance(record["bytes"], int) or isinstance(record["bytes"], bool) or record["bytes"] < 0
                or not SHA256_RE.fullmatch(str(record["sha256"])) for record in files):
            return None
        directory_fd = _open_storage_chain(path)
    except (KeyError, TypeError, OSError):
        return None
    try:
        directory = os.fstat(directory_fd)
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else directory.st_uid
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != expected_uid
                or stat.S_IMODE(directory.st_mode) != 0o700 or sorted(bounded_directory_names(directory_fd,"SKILL_INTEGRITY_ERROR","Skill bundle inventory",3)) != expected):
            return None
        captured = {}
        for record in sorted(files, key=lambda item: item["path"]):
            try:
                descriptor = os.open(record["path"], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            except OSError:
                return None
            try:
                opened = os.fstat(descriptor)
                if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_uid != expected_uid
                        or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_size != record["bytes"]):
                    return None
                chunks, remaining = [], record["bytes"] + 1
                while remaining:
                    chunk = os.read(descriptor, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk); remaining -= len(chunk)
                raw = b"".join(chunks)
                after = os.fstat(descriptor)
                linked = os.stat(record["path"], dir_fd=directory_fd, follow_symlinks=False)
                if ((after.st_dev, after.st_ino, after.st_nlink, after.st_mode, after.st_size)
                        != (opened.st_dev, opened.st_ino, opened.st_nlink, opened.st_mode, opened.st_size)
                        or (linked.st_dev, linked.st_ino) != (opened.st_dev, opened.st_ino)):
                    return None
            finally:
                os.close(descriptor)
            if len(raw) != record["bytes"] or bytes_sha256(raw) != record["sha256"]:
                return None
            captured[record["path"]] = raw
        verification_fd = _open_storage_chain(path)
        try:
            current = os.fstat(verification_fd)
        finally:
            os.close(verification_fd)
        if ((current.st_dev, current.st_ino) != (directory.st_dev, directory.st_ino)
                or sorted(bounded_directory_names(directory_fd,"SKILL_INTEGRITY_ERROR","Skill bundle inventory",3)) != expected):
            return None
        return captured
    except (KeyError, TypeError, OSError):
        return None
    finally:
        os.close(directory_fd)


def exact_bundle(path, files):
    return capture_exact_bundle(path,files) is not None


def expected_bundle_records(content, license_content):
    values = {"SKILL.md": content.encode("utf-8"), "LICENSE.txt": license_content.encode("utf-8")}
    return [
        {"path": filename, "bytes": len(values[filename]), "sha256": bytes_sha256(values[filename]), "mode": "100600"}
        for filename in sorted(values)
    ]


def _open_secure_directory(path, *, exact_mode=None):
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise AdaptiveError("UNSAFE_SKILL_STORAGE", "host lacks no-follow directory descriptors", 3)
    descriptor = _open_storage_chain(path)
    metadata = os.fstat(descriptor)
    expected_uid = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
    if (metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH)
            or (exact_mode is not None and stat.S_IMODE(metadata.st_mode) != exact_mode)):
        os.close(descriptor)
        raise AdaptiveError("UNSAFE_SKILL_STORAGE", f"Skill storage ownership or mode is unsafe: {path}", 3)
    return descriptor


def _write_bundle_file(directory_fd, name, raw):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_bundle(parent, name, content, license_content, *, staging_name=None):
    ensure_real_directory(parent)
    parent_fd = _open_secure_directory(parent)
    staging_name = staging_name or f".{name}.{uuid.uuid4().hex}"
    if (not isinstance(staging_name,str) or "/" in staging_name or staging_name in {".",".."}
            or re.fullmatch(r"[.A-Za-z0-9_-]{1,192}",staging_name) is None):
        os.close(parent_fd); raise AdaptiveError("UNSAFE_SKILL_STORAGE","Skill staging name is invalid",3)
    staging = Path(parent) / staging_name
    try:
        os.mkdir(staging_name, 0o700, dir_fd=parent_fd)
        staging_fd = os.open(staging_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            _write_bundle_file(staging_fd, "SKILL.md", content.encode("utf-8"))
            _write_bundle_file(staging_fd, "LICENSE.txt", license_content.encode("utf-8"))
            os.fsync(staging_fd)
        finally:
            os.close(staging_fd)
        files = expected_bundle_records(content, license_content)
        if not exact_bundle(staging, files):
            raise AdaptiveError("SKILL_BUNDLE_DRIFT", "descriptor-published staging bundle is unsafe", 3)
        return staging, files
    except Exception:
        if staging.exists() and not staging.is_symlink():
            shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        os.close(parent_fd)


def publish_new_bundle(staging, target, files):
    """Publish a new immutable CAS namespace entry using one pinned parent."""
    if staging.parent != target.parent or capture_exact_bundle(staging, files) is None:
        raise AdaptiveError("SKILL_BUNDLE_DRIFT", "CAS staging bundle is unsafe", 3)
    parent_fd = _open_secure_directory(target.parent)
    try:
        staged_inode = os.stat(staging.name, dir_fd=parent_fd, follow_symlinks=False)
        try:
            os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(staging.name, target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            published_inode = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
            if (published_inode.st_dev,published_inode.st_ino)!=(staged_inode.st_dev,staged_inode.st_ino):
                raise AdaptiveError("SKILL_BUNDLE_DRIFT", "CAS namespace changed during publication", 3)
        else:
            raise AdaptiveError("CAS_COLLISION", "CAS target appeared during publication", 3)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    if capture_exact_bundle(target, files) is None:
        raise AdaptiveError("SKILL_BUNDLE_DRIFT", "published CAS bundle is unsafe", 3)


def activate_from_bundle(bundle, target, files):
    parent = target.parent
    ensure_real_directory(parent)
    captured = capture_exact_bundle(bundle, files)
    if captured is None:
        raise AdaptiveError("SKILL_BUNDLE_DRIFT", "CAS bytes changed before activation", 3)
    try:
        skill_content = captured["SKILL.md"].decode("utf-8")
        license_content = captured["LICENSE.txt"].decode("utf-8")
    except UnicodeDecodeError as error:
        raise AdaptiveError("SKILL_BUNDLE_DRIFT", "CAS bundle is not canonical UTF-8", 3) from error
    staging, staged_files = write_bundle(parent, target.name + "-active", skill_content, license_content)
    if staged_files != files:
        raise AdaptiveError("SKILL_BUNDLE_DRIFT", "captured reviewed bytes changed during materialization", 3)
    old_name = None
    parent_fd = _open_secure_directory(parent)
    try:
        staged_inode = os.stat(staging.name, dir_fd=parent_fd, follow_symlinks=False)
        try:
            target_before = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            target_before = None
        if target_before is not None:
            expected_uid = os.geteuid() if hasattr(os, "geteuid") else target_before.st_uid
            if (not stat.S_ISDIR(target_before.st_mode) or target_before.st_uid != expected_uid
                    or stat.S_IMODE(target_before.st_mode) != 0o700):
                raise AdaptiveError("UNSAFE_SKILL_TARGET", f"active Skill target is unsafe: {target}", 3)
            old_name = f".{target.name}.old-{uuid.uuid4().hex}"
            os.rename(target.name, old_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            moved = os.stat(old_name, dir_fd=parent_fd, follow_symlinks=False)
            if (moved.st_dev, moved.st_ino) != (target_before.st_dev, target_before.st_ino):
                raise AdaptiveError("UNSAFE_SKILL_TARGET", "active target changed during replacement", 3)
        os.rename(staging.name, target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        published_inode = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (published_inode.st_dev,published_inode.st_ino)!=(staged_inode.st_dev,staged_inode.st_ino):
            raise AdaptiveError("UNSAFE_SKILL_TARGET", "active namespace changed during publication", 3)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    if not exact_bundle(target, files):
        raise AdaptiveError("SKILL_BUNDLE_DRIFT", "active Skill differs before lock commit", 3)
    if old_name:
        old = parent / old_name
        if old.exists() and not old.is_symlink():
            shutil.rmtree(old)


def provider_coverage_id(provider):
    return f"provider:{provider['id']}"


def required_skill_coverage(blueprint):
    """Return only explicit Skill requirements, never contextual Blueprint prose."""
    return {item["id"] for item in routing_units(blueprint)
            if item["required"] and item["id"] not in BUILTIN_SKILL_AUTHORIZED_CAPABILITIES}


def matched_capabilities(blueprint, content):
    tokens=token_set(content); matched=[]
    for item in routing_units(blueprint):
        if not item["required"]: continue
        if item["dimension"]=="provider":
            provider_id=item["id"].split(":",1)[1]
            provider=next(value for value in blueprint["design"].get("providers",[]) if value.get("id")==provider_id)
            if provider_specific_tokens(provider)&tokens: matched.append(item["id"])
        elif routing_unit_fit(item,tokens)>=0.5:
            matched.append(item["id"])
    return sorted(set(matched))


def command_discover(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    policy = load_policy(root)
    document, requests, query = discover_github(blueprint, policy, args.max_repositories)
    output = Path(args.output).resolve() if args.output else project_path(root, "skill-candidates.json")
    write_json(output, document)
    print_json({"status": "discovered-untrusted", "output": str(output), "candidate_count": len(document["candidates"]), "requests": requests, "query": query})
    return 0


def command_score(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    policy = load_policy(root)
    candidates, provenance = clean_candidate_container(skill_load_json(Path(args.candidates).resolve(), "Skill candidates"), policy, blueprint)
    report = build_report(blueprint, policy, candidates, provenance)
    output = Path(args.output).resolve() if args.output else project_path(root, "skill-recommendation.json")
    write_json(output, report)
    print_json({"output":str(output),"recommended_id":report["recommended_id"],"recommended_ids":report["recommended_ids"],
                "uncovered_coverage":report["uncovered_coverage"],"recommendation_sha256":report["recommendation_sha256"],
                "candidate_count":len(report["candidates"])})
    return 0 if report["recommended_ids"] or not report["required_coverage"] else 2


def explicit_user_source(value):
    if not isinstance(value, str) or not value.startswith("user:") or not value[5:].strip():
        raise AdaptiveError("HUMAN_DECISION_REQUIRED", "source must be an explicit user:<decision> record")
    return value


def command_install(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    policy = load_policy(root)
    report = load_report(Path(args.report).resolve())
    validate_report_context(report, blueprint, policy)
    candidates, provenance = clean_candidate_container(skill_load_json(Path(args.candidates).resolve(), "Skill candidates"), policy, blueprint)
    # Offline catalogs are explicit user-reviewed content authority, not repository
    # authenticity. Activation remains exact-byte, MIT-only, exact-file-set, and
    # human-decision gated; source_pin_for_candidate records the bounded residual.
    if provenance.get("mode")=="offline-user-reviewed":
        catalogs={"offline:"+item["id"]:item["candidate_set_sha256"] for item in policy["offline_content_catalogs"]}
        if catalogs.get(provenance.get("source"))!=provenance.get("candidate_set_sha256"):
            raise AdaptiveError("OFFLINE_CATALOG_NOT_AUTHORIZED","offline activation requires an exact policy-selected content catalog digest",3)
    if provenance != report["candidate_provenance"]:
        raise AdaptiveError("CANDIDATE_PROVENANCE_DRIFT", "candidate provenance changed after scoring")
    report_time=dt.datetime.fromisoformat(report["generated_at"].replace("Z","+00:00")).replace(hour=0,minute=0,second=0,microsecond=0)
    reassessed=[candidate_assessment(item,blueprint,policy,now=report_time,
                  trusted_repository_metadata=False) for item in candidates]
    for assessment_value,candidate_value in zip(reassessed,candidates):
        assessment_value["suggested_capabilities"]=list(assessment_value.get("approvable_coverage",[]))
    rebuilt=report_payload(blueprint,policy,reassessed,provenance)
    if any(report.get(key)!=rebuilt[key] for key in ("candidates","required_coverage","uncovered_coverage","recommended_ids","recommended_id")):
        raise AdaptiveError("CANDIDATE_DRIFT","candidate assessments or covering-set recommendation changed after scoring")
    candidate_id = args.candidate or report["recommended_id"]
    if not candidate_id:
        raise AdaptiveError("NO_ELIGIBLE_SKILL", "recommendation has no eligible Skill")
    if candidate_id not in report["recommended_ids"] and (not isinstance(args.rationale,str) or not args.rationale.strip() or len(args.rationale)>512):
        raise AdaptiveError("CANDIDATE_OVERRIDE_RATIONALE_REQUIRED", "selecting another eligible candidate requires a 1-512 character rationale")
    result = next((item for item in report["candidates"] if item["id"] == candidate_id), None)
    candidate = next((item for item in candidates if item.get("id") == candidate_id), None)
    if not result or not result.get("eligible") or candidate is None:
        raise AdaptiveError("SKILL_NOT_ELIGIBLE", f"Skill {candidate_id!r} is not eligible")
    assessment=next(item for item in reassessed if item["id"]==candidate_id)
    if assessment != result or not assessment["eligible"]:
        raise AdaptiveError("CANDIDATE_DRIFT", "candidate bytes, score, or evidence changed after scoring")
    previous = load_lock(root, blueprint, policy)
    if previous["skills"] and (
        previous["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"]
        or previous["policy_sha256"] != canonical_sha256(policy)
    ):
        raise AdaptiveError("STALE_SKILL_LOCK", "quarantine stale locked Skills before selecting for the new design or policy")
    existing = next((item for item in previous["skills"] if item["id"] == candidate_id), None)
    if args.command == "update" and existing is None:
        raise AdaptiveError("SKILL_NOT_INSTALLED", "update requires an existing locked Skill")
    if args.command == "install" and existing and not args.replace:
        raise AdaptiveError("SKILL_ALREADY_INSTALLED", "use the update command after reviewing a new recommendation")
    if existing and existing["candidate_sha256"] == assessment["candidate_sha256"]:
        raise AdaptiveError("SKILL_ALREADY_CURRENT", "the approved candidate bytes are already locked")
    blueprint_capabilities=required_skill_coverage(blueprint)
    approved_capabilities = sorted(set(args.covers_capability or []))
    if len(approved_capabilities) != len(args.covers_capability or []) or set(approved_capabilities) - blueprint_capabilities:
        raise AdaptiveError("INVALID_CAPABILITY_APPROVAL", "approved capability coverage must be a duplicate-free subset of the confirmed blueprint")
    suggested_capabilities=list(assessment.get("approvable_coverage",[]))
    if blueprint_capabilities and not approved_capabilities:
        raise AdaptiveError("CAPABILITY_APPROVAL_REQUIRED", "select at least one confirmed capability that this Skill is approved to cover")
    if set(approved_capabilities) - set(suggested_capabilities) and (not isinstance(args.rationale, str) or not args.rationale.strip()):
        raise AdaptiveError("CAPABILITY_OVERRIDE_RATIONALE_REQUIRED", "coverage beyond the relevance suggestion requires an explicit rationale")
    source_pin = source_pin_for_candidate(candidate, provenance, policy)
    if source_pin["relative_assets"]:
        raise AdaptiveError("UNAVAILABLE_RELATIVE_ASSETS", "content-only activation cannot publish relative Skill assets")
    source_pin_sha256 = canonical_sha256(source_pin)
    expected_files = expected_bundle_records(candidate["content"], candidate["license"]["content"])
    expected_bundle_sha256 = canonical_sha256({"files": expected_files})
    skill_bytes=candidate["content"].encode("utf-8")
    license_bytes=candidate["license"]["content"].encode("utf-8")
    reviewed_documents=[
        {"path":"SKILL.md","encoding":"utf-8","content":candidate["content"],
         "sha256":bytes_sha256(skill_bytes),"bytes":len(skill_bytes)},
        {"path":"LICENSE.txt","encoding":"utf-8","content":candidate["license"]["content"],
         "sha256":bytes_sha256(license_bytes),"bytes":len(license_bytes)},
    ]
    reviewed_license_documents=[
        {"source_path":item["path"],"kind":item["kind"],"encoding":"utf-8","content":item["content"],
         "sha256":bytes_sha256(item["content"].encode("utf-8")),"bytes":len(item["content"].encode("utf-8"))}
        for item in candidate["license"]["documents"]
    ]
    content_review={
        "schema":"agent-skill-human-content-review/v3",
        "candidate_sha256":assessment["candidate_sha256"],
        "source_pin_sha256":source_pin_sha256,
        "skill_content_sha256":reviewed_documents[0]["sha256"],
        "license_content_sha256":reviewed_documents[1]["sha256"],
        "license_spdx":candidate["license"]["spdx"],
        "reviewed_coverage":approved_capabilities,
        "relative_assets":[],
        "documents":reviewed_documents,"license_documents":reviewed_license_documents,
        "review_scope":"provider authority receives exact UTF-8 SKILL.md bytes and every applicable nearest-ancestor LICENSE/COPYING/NOTICE term, their canonical LICENSE.txt aggregate, complete immutable source pin, strict MIT-only classification, reviewed coverage, and proof that no relative assets are activated",
    }
    action = {
        "schema": "agent-skill-selection-action/v4", "operation": args.command,
        "activation_boundary":"candidate-quarantine-to-content-only-active/v1", "content_review":content_review,
        "candidate": candidate_id, "candidate_sha256": assessment["candidate_sha256"], "bundle_sha256": expected_bundle_sha256,
        "score": result["score"], "recommendation_sha256": report["recommendation_sha256"], "report_sha256": report["report_sha256"],
        "current_lock_sha256": previous["lock_sha256"],
        "blueprint_sha256": blueprint["confirmation"]["design_sha256"], "policy_sha256": canonical_sha256(policy),
        "report_expires_at": report["expires_at"], "replace": bool(args.replace),
        "candidate_provenance": provenance, "source_pin": source_pin,
        "source_pin_sha256": source_pin_sha256, "approved_capabilities": approved_capabilities,
        "rationale": args.rationale.strip() if isinstance(args.rationale, str) else "",
    }
    action_sha256 = canonical_sha256(action)
    if args.plan:
        print_json({"schema": "agent-skill-selection-approval/v1", "payload": action,
                    "approval_sha256": action_sha256, "mutation": False})
        return 0
    source = explicit_user_source(args.source)
    if (args.reviewed_content_sha256!=content_review["skill_content_sha256"]
            or args.reviewed_license_sha256!=content_review["license_content_sha256"]):
        raise AdaptiveError("EXACT_SKILL_CONTENT_REVIEW_REQUIRED","activation requires explicit review digests for the exact SKILL.md and LICENSE.txt bytes")
    if args.approve_digest != action_sha256:
        raise AdaptiveError("RECOMMENDATION_APPROVAL_REQUIRED", f"approve the exact candidate action digest: {action_sha256}")
    gate=f"adaptive-skill-{args.command}"
    request=prepare_provider_human_decision(root,gate=gate,artifact_sha256=action_sha256,
        source=source,receipt=args.human_decision_receipt)
    # Derive the complete immutable CAS intent without touching storage. The
    # recovery journal must exist before any approved bytes enter the CAS
    # namespace, otherwise a kill leaves an unaudited orphan.
    files=expected_bundle_records(candidate["content"],candidate["license"]["content"])
    bundle_digest=canonical_sha256({"files":files})
    if bundle_digest!=expected_bundle_sha256:
        raise AdaptiveError("SKILL_BUNDLE_DRIFT","derived Skill bundle differs from the approved action")
    cas=project_path(root,f"skill-cas/{bundle_digest}")
    cas_preexisting=cas.exists() or cas.is_symlink()
    if cas_preexisting and not exact_bundle(cas,files):
        raise AdaptiveError("CAS_COLLISION","content-addressed Skill bundle is inconsistent",3)
    receipt_placeholder=decision_placeholder(request)
    entry={
        "id":candidate_id,"status":"active","source_pin":source_pin,
        "source":{"host":candidate["repository"]["host"],"owner":candidate["repository"]["owner"],
                  "repository":candidate["repository"]["name"],"repository_id":candidate["repository"]["repository_id"],
                  "commit":candidate["commit"],"path":candidate["path"],"provenance_mode":provenance["mode"],
                  "provenance_source":provenance["source"],"authenticity":source_pin["authenticity"]},
        "license":{"spdx":candidate["license"]["spdx"],"path":candidate["license"]["path"],
                   "sha256":bytes_sha256(candidate["license"]["content"].encode("utf-8")),
                   "documents":[{"path":item["path"],"kind":item["kind"],
                                 "sha256":bytes_sha256(item["content"].encode("utf-8")),
                                 "bytes":len(item["content"].encode("utf-8"))} for item in candidate["license"]["documents"]]},
        "candidate_sha256":assessment["candidate_sha256"],"recommendation_sha256":report["recommendation_sha256"],
        "blueprint_sha256":blueprint["confirmation"]["design_sha256"],"score":result["score"],
        "matched_capabilities":approved_capabilities,"bundle_sha256":bundle_digest,"files":files,"installed_at":utc_now(),
        "decision":{"gate":gate,"source":source,"action_sha256":action_sha256,"action":action,"receipt":receipt_placeholder},
    }
    skills=[item for item in previous["skills"] if item["id"]!=candidate_id]+[entry]
    post_lock=finalize_lock({"schema":"agent-skills-lock/v2","blueprint_sha256":blueprint["confirmation"]["design_sha256"],
        "policy_sha256":canonical_sha256(policy),"skills":skills,"lock_sha256":None})
    lifecycle=load_lifecycle(root); lifecycle_exists=lifecycle_path(root).exists()
    pre=mutation_state(root,previous,lifecycle,[candidate_id],lock_exists=lock_path(root).exists(),lifecycle_exists=lifecycle_exists)
    post=intended_post_state(root,previous,post_lock,lifecycle,[candidate_id],[{"bundle_sha256":bundle_digest,"files":files,"preexisting":cas_preexisting}],
        post_lifecycle_exists=lifecycle_exists)
    journal=prepare_mutation_journal(root,operation=args.command,action_sha256=action_sha256,gate=gate,source=source,
        approval={"kind":"provider-human-decision","request":request},pre_state=pre,post_state=post)
    if not cas_preexisting:
        staging=None
        try:
            staging_name=f".mutation-staging-{journal['journal_id']}"
            staging,staged_files=write_bundle(project_path(root,"skill-cas"),candidate_id,candidate["content"],candidate["license"]["content"],staging_name=staging_name)
            if os.environ.get("SELF_TEST_CRASH_DURING_PRIVATE_SKILL_MATERIALIZATION")=="1": os._exit(93)
            if staged_files!=files:
                raise AdaptiveError("SKILL_BUNDLE_DRIFT","materialized Skill bundle differs from durable journal intent",3)
            publish_new_bundle(staging,cas,files); staging=None
        finally:
            if staging is not None and staging.exists() and not staging.is_symlink(): shutil.rmtree(staging,ignore_errors=True)
    if os.environ.get("SELF_TEST_CRASH_AFTER_SKILL_CAS_BEFORE_AUTHORIZATION")=="1":
        raise SystemExit(96)
    journal=authorize_prepared_mutation(root,journal); publish_intended_state(root,journal)
    current=materialized_post_state(journal)["lock"]["value"]
    print_json({"status": "updated-content-only" if existing else "installed-content-only", "id": candidate_id, "bundle_sha256": bundle_digest, "lock_sha256": current["lock_sha256"], "scripts_executed": False})
    return 0


def verify_entry(root, entry):
    required = {
        "id", "status", "source_pin", "source", "license", "candidate_sha256", "recommendation_sha256",
        "blueprint_sha256", "score", "matched_capabilities", "bundle_sha256", "files", "installed_at", "decision",
    }
    if not isinstance(entry, dict) or set(entry) != required or entry.get("status") not in {"active", "deprecated", "retired", "quarantined"}:
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill entry fields are invalid", 3)
    if not ID_RE.fullmatch(str(entry.get("id", ""))) or not SHA256_RE.fullmatch(str(entry.get("bundle_sha256", ""))):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill entry identity is invalid", 3)
    source = entry.get("source")
    if not isinstance(source, dict) or set(source) != {"host", "owner", "repository", "repository_id", "commit", "path", "provenance_mode", "provenance_source", "authenticity"} or not COMMIT_RE.fullmatch(str(source.get("commit", ""))):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill source lock is invalid", 3)
    if source.get("provenance_mode") not in {"github-api", "offline-user-reviewed"} or not isinstance(source.get("provenance_source"), str):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill provenance mode is invalid", 3)
    decision = entry.get("decision")
    if (not isinstance(decision, dict) or set(decision) != {"gate", "source", "action_sha256", "action", "receipt"}
            or not isinstance(decision.get("action"), dict) or decision.get("action_sha256") != canonical_sha256(decision["action"])):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill human decision binding is invalid", 3)
    action = decision["action"]
    current_blueprint=load_blueprint(root,require_confirmed=True)
    current_blueprint_sha256=current_blueprint["confirmation"]["design_sha256"]
    current_policy_sha256=canonical_sha256(load_policy(root))
    if (entry.get("blueprint_sha256")!=current_blueprint_sha256
            or action.get("blueprint_sha256")!=current_blueprint_sha256
            or action.get("policy_sha256")!=current_policy_sha256):
        raise AdaptiveError("SKILL_BLUEPRINT_STALE","locked Skill approval targets an older confirmed Blueprint or policy",3)
    files=entry.get("files")
    if not isinstance(files,list) or [item.get("path") for item in files if isinstance(item,dict)]!="LICENSE.txt SKILL.md".split():
        raise AdaptiveError("INVALID_SKILL_LOCK","Skill file exact-set is invalid",3)
    cas=project_path(root,f"skill-cas/{entry['bundle_sha256']}")
    captured=capture_exact_bundle(cas,files)
    if captured is None:
        raise AdaptiveError("SKILL_INTEGRITY_ERROR",f"CAS bundle drifted for {entry['id']}",3)
    try:
        reviewed_documents=[
            {"path":name,"encoding":"utf-8","content":captured[name].decode("utf-8"),
             "sha256":bytes_sha256(captured[name]),"bytes":len(captured[name])}
            for name in ("SKILL.md","LICENSE.txt")
        ]
    except UnicodeDecodeError as error:
        raise AdaptiveError("INVALID_SKILL_LOCK","reviewed Skill bytes are not canonical UTF-8",3) from error
    files_by_path={record.get("path"):record for record in files if isinstance(record,dict)}
    review=action.get("content_review")
    source_pin=entry.get("source_pin")
    source_pin_sha256=canonical_sha256(source_pin) if isinstance(source_pin,dict) else None
    if not isinstance(source_pin,dict) or set(source_pin)!={"schema","authenticity","repository","commit","path","skill","license","relative_assets","authenticated_evidence"}:
        raise AdaptiveError("INVALID_SKILL_LOCK", "complete Skill source pin is missing", 3)
    repository=source_pin.get("repository")
    pinned_license=source_pin.get("license")
    expected_source={
        "host":repository.get("host") if isinstance(repository,dict) else None,
        "owner":repository.get("owner") if isinstance(repository,dict) else None,
        "repository":repository.get("name") if isinstance(repository,dict) else None,
        "repository_id":repository.get("repository_id") if isinstance(repository,dict) else None,
        "commit":source_pin.get("commit"),"path":source_pin.get("path"),
        "provenance_mode":action.get("candidate_provenance",{}).get("mode"),
        "provenance_source":action.get("candidate_provenance",{}).get("source"),
        "authenticity":source_pin.get("authenticity"),
    }
    reviewed_licenses=review.get("license_documents") if isinstance(review,dict) else None
    reconstructed_documents=[]
    if isinstance(reviewed_licenses,list):
        for item in reviewed_licenses:
            if not isinstance(item,dict) or set(item)!={"source_path","kind","encoding","content","sha256","bytes"}:
                reconstructed_documents=[]; break
            raw=item.get("content","").encode("utf-8") if isinstance(item.get("content"),str) else b""
            if (item.get("encoding")!="utf-8" or item.get("sha256")!=bytes_sha256(raw)
                    or item.get("bytes")!=len(raw)):
                reconstructed_documents=[]; break
            reconstructed_documents.append({"path":item["source_path"],"kind":item["kind"],"content":item["content"]})
    expected_license={"spdx":pinned_license.get("spdx") if isinstance(pinned_license,dict) else None,
                      "path":reconstructed_documents[0]["path"] if reconstructed_documents else None,
                      "sha256":bytes_sha256(captured["LICENSE.txt"]),
                      "documents":[{"path":item["path"],"kind":item["kind"],
                          "sha256":bytes_sha256(item["content"].encode("utf-8")),
                          "bytes":len(item["content"].encode("utf-8"))} for item in reconstructed_documents]}
    reconstructed_candidate={
        "id":entry["id"],"repository":repository,"commit":source_pin.get("commit"),"path":source_pin.get("path"),
        "content":reviewed_documents[0]["content"],
        "license":{"spdx":expected_license["spdx"],"path":expected_license["path"],
                   "content":reviewed_documents[1]["content"],"documents":reconstructed_documents},
    }
    reconstructed_license_failures=[]
    validate_license_set(reconstructed_candidate["license"],source_pin.get("path"),load_policy(root),reconstructed_license_failures)
    candidate_provenance=action.get("candidate_provenance")
    provenance_fields={"mode","source","blueprint_sha256","query","requests","observed_at","candidate_set_sha256"}
    provenance_mode=candidate_provenance.get("mode") if isinstance(candidate_provenance,dict) else None
    current_policy=load_policy(root)
    offline_catalogs={"offline:"+item["id"]:item["candidate_set_sha256"] for item in current_policy["offline_content_catalogs"]}
    provenance_ok=(isinstance(candidate_provenance,dict) and set(candidate_provenance)==provenance_fields
        and candidate_provenance.get("blueprint_sha256")==current_blueprint_sha256
        and SHA256_RE.fullmatch(str(candidate_provenance.get("candidate_set_sha256",""))) is not None
        and isinstance(candidate_provenance.get("source"),str) and 0<len(candidate_provenance["source"])<=256
        and isinstance(candidate_provenance.get("requests"),int) and not isinstance(candidate_provenance.get("requests"),bool)
        and ((provenance_mode=="offline-user-reviewed" and candidate_provenance.get("query") is None
              and candidate_provenance.get("requests")==0
              and offline_catalogs.get(candidate_provenance.get("source"))==candidate_provenance.get("candidate_set_sha256"))
             or (provenance_mode=="github-api" and candidate_provenance.get("source")=="api.github.com"
                 and isinstance(candidate_provenance.get("query"),list) and candidate_provenance["query"]
                 and candidate_provenance.get("requests")>=len(candidate_provenance["query"]))))
    pin_auth_ok=(provenance_ok and ((provenance_mode=="github-api" and source_pin.get("authenticity")=="github-api-refetched-immutable"
                  and isinstance(source_pin.get("authenticated_evidence"),dict))
                 or (provenance_mode=="offline-user-reviewed"
                     and source_pin.get("authenticity")=="offline-user-reviewed-no-source-host-authenticity"
                     and source_pin.get("authenticated_evidence") is None)))
    pin_bytes_ok=(pin_auth_ok and source_pin.get("schema")=="agent-skill-source-pin/v2"
        and source_pin.get("skill")=={"source_path":source_pin.get("path"),"sha256":bytes_sha256(captured["SKILL.md"]),"bytes":len(captured["SKILL.md"])}
        and pinned_license=={"spdx":expected_license["spdx"],"classifier":"strict-license-set/v2",
            "sha256":bytes_sha256(captured["LICENSE.txt"]),"bytes":len(captured["LICENSE.txt"]),
            "documents":[{"source_path":item["path"],"kind":item["kind"],
                "classifier":"strict-mit-text/v1" if item["kind"]=="license" else "unrestricted-notice/v1",
                "sha256":bytes_sha256(item["content"].encode("utf-8")),
                "bytes":len(item["content"].encode("utf-8"))} for item in reconstructed_documents]}
        and source_pin.get("relative_assets")==[]
        and reviewed_documents[1]["content"]==canonical_license_content(reconstructed_documents)
        and not reconstructed_license_failures)
    if (action.get("schema")!="agent-skill-selection-action/v4"
            or action.get("activation_boundary")!="candidate-quarantine-to-content-only-active/v1"
            or not isinstance(review,dict) or set(review)!={"schema","candidate_sha256","source_pin_sha256","skill_content_sha256","license_content_sha256","license_spdx","reviewed_coverage","relative_assets","documents","license_documents","review_scope"}
            or review.get("schema")!="agent-skill-human-content-review/v3"
            or review.get("candidate_sha256")!=entry["candidate_sha256"]
            or review.get("source_pin_sha256")!=source_pin_sha256
            or review.get("skill_content_sha256")!=files_by_path.get("SKILL.md",{}).get("sha256")
            or review.get("license_content_sha256")!=files_by_path.get("LICENSE.txt",{}).get("sha256")
            or review.get("license_spdx")!=expected_license["spdx"]
            or review.get("reviewed_coverage")!=entry["matched_capabilities"] or review.get("relative_assets")!=[]
            or review.get("documents")!=reviewed_documents or not pin_bytes_ok
            or action.get("source_pin")!=source_pin or action.get("source_pin_sha256")!=source_pin_sha256
            or action.get("candidate") != entry["id"] or action.get("candidate_sha256") != canonical_sha256(reconstructed_candidate)
            or action.get("candidate_sha256") != entry["candidate_sha256"]
            or action.get("bundle_sha256") != entry["bundle_sha256"] or action.get("approved_capabilities") != entry["matched_capabilities"]
            or action.get("recommendation_sha256")!=entry["recommendation_sha256"] or action.get("score")!=entry["score"]
            or source!=expected_source or entry.get("license")!=expected_license):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill source, license, reviewed coverage, or CAS binding drifted", 3)
    # v2 authority is the matching immutable journal history plus its embedded
    # exact receipt bytes; the mutable receipt pathname is never an authority.
    if entry["status"] in {"active", "deprecated"}:
        active = project_path(root, f"skills/{entry['id']}")
        if not exact_bundle(active, files):
            raise AdaptiveError("SKILL_INTEGRITY_ERROR", f"active Skill drifted for {entry['id']}", 3)
    return captured


def bounded_directory_children(directory: Path,error_code: str,label: str,maximum: int):
    children=[]
    try:
        with os.scandir(directory) as scanner:
            for entry in scanner:
                if len(children)>=maximum: raise AdaptiveError(error_code,f"{label} exceeds {maximum} entries",3)
                children.append(Path(entry.path))
    except OSError as error: raise AdaptiveError(error_code,f"{label} is unreadable",3) from error
    return children


def bounded_directory_names(directory_fd,error_code: str,label: str,maximum: int):
    names=[]
    try:
        with os.scandir(directory_fd) as scanner:
            for entry in scanner:
                if len(names)>=maximum: raise AdaptiveError(error_code,f"{label} exceeds {maximum} entries",3)
                names.append(entry.name)
    except OSError as error: raise AdaptiveError(error_code,f"{label} is unreadable",3) from error
    return names


def bounded_active_skill_children(active_root: Path,error_code: str):
    return bounded_directory_children(active_root,error_code,"active Skill inventory",128)


def verify_activation(root,blueprint=None,policy=None):
    """Verify the exact lock, CAS and active bytes before any Skill is routed."""
    if mutation_journal_path(root).exists() or mutation_journal_path(root).is_symlink():
        raise AdaptiveError("INCOMPLETE_SKILL_MUTATION","Skill mutation recovery is required",3)
    blueprint=blueprint or load_blueprint(root,require_confirmed=True)
    policy=policy or load_policy(root)
    path=lock_path(root); required_capabilities=required_skill_coverage(blueprint)
    if not path.exists():
        if required_capabilities:
            raise AdaptiveError("MISSING_SKILL_LOCK","confirmed project capabilities require a verified dynamic Skill lock",3)
        return {"status":"NO_DYNAMIC_SKILLS_REQUIRED","covered_capabilities":[]},None,{}
    lock=load_lock(root,blueprint,policy,required=True)
    if lock["blueprint_sha256"]!=blueprint["confirmation"]["design_sha256"]:
        raise AdaptiveError("SKILL_BLUEPRINT_STALE","locked Skills target an older user design")
    if lock["policy_sha256"]!=canonical_sha256(policy):
        raise AdaptiveError("SKILL_POLICY_STALE","locked Skills target an older policy",3)
    captured={entry["id"]:verify_entry(root,entry) for entry in lock["skills"]}
    covered={capability for entry in lock["skills"] if entry["status"] in {"active","deprecated"} for capability in entry["matched_capabilities"]}
    missing=required_capabilities-covered; extra=covered-required_capabilities
    if missing or extra:
        raise AdaptiveError("SKILL_CAPABILITY_COVERAGE_INVALID",f"reviewed Skill coverage differs from blueprint: missing={sorted(missing)} extra={sorted(extra)}",3)
    expected_active=sorted(item["id"] for item in lock["skills"] if item["status"] in {"active","deprecated"})
    active_root=project_path(root,"skills"); observed=[]
    if active_root.exists():
        if active_root.is_symlink() or not active_root.is_dir():
            raise AdaptiveError("SKILL_INTEGRITY_ERROR","active Skill root is unsafe",3)
        children=bounded_active_skill_children(active_root,"SKILL_INTEGRITY_ERROR")
        if any(item.is_symlink() or not item.is_dir() for item in children):
            raise AdaptiveError("SKILL_INTEGRITY_ERROR","active Skill root has unexpected entries",3)
        observed=sorted(item.name for item in children)
    if observed!=expected_active:
        raise AdaptiveError("SKILL_INTEGRITY_ERROR",f"active Skill exact-set drifted: expected={expected_active} observed={observed}",3)
    require_published_mutation_authority(root,lock,_document_value(lifecycle_path(root)))
    return {"status":"verified","lock_sha256":lock["lock_sha256"],"active":expected_active,"covered_capabilities":sorted(covered)},lock,captured


def command_verify(root,_args):
    result,current,_captured=verify_activation(root)
    lifecycle=load_lifecycle(root)
    require_published_mutation_authority(root,current,_document_value(lifecycle_path(root)))
    print_json(result)
    return 0


def lifecycle_path(root):
    return project_path(root, "skill-lifecycle.json")


def mutation_journal_path(root):
    return project_path(root, "skill-mutation-journal.json")


def begin_state_journal(root, before_lock, before_lifecycle, affected_ids, post_bundles):
    path = mutation_journal_path(root)
    if path.exists() or path.is_symlink():
        raise AdaptiveError("INCOMPLETE_SKILL_MUTATION", "recover the prior Skill mutation before continuing", 3)
    payload = {
        "schema": "agent-skill-mutation-journal/v1", "before_lock": before_lock,
        "before_lock_existed": lock_path(root).exists(), "before_lifecycle": before_lifecycle,
        "before_lifecycle_existed": lifecycle_path(root).exists(), "affected_ids": sorted(affected_ids),
        "post_bundles": {key: post_bundles[key] for key in sorted(post_bundles)},
    }
    write_json(path, {**payload, "journal_sha256": canonical_sha256(payload)})


def finish_state_journal(root):
    path=mutation_journal_path(root)
    if path.exists(): durable_unlink(path)


def recover_state_journal_v1(root):
    path = mutation_journal_path(root)
    if not path.exists() and not path.is_symlink():
        return False
    if path.is_symlink() or not path.is_file():
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL", "Skill mutation journal must be one regular file", 3)
    value = skill_load_json(path, "Skill mutation journal")
    required = {"schema", "before_lock", "before_lock_existed", "before_lifecycle", "before_lifecycle_existed",
                "affected_ids", "post_bundles", "journal_sha256"}
    if set(value) != required or value.get("schema") != "agent-skill-mutation-journal/v1":
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL", "Skill mutation journal fields are invalid", 3)
    payload = {key: value[key] for key in value if key != "journal_sha256"}
    if value["journal_sha256"] != canonical_sha256(payload):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL", "Skill mutation journal digest drifted", 3)
    affected = value["affected_ids"]
    if (not isinstance(affected, list) or not affected or len(set(affected)) != len(affected) or
            any(not isinstance(item, str) or not ID_RE.fullmatch(item) for item in affected) or
            not isinstance(value["post_bundles"], dict) or set(value["post_bundles"]) != set(affected) or
            any(not isinstance(item, str) or not SHA256_RE.fullmatch(item) for item in value["post_bundles"].values())):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL", "Skill mutation journal identities are invalid", 3)
    before = value["before_lock"]
    if not isinstance(before, dict) or not isinstance(before.get("skills"), list):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL", "Skill mutation journal prior lock is invalid", 3)
    old_entries = {item.get("id"): item for item in before["skills"] if isinstance(item, dict)}
    for skill_id in affected:
        target = project_path(root, f"skills/{skill_id}")
        old = old_entries.get(skill_id)
        if old and old.get("status") in {"active", "deprecated"}:
            cas = project_path(root, f"skill-cas/{old.get('bundle_sha256', '')}")
            if not exact_bundle(cas, old.get("files", [])):
                raise AdaptiveError("SKILL_RECOVERY_FAILED", f"prior CAS bundle is unavailable for {skill_id}", 3)
            activate_from_bundle(cas, target, old.get("files", []))
        elif target.exists() or target.is_symlink():
            post_bundle = value["post_bundles"][skill_id]
            post_cas = project_path(root, f"skill-cas/{post_bundle}")
            if target.is_symlink() or not exact_bundle(post_cas, old.get("files", []) if old else _files_for_bundle(post_cas)) or not exact_bundle(target, _files_for_bundle(post_cas)):
                raise AdaptiveError("SKILL_RECOVERY_FAILED", f"unexpected active target blocks recovery for {skill_id}", 3)
            shutil.rmtree(target)
        parent = project_path(root, "skills")
        if parent.exists():
            for hidden in bounded_directory_children(parent,"SKILL_RECOVERY_FAILED","Skill recovery inventory",256):
                if re.fullmatch(r"\."+re.escape(skill_id)+r"\..+-.*",hidden.name) is None: continue
                if hidden.is_symlink() or not hidden.is_dir():
                    raise AdaptiveError("SKILL_RECOVERY_FAILED", f"unsafe recovery artifact for {skill_id}", 3)
                shutil.rmtree(hidden)
    if value["before_lock_existed"]:
        write_json(lock_path(root), before)
    elif lock_path(root).exists():
        durable_unlink(lock_path(root))
    if value["before_lifecycle_existed"]:
        write_json(lifecycle_path(root), value["before_lifecycle"])
    elif lifecycle_path(root).exists():
        durable_unlink(lifecycle_path(root))
    durable_unlink(path)
    return True


MUTATION_V2_FIELDS={"schema","journal_id","chain_sequence","previous_journal_sha256","phase","operation","action_sha256","gate","source","approval",
                    "pre_state","intended_post_state","prepared_at","authorization_result","published_at","journal_sha256"}
PRECHAIN_MUTATION_V2_FIELDS=MUTATION_V2_FIELDS-{"chain_sequence","previous_journal_sha256"}
MUTATION_OPERATIONS={"install","update","deprecate","retire","quarantine","rollback"}


def decision_placeholder(request):
    return {"schema":"agent-skill-decision-placeholder/v1","request_sha256":request["request_sha256"]}


def _active_state(lock,affected):
    entries={item["id"]:item for item in lock.get("skills",[]) if isinstance(item,dict)}; result=[]
    for skill_id in sorted(affected):
        entry=entries.get(skill_id); present=bool(entry and entry.get("status") in {"active","deprecated"})
        result.append({"id":skill_id,"present":present,
                       "bundle_sha256":entry.get("bundle_sha256") if present else None,
                       "files":entry.get("files") if present else []})
    return result


def mutation_state(root,lock,lifecycle,affected,*,lock_exists,lifecycle_exists):
    return {"lock":{"exists":bool(lock_exists),"value":lock if lock_exists else None},
            "lifecycle":{"exists":bool(lifecycle_exists),"value":lifecycle if lifecycle_exists else None},
            "active":_active_state(lock,affected)}


def intended_post_state(root,before_lock,post_lock,post_lifecycle,affected,cas_bundles,*,post_lifecycle_exists=True):
    histories=[]
    if before_lock.get("skills"):
        digest=before_lock.get("lock_sha256") or canonical_sha256(lock_payload(before_lock))
        histories.append({"relative_path":f"skill-lock-history/{digest}.json","value":before_lock,
                          "value_sha256":canonical_sha256(before_lock)})
    return {"lock":{"exists":True,"value":post_lock},"lifecycle":{"exists":bool(post_lifecycle_exists),"value":post_lifecycle if post_lifecycle_exists else None},
            "active":_active_state(post_lock,affected),
            "cas_bundles":sorted(cas_bundles,key=lambda item:item["bundle_sha256"]),
            "lock_history":histories}


def _journal_intent(value):
    return {key:value[key] for key in ("schema","chain_sequence","previous_journal_sha256","operation","action_sha256","gate","source","approval",
                                       "pre_state","intended_post_state","prepared_at")}


def _seal_journal(value):
    value={**value,"journal_sha256":None}; value["journal_sha256"]=canonical_sha256({k:v for k,v in value.items() if k!="journal_sha256"})
    return value


def _validate_state_shape(state,post=False):
    required={"lock","lifecycle","active"}|({"cas_bundles","lock_history"} if post else set())
    if not isinstance(state,dict) or set(state)!=required: raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation state fields are invalid",3)
    for key in ("lock","lifecycle"):
        document=state[key]
        if not isinstance(document,dict) or set(document)!={"exists","value"} or not isinstance(document["exists"],bool) or (document["exists"]!=(document["value"] is not None)):
            raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL",f"Skill mutation {key} state is invalid",3)
    active=state["active"]
    if (not isinstance(active,list) or not active or len(active)>64 or
            [item.get("id") for item in active]!=sorted(item.get("id") for item in active) or
            len({item.get("id") for item in active})!=len(active)):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation active set is invalid",3)
    for item in active:
        if (not isinstance(item,dict) or set(item)!={"id","present","bundle_sha256","files"}
                or not isinstance(item["id"],str) or ID_RE.fullmatch(item["id"]) is None or not isinstance(item["present"],bool)
                or (item["present"] and (not isinstance(item["bundle_sha256"],str) or SHA256_RE.fullmatch(item["bundle_sha256"]) is None or not isinstance(item["files"],list)))
                or (not item["present"] and (item["bundle_sha256"] is not None or item["files"]!=[]))):
            raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation active record is invalid",3)
    if post:
        if not isinstance(state["cas_bundles"],list) or len(state["cas_bundles"])>64 or not isinstance(state["lock_history"],list) or len(state["lock_history"])>1:
            raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation publication sets are invalid",3)
        for item in state["cas_bundles"]:
            if (not isinstance(item,dict) or set(item)!={"bundle_sha256","files","preexisting"}
                    or SHA256_RE.fullmatch(str(item.get("bundle_sha256",""))) is None or not isinstance(item.get("files"),list)
                    or not isinstance(item.get("preexisting"),bool)):
                raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation CAS record is invalid",3)
        for item in state["lock_history"]:
            if (not isinstance(item,dict) or set(item)!={"relative_path","value","value_sha256"}
                    or re.fullmatch(r"skill-lock-history/[0-9a-f]{64}\.json",str(item.get("relative_path",""))) is None
                    or item.get("value_sha256")!=canonical_sha256(item.get("value"))):
                raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation history record is invalid",3)



def _valid_utc_timestamp(value):
    if not isinstance(value,str): return False
    try: parsed=dt.datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError: return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _expected_transition_history(pre_lock):
    if not pre_lock.get("skills"): return []
    digest=pre_lock.get("lock_sha256") or canonical_sha256(lock_payload(pre_lock))
    return [{"relative_path":f"skill-lock-history/{digest}.json","value":pre_lock,"value_sha256":canonical_sha256(pre_lock)}]


def _validate_mutation_transition_authority(journal):
    """Prove that the exact post-state is the sole transition authorized by the consumed action."""
    pre=journal["pre_state"]; post=journal["intended_post_state"]
    _validate_active_projection(pre,"mutation pre-state"); _validate_active_projection(post,"mutation post-state")
    if not post["lock"]["exists"]:
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation requires an explicit post lock",3)
    post_lock=validate_lock(post["lock"]["value"])
    if pre["lock"]["exists"]:
        pre_lock=validate_lock(pre["lock"]["value"])
    elif journal["operation"]=="install":
        pre_lock=finalize_lock({"schema":"agent-skills-lock/v2","blueprint_sha256":post_lock["blueprint_sha256"],
                                "policy_sha256":post_lock["policy_sha256"],"skills":[],"lock_sha256":None})
    else:
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation requires an explicit predecessor lock",3)
    if post["lock_history"]!=_expected_transition_history(pre_lock):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation lock-history publication is not the exact predecessor",3)
    operation=journal["operation"]; before_by_id={item["id"]:item for item in pre_lock["skills"]}; after_by_id={item["id"]:item for item in post_lock["skills"]}
    if operation in {"install","update"}:
        changed=[item for item in post_lock["skills"] if isinstance(item,dict) and isinstance(item.get("decision"),dict)
                 and item["decision"].get("action_sha256")==journal["action_sha256"]]
        if len(changed)!=1:
            raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill selection transition lacks one exact approved entry",3)
        entry=changed[0]; decision=entry["decision"]; action=decision.get("action")
        if (not isinstance(action,dict) or canonical_sha256(action)!=journal["action_sha256"]
                or action.get("schema")!="agent-skill-selection-action/v4" or action.get("operation")!=operation
                or action.get("candidate")!=entry.get("id") or action.get("current_lock_sha256")!=pre_lock["lock_sha256"]
                or decision.get("gate")!=journal["gate"] or decision.get("source")!=journal["source"]
                or entry.get("status")!="active" or not _valid_utc_timestamp(entry.get("installed_at"))
                or entry.get("candidate_sha256")!=action.get("candidate_sha256")
                or entry.get("bundle_sha256")!=action.get("bundle_sha256")
                or entry.get("recommendation_sha256")!=action.get("recommendation_sha256")
                or entry.get("blueprint_sha256")!=action.get("blueprint_sha256")
                or entry.get("score")!=action.get("score") or entry.get("matched_capabilities")!=action.get("approved_capabilities")
                or canonical_sha256(entry.get("source_pin"))!=action.get("source_pin_sha256")
                or post_lock.get("blueprint_sha256")!=action.get("blueprint_sha256")
                or post_lock.get("policy_sha256")!=action.get("policy_sha256")):
            raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill selection post-state differs from its approved action",3)
        expected_ids=(set(before_by_id)-{entry["id"]})|{entry["id"]}
        if set(after_by_id)!=expected_ids or any(after_by_id[key]!=value for key,value in before_by_id.items() if key!=entry["id"]):
            raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill selection changed an unapproved lock entry",3)
        if pre["lifecycle"]!=post["lifecycle"]:
            raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill selection changed lifecycle state without approval",3)
        expected_active=_active_state(post_lock,[entry["id"]])
        if post["active"]!=expected_active:
            raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill selection active publication differs from its approved entry",3)
        expected_cas=[{"bundle_sha256":entry["bundle_sha256"],"files":entry["files"],"preexisting":post["cas_bundles"][0].get("preexisting") if len(post["cas_bundles"])==1 else None}]
        if len(post["cas_bundles"])!=1 or post["cas_bundles"]!=expected_cas:
            raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill selection CAS publication differs from its approved entry",3)
        return
    pre_lifecycle=pre["lifecycle"]["value"] if pre["lifecycle"]["exists"] else {"schema":"agent-skill-lifecycle/v1","events":[]}
    post_lifecycle=post["lifecycle"]["value"] if post["lifecycle"]["exists"] else None
    if (not isinstance(post_lifecycle,dict) or post_lifecycle.get("schema")!="agent-skill-lifecycle/v1"
            or post_lifecycle.get("events",[])[:-1]!=pre_lifecycle.get("events",[]) or len(post_lifecycle.get("events",[]))!=len(pre_lifecycle.get("events",[]))+1):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill lifecycle transition is not one append-only event",3)
    event=post_lifecycle["events"][-1]
    if isinstance(event,dict) and event.get("action")=="evolution-deprecate":
        fields={"action","skill","replacement","plan_sha256","selected_action_sha256","selected_action","approval_payload","recorded_at","decision"}
        selected=event.get("selected_action"); approval_payload=event.get("approval_payload"); decision=event.get("decision")
        selected_payload={key:selected[key] for key in selected if key!="action_sha256"} if isinstance(selected,dict) else None
        target=before_by_id.get(event.get("skill")); replacement=before_by_id.get(event.get("replacement"))
        expected=dict(before_by_id)
        if target is not None: expected[target["id"]]={**target,"status":"deprecated"}
        if (set(event)!=fields or operation!="deprecate" or not isinstance(selected_payload,dict)
                or selected.get("action_sha256")!=canonical_sha256(selected_payload)
                or selected.get("action_sha256")!=event.get("selected_action_sha256")
                or selected.get("target_type")!="skill" or selected.get("action")!="deprecate-after-replacement"
                or selected.get("target_id")!=event.get("skill") or selected.get("replacement")!=event.get("replacement")
                or selected.get("target_identity")!=skill_identity(target) or selected.get("replacement_identity")!=skill_identity(replacement)
                or not isinstance(approval_payload,dict) or canonical_sha256(approval_payload)!=journal["action_sha256"]
                or approval_payload.get("action_sha256")!=selected.get("action_sha256")
                or approval_payload.get("plan_sha256")!=event.get("plan_sha256")
                or approval_payload.get("prior_lock_sha256")!=pre_lock["lock_sha256"]
                or approval_payload.get("blueprint_sha256")!=pre_lock["blueprint_sha256"]
                or approval_payload.get("policy_sha256")!=pre_lock["policy_sha256"]
                or not _valid_utc_timestamp(event.get("recorded_at"))
                or not isinstance(decision,dict) or decision.get("gate")!=journal["gate"]
                or decision.get("source")!=journal["source"] or decision.get("action_sha256")!=journal["action_sha256"]
                or target is None or target.get("status")!="active" or replacement is None or replacement.get("status")!="active"
                or after_by_id!=expected or post["active"]!=_active_state(post_lock,[target["id"]])
                or post["cas_bundles"]!=[{"bundle_sha256":target["bundle_sha256"],"files":target["files"],"preexisting":True}]):
            raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","evolution Skill post-state differs from its exact approved action",3)
        return
    event_fields={"schema","action","prior_lock_sha256","blueprint_sha256","policy_sha256","skill","replacement","rollback_target","reason","action_sha256","decision","recorded_at"}
    decision=event.get("decision") if isinstance(event,dict) else None
    payload={key:event[key] for key in event_fields-{"action_sha256","decision","recorded_at"}} if isinstance(event,dict) and set(event)==event_fields else None
    if (payload is None or canonical_sha256(payload)!=journal["action_sha256"] or event.get("action_sha256")!=journal["action_sha256"]
            or payload.get("schema")!="agent-skill-lifecycle-action/v2" or payload.get("action")!=operation
            or payload.get("prior_lock_sha256")!=pre_lock["lock_sha256"] or payload.get("blueprint_sha256")!=pre_lock["blueprint_sha256"]
            or payload.get("policy_sha256")!=pre_lock["policy_sha256"] or not _valid_utc_timestamp(event.get("recorded_at"))
            or not isinstance(decision,dict) or decision.get("gate")!=journal["gate"] or decision.get("source")!=journal["source"]
            or decision.get("action_sha256")!=journal["action_sha256"]):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill lifecycle post-state differs from its approved action",3)
    target=(payload.get("rollback_target") if operation=="rollback" else payload.get("skill")); target_id=target.get("id") if isinstance(target,dict) else None
    if not isinstance(target_id,str): raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill lifecycle target identity is missing",3)
    expected=dict(before_by_id)
    if operation=="deprecate":
        prior=before_by_id.get(target_id)
        if prior is None or payload.get("skill")!=skill_identity(prior): raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","deprecation target differs from approved identity",3)
        expected[target_id]={**prior,"status":"deprecated"}
    elif operation in {"retire","quarantine"}:
        prior=before_by_id.get(target_id)
        if prior is None or payload.get("skill")!=skill_identity(prior): raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","retirement target differs from approved identity",3)
        expected.pop(target_id,None)
    elif operation=="rollback":
        restored=after_by_id.get(target_id)
        if (restored is None or restored.get("status")!="active" or skill_identity(restored)!=payload.get("rollback_target")
                or (target_id in before_by_id and payload.get("skill")!=skill_identity(before_by_id[target_id]))):
            raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","rollback post-state differs from approved retained identity",3)
        expected[target_id]=restored
    if after_by_id!=expected or post_lock["blueprint_sha256"]!=pre_lock["blueprint_sha256"] or post_lock["policy_sha256"]!=pre_lock["policy_sha256"]:
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill lifecycle changed unapproved lock state",3)
    if post["active"]!=_active_state(post_lock,[target_id]):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill lifecycle active publication differs from approved target",3)
    target_entry=before_by_id.get(target_id) if operation!="rollback" else after_by_id.get(target_id)
    if (target_entry is None or post["cas_bundles"]!=[{"bundle_sha256":target_entry["bundle_sha256"],"files":target_entry["files"],"preexisting":True}]):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill lifecycle CAS publication differs from approved target",3)


def _validate_provider_request(request,gate,action_sha256):
    fields={"schema","path","raw_base64","sha256","bytes","decision_id","authority","adapter_path",
            "adapter_sha256","binding","binding_sha256","record","request_sha256"}
    if not isinstance(request,dict) or set(request)!=fields or request.get("schema")!="agent-human-decision-consumption-request/v1":
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","prepared provider request fields are invalid",3)
    unsigned={key:request[key] for key in request if key!="request_sha256"}
    if request.get("request_sha256")!=canonical_sha256(unsigned):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","prepared provider request digest is invalid",3)
    try: raw=base64.b64decode(str(request.get("raw_base64","")).encode("ascii"),validate=True)
    except (ValueError,UnicodeError) as error: raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","prepared provider receipt bytes are invalid",3) from error
    if (base64.b64encode(raw).decode("ascii")!=request["raw_base64"] or not 0<len(raw)<=1024*1024
            or request.get("bytes")!=len(raw) or request.get("sha256")!=bytes_sha256(raw)):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","prepared provider receipt snapshot is invalid",3)
    record=request.get("record")
    record_fields={"schema","path","sha256","bytes","decision_id","authority","adapter_path","adapter_sha256"}
    if (not isinstance(record,dict) or set(record)!=record_fields or record.get("schema")!="agent-human-decision-receipt/v1"
            or any(record.get(key)!=request.get(key) for key in record_fields-{"schema"})
            or record.get("authority")!="provider-signed-user-message"
            or not isinstance(record.get("path"),str) or Path(record["path"]).is_absolute() or ".." in Path(record["path"]).parts
            or SHA256_RE.fullmatch(str(record.get("adapter_sha256",""))) is None):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","prepared provider record template is invalid",3)
    binding=request.get("binding"); binding_fields={"project_identity_sha256","task_generation_sha256","task_generation_id","gate","artifact_sha256","decision_id"}
    if (not isinstance(binding,dict) or set(binding)!=binding_fields or binding.get("gate")!=gate
            or binding.get("artifact_sha256")!=action_sha256 or binding.get("decision_id")!=request.get("decision_id")
            or not isinstance(binding.get("task_generation_id"),str) or not binding["task_generation_id"]
            or any(SHA256_RE.fullmatch(str(binding.get(key,""))) is None for key in ("project_identity_sha256","task_generation_sha256"))
            or request.get("binding_sha256")!=canonical_sha256(binding)):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","prepared provider binding is invalid",3)
    return record,binding


def _validate_authorization_result(journal,result):
    template,binding=_validate_provider_request(journal["approval"]["request"],journal["gate"],journal["action_sha256"])
    fields={"kind","status","sequence","binding_sha256","receipt_sha256","confirmed_via","recorded_at","record"}
    if (not isinstance(result,dict) or set(result)!=fields or result.get("kind")!="provider-human-decision"
            or result.get("status")!="consumed" or not isinstance(result.get("sequence"),int) or isinstance(result.get("sequence"),bool)
            or result["sequence"]<1 or result.get("binding_sha256")!=canonical_sha256(binding)
            or result.get("receipt_sha256")!=journal["approval"]["request"]["sha256"]
            or result.get("confirmed_via") not in {"consume-human-decision","status-human-decision"}
            or not _valid_utc_timestamp(result.get("recorded_at"))):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","consumed provider authorization result is invalid",3)
    record=result.get("record"); consumption=record.get("provider_consumption") if isinstance(record,dict) else None
    if (not isinstance(record,dict) or set(record)!=set(template)|{"provider_consumption"}
            or {key:record[key] for key in template}!=template or not isinstance(consumption,dict)
            or set(consumption)!=set(binding)|{"binding_sha256","sequence"}
            or any(consumption.get(key)!=value for key,value in binding.items())
            or consumption.get("binding_sha256")!=canonical_sha256(binding)
            or consumption.get("sequence")!=result["sequence"]):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","provider record and consumption sequence are not exact",3)


def validate_mutation_journal_v2(value):
    value=require_finite_json(value,"Skill mutation journal")
    schema_errors=validate_managed_schema(value,"skill-mutation-journal.schema.json","agent-skill-mutation-journal/v2")
    if schema_errors: raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","; ".join(schema_errors),3)
    if not isinstance(value,dict) or set(value)!=MUTATION_V2_FIELDS or value.get("schema")!="agent-skill-mutation-journal/v2":
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation v2 fields are invalid",3)
    if (value.get("phase") not in {"prepared","consumed","published"} or value.get("operation") not in MUTATION_OPERATIONS
            or SHA256_RE.fullmatch(str(value.get("action_sha256",""))) is None or SHA256_RE.fullmatch(str(value.get("journal_id",""))) is None
            or not isinstance(value.get("chain_sequence"),int) or isinstance(value.get("chain_sequence"),bool) or value["chain_sequence"]<1
            or (value.get("previous_journal_sha256")!="none" and SHA256_RE.fullmatch(str(value.get("previous_journal_sha256",""))) is None)
            or not isinstance(value.get("gate"),str) or not isinstance(value.get("source"),str)):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation v2 identity is invalid",3)
    unsigned={key:value[key] for key in value if key!="journal_sha256"}
    if value.get("journal_sha256")!=canonical_sha256(unsigned) or value.get("journal_id")!=canonical_sha256(_journal_intent(value)):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation v2 digest drifted",3)
    approval=value.get("approval")
    if not isinstance(approval,dict) or approval.get("kind") != "provider-human-decision":
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation approval is invalid",3)
    if approval["kind"]=="provider-human-decision":
        if set(approval)!={"kind","request"} or not isinstance(approval.get("request"),dict): raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","provider approval request is invalid",3)
    _validate_state_shape(value["pre_state"]); _validate_state_shape(value["intended_post_state"],post=True)
    _validate_mutation_transition_authority(value)
    if value["phase"]=="prepared" and (value["authorization_result"] is not None or value["published_at"] is not None):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","prepared mutation carries premature authorization",3)
    if value["phase"] in {"consumed","published"}:
        if not isinstance(value["authorization_result"],dict):
            raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","authorized mutation lacks durable result",3)
        _validate_authorization_result(value,value["authorization_result"])
    elif approval["kind"]=="provider-human-decision":
        _validate_provider_request(approval["request"],value["gate"],value["action_sha256"])
    if value["phase"]=="published" and not isinstance(value["published_at"],str):
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","published mutation lacks timestamp",3)
    return value


def load_mutation_journal_v2(root):
    return validate_mutation_journal_v2(load_json(mutation_journal_path(root),"Skill mutation journal",maximum=16*1024*1024))


def _prechain_journal_intent(value):
    return {key:value[key] for key in ("schema","operation","action_sha256","gate","source","approval",
                                       "pre_state","intended_post_state","prepared_at")}


def validate_prechain_mutation_journal_v2(value):
    """Validate the exact published v2 format that preceded chain fields."""
    value=require_finite_json(value,"pre-chain Skill mutation history")
    if (not isinstance(value,dict) or set(value)!=PRECHAIN_MUTATION_V2_FIELDS
            or value.get("schema")!="agent-skill-mutation-journal/v2" or value.get("phase")!="published"
            or value.get("operation") not in MUTATION_OPERATIONS
            or SHA256_RE.fullmatch(str(value.get("action_sha256",""))) is None
            or SHA256_RE.fullmatch(str(value.get("journal_id",""))) is None
            or not isinstance(value.get("gate"),str) or not isinstance(value.get("source"),str)
            or not _valid_utc_timestamp(value.get("prepared_at")) or not _valid_utc_timestamp(value.get("published_at"))):
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain mutation identity is invalid",3)
    unsigned={key:value[key] for key in value if key!="journal_sha256"}
    if (value.get("journal_sha256")!=canonical_sha256(unsigned)
            or value.get("journal_id")!=canonical_sha256(_prechain_journal_intent(value))):
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain mutation seal is invalid",3)
    approval=value.get("approval")
    if not isinstance(approval,dict) or set(approval)!={"kind","request"} or approval.get("kind")!="provider-human-decision":
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain mutation lacks provider approval",3)
    _validate_state_shape(value["pre_state"]); _validate_state_shape(value["intended_post_state"],post=True)
    if not isinstance(value.get("authorization_result"),dict):
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain mutation lacks consumed provider result",3)
    _validate_authorization_result(value,value["authorization_result"])
    return value


def _pre_state_from_materialized_post(journal):
    post=materialized_post_state(journal)
    return {key:post[key] for key in ("lock","lifecycle","active")}


def _transition_documents(state):
    return {key:state[key] for key in ("lock","lifecycle")}


def _validate_active_projection(state,label):
    lock=state["lock"]["value"] if state["lock"]["exists"] else {"skills":[]}
    ids=[item["id"] for item in state["active"]]
    if state["active"]!=_active_state(lock,ids):
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY",f"{label} active projection differs from its lock",3)


def _read_history_json(directory_fd,name,label):
    flags=os.O_RDONLY|os.O_NOFOLLOW; descriptor=os.open(name,flags,dir_fd=directory_fd)
    try:
        before=os.fstat(descriptor); expected_uid=os.geteuid() if hasattr(os,"geteuid") else before.st_uid
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=expected_uid
                or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>16*1024*1024):
            raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY",f"unsafe {label} file: {name}",3)
        chunks=[]; remaining=16*1024*1024+1
        while remaining>0:
            chunk=os.read(descriptor,min(65536,remaining))
            if not chunk: break
            chunks.append(chunk); remaining-=len(chunk)
        after=os.fstat(descriptor)
        if (remaining==0 or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)):
            raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY",f"{label} changed during snapshot: {name}",3)
        try: return strict_json_loads(b"".join(chunks).decode("utf-8"),label)
        except UnicodeDecodeError as error: raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY",f"{label} is not UTF-8: {name}",3) from error
    finally: os.close(descriptor)


def _ordered_prechain_history(root):
    directory=project_path(root,"skill-mutation-history")
    if load_mutation_head(root,required=False) is not None:
        raise AdaptiveError("PRECHAIN_SKILL_HISTORY_ALREADY_MIGRATED","a protected mutation head already exists",3)
    if directory.is_symlink() or not directory.is_dir():
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain mutation history root is missing or unsafe",3)
    directory_fd=_open_secure_directory(directory)
    try:
        names=sorted(bounded_directory_names(directory_fd,"INVALID_PRECHAIN_SKILL_HISTORY","pre-chain mutation inventory",4097))
        if not names or len(names)>4096 or any(re.fullmatch(r"[0-9a-f]{64}\.json",name) is None for name in names):
            raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain mutation inventory is invalid",3)
        values=[]
        for name in names:
            value=validate_prechain_mutation_journal_v2(_read_history_json(directory_fd,name,"pre-chain Skill mutation history"))
            if value["journal_id"]!=name[:-5]:
                raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain filename does not bind its journal",3)
            _validate_active_projection(value["pre_state"],"pre-chain pre-state")
            _validate_active_projection(_pre_state_from_materialized_post(value),"pre-chain post-state")
            observed=status_prepared_provider_human_decision(root,gate=value["gate"],artifact_sha256=value["action_sha256"],
                source=value["source"],prepared=value["approval"]["request"])
            result=value["authorization_result"]
            if (observed.get("status")!="consumed" or observed.get("authorization",{}).get("sequence")!=result["sequence"]
                    or observed.get("record")!=result["record"]):
                raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain provider approval status or record changed",3)
            values.append(value)
    finally: os.close(directory_fd)
    post_index={}
    for value in values:
        digest=canonical_sha256(_transition_documents(_pre_state_from_materialized_post(value)))
        if digest in post_index:
            raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain history has duplicate/forkable post-state",3)
        post_index[digest]=value
    roots=[value for value in values if canonical_sha256(_transition_documents(value["pre_state"])) not in post_index]
    if len(roots)!=1:
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain history has no unique genesis",3)
    root_state=roots[0]["pre_state"]
    genesis_lock=root_state["lock"]
    genesis_empty=(genesis_lock=={"exists":False,"value":None} or
        (genesis_lock.get("exists") is True and isinstance(genesis_lock.get("value"),dict) and genesis_lock["value"].get("skills")==[]))
    genesis_lifecycle=root_state["lifecycle"]
    lifecycle_empty=(genesis_lifecycle=={"exists":False,"value":None} or
        (genesis_lifecycle.get("exists") is True and genesis_lifecycle.get("value")=={"schema":"agent-skill-lifecycle/v1","events":[]}))
    if not genesis_empty or not lifecycle_empty or any(item.get("present") for item in root_state["active"]):
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain history cannot prove an untruncated empty genesis",3)
    ordered=[]; current=roots[0]; remaining={item["journal_id"]:item for item in values}
    while True:
        ordered.append(current); remaining.pop(current["journal_id"],None)
        post_digest=canonical_sha256(_transition_documents(_pre_state_from_materialized_post(current)))
        followers=[item for item in remaining.values() if canonical_sha256(_transition_documents(item["pre_state"]))==post_digest]
        if len(followers)>1:
            raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain history forks",3)
        if not followers: break
        current=followers[0]
    if remaining:
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain history is disconnected or truncated",3)
    final=_pre_state_from_materialized_post(ordered[-1])
    if not _state_documents_match(root,final) or any(not _active_matches(root,item) for item in final["active"]):
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","current Skill state does not match the pre-chain terminal state",3)
    lock=final["lock"]["value"]
    expected_active=sorted(item["id"] for item in lock.get("skills",[]) if item.get("status") in {"active","deprecated"})
    active_root=project_path(root,"skills"); observed=[]
    if active_root.exists():
        if active_root.is_symlink() or not active_root.is_dir(): raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","active Skill root is unsafe",3)
        children=bounded_active_skill_children(active_root,"INVALID_PRECHAIN_SKILL_HISTORY")
        if any(item.is_symlink() or not item.is_dir() for item in children): raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","active Skill inventory is unsafe",3)
        observed=sorted(item.name for item in children)
    if observed!=expected_active:
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","active Skill exact-set differs from terminal lock",3)
    for value in ordered:
        for bundle in value["intended_post_state"]["cas_bundles"]:
            if not exact_bundle(project_path(root,f"skill-cas/{bundle['bundle_sha256']}"),bundle["files"]):
                raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY","pre-chain CAS evidence is missing or drifted",3)
    return ordered


def _migration_head_value(journal):
    value={"schema":"agent-skill-mutation-head/v1","sequence":journal["chain_sequence"],"journal_id":journal["journal_id"],
           "journal_sha256":journal["journal_sha256"],"head_sha256":None}
    value["head_sha256"]=canonical_sha256({key:value[key] for key in value if key!="head_sha256"})
    return value


def _validate_migration_inventory(directory,mapping,old):
    if directory.is_symlink() or not directory.is_dir(): return False
    expected={f"{item['old_journal_id' if old else 'journal_id']}.json":item for item in mapping}
    directory_fd=_open_secure_directory(directory,exact_mode=0o700)
    try:
        if set(bounded_directory_names(directory_fd,"INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","migration inventory",len(expected)+1))!=set(expected): return False
        for name,item in expected.items():
            value=_read_history_json(directory_fd,name,"pre-chain migration inventory")
            value=validate_prechain_mutation_journal_v2(value) if old else validate_mutation_journal_v2(value)
            digest_key="old_journal_sha256" if old else "journal_sha256"
            id_key="old_journal_id" if old else "journal_id"
            if value["journal_id"]!=item[id_key] or value["journal_sha256"]!=item[digest_key]: return False
        return True
    finally: os.close(directory_fd)


def _finish_prechain_history_migration(root,archive,receipt):
    required={"schema","migration_sha256","records","source_count","authority_fabricated","status","staging","head"}
    mapping=receipt.get("records") if isinstance(receipt,dict) else None
    if (not isinstance(receipt,dict) or set(receipt)!=required or receipt.get("schema")!="agent-skill-prechain-migration/v1"
            or receipt.get("status")!="prepared" or receipt.get("authority_fabricated") is not False
            or not isinstance(mapping,list) or not mapping or receipt.get("source_count")!=len(mapping)
            or receipt.get("migration_sha256")!=canonical_sha256(mapping)
            or re.fullmatch(r"\.skill-mutation-history-migration-[0-9a-f]{16}",str(receipt.get("staging",""))) is None):
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","prepared migration cursor is invalid",3)
    project=project_path(root,""); history=project_path(root,"skill-mutation-history")
    staging=project/receipt["staging"]; archived=archive/"history"; expected_head=receipt["head"]
    if archived.exists() or archived.is_symlink():
        if not _validate_migration_inventory(archived,mapping,True):
            raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","archived pre-chain inventory drifted",3)
    else:
        if not _validate_migration_inventory(history,mapping,True):
            raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","live pre-chain inventory drifted before archival",3)
        parent_fd=_open_secure_directory(project); archive_fd=_open_secure_directory(archive,exact_mode=0o700)
        try: os.rename(history.name,"history",src_dir_fd=parent_fd,dst_dir_fd=archive_fd); os.fsync(archive_fd)
        finally: os.close(archive_fd); os.close(parent_fd)
        if os.environ.get("SELF_TEST_PRECHAIN_MIGRATION_CRASH")=="after-source-rename": raise SystemExit(90)
    if not history.exists() and not history.is_symlink():
        if not _validate_migration_inventory(staging,mapping,False):
            raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","staged chained inventory drifted",3)
        parent_fd=_open_secure_directory(project)
        try: os.rename(staging.name,history.name,src_dir_fd=parent_fd,dst_dir_fd=parent_fd); os.fsync(parent_fd)
        finally: os.close(parent_fd)
        if os.environ.get("SELF_TEST_PRECHAIN_MIGRATION_CRASH")=="after-target-rename": raise SystemExit(91)
    elif not _validate_migration_inventory(history,mapping,False):
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","published chained inventory drifted",3)
    if staging.exists() or staging.is_symlink():
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","unexpected duplicate migration staging remains",3)
    head=load_mutation_head(root,required=False)
    if head is None:
        if expected_head!=_migration_head_value({"chain_sequence":expected_head.get("sequence"),"journal_id":expected_head.get("journal_id"),"journal_sha256":expected_head.get("journal_sha256")}):
            raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","migration head intent is invalid",3)
        write_json(mutation_head_path(root),expected_head); os.chmod(mutation_head_path(root),0o600)
        if os.environ.get("SELF_TEST_PRECHAIN_MIGRATION_CRASH")=="after-head": raise SystemExit(92)
    elif head!=expected_head:
        raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","migration head collision",3)
    mutation_history_chain(root)
    final_receipt={**receipt,"status":"published"}; write_json(archive/"RECEIPT.json",final_receipt); os.chmod(archive/"RECEIPT.json",0o600)
    return {"status":"migrated","records":len(mapping),"migration_sha256":receipt["migration_sha256"],"head":expected_head}


def _pending_prechain_migration(root):
    base=project_path(root,"skill-mutation-prechain-v2")
    if not base.exists() and not base.is_symlink(): return None
    if base.is_symlink() or not base.is_dir(): raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","migration archive root is unsafe",3)
    pending=[]
    for item in bounded_directory_children(base,"INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","migration archive inventory",256):
        if item.is_symlink() or not item.is_dir() or SHA256_RE.fullmatch(item.name) is None:
            raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","migration archive entry is unsafe",3)
        receipt_path=item/"RECEIPT.json"
        if receipt_path.is_symlink() or not receipt_path.is_file(): raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","migration receipt is unsafe",3)
        receipt=skill_load_json(receipt_path,"pre-chain migration receipt")
        if receipt.get("status")=="prepared": pending.append((item,receipt))
    if len(pending)>1: raise AdaptiveError("INVALID_PRECHAIN_SKILL_HISTORY_MIGRATION","multiple prepared migrations exist",3)
    return pending[0] if pending else None


def migrate_prechain_mutation_history_v2(root):
    """Convert exact old v2 seals into a chained history while archiving originals."""
    if mutation_journal_path(root).exists() or mutation_journal_path(root).is_symlink():
        raise AdaptiveError("INCOMPLETE_SKILL_MUTATION","recover the active mutation before history migration",3)
    pending=_pending_prechain_migration(root)
    if pending is not None: return _finish_prechain_history_migration(root,*pending)
    if load_mutation_head(root,required=False) is not None:
        chain=mutation_history_chain(root)
        return {"status":"already-migrated","records":len(chain),"head":load_mutation_head(root,required=True)}
    ordered=_ordered_prechain_history(root); previous="none"; converted=[]; mapping=[]
    for sequence,old in enumerate(ordered,1):
        base={**old,"chain_sequence":sequence,"previous_journal_sha256":previous}; base.pop("journal_id",None); base.pop("journal_sha256",None)
        journal={**base,"journal_id":canonical_sha256(_journal_intent(base)),"journal_sha256":None}
        journal=validate_mutation_journal_v2(_seal_journal(journal)); converted.append(journal)
        mapping.append({"old_journal_id":old["journal_id"],"old_journal_sha256":old["journal_sha256"],
                        "journal_id":journal["journal_id"],"journal_sha256":journal["journal_sha256"]})
        previous=journal["journal_sha256"]
    migration_digest=canonical_sha256(mapping); project=project_path(root,"")
    staging_name=f".skill-mutation-history-migration-{migration_digest[:16]}"; staging=project/staging_name
    archive=project/f"skill-mutation-prechain-v2/{migration_digest}"
    if staging.exists() or staging.is_symlink() or archive.exists() or archive.is_symlink():
        raise AdaptiveError("PRECHAIN_SKILL_HISTORY_MIGRATION_COLLISION","history migration namespace already exists",3)
    staging.mkdir(mode=0o700); archive.mkdir(parents=True,mode=0o700)
    for journal in converted:
        target=staging/f"{journal['journal_id']}.json"; write_json(target,journal); os.chmod(target,0o600)
    staging_fd=_open_secure_directory(staging,exact_mode=0o700); os.fsync(staging_fd); os.close(staging_fd)
    head=_migration_head_value(converted[-1])
    receipt={"schema":"agent-skill-prechain-migration/v1","migration_sha256":migration_digest,"records":mapping,
             "source_count":len(ordered),"authority_fabricated":False,"status":"prepared","staging":staging_name,"head":head}
    write_json(archive/"RECEIPT.json",receipt); os.chmod(archive/"RECEIPT.json",0o600)
    if os.environ.get("SELF_TEST_PRECHAIN_MIGRATION_CRASH")=="after-stage": raise SystemExit(89)
    return _finish_prechain_history_migration(root,archive,receipt)


def prepare_mutation_journal(root,*,operation,action_sha256,gate,source,approval,pre_state,post_state):
    path=mutation_journal_path(root)
    if path.exists() or path.is_symlink(): raise AdaptiveError("INCOMPLETE_SKILL_MUTATION","recover the prior Skill mutation before continuing",3)
    require_published_mutation_authority(root,pre_state["lock"]["value"],pre_state["lifecycle"])
    chain=mutation_history_chain(root); prepared=utc_now(); base={"schema":"agent-skill-mutation-journal/v2","chain_sequence":len(chain)+1,"previous_journal_sha256":chain[-1]["journal_sha256"] if chain else "none","operation":operation,
        "action_sha256":action_sha256,"gate":gate,"source":source,"approval":approval,
        "pre_state":pre_state,"intended_post_state":post_state,"prepared_at":prepared}
    value={**base,"journal_id":canonical_sha256(base),"phase":"prepared","authorization_result":None,
           "published_at":None,"journal_sha256":None}
    value=_seal_journal(value); write_json(path,value); return value


def _write_journal_phase(root,value,phase,authorization_result,published_at=None):
    current=load_mutation_journal_v2(root)
    if current["journal_id"]!=value["journal_id"]: raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation journal identity changed",3)
    updated=validate_mutation_journal_v2(_seal_journal({**current,"phase":phase,"authorization_result":authorization_result,"published_at":published_at}))
    write_json(mutation_journal_path(root),updated); return updated


def _materialize(value,placeholder,replacement):
    if isinstance(value,dict):
        if value==placeholder: return replacement
        return {key:_materialize(item,placeholder,replacement) for key,item in value.items()}
    if isinstance(value,list): return [_materialize(item,placeholder,replacement) for item in value]
    return value


def materialized_post_state(journal):
    state=journal["intended_post_state"]
    if journal["approval"]["kind"]=="provider-human-decision":
        result=journal.get("authorization_result") or {}; record=result.get("record")
        if not isinstance(record,dict): raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","consumed provider record is unavailable",3)
        placeholder=decision_placeholder(journal["approval"]["request"]); state=_materialize(state,placeholder,record)
    lock_doc=state["lock"]
    state={**state,"lock":{**lock_doc,"value":finalize_lock(lock_doc["value"])}}
    return state




def mutation_head_path(root):
    return project_path(root,"skill-mutation-head.json")


def load_mutation_head(root,required=False):
    path=mutation_head_path(root)
    if not path.exists() and not path.is_symlink():
        if required: raise AdaptiveError("MISSING_SKILL_MUTATION_HEAD","Skill mutation history lacks its protected head",3)
        return None
    metadata=os.lstat(path); expected_uid=os.geteuid() if hasattr(os,"geteuid") else metadata.st_uid
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 or metadata.st_uid!=expected_uid or stat.S_IMODE(metadata.st_mode)!=0o600 or metadata.st_size>65536:
        raise AdaptiveError("INVALID_SKILL_MUTATION_HEAD","Skill mutation head is unsafe",3)
    value=skill_load_json(path,"Skill mutation head")
    fields={"schema","sequence","journal_id","journal_sha256","head_sha256"}
    unsigned={key:value.get(key) for key in fields if key!="head_sha256"} if isinstance(value,dict) else {}
    if (not isinstance(value,dict) or set(value)!=fields or value.get("schema")!="agent-skill-mutation-head/v1"
            or not isinstance(value.get("sequence"),int) or isinstance(value.get("sequence"),bool) or value["sequence"]<1
            or any(SHA256_RE.fullmatch(str(value.get(key,""))) is None for key in ("journal_id","journal_sha256","head_sha256"))
            or value["head_sha256"]!=canonical_sha256(unsigned)):
        raise AdaptiveError("INVALID_SKILL_MUTATION_HEAD","Skill mutation head binding is invalid",3)
    return value


def write_mutation_head(root,journal):
    value={"schema":"agent-skill-mutation-head/v1","sequence":journal["chain_sequence"],"journal_id":journal["journal_id"],"journal_sha256":journal["journal_sha256"],"head_sha256":None}
    value["head_sha256"]=canonical_sha256({key:value[key] for key in value if key!="head_sha256"})
    write_json(mutation_head_path(root),value); os.chmod(mutation_head_path(root),0o600)
    return value


def mutation_history_chain(root):
    directory=project_path(root,"skill-mutation-history"); head=load_mutation_head(root,required=False)
    if not directory.exists() and not directory.is_symlink():
        if head is not None: raise AdaptiveError("INVALID_SKILL_MUTATION_HEAD","Skill mutation head exists without history",3)
        return []
    if directory.is_symlink() or not directory.is_dir(): raise AdaptiveError("INVALID_SKILL_MUTATION_HISTORY","Skill mutation history root is unsafe",3)
    directory_fd=_open_secure_directory(directory)
    try:
        names=sorted(bounded_directory_names(directory_fd,"INVALID_SKILL_MUTATION_HISTORY","Skill mutation history inventory",4097))
        if len(names)>4096: raise AdaptiveError("INVALID_SKILL_MUTATION_HISTORY","too many Skill mutation history records",3)
        journals=[]
        for name in names:
            if re.fullmatch(r"[0-9a-f]{64}\.json",name) is None: raise AdaptiveError("INVALID_SKILL_MUTATION_HISTORY",f"unexpected Skill mutation history entry: {name}",3)
            journal=_mutation_history_value(directory_fd,name)
            if journal["journal_id"]!=name[:-5] or journal["phase"]!="published": raise AdaptiveError("INVALID_SKILL_MUTATION_HISTORY","Skill mutation history identity or phase is invalid",3)
            journals.append(journal)
    finally: os.close(directory_fd)
    journals.sort(key=lambda item:item["chain_sequence"])
    previous="none"
    for sequence,journal in enumerate(journals,1):
        if journal["chain_sequence"]!=sequence or journal["previous_journal_sha256"]!=previous: raise AdaptiveError("INVALID_SKILL_MUTATION_HISTORY","Skill mutation history chain is truncated, reordered, or forked",3)
        previous=journal["journal_sha256"]
    if not journals:
        if head is not None: raise AdaptiveError("INVALID_SKILL_MUTATION_HEAD","Skill mutation head exists without records",3)
    elif head is None or head["sequence"]!=len(journals) or head["journal_id"]!=journals[-1]["journal_id"] or head["journal_sha256"]!=journals[-1]["journal_sha256"]:
        raise AdaptiveError("INVALID_SKILL_MUTATION_HEAD","Skill mutation head does not bind the complete chain",3)
    return journals


def _mutation_history_value(directory_fd,name):
    flags=os.O_RDONLY|os.O_NOFOLLOW
    descriptor=os.open(name,flags,dir_fd=directory_fd)
    try:
        before=os.fstat(descriptor); expected_uid=os.geteuid() if hasattr(os,"geteuid") else before.st_uid
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=expected_uid
                or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>16*1024*1024):
            raise AdaptiveError("INVALID_SKILL_MUTATION_HISTORY",f"unsafe Skill mutation history file: {name}",3)
        chunks=[]; remaining=16*1024*1024+1
        while remaining>0:
            chunk=os.read(descriptor,min(65536,remaining))
            if not chunk: break
            chunks.append(chunk); remaining-=len(chunk)
        after=os.fstat(descriptor)
        if (remaining==0 or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)):
            raise AdaptiveError("INVALID_SKILL_MUTATION_HISTORY",f"Skill mutation history changed during snapshot: {name}",3)
        try: value=strict_json_loads(b"".join(chunks).decode("utf-8"),"Skill mutation history")
        except UnicodeDecodeError as error: raise AdaptiveError("INVALID_SKILL_MUTATION_HISTORY",f"Skill mutation history is not UTF-8: {name}",3) from error
        return validate_mutation_journal_v2(value)
    finally: os.close(descriptor)


def require_published_mutation_authority(root,expected_lock,expected_lifecycle):
    chain=mutation_history_chain(root)
    skills=expected_lock.get("skills",[]) if isinstance(expected_lock,dict) else []
    events=expected_lifecycle.get("value",{}).get("events",[]) if expected_lifecycle.get("exists") else []
    if not skills and not events: return chain[-1] if chain else None
    if not chain:
        raise AdaptiveError("MISSING_SKILL_MUTATION_AUTHORITY","nonempty Skill state lacks immutable mutation history",3)
    latest=chain[-1]
    expected={"lock":{"exists":True,"value":expected_lock},"lifecycle":expected_lifecycle}
    post=materialized_post_state(latest)
    if post["lock"]!=expected["lock"] or post["lifecycle"]!=expected["lifecycle"]:
        raise AdaptiveError("MISSING_SKILL_MUTATION_AUTHORITY","current Skill state does not match the protected mutation chain head",3)
    result=latest["authorization_result"]
    if latest["approval"]["kind"]=="provider-human-decision":
        if (result.get("kind")!="provider-human-decision" or result.get("status")!="consumed"
                or not isinstance(result.get("sequence"),int) or isinstance(result.get("sequence"),bool) or result["sequence"]<1
                or not isinstance(result.get("record"),dict)):
            raise AdaptiveError("INVALID_SKILL_MUTATION_HISTORY","chain-head Skill mutation lacks consumed provider authority",3)
        observed=status_prepared_provider_human_decision(root,gate=latest["gate"],
            artifact_sha256=latest["action_sha256"],source=latest["source"],prepared=latest["approval"]["request"])
        if (observed.get("status")!="consumed" or observed.get("authorization",{}).get("sequence")!=result["sequence"]
                or observed.get("record")!=result["record"]):
            raise AdaptiveError("INVALID_SKILL_MUTATION_HISTORY","chain-head provider approval status or sequence changed",3)
    return latest



def _document_value(path):
    if not path.exists() and not path.is_symlink(): return {"exists":False,"value":None}
    if path.is_symlink() or not path.is_file(): raise AdaptiveError("SKILL_PUBLICATION_DRIFT",f"publication document is unsafe: {path}",3)
    return {"exists":True,"value":skill_load_json(path,"Skill publication document")}


def _state_documents_match(root,state):
    return _document_value(lock_path(root))==state["lock"] and _document_value(lifecycle_path(root))==state["lifecycle"]


def _active_matches(root,item):
    path=project_path(root,f"skills/{item['id']}")
    if not path.exists() and not path.is_symlink(): return not item["present"]
    return bool(item["present"] and not path.is_symlink() and exact_bundle(path,item["files"]))


def _verify_pre_state(root,state):
    if not _state_documents_match(root,state) or any(not _active_matches(root,item) for item in state["active"]):
        raise AdaptiveError("SKILL_PRE_STATE_DRIFT","Skill mutation pre-state changed before authorization",3)


def authorize_prepared_mutation(root,journal):
    _verify_pre_state(root,journal["pre_state"])
    approval=journal["approval"]
    observed=consume_prepared_provider_human_decision(root,gate=journal["gate"],artifact_sha256=journal["action_sha256"],
        source=journal["source"],prepared=approval["request"])
    if observed.get("status")!="consumed": raise AdaptiveError("HUMAN_DECISION_STATUS_UNKNOWN","provider approval was not consumed",3)
    result={**observed["authorization"],"record":observed["record"]}
    return _write_journal_phase(root,journal,"consumed",result)


def _recover_hidden_active(root,item,pre_item):
    parent=project_path(root,"skills"); target=parent/item["id"]
    if not parent.exists(): return
    children=bounded_directory_children(parent,"SKILL_PUBLICATION_DRIFT","Skill publication inventory",256)
    old_prefix=f".{item['id']}.old-"; active_prefix=f".{item['id']}-active."
    remnants=[path for path in children if path.name.startswith(old_prefix) or path.name.startswith(active_prefix)]
    for remnant in remnants:
        if remnant.is_symlink() or not remnant.is_dir(): raise AdaptiveError("SKILL_PUBLICATION_DRIFT",f"unsafe Skill publication remnant: {remnant}",3)
        matches=any(candidate and candidate["present"] and exact_bundle(remnant,candidate["files"]) for candidate in (pre_item,item))
        if not matches: raise AdaptiveError("SKILL_PUBLICATION_DRIFT",f"unknown Skill publication remnant: {remnant}",3)
    old=[path for path in remnants if ".old-" in path.name]
    if not target.exists() and len(old)==1: os.replace(old[0],target)
    elif not target.exists() and len(old)>1: raise AdaptiveError("SKILL_PUBLICATION_DRIFT","multiple predecessor Skill remnants",3)
    for remnant in remnants:
        if remnant.exists(): shutil.rmtree(remnant)


def _tombstone_manifest(path,files,token):
    body={"schema":"agent-skill-tree-tombstone/v1","target":path.name,"token":token,"files":files}
    return {**body,"manifest_sha256":canonical_sha256(body)}


def _validate_tombstone_manifest(value,path,files,token):
    expected=_tombstone_manifest(path,files,token)
    if value!=expected:
        raise AdaptiveError("SKILL_RECOVERY_FAILED","Skill tombstone manifest differs from the durable deletion intent",3)
    return expected


def _delete_tombstone_contents(tombstone,files,label):
    """Delete only still-present manifest files; partial prior deletion is valid."""
    expected={item["path"]:item for item in files}
    if sorted(expected)!=["LICENSE.txt","SKILL.md"]:
        raise AdaptiveError("SKILL_RECOVERY_FAILED",f"{label} tombstone manifest is invalid",3)
    directory_fd=_open_secure_directory(tombstone,exact_mode=0o700)
    try:
        names=sorted(bounded_directory_names(directory_fd,"SKILL_RECOVERY_FAILED",f"{label} tombstone inventory",len(expected)+1))
        if any(name not in expected for name in names):
            raise AdaptiveError("SKILL_RECOVERY_FAILED",f"{label} tombstone contains unrelated bytes",3)
        expected_uid=os.geteuid() if hasattr(os,"geteuid") else os.fstat(directory_fd).st_uid
        removed=0
        for name in sorted(names):
            record=expected[name]
            descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory_fd)
            try:
                opened=os.fstat(descriptor)
                if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1 or opened.st_uid!=expected_uid
                        or stat.S_IMODE(opened.st_mode)!=0o600 or opened.st_size!=record["bytes"]):
                    raise AdaptiveError("SKILL_RECOVERY_FAILED",f"{label} tombstone file is unsafe",3)
                chunks=[]; remaining=record["bytes"]+1
                while remaining:
                    chunk=os.read(descriptor,min(65536,remaining))
                    if not chunk: break
                    chunks.append(chunk); remaining-=len(chunk)
                raw=b"".join(chunks); after=os.fstat(descriptor)
                linked=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
                if ((opened.st_dev,opened.st_ino,opened.st_mode,opened.st_size)!=(after.st_dev,after.st_ino,after.st_mode,after.st_size)
                        or (linked.st_dev,linked.st_ino)!=(opened.st_dev,opened.st_ino)
                        or len(raw)!=record["bytes"] or bytes_sha256(raw)!=record["sha256"]):
                    raise AdaptiveError("SKILL_RECOVERY_FAILED",f"{label} tombstone bytes drifted",3)
            finally: os.close(descriptor)
            os.unlink(name,dir_fd=directory_fd); os.fsync(directory_fd); removed+=1
            if removed==1 and os.environ.get("SELF_TEST_SKILL_TOMBSTONE_CRASH")=="after-first-delete":
                raise SystemExit(95)
    finally: os.close(directory_fd)


def tombstone_remove_exact_tree(path,files,token,label):
    path=Path(path); tombstone=path.parent/f".{path.name}.mutation-tombstone-{token[:16]}"
    manifest_path=path.parent/f".{path.name}.mutation-tombstone-{token[:16]}.json"
    intended=_tombstone_manifest(path,files,token)
    if manifest_path.exists() or manifest_path.is_symlink():
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise AdaptiveError("SKILL_RECOVERY_FAILED",f"{label} tombstone manifest is unsafe",3)
        _validate_tombstone_manifest(skill_load_json(manifest_path,"Skill tombstone manifest"),path,files,token)
    else:
        write_json(manifest_path,intended); os.chmod(manifest_path,0o600)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not exact_bundle(path,files): raise AdaptiveError("SKILL_PUBLICATION_DRIFT",f"{label} drifted before tombstone",3)
        if tombstone.exists() or tombstone.is_symlink(): raise AdaptiveError("SKILL_RECOVERY_FAILED",f"{label} has conflicting tombstone",3)
        parent_fd=_open_secure_directory(path.parent)
        try:
            os.rename(path.name,tombstone.name,src_dir_fd=parent_fd,dst_dir_fd=parent_fd); os.fsync(parent_fd)
        finally: os.close(parent_fd)
        if os.environ.get("SELF_TEST_SKILL_TOMBSTONE_CRASH")=="after-rename": raise SystemExit(94)
    if tombstone.exists() or tombstone.is_symlink():
        if tombstone.is_symlink() or not tombstone.is_dir(): raise AdaptiveError("SKILL_RECOVERY_FAILED",f"{label} tombstone is unsafe",3)
        _delete_tombstone_contents(tombstone,files,label)
        parent_fd=_open_secure_directory(path.parent)
        try: os.rmdir(tombstone.name,dir_fd=parent_fd); os.fsync(parent_fd)
        finally: os.close(parent_fd)
    durable_unlink(manifest_path)


def publish_intended_state(root,journal):
    if journal["phase"] not in {"consumed","published"}: raise AdaptiveError("SKILL_MUTATION_NOT_AUTHORIZED","Skill publication lacks durable authorization",3)
    post=materialized_post_state(journal); pre=journal["pre_state"]
    for item in post["cas_bundles"]:
        if not exact_bundle(project_path(root,f"skill-cas/{item['bundle_sha256']}"),item["files"]):
            raise AdaptiveError("SKILL_RECOVERY_FAILED","required immutable Skill CAS bundle is unavailable",3)
    pre_active={item["id"]:item for item in pre["active"]}
    for item in post["active"]:
        _recover_hidden_active(root,item,pre_active.get(item["id"])); target=project_path(root,f"skills/{item['id']}")
        current_pre=_active_matches(root,pre_active[item["id"]]); current_post=_active_matches(root,item)
        if not current_pre and not current_post: raise AdaptiveError("SKILL_PUBLICATION_DRIFT",f"active Skill state matches neither pre nor post: {item['id']}",3)
        if item["present"] and not current_post:
            activate_from_bundle(project_path(root,f"skill-cas/{item['bundle_sha256']}"),target,item["files"])
        elif not item["present"]:
            if target.exists() and (target.is_symlink() or not exact_bundle(target,pre_active[item["id"]]["files"])): raise AdaptiveError("SKILL_PUBLICATION_DRIFT","retirement target drifted",3)
            tombstone_remove_exact_tree(target,pre_active[item["id"]]["files"],journal["journal_id"],"retirement target")
    for history in post["lock_history"]:
        path=project_path(root,history["relative_path"])
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file() or skill_load_json(path,"Skill lock history")!=history["value"]:
                raise AdaptiveError("SKILL_LOCK_HISTORY_COLLISION","Skill lock history collision blocks publication",3)
        else: write_json(path,history["value"])
    for name,path in (("lock",lock_path(root)),("lifecycle",lifecycle_path(root))):
        current=_document_value(path)
        if current!=pre[name] and current!=post[name]: raise AdaptiveError("SKILL_PUBLICATION_DRIFT",f"{name} matches neither pre nor post",3)
        if current!=post[name]:
            if post[name]["exists"]: write_json(path,post[name]["value"])
            elif current["exists"]: durable_unlink(path)
    if not _state_documents_match(root,post) or any(not _active_matches(root,item) for item in post["active"]):
        raise AdaptiveError("SKILL_RECOVERY_FAILED","complete intended Skill post-state did not materialize",3)
    if journal["phase"]!="published": journal=_write_journal_phase(root,journal,"published",journal["authorization_result"],utc_now())
    history=project_path(root,f"skill-mutation-history/{journal['journal_id']}.json"); ensure_real_directory(history.parent)
    if history.exists() or history.is_symlink():
        if history.is_symlink() or not history.is_file() or skill_load_json(history,"Skill mutation history")!=journal: raise AdaptiveError("SKILL_MUTATION_HISTORY_COLLISION","Skill mutation history collision",3)
    else:
        write_json(history,journal); os.chmod(history,0o600)
    head=load_mutation_head(root,required=False)
    if head is None:
        if journal["chain_sequence"]!=1 or journal["previous_journal_sha256"]!="none": raise AdaptiveError("INVALID_SKILL_MUTATION_HEAD","non-genesis mutation lacks prior head",3)
        write_mutation_head(root,journal)
    elif head["sequence"]==journal["chain_sequence"] and head["journal_id"]==journal["journal_id"] and head["journal_sha256"]==journal["journal_sha256"]:
        pass
    elif head["sequence"]==journal["chain_sequence"]-1 and head["journal_sha256"]==journal["previous_journal_sha256"]:
        write_mutation_head(root,journal)
    else: raise AdaptiveError("INVALID_SKILL_MUTATION_HEAD","Skill mutation head cannot advance monotonically",3)
    if mutation_journal_path(root).exists(): durable_unlink(mutation_journal_path(root))
    mutation_history_chain(root); return journal



def _discard_private_skill_materialization(root,journal):
    path=project_path(root,f"skill-cas/.mutation-staging-{journal['journal_id']}")
    if not path.exists() and not path.is_symlink(): return
    if path.is_symlink() or not path.is_dir(): raise AdaptiveError("SKILL_RECOVERY_FAILED","private Skill materialization is unsafe",3)
    files=[]
    for bundle in journal["intended_post_state"]["cas_bundles"]: files.extend(bundle["files"])
    expected={item["path"]:item for item in files}; directory_fd=_open_secure_directory(path,exact_mode=0o700)
    try:
        names=bounded_directory_names(directory_fd,"SKILL_RECOVERY_FAILED","private Skill materialization inventory",len(expected)+1)
        if any(name not in expected for name in names): raise AdaptiveError("SKILL_RECOVERY_FAILED","private Skill materialization contains unrelated bytes",3)
        uid=os.geteuid() if hasattr(os,"geteuid") else os.fstat(directory_fd).st_uid
        for name in names:
            metadata=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=uid or metadata.st_nlink!=1 or stat.S_IMODE(metadata.st_mode)!=0o600:
                raise AdaptiveError("SKILL_RECOVERY_FAILED","private Skill materialization entry is unsafe",3)
            os.unlink(name,dir_fd=directory_fd); os.fsync(directory_fd)
    finally: os.close(directory_fd)
    parent_fd=_open_secure_directory(path.parent)
    try: os.rmdir(path.name,dir_fd=parent_fd); os.fsync(parent_fd)
    finally: os.close(parent_fd)


def _discard_unconsumed_mutation(root,journal):
    _verify_pre_state(root,journal["pre_state"])
    _discard_private_skill_materialization(root,journal)
    for item in journal["intended_post_state"]["cas_bundles"]:
        if item["preexisting"]: continue
        path=project_path(root,f"skill-cas/{item['bundle_sha256']}")
        if path.is_symlink() or (path.exists() and not exact_bundle(path,item["files"])):
            raise AdaptiveError("SKILL_RECOVERY_FAILED","unconsumed Skill CAS orphan drifted",3)
        tombstone_remove_exact_tree(path,item["files"],journal["journal_id"],"unconsumed CAS bundle")
    durable_unlink(mutation_journal_path(root))


def recover_state_journal(root):
    path=mutation_journal_path(root)
    if not path.exists() and not path.is_symlink(): return False
    if path.is_symlink() or not path.is_file(): raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL","Skill mutation journal must be one regular file",3)
    probe=require_finite_json(load_json(path,"Skill mutation journal",maximum=16*1024*1024),"Skill mutation journal")
    if isinstance(probe,dict) and probe.get("schema")=="agent-skill-mutation-journal/v1": return recover_state_journal_v1(root)
    journal=load_mutation_journal_v2(root)
    if journal["phase"]=="prepared":
        observed=status_prepared_provider_human_decision(root,gate=journal["gate"],artifact_sha256=journal["action_sha256"],
            source=journal["source"],prepared=journal["approval"]["request"])
        if observed.get("status")=="unconsumed":
            _discard_unconsumed_mutation(root,journal); return True
        if observed.get("status")!="consumed": raise AdaptiveError("HUMAN_DECISION_STATUS_UNKNOWN","prepared Skill approval status is unresolved",3)
        result={**observed["authorization"],"record":observed["record"]}; journal=_write_journal_phase(root,journal,"consumed",result)
    if journal["approval"]["kind"]=="provider-human-decision" and journal["phase"]=="consumed":
        observed=status_prepared_provider_human_decision(root,gate=journal["gate"],artifact_sha256=journal["action_sha256"],
            source=journal["source"],prepared=journal["approval"]["request"])
        prior=journal["authorization_result"]
        if observed.get("status")!="consumed" or observed.get("authorization",{}).get("sequence")!=prior.get("sequence") or observed.get("record")!=prior.get("record"):
            raise AdaptiveError("HUMAN_DECISION_STATUS_UNKNOWN","consumed Skill approval status or sequence changed",3)
    publish_intended_state(root,journal); return True



def _files_for_bundle(path):
    records = []
    if path.is_symlink() or not path.is_dir():
        return records
    for name in ("LICENSE.txt", "SKILL.md"):
        item = path / name
        if not item.is_file() or item.is_symlink():
            return []
        try: raw=boundedio.read_bytes(item,maximum=16*1024*1024,label="Skill bundle file")
        except RuntimeError: return []
        records.append({"path": name, "bytes": len(raw), "sha256": bytes_sha256(raw), "mode": "100600"})
    return records


def load_lifecycle(root):
    path = lifecycle_path(root)
    value = skill_load_json(path, "Skill lifecycle") if path.exists() else {"schema": "agent-skill-lifecycle/v1", "events": []}
    if not isinstance(value, dict) or set(value) != {"schema", "events"} or value.get("schema") != "agent-skill-lifecycle/v1" or not isinstance(value.get("events"), list) or len(value["events"]) > 4096:
        raise AdaptiveError("INVALID_SKILL_LIFECYCLE", "Skill lifecycle ledger is invalid", 3)
    for event in value["events"]:
        decision = event.get("decision") if isinstance(event, dict) else None
        if not isinstance(decision, dict) or set(decision) != {"gate", "source", "action_sha256", "receipt", "assurance"} or not SHA256_RE.fullmatch(str(decision.get("action_sha256", ""))):
            raise AdaptiveError("INVALID_SKILL_LIFECYCLE", "lifecycle decision binding is invalid", 3)
        if decision["assurance"] == "provider-authenticated-emergency-containment":
            if not decision["source"].startswith("security:") or not decision["source"][9:].strip() or event.get("action") != "quarantine":
                raise AdaptiveError("INVALID_SKILL_LIFECYCLE", "lifecycle emergency assurance is invalid", 3)
        elif decision["assurance"] != "human-decision-receipt":
            raise AdaptiveError("INVALID_SKILL_LIFECYCLE", "lifecycle decision assurance is invalid", 3)
        # Emergency containment changes urgency, never authority: every stored
        # lifecycle event remains bound to a provider-verifiable decision.
        verify_human_decision(root, gate=decision["gate"], artifact_sha256=decision["action_sha256"], source=decision["source"], record=decision["receipt"])
    return value


def skill_identity(entry):
    return None if entry is None else {"id": entry["id"], "candidate_sha256": entry["candidate_sha256"], "bundle_sha256": entry["bundle_sha256"]}


def lifecycle_action_payload(action, lock, blueprint, policy, entry, *, replacement=None, reason=None, rollback_entry=None):
    return {
        "schema": "agent-skill-lifecycle-action/v2", "action": action,
        "prior_lock_sha256": lock["lock_sha256"], "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
        "policy_sha256": canonical_sha256(policy), "skill": skill_identity(entry),
        "replacement": skill_identity(replacement), "rollback_target": skill_identity(rollback_entry),
        "reason": reason,
    }


def require_action_approval(root,args,payload,code,gate,*,allow_security=False):
    expected=canonical_sha256(payload)
    if args.approve_digest!=expected: raise AdaptiveError(code,f"approve the exact lifecycle action digest: {expected}")
    emergency=allow_security and isinstance(args.source,str) and args.source.startswith("security:") and bool(args.source[9:].strip())
    source=args.source if emergency else explicit_user_source(args.source)
    request=prepare_provider_human_decision(root,gate=gate,artifact_sha256=expected,source=source,receipt=args.human_decision_receipt)
    decision={"gate":gate,"source":source,"action_sha256":expected,"receipt":decision_placeholder(request),
              "assurance":"provider-authenticated-emergency-containment" if emergency else "human-decision-receipt"}
    approval={"kind":"provider-human-decision","request":request}
    return expected,decision,approval


def resolve_rollback_entry(root,blueprint,policy,skill_id,bundle_digest):
    history=project_path(root,"skill-lock-history")
    identities={}
    if history.exists():
        if history.is_symlink() or not history.is_dir():
            raise AdaptiveError("INVALID_SKILL_HISTORY", "Skill lock history root is unsafe", 3)
        candidates=bounded_directory_children(history,"INVALID_SKILL_HISTORY","Skill lock history inventory",4096)
        for path in sorted((item for item in candidates if item.suffix==".json"),key=lambda item:os.fsencode(item.name)):
            if path.is_symlink() or not path.is_file(): raise AdaptiveError("INVALID_SKILL_HISTORY","Skill lock history contains an unsafe entry",3)
            snapshot = validate_lock(skill_load_json(path, "Skill lock snapshot"))
            if snapshot["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"] or snapshot["policy_sha256"] != canonical_sha256(policy):
                continue
            entry = next((item for item in snapshot["skills"] if item.get("id") == skill_id and item.get("bundle_sha256") == bundle_digest), None)
            if entry:
                verify_entry(root, {**entry, "status": "retired"})
                identities[(entry["candidate_sha256"], entry["bundle_sha256"])] = entry
    if len(identities) != 1:
        raise AdaptiveError("ROLLBACK_SNAPSHOT_NOT_UNIQUE", "rollback requires one retained approved Skill identity")
    return next(iter(identities.values()))


def command_plan_lifecycle(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    policy = load_policy(root)
    lock = load_lock(root, blueprint, policy, required=True)
    entry = next((item for item in lock["skills"] if item["id"] == args.id), None)
    if args.action == "rollback":
        if not args.bundle_digest or not SHA256_RE.fullmatch(args.bundle_digest):
            raise AdaptiveError("INVALID_BUNDLE_DIGEST", "rollback planning requires --bundle-digest SHA-256")
        rollback_entry = resolve_rollback_entry(root, blueprint, policy, args.id, args.bundle_digest)
        payload = lifecycle_action_payload("rollback", lock, blueprint, policy, entry, rollback_entry=rollback_entry)
    else:
        if entry is None:
            raise AdaptiveError("SKILL_NOT_ACTIVE", f"Skill {args.id!r} is not locked")
        if not args.reason or len(args.reason) > 512:
            raise AdaptiveError("INVALID_LIFECYCLE_REASON", "lifecycle planning requires a 1-512 character --reason")
        if args.action in {"deprecate", "retire"} and not args.replacement:
            raise AdaptiveError("REPLACEMENT_REQUIRED", f"{args.action} planning requires --replacement")
        replacement = next((item for item in lock["skills"] if item["id"] == args.replacement and item["status"] == "active"), None) if args.replacement else None
        if args.replacement and replacement is None:
            raise AdaptiveError("REPLACEMENT_REQUIRED", "planned replacement must be an active locked Skill")
        payload = lifecycle_action_payload(args.action, lock, blueprint, policy, entry,
                                           replacement=replacement, reason=args.reason)
    print_json({"schema": "agent-skill-lifecycle-approval/v2", "payload": payload,
                "approval_sha256": canonical_sha256(payload), "mutation": False})
    return 0


def command_deprecate(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    policy = load_policy(root)
    lock = load_lock(root, blueprint, policy, required=True)
    if lock["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"] or lock["policy_sha256"] != canonical_sha256(policy):
        raise AdaptiveError("STALE_SKILL_LOCK", "deprecation requires the current user design and policy")
    if not args.source.startswith("user:"):
        raise AdaptiveError("DEPRECATION_APPROVAL_REQUIRED", "deprecation requires an explicit user:<decision> source")
    entry = next((item for item in lock["skills"] if item["id"] == args.id and item["status"] == "active"), None)
    replacement = next((item for item in lock["skills"] if item["id"] == args.replacement and item["status"] == "active"), None)
    if entry is None:
        raise AdaptiveError("SKILL_NOT_ACTIVE", f"Skill {args.id!r} is not active")
    if replacement is None or replacement["id"] == entry["id"]:
        raise AdaptiveError("REPLACEMENT_REQUIRED", "deprecation requires a different active replacement")
    if not set(entry["matched_capabilities"]).issubset(set(replacement["matched_capabilities"])):
        raise AdaptiveError("REPLACEMENT_MISMATCH", "replacement does not cover every locked requirement")
    payload = lifecycle_action_payload("deprecate", lock, blueprint, policy, entry, replacement=replacement, reason=args.reason)
    approval_digest,decision,approval=require_action_approval(root,args,payload,"DEPRECATION_APPROVAL_REQUIRED","adaptive-skill-deprecate")
    prior_lifecycle=load_lifecycle(root); lifecycle_exists=lifecycle_path(root).exists()
    lifecycle={"schema":prior_lifecycle["schema"],"events":[*prior_lifecycle["events"],
        {**payload,"action_sha256":approval_digest,"decision":decision,"recorded_at":utc_now()}]}
    skills=[]
    for item in lock["skills"]:
        updated=dict(item)
        if item["id"]==args.id: updated["status"]="deprecated"
        skills.append(updated)
    post_lock=finalize_lock({**lock,"skills":skills,"lock_sha256":None})
    pre=mutation_state(root,lock,prior_lifecycle,[args.id],lock_exists=True,lifecycle_exists=lifecycle_exists)
    post=intended_post_state(root,lock,post_lock,lifecycle,[args.id],
        [{"bundle_sha256":entry["bundle_sha256"],"files":entry["files"],"preexisting":True}])
    journal=prepare_mutation_journal(root,operation="deprecate",action_sha256=approval_digest,gate=decision["gate"],
        source=decision["source"],approval=approval,pre_state=pre,post_state=post)
    journal=authorize_prepared_mutation(root,journal); publish_intended_state(root,journal)
    current=materialized_post_state(journal)["lock"]["value"]
    print_json({"status": "deprecated", "id": args.id, "replacement": args.replacement, "lock_sha256": current["lock_sha256"]})
    return 0


def command_retire(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    policy = load_policy(root)
    lock = load_lock(root, blueprint, policy, required=True)
    entry = next((item for item in lock["skills"] if item["id"] == args.id), None)
    if not entry or entry["status"] not in {"active", "deprecated"}:
        raise AdaptiveError("SKILL_NOT_ACTIVE", f"Skill {args.id!r} is not active")
    if not isinstance(args.reason, str) or not args.reason.strip() or len(args.reason) > 512:
        raise AdaptiveError("INVALID_RETIREMENT_REASON", "retirement reason must be 1-512 characters")
    replacement = next((item for item in lock["skills"] if item["id"] == args.replacement and item["status"] == "active"), None) if args.replacement else None
    if args.quarantine:
        if not args.source.startswith(("user:", "security:")):
            raise AdaptiveError("RETIREMENT_APPROVAL_REQUIRED", "quarantine source must be user:<decision> or security:<incident>")
    else:
        if not args.source.startswith("user:"):
            raise AdaptiveError("RETIREMENT_APPROVAL_REQUIRED", "retirement requires an explicit user:<decision> source")
        if lock["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"] or lock["policy_sha256"] != canonical_sha256(policy):
            raise AdaptiveError("STALE_SKILL_LOCK", "normal retirement requires the current user design and policy")
        if entry["status"] != "deprecated":
            raise AdaptiveError("DEPRECATION_REQUIRED", "normal retirement requires a prior digest-bound deprecation")
        if replacement is None or replacement["id"] == entry["id"]:
            raise AdaptiveError("REPLACEMENT_REQUIRED", "normal retirement requires a different active replacement")
        if not set(entry["matched_capabilities"]).issubset(set(replacement["matched_capabilities"])):
            raise AdaptiveError("REPLACEMENT_MISMATCH", "replacement does not cover every locked requirement")
    action = "quarantine" if args.quarantine else "retire"
    payload = lifecycle_action_payload(action, lock, blueprint, policy, entry, replacement=replacement, reason=args.reason)
    approval_digest,decision,approval=require_action_approval(root,args,payload,"RETIREMENT_APPROVAL_REQUIRED",f"adaptive-skill-{action}",allow_security=args.quarantine)
    prior_lifecycle=load_lifecycle(root); lifecycle_exists=lifecycle_path(root).exists()
    lifecycle={"schema":prior_lifecycle["schema"],"events":[*prior_lifecycle["events"],
        {**payload,"action_sha256":approval_digest,"decision":decision,"recorded_at":utc_now()}]}
    skills=[item for item in lock["skills"] if item["id"]!=args.id]
    post_lock=finalize_lock({**lock,"skills":skills,"lock_sha256":None})
    pre=mutation_state(root,lock,prior_lifecycle,[args.id],lock_exists=True,lifecycle_exists=lifecycle_exists)
    post=intended_post_state(root,lock,post_lock,lifecycle,[args.id],
        [{"bundle_sha256":entry["bundle_sha256"],"files":entry["files"],"preexisting":True}])
    journal=prepare_mutation_journal(root,operation=action,action_sha256=approval_digest,gate=decision["gate"],
        source=decision["source"],approval=approval,pre_state=pre,post_state=post)
    journal=authorize_prepared_mutation(root,journal); publish_intended_state(root,journal)
    current=materialized_post_state(journal)["lock"]["value"]
    print_json({"status": action + "d" if action != "retire" else "retired", "id": args.id,
                "replacement": replacement["id"] if replacement else None, "lock_sha256": current["lock_sha256"]})
    return 0


def command_rollback(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    policy = load_policy(root)
    current = load_lock(root, blueprint, policy, required=True)
    if current["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"] or current["policy_sha256"] != canonical_sha256(policy):
        raise AdaptiveError("STALE_SKILL_LOCK", "rollback requires the current user design and policy")
    if not args.source.startswith("user:"):
        raise AdaptiveError("ROLLBACK_APPROVAL_REQUIRED", "rollback requires an explicit user:<decision> source")
    if not SHA256_RE.fullmatch(args.bundle_digest):
        raise AdaptiveError("INVALID_BUNDLE_DIGEST", "rollback bundle digest must be SHA-256")
    entry = resolve_rollback_entry(root, blueprint, policy, args.id, args.bundle_digest)
    current_entry = next((item for item in current["skills"] if item["id"] == args.id), None)
    payload = lifecycle_action_payload("rollback", current, blueprint, policy, current_entry,
                                       reason=None, rollback_entry=entry)
    approval_digest,decision,approval=require_action_approval(root,args,payload,"ROLLBACK_APPROVAL_REQUIRED","adaptive-skill-rollback")
    active=project_path(root,f"skills/{args.id}")
    if active.is_symlink() or (active.exists() and not active.is_dir()):
        raise AdaptiveError("ROLLBACK_TARGET_UNSAFE","rollback target is not a real Skill directory",3)
    prior_lifecycle=load_lifecycle(root); lifecycle_exists=lifecycle_path(root).exists()
    lifecycle={"schema":prior_lifecycle["schema"],"events":[*prior_lifecycle["events"],
        {**payload,"action_sha256":approval_digest,"decision":decision,"recorded_at":utc_now()}]}
    cas=project_path(root,f"skill-cas/{entry['bundle_sha256']}")
    if not exact_bundle(cas,entry["files"]): raise AdaptiveError("SKILL_BUNDLE_DRIFT","rollback CAS bundle is unavailable",3)
    restored=dict(entry); restored["status"]="active"; restored["installed_at"]=utc_now()
    skills=[item for item in current["skills"] if item["id"]!=args.id]+[restored]
    post_lock=finalize_lock({**current,"skills":skills,"lock_sha256":None})
    pre=mutation_state(root,current,prior_lifecycle,[args.id],lock_exists=True,lifecycle_exists=lifecycle_exists)
    post=intended_post_state(root,current,post_lock,lifecycle,[args.id],
        [{"bundle_sha256":entry["bundle_sha256"],"files":entry["files"],"preexisting":True}])
    journal=prepare_mutation_journal(root,operation="rollback",action_sha256=approval_digest,gate=decision["gate"],
        source=decision["source"],approval=approval,pre_state=pre,post_state=post)
    journal=authorize_prepared_mutation(root,journal); publish_intended_state(root,journal)
    lock=materialized_post_state(journal)["lock"]["value"]
    print_json({"status": "rolled-back", "id": args.id, "bundle_sha256": args.bundle_digest, "lock_sha256": lock["lock_sha256"]})
    return 0


def command_recover(root, _args):
    recovered = recover_state_journal(root)
    print_json({"status": "recovered" if recovered else "clean", "mutation": recovered})
    return 0


def command_migrate_history(root,_args):
    print_json(migrate_prechain_mutation_history_v2(root)); return 0


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--root")
    sub = value.add_subparsers(dest="command", required=True)
    discover = sub.add_parser("discover")
    discover.add_argument("--output"); discover.add_argument("--max-repositories", type=int, default=5)
    score = sub.add_parser("score"); score.add_argument("--candidates", required=True); score.add_argument("--output")
    for name in ("install", "update"):
        install = sub.add_parser(name)
        install.add_argument("--candidates", required=True); install.add_argument("--report", required=True)
        install.add_argument("--approve-digest"); install.add_argument("--candidate"); install.add_argument("--replace", action="store_true"); install.add_argument("--plan", action="store_true")
        install.add_argument("--reviewed-content-sha256"); install.add_argument("--reviewed-license-sha256")
        install.add_argument("--source"); install.add_argument("--rationale", default=""); install.add_argument("--covers-capability", action="append", default=[]); install.add_argument("--human-decision-receipt")
    sub.add_parser("verify"); sub.add_parser("recover"); sub.add_parser("migrate-history")
    lifecycle = sub.add_parser("plan-lifecycle")
    lifecycle.add_argument("--action", choices=("deprecate", "retire", "quarantine", "rollback"), required=True)
    lifecycle.add_argument("--id", required=True); lifecycle.add_argument("--replacement"); lifecycle.add_argument("--reason"); lifecycle.add_argument("--bundle-digest")
    deprecate = sub.add_parser("deprecate")
    deprecate.add_argument("--id", required=True); deprecate.add_argument("--replacement", required=True); deprecate.add_argument("--reason", required=True)
    deprecate.add_argument("--source", default=""); deprecate.add_argument("--approve-digest"); deprecate.add_argument("--human-decision-receipt")
    retire = sub.add_parser("retire")
    retire.add_argument("--id", required=True); retire.add_argument("--reason", required=True); retire.add_argument("--replacement")
    retire.add_argument("--source", default=""); retire.add_argument("--approve-digest"); retire.add_argument("--quarantine", action="store_true"); retire.add_argument("--human-decision-receipt")
    rollback = sub.add_parser("rollback")
    rollback.add_argument("--id", required=True); rollback.add_argument("--bundle-digest", required=True)
    rollback.add_argument("--source", default=""); rollback.add_argument("--approve-digest"); rollback.add_argument("--human-decision-receipt")
    return value


def main():
    args = parser().parse_args()
    try:
        root = resolve_root(args.root, __file__)
        if args.command == "discover" and not 1 <= args.max_repositories <= 10:
            raise AdaptiveError("INVALID_DISCOVERY_LIMIT", "max-repositories must be 1-10")
        handler = {
            "discover": command_discover, "score": command_score, "install": command_install, "update": command_install,
            "verify": command_verify, "recover": command_recover, "migrate-history": command_migrate_history, "plan-lifecycle": command_plan_lifecycle, "deprecate": command_deprecate,
            "retire": command_retire, "rollback": command_rollback,
        }[args.command]
        if args.command in {"install", "update", "deprecate", "retire", "rollback", "recover", "migrate-history"}:
            with mutation_lock(root):
                if args.command in {"recover","migrate-history"}:
                    return handler(root,args)
                recover_state_journal(root)
                try:
                    return handler(root, args)
                except Exception:
                    if mutation_journal_path(root).exists() or mutation_journal_path(root).is_symlink():
                        recover_state_journal(root)
                    raise
        if mutation_journal_path(root).exists() or mutation_journal_path(root).is_symlink():
            raise AdaptiveError("INCOMPLETE_SKILL_MUTATION", "run skillctl.py recover before read-only operations", 3)
        return handler(root, args)
    except Exception as error:
        return fail(error)


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
