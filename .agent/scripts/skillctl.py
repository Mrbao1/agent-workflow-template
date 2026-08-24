#!/usr/bin/env python3
"""Discover, score, lock, install, verify, update, retire, and roll back GitHub Skills."""
from pathlib import Path
from urllib import error as urlerror, parse as urlparse, request as urlrequest
import argparse
import base64
import datetime as dt
import json
import math
import os
import re
import shutil
import stat
import sys
import tempfile
import uuid

from adaptive_common import (
    AdaptiveError, COMMIT_RE, ID_RE, SHA256_RE, atomic_write_bytes, bytes_sha256,
    canonical_sha256, ensure_real_directory, fail, load_blueprint, load_json,
    mutation_lock, print_json, record_human_decision, resolve_root, safe_relative_path, utc_now, verify_human_decision, write_json,
)

DEFAULT_POLICY_RELATIVE = Path(".agent/assets/policies/skill-policy.json")
POLICY_KEYS = {
    "schema", "allowed_hosts", "allowed_licenses", "minimum_score", "maximum_candidates",
    "maximum_skill_bytes", "maximum_license_bytes", "github_request_budget", "maximum_recommendation_age_hours",
    "minimum_evolution_samples", "minimum_evolution_success_rate", "weights",
}
WEIGHT_KEYS = {"relevance", "quality", "maintenance", "security", "trust", "license"}
REPOSITORY_KEYS = {
    "host", "owner", "name", "repository_id", "owner_type", "archived", "fork", "stars", "pushed_at",
}
CANDIDATE_KEYS = {"id", "repository", "commit", "path", "content", "license"}
LICENSE_KEYS = {"spdx", "path", "content"}
HARD_PATTERNS = (
    ("pipe-to-shell", re.compile(r"curl[^\n|]{0,240}\|\s*(?:sh|bash|zsh)", re.I)),
    ("destructive-delete", re.compile(r"\brm\s+-rf\b", re.I)),
    ("credential-file", re.compile(r"(?:\.ssh/id_|/etc/(?:shadow|passwd))", re.I)),
    ("secret-enumeration", re.compile(r"\b(?:printenv|env)\s+(?:GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|AWS_SECRET_ACCESS_KEY)\b", re.I)),
    ("privilege-escalation", re.compile(r"\bsudo\s+", re.I)),
)
WARNING_PATTERNS = (
    ("instruction-override", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions", re.I)),
    ("credential-request", re.compile(r"(?:show|print|upload|send|exfiltrate).{0,80}(?:token|password|secret|private key)", re.I)),
    ("disable-controls", re.compile(r"(?:disable|bypass|skip).{0,60}(?:security|policy|approval|test)", re.I)),
)


def policy_path(root):
    return root / ".agent/project/skill-policy.json"


def load_policy(root):
    project_policy = policy_path(root)
    path = project_policy if project_policy.exists() else root / DEFAULT_POLICY_RELATIVE
    value = load_json(path, "Skill policy")
    if not isinstance(value, dict) or set(value) != POLICY_KEYS or value.get("schema") != "agent-skill-policy/v1":
        raise AdaptiveError("INVALID_SKILL_POLICY", "Skill policy fields are invalid")
    if not isinstance(value["allowed_hosts"], list) or not value["allowed_hosts"]:
        raise AdaptiveError("INVALID_SKILL_POLICY", "allowed_hosts must be a non-empty list")
    if not isinstance(value["allowed_licenses"], list) or not value["allowed_licenses"]:
        raise AdaptiveError("INVALID_SKILL_POLICY", "allowed_licenses must be a non-empty list")
    if not isinstance(value["minimum_score"], (int, float)) or isinstance(value["minimum_score"], bool) or not 0 <= value["minimum_score"] <= 100:
        raise AdaptiveError("INVALID_SKILL_POLICY", "minimum_score must be 0-100")
    for key, lower, upper in (
        ("maximum_candidates", 1, 100), ("maximum_skill_bytes", 1024, 1048576),
        ("maximum_license_bytes", 128, 524288), ("github_request_budget", 1, 100),
        ("maximum_recommendation_age_hours", 1, 24 * 365), ("minimum_evolution_samples", 3, 100),
    ):
        if not isinstance(value[key], int) or isinstance(value[key], bool) or not lower <= value[key] <= upper:
            raise AdaptiveError("INVALID_SKILL_POLICY", f"{key} is outside its safe bound")
    if not isinstance(value["minimum_evolution_success_rate"], (int, float)) or isinstance(value["minimum_evolution_success_rate"], bool) or not 0 <= value["minimum_evolution_success_rate"] <= 1:
        raise AdaptiveError("INVALID_SKILL_POLICY", "minimum_evolution_success_rate must be 0-1")
    weights = value.get("weights")
    if not isinstance(weights, dict) or set(weights) != WEIGHT_KEYS:
        raise AdaptiveError("INVALID_SKILL_POLICY", "scoring weights are invalid")
    if any(not isinstance(item, (int, float)) or isinstance(item, bool) or item < 0 for item in weights.values()) or abs(sum(weights.values()) - 1.0) > 0.000001:
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
    if not isinstance(value, dict) or set(value) != {"schema", "provenance", "candidates"} or value.get("schema") != "agent-skill-candidates/v1":
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
    if provenance["mode"] == "offline-user-reviewed" and (provenance["query"] is not None or provenance["requests"] != 0):
        raise AdaptiveError("INVALID_CANDIDATE_PROVENANCE", "offline candidate provenance must not claim network evidence")
    return candidates, provenance


def candidate_assessment(candidate, blueprint, policy, now=None, *, trusted_repository_metadata=True):
    failures, warnings = [], []
    if not isinstance(candidate, dict) or set(candidate) != CANDIDATE_KEYS:
        return {"id": str(candidate.get("id", "invalid")) if isinstance(candidate, dict) else "invalid",
                "eligible": False, "score": 0.0, "confidence": 0.0,
                "breakdown": {key: 0.0 for key in WEIGHT_KEYS},
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
        if not all(isinstance(repository.get(key), str) and repository[key] for key in ("owner", "name", "owner_type", "pushed_at")):
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
    if not isinstance(license_value, dict) or set(license_value) != LICENSE_KEYS:
        failures.append("invalid-license-record")
        license_value = {}
    else:
        try:
            safe_relative_path(license_value.get("path"))
        except AdaptiveError:
            failures.append("unsafe-license-path")
        license_content = license_value.get("content")
        if not isinstance(license_content, str) or not license_content or len(license_content.encode("utf-8", errors="ignore")) > policy["maximum_license_bytes"]:
            failures.append("invalid-license-content")
        if license_value.get("spdx") not in policy["allowed_licenses"]:
            failures.append("license-not-allowed")
        elif isinstance(license_content, str) and detect_license(license_content) != license_value.get("spdx"):
            failures.append("license-text-spdx-mismatch")
    for code, pattern in HARD_PATTERNS:
        if pattern.search(content):
            failures.append(code)
    for code, pattern in WARNING_PATTERNS:
        if pattern.search(content):
            warnings.append(code)
    if len(warnings) >= 2:
        failures.append("multiple-prompt-risk-signals")

    candidate_tokens = token_set(content)
    design = blueprint["design"]
    technologies = [item["name"] + " " + item["reason"] for item in design["technology_choices"]]
    capabilities = [item["id"] + " " + item["description"] for item in design["capabilities"]]
    acceptance = [item["id"] + " " + item["criterion"] for item in design["acceptance"]]
    relevance = (
        0.40 * phrase_fit(capabilities, candidate_tokens)
        + 0.25 * phrase_fit(technologies, candidate_tokens)
        + 0.20 * phrase_fit(design["goals"] + design["architecture"], candidate_tokens)
        + 0.15 * phrase_fit(design["constraints"] + acceptance, candidate_tokens)
    )
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
    base = 100.0 * sum(policy["weights"][key] * breakdown[key] for key in WEIGHT_KEYS)
    score = round(base * (0.70 + 0.30 * confidence), 3) if not failures else 0.0
    eligible = not failures and score >= policy["minimum_score"] and relevance > 0
    if not failures and score < policy["minimum_score"]:
        warnings.append("score-below-threshold")
    if not failures and relevance <= 0:
        warnings.append("no-confirmed-design-match")
    return {
        "id": candidate_id if isinstance(candidate_id, str) else "invalid",
        "eligible": eligible, "score": score, "confidence": round(confidence, 3),
        "breakdown": breakdown, "hard_failures": sorted(set(failures)),
        "warnings": sorted(set(warnings)), "candidate_sha256": canonical_sha256(candidate),
    }


def report_payload(blueprint, policy, assessments, provenance):
    eligible = [item for item in assessments if item["eligible"]]
    eligible.sort(key=lambda item: (-item["score"], -item["confidence"], item["candidate_sha256"], item["id"]))
    ordered = sorted(assessments, key=lambda item: (not item["eligible"], -item["score"], item["id"], item["candidate_sha256"]))
    return {
        "schema": "agent-skill-recommendation/v1",
        "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
        "policy_sha256": canonical_sha256(policy),
        "minimum_score": policy["minimum_score"], "candidate_provenance": provenance,
        "candidates": ordered,
        "recommended_id": eligible[0]["id"] if eligible else None,
    }


def build_report(blueprint, policy, candidates, provenance):
    generated_at = utc_now()
    generated = dt.datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    scoring_time = generated.replace(hour=0, minute=0, second=0, microsecond=0)
    trusted = provenance["mode"] == "github-api"
    assessments = [candidate_assessment(item, blueprint, policy, now=scoring_time, trusted_repository_metadata=trusted) for item in candidates]
    for assessment, candidate in zip(assessments, candidates):
        assessment["suggested_capabilities"] = matched_capabilities(blueprint, candidate.get("content", "") if isinstance(candidate, dict) else "")
    payload = report_payload(blueprint, policy, assessments, provenance)
    expires_at = (generated + dt.timedelta(hours=policy["maximum_recommendation_age_hours"])).isoformat()
    report = {**payload, "generated_at": generated_at, "expires_at": expires_at,
              "recommendation_sha256": canonical_sha256(payload)}
    return {**report, "report_sha256": canonical_sha256(report)}


def load_report(path):
    value = load_json(path, "Skill recommendation")
    expected = {
        "schema", "blueprint_sha256", "policy_sha256", "minimum_score", "candidate_provenance", "candidates",
        "recommended_id", "generated_at", "expires_at", "recommendation_sha256", "report_sha256",
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


class GitHubClient:
    def __init__(self, budget):
        self.budget = budget
        self.requests = 0
        self.token = os.environ.get("GITHUB_TOKEN")
        if self.token is not None and (not self.token.strip() or any(ord(char) < 33 for char in self.token)):
            raise AdaptiveError("INVALID_GITHUB_TOKEN", "GITHUB_TOKEN is blank or malformed; no fallback is allowed")

    def get(self, path, maximum=4 * 1024 * 1024):
        if self.requests >= self.budget:
            raise AdaptiveError("GITHUB_BUDGET_EXHAUSTED", f"GitHub request budget {self.budget} exhausted", 4)
        self.requests += 1
        url = "https://api.github.com" + path
        headers = {
            "Accept": "application/vnd.github+json", "User-Agent": "agent-workflow-template/skillctl",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token.strip()
        request = urlrequest.Request(url, headers=headers, method="GET")
        try:
            with urlrequest.urlopen(request, timeout=12) as response:
                final = urlparse.urlparse(response.geturl())
                if final.scheme != "https" or final.hostname != "api.github.com":
                    raise AdaptiveError("GITHUB_REDIRECT_REJECTED", "GitHub redirected outside api.github.com", 4)
                raw = response.read(maximum + 1)
                if len(raw) > maximum:
                    raise AdaptiveError("GITHUB_RESPONSE_TOO_LARGE", "GitHub response exceeded its byte budget", 4)
        except urlerror.HTTPError as error:
            remaining = error.headers.get("X-RateLimit-Remaining") if error.headers else None
            code = "GITHUB_RATE_LIMITED" if error.code in {403, 429} and remaining == "0" else "GITHUB_HTTP_ERROR"
            raise AdaptiveError(code, f"GitHub request failed with HTTP {error.code}; requests={self.requests}", 4) from error
        except (urlerror.URLError, TimeoutError) as error:
            raise AdaptiveError("GITHUB_NETWORK_ERROR", f"GitHub request failed; requests={self.requests}", 4) from error
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise AdaptiveError("GITHUB_INVALID_JSON", "GitHub returned invalid JSON", 4) from error


def decode_blob(value, maximum, label):
    if not isinstance(value, dict) or value.get("encoding") != "base64" or not isinstance(value.get("content"), str):
        raise AdaptiveError("GITHUB_INVALID_BLOB", f"{label} blob response is invalid", 4)
    try:
        raw = base64.b64decode(value["content"], validate=False)
    except (ValueError, TypeError) as error:
        raise AdaptiveError("GITHUB_INVALID_BLOB", f"{label} is not valid base64", 4) from error
    if len(raw) > maximum or bytes([0]) in raw:
        raise AdaptiveError("GITHUB_INVALID_BLOB", f"{label} exceeds policy or contains NUL", 4)
    try:
        return raw.decode("utf-8")
    except UnicodeError as error:
        raise AdaptiveError("GITHUB_INVALID_BLOB", f"{label} is not UTF-8 text", 4) from error


def detect_license(content):
    lower = content.casefold()
    if "mit license" in lower: return "MIT"
    if "apache license" in lower and "version 2.0" in lower: return "Apache-2.0"
    if "mozilla public license" in lower and "2.0" in lower: return "MPL-2.0"
    if "isc license" in lower: return "ISC"
    if "redistribution and use in source and binary forms" in lower:
        return "BSD-3-Clause" if "neither the name" in lower else "BSD-2-Clause"
    return "NOASSERTION"


def discovery_queries(blueprint):
    design = blueprint["design"]
    authoritative = ([item["id"] + " " + item["description"] for item in design["capabilities"]]
                     + [item["name"] for item in design["technology_choices"]])
    if not authoritative:
        authoritative = design["goals"]
    queries = []
    suffix = " in:name,description,readme"
    for value in authoritative:
        terms = sorted(token_set(value))[:5]
        term_text = " ".join(terms) if terms else str(value).strip()
        prefix = "\"agent skill\" "
        query = prefix + term_text[:240 - len(prefix) - len(suffix)] + suffix
        queries.append(query)
    return queries


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
    required_budget = len(queries) + (inspection_limit * 4)
    if required_budget > policy["github_request_budget"]:
        raise AdaptiveError(
            "GITHUB_BUDGET_INSUFFICIENT",
            f"GitHub request budget {policy['github_request_budget']} cannot cover "
            f"{len(queries)} required search queries plus {inspection_limit * 4} bounded inspection requests",
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
    candidates, used = [], set()
    design_tokens = set().union(*(token_set(value) for value in (
        blueprint["design"]["goals"] + blueprint["design"]["architecture"]
        + [item["name"] for item in blueprint["design"]["technology_choices"]]
        + [item["id"] + " " + item["description"] for item in blueprint["design"]["capabilities"]]
    )))
    for repository in ranked_repositories:
        if len(candidates) >= policy["maximum_candidates"]:
            break
        full_name = repository.get("full_name")
        default_branch = repository.get("default_branch")
        if not isinstance(full_name, str) or "/" not in full_name or not isinstance(default_branch, str):
            continue
        owner, name = full_name.split("/", 1)
        branch = client.get(f"/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/branches/{urlparse.quote(default_branch, safe='')}")
        commit = ((branch.get("commit") or {}).get("sha")) if isinstance(branch, dict) else None
        if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
            continue
        tree = client.get(f"/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/git/trees/{commit}?recursive=1")
        if not isinstance(tree, dict) or tree.get("truncated") is True or not isinstance(tree.get("tree"), list):
            continue
        blobs = {item.get("path"): item for item in tree["tree"] if isinstance(item, dict) and item.get("type") == "blob" and item.get("mode") == "100644"}
        skill_paths = [path for path in blobs if path and path.endswith("SKILL.md")]
        skill_paths.sort(key=lambda value: (-len(token_set(value) & design_tokens), value))
        skill_paths = skill_paths[:1]
        license_paths = sorted(path for path in blobs if path and "/" not in path and re.fullmatch(r"(?i)(?:LICENSE|COPYING)(?:\.[A-Za-z0-9._-]+)?", path))
        license_path = license_paths[0] if license_paths else None
        license_content, license_id = "", "NOASSERTION"
        if license_path:
            blob = client.get(f"/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/git/blobs/{blobs[license_path]['sha']}")
            license_content = decode_blob(blob, policy["maximum_license_bytes"], "license")
            license_id = detect_license(license_content)
        for skill_path in skill_paths:
            blob = client.get(f"/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/git/blobs/{blobs[skill_path]['sha']}")
            content = decode_blob(blob, policy["maximum_skill_bytes"], "Skill")
            frontmatter, _ = parse_frontmatter(content)
            candidates.append({
                "id": unique_candidate_id(skill_path, frontmatter, used),
                "repository": {"host": "github.com", "owner": owner, "name": name,
                    "repository_id": repository.get("id"), "owner_type": (repository.get("owner") or {}).get("type"),
                    "archived": repository.get("archived"), "fork": repository.get("fork"),
                    "stars": repository.get("stargazers_count"), "pushed_at": repository.get("pushed_at")},
                "commit": commit, "path": skill_path, "content": content,
                "license": {"spdx": license_id, "path": license_path or "LICENSE", "content": license_content},
            })
    if not candidates:
        raise AdaptiveError("NO_GITHUB_SKILLS_FOUND", f"no bounded GitHub candidates found; requests={client.requests}", 4)
    provenance = {"mode": "github-api", "source": "api.github.com",
        "blueprint_sha256": blueprint["confirmation"]["design_sha256"], "query": queries,
        "requests": client.requests, "observed_at": utc_now(), "candidate_set_sha256": canonical_sha256(candidates)}
    return {"schema": "agent-skill-candidates/v1", "provenance": provenance, "candidates": candidates}, client.requests, queries


def project_path(root, name):
    return root / ".agent/project" / name


def lock_path(root):
    return project_path(root, "skills.lock.json")


def empty_lock(blueprint, policy):
    value = {
        "schema": "agent-skills-lock/v1", "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
        "policy_sha256": canonical_sha256(policy), "skills": [], "lock_sha256": None,
    }
    value["lock_sha256"] = canonical_sha256(lock_payload(value))
    return value


def lock_payload(value):
    return {key: value[key] for key in value if key != "lock_sha256"}


def validate_lock(value):
    if not isinstance(value, dict) or set(value) != {"schema", "blueprint_sha256", "policy_sha256", "skills", "lock_sha256"}:
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill lock fields are invalid", 3)
    if value.get("schema") != "agent-skills-lock/v1" or not SHA256_RE.fullmatch(str(value.get("blueprint_sha256", ""))) or not SHA256_RE.fullmatch(str(value.get("policy_sha256", ""))):
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
    value = validate_lock(load_json(path, "Skill lock"))
    for entry in value["skills"]:
        verify_entry(root, entry)
    return value


def archive_lock(root, value):
    if not value.get("skills"):
        return
    digest = value.get("lock_sha256") or canonical_sha256(lock_payload(value))
    path = project_path(root, f"skill-lock-history/{digest}.json")
    if not path.exists():
        write_json(path, value)


def write_lock(root, previous, value):
    archive_lock(root, previous)
    value = {**value, "skills": sorted(value["skills"], key=lambda item: item["id"]), "lock_sha256": None}
    value["lock_sha256"] = canonical_sha256(lock_payload(value))
    write_json(lock_path(root), value)
    return value


def exact_bundle(path, files):
    try:
        directory = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISDIR(directory.st_mode) or stat.S_IMODE(directory.st_mode) != 0o700:
        return False
    try:
        observed = sorted(item.name for item in path.iterdir())
    except OSError:
        return False
    expected = sorted(item["path"] for item in files)
    if observed != expected:
        return False
    for record in files:
        item = path / record["path"]
        try:
            before = os.lstat(item)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    stat.S_IMODE(before.st_mode) != 0o600):
                return False
            flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
            descriptor = os.open(item, flags)
            try:
                opened = os.fstat(descriptor)
                if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or
                        opened.st_nlink != 1 or not stat.S_ISREG(opened.st_mode)):
                    return False
                chunks = []
                remaining = record["bytes"] + 1
                while remaining:
                    chunk = os.read(descriptor, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk); remaining -= len(chunk)
                raw = b"".join(chunks)
            finally:
                os.close(descriptor)
        except OSError:
            return False
        if len(raw) != record["bytes"] or bytes_sha256(raw) != record["sha256"]:
            return False
    return True


def expected_bundle_records(content, license_content):
    values = {"SKILL.md": content.encode("utf-8"), "LICENSE.txt": license_content.encode("utf-8")}
    return [
        {"path": filename, "bytes": len(values[filename]), "sha256": bytes_sha256(values[filename]), "mode": "100600"}
        for filename in sorted(values)
    ]


def write_bundle(parent, name, content, license_content):
    ensure_real_directory(parent)
    staging = Path(tempfile.mkdtemp(prefix=f".{name}.", dir=str(parent)))
    try:
        atomic_write_bytes(staging / "SKILL.md", content.encode("utf-8"))
        atomic_write_bytes(staging / "LICENSE.txt", license_content.encode("utf-8"))
        files = expected_bundle_records(content, license_content)
        return staging, files
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def activate_from_bundle(bundle, target):
    parent = target.parent
    ensure_real_directory(parent)
    staging = parent / f".{target.name}.active-{uuid.uuid4().hex}"
    shutil.copytree(bundle, staging, symlinks=False)
    old = None
    try:
        if target.exists():
            if target.is_symlink() or not target.is_dir():
                raise AdaptiveError("UNSAFE_SKILL_TARGET", f"active Skill target is unsafe: {target}", 3)
            old = parent / f".{target.name}.old-{uuid.uuid4().hex}"
            os.replace(target, old)
        os.replace(staging, target)
        if old:
            shutil.rmtree(old)
    except Exception:
        if staging.exists(): shutil.rmtree(staging, ignore_errors=True)
        if old and old.exists() and not target.exists(): os.replace(old, target)
        raise


def matched_capabilities(blueprint, content):
    tokens = token_set(content)
    capabilities = [item["id"] for item in blueprint["design"]["capabilities"] if phrase_fit([item["id"] + " " + item["description"]], tokens) > 0]
    technologies = [
        f"technology:{item['name']}" for item in blueprint["design"]["technology_choices"]
        if phrase_fit([item["name"]], tokens) > 0
    ]
    return sorted(set(capabilities + technologies))


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
    candidates, provenance = clean_candidate_container(load_json(Path(args.candidates).resolve(), "Skill candidates"), policy, blueprint)
    report = build_report(blueprint, policy, candidates, provenance)
    output = Path(args.output).resolve() if args.output else project_path(root, "skill-recommendation.json")
    write_json(output, report)
    print_json({"output": str(output), "recommended_id": report["recommended_id"], "recommendation_sha256": report["recommendation_sha256"], "candidate_count": len(report["candidates"])})
    return 0 if report["recommended_id"] else 2


def explicit_user_source(value):
    if not isinstance(value, str) or not value.startswith("user:") or not value[5:].strip():
        raise AdaptiveError("HUMAN_DECISION_REQUIRED", "source must be an explicit user:<decision> record")
    return value


def command_install(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    policy = load_policy(root)
    report = load_report(Path(args.report).resolve())
    validate_report_context(report, blueprint, policy)
    candidates, provenance = clean_candidate_container(load_json(Path(args.candidates).resolve(), "Skill candidates"), policy, blueprint)
    if provenance != report["candidate_provenance"]:
        raise AdaptiveError("CANDIDATE_PROVENANCE_DRIFT", "candidate provenance changed after scoring")
    candidate_id = args.candidate or report["recommended_id"]
    if not candidate_id:
        raise AdaptiveError("NO_ELIGIBLE_SKILL", "recommendation has no eligible Skill")
    if candidate_id != report["recommended_id"] and (not isinstance(args.rationale, str) or not args.rationale.strip() or len(args.rationale) > 512):
        raise AdaptiveError("CANDIDATE_OVERRIDE_RATIONALE_REQUIRED", "selecting another eligible candidate requires a 1-512 character rationale")
    result = next((item for item in report["candidates"] if item["id"] == candidate_id), None)
    candidate = next((item for item in candidates if item.get("id") == candidate_id), None)
    if not result or not result.get("eligible") or candidate is None:
        raise AdaptiveError("SKILL_NOT_ELIGIBLE", f"Skill {candidate_id!r} is not eligible")
    report_time = dt.datetime.fromisoformat(report["generated_at"].replace("Z", "+00:00")).replace(hour=0, minute=0, second=0, microsecond=0)
    assessment = candidate_assessment(candidate, blueprint, policy, now=report_time,
                                      trusted_repository_metadata=provenance["mode"] == "github-api")
    assessment["suggested_capabilities"] = matched_capabilities(blueprint, candidate["content"])
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
    blueprint_capabilities = {item["id"] for item in blueprint["design"]["capabilities"]}
    approved_capabilities = sorted(set(args.covers_capability or []))
    if len(approved_capabilities) != len(args.covers_capability or []) or set(approved_capabilities) - blueprint_capabilities:
        raise AdaptiveError("INVALID_CAPABILITY_APPROVAL", "approved capability coverage must be a duplicate-free subset of the confirmed blueprint")
    suggested_capabilities = matched_capabilities(blueprint, candidate["content"])
    if blueprint_capabilities and not approved_capabilities:
        raise AdaptiveError("CAPABILITY_APPROVAL_REQUIRED", "select at least one confirmed capability that this Skill is approved to cover")
    if set(approved_capabilities) - set(suggested_capabilities) and (not isinstance(args.rationale, str) or not args.rationale.strip()):
        raise AdaptiveError("CAPABILITY_OVERRIDE_RATIONALE_REQUIRED", "coverage beyond the relevance suggestion requires an explicit rationale")
    expected_files = expected_bundle_records(candidate["content"], candidate["license"]["content"])
    expected_bundle_sha256 = canonical_sha256({"files": expected_files})
    action = {
        "schema": "agent-skill-selection-action/v1", "operation": args.command,
        "candidate": candidate_id, "candidate_sha256": assessment["candidate_sha256"], "bundle_sha256": expected_bundle_sha256,
        "recommendation_sha256": report["recommendation_sha256"], "report_sha256": report["report_sha256"],
        "current_lock_sha256": previous["lock_sha256"],
        "blueprint_sha256": blueprint["confirmation"]["design_sha256"], "policy_sha256": canonical_sha256(policy),
        "report_expires_at": report["expires_at"], "replace": bool(args.replace),
        "candidate_provenance": provenance, "approved_capabilities": approved_capabilities,
        "rationale": args.rationale.strip() if isinstance(args.rationale, str) else "",
    }
    action_sha256 = canonical_sha256(action)
    if args.plan:
        print_json({"schema": "agent-skill-selection-approval/v1", "payload": action,
                    "approval_sha256": action_sha256, "mutation": False})
        return 0
    source = explicit_user_source(args.source)
    if args.approve_digest != action_sha256:
        raise AdaptiveError("RECOMMENDATION_APPROVAL_REQUIRED", f"approve the exact candidate action digest: {action_sha256}")
    decision_receipt = record_human_decision(
        root, gate=f"adaptive-skill-{args.command}", artifact_sha256=action_sha256,
        source=source, receipt=args.human_decision_receipt,
    )
    begin_state_journal(root, previous, load_lifecycle(root), [candidate_id], {candidate_id: expected_bundle_sha256})
    staging, files = write_bundle(project_path(root, "skill-cas"), candidate_id, candidate["content"], candidate["license"]["content"])
    bundle_digest = canonical_sha256({"files": files})
    if bundle_digest != expected_bundle_sha256:
        shutil.rmtree(staging, ignore_errors=True)
        raise AdaptiveError("SKILL_BUNDLE_DRIFT", "staged Skill bundle differs from the approved action")
    cas = project_path(root, f"skill-cas/{bundle_digest}")
    try:
        if cas.exists():
            if not exact_bundle(cas, files):
                raise AdaptiveError("CAS_COLLISION", "content-addressed Skill bundle is inconsistent", 3)
            shutil.rmtree(staging)
        else:
            os.replace(staging, cas)
    finally:
        if staging.exists(): shutil.rmtree(staging, ignore_errors=True)
    active = project_path(root, f"skills/{candidate_id}")
    activate_from_bundle(cas, active)
    entry = {
        "id": candidate_id, "status": "active",
        "source": {
            "host": candidate["repository"]["host"], "owner": candidate["repository"]["owner"],
            "repository": candidate["repository"]["name"], "repository_id": candidate["repository"]["repository_id"],
            "commit": candidate["commit"], "path": candidate["path"],
            "provenance_mode": provenance["mode"], "provenance_source": provenance["source"],
        },
        "license": {"spdx": candidate["license"]["spdx"], "sha256": bytes_sha256(candidate["license"]["content"].encode("utf-8"))},
        "candidate_sha256": assessment["candidate_sha256"], "recommendation_sha256": report["recommendation_sha256"],
        "blueprint_sha256": blueprint["confirmation"]["design_sha256"], "score": result["score"],
        "matched_capabilities": approved_capabilities,
        "bundle_sha256": bundle_digest, "files": files, "installed_at": utc_now(),
        "decision": {"gate": f"adaptive-skill-{args.command}", "source": source,
                     "action_sha256": action_sha256, "action": action, "receipt": decision_receipt},
    }
    skills = [item for item in previous["skills"] if item["id"] != candidate_id] + [entry]
    current = write_lock(root, previous, {
        "schema": "agent-skills-lock/v1", "blueprint_sha256": blueprint["confirmation"]["design_sha256"],
        "policy_sha256": canonical_sha256(policy), "skills": skills, "lock_sha256": None,
    })
    finish_state_journal(root)
    print_json({"status": "updated-content-only" if existing else "installed-content-only", "id": candidate_id, "bundle_sha256": bundle_digest, "lock_sha256": current["lock_sha256"], "scripts_executed": False})
    return 0


def verify_entry(root, entry):
    required = {
        "id", "status", "source", "license", "candidate_sha256", "recommendation_sha256",
        "blueprint_sha256", "score", "matched_capabilities", "bundle_sha256", "files", "installed_at", "decision",
    }
    if not isinstance(entry, dict) or set(entry) != required or entry.get("status") not in {"active", "deprecated", "retired", "quarantined"}:
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill entry fields are invalid", 3)
    if not ID_RE.fullmatch(str(entry.get("id", ""))) or not SHA256_RE.fullmatch(str(entry.get("bundle_sha256", ""))):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill entry identity is invalid", 3)
    source = entry.get("source")
    if not isinstance(source, dict) or set(source) != {"host", "owner", "repository", "repository_id", "commit", "path", "provenance_mode", "provenance_source"} or not COMMIT_RE.fullmatch(str(source.get("commit", ""))):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill source lock is invalid", 3)
    if source.get("provenance_mode") not in {"github-api", "offline-user-reviewed"} or not isinstance(source.get("provenance_source"), str):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill provenance mode is invalid", 3)
    decision = entry.get("decision")
    if (not isinstance(decision, dict) or set(decision) != {"gate", "source", "action_sha256", "action", "receipt"}
            or not isinstance(decision.get("action"), dict) or decision.get("action_sha256") != canonical_sha256(decision["action"])):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill human decision binding is invalid", 3)
    action = decision["action"]
    if (action.get("candidate") != entry["id"] or action.get("candidate_sha256") != entry["candidate_sha256"]
            or action.get("bundle_sha256") != entry["bundle_sha256"] or action.get("approved_capabilities") != entry["matched_capabilities"]
            or action.get("candidate_provenance", {}).get("mode") != source["provenance_mode"]
            or action.get("candidate_provenance", {}).get("source") != source["provenance_source"]):
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill reviewed coverage or provenance binding drifted", 3)
    verify_human_decision(root, gate=decision["gate"], artifact_sha256=decision["action_sha256"], source=decision["source"], record=decision["receipt"])
    files = entry.get("files")
    if not isinstance(files, list) or [item.get("path") for item in files if isinstance(item, dict)] != ["LICENSE.txt", "SKILL.md"]:
        raise AdaptiveError("INVALID_SKILL_LOCK", "Skill file exact-set is invalid", 3)
    cas = project_path(root, f"skill-cas/{entry['bundle_sha256']}")
    if not exact_bundle(cas, files):
        raise AdaptiveError("SKILL_INTEGRITY_ERROR", f"CAS bundle drifted for {entry['id']}", 3)
    if entry["status"] in {"active", "deprecated"}:
        active = project_path(root, f"skills/{entry['id']}")
        if not exact_bundle(active, files):
            raise AdaptiveError("SKILL_INTEGRITY_ERROR", f"active Skill drifted for {entry['id']}", 3)


def command_verify(root, _args):
    if mutation_journal_path(root).exists() or mutation_journal_path(root).is_symlink():
        raise AdaptiveError("INCOMPLETE_SKILL_MUTATION", "Skill mutation recovery is required", 3)
    blueprint = load_blueprint(root, require_confirmed=True)
    policy = load_policy(root)
    path = lock_path(root)
    required_capabilities = {item["id"] for item in blueprint["design"]["capabilities"]}
    if not path.exists():
        if required_capabilities:
            raise AdaptiveError("MISSING_SKILL_LOCK", "confirmed project capabilities require a verified dynamic Skill lock", 3)
        print_json({"status": "NO_DYNAMIC_SKILLS_REQUIRED", "covered_capabilities": []})
        return 0
    lock = load_lock(root, blueprint, policy, required=True)
    if lock["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"]:
        raise AdaptiveError("SKILL_BLUEPRINT_STALE", "locked Skills target an older user design")
    if lock["policy_sha256"] != canonical_sha256(policy):
        raise AdaptiveError("SKILL_POLICY_STALE", "locked Skills target an older policy", 3)
    for entry in lock["skills"]:
        verify_entry(root, entry)
    covered = {capability for entry in lock["skills"] if entry["status"] in {"active", "deprecated"} for capability in entry["matched_capabilities"]}
    missing = required_capabilities - covered
    extra = covered - required_capabilities
    if missing or extra:
        raise AdaptiveError("SKILL_CAPABILITY_COVERAGE_INVALID", f"reviewed Skill coverage differs from blueprint: missing={sorted(missing)} extra={sorted(extra)}", 3)
    expected_active = sorted(item["id"] for item in lock["skills"] if item["status"] in {"active", "deprecated"})
    active_root = project_path(root, "skills")
    observed = []
    if active_root.exists():
        if active_root.is_symlink() or not active_root.is_dir():
            raise AdaptiveError("SKILL_INTEGRITY_ERROR", "active Skill root is unsafe", 3)
        observed = sorted(item.name for item in active_root.iterdir() if item.is_dir() and not item.is_symlink())
        if any(item.is_symlink() or not item.is_dir() for item in active_root.iterdir()):
            raise AdaptiveError("SKILL_INTEGRITY_ERROR", "active Skill root has unexpected entries", 3)
    if observed != expected_active:
        raise AdaptiveError("SKILL_INTEGRITY_ERROR", f"active Skill exact-set drifted: expected={expected_active} observed={observed}", 3)
    print_json({"status": "verified", "lock_sha256": lock["lock_sha256"], "active": expected_active, "covered_capabilities": sorted(covered)})
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
    path = mutation_journal_path(root)
    if path.exists():
        path.unlink()


def recover_state_journal(root):
    path = mutation_journal_path(root)
    if not path.exists() and not path.is_symlink():
        return False
    if path.is_symlink() or not path.is_file():
        raise AdaptiveError("INVALID_SKILL_MUTATION_JOURNAL", "Skill mutation journal must be one regular file", 3)
    value = load_json(path, "Skill mutation journal")
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
            activate_from_bundle(cas, target)
        elif target.exists() or target.is_symlink():
            post_bundle = value["post_bundles"][skill_id]
            post_cas = project_path(root, f"skill-cas/{post_bundle}")
            if target.is_symlink() or not exact_bundle(post_cas, old.get("files", []) if old else _files_for_bundle(post_cas)) or not exact_bundle(target, _files_for_bundle(post_cas)):
                raise AdaptiveError("SKILL_RECOVERY_FAILED", f"unexpected active target blocks recovery for {skill_id}", 3)
            shutil.rmtree(target)
        parent = project_path(root, "skills")
        if parent.exists():
            for hidden in list(parent.glob(f".{skill_id}.*-*")):
                if hidden.is_symlink() or not hidden.is_dir():
                    raise AdaptiveError("SKILL_RECOVERY_FAILED", f"unsafe recovery artifact for {skill_id}", 3)
                shutil.rmtree(hidden)
    if value["before_lock_existed"]:
        write_json(lock_path(root), before)
    elif lock_path(root).exists():
        lock_path(root).unlink()
    if value["before_lifecycle_existed"]:
        write_json(lifecycle_path(root), value["before_lifecycle"])
    elif lifecycle_path(root).exists():
        lifecycle_path(root).unlink()
    path.unlink()
    return True


def _files_for_bundle(path):
    records = []
    if path.is_symlink() or not path.is_dir():
        return records
    for name in ("LICENSE.txt", "SKILL.md"):
        item = path / name
        if not item.is_file() or item.is_symlink():
            return []
        raw = item.read_bytes()
        records.append({"path": name, "bytes": len(raw), "sha256": bytes_sha256(raw), "mode": "100600"})
    return records


def load_lifecycle(root):
    path = lifecycle_path(root)
    value = load_json(path, "Skill lifecycle") if path.exists() else {"schema": "agent-skill-lifecycle/v1", "events": []}
    if not isinstance(value, dict) or set(value) != {"schema", "events"} or value.get("schema") != "agent-skill-lifecycle/v1" or not isinstance(value.get("events"), list) or len(value["events"]) > 4096:
        raise AdaptiveError("INVALID_SKILL_LIFECYCLE", "Skill lifecycle ledger is invalid", 3)
    for event in value["events"]:
        decision = event.get("decision") if isinstance(event, dict) else None
        if not isinstance(decision, dict) or set(decision) != {"gate", "source", "action_sha256", "receipt", "assurance"} or not SHA256_RE.fullmatch(str(decision.get("action_sha256", ""))):
            raise AdaptiveError("INVALID_SKILL_LIFECYCLE", "lifecycle decision binding is invalid", 3)
        if decision["assurance"] == "human-decision-receipt":
            verify_human_decision(root, gate=decision["gate"], artifact_sha256=decision["action_sha256"], source=decision["source"], record=decision["receipt"])
        elif decision["assurance"] != "security-emergency-containment" or not decision["source"].startswith("security:") or event.get("action") != "quarantine":
            raise AdaptiveError("INVALID_SKILL_LIFECYCLE", "lifecycle decision assurance is invalid", 3)
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


def require_action_approval(root, args, payload, code, gate, *, allow_security=False):
    expected = canonical_sha256(payload)
    if args.approve_digest != expected:
        raise AdaptiveError(code, f"approve the exact lifecycle action digest: {expected}")
    if allow_security and isinstance(args.source, str) and args.source.startswith("security:") and args.source[9:].strip():
        decision = {"gate": gate, "source": args.source, "action_sha256": expected,
                    "receipt": None, "assurance": "security-emergency-containment"}
    else:
        source = explicit_user_source(args.source)
        receipt = record_human_decision(root, gate=gate, artifact_sha256=expected, source=source,
                                        receipt=args.human_decision_receipt)
        decision = {"gate": gate, "source": source, "action_sha256": expected,
                    "receipt": receipt, "assurance": "human-decision-receipt"}
    return expected, decision


def resolve_rollback_entry(root, blueprint, policy, skill_id, bundle_digest):
    history = project_path(root, "skill-lock-history")
    identities = {}
    if history.exists():
        if history.is_symlink() or not history.is_dir():
            raise AdaptiveError("INVALID_SKILL_HISTORY", "Skill lock history root is unsafe", 3)
        for path in sorted(history.glob("*.json")):
            snapshot = validate_lock(load_json(path, "Skill lock snapshot"))
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
    approval, decision = require_action_approval(root, args, payload, "DEPRECATION_APPROVAL_REQUIRED", "adaptive-skill-deprecate")
    lifecycle = load_lifecycle(root)
    begin_state_journal(root, lock, lifecycle, [args.id], {args.id: entry["bundle_sha256"]})
    lifecycle["events"].append({**payload, "action_sha256": approval, "decision": decision, "recorded_at": utc_now()})
    skills = []
    for item in lock["skills"]:
        updated = dict(item)
        if item["id"] == args.id:
            updated["status"] = "deprecated"
        skills.append(updated)
    current = write_lock(root, lock, {**lock, "skills": skills, "lock_sha256": None})
    try:
        write_json(lifecycle_path(root), lifecycle)
    except Exception:
        write_json(lock_path(root), lock)
        raise
    finish_state_journal(root)
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
    approval, decision = require_action_approval(root, args, payload, "RETIREMENT_APPROVAL_REQUIRED", f"adaptive-skill-{action}", allow_security=args.quarantine)
    lifecycle = load_lifecycle(root)
    begin_state_journal(root, lock, lifecycle, [args.id], {args.id: entry["bundle_sha256"]})
    event = {**payload, "action_sha256": approval, "decision": decision, "recorded_at": utc_now()}
    lifecycle["events"].append(event)
    active = project_path(root, f"skills/{entry['id']}")
    tombstone = None
    if active.exists():
        if not exact_bundle(active, entry["files"]):
            raise AdaptiveError("SKILL_INTEGRITY_ERROR", "refusing to retire a drifted Skill", 3)
        tombstone = active.parent / f".{entry['id']}.retiring-{uuid.uuid4().hex}"
        os.replace(active, tombstone)
    skills = [item for item in lock["skills"] if item["id"] != args.id]
    try:
        current = write_lock(root, lock, {**lock, "skills": skills, "lock_sha256": None})
        write_json(lifecycle_path(root), lifecycle)
    except Exception:
        write_json(lock_path(root), lock)
        if tombstone and tombstone.exists() and not active.exists():
            os.replace(tombstone, active)
        raise
    if tombstone and tombstone.exists():
        shutil.rmtree(tombstone)
    finish_state_journal(root)
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
    approval, decision = require_action_approval(root, args, payload, "ROLLBACK_APPROVAL_REQUIRED", "adaptive-skill-rollback")
    active = project_path(root, f"skills/{args.id}")
    if active.is_symlink() or (active.exists() and not active.is_dir()):
        raise AdaptiveError("ROLLBACK_TARGET_UNSAFE", "rollback target is not a real Skill directory", 3)
    lifecycle = load_lifecycle(root)
    begin_state_journal(root, current, lifecycle, [args.id], {args.id: entry["bundle_sha256"]})
    lifecycle["events"].append({**payload, "action_sha256": approval, "decision": decision, "recorded_at": utc_now()})
    cas = project_path(root, f"skill-cas/{entry['bundle_sha256']}")
    restored = dict(entry); restored["status"] = "active"; restored["installed_at"] = utc_now()
    skills = [item for item in current["skills"] if item["id"] != args.id] + [restored]
    try:
        activate_from_bundle(cas, active)
        lock = write_lock(root, current, {**current, "skills": skills, "lock_sha256": None})
        write_json(lifecycle_path(root), lifecycle)
    except Exception:
        write_json(lock_path(root), current)
        if active.exists() and exact_bundle(active, entry["files"]):
            shutil.rmtree(active)
        raise
    finish_state_journal(root)
    print_json({"status": "rolled-back", "id": args.id, "bundle_sha256": args.bundle_digest, "lock_sha256": lock["lock_sha256"]})
    return 0


def command_recover(root, _args):
    recovered = recover_state_journal(root)
    print_json({"status": "recovered" if recovered else "clean", "mutation": recovered})
    return 0


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
        install.add_argument("--source"); install.add_argument("--rationale", default=""); install.add_argument("--covers-capability", action="append", default=[]); install.add_argument("--human-decision-receipt")
    sub.add_parser("verify"); sub.add_parser("recover")
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
            "verify": command_verify, "recover": command_recover, "plan-lifecycle": command_plan_lifecycle, "deprecate": command_deprecate,
            "retire": command_retire, "rollback": command_rollback,
        }[args.command]
        if args.command in {"install", "update", "deprecate", "retire", "rollback", "recover"}:
            with mutation_lock(root):
                if args.command == "recover":
                    return command_recover(root, args)
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
    raise SystemExit(main())
