#!/usr/bin/env python3
"""Prove managed JSON schemas are executable runtime contracts."""
from pathlib import Path
import copy
import datetime as dt
import json
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from adaptive_common import AdaptiveError, canonical_sha256, validate_blueprint
from blueprintctl import empty_blueprint
import knowledgectl
import skillctl
import artifactctl
import blueprintacceptance
from schema_validation import validate_managed_schema

def rejected(action):
    try:
        action()
    except AdaptiveError:
        return True
    return False

def main():
    assert artifactctl.ADAPTIVE_ACCEPTANCE_RECEIPT_SCHEMA == blueprintacceptance.RECEIPT_SCHEMA
    draft = empty_blueprint()
    assert validate_managed_schema(draft, "project-blueprint.schema.json", "agent-project-blueprint/v1") == []
    assert validate_blueprint(draft) == draft
    malformed = copy.deepcopy(draft); malformed["unexpected"] = True
    assert validate_managed_schema(malformed, "project-blueprint.schema.json", "agent-project-blueprint/v1")
    assert rejected(lambda: validate_blueprint(malformed))
    wrong_command = copy.deepcopy(draft)
    wrong_command["design"]["commands"] = [{"id": "x", "argv": ["tool"], "stage": "ci", "timeout_seconds": True, "covers": []}]
    assert validate_managed_schema(wrong_command, "project-blueprint.schema.json", "agent-project-blueprint/v1")
    assert rejected(lambda: validate_blueprint(wrong_command))

    with tempfile.TemporaryDirectory(prefix="agent-schema-contract-") as temporary:
        root = Path(temporary)
        policy_dir = root / ".agent/assets/policies"; policy_dir.mkdir(parents=True)
        policy = json.loads((HERE.parent / "assets/policies/skill-policy.json").read_text(encoding="utf-8"))
        (policy_dir / "skill-policy.json").write_text(json.dumps(policy), encoding="utf-8")
        assert validate_managed_schema(policy, "skill-policy.schema.json", "agent-skill-policy/v1") == []
        assert skillctl.load_policy(root) == policy
        bad_policy = copy.deepcopy(policy); bad_policy["maximum_candidates"] = 101
        (policy_dir / "skill-policy.json").write_text(json.dumps(bad_policy), encoding="utf-8")
        assert validate_managed_schema(bad_policy, "skill-policy.schema.json", "agent-skill-policy/v1")
        assert rejected(lambda: skillctl.load_policy(root))

        confirmed = copy.deepcopy(draft)
        confirmed["design"]["goals"] = ["schema contract"]
        confirmed["design"]["acceptance"] = [{"id": "schema", "criterion": "schemas execute", "method": "evidence"}]
        confirmed["status"] = "confirmed"
        confirmed["confirmation"] = {"source": "user:test", "design_sha256": canonical_sha256(confirmed["design"]), "confirmed_at": dt.datetime.now(dt.timezone.utc).isoformat(), "decision_receipt": {"a": 1, "b": 2, "c": 3}}
        candidate = {"id": "schema-skill", "repository": {"host": "github.com", "owner": "owner", "name": "repo", "repository_id": 1, "owner_type": "Organization", "archived": False, "fork": False, "stars": 1, "pushed_at": "2025-01-01T00:00:00Z"}, "commit": "a" * 40, "path": "SKILL.md", "content": "text", "license": {"spdx": "MIT", "path": "LICENSE", "content": "text", "documents": [{"path": "LICENSE", "kind": "license", "content": "text"}]}}
        candidates = [candidate]
        policy["offline_content_catalogs"]=[{"id":"schema-fixture","candidate_set_sha256":canonical_sha256(candidates)}]
        document = {"schema": "agent-skill-candidates/v2", "provenance": {"mode": "offline-user-reviewed", "source": "offline:schema-fixture", "blueprint_sha256": confirmed["confirmation"]["design_sha256"], "query": None, "requests": 0, "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(), "candidate_set_sha256": canonical_sha256(candidates)}, "candidates": candidates}
        assert validate_managed_schema(document, "skill-candidates.schema.json", "agent-skill-candidates/v2") == []
        assert skillctl.clean_candidate_container(document, policy, confirmed)[0] == candidates
        bad_document = copy.deepcopy(document); bad_document["candidates"][0]["extra"] = True
        bad_document["provenance"]["candidate_set_sha256"] = canonical_sha256(bad_document["candidates"])
        assert validate_managed_schema(bad_document, "skill-candidates.schema.json", "agent-skill-candidates/v2")
        assert rejected(lambda: skillctl.clean_candidate_container(bad_document, policy, confirmed))

        knowledge = {"schema": "agent-knowledge-registry/v1", "entries": [{"id": "architecture", "path": "architecture.md", "kind": "architecture", "owners": ["maintainer"], "tags": [], "source_globs": ["src/**"], "status": "active"}]}
        registry_dir = root / ".agent/knowledge"; registry_dir.mkdir(parents=True, exist_ok=True)
        (registry_dir / "registry.json").write_text(json.dumps(knowledge), encoding="utf-8")
        assert validate_managed_schema(knowledge, "knowledge-registry.schema.json", "agent-knowledge-registry/v1") == []
        assert knowledgectl.load_registry(root, require_files=False)["entries"][0]["id"] == "architecture"
        bad_knowledge = copy.deepcopy(knowledge); bad_knowledge["entries"][0]["unknown"] = 1
        (registry_dir / "registry.json").write_text(json.dumps(bad_knowledge), encoding="utf-8")
        assert validate_managed_schema(bad_knowledge, "knowledge-registry.schema.json", "agent-knowledge-registry/v1")
        assert rejected(lambda: knowledgectl.load_registry(root, require_files=False))
    print("SCHEMA CONTRACT SELF-TEST PASSED")

if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
