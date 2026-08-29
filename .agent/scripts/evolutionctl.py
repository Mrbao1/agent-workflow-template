#!/usr/bin/env python3
"""Record low-sensitivity outcomes and produce digest-bound evolution proposals."""
from pathlib import Path
import argparse
import datetime as dt

from adaptive_common import (
    AdaptiveError, ID_RE, SHA256_RE, canonical_sha256, fail, load_blueprint, load_json,
    mutation_lock, prepare_provider_human_decision, print_json, resolve_root, utc_now, write_json,
)
from skillctl import (
    authorize_prepared_mutation, decision_placeholder, finalize_lock, intended_post_state, lifecycle_path, load_lifecycle,
    load_lock, load_policy, load_report, materialized_post_state, mutation_journal_path, mutation_state,
    prepare_mutation_journal, publish_intended_state, recover_state_journal, validate_report_context,
)

OUTCOMES = {"success", "failure", "overridden", "unused"}
INVARIANTS = {
    "auto_install": False,
    "auto_merge": False,
    "auto_policy_relaxation": False,
    "retirement_requires_active_replacement": True,
    "workflow_update_uses_installer_check_first": True,
}
ACTION_TYPES = {
    "deprecate-after-replacement", "trial-replacement", "seek-replacement",
    "trial-candidate", "check-workflow-update",
}


def observations_path(root, target_type):
    name = "skill-observations.json" if target_type == "skill" else "workflow-observations.json"
    return root / ".agent/project" / name


def load_observations(root, target_type):
    path = observations_path(root, target_type)
    schema = f"agent-{target_type}-observations/v1"
    key = "skill" if target_type == "skill" else "component"
    if not path.exists():
        return {"schema": schema, "observations": []}
    value = load_json(path, f"{target_type} observations")
    if not isinstance(value, dict) or set(value) != {"schema", "observations"} or value.get("schema") != schema or not isinstance(value.get("observations"), list) or len(value["observations"]) > 4096:
        raise AdaptiveError("INVALID_EVOLUTION_OBSERVATIONS", f"{target_type} observations are invalid")
    for item in value["observations"]:
        if (
            not isinstance(item, dict)
            or set(item) != {key, "outcome", "blueprint_sha256", "run_id", "evidence_sha256", "recorded_at"}
            or not ID_RE.fullmatch(str(item.get(key, "")))
            or item.get("outcome") not in OUTCOMES
            or not SHA256_RE.fullmatch(str(item.get("blueprint_sha256", "")))
            or not ID_RE.fullmatch(str(item.get("run_id", "")))
            or not SHA256_RE.fullmatch(str(item.get("evidence_sha256", "")))
            or not isinstance(item.get("recorded_at"), str)
        ):
            raise AdaptiveError("INVALID_EVOLUTION_OBSERVATIONS", f"{target_type} observation fields are invalid")
    return value


def append_observation(root, target_type, target_id, outcome, blueprint_sha256, run_id, evidence_sha256):
    key = "skill" if target_type == "skill" else "component"
    value = load_observations(root, target_type)
    identity = (target_id, blueprint_sha256, run_id, evidence_sha256)
    if any((item[key], item["blueprint_sha256"], item["run_id"], item["evidence_sha256"]) == identity for item in value["observations"]):
        raise AdaptiveError("DUPLICATE_EVOLUTION_OBSERVATION", "the same run evidence is already recorded")
    value["observations"].append({key: target_id, "outcome": outcome, "blueprint_sha256": blueprint_sha256,
                                  "run_id": run_id, "evidence_sha256": evidence_sha256, "recorded_at": utc_now()})
    value["observations"] = value["observations"][-4096:]
    write_json(observations_path(root, target_type), value)


def require_current_lock(lock, blueprint, policy):
    if lock["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"] or lock["policy_sha256"] != canonical_sha256(policy):
        raise AdaptiveError("STALE_SKILL_LOCK", "evolution requires the current confirmed design and Skill policy")


def command_record(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    if not ID_RE.fullmatch(args.skill):
        raise AdaptiveError("INVALID_SKILL_ID", "Skill ID is invalid")
    policy = load_policy(root)
    lock = load_lock(root, blueprint, policy, required=True)
    require_current_lock(lock, blueprint, policy)
    if not any(item["id"] == args.skill and item["status"] in {"active", "deprecated"} for item in lock["skills"]):
        raise AdaptiveError("UNKNOWN_SKILL", f"Skill {args.skill!r} is not active or deprecated")
    append_observation(root, "skill", args.skill, args.outcome, blueprint["confirmation"]["design_sha256"], args.run_id, args.evidence_sha256)
    print(f"SKILL_OUTCOME_RECORDED: id={args.skill} outcome={args.outcome}")
    return 0


def command_record_workflow(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    if not ID_RE.fullmatch(args.component):
        raise AdaptiveError("INVALID_WORKFLOW_COMPONENT", "workflow component ID is invalid")
    append_observation(root, "workflow", args.component, args.outcome, blueprint["confirmation"]["design_sha256"], args.run_id, args.evidence_sha256)
    print(f"WORKFLOW_OUTCOME_RECORDED: component={args.component} outcome={args.outcome}")
    return 0


def outcome_summary(observations, key, target_id, blueprint_sha256):
    samples = [item for item in observations if item[key] == target_id and item["blueprint_sha256"] == blueprint_sha256]
    successes = sum(item["outcome"] == "success" for item in samples)
    failures = sum(item["outcome"] in {"failure", "overridden"} for item in samples)
    denominator = successes + failures
    return denominator, (successes / denominator if denominator else None)


def proposal_identity(value):
    if value is None:
        return None
    return {"id": value["id"], "candidate_sha256": value["candidate_sha256"],
            "bundle_sha256": value.get("bundle_sha256")}


def action_record(target_type, target_id, action, replacement, samples, success_rate, reason,
                  *, target_identity=None, replacement_identity=None):
    payload = {
        "target_type": target_type, "target_id": target_id, "action": action, "replacement": replacement,
        "target_identity": proposal_identity(target_identity), "replacement_identity": proposal_identity(replacement_identity),
        "samples": samples, "success_rate": round(success_rate, 4) if success_rate is not None else None,
        "reason": reason,
    }
    return {**payload, "action_sha256": canonical_sha256(payload)}


def bounded_output(root, value, default_name):
    output = Path(value).expanduser().resolve() if value else root / ".agent/project" / default_name
    try:
        output.relative_to(root)
    except ValueError as error:
        raise AdaptiveError("UNSAFE_OUTPUT_PATH", "evolution output must stay inside the project root") from error
    return output


def command_plan(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    policy = load_policy(root)
    lock = load_lock(root, blueprint, policy, required=True)
    require_current_lock(lock, blueprint, policy)
    report = validate_report_context(load_report(Path(args.report).resolve()), blueprint, policy)
    current_blueprint = blueprint["confirmation"]["design_sha256"]
    skill_observations = load_observations(root, "skill")["observations"]
    workflow_observations = load_observations(root, "workflow")["observations"]
    minimum_samples = policy["minimum_evolution_samples"]
    minimum_rate = policy["minimum_evolution_success_rate"]
    actions = []
    for entry in lock["skills"]:
        if entry["status"] not in {"active", "deprecated"}:
            continue
        samples, success_rate = outcome_summary(skill_observations, "skill", entry["id"], current_blueprint)
        if samples < minimum_samples or success_rate >= minimum_rate:
            continue
        recommended = report.get("recommended_id")
        recommendation_result = next((item for item in report["candidates"] if item["id"] == recommended), None)
        replacement = next((item for item in lock["skills"] if item["id"] == recommended and item["status"] == "active"), None)
        if replacement and replacement["id"] != entry["id"] and set(entry["matched_capabilities"]).issubset(set(replacement["matched_capabilities"])):
            action = "deprecate-after-replacement"
            reason = f"success rate is below {minimum_rate:.2f}; the recommended replacement is already active and covers all locked requirements"
        elif recommended and recommended != entry["id"]:
            action = "trial-replacement"
            reason = f"success rate is below {minimum_rate:.2f}; trial the eligible recommendation before any deprecation"
        else:
            action = "seek-replacement"
            reason = f"success rate is below {minimum_rate:.2f}; no different eligible replacement is approved"
        actions.append(action_record(
            "skill", entry["id"], action, recommended if recommended != entry["id"] else None, samples, success_rate, reason,
            target_identity=entry, replacement_identity=replacement or (recommendation_result if recommended != entry["id"] else None),
        ))
    recommended_id = report.get("recommended_id")
    if recommended_id and all(item["id"] != recommended_id for item in lock["skills"]):
        recommendation = next(item for item in report["candidates"] if item["id"] == recommended_id)
        actions.append(action_record(
            "skill", recommended_id, "trial-candidate", None, 0, None,
            f"eligible candidate scored {recommendation['score']}; installation still requires exact candidate action approval",
            target_identity=recommendation,
        ))
    components = sorted({item["component"] for item in workflow_observations if item["blueprint_sha256"] == current_blueprint})
    for component in components:
        samples, success_rate = outcome_summary(workflow_observations, "component", component, current_blueprint)
        if samples >= minimum_samples and success_rate < minimum_rate:
            actions.append(action_record("workflow", component, "check-workflow-update", None, samples, success_rate,
                                         "run installer check then dry-run; never replace local workflow files directly"))
    created_at = utc_now()
    payload = {
        "schema": "agent-evolution-plan/v1",
        "mode": "proposal-only",
        "blueprint_sha256": current_blueprint,
        "policy_sha256": canonical_sha256(policy),
        "lock_sha256": lock["lock_sha256"],
        "recommendation_sha256": report["recommendation_sha256"],
        "report_sha256": report["report_sha256"],
        "actions": actions,
        "invariants": dict(INVARIANTS),
        "created_at": created_at, "expires_at": report["expires_at"],
    }
    plan = {**payload, "plan_sha256": canonical_sha256(payload)}
    output = bounded_output(root, args.output, "evolution-plan.json")
    write_json(output, plan)
    print_json({"status": "proposal", "output": str(output), "plan_sha256": plan["plan_sha256"], "action_count": len(actions)})
    return 0


def validate_action(item):
    keys = {"target_type", "target_id", "action", "replacement", "target_identity", "replacement_identity",
            "samples", "success_rate", "reason", "action_sha256"}
    if not isinstance(item, dict) or set(item) != keys:
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution action fields are invalid")
    if item["target_type"] not in {"skill", "workflow"} or not ID_RE.fullmatch(str(item["target_id"])) or item["action"] not in ACTION_TYPES:
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution action identity is invalid")
    if item["replacement"] is not None and not ID_RE.fullmatch(str(item["replacement"])):
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution replacement identity is invalid")
    for identity in (item["target_identity"], item["replacement_identity"]):
        if identity is None:
            continue
        if (not isinstance(identity, dict) or set(identity) != {"id", "candidate_sha256", "bundle_sha256"} or
                not ID_RE.fullmatch(str(identity.get("id", ""))) or not SHA256_RE.fullmatch(str(identity.get("candidate_sha256", ""))) or
                (identity.get("bundle_sha256") is not None and not SHA256_RE.fullmatch(str(identity["bundle_sha256"])) )):
            raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution action candidate identity is invalid")
    payload = {key: item[key] for key in item if key != "action_sha256"}
    if item.get("action_sha256") != canonical_sha256(payload):
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution action digest drifted")
    if not isinstance(item["samples"], int) or isinstance(item["samples"], bool) or not 0 <= item["samples"] <= 4096:
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution sample count is invalid")
    if item["success_rate"] is not None and (not isinstance(item["success_rate"], (int, float)) or isinstance(item["success_rate"], bool) or not 0 <= item["success_rate"] <= 1):
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution success rate is invalid")
    if not isinstance(item["reason"], str) or not item["reason"] or len(item["reason"].encode("utf-8")) > 1024:
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution action reason is invalid")
    return item


def load_plan(path):
    value = load_json(path, "evolution plan")
    expected = {"schema", "mode", "blueprint_sha256", "policy_sha256", "lock_sha256", "recommendation_sha256", "report_sha256", "actions", "invariants", "created_at", "expires_at", "plan_sha256"}
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != "agent-evolution-plan/v1" or value.get("mode") != "proposal-only":
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution plan fields are invalid")
    for key in ("blueprint_sha256", "policy_sha256", "lock_sha256", "recommendation_sha256", "report_sha256", "plan_sha256"):
        if not SHA256_RE.fullmatch(str(value.get(key, ""))):
            raise AdaptiveError("INVALID_EVOLUTION_PLAN", f"evolution plan {key} is invalid")
    if value.get("invariants") != INVARIANTS or not isinstance(value.get("created_at"), str) or not isinstance(value.get("expires_at"), str):
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution invariants or timestamp are invalid")
    try:
        expires = dt.datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution plan expiry is invalid") from error
    if expires.tzinfo is None or dt.datetime.now(dt.timezone.utc) > expires:
        raise AdaptiveError("STALE_EVOLUTION_PLAN", "evolution plan has expired")
    if not isinstance(value.get("actions"), list) or len(value["actions"]) > 128:
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution action list is invalid")
    for item in value["actions"]:
        validate_action(item)
    identities = [(item["target_type"], item["target_id"], item["action"]) for item in value["actions"]]
    if len(identities) != len(set(identities)):
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution actions contain duplicates")
    payload = {key: value[key] for key in value if key != "plan_sha256"}
    if canonical_sha256(payload) != value["plan_sha256"]:
        raise AdaptiveError("INVALID_EVOLUTION_PLAN", "evolution plan digest drifted")
    return value


def command_apply(root, args):
    blueprint = load_blueprint(root, require_confirmed=True)
    policy = load_policy(root)
    lock = load_lock(root, blueprint, policy, required=True)
    require_current_lock(lock, blueprint, policy)
    plan = load_plan(Path(args.plan).resolve())
    if not args.source or not args.source.startswith("user:") or not args.source[5:].strip():
        raise AdaptiveError("EVOLUTION_APPROVAL_REQUIRED", "apply requires an explicit user:<decision> source")
    if plan["blueprint_sha256"] != blueprint["confirmation"]["design_sha256"] or plan["policy_sha256"] != canonical_sha256(policy) or plan["lock_sha256"] != lock["lock_sha256"]:
        raise AdaptiveError("STALE_EVOLUTION_PLAN", "blueprint, policy, or Skill lock changed after the proposal")
    action = next((item for item in plan["actions"] if item["action_sha256"] == args.action_sha256), None)
    if action is None:
        raise AdaptiveError("EVOLUTION_ACTION_REQUIRED", "apply requires one exact action_sha256 from the plan")
    approval_payload = {
        "schema": "agent-evolution-apply-action/v1", "action_sha256": action["action_sha256"],
        "plan_sha256": plan["plan_sha256"], "report_sha256": plan["report_sha256"],
        "recommendation_sha256": plan["recommendation_sha256"], "blueprint_sha256": plan["blueprint_sha256"],
        "policy_sha256": plan["policy_sha256"], "prior_lock_sha256": plan["lock_sha256"], "expires_at": plan["expires_at"],
    }
    approval_sha256 = canonical_sha256(approval_payload)
    if args.approve_digest != approval_sha256:
        raise AdaptiveError("EVOLUTION_APPROVAL_REQUIRED", f"approve the exact evolution action digest: {approval_sha256}")
    decision_request=prepare_provider_human_decision(root,gate="adaptive-evolution-apply",artifact_sha256=approval_sha256,
                                                     source=args.source,receipt=args.human_decision_receipt)
    decision_receipt=decision_placeholder(decision_request)
    skills = [dict(item) for item in lock["skills"]]
    if action["target_type"] != "skill" or action["action"] != "deprecate-after-replacement" or not action["replacement"]:
        raise AdaptiveError("EVOLUTION_NOT_APPLICABLE", "selected proposal is advisory and has no safe local transition")
    source = next((item for item in skills if item["id"] == action["target_id"] and item["status"] == "active"), None)
    replacement = next((item for item in skills if item["id"] == action["replacement"] and item["status"] == "active"), None)
    if (not source or not replacement or source["id"] == replacement["id"] or
            proposal_identity(source) != action["target_identity"] or proposal_identity(replacement) != action["replacement_identity"] or
            not set(source["matched_capabilities"]).issubset(set(replacement["matched_capabilities"]))):
        raise AdaptiveError("EVOLUTION_NOT_APPLICABLE", "selected replacement identity or coverage is no longer safe")
    source["status"] = "deprecated"
    changed = [{"id": source["id"], "replacement": replacement["id"]}]
    prior_lifecycle=load_lifecycle(root); lifecycle_exists=lifecycle_path(root).exists()
    lifecycle={"schema":prior_lifecycle["schema"],"events":[*prior_lifecycle["events"]]}
    for item in changed:
        lifecycle["events"].append({
            "action": "evolution-deprecate", "skill": item["id"], "replacement": item["replacement"],
            "plan_sha256": plan["plan_sha256"], "selected_action_sha256": action["action_sha256"],
            "selected_action": action, "approval_payload": approval_payload, "recorded_at": utc_now(),
            "decision": {"gate": "adaptive-evolution-apply", "source": args.source,
                         "action_sha256": approval_sha256, "receipt": decision_receipt,
                         "assurance": "human-decision-receipt"},
        })
    post_lock=finalize_lock({**lock,"skills":skills,"lock_sha256":None})
    pre=mutation_state(root,lock,prior_lifecycle,[source["id"]],lock_exists=True,lifecycle_exists=lifecycle_exists)
    post=intended_post_state(root,lock,post_lock,lifecycle,[source["id"]],
        [{"bundle_sha256":source["bundle_sha256"],"files":source["files"],"preexisting":True}])
    journal=prepare_mutation_journal(root,operation="deprecate",action_sha256=approval_sha256,
        gate="adaptive-evolution-apply",source=args.source,
        approval={"kind":"provider-human-decision","request":decision_request},pre_state=pre,post_state=post)
    journal=authorize_prepared_mutation(root,journal); publish_intended_state(root,journal)
    current=materialized_post_state(journal)["lock"]["value"]
    print_json({"status": "applied-status-only", "deprecated": [item["id"] for item in changed], "lock_sha256": current["lock_sha256"], "external_actions": False})
    return 0


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--root")
    sub = value.add_subparsers(dest="command", required=True)
    record = sub.add_parser("record"); record.add_argument("--skill", required=True); record.add_argument("--outcome", choices=sorted(OUTCOMES), required=True)
    record.add_argument("--run-id", required=True); record.add_argument("--evidence-sha256", required=True)
    workflow = sub.add_parser("record-workflow"); workflow.add_argument("--component", required=True); workflow.add_argument("--outcome", choices=sorted(OUTCOMES), required=True)
    workflow.add_argument("--run-id", required=True); workflow.add_argument("--evidence-sha256", required=True)
    plan = sub.add_parser("plan"); plan.add_argument("--report", required=True); plan.add_argument("--output")
    apply = sub.add_parser("apply"); apply.add_argument("--plan", required=True); apply.add_argument("--action-sha256", required=True)
    apply.add_argument("--approve-digest", required=True); apply.add_argument("--source", required=True); apply.add_argument("--human-decision-receipt")
    return value


def main():
    args = parser().parse_args()
    try:
        root = resolve_root(args.root, __file__)
        if args.command in {"record", "record-workflow"} and (not ID_RE.fullmatch(args.run_id) or not SHA256_RE.fullmatch(args.evidence_sha256)):
            raise AdaptiveError("INVALID_EVOLUTION_EVIDENCE", "run ID and evidence SHA-256 are invalid")
        handler = {"record": command_record, "record-workflow": command_record_workflow, "plan": command_plan, "apply": command_apply}[args.command]
        with mutation_lock(root):
            recover_state_journal(root)
            try:
                return handler(root, args)
            except Exception:
                if mutation_journal_path(root).exists() or mutation_journal_path(root).is_symlink():
                    recover_state_journal(root)
                raise
    except Exception as error:
        return fail(error)


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
