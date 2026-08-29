#!/usr/bin/env python3
"""Provider-neutral runtime, optional transport, and authority regressions."""

from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
AGENT_DIR = ROOT / ".agent"
sys.path.insert(0, str(AGENT_DIR / "scripts"))

import agentctl


def main() -> int:
    live_config = json.loads((AGENT_DIR / "config.json").read_text(encoding="utf-8"))
    seed_config = json.loads((AGENT_DIR / "assets/fresh-state/v1/config.json").read_text(encoding="utf-8"))
    for label, config in (("live", live_config), ("fresh", seed_config)):
        if config.get("context_transport") != {"default": "native"}:
            raise AssertionError(f"{label} config is not native-only")
        host_identity = config.get("runtime", {}).get("host_runner_identity")
        selected_model = config.get("agent_control", {}).get("default_model")
        if config.get("guardrails_ready") is False:
            if host_identity is not None:
                raise AssertionError(f"{label} idle config granted a default host-runner exemption")
            if selected_model is not None:
                raise AssertionError(f"{label} idle config selected a default model")
        else:
            if host_identity is not None and not agentctl.valid_host_runner_identity_contract(host_identity):
                raise AssertionError(f"{label} config stored an invalid explicit host-runner identity")
            if selected_model is not None and not agentctl.valid_model_id(selected_model):
                raise AssertionError(f"{label} config stored an invalid explicit model selection")

    if not agentctl.valid_context_transport_policy({"default": "native"}, None):
        raise AssertionError("fully absent optional extension was rejected")
    if agentctl.valid_context_transport_policy({"default": "native", "pxpipe": {"enabled": False}}, None):
        raise AssertionError("disabled provenance-free extension stub was accepted")

    model = "provider-neutral/model-v1"
    extension = {
        "default": "native",
        "pxpipe": {
            "enabled": True,
            "activation": "explicit-opt-in",
            "plugin_name": "pxpipe-context",
            "plugin_version": "0.1.0+codex.20260721210500",
            "models": [model],
            "primary_mode": "provider-proxy",
            "provider_activation": "default-new-local-sessions",
            "provider_configuration": "user-model-provider-plus-launch-agent",
            "provider_content_scope": "whole-request-eligible-content",
            "mcp_role": "optional-cold-reference",
            "selection": "analyze-then-render",
            "content_scope": "new-cold-reference-only",
            "session_boundary": "plugin-load-requires-new-chat",
            "fallback": "native",
            "provenance": {
                "status": "verified",
                "manifest_sha256": "a" * 64,
                "verified_by": "installed-extension-manifest",
            },
        },
    }
    if not agentctl.valid_context_transport_policy(extension, model):
        raise AssertionError("explicit provenance-verified extension state was rejected")
    spoof_extension = json.loads(json.dumps(extension))
    spoof_extension["pxpipe"]["provenance"]["status"] = "caller-asserted"
    if agentctl.valid_context_transport_policy(spoof_extension, model):
        raise AssertionError("caller-asserted extension provenance was accepted")

    host = {"pid": 4101, "start_time": "linux:9001", "executable": "/opt/neutral-host/bin/session-host"}
    runner = {"pid": 4102, "start_time": "linux:9002", "executable": "/opt/neutral-host/bin/tool-worker"}
    snapshot = {**runner, "ppid": host["pid"]}
    ancestors = {host["pid"]: host}
    original_load_json = agentctl.load_json
    try:
        agentctl.load_json = lambda _path: {"runtime": {"host_runner_identity": None}}
        if agentctl.host_runner_peer(snapshot, ancestors):
            raise AssertionError("default-null contract exempted a runner")
        if agentctl.host_runner_peer(
            {"pid": 7, "ppid": 6, "start_time": "linux:7", "executable": "/tmp/node_repl"},
            {6: {"pid": 6, "start_time": "linux:6", "executable": "/tmp/codex"}},
        ):
            raise AssertionError("literal executable names created an exemption")

        contract = {"schema": "agent-host-runner-identity/v1", "authority": "neutral.desktop", "host": host, "runner": runner}
        agentctl.load_json = lambda _path: {"runtime": {"host_runner_identity": contract}}
        if not agentctl.valid_host_runner_identity_contract(contract):
            raise AssertionError("valid provider-neutral runner contract was rejected")
        if not agentctl.host_runner_peer(snapshot, ancestors):
            raise AssertionError("custom non-Codex runner contract was not recognized")
        for spoof in (
            {**snapshot, "pid": 9999},
            {**snapshot, "start_time": "linux:9999"},
            {**snapshot, "executable": "/opt/neutral-host/bin/other-worker"},
        ):
            if agentctl.host_runner_peer(spoof, ancestors):
                raise AssertionError(f"spoofed runner identity was exempted: {spoof}")
        if agentctl.host_runner_peer(snapshot, {host["pid"]: {**host, "start_time": "linux:9999"}}):
            raise AssertionError("spoofed host start identity was exempted")
        bad_authority = dict(contract)
        bad_authority["authority"] = "Codex Local"
        if agentctl.valid_host_runner_identity_contract(bad_authority):
            raise AssertionError("invalid configured authority was accepted")
    finally:
        agentctl.load_json = original_load_json

    documents = {
        "INDEX": (AGENT_DIR / "INDEX.md").read_text(encoding="utf-8"),
        "README": (ROOT / "README.md").read_text(encoding="utf-8"),
        "SECURITY": (ROOT / "SECURITY.md").read_text(encoding="utf-8"),
    }
    required = {
        "INDEX": ("advisory clarification", "Every authoritative mutation", "There is no local-release opt-in"),
        "README": ("caller 自制 JSON 只算 advisory，不能授权", "默认值为"),
        "SECURITY": (
            "Caller text and project-writable receipt files are not authorization",
            "latest actually published supported `4.x` tag",
            "Before the first `4.x` tag is published, only current `main` is supported",
            "fails closed",
        ),
    }
    for label, snippets in required.items():
        missing = [snippet for snippet in snippets if snippet not in documents[label]]
        if missing:
            raise AssertionError(f"{label} authority policy drifted; missing {missing}")

    print("NEUTRALITY CONTRACTS PASS")
    return 0


if __name__ == "__main__":
    from workflowlib.publication import discover_project_root,run_cli
    raise SystemExit(run_cli(discover_project_root(),main))
