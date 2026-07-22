---
name: use-pxpipe-proxy
description: Install and verify pxpipe as the default Responses provider path for all new Codex Local sessions so eligible whole-request context can be rendered as images before reaching gpt-5.6-sol. This is the primary pxpipe integration. It cannot change the current chat.
---

# Use pxpipe Proxy

This is the primary pxpipe capability. After one installation and a Codex Local
restart, it affects every new local conversation by default; it cannot retrofit
the current chat or remove context already sent to a model.

1. Tell the user that a separate new Codex session will be created and that image transport is lossy. Keep exact IDs, hashes, secrets, active tool calls and recent state in native text according to pxpipe's model policy.
2. Resolve the plugin root from this `SKILL.md`. Run
   `scripts/install-codex-default.sh`, then verify with
   `scripts/status-codex-default.sh`. Do not invoke the optional file MCP as a
   substitute for the provider proxy.
3. The default service accepts only exact model `gpt-5.6-sol`; sibling model names do not inherit the allowlist. A different independently allowlisted model requires the explicit diagnostic path and must not silently change the user default.
4. Restart Codex Local and open the new conversation normally. The installer
   manages the user-level `model_provider = "pxpipe"` and
   `[model_providers.pxpipe]`; project-level provider settings are intentionally
   ignored by Codex. The provider uses Responses, existing Codex authentication,
   and `supports_websockets = false` so requests traverse the proxy. For isolated diagnostics only, use:

```bash
plugins/pxpipe-context/scripts/codex-pxpipe.sh /absolute/project -- <additional Codex arguments>
```

The default macOS LaunchAgent keeps the loopback-only proxy healthy, while the
installer safely backs up and changes only the user-level target key. The
diagnostic launcher passes the supported one-run Codex override
`-c openai_base_url="http://127.0.0.1:PORT/v1"`. Neither path reads Codex
credentials or persists authorization headers.
5. Roll back the default with `scripts/uninstall-codex-default.sh`. It restores
   the recorded provider value before stopping the managed service, preserves
   unrelated config changes and logs, and never stops an unowned proxy. The
   explicit launcher continues to clean only processes it created.
6. For verification, use non-sensitive synthetic bulk context and inspect pxpipe's local event evidence. Require a successful model response, `applied: true`, at least one image block, and at least 10% measured or locally estimated input-token savings. Do not claim that the current chat was compressed.
7. If the provider is unavailable, authentication fails, the port belongs to another process, or no eligible input is profitable, report that exact outcome. Never use the offline MCP result as proof that a Codex provider request passed through pxpipe.

The optional `use-pxpipe-context` Skill remains available only for cold file references that have not already entered a chat.
