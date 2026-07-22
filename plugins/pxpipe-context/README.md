# pxpipe for Codex Plugin

This plugin integrates the original `pxpipe-proxy` request transformer with Codex. Its primary capability installs pxpipe as the **default transport for all new Codex Local sessions** on macOS. Eligible bulky context is rendered as PNG blocks before the request leaves the machine.

The plugin also keeps the original read-only file MCP as an optional auxiliary. That MCP can prevent newly selected cold files from entering a chat as bulk text, but it cannot rewrite existing chat history or replace the Codex provider.

## Default whole-session provider proxy (primary)

Build the plugin from a trusted `pxpipe-proxy` checkout:

```bash
node plugins/pxpipe-context/scripts/build-runtime.mjs \
  --pxpipe-source /absolute/path/to/pxpipe
```

The build vendors source-bound proxy, default-service, rollback, status, launcher,
and optional export assets.

- the full pxpipe Node Responses proxy;
- the Codex launcher;
- the bounded export runtime used by the optional file MCP.

Install the default once, then restart Codex Local:

```bash
plugins/pxpipe-context/scripts/install-codex-default.sh
plugins/pxpipe-context/scripts/status-codex-default.sh
```

The installer registers a loopback-only macOS LaunchAgent, verifies a
pxpipe-shaped health response, backs up the user config, and manages a
user-level `model_provider = "pxpipe"` plus `[model_providers.pxpipe]` in
`~/.codex/config.toml`. The provider uses the Responses wire API and existing
Codex authentication, with WebSockets disabled so every request traverses the
HTTP proxy. Every new conversation then uses pxpipe without a special command.
Roll back with:

```bash
plugins/pxpipe-context/scripts/uninstall-codex-default.sh
```

The explicit launcher remains available for isolated diagnostics:

```bash
plugins/pxpipe-context/scripts/codex-pxpipe.sh /absolute/project -- --no-alt-screen
```

The launcher:

1. resolves the Codex CLI without reading its credentials;
2. starts pxpipe on `127.0.0.1`, or safely reuses a healthy existing pxpipe;
3. enables the exact configured model, defaulting to `gpt-5.6-sol`;
4. starts Codex with the supported one-run override `-c openai_base_url="http://127.0.0.1:47821/v1"`;
5. forwards the Codex exit status and signals;
6. cleans only the proxy process it created.

It fails closed when the port belongs to another process, pxpipe never becomes healthy, model enablement fails, or the Codex binary is unavailable. A pre-existing healthy pxpipe is never stopped by the launcher.

The default installer never writes provider settings to project
`.codex/config.toml`: Codex ignores provider redirection there. It writes only
the user-level managed provider blocks after the local service is healthy and
never reads `auth.json`, API keys, authorization headers, or request bodies.
The proxy forwards Codex's existing bearer authentication to the ChatGPT Codex
Responses backend without persisting it. The explicit launcher still uses a
one-run `openai_base_url` override and does not edit configuration.

Important boundary: installation cannot hot-swap a chat that is already
running. Restart Codex Local and open a new conversation. Existing context
tokens in the current chat cannot be reclaimed.

## Verify whole-session compression

Use a non-sensitive synthetic project and start a fresh Codex session normally,
without invoking `cpx` or the explicit launcher. Verification must establish all
of the following from the response and local pxpipe event evidence:

- the request reached the loopback Responses proxy;
- pxpipe reported that transformation was applied;
- at least one eligible historical block became an image;
- measured or locally estimated input-token savings are positive (the Agent Workflow acceptance gate uses at least 10%);
- recent messages and open or malformed tool state remained native text;
- the managed LaunchAgent remains healthy for subsequent new conversations.

An offline export or MCP render is not evidence that a Codex provider request used pxpipe.

## Offline file MCP (optional)

Each newly opened Codex chat can optionally call:

- `pxpipe_analyze_files`: estimate a bounded image rendering without returning source text;
- `pxpipe_render_files`: verify the analyzed source SHA-256 and return PNG image blocks plus a supplemental factsheet.

The MCP is for explicitly selected cold, non-authoritative reference files only. It does not bind a port, start a proxy, access the network, persist rendered files, remove history, or change model transport. Codex owns its STDIO lifecycle.

The MCP trusts standard MCP Roots returned by the host. If a host does not advertise roots, configure an explicit startup allowlist before the new chat. System roots and control directories such as `/etc`, `.git`, `.agent` and `.codex` remain forbidden.

## Install and reload

From the canonical `agent-workflow-template` checkout:

```bash
codex plugin marketplace add /absolute/path/to/agent-workflow-template
codex plugin add pxpipe-context@agent-workflow-template
```

After a source update, use the plugin cachebuster helper, reinstall the same marketplace entry, and open a new Codex chat. Plugin discovery does not hot-load changed skills or MCP servers into an existing chat.

Run both plugin checks after a build:

```bash
node plugins/pxpipe-context/scripts/provider-integration-self-test.mjs
node plugins/pxpipe-context/scripts/self-test.mjs
```

The protocol self-test covers MCP roots, bounded rendering, drift rejection, tampering and clean EOF shutdown. The provider integration self-test verifies that the plugin presents the whole-session proxy as primary, keeps the file MCP optional, and binds the launcher and full proxy bundle in `integrity.json`.
