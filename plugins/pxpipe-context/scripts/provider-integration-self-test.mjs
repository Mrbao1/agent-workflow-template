#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(pluginRoot, "../..");

const readText = (relative) => readFile(path.join(pluginRoot, relative), "utf8");
const readJson = async (relative) => JSON.parse(await readText(relative));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const manifest = await readJson(".codex-plugin/plugin.json");
assert.match(manifest.description, /provider|proxy/i);
assert.match(manifest.interface.shortDescription, /session|proxy/i);
assert.match(manifest.interface.longDescription, /whole-session|full request|完整请求/i);
assert.match(manifest.interface.longDescription, /optional|auxiliary/i);
assert.match(manifest.interface.defaultPrompt[0], /default|默认/i);

const proxySkill = await readText("skills/use-pxpipe-proxy/SKILL.md");
assert.match(proxySkill, /primary/i);
assert.match(proxySkill, /model_provider/);
assert.match(proxySkill, /model_providers\.pxpipe/);
assert.match(proxySkill, /supports_websockets/);
assert.match(proxySkill, /gpt-5\.6-sol/);
assert.match(proxySkill, /cannot.*current|不能.*当前/i);
assert.match(proxySkill, /scripts\/codex-pxpipe\.sh/);
assert.match(proxySkill, /install-codex-default\.sh/);
assert.match(proxySkill, /status-codex-default\.sh/);
assert.match(proxySkill, /uninstall-codex-default\.sh/);

const fileSkill = await readText("skills/use-pxpipe-context/SKILL.md");
assert.match(fileSkill, /optional|auxiliary|可选|辅助/i);
assert.match(fileSkill, /cold/i);
assert.match(fileSkill, /cannot remove history|不能.*历史/i);

const readme = await readText("README.md");
const primaryHeading = readme.indexOf("## Default whole-session provider proxy (primary)");
const auxiliaryHeading = readme.indexOf("## Offline file MCP (optional)");
assert.ok(primaryHeading >= 0, "README must document the provider proxy as primary");
assert.ok(auxiliaryHeading > primaryHeading, "optional MCP documentation must follow the primary provider path");
assert.match(readme, /model_provider/);
assert.match(readme, /model_providers\.pxpipe/);
assert.match(readme, /new Codex (chat|session)/i);
assert.match(readme, /all new Codex Local sessions/i);

const proxyBundlePath = path.join(pluginRoot, "proxy", "vendor", "pxpipe-node.mjs");
await access(proxyBundlePath, constants.R_OK);

const integrity = await readJson("integrity.json");
assert.equal(integrity.schema, "pxpipe-context-integrity/v3");
assert.equal(integrity.proxy_bundle, "proxy/vendor/pxpipe-node.mjs");
assert.equal(integrity.proxy_bundle_sha256, sha256(await readFile(proxyBundlePath)));
for (const relative of [
  "scripts/codex-pxpipe.sh",
  "scripts/codex-default-config.mjs",
  "scripts/install-codex-default.sh",
  "scripts/uninstall-codex-default.sh",
  "scripts/status-codex-default.sh",
]) {
  const asset = path.join(pluginRoot, relative);
  await access(asset, constants.R_OK | constants.X_OK);
  assert.equal(integrity.provider_assets[relative], sha256(await readFile(asset)));
}

const workflowConfigPath = path.join(repositoryRoot, ".agent", "config.json");
try {
  const workflowConfig = JSON.parse(await readFile(workflowConfigPath, "utf8"));
  const policy = workflowConfig.context_transport.pxpipe;
  assert.equal(policy.primary_mode, "provider-proxy");
  assert.equal(policy.provider_activation, "default-new-local-sessions");
  assert.equal(policy.provider_configuration, "user-model-provider-plus-launch-agent");
  assert.equal(policy.provider_content_scope, "whole-request-eligible-content");
  assert.equal(policy.mcp_role, "optional-cold-reference");
} catch (error) {
  if (!(error instanceof Error) || !Object.hasOwn(error, "code") || error.code !== "ENOENT") throw error;
  // Installed plugin caches intentionally contain the plugin only, not the
  // marketplace repository's Agent Workflow policy files.
}

process.stdout.write("PASS: pxpipe is the default new-session provider path and the file MCP is optional\n");
