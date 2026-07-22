#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const serverPath = path.join(pluginRoot, "mcp", "server.mjs");
const workspace = await mkdtemp(path.join(os.tmpdir(), "pxpipe-context-test-"));
const outsideWorkspace = await mkdtemp(path.join(os.tmpdir(), "pxpipe-context-outside-"));
const tamperRoot = await mkdtemp(path.join(os.tmpdir(), "pxpipe-context-tamper-"));
let tampered;
let swapped;
let eofChild;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function pluginFileHashes(root, relative = "") {
  const result = {};
  const entries = await readdir(path.join(root, relative), { withFileTypes: true });
  for (const entry of entries) {
    const child = path.join(relative, entry.name);
    if (entry.isDirectory()) Object.assign(result, await pluginFileHashes(root, child));
    else if (entry.isFile()) result[child.split(path.sep).join("/")] = sha256(await readFile(path.join(root, child)));
  }
  return result;
}

const repoPluginFiles = await pluginFileHashes(pluginRoot);
const agentsBytes = Buffer.from("# Agent Bootstrap\n\nfixture\n", "utf8");
await writeFile(path.join(workspace, "AGENTS.md"), agentsBytes);
await mkdir(path.join(workspace, ".agent"), { recursive: true });
await writeFile(
  path.join(workspace, ".agent", ".workflow-manifest.json"),
  `${JSON.stringify({
    schema: "agent-workflow-install/v3",
    version: "test",
    migration_version: 1,
    source_tree_sha256: "a".repeat(64),
    agent_files: {},
    repo_plugin_files: repoPluginFiles,
    marketplace_entry: { name: "pxpipe-context", sha256: "b".repeat(64) },
    agents_bootstrap: { path: "AGENTS.md", sha256: sha256(agentsBytes) },
  }, null, 2)}\n`,
  "utf8",
);

const child = spawn(process.execPath, [serverPath], {
  cwd: pluginRoot,
  stdio: ["pipe", "pipe", "pipe"],
});
const lines = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
const pending = new Map();
let requestId = 0;
let stderr = "";
child.stderr.setEncoding("utf8");
child.stderr.on("data", (chunk) => { stderr += chunk; });

lines.on("line", (line) => {
  const message = JSON.parse(line);
  if (message.method === "roots/list") {
    child.stdin.write(`${JSON.stringify({
      jsonrpc: "2.0",
      id: message.id,
      result: { roots: [{ uri: pathToFileURL(workspace).href, name: "fixture" }] },
    })}\n`);
    return;
  }
  const waiter = pending.get(message.id);
  if (waiter === undefined) return;
  pending.delete(message.id);
  clearTimeout(waiter.timer);
  if (message.error !== undefined) waiter.reject(new Error(message.error.message));
  else waiter.resolve(message.result);
});

function request(method, params = {}) {
  const id = ++requestId;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`request timed out: ${method}`));
    }, 30_000);
    pending.set(id, { resolve, reject, timer });
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });
}

async function expectReject(action, fragment) {
  let message = "";
  try {
    await action();
  } catch (error) {
    message = error instanceof Error ? error.message : String(error);
  }
  assert.match(message, new RegExp(fragment));
}

try {
  const initialized = await request("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: { roots: { listChanged: true } },
    clientInfo: { name: "pxpipe-context-self-test", version: "1" },
  });
  assert.equal(initialized.serverInfo.name, "pxpipe Context");
  await request("ping");

  const listed = await request("tools/list");
  assert.deepEqual(
    listed.tools.map(({ name }) => name),
    ["pxpipe_analyze_files", "pxpipe_render_files"],
  );

  const referenceText = (
    "architecture guidance describes modules boundaries dependencies recovery and semantic context.\n"
  ).repeat(2_000);
  await writeFile(path.join(workspace, "reference.md"), referenceText);
  const common = {
    workspace_root: workspace,
    paths: ["reference.md"],
    model: "gpt-5.6-sol",
    purpose: "cold-semantic-reference",
  };
  const analyzed = await request("tools/call", {
    name: "pxpipe_analyze_files",
    arguments: common,
  });
  assert.equal(
    analyzed.structuredContent.status,
    "eligible",
    JSON.stringify(analyzed.structuredContent),
  );
  assert.equal(analyzed.structuredContent.provenance.pxpipe_version, "0.9.0");
  assert.equal(analyzed.structuredContent.provenance.attestation_mode, "agent-workflow-v3");
  assert.match(analyzed.structuredContent.analyze_receipt_sha256, /^[0-9a-f]{64}$/);
  assert.ok(!analyzed.content[0].text.includes("architecture guidance describes modules"));

  await writeFile(path.join(workspace, "AGENTS.md"), "drifted bootstrap\n", "utf8");
  await expectReject(
    () => request("tools/call", {
      name: "pxpipe_analyze_files",
      arguments: common,
    }),
    "AGENTS bootstrap differs",
  );
  await writeFile(path.join(workspace, "AGENTS.md"), agentsBytes);

  // The immediate predecessor manifest remains compatible during migration.
  const workflowManifestPath = path.join(workspace, ".agent", ".workflow-manifest.json");
  const workflowV3 = JSON.parse(await readFile(workflowManifestPath, "utf8"));
  const workflowV2 = { ...workflowV3, schema: "agent-workflow-install/v2" };
  delete workflowV2.agents_bootstrap;
  await writeFile(workflowManifestPath, `${JSON.stringify(workflowV2, null, 2)}\n`, "utf8");
  const legacyAnalyzed = await request("tools/call", {
    name: "pxpipe_analyze_files",
    arguments: common,
  });
  assert.equal(legacyAnalyzed.structuredContent.status, "eligible");
  await writeFile(workflowManifestPath, `${JSON.stringify(workflowV3, null, 2)}\n`, "utf8");

  const rendered = await request("tools/call", {
    name: "pxpipe_render_files",
    arguments: {
      ...common,
      expected_source_sha256: analyzed.structuredContent.source_sha256,
      acknowledge_lossy: true,
    },
  });
  const images = rendered.content.filter(({ type }) => type === "image");
  assert.ok(images.length >= 1 && images.length <= 8);
  assert.ok(Buffer.from(images[0].data, "base64").subarray(0, 8).equals(
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  ));

  // Attack 1: redefining a system directory as workspace_root must not grant access.
  await expectReject(
    () => request("tools/call", {
      name: "pxpipe_analyze_files",
      arguments: { ...common, workspace_root: "/etc", paths: ["hosts"] },
    }),
    "trusted root|forbidden|not bound",
  );

  // Attack 2: redefining the workflow control directory as a root must not bypass path policy.
  await expectReject(
    () => request("tools/call", {
      name: "pxpipe_analyze_files",
      arguments: { ...common, workspace_root: path.join(workspace, ".agent"), paths: [".workflow-manifest.json"] },
    }),
    "trusted root|forbidden|not bound",
  );

  await writeFile(path.join(workspace, "reference.md"), `${referenceText}changed\n`);
  await expectReject(
    () => request("tools/call", {
      name: "pxpipe_render_files",
      arguments: {
        ...common,
        expected_source_sha256: analyzed.structuredContent.source_sha256,
        acknowledge_lossy: true,
      },
    }),
    "source changed after analysis",
  );

  await expectReject(
    () => request("tools/call", {
      name: "pxpipe_analyze_files",
      arguments: { ...common, paths: ["../outside.md"] },
    }),
    "invalid segment|escapes workspace_root",
  );

  await writeFile(path.join(workspace, ".env"), "SAFE_TEST_VALUE=placeholder\n");
  await expectReject(
    () => request("tools/call", {
      name: "pxpipe_analyze_files",
      arguments: { ...common, paths: [".env"] },
    }),
    "protected or sensitive",
  );

  await writeFile(path.join(outsideWorkspace, "outside.md"), "outside boundary\n");
  await symlink(path.join(outsideWorkspace, "outside.md"), path.join(workspace, "escape.md"));
  await expectReject(
    () => request("tools/call", {
      name: "pxpipe_analyze_files",
      arguments: { ...common, paths: ["escape.md"] },
    }),
    "path chain|escapes",
  );

  // Attack 3: a symlinked ancestor cannot redirect a previously valid
  // relative path outside the trusted root.
  await writeFile(path.join(outsideWorkspace, "ancestor.md"), referenceText);
  await symlink(outsideWorkspace, path.join(workspace, "ancestor-swap"));
  await expectReject(
    () => request("tools/call", {
      name: "pxpipe_analyze_files",
      arguments: { ...common, paths: ["ancestor-swap/ancestor.md"] },
    }),
    "path chain|escaped|boundary",
  );

  await writeFile(path.join(workspace, "binary.dat"), Buffer.from([0x41, 0x00, 0x42]));
  await expectReject(
    () => request("tools/call", {
      name: "pxpipe_analyze_files",
      arguments: { ...common, paths: ["binary.dat"] },
    }),
    "appears to be binary",
  );

  // Attack 4: a project-side forged plugin digest cannot impersonate the
  // verified globally installed MCP bytes.
  const forgedWorkflow = JSON.parse(await readFile(workflowManifestPath, "utf8"));
  forgedWorkflow.repo_plugin_files["integrity.json"] = "0".repeat(64);
  await writeFile(workflowManifestPath, `${JSON.stringify(forgedWorkflow, null, 2)}\n`, "utf8");
  await expectReject(
    () => request("tools/call", {
      name: "pxpipe_analyze_files",
      arguments: common,
    }),
    "installed plugin file differs.*integrity.json|loaded MCP does not match.*integrity.json",
  );
  await writeFile(workflowManifestPath, `${JSON.stringify(workflowV3, null, 2)}\n`, "utf8");

  // A normal project uses the globally installed plugin directly. The host
  // MCP Root is the session authority; neither Git nor a project-local plugin
  // copy/workflow manifest is required.
  await rm(path.join(workspace, ".agent"), { recursive: true, force: true });
  const genericAnalyzed = await request("tools/call", {
    name: "pxpipe_analyze_files",
    arguments: common,
  });
  assert.equal(genericAnalyzed.structuredContent.status, "eligible");
  assert.equal(genericAnalyzed.structuredContent.provenance.attestation_mode, "host-root-only");
  assert.equal(genericAnalyzed.structuredContent.provenance.workflow_manifest_sha256, undefined);

  child.stdin.end();
  const exitCode = await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((_, reject) => setTimeout(() => reject(new Error("server did not exit after stdin EOF")), 2_000)),
  ]);
  assert.equal(exitCode, 0, stderr);

  const tamperedPlugin = path.join(tamperRoot, "pxpipe-context");
  await cp(pluginRoot, tamperedPlugin, { recursive: true });
  const tamperedBundle = path.join(tamperedPlugin, "mcp", "vendor", "pxpipe-runtime.mjs");
  const runtimeBytes = await readFile(tamperedBundle);
  runtimeBytes[runtimeBytes.length - 1] ^= 1;
  await writeFile(tamperedBundle, runtimeBytes);
  tampered = spawn(process.execPath, [path.join(tamperedPlugin, "mcp", "server.mjs")], {
    cwd: tamperedPlugin,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const tamperedLines = readline.createInterface({ input: tampered.stdout, crlfDelay: Infinity });
  const tamperedPending = new Map();
  tamperedLines.on("line", (line) => {
    const message = JSON.parse(line);
    if (message.method === "roots/list") {
      tampered.stdin.write(`${JSON.stringify({
        jsonrpc: "2.0",
        id: message.id,
        result: { roots: [{ uri: pathToFileURL(workspace).href, name: "fixture" }] },
      })}\n`);
      return;
    }
    const waiter = tamperedPending.get(message.id);
    if (waiter === undefined) return;
    tamperedPending.delete(message.id);
    if (message.error !== undefined) waiter.reject(new Error(message.error.message));
    else waiter.resolve(message.result);
  });
  const tamperedRequest = (id, method, params = {}) => new Promise((resolve, reject) => {
    tamperedPending.set(id, { resolve, reject });
    tampered.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });
  await tamperedRequest(1, "initialize", {
    protocolVersion: "2025-11-25",
    capabilities: { roots: { listChanged: true } },
  });
  await expectReject(
    () => tamperedRequest(2, "tools/call", {
      name: "pxpipe_analyze_files",
      arguments: common,
    }),
    "runtime integrity check failed",
  );
  tampered.stdin.end();
  const tamperedExit = await Promise.race([
    new Promise((resolve) => tampered.once("exit", resolve)),
    new Promise((_, reject) => setTimeout(() => reject(new Error("tampered server did not exit")), 2_000)),
  ]);
  assert.equal(tamperedExit, 0);

  // Attack 5: once startup has verified the worker and runtime, replacing their
  // paths cannot change the bytes executed by a later request.
  const swapPlugin = path.join(tamperRoot, "pxpipe-context-swap");
  const swapSentinel = path.join(tamperRoot, "unverified-worker-executed");
  await cp(pluginRoot, swapPlugin, { recursive: true });
  swapped = spawn(process.execPath, [path.join(swapPlugin, "mcp", "server.mjs")], {
    cwd: swapPlugin,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const swapLines = readline.createInterface({ input: swapped.stdout, crlfDelay: Infinity });
  const swapPending = new Map();
  swapLines.on("line", (line) => {
    const message = JSON.parse(line);
    if (message.method === "roots/list") {
      swapped.stdin.write(`${JSON.stringify({
        jsonrpc: "2.0",
        id: message.id,
        result: { roots: [{ uri: pathToFileURL(workspace).href, name: "fixture" }] },
      })}\n`);
      return;
    }
    const waiter = swapPending.get(message.id);
    if (waiter === undefined) return;
    swapPending.delete(message.id);
    clearTimeout(waiter.timer);
    if (message.error !== undefined) waiter.reject(new Error(message.error.message));
    else waiter.resolve(message.result);
  });
  const swapRequest = (id, method, params = {}) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      swapPending.delete(id);
      reject(new Error(`swap request timed out: ${method}`));
    }, 30_000);
    swapPending.set(id, { resolve, reject, timer });
    swapped.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });
  await swapRequest(1, "initialize", {
    protocolVersion: "2025-11-25",
    capabilities: { roots: { listChanged: true } },
  });
  await writeFile(
    path.join(swapPlugin, "mcp", "worker.mjs"),
    `import { writeFileSync } from "node:fs"; writeFileSync(${JSON.stringify(swapSentinel)}, "bad"); throw new Error("unverified worker");\n`,
    "utf8",
  );
  await writeFile(
    path.join(swapPlugin, "mcp", "vendor", "pxpipe-runtime.mjs"),
    "throw new Error('unverified runtime');\n",
    "utf8",
  );
  const swapAnalyzed = await swapRequest(2, "tools/call", {
    name: "pxpipe_analyze_files",
    arguments: common,
  });
  assert.equal(swapAnalyzed.structuredContent.status, "eligible");
  await assert.rejects(readFile(swapSentinel), /ENOENT/);
  swapped.stdin.end();
  const swapExit = await Promise.race([
    new Promise((resolve) => swapped.once("exit", resolve)),
    new Promise((_, reject) => setTimeout(() => reject(new Error("swap server did not exit")), 2_000)),
  ]);
  assert.equal(swapExit, 0);

  // EOF must terminate an active isolated render rather than waiting for the
  // render timeout. The delay hook is accepted only in this explicit self-test mode.
  eofChild = spawn(process.execPath, [serverPath], {
    cwd: pluginRoot,
    env: {
      ...process.env,
      PXPIPE_CONTEXT_SELF_TEST: "1",
      PXPIPE_CONTEXT_SELF_TEST_DELAY_MS: "10000",
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const eofLines = readline.createInterface({ input: eofChild.stdout, crlfDelay: Infinity });
  const eofPending = new Map();
  eofLines.on("line", (line) => {
    const message = JSON.parse(line);
    if (message.method === "roots/list") {
      eofChild.stdin.write(`${JSON.stringify({
        jsonrpc: "2.0",
        id: message.id,
        result: { roots: [{ uri: pathToFileURL(workspace).href, name: "fixture" }] },
      })}\n`);
      return;
    }
    const waiter = eofPending.get(message.id);
    if (waiter === undefined) return;
    eofPending.delete(message.id);
    clearTimeout(waiter.timer);
    if (message.error !== undefined) waiter.reject(new Error(message.error.message));
    else waiter.resolve(message.result);
  });
  const eofRequest = (id, method, params = {}) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      eofPending.delete(id);
      reject(new Error(`EOF fixture request timed out: ${method}`));
    }, 5_000);
    eofPending.set(id, { resolve, reject, timer });
    eofChild.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  });
  await eofRequest(1, "initialize", {
    protocolVersion: "2025-11-25",
    capabilities: { roots: { listChanged: true } },
  });
  eofChild.stdin.write(`${JSON.stringify({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "pxpipe_analyze_files", arguments: common },
  })}\n`);
  await new Promise((resolve) => setTimeout(resolve, 300));
  eofChild.stdin.end();
  const eofExit = await Promise.race([
    new Promise((resolve) => eofChild.once("exit", resolve)),
    new Promise((_, reject) => setTimeout(() => reject(new Error("server did not stop active render after EOF")), 2_000)),
  ]);
  assert.equal(eofExit, 0);
  process.stdout.write("PASS: pxpipe-context MCP protocol, render boundary, drift rejection and clean EOF exit\n");
} finally {
  if (child.exitCode === null) child.kill("SIGTERM");
  if (tampered !== undefined && tampered.exitCode === null) tampered.kill("SIGTERM");
  if (swapped !== undefined && swapped.exitCode === null) swapped.kill("SIGTERM");
  if (eofChild !== undefined && eofChild.exitCode === null) eofChild.kill("SIGTERM");
  await rm(workspace, { recursive: true, force: true });
  await rm(outsideWorkspace, { recursive: true, force: true });
  await rm(tamperRoot, { recursive: true, force: true });
}
