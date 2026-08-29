#!/usr/bin/env node

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const proxy = path.join(pluginRoot, "proxy", "vendor", "pxpipe-node.mjs");
const integrity = JSON.parse(await readFile(path.join(pluginRoot, "integrity.json"), "utf8"));
if (integrity.provenance_status === "quarantined") {
  assert.equal(integrity.proxy_bundle, null);
  assert.equal(integrity.proxy_bundle_sha256, null);
  await assert.rejects(readFile(proxy), /ENOENT/);
  process.stdout.write("PASS: quarantined pxpipe exposes no dashboard executable\n");
  process.exit(0);
}
const workspace = await mkdtemp(path.join(os.tmpdir(), "pxpipe-dashboard-auth-"));

async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

async function stop(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((_, reject) => setTimeout(() => reject(new Error("proxy did not stop")), 3_000)),
  ]);
}

async function start(token) {
  const port = await freePort();
  const env = {
    PATH: process.env.PATH ?? "",
    HOME: workspace,
    PORT: String(port),
    HOST: "127.0.0.1",
    PXPIPE_MODELS: "off",
    PXPIPE_LOG: path.join(workspace, `events-${port}.jsonl`),
  };
  if (token) env.PXPIPE_DASHBOARD_TOKEN = token;
  const child = spawn(process.execPath, [proxy], { cwd: pluginRoot, env, stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const base = `http://127.0.0.1:${port}`;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`proxy exited early: ${stderr}`);
    try {
      const response = await fetch(`${base}/proxy-stats`);
      if (response.ok) return { child, base, stderr: () => stderr };
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 40));
  }
  await stop(child);
  throw new Error(`proxy did not become ready: ${stderr}`);
}

const token = randomBytes(32).toString("hex");
let protectedProxy;
let disabledProxy;
try {
  protectedProxy = await start(token);
  const basic = `Basic ${Buffer.from(`pxpipe:${token}`).toString("base64")}`;
  assert.equal((await fetch(`${protectedProxy.base}/api/image-source`)).status, 401);
  assert.equal((await fetch(`${protectedProxy.base}/`, { headers: { authorization: "Basic cHhwaXBlOndyb25n" } })).status, 401);
  const dashboard = await fetch(`${protectedProxy.base}/`, { headers: { authorization: basic } });
  assert.equal(dashboard.status, 200);
  assert.equal(dashboard.headers.get("cache-control"), "no-store");
  assert.equal((await fetch(`${protectedProxy.base}/api/compression`, {
    method: "POST",
    headers: { authorization: basic, origin: "https://evil.example", "content-type": "application/json" },
    body: JSON.stringify({ enabled: false }),
  })).status, 403);
  const sameOrigin = await fetch(`${protectedProxy.base}/api/compression`, {
    method: "POST",
    headers: { authorization: basic, origin: protectedProxy.base, "content-type": "application/json" },
    body: JSON.stringify({ enabled: false }),
  });
  assert.equal(sameOrigin.status, 200);

  disabledProxy = await start(null);
  assert.equal((await fetch(`${disabledProxy.base}/`)).status, 404);
  assert.equal((await fetch(`${disabledProxy.base}/proxy-stats`)).status, 200);
  process.stdout.write("PASS: pxpipe sensitive dashboard routes are disabled or authenticated\n");
} finally {
  if (protectedProxy) await stop(protectedProxy.child);
  if (disabledProxy) await stop(disabledProxy.child);
  await rm(workspace, { recursive: true, force: true });
}
