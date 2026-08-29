#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants, realpathSync } from "node:fs";
import { lstat, open, opendir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const hex64 = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_TREE_BYTES = 64 * 1024 * 1024;
const MAX_TREE_ENTRIES = 4096;
const MAX_TREE_DEPTH = 16;
const MAX_RELATIVE_BYTES = 4096;

async function readStable(relative, label) {
  const target = path.join(root, ...relative.split("/"));
  const before = await lstat(target, { bigint: true });
  assert.equal(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n
    && before.size >= 0n && before.size <= BigInt(MAX_FILE_BYTES), true, `${label} bounded stable regular file`);
  const descriptor = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await descriptor.stat({ bigint: true });
    assert.equal(opened.dev === before.dev && opened.ino === before.ino && opened.nlink === 1n
      && opened.size === before.size, true, `${label} identity`);
    const chunks = [];
    let offset = 0, expectedSize = Number(opened.size);
    while (offset < expectedSize) {
      const chunk = Buffer.allocUnsafe(Math.min(65536, expectedSize - offset));
      const { bytesRead } = await descriptor.read(chunk, 0, chunk.length, offset);
      assert.notEqual(bytesRead, 0, `${label} truncated while reading`);
      chunks.push(chunk.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const bytes = Buffer.concat(chunks, offset);
    const after = await descriptor.stat({ bigint: true });
    assert.equal(after.dev === opened.dev && after.ino === opened.ino && after.size === BigInt(bytes.length)
      && after.mtimeNs === opened.mtimeNs && after.ctimeNs === opened.ctimeNs, true, `${label} changed while reading`);
    return bytes;
  } finally { await descriptor.close(); }
}

async function treeRecords(relative = "", depth = 0, state = { entries: 0, bytes: 0 }) {
  assert.equal(depth <= MAX_TREE_DEPTH, true, "plugin tree exceeds depth bound");
  const records = [];
  const entries = [];
  const target = path.join(root, relative);
  const directoryBefore = await lstat(target, { bigint: true });
  assert.equal(directoryBefore.isDirectory() && !directoryBefore.isSymbolicLink(), true, "plugin tree directory is unsafe");
  const directory = await opendir(target);
  for await (const entry of directory) {
    state.entries += 1;
    assert.equal(state.entries <= MAX_TREE_ENTRIES, true, "plugin tree exceeds entry bound");
    entries.push(entry);
  }
  for (const entry of entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
    const child = path.join(relative, entry.name);
    const portable = child.split(path.sep).join("/");
    assert.equal(Buffer.byteLength(portable, "utf8") <= MAX_RELATIVE_BYTES, true, "plugin tree path exceeds bound");
    if (portable === "integrity.json") continue;
    assert.equal(entry.isSymbolicLink(), false, `plugin tree symlink: ${portable}`);
    if (entry.isDirectory()) records.push(...await treeRecords(child, depth + 1, state));
    else if (entry.isFile()) {
      const bytes = await readStable(portable, portable);
      state.bytes += bytes.length;
      assert.equal(state.bytes <= MAX_TREE_BYTES, true, "plugin tree exceeds aggregate byte bound");
      records.push([portable, sha256(bytes)]);
    } else assert.fail(`unsupported plugin tree entry: ${portable}`);
  }
  const directoryAfter = await lstat(target, { bigint: true });
  assert.equal(directoryAfter.dev === directoryBefore.dev && directoryAfter.ino === directoryBefore.ino
    && directoryAfter.mtimeNs === directoryBefore.mtimeNs && directoryAfter.ctimeNs === directoryBefore.ctimeNs,
  true, "plugin tree directory changed during traversal");
  return records;
}

async function safeFile(relative, expected, label) {
  assert.match(relative, /^[A-Za-z0-9._/-]+$/, `${label} path`);
  assert.equal(relative.includes(".."), false, `${label} traversal`);
  assert.equal(sha256(await readStable(relative, label)), expected, `${label} digest`);
}

export async function verifyIntegrity({ allowQuarantined = false } = {}) {
  const integrity = JSON.parse((await readStable("integrity.json", "integrity receipt")).toString("utf8"));
  const manifest = JSON.parse((await readStable(".codex-plugin/plugin.json", "plugin manifest")).toString("utf8"));
  assert.equal(integrity.schema, "pxpipe-context-integrity/v4");
  assert.equal(integrity.plugin_version, manifest.version);
  assert.equal(hex64(integrity.plugin_tree_sha256), true);
  const records = await treeRecords();
  const repeatedRecords = await treeRecords();
  assert.deepEqual(repeatedRecords, records, "plugin tree changed during integrity verification");
  assert.equal(sha256(Buffer.from(JSON.stringify(records), "utf8")), integrity.plugin_tree_sha256, "plugin tree digest");
  assert.equal(integrity.pxpipe_package, "pxpipe-proxy");
  assert.equal(typeof integrity.pxpipe_version, "string");
  assert.equal(integrity.source_repository, "https://github.com/teamchong/pxpipe.git");
  const providerAssetKeys = [
    "scripts/codex-default-config.mjs", "scripts/codex-pxpipe.sh", "scripts/install-codex-default.sh",
    "scripts/status-codex-default.sh", "scripts/uninstall-codex-default.sh",
  ];
  assert.deepEqual(Object.keys(integrity.provider_assets).sort(), providerAssetKeys);
  for (const relative of providerAssetKeys) await safeFile(relative, integrity.provider_assets[relative], relative);
  assert.equal(integrity.provenance_status, "quarantined",
    "verified activation requires an external reproducible-build and license-review trust root");
  for (const field of ["source_commit", "source_tree", "source_lockfile", "source_lockfile_sha256",
    "esbuild_main_sha256", "source_package_sha256", "runtime_bundle", "runtime_bundle_sha256",
    "proxy_bundle", "proxy_bundle_sha256"]) assert.equal(integrity[field], null, `quarantined field ${field}`);
  assert.equal(records.some(([relative]) => relative.startsWith("mcp/vendor/")
    || relative.startsWith("proxy/vendor/") || relative.startsWith("dist/")), false,
  "quarantined tree must not redistribute dist or opaque vendor bundles");
  if (!allowQuarantined) throw new Error("pxpipe plugin is quarantined until rebuilt from verified source and toolchain inputs");
  return { integrity, records };
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  await verifyIntegrity({ allowQuarantined: process.argv.slice(2).includes("--allow-quarantined") });
  process.stdout.write("PASS: pxpipe integrity quarantined\n");
}
