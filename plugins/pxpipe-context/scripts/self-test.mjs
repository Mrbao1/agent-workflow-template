#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalJson, validateVerifiedV5Anchor } from "../mcp/project-attestation.mjs";

const pluginRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
const repositoryRoot=path.resolve(pluginRoot,"../..");
const readJson=async (file) => JSON.parse(await readFile(file,"utf8"));
const sha256=(value) => createHash("sha256").update(value).digest("hex");

const integrity=await readJson(path.join(pluginRoot,"integrity.json"));
assert.equal(integrity.provenance_status,"quarantined");
assert.equal(integrity.runtime_bundle,null);
assert.equal(integrity.proxy_bundle,null);
await assert.rejects(access(path.join(pluginRoot,"mcp/vendor/pxpipe-runtime.mjs")),/ENOENT/);
await assert.rejects(access(path.join(pluginRoot,"proxy/vendor/pxpipe-node.mjs")),/ENOENT/);
const marketplace=await readJson(path.join(repositoryRoot,".agents/plugins/marketplace.json"));
assert.deepEqual(marketplace.plugins,[]);

const serverSource=await readFile(path.join(pluginRoot,"mcp/server.mjs"),"utf8");
assert.doesNotMatch(serverSource,/host-root-only/);
assert.match(serverSource,/requires an exact agent-workflow-install\/v5 manifest/);
const verifier=path.join(pluginRoot,"scripts/verify-integrity.mjs");
const audit=spawnSync(process.execPath,[verifier,"--allow-quarantined"],{cwd:pluginRoot,encoding:"utf8"});
assert.equal(audit.status,0,audit.stderr);
const activation=spawnSync(process.execPath,[verifier],{cwd:pluginRoot,encoding:"utf8"});
assert.notEqual(activation.status,0);
assert.match(activation.stderr,/quarantined/);

const server=spawnSync(process.execPath,[path.join(pluginRoot,"mcp/server.mjs")],{
  cwd:pluginRoot,encoding:"utf8",input:`${JSON.stringify({jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2025-11-25",capabilities:{}}})}\n`,
  env:{...process.env,PXPIPE_MCP_MODELS:"provider/model"},timeout:10_000,
});
assert.equal(server.status,0,server.stderr);
const response=JSON.parse(server.stdout.trim());
assert.equal(response.error?.code,-32603);
assert.match(response.error?.message ?? "",/quarantined/);

const entry={name:"pxpipe-context",source:{source:"local",path:"./plugins/pxpipe-context"}};
const binding={
  name:"pxpipe-context",provenance_status:"verified",files:{"mcp/server.mjs":"a".repeat(64)},
  marketplace_entry_sha256:sha256(Buffer.from(canonicalJson(entry),"utf8")),
};
const agents={path:"AGENTS.md",sha256:"b".repeat(64)};
const claude={path:"CLAUDE.md",sha256:"c".repeat(64)};
const source={
  schema:"agent-workflow-install/v5",version:"4.0.0",migration_version:42,agent_root_mode:0o700,agent_files:{},agent_modes:{},
  pxpipe:binding,agents_bootstrap_sha256:agents.sha256,claude_bootstrap_sha256:claude.sha256,
};
const workflow={
  schema:source.schema,version:source.version,migration_version:source.migration_version,agent_root_mode:source.agent_root_mode,
  source_tree_sha256:sha256(Buffer.from(canonicalJson(source),"utf8")),agent_files:{},agent_modes:{},
  pxpipe:binding,agents_bootstrap:agents,claude_bootstrap:claude,
};
const anchoredMarketplace={plugins:[entry]};
assert.deepEqual(validateVerifiedV5Anchor(workflow,anchoredMarketplace).recorded,binding.files);
for (const schema of ["agent-workflow-install/v2","agent-workflow-install/v3"]) {
  assert.throws(() => validateVerifiedV5Anchor({...workflow,schema},anchoredMarketplace),/exact verified v5/);
}
assert.throws(() => validateVerifiedV5Anchor({...workflow,pxpipe:{...binding,provenance_status:"disabled"}},anchoredMarketplace),/verified v5 provenance/);
assert.throws(() => validateVerifiedV5Anchor({...workflow,source_tree_sha256:"d".repeat(64)},anchoredMarketplace),/source tree binding/);
assert.throws(() => validateVerifiedV5Anchor(workflow,{plugins:[]}),/marketplace entry/);
assert.throws(() => validateVerifiedV5Anchor({...workflow,unexpected:true},anchoredMarketplace),/exact verified v5/);

process.stdout.write("PASS: pxpipe quarantine and exact v5-only project anchor\n");
