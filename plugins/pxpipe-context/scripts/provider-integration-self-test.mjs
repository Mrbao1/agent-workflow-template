#!/usr/bin/env node

import assert from "node:assert/strict";
import { chmod, cp, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canonicalJson, validateVerifiedV5Anchor } from "../mcp/project-attestation.mjs";

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(pluginRoot, "../..");
const readText = (relative) => readFile(path.join(pluginRoot, relative), "utf8");
const readJson = async (relative) => JSON.parse(await readText(relative));

const manifest = await readJson(".codex-plugin/plugin.json");
assert.match(manifest.description, /quarantined/i);
assert.match(manifest.interface.shortDescription, /quarantined/i);
assert.match(manifest.interface.longDescription, /blocked|quarantined/i);

const marketplace = JSON.parse(await readFile(path.join(repositoryRoot, ".agents/plugins/marketplace.json"), "utf8"));
assert.deepEqual(marketplace.plugins, []);

const integrity = await readJson("integrity.json");
assert.equal(integrity.schema, "pxpipe-context-integrity/v4");
assert.equal(integrity.provenance_status, "quarantined");
assert.equal(integrity.plugin_version, manifest.version);
assert.equal(integrity.source_repository, "https://github.com/teamchong/pxpipe.git");
assert.equal(integrity.source_commit, null);
assert.equal(integrity.source_tree, null);
for (const field of ["source_package_sha256", "runtime_bundle", "runtime_bundle_sha256", "proxy_bundle", "proxy_bundle_sha256"]) {
  assert.equal(integrity[field], null, `quarantined field ${field}`);
}
await assert.rejects(readFile(path.join(pluginRoot, "mcp/vendor/pxpipe-runtime.mjs")), /ENOENT/);
await assert.rejects(readFile(path.join(pluginRoot, "proxy/vendor/pxpipe-node.mjs")), /ENOENT/);

const anchorSha256=(value) => createHash("sha256").update(value).digest("hex");
const marketplaceEntry={
  name:"pxpipe-context",source:{source:"local",path:"./plugins/pxpipe-context"},
  policy:{installation:"AVAILABLE",authentication:"ON_INSTALL"},category:"Developer Tools",
};
const pxpipeBinding={
  name:"pxpipe-context",provenance_status:"verified",
  files:{"mcp/server.mjs":"a".repeat(64)},
  marketplace_entry_sha256:anchorSha256(Buffer.from(canonicalJson(marketplaceEntry),"utf8")),
};
const agentsBootstrap={path:"AGENTS.md",sha256:"b".repeat(64)};
const claudeBootstrap={path:"CLAUDE.md",sha256:"c".repeat(64)};
const sourcePayload={
  schema:"agent-workflow-install/v5",version:"4.0.0",migration_version:42,agent_root_mode:0o700,
  agent_files:{},agent_modes:{},pxpipe:pxpipeBinding,
  agents_bootstrap_sha256:agentsBootstrap.sha256,claude_bootstrap_sha256:claudeBootstrap.sha256,
};
const workflowV5={
  schema:sourcePayload.schema,version:sourcePayload.version,migration_version:sourcePayload.migration_version,agent_root_mode:sourcePayload.agent_root_mode,
  source_tree_sha256:anchorSha256(Buffer.from(canonicalJson(sourcePayload),"utf8")),
  agent_files:{},agent_modes:{},pxpipe:pxpipeBinding,agents_bootstrap:agentsBootstrap,claude_bootstrap:claudeBootstrap,
};
const marketplaceV5={name:"fixture",interface:{displayName:"Fixture"},plugins:[marketplaceEntry]};
assert.deepEqual(validateVerifiedV5Anchor(workflowV5,marketplaceV5).recorded,pxpipeBinding.files);
for (const legacy of ["agent-workflow-install/v2","agent-workflow-install/v3"]) {
  assert.throws(() => validateVerifiedV5Anchor({...workflowV5,schema:legacy},marketplaceV5),/exact verified v5/);
}
assert.throws(() => validateVerifiedV5Anchor({
  ...workflowV5,pxpipe:{...pxpipeBinding,provenance_status:"disabled"},
},marketplaceV5),/verified v5 provenance/);
assert.throws(() => validateVerifiedV5Anchor({...workflowV5,source_tree_sha256:"d".repeat(64)},marketplaceV5),/source tree binding/);
assert.throws(() => validateVerifiedV5Anchor(workflowV5,{...marketplaceV5,plugins:[]}),/marketplace entry/);
assert.throws(() => validateVerifiedV5Anchor({...workflowV5,agents_bootstrap:{...agentsBootstrap,sha256:"bad"}},marketplaceV5),/exact verified v5/);

const verifier = path.join(pluginRoot, "scripts/verify-integrity.mjs");
const allowed = spawnSync(process.execPath, [verifier, "--allow-quarantined"], { cwd: pluginRoot, encoding: "utf8" });
assert.equal(allowed.status, 0, allowed.stderr);
assert.match(allowed.stdout, /quarantined/);
const rejected = spawnSync(process.execPath, [verifier], { cwd: pluginRoot, encoding: "utf8" });
assert.notEqual(rejected.status, 0);
assert.match(rejected.stderr, /quarantined/);

const mcpServer = path.join(pluginRoot, "mcp/server.mjs");
for (const [method, params] of [
  ["initialize", { protocolVersion: "2025-11-25", capabilities: {} }],
  ["tools/list", {}],
]) {
  const env = { ...process.env };
  delete env.PXPIPE_MCP_MODELS;
  const request = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) + "\n";
  const response = spawnSync(process.execPath, [mcpServer], {
    cwd: pluginRoot, env, input: request, encoding: "utf8", timeout: 10_000,
  });
  assert.equal(response.status, 0, response.stderr);
  const messages = response.stdout.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  assert.equal(messages.length, 1, response.stdout);
  assert.equal(messages[0].error?.code, -32603, response.stdout);
  assert.match(messages[0].error?.message ?? "", /quarantined/);
}
const mcpSource = await readText("mcp/server.mjs");
const anchorSource = await readText("mcp/project-attestation.mjs");
assert.match(anchorSource, /agent-workflow-install\/v5/);
assert.doesNotMatch(anchorSource, /agent-workflow-install\/v[23]/);
assert.match(mcpSource, /validateVerifiedV5Anchor/);
assert.match(mcpSource, /attestation_mode: "agent-workflow-v5"/);

const forgedRoot = await mkdtemp(path.join(os.tmpdir(), "pxpipe-forged-verified-"));
try {
  await cp(pluginRoot, forgedRoot, { recursive: true });
  const forgedIntegrityPath = path.join(forgedRoot, "integrity.json");
  const forgedIntegrity = JSON.parse(await readFile(forgedIntegrityPath, "utf8"));
  forgedIntegrity.provenance_status = "verified";
  await writeFile(forgedIntegrityPath, JSON.stringify(forgedIntegrity, null, 2) + "\n", "utf8");
  const forged = spawnSync(process.execPath, [path.join(forgedRoot, "scripts/verify-integrity.mjs")], {
    cwd: forgedRoot, encoding: "utf8",
  });
  assert.notEqual(forged.status, 0);
  assert.match(forged.stderr, /verified activation requires an external reproducible-build and license-review trust root/i);
  const extra=path.join(forgedRoot,"unreviewed-executable");
  await writeFile(extra,"#!/bin/sh\nexit 0\n",{mode:0o755});
  const staleTree=spawnSync(process.execPath,[path.join(forgedRoot,"scripts/verify-integrity.mjs"),"--allow-quarantined"],{cwd:forgedRoot,encoding:"utf8"});
  assert.notEqual(staleTree.status,0,"an extra executable escaped whole-tree integrity");
  assert.match(staleTree.stderr,/plugin tree digest/);
  let deep=path.join(forgedRoot,"00-depth");
  for(let index=0;index<18;index++){ deep=path.join(deep,"d"); await mkdir(deep,{recursive:true}); }
  await writeFile(path.join(deep,"leaf"),"x");
  const deepTree=spawnSync(process.execPath,[path.join(forgedRoot,"scripts/verify-integrity.mjs"),"--allow-quarantined"],{cwd:forgedRoot,encoding:"utf8"});
  assert.notEqual(deepTree.status,0); assert.match(deepTree.stderr,/depth bound/);
  await rm(path.join(forgedRoot,"00-depth"),{recursive:true,force:true});
  await writeFile(path.join(forgedRoot,"00-oversize"),Buffer.alloc(16*1024*1024+1));
  const largeTree=spawnSync(process.execPath,[path.join(forgedRoot,"scripts/verify-integrity.mjs"),"--allow-quarantined"],{cwd:forgedRoot,encoding:"utf8"});
  assert.notEqual(largeTree.status,0); assert.match(largeTree.stderr,/bounded stable regular file/);
  await rm(path.join(forgedRoot,"00-oversize"),{force:true});
  const crowded=path.join(forgedRoot,"00-entries"); await mkdir(crowded);
  for(let index=0;index<4097;index++) await writeFile(path.join(crowded,String(index).padStart(4,"0")),"");
  const crowdedTree=spawnSync(process.execPath,[path.join(forgedRoot,"scripts/verify-integrity.mjs"),"--allow-quarantined"],{cwd:forgedRoot,encoding:"utf8"});
  assert.notEqual(crowdedTree.status,0); assert.match(crowdedTree.stderr,/entry bound/);
} finally {
  await rm(forgedRoot, { recursive: true, force: true });
}

const build = await readText("scripts/build-runtime.mjs");
assert.match(build, /external trusted release process/);
assert.doesNotMatch(build, /provenance_status:\s*["\']verified["\']/);
const buildRejected = spawnSync(process.execPath, [path.join(pluginRoot, "scripts/build-runtime.mjs")], {
  cwd: pluginRoot, encoding: "utf8",
});
assert.notEqual(buildRejected.status, 0);
assert.match(buildRejected.stderr, /external trusted release process/);
const installer = await readText("scripts/install-codex-default.sh");
const directLauncher = await readText("scripts/codex-pxpipe.sh");
const integritySource = await readText("scripts/verify-integrity.mjs");
for (const bound of ["MAX_FILE_BYTES", "MAX_TREE_BYTES", "MAX_TREE_ENTRIES", "MAX_TREE_DEPTH", "MAX_RELATIVE_BYTES"]) assert.match(integritySource,new RegExp(bound));
assert.match(integritySource,/descriptor\.read\(/); assert.doesNotMatch(integritySource,/descriptor\.readFile\(/);
assert.match(integritySource,/opendir\(/); assert.doesNotMatch(integritySource,/\breaddir\(/);
assert.match(integritySource,/mtimeNs/); assert.match(integritySource,/directory changed during traversal/);
assert.match(installer, /verify-integrity\.mjs/);
assert.match(directLauncher, /verify-integrity\.mjs/);
assert.doesNotMatch(directLauncher, /dist\/node\.js|proxy\/vendor/);
assert.match(installer, /PXPIPE_DASHBOARD_TOKEN/);
assert.match(installer, /\^\[0-9a-f\]\{64\}\$/);
for (const marker of ["O_EXCL", "O_NOFOLLOW", "randomBytes(16)", "nlink !== 1"]) {
  assert.equal(installer.includes(marker), true, "missing safe dashboard token marker: " + marker);
}
assert.doesNotMatch(installer, /DASHBOARD_TOKEN_FILE\.tmp-\$\$/);
assert.doesNotMatch(installer, /restricted to exact model/);
for (const name of ["CODEX_HOME", "PXPIPE_STATE_DIR", "LAUNCH_AGENTS_DIR", "PXPIPE_LAUNCH_LABEL", "PXPIPE_DASHBOARD_TOKEN_FILE", "PXPIPE_NODE_BIN"]) {
  assert.match(installer, new RegExp(name));
}

const statusSource=await readText("scripts/status-codex-default.sh"), uninstallSource=await readText("scripts/uninstall-codex-default.sh");
const lifecycleScripts=["install-codex-default.sh","status-codex-default.sh","uninstall-codex-default.sh"];
for(const injected of ["PXPIPE_TEST_MODE","PXPIPE_SKIP_LAUNCHCTL","PXPIPE_NODE_BIN"]) {
  for(const script of lifecycleScripts) {
    const env={...process.env};
    for(const name of ["PXPIPE_TEST_MODE","PXPIPE_SKIP_LAUNCHCTL","PXPIPE_NODE_BIN","PXPIPE_LIFECYCLE_TEST_ROOT","PXPIPE_LAUNCHCTL_BIN","PXPIPE_ID_BIN"]) delete env[name];
    env[injected]=injected==="PXPIPE_NODE_BIN"?process.execPath:"1";
    const refused=spawnSync("/bin/bash",[path.join(pluginRoot,"scripts",script)],{encoding:"utf8",env});
    assert.notEqual(refused.status,0,script+" accepted production "+injected+" bypass");
    assert.match(refused.stderr,/unavailable|isolated|requires an absolute isolated/);
  }
}
const cleanLifecycleHome=await mkdtemp(path.join(os.tmpdir(),"pxpipe-clean-lifecycle-"));
try {
  const cleanEnv={HOME:cleanLifecycleHome,PATH:process.env.PATH||"/usr/bin:/bin",LANG:"C"};
  for(const script of [...lifecycleScripts,"codex-pxpipe.sh"]) {
    const attempted=spawnSync("/bin/bash",[path.join(pluginRoot,"scripts",script)],{encoding:"utf8",env:cleanEnv});
    assert.notEqual(attempted.status,0,script+" unexpectedly activated quarantined pxpipe");
    assert.doesNotMatch(attempted.stderr,/Caller path overrides|CODEX_HOME override|PXPIPE_STATE_DIR override/,script+" mistook its own defaults for caller overrides");
  }
  const sentinel=path.join(cleanLifecycleHome,"executed");
  const fakeBundle=path.join(cleanLifecycleHome,"fake-pxpipe.mjs");
  await writeFile(fakeBundle,`import {writeFileSync} from "node:fs"; writeFileSync(${JSON.stringify(sentinel)},"executed");\n`);
  const overrideAttempt=spawnSync("/bin/bash",[path.join(pluginRoot,"scripts/codex-pxpipe.sh")],{encoding:"utf8",
    env:{...cleanEnv,PXPIPE_NODE:fakeBundle}});
  assert.notEqual(overrideAttempt.status,0,"direct launcher accepted an override during quarantine");
  await assert.rejects(lstat(sentinel),/ENOENT/);
} finally { await rm(cleanLifecycleHome,{recursive:true,force:true}); }
for (const source of [installer,statusSource,uninstallSource]) {
  assert.ok(source.indexOf('CALLER_PATH_OVERRIDES=""') < source.indexOf('PXPIPE_STATE_DIR="${PXPIPE_STATE_DIR:-'),"caller overrides were captured after defaults");
  assert.match(source,/Production Node\.js path must be root-owned/);
}
assert.doesNotMatch(installer,/process\.argv\[3\]/);
assert.doesNotMatch(statusSource,/--user\s+"pxpipe:\$dashboard_token"/);
assert.match(uninstallSource,/rollback_uninstall/); assert.match(uninstallSource,/verify_install_ownership stage/);
assert.match(uninstallSource,/pxpipe-codex-default-uninstall-recovery\/v2/);
assert.match(uninstallSource,/--recover/); assert.match(uninstallSource,/RECOVERY_EXIT=75/);
assert.match(uninstallSource,/journal_op cleanup/); assert.match(uninstallSource,/prove_service_absent/);
assert.match(installer,/exact predecessor and managed artifacts were preserved/);
assert.match(installer,/managed_plist_installed/); assert.match(installer,/prior_service_loaded/);
for (const lifecycleSource of [installer,uninstallSource]) {
  assert.doesNotMatch(lifecycleSource,/\|\| true/,"lifecycle compensation suppresses a failure");
  assert.doesNotMatch(lifecycleSource,/catch\s*\{\s*\}/,"lifecycle compensation swallows an exception");
}

const extractNodeHelper = (script) => {
  const start = script.indexOf('const fs=require("node:fs")');
  const end = script.indexOf("\nNODE", start);
  assert.ok(start >= 0 && end > start, "missing embedded ownership helper");
  return script.slice(start, end) + "\n";
};
const ownershipRoot = await mkdtemp(path.join(os.tmpdir(), "pxpipe-ownership-"));
try {
  const tokenPath=path.join(ownershipRoot,"dashboard-token"), plistPath=path.join(ownershipRoot,"agent.plist"), statePath=path.join(ownershipRoot,"install.json");
  const priorPresent=path.join(ownershipRoot,"prior.plist"),priorAbsent=path.join(ownershipRoot,"prior-absent");
  const label="io.pxpipe.codex-default";
  const record=async target => { const raw=await readFile(target), observed=await lstat(target); return {
    path:path.resolve(target),dev:observed.dev,ino:observed.ino,bytes:raw.length,sha256:createHash("sha256").update(raw).digest("hex"),
  }; };
  const writeOwned=async (target,bytes) => { await writeFile(target,bytes,{mode:0o600}); await chmod(target,0o600); };
  const writeState=async reverse => { const value={schema:"pxpipe-codex-default-install/v2",label,token:await record(tokenPath),plist:await record(plistPath),prior_plist:{kind:"present",artifact:await record(priorPresent)}};
    const ordered=reverse?{token:value.token,schema:value.schema,prior_plist:value.prior_plist,plist:value.plist,label:value.label}:value; await writeOwned(statePath,JSON.stringify(ordered)+"\n"); };
  await writeOwned(tokenPath,"a".repeat(64)+"\n"); await writeOwned(plistPath,"<plist/>\n"); await writeOwned(priorPresent,"<prior/>\n"); await writeState(false);
  const statusScript=await readText("scripts/status-codex-default.sh"), uninstallScript=await readText("scripts/uninstall-codex-default.sh");
  const statusHelper=path.join(ownershipRoot,"status.cjs"), uninstallHelper=path.join(ownershipRoot,"uninstall.cjs");
  await writeFile(statusHelper,extractNodeHelper(statusScript)); await writeFile(uninstallHelper,extractNodeHelper(uninstallScript));
  const status=() => spawnSync(process.execPath,[statusHelper,statePath,tokenPath,plistPath,label,priorPresent,priorAbsent],{encoding:"utf8"});
  assert.equal(status().status,0,"valid ownership state rejected");
  await writeState(true); assert.equal(status().status,0,"ownership state depended on JSON key order");
  await writeOwned(tokenPath,"b".repeat(64)+"\n"); assert.notEqual(status().status,0,"token content replacement was accepted");
  await writeOwned(tokenPath,"a".repeat(64)+"\n"); assert.equal(status().status,0,"restored exact token unexpectedly failed");
  const originalToken=path.join(ownershipRoot,"dashboard-token-original"); await rename(tokenPath,originalToken);
  await writeOwned(tokenPath,"a".repeat(64)+"\n"); assert.notEqual(status().status,0,"same-byte inode replacement was accepted");
  await rm(tokenPath); await symlink(originalToken,tokenPath); assert.notEqual(status().status,0,"token symlink replacement was accepted");
  await rm(tokenPath); await rename(originalToken,tokenPath); assert.equal(status().status,0,"original authenticated token identity was not restorable");
  await writeOwned(priorPresent,"<tampered/>\n"); assert.notEqual(status().status,0,"prior plist content replacement was accepted");
  await writeOwned(priorPresent,"<prior/>\n"); assert.equal(status().status,0,"restored prior plist unexpectedly failed ownership validation");
  const staged=[tokenPath,plistPath,statePath].map(target=>target+".pxpipe-uninstall-staged");
  const priorStaged=[priorPresent,priorAbsent].map(target=>target+".pxpipe-uninstall-staged");
  const stageArgs=[uninstallHelper,"stage",statePath,tokenPath,plistPath,label,...staged,priorPresent,priorAbsent,...priorStaged];
  await writeOwned(staged[0],"collision\n");
  const collided=spawnSync(process.execPath,stageArgs,{encoding:"utf8"});
  assert.notEqual(collided.status,0,"preexisting uninstall stage was overwritten");
  for (const target of [statePath,tokenPath,plistPath,priorPresent]) assert.equal((await lstat(target)).isFile(),true,"failed staging did not restore originals");
  await rm(staged[0]);
  const removed=spawnSync(process.execPath,stageArgs,{encoding:"utf8"});
  assert.equal(removed.status,0,removed.stderr);
  for (const target of [statePath,tokenPath,plistPath,priorPresent]) await assert.rejects(lstat(target),/ENOENT/);
  for (const target of [...staged,priorStaged[0]]) assert.equal((await lstat(target)).isFile(),true,"authenticated artifact was not staged safely");
  await assert.rejects(lstat(priorStaged[1]),/ENOENT/);
} finally { await rm(ownershipRoot,{recursive:true,force:true}); }

const configRoot=await mkdtemp(path.join(os.tmpdir(),"pxpipe-config-auth-"));
try {
  const configDir=path.join(configRoot,"codex"),stateDir=path.join(configRoot,"state");
  await mkdir(configDir,{mode:0o700}); await mkdir(stateDir,{mode:0o700});
  const config=path.join(configDir,"config.toml"),state=path.join(stateDir,"codex-default.json"),backup=state+".config-before";
  const victim=path.join(configRoot,"victim"),originalConfig="model = \"existing\"\n";
  await writeFile(config,originalConfig,{mode:0o600}); await chmod(config,0o600);
  await writeFile(victim,"never-touch\n",{mode:0o600}); await chmod(victim,0o600);
  const configTool=path.join(pluginRoot,"scripts/codex-default-config.mjs");
  const invoke=(action)=>spawnSync(process.execPath,[configTool,action,"--config",config,"--state",state,...(action==="install"?["--base-url","http://127.0.0.1:8787/v1"]:[])],{encoding:"utf8"});
  assert.equal(invoke("install").status,0,"authenticated Codex config install failed");
  const stateBytes=await readFile(state),backupBytes=await readFile(backup);
  const tampered=JSON.parse(stateBytes); tampered.backup=victim;
  await writeFile(state,JSON.stringify(tampered)+"\n"); await chmod(state,0o600);
  assert.notEqual(invoke("status").status,0,"unbound backup path was accepted by status");
  assert.notEqual(invoke("uninstall").status,0,"unbound backup path was accepted by uninstall");
  assert.equal(await readFile(victim,"utf8"),"never-touch\n","unbound backup path changed an unrelated file");
  await writeFile(state,stateBytes); await chmod(state,0o600);
  await rm(backup); await symlink(victim,backup);
  assert.notEqual(invoke("status").status,0,"symlinked config backup was accepted by status");
  assert.notEqual(invoke("uninstall").status,0,"symlinked config backup was accepted by uninstall");
  assert.equal(await readFile(victim,"utf8"),"never-touch\n","symlinked config backup changed its target");
  await rm(backup); await writeFile(backup,backupBytes,{mode:0o600}); await chmod(backup,0o600);
  assert.equal(invoke("uninstall").status,0,"authenticated Codex config uninstall failed");
  assert.equal(await readFile(config,"utf8"),originalConfig,"Codex config uninstall did not restore exact original bytes");
} finally { await rm(configRoot,{recursive:true,force:true}); }

let systemTempRaw="/tmp";
if(process.platform==="darwin") {
  const discovered=spawnSync("/usr/bin/getconf",["DARWIN_USER_TEMP_DIR"],{encoding:"utf8",env:{PATH:"/usr/bin:/bin"}});
  assert.equal(discovered.status,0,discovered.stderr);
  systemTempRaw=discovered.stdout.trim();
}
const systemTemp=await realpath(systemTempRaw);
const rollbackRoot=await mkdtemp(path.join(systemTemp,"pxpipe-lifecycle-fixture-"));
try {
  const codex=path.join(rollbackRoot,"codex"),state=path.join(rollbackRoot,"state"),agents=path.join(rollbackRoot,"agents");
  await mkdir(codex,{recursive:true,mode:0o700}); await mkdir(state,{recursive:true,mode:0o700}); await mkdir(agents,{recursive:true,mode:0o700});
  const config=path.join(codex,"config.toml"),managedState=path.join(state,"codex-default.json"),token=path.join(state,"dashboard-token");
  const label="io.pxpipe.rollback-test",plist=path.join(agents,label+".plist"),ownership=path.join(state,"codex-default-install.json");
  const fixtureScripts=path.join(rollbackRoot,"scripts"); await mkdir(fixtureScripts,{mode:0o700});
  const configTool=path.join(fixtureScripts,"codex-default-config.mjs");
  const uninstallScriptPath=path.join(fixtureScripts,"uninstall-codex-default.sh");
  await cp(path.join(pluginRoot,"scripts/codex-default-config.mjs"),configTool);
  await cp(path.join(pluginRoot,"scripts/uninstall-codex-default.sh"),uninstallScriptPath);
  await chmod(uninstallScriptPath,0o700);
  const configured=spawnSync(process.execPath,[configTool,"install","--config",config,"--state",managedState,"--base-url","http://127.0.0.1:47821/v1"],{encoding:"utf8"});
  assert.equal(configured.status,0,configured.stderr);
  const writePrivate=async(target,bytes)=>{await writeFile(target,bytes,{mode:0o600});await chmod(target,0o600);};
  await writePrivate(token,"c".repeat(64)+"\n"); await writePrivate(plist,"<managed/>\n");
  const ownedRecord=async target=>{const raw=await readFile(target),observed=await lstat(target);return {path:path.resolve(target),dev:observed.dev,ino:observed.ino,bytes:raw.length,sha256:createHash("sha256").update(raw).digest("hex")};};
  const priorPlist=path.join(state,"codex-default.plist-before"); await writePrivate(priorPlist,"<prior/>\n");
  await writePrivate(ownership,JSON.stringify({schema:"pxpipe-codex-default-install/v2",label,token:await ownedRecord(token),plist:await ownedRecord(plist),prior_plist:{kind:"present",artifact:await ownedRecord(priorPlist)}})+"\n");
  const launchctl=path.join(rollbackRoot,"launchctl"); await writeFile(launchctl,`#!/bin/sh
state="$0.state"
[ -f "$state" ] || printf 'loaded\n' >"$state"
case "$1" in
  print) case "$2" in */${label}) [ "$(cat "$state")" = loaded ] || exit 1; printf 'pid = 4242\n';; *) exit 0;; esac;;
  bootout) printf 'absent\n' >"$state";;
  bootstrap) if [ -f "$0.block" ]; then exit 72; fi; if grep -q prior "$3"; then exit 71; fi; printf 'loaded\n' >"$state";;
  *) exit 64;;
esac
`,{mode:0o755}); await chmod(launchctl,0o755);
  const lsof=path.join(rollbackRoot,"lsof"),ps=path.join(rollbackRoot,"ps");
  await writeFile(lsof,`#!/bin/sh\nif [ "$(cat ${launchctl}.state)" = loaded ] || [ -f ${launchctl}.survivor ]; then printf '4242\n'; exit 0; fi\nexit 1\n`,{mode:0o755});
  await writeFile(ps,`#!/bin/sh\nif [ "$1" = "-o" ]; then printf ' 5252\n'; exit 0; fi\nif [ "$(cat ${launchctl}.state)" = loaded ] || [ -f ${launchctl}.survivor ]; then printf ' 4242 5252\n'; fi\n`,{mode:0o755});
  await chmod(lsof,0o755); await chmod(ps,0o755);
  const tracked=[config,managedState,managedState+".config-before",token,plist,ownership,priorPlist];
  const before=new Map(await Promise.all(tracked.map(async target=>[target,await readFile(target)])));
  const uninstallEnv={...process.env,PXPIPE_TEST_MODE:"1",PXPIPE_LIFECYCLE_TEST_ROOT:rollbackRoot,CODEX_HOME:codex,PXPIPE_STATE_DIR:state,LAUNCH_AGENTS_DIR:agents,PXPIPE_LAUNCH_LABEL:label,PXPIPE_DASHBOARD_TOKEN_FILE:token,PXPIPE_NODE_BIN:process.execPath,PXPIPE_LAUNCHCTL_BIN:launchctl,PXPIPE_LSOF_BIN:lsof,PXPIPE_PS_BIN:ps};
  const invokeUninstall=(...args)=>spawnSync("/bin/bash",[uninstallScriptPath,...args],{encoding:"utf8",env:uninstallEnv});
  const configHelperOriginal=await readFile(configTool,"utf8");
  const crashJournal=path.join(state,"codex-default-uninstall-recovery.json");
  const crashPoints=[
    ["config",'    else atomicWrite(value.config, value.restored, 0o600, value.current);'],
    ["state",'    removeSnapshot(value.stateFile, value.stateSnapshot, "pxpipe Codex install state");'],
    ["backup",'    removeSnapshot(value.state.backup, value.original, "pxpipe Codex config backup");'],
  ];
  for(const [point,needle] of crashPoints) {
    assert.ok(configHelperOriginal.includes(needle),"crash fixture lost the "+point+" mutation point");
    const crashHelper=configHelperOriginal.replace(needle,needle+'\n    if (process.env.PXPIPE_FIXTURE_CRASH_POINT === "'+point+'") { process.kill(process.ppid, "SIGKILL"); process.kill(process.pid, "SIGKILL"); }');
    await writeFile(configTool,crashHelper,{mode:0o600}); await chmod(configTool,0o600);
    const crashed=spawnSync("/bin/bash",[uninstallScriptPath],{encoding:"utf8",env:{...uninstallEnv,PXPIPE_FIXTURE_CRASH_POINT:point}});
    assert.notEqual(crashed.status,0,"fixture SIGKILL after "+point+" unexpectedly committed uninstall");
    let crashJournalBytes;
    try { crashJournalBytes=await readFile(crashJournal,"utf8"); }
    catch (error) { assert.fail("hard-crash after "+point+" created no journal\nstdout:\n"+crashed.stdout+"\nstderr:\n"+crashed.stderr+"\n"+error); }
    const crashJournalValue=JSON.parse(crashJournalBytes);
    assert.equal(crashJournalValue.phase,"prepared","hard crash advanced the durable journal phase");
    assert.equal(typeof crashJournalValue.post_config_snapshots,"object","journal omitted preplanned post-images");
    await writeFile(configTool,configHelperOriginal,{mode:0o600}); await chmod(configTool,0o600);
    const crashRecovered=invokeUninstall("--recover");
    assert.equal(crashRecovered.status,0,crashRecovered.stdout+crashRecovered.stderr);
    for(const target of tracked) assert.deepEqual(await readFile(target),before.get(target),"hard-crash recovery after "+point+" did not restore "+target);
    await assert.rejects(lstat(crashJournal),/ENOENT/);
  }

  const uninstallOriginal=await readFile(uninstallScriptPath,"utf8");
  const boundaryNeedle="journal_op update config-mutated";
  assert.ok(uninstallOriginal.includes(boundaryNeedle),"config/journal boundary fixture drifted");
  await writeFile(uninstallScriptPath,uninstallOriginal.replace(boundaryNeedle,()=>
    'if [[ "${PXPIPE_FIXTURE_CRASH_AFTER_CONFIG:-0}" == "1" ]]; then kill -KILL $$; fi\n'+boundaryNeedle),{mode:0o700});
  const boundaryCrash=spawnSync("/bin/bash",[uninstallScriptPath],{encoding:"utf8",
    env:{...uninstallEnv,PXPIPE_FIXTURE_CRASH_AFTER_CONFIG:"1"}});
  assert.notEqual(boundaryCrash.status,0,"post-config/pre-journal crash unexpectedly committed");
  let boundaryJournal;
  try { boundaryJournal=JSON.parse(await readFile(crashJournal,"utf8")); }
  catch(error) { assert.fail("post-config boundary created no journal\nstdout:\n"+boundaryCrash.stdout+"\nstderr:\n"+boundaryCrash.stderr+"\n"+error); }
  assert.equal(boundaryJournal.phase,"prepared");
  assert.equal(typeof boundaryJournal.post_config_snapshots,"object");
  await writePrivate(managedState,"tampered post-image\n");
  const preflightTargets=[config,managedState,managedState+".config-before",token,plist,ownership,priorPlist];
  const beforeRefusal=new Map(await Promise.all(preflightTargets.map(async target=>{try{return [target,{present:true,bytes:await readFile(target)}];}catch(error){if(error.code==="ENOENT")return [target,{present:false}];throw error;}})));
  await writeFile(uninstallScriptPath,uninstallOriginal,{mode:0o700}); await chmod(uninstallScriptPath,0o700);
  const preflightRefused=invokeUninstall("--recover");
  assert.equal(preflightRefused.status,75,"tampered post-image did not fail recovery preflight");
  for(const [target,expected] of beforeRefusal){try{const actual=await readFile(target);assert.equal(expected.present,true,"recovery created "+target);assert.deepEqual(actual,expected.bytes,"recovery partially mutated "+target);}catch(error){if(error.code!=="ENOENT")throw error;assert.equal(expected.present,false,"recovery removed "+target);}}
  const rollbackDir=boundaryJournal.paths.rollback_dir;
  try { await rm(managedState); } catch(error) { if(error.code!=="ENOENT") throw error; }
  try { await writePrivate(managedState,await readFile(path.join(rollbackDir,"post-state"))); } catch(error) { if(error.code!=="ENOENT") throw error; }
  const boundaryRecovered=invokeUninstall("--recover");
  assert.equal(boundaryRecovered.status,0,boundaryRecovered.stdout+boundaryRecovered.stderr);
  for(const target of tracked) assert.deepEqual(await readFile(target),before.get(target),"boundary recovery did not restore "+target);

  const survivor=launchctl+".survivor";
  await writePrivate(survivor,"detached listener survives bootout\n");
  const survived=invokeUninstall();
  assert.equal(survived.status,75,"surviving process group/listener was not recovery-required");
  const survivedJournal=JSON.parse(await readFile(crashJournal,"utf8"));
  assert.equal(survivedJournal.phase,"recovery-required");
  assert.equal(survivedJournal.service_pid,"4242");
  assert.equal(survivedJournal.service_pgid,"5252");
  assert.equal(survivedJournal.service_listeners,"4242");
  for(const target of [token,ownership]) assert.equal((await lstat(target)).isFile(),true,"uncertain stop discarded credential ownership");
  await rm(survivor);
  const survivorRecovered=invokeUninstall("--recover");
  assert.equal(survivorRecovered.status,0,survivorRecovered.stdout+survivorRecovered.stderr);
  for(const target of tracked) assert.deepEqual(await readFile(target),before.get(target),"survivor recovery did not restore "+target);

  await writeFile(launchctl+".state","absent\n");
  const applyNeedle='else if (action === "apply-uninstall") await applyUninstall(options);';
  assert.ok(configHelperOriginal.includes(applyNeedle),"config apply race fixture drifted");
  const raceHelper=configHelperOriginal.replace(applyNeedle,
    `else if (action === "apply-uninstall") { fs.writeFileSync(${JSON.stringify(launchctl+".state")},"loaded\\n"); fs.writeFileSync(${JSON.stringify(launchctl+".survivor")},"raced listener\\n"); await applyUninstall(options); }`);
  await writeFile(configTool,raceHelper,{mode:0o600}); await chmod(configTool,0o600);
  const raced=invokeUninstall();
  assert.equal(raced.status,75,"absent-to-loaded race was not recovery-required");
  const racedJournal=JSON.parse(await readFile(crashJournal,"utf8"));
  assert.equal(racedJournal.service_was_loaded,false,"raced service was trusted retroactively");
  for(const target of [token,plist,ownership]) assert.equal((await lstat(target)).isFile(),true,"raced service discarded authenticated artifacts");
  await writeFile(configTool,configHelperOriginal,{mode:0o600}); await chmod(configTool,0o600);
  await rm(launchctl+".survivor"); await writeFile(launchctl+".state","absent\n");
  const raceRecovered=invokeUninstall("--recover");
  assert.equal(raceRecovered.status,0,raceRecovered.stdout+raceRecovered.stderr);
  for(const target of tracked) assert.deepEqual(await readFile(target),before.get(target),"race recovery did not restore "+target);
  await writeFile(launchctl+".state","loaded\n");

  const failed=invokeUninstall();
  assert.notEqual(failed.status,0,"injected service-restoration failure unexpectedly committed uninstall");
  for(const target of tracked) {
    let actual; try { actual=await readFile(target); }
    catch(error) { assert.fail("uninstall compensation lost "+target+"\nstdout:\n"+failed.stdout+"\nstderr:\n"+failed.stderr+"\n"+error); }
    assert.deepEqual(actual,before.get(target),"uninstall compensation did not restore "+target);
  }
  for(const target of [token,plist,ownership,priorPlist]) await assert.rejects(lstat(target+".pxpipe-uninstall-staged"),/ENOENT/);

  // If launchd compensation itself is unavailable, preserve an authenticated
  // marker-last recovery transaction and require explicit, idempotent recovery.
  const block=launchctl+".block",journal=path.join(state,"codex-default-uninstall-recovery.json");
  await writePrivate(block,"block launchd restore\n");
  const recoveryRequired=invokeUninstall();
  assert.equal(recoveryRequired.status,75,"failed compensation did not return the recovery-required status");
  const journalBytes=await readFile(journal),journalStat=await lstat(journal),journalValue=JSON.parse(journalBytes);
  assert.equal(journalStat.mode&0o777,0o600,"recovery journal is not private");
  assert.equal(journalValue.schema,"pxpipe-codex-default-uninstall-recovery/v2");
  assert.equal(journalValue.phase,"recovery-required");
  assert.equal(journalValue.primary_status,72);
  assert.match(journalValue.journal_sha256,/^[0-9a-f]{64}$/);
  assert.equal(invokeUninstall().status,75,"a new uninstall bypassed an existing recovery transaction");
  assert.deepEqual(await readFile(journal),journalBytes,"refused new uninstall rewrote recovery evidence");

  const forged={...journalValue,phase:"committed"};
  await writeFile(journal,JSON.stringify(forged)+"\n",{mode:0o600}); await chmod(journal,0o600);
  assert.equal(invokeUninstall("--recover").status,75,"tampered recovery phase bypassed the journal digest");
  await writeFile(journal,journalBytes,{mode:0o600}); await chmod(journal,0o600);
  assert.equal(invokeUninstall("--recover").status,75,"unavailable launchd compensation discarded recovery evidence");
  await rm(block);
  const recovered=invokeUninstall("--recover");
  assert.equal(recovered.status,0,recovered.stdout+recovered.stderr);
  for(const target of tracked) assert.deepEqual(await readFile(target),before.get(target),"explicit recovery did not restore "+target);
  await assert.rejects(lstat(journal),/ENOENT/);
  assert.equal((await readdir(state)).some(name=>name.startsWith(".codex-uninstall-rollback.")),false,"explicit recovery left rollback artifacts");
} finally { await rm(rollbackRoot,{recursive:true,force:true}); }

const installRollbackRoot=await mkdtemp(path.join(os.tmpdir(),"pxpipe-install-rollback-fixture-"));
try {
  const fixtureScripts=path.join(installRollbackRoot,"scripts"), codex=path.join(installRollbackRoot,"codex");
  const state=path.join(installRollbackRoot,"state"), agents=path.join(installRollbackRoot,"agents");
  await mkdir(fixtureScripts,{recursive:true,mode:0o700}); await mkdir(path.join(installRollbackRoot,"dist"),{mode:0o700});
  for(const directory of [codex,state,agents]) { await mkdir(directory,{mode:0o700}); await chmod(directory,0o700); }
  await cp(path.join(pluginRoot,"scripts/codex-default-config.mjs"),path.join(fixtureScripts,"codex-default-config.mjs"));
  await writeFile(path.join(fixtureScripts,"verify-integrity.mjs"),"process.exit(0);\n",{mode:0o600});
  await writeFile(path.join(installRollbackRoot,"dist/node.js"),"// isolated fixture bundle\n",{mode:0o600});
  const overrideGuard=`if [[ -n "\${CALLER_PATH_OVERRIDES// /}" ]]; then
  echo "Caller path overrides are unavailable in production installation:$CALLER_PATH_OVERRIDES" >&2
  exit 1
fi
for name in PXPIPE_TEST_MODE PXPIPE_LIFECYCLE_TEST_ROOT PXPIPE_SKIP_LAUNCHCTL PXPIPE_LAUNCHCTL_BIN PXPIPE_CURL_BIN PXPIPE_LSOF_BIN PXPIPE_ID_BIN; do
  if declare -p "$name" >/dev/null 2>&1; then echo "$name override is unavailable in production installation." >&2; exit 1; fi
done`;
  const configBoundary='"$NODE_BIN" "$CONFIG_TOOL" install --config "$CONFIG_PATH" --state "$MANAGED_STATE" --base-url "$BASE_URL/v1"';
  assert.equal(installer.includes(overrideGuard),true,"install fixture could not identify the production override guard");
  assert.equal(installer.split(configBoundary).length,2,"install config mutation boundary is ambiguous");
  const fixtureSource=installer.replace(overrideGuard,": # isolated copied fixture permits path overrides")
    .replace(configBoundary,configBoundary+'\nexit 97 # injected late failure after config mutation');
  const installScript=path.join(fixtureScripts,"install-codex-default.sh");
  await writeFile(installScript,fixtureSource,{mode:0o700}); await chmod(installScript,0o700);
  const config=path.join(codex,"config.toml"), originalConfig=Buffer.from('model = "user-selected"\n');
  await writeFile(config,originalConfig,{mode:0o600}); await chmod(config,0o600);
  const label="com.pxpipe.install-rollback-test", managed=path.join(state,"codex-default.json");
  const backup=managed+".config-before", ownership=path.join(state,"codex-default-install.json");
  const token=path.join(state,"dashboard-token"), plist=path.join(agents,label+".plist");
  const result=spawnSync("/bin/bash",[installScript],{encoding:"utf8",env:{...process.env,HOME:installRollbackRoot,
    CODEX_HOME:codex,PXPIPE_STATE_DIR:state,LAUNCH_AGENTS_DIR:agents,PXPIPE_LAUNCH_LABEL:label,
    PXPIPE_DASHBOARD_TOKEN_FILE:token,PXPIPE_NODE_BIN:process.execPath,PXPIPE_TEST_MODE:"1",PXPIPE_SKIP_LAUNCHCTL:"1",
    PXPIPE_LAUNCHCTL_BIN:"/usr/bin/true",PXPIPE_CURL_BIN:"/usr/bin/true",PXPIPE_LSOF_BIN:"/usr/bin/true",PXPIPE_ID_BIN:"/usr/bin/id"}});
  assert.notEqual(result.status,0,"injected post-config install failure unexpectedly committed");
  assert.deepEqual(await readFile(config),originalConfig,"late install failure did not restore exact config bytes");
  for(const target of [managed,backup,ownership,token,plist]) await assert.rejects(lstat(target),/ENOENT/,"late install failure left "+target);
  assert.equal((await readdir(state)).some(name=>name.startsWith(".codex-default-config-transaction.")),false,"late install failure left config transaction journal");
} finally { await rm(installRollbackRoot,{recursive:true,force:true}); }

process.stdout.write("PASS: pxpipe is quarantined and exact provenance is required before activation\n");
