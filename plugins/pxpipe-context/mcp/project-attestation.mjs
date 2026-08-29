import { createHash } from "node:crypto";

const HEX64=/^[0-9a-f]{64}$/;
const VERSION=/^(?:0|[1-9][0-9]{0,9})\.(?:0|[1-9][0-9]{0,9})\.(?:0|[1-9][0-9]{0,9})$/;
const PLUGIN_PATH=/^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/;
const WORKFLOW_KEYS=[
  "agent_files","agent_modes","agent_root_mode","agents_bootstrap","claude_bootstrap","migration_version",
  "pxpipe","schema","source_tree_sha256","version",
];
const PXPIPE_KEYS=["files","marketplace_entry_sha256","name","provenance_status"];

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function exactObject(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
}

function bootstrap(value, path) {
  return exactObject(value,["path","sha256"]) && value.path===path && HEX64.test(value.sha256);
}

export function validateVerifiedV5Anchor(workflow, marketplace, { maxPluginFiles = 128 } = {}) {
  if (!exactObject(workflow,WORKFLOW_KEYS) || workflow.schema!=="agent-workflow-install/v5"
      || !VERSION.test(workflow.version) || !Number.isSafeInteger(workflow.migration_version)
      || workflow.migration_version<0 || workflow.agent_root_mode!==0o700 || !HEX64.test(workflow.source_tree_sha256 ?? "")
      || !bootstrap(workflow.agents_bootstrap,"AGENTS.md")
      || !bootstrap(workflow.claude_bootstrap,"CLAUDE.md")
      || !exactObject(workflow.pxpipe,PXPIPE_KEYS)) {
    throw new Error("workspace_root lacks an exact verified v5 workflow/plugin installation anchor");
  }
  const pxpipeBinding=workflow.pxpipe;
  const recorded=pxpipeBinding.files;
  if (pxpipeBinding.name!=="pxpipe-context" || pxpipeBinding.provenance_status!=="verified"
      || !HEX64.test(pxpipeBinding.marketplace_entry_sha256 ?? "")
      || recorded===null || typeof recorded!=="object" || Array.isArray(recorded)
      || Object.keys(recorded).length<1 || Object.keys(recorded).length>maxPluginFiles
      || Object.entries(recorded).some(([relative,digest]) => !PLUGIN_PATH.test(relative) || !HEX64.test(digest))) {
    throw new Error("workflow pxpipe binding is not exact verified v5 provenance");
  }
  const agentFiles=workflow.agent_files; const agentModes=workflow.agent_modes;
  if (agentFiles===null || typeof agentFiles!=="object" || Array.isArray(agentFiles)
      || agentModes===null || typeof agentModes!=="object" || Array.isArray(agentModes)
      || JSON.stringify(Object.keys(agentFiles).sort())!==JSON.stringify(Object.keys(agentModes).sort())
      || Object.entries(agentFiles).some(([relative,digest]) => !PLUGIN_PATH.test(relative) || !HEX64.test(digest))
      || Object.values(agentModes).some((mode) => !Number.isSafeInteger(mode) || mode<0 || mode>0o777)) {
    throw new Error("workflow v5 managed file and mode bindings are invalid");
  }
  const sourcePayload={
    schema:workflow.schema,version:workflow.version,migration_version:workflow.migration_version,
    agent_root_mode:workflow.agent_root_mode,agent_files:agentFiles,agent_modes:agentModes,pxpipe:pxpipeBinding,
    agents_bootstrap_sha256:workflow.agents_bootstrap.sha256,
    claude_bootstrap_sha256:workflow.claude_bootstrap.sha256,
  };
  if (sha256(Buffer.from(canonicalJson(sourcePayload),"utf8"))!==workflow.source_tree_sha256) {
    throw new Error("workflow v5 source tree binding differs from its exact metadata");
  }
  const entries=Array.isArray(marketplace?.plugins)
    ? marketplace.plugins.filter((entry) => entry?.name==="pxpipe-context") : [];
  if (entries.length!==1
      || sha256(Buffer.from(canonicalJson(entries[0]),"utf8"))!==pxpipeBinding.marketplace_entry_sha256) {
    throw new Error("workflow pxpipe marketplace entry differs from the v5 installation anchor");
  }
  return {
    recorded,pxpipeBinding,agentsBootstrap:workflow.agents_bootstrap,
    claudeBootstrap:workflow.claude_bootstrap,marketplaceEntry:entries[0],
  };
}
