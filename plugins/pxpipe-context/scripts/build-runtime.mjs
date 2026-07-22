#!/usr/bin/env node

import { createHash } from "node:crypto";
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseArgs(argv) {
  const result = { source: process.env.PXPIPE_SOURCE ?? "" };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--pxpipe-source") {
      result.source = argv[index + 1] ?? "";
      index += 1;
    } else {
      throw new Error(`unknown argument: ${argv[index]}`);
    }
  }
  if (!result.source) {
    throw new Error("pass --pxpipe-source <checkout> or set PXPIPE_SOURCE");
  }
  return result;
}

const pluginRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { source } = parseArgs(process.argv.slice(2));
const pxpipeRoot = path.resolve(source);
const packagePath = path.join(pxpipeRoot, "package.json");
const packageBytes = await readFile(packagePath);
const packageJson = JSON.parse(packageBytes.toString("utf8"));
if (packageJson.name !== "pxpipe-proxy" || typeof packageJson.version !== "string") {
  throw new Error("pxpipe source must contain pxpipe-proxy package.json");
}

const pluginManifest = JSON.parse(
  await readFile(path.join(pluginRoot, ".codex-plugin", "plugin.json"), "utf8"),
);
const esbuildPath = path.join(pxpipeRoot, "node_modules", "esbuild", "lib", "main.js");
const { build } = await import(pathToFileURL(esbuildPath).href);
const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "pxpipe-context-build-"));
const entry = path.join(temporaryRoot, "entry.ts");
const output = path.join(pluginRoot, "mcp", "vendor", "pxpipe-runtime.mjs");
const proxyOutput = path.join(pluginRoot, "proxy", "vendor", "pxpipe-node.mjs");
const providerAssets = [
  "scripts/codex-pxpipe.sh",
  "scripts/codex-default-config.mjs",
  "scripts/install-codex-default.sh",
  "scripts/uninstall-codex-default.sh",
  "scripts/status-codex-default.sh",
];

try {
  await mkdir(path.dirname(proxyOutput), { recursive: true });
  const exportModule = path.join(pxpipeRoot, "src", "core", "export.ts");
  await writeFile(entry, `export { runExportCore } from ${JSON.stringify(exportModule)};\n`);
  await build({
    entryPoints: [entry],
    outfile: output,
    bundle: true,
    platform: "node",
    target: "node18",
    format: "esm",
    sourcemap: false,
    external: [],
    logLevel: "warning",
  });
  await build({
    entryPoints: [path.join(pxpipeRoot, "src", "node.ts")],
    outfile: proxyOutput,
    bundle: true,
    platform: "node",
    target: "node18",
    format: "esm",
    sourcemap: false,
    external: [],
    logLevel: "warning",
  });
  for (const relative of providerAssets) {
    const destination = path.join(pluginRoot, relative);
    await copyFile(path.join(pxpipeRoot, relative), destination);
    await chmod(destination, 0o755);
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

const runtimeBytes = await readFile(output);
const proxyBytes = await readFile(proxyOutput);
const providerAssetHashes = {};
for (const relative of providerAssets) {
  providerAssetHashes[relative] = sha256(await readFile(path.join(pluginRoot, relative)));
}
const integrity = {
  schema: "pxpipe-context-integrity/v3",
  plugin_version: pluginManifest.version,
  pxpipe_package: packageJson.name,
  pxpipe_version: packageJson.version,
  source_package_sha256: sha256(packageBytes),
  runtime_bundle: "mcp/vendor/pxpipe-runtime.mjs",
  runtime_bundle_sha256: sha256(runtimeBytes),
  proxy_bundle: "proxy/vendor/pxpipe-node.mjs",
  proxy_bundle_sha256: sha256(proxyBytes),
  provider_assets: providerAssetHashes,
};
await writeFile(
  path.join(pluginRoot, "integrity.json"),
  `${JSON.stringify(integrity, null, 2)}\n`,
);
process.stdout.write(`${JSON.stringify(integrity)}\n`);
