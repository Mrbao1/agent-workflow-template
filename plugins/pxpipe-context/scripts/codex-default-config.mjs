#!/usr/bin/env node
import { chmod, mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";

const ROOT_START = "# >>> pxpipe managed Codex provider selection >>>";
const ROOT_END = "# <<< pxpipe managed Codex provider selection <<<";
const PROVIDER_START = "# >>> pxpipe managed Codex provider definition >>>";
const PROVIDER_END = "# <<< pxpipe managed Codex provider definition <<<";
const LEGACY_START = "# >>> pxpipe managed Codex default >>>";
const LEGACY_END = "# <<< pxpipe managed Codex default <<<";
const PROVIDER_NAME = "pxpipe";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function parseArgs(argv) {
  const [action, ...rest] = argv;
  const options = {};
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    const value = rest[index + 1];
    if (!key?.startsWith("--") || value === undefined) fail(`Invalid argument: ${key ?? ""}`);
    options[key.slice(2)] = value;
  }
  return { action, options };
}

function splitLines(text) {
  return text === "" ? [] : text.replace(/\r\n/g, "\n").split("\n");
}

function rangeFor(lines, startMarker, endMarker) {
  const starts = lines.flatMap((line, index) => line === startMarker ? [index] : []);
  const ends = lines.flatMap((line, index) => line === endMarker ? [index] : []);
  if (starts.length === 0 && ends.length === 0) return null;
  if (starts.length !== 1 || ends.length !== 1 || ends[0] <= starts[0]) {
    throw new Error(`Codex config contains a malformed managed block: ${startMarker}`);
  }
  return { start: starts[0], end: ends[0] };
}

function rootKeyIndexes(lines, key) {
  const indexes = [];
  let inRoot = true;
  const pattern = new RegExp(`^${key}\\s*=`);
  for (let index = 0; index < lines.length; index += 1) {
    const trimmed = lines[index].trim();
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) inRoot = false;
    if (inRoot && pattern.test(trimmed)) indexes.push(index);
  }
  return indexes;
}

function tableIndexes(lines, table) {
  return lines.flatMap((line, index) => line.trim() === `[${table}]` ? [index] : []);
}

function rootBlock() {
  return [ROOT_START, `model_provider = ${JSON.stringify(PROVIDER_NAME)}`, ROOT_END];
}

function providerBlock(baseUrl) {
  return [
    PROVIDER_START,
    `[model_providers.${PROVIDER_NAME}]`,
    `name = "pxpipe for Codex"`,
    `base_url = ${JSON.stringify(baseUrl)}`,
    `wire_api = "responses"`,
    `requires_openai_auth = true`,
    `supports_websockets = false`,
    PROVIDER_END,
  ];
}

function normalizeText(lines) {
  while (lines.length > 0 && lines.at(-1) === "") lines.pop();
  return lines.length === 0 ? "" : `${lines.join("\n")}\n`;
}

function exactBlock(lines, range, expected) {
  if (!range) return false;
  return JSON.stringify(lines.slice(range.start, range.end + 1)) === JSON.stringify(expected);
}

function removeRange(lines, range) {
  if (range) lines.splice(range.start, range.end - range.start + 1);
}

function restoreOriginalRootKey(current, original, key) {
  const originalIndexes = rootKeyIndexes(original, key);
  const currentIndexes = rootKeyIndexes(current, key);
  if (originalIndexes.length > 1) throw new Error(`Backup contains duplicate top-level ${key} keys`);
  if (currentIndexes.length > 1) throw new Error(`Codex config contains duplicate top-level ${key} keys`);
  if (originalIndexes.length === 1 && currentIndexes.length === 0) {
    const firstTable = current.findIndex((line) => /^\s*\[/.test(line));
    const at = firstTable < 0 ? current.length : firstTable;
    current.splice(at, 0, original[originalIndexes[0]], ...(at > 0 && current[at - 1] !== "" ? [""] : []));
  }
}

function validateManagedCurrent(lines, baseUrl) {
  const rootRange = rangeFor(lines, ROOT_START, ROOT_END);
  const providerRange = rangeFor(lines, PROVIDER_START, PROVIDER_END);
  if (!exactBlock(lines, rootRange, rootBlock()) || !exactBlock(lines, providerRange, providerBlock(baseUrl))) {
    throw new Error("Managed pxpipe provider configuration was changed after installation; refusing to overwrite it");
  }
}

function validateLegacyCurrent(lines, baseUrl) {
  const range = rangeFor(lines, LEGACY_START, LEGACY_END);
  const expected = [LEGACY_START, `openai_base_url = ${JSON.stringify(baseUrl)}`, LEGACY_END];
  if (range) {
    if (!exactBlock(lines, range, expected)) {
      throw new Error("Managed legacy openai_base_url was changed after installation; refusing migration");
    }
    return;
  }
  const indexes = rootKeyIndexes(lines, "openai_base_url");
  if (indexes.length !== 1 || lines[indexes[0]].trim() !== expected[1]) {
    throw new Error("Existing pxpipe install state does not match Codex config; refusing migration");
  }
}

function installText(text, baseUrl, existingState) {
  const lines = splitLines(text);
  const rootRange = rangeFor(lines, ROOT_START, ROOT_END);
  const providerRange = rangeFor(lines, PROVIDER_START, PROVIDER_END);
  const legacyRange = rangeFor(lines, LEGACY_START, LEGACY_END);

  if (existingState) {
    if (existingState.baseUrl !== baseUrl) {
      throw new Error("Existing pxpipe installation manages a different base URL; uninstall it first");
    }
    if (rootRange || providerRange) validateManagedCurrent(lines, baseUrl);
    else validateLegacyCurrent(lines, baseUrl);
  } else if (rootRange || providerRange || legacyRange) {
    throw new Error("Codex config has pxpipe managed markers but no install state; refusing to adopt them");
  }

  // Remove the old managed form before inserting the custom provider form.
  const ranges = [rootRange, providerRange, legacyRange].filter(Boolean).sort((a, b) => b.start - a.start);
  for (const range of ranges) removeRange(lines, range);

  // A legacy install can also exist as one exact unmarked root key.
  if (existingState && !rootRange && !providerRange && !legacyRange) {
    const legacyIndexes = rootKeyIndexes(lines, "openai_base_url");
    if (legacyIndexes.length === 1) lines.splice(legacyIndexes[0], 1);
  }

  const providerIndexes = rootKeyIndexes(lines, "model_provider");
  if (providerIndexes.length > 1) throw new Error("Codex config contains duplicate top-level model_provider keys");
  const unmanagedProviderTables = tableIndexes(lines, `model_providers.${PROVIDER_NAME}`);
  if (unmanagedProviderTables.length > 0) {
    throw new Error(`Codex config already defines [model_providers.${PROVIDER_NAME}]; choose another provider name first`);
  }

  const insertion = providerIndexes[0] ?? lines.findIndex((line) => /^\s*\[/.test(line));
  const at = insertion < 0 ? lines.length : insertion;
  if (providerIndexes.length === 1) lines.splice(providerIndexes[0], 1, ...rootBlock());
  else lines.splice(at, 0, ...rootBlock(), ...(at > 0 && lines[at - 1] !== "" ? [""] : []));

  while (lines.length > 0 && lines.at(-1) === "") lines.pop();
  if (lines.length > 0) lines.push("");
  lines.push(...providerBlock(baseUrl));
  return normalizeText(lines);
}

function uninstallText(currentText, originalText, baseUrl) {
  const current = splitLines(currentText);
  validateManagedCurrent(current, baseUrl);

  const original = splitLines(originalText);
  const ranges = [
    rangeFor(current, ROOT_START, ROOT_END),
    rangeFor(current, PROVIDER_START, PROVIDER_END),
  ].sort((a, b) => b.start - a.start);
  for (const range of ranges) removeRange(current, range);
  restoreOriginalRootKey(current, original, "model_provider");
  restoreOriginalRootKey(current, original, "openai_base_url");
  return normalizeText(current);
}

async function atomicWrite(file, content, mode = 0o600) {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${process.pid}`;
  await writeFile(temporary, content, { encoding: "utf8", mode });
  await chmod(temporary, mode);
  await rename(temporary, file);
}

async function install(options) {
  const config = path.resolve(options.config ?? fail("--config is required"));
  const stateFile = path.resolve(options.state ?? fail("--state is required"));
  const baseUrl = options["base-url"] ?? fail("--base-url is required");
  if (!/^http:\/\/127\.0\.0\.1:\d+\/v1$/.test(baseUrl)) fail("Base URL must be a loopback http /v1 URL");

  const existed = existsSync(config);
  const original = existed ? await readFile(config, "utf8") : "";
  const existingState = existsSync(stateFile) ? JSON.parse(await readFile(stateFile, "utf8")) : null;
  let backup = existingState?.backup;
  if (!backup || !existsSync(backup)) {
    await mkdir(path.dirname(stateFile), { recursive: true });
    backup = `${stateFile}.config-before`;
    await writeFile(backup, original, { encoding: "utf8", mode: 0o600 });
    await chmod(backup, 0o600);
  }

  let updated;
  try {
    updated = installText(original, baseUrl, existingState);
  } catch (error) {
    fail(error.message);
  }
  await atomicWrite(config, updated);
  const state = {
    schema: "pxpipe-codex-default/v2",
    config,
    backup,
    configExisted: existingState?.configExisted ?? existed,
    beforeSha256: existingState?.beforeSha256 ?? sha256(await readFile(backup)),
    managedSha256: sha256(updated),
    providerName: PROVIDER_NAME,
    baseUrl,
  };
  await atomicWrite(stateFile, `${JSON.stringify(state, null, 2)}\n`);
  process.stdout.write(`Codex default provider configured: ${PROVIDER_NAME} -> ${baseUrl}\n`);
}

async function uninstall(options) {
  const config = path.resolve(options.config ?? fail("--config is required"));
  const stateFile = path.resolve(options.state ?? fail("--state is required"));
  if (!existsSync(stateFile)) {
    process.stdout.write("No pxpipe-managed Codex default configuration found.\n");
    return;
  }
  const state = JSON.parse(await readFile(stateFile, "utf8"));
  if (!state.backup || !existsSync(state.backup)) fail("pxpipe Codex config backup is missing; refusing destructive rollback");
  const current = existsSync(config) ? await readFile(config, "utf8") : "";
  const original = await readFile(state.backup, "utf8");
  let restored;
  try {
    restored = uninstallText(current, original, state.baseUrl);
  } catch (error) {
    fail(error.message);
  }
  if (!state.configExisted && restored === "") {
    if (existsSync(config)) await unlink(config);
  } else {
    await atomicWrite(config, restored);
  }
  await unlink(state.backup);
  await unlink(stateFile);
  process.stdout.write("Codex default provider configuration restored.\n");
}

async function status(options) {
  const config = path.resolve(options.config ?? fail("--config is required"));
  const stateFile = path.resolve(options.state ?? fail("--state is required"));
  if (!existsSync(config)) fail("Codex config is missing");
  if (!existsSync(stateFile)) fail("pxpipe Codex install state is missing");
  const state = JSON.parse(await readFile(stateFile, "utf8"));
  const lines = splitLines(await readFile(config, "utf8"));
  try {
    validateManagedCurrent(lines, state.baseUrl);
  } catch (error) {
    fail(error.message);
  }
  process.stdout.write(`model_provider = ${JSON.stringify(PROVIDER_NAME)}\n`);
  process.stdout.write(`base_url = ${JSON.stringify(state.baseUrl)}\n`);
  process.stdout.write("supports_websockets = false\n");
}

const { action, options } = parseArgs(process.argv.slice(2));
if (action === "install") await install(options);
else if (action === "uninstall") await uninstall(options);
else if (action === "status") await status(options);
else fail("Usage: codex-default-config.mjs <install|uninstall|status> --config PATH --state PATH [--base-url URL]");
