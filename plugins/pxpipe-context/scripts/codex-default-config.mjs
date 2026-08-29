#!/usr/bin/env node
import fs from "node:fs";
import { createHash, randomBytes } from "node:crypto";
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

const MAX_PRIVATE_BYTES = 2 * 1024 * 1024;
const OWNER = typeof process.getuid === "function" ? process.getuid() : null;
const HEX_SHA256 = /^[0-9a-f]{64}$/;

function privateParent(file) {
  const parent = path.dirname(file);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const observed = fs.lstatSync(parent);
  if (!observed.isDirectory() || observed.isSymbolicLink()
      || (OWNER !== null && observed.uid !== OWNER) || (observed.mode & 0o077) !== 0) {
    throw new Error(`Private state parent is unsafe: ${parent}`);
  }
  return parent;
}

function decodeUtf8(raw, label) {
  const text = raw.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(raw)) throw new Error(`${label} is not valid UTF-8`);
  return text;
}

function privateSnapshot(file, label, { allowMissing = false, exactMode = null } = {}) {
  let before;
  try { before = fs.lstatSync(file); }
  catch (error) {
    if (allowMissing && error.code === "ENOENT") return null;
    throw new Error(`${label} is missing or unsafe`);
  }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
      || before.size > MAX_PRIVATE_BYTES || (OWNER !== null && before.uid !== OWNER)
      || (before.mode & 0o077) !== 0 || (exactMode !== null && (before.mode & 0o777) !== exactMode)) {
    throw new Error(`${label} must be one bounded owner-private single-link regular file`);
  }
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const opened = fs.fstatSync(descriptor);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.nlink !== 1
        || opened.size !== before.size || (OWNER !== null && opened.uid !== OWNER)) {
      throw new Error(`${label} changed while opening`);
    }
    const raw = fs.readFileSync(descriptor);
    if (raw.length !== opened.size || raw.length > MAX_PRIVATE_BYTES) throw new Error(`${label} changed while reading`);
    return { raw, text: decodeUtf8(raw, label), dev: opened.dev, ino: opened.ino, mode: opened.mode & 0o777 };
  } finally { fs.closeSync(descriptor); }
}

function syncParent(file) {
  const descriptor = fs.openSync(path.dirname(file), fs.constants.O_RDONLY);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function removeSnapshot(file, snapshot, label) {
  const current = privateSnapshot(file, label);
  if (current.dev !== snapshot.dev || current.ino !== snapshot.ino || !current.raw.equals(snapshot.raw)) {
    throw new Error(`${label} changed before removal`);
  }
  fs.unlinkSync(file);
  syncParent(file);
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
  validateManagedCurrent(splitLines(currentText), baseUrl);
  return originalText;
}

function validBaseUrl(value) {
  const matched = /^http:\/\/127\.0\.0\.1:(\d{1,5})\/v1$/.exec(value);
  return matched !== null && Number(matched[1]) >= 1 && Number(matched[1]) <= 65535;
}

function managedState(config, stateFile) {
  const stateSnapshot = privateSnapshot(stateFile, "pxpipe Codex install state", { exactMode: 0o600 });
  let state;
  try { state = JSON.parse(stateSnapshot.text); }
  catch { throw new Error("pxpipe Codex install state is not valid JSON"); }
  const fields = ["backup", "baseUrl", "beforeSha256", "config", "configExisted", "managedSha256", "providerName", "schema"];
  if (!state || typeof state !== "object" || Array.isArray(state)
      || JSON.stringify(Object.keys(state).sort()) !== JSON.stringify(fields.sort())
      || state.schema !== "pxpipe-codex-default/v2" || state.providerName !== PROVIDER_NAME
      || state.config !== config || state.backup !== `${stateFile}.config-before`
      || typeof state.configExisted !== "boolean" || !HEX_SHA256.test(state.beforeSha256)
      || !HEX_SHA256.test(state.managedSha256) || !validBaseUrl(state.baseUrl)) {
    throw new Error("pxpipe Codex install state is invalid or has unbound paths");
  }
  const current = privateSnapshot(config, "Codex config", { exactMode: 0o600 });
  const original = privateSnapshot(state.backup, "pxpipe Codex config backup", { exactMode: 0o600 });
  if (sha256(original.raw) !== state.beforeSha256 || (!state.configExisted && original.raw.length !== 0)) {
    throw new Error("pxpipe Codex config backup does not match install state");
  }
  const expectedManaged = installText(original.text, state.baseUrl, null);
  if (sha256(expectedManaged) !== state.managedSha256) throw new Error("pxpipe Codex managed digest is invalid");
  if (sha256(current.raw) !== state.managedSha256) throw new Error("Codex config bytes drifted after pxpipe installation");
  validateManagedCurrent(splitLines(current.text), state.baseUrl);
  return { state, stateSnapshot, current, original };
}

function sameSnapshot(actual, expected) {
  return actual === null ? expected === null : (expected !== null && actual.dev === expected.dev && actual.ino === expected.ino && actual.mode === expected.mode && actual.raw.equals(expected.raw));
}

function atomicWrite(file, content, mode = 0o600, expectedSnapshot = undefined) {
  if (mode !== 0o600) throw new Error("private managed files require mode 0600");
  privateParent(file);
  const initial=privateSnapshot(file, "managed replacement target", { allowMissing: true });
  if (expectedSnapshot !== undefined && !sameSnapshot(initial,expectedSnapshot)) throw new Error("managed replacement target changed before compare-and-swap");
  const raw = Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8");
  if (raw.length > MAX_PRIVATE_BYTES) throw new Error("managed replacement exceeds its byte bound");
  const temporary = `${file}.tmp-${randomBytes(16).toString("hex")}`;
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, mode);
    fs.writeFileSync(descriptor, raw);
    fs.fchmodSync(descriptor, mode);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor); descriptor = undefined;
    const current=privateSnapshot(file,"managed replacement target",{allowMissing:true});
    if (!sameSnapshot(current,initial)) throw new Error("managed replacement target changed during compare-and-swap");
    fs.renameSync(temporary, file);
    syncParent(file);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try { fs.unlinkSync(temporary); } catch (error) { if (error.code !== "ENOENT") throw error; }
  }
}

function restoreSnapshot(file, snapshot, label) {
  const current = privateSnapshot(file, label, { allowMissing: true });
  if (snapshot === null) {
    if (current !== null) removeSnapshot(file, current, label);
  } else {
    atomicWrite(file, snapshot.raw);
  }
}

function compensate(entries, cause) {
  const failures = [];
  for (const [file, snapshot, label] of entries) {
    try { restoreSnapshot(file, snapshot, label); }
    catch (error) { failures.push(`${label}: ${error.message}`); }
  }
  if (failures.length > 0) throw new Error(`${cause.message}; compensation failed: ${failures.join("; ")}`);
  throw cause;
}

async function install(options) {
  const config = path.resolve(options.config ?? fail("--config is required"));
  const stateFile = path.resolve(options.state ?? fail("--state is required"));
  const baseUrl = options["base-url"] ?? fail("--base-url is required");
  if (!validBaseUrl(baseUrl)) fail("Base URL must be a loopback http /v1 URL with a valid port");

  privateParent(config);
  privateParent(stateFile);
  const backup = `${stateFile}.config-before`;
  if (new Set([config, stateFile, backup]).size !== 3) fail("Config, state, and backup paths must be distinct");
  const priorConfig = privateSnapshot(config, "Codex config", { allowMissing: true, exactMode: 0o600 });
  const priorState = privateSnapshot(stateFile, "pxpipe Codex install state", { allowMissing: true, exactMode: 0o600 });
  const priorBackup = privateSnapshot(backup, "pxpipe Codex config backup", { allowMissing: true, exactMode: 0o600 });

  let existingState = null;
  if (priorState !== null) {
    const authenticated = managedState(config, stateFile);
    if (authenticated.stateSnapshot.dev !== priorState.dev || authenticated.stateSnapshot.ino !== priorState.ino
        || !authenticated.stateSnapshot.raw.equals(priorState.raw)
        || authenticated.current.dev !== priorConfig?.dev || authenticated.current.ino !== priorConfig?.ino
        || authenticated.original.dev !== priorBackup?.dev || authenticated.original.ino !== priorBackup?.ino) {
      throw new Error("Codex managed files changed during authenticated planning");
    }
    existingState = authenticated.state;
  } else if (priorBackup !== null) {
    throw new Error("Orphaned pxpipe Codex backup exists without authenticated install state");
  }

  const original = priorConfig?.text ?? "";
  const updated = installText(original, baseUrl, existingState);
  const state = {
    schema: "pxpipe-codex-default/v2",
    config,
    backup,
    configExisted: existingState?.configExisted ?? (priorConfig !== null),
    beforeSha256: existingState?.beforeSha256 ?? sha256(original),
    managedSha256: sha256(installText(existingState ? priorBackup.text : original, baseUrl, null)),
    providerName: PROVIDER_NAME,
    baseUrl,
  };

  try {
    if (priorBackup === null) atomicWrite(backup, original);
    atomicWrite(config, updated);
    atomicWrite(stateFile, `${JSON.stringify(state, null, 2)}\n`);
  } catch (error) {
    compensate([
      [config, priorConfig, "Codex config"],
      [backup, priorBackup, "pxpipe Codex config backup"],
      [stateFile, priorState, "pxpipe Codex install state"],
    ], error);
  }
  process.stdout.write(`Codex default provider configured: ${PROVIDER_NAME} -> ${baseUrl}\n`);
}
function planDirectory(options) {
  const directory = path.resolve(options["plan-dir"] ?? options["output-dir"] ?? fail("--plan-dir or --output-dir is required"));
  const observed = fs.lstatSync(directory);
  if (!observed.isDirectory() || observed.isSymbolicLink()
      || (OWNER !== null && observed.uid !== OWNER) || (observed.mode & 0o077) !== 0) {
    throw new Error("Uninstall plan directory must be one owner-private real directory");
  }
  return directory;
}

function writePlanArtifact(directory, key, raw) {
  const target = path.join(directory, raw === null ? `${key}.absent` : key);
  const sibling = path.join(directory, raw === null ? key : `${key}.absent`);
  if (fs.existsSync(target) || fs.existsSync(sibling)) throw new Error(`Uninstall plan artifact already exists: ${key}`);
  const bytes = raw === null ? Buffer.alloc(0) : (Buffer.isBuffer(raw) ? raw : Buffer.from(raw, "utf8"));
  let descriptor;
  try {
    descriptor = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(descriptor, bytes);
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  syncParent(target);
  return target;
}

function readPlanArtifact(directory, key, label) {
  const present = path.join(directory, key);
  const absent = `${present}.absent`;
  const value = privateSnapshot(present, label, { allowMissing: true, exactMode: 0o600 });
  const marker = privateSnapshot(absent, `${label} absence marker`, { allowMissing: true, exactMode: 0o600 });
  if ((value === null) === (marker === null)) throw new Error(`${label} topology is invalid`);
  if (marker !== null && marker.raw.length !== 0) throw new Error(`${label} absence marker is not empty`);
  return value?.raw ?? null;
}

function requirePlannedBytes(actual, expected, label) {
  if ((actual === null) !== (expected === null)
      || (actual !== null && !actual.equals(expected))) {
    throw new Error(`${label} differs from the authenticated uninstall plan`);
  }
}

function authenticatedUninstall(options) {
  const config = path.resolve(options.config ?? fail("--config is required"));
  const stateFile = path.resolve(options.state ?? fail("--state is required"));
  privateParent(config);
  privateParent(stateFile);
  const candidate = privateSnapshot(stateFile, "pxpipe Codex install state", { exactMode: 0o600 });
  const authenticated = managedState(config, stateFile);
  if (authenticated.stateSnapshot.dev !== candidate.dev || authenticated.stateSnapshot.ino !== candidate.ino
      || !authenticated.stateSnapshot.raw.equals(candidate.raw)) {
    throw new Error("pxpipe Codex install state changed during authenticated planning");
  }
  const { state, stateSnapshot, current, original } = authenticated;
  const restored = uninstallText(current.text, original.text, state.baseUrl);
  const postConfig = !state.configExisted && restored === "" ? null : Buffer.from(restored, "utf8");
  return { config, stateFile, state, stateSnapshot, current, original, restored, postConfig };
}

async function planUninstall(options) {
  const directory = planDirectory(options);
  const value = authenticatedUninstall(options);
  const created = [];
  try {
    created.push(writePlanArtifact(directory, "post-config", value.postConfig));
    created.push(writePlanArtifact(directory, "post-state", null));
    created.push(writePlanArtifact(directory, "post-backup", null));
  } catch (error) {
    for (const target of created.reverse()) {
      try { fs.unlinkSync(target); } catch (cleanupError) { if (cleanupError.code !== "ENOENT") throw cleanupError; }
    }
    syncParent(path.join(directory, "post-config"));
    throw error;
  }
  process.stdout.write("Codex default provider uninstall post-images planned.\n");
}

async function applyUninstall(options) {
  const directory = planDirectory(options);
  const value = authenticatedUninstall(options);
  requirePlannedBytes(readPlanArtifact(directory, "config", "Codex config pre-image"), value.current.raw, "Codex config pre-image");
  requirePlannedBytes(readPlanArtifact(directory, "state", "pxpipe state pre-image"), value.stateSnapshot.raw, "pxpipe state pre-image");
  requirePlannedBytes(readPlanArtifact(directory, "backup", "pxpipe backup pre-image"), value.original.raw, "pxpipe backup pre-image");
  requirePlannedBytes(readPlanArtifact(directory, "post-config", "Codex config post-image"), value.postConfig, "Codex config post-image");
  requirePlannedBytes(readPlanArtifact(directory, "post-state", "pxpipe state post-image"), null, "pxpipe state post-image");
  requirePlannedBytes(readPlanArtifact(directory, "post-backup", "pxpipe backup post-image"), null, "pxpipe backup post-image");
  try {
    if (value.postConfig === null) removeSnapshot(value.config, value.current, "Codex config");
    else atomicWrite(value.config, value.restored, 0o600, value.current);
    removeSnapshot(value.stateFile, value.stateSnapshot, "pxpipe Codex install state");
    removeSnapshot(value.state.backup, value.original, "pxpipe Codex config backup");
  } catch (error) {
    compensate([
      [value.config, value.current, "Codex config"],
      [value.state.backup, value.original, "pxpipe Codex config backup"],
      [value.stateFile, value.stateSnapshot, "pxpipe Codex install state"],
    ], error);
  }
  process.stdout.write("Codex default provider configuration restored from authenticated plan.\n");
}

async function uninstall(options) {
  const config = path.resolve(options.config ?? fail("--config is required"));
  const stateFile = path.resolve(options.state ?? fail("--state is required"));
  privateParent(config);
  privateParent(stateFile);
  const candidate = privateSnapshot(stateFile, "pxpipe Codex install state", { allowMissing: true, exactMode: 0o600 });
  if (candidate === null) {
    process.stdout.write("No pxpipe-managed Codex default configuration found.\n");
    return;
  }
  const authenticated = managedState(config, stateFile);
  if (authenticated.stateSnapshot.dev !== candidate.dev || authenticated.stateSnapshot.ino !== candidate.ino
      || !authenticated.stateSnapshot.raw.equals(candidate.raw)) {
    throw new Error("pxpipe Codex install state changed during authenticated planning");
  }
  const { state, stateSnapshot, current, original } = authenticated;
  const restored = uninstallText(current.text, original.text, state.baseUrl);
  try {
    if (!state.configExisted && restored === "") removeSnapshot(config, current, "Codex config");
    else atomicWrite(config, restored, 0o600, current);
    removeSnapshot(stateFile, stateSnapshot, "pxpipe Codex install state");
    removeSnapshot(state.backup, original, "pxpipe Codex config backup");
  } catch (error) {
    compensate([
      [config, current, "Codex config"],
      [state.backup, original, "pxpipe Codex config backup"],
      [stateFile, stateSnapshot, "pxpipe Codex install state"],
    ], error);
  }
  process.stdout.write("Codex default provider configuration restored.\n");
}

async function status(options) {
  const config = path.resolve(options.config ?? fail("--config is required"));
  const stateFile = path.resolve(options.state ?? fail("--state is required"));
  const { state } = managedState(config, stateFile);
  process.stdout.write(`model_provider = ${JSON.stringify(PROVIDER_NAME)}\n`);
  process.stdout.write(`base_url = ${JSON.stringify(state.baseUrl)}\n`);
  process.stdout.write("supports_websockets = false\n");
}
try {
  const { action, options } = parseArgs(process.argv.slice(2));
  if (action === "install") await install(options);
  else if (action === "plan-uninstall") await planUninstall(options);
  else if (action === "apply-uninstall") await applyUninstall(options);
  else if (action === "uninstall") await uninstall(options);
  else if (action === "status") await status(options);
  else fail("Usage: codex-default-config.mjs <install|plan-uninstall|apply-uninstall|uninstall|status> --config PATH --state PATH [--base-url URL]");
} catch (error) {
  fail(error instanceof Error ? error.message : "Codex config operation failed");
}
