import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { parentPort, workerData } from "node:worker_threads";

const MAX_PAGES = 8;
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const MAX_FACTSHEET_BYTES = 64 * 1024;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

try {
  const {
    runtimeBase64,
    runtimeSha256,
    sourceText,
    sourceFiles,
    model,
    selfTestDelayMs = 0,
  } = workerData;
  if (typeof runtimeBase64 !== "string" || runtimeBase64.length === 0) {
    throw new Error("verified runtime bytes were not provided");
  }
  const runtimeBytes = Buffer.from(runtimeBase64, "base64");
  const actualSha256 = sha256(runtimeBytes);
  if (actualSha256 !== runtimeSha256) throw new Error("verified runtime bytes do not match their SHA-256");
  if (Number.isSafeInteger(selfTestDelayMs) && selfTestDelayMs > 0) {
    await delay(Math.min(selfTestDelayMs, 30_000));
  }
  const runtime = await import(`data:text/javascript;base64,${runtimeBase64}`);
  if (typeof runtime.runExportCore !== "function") throw new Error("runtime does not export runExportCore");
  const result = await runtime.runExportCore(sourceText, { sourceFiles, model });
  const pages = result.artifacts.filter(({ filename }) => /^page-\d+\.png$/.test(filename));
  const factsheet = result.artifacts.find(({ filename }) => filename === "factsheet.txt");
  const imageBytes = pages.reduce((sum, item) => sum + item.data.byteLength, 0);
  if (pages.length > MAX_PAGES) throw new Error(`render produced more than ${MAX_PAGES} pages`);
  if (imageBytes > MAX_IMAGE_BYTES) throw new Error(`render produced more than ${MAX_IMAGE_BYTES} image bytes`);
  if (factsheet === undefined || factsheet.data.byteLength > MAX_FACTSHEET_BYTES) {
    throw new Error("render produced an invalid or oversized factsheet");
  }
  parentPort.postMessage({ ok: true, result });
} catch (error) {
  parentPort.postMessage({
    ok: false,
    error: error instanceof Error ? error.message : String(error),
  });
}
