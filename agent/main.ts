import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { hostname } from "node:os";
import { createAgentHandler } from "./app.ts";
import { log } from "./log.ts";
import { heartbeat, sendSbom, type HeartbeatState, type Target } from "./report.ts";
import { DEFAULT_EXCLUDES, packagesIn, scan } from "./scan.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const url = process.env.VULNS_URL;
const token = process.env.VULNS_INGEST_TOKEN;
if (!url || !token) {
  log("error", "VULNS_URL and VULNS_INGEST_TOKEN are required");
  process.exit(1);
}
const id = (process.env.VULNS_AGENT_ID ?? hostname()).toLowerCase();
if (!/^[a-z0-9][a-z0-9.-]{0,62}$/.test(id)) {
  log("error", "VULNS_AGENT_ID must be a host name: lowercase letters, digits, dots and dashes", { id });
  process.exit(1);
}
const root = process.env.HOST_ROOT ?? "/host";
const port = Number(process.env.PORT ?? 9100);
const scanEvery = Number(process.env.SCAN_HOURS ?? 6) * 3_600_000;
const beatEvery = Number(process.env.HEARTBEAT_SECONDS ?? 60) * 1000;
const excludes = [...DEFAULT_EXCLUDES, ...(process.env.SCAN_EXCLUDE ?? "").split(",").map((p) => p.trim()).filter(Boolean)];
const target: Target = { url, token, id, version, platform: process.env.VULNS_AGENT_PLATFORM === "kubernetes" ? "kubernetes" : "container" };

const state: HeartbeatState = { ok: false, failures: 0 };
let lastScanAt: string | undefined;
let lastError: string | undefined;
let scans = 0;
let scanFailures = 0;
let lastPackages = 0;
let lastScanSeconds = 0;
let scanning = false;
/** After a failed scan, retry from this time on, backing off up to 30 minutes, instead of waiting SCAN_HOURS. */
let retryAt = 0;
let retryDelay = 30_000;

async function runScan(reason: string) {
  if (scanning) return;
  scanning = true;
  const started = performance.now();
  try {
    log("info", "scanning", { reason, root });
    const sbom = await scan({ bin: process.env.SYFT_BIN ?? "/usr/local/bin/syft", root, name: id, excludes });
    lastPackages = packagesIn(sbom, root);
    const result = await sendSbom(target, sbom);
    lastScanSeconds = Math.round((performance.now() - started) / 1000);
    lastScanAt = new Date().toISOString();
    lastError = undefined;
    retryDelay = 30_000;
    scans++;
    log("info", "scan sent", { packages: lastPackages, seconds: lastScanSeconds, match: result?.status });
  } catch (err) {
    lastError = (err as Error).message;
    scanFailures++;
    retryAt = Date.now() + retryDelay;
    log("warn", "scan failed", { error: lastError, retryInSeconds: retryDelay / 1000 });
    retryDelay = Math.min(retryDelay * 2, 30 * 60_000);
  } finally {
    scanning = false;
  }
}

async function beat() {
  if (await heartbeat(target, { lastScanAt, lastError }, state)) void runScan("requested from vulns");
  else if (state.ok && lastError && Date.now() >= retryAt) void runScan("retry");
}

void beat().then(() => runScan("start"));
const timers = [setInterval(() => void beat(), beatEvery), setInterval(() => void runScan("schedule"), scanEvery)];

const server = createServer(
  createAgentHandler({ version, heartbeat: state, lastScanAt: () => lastScanAt, lastError: () => lastError, scans: () => scans, scanFailures: () => scanFailures, lastPackages: () => lastPackages, lastScanSeconds: () => lastScanSeconds }),
);
server.listen(port, () => log("info", "vulns-agent started", { version, id, port, root, vulns: url, scanHours: scanEvery / 3_600_000 }));

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  setTimeout(() => process.exit(1), 10_000).unref();
  server.close(() => process.exit(0));
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
