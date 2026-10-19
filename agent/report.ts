// Everything the agent sends goes to the vulns API (ADR 0018, 0023). The agent accepts no inbound requests from it.
import { gzipSync } from "node:zlib";
import { log } from "./log.ts";

export interface Target {
  url: string;
  token: string;
  id: string;
  version: string;
  /** kubernetes when the Helm chart runs it on a node; container otherwise. */
  platform: "container" | "kubernetes";
}

export interface HeartbeatState {
  ok: boolean;
  lastStatus?: number;
  lastError?: string;
  failures: number;
}

/** vulns answers with RFC 9457 Problem Details (ADR 0024). */
async function problem(res: Response): Promise<string> {
  const p = (await res.json().catch(() => ({}))) as { detail?: string; title?: string };
  return p.detail ?? p.title ?? `${res.status} ${res.statusText}`;
}

/** Reports this agent. Returns whether vulns asks for a scan now. */
export async function heartbeat(t: Target, status: { lastScanAt?: string; lastError?: string }, state: HeartbeatState): Promise<boolean> {
  try {
    const res = await fetch(new URL("/api/v1/agents/heartbeat", t.url), {
      method: "POST",
      headers: { authorization: `Bearer ${t.token}`, "content-type": "application/json" },
      body: JSON.stringify({ id: t.id, version: t.version, platform: t.platform, lastScanAt: status.lastScanAt ?? null, lastError: status.lastError?.slice(0, 1000) ?? null }),
      signal: AbortSignal.timeout(10_000),
    });
    state.lastStatus = res.status;
    state.ok = res.ok;
    if (res.ok) {
      state.lastError = undefined;
      return ((await res.json().catch(() => ({}))) as { scanNow?: unknown }).scanNow === true;
    }
    state.lastError = await problem(res);
  } catch (err) {
    state.ok = false;
    state.lastStatus = undefined;
    state.lastError = String(err);
  }
  state.failures++;
  log("warn", "heartbeat failed", { status: state.lastStatus, error: state.lastError });
  return false;
}

/** Sends the host's SBOM, gzipped. Throws with vulns's explanation when it is refused. */
export async function sendSbom(t: Target, sbom: Buffer): Promise<{ status: string; open: Record<string, number> } | undefined> {
  const res = await fetch(new URL(`/api/v1/sboms?kind=host&name=${encodeURIComponent(t.id)}`, t.url), {
    method: "POST",
    headers: { authorization: `Bearer ${t.token}`, "content-type": "application/json", "content-encoding": "gzip" },
    body: gzipSync(sbom),
    signal: AbortSignal.timeout(120_000),
  });
  if (!res.ok) throw new Error(`vulns refused the SBOM: ${await problem(res)}`);
  const asset = (await res.json().catch(() => undefined)) as { match?: { status: string }; open?: Record<string, number> } | undefined;
  return asset?.match ? { status: asset.match.status, open: asset.open ?? {} } : undefined;
}
