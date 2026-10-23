import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { createAgentHandler, type AgentStatus } from "./app.ts";
import { heartbeat, sendSbom, type HeartbeatState } from "./report.ts";
import { DEFAULT_EXCLUDES, packagesIn, scan, syftArgs } from "./scan.ts";

const servers: Server[] = [];
afterEach(() => Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r)))));

async function listen(handler: RequestListener): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  return `http://localhost:${(server.address() as AddressInfo).port}`;
}

async function read(req: Parameters<RequestListener>[0]): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks);
}

const target = (url: string) => ({ url, token: "t", id: "web-1", version: "1.2.3", platform: "kubernetes" as const });

describe("syft", () => {
  it("scans the host root, names the SBOM after the host and skips what is not the host's software", () => {
    const args = syftArgs({ bin: "syft", root: "/host", name: "web-1", excludes: [...DEFAULT_EXCLUDES, "/srv/cache/"] });
    expect(args.slice(0, 7)).toEqual(["scan", "dir:/host", "--source-name", "web-1", "-o", "syft-json", "-q"]);
    expect(args).toContain("./proc/**");
    expect(args).toContain("./var/lib/docker/**");
    expect(args).toContain("./srv/cache/**");
  });

  it("returns the SBOM, and Syft's last error line when it fails", async () => {
    const dir = mkdtempSync(join(tmpdir(), "syft-"));
    const ok = join(dir, "ok");
    writeFileSync(ok, `#!/bin/sh\n[ "$SYFT_CHECK_FOR_APP_UPDATE" = false ] || exit 3\necho '{"artifacts":[{"name":"bash"}]}'\n`);
    const bad = join(dir, "bad");
    writeFileSync(bad, "#!/bin/sh\necho 'could not read /host/var/lib/dpkg' >&2\nexit 1\n");
    chmodSync(ok, 0o755);
    chmodSync(bad, 0o755);
    const opts = { root: "/host", name: "web-1", excludes: [] };
    expect(JSON.parse((await scan({ ...opts, bin: ok })).toString())).toEqual({ artifacts: [{ name: "bash" }] });
    await expect(scan({ ...opts, bin: bad })).rejects.toThrow("syft failed (exit 1): could not read /host/var/lib/dpkg");
  });
});

describe("an empty SBOM", () => {
  it("is never sent: it would resolve every finding of the host", () => {
    expect(packagesIn(Buffer.from('{"artifacts":[{"name":"bash"},{"name":"openssl"}]}'), "/host")).toBe(2);
    expect(() => packagesIn(Buffer.from('{"artifacts":[]}'), "/host")).toThrow(/no packages under \/host.*nothing was sent/);
  });
});

describe("reporting to vulns", () => {
  it("sends the heartbeat with the token and hears scan requests", async () => {
    let received: { auth?: string; body?: unknown } = {};
    const url = await listen(async (req, res) => {
      received = { auth: req.headers.authorization, body: JSON.parse((await read(req)).toString()) };
      res.writeHead(202).end(JSON.stringify({ status: "accepted", scanNow: true }));
    });
    const state: HeartbeatState = { ok: false, failures: 0 };
    expect(await heartbeat(target(url), { lastScanAt: "2026-10-19T00:00:00.000Z" }, state)).toBe(true);
    expect(state).toMatchObject({ ok: true, lastStatus: 202, failures: 0 });
    expect(received).toEqual({
      auth: "Bearer t",
      body: { id: "web-1", version: "1.2.3", platform: "kubernetes", lastScanAt: "2026-10-19T00:00:00.000Z", lastError: null },
    });
  });

  it("keeps vulns's explanation when the heartbeat is refused", async () => {
    const url = await listen((_req, res) =>
      res
        .writeHead(409, { "content-type": "application/problem+json" })
        .end(JSON.stringify({ status: 409, code: "version-mismatch", title: "Version mismatch", detail: "install vulns-agent 1.2.4" })),
    );
    const state: HeartbeatState = { ok: true, failures: 0 };
    expect(await heartbeat(target(url), {}, state)).toBe(false);
    expect(state).toMatchObject({ ok: false, lastStatus: 409, lastError: "install vulns-agent 1.2.4", failures: 1 });
  });

  it("sends the SBOM gzipped as this host", async () => {
    let got: { path?: string; encoding?: string; body?: string } = {};
    const url = await listen(async (req, res) => {
      got = { path: req.url, encoding: req.headers["content-encoding"], body: gunzipSync(await read(req)).toString() };
      res.writeHead(202).end(JSON.stringify({ match: { status: "queued" }, open: { critical: 0 } }));
    });
    expect(await sendSbom(target(url), Buffer.from('{"artifacts":[]}'))).toEqual({ status: "queued", open: { critical: 0 } });
    expect(got).toEqual({ path: "/api/v1/sboms?kind=host&name=web-1", encoding: "gzip", body: '{"artifacts":[]}' });
  });

  it("throws with the reason when the SBOM is refused", async () => {
    const url = await listen((_req, res) => res.writeHead(401).end(JSON.stringify({ detail: "Send VULNS_INGEST_TOKEN as a bearer token." })));
    await expect(sendSbom(target(url), Buffer.from("{}"))).rejects.toThrow("vulns refused the SBOM: Send VULNS_INGEST_TOKEN as a bearer token.");
  });
});

describe("health", () => {
  const base: AgentStatus = {
    version: "1.2.3",
    heartbeat: { ok: true, failures: 0 },
    lastScanAt: () => undefined,
    lastError: () => undefined,
    scans: () => 0,
    scanFailures: () => 0,
    lastPackages: () => 0,
    lastScanSeconds: () => 0,
  };

  it("is not ready before the first scan or without vulns", async () => {
    const url = await listen(
      createAgentHandler({ ...base, heartbeat: { ok: false, failures: 2, lastError: "fetch failed" }, lastError: () => "syft failed (exit 1): boom" }),
    );
    expect((await fetch(`${url}/healthz`)).status).toBe(200);
    const res = await fetch(`${url}/readyz`);
    expect(res.status).toBe(503);
    expect(((await res.json()) as { problems: string[] }).problems).toEqual([
      "no scan sent yet: syft failed (exit 1): boom",
      "vulns unreachable: fetch failed",
    ]);
  });

  it("is ready after a scan, and exposes metrics", async () => {
    const url = await listen(createAgentHandler({ ...base, lastScanAt: () => "2026-10-19T00:00:00.000Z", scans: () => 3, lastPackages: () => 412 }));
    expect((await fetch(`${url}/readyz`)).status).toBe(200);
    const metrics = await (await fetch(`${url}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="vulns-agent",version="1.2.3"} 1');
    expect(metrics).toContain("openasy_vulns_agent_scans_total 3");
    expect(metrics).toContain("openasy_vulns_agent_packages 412");
    expect(metrics).toContain("openasy_vulns_agent_last_scan_timestamp_seconds 1792368000");
  });
});
