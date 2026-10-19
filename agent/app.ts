import type { IncomingMessage, ServerResponse } from "node:http";
import type { HeartbeatState } from "./report.ts";

export interface AgentStatus {
  version: string;
  heartbeat: HeartbeatState;
  lastScanAt: () => string | undefined;
  lastError: () => string | undefined;
  scans: () => number;
  scanFailures: () => number;
  lastPackages: () => number;
  lastScanSeconds: () => number;
}

function send(res: ServerResponse, status: number, body: string, type = "application/json") {
  res.writeHead(status, { "content-type": type, "content-length": Buffer.byteLength(body), "x-content-type-options": "nosniff" });
  res.end(body);
}

/** Health and metrics for the agent (ADR 0017). The agent has no API of its own. */
export function createAgentHandler(s: AgentStatus) {
  return (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;

    if (path === "/healthz") return send(res, 200, JSON.stringify({ status: "ok" }));

    if (path === "/readyz") {
      const problems = [
        !s.lastScanAt() && `no scan sent yet${s.lastError() ? `: ${s.lastError()}` : ""}`,
        s.lastScanAt() && s.lastError() && `last scan failed: ${s.lastError()}`,
        !s.heartbeat.ok && `vulns unreachable${s.heartbeat.lastError ? `: ${s.heartbeat.lastError}` : ""}`,
      ].filter(Boolean);
      return send(res, problems.length ? 503 : 200, JSON.stringify(problems.length ? { status: "not ready", problems } : { status: "ready" }));
    }

    if (path === "/metrics") {
      const at = s.lastScanAt();
      const lines = [
        "# HELP openasy_build_info Build information.",
        "# TYPE openasy_build_info gauge",
        `openasy_build_info{product="vulns-agent",version="${s.version}"} 1`,
        "# HELP openasy_vulns_agent_scans_total Scans sent to vulns.",
        "# TYPE openasy_vulns_agent_scans_total counter",
        `openasy_vulns_agent_scans_total ${s.scans()}`,
        "# HELP openasy_vulns_agent_scan_failures_total Scans that failed or were refused.",
        "# TYPE openasy_vulns_agent_scan_failures_total counter",
        `openasy_vulns_agent_scan_failures_total ${s.scanFailures()}`,
        "# HELP openasy_vulns_agent_last_scan_timestamp_seconds When the last scan was sent; 0 before the first.",
        "# TYPE openasy_vulns_agent_last_scan_timestamp_seconds gauge",
        `openasy_vulns_agent_last_scan_timestamp_seconds ${at ? Math.floor(Date.parse(at) / 1000) : 0}`,
        "# HELP openasy_vulns_agent_last_scan_seconds How long the last scan took.",
        "# TYPE openasy_vulns_agent_last_scan_seconds gauge",
        `openasy_vulns_agent_last_scan_seconds ${s.lastScanSeconds()}`,
        "# HELP openasy_vulns_agent_packages Packages in the last SBOM.",
        "# TYPE openasy_vulns_agent_packages gauge",
        `openasy_vulns_agent_packages ${s.lastPackages()}`,
        "# HELP openasy_heartbeat_failures_total Failed heartbeats to vulns.",
        "# TYPE openasy_heartbeat_failures_total counter",
        `openasy_heartbeat_failures_total ${s.heartbeat.failures}`,
      ];
      return send(res, 200, lines.join("\n") + "\n", "text/plain; version=0.0.4");
    }

    send(res, 404, JSON.stringify({ error: "not found" }));
  };
}
