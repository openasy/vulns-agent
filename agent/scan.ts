// Syft lists the packages on the host: OS packages (dpkg, rpm, apk) and language packages it finds on disk.
// It reads the host's filesystem through a read-only mount and runs with a fixed argument list, no shell.
import { spawn } from "node:child_process";

/**
 * Paths under the host root that are not the host's own software: kernel and device trees, scratch space,
 * and container storage (images are scanned from CI, where they are built).
 */
export const DEFAULT_EXCLUDES = [
  "proc",
  "sys",
  "dev",
  "run",
  "tmp",
  "var/tmp",
  "var/lib/docker",
  "var/lib/containerd",
  "var/lib/kubelet",
  "var/lib/containers",
  "var/log",
];

export interface ScanOptions {
  bin: string;
  /** The host's root filesystem, mounted read-only, such as /host. */
  root: string;
  /** Name the SBOM carries; the host's name in vulns. */
  name: string;
  excludes: string[];
  timeoutMs?: number;
}

export function syftArgs({ root, name, excludes }: ScanOptions): string[] {
  return [
    "scan",
    `dir:${root}`,
    "--source-name",
    name,
    "-o",
    "syft-json",
    "-q",
    ...excludes.flatMap((p) => ["--exclude", `./${p.replace(/^\.?\/+|\/+$/g, "")}/**`]),
  ];
}

/**
 * Counts the packages in Syft's SBOM, and refuses an empty one: sent to vulns, it would mark every finding of this host
 * as resolved. An empty result means the host's root is not mounted or not readable, not that the host has no packages.
 */
export function packagesIn(sbom: Buffer, root: string): number {
  const n = ((JSON.parse(sbom.toString("utf8")) as { artifacts?: unknown[] }).artifacts ?? []).length;
  if (n === 0) {
    throw new Error(
      `Syft found no packages under ${root}: mount the host's / there read-only, readable by uid ${process.getuid?.() ?? "65532"}; nothing was sent`,
    );
  }
  return n;
}

/** Runs Syft and returns its JSON SBOM. */
export function scan(opts: ScanOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = spawn(opts.bin, syftArgs(opts), {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: opts.timeoutMs ?? 30 * 60_000,
      // Syft never checks for new versions of itself (ADR 0015).
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        HOME: process.env.TMPDIR ?? "/tmp",
        TMPDIR: process.env.TMPDIR ?? "/tmp",
        SYFT_CHECK_FOR_APP_UPDATE: "false",
      },
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (code === 0) return resolve(Buffer.concat(out));
      const last = Buffer.concat(err).toString("utf8").trim().split("\n").pop()?.trim();
      reject(new Error(`syft failed (${signal ? `killed by ${signal}` : `exit ${code}`}): ${last ?? ""}`));
    });
  });
}
