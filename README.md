# vulns-agent

[![CI](https://github.com/openasy/vulns-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/vulns-agent/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/openasy/vulns-agent?sort=semver)](https://github.com/openasy/vulns-agent/releases)
[![Image](https://img.shields.io/badge/ghcr.io-openasy%2Fvulns--agent-2496ED?logo=docker&logoColor=white)](https://github.com/openasy/vulns-agent/pkgs/container/vulns-agent)
[![Signed with cosign](https://img.shields.io/badge/image-signed%20with%20cosign-2a6db2)](#verify-an-image)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Vulnerabilities agent: lists a host's packages with
[Syft](https://github.com/anchore/syft) and sends the SBOM to [vulns](https://github.com/openasy/vulns). It has no
database, accepts no connections and talks only to the vulns API. It always has the same version as vulns.

## Run

```bash
docker run -d --name vulns-agent --restart unless-stopped --hostname "$(hostname)" \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -v /:/host:ro -e VULNS_URL=https://vulns.example.com -e VULNS_INGEST_TOKEN=... \
  ghcr.io/openasy/vulns-agent:0.2.0
```

The agent runs as an unprivileged user with no capabilities. It reads the host's root through a read-only mount:
package databases (dpkg, rpm, apk) are readable by everyone, so it needs no more. Language packages in directories only
root can read are not seen. It skips `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`, `/var/log` and container
storage (`/var/lib/docker`, `/var/lib/containerd`, `/var/lib/containers`, `/var/lib/kubelet`): images are scanned
from CI, where they are built.

It scans on start, every `SCAN_HOURS`, and when vulns asks (the *Scan now* button, delivered with the next heartbeat).
When a scan fails, for example because vulns is still starting, it tries again after 30 seconds, doubling up to 30
minutes, instead of waiting `SCAN_HOURS`.
SBOMs are sent gzipped. Syft's own update check is off; the agent contacts nothing but vulns (ADR 0015).

| Variable | Default | |
| --- | --- | --- |
| `VULNS_URL` | | vulns base URL (required) |
| `VULNS_INGEST_TOKEN` | | Same token as vulns (required) |
| `VULNS_AGENT_ID` | host name | Name of this host in vulns: lowercase letters, digits, dots and dashes |
| `HOST_ROOT` | `/host` | Where the host's root is mounted |
| `SCAN_HOURS` | `6` | |
| `SCAN_EXCLUDE` | | More paths to skip, comma-separated, relative to the host root |
| `HEARTBEAT_SECONDS` | `60` | |
| `PORT` | `9100` | `/healthz`, `/readyz`, `/metrics` |
| `VULNS_AGENT_PLATFORM` | `container` | `kubernetes` marks the host as a Kubernetes node in vulns; the Helm chart sets it |

`/readyz` is ready when a scan was sent and vulns accepts the heartbeat; otherwise it lists the problems.

Measured on 0.1.0: about 55 MB of memory between scans; scanning an Ubuntu 24.04 root (92 packages) takes about
3 seconds. A host with many language packages takes longer and Syft uses more memory while it runs.

## Kubernetes

The [vulns Helm chart](https://github.com/openasy/vulns/tree/main/charts/vulns) runs the agent on every node as a
DaemonSet, named after the node. To report to a vulns that runs elsewhere, install only the agents:

```bash
helm install vulns-agent oci://ghcr.io/openasy/charts/vulns --version 0.2.0 --namespace openasy --create-namespace \
  --set vulns.enabled=false --set agent.url=https://vulns.example.com --set auth.ingestToken=$VULNS_INGEST_TOKEN
```

The node's `/` is mounted read-only through `hostPath`, which the Pod Security `baseline` and `restricted` levels
forbid; the namespace must allow it.

## Verify an image

```bash
cosign verify ghcr.io/openasy/vulns-agent:0.2.0 \
  --certificate-identity-regexp '^https://github.com/openasy/vulns-agent/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Develop

```bash
npm ci
npm run typecheck && npm test
```

The end-to-end test lives in vulns: `e2e/run.sh`.

## Release

Release vulns first, then push the same tag here (`v0.1.0`). The workflow refuses to publish a version of vulns-agent
for which no vulns image exists.

## Licence

[AGPL-3.0](./LICENSE). You may use, change and share it; if you run a changed version for others, including as a
hosted service, you must offer them your source code under the same licence. A commercial licence without these
obligations is available: see [ADR 0008](https://github.com/openasy/openasy.github.io/blob/main/docs/decisions/0008-open-source.md).
"OpenAsy" and its logo are trademarks and are not covered by the licence. Syft is Apache-2.0, by Anchore.
