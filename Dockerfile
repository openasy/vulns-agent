# syntax=docker/dockerfile:1

# Syft lists the host's packages. Pinned by digest (ADR 0027); Dependabot proposes updates.
FROM anchore/syft:v1.55.0@sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a AS syft

# The agent has no runtime dependencies: Node runs the TypeScript sources directly.
FROM gcr.io/distroless/nodejs26-debian13:nonroot
WORKDIR /app
COPY --from=syft /syft /usr/local/bin/syft
COPY package.json ./
COPY agent ./agent
ENV NODE_ENV=production PORT=9100 HOST_ROOT=/host TMPDIR=/tmp
EXPOSE 9100
# Unprivileged, no capabilities: package databases are world-readable on the host's root, mounted read-only at /host.
USER nonroot
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:9100/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["agent/main.ts"]
