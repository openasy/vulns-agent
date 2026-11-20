# syntax=docker/dockerfile:1

# Syft lists the host's packages. Pinned by digest (ADR 0027); Dependabot proposes updates.
FROM anchore/syft:v1.57.2@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a AS syft

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
