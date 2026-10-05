# Aegis runtime image.
#
# Deliberately minimal: Node 22 alone, no npm install, no build toolchain. The
# scanner's own supply-chain surface is therefore zero packages rather than
# "a few hundred, none of which we audited".
FROM node:22-alpine

# `tini` reaps zombies and forwards signals, so a killed agent does not leave
# the scanner hanging.
RUN apk add --no-cache tini

# Never run as root. A scanner that reads your source should not be able to
# write to the host if it is ever compromised.
RUN addgroup -S aegis && adduser -S -G aegis aegis

WORKDIR /opt/aegis

# Only the runtime files. No tests, no fixtures, no package metadata that
# implies an install step.
COPY --chown=aegis:aegis packages/core/src ./packages/core/src
COPY --chown=aegis:aegis packages/cli/src ./packages/cli/src
COPY --chown=aegis:aegis packages/rules ./packages/rules
COPY --chown=aegis:aegis packages/web/src ./packages/web/src
COPY --chown=aegis:aegis packages/web/public ./packages/web/public
COPY --chown=aegis:aegis tools ./tools
COPY --chown=aegis:aegis package.json tsconfig.base.json ./

ENV NODE_ENV=production \
    AEGIS_TELEMETRY=0

USER aegis

# The workspace is mounted at runtime, read-only by default.
VOLUME ["/workspace"]

ENTRYPOINT ["/sbin/tini", "--", "node", "--import", "/opt/aegis/tools/register-ts.mjs", "/opt/aegis/packages/cli/src/bin.ts"]
CMD ["--help"]

LABEL org.opencontainers.image.title="Aegis" \
      org.opencontainers.image.description="The security platform for AI agents" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/aegis-security/aegis" \
      org.opencontainers.image.version="0.1.0"