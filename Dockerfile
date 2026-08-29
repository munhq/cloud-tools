# cloud-tools as a container, for Docker's MCP catalog.
#
# The image fetches the release asset for the target architecture and verifies it
# against the SHA256SUMS published beside it — the same contract npm/bin/resolve.js
# and install.sh follow, and npm/test_platform.sh holds all three to the release
# matrix.
#
# The server speaks MCP over stdio, so the client talks to the container's stdin
# and stdout and `-i` is required:
#
#   docker run -i --rm \
#     -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_REGION \
#     munhq/cloud-tools
#
# Credentials come from the environment, because that is where every one of these
# clouds already keeps them. Nothing is written to the image or the host.
ARG VERSION=0.2.0

FROM alpine:3.21 AS fetch
ARG VERSION
ARG TARGETARCH
RUN apk add --no-cache ca-certificates curl
WORKDIR /out
# TARGETARCH is Docker's vocabulary (amd64/arm64); the release names assets by
# machine architecture. The mapping is spelled out rather than assembled, and
# npm/test_platform.sh asserts these two lines against the release matrix.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) ASSET="cloud-tools-x86_64-linux" ;; \
      arm64) ASSET="cloud-tools-aarch64-linux" ;; \
      *) echo "no cloud-tools release build for TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac; \
    BASE="https://github.com/munhq/cloud-tools/releases/download/v${VERSION}"; \
    curl -fsSL -o cloud-tools "$BASE/$ASSET"; \
    curl -fsSL -o SHA256SUMS "$BASE/SHA256SUMS"; \
    WANT="$(awk -v a="$ASSET" '$2==a{print $1}' SHA256SUMS)"; \
    [ -n "$WANT" ] || { echo "SHA256SUMS for v${VERSION} does not list $ASSET" >&2; exit 1; }; \
    printf '%s  cloud-tools\n' "$WANT" | sha256sum -c -; \
    chmod 0755 cloud-tools; \
    rm SHA256SUMS

# The release binary is a glibc build, so the runtime stage needs glibc. Debian
# slim rather than distroless: cloud-tools calls four cloud APIs over TLS and
# needs the CA bundle, and a shell-less image makes a credential problem
# undiagnosable.
FROM debian:bookworm-slim
ARG VERSION
LABEL org.opencontainers.image.title="cloud-tools" \
      org.opencontainers.image.description="Multi-cloud cost, inventory and waste analysis over MCP: AWS, GCP, Cloudflare and OVH." \
      org.opencontainers.image.source="https://github.com/munhq/cloud-tools" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /out/cloud-tools /usr/local/bin/cloud-tools
# The server reads credentials, never writes them, and needs no state of its own.
RUN useradd --system --create-home --shell /usr/sbin/nologin cloudtools
USER cloudtools
# MCP over stdio is the default mode, so an MCP client needs no configuration.
# CLOUD_TOOLS_MODE=http switches to the REST API, which also needs a published
# port; that is a deliberate opt-in, not the default a catalog installs.
ENV CLOUD_TOOLS_MODE=mcp
# stdio: the client speaks JSON-RPC over the container's stdin and stdout, so
# `docker run -i` is required and nothing may be printed to stdout but protocol.
ENTRYPOINT ["/usr/local/bin/cloud-tools"]
