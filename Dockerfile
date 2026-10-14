# Kicktemp fork: multi-stage build, distroless non-root runtime, base images pinned by digest.
# Refresh the digests with: docker buildx imagetools inspect <image>:<tag>

# Build stage (Google mirror avoids Docker Hub rate limits). golang:1.26.9-alpine at this digest is Go 1.26.9 (stdlib fixes for GO-2026-6610..6617).
FROM --platform=$BUILDPLATFORM mirror.gcr.io/library/golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS builder
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Cross-compile on the build platform: the image for TARGETARCH (amd64 on GHCR) needs no emulation.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-w -s" -o gtm-mcp-server .
# Data directory for the audit log and token store, owned by the runtime user (65532).
RUN mkdir -p /out/data && chmod 700 /out/data

# Runtime stage: no shell, no package manager, CA certificates and tzdata included.
FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=builder --chown=65532:65532 /app/gtm-mcp-server /gtm-mcp-server
COPY --from=builder --chown=65532:65532 /out/data /data
# Inside the container the server must listen on all interfaces; publish the port on 127.0.0.1 only.
# PORT is honoured (the stack sets it); KT_LISTEN_ADDR would override both.
ENV KT_LISTEN_HOST=0.0.0.0 PORT=8080
USER 65532:65532
EXPOSE 8080
# distroless has no wget/curl: the binary probes its own /health.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/gtm-mcp-server", "-healthcheck"]
ENTRYPOINT ["/gtm-mcp-server"]
