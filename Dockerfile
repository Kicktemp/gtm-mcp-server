# Kicktemp fork: multi-stage build, distroless non-root runtime, base images pinned by digest.
# Refresh the digests with: docker buildx imagetools inspect <image>:<tag>

# Build stage (Google mirror avoids Docker Hub rate limits). golang:1.26-alpine at this digest is Go 1.26.8.
FROM mirror.gcr.io/library/golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-w -s" -o gtm-mcp-server .
# Data directory for the audit log and token store, owned by the runtime user (65532).
RUN mkdir -p /out/data && chmod 700 /out/data

# Runtime stage: no shell, no package manager, CA certificates and tzdata included.
FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=builder --chown=65532:65532 /app/gtm-mcp-server /gtm-mcp-server
COPY --from=builder --chown=65532:65532 /out/data /data
# Inside the container the server must listen on all interfaces; publish the port on 127.0.0.1 only.
ENV KT_LISTEN_ADDR=0.0.0.0:8080
USER 65532:65532
EXPOSE 8080
# distroless has no wget/curl: the binary probes its own /health.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/gtm-mcp-server", "-healthcheck"]
ENTRYPOINT ["/gtm-mcp-server"]
