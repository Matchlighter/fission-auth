# Multi-stage Dockerfile for Crystal Fission Auth
FROM crystallang/crystal:1.14.0-alpine AS builder

WORKDIR /app

# Copy shard files
COPY shard.yml shard.lock* ./

# Install dependencies
RUN shards install --production

# Copy source code and CRD
COPY main.cr .
COPY src/ src/
COPY k8s/crd-functionaccessrule.yaml k8s/

# Build the application (statically linked)
RUN crystal build --release --static --no-debug main.cr -o fission-auth

# Final stage - minimal runtime
FROM alpine:latest

WORKDIR /app

# Copy the compiled binary and CRD
COPY --from=builder /app/fission-auth .
COPY --from=builder /app/k8s k8s/

# Run as non-root user
RUN adduser -D -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./fission-auth"]
