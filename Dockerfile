# syntax=docker/dockerfile:1

ARG BINARY

# ==========================
# Stage: minimal
# ==========================
FROM debian:12-slim AS minimal

RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    \
    && curl -fL \
        --retry 5 \
        --retry-delay 3 \
        --connect-timeout 10 \
        --max-time 120 \
        -o /tmp/upx.tar.xz \
        https://github.com/telemt/telemt/releases/download/toolchains/upx-amd64_linux.tar.xz \
    && tar -xf /tmp/upx.tar.xz -C /tmp \
    && mv /tmp/upx*/upx /usr/local/bin/upx \
    && chmod +x /usr/local/bin/upx \
    && rm -rf /tmp/upx*

COPY ${BINARY} /telemt

RUN strip /telemt || true
RUN upx --best --lzma /telemt || true

# ==========================
# Debug image
# ==========================
FROM debian:12-slim AS debug

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    curl \
    iproute2 \
    busybox \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=minimal /telemt /app/telemt
COPY config.toml /app/config.toml

EXPOSE 443 9090 9091

ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]

# ==========================
# Production (REAL distroless)
# ==========================
FROM gcr.io/distroless/static-debian12 AS prod

WORKDIR /app

COPY --from=minimal /telemt /app/telemt
COPY config.toml /app/config.toml

USER nonroot:nonroot

EXPOSE 443 9090 9091

ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]