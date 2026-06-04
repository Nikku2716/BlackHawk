# ---- Build stage ----
FROM rust:slim AS builder

WORKDIR /build

# Install build dependencies for OpenSSL (required by reqwest/native-tls)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Cache dependency compilation: copy manifests first, build a dummy, then swap in real source
COPY Cargo.toml Cargo.toml
RUN mkdir src && echo 'fn main() { println!("dummy"); }' > src/main.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Copy actual source and build
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# ---- Runtime stage ----
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime deps: OpenSSL libs + curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/zscanner-api /app/zscanner-api

EXPOSE 8000

CMD ["/app/zscanner-api"]
