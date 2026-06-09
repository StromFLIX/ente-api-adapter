# syntax=docker/dockerfile:1

# --- Build stage: static musl binary --------------------------------------
FROM rust:alpine AS builder

# musl-dev for libc headers; the rest are needed to build the rustls crypto
# provider (aws-lc-rs) from source under musl.
RUN apk add --no-cache musl-dev build-base cmake perl

WORKDIR /app

# Cache dependencies first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
# Touch main so cargo rebuilds with the real sources.
RUN touch src/main.rs && cargo build --release \
    && strip target/release/ente-api

# --- Runtime stage: scratch (just the static binary) ----------------------
FROM scratch

COPY --from=builder /app/target/release/ente-api /ente-api

ENV HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

ENTRYPOINT ["/ente-api"]
