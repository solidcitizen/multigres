FROM rust:1.85-slim AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/pgvpd /usr/local/bin/pgvpd
COPY sql/ /usr/local/share/pgvpd/sql/

EXPOSE 6432
ENTRYPOINT ["pgvpd"]
