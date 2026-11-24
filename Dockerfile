FROM rust:1.83 AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN mkdir -p src && cp -r /build/src/* src/ 2>/dev/null || true
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/trust_roundabout /usr/local/bin/trust_roundabout
COPY config.toml /etc/trust_roundabout/config.toml
WORKDIR /etc/trust_roundabout
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/trust_roundabout"]
