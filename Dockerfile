# syntax=docker/dockerfile:1.7
FROM rust:1.85-bookworm AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release && \
    cp target/release/zju-connect /usr/local/bin/zju-connect

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates iproute2 libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/zju-connect /usr/local/bin/zju-connect
WORKDIR /etc/zju-connect
ENTRYPOINT ["/usr/local/bin/zju-connect", "--config", "/etc/zju-connect/config.toml"]
