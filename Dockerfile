# syntax=docker/dockerfile:1.7
FROM rust:1.85-bookworm AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release && \
    cp target/release/sftd target/release/sft /usr/local/bin/

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates iproute2 libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/sftd /usr/local/bin/sftd
COPY --from=build /usr/local/bin/sft /usr/local/bin/sft
WORKDIR /etc/sangfordetunz
# The daemon runs in the foreground; use `docker exec <container> sft ...` to
# control it, or set autostart = true on a profile to connect on startup.
ENTRYPOINT ["/usr/local/bin/sftd", "--config", "/etc/sangfordetunz/config.toml"]
