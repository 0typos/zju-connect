# Changelog

All notable changes to the Rust/Linux port are documented here. The port has
its own version line and does not track the Go project's tags. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Ground-up Rust rewrite of the Linux client for Sangfor EasyConnect and aTrust
  gateways: password/CAPTCHA/SMS/TOTP authentication, multi-line selection,
  server resource and split-tunnel policy parsing, the EasyConnect L3IP
  TLS 1.1/RC4-SHA data plane, the aTrust L3 packet and per-application TCP
  tunnels, Linux TUN setup with `iproute2` routing, and SOCKS5/HTTP proxies.
- A reusable async library API (`VpnClient`, `EasyConnectClient`,
  `AtrustClient`, policy, resource, proxy, and TUN modules).
- Certificate verification on the authentication channel (default on), with an
  `insecure_skip_verify` opt-out for self-signed gateways.
- HTTP proxy `Proxy-Authorization` (Basic) support, shared with the SOCKS
  credentials.
- Resolved-address DNS caching (`dns_ttl`) and a `secondary_dns_server`
  fallback.
- Release workflow that attaches cross-compiled `x86_64` and `aarch64` Linux
  binaries to each GitHub release.

### Changed

- Proxies default to `127.0.0.1`. Binding a non-loopback address requires
  credentials or an explicit `allow_open_proxy` acknowledgement.
- `--add-route` is meaningful again: proxy-only mode uses per-connection host
  routes and no longer installs host-wide routes unless requested.
- Exit codes distinguish configuration (2) and authentication (3) failures from
  transient runtime errors (1).
- Frame headers are (de)serialized with `binrw` instead of hand-rolled byte
  packing.
- The public `Error` type no longer exposes `reqwest`; `Error`, `Resources`,
  `IpResource`, `DomainResource`, and `ConnectionInfo` are `#[non_exhaustive]`.

### Fixed

- aTrust control-plane connect: tolerate the gateway's interleaved control
  frames (the `05 d0` method echo and deferred status frames) instead of
  erroring, matching the official client.
- Survivability: reconnect dropped tunnels (EasyConnect up to five times per
  direction; aTrust node connections with a cooldown), drop unroutable packets
  instead of tearing down the tunnel, add timeouts to all tunnel and proxy
  handshakes, detect dead peers via heartbeats, evict idle flows, and handle
  SIGTERM as well as SIGINT.
- Pin the gateway address to the underlay before installing tunnel routes to
  prevent a routing loop.
- `proxy_all` no longer silently sends IPv6 traffic direct (it fails closed);
  HTTP CONNECT forwards pipelined early data; absolute-form requests force
  `Connection: close`.
- Correct license metadata to AGPL-3.0-only.

### Security

- Closes the default open-proxy relay into the campus network and the
  plaintext-password MITM vector on the authentication channel. Credentials are
  redacted from `Config`'s `Debug` output.
