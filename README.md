# sangfordetunz

An asynchronous Rust library, daemon (`sftd`), and client (`sft`) for connecting to Sangfor EasyConnect and aTrust VPN gateways on Linux.

> This software is provided as-is. VPN software changes system routes and handles sensitive credentials. Review the configuration and use it at your own risk.

This is a ground-up Rust conversion of the original Go project. Cargo is the only build; the Go sources have been removed (their history remains in the pre-port git tags for protocol reference).

## Current support

The Rust implementation currently provides:

- EasyConnect password authentication, CAPTCHA, SMS, and TOTP challenges
- multi-line gateway selection and server session keep-alive
- server resource, domain, DNS, and split-tunnel policy parsing
- the Sangfor `L3IP` TLS 1.1/RC4-SHA handshake and bidirectional IP packet tunnel
- Linux TUN setup and `iproute2` route installation
- SOCKS5 CONNECT, including optional username/password authentication
- HTTP CONNECT and ordinary absolute-form HTTP proxying
- remote VPN DNS, custom DNS records, and dynamic routes for domain resources
- aTrust password, CAPTCHA, SMS, and TOTP authentication
- aTrust policy parsing, node selection, virtual-IP negotiation, per-flow authorization, and L3 packet tunnels
- aTrust connectivity through Linux TUN or its native per-application TCP proxy tunnels
- a background daemon (`sftd`) that holds one or more named connection profiles, controlled by a Unix-socket client (`sft up`/`down`/`status`/`list`/`reload`)
- a reusable async Rust API (`VpnClient`, `EasyConnectClient`, `AtrustClient`, policy, resource, proxy, TUN, and connection-manager modules)

Still to port: aTrust CAS/OAuth/RADIUS/enhanced login, certificate authentication, Shadowsocks, TCP/UDP forwarding, DNS listener/hijacking, Fake IP, and explicit underlay-interface binding. Enabling an unimplemented configuration option fails validation instead of silently ignoring it.

Linux is the only supported operating system for this Rust port.

## Build

Requirements:

- Rust 1.85 or newer
- Linux TUN support (`/dev/net/tun`)
- `iproute2`
- OpenSSL development libraries when building from source

```bash
cargo build --release
cargo test --all-targets
```

The build produces two binaries — `target/release/sftd` (daemon) and `target/release/sft` (client) — and the library crate `sangfordetunz`.

## Configuration

Connections are defined as named profiles in a single TOML file. Copy [`config.toml.example`](config.toml.example) and edit the `[profiles.<name>]` blocks:

```toml
[daemon]
socket = "/run/sangfordetunz.sock"

[profiles.zju]
protocol = "easyconnect"
server_address = "rvpn.zju.edu.cn"
username = "student-id"
password = "password"
autostart = false        # bring this profile up when sftd starts

[profiles.work]
protocol = "atrust"
server_address = "vpn.example.edu"
username = "user"
password = "password"
```

Validate it without contacting a gateway:

```bash
sft check-config config.toml
```

## Daemon and client

Start the daemon (foreground; normally under systemd — see [`docs/service_en.md`](docs/service_en.md)). TUN mode and EasyConnect proxy mode need root or `CAP_NET_ADMIN`; the default aTrust SOCKS/HTTP mode does not.

```bash
sudo sftd --config config.toml
```

Control it with `sft`:

```bash
sft up zju          # bring the 'zju' profile up
sft status          # show active connections, their state, IP, and uptime
sft list            # every configured profile, and which are active
sft down zju        # bring it down
sft reload          # re-read the configuration file
sft ping            # check the daemon is responding
```

`sft` talks to the daemon over the Unix socket in `[daemon].socket` (override with `--socket`). Interactive challenges (CAPTCHA, SMS) cannot be answered by a background daemon; set `totp_secret` for a TOTP gateway, or reuse a preconfigured session.

## Library

The public API deliberately separates interactive prompts from protocol logic. Embedders implement `ChallengeHandler`, create an `EasyConnectClient`, then use the common `VpnClient` trait:

```rust,no_run
use sangfordetunz::{Config, VpnClient, easyconnect::EasyConnectClient};

# async fn example(handler: &dyn sangfordetunz::ChallengeHandler) -> Result<(), sangfordetunz::Error> {
let mut client = EasyConnectClient::new(Config::default())?;
let connection = client.connect(handler).await?;
let packets = client.open_l3().await?;
println!("VPN address: {}", connection.client_ip);
drop(packets);
client.close().await?;
# Ok(())
# }
```

`open_l3()` returns an async stream of complete IP packets. Applications may attach it to the included Linux TUN integration or provide their own network stack. `AtrustClient::connect_control_plane()` prepares aTrust policy, and its `TcpConnector` implementation can alternatively back the included proxy service without TUN. The `manager::ConnectionManager` supervises named connections the same way `sftd` does.

## Docker

The image runs `sftd`. The container needs access to the TUN device and `NET_ADMIN` for TUN-mode profiles; the included Compose file supplies both:

```bash
cp config.toml.example config.toml
docker compose up --build
# then, in another shell:
docker compose exec sangfordetunz sft up zju
```

Because the proxies default to `127.0.0.1`, set the profile's binds to `0.0.0.0` (with credentials or `allow_open_proxy = true`) if you publish container ports.

Because the proxies default to `127.0.0.1`, a published container port cannot reach them. For Docker, set the binds to `0.0.0.0` in `config.toml` and either configure `socks_user`/`socks_password` or set `allow_open_proxy = true` (the container's network namespace is isolated, and Docker only exposes the ports you publish).

## Security notes

The authentication channel (which carries your credentials and the password-encryption key) verifies the gateway's TLS certificate by default. Sangfor appliances often use an appliance-local certificate; if yours does, set `insecure_skip_verify = true` — but only on a trusted network path, since it disables MITM protection. The data-plane tunnels keep the official client's behavior and do not validate certificates, as they carry only tunnel framing.

The proxy listeners bind to `127.0.0.1` by default. Binding a non-loopback address requires either SOCKS/HTTP credentials (`socks_user`/`socks_password`) or an explicit `allow_open_proxy = true`, so the VPN is never exposed as an unauthenticated relay by accident.

The custom TLS implementation is deliberately isolated to the legacy Sangfor `L3IP` transport and supports only TLS 1.1 with `TLS_RSA_WITH_RC4_128_SHA`, as required by that protocol. It must not be reused as a general TLS implementation.

## License and attribution

AGPL-3.0-only. This project derives from ZJU Connect and EasierConnect; see [`LICENSE`](LICENSE) and the repository history for contributors.
