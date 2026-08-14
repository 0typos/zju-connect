# ZJU Connect (Rust/Linux port)

An asynchronous Rust library and Linux CLI for connecting to Sangfor EasyConnect and aTrust VPN gateways.

> This software is provided as-is. VPN software changes system routes and handles sensitive credentials. Review the configuration and use it at your own risk.

This branch is a ground-up Rust conversion of the original Go project. Cargo is the authoritative build; the old Go sources remain temporarily as a protocol reference and are not part of the Rust/Linux build.

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
- a reusable async Rust API (`VpnClient`, `EasyConnectClient`, `AtrustClient`, policy, resource, proxy, and TUN modules)

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

The binary is `target/release/zju-connect` and the library crate is `zju_connect`.

## CLI

EasyConnect with the default SOCKS5 (`0.0.0.0:1080`) and HTTP (`0.0.0.0:1081`) proxies:

```bash
sudo --preserve-env=ZJU_CONNECT_USERNAME,ZJU_CONNECT_PASSWORD \
  target/release/zju-connect
```

Credentials can be supplied through flags, but environment variables avoid putting the password in shell history:

```bash
export ZJU_CONNECT_USERNAME='student-id'
export ZJU_CONNECT_PASSWORD='password'
sudo --preserve-env=ZJU_CONNECT_USERNAME,ZJU_CONNECT_PASSWORD \
  target/release/zju-connect --tun-mode --add-route
```

Useful modes:

```bash
# Validate TOML without contacting the gateway
zju-connect --config config.toml --check-config

# Authenticate and inspect gateway policy without creating a TUN device
zju-connect --username USER --password PASS --control-plane-only

# Disable one or both proxy listeners (an empty argument disables it)
zju-connect --socks-bind '' --http-bind '' --tun-mode --add-route
```

For an aTrust gateway, the current data plane is its native per-application TCP tunnel and does not require root:

```bash
zju-connect --protocol atrust --server vpn.example.edu \
  --username USER --password PASS
```

EasyConnect proxy mode and either protocol's TUN mode use the kernel TUN data path and therefore need root or `CAP_NET_ADMIN`. Press Ctrl-C to close the interface and VPN session. The default aTrust SOCKS/HTTP mode uses native TCP tunnels and does not create a TUN device.

For a configuration file, copy [`config.toml.example`](config.toml.example), then run:

```bash
sudo target/release/zju-connect --config config.toml
```

## Library

The public API deliberately separates interactive prompts from protocol logic. Embedders implement `ChallengeHandler`, create an `EasyConnectClient`, then use the common `VpnClient` trait:

```rust,no_run
use zju_connect::{Config, VpnClient, easyconnect::EasyConnectClient};

# async fn example(handler: &dyn zju_connect::ChallengeHandler) -> Result<(), zju_connect::Error> {
let mut client = EasyConnectClient::new(Config::default())?;
let connection = client.connect(handler).await?;
let packets = client.open_l3().await?;
println!("VPN address: {}", connection.client_ip);
drop(packets);
client.close().await?;
# Ok(())
# }
```

`open_l3()` returns an async stream of complete IP packets. Applications may attach it to the included Linux TUN integration or provide their own network stack. `AtrustClient::connect_control_plane()` prepares aTrust policy, and its `TcpConnector` implementation can alternatively back the included proxy service without TUN.

## Docker

The container requires access to the TUN device and `NET_ADMIN`; the included Compose file supplies both:

```bash
cp config.toml.example config.toml
docker compose up --build
```

## Security notes

Sangfor appliances commonly use appliance-local certificates, and the original client does not validate the HTTPS certificate. The Rust EasyConnect and aTrust clients currently preserve that behavior. Use a trusted network path to the gateway.

The example proxy listeners bind to all interfaces. Bind them to `127.0.0.1`, configure SOCKS authentication, or enforce an equivalent firewall policy unless other hosts should be allowed to use your VPN session.

The custom TLS implementation is deliberately isolated to the legacy Sangfor `L3IP` transport and supports only TLS 1.1 with `TLS_RSA_WITH_RC4_128_SHA`, as required by that protocol. It must not be reused as a general TLS implementation.

## License and attribution

GPL-3.0-only. This project derives from ZJU Connect and EasierConnect; see [`LICENSE`](LICENSE) and the repository history for contributors.
