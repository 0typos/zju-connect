use std::{collections::BTreeMap, io::Write as _, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use clap::{Parser, ValueEnum};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tracing_subscriber::EnvFilter;
use zju_connect::{
    Challenge, ChallengeHandler, Config, ConnectionInfo, Error, Protocol, VpnClient,
    atrust::AtrustClient,
    easyconnect::EasyConnectClient,
    policy::Policy,
    service::{Connector, ProxyConfig, serve as serve_proxies},
    tun::{TunOptions, create as create_tun},
};

// No Debug derive: the credential fields must never reach a log or panic message.
#[derive(Parser)]
#[allow(clippy::struct_excessive_bools)]
#[command(
    version,
    about = "Connect to Sangfor EasyConnect and aTrust VPN gateways"
)]
struct Cli {
    /// Load all settings from a TOML file. Other connection flags are ignored.
    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(long, value_enum, default_value = "easyconnect")]
    protocol: ProtocolArg,

    #[arg(long, default_value = "rvpn.zju.edu.cn")]
    server: String,

    #[arg(long, default_value_t = 443)]
    port: u16,

    #[arg(long, env = "ZJU_CONNECT_USERNAME", default_value = "")]
    username: String,

    #[arg(
        long,
        env = "ZJU_CONNECT_PASSWORD",
        default_value = "",
        hide_env_values = true
    )]
    password: String,

    #[arg(
        long,
        env = "ZJU_CONNECT_TOTP_SECRET",
        default_value = "",
        hide_env_values = true
    )]
    totp_secret: String,

    #[arg(long)]
    twf_id: Option<String>,

    #[arg(long)]
    graph_code_file: Option<String>,

    /// aTrust authentication service name.
    #[arg(long, default_value = "auth/psw")]
    auth_type: String,

    /// aTrust login domain advertised by the gateway.
    #[arg(long, default_value = "Radius")]
    login_domain: String,

    /// Reuse an aTrust sid together with --device-id and --resource-file.
    #[arg(long)]
    sid: Option<String>,

    #[arg(long)]
    device_id: Option<String>,

    #[arg(long, hide_default_value = true)]
    sign_key: Option<String>,

    #[arg(long)]
    resource_file: Option<String>,

    /// Skip the final aTrust TCP tunnel status probe for older gateways.
    #[arg(long)]
    skip_tcp_tunnel_wait: bool,

    #[arg(long, default_value = "127.0.0.1:1080")]
    socks_bind: Option<String>,

    #[arg(long, default_value = "")]
    socks_user: String,

    #[arg(long, default_value = "", hide_default_value = true)]
    socks_password: String,

    #[arg(long, default_value = "127.0.0.1:1081")]
    http_bind: Option<String>,

    /// Allow binding the proxies to a non-loopback address without credentials.
    #[arg(long)]
    allow_open_proxy: bool,

    /// Skip TLS verification on the auth channel (self-signed gateways only).
    #[arg(long)]
    insecure_skip_verify: bool,

    #[arg(long)]
    disable_server_config: bool,

    #[arg(long)]
    skip_domain_resource: bool,

    /// Create an operating-system TUN interface for the VPN packet stream.
    #[arg(long)]
    tun_mode: bool,

    /// Install all IPv4 routes supplied by the gateway on the TUN interface.
    #[arg(long)]
    add_route: bool,

    /// Authenticate and retrieve policy, but do not start packet or proxy services.
    #[arg(long)]
    control_plane_only: bool,

    /// Parse and validate configuration without contacting the gateway.
    #[arg(long)]
    check_config: bool,

    #[arg(long, short)]
    verbose: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProtocolArg {
    Easyconnect,
    Atrust,
}

impl From<ProtocolArg> for Protocol {
    fn from(value: ProtocolArg) -> Self {
        match value {
            ProtocolArg::Easyconnect => Self::Easyconnect,
            ProtocolArg::Atrust => Self::Atrust,
        }
    }
}

struct TerminalChallenges {
    totp_secret: String,
}

#[async_trait]
impl ChallengeHandler for TerminalChallenges {
    async fn answer(&self, challenge: Challenge) -> Result<String, Error> {
        match challenge {
            Challenge::Captcha { .. } => prompt("CAPTCHA code: ").await,
            Challenge::SmsCode => prompt("SMS verification code: ").await,
            Challenge::TotpCode if !self.totp_secret.is_empty() => {
                let secret = totp_rs::Secret::Encoded(self.totp_secret.clone())
                    .to_bytes()
                    .map_err(|error| Error::Config(format!("invalid TOTP secret: {error}")))?;
                let totp = totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 1, 30, secret)
                    .map_err(|error| Error::Config(format!("invalid TOTP settings: {error}")))?;
                totp.generate_current().map_err(|error| {
                    Error::Authentication(format!("cannot generate TOTP: {error}"))
                })
            }
            Challenge::TotpCode => prompt("TOTP code: ").await,
        }
    }
}

async fn prompt(message: &str) -> Result<String, Error> {
    print!("{message}");
    std::io::stdout().flush()?;
    let mut input = String::new();
    BufReader::new(tokio::io::stdin())
        .read_line(&mut input)
        .await?;
    let answer = input.trim().to_owned();
    if answer.is_empty() {
        Err(Error::Authentication("empty challenge response".into()))
    } else {
        Ok(answer)
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("zju-connect: {error}");
        std::process::exit(exit_code(&error));
    }
}

/// Map an error to a process exit code so supervisors can distinguish a
/// configuration mistake (2) or an authentication failure (3), which will not
/// succeed on restart, from a transient runtime failure (1).
fn exit_code(error: &Error) -> i32 {
    match error {
        Error::Config(_) => 2,
        Error::Authentication(_) | Error::UnsupportedAuthentication(_) => 3,
        _ => 1,
    }
}

async fn run() -> Result<(), Error> {
    let cli = Cli::parse();

    let config = if let Some(path) = &cli.config {
        Config::from_file(path).await?
    } else {
        Config {
            protocol: cli.protocol.into(),
            server_address: cli.server,
            server_port: cli.port,
            username: cli.username,
            password: cli.password,
            totp_secret: cli.totp_secret,
            twf_id: cli.twf_id,
            graph_code_file: cli.graph_code_file,
            auth_type: Some(cli.auth_type),
            login_domain: cli.login_domain,
            sid: cli.sid,
            device_id: cli.device_id,
            sign_key: cli.sign_key,
            resource_file: cli.resource_file,
            skip_tcp_tunnel_wait: cli.skip_tcp_tunnel_wait,
            socks_bind: cli.socks_bind,
            socks_user: cli.socks_user,
            socks_password: cli.socks_password,
            http_bind: cli.http_bind,
            allow_open_proxy: cli.allow_open_proxy,
            insecure_skip_verify: cli.insecure_skip_verify,
            disable_server_config: cli.disable_server_config,
            skip_domain_resource: cli.skip_domain_resource,
            tun_mode: cli.tun_mode,
            add_route: cli.add_route,
            ..Config::default()
        }
    };
    config.validate()?;

    let filter = if config.debug_dump {
        "trace"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .with_target(false)
        .init();

    if cli.config.is_some() {
        tracing::debug!("settings loaded from --config; command-line connection flags are ignored");
    }

    if cli.check_config {
        println!("configuration is valid");
        return Ok(());
    }

    match config.protocol {
        Protocol::Easyconnect => connect_easyconnect(config, cli.control_plane_only).await,
        Protocol::Atrust => connect_atrust(config, cli.control_plane_only).await,
    }
}

async fn connect_atrust(config: Config, control_plane_only: bool) -> Result<(), Error> {
    let challenges = TerminalChallenges {
        totp_secret: config.totp_secret.clone(),
    };
    let mut client = AtrustClient::new(config.clone())?;
    let info = client.connect_control_plane(&challenges).await?;
    tracing::info!(
        username = client.username().unwrap_or("unknown"),
        client_ip = %info.client_ip,
        ip_rules = info.resources.ip.len(),
        domain_rules = info.resources.domains.len(),
        dns_servers = info.dns_servers.len(),
        tunnel_nodes = client.best_nodes().len(),
        "aTrust control plane is ready"
    );
    if control_plane_only {
        return Ok(());
    }
    if config.tun_mode {
        return run_atrust_tun_services(client, config, info).await;
    }
    let proxy_enabled = config
        .socks_bind
        .as_deref()
        .is_some_and(|bind| !bind.is_empty())
        || config
            .http_bind
            .as_deref()
            .is_some_and(|bind| !bind.is_empty());
    if !proxy_enabled {
        return Err(Error::Config(
            "aTrust currently requires a SOCKS5 or HTTP proxy listener".into(),
        ));
    }
    let proxies = serve_proxies(
        ProxyConfig {
            socks_bind: config.socks_bind,
            socks_username: config.socks_user,
            socks_password: config.socks_password,
            http_bind: config.http_bind,
        },
        Arc::new(client),
    );
    tokio::select! {
        result = proxies => result,
        result = zju_connect::shutdown_signal() => result,
    }
}

async fn run_atrust_tun_services(
    mut client: AtrustClient,
    config: Config,
    info: ConnectionInfo,
) -> Result<(), Error> {
    let proxy_enabled = config
        .socks_bind
        .as_deref()
        .is_some_and(|bind| !bind.is_empty())
        || config
            .http_bind
            .as_deref()
            .is_some_and(|bind| !bind.is_empty());
    let client_ip = match info.client_ip {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            return Err(Error::Protocol(
                "aTrust returned an unsupported IPv6-only client address".into(),
            ));
        }
    };
    // The aTrust TUN captures traffic by the gateway's resource networks, so
    // those routes are always required here; add_route does not gate them.
    let routes = info.resources.routed_networks();
    let exclude = gateway_exclusions(&config).await;
    let l3 = client.open_l3().await?;
    let tun = create_tun(
        client_ip,
        TunOptions {
            routes,
            exclude,
            ..TunOptions::default()
        },
    )
    .await?;
    let connector = Arc::new(Connector::new(
        Policy::new(info.resources.clone(), config.proxy_all),
        dns_config(&config, &info),
        tun.interface(),
        config
            .custom_dns
            .iter()
            .map(|entry| (entry.host_name.to_ascii_lowercase(), entry.ip))
            .collect::<BTreeMap<_, _>>(),
    ));
    let tunnel = tun.run(l3);
    let result = if proxy_enabled {
        let proxies = serve_proxies(
            ProxyConfig {
                socks_bind: config.socks_bind.clone(),
                socks_username: config.socks_user.clone(),
                socks_password: config.socks_password.clone(),
                http_bind: config.http_bind.clone(),
            },
            connector,
        );
        tokio::select! {
            result = tunnel => result,
            result = proxies => result,
        }
    } else {
        tunnel.await
    };
    client.close().await?;
    result
}

/// Resolve the gateway addresses that must bypass the TUN, so the outer VPN
/// transport is never routed back through the tunnel it depends on.
async fn gateway_exclusions(config: &Config) -> Vec<std::net::IpAddr> {
    if let Ok(address) = config.server_address.parse::<std::net::IpAddr>() {
        return vec![address];
    }
    match tokio::net::lookup_host((config.server_address.as_str(), config.server_port)).await {
        Ok(addresses) => {
            let mut resolved: Vec<std::net::IpAddr> = addresses.map(|socket| socket.ip()).collect();
            resolved.sort_unstable();
            resolved.dedup();
            if resolved.is_empty() {
                tracing::warn!(
                    server = %config.server_address,
                    "gateway address resolved to nothing; skipping route exclusion"
                );
            }
            resolved
        }
        Err(error) => {
            tracing::warn!(
                server = %config.server_address,
                %error,
                "could not resolve gateway address for route exclusion"
            );
            Vec::new()
        }
    }
}

fn configured_remote_dns(config: &Config, info: &ConnectionInfo) -> Option<std::net::IpAddr> {
    if config.disable_remote_dns {
        return None;
    }
    resolve_dns_setting(&config.remote_dns_server, info, 0)
}

fn configured_secondary_dns(config: &Config, info: &ConnectionInfo) -> Option<std::net::IpAddr> {
    if config.disable_remote_dns {
        return None;
    }
    resolve_dns_setting(&config.secondary_dns_server, info, 1)
}

/// Resolve a DNS setting to an address, mapping the `auto` keyword to the
/// gateway-supplied server at `auto_index`.
fn resolve_dns_setting(
    setting: &zju_connect::config::RemoteDns,
    info: &ConnectionInfo,
    auto_index: usize,
) -> Option<std::net::IpAddr> {
    match setting {
        zju_connect::config::RemoteDns::Address(address) => Some(*address),
        zju_connect::config::RemoteDns::Keyword(
            zju_connect::config::RemoteDnsKeyword::Disabled,
        ) => None,
        zju_connect::config::RemoteDns::Keyword(zju_connect::config::RemoteDnsKeyword::Auto) => {
            info.dns_servers.get(auto_index).copied()
        }
    }
}

fn dns_config(config: &Config, info: &ConnectionInfo) -> zju_connect::service::DnsConfig {
    zju_connect::service::DnsConfig {
        remote_dns: configured_remote_dns(config, info),
        secondary_dns: configured_secondary_dns(config, info),
        ttl: std::time::Duration::from_secs(config.dns_ttl),
    }
}

async fn connect_easyconnect(config: Config, control_plane_only: bool) -> Result<(), Error> {
    let challenges = TerminalChallenges {
        totp_secret: config.totp_secret.clone(),
    };
    let mut client = EasyConnectClient::new(config.clone())?;
    if control_plane_only {
        return inspect_easyconnect(&mut client, &config, &challenges).await;
    }

    let info = client.connect(&challenges).await?;
    tracing::info!(client_ip = %info.client_ip, "EasyConnect data plane is ready");
    run_easyconnect_services(client, config, info).await
}

async fn inspect_easyconnect(
    client: &mut EasyConnectClient,
    config: &Config,
    challenges: &TerminalChallenges,
) -> Result<(), Error> {
    let auth = client.authenticate(challenges).await?;
    tracing::info!(
        server_version = auth.server_version.as_deref().unwrap_or("unknown"),
        "EasyConnect authentication succeeded"
    );
    if !config.disable_server_config {
        let resources = client.fetch_resources().await?;
        tracing::info!(
            ip_rules = resources.ip.len(),
            domain_rules = resources.domains.len(),
            dns_servers = resources.dns_servers.len(),
            "retrieved VPN policy"
        );
    }
    Ok(())
}

async fn run_easyconnect_services(
    mut client: EasyConnectClient,
    config: Config,
    info: ConnectionInfo,
) -> Result<(), Error> {
    let proxy_enabled = config
        .socks_bind
        .as_deref()
        .is_some_and(|bind| !bind.is_empty())
        || config
            .http_bind
            .as_deref()
            .is_some_and(|bind| !bind.is_empty());
    if !config.tun_mode && !proxy_enabled {
        return Err(Error::Config("no TUN or proxy service is enabled".into()));
    }
    let client_ip = match info.client_ip {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            return Err(Error::Protocol(
                "EasyConnect returned an unsupported IPv6 client address".into(),
            ));
        }
    };
    // In TUN mode the OS routes traffic into the interface, so routes are
    // required: add_route installs every gateway network, otherwise the ZJU
    // default. In proxy-only mode the connector installs per-destination /32
    // routes on demand, so no host-wide routes are added unless add_route asks.
    let routes = if config.tun_mode {
        if config.add_route {
            info.resources.routed_networks()
        } else if config.disable_zju_config {
            Vec::new()
        } else {
            vec!["10.0.0.0/8".parse().expect("valid constant")]
        }
    } else if config.add_route {
        info.resources.routed_networks()
    } else {
        Vec::new()
    };
    let exclude = gateway_exclusions(&config).await;
    let l3 = client.open_l3().await?;
    let tun = create_tun(
        client_ip,
        TunOptions {
            routes,
            exclude,
            ..TunOptions::default()
        },
    )
    .await?;
    let connector = Arc::new(Connector::new(
        Policy::new(info.resources.clone(), config.proxy_all),
        dns_config(&config, &info),
        tun.interface(),
        config
            .custom_dns
            .iter()
            .map(|entry| (entry.host_name.to_ascii_lowercase(), entry.ip))
            .collect::<BTreeMap<_, _>>(),
    ));
    let tunnel = tun.run(l3);
    let result = if proxy_enabled {
        let proxies = serve_proxies(
            ProxyConfig {
                socks_bind: config.socks_bind.clone(),
                socks_username: config.socks_user.clone(),
                socks_password: config.socks_password.clone(),
                http_bind: config.http_bind.clone(),
            },
            connector,
        );
        tokio::select! {
            result = tunnel => result,
            result = proxies => result,
        }
    } else {
        tunnel.await
    };
    client.close().await?;
    result
}
