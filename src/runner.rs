//! Runs a single VPN connection to completion, cancellably.
//!
//! This is the shared engine behind the daemon: it authenticates a profile,
//! establishes the data plane, reports liveness through a [`StatusHandle`], and
//! serves the TUN and/or proxies until it is cancelled or a stream fails.

use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::watch;

use crate::{
    Challenge, ChallengeHandler, Config, ConnectionInfo, Error, Protocol, VpnClient,
    atrust::AtrustClient,
    config::{RemoteDns, RemoteDnsKeyword},
    control::ConnectionState,
    easyconnect::EasyConnectClient,
    policy::Policy,
    service::{Connector, DnsConfig, ProxyConfig, serve as serve_proxies},
    tun::{TunOptions, create as create_tun},
};

/// Challenge handler for daemon-managed connections. It answers a TOTP prompt
/// from the profile's `totp_secret` and rejects interactive challenges, which
/// a background daemon cannot present to a user.
pub struct NonInteractiveChallenges {
    totp_secret: String,
}

impl NonInteractiveChallenges {
    #[must_use]
    pub fn new(totp_secret: String) -> Self {
        Self { totp_secret }
    }
}

#[async_trait]
impl ChallengeHandler for NonInteractiveChallenges {
    async fn answer(&self, challenge: Challenge) -> Result<String, Error> {
        match challenge {
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
            Challenge::TotpCode => Err(Error::UnsupportedAuthentication(
                "gateway requires TOTP but no totp_secret is configured for this profile".into(),
            )),
            Challenge::Captcha { .. } => Err(Error::UnsupportedAuthentication(
                "gateway requires a CAPTCHA, which cannot be answered in daemon mode".into(),
            )),
            Challenge::SmsCode => Err(Error::UnsupportedAuthentication(
                "gateway requires an SMS code, which cannot be answered in daemon mode".into(),
            )),
        }
    }
}

/// A cloneable, thread-safe view of a connection's current state, shared
/// between the running connection and the daemon that reports it.
#[derive(Clone, Debug)]
pub struct StatusHandle(Arc<Mutex<ConnectionState>>);

impl StatusHandle {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(ConnectionState::Connecting)))
    }

    pub fn set(&self, state: ConnectionState) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = state;
    }

    #[must_use]
    pub fn get(&self) -> ConnectionState {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Default for StatusHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// A per-connection cancellation receiver. The manager flips the paired sender
/// to ask the connection to stop.
pub type Cancel = watch::Receiver<bool>;

async fn cancelled(cancel: &mut Cancel) {
    // Resolves as soon as the flag is set, including if it is already set.
    let _ = cancel.wait_for(|stop| *stop).await;
}

/// The Linux interface name for a profile, within the kernel's length limit.
#[must_use]
pub fn interface_name(profile: &str) -> String {
    let mut name = format!("sft-{profile}");
    name.truncate(15);
    name
}

/// Run one connection until cancelled or a stream fails.
///
/// # Errors
///
/// Returns any authentication, protocol, or I/O error that stops the
/// connection. A clean cancellation returns `Ok(())`.
pub async fn run_connection(
    config: Config,
    profile: &str,
    challenges: Arc<dyn ChallengeHandler>,
    cancel: Cancel,
    status: &StatusHandle,
) -> Result<(), Error> {
    status.set(ConnectionState::Connecting);
    match config.protocol {
        Protocol::Easyconnect => {
            run_easyconnect(config, profile, challenges.as_ref(), cancel, status).await
        }
        Protocol::Atrust => run_atrust(config, profile, challenges.as_ref(), cancel, status).await,
    }
}

async fn run_easyconnect(
    config: Config,
    profile: &str,
    challenges: &dyn ChallengeHandler,
    mut cancel: Cancel,
    status: &StatusHandle,
) -> Result<(), Error> {
    let proxy_enabled = proxy_enabled(&config);
    if !config.tun_mode && !proxy_enabled {
        return Err(Error::Config("no TUN or proxy service is enabled".into()));
    }
    let mut client = EasyConnectClient::new(config.clone())?;
    let info = client.connect(challenges).await?;
    let client_ip = require_ipv4(info.client_ip, "EasyConnect")?;
    status.set(ConnectionState::Connected {
        client_ip: info.client_ip,
    });
    tracing::info!(profile, client_ip = %info.client_ip, "EasyConnect data plane is ready");

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
            name: interface_name(profile),
            routes,
            exclude: exclude.clone(),
            ..TunOptions::default()
        },
    )
    .await?;
    let connector = build_connector(&config, &info, tun.interface(), exclude);
    let tunnel = tun.run(l3);
    let result = tokio::select! {
        result = tunnel => result,
        result = serve_optional(proxy_enabled, &config, connector) => result,
        () = cancelled(&mut cancel) => Ok(()),
    };
    client.close().await?;
    result
}

async fn run_atrust(
    config: Config,
    profile: &str,
    challenges: &dyn ChallengeHandler,
    mut cancel: Cancel,
    status: &StatusHandle,
) -> Result<(), Error> {
    let mut client = AtrustClient::new(config.clone())?;
    let info = client.connect_control_plane(challenges).await?;
    status.set(ConnectionState::Connected {
        client_ip: info.client_ip,
    });
    tracing::info!(
        profile,
        client_ip = %info.client_ip,
        tunnel_nodes = client.best_nodes().len(),
        "aTrust control plane is ready"
    );

    if config.tun_mode {
        return run_atrust_tun(client, config, profile, info, cancel).await;
    }
    if !proxy_enabled(&config) {
        return Err(Error::Config(
            "aTrust without tun_mode requires a SOCKS5 or HTTP proxy listener".into(),
        ));
    }
    let proxies = serve_proxies(proxy_config(&config), Arc::new(client));
    tokio::select! {
        result = proxies => result,
        () = cancelled(&mut cancel) => Ok(()),
    }
}

async fn run_atrust_tun(
    mut client: AtrustClient,
    config: Config,
    profile: &str,
    info: ConnectionInfo,
    mut cancel: Cancel,
) -> Result<(), Error> {
    let client_ip = require_ipv4(info.client_ip, "aTrust")?;
    // aTrust captures traffic by the gateway's resource networks, so those
    // routes are always required in TUN mode.
    let routes = info.resources.routed_networks();
    let exclude = gateway_exclusions(&config).await;
    let l3 = client.open_l3().await?;
    let tun = create_tun(
        client_ip,
        TunOptions {
            name: interface_name(profile),
            routes,
            exclude: exclude.clone(),
            ..TunOptions::default()
        },
    )
    .await?;
    let connector = build_connector(&config, &info, tun.interface(), exclude);
    let tunnel = tun.run(l3);
    let result = tokio::select! {
        result = tunnel => result,
        result = serve_optional(proxy_enabled(&config), &config, connector) => result,
        () = cancelled(&mut cancel) => Ok(()),
    };
    client.close().await?;
    result
}

/// Serve the proxies if enabled; otherwise never resolve (so `select!` waits on
/// the tunnel or cancellation).
async fn serve_optional(
    enabled: bool,
    config: &Config,
    connector: Arc<Connector>,
) -> Result<(), Error> {
    if enabled {
        serve_proxies(proxy_config(config), connector).await
    } else {
        std::future::pending().await
    }
}

fn proxy_enabled(config: &Config) -> bool {
    config
        .socks_bind
        .as_deref()
        .is_some_and(|bind| !bind.is_empty())
        || config
            .http_bind
            .as_deref()
            .is_some_and(|bind| !bind.is_empty())
}

fn proxy_config(config: &Config) -> ProxyConfig {
    ProxyConfig {
        socks_bind: config.socks_bind.clone(),
        socks_username: config.socks_user.clone(),
        socks_password: config.socks_password.clone(),
        http_bind: config.http_bind.clone(),
    }
}

fn require_ipv4(address: IpAddr, protocol: &str) -> Result<std::net::Ipv4Addr, Error> {
    match address {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(Error::Protocol(format!(
            "{protocol} returned an unsupported IPv6-only client address"
        ))),
    }
}

fn build_connector(
    config: &Config,
    info: &ConnectionInfo,
    interface: &str,
    exclude: Vec<IpAddr>,
) -> Arc<Connector> {
    Arc::new(Connector::with_exclusions(
        Policy::new(info.resources.clone(), config.proxy_all),
        dns_config(config, info),
        interface,
        config
            .custom_dns
            .iter()
            .map(|entry| (entry.host_name.to_ascii_lowercase(), entry.ip))
            .collect::<BTreeMap<_, _>>(),
        exclude,
    ))
}

/// Resolve the gateway addresses that must bypass the TUN, so the outer VPN
/// transport is never routed back through the tunnel it depends on.
async fn gateway_exclusions(config: &Config) -> Vec<IpAddr> {
    if let Ok(address) = config.server_address.parse::<IpAddr>() {
        return vec![address];
    }
    match tokio::net::lookup_host((config.server_address.as_str(), config.server_port)).await {
        Ok(addresses) => {
            let mut resolved: Vec<IpAddr> = addresses.map(|socket| socket.ip()).collect();
            resolved.sort_unstable();
            resolved.dedup();
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

fn dns_config(config: &Config, info: &ConnectionInfo) -> DnsConfig {
    DnsConfig {
        remote_dns: configured_dns(config, &config.remote_dns_server, info, 0),
        secondary_dns: configured_dns(config, &config.secondary_dns_server, info, 1),
        ttl: Duration::from_secs(config.dns_ttl),
    }
}

fn configured_dns(
    config: &Config,
    setting: &RemoteDns,
    info: &ConnectionInfo,
    auto_index: usize,
) -> Option<IpAddr> {
    if config.disable_remote_dns {
        return None;
    }
    match setting {
        RemoteDns::Address(address) => Some(*address),
        RemoteDns::Keyword(RemoteDnsKeyword::Disabled) => None,
        RemoteDns::Keyword(RemoteDnsKeyword::Auto) => info.dns_servers.get(auto_index).copied(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_name_stays_within_kernel_limit() {
        assert_eq!(interface_name("zju"), "sft-zju");
        assert!(interface_name("a-very-long-profile-name").len() <= 15);
    }

    #[test]
    fn status_handle_reports_latest_state() {
        let handle = StatusHandle::new();
        assert_eq!(handle.get(), ConnectionState::Connecting);
        handle.set(ConnectionState::Connected {
            client_ip: "10.0.0.1".parse().unwrap(),
        });
        assert!(matches!(handle.get(), ConnectionState::Connected { .. }));
    }
}
