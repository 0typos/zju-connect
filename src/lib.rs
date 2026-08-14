//! A reusable, asynchronous client for Sangfor `EasyConnect` and `aTrust` VPNs.
//!
//! The crate keeps interactive concerns outside of the protocol clients. Applications
//! provide a [`ChallengeHandler`] when a gateway requests a CAPTCHA, SMS code, or TOTP.

#[cfg(not(target_os = "linux"))]
compile_error!("zju-connect's Rust port supports Linux only");

pub mod atrust;
pub mod config;
pub mod easyconnect;
pub mod policy;
pub mod resource;
pub mod service;
#[cfg(target_os = "linux")]
pub mod tun;
mod wire;

use std::{net::IpAddr, pin::Pin};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

pub use config::{Config, Protocol};
pub use resource::{DomainResource, IpResource, ProtocolMatch, Resources};

/// An owned asynchronous byte stream used for raw IP packets.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

/// A boxed L3 packet stream. Each write is one IP packet; reads return packet bytes.
pub type L3Stream = Pin<Box<dyn AsyncStream>>;

/// Information negotiated while establishing the VPN control plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionInfo {
    pub client_ip: IpAddr,
    pub dns_servers: Vec<IpAddr>,
    pub resources: Resources,
}

/// Resolve once the process receives SIGINT (Ctrl-C) or SIGTERM.
///
/// # Errors
///
/// Returns an I/O error if a signal handler cannot be registered.
pub async fn shutdown_signal() -> Result<(), Error> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {}
    }
    Ok(())
}

/// Prompts which a VPN server can issue during authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Challenge {
    Captcha { image: Vec<u8> },
    SmsCode,
    TotpCode,
}

/// Supplies answers to server-side authentication challenges.
#[async_trait]
pub trait ChallengeHandler: Send + Sync {
    async fn answer(&self, challenge: Challenge) -> Result<String, Error>;
}

/// Common interface implemented by each VPN protocol.
#[async_trait]
pub trait VpnClient: Send {
    async fn connect(&mut self, challenges: &dyn ChallengeHandler)
    -> Result<ConnectionInfo, Error>;

    async fn open_l3(&self) -> Result<L3Stream, Error>;

    async fn close(&mut self) -> Result<(), Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("authentication failed: {0}")]
    Authentication(String),
    #[error("gateway protocol error: {0}")]
    Protocol(String),
    #[error("VPN resource data is invalid: {0}")]
    Resource(String),
    #[error("the gateway requested unsupported authentication: {0}")]
    UnsupportedAuthentication(String),
    #[error("VPN connection is not established")]
    NotConnected,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("TLS error: {0}")]
    Tls(String),
}
