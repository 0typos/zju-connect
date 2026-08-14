//! Linux proxy services backed by the VPN TUN interface.

use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore as _;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
};

use crate::{
    Error,
    policy::{Policy, Route},
    resource::ProtocolMatch,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HTTP_HEADER: usize = 32 * 1024;
/// Bound on how long a client may take to complete the proxy handshake before
/// its task and socket are reclaimed.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

pub trait ProxyIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> ProxyIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type ProxyStream = Pin<Box<dyn ProxyIo>>;

#[async_trait]
pub trait TcpConnector: Send + Sync {
    /// Establish a stream to a proxy client's requested destination.
    ///
    /// # Errors
    ///
    /// Returns a policy, DNS, route, or connection error.
    async fn connect_tcp(&self, host: &str, port: u16) -> Result<ProxyStream, Error>;
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub socks_bind: Option<String>,
    pub socks_username: String,
    pub socks_password: String,
    pub http_bind: Option<String>,
}

/// DNS servers and cache lifetime for VPN-routed name resolution.
#[derive(Clone, Copy, Debug)]
pub struct DnsConfig {
    pub remote_dns: Option<IpAddr>,
    pub secondary_dns: Option<IpAddr>,
    pub ttl: Duration,
}

type DnsCache = Arc<Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>>;

#[derive(Clone, Debug)]
pub struct Connector {
    policy: Policy,
    remote_dns: Option<IpAddr>,
    secondary_dns: Option<IpAddr>,
    interface: String,
    custom_dns: BTreeMap<String, IpAddr>,
    dns_ttl: Duration,
    dns_cache: DnsCache,
}

impl Connector {
    pub fn new(
        policy: Policy,
        dns: DnsConfig,
        interface: impl Into<String>,
        custom_dns: BTreeMap<String, IpAddr>,
    ) -> Self {
        let DnsConfig {
            remote_dns,
            secondary_dns,
            ttl,
        } = dns;
        Self {
            policy,
            remote_dns,
            secondary_dns,
            interface: interface.into(),
            custom_dns,
            dns_ttl: ttl,
            dns_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        let cache = self.dns_cache.lock().ok()?;
        let (addresses, expiry) = cache.get(host)?;
        (*expiry > Instant::now()).then(|| addresses.clone())
    }

    fn store_cache(&self, host: &str, addresses: &[IpAddr]) {
        if self.dns_ttl.is_zero() {
            return;
        }
        if let Ok(mut cache) = self.dns_cache.lock() {
            cache.insert(host.to_owned(), (addresses.to_vec(), Instant::now() + self.dns_ttl));
        }
    }

    async fn resolve_via_vpn(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, Error> {
        if let Some(addresses) = self.cached(host) {
            return Ok(addresses);
        }
        let addresses = match self.remote_dns {
            Some(primary) => {
                add_host_route(primary, &self.interface).await?;
                match resolve_dns(host, primary).await {
                    Ok(addresses) => addresses,
                    Err(primary_error) => match self.secondary_dns {
                        Some(secondary) => {
                            tracing::debug!(%primary_error, "primary VPN DNS failed; trying secondary");
                            add_host_route(secondary, &self.interface).await?;
                            resolve_dns(host, secondary).await?
                        }
                        None => return Err(primary_error),
                    },
                }
            }
            None => system_resolve(host, port).await?,
        };
        self.store_cache(host, &addresses);
        Ok(addresses)
    }

    /// Resolve a destination according to VPN policy and establish a TCP stream.
    ///
    /// # Errors
    ///
    /// Returns a DNS, route-installation, timeout, or TCP connection error.
    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, Error> {
        let host = host.trim_matches(['[', ']']);
        if let Ok(address) = host.parse::<IpAddr>() {
            match self.policy.route_ip(address, port, ProtocolMatch::Tcp) {
                Route::Vpn => add_host_route(address, &self.interface).await?,
                Route::Reject => return Err(rejected(&address.to_string())),
                Route::Direct => {}
            }
            return connect_addresses([SocketAddr::new(address, port)]).await;
        }

        let normalized = host.trim_end_matches('.').to_ascii_lowercase();
        let route = self
            .policy
            .route_domain(&normalized, port, ProtocolMatch::Tcp);
        if route == Route::Reject {
            return Err(rejected(&normalized));
        }
        let mut addresses = if let Some(address) = self.custom_dns.get(&normalized) {
            vec![*address]
        } else if route == Route::Vpn {
            self.resolve_via_vpn(&normalized, port).await?
        } else {
            system_resolve(&normalized, port).await?
        };
        if route == Route::Vpn {
            // The tunnel carries IPv4 only; never route a resolved IPv6 address
            // into it or connect to it directly under a VPN policy.
            addresses.retain(IpAddr::is_ipv4);
            if addresses.is_empty() {
                return Err(Error::Protocol(format!(
                    "{normalized} resolved to no IPv4 address reachable over the VPN"
                )));
            }
            for address in &addresses {
                add_host_route(*address, &self.interface).await?;
            }
        }
        connect_addresses(
            addresses
                .into_iter()
                .map(|address| SocketAddr::new(address, port)),
        )
        .await
    }
}

fn rejected(destination: &str) -> Error {
    Error::Protocol(format!(
        "{destination} cannot be reached: proxy_all is set but the VPN tunnel is IPv4-only"
    ))
}

#[async_trait]
impl TcpConnector for Connector {
    async fn connect_tcp(&self, host: &str, port: u16) -> Result<ProxyStream, Error> {
        Ok(Box::pin(Connector::connect_tcp(self, host, port).await?))
    }
}

/// Serve configured SOCKS5 and HTTP proxies until one fails or the task is cancelled.
///
/// # Errors
///
/// Returns a listener or connection-task error. At least one bind address must be set.
pub async fn serve(config: ProxyConfig, connector: Arc<dyn TcpConnector>) -> Result<(), Error> {
    let mut services = JoinSet::new();
    // The same credentials guard the SOCKS and HTTP listeners.
    let credentials = (!config.socks_username.is_empty())
        .then(|| (config.socks_username.clone(), config.socks_password.clone()));
    if let Some(bind) = config.socks_bind.filter(|bind| !bind.is_empty()) {
        let connector = Arc::clone(&connector);
        let username = config.socks_username;
        let password = config.socks_password;
        services.spawn(async move { serve_socks(&bind, connector, username, password).await });
    }
    if let Some(bind) = config.http_bind.filter(|bind| !bind.is_empty()) {
        let credentials = credentials.clone();
        services.spawn(async move { serve_http(&bind, connector, credentials).await });
    }
    if services.is_empty() {
        return Err(Error::Config("no proxy listener is enabled".into()));
    }
    match services.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(error)) => Err(Error::Io(std::io::Error::other(error))),
        None => Ok(()),
    }
}

async fn serve_socks(
    bind: &str,
    connector: Arc<dyn TcpConnector>,
    username: String,
    password: String,
) -> Result<(), Error> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(bind, "SOCKS5 proxy is listening");
    loop {
        let Some((stream, peer)) = accept(&listener).await else {
            continue;
        };
        let connector = Arc::clone(&connector);
        let username = username.clone();
        let password = password.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_socks(stream, connector, &username, &password).await {
                tracing::debug!(%peer, %error, "SOCKS5 connection failed");
            }
        });
    }
}

/// Accept one connection, tolerating transient per-socket and descriptor
/// exhaustion errors so a single failure never terminates the daemon.
async fn accept(listener: &TcpListener) -> Option<(TcpStream, SocketAddr)> {
    match listener.accept().await {
        Ok(pair) => Some(pair),
        Err(error) => {
            match error.raw_os_error() {
                // ECONNABORTED — client vanished mid-handshake.
                Some(103) => {}
                // EMFILE/ENFILE — out of descriptors; back off so we don't spin.
                Some(24 | 23) => {
                    tracing::warn!(%error, "accept hit a descriptor limit; backing off");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
                _ => tracing::warn!(%error, "transient accept error"),
            }
            None
        }
    }
}

async fn handle_socks(
    mut client: TcpStream,
    connector: Arc<dyn TcpConnector>,
    username: &str,
    password: &str,
) -> Result<(), Error> {
    let negotiate = socks_negotiate(&mut client, username, password);
    let (host, port) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, negotiate).await {
        Ok(result) => result?,
        Err(_) => return Err(Error::Protocol("SOCKS handshake timed out".into())),
    };
    let mut upstream = match connector.connect_tcp(&host, port).await {
        Ok(stream) => stream,
        Err(error) => {
            send_socks_reply(&mut client, socks_error_code(&error)).await?;
            return Err(error);
        }
    };
    send_socks_reply(&mut client, 0).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn socks_negotiate(
    client: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<(String, u16), Error> {
    let version = client.read_u8().await?;
    let method_count = client.read_u8().await?;
    if version != 5 {
        return Err(Error::Protocol("invalid SOCKS version".into()));
    }
    let mut methods = vec![0_u8; usize::from(method_count)];
    client.read_exact(&mut methods).await?;
    let required_method = if username.is_empty() { 0x00 } else { 0x02 };
    if !methods.contains(&required_method) {
        client.write_all(&[5, 0xff]).await?;
        return Err(Error::Authentication(
            "SOCKS client did not offer the required method".into(),
        ));
    }
    client.write_all(&[5, required_method]).await?;
    if required_method == 0x02 {
        authenticate_socks(client, username, password).await?;
    }

    let version = client.read_u8().await?;
    let command = client.read_u8().await?;
    let _reserved = client.read_u8().await?;
    let address_type = client.read_u8().await?;
    if version != 5 {
        send_socks_reply(client, 0x01).await?;
        return Err(Error::Protocol("invalid SOCKS version".into()));
    }
    if command != 1 {
        send_socks_reply(client, 0x07).await?;
        return Err(Error::Protocol("only SOCKS5 CONNECT is supported".into()));
    }
    let host = match address_type {
        1 => {
            let mut address = [0_u8; 4];
            client.read_exact(&mut address).await?;
            Ipv4Addr::from(address).to_string()
        }
        3 => {
            let length = usize::from(client.read_u8().await?);
            let mut domain = vec![0_u8; length];
            client.read_exact(&mut domain).await?;
            String::from_utf8(domain)
                .map_err(|_| Error::Protocol("SOCKS domain is not UTF-8".into()))?
        }
        4 => {
            let mut address = [0_u8; 16];
            client.read_exact(&mut address).await?;
            Ipv6Addr::from(address).to_string()
        }
        _ => {
            send_socks_reply(client, 0x08).await?;
            return Err(Error::Protocol("invalid SOCKS address type".into()));
        }
    };
    let port = client.read_u16().await?;
    Ok((host, port))
}

/// Map a connection failure to the closest SOCKS5 reply code.
fn socks_error_code(error: &Error) -> u8 {
    match error {
        Error::Io(io) => match io.kind() {
            std::io::ErrorKind::ConnectionRefused => 0x05,
            std::io::ErrorKind::TimedOut => 0x06,
            std::io::ErrorKind::HostUnreachable => 0x04,
            std::io::ErrorKind::NetworkUnreachable => 0x03,
            _ => 0x01,
        },
        // Policy denial, DNS failure, route installation.
        _ => 0x01,
    }
}

async fn authenticate_socks(
    client: &mut TcpStream,
    expected_username: &str,
    expected_password: &str,
) -> Result<(), Error> {
    if client.read_u8().await? != 1 {
        return Err(Error::Protocol(
            "invalid SOCKS username/password version".into(),
        ));
    }
    let username_length = usize::from(client.read_u8().await?);
    let mut username = vec![0_u8; username_length];
    client.read_exact(&mut username).await?;
    let password_length = usize::from(client.read_u8().await?);
    let mut password = vec![0_u8; password_length];
    client.read_exact(&mut password).await?;
    let valid =
        username == expected_username.as_bytes() && password == expected_password.as_bytes();
    client.write_all(&[1, u8::from(!valid)]).await?;
    if valid {
        Ok(())
    } else {
        Err(Error::Authentication(
            "invalid SOCKS username or password".into(),
        ))
    }
}

async fn send_socks_reply(client: &mut TcpStream, status: u8) -> Result<(), Error> {
    client
        .write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn serve_http(
    bind: &str,
    connector: Arc<dyn TcpConnector>,
    credentials: Option<(String, String)>,
) -> Result<(), Error> {
    let listener = TcpListener::bind(bind).await?;
    let credentials = Arc::new(credentials);
    tracing::info!(bind, "HTTP proxy is listening");
    loop {
        let Some((stream, peer)) = accept(&listener).await else {
            continue;
        };
        let connector = Arc::clone(&connector);
        let credentials = Arc::clone(&credentials);
        tokio::spawn(async move {
            if let Err(error) = handle_http(stream, connector, credentials.as_ref().as_ref()).await
            {
                tracing::debug!(%peer, %error, "HTTP proxy connection failed");
            }
        });
    }
}

async fn handle_http(
    mut client: TcpStream,
    connector: Arc<dyn TcpConnector>,
    credentials: Option<&(String, String)>,
) -> Result<(), Error> {
    let mut request = Vec::with_capacity(1024);
    let read_header = async {
        loop {
            if request.len() >= MAX_HTTP_HEADER {
                return Err(Error::Protocol("HTTP proxy header is too large".into()));
            }
            let read = client.read_buf(&mut request).await?;
            if read == 0 {
                return Err(Error::Protocol("incomplete HTTP proxy request".into()));
            }
            if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                return Ok(position + 4);
            }
        }
    };
    let header_end = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_header).await {
        Ok(result) => result?,
        Err(_) => return Err(Error::Protocol("HTTP proxy header timed out".into())),
    };
    let header = std::str::from_utf8(&request[..header_end])
        .map_err(|_| Error::Protocol("HTTP proxy header is not UTF-8".into()))?
        .to_owned();
    let first_line = header
        .lines()
        .next()
        .ok_or_else(|| Error::Protocol("HTTP proxy request line is missing".into()))?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let version = parts.next().unwrap_or_default().to_owned();

    if !proxy_auth_ok(&header, credentials) {
        client
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"zju-connect\"\r\n\
                  Connection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        return Err(Error::Authentication("HTTP proxy authentication failed".into()));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_authority(&target, 443)?;
        let mut upstream = connector.connect_tcp(&host, port).await?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        // Forward any bytes the client pipelined after the CONNECT header
        // (e.g. a TLS ClientHello sent in the same segment).
        if header_end < request.len() {
            upstream.write_all(&request[header_end..]).await?;
        }
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        return Ok(());
    }

    let url = url::Url::parse(&target)
        .map_err(|error| Error::Protocol(format!("invalid absolute proxy URL: {error}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| Error::Protocol("HTTP proxy URL has no host".into()))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let mut upstream = connector.connect_tcp(host, port).await?;
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    let mut rewritten = format!("{method} {path} {version}\r\n");
    for line in header.lines().skip(1).filter(|line| {
        let lower = line.to_ascii_lowercase();
        // Strip hop-by-hop and proxy-only headers; a fresh Connection header
        // is appended below.
        !lower.starts_with("proxy-connection:")
            && !lower.starts_with("proxy-authorization:")
            && !lower.starts_with("connection:")
    }) {
        rewritten.push_str(line);
        rewritten.push_str("\r\n");
    }
    // Absolute-form requests are only correct for the first request on the
    // connection; force a single request/response exchange so a keep-alive
    // client cannot send a second request to the wrong upstream.
    rewritten.push_str("Connection: close\r\n\r\n");
    upstream.write_all(rewritten.as_bytes()).await?;
    upstream.write_all(&request[header_end..]).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Check the `Proxy-Authorization` header against the configured credentials.
/// Returns true when no credentials are required.
fn proxy_auth_ok(header: &str, credentials: Option<&(String, String)>) -> bool {
    let Some((username, password)) = credentials else {
        return true;
    };
    let expected = BASE64.encode(format!("{username}:{password}"));
    header.lines().skip(1).any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("proxy-authorization")
            && value
                .trim()
                .strip_prefix("Basic ")
                .is_some_and(|token| token.trim() == expected)
    })
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16), Error> {
    if let Ok(address) = authority.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if let Ok(port) = port.parse() {
            return Ok((host.trim_matches(['[', ']']).into(), port));
        }
    }
    if authority.is_empty() {
        Err(Error::Protocol("empty proxy authority".into()))
    } else {
        Ok((authority.into(), default_port))
    }
}

async fn system_resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, Error> {
    let addresses = tokio::net::lookup_host((host, port))
        .await?
        .map(|socket| socket.ip())
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        Err(Error::Protocol(format!(
            "DNS returned no addresses for {host}"
        )))
    } else {
        Ok(addresses)
    }
}

async fn connect_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Result<TcpStream, Error> {
    let mut last_error = None;
    for address in addresses {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                last_error = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("connection to {address} timed out"),
                ));
            }
        }
    }
    Err(Error::Io(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "destination has no address")
    })))
}

async fn add_host_route(address: IpAddr, interface: &str) -> Result<(), Error> {
    let prefix = if address.is_ipv4() { 32 } else { 128 };
    let output = tokio::process::Command::new("ip")
        .args([
            "route",
            "replace",
            &format!("{address}/{prefix}"),
            "dev",
            interface,
        ])
        .stdin(Stdio::null())
        .output()
        .await?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::Io(std::io::Error::other(format!(
            "failed to install route for {address}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))))
    }
}

async fn resolve_dns(host: &str, server: IpAddr) -> Result<Vec<IpAddr>, Error> {
    let mut id_bytes = [0_u8; 2];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    let id = u16::from_be_bytes(id_bytes);
    let query = dns_query(id, host, 1)?;
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    // Connect so the kernel drops datagrams from any peer other than the
    // resolver, closing the off-path spoofing window to the query ID alone.
    socket.connect(SocketAddr::new(server, 53)).await?;
    socket.send(&query).await?;

    let deadline = tokio::time::Instant::now() + DNS_TIMEOUT;
    let mut response = vec![0_u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let length = tokio::time::timeout(remaining, socket.recv(&mut response))
            .await
            .map_err(|_| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("DNS query to {server} timed out"),
                ))
            })??;
        // A response whose ID does not match ours is stale or spoofed; keep
        // reading until the deadline instead of failing the whole query.
        match parse_dns_response(id, &response[..length]) {
            Ok(addresses) if addresses.is_empty() => {
                return Err(Error::Protocol(format!(
                    "remote DNS returned no address for {host}"
                )));
            }
            Ok(addresses) => return Ok(addresses),
            Err(_) if tokio::time::Instant::now() < deadline => {}
            Err(error) => return Err(error),
        }
    }
}

fn dns_query(id: u16, host: &str, record_type: u16) -> Result<Vec<u8>, Error> {
    let mut query = Vec::with_capacity(512);
    query.extend_from_slice(&crate::wire::to_bytes(&crate::wire::DnsHeader {
        id,
        flags: 0x0100,
        questions: 1,
        answers: 0,
        authorities: 0,
        additionals: 0,
    })?);
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::Protocol(format!("invalid DNS name: {host}")));
        }
        query.push(u8::try_from(label.len()).expect("DNS label length was checked"));
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

fn parse_dns_response(id: u16, response: &[u8]) -> Result<Vec<IpAddr>, Error> {
    if response.len() < 12 || u16::from_be_bytes([response[0], response[1]]) != id {
        return Err(Error::Protocol("invalid DNS response header".into()));
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x000f != 0 {
        return Err(Error::Protocol(format!(
            "remote DNS returned rcode {}",
            flags & 0x000f
        )));
    }
    let questions = u16::from_be_bytes([response[4], response[5]]);
    let answers = u16::from_be_bytes([response[6], response[7]]);
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_dns_name(response, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|offset| *offset <= response.len())
            .ok_or_else(|| Error::Protocol("truncated DNS question".into()))?;
    }
    let mut addresses = Vec::new();
    for _ in 0..answers {
        offset = skip_dns_name(response, offset)?;
        if offset + 10 > response.len() {
            return Err(Error::Protocol("truncated DNS answer".into()));
        }
        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let length = usize::from(u16::from_be_bytes([
            response[offset + 8],
            response[offset + 9],
        ]));
        offset += 10;
        if offset + length > response.len() {
            return Err(Error::Protocol("truncated DNS record data".into()));
        }
        if class == 1 && record_type == 1 && length == 4 {
            addresses.push(IpAddr::V4(Ipv4Addr::new(
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            )));
        } else if class == 1 && record_type == 28 && length == 16 {
            let octets: [u8; 16] = response[offset..offset + 16]
                .try_into()
                .expect("DNS record length was checked");
            addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
        }
        offset += length;
    }
    Ok(addresses)
}

fn skip_dns_name(message: &[u8], mut offset: usize) -> Result<usize, Error> {
    loop {
        let length = *message
            .get(offset)
            .ok_or_else(|| Error::Protocol("truncated DNS name".into()))?;
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        if length & 0xc0 == 0xc0 {
            if offset >= message.len() {
                return Err(Error::Protocol("truncated DNS compression pointer".into()));
            }
            return Ok(offset + 1);
        }
        if length & 0xc0 != 0 {
            return Err(Error::Protocol("invalid DNS label length".into()));
        }
        offset = offset
            .checked_add(usize::from(length))
            .filter(|offset| *offset <= message.len())
            .ok_or_else(|| Error::Protocol("truncated DNS label".into()))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::Resources;

    #[test]
    fn creates_dns_query() {
        let query = dns_query(0x1234, "www.zju.edu.cn", 1).unwrap();
        assert_eq!(&query[..2], &[0x12, 0x34]);
        assert!(query.windows(3).any(|window| window == b"zju"));
        assert_eq!(&query[query.len() - 4..], &[0, 1, 0, 1]);
    }

    #[test]
    fn checks_http_proxy_basic_auth() {
        let credentials = ("alice".to_owned(), "s3cret".to_owned());
        let token = BASE64.encode("alice:s3cret");
        let good = format!("GET http://x/ HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n");
        assert!(proxy_auth_ok(&good, Some(&credentials)));
        assert!(proxy_auth_ok("GET http://x/ HTTP/1.1\r\n", None));
        assert!(!proxy_auth_ok("GET http://x/ HTTP/1.1\r\n", Some(&credentials)));
        assert!(!proxy_auth_ok(
            "GET http://x/ HTTP/1.1\r\nProxy-Authorization: Basic wrong\r\n",
            Some(&credentials)
        ));
    }

    #[test]
    fn maps_connect_errors_to_socks_codes() {
        use std::io::ErrorKind;
        let code = |kind| socks_error_code(&Error::Io(std::io::Error::from(kind)));
        assert_eq!(code(ErrorKind::ConnectionRefused), 0x05);
        assert_eq!(code(ErrorKind::TimedOut), 0x06);
        assert_eq!(code(ErrorKind::HostUnreachable), 0x04);
        assert_eq!(code(ErrorKind::NetworkUnreachable), 0x03);
        assert_eq!(socks_error_code(&Error::NotConnected), 0x01);
    }

    #[test]
    fn parses_connect_authorities() {
        assert_eq!(
            parse_authority("example.com:8443", 443).unwrap(),
            ("example.com".into(), 8443)
        );
        assert_eq!(
            parse_authority("[2001:db8::1]:443", 80).unwrap(),
            ("2001:db8::1".into(), 443)
        );
    }

    #[test]
    fn parses_a_dns_a_response() {
        let query = dns_query(7, "example.com", 1).unwrap();
        let mut response = query;
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        assert_eq!(
            parse_dns_response(7, &response).unwrap(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
    }

    fn direct_connector() -> Arc<Connector> {
        Arc::new(Connector::new(
            Policy::new(Resources::default(), false),
            DnsConfig {
                remote_dns: None,
                secondary_dns: None,
                ttl: Duration::ZERO,
            },
            "unused",
            BTreeMap::new(),
        ))
    }

    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = stream.split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        });
        address
    }

    #[tokio::test]
    async fn socks5_connect_relays_tcp() {
        let destination = echo_server().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_socks(stream, direct_connector(), "", "")
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1];
        let SocketAddr::V4(destination) = destination else {
            panic!("test listener was not IPv4");
        };
        request.extend_from_slice(&destination.ip().octets());
        request.extend_from_slice(&destination.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response[..2], &[5, 0]);
        client.write_all(b"through socks").await.unwrap();
        let mut echoed = [0_u8; 13];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"through socks");
    }

    #[tokio::test]
    async fn http_connect_relays_tcp() {
        let destination = echo_server().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_http(stream, direct_connector(), None).await.unwrap();
        });

        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(format!("CONNECT {destination} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = [0_u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        client.write_all(b"through http").await.unwrap();
        let mut echoed = [0_u8; 12];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"through http");
    }
}
