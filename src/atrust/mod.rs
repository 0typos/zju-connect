//! Linux aTrust control-plane implementation.

mod auth;
mod l3;
mod parse;
mod tunnel;

use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use md5::{Digest as _, Md5};
use native_tls::TlsConnector as NativeTlsConnector;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    task::JoinSet,
};
use tokio_native_tls::TlsConnector;

use crate::{ChallengeHandler, Config, ConnectionInfo, Error};

pub use auth::{AuthInfo, AuthResult};
pub use parse::{NodeGroup, ParsedResources, parse_resources};

const NODE_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const IP_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);

pub struct AtrustClient {
    config: Config,
    username: Option<String>,
    sid: Option<String>,
    device_id: String,
    connection_id: String,
    sign_key: String,
    parsed: Option<ParsedResources>,
    best_nodes: BTreeMap<String, String>,
    client_ip: Option<IpAddr>,
}

impl AtrustClient {
    /// Construct an aTrust client without contacting the gateway.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when a preconfigured session is incomplete.
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.protocol != crate::Protocol::Atrust {
            return Err(Error::Config(
                "AtrustClient requires protocol = \"atrust\"".into(),
            ));
        }
        let device_id = config
            .device_id
            .clone()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| auth::random_hex(32, true));
        let connection_id = connection_id(&device_id);
        let sign_key = config
            .sign_key
            .clone()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| auth::random_hex(64, false));
        Ok(Self {
            username: (!config.username.is_empty()).then(|| config.username.clone()),
            sid: config.sid.clone().filter(|value| !value.is_empty()),
            config,
            device_id,
            connection_id,
            sign_key,
            parsed: None,
            best_nodes: BTreeMap::new(),
            client_ip: None,
        })
    }

    /// Query the login methods advertised by the gateway.
    ///
    /// # Errors
    ///
    /// Returns a network or malformed-response error.
    pub async fn authentication_methods(&self) -> Result<Vec<AuthInfo>, Error> {
        let mut session = auth::AuthSession::new(&self.config, self.device_id.clone())?;
        let (_, methods) = session.auth_info().await?;
        Ok(methods)
    }

    /// Authenticate, download aTrust policy, select a tunnel node, and negotiate a virtual IP.
    ///
    /// # Errors
    ///
    /// Returns an authentication, policy, TLS, or node-negotiation error.
    pub async fn connect_control_plane(
        &mut self,
        challenges: &dyn ChallengeHandler,
    ) -> Result<ConnectionInfo, Error> {
        let resource_data = if self.sid.is_some() {
            let path = self
                .config
                .resource_file
                .as_ref()
                .filter(|path| !path.is_empty())
                .ok_or_else(|| {
                    Error::Config("aTrust sid requires resource_file for session reuse".into())
                })?;
            tokio::fs::read(path).await?
        } else {
            let mut session = auth::AuthSession::new(&self.config, self.device_id.clone())?;
            let result = session.login(&self.config, challenges).await?;
            self.username = Some(result.username);
            self.sid = Some(result.sid);
            self.device_id = result.device_id;
            let resources = session.client_resources().await?;
            if let Some(path) = self
                .config
                .resource_file
                .as_ref()
                .filter(|path| !path.is_empty())
            {
                tokio::fs::write(path, &resources).await?;
            }
            resources
        };

        let parsed = parse_resources(&resource_data, &self.config.server_address)?;
        let best_nodes = select_best_nodes(&parsed.node_groups).await;
        let node = preferred_node(&best_nodes, &parsed.major_node_group)
            .ok_or_else(|| Error::Protocol("no reachable aTrust tunnel node".into()))?;
        let sid = self
            .sid
            .as_deref()
            .ok_or_else(|| Error::Protocol("aTrust session has no sid".into()))?;
        let client_ip = request_virtual_ip(node, sid).await?;
        let info = ConnectionInfo {
            client_ip,
            dns_servers: parsed.resources.dns_servers.clone(),
            resources: parsed.resources.clone(),
        };
        self.parsed = Some(parsed);
        self.best_nodes = best_nodes;
        self.client_ip = Some(client_ip);
        Ok(info)
    }

    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    pub fn sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub fn sign_key(&self) -> &str {
        &self.sign_key
    }

    pub fn parsed_resources(&self) -> Option<&ParsedResources> {
        self.parsed.as_ref()
    }

    pub fn best_nodes(&self) -> &BTreeMap<String, String> {
        &self.best_nodes
    }

    pub fn client_ip(&self) -> Option<IpAddr> {
        self.client_ip
    }
}

async fn select_best_nodes(groups: &BTreeMap<String, NodeGroup>) -> BTreeMap<String, String> {
    let mut selected = BTreeMap::new();
    for (id, group) in groups {
        if let Some(node) = fastest_reachable(&group.wan).await {
            selected.insert(id.clone(), node);
        } else if let Some(node) = fastest_reachable(&group.lan).await {
            selected.insert(id.clone(), node);
        }
    }
    selected
}

async fn fastest_reachable(nodes: &[String]) -> Option<String> {
    let mut probes = JoinSet::new();
    for node in nodes {
        let node = node.clone();
        probes.spawn(async move {
            let started = tokio::time::Instant::now();
            let reachable = tokio::time::timeout(NODE_CONNECT_TIMEOUT, TcpStream::connect(&node))
                .await
                .is_ok_and(|result| result.is_ok());
            (reachable, started.elapsed(), node)
        });
    }
    let mut fastest = None;
    while let Some(result) = probes.join_next().await {
        if let Ok((true, elapsed, node)) = result {
            if fastest
                .as_ref()
                .is_none_or(|(best, _): &(Duration, String)| elapsed < *best)
            {
                fastest = Some((elapsed, node));
            }
        }
    }
    fastest.map(|(_, node)| node)
}

fn preferred_node<'a>(nodes: &'a BTreeMap<String, String>, major: &str) -> Option<&'a str> {
    nodes
        .get(major)
        .or_else(|| nodes.values().next())
        .map(String::as_str)
}

async fn request_virtual_ip(node: &str, sid: &str) -> Result<IpAddr, Error> {
    tokio::time::timeout(IP_NEGOTIATION_TIMEOUT, request_virtual_ip_inner(node, sid))
        .await
        .map_err(|_| Error::Protocol("aTrust virtual-IP negotiation timed out".into()))?
}

async fn request_virtual_ip_inner(node: &str, sid: &str) -> Result<IpAddr, Error> {
    let (host, _) = split_endpoint(node)?;
    let tcp = TcpStream::connect(node).await?;
    let connector = NativeTlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .use_sni(false)
        .build()
        .map_err(|error| Error::Tls(error.to_string()))?;
    let mut tls = TlsConnector::from(connector)
        .connect(host, tcp)
        .await
        .map_err(|error| Error::Tls(error.to_string()))?;
    negotiate_virtual_ip(&mut tls, sid).await
}

async fn negotiate_virtual_ip<S>(tls: &mut S, sid: &str) -> Result<IpAddr, Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let authentication = serde_json::to_vec(&serde_json::json!({"sid": sid}))
        .map_err(|error| Error::Protocol(format!("cannot encode aTrust sid: {error}")))?;
    let length = u16::try_from(authentication.len())
        .map_err(|_| Error::Protocol("aTrust sid frame is too large".into()))?;
    let mut request = vec![0x05, 0x01, 0xd0, 0x53, 0x00];
    request.extend_from_slice(&length.to_be_bytes());
    request.extend_from_slice(&authentication);
    tls.write_all(&request).await?;
    tls.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    loop {
        let mut header = [0_u8; 2];
        tls.read_exact(&mut header).await?;
        match header {
            [0x53, 0x00] => {
                let length = tls.read_u16().await?;
                let mut response = vec![0_u8; usize::from(length)];
                tls.read_exact(&mut response).await?;
                let text = String::from_utf8_lossy(&response);
                if !text.contains("OK") {
                    return Err(Error::Protocol(format!(
                        "aTrust tunnel authorization failed: {text}"
                    )));
                }
            }
            [0x05, 0x00] => {
                let mut response = [0_u8; 6];
                tls.read_exact(&mut response).await?;
                if response[..2] != [0, 1] {
                    return Err(Error::Protocol(format!(
                        "unexpected aTrust virtual-IP response: {}",
                        hex::encode(response)
                    )));
                }
                return Ok(std::net::Ipv4Addr::new(
                    response[2],
                    response[3],
                    response[4],
                    response[5],
                )
                .into());
            }
            // The gateway interleaves other frames (e.g. the 05 d0 method
            // echo) before the virtual-IP response; the official flow reads
            // past anything it does not recognize.
            _ => {
                tracing::debug!(
                    frame = %hex::encode(header),
                    "ignoring aTrust virtual-IP negotiation frame"
                );
            }
        }
    }
}

fn split_endpoint(endpoint: &str) -> Result<(&str, u16), Error> {
    if endpoint.starts_with('[') {
        let end = endpoint
            .find(']')
            .ok_or_else(|| Error::Resource(format!("invalid node address: {endpoint}")))?;
        let host = &endpoint[1..end];
        let port = endpoint[end + 1..]
            .strip_prefix(':')
            .and_then(|port| port.parse().ok())
            .ok_or_else(|| Error::Resource(format!("invalid node port: {endpoint}")))?;
        return Ok((host, port));
    }
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| Error::Resource(format!("node has no port: {endpoint}")))?;
    let port = port
        .parse()
        .map_err(|_| Error::Resource(format!("invalid node port: {endpoint}")))?;
    Ok((host, port))
}

fn connection_id(device_id: &str) -> String {
    let hash = Md5::digest(device_id.as_bytes());
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    format!("{}-{micros}", hex::encode_upper(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6_node_endpoints() {
        assert_eq!(
            split_endpoint("node.example:441").unwrap(),
            ("node.example", 441)
        );
        assert_eq!(
            split_endpoint("[2001:db8::1]:441").unwrap(),
            ("2001:db8::1", 441)
        );
    }

    #[test]
    fn connection_id_uses_official_shape() {
        let id = connection_id("device");
        let (hash, timestamp) = id.split_once('-').unwrap();
        assert_eq!(hash.len(), 32);
        assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(timestamp.parse::<u128>().is_ok());
    }

    #[test]
    fn prefers_major_node_group() {
        let nodes = BTreeMap::from([
            ("fallback".into(), "node-a:441".into()),
            ("major".into(), "node-b:441".into()),
        ]);
        assert_eq!(preferred_node(&nodes, "major"), Some("node-b:441"));
    }

    #[tokio::test]
    async fn virtual_ip_negotiation_skips_method_echo() {
        let (mut gateway, mut client) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            // Method echo, then an authorization result, then the IP reply.
            gateway.write_all(&[0x05, 0xd0]).await.unwrap();
            gateway.write_all(&[0x53, 0x00, 0x00, 0x02]).await.unwrap();
            gateway.write_all(b"OK").await.unwrap();
            gateway
                .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 20, 30, 40])
                .await
                .unwrap();
        });
        let ip = negotiate_virtual_ip(&mut client, "session-sid")
            .await
            .unwrap();
        assert_eq!(ip, IpAddr::from([10, 20, 30, 40]));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn virtual_ip_negotiation_rejects_failed_authorization() {
        let (mut gateway, mut client) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            gateway.write_all(&[0x53, 0x00, 0x00, 0x04]).await.unwrap();
            gateway.write_all(b"BUSY").await.unwrap();
        });
        let error = negotiate_virtual_ip(&mut client, "session-sid")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("authorization failed"));
        server.await.unwrap();
    }
}
