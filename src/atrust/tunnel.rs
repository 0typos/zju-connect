use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;
use hmac::{Hmac, Mac as _};
use native_tls::TlsConnector as NativeTlsConnector;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream},
    net::TcpStream,
};
use tokio_native_tls::{TlsConnector, TlsStream};

use crate::{
    Error,
    policy::Policy,
    resource::ProtocolMatch,
    service::{ProxyStream, TcpConnector},
};

use super::{AtrustClient, split_endpoint};

const MAX_FRAME: usize = 65_535;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);

#[async_trait]
impl TcpConnector for AtrustClient {
    async fn connect_tcp(&self, host: &str, port: u16) -> Result<ProxyStream, Error> {
        let parsed = self.parsed.as_ref().ok_or(Error::NotConnected)?;
        let normalized = host
            .trim_matches(['[', ']'])
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let policy = Policy::new(parsed.resources.clone(), false);

        let (destination_ip, domain, app_id, group) = if let Ok(ip) = normalized.parse::<IpAddr>() {
            let Some(resource) = policy.matching_ip_resource(ip, port, ProtocolMatch::Tcp) else {
                return direct_connect(&normalized, port).await;
            };
            (
                ip,
                None,
                resource.app_id.as_deref(),
                resource.node_group_id.as_deref(),
            )
        } else {
            let Some(resource) =
                policy.matching_domain_resource(&normalized, port, ProtocolMatch::Tcp)
            else {
                return direct_connect(&normalized, port).await;
            };
            let ip = resolve_tunnel_domain(self, &normalized, port).await?;
            (
                ip,
                Some(normalized.as_str()),
                resource.app_id.as_deref(),
                resource.node_group_id.as_deref(),
            )
        };

        let app_id =
            app_id.ok_or_else(|| Error::Resource("aTrust TCP resource has no app ID".into()))?;
        let group = group.unwrap_or_default();
        let node = self
            .best_nodes
            .get(group)
            .or_else(|| self.best_nodes.get(&parsed.major_node_group))
            .ok_or_else(|| {
                Error::Protocol(format!("no reachable aTrust node for group {group:?}"))
            })?;
        let tls = open_tls(node).await?;
        let stream = open_tcp_tunnel(
            tls,
            TunnelRequest {
                sid: self.sid.as_deref().ok_or(Error::NotConnected)?,
                app_id,
                device_id: &self.device_id,
                connection_id: &self.connection_id,
                sign_key: &self.sign_key,
                username: self.username.as_deref().ok_or(Error::NotConnected)?,
                destination_ip,
                domain,
                port,
                skip_wait: self.config.skip_tcp_tunnel_wait,
            },
        )
        .await?;
        Ok(Box::pin(stream))
    }
}

async fn direct_connect(host: &str, port: u16) -> Result<ProxyStream, Error> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| Error::Protocol(format!("direct connection to {host}:{port} timed out")))??;
    Ok(Box::pin(stream))
}

async fn resolve_tunnel_domain(
    client: &AtrustClient,
    domain: &str,
    port: u16,
) -> Result<IpAddr, Error> {
    if let Some(address) = client
        .config
        .custom_dns
        .iter()
        .find(|entry| entry.host_name.eq_ignore_ascii_case(domain))
        .map(|entry| entry.ip)
    {
        return Ok(address);
    }
    let resources = &client.parsed.as_ref().ok_or(Error::NotConnected)?.resources;
    if let Some(address) = domain_suffixes(domain).find_map(|suffix| {
        resources
            .dns_records
            .get(suffix)
            .or_else(|| resources.dns_records.get(&format!(".{suffix}")))
            .and_then(|addresses| addresses.iter().copied().find(IpAddr::is_ipv4))
    }) {
        return Ok(address);
    }
    tokio::net::lookup_host((domain, port))
        .await?
        .map(|address| address.ip())
        .find(IpAddr::is_ipv4)
        .ok_or_else(|| Error::Protocol(format!("DNS returned no IPv4 address for {domain}")))
}

fn domain_suffixes(domain: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(domain), |part| {
        part.split_once('.').map(|(_, tail)| tail)
    })
}

async fn open_tls(node: &str) -> Result<TlsStream<TcpStream>, Error> {
    let (host, _) = split_endpoint(node)?;
    let connect = async {
        let tcp = TcpStream::connect(node).await?;
        let connector = NativeTlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .use_sni(false)
            .build()
            .map_err(|error| Error::Tls(error.to_string()))?;
        TlsConnector::from(connector)
            .connect(host, tcp)
            .await
            .map_err(|error| Error::Tls(error.to_string()))
    };
    tokio::time::timeout(CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| Error::Protocol(format!("aTrust node {node} TLS connect timed out")))?
}

struct TunnelRequest<'a> {
    sid: &'a str,
    app_id: &'a str,
    device_id: &'a str,
    connection_id: &'a str,
    sign_key: &'a str,
    username: &'a str,
    destination_ip: IpAddr,
    domain: Option<&'a str>,
    port: u16,
    skip_wait: bool,
}

async fn open_tcp_tunnel(
    mut tls: TlsStream<TcpStream>,
    request: TunnelRequest<'_>,
) -> Result<DuplexStream, Error> {
    let destination_ip = match request.destination_ip {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => {
            return Err(Error::Protocol(
                "aTrust TCP tunnel does not support IPv6 destinations".into(),
            ));
        }
    };
    let destination = request.domain.map_or_else(
        || format!("{destination_ip}:{}", request.port),
        |domain| format!("{domain}:{}", request.port),
    );
    let (process_name, process_path) = if request.port == 22 {
        ("ssh", "/usr/bin/ssh")
    } else {
        ("google-chrome-stable", "/usr/bin/google-chrome-stable")
    };
    let authorization = build_authorization(&request, &destination, process_name, process_path)?;

    let length = u16::try_from(authorization.len())
        .map_err(|_| Error::Protocol("aTrust authorization frame is too large".into()))?;
    let mut init = vec![0x05, 0x01, 0x81, 0x53, 0x03];
    init.extend_from_slice(&length.to_be_bytes());
    init.extend_from_slice(authorization.as_bytes());
    tls.write_all(&init).await?;

    let mut destination_frame = vec![0x05, 0x01, 0x01];
    if let Some(domain) = request.domain {
        let length = u8::try_from(domain.len())
            .map_err(|_| Error::Protocol(format!("domain is too long: {domain}")))?;
        destination_frame.extend_from_slice(&[0x03, length]);
        destination_frame.extend_from_slice(domain.as_bytes());
    } else {
        destination_frame.push(0x01);
        destination_frame.extend_from_slice(&destination_ip.octets());
    }
    destination_frame.extend_from_slice(&request.port.to_be_bytes());
    tls.write_all(&destination_frame).await?;
    tokio::time::timeout(SETUP_TIMEOUT, wait_for_connect(&mut tls, request.skip_wait))
        .await
        .map_err(|_| Error::Protocol("aTrust TCP tunnel setup timed out".into()))??;

    let (application, bridge) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Err(error) = bridge_frames(tls, bridge).await {
            tracing::debug!(%error, "aTrust TCP tunnel closed");
        }
    });
    Ok(application)
}

fn build_authorization(
    request: &TunnelRequest<'_>,
    destination: &str,
    process_name: &str,
    process_path: &str,
) -> Result<String, Error> {
    let process_hash = hex::encode_upper(Sha256::digest(process_path.as_bytes()));
    let json_string =
        |value: &str| serde_json::to_string(value).expect("serializing a string cannot fail");
    let mut authorization = format!(
        concat!(
            "{{\"sid\":{},\"appId\":{},\"url\":{},\"deviceId\":{},",
            "\"connectionId\":{},\"procHash\":{},\"userName\":{},",
            "\"rcAppliedInfo\":0,\"lang\":\"en-US\",\"destAddr\":{},",
            "\"env\":{{\"application\":{{\"runtime\":{{\"process\":{{",
            "\"name\":{},\"digital_signature\":\"TrustAppClosed\",",
            "\"platform\":\"Linux\",\"fingerprint\":{},",
            "\"description\":\"TrustAppClosed\",\"path\":{},",
            "\"version\":\"TrustAppClosed\",\"security_env\":\"normal\"}},",
            "\"process_trusted\":\"TRUSTED\"}}}}}},\"xRequestSig\":\"\"}}"
        ),
        json_string(request.sid),
        json_string(request.app_id),
        json_string(&format!("tcp://{destination}")),
        json_string(request.device_id),
        json_string(request.connection_id),
        json_string(&process_hash),
        json_string(request.username),
        json_string(destination),
        json_string(process_name),
        json_string(&process_hash),
        json_string(process_path),
    );
    let sign_key = hex::decode(request.sign_key)
        .map_err(|error| Error::Config(format!("invalid aTrust sign key: {error}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&sign_key)
        .map_err(|error| Error::Config(format!("invalid aTrust sign key: {error}")))?;
    mac.update(authorization.as_bytes());
    let signature = hex::encode_upper(mac.finalize().into_bytes());
    authorization.truncate(authorization.len() - 3);
    authorization.push('"');
    authorization.push_str(&signature);
    authorization.push_str("\"}");
    Ok(authorization)
}

async fn wait_for_connect(tls: &mut TlsStream<TcpStream>, skip_wait: bool) -> Result<(), Error> {
    if skip_wait {
        return Ok(());
    }
    loop {
        let mut header = [0_u8; 2];
        tls.read_exact(&mut header).await?;
        if header == [0x05, 0x81] {
            continue;
        }
        if header != [0x53, 0x00] {
            return Err(Error::Protocol(format!(
                "unexpected aTrust TCP setup frame: {}",
                hex::encode(header)
            )));
        }
        let length = tls.read_u16().await?;
        let mut response = vec![0_u8; usize::from(length)];
        tls.read_exact(&mut response).await?;
        let text = String::from_utf8_lossy(&response);
        if !text.contains("OK") {
            return Err(Error::Protocol(format!("aTrust TCP setup failed: {text}")));
        }
        break;
    }

    tls.write_all(&[0x01, 0x00, 0x00, 0x00]).await?;
    let mut status = [0_u8; 2];
    tls.read_exact(&mut status).await?;
    if status == [0x05, 0x00] {
        Ok(())
    } else {
        Err(Error::Protocol(tunnel_status(status)))
    }
}

fn tunnel_status(status: [u8; 2]) -> String {
    if status[0] != 0x05 {
        return format!("unexpected aTrust TCP status: {}", hex::encode(status));
    }
    let message = match status[1] {
        0x01 => "server failure",
        0x02 => "connection not allowed",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown failure",
    };
    format!("aTrust TCP tunnel failed: {message} (0x{:02x})", status[1])
}

async fn bridge_frames(tls: TlsStream<TcpStream>, bridge: DuplexStream) -> Result<(), Error> {
    let (tls_read, tls_write) = tokio::io::split(tls);
    let (app_read, app_write) = tokio::io::split(bridge);
    let uplink = application_to_tunnel(app_read, tls_write);
    let downlink = tunnel_to_application(tls_read, app_write);
    tokio::pin!(uplink, downlink);
    let mut uplink_done = false;
    loop {
        tokio::select! {
            // The server→application direction owns connection lifetime.
            result = &mut downlink => return result,
            // A clean application half-close keeps the server draining so
            // in-flight response data is never dropped; an uplink *error*
            // tears the bridge down instead of hanging until the server acts.
            result = &mut uplink, if !uplink_done => match result {
                Ok(()) => uplink_done = true,
                Err(error) => return Err(error),
            },
        }
    }
}

async fn application_to_tunnel<R, W>(mut app: R, mut tls: W) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; MAX_FRAME];
    loop {
        let count = app.read(&mut buffer).await?;
        if count == 0 {
            tls.write_all(&[0x01, 0x01, 0x00, 0x00]).await?;
            tls.shutdown().await?;
            return Ok(());
        }
        tls.write_all(&[0x01, 0x00]).await?;
        tls.write_all(&u16::try_from(count).expect("bounded buffer").to_be_bytes())
            .await?;
        tls.write_all(&buffer[..count]).await?;
    }
}

async fn tunnel_to_application<R, W>(mut tls: R, mut app: W) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let mut header = [0_u8; 2];
        tls.read_exact(&mut header).await?;
        match header {
            [0x01, 0x00] => {
                let length = tls.read_u16().await?;
                let mut data = vec![0_u8; usize::from(length)];
                tls.read_exact(&mut data).await?;
                app.write_all(&data).await?;
            }
            [0x01, 0x01] => {
                // Only a 0x3030 payload is a close; the official client keeps
                // reading through any other control value.
                let mut close = [0_u8; 2];
                tls.read_exact(&mut close).await?;
                if close == [0x30, 0x30] {
                    app.shutdown().await?;
                    return Ok(());
                }
            }
            [0x53, 0x00] => {
                let length = tls.read_u16().await?;
                let mut response = vec![0_u8; usize::from(length)];
                tls.read_exact(&mut response).await?;
                if !String::from_utf8_lossy(&response).contains("OK") {
                    return Err(Error::Protocol(format!(
                        "aTrust TCP protocol error: {}",
                        String::from_utf8_lossy(&response)
                    )));
                }
            }
            // The gateway interleaves bare two-byte control frames (the
            // 05 81 acknowledgement, and with skip_tcp_tunnel_wait also the
            // deferred 05 xx connect status); the official client reads past
            // every header it does not recognize.
            _ => {
                tracing::trace!(
                    frame = %hex::encode(header),
                    "ignoring aTrust TCP tunnel frame"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_tunnel_statuses() {
        assert!(tunnel_status([0x05, 0x05]).contains("connection refused"));
        assert!(tunnel_status([0xff, 0x00]).contains("unexpected"));
    }

    #[test]
    fn builds_valid_signed_linux_authorization() {
        let request = TunnelRequest {
            sid: "sid",
            app_id: "app",
            device_id: "device",
            connection_id: "connection",
            sign_key: &"ab".repeat(32),
            username: "user@Radius",
            destination_ip: "192.0.2.10".parse().unwrap(),
            domain: Some("internal.example"),
            port: 443,
            skip_wait: false,
        };
        let message = build_authorization(
            &request,
            "internal.example:443",
            "google-chrome-stable",
            "/usr/bin/google-chrome-stable",
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&message).unwrap();
        assert_eq!(
            value["env"]["application"]["runtime"]["process"]["platform"],
            "Linux"
        );
        assert_eq!(value["xRequestSig"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn tunnel_reader_closes_only_on_3030_control() {
        let (mut wire, tunnel_side) = tokio::io::duplex(4096);
        let (mut application, app_side) = tokio::io::duplex(4096);
        let (tunnel_reader, _tunnel_writer) = tokio::io::split(tunnel_side);
        let (_, app_writer) = tokio::io::split(app_side);
        let task = tokio::spawn(tunnel_to_application(tunnel_reader, app_writer));

        // Non-close 01 01 control, an unknown bare frame, a deferred connect
        // status, then data, then a real close.
        wire.write_all(&[0x01, 0x01, 0x31, 0x31]).await.unwrap();
        wire.write_all(&[0x05, 0x81]).await.unwrap();
        wire.write_all(&[0x05, 0x00]).await.unwrap();
        wire.write_all(&[0x01, 0x00, 0x00, 0x02]).await.unwrap();
        wire.write_all(b"ok").await.unwrap();
        wire.write_all(&[0x01, 0x01, 0x30, 0x30]).await.unwrap();

        let mut received = [0_u8; 2];
        application.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"ok");
        task.await.unwrap().unwrap();
        assert_eq!(application.read(&mut received).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn bridges_application_frames() {
        let (mut application, bridge) = tokio::io::duplex(64);
        let (mut wire_reader, wire_writer) = tokio::io::duplex(64);
        let (bridge_reader, _) = tokio::io::split(bridge);
        let (_, wire_writer) = tokio::io::split(wire_writer);
        let task = tokio::spawn(application_to_tunnel(bridge_reader, wire_writer));
        application.write_all(b"hello").await.unwrap();
        let mut frame = [0_u8; 9];
        wire_reader.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x01\x00\x00\x05hello");
        drop(application);
        task.await.unwrap().unwrap();
    }
}
