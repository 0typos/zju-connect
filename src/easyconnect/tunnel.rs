use std::{
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf},
    net::TcpStream,
};

use crate::{
    ChallengeHandler, ConnectionInfo, Error, L3Stream, VpnClient,
    resource::{DomainResource, IpRange, IpResource, ProtocolMatch},
};

use super::{EasyConnectClient, legacy_tls::LegacyTlsStream};

const TUNNEL_BUFFER_SIZE: usize = 256 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// The gateway rejects an IP request that follows the token request too
/// closely; the official flow waits at least one second between them.
const TOKEN_TO_IP_DELAY: Duration = Duration::from_secs(1);
const MAX_TUNNEL_RETRIES: u32 = 5;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

impl EasyConnectClient {
    /// Establish the token exchange and negotiate the L3 virtual IPv4 address.
    ///
    /// # Errors
    ///
    /// Returns an I/O, TLS, or gateway protocol error. Authentication must have
    /// completed successfully before calling this method.
    pub async fn establish_data_plane(&mut self) -> Result<Ipv4Addr, Error> {
        let token = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.request_token())
            .await
            .map_err(|_| Error::Protocol("EasyConnect token request timed out".into()))??;
        self.token = Some(token);
        tokio::time::sleep(TOKEN_TO_IP_DELAY).await;

        let request_ip = async {
            let mut connection = LegacyTlsStream::connect(&self.config.server_host()).await?;
            let request = crate::wire::to_bytes(&crate::wire::EcIpRequest { token, _suffix: () })?;
            connection.write_all(&request).await?;
            let reply = connection.read_record().await?;
            if reply.len() < 8 || reply[0] != 0 {
                return Err(Error::Protocol(format!(
                    "unexpected EasyConnect IP reply: {}",
                    hex::encode(reply)
                )));
            }
            Ok((Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]), connection))
        };
        let (ip, connection) = tokio::time::timeout(HANDSHAKE_TIMEOUT, request_ip)
            .await
            .map_err(|_| Error::Protocol("EasyConnect IP negotiation timed out".into()))??;
        self.client_ip = Some(ip);
        // The server uses the lifetime of this connection as part of the session.
        self.request_ip_connection = Some(connection);
        Ok(ip)
    }

    async fn request_token(&self) -> Result<[u8; 48], Error> {
        let twf_id = self.twf_id.as_deref().ok_or(Error::NotConnected)?;
        let capture = Arc::new(Mutex::new(Vec::new()));
        let socket = TcpStream::connect(self.config.server_host()).await?;
        let io = CaptureIo {
            inner: socket,
            received: Arc::clone(&capture),
        };
        let mut builder = native_tls::TlsConnector::builder();
        builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
        let connector = builder
            .build()
            .map_err(|error| Error::Tls(error.to_string()))?;
        let connector = tokio_native_tls::TlsConnector::from(connector);
        let mut tls = connector
            .connect(&self.config.server_address, io)
            .await
            .map_err(|error| Error::Tls(error.to_string()))?;

        let request = format!(
            "GET /por/conf.csp HTTP/1.1\r\nHost: {host}\r\nCookie: TWFID={twf_id}\r\nConnection: keep-alive\r\n\r\nGET /por/rclist.csp HTTP/1.1\r\nHost: {host}\r\nCookie: TWFID={twf_id}\r\nConnection: close\r\n\r\n",
            host = self.config.server_host(),
        );
        tls.write_all(request.as_bytes()).await?;
        tls.flush().await?;
        let mut prefix = [0_u8; 8];
        let received = tls.read(&mut prefix).await?;
        if received == 0 {
            return Err(Error::Protocol(
                "EasyConnect token request returned no HTTP data".into(),
            ));
        }

        let handshake = capture
            .lock()
            .map_err(|_| Error::Protocol("TLS capture lock was poisoned".into()))?;
        let session_id = parse_server_session_id(&handshake)?;
        let session_hex = hex::encode(session_id);
        if session_hex.len() < 31 || twf_id.len() != 16 {
            return Err(Error::Protocol(format!(
                "gateway token inputs have invalid lengths (TLS session hex={}, TwfID={})",
                session_hex.len(),
                twf_id.len()
            )));
        }
        let mut token = [0_u8; 48];
        token[..31].copy_from_slice(&session_hex.as_bytes()[..31]);
        token[31] = 0;
        token[32..].copy_from_slice(twf_id.as_bytes());
        Ok(token)
    }

    fn tunnel_session(&self) -> Result<TunnelSession, Error> {
        Ok(TunnelSession {
            server_host: self.config.server_host(),
            token: self.token.ok_or(Error::NotConnected)?,
            client_ip: self.client_ip.ok_or(Error::NotConnected)?,
        })
    }

    async fn create_l3_stream(&self) -> Result<L3Stream, Error> {
        let session = Arc::new(self.tunnel_session()?);
        let send = tunnel_connection(&session, 0x05).await?;
        let receive = tunnel_connection(&session, 0x06).await?;
        let (application, bridge) = tokio::io::duplex(TUNNEL_BUFFER_SIZE);
        tokio::spawn(async move {
            if let Err(error) = bridge_tunnel(bridge, session, send, receive).await {
                tracing::warn!(%error, "EasyConnect L3 tunnel stopped");
            }
        });
        Ok(Box::pin(application))
    }

    fn add_zju_resources(&mut self) {
        if !self.config.disable_zju_config {
            self.resources.ip.insert(
                0,
                IpResource {
                    addresses: IpRange::Inclusive {
                        first: "10.0.0.0".parse().expect("valid constant"),
                        last: "10.255.255.255".parse().expect("valid constant"),
                    },
                    ports: 1..=u16::MAX,
                    protocol: ProtocolMatch::All,
                    app_id: None,
                    node_group_id: None,
                },
            );
            self.resources
                .domains
                .entry("zju.edu.cn".into())
                .or_default()
                .push(DomainResource {
                    ports: 1..=u16::MAX,
                    protocol: ProtocolMatch::All,
                    app_id: None,
                    node_group_id: None,
                });
        }
        for domain in &self.config.custom_proxy_domain {
            self.resources
                .domains
                .entry(domain.to_ascii_lowercase())
                .or_default()
                .push(DomainResource {
                    ports: 1..=u16::MAX,
                    protocol: ProtocolMatch::All,
                    app_id: None,
                    node_group_id: None,
                });
        }
    }
}

#[async_trait]
impl VpnClient for EasyConnectClient {
    async fn connect(
        &mut self,
        challenges: &dyn ChallengeHandler,
    ) -> Result<ConnectionInfo, Error> {
        self.authenticate(challenges).await?;
        self.select_best_line(challenges).await?;
        if !self.config.disable_server_config {
            self.fetch_resources().await?;
        }
        self.add_zju_resources();
        let client_ip = IpAddr::V4(self.establish_data_plane().await?);
        self.start_keepalive();
        Ok(ConnectionInfo {
            client_ip,
            dns_servers: self.resources.dns_servers.clone(),
            resources: self.resources.clone(),
        })
    }

    async fn open_l3(&self) -> Result<L3Stream, Error> {
        self.create_l3_stream().await
    }

    async fn close(&mut self) -> Result<(), Error> {
        if let Some(task) = self.keepalive_task.take() {
            task.abort();
            let _ = task.await;
        }
        self.request_ip_connection = None;
        self.token = None;
        self.client_ip = None;
        Ok(())
    }
}

struct TunnelSession {
    server_host: String,
    token: [u8; 48],
    client_ip: Ipv4Addr,
}

async fn tunnel_connection(
    session: &TunnelSession,
    command: u8,
) -> Result<LegacyTlsStream, Error> {
    let handshake = async {
        let mut connection = LegacyTlsStream::connect(&session.server_host).await?;
        let mut reversed_ip = session.client_ip.octets();
        reversed_ip.reverse();
        let request = crate::wire::to_bytes(&crate::wire::EcTunnelRequest {
            command,
            token: session.token,
            reversed_ip,
        })?;
        connection.write_all(&request).await?;
        let reply = connection.read_record().await?;
        let expected = if command == 0x05 { 0x02 } else { 0x01 };
        if reply.first() != Some(&expected) {
            let detail = match reply.first() {
                Some(0x08) => "server shut down the session".to_owned(),
                Some(code @ (0x05 | 0x06 | 0x07 | 0x09)) => {
                    format!("server requested reconnect later (0x{code:02x})")
                }
                Some(code) => format!("unexpected reply 0x{code:02x}"),
                None => "empty reply".to_owned(),
            };
            return Err(Error::Protocol(format!(
                "EasyConnect tunnel handshake failed: {detail}"
            )));
        }
        Ok(connection)
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| Error::Protocol("EasyConnect tunnel handshake timed out".into()))?
}

async fn bridge_tunnel(
    bridge: DuplexStream,
    session: Arc<TunnelSession>,
    send: LegacyTlsStream,
    receive: LegacyTlsStream,
) -> Result<(), Error> {
    let (mut from_application, mut to_application) = tokio::io::split(bridge);
    let send_loop = async {
        let mut connection = send;
        let mut failures = 0_u32;
        loop {
            let packet = read_ip_packet(&mut from_application).await?;
            while let Err(error) = connection.write_all(&packet).await {
                connection =
                    reconnect_tunnel(&session, 0x05, &error, &mut failures, "send").await?;
            }
            failures = 0;
        }
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    };
    let receive_loop = async {
        let mut connection = receive;
        let mut failures = 0_u32;
        loop {
            match connection.read_record().await {
                Ok(packet_bytes) => {
                    failures = 0;
                    to_application.write_all(&packet_bytes).await?;
                    to_application.flush().await?;
                }
                Err(error) => {
                    connection =
                        reconnect_tunnel(&session, 0x06, &error, &mut failures, "receive").await?;
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    };
    tokio::select! {
        result = send_loop => result,
        result = receive_loop => result,
    }
}

/// Recreate one tunnel direction after `error`, giving up once
/// [`MAX_TUNNEL_RETRIES`] consecutive attempts have failed.
async fn reconnect_tunnel(
    session: &TunnelSession,
    command: u8,
    error: &Error,
    failures: &mut u32,
    direction: &str,
) -> Result<LegacyTlsStream, Error> {
    loop {
        *failures += 1;
        if *failures > MAX_TUNNEL_RETRIES {
            return Err(Error::Protocol(format!(
                "EasyConnect {direction} tunnel failed after {MAX_TUNNEL_RETRIES} reconnect attempts: {error}"
            )));
        }
        tracing::warn!(
            %error,
            direction,
            attempt = *failures,
            "EasyConnect tunnel connection failed; reconnecting"
        );
        tokio::time::sleep(RECONNECT_DELAY).await;
        match tunnel_connection(session, command).await {
            Ok(connection) => return Ok(connection),
            Err(retry_error) => {
                tracing::warn!(%retry_error, direction, "EasyConnect tunnel reconnect failed");
            }
        }
    }
}

async fn read_ip_packet(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, Error> {
    let mut prefix = [0_u8; 6];
    reader.read_exact(&mut prefix[..1]).await?;
    let length = match prefix[0] >> 4 {
        4 => {
            reader.read_exact(&mut prefix[1..4]).await?;
            let header_length = usize::from(prefix[0] & 0x0f) * 4;
            let length = usize::from(u16::from_be_bytes([prefix[2], prefix[3]]));
            if header_length < 20 || length < header_length {
                return Err(Error::Protocol("invalid IPv4 packet length".into()));
            }
            length
        }
        6 => {
            reader.read_exact(&mut prefix[1..6]).await?;
            40 + usize::from(u16::from_be_bytes([prefix[4], prefix[5]]))
        }
        version => {
            return Err(Error::Protocol(format!(
                "unexpected IP version {version} on L3 stream"
            )));
        }
    };
    // Both arms are bounded by their u16 length fields: at most 65535 for
    // IPv4 and 40 + 65535 for IPv6.
    let prefix_length = if prefix[0] >> 4 == 4 { 4 } else { 6 };
    let mut packet = vec![0_u8; length];
    packet[..prefix_length].copy_from_slice(&prefix[..prefix_length]);
    reader.read_exact(&mut packet[prefix_length..]).await?;
    Ok(packet)
}

fn parse_server_session_id(records: &[u8]) -> Result<Vec<u8>, Error> {
    let mut offset = 0;
    let mut handshake = Vec::new();
    while offset + 5 <= records.len() {
        let record_type = records[offset];
        let length = usize::from(u16::from_be_bytes([
            records[offset + 3],
            records[offset + 4],
        ]));
        offset += 5;
        if offset + length > records.len() {
            break;
        }
        if record_type == 22 {
            handshake.extend_from_slice(&records[offset..offset + length]);
            while handshake.len() >= 4 {
                let message_length = (usize::from(handshake[1]) << 16)
                    | (usize::from(handshake[2]) << 8)
                    | usize::from(handshake[3]);
                if handshake.len() < 4 + message_length {
                    break;
                }
                if handshake[0] == 2 {
                    let body = &handshake[4..4 + message_length];
                    if body.len() < 35 {
                        return Err(Error::Protocol("truncated TLS ServerHello".into()));
                    }
                    let session_length = usize::from(body[34]);
                    if body.len() < 35 + session_length {
                        return Err(Error::Protocol(
                            "truncated TLS ServerHello session ID".into(),
                        ));
                    }
                    return Ok(body[35..35 + session_length].to_vec());
                }
                handshake.drain(..4 + message_length);
            }
        }
        offset += length;
    }
    Err(Error::Protocol(
        "TLS ServerHello session ID was not captured".into(),
    ))
}

struct CaptureIo {
    inner: TcpStream,
    received: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for CaptureIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let previous = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if let std::task::Poll::Ready(Ok(())) = &result {
            let added = &buffer.filled()[previous..];
            if !added.is_empty() {
                if let Ok(mut received) = self.received.lock() {
                    received.extend_from_slice(added);
                }
            }
        }
        result
    }
}

impl AsyncWrite for CaptureIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_session_id_from_fragmented_record_capture() {
        let session = [0x42; 32];
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.push(u8::try_from(session.len()).unwrap());
        body.extend_from_slice(&session);
        body.extend_from_slice(&[0x13, 0x01, 0]);
        let mut message = vec![2, 0, 0, u8::try_from(body.len()).unwrap()];
        message.extend_from_slice(&body);
        let split = 20;
        let mut records = Vec::new();
        for fragment in [&message[..split], &message[split..]] {
            records.extend_from_slice(&[22, 3, 3]);
            records.extend_from_slice(&u16::try_from(fragment.len()).unwrap().to_be_bytes());
            records.extend_from_slice(fragment);
        }
        assert_eq!(parse_server_session_id(&records).unwrap(), session);
    }

    #[tokio::test]
    async fn packet_reader_preserves_boundaries() {
        let mut ipv4 = vec![0_u8; 24];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&24_u16.to_be_bytes());
        let mut ipv6 = vec![0_u8; 44];
        ipv6[0] = 0x60;
        ipv6[4..6].copy_from_slice(&4_u16.to_be_bytes());
        let (mut writer, mut reader) = tokio::io::duplex(128);
        writer
            .write_all(&[ipv4.clone(), ipv6.clone()].concat())
            .await
            .unwrap();
        assert_eq!(read_ip_packet(&mut reader).await.unwrap(), ipv4);
        assert_eq!(read_ip_packet(&mut reader).await.unwrap(), ipv6);
    }
}
