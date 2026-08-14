use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use async_trait::async_trait;
use hmac::{Hmac, Mac as _};
use native_tls::TlsConnector as NativeTlsConnector;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    net::TcpStream,
    sync::mpsc,
};
use tokio_native_tls::{TlsConnector, TlsStream};

use crate::{
    ChallengeHandler, ConnectionInfo, Error, L3Stream, VpnClient, resource::ProtocolMatch,
};

use super::{AtrustClient, split_endpoint};

const VERSION: u8 = 0x05;
const AUTH_REQUEST: u8 = 0x13;
const AUTH_RESPONSE: u8 = 0x93;
const DATA_REQUEST: u8 = 0x14;
const DATA_RESPONSE: u8 = 0x94;
const HEARTBEAT_REQUEST: u8 = 0x15;
const HEARTBEAT_RESPONSE: u8 = 0x95;
const SECOND_VIP_RESPONSE: u8 = 0x96;
const MAX_PENDING_PACKETS: usize = 64;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const MAX_HEARTBEAT_MISSES: u32 = 3;
const NODE_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const NODE_RETRY_COOLDOWN: Duration = Duration::from_secs(3);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const FLOW_AUTH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct L3Settings {
    sid: String,
    device_id: String,
    connection_id: String,
    sign_key: Vec<u8>,
    expected_vip: Option<IpAddr>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    protocol: u8,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
}

#[derive(Clone, Debug)]
struct PacketMeta {
    key: FlowKey,
}

struct Flow {
    auth_id: u64,
    token: Option<String>,
    pending: Vec<Vec<u8>>,
    last_activity: tokio::time::Instant,
}

struct PacketCommand {
    packet: Vec<u8>,
    meta: PacketMeta,
    app_id: String,
}

struct NodeHandle {
    commands: mpsc::Sender<PacketCommand>,
}

enum Frame {
    Data(Vec<u8>),
    Authentication { status: u8, payload: Vec<u8> },
    VipUpdate { status: u8, payload: Vec<u8> },
    Heartbeat,
    Other,
}

impl AtrustClient {
    /// Open the aTrust packet tunnel after control-plane setup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotConnected`] until [`Self::connect_control_plane`] succeeds,
    /// or a configuration error when the connection signing key is malformed.
    pub fn open_l3_stream(&self) -> Result<L3Stream, Error> {
        let parsed = self.parsed.clone().ok_or(Error::NotConnected)?;
        let settings = L3Settings {
            sid: self.sid.clone().ok_or(Error::NotConnected)?,
            device_id: self.device_id.clone(),
            connection_id: self.connection_id.clone(),
            sign_key: hex::decode(&self.sign_key)
                .map_err(|error| Error::Config(format!("invalid aTrust sign key: {error}")))?,
            expected_vip: self.client_ip,
        };
        let best_nodes = self.best_nodes.clone();
        let (application, bridge) = tokio::io::duplex(256 * 1024);
        tokio::spawn(async move {
            if let Err(error) = run_l3(bridge, parsed, best_nodes, settings).await {
                tracing::warn!(%error, "aTrust L3 tunnel stopped");
            }
        });
        Ok(Box::pin(application))
    }
}

#[async_trait]
impl VpnClient for AtrustClient {
    async fn connect(
        &mut self,
        challenges: &dyn ChallengeHandler,
    ) -> Result<ConnectionInfo, Error> {
        self.connect_control_plane(challenges).await
    }

    async fn open_l3(&self) -> Result<L3Stream, Error> {
        self.open_l3_stream()
    }

    async fn close(&mut self) -> Result<(), Error> {
        self.parsed = None;
        self.best_nodes.clear();
        self.client_ip = None;
        Ok(())
    }
}

async fn run_l3(
    bridge: DuplexStream,
    parsed: super::ParsedResources,
    best_nodes: std::collections::BTreeMap<String, String>,
    settings: L3Settings,
) -> Result<(), Error> {
    let (application_reader, mut application_writer) = tokio::io::split(bridge);
    let (incoming_sender, mut incoming_receiver) = mpsc::channel::<Vec<u8>>(4096);
    let (outbound_sender, mut outbound_receiver) = mpsc::channel::<Vec<u8>>(256);
    let mut nodes = HashMap::<String, NodeHandle>::new();
    let mut node_failures = HashMap::<String, tokio::time::Instant>::new();

    // A dedicated task owns the multi-read packet framing so this loop only
    // races cancellation-safe channel reads.
    let reader = tokio::spawn(read_outbound_packets(application_reader, outbound_sender));

    let result = loop {
        tokio::select! {
            outbound = outbound_receiver.recv() => {
                let Some(packet) = outbound else {
                    break Ok(());
                };
                forward_outbound_packet(
                    packet,
                    &parsed,
                    &best_nodes,
                    &settings,
                    &incoming_sender,
                    &mut nodes,
                    &mut node_failures,
                ).await;
            }
            incoming = incoming_receiver.recv() => {
                let Some(packet) = incoming else {
                    break Ok(());
                };
                if application_writer.write_all(&packet).await.is_err()
                    || application_writer.flush().await.is_err()
                {
                    break Ok(());
                }
            }
        }
    };
    reader.abort();
    result
}

async fn read_outbound_packets(
    mut reader: tokio::io::ReadHalf<DuplexStream>,
    packets: mpsc::Sender<Vec<u8>>,
) {
    loop {
        match read_ip_packet(&mut reader).await {
            Ok(packet) => {
                if packets.send(packet).await.is_err() {
                    return;
                }
            }
            Err(error) => {
                tracing::debug!(%error, "aTrust L3 outbound stream ended");
                return;
            }
        }
    }
}

/// Route one TUN packet to its node connection. Per-packet problems drop the
/// packet — IP is lossy by contract — and must never take the tunnel down.
async fn forward_outbound_packet(
    packet: Vec<u8>,
    parsed: &super::ParsedResources,
    best_nodes: &std::collections::BTreeMap<String, String>,
    settings: &L3Settings,
    incoming_sender: &mpsc::Sender<Vec<u8>>,
    nodes: &mut HashMap<String, NodeHandle>,
    node_failures: &mut HashMap<String, tokio::time::Instant>,
) {
    let meta = match parse_packet_meta(&packet) {
        Ok(meta) => meta,
        Err(error) => {
            tracing::trace!(%error, "dropping unsupported TUN packet");
            return;
        }
    };
    let Ok(protocol) = protocol_match(meta.key.protocol) else {
        tracing::trace!(protocol = meta.key.protocol, "dropping unsupported IP protocol");
        return;
    };
    let resource = parsed.resources.ip.iter().rev().find(|resource| {
        resource.matches(
            IpAddr::V4(meta.key.destination),
            meta.key.destination_port,
            protocol,
        )
    });
    let Some(resource) = resource else {
        tracing::debug!(
            destination = %meta.key.destination,
            port = meta.key.destination_port,
            "dropping packet with no matching aTrust resource"
        );
        return;
    };
    let Some(app_id) = resource.app_id.clone() else {
        tracing::debug!(destination = %meta.key.destination, "aTrust resource has no app ID");
        return;
    };
    let group = resource.node_group_id.clone().unwrap_or_default();

    if !nodes.contains_key(&group) {
        if node_failures
            .get(&group)
            .is_some_and(|failed| failed.elapsed() < NODE_RETRY_COOLDOWN)
        {
            return;
        }
        let endpoint = best_nodes
            .get(&group)
            .or_else(|| best_nodes.get(&parsed.major_node_group));
        let Some(endpoint) = endpoint else {
            tracing::debug!(group, "no reachable aTrust node for packet");
            return;
        };
        let opened = tokio::time::timeout(
            NODE_OPEN_TIMEOUT,
            open_node(endpoint, settings.clone(), incoming_sender.clone()),
        )
        .await;
        match opened {
            Ok(Ok(handle)) => {
                nodes.insert(group.clone(), handle);
                node_failures.remove(&group);
            }
            Ok(Err(error)) => {
                tracing::warn!(%error, group, "failed to open aTrust node connection");
                node_failures.insert(group, tokio::time::Instant::now());
                return;
            }
            Err(_) => {
                tracing::warn!(group, "timed out opening aTrust node connection");
                node_failures.insert(group, tokio::time::Instant::now());
                return;
            }
        }
    }

    let handle = nodes.get(&group).expect("node was just ensured");
    match handle.commands.try_send(PacketCommand { packet, meta, app_id }) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::trace!(group, "dropping packet: node queue is full");
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!(group, "aTrust node connection closed; scheduling reconnect");
            nodes.remove(&group);
            node_failures.insert(group, tokio::time::Instant::now());
        }
    }
}

async fn open_node(
    endpoint: &str,
    settings: L3Settings,
    incoming: mpsc::Sender<Vec<u8>>,
) -> Result<NodeHandle, Error> {
    let mut tls = connect_tls(endpoint).await?;
    let negotiated = authenticate_tunnel(&mut tls, &settings.sid).await?;
    report_negotiated_vips(&negotiated, settings.expected_vip);
    let (sender, receiver) = mpsc::channel(1024);
    tokio::spawn(async move {
        if let Err(error) = node_loop(tls, settings, receiver, incoming).await {
            tracing::warn!(%error, "aTrust L3 node connection closed; traffic will reconnect");
        }
    });
    Ok(NodeHandle { commands: sender })
}

async fn connect_tls(endpoint: &str) -> Result<TlsStream<TcpStream>, Error> {
    let (host, _) = split_endpoint(endpoint)?;
    let tcp = TcpStream::connect(endpoint).await?;
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
}

async fn authenticate_tunnel<S>(tls: &mut S, sid: &str) -> Result<Vec<IpAddr>, Error>
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let json = serde_json::to_vec(&serde_json::json!({"sid": sid}))
        .map_err(|error| Error::Protocol(format!("cannot encode aTrust sid: {error}")))?;
    let length =
        u16::try_from(json.len()).map_err(|_| Error::Protocol("aTrust sid is too large".into()))?;
    let mut request = vec![VERSION, 0x01, 0xd0, 0x53, 0x00];
    request.extend_from_slice(&length.to_be_bytes());
    request.extend_from_slice(&json);
    request.extend_from_slice(&[VERSION, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    tls.write_all(&request).await?;

    let mut method = [0_u8; 2];
    tls.read_exact(&mut method).await?;
    if method != [VERSION, 0xd0] {
        return Err(Error::Protocol(format!(
            "unexpected aTrust L3 authentication method: {}",
            hex::encode(method)
        )));
    }
    let mut header = [0_u8; 4];
    tls.read_exact(&mut header).await?;
    if header[0] != 0x53 || header[1] != 0 {
        return Err(Error::Authentication(format!(
            "aTrust L3 authentication failed with status {}",
            header[1]
        )));
    }
    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let mut response = vec![0_u8; length];
    tls.read_exact(&mut response).await?;
    if !response.is_empty() {
        let response: ApiStatus = serde_json::from_slice(&response).map_err(|error| {
            Error::Protocol(format!(
                "invalid aTrust L3 authentication response: {error}"
            ))
        })?;
        if response.code != 0 {
            return Err(Error::Authentication(format!(
                "aTrust L3 authentication failed with code {}: {}",
                response.code, response.message
            )));
        }
    }

    let mut vip_header = [0_u8; 4];
    tls.read_exact(&mut vip_header).await?;
    let vip_length = match vip_header {
        [VERSION, 0, 0, 1] => 6,
        [VERSION, 0, 0, 4] => 18,
        [VERSION, 0, 0, 5] => 22,
        _ => {
            return Err(Error::Protocol(format!(
                "unexpected aTrust L3 virtual-IP header: {}",
                hex::encode(vip_header)
            )));
        }
    };
    let mut vip = vec![0_u8; vip_length];
    tls.read_exact(&mut vip).await?;
    Ok(parse_virtual_ip_data(&vip))
}

fn parse_virtual_ip_data(data: &[u8]) -> Vec<IpAddr> {
    match data.len() {
        6 => vec![Ipv4Addr::new(data[0], data[1], data[2], data[3]).into()],
        18 => vec![ipv6_from(&data[..16])],
        22 => vec![
            Ipv4Addr::new(data[0], data[1], data[2], data[3]).into(),
            ipv6_from(&data[4..20]),
        ],
        _ => Vec::new(),
    }
}

fn ipv6_from(bytes: &[u8]) -> IpAddr {
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(bytes);
    std::net::Ipv6Addr::from(octets).into()
}

fn report_negotiated_vips(negotiated: &[IpAddr], expected: Option<IpAddr>) {
    let Some(expected) = expected else { return };
    if negotiated.is_empty() || negotiated.contains(&expected) {
        return;
    }
    // The TUN keeps the address from the initial negotiation; a different
    // per-node lease means the gateway may drop packets sourced from it.
    tracing::warn!(
        %expected,
        ?negotiated,
        "aTrust node negotiated a different virtual IP than the TUN uses"
    );
}

fn handle_vip_update(status: u8, payload: &[u8], expected: Option<IpAddr>) {
    if status != 0 {
        tracing::debug!(status, "aTrust virtual-IP update carried an error status");
        return;
    }
    report_negotiated_vips(&extract_vips(payload), expected);
}

fn extract_vips(payload: &[u8]) -> Vec<IpAddr> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return Vec::new();
    };
    let vip_at = |object: &serde_json::Value, key: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(|text| text.parse::<IpAddr>().ok())
    };
    let object = if vip_at(&value, "vip").is_some() || vip_at(&value, "vip6").is_some() {
        value.clone()
    } else {
        value.get("data").cloned().unwrap_or(value)
    };
    let mut addresses = Vec::new();
    if let Some(IpAddr::V4(address)) = vip_at(&object, "vip") {
        addresses.push(IpAddr::V4(address));
    }
    if let Some(IpAddr::V6(address)) = vip_at(&object, "vip6") {
        addresses.push(IpAddr::V6(address));
    }
    addresses
}

async fn node_loop<S>(
    tls: S,
    settings: L3Settings,
    mut commands: mpsc::Receiver<PacketCommand>,
    incoming: mpsc::Sender<Vec<u8>>,
) -> Result<(), Error>
where
    S: AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (read_half, mut write) = tokio::io::split(tls);
    // A dedicated task owns the multi-read frame parser; dropping a partially
    // completed read_frame future here would desync the wire stream.
    let (frame_sender, mut frames) = mpsc::channel::<Result<Frame, Error>>(64);
    let reader = tokio::spawn(async move {
        let mut read_half = read_half;
        loop {
            let frame = read_frame(&mut read_half).await;
            let failed = frame.is_err();
            if frame_sender.send(frame).await.is_err() || failed {
                return;
            }
        }
    });

    let mut flows = HashMap::<FlowKey, Flow>::new();
    let mut auth_flows = HashMap::<u64, FlowKey>::new();
    let mut next_auth_id = 0_u64;
    let mut incoming_bytes = Vec::new();
    let mut outstanding_heartbeats = 0_u32;
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;

    let result = loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    break Ok(());
                };
                if let Err(error) = process_command(
                    &mut write,
                    &settings,
                    command,
                    &mut flows,
                    &mut auth_flows,
                    &mut next_auth_id,
                ).await {
                    break Err(error);
                }
            }
            frame = frames.recv() => {
                let Some(frame) = frame else {
                    break Err(Error::Protocol("aTrust node reader stopped".into()));
                };
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(error) => break Err(error),
                };
                match frame {
                    Frame::Data(data) => {
                        incoming_bytes.extend_from_slice(&data);
                        match deliver_complete_packets(&mut incoming_bytes, &incoming).await {
                            Ok(true) => {}
                            Ok(false) => break Ok(()),
                            Err(error) => break Err(error),
                        }
                    }
                    Frame::Authentication { status, payload } => {
                        if let Err(error) = process_authentication_response(
                            &mut write,
                            status,
                            &payload,
                            &mut flows,
                            &mut auth_flows,
                        ).await {
                            break Err(error);
                        }
                    }
                    Frame::VipUpdate { status, payload } => {
                        handle_vip_update(status, &payload, settings.expected_vip);
                    }
                    Frame::Heartbeat => {
                        outstanding_heartbeats = 0;
                    }
                    Frame::Other => {}
                }
            }
            _ = heartbeat.tick() => {
                if outstanding_heartbeats >= MAX_HEARTBEAT_MISSES {
                    break Err(Error::Protocol(
                        "aTrust node stopped answering heartbeats".into(),
                    ));
                }
                if let Err(error) =
                    write_with_timeout(&mut write, &[VERSION, HEARTBEAT_REQUEST, 0, 0]).await
                {
                    break Err(error);
                }
                outstanding_heartbeats += 1;
                evict_stale_flows(&mut flows, &mut auth_flows);
            }
        }
    };
    reader.abort();
    result
}

/// Forward every complete packet in `incoming_bytes`; returns `Ok(false)`
/// when the receiving side has shut down.
async fn deliver_complete_packets(
    incoming_bytes: &mut Vec<u8>,
    incoming: &mpsc::Sender<Vec<u8>>,
) -> Result<bool, Error> {
    for packet in take_complete_packets(incoming_bytes)? {
        if incoming.send(packet).await.is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn evict_stale_flows(flows: &mut HashMap<FlowKey, Flow>, auth_flows: &mut HashMap<u64, FlowKey>) {
    flows.retain(|key, flow| {
        let timeout = if flow.token.is_some() {
            FLOW_IDLE_TIMEOUT
        } else {
            FLOW_AUTH_TIMEOUT
        };
        let keep = flow.last_activity.elapsed() < timeout;
        if !keep {
            tracing::trace!(?key, "evicting idle aTrust flow");
            auth_flows.remove(&flow.auth_id);
        }
        keep
    });
}

async fn write_with_timeout<W>(write: &mut W, data: &[u8]) -> Result<(), Error>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(WRITE_TIMEOUT, write.write_all(data))
        .await
        .map_err(|_| Error::Protocol("aTrust node write timed out".into()))??;
    Ok(())
}

async fn process_command<W>(
    tls: &mut W,
    settings: &L3Settings,
    command: PacketCommand,
    flows: &mut HashMap<FlowKey, Flow>,
    auth_flows: &mut HashMap<u64, FlowKey>,
    next_auth_id: &mut u64,
) -> Result<(), Error>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if let Some(flow) = flows.get_mut(&command.meta.key) {
        flow.last_activity = tokio::time::Instant::now();
        if let Some(token) = flow.token.clone() {
            return write_data_packet(tls, &token, &command.packet).await;
        }
        if flow.pending.len() < MAX_PENDING_PACKETS {
            flow.pending.push(command.packet);
        }
        return Ok(());
    }

    *next_auth_id = next_auth_id.wrapping_add(1).max(1);
    let auth_id = *next_auth_id;
    let request = match build_flow_authentication(settings, &command.meta, &command.app_id, auth_id)
    {
        Ok(request) => request,
        Err(error) => {
            tracing::warn!(%error, "cannot build aTrust flow authorization");
            return Ok(());
        }
    };
    let Ok(length) = u16::try_from(request.len()) else {
        tracing::warn!("aTrust flow authorization is too large");
        return Ok(());
    };
    let mut frame = vec![VERSION, AUTH_REQUEST];
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&request);
    write_with_timeout(tls, &frame).await?;
    auth_flows.insert(auth_id, command.meta.key.clone());
    flows.insert(
        command.meta.key,
        Flow {
            auth_id,
            token: None,
            pending: vec![command.packet],
            last_activity: tokio::time::Instant::now(),
        },
    );
    Ok(())
}

/// Handle one flow-authorization reply. A rejected or malformed authorization
/// affects only its flow — the entry is dropped so the next packet retries —
/// and only connection-level write failures are propagated.
async fn process_authentication_response<W>(
    tls: &mut W,
    status: u8,
    payload: &[u8],
    flows: &mut HashMap<FlowKey, Flow>,
    auth_flows: &mut HashMap<u64, FlowKey>,
) -> Result<(), Error>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let response: FlowAuthResponse = match serde_json::from_slice(payload) {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "ignoring malformed aTrust flow authorization response");
            return Ok(());
        }
    };
    let auth_id = response.data.conntrack_hash;
    let Some(key) = auth_flows.remove(&auth_id) else {
        tracing::debug!(auth_id, "ignoring unknown aTrust flow authorization");
        return Ok(());
    };
    if status != 0 || response.code != 0 {
        flows.remove(&key);
        tracing::warn!(
            destination = %key.destination,
            port = key.destination_port,
            status,
            code = response.code,
            message = %response.message,
            "aTrust flow authorization rejected; the flow will retry on new traffic"
        );
        return Ok(());
    }
    let token = if response.data.connect_token.is_empty() {
        response.data.token
    } else {
        response.data.connect_token
    };
    if token.is_empty() {
        flows.remove(&key);
        tracing::warn!(
            destination = %key.destination,
            "aTrust flow authorization returned no connection token"
        );
        return Ok(());
    }
    let Some(flow) = flows.get_mut(&key) else {
        return Ok(());
    };
    if flow.auth_id != auth_id {
        tracing::debug!(auth_id, "ignoring superseded aTrust flow authorization");
        return Ok(());
    }
    for packet in &flow.pending {
        write_data_packet(tls, &token, packet).await?;
    }
    flow.pending.clear();
    flow.token = Some(token);
    flow.last_activity = tokio::time::Instant::now();
    Ok(())
}

async fn write_data_packet<W>(tls: &mut W, token: &str, packet: &[u8]) -> Result<(), Error>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let token_length = u8::try_from(token.len())
        .map_err(|_| Error::Protocol("aTrust flow token is too large".into()))?;
    let packet_length = u16::try_from(packet.len())
        .map_err(|_| Error::Protocol("IP packet is too large".into()))?;
    let mut frame = Vec::with_capacity(8 + token.len() + packet.len());
    frame.extend_from_slice(&[VERSION, DATA_REQUEST, token_length]);
    frame.extend_from_slice(token.as_bytes());
    frame.extend_from_slice(&[0, 0, 1]);
    frame.extend_from_slice(&packet_length.to_be_bytes());
    frame.extend_from_slice(packet);
    write_with_timeout(tls, &frame).await
}

async fn read_frame<R>(tls: &mut R) -> Result<Frame, Error>
where
    R: AsyncRead + Unpin,
{
    loop {
        let mut header = [0_u8; 2];
        tls.read_exact(&mut header).await?;
        if header == [0x53, 0x00] {
            let length = tls.read_u16().await?;
            let mut ignored = vec![0_u8; usize::from(length)];
            tls.read_exact(&mut ignored).await?;
            continue;
        }
        if header[0] != VERSION {
            return Err(Error::Protocol(format!(
                "unexpected aTrust L3 frame: {}",
                hex::encode(header)
            )));
        }
        return match header[1] {
            AUTH_RESPONSE | SECOND_VIP_RESPONSE => {
                let status = tls.read_u8().await?;
                let length = tls.read_u16().await?;
                let mut payload = vec![0_u8; usize::from(length)];
                tls.read_exact(&mut payload).await?;
                if header[1] == AUTH_RESPONSE {
                    Ok(Frame::Authentication { status, payload })
                } else {
                    Ok(Frame::VipUpdate { status, payload })
                }
            }
            DATA_RESPONSE => {
                let length = tls.read_u16().await?;
                let mut payload = vec![0_u8; usize::from(length)];
                tls.read_exact(&mut payload).await?;
                Ok(Frame::Data(payload))
            }
            HEARTBEAT_RESPONSE => {
                let length = tls.read_u16().await?;
                let mut payload = vec![0_u8; usize::from(length)];
                tls.read_exact(&mut payload).await?;
                Ok(Frame::Heartbeat)
            }
            _ => {
                let length = tls.read_u16().await?;
                let mut payload = vec![0_u8; usize::from(length)];
                tls.read_exact(&mut payload).await?;
                Ok(Frame::Other)
            }
        };
    }
}

fn build_flow_authentication(
    settings: &L3Settings,
    meta: &PacketMeta,
    app_id: &str,
    auth_id: u64,
) -> Result<Vec<u8>, Error> {
    let process_path = "/usr/bin/zju-connect";
    let fingerprint = hex::encode_upper(Sha256::digest(process_path.as_bytes()));
    let process = ProcessEnvironment {
        name: "zju-connect",
        digital_signature: "TrustAppClosed",
        platform: "Linux",
        fingerprint: &fingerprint,
        description: "TrustAppClosed",
        path: process_path,
        version: "TrustAppClosed",
        security_env: "normal",
    };
    let protocol = protocol_name(meta.key.protocol);
    let mut request = FlowAuthRequest {
        sid: &settings.sid,
        app_id,
        url: format!(
            "{protocol}:{}:{}",
            meta.key.destination, meta.key.destination_port
        ),
        device_id: &settings.device_id,
        connection_id: &settings.connection_id,
        env: TrustEnvironment {
            application: ApplicationEnvironment {
                runtime: RuntimeEnvironment {
                    process,
                    process_trusted: "TRUSTED",
                },
            },
        },
        conntrack_hash: auth_id,
        lang: "en-US",
        ip: FlowIp {
            atype: 0x0800,
            protocol: meta.key.protocol,
            dest_addr: meta.key.destination,
            dest_port: meta.key.destination_port,
            src_addr: meta.key.source,
            src_port: meta.key.source_port,
        },
        proc_hash: &fingerprint,
        x_request_sig: String::new(),
    };
    let unsigned = serde_json::to_vec(&request)
        .map_err(|error| Error::Protocol(format!("cannot encode aTrust flow: {error}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&settings.sign_key)
        .map_err(|error| Error::Config(format!("invalid aTrust sign key: {error}")))?;
    mac.update(&unsigned);
    request.x_request_sig = hex::encode_upper(mac.finalize().into_bytes());
    serde_json::to_vec(&request)
        .map_err(|error| Error::Protocol(format!("cannot encode aTrust flow: {error}")))
}

fn parse_packet_meta(packet: &[u8]) -> Result<PacketMeta, Error> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return Err(Error::Protocol(
            "aTrust L3 currently requires a complete IPv4 packet".into(),
        ));
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_length < 20 || total_length != packet.len() || packet.len() < header_length {
        return Err(Error::Protocol("invalid IPv4 packet length".into()));
    }
    let protocol = packet[9];
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let (source_port, destination_port) = match protocol {
        1 => (0, 0),
        6 | 17 if packet.len() >= header_length + 4 => (
            u16::from_be_bytes([packet[header_length], packet[header_length + 1]]),
            u16::from_be_bytes([packet[header_length + 2], packet[header_length + 3]]),
        ),
        6 | 17 => {
            return Err(Error::Protocol(
                "truncated TCP/UDP header in IPv4 packet".into(),
            ));
        }
        value => {
            return Err(Error::Protocol(format!(
                "unsupported aTrust IP protocol {value}"
            )));
        }
    };
    Ok(PacketMeta {
        key: FlowKey {
            protocol,
            source,
            destination,
            source_port,
            destination_port,
        },
    })
}

fn protocol_match(protocol: u8) -> Result<ProtocolMatch, Error> {
    match protocol {
        1 => Ok(ProtocolMatch::Icmp),
        6 => Ok(ProtocolMatch::Tcp),
        17 => Ok(ProtocolMatch::Udp),
        value => Err(Error::Protocol(format!(
            "unsupported aTrust IP protocol {value}"
        ))),
    }
}

fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "ip",
    }
}

async fn read_ip_packet(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, Error> {
    let mut prefix = [0_u8; 6];
    reader.read_exact(&mut prefix[..1]).await?;
    let (prefix_length, length) = match prefix[0] >> 4 {
        4 => {
            reader.read_exact(&mut prefix[1..4]).await?;
            let header_length = usize::from(prefix[0] & 0x0f) * 4;
            let length = usize::from(u16::from_be_bytes([prefix[2], prefix[3]]));
            if header_length < 20 || length < header_length {
                return Err(Error::Protocol("invalid IPv4 packet length".into()));
            }
            (4, length)
        }
        6 => {
            reader.read_exact(&mut prefix[1..6]).await?;
            (
                6,
                40 + usize::from(u16::from_be_bytes([prefix[4], prefix[5]])),
            )
        }
        version => {
            return Err(Error::Protocol(format!(
                "unexpected IP version {version} on aTrust L3 stream"
            )));
        }
    };
    let mut packet = vec![0_u8; length];
    packet[..prefix_length].copy_from_slice(&prefix[..prefix_length]);
    reader.read_exact(&mut packet[prefix_length..]).await?;
    Ok(packet)
}

fn take_complete_packets(stream: &mut Vec<u8>) -> Result<Vec<Vec<u8>>, Error> {
    let mut packets = Vec::new();
    let mut consumed = 0;
    while consumed < stream.len() {
        let remaining = &stream[consumed..];
        let Some(first) = remaining.first() else {
            break;
        };
        let length = match first >> 4 {
            4 if remaining.len() >= 4 => {
                let header_length = usize::from(first & 0x0f) * 4;
                let length = usize::from(u16::from_be_bytes([remaining[2], remaining[3]]));
                if header_length < 20 || length < header_length {
                    return Err(Error::Protocol("invalid incoming IPv4 packet".into()));
                }
                length
            }
            6 if remaining.len() >= 6 => {
                40 + usize::from(u16::from_be_bytes([remaining[4], remaining[5]]))
            }
            4 | 6 => break,
            version => {
                return Err(Error::Protocol(format!(
                    "unexpected incoming IP version {version}"
                )));
            }
        };
        if remaining.len() < length {
            break;
        }
        packets.push(remaining[..length].to_vec());
        consumed += length;
    }
    stream.drain(..consumed);
    Ok(packets)
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ApiStatus {
    code: i64,
    message: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FlowAuthResponse {
    code: i64,
    message: String,
    data: FlowAuthResponseData,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct FlowAuthResponseData {
    conntrack_hash: u64,
    connect_token: String,
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FlowAuthRequest<'a> {
    sid: &'a str,
    #[serde(rename = "appId")]
    app_id: &'a str,
    url: String,
    #[serde(rename = "deviceId")]
    device_id: &'a str,
    #[serde(rename = "connectionId")]
    connection_id: &'a str,
    env: TrustEnvironment<'a>,
    conntrack_hash: u64,
    lang: &'static str,
    ip: FlowIp,
    #[serde(rename = "procHash")]
    proc_hash: &'a str,
    #[serde(rename = "xRequestSig")]
    x_request_sig: String,
}

#[derive(Serialize)]
struct FlowIp {
    atype: u16,
    protocol: u8,
    #[serde(rename = "destAddr")]
    dest_addr: Ipv4Addr,
    #[serde(rename = "destPort")]
    dest_port: u16,
    #[serde(rename = "srcAddr")]
    src_addr: Ipv4Addr,
    #[serde(rename = "srcPort")]
    src_port: u16,
}

#[derive(Serialize)]
struct TrustEnvironment<'a> {
    application: ApplicationEnvironment<'a>,
}

#[derive(Serialize)]
struct ApplicationEnvironment<'a> {
    runtime: RuntimeEnvironment<'a>,
}

#[derive(Serialize)]
struct RuntimeEnvironment<'a> {
    process: ProcessEnvironment<'a>,
    process_trusted: &'static str,
}

#[derive(Serialize)]
struct ProcessEnvironment<'a> {
    name: &'static str,
    digital_signature: &'static str,
    platform: &'static str,
    fingerprint: &'a str,
    description: &'static str,
    path: &'static str,
    version: &'static str,
    security_env: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_virtual_ip_payload_shapes() {
        assert_eq!(
            parse_virtual_ip_data(&[10, 0, 0, 7, 0, 0]),
            vec![IpAddr::from([10, 0, 0, 7])]
        );
        let mut dual = vec![10, 0, 0, 7];
        dual.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        dual.extend_from_slice(&[0, 0]);
        assert_eq!(
            parse_virtual_ip_data(&dual),
            vec![
                IpAddr::from([10, 0, 0, 7]),
                "2001:db8::1".parse::<IpAddr>().unwrap(),
            ]
        );
        assert!(parse_virtual_ip_data(&[1, 2, 3]).is_empty());
    }

    #[test]
    fn extracts_vip_updates_from_flat_and_nested_json() {
        assert_eq!(
            extract_vips(br#"{"vip":"10.0.0.9"}"#),
            vec![IpAddr::from([10, 0, 0, 9])]
        );
        assert_eq!(
            extract_vips(br#"{"data":{"vip":"10.0.0.9","vip6":"2001:db8::9"}}"#),
            vec![
                IpAddr::from([10, 0, 0, 9]),
                "2001:db8::9".parse::<IpAddr>().unwrap(),
            ]
        );
        assert!(extract_vips(b"not json").is_empty());
        assert!(extract_vips(br#"{"data":{"vip":""}}"#).is_empty());
    }

    async fn read_auth_request(gateway: &mut (impl AsyncRead + Unpin)) -> serde_json::Value {
        let mut header = [0_u8; 4];
        gateway.read_exact(&mut header).await.unwrap();
        assert_eq!(header[..2], [VERSION, AUTH_REQUEST]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut payload = vec![0_u8; length];
        gateway.read_exact(&mut payload).await.unwrap();
        serde_json::from_slice(&payload).unwrap()
    }

    #[tokio::test]
    async fn node_survives_rejected_flow_authorization() {
        let (gateway, node_side) = tokio::io::duplex(65536);
        let (mut gateway_read, mut gateway_write) = tokio::io::split(gateway);
        let settings = L3Settings {
            sid: "sid".into(),
            device_id: "device".into(),
            connection_id: "connection".into(),
            sign_key: vec![0xab; 32],
            expected_vip: None,
        };
        let (commands_sender, commands_receiver) = mpsc::channel(16);
        let (incoming_sender, mut incoming_receiver) = mpsc::channel(16);
        let node = tokio::spawn(node_loop(
            node_side,
            settings,
            commands_receiver,
            incoming_sender,
        ));

        let packet = ipv4_packet(6, 1000, 443);
        let meta = parse_packet_meta(&packet).unwrap();
        let command = || PacketCommand {
            packet: packet.clone(),
            meta: meta.clone(),
            app_id: "app".into(),
        };

        commands_sender.send(command()).await.unwrap();
        let first = read_auth_request(&mut gateway_read).await;
        assert_eq!(first["conntrackHash"], 1);

        // Reject the flow: the node must survive and drop only that flow.
        let rejection = br#"{"code":7,"message":"denied","data":{"conntrackHash":1}}"#;
        let mut frame = vec![VERSION, AUTH_RESPONSE, 0x01];
        frame.extend_from_slice(&u16::try_from(rejection.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(rejection);
        gateway_write.write_all(&frame).await.unwrap();

        // Frames are handled in order, so receiving this data packet proves
        // the rejection has been processed.
        let inbound = ipv4_packet(6, 443, 1000);
        let mut data_frame = vec![VERSION, DATA_RESPONSE];
        data_frame.extend_from_slice(&u16::try_from(inbound.len()).unwrap().to_be_bytes());
        data_frame.extend_from_slice(&inbound);
        gateway_write.write_all(&data_frame).await.unwrap();
        assert_eq!(incoming_receiver.recv().await.unwrap(), inbound);

        // The same 5-tuple retries with a fresh authorization on new traffic.
        commands_sender.send(command()).await.unwrap();
        let second = read_auth_request(&mut gateway_read).await;
        assert_eq!(second["conntrackHash"], 2);

        drop(commands_sender);
        node.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tunnel_stream_survives_unroutable_packets() {
        let parsed = super::super::ParsedResources::default();
        let settings = L3Settings {
            sid: "sid".into(),
            device_id: "device".into(),
            connection_id: "connection".into(),
            sign_key: vec![0xab; 32],
            expected_vip: None,
        };
        let (mut application, bridge) = tokio::io::duplex(65536);
        let tunnel = tokio::spawn(run_l3(
            bridge,
            parsed,
            std::collections::BTreeMap::new(),
            settings,
        ));

        // An IPv6 router solicitation (unsupported), an IGMP packet
        // (unsupported protocol), and an unmatched IPv4 packet must all be
        // dropped without stopping the tunnel.
        let mut ipv6 = vec![0x60, 0, 0, 0, 0, 8, 58, 255];
        ipv6.extend_from_slice(&[0_u8; 32]);
        ipv6.extend_from_slice(&[133, 0, 0, 0, 0, 0, 0, 0]);
        application.write_all(&ipv6).await.unwrap();
        application.write_all(&ipv4_packet(2, 0, 0)).await.unwrap();
        application
            .write_all(&ipv4_packet(6, 1000, 443))
            .await
            .unwrap();

        drop(application);
        tunnel.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tunnel_authentication_returns_negotiated_vip() {
        let (mut gateway, mut client) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            // Method echo, empty auth result, then a type-1 virtual IP.
            gateway.write_all(&[VERSION, 0xd0]).await.unwrap();
            gateway.write_all(&[0x53, 0x00, 0x00, 0x00]).await.unwrap();
            gateway
                .write_all(&[VERSION, 0, 0, 1, 10, 0, 0, 7, 0, 0])
                .await
                .unwrap();
        });
        let vips = authenticate_tunnel(&mut client, "sid").await.unwrap();
        assert_eq!(vips, vec![IpAddr::from([10, 0, 0, 7])]);
        server.await.unwrap();
    }

    fn ipv4_packet(protocol: u8, source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 24];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&24_u16.to_be_bytes());
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 3]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet
    }

    #[test]
    fn parses_ipv4_flow_metadata() {
        let meta = parse_packet_meta(&ipv4_packet(6, 12345, 443)).unwrap();
        assert_eq!(meta.key.protocol, 6);
        assert_eq!(meta.key.source, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(meta.key.destination, Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(meta.key.source_port, 12345);
        assert_eq!(meta.key.destination_port, 443);
    }

    #[test]
    fn splits_fragmented_incoming_packet_stream() {
        let packet = ipv4_packet(17, 2000, 53);
        let mut stream = packet[..10].to_vec();
        assert!(take_complete_packets(&mut stream).unwrap().is_empty());
        stream.extend_from_slice(&packet[10..]);
        stream.extend_from_slice(&packet);
        let packets = take_complete_packets(&mut stream).unwrap();
        assert_eq!(packets, [packet.clone(), packet]);
        assert!(stream.is_empty());
    }

    #[test]
    fn signs_flow_authorization() {
        let settings = L3Settings {
            sid: "sid".into(),
            device_id: "device".into(),
            connection_id: "connection".into(),
            sign_key: vec![0xab; 32],
            expected_vip: None,
        };
        let meta = parse_packet_meta(&ipv4_packet(6, 12345, 443)).unwrap();
        let encoded = build_flow_authentication(&settings, &meta, "app", 7).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["conntrackHash"], 7);
        assert_eq!(
            value["env"]["application"]["runtime"]["process"]["platform"],
            "Linux"
        );
        assert_eq!(value["xRequestSig"].as_str().unwrap().len(), 64);
    }
}
