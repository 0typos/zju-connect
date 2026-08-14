//! Operating-system TUN device integration.

use std::{
    net::{IpAddr, Ipv4Addr},
    process::Stdio,
};

use ipnet::IpNet;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tun::AbstractDevice as _;

use crate::{Error, L3Stream};

pub const DEFAULT_MTU: u16 = 1400;

#[derive(Clone, Debug)]
pub struct TunOptions {
    pub name: String,
    pub mtu: u16,
    pub routes: Vec<IpNet>,
    /// Gateway addresses to pin to the underlay so the tunnel's own transport
    /// is never routed back into the TUN.
    pub exclude: Vec<IpAddr>,
}

pub struct TunSession {
    device: tun::AsyncDevice,
    interface: String,
    mtu: u16,
}

impl Default for TunOptions {
    fn default() -> Self {
        Self {
            name: "zju-connect".into(),
            mtu: DEFAULT_MTU,
            routes: Vec::new(),
            exclude: Vec::new(),
        }
    }
}

/// Create a TUN device, install the requested routes, and forward packets until
/// the tunnel closes or the task is cancelled.
///
/// # Errors
///
/// Returns an error when the device cannot be configured, route installation
/// fails, or either packet stream fails.
pub async fn create(client_ip: Ipv4Addr, options: TunOptions) -> Result<TunSession, Error> {
    let mut configuration = tun::Configuration::default();
    configuration
        .tun_name(&options.name)
        .address(client_ip)
        .netmask((255, 255, 255, 255))
        .mtu(options.mtu)
        .up();
    configuration.platform_config(|platform| {
        platform.ensure_root_privileges(true);
    });

    let device = tun::create_as_async(&configuration)
        .map_err(|error| Error::Io(std::io::Error::other(error)))?;
    let interface = device
        .tun_name()
        .map_err(|error| Error::Io(std::io::Error::other(error)))?;
    // Pin the gateway path to the underlay before installing tunnel routes so
    // the outer VPN transport can never be captured by the TUN.
    for address in &options.exclude {
        exclude_route(*address).await;
    }
    for route in &options.routes {
        add_route(route, &interface).await?;
    }
    tracing::info!(interface, %client_ip, "TUN interface is ready");

    Ok(TunSession {
        device,
        interface,
        mtu: options.mtu,
    })
}

impl TunSession {
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Forward packets between this TUN device and a connected VPN L3 stream.
    ///
    /// # Errors
    ///
    /// Returns an I/O or invalid-packet error when either stream fails.
    pub async fn run(self, l3: L3Stream) -> Result<(), Error> {
        let Self { device, mtu, .. } = self;

        let (mut tun_writer, mut tun_reader) = device
            .split()
            .map_err(|error| Error::Io(std::io::Error::other(error)))?;
        let (mut vpn_reader, mut vpn_writer) = tokio::io::split(l3);
        let to_vpn = async {
            let mut packet = vec![0_u8; usize::from(mtu) + 64];
            loop {
                let length = tun_reader.read(&mut packet).await?;
                if length == 0 {
                    return Ok::<(), Error>(());
                }
                validate_ip_packet(&packet[..length])?;
                vpn_writer.write_all(&packet[..length]).await?;
                vpn_writer.flush().await?;
            }
        };
        let from_vpn = async {
            loop {
                let packet = read_ip_packet(&mut vpn_reader).await?;
                tun_writer.write_all(&packet).await?;
                tun_writer.flush().await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), Error>(())
        };
        // The caller owns shutdown (a global signal, or a per-connection
        // cancel in the daemon); this future ends only when a packet stream
        // fails. Dropping the returned future removes the interface and its
        // routes, so cancellation needs no cooperation here.
        tokio::select! {
            result = to_vpn => result,
            result = from_vpn => result,
        }
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
                "unexpected IP version {version} on L3 stream"
            )));
        }
    };
    let mut packet = vec![0_u8; length];
    packet[..prefix_length].copy_from_slice(&prefix[..prefix_length]);
    reader.read_exact(&mut packet[prefix_length..]).await?;
    Ok(packet)
}

fn validate_ip_packet(packet: &[u8]) -> Result<(), Error> {
    let valid = match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
        }
        Some(6) if packet.len() >= 40 => {
            40 + usize::from(u16::from_be_bytes([packet[4], packet[5]])) == packet.len()
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "TUN returned an invalid IP packet of {} bytes",
            packet.len()
        )))
    }
}

async fn add_route(route: &IpNet, interface: &str) -> Result<(), Error> {
    let output = tokio::process::Command::new("ip")
        .args(["route", "replace"])
        .arg(route.to_string())
        .args(["dev", interface])
        .stdin(Stdio::null())
        .output()
        .await?;
    route_result(&output, route)
}

/// Pin `address` to its current underlay path as a host route, so it is not
/// captured by the tunnel routes installed afterward. Best-effort: a failure
/// is logged rather than fatal, since the address may already be off-tunnel.
async fn exclude_route(address: IpAddr) {
    let Some((via, dev)) = underlay_path(address).await else {
        tracing::debug!(%address, "could not determine underlay path for gateway exclusion");
        return;
    };
    let mut command = tokio::process::Command::new("ip");
    command
        .args(["route", "replace"])
        .arg(format!("{address}/{}", host_prefix(address)));
    if let Some(via) = &via {
        command.args(["via", via]);
    }
    command.args(["dev", &dev]).stdin(Stdio::null());
    match command.output().await {
        Ok(output) if output.status.success() => {
            tracing::info!(%address, dev, "pinned gateway to the underlay interface");
        }
        Ok(output) => tracing::warn!(
            %address,
            error = %String::from_utf8_lossy(&output.stderr).trim(),
            "could not pin gateway route"
        ),
        Err(error) => tracing::warn!(%address, %error, "could not run ip route replace"),
    }
}

/// Query the kernel for the interface (and optional gateway) that currently
/// reaches `address`, before any tunnel route can shadow it.
async fn underlay_path(address: IpAddr) -> Option<(Option<String>, String)> {
    let output = tokio::process::Command::new("ip")
        .args(["route", "get"])
        .arg(address.to_string())
        .stdin(Stdio::null())
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let dev = tokens
        .iter()
        .position(|token| *token == "dev")
        .and_then(|index| tokens.get(index + 1))
        .map(|dev| (*dev).to_owned())?;
    let via = tokens
        .iter()
        .position(|token| *token == "via")
        .and_then(|index| tokens.get(index + 1))
        .map(|via| (*via).to_owned());
    Some((via, dev))
}

fn host_prefix(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn route_result(output: &std::process::Output, route: &IpNet) -> Result<(), Error> {
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::Io(std::io::Error::other(format!(
            "failed to install route {route}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_complete_packets() {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        assert!(validate_ip_packet(&packet).is_ok());
        packet.push(0);
        assert!(validate_ip_packet(&packet).is_err());
    }

    #[tokio::test]
    async fn reads_ip_packet_across_fragmented_reads() {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let expected = packet.clone();
        let sender = tokio::spawn(async move {
            for chunk in expected.chunks(7) {
                writer.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        assert_eq!(read_ip_packet(&mut reader).await.unwrap(), packet);
        sender.await.unwrap();
    }

    #[test]
    fn host_prefixes_match_family() {
        assert_eq!(host_prefix("10.0.0.1".parse().unwrap()), 32);
        assert_eq!(host_prefix("2001:db8::1".parse().unwrap()), 128);
    }
}
