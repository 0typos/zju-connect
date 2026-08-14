//! Operating-system TUN device integration.

use std::{net::Ipv4Addr, process::Stdio};

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
        tokio::select! {
            result = to_vpn => result,
            result = from_vpn => result,
            signal = tokio::signal::ctrl_c() => {
                signal?;
                Ok(())
            }
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
}
