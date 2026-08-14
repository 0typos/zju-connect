use std::{collections::BTreeMap, net::IpAddr, ops::RangeInclusive};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolMatch {
    All,
    Tcp,
    Udp,
    Icmp,
}

impl ProtocolMatch {
    pub fn matches(self, network: Self) -> bool {
        self == Self::All || self == network
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct IpResource {
    pub addresses: IpRange,
    pub ports: RangeInclusive<u16>,
    pub protocol: ProtocolMatch,
    pub app_id: Option<String>,
    pub node_group_id: Option<String>,
}

impl IpResource {
    pub fn matches(&self, address: IpAddr, port: u16, protocol: ProtocolMatch) -> bool {
        self.addresses.contains(address)
            && (protocol == ProtocolMatch::Icmp || self.ports.contains(&port))
            && self.protocol.matches(protocol)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum IpRange {
    Network(IpNet),
    Inclusive { first: IpAddr, last: IpAddr },
}

impl IpRange {
    pub fn contains(&self, address: IpAddr) -> bool {
        match self {
            Self::Network(network) => network.contains(&address),
            Self::Inclusive { first, last } => match (first, address, last) {
                (IpAddr::V4(first), IpAddr::V4(address), IpAddr::V4(last)) => {
                    first <= &address && &address <= last
                }
                (IpAddr::V6(first), IpAddr::V6(address), IpAddr::V6(last)) => {
                    first <= &address && &address <= last
                }
                _ => false,
            },
        }
    }

    pub fn networks(&self) -> Vec<IpNet> {
        match self {
            Self::Network(network) => vec![*network],
            Self::Inclusive {
                first: IpAddr::V4(first),
                last: IpAddr::V4(last),
            } => ipv4_range_networks(u32::from(*first), u32::from(*last)),
            Self::Inclusive {
                first: IpAddr::V6(first),
                last: IpAddr::V6(last),
            } => ipv6_range_networks(u128::from(*first), u128::from(*last)),
            Self::Inclusive { .. } => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct DomainResource {
    pub ports: RangeInclusive<u16>,
    pub protocol: ProtocolMatch,
    pub app_id: Option<String>,
    pub node_group_id: Option<String>,
}

impl DomainResource {
    pub fn matches(&self, port: u16, protocol: ProtocolMatch) -> bool {
        (protocol == ProtocolMatch::Icmp || self.ports.contains(&port))
            && self.protocol.matches(protocol)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Resources {
    pub ip: Vec<IpResource>,
    pub domains: BTreeMap<String, Vec<DomainResource>>,
    pub dns_records: BTreeMap<String, Vec<IpAddr>>,
    pub dns_servers: Vec<IpAddr>,
}

impl Resources {
    pub fn routed_networks(&self) -> Vec<IpNet> {
        let mut networks = self
            .ip
            .iter()
            .flat_map(|resource| resource.addresses.networks())
            .collect::<Vec<_>>();
        networks.sort_unstable_by_key(|network| (network.addr(), network.prefix_len()));
        networks.dedup();
        networks
    }
}

fn ipv4_range_networks(mut first: u32, last: u32) -> Vec<IpNet> {
    let mut networks = Vec::new();
    while first <= last {
        let alignment_bits = first.trailing_zeros();
        let remaining = u64::from(last) - u64::from(first) + 1;
        let size_bits = remaining.ilog2();
        let host_bits = alignment_bits.min(size_bits);
        let prefix = 32 - host_bits;
        networks.push(
            IpNet::new(
                IpAddr::V4(first.into()),
                u8::try_from(prefix).expect("IPv4 prefix fits in u8"),
            )
            .expect("computed IPv4 prefix"),
        );
        let increment = 1_u64 << host_bits;
        if u64::from(first) + increment > u64::from(u32::MAX) {
            break;
        }
        first = u32::try_from(u64::from(first) + increment).expect("range end was checked");
    }
    networks
}

fn ipv6_range_networks(mut first: u128, last: u128) -> Vec<IpNet> {
    let mut networks = Vec::new();
    while first <= last {
        let alignment_bits = first.trailing_zeros();
        let remaining = last - first;
        let size_bits = if remaining == u128::MAX {
            128
        } else {
            (remaining + 1).ilog2()
        };
        let host_bits = alignment_bits.min(size_bits);
        let prefix = 128 - host_bits;
        networks.push(
            IpNet::new(
                IpAddr::V6(first.into()),
                u8::try_from(prefix).expect("IPv6 prefix fits in u8"),
            )
            .expect("computed IPv6 prefix"),
        );
        let Some(increment) = 1_u128.checked_shl(host_bits) else {
            break;
        };
        let Some(next) = first.checked_add(increment) else {
            break;
        };
        first = next;
    }
    networks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_ipv4_ranges_to_minimal_networks() {
        let range = IpRange::Inclusive {
            first: "10.0.0.0".parse().unwrap(),
            last: "10.255.255.255".parse().unwrap(),
        };
        assert_eq!(range.networks(), vec!["10.0.0.0/8".parse().unwrap()]);

        let uneven = IpRange::Inclusive {
            first: "192.0.2.1".parse().unwrap(),
            last: "192.0.2.6".parse().unwrap(),
        };
        assert_eq!(
            uneven.networks(),
            [
                "192.0.2.1/32".parse().unwrap(),
                "192.0.2.2/31".parse().unwrap(),
                "192.0.2.4/31".parse().unwrap(),
                "192.0.2.6/32".parse().unwrap(),
            ]
        );
    }
}
