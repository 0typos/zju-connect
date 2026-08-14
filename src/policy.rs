use std::net::IpAddr;

use crate::resource::{DomainResource, IpResource, ProtocolMatch, Resources};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Vpn,
    Direct,
    /// The destination must not be reached: it cannot traverse the IPv4-only
    /// tunnel, but `proxy_all` forbids a direct connection.
    Reject,
}

#[derive(Clone, Debug)]
pub struct Policy {
    resources: Resources,
    proxy_all: bool,
}

impl Policy {
    pub fn new(resources: Resources, proxy_all: bool) -> Self {
        Self {
            resources,
            proxy_all,
        }
    }

    pub fn route_ip(&self, address: IpAddr, port: u16, protocol: ProtocolMatch) -> Route {
        if address.is_ipv6() {
            // The tunnel is IPv4-only; under proxy_all a direct IPv6 connection
            // would silently bypass the VPN, so fail closed instead.
            return if self.proxy_all {
                Route::Reject
            } else {
                Route::Direct
            };
        }
        if self.proxy_all
            || self
                .resources
                .ip
                .iter()
                .any(|resource| resource.matches(address, port, protocol))
        {
            Route::Vpn
        } else {
            Route::Direct
        }
    }

    pub fn route_domain(&self, domain: &str, port: u16, protocol: ProtocolMatch) -> Route {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let matched = domain_suffixes(&domain).any(|suffix| {
            let exact =
                self.resources.domains.get(suffix).is_some_and(|entries| {
                    entries.iter().any(|entry| entry.matches(port, protocol))
                });
            let wildcard = self
                .resources
                .domains
                .get(&format!(".{suffix}"))
                .is_some_and(|entries| entries.iter().any(|entry| entry.matches(port, protocol)));
            exact || wildcard
        });
        if self.proxy_all || matched {
            Route::Vpn
        } else {
            Route::Direct
        }
    }

    pub fn matching_ip_resource(
        &self,
        address: IpAddr,
        port: u16,
        protocol: ProtocolMatch,
    ) -> Option<&IpResource> {
        self.resources
            .ip
            .iter()
            .rev()
            .find(|resource| resource.matches(address, port, protocol))
    }

    pub fn matching_domain_resource(
        &self,
        domain: &str,
        port: u16,
        protocol: ProtocolMatch,
    ) -> Option<&DomainResource> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        domain_suffixes(&domain).find_map(|suffix| {
            let exact = self.resources.domains.get(suffix).and_then(|entries| {
                entries
                    .iter()
                    .rev()
                    .find(|entry| entry.matches(port, protocol))
            });
            exact.or_else(|| {
                self.resources
                    .domains
                    .get(&format!(".{suffix}"))?
                    .iter()
                    .rev()
                    .find(|entry| entry.matches(port, protocol))
            })
        })
    }
}

fn domain_suffixes(domain: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(domain), |part| {
        part.split_once('.').map(|(_, tail)| tail)
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, net::Ipv4Addr};

    use super::*;
    use crate::resource::{DomainResource, IpRange};

    fn policy() -> Policy {
        Policy::new(
            Resources {
                ip: vec![IpResource {
                    addresses: IpRange::Inclusive {
                        first: "10.0.0.0".parse().unwrap(),
                        last: "10.255.255.255".parse().unwrap(),
                    },
                    ports: 1..=u16::MAX,
                    protocol: ProtocolMatch::All,
                    app_id: None,
                    node_group_id: None,
                }],
                domains: BTreeMap::from([(
                    "zju.edu.cn".into(),
                    vec![DomainResource {
                        ports: 443..=443,
                        protocol: ProtocolMatch::Tcp,
                        app_id: None,
                        node_group_id: None,
                    }],
                )]),
                ..Resources::default()
            },
            false,
        )
    }

    #[test]
    fn matches_ip_range() {
        assert_eq!(
            policy().route_ip(
                IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
                22,
                ProtocolMatch::Tcp
            ),
            Route::Vpn
        );
    }

    #[test]
    fn matches_domain_suffix_but_honors_port() {
        assert_eq!(
            policy().route_domain("mail.ZJU.edu.cn.", 443, ProtocolMatch::Tcp),
            Route::Vpn
        );
        assert_eq!(
            policy().route_domain("mail.zju.edu.cn", 80, ProtocolMatch::Tcp),
            Route::Direct
        );
    }

    #[test]
    fn ipv6_is_direct_split_but_rejected_under_proxy_all() {
        let v6 = "2001:db8::1".parse::<IpAddr>().unwrap();
        assert_eq!(
            policy().route_ip(v6, 443, ProtocolMatch::Tcp),
            Route::Direct
        );
        let all = Policy::new(Resources::default(), true);
        assert_eq!(all.route_ip(v6, 443, ProtocolMatch::Tcp), Route::Reject);
        assert_eq!(
            all.route_ip("1.1.1.1".parse().unwrap(), 443, ProtocolMatch::Tcp),
            Route::Vpn
        );
    }
}
