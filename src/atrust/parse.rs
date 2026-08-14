use std::{collections::BTreeMap, net::IpAddr, ops::RangeInclusive};

use ipnet::IpNet;
use serde::Deserialize;

use crate::{DomainResource, Error, IpResource, ProtocolMatch, Resources, resource::IpRange};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeGroup {
    pub wan: Vec<String>,
    pub lan: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParsedResources {
    pub resources: Resources,
    pub major_node_group: String,
    pub node_groups: BTreeMap<String, NodeGroup>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct ClientResource {
    data: ResourceData,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct ResourceData {
    app_list: AppList,
    sdp_policy: SdpPolicy,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct AppList {
    data: AppListData,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct AppListData {
    app_info: Vec<AppInfo>,
    config: AppConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct AppInfo {
    apps: Vec<App>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct App {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "nodeGroupID")]
    node_group_id: String,
    address_list: Vec<Address>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Address {
    protocol: String,
    port: String,
    host: String,
    #[serde(rename = "IP")]
    ip: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct AppConfig {
    node_group_conf: NodeGroupConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct NodeGroupConfig {
    major_node_group: MajorNodeGroup,
    node_group_list: Vec<NodeGroupEntry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct MajorNodeGroup {
    #[serde(rename = "ID")]
    id: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct NodeGroupEntry {
    #[serde(rename = "ID")]
    id: String,
    address_info: Vec<NodeAddress>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct NodeAddress {
    #[serde(rename = "Address")]
    address: String,
    #[serde(rename = "Type")]
    kind: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct SdpPolicy {
    data: SdpPolicyData,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct SdpPolicyData {
    client_option: ClientOption,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct ClientOption {
    dns_option: DnsOption,
    dns_option_v2: DnsOption,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct DnsOption {
    #[serde(rename = "firstDNS")]
    first_dns: String,
    #[serde(rename = "secondDNS")]
    second_dns: String,
}

/// Parse the resource policy returned by aTrust's `clientResource` endpoint.
///
/// # Errors
///
/// Returns [`Error::Resource`] when the response is not valid JSON.
pub fn parse_resources(data: &[u8], gateway: &str) -> Result<ParsedResources, Error> {
    let parsed: ClientResource = serde_json::from_slice(data)
        .map_err(|error| Error::Resource(format!("invalid aTrust resource JSON: {error}")))?;
    let mut resources = Resources::default();

    for group in parsed.data.app_list.data.app_info {
        for app in group.apps {
            for address in app.address_list {
                let Some(protocol) = parse_protocol(&address.protocol) else {
                    continue;
                };
                let Some(ports) = parse_ports(&address.port) else {
                    continue;
                };
                let metadata = (Some(app.id.clone()), Some(app.node_group_id.clone()));
                if let Some(addresses) = parse_ip_range(&address.host) {
                    resources.ip.push(IpResource {
                        addresses,
                        ports,
                        protocol,
                        app_id: metadata.0,
                        node_group_id: metadata.1,
                    });
                    continue;
                }

                let Some(domain) = normalize_policy_domain(&address.host) else {
                    continue;
                };
                resources
                    .domains
                    .entry(domain.clone())
                    .or_default()
                    .push(DomainResource {
                        ports,
                        protocol,
                        app_id: metadata.0,
                        node_group_id: metadata.1,
                    });
                for ip in address.ip {
                    if let Some(ip) = ip.parse::<IpAddr>().ok().filter(IpAddr::is_ipv4) {
                        resources
                            .dns_records
                            .entry(domain.clone())
                            .or_default()
                            .push(ip);
                    }
                }
            }
        }
    }

    let client_option = parsed.data.sdp_policy.data.client_option;
    let dns = if client_option.dns_option.first_dns.is_empty() {
        client_option.dns_option_v2
    } else {
        client_option.dns_option
    };
    resources.dns_servers = [dns.first_dns, dns.second_dns]
        .into_iter()
        .filter_map(|address| address.parse::<IpAddr>().ok())
        .filter(IpAddr::is_ipv4)
        .collect();

    let node_config = parsed.data.app_list.data.config.node_group_conf;
    let mut node_groups = BTreeMap::new();
    for entry in node_config.node_group_list {
        let mut group = NodeGroup::default();
        for address in entry.address_info {
            let host = if address.address == "{{sdpcHost}}" {
                gateway.to_owned()
            } else {
                address.address
            };
            let endpoint = with_default_node_port(&host);
            match address.kind.to_ascii_lowercase().as_str() {
                "wan" => group.wan.push(endpoint),
                "lan" => group.lan.push(endpoint),
                _ => {}
            }
        }
        node_groups.insert(entry.id, group);
    }

    Ok(ParsedResources {
        resources,
        major_node_group: node_config.major_node_group.id,
        node_groups,
    })
}

fn parse_protocol(value: &str) -> Option<ProtocolMatch> {
    match value.to_ascii_lowercase().as_str() {
        "all" => Some(ProtocolMatch::All),
        "tcp" => Some(ProtocolMatch::Tcp),
        "udp" => Some(ProtocolMatch::Udp),
        _ => None,
    }
}

fn parse_ports(value: &str) -> Option<RangeInclusive<u16>> {
    let (first, last) = value.split_once('-').unwrap_or((value, value));
    let first = first.parse().ok()?;
    let last = last.parse().ok()?;
    (first <= last).then_some(first..=last)
}

fn parse_ip_range(value: &str) -> Option<IpRange> {
    if let Ok(network) = value.parse::<IpNet>() {
        return network
            .addr()
            .is_ipv4()
            .then_some(IpRange::Network(network));
    }
    if let Ok(address @ IpAddr::V4(_)) = value.parse::<IpAddr>() {
        return Some(IpRange::Inclusive {
            first: address,
            last: address,
        });
    }
    let (first, last) = value.split_once('-')?;
    let first = first.parse::<IpAddr>().ok()?;
    let last = last.parse::<IpAddr>().ok()?;
    match (first, last) {
        (IpAddr::V4(first), IpAddr::V4(last)) if first <= last => Some(IpRange::Inclusive {
            first: first.into(),
            last: last.into(),
        }),
        _ => None,
    }
}

fn normalize_policy_domain(value: &str) -> Option<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let domain = domain
        .strip_prefix("*.")
        .map_or(domain.clone(), |rest| format!(".{rest}"));
    (!domain.is_empty() && !domain.contains('*')).then_some(domain)
}

fn with_default_node_port(host: &str) -> String {
    if host.parse::<std::net::SocketAddr>().is_ok() {
        host.to_owned()
    } else if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:441")
    } else if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        host.to_owned()
    } else {
        format!("{host}:441")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"{
      "data": {
        "appList": {"data": {
          "appInfo": [{"apps": [
            {"ID":"web", "nodeGroupID":"group-1", "addressList":[
              {"protocol":"tcp", "port":"443", "host":"*.example.edu", "IP":["10.1.2.3"]},
              {"protocol":"all", "port":"1-65535", "host":"10.20.0.0/16"}
            ]},
            {"ID":"ssh", "nodeGroupID":"group-2", "addressList":[
              {"protocol":"tcp", "port":"22", "host":"192.0.2.1-192.0.2.3"}
            ]}
          ]}],
          "config":{"nodeGroupConf":{
            "majorNodeGroup":{"ID":"group-1"},
            "nodeGroupList":[
              {"ID":"group-1", "addressInfo":[{"Address":"{{sdpcHost}}", "Type":"WAN"}]},
              {"ID":"group-2", "addressInfo":[{"Address":"192.0.2.10:8443", "Type":"LAN"}]}
            ]
          }}
        }},
        "sdpPolicy":{"data":{"clientOption":{"dnsOption":{"firstDNS":"10.10.0.53","secondDNS":""}}}}
      }
    }"#;

    #[test]
    fn parses_policy_and_tunnel_metadata() {
        let parsed = parse_resources(POLICY.as_bytes(), "vpn.example.edu").unwrap();
        assert_eq!(parsed.major_node_group, "group-1");
        assert_eq!(parsed.resources.ip.len(), 2);
        assert_eq!(parsed.resources.domains[".example.edu"].len(), 1);
        assert_eq!(
            parsed.resources.dns_records[".example.edu"],
            ["10.1.2.3".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            parsed.resources.dns_servers,
            ["10.10.0.53".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(parsed.node_groups["group-1"].wan, ["vpn.example.edu:441"]);
        assert_eq!(parsed.node_groups["group-2"].lan, ["192.0.2.10:8443"]);
    }

    #[test]
    fn preserves_multiple_domain_rules() {
        let policy = POLICY.replace(
            "{\"protocol\":\"tcp\", \"port\":\"443\", \"host\":\"*.example.edu\", \"IP\":[\"10.1.2.3\"]}",
            "{\"protocol\":\"tcp\", \"port\":\"443\", \"host\":\"www.example.edu\"}, {\"protocol\":\"tcp\", \"port\":\"80\", \"host\":\"www.example.edu\"}",
        );
        let parsed = parse_resources(policy.as_bytes(), "vpn.example.edu").unwrap();
        assert_eq!(parsed.resources.domains["www.example.edu"].len(), 2);
    }

    #[test]
    fn defaults_ipv6_node_port() {
        assert_eq!(with_default_node_port("2001:db8::1"), "[2001:db8::1]:441");
    }

    #[test]
    fn skips_ipv6_policy_ranges_until_atrust_supports_them() {
        assert!(parse_ip_range("2001:db8::/32").is_none());
        assert!(parse_ip_range("2001:db8::1").is_none());
    }
}
