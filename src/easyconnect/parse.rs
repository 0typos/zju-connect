use std::{collections::BTreeMap, net::IpAddr, str::FromStr};

use crate::{
    Error,
    resource::{DomainResource, IpRange, IpResource, ProtocolMatch, Resources},
};

/// Parse enabled gateway endpoints from an `EasyConnect` configuration response.
///
/// # Errors
///
/// Returns [`Error::Protocol`] or [`Error::Resource`] for malformed XML, a disabled
/// multi-line configuration, or an empty endpoint list.
pub fn parse_line_list(xml: &str) -> Result<Vec<String>, Error> {
    let document = document(xml)?;
    let mline = document
        .descendants()
        .find(|node| node.has_tag_name("Mline"))
        .ok_or_else(|| Error::Protocol("EasyConnect config has no Mline element".into()))?;
    if mline.attribute("enable") != Some("1") {
        return Err(Error::Protocol(
            "EasyConnect gateway disabled multiple lines".into(),
        ));
    }
    let lines = mline
        .attribute("list")
        .unwrap_or_default()
        .split(';')
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if lines.is_empty() {
        Err(Error::Protocol(
            "EasyConnect gateway returned an empty line list".into(),
        ))
    } else {
        Ok(lines)
    }
}

/// Parse `EasyConnect` IP, domain, and DNS policy XML.
///
/// # Errors
///
/// Returns [`Error::Resource`] when required XML elements are absent or malformed.
pub fn parse_resources(xml: &str, use_domains: bool) -> Result<Resources, Error> {
    let document = document(xml)?;
    let root = document
        .descendants()
        .find(|node| node.has_tag_name("Resource"))
        .ok_or_else(|| Error::Resource("missing Resource element".into()))?;
    let rcs = root
        .children()
        .find(|node| node.has_tag_name("Rcs"))
        .ok_or_else(|| Error::Resource("missing Rcs element".into()))?;
    let mut resources = Resources::default();
    for rc in rcs.children().filter(|node| node.has_tag_name("Rc")) {
        if !matches!(rc.attribute("type"), Some("1" | "2")) {
            continue;
        }
        let Some(protocol) = rc.attribute("proto").and_then(parse_protocol) else {
            continue;
        };
        let hosts = rc.attribute("host").unwrap_or_default().split(';');
        let ports = rc.attribute("port").unwrap_or_default().split(';');
        for (host, ports) in hosts.zip(ports) {
            let Some(ports) = parse_ports(ports) else {
                continue;
            };
            parse_host(&mut resources, host, ports, protocol, use_domains);
        }
    }

    let dns = root
        .children()
        .find(|node| node.has_tag_name("Dns"))
        .ok_or_else(|| Error::Resource("missing Dns element".into()))?;
    resources.dns_records = parse_dns_records(dns.attribute("data").unwrap_or_default());
    resources.dns_servers = dns
        .attribute("dnsserver")
        .unwrap_or_default()
        .split(';')
        .filter_map(|value| value.parse::<IpAddr>().ok())
        .filter(|address| !address.is_unspecified())
        .collect();
    Ok(resources)
}

fn document(xml: &str) -> Result<roxmltree::Document<'_>, Error> {
    roxmltree::Document::parse(xml)
        .map_err(|error| Error::Resource(format!("invalid XML: {error}")))
}

fn parse_protocol(value: &str) -> Option<ProtocolMatch> {
    match value {
        "-1" => Some(ProtocolMatch::All),
        "0" => Some(ProtocolMatch::Tcp),
        "1" => Some(ProtocolMatch::Udp),
        "2" => Some(ProtocolMatch::Icmp),
        _ => None,
    }
}

fn parse_ports(value: &str) -> Option<std::ops::RangeInclusive<u16>> {
    let (first, last) = value.split_once('~')?;
    let first = first.parse().ok()?;
    let last = last.parse().ok()?;
    (first <= last).then_some(first..=last)
}

fn parse_host(
    resources: &mut Resources,
    raw_host: &str,
    mut ports: std::ops::RangeInclusive<u16>,
    protocol: ProtocolMatch,
    use_domains: bool,
) {
    if let Some((first, last)) = raw_host.split_once('~') {
        if let (Ok(first), Ok(last)) = (first.parse::<IpAddr>(), last.parse::<IpAddr>()) {
            if first.is_ipv4() == last.is_ipv4() {
                resources.ip.push(IpResource {
                    addresses: IpRange::Inclusive { first, last },
                    ports,
                    protocol,
                    app_id: None,
                    node_group_id: None,
                });
            }
        }
        return;
    }

    let (host, explicit_port) = normalize_host(raw_host);
    if let Some(port) = explicit_port {
        ports = port..=port;
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        resources.ip.push(IpResource {
            addresses: IpRange::Inclusive {
                first: address,
                last: address,
            },
            ports,
            protocol,
            app_id: None,
            node_group_id: None,
        });
    } else if use_domains && !host.is_empty() {
        resources
            .domains
            .entry(host)
            .or_default()
            .push(DomainResource {
                ports,
                protocol,
                app_id: None,
                node_group_id: None,
            });
    }
}

fn normalize_host(raw: &str) -> (String, Option<u16>) {
    let raw = raw.trim();
    if raw.contains("://") {
        if let Ok(url) = url::Url::parse(raw) {
            return (
                url.host_str()
                    .unwrap_or_default()
                    .trim_start_matches("*.")
                    .to_ascii_lowercase(),
                url.port(),
            );
        }
    }
    let raw = raw.split('/').next().unwrap_or_default();
    if let Ok(socket) = std::net::SocketAddr::from_str(raw) {
        return (socket.ip().to_string(), Some(socket.port()));
    }
    if let Some((host, port)) = raw.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return (
                host.trim_matches(['[', ']'])
                    .trim_start_matches("*.")
                    .to_ascii_lowercase(),
                Some(port),
            );
        }
    }
    (raw.trim_start_matches("*.").to_ascii_lowercase(), None)
}

fn parse_dns_records(data: &str) -> BTreeMap<String, Vec<IpAddr>> {
    let mut records = BTreeMap::<String, Vec<IpAddr>>::new();
    for entry in data.split(';').filter(|entry| !entry.is_empty()) {
        let mut parts = entry.splitn(3, ':');
        let (_kind, Some(domain), Some(address)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if let Ok(address) = address.parse() {
            records
                .entry(domain.trim_end_matches('.').to_ascii_lowercase())
                .or_default()
                .push(address);
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESOURCES: &str = r#"
        <Resource>
          <Rcs>
            <Rc type="1" proto="0" host="10.0.0.1~10.0.0.9;https://*.zju.edu.cn/path;10.20.30.40:8443" port="1~65535;443~443;1~65535"/>
            <Rc type="9" proto="0" host="ignored.example" port="1~2"/>
          </Rcs>
          <Dns data="0:www.zju.edu.cn:10.10.0.1;" dnsserver="10.10.0.21;8.8.8.8;0.0.0.0"/>
        </Resource>
    "#;

    #[test]
    fn parses_easyconnect_resources() {
        let resources = parse_resources(RESOURCES, true).unwrap();
        assert_eq!(resources.ip.len(), 2);
        assert_eq!(resources.domains["zju.edu.cn"][0].ports, 443..=443);
        assert_eq!(resources.ip[1].ports, 8443..=8443);
        assert_eq!(
            resources.dns_records["www.zju.edu.cn"],
            vec!["10.10.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(resources.dns_servers.len(), 2);
    }

    #[test]
    fn can_skip_domain_resources() {
        let resources = parse_resources(RESOURCES, false).unwrap();
        assert!(resources.domains.is_empty());
        assert_eq!(resources.ip.len(), 2);
    }

    #[test]
    fn parses_enabled_line_list() {
        assert_eq!(
            parse_line_list("<Conf><Mline enable=\"1\" list=\"a:443;b:443;\"/></Conf>").unwrap(),
            ["a:443", "b:443"]
        );
    }
}
