use std::{net::IpAddr, path::Path};

use serde::{Deserialize, Serialize};

use crate::Error;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Easyconnect,
    Atrust,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    pub protocol: Protocol,
    pub server_address: String,
    pub server_port: u16,
    pub username: String,
    pub password: String,
    pub totp_secret: String,
    pub graph_code_file: Option<String>,
    pub socks_bind: Option<String>,
    pub socks_user: String,
    #[serde(alias = "socks_passwd")]
    pub socks_password: String,
    pub http_bind: Option<String>,
    /// Permit binding the proxies to a non-loopback address without credentials.
    pub allow_open_proxy: bool,
    /// Skip TLS certificate verification on the authentication channel. Needed
    /// for gateways with a self-signed certificate; disables MITM protection.
    pub insecure_skip_verify: bool,
    pub shadowsocks_url: Option<String>,
    pub dial_direct_proxy: Option<String>,
    pub dns_server_bind: Option<String>,
    #[serde(alias = "zju_dns_server")]
    pub remote_dns_server: RemoteDns,
    pub secondary_dns_server: RemoteDns,
    #[serde(alias = "disable_zju_dns")]
    pub disable_remote_dns: bool,
    pub dns_ttl: u64,
    pub disable_server_config: bool,
    pub skip_domain_resource: bool,
    pub disable_zju_config: bool,
    pub disable_multi_line: bool,
    pub disable_keep_alive: bool,
    pub keep_alive_url: Option<String>,
    pub debug_dump: bool,
    pub proxy_all: bool,
    pub tcp_tunnel_mode: bool,
    pub skip_tcp_tunnel_wait: bool,
    pub tun_mode: bool,
    pub add_route: bool,
    pub dns_hijack: bool,
    pub fake_ip: bool,
    pub bind_interface: Option<String>,
    pub auto_detect_interface: bool,
    pub twf_id: Option<String>,
    pub cert_file: Option<String>,
    pub cert_password: String,
    pub auth_type: Option<String>,
    pub login_domain: String,
    pub phone: Option<String>,
    pub cas_ticket: Option<String>,
    pub oauth2_code: Option<String>,
    pub client_data_file: Option<String>,
    pub resource_file: Option<String>,
    pub update_best_nodes_interval: Option<u64>,
    pub sid: Option<String>,
    pub device_id: Option<String>,
    pub sign_key: Option<String>,
    pub custom_proxy_domain: Vec<String>,
    pub custom_dns: Vec<CustomDns>,
    pub port_forwarding: Vec<PortForward>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |value: &str| {
            if value.is_empty() {
                "\"\""
            } else {
                "\"<redacted>\""
            }
        };
        formatter
            .debug_struct("Config")
            .field("protocol", &self.protocol)
            .field("server_address", &self.server_address)
            .field("server_port", &self.server_port)
            .field("username", &self.username)
            .field("password", &format_args!("{}", redact(&self.password)))
            .field(
                "totp_secret",
                &format_args!("{}", redact(&self.totp_secret)),
            )
            .field("socks_bind", &self.socks_bind)
            .field("socks_user", &self.socks_user)
            .field(
                "socks_password",
                &format_args!("{}", redact(&self.socks_password)),
            )
            .field("http_bind", &self.http_bind)
            .field("allow_open_proxy", &self.allow_open_proxy)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("tun_mode", &self.tun_mode)
            .field("add_route", &self.add_route)
            .field("proxy_all", &self.proxy_all)
            .field("sign_key", &self.sign_key.as_deref().map(|_| "<redacted>"))
            .field(
                "cert_password",
                &format_args!("{}", redact(&self.cert_password)),
            )
            .finish_non_exhaustive()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol: Protocol::Easyconnect,
            server_address: "rvpn.zju.edu.cn".into(),
            server_port: 443,
            username: String::new(),
            password: String::new(),
            totp_secret: String::new(),
            graph_code_file: None,
            socks_bind: Some("127.0.0.1:1080".into()),
            socks_user: String::new(),
            socks_password: String::new(),
            http_bind: Some("127.0.0.1:1081".into()),
            allow_open_proxy: false,
            insecure_skip_verify: false,
            shadowsocks_url: None,
            dial_direct_proxy: None,
            dns_server_bind: None,
            remote_dns_server: RemoteDns::AUTO,
            secondary_dns_server: RemoteDns::AUTO,
            disable_remote_dns: false,
            dns_ttl: 3600,
            disable_server_config: false,
            skip_domain_resource: false,
            disable_zju_config: false,
            disable_multi_line: false,
            disable_keep_alive: false,
            keep_alive_url: None,
            debug_dump: false,
            proxy_all: false,
            tcp_tunnel_mode: false,
            skip_tcp_tunnel_wait: false,
            tun_mode: false,
            add_route: false,
            dns_hijack: false,
            fake_ip: false,
            bind_interface: None,
            auto_detect_interface: false,
            twf_id: None,
            cert_file: None,
            cert_password: String::new(),
            auth_type: None,
            login_domain: "Radius".into(),
            phone: None,
            cas_ticket: None,
            oauth2_code: None,
            client_data_file: None,
            resource_file: None,
            update_best_nodes_interval: None,
            sid: None,
            device_id: None,
            sign_key: None,
            custom_proxy_domain: Vec::new(),
            custom_dns: Vec::new(),
            port_forwarding: Vec::new(),
        }
    }
}

impl Config {
    /// Load and validate a TOML configuration file.
    ///
    /// # Errors
    ///
    /// Returns an I/O error, a TOML syntax/schema error, or a validation error.
    pub async fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let text = tokio::fs::read_to_string(path).await?;
        let config: Self = toml::from_str(&text)
            .map_err(|error| Error::Config(format!("could not parse TOML: {error}")))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate cross-field and address constraints.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when a field is malformed or incompatible with
    /// another enabled option.
    pub fn validate(&self) -> Result<(), Error> {
        if self.server_address.trim().is_empty() {
            return Err(Error::Config("server_address cannot be empty".into()));
        }
        if self.server_address.contains("://") {
            return Err(Error::Config(
                "server_address must not include a URL scheme".into(),
            ));
        }
        // A bare "host:port" in server_address is a common mistake; the port
        // belongs in server_port. IPv6 literals legitimately contain colons.
        if self.server_address.parse::<std::net::Ipv6Addr>().is_err()
            && self.server_address.contains(':')
        {
            return Err(Error::Config(
                "server_address must not include a port; set server_port instead".into(),
            ));
        }
        if self.server_port == 0 {
            return Err(Error::Config("server_port must not be zero".into()));
        }
        self.validate_proxy_binds()?;
        if self
            .twf_id
            .as_deref()
            .is_some_and(|value| !value.is_empty() && value.len() != 16)
        {
            return Err(Error::Config("twf_id must contain exactly 16 bytes".into()));
        }
        if self.sign_key.as_deref().is_some_and(|value| {
            !value.is_empty()
                && (value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        }) {
            return Err(Error::Config(
                "sign_key must contain 64 hexadecimal characters".into(),
            ));
        }
        if self.protocol == Protocol::Atrust {
            let auth_type = self.auth_type.as_deref().unwrap_or("auth/psw");
            if auth_type != "auth/psw" {
                return Err(Error::Config(format!(
                    "aTrust authentication type {auth_type} is not implemented in the Rust port yet"
                )));
            }
            if self
                .client_data_file
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            {
                return Err(Error::Config(
                    "aTrust client_data_file persistence is not implemented yet".into(),
                ));
            }
            if self.sid.as_deref().is_some_and(|value| !value.is_empty())
                && (self.device_id.as_deref().is_none_or(str::is_empty)
                    || self.resource_file.as_deref().is_none_or(str::is_empty))
            {
                return Err(Error::Config(
                    "aTrust sid reuse requires device_id and resource_file".into(),
                ));
            }
            if !self.custom_proxy_domain.is_empty() {
                return Err(Error::Config(
                    "custom_proxy_domain is not supported for aTrust; its resources are gateway-defined".into(),
                ));
            }
        }
        if self.update_best_nodes_interval.is_some() {
            return Err(Error::Config(
                "update_best_nodes_interval is not implemented in the Rust port yet".into(),
            ));
        }
        if self.tun_mode && self.fake_ip && !self.dns_hijack {
            return Err(Error::Config(
                "fake_ip requires dns_hijack when tun_mode is enabled".into(),
            ));
        }
        self.reject_unsupported_features()?;
        for domain in &self.custom_proxy_domain {
            validate_domain(domain)?;
        }
        Ok(())
    }

    fn reject_unsupported_features(&self) -> Result<(), Error> {
        let unsupported = [
            (self.shadowsocks_url.as_deref(), "shadowsocks_url"),
            (self.dial_direct_proxy.as_deref(), "dial_direct_proxy"),
            (self.dns_server_bind.as_deref(), "dns_server_bind"),
            (self.keep_alive_url.as_deref(), "keep_alive_url"),
            (self.bind_interface.as_deref(), "bind_interface"),
            (self.cert_file.as_deref(), "cert_file"),
        ];
        if let Some((_, name)) = unsupported
            .into_iter()
            .find(|(value, _)| value.is_some_and(|value| !value.is_empty()))
        {
            return Err(Error::Config(format!(
                "{name} is not implemented in the Rust port yet"
            )));
        }
        if (self.tcp_tunnel_mode && self.protocol != Protocol::Atrust)
            || self.dns_hijack
            || self.fake_ip
            || self.auto_detect_interface
            || !self.port_forwarding.is_empty()
        {
            return Err(Error::Config(
                "EasyConnect TCP tunnel mode, DNS hijacking, fake IP, interface auto-detection, and port forwarding are not implemented in the Rust port yet"
                    .into(),
            ));
        }
        Ok(())
    }

    fn validate_proxy_binds(&self) -> Result<(), Error> {
        if !self.socks_password.is_empty() && self.socks_user.is_empty() {
            return Err(Error::Config(
                "socks_password is set but socks_user is empty; both are required".into(),
            ));
        }
        let has_credentials = !self.socks_user.is_empty();
        for (bind, name) in [
            (self.socks_bind.as_deref(), "socks_bind"),
            (self.http_bind.as_deref(), "http_bind"),
        ] {
            let Some(bind) = bind.filter(|value| !value.is_empty()) else {
                continue;
            };
            let address = bind.parse::<std::net::SocketAddr>().map_err(|_| {
                Error::Config(format!("{name} must be a valid host:port address: {bind}"))
            })?;
            if !address.ip().is_loopback() && !has_credentials && !self.allow_open_proxy {
                return Err(Error::Config(format!(
                    "{name} listens on a non-loopback address ({bind}); set socks_user/socks_password or enable allow_open_proxy to expose the proxy"
                )));
            }
        }
        Ok(())
    }

    pub fn server_host(&self) -> String {
        if self.server_address.contains(':') && !self.server_address.starts_with('[') {
            format!("[{}]:{}", self.server_address, self.server_port)
        } else {
            format!("{}:{}", self.server_address, self.server_port)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RemoteDns {
    Keyword(RemoteDnsKeyword),
    Address(IpAddr),
}

impl RemoteDns {
    pub const AUTO: Self = Self::Keyword(RemoteDnsKeyword::Auto);
    pub const DISABLED: Self = Self::Keyword(RemoteDnsKeyword::Disabled);
}

impl Default for RemoteDns {
    fn default() -> Self {
        Self::AUTO
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RemoteDnsKeyword {
    Auto,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomDns {
    pub host_name: String,
    pub ip: IpAddr,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortForward {
    pub network_type: Network,
    pub bind_address: String,
    pub remote_address: String,
}

fn validate_domain(domain: &str) -> Result<(), Error> {
    let valid = !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if valid {
        Ok(())
    } else {
        Err(Error::Config(format!("invalid domain: {domain}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_zju_service() {
        let config = Config::default();
        assert_eq!(config.server_host(), "rvpn.zju.edu.cn:443");
        assert_eq!(config.socks_bind.as_deref(), Some("127.0.0.1:1080"));
        assert_eq!(config.http_bind.as_deref(), Some("127.0.0.1:1081"));
        config.validate().unwrap();
    }

    #[test]
    fn brackets_ipv6_gateway() {
        let config = Config {
            server_address: "2001:db8::1".into(),
            ..Config::default()
        };
        assert_eq!(config.server_host(), "[2001:db8::1]:443");
    }

    #[test]
    fn rejects_open_proxy_bind_without_credentials() {
        let open = Config {
            socks_bind: Some("0.0.0.0:1080".into()),
            ..Config::default()
        };
        assert!(open.validate().is_err());

        let with_auth = Config {
            socks_bind: Some("0.0.0.0:1080".into()),
            socks_user: "user".into(),
            socks_password: "pass".into(),
            ..Config::default()
        };
        with_auth.validate().unwrap();

        let acknowledged = Config {
            socks_bind: Some("0.0.0.0:1080".into()),
            allow_open_proxy: true,
            ..Config::default()
        };
        acknowledged.validate().unwrap();
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let config = Config {
            password: "hunter2".into(),
            totp_secret: "ABCDEF".into(),
            sign_key: Some("ab".repeat(32)),
            ..Config::default()
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("ABCDEF"));
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn rejects_unimplemented_and_unsupported_keys() {
        let interval = Config {
            update_best_nodes_interval: Some(300),
            ..Config::default()
        };
        assert!(interval.validate().is_err());

        let atrust_custom = Config {
            protocol: Protocol::Atrust,
            custom_proxy_domain: vec!["example.com".into()],
            ..Config::default()
        };
        assert!(atrust_custom.validate().is_err());
    }

    #[test]
    fn rejects_socks_password_without_user() {
        let config = Config {
            socks_password: "secret".into(),
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_unparsable_bind_and_server_port_in_address() {
        let bad_bind = Config {
            socks_bind: Some("not-an-address".into()),
            ..Config::default()
        };
        assert!(bad_bind.validate().is_err());

        let host_port = Config {
            server_address: "vpn.example.edu:443".into(),
            ..Config::default()
        };
        assert!(host_port.validate().is_err());
    }

    #[test]
    fn rejects_fake_ip_without_dns_hijacking() {
        let config = Config {
            tun_mode: true,
            fake_ip: true,
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validates_atrust_session_reuse_as_a_unit() {
        let incomplete = Config {
            protocol: Protocol::Atrust,
            sid: Some("session".into()),
            ..Config::default()
        };
        assert!(incomplete.validate().is_err());

        let complete = Config {
            device_id: Some("device".into()),
            resource_file: Some("resources.json".into()),
            ..incomplete
        };
        complete.validate().unwrap();
    }

    #[test]
    fn rejects_unsupported_atrust_login_type() {
        let config = Config {
            protocol: Protocol::Atrust,
            auth_type: Some("auth/cas".into()),
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn repository_example_remains_compatible() {
        let config: Config = toml::from_str(include_str!("../config.toml.example")).unwrap();
        config.validate().unwrap();
        assert_eq!(config.server_address, "rvpn.zju.edu.cn");
        assert_eq!(config.socks_password, "");
    }
}
