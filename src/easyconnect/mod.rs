//! Sangfor `EasyConnect` control-plane and L3 protocol support.

mod auth;
mod legacy_tls;
mod parse;
mod tunnel;

use std::{
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use reqwest::{Client as HttpClient, StatusCode};

use crate::{ChallengeHandler, Config, Error, Resources};

pub use auth::{AuthResult, NextAuthentication};
pub use parse::{parse_line_list, parse_resources};

const USER_AGENT: &str = "EasyConnect_windows";

/// Authenticated `EasyConnect` control-plane client.
pub struct EasyConnectClient {
    config: Config,
    http: HttpClient,
    twf_id: Option<String>,
    resources: Resources,
    token: Option<[u8; 48]>,
    client_ip: Option<Ipv4Addr>,
    request_ip_connection: Option<legacy_tls::LegacyTlsStream>,
    keepalive_task: Option<tokio::task::JoinHandle<()>>,
}

impl EasyConnectClient {
    /// Create a client using the standard HTTPS transport.
    ///
    /// # Errors
    ///
    /// Returns a configuration error or an HTTP client construction error.
    pub fn new(config: Config) -> Result<Self, Error> {
        config.validate()?;
        let http = HttpClient::builder()
            .cookie_store(true)
            // The authentication channel carries the password-encryption key and
            // credentials, so certificates are verified by default. Gateways with
            // a self-signed certificate require insecure_skip_verify.
            .danger_accept_invalid_certs(config.insecure_skip_verify)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(USER_AGENT)
            .build()?;
        if config.insecure_skip_verify {
            tracing::warn!(
                "insecure_skip_verify is set; the authentication channel is exposed to MITM"
            );
        }
        let twf_id = config.twf_id.clone().filter(|value| !value.is_empty());
        Ok(Self {
            config,
            http,
            twf_id,
            resources: Resources::default(),
            token: None,
            client_ip: None,
            request_ip_connection: None,
            keepalive_task: None,
        })
    }

    /// Create a client with an injected HTTP transport, primarily for embedding and tests.
    ///
    /// # Errors
    ///
    /// Returns an error when `config` is invalid.
    pub fn with_http_client(config: Config, http: HttpClient) -> Result<Self, Error> {
        config.validate()?;
        let twf_id = config.twf_id.clone().filter(|value| !value.is_empty());
        Ok(Self {
            config,
            http,
            twf_id,
            resources: Resources::default(),
            token: None,
            client_ip: None,
            request_ip_connection: None,
            keepalive_task: None,
        })
    }

    pub fn twf_id(&self) -> Option<&str> {
        self.twf_id.as_deref()
    }

    pub fn resources(&self) -> &Resources {
        &self.resources
    }

    /// Authenticate and retain the gateway's `TwfID` session identifier.
    ///
    /// # Errors
    ///
    /// Returns an HTTP, protocol, authentication, or challenge-handler error.
    pub async fn authenticate(
        &mut self,
        challenges: &dyn ChallengeHandler,
    ) -> Result<AuthResult, Error> {
        if let Some(twf_id) = self.twf_id.clone() {
            return Ok(AuthResult {
                twf_id,
                server_version: None,
            });
        }
        let result = auth::authenticate(&self.http, &self.config, challenges).await?;
        self.twf_id = Some(result.twf_id.clone());
        Ok(result)
    }

    /// Download the gateway's configuration XML.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotConnected`] before authentication, or an HTTP error.
    pub async fn fetch_server_config(&self) -> Result<String, Error> {
        self.get_text("/por/conf.csp").await
    }

    /// Download and parse split-tunnel and DNS resources.
    ///
    /// # Errors
    ///
    /// Returns an HTTP error or [`Error::Resource`] for malformed gateway XML.
    pub async fn fetch_resources(&mut self) -> Result<&Resources, Error> {
        let xml = self.get_text("/por/rclist.csp").await?;
        self.resources = parse_resources(&xml, !self.config.skip_domain_resource)?;
        Ok(&self.resources)
    }

    /// Refresh the server-side authenticated session.
    ///
    /// # Errors
    ///
    /// Returns an error if the gateway does not support the request, rejects it,
    /// or supplies a malformed response.
    pub async fn update_session(&self) -> Result<(), Error> {
        let twf_id = self.twf_id.as_deref().ok_or(Error::NotConnected)?;
        let response = self
            .http
            .get(self.url("/por/update_session.csp"))
            .query(&[("twfid", twf_id), ("apiversion", "1")])
            .header("Cookie", self.cookie()?)
            .header("User-Agent", "EasyConnect_Linux_Ubuntu")
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(Error::Protocol(
                "gateway does not support session keep-alive".into(),
            ));
        }
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(Error::Protocol(format!(
                "session keep-alive returned HTTP {status}"
            )));
        }
        if !keepalive_body_is_success(&body) {
            return Err(Error::Protocol(format!(
                "gateway rejected session keep-alive: {body}"
            )));
        }
        Ok(())
    }

    pub fn preferred_dns_server(&self) -> Option<IpAddr> {
        self.resources.dns_servers.first().copied()
    }

    pub fn client_ip(&self) -> Option<Ipv4Addr> {
        self.client_ip
    }

    async fn select_best_line(&mut self, challenges: &dyn ChallengeHandler) -> Result<(), Error> {
        if self.config.disable_multi_line {
            return Ok(());
        }
        let xml = match self.fetch_server_config().await {
            Ok(xml) => xml,
            Err(error) => {
                tracing::warn!(%error, "could not retrieve EasyConnect line list");
                return Ok(());
            }
        };
        let lines = match parse_line_list(&xml) {
            Ok(lines) => lines,
            Err(error) => {
                tracing::debug!(%error, "gateway did not supply an enabled line list");
                return Ok(());
            }
        };
        let mut probes = tokio::task::JoinSet::new();
        for line in lines {
            probes.spawn(async move {
                let started = Instant::now();
                let result = tokio::time::timeout(
                    Duration::from_secs(3),
                    tokio::net::TcpStream::connect(&line),
                )
                .await;
                result
                    .ok()
                    .and_then(Result::ok)
                    .map(|_| (line, started.elapsed()))
            });
        }
        let mut best = None;
        while let Some(result) = probes.join_next().await {
            let Ok(Some(candidate)) = result else {
                continue;
            };
            if best
                .as_ref()
                .is_none_or(|(_, latency)| candidate.1 < *latency)
            {
                best = Some(candidate);
            }
        }
        let Some((best, latency)) = best else {
            tracing::warn!("none of the EasyConnect gateway lines were reachable");
            return Ok(());
        };
        if best == self.config.server_host() {
            return Ok(());
        }
        let (host, port) = split_host_port(&best)?;
        tracing::info!(line = best, ?latency, "selected fastest EasyConnect line");
        self.config.server_address = host;
        self.config.server_port = port;
        self.config.disable_multi_line = true;
        self.twf_id = None;
        self.authenticate(challenges).await?;
        Ok(())
    }

    fn start_keepalive(&mut self) {
        if self.config.disable_keep_alive || self.keepalive_task.is_some() {
            return;
        }
        let http = self.http.clone();
        let url = self.url("/por/update_session.csp");
        let Some(twf_id) = self.twf_id.clone() else {
            return;
        };
        self.keepalive_task = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            // After a laptop resume, run one catch-up request instead of a
            // burst of every missed tick.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                interval.tick().await;
                let response = http
                    .get(&url)
                    .query(&[("twfid", twf_id.as_str()), ("apiversion", "1")])
                    .header("Cookie", format!("TWFID={twf_id}"))
                    .header("User-Agent", "EasyConnect_Linux_Ubuntu")
                    .send()
                    .await;
                match response {
                    Ok(response) if response.status() == StatusCode::NOT_FOUND => {
                        tracing::debug!("gateway does not support session keep-alive");
                        return;
                    }
                    Ok(response) if response.status().is_success() => {
                        let body = response.text().await.unwrap_or_default();
                        if !keepalive_body_is_success(&body) {
                            tracing::warn!(body, "gateway rejected EasyConnect keep-alive");
                        }
                    }
                    Ok(response) => {
                        tracing::warn!(status = %response.status(), "EasyConnect keep-alive failed");
                    }
                    Err(error) => tracing::warn!(%error, "EasyConnect keep-alive failed"),
                }
            }
        }));
    }

    fn url(&self, path: &str) -> String {
        format!("https://{}{}", self.config.server_host(), path)
    }

    fn cookie(&self) -> Result<String, Error> {
        self.twf_id
            .as_ref()
            .map(|id| format!("TWFID={id}"))
            .ok_or(Error::NotConnected)
    }

    async fn get_text(&self, path: &str) -> Result<String, Error> {
        let response = self
            .http
            .get(self.url(path))
            .header("Cookie", self.cookie()?)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.text().await?)
    }
}

impl Drop for EasyConnectClient {
    fn drop(&mut self) {
        if let Some(task) = self.keepalive_task.take() {
            task.abort();
        }
    }
}

fn keepalive_body_is_success(body: &str) -> bool {
    let Ok(document) = roxmltree::Document::parse(body) else {
        return false;
    };
    let value = |name| {
        document
            .descendants()
            .find(|node| node.has_tag_name(name))
            .and_then(|node| node.text())
    };
    value("Message") == Some("success") && value("ErrorCode") == Some("1")
}

fn split_host_port(value: &str) -> Result<(String, u16), Error> {
    if let Ok(address) = value.parse::<std::net::SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| Error::Protocol(format!("invalid EasyConnect line address: {value}")))?;
    let port = port
        .parse()
        .map_err(|_| Error::Protocol(format!("invalid EasyConnect line port: {value}")))?;
    Ok((host.trim_matches(['[', ']']).to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_keepalive_response_body() {
        let success = "<Auth><Message>success</Message><ErrorCode>1</ErrorCode></Auth>";
        let failure = "<Auth><Message>failure</Message><ErrorCode>0</ErrorCode></Auth>";
        assert!(keepalive_body_is_success(success));
        assert!(!keepalive_body_is_success(failure));
        assert!(!keepalive_body_is_success("not xml"));
    }

    #[test]
    fn splits_line_hosts_and_ports() {
        assert_eq!(
            split_host_port("vpn.example.edu:443").unwrap(),
            ("vpn.example.edu".into(), 443)
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".into(), 443)
        );
        assert!(split_host_port("no-port").is_err());
    }
}
