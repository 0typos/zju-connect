use std::{collections::BTreeMap, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::{RngCore as _, rngs::OsRng};
use reqwest::{Client, Url, cookie::CookieStore as _};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey, traits::PublicKeyParts as _};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Challenge, ChallengeHandler, Config, Error};

pub const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.4.10.50 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType";
const MAX_AUTH_STEPS: usize = 8;
const MAX_CAPTCHA_ATTEMPTS: usize = 5;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthInfo {
    pub login_domain: String,
    pub auth_type: String,
    pub auth_name: String,
    pub login_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthResult {
    pub username: String,
    pub sid: String,
    pub device_id: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct AuthStepData {
    next_service: String,
    next_service_list: Vec<AuthService>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct AuthService {
    auth_id: String,
    auth_type: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct AuthStep {
    service: String,
    auth_id: String,
}

impl From<AuthStepData> for AuthStep {
    fn from(data: AuthStepData) -> Self {
        let selected = data
            .next_service_list
            .iter()
            .find(|candidate| candidate.auth_type == data.next_service)
            .or_else(|| data.next_service_list.first());
        let mut service = data.next_service;
        let mut auth_id = String::new();
        if let Some(selected) = selected {
            auth_id.clone_from(&selected.auth_id);
            if service.is_empty()
                || (service == "auth/token"
                    && matches!(
                        selected.auth_type.as_str(),
                        "auth/totp" | "auth/radius" | "auth/challenge"
                    ))
            {
                service.clone_from(&selected.auth_type);
            }
        }
        if service == "auth/sendSms" || (service.is_empty() && !auth_id.is_empty()) {
            service = "auth/sms".into();
        }
        Self { service, auth_id }
    }
}

pub(super) struct AuthSession {
    http: Client,
    cookies: Arc<reqwest::cookie::Jar>,
    base: String,
    base_url: Url,
    rid: String,
    env: String,
    csrf: String,
    public_key: String,
    public_exponent: String,
    anti_replay: String,
    ticket: String,
    username: String,
    device_id: String,
}

impl AuthSession {
    pub(super) fn new(config: &Config, device_id: String) -> Result<Self, Error> {
        let gateway = authentication_host(config);
        let base = format!("https://{gateway}");
        let base_url = Url::parse(&base)
            .map_err(|error| Error::Config(format!("invalid aTrust gateway URL: {error}")))?;
        let cookies = Arc::new(reqwest::cookie::Jar::default());
        let http = Client::builder()
            .cookie_provider(Arc::clone(&cookies))
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(20))
            .build()?;
        Ok(Self {
            http,
            cookies,
            base,
            base_url,
            rid: BASE64.encode(gateway),
            env: BASE64.encode(format!(r#"{{"deviceId":"{device_id}"}}"#)),
            csrf: String::new(),
            public_key: String::new(),
            public_exponent: String::new(),
            anti_replay: String::new(),
            ticket: String::new(),
            username: String::new(),
            device_id,
        })
    }

    pub(super) async fn auth_info(&mut self) -> Result<(bool, Vec<AuthInfo>), Error> {
        self.auth_config(false, true).await
    }

    pub(super) async fn login(
        &mut self,
        config: &Config,
        challenges: &dyn ChallengeHandler,
    ) -> Result<AuthResult, Error> {
        let (already_logged_in, methods) = self.auth_config(false, true).await?;
        if !already_logged_in {
            let auth_type = config.auth_type.as_deref().unwrap_or("auth/psw");
            if auth_type != "auth/psw" {
                return Err(Error::UnsupportedAuthentication(format!(
                    "aTrust {auth_type}; the Rust client currently supports password login"
                )));
            }
            if !methods.iter().any(|method| {
                method.auth_type == auth_type && method.login_domain == config.login_domain
            }) {
                let available = methods
                    .iter()
                    .map(|method| format!("{}@{}", method.auth_type, method.login_domain))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(Error::Authentication(format!(
                    "aTrust login method {auth_type}@{} is unavailable; gateway offers: {available}",
                    config.login_domain
                )));
            }
            self.password_login(config, challenges).await?;
            self.report_environment().await?;
            self.continue_auth(challenges).await?;
        }

        let username = self.online_info().await?;
        let sid = self.sid_cookie().ok_or_else(|| {
            Error::Protocol("aTrust authentication completed without a sid cookie".into())
        })?;
        Ok(AuthResult {
            username,
            sid,
            device_id: self.device_id.clone(),
        })
    }

    pub(super) async fn client_resources(&self) -> Result<Vec<u8>, Error> {
        let body = json!({
            "resourceType": {
                "sdpPolicy": {},
                "appList": {},
                "favoriteAppList": {},
                "featureCenter": {},
                "uemSpace": {"params": {"action": "login"}}
            }
        });
        let response = self
            .headers(
                self.http
                    .post(self.endpoint("/controller/v1/user/clientResource")),
            )
            .query(&shared_params())
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.bytes().await?.to_vec())
    }

    async fn auth_config(
        &mut self,
        modified: bool,
        need_ticket: bool,
    ) -> Result<(bool, Vec<AuthInfo>), Error> {
        let mut query = shared_params();
        if modified {
            query.insert("mod", "1".into());
        }
        if need_ticket {
            query.insert("needTicket", "1".into());
        }
        let response: ApiResponse<AuthConfigData> = self
            .headers(
                self.http
                    .get(self.endpoint("/passport/v1/public/authConfig")),
            )
            .header("x-sdp-rid", &self.rid)
            .query(&query)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        response.ensure_success("authConfig")?;
        self.csrf = if response.data.csrf_token.is_empty() {
            response.data.security.csrf_token
        } else {
            response.data.csrf_token
        };
        self.public_key = response.data.public_key;
        self.public_exponent = response.data.public_exponent;
        self.anti_replay = response.data.anti_replay;
        Ok((
            response.data.is_login == 1,
            response.data.auth_server_info_list,
        ))
    }

    async fn password_login(
        &mut self,
        config: &Config,
        challenges: &dyn ChallengeHandler,
    ) -> Result<(), Error> {
        let mut captcha = String::new();
        for attempt in 0..=MAX_CAPTCHA_ATTEMPTS {
            let requires_captcha = self.submit_password(config, &captcha).await?;
            if !requires_captcha {
                return Ok(());
            }
            if attempt == MAX_CAPTCHA_ATTEMPTS {
                break;
            }
            let image = self.captcha().await?;
            if let Some(path) = &config.graph_code_file {
                tokio::fs::write(path, &image).await?;
            }
            self.auth_config(false, true).await?;
            captcha = challenges.answer(Challenge::Captcha { image }).await?;
        }
        Err(Error::Authentication(format!(
            "aTrust CAPTCHA failed after {MAX_CAPTCHA_ATTEMPTS} attempts"
        )))
    }

    async fn submit_password(&mut self, config: &Config, captcha: &str) -> Result<bool, Error> {
        let modulus = BigUint::parse_bytes(self.public_key.as_bytes(), 16)
            .ok_or_else(|| Error::Protocol("aTrust sent an invalid RSA modulus".into()))?;
        let exponent = BigUint::parse_bytes(self.public_exponent.as_bytes(), 10)
            .ok_or_else(|| Error::Protocol("aTrust sent an invalid RSA exponent".into()))?;
        let key = RsaPublicKey::new(modulus, exponent)
            .map_err(|error| Error::Protocol(format!("invalid aTrust RSA key: {error}")))?;
        let encrypted = encrypt_password_chunks(
            &key,
            format!("{}_{}", config.password, self.anti_replay).as_bytes(),
        )?;
        self.username = format!("{}@{}", config.username, config.login_domain);
        let mut body = json!({
            "username": self.username,
            "password": hex::encode(encrypted),
            "rememberPwd": "0"
        });
        if !captcha.is_empty() {
            body["graphCheckCode"] = Value::String(captcha.to_owned());
        }
        let response: ApiResponse<PasswordData> = self
            .headers(self.http.post(self.endpoint("/passport/v1/auth/psw")))
            .header("x-sdp-env", &self.env)
            .query(&shared_params())
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if response.data.captcha_enabled == 1 {
            return Ok(true);
        }
        if response.code != 0 {
            return Err(Error::Authentication(format!(
                "aTrust password login failed with code {}: {}",
                response.code, response.message
            )));
        }
        if response.data.ticket.is_empty() {
            return Err(Error::Protocol(
                "aTrust password login succeeded without a ticket".into(),
            ));
        }
        self.ticket = response.data.ticket;
        Ok(false)
    }

    async fn report_environment(&self) -> Result<(), Error> {
        let body = json!({
            "ticket": self.ticket,
            "deviceId": self.device_id,
            "env": {"endpoint": {"device_id": self.device_id, "device": {"type": "browser"}}}
        });
        let response: ApiResponse<Value> = self
            .headers(
                self.http
                    .post(self.endpoint("/controller/v1/public/reportEnv")),
            )
            .query(&shared_params())
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        response.ensure_success("reportEnv")
    }

    async fn continue_auth(&mut self, challenges: &dyn ChallengeHandler) -> Result<(), Error> {
        let mut step = AuthStep {
            service: "auth/authCheck".into(),
            auth_id: String::new(),
        };
        for _ in 0..MAX_AUTH_STEPS {
            step = match step.service.as_str() {
                "" => return Ok(()),
                "auth/authCheck" => self.auth_check().await?,
                "auth/totp" => {
                    let token = challenges.answer(Challenge::TotpCode).await?;
                    self.submit_token(&token).await?
                }
                "auth/sms" => self.complete_sms(&step.auth_id, challenges).await?,
                "auth/accessCheck" => self.access_check().await?,
                service => {
                    return Err(Error::UnsupportedAuthentication(format!(
                        "aTrust continuation service {service}"
                    )));
                }
            };
        }
        Err(Error::Authentication(format!(
            "aTrust authentication exceeded {MAX_AUTH_STEPS} steps"
        )))
    }

    async fn auth_check(&self) -> Result<AuthStep, Error> {
        self.get_auth_step("/passport/v1/auth/authCheck", "authCheck")
            .await
    }

    async fn access_check(&self) -> Result<AuthStep, Error> {
        self.get_auth_step("/passport/v1/auth/accessCheck", "accessCheck")
            .await
    }

    async fn get_auth_step(&self, path: &str, operation: &str) -> Result<AuthStep, Error> {
        let response: ApiResponse<AuthStepData> = self
            .headers(self.http.get(self.endpoint(path)))
            .query(&shared_params())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        response.ensure_success(operation)?;
        Ok(response.data.into())
    }

    async fn submit_token(&self, token: &str) -> Result<AuthStep, Error> {
        let body = json!({
            "action": "auth",
            "totpToken": token,
            "isPrevEffect": false,
            "skipSecondaryAuth": 0,
            "username": self.username
        });
        let response: ApiResponse<AuthStepData> = self
            .headers(self.http.post(self.endpoint("/passport/v1/auth/token")))
            .header("x-sdp-env", &self.env)
            .query(&shared_params())
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        response.ensure_success("TOTP authentication")?;
        Ok(response.data.into())
    }

    async fn complete_sms(
        &mut self,
        auth_id: &str,
        challenges: &dyn ChallengeHandler,
    ) -> Result<AuthStep, Error> {
        if !auth_id.is_empty() {
            self.auth_config(true, true).await?;
        }
        let mut query = shared_params();
        query.insert("action", "sendsms".into());
        if !auth_id.is_empty() {
            query.insert("isPrevEffect", "0".into());
            query.insert("taskId", String::new());
            query.insert("authId", auth_id.into());
        }
        let sent: ApiResponse<Value> = self
            .headers(self.http.get(self.endpoint("/passport/v1/auth/sms")))
            .query(&query)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if sent.code != 0 && sent.code != 75_500_401 {
            return Err(Error::Authentication(format!(
                "aTrust SMS request failed with code {}: {}",
                sent.code, sent.message
            )));
        }
        if auth_id.is_empty() {
            self.auth_config(true, true).await?;
        }
        let code = challenges.answer(Challenge::SmsCode).await?;
        let mut check_query = shared_params();
        check_query.insert("action", "checkcode".into());
        let request = if auth_id.is_empty() {
            self.headers(self.http.post(self.endpoint("/passport/v1/auth/sms")))
                .query(&check_query)
                .form(&[("code", code.as_str()), ("skipSecondaryAuth", "0")])
        } else {
            self.headers(self.http.post(self.endpoint("/passport/v1/auth/sms")))
                .query(&check_query)
                .json(&json!({
                    "isPrevEffect": false,
                    "code": code,
                    "skipSecondaryAuth": "0",
                    "taskId": "",
                    "authId": auth_id
                }))
        };
        let response: ApiResponse<AuthStepData> =
            request.send().await?.error_for_status()?.json().await?;
        response.ensure_success("SMS authentication")?;
        Ok(response.data.into())
    }

    async fn online_info(&self) -> Result<String, Error> {
        let response: ApiResponse<OnlineInfo> = self
            .headers(self.http.get(self.endpoint("/passport/v1/user/onlineInfo")))
            .query(&shared_params())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        response.ensure_success("onlineInfo")?;
        if response.data.username.is_empty() {
            Err(Error::Protocol(
                "aTrust onlineInfo returned an empty username".into(),
            ))
        } else {
            Ok(response.data.username)
        }
    }

    async fn captcha(&self) -> Result<Vec<u8>, Error> {
        let mut query = shared_params();
        query.insert(
            "rnd",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .to_string(),
        );
        Ok(self
            .http
            .get(self.endpoint("/passport/v1/public/checkCode"))
            .header("User-Agent", USER_AGENT)
            .query(&query)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?
            .to_vec())
    }

    fn headers(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request
            .header("User-Agent", USER_AGENT)
            .header("x-csrf-token", &self.csrf)
            .header("x-sdp-traceid", random_hex(8, false))
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn sid_cookie(&self) -> Option<String> {
        self.cookies
            .cookies(&self.base_url)?
            .to_str()
            .ok()?
            .split(';')
            .filter_map(|cookie| cookie.trim().split_once('='))
            .find_map(|(name, value)| (name == "sid").then(|| value.to_owned()))
    }
}

fn authentication_host(config: &Config) -> String {
    if config.server_port == 443 {
        config.server_address.clone()
    } else {
        config.server_host()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct AuthConfigData {
    auth_server_info_list: Vec<AuthInfo>,
    is_login: i32,
    csrf_token: String,
    security: Security,
    #[serde(rename = "pubKey")]
    public_key: String,
    #[serde(rename = "pubKeyExp")]
    public_exponent: String,
    #[serde(rename = "antiReplayRand")]
    anti_replay: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Security {
    csrf_token: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct PasswordData {
    ticket: String,
    #[serde(rename = "graphCheckCodeEnable")]
    captcha_enabled: i32,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct OnlineInfo {
    username: String,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct ApiResponse<T: Default> {
    code: i64,
    message: String,
    data: T,
}

impl<T: Default> Default for ApiResponse<T> {
    fn default() -> Self {
        Self {
            code: 0,
            message: String::new(),
            data: T::default(),
        }
    }
}

impl<T: Default> ApiResponse<T> {
    fn ensure_success(&self, operation: &str) -> Result<(), Error> {
        if self.code == 0 {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "aTrust {operation} failed with code {}: {}",
                self.code, self.message
            )))
        }
    }
}

fn shared_params() -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("clientType", "SDPClient".into()),
        ("lang", "en-US".into()),
        ("platform", "Linux".into()),
    ])
}

fn encrypt_password_chunks(key: &RsaPublicKey, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let max_chunk = key
        .size()
        .checked_sub(11)
        .ok_or_else(|| Error::Protocol("aTrust RSA key is too small".into()))?;
    let mut encrypted = Vec::new();
    for chunk in plaintext.chunks(max_chunk) {
        encrypted.extend(
            key.encrypt(&mut OsRng, Pkcs1v15Encrypt, chunk)
                .map_err(|error| Error::Protocol(format!("password encryption failed: {error}")))?,
        );
    }
    Ok(encrypted)
}

pub(super) fn random_hex(length: usize, lowercase: bool) -> String {
    let mut bytes = vec![0_u8; length.div_ceil(2)];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut value = hex::encode(bytes);
    value.truncate(length);
    if lowercase {
        value.make_ascii_lowercase();
    } else {
        value.make_ascii_uppercase();
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_explicit_secondary_authentication_type() {
        let step = AuthStep::from(AuthStepData {
            next_service: "auth/token".into(),
            next_service_list: vec![AuthService {
                auth_id: "id".into(),
                auth_type: "auth/totp".into(),
            }],
        });
        assert_eq!(step.service, "auth/totp");
        assert_eq!(step.auth_id, "id");
    }

    #[test]
    fn shared_parameters_identify_linux_client() {
        let parameters = shared_params();
        assert_eq!(parameters["clientType"], "SDPClient");
        assert_eq!(parameters["platform"], "Linux");
    }

    #[test]
    fn random_identifiers_have_requested_shape() {
        let value = random_hex(64, false);
        assert_eq!(value.len(), 64);
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(value, value.to_ascii_uppercase());
    }

    #[test]
    fn default_tls_port_is_omitted_from_atrust_rid_host() {
        assert_eq!(authentication_host(&Config::default()), "rvpn.zju.edu.cn");
        let config = Config {
            server_port: 8443,
            ..Config::default()
        };
        assert_eq!(authentication_host(&config), "rvpn.zju.edu.cn:8443");
    }
}
