use std::collections::HashMap;

use rand::rngs::OsRng;
use reqwest::Client;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};

use crate::{Challenge, ChallengeHandler, Config, Error};

use super::USER_AGENT;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthResult {
    pub twf_id: String,
    pub server_version: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NextAuthentication {
    None,
    Sms,
    Totp,
    Certificate,
}

struct LoginParameters {
    twf_id: String,
    rsa_modulus: BigUint,
    rsa_exponent: BigUint,
    csrf_code: Option<String>,
    captcha: bool,
    server_version: Option<String>,
}

pub(super) async fn authenticate(
    http: &Client,
    config: &Config,
    challenges: &dyn ChallengeHandler,
) -> Result<AuthResult, Error> {
    let base = format!("https://{}", config.server_host());
    let initial = http
        .get(format!("{base}/por/login_auth.csp?apiversion=1"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let parameters = parse_login_parameters(&initial)?;

    let mut captcha_code = String::new();
    if parameters.captcha {
        let image = http
            .get(format!("{base}/por/rand_code.csp?apiversion=1"))
            .header("Cookie", format!("TWFID={}", parameters.twf_id))
            .header("User-Agent", USER_AGENT)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?
            .to_vec();
        if let Some(path) = &config.graph_code_file {
            tokio::fs::write(path, &image).await?;
        }
        captcha_code = challenges.answer(Challenge::Captcha { image }).await?;
    }

    let password = match &parameters.csrf_code {
        Some(csrf) => format!("{}_{csrf}", config.password),
        None => config.password.clone(),
    };
    let key = RsaPublicKey::new(parameters.rsa_modulus, parameters.rsa_exponent)
        .map_err(|error| Error::Protocol(format!("invalid gateway RSA key: {error}")))?;
    let encrypted_password = key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, password.as_bytes())
        .map_err(|error| Error::Protocol(format!("password encryption failed: {error}")))?;

    let form = HashMap::from([
        ("svpn_rand_code", captcha_code),
        ("mitm", String::new()),
        (
            "svpn_req_randcode",
            parameters.csrf_code.clone().unwrap_or_default(),
        ),
        ("svpn_name", config.username.clone()),
        ("svpn_password", hex::encode(encrypted_password)),
    ]);
    let response = http
        .post(format!(
            "{base}/por/login_psw.csp?anti_replay=1&encrypt=1&type=cs"
        ))
        .header("Cookie", format!("TWFID={}", parameters.twf_id))
        .header("User-Agent", USER_AGENT)
        .form(&form)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let next = parse_password_response(&response)?;
    let mut twf_id = xml_text(&response, "TwfID").unwrap_or(parameters.twf_id);
    match next {
        NextAuthentication::None => {}
        NextAuthentication::Sms => {
            twf_id = login_sms(http, &base, &twf_id, challenges).await?;
        }
        NextAuthentication::Totp => {
            twf_id = login_totp(http, &base, &twf_id, challenges).await?;
        }
        NextAuthentication::Certificate => {
            return Err(Error::UnsupportedAuthentication(
                "EasyConnect PKCS#12 client-certificate login".into(),
            ));
        }
    }

    Ok(AuthResult {
        twf_id,
        server_version: parameters.server_version,
    })
}

fn parse_login_parameters(xml: &str) -> Result<LoginParameters, Error> {
    let twf_id = required_xml_text(xml, "TwfID")?;
    let modulus = required_xml_text(xml, "RSA_ENCRYPT_KEY")?;
    let exponent = xml_text(xml, "RSA_ENCRYPT_EXP").unwrap_or_else(|| "65537".into());
    let rsa_modulus = BigUint::parse_bytes(modulus.as_bytes(), 16)
        .ok_or_else(|| Error::Protocol("gateway sent an invalid RSA modulus".into()))?;
    let rsa_exponent = BigUint::parse_bytes(exponent.as_bytes(), 10)
        .ok_or_else(|| Error::Protocol("gateway sent an invalid RSA exponent".into()))?;
    Ok(LoginParameters {
        twf_id,
        rsa_modulus,
        rsa_exponent,
        csrf_code: xml_text(xml, "CSRF_RAND_CODE"),
        captcha: xml_text(xml, "RndImg").as_deref() == Some("1"),
        server_version: xml_text(xml, "VPNVERSION"),
    })
}

fn parse_password_response(xml: &str) -> Result<NextAuthentication, Error> {
    let next_service = xml_text(xml, "NextService");
    let next_auth = xml_text(xml, "NextAuth");
    if next_service.as_deref() == Some("auth/sms") || next_auth.as_deref() == Some("2") {
        return Ok(NextAuthentication::Sms);
    }
    if next_service.as_deref() == Some("auth/token") || next_auth.as_deref() == Some("7") {
        return Ok(NextAuthentication::Totp);
    }
    if next_auth.as_deref() == Some("0") {
        return Ok(NextAuthentication::Certificate);
    }
    if next_auth.as_deref().is_some_and(|value| value != "-1") {
        return Err(Error::UnsupportedAuthentication(format!(
            "EasyConnect NextAuth={}",
            next_auth.unwrap_or_default()
        )));
    }
    if xml_text(xml, "Result").as_deref() != Some("1") {
        return Err(Error::Authentication(xml.to_owned()));
    }
    Ok(NextAuthentication::None)
}

async fn login_sms(
    http: &Client,
    base: &str,
    twf_id: &str,
    challenges: &dyn ChallengeHandler,
) -> Result<String, Error> {
    let request_body = http
        .post(format!("{base}/por/login_sms.csp?apiversion=1"))
        .header("Cookie", format!("TWFID={twf_id}"))
        .header("User-Agent", USER_AGENT)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    if !(request_body.contains("<USER_PHONE>")
        || request_body.contains("验证码已发送到您的手机")
        || request_body.contains("请输入验证码："))
    {
        return Err(Error::Protocol(format!(
            "unexpected SMS request response: {request_body}"
        )));
    }
    let code = challenges.answer(Challenge::SmsCode).await?;
    let response = http
        .post(format!("{base}/por/login_sms1.csp?apiversion=1"))
        .header("Cookie", format!("TWFID={twf_id}"))
        .header("User-Agent", USER_AGENT)
        .form(&[("svpn_inputsms", code)])
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    if !response.contains("Auth sms suc") && !response.contains("欢迎访问") {
        return Err(Error::Authentication(response));
    }
    Ok(xml_text(&response, "TwfID").unwrap_or_else(|| twf_id.to_owned()))
}

async fn login_totp(
    http: &Client,
    base: &str,
    twf_id: &str,
    challenges: &dyn ChallengeHandler,
) -> Result<String, Error> {
    let code = challenges.answer(Challenge::TotpCode).await?;
    let response = http
        .post(format!("{base}/por/login_token.csp"))
        .header("Cookie", format!("TWFID={twf_id}"))
        .header("User-Agent", USER_AGENT)
        .form(&[("svpn_inputtoken", code)])
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    if !response.contains("Totp auth succ") {
        return Err(Error::Authentication(response));
    }
    xml_text(&response, "TwfID")
        .ok_or_else(|| Error::Protocol("TOTP response did not contain TwfID".into()))
}

fn required_xml_text(xml: &str, name: &str) -> Result<String, Error> {
    xml_text(xml, name)
        .ok_or_else(|| Error::Protocol(format!("gateway response did not contain <{name}>")))
}

fn xml_text(xml: &str, name: &str) -> Option<String> {
    let document = roxmltree::Document::parse(xml).ok()?;
    document
        .descendants()
        .find(|node| node.has_tag_name(name))
        .and_then(|node| node.text())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_login_parameters_with_default_exponent() {
        let modulus = "C1".repeat(128);
        let xml = format!(
            "<Auth><TwfID>session</TwfID><RSA_ENCRYPT_KEY>{modulus}</RSA_ENCRYPT_KEY><RndImg>1</RndImg><VPNVERSION>7.6</VPNVERSION></Auth>"
        );
        let parsed = parse_login_parameters(&xml).unwrap();
        assert_eq!(parsed.twf_id, "session");
        assert!(parsed.captcha);
        assert_eq!(parsed.rsa_exponent, BigUint::from(65_537_u32));
    }

    #[test]
    fn recognizes_follow_up_authentication() {
        assert_eq!(
            parse_password_response("<Auth><NextService>auth/sms</NextService></Auth>").unwrap(),
            NextAuthentication::Sms
        );
        assert_eq!(
            parse_password_response("<Auth><NextAuth>7</NextAuth></Auth>").unwrap(),
            NextAuthentication::Totp
        );
    }

    #[test]
    fn rejects_a_failed_password_response() {
        assert!(parse_password_response("<Auth><Result>0</Result></Auth>").is_err());
    }
}
