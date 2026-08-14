//! Control protocol between the `sft` client and the `sftd` daemon.
//!
//! Each client connection carries a single newline-delimited JSON [`Request`]
//! and receives a single newline-delimited JSON [`Response`]. The framing
//! helpers here are shared by both binaries; request dispatch lives in the
//! daemon, which owns the connection state.

use std::{net::IpAddr, path::Path};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader},
    net::UnixStream,
};

use crate::Error;

/// A command sent from `sft` to `sftd`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Request {
    /// Bring the named profile up.
    Up { profile: String },
    /// Bring the named profile down.
    Down { profile: String },
    /// Report the state of one profile, or all active connections.
    Status { profile: Option<String> },
    /// List every configured profile and whether it is active.
    List,
    /// Re-read the daemon configuration file.
    Reload,
    /// Liveness check.
    Ping,
}

/// The daemon's reply to a [`Request`].
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    /// The command succeeded; `message` is a human-readable summary.
    Ok { message: String },
    /// State of the requested connection(s).
    Status { connections: Vec<ConnectionStatus> },
    /// Every configured profile.
    Profiles { profiles: Vec<ProfileInfo> },
    /// The command failed; `message` explains why.
    Error { message: String },
}

impl Response {
    pub fn ok(message: impl Into<String>) -> Self {
        Self::Ok {
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

/// The lifecycle state of a managed connection.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectionState {
    /// Authenticating and establishing the data plane.
    Connecting,
    /// Established; carrying traffic with the given virtual IP.
    Connected { client_ip: IpAddr },
    /// Stopped after an error.
    Failed { error: String },
    /// Stopped cleanly.
    Down,
}

/// A connection's profile name, state, and uptime.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConnectionStatus {
    pub profile: String,
    pub state: ConnectionState,
    pub uptime_seconds: u64,
}

/// A configured profile and whether it currently has an active connection.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProfileInfo {
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub active: bool,
    pub autostart: bool,
}

/// Send one request to the daemon and read its response.
///
/// # Errors
///
/// Returns an I/O error if the socket cannot be reached, or a protocol error
/// if the daemon's reply is missing or malformed.
pub async fn send_request(socket: impl AsRef<Path>, request: &Request) -> Result<Response, Error> {
    let stream = UnixStream::connect(socket.as_ref()).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut line = serde_json::to_string(request)
        .map_err(|error| Error::Protocol(format!("cannot encode control request: {error}")))?;
    line.push('\n');
    write_half.write_all(line.as_bytes()).await?;
    write_half.flush().await?;

    let mut reader = BufReader::new(read_half);
    let mut response = String::new();
    if reader.read_line(&mut response).await? == 0 {
        return Err(Error::Protocol("daemon closed the connection".into()));
    }
    serde_json::from_str(response.trim_end())
        .map_err(|error| Error::Protocol(format!("invalid control response: {error}")))
}

/// Read one newline-delimited request from a client connection.
///
/// # Errors
///
/// Returns an I/O error, or a protocol error if the line is not a valid request.
/// Returns `Ok(None)` if the client closed without sending anything.
pub async fn read_request<R>(reader: &mut R) -> Result<Option<Request>, Error>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(None);
    }
    let request = serde_json::from_str(line.trim_end())
        .map_err(|error| Error::Protocol(format!("invalid control request: {error}")))?;
    Ok(Some(request))
}

/// Write one newline-delimited response to a client connection.
///
/// # Errors
///
/// Returns an I/O error, or a protocol error if the response cannot be encoded.
pub async fn write_response<W>(writer: &mut W, response: &Response) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_string(response)
        .map_err(|error| Error::Protocol(format!("cannot encode control response: {error}")))?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_through_json() {
        let cases = [
            Request::Up {
                profile: "zju".into(),
            },
            Request::Down {
                profile: "work".into(),
            },
            Request::Status {
                profile: Some("zju".into()),
            },
            Request::Status { profile: None },
            Request::List,
            Request::Reload,
            Request::Ping,
        ];
        for request in cases {
            let encoded = serde_json::to_string(&request).unwrap();
            let decoded: Request = serde_json::from_str(&encoded).unwrap();
            assert_eq!(request, decoded);
        }
    }

    #[test]
    fn responses_round_trip_through_json() {
        let response = Response::Status {
            connections: vec![ConnectionStatus {
                profile: "zju".into(),
                state: ConnectionState::Connected {
                    client_ip: "10.0.0.5".parse().unwrap(),
                },
                uptime_seconds: 42,
            }],
        };
        let encoded = serde_json::to_string(&response).unwrap();
        let decoded: Response = serde_json::from_str(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[tokio::test]
    async fn framing_reads_one_request_per_line() {
        let mut input = "{\"command\":\"up\",\"profile\":\"zju\"}\n".as_bytes();
        let request = read_request(&mut input).await.unwrap();
        assert_eq!(
            request,
            Some(Request::Up {
                profile: "zju".into()
            })
        );

        let mut output = Vec::new();
        write_response(&mut output, &Response::ok("up"))
            .await
            .unwrap();
        assert!(output.ends_with(b"\n"));
        let decoded: Response = serde_json::from_slice(&output[..output.len() - 1]).unwrap();
        assert_eq!(decoded, Response::ok("up"));
    }
}
