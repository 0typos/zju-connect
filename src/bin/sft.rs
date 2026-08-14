//! `sft` — the sangfordetunz control client.
//!
//! Talks to a running `sftd` over its Unix socket to bring profiles up and
//! down, query status, list profiles, and trigger a config reload. The
//! `check-config` subcommand validates a configuration file without a daemon.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sangfordetunz::{
    Error,
    config::{DEFAULT_SOCKET_PATH, DaemonConfig},
    control::{self, ConnectionState, ConnectionStatus, ProfileInfo, Request, Response},
};

#[derive(Parser)]
#[command(version, about = "sangfordetunz control client")]
struct Cli {
    /// Path to the daemon's control socket.
    #[arg(long, default_value = DEFAULT_SOCKET_PATH)]
    socket: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bring a profile up.
    Up { profile: String },
    /// Bring a profile down.
    Down { profile: String },
    /// Show the state of one profile, or of all active connections.
    Status { profile: Option<String> },
    /// List every configured profile.
    List,
    /// Ask the daemon to re-read its configuration file.
    Reload,
    /// Check that the daemon is responding.
    Ping,
    /// Validate a configuration file without contacting the daemon.
    CheckConfig {
        #[arg(default_value = "/etc/sangfordetunz/config.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("sft: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Error> {
    let cli = Cli::parse();

    // check-config runs locally and never touches the socket.
    if let Command::CheckConfig { config } = &cli.command {
        DaemonConfig::from_file(config).await?;
        println!("configuration is valid");
        return Ok(());
    }

    let request = match cli.command {
        Command::Up { profile } => Request::Up { profile },
        Command::Down { profile } => Request::Down { profile },
        Command::Status { profile } => Request::Status { profile },
        Command::List => Request::List,
        Command::Reload => Request::Reload,
        Command::Ping => Request::Ping,
        Command::CheckConfig { .. } => unreachable!("handled above"),
    };

    let response = control::send_request(&cli.socket, &request)
        .await
        .map_err(|error| {
            Error::Io(std::io::Error::other(format!(
                "could not reach sftd at {}: {error}",
                cli.socket
            )))
        })?;
    render(&response);
    Ok(())
}

/// Print the response. A daemon-side error is shown verbatim (it is already a
/// complete message) and exits non-zero.
fn render(response: &Response) {
    match response {
        Response::Ok { message } => println!("{message}"),
        Response::Status { connections } => print_status(connections),
        Response::Profiles { profiles } => print_profiles(profiles),
        Response::Error { message } => {
            eprintln!("sft: {message}");
            std::process::exit(1);
        }
    }
}

fn print_status(connections: &[ConnectionStatus]) {
    if connections.is_empty() {
        println!("no active connections");
        return;
    }
    println!("{:<16} {:<12} {:<16} UPTIME", "PROFILE", "STATE", "ADDRESS");
    for connection in connections {
        let (state, address) = match &connection.state {
            ConnectionState::Connecting => ("connecting", String::new()),
            ConnectionState::Connected { client_ip } => ("connected", client_ip.to_string()),
            ConnectionState::Failed { .. } => ("failed", String::new()),
            ConnectionState::Down => ("down", String::new()),
        };
        println!(
            "{:<16} {:<12} {:<16} {}",
            connection.profile,
            state,
            address,
            format_uptime(connection.uptime_seconds),
        );
        if let ConnectionState::Failed { error } = &connection.state {
            println!("    error: {error}");
        }
    }
}

fn print_profiles(profiles: &[ProfileInfo]) {
    if profiles.is_empty() {
        println!("no profiles configured");
        return;
    }
    println!(
        "{:<16} {:<12} {:<28} {:<8} AUTOSTART",
        "PROFILE", "PROTOCOL", "SERVER", "ACTIVE"
    );
    for profile in profiles {
        println!(
            "{:<16} {:<12} {:<28} {:<8} {}",
            profile.name,
            profile.protocol,
            profile.server,
            if profile.active { "yes" } else { "no" },
            if profile.autostart { "yes" } else { "no" },
        );
    }
}

fn format_uptime(seconds: u64) -> String {
    let (hours, minutes, seconds) = (seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    if hours > 0 {
        format!("{hours}h{minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m{seconds}s")
    } else {
        format!("{seconds}s")
    }
}
