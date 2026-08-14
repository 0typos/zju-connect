//! `sftd` — the sangfordetunz VPN daemon.
//!
//! Loads a TOML configuration of named connection profiles, autostarts the
//! ones flagged for it, and serves control commands from `sft` over a Unix
//! socket until it receives SIGINT or SIGTERM.

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use clap::Parser;
use sangfordetunz::{
    Error,
    config::DaemonConfig,
    control::{self, ProfileInfo, Request, Response},
    manager::ConnectionManager,
    shutdown_signal,
};
use tokio::{
    io::BufReader,
    net::{UnixListener, UnixStream},
};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "sangfordetunz VPN daemon")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "/etc/sangfordetunz/config.toml")]
    config: PathBuf,

    /// Override the control socket path from the configuration file.
    #[arg(long)]
    socket: Option<String>,

    /// Enable debug logging.
    #[arg(long, short)]
    verbose: bool,
}

struct Daemon {
    manager: ConnectionManager,
    config: RwLock<DaemonConfig>,
    config_path: PathBuf,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("sftd: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Error> {
    let cli = Cli::parse();
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .with_target(false)
        .init();

    let config = DaemonConfig::from_file(&cli.config).await?;
    let socket_path = cli.socket.unwrap_or_else(|| config.daemon.socket.clone());

    let daemon = Arc::new(Daemon {
        manager: ConnectionManager::with_default_runner(),
        config: RwLock::new(config),
        config_path: cli.config,
    });

    autostart(&daemon);

    // Remove a stale socket from a previous run before binding.
    let _ = std::fs::remove_file(&socket_path);
    if let Some(parent) = std::path::Path::new(&socket_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!(socket = %socket_path, "sftd is listening for client commands");

    let result = accept_loop(&listener, &daemon).await;

    tracing::info!("shutting down; bringing all connections down");
    daemon.manager.shutdown_all().await;
    let _ = std::fs::remove_file(&socket_path);
    result
}

fn autostart(daemon: &Arc<Daemon>) {
    let profiles: Vec<(String, _)> = {
        let config = daemon
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        config
            .profiles
            .iter()
            .filter(|(_, profile)| profile.autostart)
            .map(|(name, profile)| (name.clone(), profile.clone()))
            .collect()
    };
    for (name, profile) in profiles {
        match daemon.manager.up(&name, profile) {
            Ok(()) => tracing::info!(profile = name, "autostarting profile"),
            Err(error) => tracing::warn!(profile = name, %error, "could not autostart profile"),
        }
    }
}

async fn accept_loop(listener: &UnixListener, daemon: &Arc<Daemon>) -> Result<(), Error> {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let daemon = Arc::clone(daemon);
                        tokio::spawn(async move { serve_client(stream, &daemon).await; });
                    }
                    Err(error) => tracing::warn!(%error, "control socket accept failed"),
                }
            }
            result = shutdown_signal() => return result,
        }
    }
}

async fn serve_client(stream: UnixStream, daemon: &Arc<Daemon>) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let response = match control::read_request(&mut reader).await {
        Ok(Some(request)) => dispatch(request, daemon).await,
        Ok(None) => return,
        Err(error) => Response::error(error.to_string()),
    };
    if let Err(error) = control::write_response(&mut write_half, &response).await {
        tracing::debug!(%error, "could not send control response");
    }
}

/// Render an error for the client without the `Error` variant's Display prefix,
/// which reads oddly for the daemon's operational messages.
fn message(error: &Error) -> String {
    match error {
        Error::Config(text) => text.clone(),
        other => other.to_string(),
    }
}

async fn dispatch(request: Request, daemon: &Arc<Daemon>) -> Response {
    match request {
        Request::Up { profile } => {
            let config = daemon
                .config
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .profile(&profile)
                .cloned();
            match config {
                Ok(config) => match daemon.manager.up(&profile, config) {
                    Ok(()) => Response::ok(format!("{profile} is coming up")),
                    Err(error) => Response::error(message(&error)),
                },
                Err(error) => Response::error(message(&error)),
            }
        }
        Request::Down { profile } => match daemon.manager.down(&profile).await {
            Ok(()) => Response::ok(format!("{profile} is down")),
            Err(error) => Response::error(message(&error)),
        },
        Request::Status { profile } => Response::Status {
            connections: daemon.manager.status(profile.as_deref()),
        },
        Request::List => Response::Profiles {
            profiles: list_profiles(daemon),
        },
        Request::Reload => match DaemonConfig::from_file(&daemon.config_path).await {
            Ok(config) => {
                *daemon
                    .config
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = config;
                Response::ok("configuration reloaded")
            }
            Err(error) => Response::error(error.to_string()),
        },
        Request::Ping => Response::ok("pong"),
    }
}

fn list_profiles(daemon: &Arc<Daemon>) -> Vec<ProfileInfo> {
    let config = daemon
        .config
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    config
        .profiles
        .iter()
        .map(|(name, profile)| ProfileInfo {
            name: name.clone(),
            protocol: format!("{:?}", profile.protocol).to_lowercase(),
            server: format!("{}:{}", profile.server_address, profile.server_port),
            active: daemon.manager.is_active(name),
            autostart: profile.autostart,
        })
        .collect()
}
