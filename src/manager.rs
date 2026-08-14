//! Supervises the daemon's named VPN connections.
//!
//! Each connection runs as its own task with a cancellation channel and a
//! shared [`StatusHandle`]. The manager brings connections up and down and
//! reports their state; the connection-running logic itself is injected, so
//! the supervisor can be tested without a real gateway.

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use tokio::{sync::watch, task::JoinHandle};

use crate::{
    Config, Error,
    control::{ConnectionState, ConnectionStatus},
    runner::{self, Cancel, StatusHandle},
};

/// How long a connection may take to shut down gracefully before it is aborted.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

type RunFuture = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

/// Runs one connection to completion. Injected so tests can supply a fake.
pub type Runner = Arc<dyn Fn(Config, String, Cancel, StatusHandle) -> RunFuture + Send + Sync>;

struct ManagedConnection {
    cancel: watch::Sender<bool>,
    status: StatusHandle,
    handle: JoinHandle<()>,
    started: SystemTime,
}

/// Owns the set of active connections and mediates control commands.
pub struct ConnectionManager {
    connections: Mutex<BTreeMap<String, ManagedConnection>>,
    runner: Runner,
}

impl ConnectionManager {
    #[must_use]
    pub fn new(runner: Runner) -> Self {
        Self {
            connections: Mutex::new(BTreeMap::new()),
            runner,
        }
    }

    /// A manager whose connections run the real VPN engine, answering TOTP from
    /// each profile's `totp_secret` and rejecting interactive challenges.
    #[must_use]
    pub fn with_default_runner() -> Self {
        Self::new(Arc::new(|config: Config, profile, cancel, status| {
            Box::pin(async move {
                let challenges = Arc::new(runner::NonInteractiveChallenges::new(
                    config.totp_secret.clone(),
                ));
                runner::run_connection(config, &profile, challenges, cancel, &status).await
            })
        }))
    }

    /// Bring a profile up. Errors if it is already connecting or connected.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if a connection for `name` is already active.
    pub fn up(&self, name: &str, config: Config) -> Result<(), Error> {
        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = connections.get(name) {
            match existing.status.get() {
                ConnectionState::Connecting | ConnectionState::Connected { .. } => {
                    return Err(Error::Config(format!("{name} is already up")));
                }
                // A finished connection lingers only for status; replace it.
                ConnectionState::Down | ConnectionState::Failed { .. } => {
                    connections.remove(name);
                }
            }
        }

        let status = StatusHandle::new();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let runner = Arc::clone(&self.runner);
        let task_status = status.clone();
        let profile = name.to_owned();
        let handle = tokio::spawn(async move {
            let result = runner(config, profile.clone(), cancel_rx, task_status.clone()).await;
            match result {
                Ok(()) => task_status.set(ConnectionState::Down),
                Err(error) => {
                    tracing::warn!(profile, %error, "connection stopped with an error");
                    task_status.set(ConnectionState::Failed {
                        error: error.to_string(),
                    });
                }
            }
        });

        connections.insert(
            name.to_owned(),
            ManagedConnection {
                cancel: cancel_tx,
                status,
                handle,
                started: SystemTime::now(),
            },
        );
        Ok(())
    }

    /// Bring a profile down, waiting for a graceful stop before aborting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if no connection for `name` is running.
    pub async fn down(&self, name: &str) -> Result<(), Error> {
        let connection = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(name);
        let Some(connection) = connection else {
            return Err(Error::Config(format!("{name} is not running")));
        };
        let _ = connection.cancel.send(true);
        let abort = connection.handle.abort_handle();
        if tokio::time::timeout(SHUTDOWN_GRACE, connection.handle)
            .await
            .is_err()
        {
            tracing::warn!(
                name,
                "connection did not stop within grace period; aborting"
            );
            abort.abort();
        }
        Ok(())
    }

    /// Stop every connection concurrently (used on daemon shutdown).
    pub async fn shutdown_all(&self) {
        let names: Vec<String> = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        for name in names {
            let _ = self.down(&name).await;
        }
    }

    /// Status of one connection, or of all connections when `name` is `None`.
    #[must_use]
    pub fn status(&self, name: Option<&str>) -> Vec<ConnectionStatus> {
        let connections = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        connections
            .iter()
            .filter(|(key, _)| name.is_none_or(|wanted| wanted == key.as_str()))
            .map(|(profile, connection)| ConnectionStatus {
                profile: profile.clone(),
                state: connection.status.get(),
                uptime_seconds: connection
                    .started
                    .elapsed()
                    .map_or(0, |elapsed| elapsed.as_secs()),
            })
            .collect()
    }

    /// Whether a connection for `name` is currently connecting or connected.
    #[must_use]
    pub fn is_active(&self, name: &str) -> bool {
        self.connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .is_some_and(|connection| {
                matches!(
                    connection.status.get(),
                    ConnectionState::Connecting | ConnectionState::Connected { .. }
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A runner that reports Connected and then waits for cancellation.
    fn parking_runner() -> Runner {
        Arc::new(|_config, _profile, mut cancel, status| {
            Box::pin(async move {
                status.set(ConnectionState::Connected {
                    client_ip: "10.0.0.1".parse().unwrap(),
                });
                let _ = cancel.wait_for(|stop| *stop).await;
                Ok(())
            })
        })
    }

    #[tokio::test]
    async fn up_then_down_transitions_state() {
        let manager = ConnectionManager::new(parking_runner());
        manager.up("zju", Config::default()).unwrap();

        // The spawned task sets Connected; wait for that specific state.
        for _ in 0..1000 {
            if matches!(
                manager.status(Some("zju")).first().map(|c| &c.state),
                Some(ConnectionState::Connected { .. })
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
        let status = manager.status(Some("zju"));
        assert_eq!(status.len(), 1);
        assert!(matches!(status[0].state, ConnectionState::Connected { .. }));

        // A second up on an active profile is rejected.
        assert!(manager.up("zju", Config::default()).is_err());

        manager.down("zju").await.unwrap();
        assert!(manager.status(None).is_empty());
        assert!(manager.down("zju").await.is_err());
    }

    #[tokio::test]
    async fn failed_connection_reports_failure_and_can_restart() {
        let runner: Runner = Arc::new(|_config, _profile, _cancel, _status| {
            Box::pin(async move { Err(Error::Authentication("bad password".into())) })
        });
        let manager = ConnectionManager::new(runner);
        manager.up("zju", Config::default()).unwrap();

        for _ in 0..100 {
            if matches!(
                manager.status(Some("zju")).first().map(|c| &c.state),
                Some(ConnectionState::Failed { .. })
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
        let status = manager.status(Some("zju"));
        assert!(matches!(status[0].state, ConnectionState::Failed { .. }));
        assert!(!manager.is_active("zju"));

        // A failed connection can be replaced by a new `up`.
        manager.up("zju", Config::default()).unwrap();
    }
}
