//! Multi-switch lifecycle management for controller deployments.
//!
//! [`Connection`] remains the single-switch wire API. [`ConnectionManager`]
//! adds endpoint ownership, automatic reconnect, exponential backoff, and a
//! safe-operation retry boundary without retrying arbitrary mutating frames.

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex, Notify};

use super::{Connection, Error as ConnectionError, Result as ConnectionResult};
use crate::protocol::codec::Encoder;
use crate::protocol::control::Property;
use crate::protocol::message::Message;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A stream that can carry a managed `OpenFlow` connection.
pub trait ManagedStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ManagedStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A type-erased stream used by [`ConnectionManager`].
pub type BoxedStream = Box<dyn ManagedStream>;

/// A boxed connection factory future.
pub type ConnectorFuture<'a> =
    Pin<Box<dyn Future<Output = ConnectionResult<BoxedStream>> + Send + 'a>>;

/// A factory for creating a fresh transport connection to one switch.
pub trait Connector: Send + Sync {
    /// Open one transport stream. The manager performs the `OpenFlow` handshake
    /// after this future succeeds.
    fn connect(&self) -> ConnectorFuture<'_>;
}

/// A TCP endpoint connector.
#[derive(Debug, Clone)]
pub struct TcpConnector {
    address: String,
}

impl TcpConnector {
    /// Create a connector for a TCP address such as `127.0.0.1:6653`.
    #[must_use]
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
        }
    }
}

impl Connector for TcpConnector {
    fn connect(&self) -> ConnectorFuture<'_> {
        Box::pin(async move {
            let stream =
                tokio::time::timeout(DEFAULT_CONNECT_TIMEOUT, TcpStream::connect(&self.address))
                    .await
                    .map_err(|_| connection_timeout("TCP connect"))??;
            Ok(Box::new(stream) as BoxedStream)
        })
    }
}

/// A Unix-domain socket endpoint connector.
#[derive(Debug, Clone)]
pub struct UnixConnector {
    path: PathBuf,
}

impl UnixConnector {
    /// Create a connector for a Unix socket path.
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
        }
    }
}

impl Connector for UnixConnector {
    fn connect(&self) -> ConnectorFuture<'_> {
        Box::pin(async move {
            let stream =
                tokio::time::timeout(DEFAULT_CONNECT_TIMEOUT, UnixStream::connect(&self.path))
                    .await
                    .map_err(|_| connection_timeout("Unix socket connect"))??;
            Ok(Box::new(stream) as BoxedStream)
        })
    }
}

/// A verified TLS-over-TCP endpoint connector.
#[cfg(feature = "tls")]
#[derive(Clone)]
pub struct TlsConnector {
    address: String,
    server_name: String,
    config: Arc<rustls::ClientConfig>,
}

#[cfg(feature = "tls")]
impl TlsConnector {
    /// Create a TLS connector with an application-supplied trust policy.
    #[must_use]
    pub fn new(
        address: impl Into<String>,
        server_name: impl Into<String>,
        config: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            address: address.into(),
            server_name: server_name.into(),
            config,
        }
    }
}

#[cfg(feature = "tls")]
impl Connector for TlsConnector {
    fn connect(&self) -> ConnectorFuture<'_> {
        Box::pin(async move {
            let stream =
                tokio::time::timeout(DEFAULT_CONNECT_TIMEOUT, TcpStream::connect(&self.address))
                    .await
                    .map_err(|_| connection_timeout("TLS TCP connect"))??;
            let stream =
                crate::tls::connect_transport(stream, &self.server_name, Arc::clone(&self.config))
                    .await?;
            Ok(Box::new(stream) as BoxedStream)
        })
    }
}

/// Configuration for [`ConnectionManager`].
#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct ManagerConfig {
    /// Maximum time allowed for transport setup and each `OpenFlow` handshake.
    pub handshake_timeout: Duration,
    /// Delay before the first reconnect attempt.
    pub initial_backoff: Duration,
    /// Maximum delay between reconnect attempts.
    pub max_backoff: Duration,
    /// Maximum time a managed operation waits for a connection.
    pub connect_wait_timeout: Duration,
    /// Maximum time allowed for one request or command operation.
    pub operation_timeout: Duration,
    /// Optional interval for a barrier keepalive while a switch is idle.
    /// `None` disables proactive idle probing.
    pub keepalive_interval: Option<Duration>,
    /// Number of retries for an explicitly safe operation after a transport
    /// failure. Mutating operations are never retried automatically.
    pub safe_operation_retries: usize,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            connect_wait_timeout: Duration::from_secs(30),
            operation_timeout: Duration::from_secs(30),
            keepalive_interval: Some(Duration::from_secs(30)),
            safe_operation_retries: 2,
        }
    }
}

/// Controller state to restore after each successful reconnect.
#[derive(Debug, Clone, Default)]
#[allow(clippy::module_name_repetitions)]
pub struct ReconnectPolicy {
    /// Optional switch configuration `(flags, miss_send_len)` to reapply.
    pub config: Option<(u16, u16)>,
    /// Optional asynchronous-event properties to reapply with `SET_ASYNC`.
    pub async_properties: Option<Vec<Property>>,
    /// Optional controller role to reclaim after reconnect.
    pub role: Option<RolePolicy>,
}

/// A controller role request restored by [`ReconnectPolicy`].
#[derive(Debug, Clone, Copy)]
pub struct RolePolicy {
    /// Requested `OFPCR_ROLE_*` value.
    pub role: u32,
    /// Controller short id.
    pub short_id: u16,
    /// Role generation id.
    pub generation_id: u64,
}

/// A stable identifier assigned to a managed switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwitchId(u64);

impl std::fmt::Display for SwitchId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "switch-{}", self.0)
    }
}

/// The current lifecycle state of one managed switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchStatus {
    /// The manager is attempting the initial connection or a reconnect.
    Connecting,
    /// The switch is connected and its `OpenFlow` handshake completed.
    Connected {
        /// Number of successful connections for this switch.
        generation: u64,
    },
    /// No connection is currently available; reconnect will continue in the
    /// background.
    Disconnected {
        /// The most recent connection error.
        error: String,
    },
    /// The switch was removed from the manager.
    Stopped,
}

/// A lifecycle notification emitted by [`ConnectionManager`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// A switch was registered.
    Added {
        /// The registered switch id.
        id: SwitchId,
        /// The caller-supplied display label.
        label: String,
    },
    /// A connection attempt started.
    Connecting {
        /// The affected switch id.
        id: SwitchId,
    },
    /// The `OpenFlow` handshake completed.
    Connected {
        /// The affected switch id.
        id: SwitchId,
        /// Number of successful connections for this switch.
        generation: u64,
    },
    /// A connection failed or was lost.
    Disconnected {
        /// The affected switch id.
        id: SwitchId,
        /// The connection error rendered for logs and status displays.
        error: String,
    },
    /// A switch was removed from the manager.
    Removed {
        /// The removed switch id.
        id: SwitchId,
    },
}

/// An error from a managed controller operation.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum ManagerError {
    /// The underlying connection or `OpenFlow` operation failed.
    Connection(ConnectionError),
    /// No switch with this id is registered.
    SwitchNotFound(SwitchId),
    /// The switch was stopped while an operation was waiting.
    Stopped,
    /// The operation waited longer than [`ManagerConfig::connect_wait_timeout`].
    ConnectTimeout,
    /// A request or command exceeded [`ManagerConfig::operation_timeout`].
    OperationTimeout,
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(error) => write!(formatter, "managed OpenFlow connection: {error}"),
            Self::SwitchNotFound(id) => write!(formatter, "unknown managed {id}"),
            Self::Stopped => formatter.write_str("managed switch is stopped"),
            Self::ConnectTimeout => {
                formatter.write_str("timed out waiting for a switch connection")
            }
            Self::OperationTimeout => {
                formatter.write_str("timed out waiting for an OpenFlow operation")
            }
        }
    }
}

impl std::error::Error for ManagerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            Self::SwitchNotFound(_)
            | Self::Stopped
            | Self::ConnectTimeout
            | Self::OperationTimeout => None,
        }
    }
}

impl From<ConnectionError> for ManagerError {
    fn from(value: ConnectionError) -> Self {
        Self::Connection(value)
    }
}

/// Result type for managed controller operations.
pub type Result<T> = std::result::Result<T, ManagerError>;

/// A future returned by an operation executed on a managed connection.
pub type OperationFuture<'a, T> = Pin<Box<dyn Future<Output = ConnectionResult<T>> + Send + 'a>>;

/// An asynchronous message emitted by a managed switch connection.
pub type MessageEvent = Arc<Message>;

type ErasedValue = Box<dyn Any + Send>;
type ErasedFuture<'a> = Pin<Box<dyn Future<Output = ConnectionResult<ErasedValue>> + Send + 'a>>;
type CommandOperation =
    Box<dyn for<'a> FnOnce(&'a mut Connection<BoxedStream>) -> ErasedFuture<'a> + Send>;

enum CommandError {
    Connection(ConnectionError),
    OperationTimeout,
}

type CommandResult = std::result::Result<ErasedValue, CommandError>;

enum Command {
    Operation {
        operation: CommandOperation,
        response: oneshot::Sender<CommandResult>,
    },
}

struct ManagedState {
    status: SwitchStatus,
    generation: u64,
    stopping: bool,
}

struct ManagedSwitch {
    id: SwitchId,
    label: String,
    connector: Arc<dyn Connector>,
    config: ManagerConfig,
    policy: ReconnectPolicy,
    state: Mutex<ManagedState>,
    changed: Notify,
    stop_notify: Notify,
    status: watch::Sender<SwitchStatus>,
    events: broadcast::Sender<LifecycleEvent>,
    messages: broadcast::Sender<MessageEvent>,
    commands: mpsc::Sender<Command>,
}

impl ManagedSwitch {
    async fn run(self: Arc<Self>, mut commands: mpsc::Receiver<Command>) {
        let mut backoff = self.config.initial_backoff;
        let mut connection = None;

        loop {
            if self.is_stopping().await {
                return;
            }

            if connection.is_none() && !self.ensure_connection(&mut connection, &mut backoff).await
            {
                continue;
            }

            if !self.run_connected(&mut connection, &mut commands).await {
                return;
            }
        }
    }

    async fn ensure_connection(
        &self,
        connection: &mut Option<Connection<BoxedStream>>,
        backoff: &mut Duration,
    ) -> bool {
        self.publish_status(
            SwitchStatus::Connecting,
            LifecycleEvent::Connecting { id: self.id },
        )
        .await;

        let result = tokio::select! {
            result = self.connect_and_handshake() => result,
            () = self.stop_notify.notified() => return false,
        };
        match result {
            Ok(connected) => {
                if !self.install_connection().await {
                    return false;
                }
                *connection = Some(connected);
                *backoff = self.config.initial_backoff;
                true
            }
            Err(error) => {
                self.publish_status(
                    SwitchStatus::Disconnected {
                        error: error.to_string(),
                    },
                    LifecycleEvent::Disconnected {
                        id: self.id,
                        error: error.to_string(),
                    },
                )
                .await;
                self.wait_backoff(*backoff).await;
                *backoff = next_backoff(*backoff, self.config.max_backoff);
                false
            }
        }
    }

    async fn run_connected(
        &self,
        connection: &mut Option<Connection<BoxedStream>>,
        commands: &mut mpsc::Receiver<Command>,
    ) -> bool {
        let Some(active) = connection.as_mut() else {
            return true;
        };

        tokio::select! {
            biased;
            message = active.recv_message() => {
                match message {
                    Ok(message) => self.dispatch_message(connection, message).await,
                    Err(error) => {
                        *connection = None;
                        self.publish_connection_loss(error.to_string()).await;
                    }
                }
                true
            }
            command = commands.recv() => self.handle_command(connection, command).await,
            () = self.keepalive() => {
                self.probe_connection(connection).await;
                true
            }
            () = self.stop_notify.notified() => {
                *connection = None;
                false
            }
        }
    }

    async fn keepalive(&self) {
        match self.config.keepalive_interval {
            Some(interval) => tokio::time::sleep(interval).await,
            None => std::future::pending::<()>().await,
        }
    }

    async fn probe_connection(&self, connection: &mut Option<Connection<BoxedStream>>) {
        let Some(active) = connection.as_mut() else {
            return;
        };
        if active.has_pending_commands() {
            return;
        }
        let result =
            tokio::time::timeout(self.config.operation_timeout, active.send_barrier()).await;
        let failure = match result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error.to_string()),
            Err(_) => Some("keepalive barrier timed out".to_owned()),
        };
        if let Some(error) = failure {
            *connection = None;
            self.publish_connection_loss(format!("idle OpenFlow keepalive failed: {error}"))
                .await;
        }
    }

    async fn dispatch_message(
        &self,
        connection: &mut Option<Connection<BoxedStream>>,
        message: Message,
    ) {
        if let Message::EchoRequest { xid, payload } = &message {
            let reply = match Encoder::echo_reply(*xid, payload) {
                Ok(reply) => reply,
                Err(error) => {
                    self.publish_connection_loss(error.to_string()).await;
                    return;
                }
            };
            let result = match connection.as_mut() {
                Some(active) => active.send_raw(&reply).await,
                None => return,
            };
            if let Err(error) = result {
                *connection = None;
                self.publish_connection_loss(error.to_string()).await;
                return;
            }
        }
        let _ = self.messages.send(Arc::new(message));
    }

    async fn handle_command(
        &self,
        connection: &mut Option<Connection<BoxedStream>>,
        command: Option<Command>,
    ) -> bool {
        match command {
            Some(Command::Operation {
                operation,
                mut response,
            }) => {
                if response.is_closed() {
                    *connection = None;
                    self.publish_connection_loss("managed operation cancelled".to_owned())
                        .await;
                    return true;
                }
                let result = {
                    let Some(active) = connection.as_mut() else {
                        return true;
                    };
                    tokio::select! {
                        result = tokio::time::timeout(self.config.operation_timeout, operation(active)) => {
                            result.map_or_else(
                                |_| Err(CommandError::OperationTimeout),
                                |result| result.map_err(CommandError::Connection),
                            )
                        }
                        () = response.closed() => {
                            *connection = None;
                            self.publish_connection_loss("managed operation cancelled".to_owned())
                                .await;
                            return true;
                        }
                        () = self.stop_notify.notified() => {
                            *connection = None;
                            let _ = response.send(Err(CommandError::Connection(
                                ConnectionError::Io(std::io::Error::new(
                                    std::io::ErrorKind::Interrupted,
                                    "managed switch stopped",
                                )),
                            )));
                            return false;
                        }
                    }
                };
                let transport_failure = matches!(
                    &result,
                    Err(CommandError::Connection(error)) if is_transport_failure(error)
                );
                let operation_timed_out = matches!(&result, Err(CommandError::OperationTimeout));
                let _ = response.send(result);
                if transport_failure || operation_timed_out {
                    *connection = None;
                    let reason = if operation_timed_out {
                        "managed operation timed out"
                    } else {
                        "managed operation lost its transport"
                    };
                    self.publish_connection_loss(reason.to_owned()).await;
                }
                true
            }
            None => false,
        }
    }

    async fn connect_and_handshake(&self) -> ConnectionResult<Connection<BoxedStream>> {
        let stream = tokio::time::timeout(self.config.handshake_timeout, self.connector.connect())
            .await
            .map_err(|_| connection_timeout("connector connection"))??;
        let mut connection = Connection::new(stream);
        connection
            .handshake_with_timeout(self.config.handshake_timeout)
            .await?;
        tokio::time::timeout(
            self.config.operation_timeout,
            self.restore_policy(&mut connection),
        )
        .await
        .map_err(|_| connection_timeout("reconnect policy"))??;
        Ok(connection)
    }

    async fn restore_policy(
        &self,
        connection: &mut Connection<BoxedStream>,
    ) -> ConnectionResult<()> {
        if let Some((flags, miss_send_len)) = self.policy.config {
            connection.set_config(flags, miss_send_len).await?;
        }
        if let Some(properties) = &self.policy.async_properties {
            connection.set_async(properties).await?;
        }
        if let Some(role) = self.policy.role {
            connection
                .request_role(role.role, role.short_id, role.generation_id)
                .await?;
        }
        Ok(())
    }

    async fn install_connection(&self) -> bool {
        let mut state = self.state.lock().await;
        if state.stopping {
            return false;
        }
        state.generation = state.generation.saturating_add(1);
        let generation = state.generation;
        state.status = SwitchStatus::Connected { generation };
        drop(state);
        let _ = self.status.send(SwitchStatus::Connected { generation });
        let _ = self.events.send(LifecycleEvent::Connected {
            id: self.id,
            generation,
        });
        self.changed.notify_waiters();
        true
    }

    async fn execute<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: Send
            + 'static
            + for<'a> FnOnce(&'a mut Connection<BoxedStream>) -> OperationFuture<'a, T>,
    {
        self.send_operation(operation).await
    }

    async fn execute_safe<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: Clone
            + Send
            + 'static
            + for<'a> Fn(&'a mut Connection<BoxedStream>) -> OperationFuture<'a, T>,
    {
        for attempt in 0..=self.config.safe_operation_retries {
            match self.send_operation(operation.clone()).await {
                Err(ManagerError::Connection(error))
                    if is_transport_failure(&error)
                        && attempt < self.config.safe_operation_retries =>
                {
                    self.wait_for_connection().await?;
                }
                result => return result,
            }
        }
        Err(ManagerError::ConnectTimeout)
    }

    async fn send_operation<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: Send
            + 'static
            + for<'a> FnOnce(&'a mut Connection<BoxedStream>) -> OperationFuture<'a, T>,
    {
        self.wait_for_connection().await?;
        let (response, result) = oneshot::channel();
        let command = Command::Operation {
            operation: Box::new(move |connection| {
                Box::pin(async move {
                    operation(connection)
                        .await
                        .map(|value| Box::new(value) as ErasedValue)
                })
            }),
            response,
        };
        let operation = async move {
            self.commands
                .send(command)
                .await
                .map_err(|_| ManagerError::Stopped)?;
            let value = match result.await.map_err(|_| ManagerError::Stopped)? {
                Ok(value) => value,
                Err(CommandError::Connection(error)) => return Err(error.into()),
                Err(CommandError::OperationTimeout) => {
                    return Err(ManagerError::OperationTimeout);
                }
            };
            value
                .downcast::<T>()
                .map(|value| *value)
                .map_err(|_| ManagerError::Stopped)
        };
        tokio::time::timeout(self.config.operation_timeout, operation)
            .await
            .map_err(|_| ManagerError::OperationTimeout)?
    }

    async fn wait_for_connection(&self) -> Result<()> {
        let wait = async {
            loop {
                let notified = self.changed.notified();
                let state = self.state.lock().await;
                if matches!(state.status, SwitchStatus::Connected { .. }) {
                    return Ok(());
                }
                if state.stopping {
                    return Err(ManagerError::Stopped);
                }
                drop(state);
                notified.await;
            }
        };

        tokio::time::timeout(self.config.connect_wait_timeout, wait)
            .await
            .map_err(|_| ManagerError::ConnectTimeout)?
    }

    async fn wait_backoff(&self, delay: Duration) {
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = self.changed.notified() => {}
            () = self.stop_notify.notified() => {}
        }
    }

    async fn is_stopping(&self) -> bool {
        self.state.lock().await.stopping
    }

    async fn publish_status(&self, status: SwitchStatus, event: LifecycleEvent) {
        let mut state = self.state.lock().await;
        if state.stopping {
            return;
        }
        state.status = status.clone();
        drop(state);
        let _ = self.status.send(status);
        let _ = self.events.send(event);
    }

    async fn publish_connection_loss(&self, error: String) {
        self.publish_status(
            SwitchStatus::Disconnected {
                error: error.clone(),
            },
            LifecycleEvent::Disconnected { id: self.id, error },
        )
        .await;
    }

    async fn stop(&self) {
        let mut state = self.state.lock().await;
        if state.stopping {
            return;
        }
        state.stopping = true;
        state.status = SwitchStatus::Stopped;
        drop(state);
        let _ = self.status.send(SwitchStatus::Stopped);
        let _ = self.events.send(LifecycleEvent::Removed { id: self.id });
        self.stop_notify.notify_waiters();
        self.changed.notify_waiters();
    }
}

/// A handle for one switch registered with a [`ConnectionManager`].
#[derive(Clone)]
pub struct SwitchHandle {
    inner: Arc<ManagedSwitch>,
}

impl SwitchHandle {
    /// Return this switch's stable manager id.
    #[must_use]
    pub fn id(&self) -> SwitchId {
        self.inner.id
    }

    /// Return the caller-supplied display label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.inner.label
    }

    /// Read the latest lifecycle status without waiting.
    pub async fn status(&self) -> SwitchStatus {
        self.inner.state.lock().await.status.clone()
    }

    /// Subscribe to status changes for this switch.
    #[must_use]
    pub fn subscribe_status(&self) -> watch::Receiver<SwitchStatus> {
        self.inner.status.subscribe()
    }

    /// Subscribe to inbound messages from this switch.
    #[must_use]
    pub fn subscribe_messages(&self) -> broadcast::Receiver<MessageEvent> {
        self.inner.messages.subscribe()
    }

    /// Wait until the `OpenFlow` handshake has completed.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::ConnectTimeout`] if the switch remains
    /// unavailable for the configured wait period.
    pub async fn wait_until_connected(&self) -> Result<()> {
        self.inner.wait_for_connection().await
    }

    /// Execute one operation on this switch without retrying it.
    ///
    /// Use this for mutating operations. A transport failure is reported and
    /// the manager reconnects in the background, but the operation is not
    /// replayed because the switch may have applied it before the failure.
    ///
    /// # Errors
    ///
    /// Returns the operation or lifecycle error.
    pub async fn execute<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: Send
            + 'static
            + for<'a> FnOnce(&'a mut Connection<BoxedStream>) -> OperationFuture<'a, T>,
    {
        self.inner.execute(operation).await
    }

    /// Execute a read-only or otherwise idempotent operation with retry.
    ///
    /// The operation is retried only after a transport failure and only up to
    /// [`ManagerConfig::safe_operation_retries`]. Callers must not use this
    /// method for flow-mod, group-mod, meter-mod, bundle, packet-out, role, or
    /// other operations whose result could be uncertain after a disconnect.
    ///
    /// # Errors
    ///
    /// Returns the operation or lifecycle error after the retry policy is
    /// exhausted.
    pub async fn execute_safe<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: Clone
            + Send
            + 'static
            + for<'a> Fn(&'a mut Connection<BoxedStream>) -> OperationFuture<'a, T>,
    {
        self.inner.execute_safe(operation).await
    }
}

/// Owns multiple `OpenFlow` switch connections and their reconnect loops.
#[derive(Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct ConnectionManager {
    switches: Arc<RwLock<HashMap<SwitchId, SwitchHandle>>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
    config: ManagerConfig,
    events: broadcast::Sender<LifecycleEvent>,
}

impl ConnectionManager {
    /// Create an empty manager with the supplied reconnect policy.
    #[must_use]
    pub fn new(config: ManagerConfig) -> Self {
        let (events, _) = broadcast::channel(128);
        Self {
            switches: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            config,
            events,
        }
    }

    /// Register a custom switch endpoint and start managing it.
    #[must_use]
    pub fn add<C>(&self, label: impl Into<String>, connector: C) -> SwitchHandle
    where
        C: Connector + 'static,
    {
        self.add_with_policy(label, connector, ReconnectPolicy::default())
    }

    /// Register a custom switch endpoint with reconnect restoration policy.
    #[must_use]
    pub fn add_with_policy<C>(
        &self,
        label: impl Into<String>,
        connector: C,
        policy: ReconnectPolicy,
    ) -> SwitchHandle
    where
        C: Connector + 'static,
    {
        let id = SwitchId(
            self.next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        let label = label.into();
        let (status, _) = watch::channel(SwitchStatus::Connecting);
        let (commands, command_receiver) = mpsc::channel(128);
        let (messages, _) = broadcast::channel(256);
        let switch = SwitchHandle {
            inner: Arc::new(ManagedSwitch {
                id,
                label: label.clone(),
                connector: Arc::new(connector),
                config: self.config.clone(),
                policy,
                state: Mutex::new(ManagedState {
                    status: SwitchStatus::Connecting,
                    generation: 0,
                    stopping: false,
                }),
                changed: Notify::new(),
                stop_notify: Notify::new(),
                status,
                events: self.events.clone(),
                messages,
                commands,
            }),
        };

        let task_switch = switch.clone();
        self.switches
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, switch.clone());
        let _ = self.events.send(LifecycleEvent::Added { id, label });
        tokio::spawn(async move { task_switch.inner.run(command_receiver).await });
        switch
    }

    /// Register a TCP switch endpoint.
    #[must_use]
    pub fn add_tcp(&self, address: impl Into<String>) -> SwitchHandle {
        let address = address.into();
        self.add(address.clone(), TcpConnector::new(address))
    }

    /// Register a TCP switch endpoint with reconnect restoration policy.
    #[must_use]
    pub fn add_tcp_with_policy(
        &self,
        address: impl Into<String>,
        policy: ReconnectPolicy,
    ) -> SwitchHandle {
        let address = address.into();
        self.add_with_policy(address.clone(), TcpConnector::new(address), policy)
    }

    /// Register a Unix-domain switch endpoint.
    #[must_use]
    pub fn add_unix(&self, path: impl AsRef<Path>) -> SwitchHandle {
        let path = path.as_ref().to_owned();
        self.add(path.display().to_string(), UnixConnector::new(path))
    }

    /// Register a Unix-domain switch endpoint with reconnect restoration
    /// policy.
    #[must_use]
    pub fn add_unix_with_policy(
        &self,
        path: impl AsRef<Path>,
        policy: ReconnectPolicy,
    ) -> SwitchHandle {
        let path = path.as_ref().to_owned();
        self.add_with_policy(path.display().to_string(), UnixConnector::new(path), policy)
    }

    /// Look up a registered switch.
    pub fn get(&self, id: SwitchId) -> Option<SwitchHandle> {
        self.switches
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
            .cloned()
    }

    /// Return all currently registered switches.
    pub fn switches(&self) -> Vec<SwitchHandle> {
        self.switches
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// Subscribe to manager-wide lifecycle events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<LifecycleEvent> {
        self.events.subscribe()
    }

    /// Remove one switch and stop its reconnect loop.
    pub async fn remove(&self, id: SwitchId) -> bool {
        let switch = self
            .switches
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
        if let Some(switch) = switch {
            switch.inner.stop().await;
            true
        } else {
            false
        }
    }

    /// Stop and remove every managed switch.
    pub async fn shutdown(&self) {
        let switches = std::mem::take(
            &mut *self
                .switches
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for switch in switches.into_values() {
            switch.inner.stop().await;
        }
    }

    /// Execute one operation on a registered switch without retrying it.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::SwitchNotFound`] when `id` is not registered,
    /// or the operation/lifecycle error otherwise.
    pub async fn execute<T, F>(&self, id: SwitchId, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: Send
            + 'static
            + for<'a> FnOnce(&'a mut Connection<BoxedStream>) -> OperationFuture<'a, T>,
    {
        self.get(id)
            .ok_or(ManagerError::SwitchNotFound(id))?
            .execute(operation)
            .await
    }

    /// Execute a read-only or idempotent operation with the configured retry
    /// policy.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::SwitchNotFound`] when `id` is not registered,
    /// or the operation/lifecycle error otherwise.
    pub async fn execute_safe<T, F>(&self, id: SwitchId, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: Clone
            + Send
            + 'static
            + for<'a> Fn(&'a mut Connection<BoxedStream>) -> OperationFuture<'a, T>,
    {
        self.get(id)
            .ok_or(ManagerError::SwitchNotFound(id))?
            .execute_safe(operation)
            .await
    }
}

const fn is_transport_failure(error: &ConnectionError) -> bool {
    matches!(error, ConnectionError::Io(_))
}

fn connection_timeout(message: &'static str) -> ConnectionError {
    ConnectionError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
}

fn next_backoff(current: Duration, maximum: Duration) -> Duration {
    current.saturating_mul(2).min(maximum)
}

#[cfg(all(test, not(clippy)))]
mod tests {
    use super::*;

    use crate::protocol::codec::Encoder;
    use crate::protocol::constants::{
        OFPBRC_BAD_TYPE, OFPCR_ROLE_MASTER, OFPET_BAD_REQUEST, OFPT_BARRIER_REQUEST,
        OFPT_ECHO_REPLY, OFPT_FEATURES_REQUEST, OFPT_GET_CONFIG_REQUEST, OFPT_HELLO,
        OFPT_PACKET_OUT, OFPT_ROLE_REQUEST, OFPT_SET_CONFIG, OFP_NO_BUFFER,
    };
    use crate::protocol::features::Reply;
    use crate::protocol::header::Header;
    use crate::protocol::io::read_frame;
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

    struct PendingConnector;

    impl Connector for PendingConnector {
        fn connect(&self) -> ConnectorFuture<'_> {
            Box::pin(std::future::pending())
        }
    }

    async fn serve_once<S>(mut stream: S, send_event: bool)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let hello = read_frame(&mut stream).await.unwrap();
        assert_eq!(Header::parse(&hello).unwrap().msg_type, OFPT_HELLO);
        stream.write_all(&Encoder::hello(1).unwrap()).await.unwrap();

        let request = read_frame(&mut stream).await.unwrap();
        let request_header = Header::parse(&request).unwrap();
        assert_eq!(request_header.msg_type, OFPT_FEATURES_REQUEST);
        stream
            .write_all(&Encoder::features_reply(&Reply {
                xid: request_header.xid,
                datapath_id: 1,
                n_buffers: 0,
                n_tables: 1,
                auxiliary_id: 0,
                capabilities: 0,
                reserved: 0,
            }))
            .await
            .unwrap();

        let request = read_frame(&mut stream).await.unwrap();
        let request_header = Header::parse(&request).unwrap();
        assert_eq!(request_header.msg_type, OFPT_GET_CONFIG_REQUEST);
        stream
            .write_all(&Encoder::get_config_reply(request_header.xid, 0, 128))
            .await
            .unwrap();
        if send_event {
            stream
                .write_all(&Encoder::echo_request(77, b"event").unwrap())
                .await
                .unwrap();
        }
    }

    async fn serve_echo_during_request<S>(mut stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let hello = read_frame(&mut stream).await.unwrap();
        assert_eq!(Header::parse(&hello).unwrap().msg_type, OFPT_HELLO);
        stream.write_all(&Encoder::hello(1).unwrap()).await.unwrap();

        let request = read_frame(&mut stream).await.unwrap();
        let request_header = Header::parse(&request).unwrap();
        assert_eq!(request_header.msg_type, OFPT_FEATURES_REQUEST);
        stream
            .write_all(&Encoder::features_reply(&Reply {
                xid: request_header.xid,
                datapath_id: 1,
                n_buffers: 0,
                n_tables: 1,
                auxiliary_id: 0,
                capabilities: 0,
                reserved: 0,
            }))
            .await
            .unwrap();

        let request = read_frame(&mut stream).await.unwrap();
        let request_header = Header::parse(&request).unwrap();
        assert_eq!(request_header.msg_type, OFPT_GET_CONFIG_REQUEST);
        stream
            .write_all(&Encoder::echo_request(77, b"during-request").unwrap())
            .await
            .unwrap();
        let echo_reply = read_frame(&mut stream).await.unwrap();
        let echo_header = Header::parse(&echo_reply).unwrap();
        assert_eq!(echo_header.msg_type, OFPT_ECHO_REPLY);
        assert_eq!(&echo_reply[8..], b"during-request");
        stream
            .write_all(&Encoder::get_config_reply(request_header.xid, 0, 128))
            .await
            .unwrap();
    }

    async fn serve_batch_error<S>(mut stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let hello = read_frame(&mut stream).await.unwrap();
        assert_eq!(Header::parse(&hello).unwrap().msg_type, OFPT_HELLO);
        stream.write_all(&Encoder::hello(1).unwrap()).await.unwrap();

        let request = read_frame(&mut stream).await.unwrap();
        let request_header = Header::parse(&request).unwrap();
        assert_eq!(request_header.msg_type, OFPT_FEATURES_REQUEST);
        stream
            .write_all(&Encoder::features_reply(&Reply {
                xid: request_header.xid,
                datapath_id: 1,
                n_buffers: 0,
                n_tables: 1,
                auxiliary_id: 0,
                capabilities: 0,
                reserved: 0,
            }))
            .await
            .unwrap();

        let packet_out = read_frame(&mut stream).await.unwrap();
        let packet_header = Header::parse(&packet_out).unwrap();
        assert_eq!(packet_header.msg_type, OFPT_PACKET_OUT);
        let barrier = read_frame(&mut stream).await.unwrap();
        let barrier_header = Header::parse(&barrier).unwrap();
        assert_eq!(barrier_header.msg_type, OFPT_BARRIER_REQUEST);
        stream
            .write_all(
                &Encoder::error(packet_header.xid, OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE, b"")
                    .unwrap(),
            )
            .await
            .unwrap();
        stream
            .write_all(&Encoder::barrier_reply(barrier_header.xid))
            .await
            .unwrap();
    }

    async fn serve_hanging<S>(mut stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let hello = read_frame(&mut stream).await.unwrap();
        assert_eq!(Header::parse(&hello).unwrap().msg_type, OFPT_HELLO);
        stream.write_all(&Encoder::hello(1).unwrap()).await.unwrap();
        let request = read_frame(&mut stream).await.unwrap();
        let request_header = Header::parse(&request).unwrap();
        stream
            .write_all(&Encoder::features_reply(&Reply {
                xid: request_header.xid,
                datapath_id: 1,
                n_buffers: 0,
                n_tables: 1,
                auxiliary_id: 0,
                capabilities: 0,
                reserved: 0,
            }))
            .await
            .unwrap();
        let request = read_frame(&mut stream).await.unwrap();
        assert_eq!(
            Header::parse(&request).unwrap().msg_type,
            OFPT_GET_CONFIG_REQUEST
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    async fn serve_policy<S>(mut stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let hello = read_frame(&mut stream).await.unwrap();
        assert_eq!(Header::parse(&hello).unwrap().msg_type, OFPT_HELLO);
        stream.write_all(&Encoder::hello(1).unwrap()).await.unwrap();
        let request = read_frame(&mut stream).await.unwrap();
        let request_header = Header::parse(&request).unwrap();
        stream
            .write_all(&Encoder::features_reply(&Reply {
                xid: request_header.xid,
                datapath_id: 1,
                n_buffers: 0,
                n_tables: 1,
                auxiliary_id: 0,
                capabilities: 0,
                reserved: 0,
            }))
            .await
            .unwrap();

        let set_config = read_frame(&mut stream).await.unwrap();
        assert_eq!(
            Header::parse(&set_config).unwrap().msg_type,
            OFPT_SET_CONFIG
        );
        let barrier = read_frame(&mut stream).await.unwrap();
        let barrier_header = Header::parse(&barrier).unwrap();
        assert_eq!(barrier_header.msg_type, OFPT_BARRIER_REQUEST);
        stream
            .write_all(&Encoder::barrier_reply(barrier_header.xid))
            .await
            .unwrap();

        let role = read_frame(&mut stream).await.unwrap();
        let role_header = Header::parse(&role).unwrap();
        assert_eq!(role_header.msg_type, OFPT_ROLE_REQUEST);
        stream
            .write_all(&Encoder::role_reply(role_header.xid, OFPCR_ROLE_MASTER, 7, 9).unwrap())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn reconnects_and_retries_safe_operation_after_transport_loss() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for connection in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                serve_once(stream, connection == 0).await;
            }
        });

        let manager = ConnectionManager::new(ManagerConfig {
            handshake_timeout: Duration::from_secs(1),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
            connect_wait_timeout: Duration::from_secs(2),
            operation_timeout: Duration::from_secs(1),
            keepalive_interval: None,
            safe_operation_retries: 1,
        });
        let mut events = manager.subscribe();
        let switch = manager.add_tcp(address.to_string());
        switch.wait_until_connected().await.unwrap();
        let first = switch
            .execute_safe(|connection| Box::pin(connection.get_config()))
            .await
            .unwrap();
        assert_eq!(first.miss_send_len, 128);

        let second = switch
            .execute_safe(|connection| Box::pin(connection.get_config()))
            .await
            .unwrap();
        assert_eq!(second.miss_send_len, 128);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if matches!(
                    events.recv().await.unwrap(),
                    LifecycleEvent::Connected { generation: 2, .. }
                ) {
                    break;
                }
            }
        })
        .await
        .unwrap();

        manager.shutdown().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn operation_waits_for_connection_with_a_deadline() {
        let manager = ConnectionManager::new(ManagerConfig {
            handshake_timeout: Duration::from_millis(10),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
            connect_wait_timeout: Duration::from_millis(10),
            operation_timeout: Duration::from_millis(10),
            keepalive_interval: None,
            safe_operation_retries: 0,
        });
        let switch = manager.add("pending", PendingConnector);
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            switch.execute(|connection| Box::pin(connection.get_config())),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(ManagerError::ConnectTimeout)));
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn answers_echo_while_an_operation_waits_for_reply() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_echo_during_request(stream).await;
        });
        let manager = ConnectionManager::new(ManagerConfig {
            handshake_timeout: Duration::from_secs(1),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
            connect_wait_timeout: Duration::from_secs(1),
            operation_timeout: Duration::from_secs(1),
            keepalive_interval: None,
            safe_operation_retries: 0,
        });
        let switch = manager.add_tcp(address.to_string());
        switch.wait_until_connected().await.unwrap();
        let config = switch
            .execute(|connection| Box::pin(connection.get_config()))
            .await
            .unwrap();
        assert_eq!(config.miss_send_len, 128);
        manager.shutdown().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn keepalive_does_not_consume_a_pending_batch_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_batch_error(stream).await;
        });
        let manager = ConnectionManager::new(ManagerConfig {
            handshake_timeout: Duration::from_secs(1),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
            connect_wait_timeout: Duration::from_secs(1),
            operation_timeout: Duration::from_millis(200),
            keepalive_interval: Some(Duration::from_millis(5)),
            safe_operation_retries: 0,
        });
        let switch = manager.add_tcp(address.to_string());
        switch.wait_until_connected().await.unwrap();
        switch
            .execute(|connection| {
                Box::pin(connection.send_packet_out(OFP_NO_BUFFER, None, Vec::new(), &[]))
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        let result = switch
            .execute(|connection| Box::pin(connection.send_barrier()))
            .await;
        assert!(matches!(
            result,
            Err(ManagerError::Connection(ConnectionError::Remote { .. }))
        ));
        manager.shutdown().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn operation_deadline_cancels_a_hanging_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_hanging(stream).await;
        });
        let manager = ConnectionManager::new(ManagerConfig {
            handshake_timeout: Duration::from_secs(1),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
            connect_wait_timeout: Duration::from_secs(1),
            operation_timeout: Duration::from_millis(10),
            keepalive_interval: None,
            safe_operation_retries: 0,
        });
        let switch = manager.add_tcp(address.to_string());
        switch.wait_until_connected().await.unwrap();
        let result = switch
            .execute(|connection| Box::pin(connection.get_config()))
            .await;
        assert!(matches!(result, Err(ManagerError::OperationTimeout)));
        manager.shutdown().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn reconnect_policy_is_applied_after_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_policy(stream).await;
        });
        let manager = ConnectionManager::new(ManagerConfig {
            handshake_timeout: Duration::from_secs(1),
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
            connect_wait_timeout: Duration::from_secs(1),
            operation_timeout: Duration::from_secs(1),
            keepalive_interval: None,
            safe_operation_retries: 0,
        });
        let switch = manager.add_tcp_with_policy(
            address.to_string(),
            ReconnectPolicy {
                config: Some((0, 128)),
                async_properties: None,
                role: Some(RolePolicy {
                    role: OFPCR_ROLE_MASTER,
                    short_id: 7,
                    generation_id: 9,
                }),
            },
        );
        switch.wait_until_connected().await.unwrap();
        manager.shutdown().await;
        server.await.unwrap();
    }

    #[test]
    fn backoff_is_capped() {
        assert_eq!(
            next_backoff(Duration::from_millis(2), Duration::from_millis(5)),
            Duration::from_millis(4)
        );
        assert_eq!(
            next_backoff(Duration::from_millis(4), Duration::from_millis(5)),
            Duration::from_millis(5)
        );
    }
}
