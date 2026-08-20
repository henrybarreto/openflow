//! [`Connection`], an async `OpenFlow` client that speaks to a switch.
//!
//! Connect with [`Connection::connect_tcp`], [`Connection::connect_unix`]
//! or [`Connection::connect_bridge`] -- each performs the hello and
//! features handshake before returning -- then use the message helpers:
//! [`Connection::add_flow`], [`Connection::multipart_request`],
//! [`Connection::send_packet_out`], the bundle calls, and so on.
//!
//! Methods named `add_*`/`delete_*`/`set_*` send their message and then
//! wait on a barrier, so a switch's rejection surfaces at the call rather
//! than several messages later. The `send_*` methods do not -- batch
//! several and call [`Connection::send_barrier`] once, as
//! `examples/08_batch_with_barrier.rs` does.

pub mod manager;
#[cfg(feature = "tls")]
pub use manager::TlsConnector;
pub use manager::{
    BoxedStream, ConnectionManager, Connector, ConnectorFuture, LifecycleEvent, ManagedStream,
    ManagerConfig, ManagerError, MessageEvent, OperationFuture, ReconnectPolicy, RolePolicy,
    SwitchHandle, SwitchId, SwitchStatus, TcpConnector, UnixConnector,
};

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{
    error::Error as StdError,
    fmt::{Display, Formatter},
};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs, UnixStream};

use crate::protocol::action::Action;
use crate::protocol::codec::{Decoder, Encoder};
use crate::protocol::config::Config;
use crate::protocol::constants::{
    OFPACPT_CONT_STATUS_MASTER, OFPACPT_CONT_STATUS_SLAVE, OFPACPT_FLOW_REMOVED_MASTER,
    OFPACPT_FLOW_REMOVED_SLAVE, OFPACPT_FLOW_STATS_MASTER, OFPACPT_FLOW_STATS_SLAVE,
    OFPACPT_PACKET_IN_MASTER, OFPACPT_PACKET_IN_SLAVE, OFPACPT_PORT_STATUS_MASTER,
    OFPACPT_PORT_STATUS_SLAVE, OFPACPT_REQUESTFORWARD_MASTER, OFPACPT_REQUESTFORWARD_SLAVE,
    OFPACPT_ROLE_STATUS_MASTER, OFPACPT_ROLE_STATUS_SLAVE, OFPACPT_TABLE_STATUS_MASTER,
    OFPACPT_TABLE_STATUS_SLAVE, OFPBCT_COMMIT_REQUEST, OFPBCT_DISCARD_REQUEST, OFPBCT_OPEN_REQUEST,
    OFPET_HELLO_FAILED, OFPG_ANY, OFPHFC_INCOMPATIBLE, OFPMPF_REPLY_MORE, OFPP_ANY, OFPTT_ALL,
};
use crate::protocol::control::{
    GroupMod, MeterBand, MultipartMessage, MultipartReplyBody, MultipartRequestBody,
    PortModProperty, Property,
};
use crate::protocol::error::OfError;
use crate::protocol::features::Reply;
use crate::protocol::hello;
use crate::protocol::io::{write_frame, FrameReader, DEFAULT_MAX_FRAME_SIZE};
use crate::protocol::message::Message;
use crate::protocol::ofmatch::Match;
use crate::protocol::rule::Rule;

/// Default time to wait for a full multipart reply sequence (across
/// however many `OFPMPF_REPLY_MORE`-flagged messages it takes) before
/// giving up.
const DEFAULT_MULTIPART_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time a request helper waits for its matching reply.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum number of body bytes retained while reassembling one
/// multipart reply.
pub const DEFAULT_MULTIPART_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Default maximum number of messages retained while reassembling one
/// multipart reply.
pub const DEFAULT_MULTIPART_MAX_PARTS: usize = 256;

/// Maximum time a convenience connector waits for the `OpenFlow` handshake.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of unmatched frames retained while a synchronous request is
/// waiting for its reply. This bounds memory when a peer floods async events.
const MAX_PENDING_MESSAGES: usize = 256;

/// Maximum number of command XIDs awaiting an explicit barrier. Keeping these
/// lets a caller batch `send_*` calls and still have `send_barrier` surface a
/// rejection of any command in that batch.
const MAX_PENDING_COMMAND_XIDS: usize = 256;

/// Limits applied while reassembling a multipart reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipartLimits {
    /// Maximum cumulative size of multipart reply bodies in bytes.
    pub max_bytes: usize,
    /// Maximum number of multipart reply messages in one sequence.
    pub max_parts: usize,
}

impl Default for MultipartLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MULTIPART_MAX_BYTES,
            max_parts: DEFAULT_MULTIPART_MAX_PARTS,
        }
    }
}

#[derive(Debug)]
/// Something went wrong on a [`Connection`].
pub enum Error {
    /// A frame could not be encoded or decoded.
    Protocol(OfError),
    /// The underlying socket failed.
    Io(std::io::Error),
    /// A reply arrived, but not the kind being waited for.
    UnexpectedMessage {
        /// What the caller was waiting for.
        expected: &'static str,
        /// A debug rendering of what arrived instead.
        got: String,
    },
    /// The switch answered with `OFPT_ERROR`. Decode the pair with
    /// [`crate::protocol::error_msg::ErrorType::parse`] to see what it
    /// objected to.
    Remote {
        /// Raw `OFPET_*` type.
        error_type: u16,
        /// Raw code, meaningful relative to `error_type`.
        code: u16,
        /// As much of the offending message as the switch returned.
        data: Vec<u8>,
    },
    /// The `OpenFlow` hello/features handshake did not complete in time.
    HandshakeTimeout,
    /// The TLS handshake did not complete in time.
    TlsHandshakeTimeout,
    /// The handshake finished without a features reply, so the switch's
    /// datapath id and table count are unknown.
    MissingFeaturesReply,
    /// A request did not receive its matching reply before its deadline.
    RequestTimeout,
    /// A multipart reply sequence did not finish in time -- see
    /// [`Connection::multipart_request_with_timeout`].
    MultipartTimeout,
    /// The cumulative multipart reply body exceeded its configured byte limit.
    MultipartReplyTooLarge {
        /// Maximum cumulative body size permitted by the active policy.
        max_bytes: usize,
        /// Cumulative body size that the rejected part would have reached.
        size: usize,
    },
    /// A multipart reply sequence exceeded its configured part limit.
    MultipartReplyTooManyParts {
        /// Maximum number of reply messages permitted by the active policy.
        max_parts: usize,
        /// Number of reply messages that the rejected part would have reached.
        parts: usize,
    },
    /// Too many unrelated messages arrived while a synchronous request was
    /// waiting for its reply.
    PendingMessageOverflow,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(err) => write!(f, "OpenFlow protocol error: {err}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::UnexpectedMessage { expected, got } => {
                write!(
                    f,
                    "unexpected OpenFlow message while waiting for {expected}: {got:?}"
                )
            }
            Self::Remote {
                error_type,
                code,
                data,
            } => write!(
                f,
                "remote OpenFlow error: type={error_type} code={code} data={data:02x?}"
            ),
            Self::HandshakeTimeout => write!(f, "timed out waiting for the OpenFlow handshake"),
            Self::TlsHandshakeTimeout => write!(f, "timed out waiting for the TLS handshake"),
            Self::MissingFeaturesReply => {
                write!(f, "handshake completed without a features reply")
            }
            Self::RequestTimeout => write!(f, "timed out waiting for an OpenFlow request reply"),
            Self::MultipartTimeout => {
                write!(f, "timed out waiting for a full multipart reply sequence")
            }
            Self::MultipartReplyTooLarge { max_bytes, size } => write!(
                f,
                "multipart reply size {size} exceeds configured limit of {max_bytes} bytes"
            ),
            Self::MultipartReplyTooManyParts { max_parts, parts } => write!(
                f,
                "multipart reply part count {parts} exceeds configured limit of {max_parts}"
            ),
            Self::PendingMessageOverflow => {
                write!(
                    f,
                    "too many pending OpenFlow messages while waiting for a reply"
                )
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Protocol(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::UnexpectedMessage { .. }
            | Self::Remote { .. }
            | Self::HandshakeTimeout
            | Self::TlsHandshakeTimeout
            | Self::MissingFeaturesReply
            | Self::RequestTimeout
            | Self::MultipartTimeout
            | Self::MultipartReplyTooLarge { .. }
            | Self::MultipartReplyTooManyParts { .. }
            | Self::PendingMessageOverflow => None,
        }
    }
}

impl From<OfError> for Error {
    fn from(value: OfError) -> Self {
        Self::Protocol(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// `Result` with this module's [`Error`] as the error type.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
/// A connected `OpenFlow` client.
///
/// Generic over the stream, so it works over TCP, a Unix socket, or
/// anything else implementing `AsyncRead + AsyncWrite` -- including an
/// in-memory duplex for tests.
///
/// ```no_run
/// use openflow::client::Connection;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// // connect_tcp performs the handshake before it returns.
/// let mut client = Connection::connect_tcp("127.0.0.1:6653").await?;
/// let tables = client.features().map(|f| f.n_tables);
/// client.send_barrier().await?;
/// # Ok(())
/// # }
/// ```
pub struct Connection<S> {
    stream: FrameReader<S>,
    next_xid: u32,
    features: Option<Reply>,
    config: Option<Config>,
    pending_messages: VecDeque<Message>,
    pending_command_xids: VecDeque<u32>,
    multipart_limits: MultipartLimits,
}

impl<S> Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap an already-connected stream.
    ///
    /// No handshake is performed -- call [`Self::handshake`] yourself, or
    /// use one of the `connect_*` constructors, which do both.
    pub const fn new(stream: S) -> Self {
        Self::with_max_frame_size(stream, DEFAULT_MAX_FRAME_SIZE)
    }

    /// Wrap an already-connected stream with an explicit frame-size limit.
    ///
    /// The limit is enforced before the advertised body is allocated. This is
    /// useful when the embedding application wants a stricter policy than the
    /// protocol's representable `u16` maximum.
    pub const fn with_max_frame_size(stream: S, max_frame_size: usize) -> Self {
        Self::with_max_frame_size_and_multipart_limits(
            stream,
            max_frame_size,
            MultipartLimits {
                max_bytes: DEFAULT_MULTIPART_MAX_BYTES,
                max_parts: DEFAULT_MULTIPART_MAX_PARTS,
            },
        )
    }

    /// Wrap an already-connected stream with explicit multipart-reply limits.
    pub const fn with_multipart_limits(stream: S, limits: MultipartLimits) -> Self {
        Self::with_max_frame_size_and_multipart_limits(stream, DEFAULT_MAX_FRAME_SIZE, limits)
    }

    /// Wrap an already-connected stream with explicit frame and multipart-reply limits.
    pub const fn with_max_frame_size_and_multipart_limits(
        stream: S,
        max_frame_size: usize,
        multipart_limits: MultipartLimits,
    ) -> Self {
        Self {
            stream: FrameReader::with_max_frame_size(stream, max_frame_size),
            next_xid: 1,
            features: None,
            config: None,
            pending_messages: VecDeque::new(),
            pending_command_xids: VecDeque::new(),
            multipart_limits,
        }
    }

    /// Take the underlying stream back.
    pub fn into_inner(self) -> S {
        self.stream.into_inner()
    }

    /// The switch's features reply, once the handshake has completed.
    pub const fn features(&self) -> Option<&Reply> {
        self.features.as_ref()
    }

    /// The switch configuration received by an optional config handshake.
    #[must_use]
    pub const fn config(&self) -> Option<&Config> {
        self.config.as_ref()
    }

    /// Return the active multipart-reply memory limits.
    #[must_use]
    pub const fn multipart_limits(&self) -> MultipartLimits {
        self.multipart_limits
    }

    /// Replace the active multipart-reply memory limits.
    pub const fn set_multipart_limits(&mut self, limits: MultipartLimits) {
        self.multipart_limits = limits;
    }

    /// The auxiliary connection identifier from the features reply.
    ///
    /// `0` identifies the main connection; non-zero values identify an
    /// auxiliary connection opened by the switch.
    #[must_use]
    pub const fn auxiliary_id(&self) -> Option<u8> {
        match &self.features {
            Some(features) => Some(features.auxiliary_id),
            None => None,
        }
    }

    const fn next_xid(&mut self) -> u32 {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1);
        xid
    }

    async fn read_wire_message(&mut self) -> Result<Message> {
        let frame = self.stream.read_frame().await?.ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed between OpenFlow frames",
            ))
        })?;
        Ok(Decoder::message(&frame)?)
    }

    fn retain_pending_message(&mut self, msg: Message) -> Result<()> {
        if self.pending_messages.len() == MAX_PENDING_MESSAGES {
            return Err(Error::PendingMessageOverflow);
        }
        self.pending_messages.push_back(msg);
        Ok(())
    }

    fn retain_pending_command_xid(&mut self, xid: u32) -> Result<()> {
        if self.pending_command_xids.len() == MAX_PENDING_COMMAND_XIDS {
            return Err(Error::PendingMessageOverflow);
        }
        self.pending_command_xids.push_back(xid);
        Ok(())
    }

    pub(crate) fn has_pending_commands(&self) -> bool {
        !self.pending_command_xids.is_empty()
    }

    async fn write_command(&mut self, xid: u32, frame: Vec<u8>) -> Result<()> {
        if self.pending_command_xids.len() == MAX_PENDING_COMMAND_XIDS {
            return Err(Error::PendingMessageOverflow);
        }
        self.write_frame(&frame).await?;
        self.pending_command_xids.push_back(xid);
        Ok(())
    }

    async fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        write_frame(self.stream.get_mut(), frame).await?;
        Ok(())
    }

    async fn respond_to_echo(&mut self, message: Message) -> Result<Option<Message>> {
        match message {
            Message::EchoRequest { xid, payload } => {
                let reply = Encoder::echo_reply(xid, &payload)?;
                self.write_frame(&reply).await?;
                Ok(None)
            }
            message => Ok(Some(message)),
        }
    }

    async fn read_message_responding_to_echo(&mut self) -> Result<Message> {
        loop {
            let message = self.read_wire_message().await?;
            if let Some(message) = self.respond_to_echo(message).await? {
                return Ok(message);
            }
        }
    }

    /// Read the next pending or wire `OpenFlow` message. Echo requests are
    /// answered before this method returns the next application-visible
    /// message. Synchronous helper methods retain unrelated messages, so
    /// callers do not lose switch-initiated traffic (`PACKET_IN`,
    /// `PORT_STATUS`, ...) that arrives while waiting for a reply.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer closes the connection or sends a frame
    /// that cannot be decoded.
    pub async fn recv_message(&mut self) -> Result<Message> {
        loop {
            let message = match self.pending_messages.pop_front() {
                Some(message) => message,
                None => self.read_wire_message().await?,
            };
            if let Some(message) = self.respond_to_echo(message).await? {
                return Ok(message);
            }
        }
    }

    /// Write a pre-encoded `OpenFlow` frame to the peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame cannot be written to the stream.
    pub async fn send_raw(&mut self, frame: &[u8]) -> Result<()> {
        self.write_frame(frame).await
    }

    async fn wait_for_message<T, E, F>(
        &mut self,
        mut is_expected_error: E,
        mut map_message: F,
    ) -> Result<T>
    where
        E: FnMut(&crate::protocol::error_msg::ErrorMessage) -> bool,
        F: FnMut(Message) -> std::result::Result<T, Message>,
    {
        loop {
            let msg = self.read_message_responding_to_echo().await?;
            if let Message::Error(err) = &msg {
                if is_expected_error(err) {
                    return Err(Error::Remote {
                        error_type: err.error_type,
                        code: err.code,
                        data: err.data.clone(),
                    });
                }
            }

            match map_message(msg) {
                Ok(value) => return Ok(value),
                Err(msg) => self.retain_pending_message(msg)?,
            }
        }
    }

    async fn wait_for_features_reply(&mut self, xid: u32) -> Result<Reply> {
        self.wait_for_message(
            |err| err.xid == xid,
            |msg| match msg {
                Message::FeaturesReply(reply) if reply.xid == xid => Ok(reply),
                other => Err(other),
            },
        )
        .await
    }

    async fn exchange_hello(&mut self) -> Result<()> {
        let hello_xid = self.next_xid();
        let hello_frame = Encoder::hello(hello_xid)?;
        self.write_frame(&hello_frame).await?;

        let hello = self.read_message_responding_to_echo().await?;

        match hello {
            Message::Hello {
                version,
                version_bitmap,
                ..
            } => {
                if !hello::is_version_compatible(version, version_bitmap.as_deref()) {
                    let fail = Encoder::error(
                        hello_xid,
                        OFPET_HELLO_FAILED,
                        OFPHFC_INCOMPATIBLE,
                        b"no compatible OpenFlow version (this crate only speaks 1.5)",
                    )?;
                    self.write_frame(&fail).await?;
                    return Err(Error::Protocol(OfError::UnsupportedVersion(version)));
                }
            }
            Message::Error(err) => {
                return Err(Error::Remote {
                    error_type: err.error_type,
                    code: err.code,
                    data: err.data,
                });
            }
            got => {
                return Err(Error::UnexpectedMessage {
                    expected: "hello",
                    got: format!("{got:?}"),
                });
            }
        }

        Ok(())
    }

    async fn request_features(&mut self) -> Result<Reply> {
        let features_xid = self.next_xid();
        self.write_frame(&Encoder::features_request(features_xid))
            .await?;
        self.wait_for_features_reply(features_xid).await
    }

    async fn request_features_and_config(&mut self) -> Result<Config> {
        let features_xid = self.next_xid();
        let config_xid = self.next_xid();

        // Both requests are valid after Hello and are deliberately written
        // before reading either response. A switch is allowed to return the
        // two replies in either order, and a single socket read commonly
        // contains both frames.
        self.write_frame(&Encoder::features_request(features_xid))
            .await?;
        self.write_frame(&Config::get_request(config_xid)).await?;

        let mut features = None;
        let mut config = None;
        while features.is_none() || config.is_none() {
            let msg = self.read_message_responding_to_echo().await?;
            match msg {
                Message::FeaturesReply(reply) if reply.xid == features_xid => {
                    features = Some(reply);
                }
                Message::GetConfigReply(reply) if reply.xid == config_xid => {
                    config = Some(reply);
                }
                Message::Error(err) if err.xid == features_xid || err.xid == config_xid => {
                    return Err(Error::Remote {
                        error_type: err.error_type,
                        code: err.code,
                        data: err.data,
                    });
                }
                other => self.retain_pending_message(other)?,
            }
        }

        let features = features.ok_or(Error::MissingFeaturesReply)?;
        let config = config.ok_or(Error::MissingFeaturesReply)?;
        self.features = Some(features);
        self.config = Some(config);
        Ok(config)
    }

    async fn wait_for_barrier(&mut self, xid: u32, command_xids: &[u32]) -> Result<()> {
        // A command error can precede its barrier reply. Keep reading through
        // that reply before returning it, so the next request cannot mistake
        // this barrier's reply for its own.
        let mut command_error = None;
        loop {
            let msg = self.read_message_responding_to_echo().await?;
            match msg {
                Message::Error(err) if err.xid == xid || command_xids.contains(&err.xid) => {
                    command_error.get_or_insert(Error::Remote {
                        error_type: err.error_type,
                        code: err.code,
                        data: err.data,
                    });
                }
                Message::BarrierReply { xid: reply_xid } if reply_xid == xid => {
                    return command_error.map_or(Ok(()), Err);
                }
                other => self.retain_pending_message(other)?,
            }
        }
    }

    /// Perform the `OpenFlow` handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer closes the connection, sends an unexpected
    /// message, or replies with an `OpenFlow` error.
    pub async fn handshake(&mut self) -> Result<()> {
        self.handshake_with_timeout(DEFAULT_HANDSHAKE_TIMEOUT).await
    }

    async fn handshake_inner(&mut self) -> Result<()> {
        self.exchange_hello().await?;
        self.features = Some(self.request_features().await?);

        Ok(())
    }

    /// Perform the handshake and request the switch configuration as an
    /// optional, pipelined phase.
    ///
    /// The ordinary [`Self::handshake`] deliberately keeps its historical
    /// wire sequence (Hello followed by Features) and does not require a
    /// switch to support or answer a config request. This opt-in variant
    /// writes `FEATURES_REQUEST` and `GET_CONFIG_REQUEST` back-to-back, then
    /// accepts either reply order. The resulting configuration is also
    /// available through [`Self::config`].
    ///
    /// # Errors
    ///
    /// Returns an error if the peer closes the connection, version
    /// negotiation fails, either request receives an `OpenFlow` error, or the
    /// expected replies cannot be decoded.
    pub async fn handshake_with_config(&mut self) -> Result<Config> {
        tokio::time::timeout(
            DEFAULT_HANDSHAKE_TIMEOUT,
            self.handshake_with_config_inner(),
        )
        .await
        .map_err(|_| Error::HandshakeTimeout)?
    }

    async fn handshake_with_config_inner(&mut self) -> Result<Config> {
        self.exchange_hello().await?;
        self.request_features_and_config().await
    }

    /// Request the switch's current configuration.
    ///
    /// The reply is correlated by transaction id and retained in
    /// [`Self::config`] for callers that need to inspect it later.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be written, the reply cannot be
    /// decoded, or the switch returns a matching `OpenFlow` error.
    pub async fn get_config(&mut self) -> Result<Config> {
        self.get_config_with_timeout(DEFAULT_REQUEST_TIMEOUT).await
    }

    /// Request the switch's current configuration with an explicit deadline.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RequestTimeout`] when the request or matching reply
    /// exceeds `timeout`, or the same errors as [`Self::get_config`].
    pub async fn get_config_with_timeout(&mut self, timeout: Duration) -> Result<Config> {
        let config = tokio::time::timeout(timeout, async {
            let xid = self.next_xid();
            self.write_frame(&Config::get_request(xid)).await?;
            self.wait_for_message(
                |err| err.xid == xid,
                |msg| match msg {
                    Message::GetConfigReply(config) if config.xid == xid => Ok(config),
                    other => Err(other),
                },
            )
            .await
        })
        .await
        .map_err(|_| Error::RequestTimeout)??;
        self.config = Some(config);
        Ok(config)
    }

    /// Set the switch's current configuration and wait for a barrier.
    ///
    /// The configuration is sent as `OFPT_SET_CONFIG`; `OpenFlow` does not
    /// define a reply for that message, so the barrier confirms processing
    /// and surfaces a rejection. Use [`Self::get_config`] when the switch's
    /// accepted values must be read back.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame cannot be written, the switch rejects
    /// it, or the barrier reply does not arrive.
    pub async fn set_config(&mut self, flags: u16, miss_send_len: u16) -> Result<()> {
        let xid = self.next_xid();
        self.write_command(xid, Config::new(xid, flags, miss_send_len).encode_set())
            .await?;
        self.send_barrier_after(xid).await
    }

    /// Perform the `OpenFlow` handshake with an explicit deadline.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HandshakeTimeout`] when the deadline expires, or the
    /// same protocol/I/O error as [`Self::handshake`].
    pub async fn handshake_with_timeout(&mut self, timeout: Duration) -> Result<()> {
        tokio::time::timeout(timeout, self.handshake_inner())
            .await
            .map_err(|_| Error::HandshakeTimeout)??;
        Ok(())
    }

    /// Send a barrier request and wait for the matching reply.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer closes the connection, sends an
    /// unexpected message, or replies with an `OpenFlow` error.
    pub async fn send_barrier(&mut self) -> Result<()> {
        let xid = self.next_xid();
        let command_xids: Vec<_> = self.pending_command_xids.iter().copied().collect();
        self.write_frame(&Encoder::barrier_request(xid)).await?;
        let result = self.wait_for_barrier(xid, &command_xids).await;
        self.pending_command_xids.clear();
        result
    }

    /// Request a controller role from the switch and return the matching role
    /// reply.
    ///
    /// The switch may reject a stale generation id with an `OFPT_ERROR`; that
    /// error is returned as [`Error::Remote`]. Unrelated asynchronous
    /// messages are retained for the next [`Self::recv_message`] call.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be encoded or written, the
    /// switch sends a matching error, or the connection closes before the
    /// matching reply arrives.
    pub async fn request_role(
        &mut self,
        role: u32,
        short_id: u16,
        generation_id: u64,
    ) -> Result<crate::protocol::control::RoleRequest> {
        self.request_role_with_timeout(role, short_id, generation_id, DEFAULT_REQUEST_TIMEOUT)
            .await
    }

    /// Request a controller role with an explicit deadline.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RequestTimeout`] when the request or matching reply
    /// exceeds `timeout`, or the same errors as [`Self::request_role`].
    pub async fn request_role_with_timeout(
        &mut self,
        role: u32,
        short_id: u16,
        generation_id: u64,
        timeout: Duration,
    ) -> Result<crate::protocol::control::RoleRequest> {
        tokio::time::timeout(timeout, async {
            let xid = self.next_xid();
            self.write_frame(&Encoder::role_request(xid, role, short_id, generation_id)?)
                .await?;
            self.wait_for_message(
                |err| err.xid == xid,
                |msg| match msg {
                    Message::RoleReply(reply) if reply.xid == xid => Ok(reply),
                    other => Err(other),
                },
            )
            .await
        })
        .await
        .map_err(|_| Error::RequestTimeout)?
    }

    async fn send_barrier_after(&mut self, prior_xid: u32) -> Result<()> {
        if !self.pending_command_xids.contains(&prior_xid) {
            self.retain_pending_command_xid(prior_xid)?;
        }
        self.send_barrier().await
    }

    /// Read this connection's asynchronous-message configuration
    /// (`OFPT_GET_ASYNC_REQUEST`).
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be written or the reply
    /// never arrives.
    pub async fn get_async(&mut self) -> Result<Vec<Property>> {
        let xid = self.next_xid();
        self.write_frame(&Encoder::get_async_request(xid)?).await?;
        self.wait_for_message(
            |err| err.xid == xid,
            |msg| match msg {
                Message::GetAsyncReply {
                    xid: reply_xid,
                    properties,
                } if reply_xid == xid => Ok(properties),
                other => Err(other),
            },
        )
        .await
    }

    /// Set this connection's asynchronous-message configuration
    /// (`OFPT_SET_ASYNC`) and wait for a barrier so any rejection
    /// surfaces here rather than later.
    ///
    /// A freshly opened connection does **not** reliably receive
    /// `FLOW_REMOVED` or `PORT_STATUS` until it asks for them: against
    /// real OVS, those events are silently dropped until an explicit
    /// `SET_ASYNC` enables them. Call this (or
    /// [`Self::enable_all_async_events`]) before relying on them.
    ///
    /// # Errors
    ///
    /// Returns an error if the message cannot be written, or if the
    /// switch rejects the configuration (an unsupported reason bit is
    /// answered with `OFPET_ASYNC_CONFIG_FAILED`).
    pub async fn set_async(&mut self, properties: &[Property]) -> Result<()> {
        let xid = self.next_xid();
        self.write_command(xid, Encoder::set_async(xid, properties)?)
            .await?;
        self.send_barrier_after(xid).await
    }

    /// Enable every asynchronous event this crate models, for both the
    /// master/equal and slave reason masks.
    ///
    /// Masks are per-message-kind rather than all-ones because a switch
    /// rejects reason bits it does not define (OVS answers
    /// `OFPET_ASYNC_CONFIG_FAILED`/`OFPACFC_INVALID`).
    ///
    /// # Errors
    ///
    /// As [`Self::set_async`].
    pub async fn enable_all_async_events(&mut self) -> Result<()> {
        const PACKET_IN: u32 = 0x3f; // 6 OFPR_* reasons
        const PORT_STATUS: u32 = 0x7; // 3 OFPPR_* reasons
        const FLOW_REMOVED: u32 = 0x3f; // 6 OFPRR_* reasons
        const ROLE_STATUS: u32 = 0x7; // 3 OFPCRR_* reasons
        const TABLE_STATUS: u32 = 0x18; // OFPTR_VACANCY_DOWN and OFPTR_VACANCY_UP
        const REQUEST_FORWARD: u32 = 0x3; // 2 OFPRFR_* reasons
        const FLOW_STATS: u32 = 0x2; // OFPFSR_STAT_TRIGGER
        const CONTROLLER_STATUS: u32 = 0x7f; // 7 OFPCSR_* reasons
        let properties = vec![
            Property::ReasonMask {
                kind: OFPACPT_PACKET_IN_SLAVE,
                mask: PACKET_IN,
            },
            Property::ReasonMask {
                kind: OFPACPT_PACKET_IN_MASTER,
                mask: PACKET_IN,
            },
            Property::ReasonMask {
                kind: OFPACPT_PORT_STATUS_SLAVE,
                mask: PORT_STATUS,
            },
            Property::ReasonMask {
                kind: OFPACPT_PORT_STATUS_MASTER,
                mask: PORT_STATUS,
            },
            Property::ReasonMask {
                kind: OFPACPT_FLOW_REMOVED_SLAVE,
                mask: FLOW_REMOVED,
            },
            Property::ReasonMask {
                kind: OFPACPT_FLOW_REMOVED_MASTER,
                mask: FLOW_REMOVED,
            },
            Property::ReasonMask {
                kind: OFPACPT_ROLE_STATUS_SLAVE,
                mask: ROLE_STATUS,
            },
            Property::ReasonMask {
                kind: OFPACPT_ROLE_STATUS_MASTER,
                mask: ROLE_STATUS,
            },
            Property::ReasonMask {
                kind: OFPACPT_TABLE_STATUS_SLAVE,
                mask: TABLE_STATUS,
            },
            Property::ReasonMask {
                kind: OFPACPT_TABLE_STATUS_MASTER,
                mask: TABLE_STATUS,
            },
            Property::ReasonMask {
                kind: OFPACPT_REQUESTFORWARD_SLAVE,
                mask: REQUEST_FORWARD,
            },
            Property::ReasonMask {
                kind: OFPACPT_REQUESTFORWARD_MASTER,
                mask: REQUEST_FORWARD,
            },
            Property::ReasonMask {
                kind: OFPACPT_FLOW_STATS_SLAVE,
                mask: FLOW_STATS,
            },
            Property::ReasonMask {
                kind: OFPACPT_FLOW_STATS_MASTER,
                mask: FLOW_STATS,
            },
            Property::ReasonMask {
                kind: OFPACPT_CONT_STATUS_SLAVE,
                mask: CONTROLLER_STATUS,
            },
            Property::ReasonMask {
                kind: OFPACPT_CONT_STATUS_MASTER,
                mask: CONTROLLER_STATUS,
            },
        ];
        self.set_async(&properties).await
    }

    /// Send a flow-mod message.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame cannot be written to the stream.
    async fn send_flow_mod_with_xid(&mut self, mut flow_mod: Rule) -> Result<u32> {
        flow_mod.xid = self.next_xid();
        let xid = flow_mod.xid;
        self.write_command(xid, Encoder::flow_mod(&flow_mod)?)
            .await?;
        Ok(xid)
    }

    /// Send a flow-mod message.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame cannot be written to the stream.
    pub async fn send_flow_mod(&mut self, flow_mod: Rule) -> Result<()> {
        self.send_flow_mod_with_xid(flow_mod).await?;
        Ok(())
    }

    /// Send a flow-mod and wait for the barrier that follows it.
    ///
    /// # Errors
    ///
    /// Returns an error if either frame cannot be written or the barrier
    /// reply never arrives.
    pub async fn add_flow(&mut self, flow_mod: Rule) -> Result<()> {
        let xid = self.send_flow_mod_with_xid(flow_mod).await?;
        self.send_barrier_after(xid).await
    }

    /// Delete flows matching the provided cookie mask and wait for the barrier.
    ///
    /// # Errors
    ///
    /// Returns an error if either frame cannot be written or the barrier
    /// reply never arrives.
    pub async fn delete_flows(&mut self, cookie: Option<u64>) -> Result<()> {
        let mut flow_mod = Rule::delete(self.next_xid(), OFPTT_ALL, Match::any())
            .with_out_port(OFPP_ANY)
            .with_out_group(OFPG_ANY);

        flow_mod = match cookie {
            Some(cookie) => flow_mod.with_cookie(cookie).with_cookie_mask(u64::MAX),
            None => flow_mod.with_cookie(0).with_cookie_mask(0),
        };

        self.write_command(flow_mod.xid, Encoder::flow_mod(&flow_mod)?)
            .await?;
        self.send_barrier_after(flow_mod.xid).await
    }

    /// Send a group-mod message.
    ///
    /// # Errors
    ///
    /// Returns an error if the message fails to encode (see
    /// [`GroupMod::encode`]) or the frame cannot be written to the stream.
    async fn send_group_mod_with_xid(&mut self, mut group_mod: GroupMod) -> Result<u32> {
        group_mod.xid = self.next_xid();
        let xid = group_mod.xid;
        self.write_command(xid, group_mod.encode()?).await?;
        Ok(xid)
    }

    /// Send a group-mod message.
    ///
    /// # Errors
    ///
    /// Returns an error if the message fails to encode (see
    /// [`GroupMod::encode`]) or the frame cannot be written to the stream.
    pub async fn send_group_mod(&mut self, group_mod: GroupMod) -> Result<()> {
        self.send_group_mod_with_xid(group_mod).await?;
        Ok(())
    }

    /// Send a group-mod and wait for the barrier that follows it.
    ///
    /// # Errors
    ///
    /// As [`Self::send_group_mod`], plus an error if the barrier reply
    /// never arrives.
    pub async fn add_group(&mut self, group_mod: GroupMod) -> Result<()> {
        let xid = self.send_group_mod_with_xid(group_mod).await?;
        self.send_barrier_after(xid).await
    }

    /// Send a packet-out message.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame cannot be written to the stream.
    pub async fn send_packet_out(
        &mut self,
        buffer_id: u32,
        in_port: Option<u32>,
        actions: Vec<Action>,
        data: &[u8],
    ) -> Result<()> {
        let xid = self.next_xid();
        self.write_command(
            xid,
            Encoder::packet_out(xid, buffer_id, in_port, actions, data)?,
        )
        .await
    }

    /// Send a meter-mod message.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit, or the frame cannot be written.
    pub async fn send_meter_mod(
        &mut self,
        command: u16,
        flags: u16,
        meter_id: u32,
        bands: &[MeterBand],
    ) -> Result<()> {
        let xid = self.next_xid();
        self.write_command(
            xid,
            Encoder::meter_mod(xid, command, flags, meter_id, bands)?,
        )
        .await
    }

    /// Send a port-mod message.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit, or the frame cannot be written.
    pub async fn send_port_mod(
        &mut self,
        port_no: u32,
        hw_addr: [u8; 6],
        config: u32,
        mask: u32,
        properties: &[PortModProperty],
    ) -> Result<()> {
        let xid = self.next_xid();
        self.write_command(
            xid,
            Encoder::port_mod(xid, port_no, hw_addr, config, mask, properties)?,
        )
        .await
    }

    /// Open a bundle (`OFPBCT_OPEN_REQUEST`).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit, or the frame cannot be written.
    pub async fn bundle_open(&mut self, bundle_id: u32, flags: u16) -> Result<()> {
        let xid = self.next_xid();
        self.write_command(
            xid,
            Encoder::bundle_control(xid, bundle_id, OFPBCT_OPEN_REQUEST, flags, &[])?,
        )
        .await
    }

    /// Add a flow-mod to an open bundle (`OFPT_BUNDLE_ADD_MESSAGE`).
    ///
    /// Sets the nested flow-mod's `xid` to match the `BUNDLE_ADD_MESSAGE`
    /// carrying it, as spec 7.3.9.4 requires (a mismatch is rejected by
    /// real switches, e.g. OVS's `OFPBFC_MSG_BAD_XID`).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit, or the frame cannot be written.
    pub async fn bundle_add_flow_mod(
        &mut self,
        bundle_id: u32,
        flags: u16,
        mut flow_mod: Rule,
    ) -> Result<()> {
        let xid = self.next_xid();
        flow_mod.xid = xid;
        let message = Encoder::flow_mod(&flow_mod)?;
        self.write_command(
            xid,
            Encoder::bundle_add_message(xid, bundle_id, flags, &message, &[])?,
        )
        .await
    }

    /// Commit a bundle (`OFPBCT_COMMIT_REQUEST`) and wait for the barrier
    /// that follows it.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit, either frame cannot be written, or the
    /// barrier reply never arrives.
    pub async fn bundle_commit(&mut self, bundle_id: u32, flags: u16) -> Result<()> {
        let xid = self.next_xid();
        self.write_command(
            xid,
            Encoder::bundle_control(xid, bundle_id, OFPBCT_COMMIT_REQUEST, flags, &[])?,
        )
        .await?;
        self.send_barrier_after(xid).await
    }

    /// Discard a bundle (`OFPBCT_DISCARD_REQUEST`).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit, or the frame cannot be written.
    pub async fn bundle_discard(&mut self, bundle_id: u32, flags: u16) -> Result<()> {
        let xid = self.next_xid();
        self.write_command(
            xid,
            Encoder::bundle_control(xid, bundle_id, OFPBCT_DISCARD_REQUEST, flags, &[])?,
        )
        .await
    }

    /// Send a multipart request and reassemble the full reply, following
    /// `OFPMPF_REPLY_MORE` across as many reply messages as the peer sends,
    /// up to `DEFAULT_MULTIPART_TIMEOUT`. See
    /// [`Self::multipart_request_with_timeout`] to use a different timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer closes the connection, sends an
    /// unexpected message, replies with an `OpenFlow` error, the reassembled
    /// body cannot be decoded for `kind`, or no complete reply arrives
    /// within the timeout.
    pub async fn multipart_request(
        &mut self,
        kind: u16,
        body: &MultipartRequestBody,
    ) -> Result<MultipartReplyBody> {
        self.multipart_request_with_timeout(kind, body, DEFAULT_MULTIPART_TIMEOUT)
            .await
    }

    /// Like [`Self::multipart_request`], but with an explicit timeout for
    /// the whole reassembly loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer closes the connection, sends an
    /// unexpected message, replies with an `OpenFlow` error, the reassembled
    /// body cannot be decoded for `kind`, or no complete reply arrives
    /// within `timeout`.
    pub async fn multipart_request_with_timeout(
        &mut self,
        kind: u16,
        body: &MultipartRequestBody,
        timeout: Duration,
    ) -> Result<MultipartReplyBody> {
        let xid = self.next_xid();
        let frame = Encoder::multipart_request_from_body(xid, kind, 0, body)?;
        self.write_frame(&frame).await?;

        let assembled = tokio::time::timeout(timeout, self.collect_multipart_reply(xid, kind))
            .await
            .map_err(|_| Error::MultipartTimeout)??;

        Ok(MultipartMessage::reply(xid, kind, 0, assembled).typed_reply_body()?)
    }

    async fn collect_multipart_reply(&mut self, xid: u32, kind: u16) -> Result<Vec<u8>> {
        let mut collected = Vec::new();
        let mut parts: usize = 0;
        loop {
            let (flags, chunk) = self
                .wait_for_message(
                    |err| err.xid == xid,
                    |msg| match msg {
                        Message::MultipartReply(reply)
                            if reply.xid == xid && reply.kind == kind =>
                        {
                            Ok((reply.flags, reply.body))
                        }
                        other => Err(other),
                    },
                )
                .await?;

            let next_parts = parts
                .checked_add(1)
                .ok_or(Error::MultipartReplyTooManyParts {
                    max_parts: self.multipart_limits.max_parts,
                    parts: usize::MAX,
                })?;
            if next_parts > self.multipart_limits.max_parts {
                return Err(Error::MultipartReplyTooManyParts {
                    max_parts: self.multipart_limits.max_parts,
                    parts: next_parts,
                });
            }

            let next_size =
                collected
                    .len()
                    .checked_add(chunk.len())
                    .ok_or(Error::MultipartReplyTooLarge {
                        max_bytes: self.multipart_limits.max_bytes,
                        size: usize::MAX,
                    })?;
            if next_size > self.multipart_limits.max_bytes {
                return Err(Error::MultipartReplyTooLarge {
                    max_bytes: self.multipart_limits.max_bytes,
                    size: next_size,
                });
            }

            collected.extend_from_slice(&chunk);
            parts = next_parts;
            if flags & OFPMPF_REPLY_MORE == 0 {
                return Ok(collected);
            }
        }
    }
}

impl Connection<UnixStream> {
    /// Connect to an `OpenFlow` switch over a Unix socket and perform the
    /// handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or handshake fails.
    pub async fn connect_unix(path: impl AsRef<Path>) -> Result<Self> {
        let stream = UnixStream::connect(path).await?;
        let mut client = Self::new(stream);
        client
            .handshake_with_timeout(DEFAULT_HANDSHAKE_TIMEOUT)
            .await?;
        Ok(client)
    }

    /// Connect to an `OpenFlow` switch using an Open vSwitch bridge socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or handshake fails.
    pub async fn connect_bridge(bridge: &str) -> Result<Self> {
        Self::connect_unix(bridge_socket_path(bridge)).await
    }
}

impl Connection<TcpStream> {
    /// Connect to an `OpenFlow` switch over TCP and perform the handshake.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or handshake fails.
    pub async fn connect_tcp(addr: impl ToSocketAddrs) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let mut client = Self::new(stream);
        client
            .handshake_with_timeout(DEFAULT_HANDSHAKE_TIMEOUT)
            .await?;
        Ok(client)
    }
}

fn bridge_socket_path(bridge: &str) -> PathBuf {
    PathBuf::from(format!("/run/openvswitch/{bridge}.mgmt"))
}

#[cfg(all(test, not(clippy)))]
mod tests {
    use super::*;

    use std::time::Duration;

    use crate::protocol::constants::{
        ETH_TYPE_IPV4, OFPCR_ROLE_MASTER, OFPP_FLOOD, OFPT_BARRIER_REPLY, OFPT_BARRIER_REQUEST,
        OFPT_BUNDLE_ADD_MESSAGE, OFPT_BUNDLE_CONTROL, OFPT_ECHO_REPLY, OFPT_ERROR,
        OFPT_FEATURES_REPLY, OFPT_FEATURES_REQUEST, OFPT_FLOW_MOD, OFPT_GET_CONFIG_REQUEST,
        OFPT_GROUP_MOD, OFPT_HELLO, OFPT_PACKET_OUT, OFP_NO_BUFFER, OFP_VERSION_1_5,
    };
    use crate::protocol::header::Header;
    use crate::protocol::instruction::Instruction;
    use crate::protocol::ofmatch::Match;
    use crate::protocol::oxm;
    use tokio::io::DuplexStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    async fn read_frame(stream: &mut DuplexStream) -> Vec<u8> {
        let mut header_buf = [0u8; 8];
        stream.read_exact(&mut header_buf).await.unwrap();

        let header = Header::parse(&header_buf).unwrap();
        let mut frame = Vec::with_capacity(header.length as usize);
        frame.extend_from_slice(&header_buf);

        let body_len = header.length as usize - 8;
        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body).await.unwrap();
        frame.extend_from_slice(&body);

        frame
    }

    async fn read_frame_timeout(stream: &mut DuplexStream) -> Vec<u8> {
        timeout(Duration::from_millis(500), read_frame(stream))
            .await
            .unwrap()
    }

    fn hello_frame(xid: u32) -> Vec<u8> {
        let mut out = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_HELLO,
            length: 8,
            xid,
        }
        .encode(&mut out);
        out
    }

    fn features_reply_frame(xid: u32) -> Vec<u8> {
        let mut out = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_FEATURES_REPLY,
            length: 32,
            xid,
        }
        .encode(&mut out);
        out.extend_from_slice(&0x0011_2233_4455_6677u64.to_be_bytes());
        out.extend_from_slice(&0x0000_0020u32.to_be_bytes());
        out.push(254);
        out.push(0);
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out
    }

    fn barrier_reply_frame(xid: u32) -> Vec<u8> {
        let mut out = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_BARRIER_REPLY,
            length: 8,
            xid,
        }
        .encode(&mut out);
        out
    }

    fn error_frame(xid: u32, error_type: u16, code: u16) -> Vec<u8> {
        let mut out = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_ERROR,
            length: 12,
            xid,
        }
        .encode(&mut out);
        out.extend_from_slice(&error_type.to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out
    }

    #[tokio::test]
    async fn handshake_tracks_features() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let client_hello = read_frame_timeout(&mut server_io).await;
            let client_hello_hdr = Header::parse(&client_hello).unwrap();
            assert_eq!(client_hello_hdr.msg_type, OFPT_HELLO);

            server_io
                .write_all(&hello_frame(7))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_request_hdr = Header::parse(&features_request).unwrap();
            assert_eq!(features_request_hdr.msg_type, OFPT_FEATURES_REQUEST);

            server_io
                .write_all(&features_reply_frame(features_request_hdr.xid))
                .await
                .expect("features reply write");
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();

        let features = client.features().unwrap();
        assert_eq!(features.datapath_id, 0x0011_2233_4455_6677);
        assert_eq!(features.n_tables, 254);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn recv_message_answers_echo_requests() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            server_io
                .write_all(&Encoder::echo_request(77, b"keepalive").unwrap())
                .await
                .expect("echo request write");
            server_io
                .write_all(&barrier_reply_frame(78))
                .await
                .expect("barrier reply write");

            let reply = read_frame_timeout(&mut server_io).await;
            let header = Header::parse(&reply).unwrap();
            assert_eq!(header.msg_type, OFPT_ECHO_REPLY);
            assert_eq!(header.xid, 77);
            assert_eq!(&reply[8..], b"keepalive");
        });

        let mut client = Connection::new(client_io);
        assert!(matches!(
            client.recv_message().await.unwrap(),
            Message::BarrierReply { xid: 78 }
        ));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn optional_config_handshake_accepts_pipelined_replies_in_either_order() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(7))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_header = Header::parse(&features_request).unwrap();
            assert_eq!(features_header.msg_type, OFPT_FEATURES_REQUEST);
            let config_request = read_frame_timeout(&mut server_io).await;
            let config_header = Header::parse(&config_request).unwrap();
            assert_eq!(config_header.msg_type, OFPT_GET_CONFIG_REQUEST);

            // The two responses are deliberately coalesced and reversed to
            // prove that framing and xid matching are independent of TCP
            // packet boundaries and response order.
            let features = features_reply_frame(features_header.xid);
            let config = Encoder::get_config_reply(config_header.xid, 1, 128);
            server_io
                .write_all(&config)
                .await
                .expect("config reply write");
            server_io
                .write_all(&features)
                .await
                .expect("features reply write");
        });

        let mut client = Connection::new(client_io);
        let config = client.handshake_with_config().await.unwrap();
        assert_eq!(config.flags, 1);
        assert_eq!(config.miss_send_len, 128);
        assert_eq!(client.config(), Some(&config));
        assert_eq!(
            client.features().unwrap().datapath_id,
            0x0011_2233_4455_6677
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn request_role_matches_the_role_reply_xid() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(7))
                .await
                .expect("hello write");
            let features_request = read_frame_timeout(&mut server_io).await;
            let features_xid = Header::parse(&features_request).unwrap().xid;
            server_io
                .write_all(&features_reply_frame(features_xid))
                .await
                .expect("features reply write");
            let role_request = read_frame_timeout(&mut server_io).await;
            let role_xid = Header::parse(&role_request).unwrap().xid;
            server_io
                .write_all(&Encoder::role_reply(role_xid, OFPCR_ROLE_MASTER, 7, 99).unwrap())
                .await
                .expect("role reply write");
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();
        let reply = client.request_role(OFPCR_ROLE_MASTER, 7, 99).await.unwrap();
        assert_eq!(reply.role, OFPCR_ROLE_MASTER);
        assert_eq!(reply.short_id, 7);
        assert_eq!(reply.generation_id, 99);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn direct_requests_have_explicit_deadlines() {
        let (client_io, _server_io) = tokio::io::duplex(4096);
        let mut client = Connection::new(client_io);
        assert!(matches!(
            client
                .get_config_with_timeout(Duration::from_millis(10))
                .await,
            Err(Error::RequestTimeout)
        ));

        let (client_io, _server_io) = tokio::io::duplex(4096);
        let mut client = Connection::new(client_io);
        assert!(matches!(
            client
                .request_role_with_timeout(OFPCR_ROLE_MASTER, 0, 1, Duration::from_millis(10))
                .await,
            Err(Error::RequestTimeout)
        ));
    }

    #[tokio::test]
    async fn handshake_ignores_a_features_reply_with_the_wrong_xid() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(7))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let request_xid = Header::parse(&features_request).unwrap().xid;
            server_io
                .write_all(&features_reply_frame(request_xid.wrapping_add(1)))
                .await
                .expect("wrong features reply write");
            server_io
                .write_all(&features_reply_frame(request_xid))
                .await
                .expect("features reply write");
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();
        assert_eq!(client.features().unwrap().xid, 2);
        assert!(matches!(
            client.recv_message().await.unwrap(),
            Message::FeaturesReply(reply) if reply.xid == 3
        ));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn get_async_ignores_replies_and_errors_with_the_wrong_xid() {
        use crate::protocol::constants::{OFPBRC_BAD_TYPE, OFPET_BAD_REQUEST};

        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(7))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_xid = Header::parse(&features_request).unwrap().xid;
            server_io
                .write_all(&features_reply_frame(features_xid))
                .await
                .expect("features reply write");

            let request = read_frame_timeout(&mut server_io).await;
            let request_xid = Header::parse(&request).unwrap().xid;
            server_io
                .write_all(
                    &Encoder::get_async_reply(request_xid.wrapping_add(1), &[])
                        .expect("wrong async reply encodes"),
                )
                .await
                .expect("wrong async reply write");
            server_io
                .write_all(
                    &Encoder::error(
                        request_xid.wrapping_add(1),
                        OFPET_BAD_REQUEST,
                        OFPBRC_BAD_TYPE,
                        b"",
                    )
                    .unwrap(),
                )
                .await
                .expect("wrong error write");
            server_io
                .write_all(
                    &Encoder::get_async_reply(request_xid, &[]).expect("empty async reply encodes"),
                )
                .await
                .expect("async reply write");
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();
        assert!(client.get_async().await.unwrap().is_empty());
        assert!(matches!(
            client.recv_message().await.unwrap(),
            Message::GetAsyncReply { xid: 4, .. }
        ));
        assert!(matches!(
            client.recv_message().await.unwrap(),
            Message::Error(err) if err.xid == 4
        ));

        server.await.unwrap();
    }

    #[test]
    fn pending_message_queue_is_bounded() {
        let (stream, _peer) = tokio::io::duplex(1);
        let mut client = Connection::new(stream);

        for xid in 0..MAX_PENDING_MESSAGES {
            client
                .retain_pending_message(Message::BarrierReply { xid: xid as u32 })
                .unwrap();
        }

        assert!(matches!(
            client.retain_pending_message(Message::BarrierReply { xid: u32::MAX }),
            Err(Error::PendingMessageOverflow)
        ));
    }

    #[tokio::test]
    async fn command_queue_overflow_is_rejected_before_writing() {
        let (stream, mut peer) = tokio::io::duplex(256);
        let mut client = Connection::new(stream);
        for xid in 0..MAX_PENDING_COMMAND_XIDS {
            client.retain_pending_command_xid(xid as u32).unwrap();
        }

        assert!(matches!(
            client
                .send_packet_out(OFP_NO_BUFFER, None, Vec::new(), &[])
                .await,
            Err(Error::PendingMessageOverflow)
        ));
        assert!(timeout(Duration::from_millis(25), peer.read_u8())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn handshake_timeout_is_reported_without_a_peer() {
        let (stream, _peer) = tokio::io::duplex(256);
        let mut client = Connection::new(stream);
        assert!(matches!(
            client
                .handshake_with_timeout(Duration::from_millis(1))
                .await,
            Err(Error::HandshakeTimeout)
        ));
    }

    #[tokio::test]
    async fn add_flow_sends_flow_mod_and_barrier() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(9))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_request_hdr = Header::parse(&features_request).unwrap();
            server_io
                .write_all(&features_reply_frame(features_request_hdr.xid))
                .await
                .expect("features reply write");

            let flow_mod = read_frame_timeout(&mut server_io).await;
            let flow_mod_hdr = Header::parse(&flow_mod).unwrap();
            assert_eq!(flow_mod_hdr.msg_type, OFPT_FLOW_MOD);

            let barrier = read_frame_timeout(&mut server_io).await;
            let barrier_hdr = Header::parse(&barrier).unwrap();
            assert_eq!(barrier_hdr.msg_type, OFPT_BARRIER_REQUEST);

            server_io
                .write_all(&barrier_reply_frame(barrier_hdr.xid))
                .await
                .expect("barrier reply write");
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();

        let flow = Rule::add(
            100,
            0,
            42,
            Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]),
            vec![Instruction::apply_actions(vec![])],
        );
        client.add_flow(flow).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn barrier_reports_an_error_from_a_batched_flow_mod() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(1))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_xid = Header::parse(&features_request).unwrap().xid;
            server_io
                .write_all(&features_reply_frame(features_xid))
                .await
                .expect("features reply write");

            let flow_mod = read_frame_timeout(&mut server_io).await;
            let flow_mod_xid = Header::parse(&flow_mod).unwrap().xid;
            let barrier = read_frame_timeout(&mut server_io).await;
            let barrier_xid = Header::parse(&barrier).unwrap().xid;

            server_io
                .write_all(&error_frame(flow_mod_xid, 3, 9))
                .await
                .expect("flow-mod error write");
            server_io
                .write_all(&barrier_reply_frame(barrier_xid))
                .await
                .expect("barrier reply write");
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();
        client
            .send_flow_mod(Rule::add(0, 0, 42, Match::any(), vec![]))
            .await
            .unwrap();

        assert!(matches!(
            client.send_barrier().await,
            Err(Error::Remote { .. })
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn add_group_sends_group_mod_and_barrier() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(1))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_request_hdr = Header::parse(&features_request).unwrap();
            server_io
                .write_all(&features_reply_frame(features_request_hdr.xid))
                .await
                .expect("features reply write");

            let group_mod = read_frame_timeout(&mut server_io).await;
            let group_mod_hdr = Header::parse(&group_mod).unwrap();
            assert_eq!(group_mod_hdr.msg_type, OFPT_GROUP_MOD);

            let barrier = read_frame_timeout(&mut server_io).await;
            let barrier_hdr = Header::parse(&barrier).unwrap();
            assert_eq!(barrier_hdr.msg_type, OFPT_BARRIER_REQUEST);

            server_io
                .write_all(&barrier_reply_frame(barrier_hdr.xid))
                .await
                .expect("barrier reply write");
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();

        client
            .add_group(crate::protocol::control::GroupMod::delete(0, 1))
            .await
            .unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn send_packet_out_writes_a_packet_out_frame() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(1))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_request_hdr = Header::parse(&features_request).unwrap();
            server_io
                .write_all(&features_reply_frame(features_request_hdr.xid))
                .await
                .expect("features reply write");

            let packet_out = read_frame_timeout(&mut server_io).await;
            let packet_out_hdr = Header::parse(&packet_out).unwrap();
            assert_eq!(packet_out_hdr.msg_type, OFPT_PACKET_OUT);
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();

        client
            .send_packet_out(
                OFP_NO_BUFFER,
                Some(1),
                vec![crate::protocol::action::Action::output(OFPP_FLOOD)],
                b"payload",
            )
            .await
            .unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn bundle_open_add_flow_mod_commit_sequence() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(1))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_request_hdr = Header::parse(&features_request).unwrap();
            server_io
                .write_all(&features_reply_frame(features_request_hdr.xid))
                .await
                .expect("features reply write");

            let open = read_frame_timeout(&mut server_io).await;
            let open_hdr = Header::parse(&open).unwrap();
            assert_eq!(open_hdr.msg_type, OFPT_BUNDLE_CONTROL);

            let add = read_frame_timeout(&mut server_io).await;
            let add_hdr = Header::parse(&add).unwrap();
            assert_eq!(add_hdr.msg_type, OFPT_BUNDLE_ADD_MESSAGE);

            let commit = read_frame_timeout(&mut server_io).await;
            let commit_hdr = Header::parse(&commit).unwrap();
            assert_eq!(commit_hdr.msg_type, OFPT_BUNDLE_CONTROL);

            let barrier = read_frame_timeout(&mut server_io).await;
            let barrier_hdr = Header::parse(&barrier).unwrap();
            assert_eq!(barrier_hdr.msg_type, OFPT_BARRIER_REQUEST);

            server_io
                .write_all(&barrier_reply_frame(barrier_hdr.xid))
                .await
                .expect("barrier reply write");
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();

        let flow = Rule::add(
            0,
            0,
            42,
            Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]),
            vec![Instruction::apply_actions(vec![])],
        );
        client.bundle_open(1, 0).await.unwrap();
        client.bundle_add_flow_mod(1, 0, flow).await.unwrap();
        client.bundle_commit(1, 0).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn delete_flows_supports_cookie_filtering() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(11))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_request_hdr = Header::parse(&features_request).unwrap();
            server_io
                .write_all(&features_reply_frame(features_request_hdr.xid))
                .await
                .expect("features reply write");

            let flow_mod = read_frame_timeout(&mut server_io).await;
            let flow_mod_hdr = Header::parse(&flow_mod).unwrap();
            assert_eq!(flow_mod_hdr.msg_type, OFPT_FLOW_MOD);

            let barrier = read_frame_timeout(&mut server_io).await;
            let barrier_hdr = Header::parse(&barrier).unwrap();
            assert_eq!(barrier_hdr.msg_type, OFPT_BARRIER_REQUEST);

            server_io
                .write_all(&barrier_reply_frame(barrier_hdr.xid))
                .await
                .expect("barrier reply write");
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();
        client.delete_flows(Some(0xdead_beef)).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_rejects_error_reply() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(1))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_request_hdr = Header::parse(&features_request).unwrap();
            server_io
                .write_all(&error_frame(features_request_hdr.xid, 1, 2))
                .await
                .expect("error write");
        });

        let mut client = Connection::new(client_io);
        let err = client.handshake().await.unwrap_err();
        assert!(matches!(err, Error::Remote { .. }));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn multipart_request_reassembles_more_flagged_replies() {
        use crate::protocol::constants::{
            OFPMPF_REPLY_MORE, OFPMP_TABLE_STATS, OFPT_MULTIPART_REQUEST,
        };
        use crate::protocol::control::{MultipartReplyBody, MultipartRequestBody, TableStatsEntry};

        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let entry_one = TableStatsEntry {
            table_id: 0,
            active_count: 1,
            lookup_count: 2,
            matched_count: 3,
        };
        let entry_two = TableStatsEntry {
            table_id: 1,
            active_count: 4,
            lookup_count: 5,
            matched_count: 6,
        };
        let entry_one_bytes = MultipartMessage::from_reply_body(
            0,
            OFPMP_TABLE_STATS,
            0,
            &MultipartReplyBody::TableStats(vec![entry_one.clone()]),
        )
        .unwrap()
        .body;
        let entry_two_bytes = MultipartMessage::from_reply_body(
            0,
            OFPMP_TABLE_STATS,
            0,
            &MultipartReplyBody::TableStats(vec![entry_two.clone()]),
        )
        .unwrap()
        .body;

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(1))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_request_hdr = Header::parse(&features_request).unwrap();
            server_io
                .write_all(&features_reply_frame(features_request_hdr.xid))
                .await
                .expect("features reply write");

            let multipart_request = read_frame_timeout(&mut server_io).await;
            let multipart_request_hdr = Header::parse(&multipart_request).unwrap();
            assert_eq!(multipart_request_hdr.msg_type, OFPT_MULTIPART_REQUEST);
            let xid = multipart_request_hdr.xid;

            server_io
                .write_all(
                    &Encoder::multipart_reply(
                        xid,
                        OFPMP_TABLE_STATS,
                        OFPMPF_REPLY_MORE,
                        &entry_one_bytes,
                    )
                    .unwrap(),
                )
                .await
                .expect("first reply write");
            server_io
                .write_all(
                    &Encoder::multipart_reply(xid, OFPMP_TABLE_STATS, 0, &entry_two_bytes).unwrap(),
                )
                .await
                .expect("second reply write");
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();

        let reply = client
            .multipart_request(OFPMP_TABLE_STATS, &MultipartRequestBody::Empty)
            .await
            .unwrap();
        assert_eq!(
            reply,
            MultipartReplyBody::TableStats(vec![entry_one, entry_two])
        );

        server.await.unwrap();
    }

    /// Spec 7.3.5: a multipart reply may span an arbitrary number of
    /// `OFPMPF_REPLY_MORE`-flagged messages, not just two. A reassembly bug
    /// that only handles a single continuation (e.g. state cleared after
    /// the first `MORE` chunk) would pass the two-fragment test above but
    /// fail here.
    #[tokio::test]
    async fn multipart_request_reassembles_more_than_two_fragments() {
        use crate::protocol::constants::{
            OFPMPF_REPLY_MORE, OFPMP_TABLE_STATS, OFPT_MULTIPART_REQUEST,
        };
        use crate::protocol::control::{MultipartReplyBody, MultipartRequestBody, TableStatsEntry};

        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let entries: Vec<TableStatsEntry> = (0..4)
            .map(|i| TableStatsEntry {
                table_id: i,
                active_count: u32::from(i),
                lookup_count: u64::from(i) * 10,
                matched_count: u64::from(i) * 100,
            })
            .collect();
        let entry_bytes: Vec<Vec<u8>> = entries
            .iter()
            .map(|entry| {
                MultipartMessage::from_reply_body(
                    0,
                    OFPMP_TABLE_STATS,
                    0,
                    &MultipartReplyBody::TableStats(vec![entry.clone()]),
                )
                .unwrap()
                .body
            })
            .collect();

        let expected = entries.clone();
        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(1))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_request_hdr = Header::parse(&features_request).unwrap();
            server_io
                .write_all(&features_reply_frame(features_request_hdr.xid))
                .await
                .expect("features reply write");

            let multipart_request = read_frame_timeout(&mut server_io).await;
            let multipart_request_hdr = Header::parse(&multipart_request).unwrap();
            assert_eq!(multipart_request_hdr.msg_type, OFPT_MULTIPART_REQUEST);
            let xid = multipart_request_hdr.xid;

            let last = entry_bytes.len() - 1;
            for (i, body) in entry_bytes.iter().enumerate() {
                let flags = if i == last { 0 } else { OFPMPF_REPLY_MORE };
                server_io
                    .write_all(
                        &Encoder::multipart_reply(xid, OFPMP_TABLE_STATS, flags, body).unwrap(),
                    )
                    .await
                    .unwrap_or_else(|_| panic!("reply {i} write"));
            }
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();

        let reply = client
            .multipart_request(OFPMP_TABLE_STATS, &MultipartRequestBody::Empty)
            .await
            .unwrap();
        assert_eq!(reply, MultipartReplyBody::TableStats(expected));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn multipart_reply_rejects_oversized_aggregate_before_extending() {
        use crate::protocol::constants::{OFPMPF_REPLY_MORE, OFPMP_TABLE_STATS};

        let (client_io, mut server_io) = tokio::io::duplex(1024);
        server_io
            .write_all(
                &Encoder::multipart_reply(1, OFPMP_TABLE_STATS, OFPMPF_REPLY_MORE, &[1, 2, 3])
                    .unwrap(),
            )
            .await
            .unwrap();
        server_io
            .write_all(&Encoder::multipart_reply(1, OFPMP_TABLE_STATS, 0, &[4]).unwrap())
            .await
            .unwrap();

        let mut client = Connection::with_multipart_limits(
            client_io,
            MultipartLimits {
                max_bytes: 3,
                max_parts: 2,
            },
        );
        let err = client
            .collect_multipart_reply(1, OFPMP_TABLE_STATS)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            Error::MultipartReplyTooLarge {
                max_bytes: 3,
                size: 4
            }
        ));
    }

    #[tokio::test]
    async fn multipart_reply_rejects_excessive_part_count_before_extending() {
        use crate::protocol::constants::{OFPMPF_REPLY_MORE, OFPMP_TABLE_STATS};

        let (client_io, mut server_io) = tokio::io::duplex(1024);
        server_io
            .write_all(
                &Encoder::multipart_reply(1, OFPMP_TABLE_STATS, OFPMPF_REPLY_MORE, &[1, 2])
                    .unwrap(),
            )
            .await
            .unwrap();
        server_io
            .write_all(&Encoder::multipart_reply(1, OFPMP_TABLE_STATS, 0, &[3, 4]).unwrap())
            .await
            .unwrap();

        let mut client = Connection::with_multipart_limits(
            client_io,
            MultipartLimits {
                max_bytes: 4,
                max_parts: 1,
            },
        );
        let err = client
            .collect_multipart_reply(1, OFPMP_TABLE_STATS)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            Error::MultipartReplyTooManyParts {
                max_parts: 1,
                parts: 2
            }
        ));
    }

    /// A multipart request whose reply never completes (the peer sends a
    /// `MORE`-flagged fragment and then stalls forever) must time out
    /// rather than hang the caller indefinitely.
    #[tokio::test]
    async fn multipart_request_times_out_on_incomplete_reply() {
        use crate::protocol::constants::{
            OFPMPF_REPLY_MORE, OFPMP_TABLE_STATS, OFPT_MULTIPART_REQUEST,
        };
        use crate::protocol::control::{MultipartReplyBody, MultipartRequestBody, TableStatsEntry};

        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let entry = TableStatsEntry {
            table_id: 0,
            active_count: 1,
            lookup_count: 2,
            matched_count: 3,
        };
        let entry_bytes = MultipartMessage::from_reply_body(
            0,
            OFPMP_TABLE_STATS,
            0,
            &MultipartReplyBody::TableStats(vec![entry]),
        )
        .unwrap()
        .body;

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(1))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_request_hdr = Header::parse(&features_request).unwrap();
            server_io
                .write_all(&features_reply_frame(features_request_hdr.xid))
                .await
                .expect("features reply write");

            let multipart_request = read_frame_timeout(&mut server_io).await;
            let multipart_request_hdr = Header::parse(&multipart_request).unwrap();
            assert_eq!(multipart_request_hdr.msg_type, OFPT_MULTIPART_REQUEST);
            let xid = multipart_request_hdr.xid;

            // Send only a MORE-flagged fragment, then never send the
            // terminating reply: keep server_io alive so the connection
            // doesn't just close out from under the client.
            server_io
                .write_all(
                    &Encoder::multipart_reply(
                        xid,
                        OFPMP_TABLE_STATS,
                        OFPMPF_REPLY_MORE,
                        &entry_bytes,
                    )
                    .unwrap(),
                )
                .await
                .expect("first reply write");

            // Hold the connection open past the client's short timeout.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();

        let err = client
            .multipart_request_with_timeout(
                OFPMP_TABLE_STATS,
                &MultipartRequestBody::Empty,
                Duration::from_millis(50),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::MultipartTimeout));

        server.await.unwrap();
    }

    /// Client-side mirror of the server's version-negotiation rejection:
    /// if the peer's Hello advertises a version this crate can't speak,
    /// `handshake()` must send `HelloFailed`/`Incompatible` and fail rather
    /// than silently proceeding as if negotiation succeeded.
    #[tokio::test]
    async fn handshake_rejects_incompatible_hello_version() {
        use crate::protocol::constants::{OFPET_HELLO_FAILED, OFPHFC_INCOMPATIBLE, OFPT_ERROR};
        use crate::protocol::error::OfError;

        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            // OpenFlow 1.0 header, no version bitmap: incompatible with
            // this crate, which only ever speaks 1.5.
            let mut incompatible_hello = Vec::new();
            Header {
                version: 0x01,
                msg_type: OFPT_HELLO,
                length: 8,
                xid: 5,
            }
            .encode(&mut incompatible_hello);
            server_io
                .write_all(&incompatible_hello)
                .await
                .expect("incompatible hello write");

            let fail = read_frame_timeout(&mut server_io).await;
            let fail_hdr = Header::parse(&fail).unwrap();
            assert_eq!(fail_hdr.msg_type, OFPT_ERROR);
            let error_type = u16::from_be_bytes([fail[8], fail[9]]);
            let code = u16::from_be_bytes([fail[10], fail[11]]);
            assert_eq!(error_type, OFPET_HELLO_FAILED);
            assert_eq!(code, OFPHFC_INCOMPATIBLE);
        });

        let mut client = Connection::new(client_io);
        let err = client.handshake().await.unwrap_err();
        assert!(matches!(
            err,
            Error::Protocol(OfError::UnsupportedVersion(0x01))
        ));

        server.await.unwrap();
    }

    /// The handshake's third arm: the peer answered with a message that is
    /// neither a hello nor an error, so there is nothing to negotiate.
    #[tokio::test]
    async fn handshake_rejects_a_non_hello_first_message() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            // A barrier reply is a perfectly valid frame, just not a
            // legal answer to our hello.
            server_io
                .write_all(&Encoder::barrier_reply(1))
                .await
                .expect("write barrier reply");
        });

        let mut client = Connection::new(client_io);
        let err = client.handshake().await.unwrap_err();
        match err {
            Error::UnexpectedMessage { expected, .. } => assert_eq!(expected, "hello"),
            other => panic!("expected UnexpectedMessage, got: {other}"),
        }

        server.await.unwrap();
    }

    /// A switch that rejects the handshake outright by replying to our
    /// Hello with `OFPT_ERROR` (instead of its own Hello) must surface as
    /// `Error::Remote`, carrying the switch's error type/code/data.
    #[tokio::test]
    async fn handshake_reports_a_remote_error_reply() {
        use crate::protocol::constants::{OFPET_HELLO_FAILED, OFPHFC_EPERM};

        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let hello = read_frame_timeout(&mut server_io).await;
            let hdr = Header::parse(&hello).unwrap();
            server_io
                .write_all(
                    &Encoder::error(hdr.xid, OFPET_HELLO_FAILED, OFPHFC_EPERM, b"no").unwrap(),
                )
                .await
                .expect("write error reply");
        });

        let mut client = Connection::new(client_io);
        let err = client.handshake().await.unwrap_err();
        match err {
            Error::Remote {
                error_type, code, ..
            } => {
                assert_eq!(error_type, OFPET_HELLO_FAILED);
                assert_eq!(code, OFPHFC_EPERM);
            }
            other => panic!("expected Error::Remote, got: {other}"),
        }

        server.await.unwrap();
    }

    /// If the switch answers a multipart request with `OFPT_ERROR` instead
    /// of a multipart reply, the request must fail with `Error::Remote`
    /// rather than hang until the timeout.
    #[tokio::test]
    async fn multipart_request_reports_a_remote_error_reply() {
        use crate::protocol::constants::{
            OFPBRC_BAD_MULTIPART, OFPET_BAD_REQUEST, OFPMP_TABLE_STATS, OFPT_MULTIPART_REQUEST,
        };
        use crate::protocol::control::MultipartRequestBody;

        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let _ = read_frame_timeout(&mut server_io).await;
            server_io
                .write_all(&hello_frame(1))
                .await
                .expect("hello write");

            let features_request = read_frame_timeout(&mut server_io).await;
            let features_request_hdr = Header::parse(&features_request).unwrap();
            server_io
                .write_all(&features_reply_frame(features_request_hdr.xid))
                .await
                .expect("features reply write");

            let multipart_request = read_frame_timeout(&mut server_io).await;
            let multipart_request_hdr = Header::parse(&multipart_request).unwrap();
            assert_eq!(multipart_request_hdr.msg_type, OFPT_MULTIPART_REQUEST);
            server_io
                .write_all(
                    &Encoder::error(
                        multipart_request_hdr.xid,
                        OFPET_BAD_REQUEST,
                        OFPBRC_BAD_MULTIPART,
                        b"",
                    )
                    .unwrap(),
                )
                .await
                .expect("error reply write");
        });

        let mut client = Connection::new(client_io);
        client.handshake().await.unwrap();

        let err = client
            .multipart_request(OFPMP_TABLE_STATS, &MultipartRequestBody::Empty)
            .await
            .unwrap_err();
        match err {
            Error::Remote {
                error_type, code, ..
            } => {
                assert_eq!(error_type, OFPET_BAD_REQUEST);
                assert_eq!(code, OFPBRC_BAD_MULTIPART);
            }
            other => panic!("expected Error::Remote, got: {other}"),
        }

        server.await.unwrap();
    }

    /// A frame whose header is well formed but whose body is malformed
    /// must surface as a protocol error, not a panic or a hang.
    #[tokio::test]
    async fn reading_a_malformed_frame_reports_a_protocol_error() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            // A PACKET_IN whose declared length covers the buffer but
            // whose match block is nonsense.
            let mut frame = vec![
                OFP_VERSION_1_5,
                crate::protocol::constants::OFPT_PACKET_IN,
                0,
                32,
            ];
            frame.extend_from_slice(&7u32.to_be_bytes());
            frame.resize(24, 0);
            frame.extend_from_slice(&0xffffu16.to_be_bytes()); // bad match type
            frame.extend_from_slice(&4u16.to_be_bytes());
            frame.resize(32, 0);
            server_io.write_all(&frame).await.expect("write");
        });

        let mut client = Connection::new(client_io);
        assert!(
            client.recv_message().await.is_err(),
            "a malformed packet-in must be reported as an error"
        );
        server.await.unwrap();
    }
}
