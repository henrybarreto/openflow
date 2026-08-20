//! Per-connection state for the bundled learning-switch controller: what
//! the switch told us about itself, and what we have learned since.

use std::collections::HashMap;
use tokio::net::TcpStream;

use crate::protocol::control::Property;

/// Default maximum number of bundles retained on one switch connection.
pub const DEFAULT_MAX_OPEN_BUNDLES: usize = 64;
/// Default maximum number of nested messages retained in one bundle.
pub const DEFAULT_MAX_MESSAGES_PER_BUNDLE: usize = 1024;
/// Default maximum number of nested-message bytes retained across one
/// connection's open bundles.
pub const DEFAULT_MAX_TOTAL_BUNDLE_BYTES: usize = 4 * 1024 * 1024;
/// Default maximum number of learned source MAC addresses on one connection.
pub const DEFAULT_MAX_MAC_ENTRIES: usize = 4096;

/// Resource limits applied independently to each switch connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLimits {
    /// Maximum number of open or closed-but-not-discarded bundles.
    pub max_open_bundles: usize,
    /// Maximum number of nested messages retained in one bundle.
    pub max_messages_per_bundle: usize,
    /// Maximum total length of retained nested messages across all bundles.
    pub max_total_bundle_bytes: usize,
    /// Maximum number of learned source MAC addresses.
    pub max_mac_entries: usize,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_open_bundles: DEFAULT_MAX_OPEN_BUNDLES,
            max_messages_per_bundle: DEFAULT_MAX_MESSAGES_PER_BUNDLE,
            max_total_bundle_bytes: DEFAULT_MAX_TOTAL_BUNDLE_BYTES,
            max_mac_entries: DEFAULT_MAX_MAC_ENTRIES,
        }
    }
}

#[derive(Debug)]
/// How far a switch connection has progressed through the handshake.
pub enum State {
    /// The TCP connection is up; nothing has been exchanged yet.
    Connected,
    /// Hellos have been exchanged and the version is agreed. The contained
    /// transaction id identifies the outstanding features request.
    HelloDone {
        /// XID of the controller's outstanding features request.
        features_xid: u32,
    },
    /// The features reply has arrived, so the datapath is identified. The
    /// contained transaction id identifies the outstanding config request.
    FeaturesKnown {
        /// XID of the controller's outstanding get-config request.
        get_config_xid: u32,
    },
    /// Configured and forwarding: packet-ins are being handled.
    Running,
}

#[derive(Debug)]
/// One open bundle's accumulated state.
///
/// This is the controller's own bookkeeping for bundles a switch opened
/// against it, not switch-side atomicity.
pub struct BundleRecord {
    /// `OFPBF_*` flags the bundle was opened with.
    pub flags: u16,
    /// Whether an `OFPBCT_CLOSE_REQUEST` has been seen, after which no
    /// further messages may be added.
    pub closed: bool,
    /// The encoded messages added so far, in arrival order.
    pub messages: Vec<Vec<u8>>,
}

#[derive(Debug)]
/// One switch connected to this controller.
///
/// The `Option` fields are unset until the handshake fills them in from
/// the switch's features and config replies.
pub struct Connection<S = TcpStream> {
    /// Controller-local connection id, for logging.
    pub id: u64,
    /// Datapath id from the features reply.
    pub datapath_id: Option<u64>,
    /// How many packets the switch can buffer, from the features reply.
    pub n_buffers: Option<u32>,
    /// Number of pipeline tables, from the features reply.
    pub n_tables: Option<u8>,
    /// 0 for a main connection, non-zero for an auxiliary one.
    pub auxiliary_id: Option<u8>,
    /// `OFPC_*` capability bits from the features reply.
    pub capabilities: Option<u32>,
    /// `OFPC_FRAG_*` bits from the config reply.
    pub config_flags: Option<u16>,
    /// The switch's `miss_send_len`, from the config reply.
    pub miss_send_len: Option<u16>,
    /// This connection's `OFPCR_ROLE_*` role.
    pub role: u32,
    /// Controller short id, as used by `OFPT_ROLE_STATUS`.
    pub short_id: u16,
    /// Generation id of the last accepted role request; a role request
    /// with an older one is rejected as stale. It is `u64::MAX` until the
    /// first master/slave request is accepted, as required by the protocol.
    pub generation_id: u64,
    /// Whether `generation_id` came from an accepted master/slave request.
    /// The separate flag matters because `u64::MAX` is both the protocol's
    /// initial sentinel and a valid wrapping sequence number.
    pub generation_id_defined: bool,
    /// The async-event mask this connection last set.
    pub async_config: Vec<Property>,
    /// Open bundles, keyed by bundle id.
    pub bundles: HashMap<u32, BundleRecord>,
    /// Handshake progress.
    pub state: State,
    /// The socket to this switch.
    pub stream: S,
    /// Next transaction id to hand out.
    pub next_xid: u32,
    /// Learned MAC-to-port table driving the learning-switch policy.
    pub mac_table: HashMap<[u8; 6], u32>,
}

impl<S> Connection<S> {
    /// Hand out the next transaction id, wrapping at `u32::MAX`.
    pub const fn next_xid(&mut self) -> u32 {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1);
        xid
    }
}
