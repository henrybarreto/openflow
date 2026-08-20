//! `OFPT_BARRIER_REQUEST` / `OFPT_BARRIER_REPLY` (§7.3.7).
//!
//! A barrier makes the switch finish processing every message it received
//! before the barrier, then answer. It is how a controller turns the
//! otherwise fire-and-forget message stream into something it can wait on.
//! [`crate::client::Connection::send_barrier`] is the usual entry point.

use crate::protocol::constants::{
    OFPT_BARRIER_REPLY, OFPT_BARRIER_REQUEST, OFP_HEADER_LEN, OFP_VERSION_1_5,
};
use crate::protocol::header::Header;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A barrier request or reply; both are a bare `OpenFlow` header.
pub struct Barrier {
    /// Transaction id echoed by the peer in its reply.
    pub xid: u32,
}

impl Barrier {
    /// A barrier with the given transaction id.
    #[must_use]
    pub const fn new(xid: u32) -> Self {
        Self { xid }
    }

    /// Encode as `OFPT_BARRIER_REQUEST`.
    #[must_use]
    pub fn encode_request(&self) -> Vec<u8> {
        self.encode(OFPT_BARRIER_REQUEST)
    }

    /// Encode as `OFPT_BARRIER_REPLY`.
    #[must_use]
    pub fn encode_reply(&self) -> Vec<u8> {
        self.encode(OFPT_BARRIER_REPLY)
    }

    fn encode(self, msg_type: u8) -> Vec<u8> {
        let mut out = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type,
            length: u16::try_from(OFP_HEADER_LEN).unwrap_or(u16::MAX),
            xid: self.xid,
        }
        .encode(&mut out);
        out
    }
}

/// Encode a barrier request frame.
///
/// Low-level form of [`crate::protocol::codec::Encoder::barrier_request`].
#[must_use]
pub fn encode_barrier_request(xid: u32) -> Vec<u8> {
    Barrier::new(xid).encode_request()
}

/// Encode a barrier reply frame.
///
/// Low-level form of [`crate::protocol::codec::Encoder::barrier_reply`].
#[must_use]
pub fn encode_barrier_reply(xid: u32) -> Vec<u8> {
    Barrier::new(xid).encode_reply()
}
