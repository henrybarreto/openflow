//! `OFPT_ECHO_REQUEST` / `OFPT_ECHO_REPLY` (§7.5.2--7.5.3 -- keepalives).
//!
//! An echo reply must return the request's payload unchanged, so a
//! controller can use it both as a liveness probe and as a round-trip
//! timer.

use crate::protocol::bytes::checked_u16_len;
use crate::protocol::constants::{
    OFPT_ECHO_REPLY, OFPT_ECHO_REQUEST, OFP_HEADER_LEN, OFP_VERSION_1_5,
};
use crate::protocol::error::Result;
use crate::protocol::header::Header;

#[derive(Debug, Clone, PartialEq, Eq)]
/// An echo request or reply: a header plus an opaque payload.
pub struct Echo {
    /// Transaction id; a reply must echo the request's.
    pub xid: u32,
    /// Arbitrary bytes the peer must return unchanged in its reply.
    pub payload: Vec<u8>,
}

impl Echo {
    /// An echo with the given transaction id and payload.
    #[must_use]
    pub const fn new(xid: u32, payload: Vec<u8>) -> Self {
        Self { xid, payload }
    }

    /// Encode as `OFPT_ECHO_REQUEST`.
    /// # Errors
    ///
    /// Returns an error if the payload does not fit in the header's `u16`
    /// length field.
    pub fn encode_request(&self) -> Result<Vec<u8>> {
        self.encode(OFPT_ECHO_REQUEST)
    }

    /// Encode as `OFPT_ECHO_REPLY`.
    /// # Errors
    ///
    /// Returns an error if the payload does not fit in the header's `u16`
    /// length field.
    pub fn encode_reply(&self) -> Result<Vec<u8>> {
        self.encode(OFPT_ECHO_REPLY)
    }

    fn encode(&self, msg_type: u8) -> Result<Vec<u8>> {
        let length = OFP_HEADER_LEN + self.payload.len();
        let length = checked_u16_len(length)?;
        let mut out = Vec::with_capacity(usize::from(length));

        Header {
            version: OFP_VERSION_1_5,
            msg_type,
            length,
            xid: self.xid,
        }
        .encode(&mut out);

        out.extend_from_slice(&self.payload);
        Ok(out)
    }
}

/// Encode an echo reply frame.
///
/// Low-level form of [`crate::protocol::codec::Encoder::echo_reply`].
///
/// # Errors
///
/// Returns an error if the encoded frame exceeds the wire length limit.
pub fn encode_echo_reply(xid: u32, payload: &[u8]) -> Result<Vec<u8>> {
    Echo::new(xid, payload.to_vec()).encode_reply()
}

/// Encode an echo request frame.
///
/// Low-level form of [`crate::protocol::codec::Encoder::echo_request`].
///
/// # Errors
///
/// Returns an error if the encoded frame exceeds the wire length limit.
pub fn encode_echo_request(xid: u32, payload: &[u8]) -> Result<Vec<u8>> {
    Echo::new(xid, payload.to_vec()).encode_request()
}
