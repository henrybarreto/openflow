//! The fixed 8-byte `ofp_header` every `OpenFlow` message starts with.
//!
//! Its layout (version, type, length, xid) is stable across `OpenFlow`
//! versions, which is what makes version negotiation possible: a peer's
//! Hello can be read even when its version is one this crate does not
//! speak.

use crate::protocol::constants::{OFPT_HELLO, OFP_VERSION_1_5};
use crate::protocol::error::{OfError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
/// A decoded `ofp_header`.
pub struct Header {
    /// Wire version; `OFP_VERSION_1_5` (`0x06`) for this crate.
    pub version: u8,
    /// The `OFPT_*` message type.
    pub msg_type: u8,
    /// Total message length in bytes, header included. Never below 8.
    pub length: u16,
    /// Transaction id, echoed by a reply to correlate it with its request.
    pub xid: u32,
}

impl Header {
    /// Parse an `OpenFlow` header from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short or the encoded length is
    /// invalid.
    ///
    /// A peer's Hello may legitimately arrive with a header version other
    /// than 1.5 as part of version negotiation (see
    /// `hello::is_version_compatible`). Every other message is rejected when
    /// its header version is not 1.5.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let bytes = buf.first_chunk::<8>().ok_or(OfError::ShortBuffer)?;
        let version = bytes[0];
        let msg_type = bytes[1];
        let length = u16::from_be_bytes([bytes[2], bytes[3]]);
        let xid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        if length < 8 {
            return Err(OfError::InvalidLength(length));
        }
        if msg_type != OFPT_HELLO && version != OFP_VERSION_1_5 {
            return Err(OfError::UnsupportedVersion(version));
        }

        Ok(Self {
            version,
            msg_type,
            length,
            xid,
        })
    }

    /// Append this header's 8 bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.version);
        out.push(self.msg_type);
        out.extend_from_slice(&self.length.to_be_bytes());
        out.extend_from_slice(&self.xid.to_be_bytes());
    }
}
