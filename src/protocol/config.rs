//! `OFPT_SET_CONFIG` / `OFPT_GET_CONFIG_REQUEST` / `OFPT_GET_CONFIG_REPLY`
//! (`ofp_switch_config`, §7.3.2).

use crate::protocol::bytes::read_u16;
use crate::protocol::constants::{
    OFPT_GET_CONFIG_REPLY, OFPT_GET_CONFIG_REQUEST, OFPT_SET_CONFIG, OFP_HEADER_LEN,
    OFP_VERSION_1_5,
};
use crate::protocol::error::{OfError, Result};
use crate::protocol::header::Header;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A switch's global configuration: fragment handling plus how much of a
/// packet accompanies a packet-in.
///
/// ```
/// use openflow::protocol::config::Config;
/// use openflow::protocol::constants::OFPCML_NO_BUFFER;
///
/// // Send whole packets to the controller instead of buffering them.
/// let cfg = Config::new(1, 0, OFPCML_NO_BUFFER);
/// assert_eq!(cfg.encode_set().len(), 12);
/// ```
pub struct Config {
    /// Transaction id.
    pub xid: u32,
    /// `OFPC_FRAG_*` fragment-handling bits.
    pub flags: u16,
    /// Bytes of each packet included in an `OFPT_PACKET_IN` the pipeline
    /// raised on its own (a table miss, an invalid TTL). A packet-in
    /// caused by an explicit output to `OFPP_CONTROLLER` is bounded by
    /// that action's `max_len` instead. 0 sends no packet bytes;
    /// `OFPCML_NO_BUFFER` sends the whole packet and buffers nothing.
    pub miss_send_len: u16,
}

impl Config {
    /// A config message with the given flags and miss-send length.
    #[must_use]
    pub const fn new(xid: u32, flags: u16, miss_send_len: u16) -> Self {
        Self {
            xid,
            flags,
            miss_send_len,
        }
    }

    /// Encode an `OFPT_GET_CONFIG_REQUEST` (header only).
    #[must_use]
    pub fn get_request(xid: u32) -> Vec<u8> {
        let mut out = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_GET_CONFIG_REQUEST,
            length: u16::try_from(OFP_HEADER_LEN).unwrap_or(u16::MAX),
            xid,
        }
        .encode(&mut out);
        out
    }

    /// Encode as `OFPT_GET_CONFIG_REPLY` (switch side).
    #[must_use]
    pub fn encode_reply(&self) -> Vec<u8> {
        self.encode(OFPT_GET_CONFIG_REPLY)
    }

    /// Encode as `OFPT_SET_CONFIG` (controller side).
    #[must_use]
    pub fn encode_set(&self) -> Vec<u8> {
        self.encode(OFPT_SET_CONFIG)
    }

    fn encode(self, msg_type: u8) -> Vec<u8> {
        let mut out = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type,
            length: 12,
            xid: self.xid,
        }
        .encode(&mut out);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.miss_send_len.to_be_bytes());
        out
    }

    pub(crate) fn parse_reply(frame: &[u8]) -> Result<Self> {
        Self::parse_of_type(frame, OFPT_GET_CONFIG_REPLY)
    }

    pub(crate) fn parse_set(frame: &[u8]) -> Result<Self> {
        Self::parse_of_type(frame, OFPT_SET_CONFIG)
    }

    /// `OFPT_GET_CONFIG_REPLY` and `OFPT_SET_CONFIG` share the
    /// `ofp_switch_config` body; only the message type differs.
    fn parse_of_type(frame: &[u8], expected: u8) -> Result<Self> {
        let h = Header::parse(frame)?;
        if h.msg_type != expected {
            return Err(OfError::UnknownMessageType(h.msg_type));
        }
        if frame.len() < h.length as usize {
            return Err(OfError::ShortBuffer);
        }
        if h.length != 12 || frame.len() != 12 {
            return Err(OfError::InvalidLength(h.length));
        }

        Ok(Self {
            xid: h.xid,
            flags: read_u16(frame, 8)?,
            miss_send_len: read_u16(frame, 10)?,
        })
    }

    /// Parse an `OFPT_GET_CONFIG_REQUEST`, which carries only a header.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame is malformed or is not a
    /// get-config request.
    pub fn parse_get_request(frame: &[u8]) -> Result<u32> {
        let h = Header::parse(frame)?;
        if h.msg_type != OFPT_GET_CONFIG_REQUEST {
            return Err(OfError::UnknownMessageType(h.msg_type));
        }
        if frame.len() < h.length as usize {
            return Err(OfError::ShortBuffer);
        }
        if h.length as usize != OFP_HEADER_LEN || frame.len() != OFP_HEADER_LEN {
            return Err(OfError::InvalidLength(h.length));
        }
        Ok(h.xid)
    }
}

/// Encode an `OFPT_GET_CONFIG_REQUEST` frame.
///
/// Low-level form of [`crate::protocol::codec::Encoder::get_config_request`].
#[must_use]
pub fn encode_get_config_request(xid: u32) -> Vec<u8> {
    Config::get_request(xid)
}

/// Encode an `OFPT_GET_CONFIG_REPLY` frame.
///
/// Low-level form of [`crate::protocol::codec::Encoder::get_config_reply`].
#[must_use]
pub fn encode_get_config_reply(xid: u32, flags: u16, miss_send_len: u16) -> Vec<u8> {
    Config::new(xid, flags, miss_send_len).encode_reply()
}

/// Encode an `OFPT_SET_CONFIG` frame.
///
/// Low-level form of [`crate::protocol::codec::Encoder::set_config`].
#[must_use]
pub fn encode_set(xid: u32, flags: u16, miss_send_len: u16) -> Vec<u8> {
    Config::new(xid, flags, miss_send_len).encode_set()
}

pub(crate) fn parse_get_config_reply(frame: &[u8]) -> Result<Config> {
    Config::parse_reply(frame)
}

pub(crate) fn parse_set_config(frame: &[u8]) -> Result<Config> {
    Config::parse_set(frame)
}
