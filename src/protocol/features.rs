//! `OFPT_FEATURES_REQUEST` / `OFPT_FEATURES_REPLY`
//! (`ofp_switch_features`, §7.3.1).
//!
//! The reply is how a controller learns the datapath id, table count, and
//! `OFPC_*` capability bits. Note 1.5 carries no port list here -- ports
//! come from an `OFPMP_PORT_DESC` multipart request.

use crate::protocol::bytes::{read_u32, read_u64};
use crate::protocol::constants::{
    OFPT_FEATURES_REPLY, OFPT_FEATURES_REQUEST, OFP_HEADER_LEN, OFP_VERSION_1_5,
};
use crate::protocol::error::{OfError, Result};
use crate::protocol::header::Header;

#[derive(Debug, Clone, PartialEq, Eq)]
/// A switch's `ofp_switch_features` reply.
pub struct Reply {
    /// Transaction id, echoing the request's.
    pub xid: u32,
    /// Unique datapath id: lower 48 bits a MAC, upper 16 implementer-defined.
    pub datapath_id: u64,
    /// How many packets the switch can buffer at once. Zero means it
    /// buffers nothing, so a packet-in carries as much of the packet as
    /// `miss_send_len` allows rather than a buffer id.
    pub n_buffers: u32,
    /// Number of tables in the pipeline; valid table ids are `0..n_tables`.
    pub n_tables: u8,
    /// 0 for the main connection, non-zero for an auxiliary one.
    pub auxiliary_id: u8,
    /// Bitmap of `OFPC_*` capabilities.
    pub capabilities: u32,
    /// `ofp_switch_features.reserved`; the spec assigns it no meaning.
    pub reserved: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// An `OFPT_FEATURES_REQUEST`, which carries only a header.
pub struct Request {
    /// Transaction id the reply will echo.
    pub xid: u32,
}

impl Request {
    /// A features request with the given transaction id.
    #[must_use]
    pub const fn new(xid: u32) -> Self {
        Self { xid }
    }

    /// Parse an `OFPT_FEATURES_REQUEST`, which carries only a header.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame is malformed or is not a
    /// features request.
    pub fn parse(frame: &[u8]) -> Result<Self> {
        let header = Header::parse(frame)?;
        if header.msg_type != OFPT_FEATURES_REQUEST {
            return Err(OfError::UnknownMessageType(header.msg_type));
        }
        if frame.len() < header.length as usize {
            return Err(OfError::ShortBuffer);
        }
        if header.length as usize != OFP_HEADER_LEN || frame.len() != OFP_HEADER_LEN {
            return Err(OfError::InvalidLength(header.length));
        }
        Ok(Self { xid: header.xid })
    }

    /// Encode this request as a frame.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_FEATURES_REQUEST,
            length: u16::try_from(OFP_HEADER_LEN).unwrap_or(u16::MAX),
            xid: self.xid,
        }
        .encode(&mut out);
        out
    }
}

impl Reply {
    /// Encode this `ofp_switch_features` reply. Switch-side counterpart
    /// of `Self::parse`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_FEATURES_REPLY,
            length: 32,
            xid: self.xid,
        }
        .encode(&mut out);
        out.extend_from_slice(&self.datapath_id.to_be_bytes());
        out.extend_from_slice(&self.n_buffers.to_be_bytes());
        out.push(self.n_tables);
        out.push(self.auxiliary_id);
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&self.capabilities.to_be_bytes());
        out.extend_from_slice(&self.reserved.to_be_bytes());
        out
    }

    pub(crate) fn parse(frame: &[u8]) -> Result<Self> {
        let header = Header::parse(frame)?;

        if header.msg_type != OFPT_FEATURES_REPLY {
            return Err(OfError::UnknownMessageType(header.msg_type));
        }

        if frame.len() < header.length as usize {
            return Err(OfError::ShortBuffer);
        }
        if header.length != 32 || frame.len() != 32 {
            return Err(OfError::InvalidLength(header.length));
        }

        let datapath_id = read_u64(frame, 8)?;
        let n_buffers = read_u32(frame, 16)?;
        let n_tables = *frame.get(20).ok_or(OfError::ShortBuffer)?;
        let auxiliary_id = *frame.get(21).ok_or(OfError::ShortBuffer)?;
        let capabilities = read_u32(frame, 24)?;
        let reserved = read_u32(frame, 28)?;

        Ok(Self {
            xid: header.xid,
            datapath_id,
            n_buffers,
            n_tables,
            auxiliary_id,
            capabilities,
            reserved,
        })
    }
}
