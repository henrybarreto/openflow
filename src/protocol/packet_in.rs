//! `OFPT_PACKET_IN` (`ofp_packet_in`, §7.4.1): a packet the pipeline
//! handed to the controller.
//!
//! See `examples/16_async_events.rs` for a receive loop. Per §7.3.10 a
//! master- or equal-role connection receives every packet-in except
//! `OFPR_INVALID_TTL` without asking; use `OFPT_SET_ASYNC` to widen or
//! narrow that. (A slave-role connection gets none by default, and real
//! switches do not always follow the spec's defaults -- see
//! [`crate::client::Connection::set_async`].)

use crate::protocol::bytes::{read_u16, read_u32, read_u64};
use crate::protocol::constants::{
    OFPMT_OXM, OFPT_PACKET_IN, OFPXMT_OFB_IN_PORT, OFPXMT_OFB_METADATA,
};
use crate::protocol::constants::{OFP_HEADER_LEN, OFP_VERSION_1_5};
use crate::protocol::error::{OfError, Result};
use crate::protocol::header::Header;
use crate::protocol::ofmatch::Match;
use crate::protocol::oxm::{self, Tlv};

#[derive(Debug, Clone, PartialEq, Eq)]
/// A packet punted to the controller, with the pipeline context that
/// produced it.
pub struct PacketIn {
    /// Transaction id chosen by the switch.
    pub xid: u32,
    /// Where the switch buffered the packet, or `OFP_NO_BUFFER` if it did
    /// not buffer it. Echo this back in a packet-out to release it.
    pub buffer_id: u32,
    /// The packet's full length on the wire. [`Self::data`] may be
    /// shorter: a truncated packet is cut to the switch's `miss_send_len`,
    /// or to the `max_len` of the output action that sent it here.
    pub total_len: u16,
    /// Why the packet came up: `OFPR_TABLE_MISS`, `OFPR_APPLY_ACTION`, ...
    pub reason: u8,
    /// The table that sent it to the controller.
    pub table_id: u8,
    /// Cookie of the flow entry that sent the packet up, or `u64::MAX`
    /// (the spec's -1) when no flow entry applies -- a packet-in raised
    /// from a group bucket or from the action set, for instance.
    pub cookie: u64,
    /// Every OXM TLV of the packet-in's own match, in wire order.
    ///
    /// A switch may attach any pipeline field it knows here, not just
    /// the two [`Self::in_port`] and [`Self::metadata`] pull out --
    /// `TUNNEL_ID` and `PACKET_TYPE` are both common. Read the rest with
    /// [`Self::field`].
    pub of_match: Vec<Tlv>,
    /// The packet, possibly truncated -- see [`Self::total_len`].
    pub data: Vec<u8>,
}

impl PacketIn {
    /// Encode this `ofp_packet_in`. Switch-side counterpart of
    /// `Self::parse`.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message length overflows a `u16`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.buffer_id.to_be_bytes());
        body.extend_from_slice(&self.total_len.to_be_bytes());
        body.push(self.reason);
        body.push(self.table_id);
        body.extend_from_slice(&self.cookie.to_be_bytes());
        Match::new(vec![oxm::encode_tlv_list(&self.of_match)?]).encode(&mut body)?;
        body.extend_from_slice(&[0u8; 2]); // pad before the frame
        if self.data.len() > usize::from(self.total_len) {
            return Err(OfError::InvalidLength(self.total_len));
        }
        body.extend_from_slice(&self.data);

        let length = u16::try_from(OFP_HEADER_LEN + body.len())
            .map_err(|_| OfError::InvalidLength(u16::MAX))?;
        let mut out = Vec::with_capacity(usize::from(length));
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_PACKET_IN,
            length,
            xid: self.xid,
        }
        .encode(&mut out);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// The input port this packet arrived on, if the switch reported one.
    #[must_use]
    pub fn in_port(&self) -> Option<u32> {
        self.basic_field(OFPXMT_OFB_IN_PORT)
            .and_then(|v| v.try_into().ok())
            .map(u32::from_be_bytes)
    }

    /// The pipeline's `metadata` field at the point this packet was
    /// punted, if an earlier table wrote one (e.g. `WriteMetadata`).
    #[must_use]
    pub fn metadata(&self) -> Option<u64> {
        self.basic_field(OFPXMT_OFB_METADATA)
            .and_then(|v| v.try_into().ok())
            .map(u64::from_be_bytes)
    }

    /// The raw value of one `OFPXMC_OPENFLOW_BASIC` field of the match,
    /// for the fields without a named accessor above.
    #[must_use]
    pub fn field(&self, field: u8) -> Option<&[u8]> {
        self.basic_field(field)
    }

    fn basic_field(&self, field: u8) -> Option<&[u8]> {
        self.of_match.iter().find_map(|tlv| match tlv {
            Tlv::Basic {
                field: id,
                value,
                mask: None,
            } if *id == field => Some(value.as_slice()),
            _ => None,
        })
    }
}

impl PacketIn {
    /// Parse a `PACKET_IN` frame.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame is malformed or the message type is not
    /// `PACKET_IN`.
    pub(crate) fn parse(frame: &[u8]) -> Result<Self> {
        let h = Header::parse(frame)?;

        if h.msg_type != OFPT_PACKET_IN {
            return Err(OfError::UnknownMessageType(h.msg_type));
        }

        if frame.len() < 32 {
            return Err(OfError::ShortBuffer);
        }

        let buffer_id = read_u32(frame, 8)?;
        let total_len = read_u16(frame, 12)?;
        let reason = *frame.get(14).ok_or(OfError::ShortBuffer)?;
        let table_id = *frame.get(15).ok_or(OfError::ShortBuffer)?;
        let cookie = read_u64(frame, 16)?;

        let match_start = 24;
        let match_type = read_u16(frame, match_start)?;
        if match_type != OFPMT_OXM {
            return Err(OfError::InvalidOxmLength);
        }

        let match_len = read_u16(frame, match_start + 2)? as usize;
        let oxm_end = match_start + match_len;
        if match_len < 4 {
            return Err(OfError::InvalidOxmLength);
        }
        if match_start + match_len > frame.len() {
            return Err(OfError::InvalidOxmLength);
        }
        let padded_match_len = match_len.div_ceil(8) * 8;
        let data_start = match_start + padded_match_len + 2;
        if frame.len() < data_start {
            return Err(OfError::ShortBuffer);
        }

        let _ = frame
            .get(match_start + match_len..data_start)
            .ok_or(OfError::ShortBuffer)?;

        let of_match = oxm::parse_oxm_list_unchecked(
            frame
                .get(match_start + 4..oxm_end)
                .ok_or(OfError::ShortBuffer)?,
        )?;

        let data = frame
            .get(data_start..h.length as usize)
            .ok_or(OfError::ShortBuffer)?
            .to_vec();
        if data.len() > usize::from(total_len) {
            return Err(OfError::InvalidLength(total_len));
        }

        Ok(Self {
            xid: h.xid,
            buffer_id,
            total_len,
            reason,
            table_id,
            cookie,
            of_match,
            data,
        })
    }
}
