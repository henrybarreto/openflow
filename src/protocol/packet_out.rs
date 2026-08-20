//! `OFPT_PACKET_OUT` (`ofp_packet_out`, §7.3.6): inject a packet into a
//! switch's pipeline, or release one the switch buffered.
//!
//! See `examples/13_packet_out.rs`.

use crate::protocol::action::{parse_actions, Action};
use crate::protocol::bytes::{checked_u16_len, read_u16, read_u32};
use crate::protocol::constants::{
    OFPMT_OXM, OFPP_CONTROLLER, OFPT_PACKET_OUT, OFPXMT_OFB_IN_PORT, OFP_HEADER_LEN, OFP_NO_BUFFER,
    OFP_VERSION_1_5,
};
use crate::protocol::error::{OfError, Result};
use crate::protocol::header::Header;
use crate::protocol::ofmatch::Match;

#[derive(Debug, Clone, PartialEq, Eq)]
/// A packet to send out of a switch, plus the actions to apply to it.
pub struct PacketOut {
    /// Transaction id.
    pub xid: u32,
    /// A buffer id from an earlier packet-in, to send that buffered packet
    /// instead of [`Self::data`]; `OFP_NO_BUFFER` to send `data`.
    pub buffer_id: u32,
    /// Pipeline context for the injected packet. Must contain
    /// `OXM_OF_IN_PORT` -- see [`Self::new`].
    pub of_match: Match,
    /// Actions to apply, in order. An empty list drops the packet.
    pub actions: Vec<Action>,
    /// The raw frame to send. Ignored when `buffer_id` is not
    /// `OFP_NO_BUFFER`.
    pub data: Vec<u8>,
}

impl PacketOut {
    /// Build a packet-out.
    ///
    /// `in_port` names the ingress port the packet is treated as having
    /// arrived on. The spec makes `OXM_OF_IN_PORT` **mandatory** in a
    /// packet-out's match ("This TLV is mandatory in the match field"),
    /// so `None` means "the controller injected this packet" and encodes
    /// `OFPP_CONTROLLER` rather than an empty match -- a genuinely empty
    /// match is rejected by real switches (OVS answers
    /// `OFPBRC_BAD_PORT`).
    pub fn new(
        xid: u32,
        buffer_id: u32,
        in_port: Option<u32>,
        actions: Vec<Action>,
        data: Vec<u8>,
    ) -> Self {
        let port = in_port.unwrap_or(OFPP_CONTROLLER);
        let of_match = Match::new(vec![crate::protocol::oxm::in_port(port)]);

        Self {
            xid,
            buffer_id,
            of_match,
            actions,
            data,
        }
    }

    /// Build a packet-out with a match you construct yourself.
    ///
    /// Unlike [`Self::new`], nothing is added for you -- the match must
    /// already carry `OXM_OF_IN_PORT`, or a switch will reject it.
    #[must_use]
    pub const fn with_match(
        xid: u32,
        buffer_id: u32,
        of_match: Match,
        actions: Vec<Action>,
        data: Vec<u8>,
    ) -> Self {
        Self {
            xid,
            buffer_id,
            of_match,
            actions,
            data,
        }
    }

    /// Encode this `ofp_packet_out` as a frame.
    /// # Errors
    ///
    /// Returns an error if an action, match, or complete packet-out exceeds a
    /// wire length field.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut action_bytes = Vec::new();
        for action in &self.actions {
            action.encode(&mut action_bytes)?;
        }
        let actions_len = checked_u16_len(action_bytes.len())?;

        let mut match_bytes = Vec::new();
        self.of_match.encode(&mut match_bytes)?;

        let include_data = self.buffer_id == OFP_NO_BUFFER;
        let mut body = Vec::with_capacity(
            8 + match_bytes.len()
                + action_bytes.len()
                + if include_data { self.data.len() } else { 0 },
        );
        body.extend_from_slice(&self.buffer_id.to_be_bytes());
        body.extend_from_slice(&actions_len.to_be_bytes());
        body.extend_from_slice(&[0u8; 2]);
        body.extend_from_slice(&match_bytes);
        body.extend_from_slice(&action_bytes);
        if include_data {
            body.extend_from_slice(&self.data);
        }

        let length = checked_u16_len(OFP_HEADER_LEN + body.len())?;
        let mut out = Vec::with_capacity(usize::from(length));

        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_PACKET_OUT,
            length,
            xid: self.xid,
        }
        .encode(&mut out);
        out.extend_from_slice(&body);
        Ok(out)
    }
}

impl PacketOut {
    /// Parse an `OFPT_PACKET_OUT`. Switch-side counterpart of
    /// [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Returns an error if the frame is malformed, is not a packet-out,
    /// or its match, actions or lengths are inconsistent.
    pub fn parse(frame: &[u8]) -> Result<Self> {
        let header = Header::parse(frame)?;
        if header.msg_type != OFPT_PACKET_OUT {
            return Err(OfError::UnknownMessageType(header.msg_type));
        }
        let msg_len = usize::from(header.length);
        if frame.len() < msg_len || msg_len < 24 {
            return Err(OfError::ShortBuffer);
        }

        let buffer_id = read_u32(frame, 8)?;
        let actions_len = usize::from(read_u16(frame, 12)?);
        let _ = frame.get(14..16).ok_or(OfError::ShortBuffer)?;

        let match_start = 16;
        if read_u16(frame, match_start)? != OFPMT_OXM {
            return Err(OfError::InvalidOxmLength);
        }
        let match_len = usize::from(read_u16(frame, match_start + 2)?);
        if match_len < 4 {
            return Err(OfError::InvalidOxmLength);
        }
        let match_padded = match_len.div_ceil(8) * 8;
        if match_start + match_padded > msg_len {
            return Err(OfError::ShortBuffer);
        }
        let _ = frame
            .get(match_start + match_len..match_start + match_padded)
            .ok_or(OfError::ShortBuffer)?;
        let oxm_bytes = frame
            .get(match_start + 4..match_start + match_len)
            .ok_or(OfError::ShortBuffer)?;
        let parsed_oxms = crate::protocol::oxm::parse_oxm_list(oxm_bytes)?;
        if !parsed_oxms.iter().any(|oxm| {
            matches!(
                oxm,
                crate::protocol::oxm::Tlv::Basic {
                    field,
                    mask: None,
                    ..
                } if *field == OFPXMT_OFB_IN_PORT
            )
        }) {
            return Err(OfError::InvalidValue {
                field: "packet-out in_port",
                value: 0,
            });
        }

        let actions_start = match_start + match_padded;
        let data_start = actions_start
            .checked_add(actions_len)
            .ok_or(OfError::ShortBuffer)?;
        if data_start > msg_len {
            return Err(OfError::InvalidLength(header.length));
        }
        let actions = parse_actions(
            frame
                .get(actions_start..data_start)
                .ok_or(OfError::ShortBuffer)?,
        )?;
        let data = frame.get(data_start..msg_len).ok_or(OfError::ShortBuffer)?;
        if buffer_id != OFP_NO_BUFFER && !data.is_empty() {
            return Err(OfError::InvalidLength(header.length));
        }

        Ok(Self {
            xid: header.xid,
            buffer_id,
            of_match: if oxm_bytes.is_empty() {
                Match::any()
            } else {
                Match::new(vec![oxm_bytes.to_vec()])
            },
            actions,
            data: data.to_vec(),
        })
    }
}

/// Encode an `OFPT_PACKET_OUT` frame.
///
/// Low-level form of [`crate::protocol::codec::Encoder::packet_out`];
/// `in_port` follows the same rule as [`PacketOut::new`].
///
/// # Errors
///
/// Returns an error if the encoded frame exceeds the wire length limit or an
/// action is invalid.
pub fn encode(
    xid: u32,
    buffer_id: u32,
    in_port: Option<u32>,
    actions: Vec<Action>,
    data: &[u8],
) -> Result<Vec<u8>> {
    PacketOut::new(xid, buffer_id, in_port, actions, data.to_vec()).encode()
}
