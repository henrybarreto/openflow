//! `OpenFlow` actions (`ofp_action_*`, §7.2.6).
//!
//! An action is a single operation on a packet -- output it, rewrite a
//! field, push a tag. Actions are carried by an
//! [`crate::protocol::instruction::Instruction`], never on their own.

use crate::protocol::bytes::{checked_u16_len, read_u16, read_u32};
use crate::protocol::constants::{
    OFPAT_COPY_FIELD, OFPAT_COPY_TTL_IN, OFPAT_COPY_TTL_OUT, OFPAT_DEC_MPLS_TTL, OFPAT_DEC_NW_TTL,
    OFPAT_EXPERIMENTER, OFPAT_GROUP, OFPAT_METER, OFPAT_OUTPUT, OFPAT_POP_MPLS, OFPAT_POP_PBB,
    OFPAT_POP_VLAN, OFPAT_PUSH_MPLS, OFPAT_PUSH_PBB, OFPAT_PUSH_VLAN, OFPAT_SET_FIELD,
    OFPAT_SET_MPLS_TTL, OFPAT_SET_NW_TTL, OFPAT_SET_QUEUE, OFPCML_NO_BUFFER, OFPP_CONTROLLER,
};
use crate::protocol::error::{OfError, Result};
use crate::protocol::oxm;

#[allow(clippy::unnecessary_wraps)]
const fn ensure_zero_padding(_buf: &[u8]) -> Result<()> {
    // Section 7.1.2 requires recipients to ignore padding contents.
    Ok(())
}

fn pad_to_8(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
}

fn write_len(out: &mut [u8], start: usize) -> Result<()> {
    let len = checked_u16_len(
        out.len()
            .checked_sub(start)
            .ok_or(OfError::InvalidLength(0))?,
    )?;
    if let Some(dst) = out.get_mut(start + 2..start + 4) {
        dst.copy_from_slice(&len.to_be_bytes());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// One action a flow entry, group bucket, or packet-out can apply.
///
/// ```
/// use openflow::protocol::action::Action;
/// use openflow::protocol::oxm;
///
/// // Rewrite the destination address, then forward.
/// let actions = vec![
///     Action::SetField(oxm::ipv4_dst([10, 0, 0, 8])),
///     Action::output(2),
/// ];
/// assert_eq!(actions.len(), 2);
/// ```
pub enum Action {
    /// `OFPAT_OUTPUT`: send the packet to a port, which may be a reserved
    /// one such as `OFPP_CONTROLLER` or `OFPP_FLOOD`.
    Output {
        /// Egress port number, or an `OFPP_*` reserved port.
        port: u32,
        /// When `port` is `OFPP_CONTROLLER`, how many bytes of the packet
        /// to include in the packet-in; `OFPCML_NO_BUFFER` sends all of
        /// it. Ignored for any other port.
        max_len: u16,
    },
    /// `OFPAT_COPY_TTL_OUT`: copy the TTL from the next-to-outermost
    /// header to the outermost one.
    CopyTtlOut,
    /// `OFPAT_COPY_TTL_IN`: copy the TTL from the outermost header inward.
    CopyTtlIn,
    /// `OFPAT_SET_MPLS_TTL`: set the outermost MPLS TTL.
    SetMplsTtl(u8),
    /// `OFPAT_DEC_MPLS_TTL`: decrement the outermost MPLS TTL.
    DecMplsTtl,
    /// `OFPAT_PUSH_VLAN`: push a VLAN tag with this `EtherType`
    /// (`0x8100` or `0x88a8`).
    PushVlan(u16),
    /// `OFPAT_POP_VLAN`: pop the outermost VLAN tag.
    PopVlan,
    /// `OFPAT_PUSH_MPLS`: push an MPLS shim with this `EtherType`
    /// (`0x8847` or `0x8848`).
    PushMpls(u16),
    /// `OFPAT_POP_MPLS`: pop the outermost MPLS shim, leaving a packet of
    /// this `EtherType`.
    PopMpls(u16),
    /// `OFPAT_SET_QUEUE`: pick the egress queue for later output actions.
    SetQueue(u32),
    /// `OFPAT_GROUP`: process the packet through this group.
    Group(u32),
    /// `OFPAT_SET_NW_TTL`: set the IPv4 TTL or IPv6 hop limit.
    SetNwTtl(u8),
    /// `OFPAT_DEC_NW_TTL`: decrement the IPv4 TTL or IPv6 hop limit.
    DecNwTtl,
    /// `OFPAT_SET_FIELD`: overwrite a header field, given as one encoded
    /// OXM TLV -- build it with an [`crate::protocol::oxm`] helper.
    SetField(Vec<u8>),
    /// `OFPAT_PUSH_PBB`: push a PBB service tag (`EtherType` `0x88e7`).
    PushPbb(u16),
    /// `OFPAT_POP_PBB`: pop the outermost PBB service tag.
    PopPbb,
    /// `OFPAT_COPY_FIELD`: copy a bit range from one OXM field to another.
    CopyField {
        /// Number of bits to copy.
        n_bits: u16,
        /// Bit offset into the source field.
        src_offset: u16,
        /// Bit offset into the destination field.
        dst_offset: u16,
        /// The source and destination OXM ids, in that order -- see
        /// [`crate::protocol::oxm::copy_field_ids`].
        oxm_ids: Vec<u8>,
    },
    /// `OFPAT_METER`: run the packet through this meter. In 1.5 metering
    /// is an action; in 1.3 it was an instruction.
    Meter(u32),
    /// `OFPAT_EXPERIMENTER`: a vendor action, uninterpreted.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor payload.
        data: Vec<u8>,
    },
    /// An action type this crate does not implement, kept verbatim so it
    /// round-trips.
    Unknown {
        /// The `OFPAT_*` type from the wire.
        action_type: u16,
        /// Body bytes following the 4-byte action header.
        data: Vec<u8>,
    },
}

impl Action {
    /// Output to `port` with `max_len` 0.
    ///
    /// Suitable for any normal port. For `OFPP_CONTROLLER` use
    /// [`Self::output_controller_no_buffer`] instead -- a `max_len` of 0
    /// would send a zero-byte packet-in.
    #[must_use]
    pub const fn output(port: u32) -> Self {
        Self::Output { port, max_len: 0 }
    }

    /// Output the whole packet to the controller, unbuffered
    /// (`OFPP_CONTROLLER` with `OFPCML_NO_BUFFER`).
    ///
    /// This is the action a table-miss entry uses.
    #[must_use]
    pub const fn output_controller_no_buffer() -> Self {
        Self::Output {
            port: OFPP_CONTROLLER,
            max_len: OFPCML_NO_BUFFER,
        }
    }

    /// Appends this action's wire encoding to `out`, padded to the
    /// spec's 8-byte action alignment.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded action length overflows a `u16`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut encoded = Vec::new();
        self.encode_into(&mut encoded)?;
        out.extend_from_slice(&encoded);
        Ok(())
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        // `pad_to_8` pads to the whole buffer's length, so it only pads
        // this action correctly when the action itself starts 8-aligned.
        // Every action is a multiple of 8 long, so an action list stays
        // aligned once it starts that way.
        debug_assert!(out.len().is_multiple_of(8), "action must start 8-aligned");
        match self {
            Self::Output { port, max_len } => {
                out.extend_from_slice(&OFPAT_OUTPUT.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                out.extend_from_slice(&max_len.to_be_bytes());
                out.extend_from_slice(&[0u8; 6]);
            }
            Self::CopyTtlOut => encode_generic(out, OFPAT_COPY_TTL_OUT),
            Self::CopyTtlIn => encode_generic(out, OFPAT_COPY_TTL_IN),
            Self::SetMplsTtl(ttl) => encode_u8_arg(out, OFPAT_SET_MPLS_TTL, *ttl),
            Self::DecMplsTtl => encode_generic(out, OFPAT_DEC_MPLS_TTL),
            Self::PushVlan(ethertype) => encode_u16_arg(out, OFPAT_PUSH_VLAN, *ethertype),
            Self::PopVlan => encode_generic(out, OFPAT_POP_VLAN),
            Self::PushMpls(ethertype) => encode_u16_arg(out, OFPAT_PUSH_MPLS, *ethertype),
            Self::PopMpls(ethertype) => encode_u16_arg(out, OFPAT_POP_MPLS, *ethertype),
            Self::SetQueue(queue_id) => encode_u32_arg(out, OFPAT_SET_QUEUE, *queue_id),
            Self::Group(group_id) => encode_u32_arg(out, OFPAT_GROUP, *group_id),
            Self::SetNwTtl(ttl) => encode_u8_arg(out, OFPAT_SET_NW_TTL, *ttl),
            Self::DecNwTtl => encode_generic(out, OFPAT_DEC_NW_TTL),
            Self::SetField(field) => {
                validate_set_field(field)?;
                let start = out.len();
                out.extend_from_slice(&OFPAT_SET_FIELD.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(field);
                pad_to_8(out);
                write_len(out.as_mut_slice(), start)?;
            }
            Self::PushPbb(ethertype) => encode_u16_arg(out, OFPAT_PUSH_PBB, *ethertype),
            Self::PopPbb => encode_generic(out, OFPAT_POP_PBB),
            Self::CopyField {
                n_bits,
                src_offset,
                dst_offset,
                oxm_ids,
            } => {
                validate_copy_field(*n_bits, *src_offset, *dst_offset, oxm_ids)?;
                let start = out.len();
                out.extend_from_slice(&OFPAT_COPY_FIELD.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&n_bits.to_be_bytes());
                out.extend_from_slice(&src_offset.to_be_bytes());
                out.extend_from_slice(&dst_offset.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(oxm_ids);
                pad_to_8(out);
                write_len(out.as_mut_slice(), start)?;
            }
            Self::Meter(meter_id) => encode_u32_arg(out, OFPAT_METER, *meter_id),
            Self::Experimenter { experimenter, data } => {
                let start = out.len();
                out.extend_from_slice(&OFPAT_EXPERIMENTER.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(&experimenter.to_be_bytes());
                out.extend_from_slice(data);
                pad_to_8(out);
                write_len(out.as_mut_slice(), start)?;
            }
            Self::Unknown { action_type, data } => {
                let start = out.len();
                out.extend_from_slice(&action_type.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes());
                out.extend_from_slice(data);
                pad_to_8(out);
                write_len(out.as_mut_slice(), start)?;
            }
        }
        Ok(())
    }
}

fn encode_generic(out: &mut Vec<u8>, action_type: u16) {
    out.extend_from_slice(&action_type.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.extend_from_slice(&[0u8; 4]);
}

fn encode_u8_arg(out: &mut Vec<u8>, action_type: u16, value: u8) {
    out.extend_from_slice(&action_type.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.push(value);
    out.extend_from_slice(&[0u8; 3]);
}

fn encode_u16_arg(out: &mut Vec<u8>, action_type: u16, value: u16) {
    out.extend_from_slice(&action_type.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.extend_from_slice(&value.to_be_bytes());
    out.extend_from_slice(&[0u8; 2]);
}

fn encode_u32_arg(out: &mut Vec<u8>, action_type: u16, value: u32) {
    out.extend_from_slice(&action_type.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.extend_from_slice(&value.to_be_bytes());
}

/// Parse a sequence of `OpenFlow` actions.
///
/// # Errors
///
/// Returns an error if the buffer is truncated or contains an invalid action.
pub fn parse_actions(buf: &[u8]) -> Result<Vec<Action>> {
    let mut actions = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        if buf.len() - offset < 4 {
            return Err(OfError::ShortBuffer);
        }
        let action_type = read_u16(buf, offset)?;
        let len = read_u16(buf, offset + 2)? as usize;
        if len < 4 || !len.is_multiple_of(8) {
            return Err(OfError::InvalidLength(
                u16::try_from(len).unwrap_or(u16::MAX),
            ));
        }
        if offset + len > buf.len() {
            return Err(OfError::ShortBuffer);
        }
        let raw = buf.get(offset..offset + len).ok_or(OfError::ShortBuffer)?;
        actions.push(parse_action(action_type, raw)?);
        offset += len;
    }
    Ok(actions)
}

fn parse_action(action_type: u16, raw: &[u8]) -> Result<Action> {
    match action_type {
        OFPAT_OUTPUT => parse_output_action(raw),
        OFPAT_COPY_TTL_OUT | OFPAT_COPY_TTL_IN | OFPAT_DEC_MPLS_TTL | OFPAT_POP_VLAN
        | OFPAT_DEC_NW_TTL | OFPAT_POP_PBB => parse_flag_action(action_type, raw),
        OFPAT_SET_MPLS_TTL | OFPAT_SET_NW_TTL => parse_ttl_action(action_type, raw),
        OFPAT_PUSH_VLAN | OFPAT_PUSH_MPLS | OFPAT_POP_MPLS | OFPAT_PUSH_PBB => {
            parse_ethertype_action(action_type, raw)
        }
        OFPAT_SET_QUEUE | OFPAT_GROUP | OFPAT_METER => parse_value_action(action_type, raw),
        OFPAT_SET_FIELD => parse_set_field(raw),
        OFPAT_COPY_FIELD => parse_copy_field(raw),
        OFPAT_EXPERIMENTER => parse_experimenter(raw),
        _ => Ok(Action::Unknown {
            action_type,
            data: raw.get(4..).ok_or(OfError::ShortBuffer)?.to_vec(),
        }),
    }
}

fn invalid_len(len: usize) -> OfError {
    OfError::InvalidLength(u16::try_from(len).unwrap_or(u16::MAX))
}

fn parse_output_action(raw: &[u8]) -> Result<Action> {
    let fixed: &[u8; 16] = raw.try_into().map_err(|_| invalid_len(raw.len()))?;
    ensure_zero_padding(&fixed[10..16])?;
    Ok(Action::Output {
        port: read_u32(raw, 4)?,
        max_len: read_u16(raw, 8)?,
    })
}

fn parse_flag_action(action_type: u16, raw: &[u8]) -> Result<Action> {
    let fixed: &[u8; 8] = raw.try_into().map_err(|_| invalid_len(raw.len()))?;
    ensure_zero_padding(&fixed[4..8])?;
    Ok(match action_type {
        OFPAT_COPY_TTL_OUT => Action::CopyTtlOut,
        OFPAT_COPY_TTL_IN => Action::CopyTtlIn,
        OFPAT_DEC_MPLS_TTL => Action::DecMplsTtl,
        OFPAT_POP_VLAN => Action::PopVlan,
        OFPAT_DEC_NW_TTL => Action::DecNwTtl,
        _ => Action::PopPbb,
    })
}

fn parse_ttl_action(action_type: u16, raw: &[u8]) -> Result<Action> {
    let fixed: &[u8; 8] = raw.try_into().map_err(|_| invalid_len(raw.len()))?;
    ensure_zero_padding(&fixed[5..8])?;
    Ok(if action_type == OFPAT_SET_MPLS_TTL {
        Action::SetMplsTtl(fixed[4])
    } else {
        Action::SetNwTtl(fixed[4])
    })
}

fn parse_ethertype_action(action_type: u16, raw: &[u8]) -> Result<Action> {
    let fixed: &[u8; 8] = raw.try_into().map_err(|_| invalid_len(raw.len()))?;
    ensure_zero_padding(&fixed[6..8])?;
    let ethertype = read_u16(raw, 4)?;
    Ok(match action_type {
        OFPAT_PUSH_VLAN => Action::PushVlan(ethertype),
        OFPAT_PUSH_MPLS => Action::PushMpls(ethertype),
        OFPAT_POP_MPLS => Action::PopMpls(ethertype),
        _ => Action::PushPbb(ethertype),
    })
}

fn parse_value_action(action_type: u16, raw: &[u8]) -> Result<Action> {
    if raw.len() != 8 {
        return Err(invalid_len(raw.len()));
    }
    let value = read_u32(raw, 4)?;
    Ok(match action_type {
        OFPAT_SET_QUEUE => Action::SetQueue(value),
        OFPAT_GROUP => Action::Group(value),
        _ => Action::Meter(value),
    })
}

fn parse_set_field(raw: &[u8]) -> Result<Action> {
    let head: &[u8; 8] = raw
        .first_chunk::<8>()
        .ok_or_else(|| invalid_len(raw.len()))?;
    let oxm_len = usize::from(head[7]);
    let field_len = 4 + oxm_len;
    let expected_len = (4 + field_len).div_ceil(8) * 8;
    if raw.len() != expected_len {
        return Err(invalid_len(raw.len()));
    }
    ensure_zero_padding(raw.get(4 + field_len..).ok_or(OfError::ShortBuffer)?)?;
    let field = raw.get(4..4 + field_len).ok_or(OfError::ShortBuffer)?;
    validate_set_field(field)?;
    Ok(Action::SetField(field.to_vec()))
}

fn parse_copy_field(raw: &[u8]) -> Result<Action> {
    if raw.len() != 24 {
        return Err(invalid_len(raw.len()));
    }
    let fixed: &[u8; 16] = raw
        .first_chunk::<16>()
        .ok_or_else(|| invalid_len(raw.len()))?;
    ensure_zero_padding(&fixed[10..12])?;
    let n_bits = read_u16(raw, 4)?;
    let src_offset = read_u16(raw, 6)?;
    let dst_offset = read_u16(raw, 8)?;
    let oxm_ids = raw.get(12..20).ok_or(OfError::ShortBuffer)?;
    ensure_zero_padding(raw.get(20..).ok_or(OfError::ShortBuffer)?)?;
    validate_copy_field(n_bits, src_offset, dst_offset, oxm_ids)?;
    Ok(Action::CopyField {
        n_bits,
        src_offset,
        dst_offset,
        oxm_ids: oxm_ids.to_vec(),
    })
}

fn validate_set_field(field: &[u8]) -> Result<()> {
    let fields = oxm::parse_oxm_list_unchecked(field)?;
    match fields.as_slice() {
        [field] if !field.has_mask() => Ok(()),
        _ => Err(OfError::InvalidOxmLength),
    }
}

fn validate_copy_field(
    n_bits: u16,
    src_offset: u16,
    dst_offset: u16,
    oxm_ids: &[u8],
) -> Result<()> {
    if oxm_ids.len() != 8 || n_bits == 0 {
        return Err(OfError::InvalidOxmLength);
    }

    let src_width = oxm::field_id_width(oxm_ids.get(..4).ok_or(OfError::ShortBuffer)?)?;
    let dst_width = oxm::field_id_width(oxm_ids.get(4..).ok_or(OfError::ShortBuffer)?)?;
    let bits = usize::from(n_bits);
    if usize::from(src_offset)
        .checked_add(bits)
        .is_none_or(|end| end > src_width.saturating_mul(8))
        || usize::from(dst_offset)
            .checked_add(bits)
            .is_none_or(|end| end > dst_width.saturating_mul(8))
    {
        return Err(OfError::InvalidValue {
            field: "copy_field_bit_range",
            value: u64::from(n_bits),
        });
    }
    Ok(())
}

fn parse_experimenter(raw: &[u8]) -> Result<Action> {
    if raw.len() < 8 {
        return Err(invalid_len(raw.len()));
    }
    Ok(Action::Experimenter {
        experimenter: read_u32(raw, 4)?,
        data: raw.get(8..).ok_or(OfError::ShortBuffer)?.to_vec(),
    })
}
