//! OXS (`OpenFlow` eXtensible Stat) field parsing.
//!
//! OXS fields appear in the `stats` list of `OFPMP_FLOW_STATS` and
//! `OFPMP_AGGREGATE_STATS` replies (see spec section 7.2.4). They use the
//! same 4-byte TLV header shape as OXM, but where OXM has a `has_mask`
//! bit OXS has `oxs_reserved`, which must be zero: the basic OXS field
//! set is small (5 fields) and none of them support masking.

use crate::protocol::bytes::{checked_u16_len, read_u16, read_u32, read_u64};
use crate::protocol::constants::{
    OFPXSC_EXPERIMENTER, OFPXSC_OPENFLOW_BASIC, OFPXST_OFB_BYTE_COUNT, OFPXST_OFB_DURATION,
    OFPXST_OFB_FLOW_COUNT, OFPXST_OFB_IDLE_TIME, OFPXST_OFB_PACKET_COUNT,
};
use crate::protocol::error::{OfError, Result};

fn invalid_length(len: usize) -> OfError {
    OfError::InvalidLength(u16::try_from(len).unwrap_or(u16::MAX))
}

/// A single decoded OXS TLV entry from a flow-stats or aggregate-stats
/// `stats` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tlv {
    /// `OFPXST_OFB_DURATION`: how long the flow has been installed.
    Duration {
        /// Whole seconds.
        sec: u32,
        /// Nanoseconds beyond `sec`.
        nsec: u32,
    },
    /// `OFPXST_OFB_IDLE_TIME`: time since the flow last matched a packet.
    IdleTime {
        /// Whole seconds.
        sec: u32,
        /// Nanoseconds beyond `sec`.
        nsec: u32,
    },
    /// `OFPXST_OFB_FLOW_COUNT`: number of flows counted, in an aggregate
    /// reply.
    FlowCount(u32),
    /// `OFPXST_OFB_PACKET_COUNT`: packets matched.
    PacketCount(u64),
    /// `OFPXST_OFB_BYTE_COUNT`: bytes matched.
    ByteCount(u64),
    /// An `OFPXSC_EXPERIMENTER`-class field; its meaning is vendor-defined.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor payload, uninterpreted.
        data: Vec<u8>,
    },
    /// A field this crate does not know, kept verbatim so it round-trips.
    Raw {
        /// `OFPXSC_*` class.
        class: u16,
        /// Field id within the class.
        field: u8,
        /// The value bytes.
        data: Vec<u8>,
    },
}

impl Tlv {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Duration { sec, nsec } => {
                encode_header(out, OFPXSC_OPENFLOW_BASIC, OFPXST_OFB_DURATION, 8);
                out.extend_from_slice(&sec.to_be_bytes());
                out.extend_from_slice(&nsec.to_be_bytes());
            }
            Self::IdleTime { sec, nsec } => {
                encode_header(out, OFPXSC_OPENFLOW_BASIC, OFPXST_OFB_IDLE_TIME, 8);
                out.extend_from_slice(&sec.to_be_bytes());
                out.extend_from_slice(&nsec.to_be_bytes());
            }
            Self::FlowCount(count) => {
                encode_header(out, OFPXSC_OPENFLOW_BASIC, OFPXST_OFB_FLOW_COUNT, 4);
                out.extend_from_slice(&count.to_be_bytes());
            }
            Self::PacketCount(count) => {
                encode_header(out, OFPXSC_OPENFLOW_BASIC, OFPXST_OFB_PACKET_COUNT, 8);
                out.extend_from_slice(&count.to_be_bytes());
            }
            Self::ByteCount(count) => {
                encode_header(out, OFPXSC_OPENFLOW_BASIC, OFPXST_OFB_BYTE_COUNT, 8);
                out.extend_from_slice(&count.to_be_bytes());
            }
            Self::Experimenter { experimenter, data } => {
                let len =
                    u8::try_from(4 + data.len()).map_err(|_| OfError::InvalidLength(u16::MAX))?;
                encode_header(out, OFPXSC_EXPERIMENTER, 0, len);
                out.extend_from_slice(&experimenter.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::Raw { class, field, data } => {
                if *field > 0x7f {
                    return Err(OfError::InvalidValue {
                        field: "oxs_field",
                        value: u64::from(*field),
                    });
                }
                let len = u8::try_from(data.len()).map_err(|_| OfError::InvalidLength(u16::MAX))?;
                encode_header(out, *class, *field, len);
                out.extend_from_slice(data);
            }
        }
        Ok(())
    }

    fn parse(class: u16, field: u8, value: &[u8]) -> Result<Self> {
        match (class, field) {
            (OFPXSC_OPENFLOW_BASIC, OFPXST_OFB_DURATION) => {
                if value.len() != 8 {
                    return Err(invalid_length(value.len()));
                }
                Ok(Self::Duration {
                    sec: read_u32(value, 0)?,
                    nsec: read_u32(value, 4)?,
                })
            }
            (OFPXSC_OPENFLOW_BASIC, OFPXST_OFB_IDLE_TIME) => {
                if value.len() != 8 {
                    return Err(invalid_length(value.len()));
                }
                Ok(Self::IdleTime {
                    sec: read_u32(value, 0)?,
                    nsec: read_u32(value, 4)?,
                })
            }
            (OFPXSC_OPENFLOW_BASIC, OFPXST_OFB_FLOW_COUNT) => {
                if value.len() != 4 {
                    return Err(invalid_length(value.len()));
                }
                Ok(Self::FlowCount(read_u32(value, 0)?))
            }
            (OFPXSC_OPENFLOW_BASIC, OFPXST_OFB_PACKET_COUNT) => {
                if value.len() != 8 {
                    return Err(invalid_length(value.len()));
                }
                Ok(Self::PacketCount(read_u64(value, 0)?))
            }
            (OFPXSC_OPENFLOW_BASIC, OFPXST_OFB_BYTE_COUNT) => {
                if value.len() != 8 {
                    return Err(invalid_length(value.len()));
                }
                Ok(Self::ByteCount(read_u64(value, 0)?))
            }
            (OFPXSC_EXPERIMENTER, _) => {
                if value.len() < 4 {
                    return Err(invalid_length(value.len()));
                }
                Ok(Self::Experimenter {
                    experimenter: read_u32(value, 0)?,
                    data: value.get(4..).unwrap_or_default().to_vec(),
                })
            }
            _ => Ok(Self::Raw {
                class,
                field,
                data: value.to_vec(),
            }),
        }
    }
}

fn encode_header(out: &mut Vec<u8>, class: u16, field: u8, len: u8) {
    let header = (u32::from(class) << 16) | (u32::from(field) << 9) | u32::from(len);
    out.extend_from_slice(&header.to_be_bytes());
}

/// Parse a sequence of OXS TLVs, such as an `ofp_flow_stats`/
/// `ofp_aggregate_stats_reply` `stats` list.
///
/// # Errors
///
/// Returns an error if the buffer is truncated, a basic-class field's
/// declared length doesn't match the spec, or the same `(class, field)` pair
/// appears more than once.
pub fn parse_oxs_list(buf: &[u8]) -> Result<Vec<Tlv>> {
    let mut tlvs = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut offset = 0;
    while offset < buf.len() {
        if buf.len() - offset < 4 {
            return Err(OfError::ShortBuffer);
        }
        let class = read_u16(buf, offset)?;
        let field_and_mask = *buf.get(offset + 2).ok_or(OfError::ShortBuffer)?;
        if field_and_mask & 1 != 0 {
            return Err(OfError::InvalidValue {
                field: "oxs_reserved",
                value: u64::from(field_and_mask & 1),
            });
        }
        let field = field_and_mask >> 1;
        let length = usize::from(*buf.get(offset + 3).ok_or(OfError::ShortBuffer)?);
        if offset + 4 + length > buf.len() {
            return Err(OfError::ShortBuffer);
        }
        let value = buf
            .get(offset + 4..offset + 4 + length)
            .ok_or(OfError::ShortBuffer)?;
        if !seen.insert((class, field)) {
            return Err(OfError::DuplicateOxmField { class, field });
        }
        tlvs.push(Tlv::parse(class, field, value)?);
        offset += 4 + length;
    }
    Ok(tlvs)
}

/// Encode a sequence of OXS TLVs back to wire form.
///
/// # Errors
///
/// Returns an error if a TLV payload cannot fit in the wire's 8-bit length.
pub fn encode_oxs_list(tlvs: &[Tlv]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for tlv in tlvs {
        tlv.encode(&mut out)?;
    }
    Ok(out)
}

/// Parses a `struct ofp_stats` (spec 7.2.4.1) at `offset` in `buf`: a
/// `reserved`/`length` header, then `length - 4` bytes of OXS TLVs, then
/// padding out to a multiple of 8.
///
/// Returns the decoded fields and the padded size, so a caller can find
/// whatever follows. The reserved field must be zero; alignment padding is
/// accepted with any value as required by section 7.1.2.
///
/// # Errors
///
/// Returns an error if the buffer is truncated, the declared length is
/// under the 4-byte minimum, or the OXS list
/// itself is malformed.
pub fn parse_stats(buf: &[u8], offset: usize) -> Result<(Vec<Tlv>, usize)> {
    let reserved = read_u16(buf, offset)?;
    if reserved != 0 {
        return Err(OfError::InvalidValue {
            field: "stats_reserved",
            value: u64::from(reserved),
        });
    }
    let len = usize::from(read_u16(buf, offset + 2)?);
    if len < 4 {
        return Err(invalid_length(len));
    }
    let padded = len.div_ceil(8) * 8;
    if buf.len() < offset + padded {
        return Err(OfError::ShortBuffer);
    }
    let _ = buf
        .get(offset + len..offset + padded)
        .ok_or(OfError::ShortBuffer)?;
    let fields = parse_oxs_list(
        buf.get(offset + 4..offset + len)
            .ok_or(OfError::ShortBuffer)?,
    )?;
    Ok((fields, padded))
}

/// Appends a `struct ofp_stats` holding `stats`, padded to a multiple of 8.
///
/// # Errors
///
/// Returns an error if the stats structure or one of its TLVs is too large
/// for its wire length fields.
pub fn encode_stats(out: &mut Vec<u8>, stats: &[Tlv]) -> Result<()> {
    let fields = encode_oxs_list(stats)?;
    let len = checked_u16_len(4 + fields.len())?;
    let mut encoded = Vec::with_capacity(4 + fields.len());
    encoded.extend_from_slice(&[0u8; 2]); // reserved
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(&fields);
    while !encoded.len().is_multiple_of(8) {
        encoded.push(0);
    }
    out.extend_from_slice(&encoded);
    Ok(())
}
