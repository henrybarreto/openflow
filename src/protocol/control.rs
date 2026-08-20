//! The large message families: multipart statistics, the
//! table/port/group/meter modifications, bundles, and the asynchronous
//! status messages.
//!
//! Everything here follows the same shape: a message struct
//! (`TableMod`, `GroupMod`, `BundleMessage`, ...) with an `encode`, a
//! matching parser, and -- where the wire format has one -- a property
//! enum whose `Raw` variant keeps anything this crate does not model, so
//! an unknown property still round-trips.
//!
//! [`MultipartMessage`] carries a raw body; [`MultipartRequestBody`] and
//! [`MultipartReplyBody`] are its typed forms, covering all 21
//! `OFPMP_*` kinds.

use crate::protocol::action::{parse_actions, Action};
use crate::protocol::bytes::{checked_u16_len, read_u16, read_u32, read_u64};
use crate::protocol::constants::{
    OFPACPT_CONT_STATUS_MASTER, OFPACPT_CONT_STATUS_SLAVE, OFPACPT_EXPERIMENTER_MASTER,
    OFPACPT_EXPERIMENTER_SLAVE, OFPACPT_FLOW_REMOVED_MASTER, OFPACPT_FLOW_REMOVED_SLAVE,
    OFPACPT_FLOW_STATS_MASTER, OFPACPT_FLOW_STATS_SLAVE, OFPACPT_PACKET_IN_MASTER,
    OFPACPT_PACKET_IN_SLAVE, OFPACPT_PORT_STATUS_MASTER, OFPACPT_PORT_STATUS_SLAVE,
    OFPACPT_REQUESTFORWARD_MASTER, OFPACPT_REQUESTFORWARD_SLAVE, OFPACPT_ROLE_STATUS_MASTER,
    OFPACPT_ROLE_STATUS_SLAVE, OFPACPT_TABLE_STATUS_MASTER, OFPACPT_TABLE_STATUS_SLAVE,
    OFPBCT_CLOSE_REPLY, OFPBCT_CLOSE_REQUEST, OFPBCT_COMMIT_REPLY, OFPBCT_COMMIT_REQUEST,
    OFPBCT_DISCARD_REPLY, OFPBCT_DISCARD_REQUEST, OFPBCT_OPEN_REPLY, OFPBCT_OPEN_REQUEST,
    OFPBPT_EXPERIMENTER, OFPBPT_TIME, OFPCRR_CONFIG, OFPCRR_EXPERIMENTER, OFPCRR_MASTER_REQUEST,
    OFPCR_ROLE_EQUAL, OFPCR_ROLE_MASTER, OFPCR_ROLE_NOCHANGE, OFPCR_ROLE_SLAVE,
    OFPCSPT_EXPERIMENTER, OFPCSPT_URI, OFPCSR_CHANNEL_STATUS, OFPCSR_CONTROLLER_ADDED,
    OFPCSR_CONTROLLER_REMOVED, OFPCSR_EXPERIMENTER, OFPCSR_REQUEST, OFPCSR_ROLE, OFPCSR_SHORT_ID,
    OFPCT_STATUS_DOWN, OFPCT_STATUS_UP, OFPFME_ABBREV, OFPFME_ADDED, OFPFME_INITIAL,
    OFPFME_MODIFIED, OFPFME_PAUSED, OFPFME_REMOVED, OFPFME_RESUMED, OFPGBPT_EXPERIMENTER,
    OFPGBPT_WATCH_GROUP, OFPGBPT_WATCH_PORT, OFPGBPT_WEIGHT, OFPGC_ADD, OFPGC_DELETE,
    OFPGC_INSERT_BUCKET, OFPGC_MODIFY, OFPGC_REMOVE_BUCKET, OFPGPT_EXPERIMENTER, OFPGT_ALL,
    OFPG_BUCKET_ALL, OFPMBT_DROP, OFPMBT_DSCP_REMARK, OFPMBT_EXPERIMENTER, OFPMC_ADD, OFPMC_DELETE,
    OFPMC_MODIFY, OFPMP_AGGREGATE_STATS, OFPMP_BUNDLE_FEATURES, OFPMP_CONTROLLER_STATUS,
    OFPMP_DESC, OFPMP_EXPERIMENTER, OFPMP_FLOW_DESC, OFPMP_FLOW_MONITOR, OFPMP_FLOW_STATS,
    OFPMP_GROUP_DESC, OFPMP_GROUP_FEATURES, OFPMP_GROUP_STATS, OFPMP_METER_DESC,
    OFPMP_METER_FEATURES, OFPMP_METER_STATS, OFPMP_PORT_DESC, OFPMP_PORT_STATS, OFPMP_QUEUE_DESC,
    OFPMP_QUEUE_STATS, OFPMP_TABLE_DESC, OFPMP_TABLE_FEATURES, OFPMP_TABLE_STATS, OFPPDPT_ETHERNET,
    OFPPDPT_EXPERIMENTER, OFPPDPT_OPTICAL, OFPPDPT_PIPELINE_INPUT, OFPPDPT_PIPELINE_OUTPUT,
    OFPPDPT_RECIRCULATE, OFPPMPT_ETHERNET, OFPPMPT_EXPERIMENTER, OFPPMPT_OPTICAL, OFPPR_ADD,
    OFPPR_DELETE, OFPPR_MODIFY, OFPPSPT_ETHERNET, OFPPSPT_EXPERIMENTER, OFPPSPT_OPTICAL,
    OFPQDPT_EXPERIMENTER, OFPQDPT_MAX_RATE, OFPQDPT_MIN_RATE, OFPQSPT_EXPERIMENTER, OFPRR_DELETE,
    OFPRR_EVICTION, OFPRR_GROUP_DELETE, OFPRR_HARD_TIMEOUT, OFPRR_IDLE_TIMEOUT, OFPRR_METER_DELETE,
    OFPTFPT_APPLY_ACTIONS, OFPTFPT_APPLY_ACTIONS_MISS, OFPTFPT_APPLY_COPYFIELD,
    OFPTFPT_APPLY_COPYFIELD_MISS, OFPTFPT_APPLY_SETFIELD, OFPTFPT_APPLY_SETFIELD_MISS,
    OFPTFPT_EXPERIMENTER, OFPTFPT_EXPERIMENTER_MISS, OFPTFPT_INSTRUCTIONS,
    OFPTFPT_INSTRUCTIONS_MISS, OFPTFPT_MATCH, OFPTFPT_NEXT_TABLES, OFPTFPT_NEXT_TABLES_MISS,
    OFPTFPT_PACKET_TYPES, OFPTFPT_TABLE_SYNC_FROM, OFPTFPT_WILDCARDS, OFPTFPT_WRITE_ACTIONS,
    OFPTFPT_WRITE_ACTIONS_MISS, OFPTFPT_WRITE_COPYFIELD, OFPTFPT_WRITE_COPYFIELD_MISS,
    OFPTFPT_WRITE_SETFIELD, OFPTFPT_WRITE_SETFIELD_MISS, OFPTMPBF_EXPERIMENTER,
    OFPTMPBF_TIME_CAPABILITY, OFPTMPT_EVICTION, OFPTMPT_EXPERIMENTER, OFPTMPT_VACANCY,
    OFPTR_VACANCY_DOWN, OFPTR_VACANCY_UP, OFPT_BUNDLE_ADD_MESSAGE, OFPT_BUNDLE_CONTROL,
    OFPT_CONTROLLER_STATUS, OFPT_EXPERIMENTER, OFPT_FLOW_REMOVED, OFPT_GET_ASYNC_REPLY,
    OFPT_GET_ASYNC_REQUEST, OFPT_GROUP_MOD, OFPT_METER_MOD, OFPT_MULTIPART_REPLY,
    OFPT_MULTIPART_REQUEST, OFPT_PORT_MOD, OFPT_PORT_STATUS, OFPT_REQUESTFORWARD, OFPT_ROLE_REPLY,
    OFPT_ROLE_REQUEST, OFPT_ROLE_STATUS, OFPT_SET_ASYNC, OFPT_TABLE_MOD, OFPT_TABLE_STATUS,
    OFPXMC_EXPERIMENTER, OFP_HEADER_LEN, OFP_VERSION_1_5,
};
use crate::protocol::error::{OfError, Result};
use crate::protocol::header::Header;
use crate::protocol::instruction::{parse_instructions, Instruction};
use crate::protocol::oxs;

fn invalid_length(len: usize) -> OfError {
    OfError::InvalidLength(u16::try_from(len).unwrap_or(u16::MAX))
}

fn encode_message(msg_type: u8, xid: u32, body: &[u8]) -> Result<Vec<u8>> {
    let length = OFP_HEADER_LEN + body.len();
    let mut out = Vec::with_capacity(length);
    Header {
        version: OFP_VERSION_1_5,
        msg_type,
        length: checked_u16_len(length)?,
        xid,
    }
    .encode(&mut out);
    out.extend_from_slice(body);
    Ok(out)
}

fn ensure_zero_padding(frame: &[u8], start: usize, end: usize) -> Result<()> {
    // Preserve bounds validation while ignoring padding contents as required
    // by section 7.1.2.
    let _ = frame.get(start..end).ok_or(OfError::ShortBuffer)?;
    Ok(())
}

fn body_from_frame(frame: &[u8], expected_type: u8, min_len: usize) -> Result<(Header, &[u8])> {
    let header = Header::parse(frame)?;
    if header.msg_type != expected_type {
        return Err(OfError::UnknownMessageType(header.msg_type));
    }
    let msg_len = header.length as usize;
    if frame.len() < msg_len {
        return Err(OfError::ShortBuffer);
    }
    if frame.len() != msg_len {
        return Err(OfError::InvalidLength(header.length));
    }
    if msg_len < min_len {
        return Err(OfError::InvalidLength(header.length));
    }
    let body = frame
        .get(OFP_HEADER_LEN..msg_len)
        .ok_or(OfError::ShortBuffer)?;
    Ok((header, body))
}

const fn validate_multipart_kind(kind: u16) -> Result<()> {
    let known = matches!(
        kind,
        OFPMP_DESC
            | OFPMP_FLOW_DESC
            | OFPMP_AGGREGATE_STATS
            | OFPMP_TABLE_STATS
            | OFPMP_PORT_STATS
            | OFPMP_QUEUE_STATS
            | OFPMP_GROUP_STATS
            | OFPMP_GROUP_DESC
            | OFPMP_GROUP_FEATURES
            | OFPMP_METER_STATS
            | OFPMP_METER_DESC
            | OFPMP_METER_FEATURES
            | OFPMP_TABLE_FEATURES
            | OFPMP_PORT_DESC
            | OFPMP_TABLE_DESC
            | OFPMP_QUEUE_DESC
            | OFPMP_FLOW_MONITOR
            | OFPMP_FLOW_STATS
            | OFPMP_CONTROLLER_STATUS
            | OFPMP_BUNDLE_FEATURES
            | OFPMP_EXPERIMENTER
    );
    if known {
        Ok(())
    } else {
        let bytes = kind.to_be_bytes();
        Err(OfError::InvalidValue {
            field: "multipart_type",
            value: u64::from_be_bytes([0, 0, 0, 0, 0, 0, bytes[0], bytes[1]]),
        })
    }
}

const fn validate_role(role: u32) -> Result<()> {
    let known = matches!(
        role,
        OFPCR_ROLE_NOCHANGE | OFPCR_ROLE_EQUAL | OFPCR_ROLE_MASTER | OFPCR_ROLE_SLAVE
    );
    if known {
        Ok(())
    } else {
        let bytes = role.to_be_bytes();
        Err(OfError::InvalidValue {
            field: "role",
            value: u64::from_be_bytes([0, 0, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }
}

const fn validate_meter_command(command: u16) -> Result<()> {
    if matches!(command, OFPMC_ADD | OFPMC_MODIFY | OFPMC_DELETE) {
        Ok(())
    } else {
        let bytes = command.to_be_bytes();
        Err(OfError::InvalidValue {
            field: "meter_command",
            value: u64::from_be_bytes([0, 0, 0, 0, 0, 0, bytes[0], bytes[1]]),
        })
    }
}

const fn validate_group_command(command: u16) -> Result<()> {
    if matches!(
        command,
        OFPGC_ADD | OFPGC_MODIFY | OFPGC_DELETE | OFPGC_INSERT_BUCKET | OFPGC_REMOVE_BUCKET
    ) {
        Ok(())
    } else {
        let bytes = command.to_be_bytes();
        Err(OfError::InvalidValue {
            field: "group_command",
            value: u64::from_be_bytes([0, 0, 0, 0, 0, 0, bytes[0], bytes[1]]),
        })
    }
}

const fn validate_bundle_type(ctrl_type: u16) -> Result<()> {
    if matches!(
        ctrl_type,
        OFPBCT_OPEN_REQUEST
            | OFPBCT_OPEN_REPLY
            | OFPBCT_CLOSE_REQUEST
            | OFPBCT_CLOSE_REPLY
            | OFPBCT_COMMIT_REQUEST
            | OFPBCT_COMMIT_REPLY
            | OFPBCT_DISCARD_REQUEST
            | OFPBCT_DISCARD_REPLY
    ) {
        Ok(())
    } else {
        let bytes = ctrl_type.to_be_bytes();
        Err(OfError::InvalidValue {
            field: "bundle_ctrl_type",
            value: u64::from_be_bytes([0, 0, 0, 0, 0, 0, bytes[0], bytes[1]]),
        })
    }
}

const fn padded_len(len: usize) -> usize {
    len.div_ceil(8) * 8
}

const fn validate_async_property_type(kind: u16) -> Result<()> {
    let known = matches!(
        kind,
        OFPACPT_PACKET_IN_SLAVE
            | OFPACPT_PACKET_IN_MASTER
            | OFPACPT_PORT_STATUS_SLAVE
            | OFPACPT_PORT_STATUS_MASTER
            | OFPACPT_FLOW_REMOVED_SLAVE
            | OFPACPT_FLOW_REMOVED_MASTER
            | OFPACPT_ROLE_STATUS_SLAVE
            | OFPACPT_ROLE_STATUS_MASTER
            | OFPACPT_TABLE_STATUS_SLAVE
            | OFPACPT_TABLE_STATUS_MASTER
            | OFPACPT_REQUESTFORWARD_SLAVE
            | OFPACPT_REQUESTFORWARD_MASTER
            | OFPACPT_FLOW_STATS_SLAVE
            | OFPACPT_FLOW_STATS_MASTER
            | OFPACPT_CONT_STATUS_SLAVE
            | OFPACPT_CONT_STATUS_MASTER
            | OFPACPT_EXPERIMENTER_SLAVE
            | OFPACPT_EXPERIMENTER_MASTER
    );
    if known {
        Ok(())
    } else {
        let bytes = kind.to_be_bytes();
        Err(OfError::InvalidValue {
            field: "async_property_type",
            value: u64::from_be_bytes([0, 0, 0, 0, 0, 0, bytes[0], bytes[1]]),
        })
    }
}

fn encode_properties(properties: &[Property]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for property in properties {
        property.encode(&mut out)?;
    }
    Ok(out)
}

fn parse_property_entries(
    body: &[u8],
    validate_type: fn(u16) -> Result<()>,
) -> Result<Vec<(u16, Vec<u8>)>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        if body.len() - offset < 4 {
            return Err(OfError::ShortBuffer);
        }
        let kind = read_u16(body, offset)?;
        validate_type(kind)?;
        let len = usize::from(read_u16(body, offset + 2)?);
        if len < 4 {
            return Err(invalid_length(len));
        }
        let padded = padded_len(len);
        if offset + padded > body.len() {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(body, offset + len, offset + padded)?;
        let raw = body.get(offset..offset + len).ok_or(OfError::ShortBuffer)?;
        entries.push((kind, raw.to_vec()));
        offset += padded;
    }
    Ok(entries)
}

fn parse_properties(body: &[u8], validate_type: fn(u16) -> Result<()>) -> Result<Vec<Property>> {
    parse_property_entries(body, validate_type)?
        .into_iter()
        .map(|(kind, raw)| Property::parse(kind, &raw))
        .collect()
}

#[allow(clippy::unnecessary_wraps)]
const fn allow_any_property_type(_kind: u16) -> Result<()> {
    Ok(())
}

fn parse_typed_properties<T>(
    body: &[u8],
    parse_one: fn(u16, &[u8]) -> Result<T>,
) -> Result<Vec<T>> {
    parse_property_entries(body, allow_any_property_type)?
        .into_iter()
        .map(|(kind, raw)| parse_one(kind, &raw))
        .collect()
}

fn encode_typed_properties<T>(
    properties: &[T],
    encode_one: fn(&T, &mut Vec<u8>) -> Result<()>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for property in properties {
        encode_one(property, &mut out)?;
    }
    Ok(out)
}

/// `struct ofp_time` (spec 7.2.10): a seconds/nanoseconds pair used by
/// the bundle scheduling properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Time {
    /// Whole seconds since the epoch.
    pub seconds: u64,
    /// Nanoseconds beyond `seconds`.
    pub nanoseconds: u32,
}

impl Time {
    fn parse(raw: &[u8], offset: usize) -> Result<Self> {
        ensure_zero_padding(raw, offset + 12, offset + 16)?;
        Ok(Self {
            seconds: read_u64(raw, offset)?,
            nanoseconds: read_u32(raw, offset + 8)?,
        })
    }

    fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.seconds.to_be_bytes());
        out.extend_from_slice(&self.nanoseconds.to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
    }
}

/// Reads the fixed `experimenter`/`exp_type` pair every `*_prop_experimenter`
/// property shares, plus its trailing vendor data.
fn parse_experimenter_property(raw: &[u8]) -> Result<(u32, u32, Vec<u8>)> {
    if raw.len() < 12 {
        return Err(invalid_length(raw.len()));
    }
    Ok((
        read_u32(raw, 4)?,
        read_u32(raw, 8)?,
        raw.get(12..).unwrap_or_default().to_vec(),
    ))
}

fn encode_experimenter_property(
    out: &mut Vec<u8>,
    kind: u16,
    experimenter: u32,
    exp_type: u32,
    data: &[u8],
) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&[0u8; 2]);
    out.extend_from_slice(&experimenter.to_be_bytes());
    out.extend_from_slice(&exp_type.to_be_bytes());
    out.extend_from_slice(data);
}

/// Writes a property's `length` (excluding padding) at `start + 2`, then
/// pads the property out to the spec's 8-byte property alignment.
fn finish_property(out: &mut Vec<u8>, start: usize) -> Result<()> {
    let len = checked_u16_len(out.len() - start)?;
    if let Some(dst) = out.get_mut(start + 2..start + 4) {
        dst.copy_from_slice(&len.to_be_bytes());
    }
    while !(out.len() - start).is_multiple_of(8) {
        out.push(0);
    }
    Ok(())
}

/// One `ofp_controller_status_prop_header`-framed property of an
/// `ofp_controller_status` (spec 7.4.6). The connection URI is
/// mandatory; everything else is optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerStatusProperty {
    /// `OFPCSPT_URI`: the connection URI, e.g. `tls:10.0.0.1:6653`.
    Uri(String),
    /// A vendor property.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload, uninterpreted.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// round-trips.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl ControllerStatusProperty {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        match kind {
            OFPCSPT_URI => {
                let bytes = raw.get(4..).unwrap_or_default();
                let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
                Ok(Self::Uri(
                    String::from_utf8_lossy(bytes.get(..end).unwrap_or_default()).into_owned(),
                ))
            }
            OFPCSPT_EXPERIMENTER => {
                let (experimenter, exp_type, data) = parse_experimenter_property(raw)?;
                Ok(Self::Experimenter {
                    experimenter,
                    exp_type,
                    data,
                })
            }
            _ => Ok(Self::Raw {
                kind,
                data: raw.get(4..).unwrap_or_default().to_vec(),
            }),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        match self {
            Self::Uri(uri) => {
                out.extend_from_slice(&OFPCSPT_URI.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(uri.as_bytes());
            }
            Self::Experimenter {
                experimenter,
                exp_type,
                data,
            } => encode_experimenter_property(
                out,
                OFPCSPT_EXPERIMENTER,
                *experimenter,
                *exp_type,
                data,
            ),
            Self::Raw { kind, data } => {
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(data);
            }
        }
        finish_property(out, start)
    }
}

/// One `ofp_table_mod_prop_header`-framed property, shared by
/// `ofp_table_mod` and `ofp_table_desc` (spec 7.3.3 / 7.3.5.16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableModProperty {
    /// `OFPTMPT_EVICTION`: bitmap of `OFPTMPEF_*`.
    Eviction {
        /// Bitmap of `OFPTMPEF_*`: which eviction heuristics are enabled.
        flags: u32,
    },
    /// `OFPTMPT_VACANCY`. `vacancy` is only meaningful in an
    /// `ofp_table_desc`; a table-mod sets it to zero.
    Vacancy {
        /// Fill percentage below which a vacancy event is generated.
        vacancy_down: u8,
        /// Fill percentage above which a vacancy event is generated.
        vacancy_up: u8,
        /// Current fill percentage; read-only, zero in a table-mod.
        vacancy: u8,
    },
    /// An experimenter (vendor-defined) property.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload, uninterpreted.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// round-trips.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl TableModProperty {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        match kind {
            OFPTMPT_EVICTION => {
                if raw.len() != 8 {
                    return Err(invalid_length(raw.len()));
                }
                Ok(Self::Eviction {
                    flags: read_u32(raw, 4)?,
                })
            }
            OFPTMPT_VACANCY => {
                let fixed: &[u8; 8] = raw.try_into().map_err(|_| invalid_length(raw.len()))?;
                ensure_zero_padding(fixed, 7, 8)?;
                Ok(Self::Vacancy {
                    vacancy_down: fixed[4],
                    vacancy_up: fixed[5],
                    vacancy: fixed[6],
                })
            }
            OFPTMPT_EXPERIMENTER => {
                let (experimenter, exp_type, data) = parse_experimenter_property(raw)?;
                Ok(Self::Experimenter {
                    experimenter,
                    exp_type,
                    data,
                })
            }
            _ => Ok(Self::Raw {
                kind,
                data: raw.get(4..).unwrap_or_default().to_vec(),
            }),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        match self {
            Self::Eviction { flags } => {
                out.extend_from_slice(&OFPTMPT_EVICTION.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(&flags.to_be_bytes());
            }
            Self::Vacancy {
                vacancy_down,
                vacancy_up,
                vacancy,
            } => {
                out.extend_from_slice(&OFPTMPT_VACANCY.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.push(*vacancy_down);
                out.push(*vacancy_up);
                out.push(*vacancy);
                out.push(0);
            }
            Self::Experimenter {
                experimenter,
                exp_type,
                data,
            } => encode_experimenter_property(
                out,
                OFPTMPT_EXPERIMENTER,
                *experimenter,
                *exp_type,
                data,
            ),
            Self::Raw { kind, data } => {
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(data);
            }
        }
        finish_property(out, start)
    }
}

/// One `ofp_port_mod_prop_header`-framed property of an `ofp_port_mod`
/// (spec 7.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortModProperty {
    /// `OFPPMPT_ETHERNET`: bitmap of `OFPPF_*` to advertise.
    Ethernet {
        /// Bitmap of `OFPPF_*` features to advertise.
        advertise: u32,
    },
    /// `OFPPMPT_OPTICAL`.
    Optical {
        /// Bitmap of `OFPOPT_*`: which optical parameters to apply.
        configure: u32,
        /// Frequency or wavelength to set.
        freq_lmda: u32,
        /// Signed frequency offset.
        fl_offset: i32,
        /// Channel spacing around `freq_lmda`.
        grid_span: u32,
        /// Transmit power.
        tx_pwr: u32,
    },
    /// An experimenter (vendor-defined) property.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload, uninterpreted.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// round-trips.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl PortModProperty {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        match kind {
            OFPPMPT_ETHERNET => {
                if raw.len() != 8 {
                    return Err(invalid_length(raw.len()));
                }
                Ok(Self::Ethernet {
                    advertise: read_u32(raw, 4)?,
                })
            }
            OFPPMPT_OPTICAL => {
                if raw.len() != 24 {
                    return Err(invalid_length(raw.len()));
                }
                Ok(Self::Optical {
                    configure: read_u32(raw, 4)?,
                    freq_lmda: read_u32(raw, 8)?,
                    fl_offset: read_u32(raw, 12)?.cast_signed(),
                    grid_span: read_u32(raw, 16)?,
                    tx_pwr: read_u32(raw, 20)?,
                })
            }
            OFPPMPT_EXPERIMENTER => {
                let (experimenter, exp_type, data) = parse_experimenter_property(raw)?;
                Ok(Self::Experimenter {
                    experimenter,
                    exp_type,
                    data,
                })
            }
            _ => Ok(Self::Raw {
                kind,
                data: raw.get(4..).unwrap_or_default().to_vec(),
            }),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        match self {
            Self::Ethernet { advertise } => {
                out.extend_from_slice(&OFPPMPT_ETHERNET.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(&advertise.to_be_bytes());
            }
            Self::Optical {
                configure,
                freq_lmda,
                fl_offset,
                grid_span,
                tx_pwr,
            } => {
                out.extend_from_slice(&OFPPMPT_OPTICAL.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(&configure.to_be_bytes());
                out.extend_from_slice(&freq_lmda.to_be_bytes());
                out.extend_from_slice(&fl_offset.to_be_bytes());
                out.extend_from_slice(&grid_span.to_be_bytes());
                out.extend_from_slice(&tx_pwr.to_be_bytes());
            }
            Self::Experimenter {
                experimenter,
                exp_type,
                data,
            } => encode_experimenter_property(
                out,
                OFPPMPT_EXPERIMENTER,
                *experimenter,
                *exp_type,
                data,
            ),
            Self::Raw { kind, data } => {
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(data);
            }
        }
        finish_property(out, start)
    }
}

/// One `ofp_port_stats_prop_header`-framed property of an
/// `ofp_port_stats` entry (spec 7.3.5.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortStatsProperty {
    /// `OFPPSPT_ETHERNET`: the Ethernet-specific error counters.
    Ethernet {
        /// Frames received with a framing error.
        rx_frame_err: u64,
        /// Frames dropped to receiver overrun.
        rx_over_err: u64,
        /// Frames received with a bad CRC.
        rx_crc_err: u64,
        /// Collisions seen on this port.
        collisions: u64,
    },
    /// `OFPPSPT_OPTICAL`: optical transceiver readings.
    Optical {
        /// Bitmap of `OFPOSF_*` saying which of the fields below are valid.
        flags: u32,
        /// Transmit frequency or wavelength.
        tx_freq_lmda: u32,
        /// Signed offset from `tx_freq_lmda`.
        tx_offset: u32,
        /// Channel spacing around `tx_freq_lmda`.
        tx_grid_span: u32,
        /// Receive frequency or wavelength.
        rx_freq_lmda: u32,
        /// Signed offset from `rx_freq_lmda`.
        rx_offset: u32,
        /// Channel spacing around `rx_freq_lmda`.
        rx_grid_span: u32,
        /// Current transmit power.
        tx_pwr: u16,
        /// Current receive power.
        rx_pwr: u16,
        /// Transmitter bias current.
        bias_current: u16,
        /// Transmitter temperature.
        temperature: u16,
    },
    /// An experimenter (vendor-defined) property.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload, uninterpreted.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// round-trips.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl PortStatsProperty {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        match kind {
            OFPPSPT_ETHERNET => {
                if raw.len() != 40 {
                    return Err(invalid_length(raw.len()));
                }
                ensure_zero_padding(raw, 4, 8)?;
                Ok(Self::Ethernet {
                    rx_frame_err: read_u64(raw, 8)?,
                    rx_over_err: read_u64(raw, 16)?,
                    rx_crc_err: read_u64(raw, 24)?,
                    collisions: read_u64(raw, 32)?,
                })
            }
            OFPPSPT_OPTICAL => {
                if raw.len() != 44 {
                    return Err(invalid_length(raw.len()));
                }
                ensure_zero_padding(raw, 4, 8)?;
                Ok(Self::Optical {
                    flags: read_u32(raw, 8)?,
                    tx_freq_lmda: read_u32(raw, 12)?,
                    tx_offset: read_u32(raw, 16)?,
                    tx_grid_span: read_u32(raw, 20)?,
                    rx_freq_lmda: read_u32(raw, 24)?,
                    rx_offset: read_u32(raw, 28)?,
                    rx_grid_span: read_u32(raw, 32)?,
                    tx_pwr: read_u16(raw, 36)?,
                    rx_pwr: read_u16(raw, 38)?,
                    bias_current: read_u16(raw, 40)?,
                    temperature: read_u16(raw, 42)?,
                })
            }
            OFPPSPT_EXPERIMENTER => {
                let (experimenter, exp_type, data) = parse_experimenter_property(raw)?;
                Ok(Self::Experimenter {
                    experimenter,
                    exp_type,
                    data,
                })
            }
            _ => Ok(Self::Raw {
                kind,
                data: raw.get(4..).unwrap_or_default().to_vec(),
            }),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        match self {
            Self::Ethernet {
                rx_frame_err,
                rx_over_err,
                rx_crc_err,
                collisions,
            } => {
                out.extend_from_slice(&OFPPSPT_ETHERNET.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(&[0u8; 4]);
                for value in [rx_frame_err, rx_over_err, rx_crc_err, collisions] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }
            Self::Optical {
                flags,
                tx_freq_lmda,
                tx_offset,
                tx_grid_span,
                rx_freq_lmda,
                rx_offset,
                rx_grid_span,
                tx_pwr,
                rx_pwr,
                bias_current,
                temperature,
            } => {
                out.extend_from_slice(&OFPPSPT_OPTICAL.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(&[0u8; 4]);
                for value in [
                    flags,
                    tx_freq_lmda,
                    tx_offset,
                    tx_grid_span,
                    rx_freq_lmda,
                    rx_offset,
                    rx_grid_span,
                ] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
                for value in [tx_pwr, rx_pwr, bias_current, temperature] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }
            Self::Experimenter {
                experimenter,
                exp_type,
                data,
            } => encode_experimenter_property(
                out,
                OFPPSPT_EXPERIMENTER,
                *experimenter,
                *exp_type,
                data,
            ),
            Self::Raw { kind, data } => {
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(data);
            }
        }
        finish_property(out, start)
    }
}

/// One `ofp_queue_stats_prop_header`-framed property of an
/// `ofp_queue_stats` entry (spec 7.3.5.12). `OFPQSPT_EXPERIMENTER` is
/// the only type the spec defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueStatsProperty {
    /// A vendor property.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload, uninterpreted.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// round-trips.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl QueueStatsProperty {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        if kind == OFPQSPT_EXPERIMENTER {
            let (experimenter, exp_type, data) = parse_experimenter_property(raw)?;
            return Ok(Self::Experimenter {
                experimenter,
                exp_type,
                data,
            });
        }
        Ok(Self::Raw {
            kind,
            data: raw.get(4..).unwrap_or_default().to_vec(),
        })
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        match self {
            Self::Experimenter {
                experimenter,
                exp_type,
                data,
            } => encode_experimenter_property(
                out,
                OFPQSPT_EXPERIMENTER,
                *experimenter,
                *exp_type,
                data,
            ),
            Self::Raw { kind, data } => {
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(data);
            }
        }
        finish_property(out, start)
    }
}

/// One `ofp_queue_desc_prop_header`-framed property of an
/// `ofp_queue_desc` entry (spec 7.3.5.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueDescProperty {
    /// `OFPQDPT_MIN_RATE`, in 1/10 of a percent;
    /// `OFPQ_MIN_RATE_UNCFG` (or any value > 1000) means unconfigured.
    MinRate(u16),
    /// `OFPQDPT_MAX_RATE`, same units and sentinel as [`Self::MinRate`].
    MaxRate(u16),
    /// A vendor property.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload, uninterpreted.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// round-trips.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl QueueDescProperty {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        match kind {
            OFPQDPT_MIN_RATE | OFPQDPT_MAX_RATE => {
                if raw.len() != 8 {
                    return Err(invalid_length(raw.len()));
                }
                ensure_zero_padding(raw, 6, 8)?;
                let rate = read_u16(raw, 4)?;
                Ok(match kind {
                    OFPQDPT_MIN_RATE => Self::MinRate(rate),
                    _ => Self::MaxRate(rate),
                })
            }
            OFPQDPT_EXPERIMENTER => {
                let (experimenter, exp_type, data) = parse_experimenter_property(raw)?;
                Ok(Self::Experimenter {
                    experimenter,
                    exp_type,
                    data,
                })
            }
            _ => Ok(Self::Raw {
                kind,
                data: raw.get(4..).unwrap_or_default().to_vec(),
            }),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        match self {
            Self::MinRate(rate) | Self::MaxRate(rate) => {
                let kind = match self {
                    Self::MinRate(_) => OFPQDPT_MIN_RATE,
                    _ => OFPQDPT_MAX_RATE,
                };
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(&rate.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
            }
            Self::Experimenter {
                experimenter,
                exp_type,
                data,
            } => encode_experimenter_property(
                out,
                OFPQDPT_EXPERIMENTER,
                *experimenter,
                *exp_type,
                data,
            ),
            Self::Raw { kind, data } => {
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(data);
            }
        }
        finish_property(out, start)
    }
}

/// One `ofp_bundle_prop_header`-framed property of an
/// `ofp_bundle_ctrl_msg` or `ofp_bundle_add_msg` (spec 7.3.9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleProperty {
    /// `OFPBPT_TIME`: the scheduled commit time.
    Time {
        /// When the bundle should be committed.
        scheduled_time: Time,
    },
    /// An experimenter (vendor-defined) property.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload, uninterpreted.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// round-trips.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl BundleProperty {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        match kind {
            OFPBPT_TIME => {
                if raw.len() != 24 {
                    return Err(invalid_length(raw.len()));
                }
                ensure_zero_padding(raw, 4, 8)?;
                Ok(Self::Time {
                    scheduled_time: Time::parse(raw, 8)?,
                })
            }
            OFPBPT_EXPERIMENTER => {
                let (experimenter, exp_type, data) = parse_experimenter_property(raw)?;
                Ok(Self::Experimenter {
                    experimenter,
                    exp_type,
                    data,
                })
            }
            _ => Ok(Self::Raw {
                kind,
                data: raw.get(4..).unwrap_or_default().to_vec(),
            }),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        match self {
            Self::Time { scheduled_time } => {
                out.extend_from_slice(&OFPBPT_TIME.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(&[0u8; 4]);
                scheduled_time.encode(out);
            }
            Self::Experimenter {
                experimenter,
                exp_type,
                data,
            } => encode_experimenter_property(
                out,
                OFPBPT_EXPERIMENTER,
                *experimenter,
                *exp_type,
                data,
            ),
            Self::Raw { kind, data } => {
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(data);
            }
        }
        finish_property(out, start)
    }
}

/// One `ofp_bundle_features_prop_header`-framed property of an
/// `OFPMP_BUNDLE_FEATURES` request or reply (spec 7.3.5.20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleFeaturesProperty {
    /// `OFPTMPBF_TIME_CAPABILITY`. Only meaningful in a reply; a request
    /// sends the fields zeroed.
    Time {
        /// How closely the switch can honour a scheduled commit.
        sched_accuracy: Time,
        /// Furthest into the future a commit may be scheduled.
        sched_max_future: Time,
        /// Furthest into the past a commit may be scheduled.
        sched_max_past: Time,
        /// The switch's own clock reading.
        timestamp: Time,
    },
    /// An experimenter (vendor-defined) property.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload, uninterpreted.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// round-trips.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl BundleFeaturesProperty {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        match kind {
            OFPTMPBF_TIME_CAPABILITY => {
                if raw.len() != 72 {
                    return Err(invalid_length(raw.len()));
                }
                ensure_zero_padding(raw, 4, 8)?;
                Ok(Self::Time {
                    sched_accuracy: Time::parse(raw, 8)?,
                    sched_max_future: Time::parse(raw, 24)?,
                    sched_max_past: Time::parse(raw, 40)?,
                    timestamp: Time::parse(raw, 56)?,
                })
            }
            OFPTMPBF_EXPERIMENTER => {
                let (experimenter, exp_type, data) = parse_experimenter_property(raw)?;
                Ok(Self::Experimenter {
                    experimenter,
                    exp_type,
                    data,
                })
            }
            _ => Ok(Self::Raw {
                kind,
                data: raw.get(4..).unwrap_or_default().to_vec(),
            }),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        match self {
            Self::Time {
                sched_accuracy,
                sched_max_future,
                sched_max_past,
                timestamp,
            } => {
                out.extend_from_slice(&OFPTMPBF_TIME_CAPABILITY.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(&[0u8; 4]);
                for time in [sched_accuracy, sched_max_future, sched_max_past, timestamp] {
                    time.encode(out);
                }
            }
            Self::Experimenter {
                experimenter,
                exp_type,
                data,
            } => encode_experimenter_property(
                out,
                OFPTMPBF_EXPERIMENTER,
                *experimenter,
                *exp_type,
                data,
            ),
            Self::Raw { kind, data } => {
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(data);
            }
        }
        finish_property(out, start)
    }
}

/// One `ofp_group_bucket_prop_header`-framed property of a group
/// bucket (spec 7.3.4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketProperty {
    /// `OFPGBPT_WEIGHT`: relative share of traffic for a `SELECT` group.
    Weight(u16),
    /// `OFPGBPT_WATCH_PORT`: bucket is live only while this port is up
    /// (`FF` groups).
    WatchPort(u32),
    /// `OFPGBPT_WATCH_GROUP`: bucket is live only while this group is
    /// live (`FF` groups).
    WatchGroup(u32),
    /// A vendor property.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload, uninterpreted.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// round-trips.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl BucketProperty {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        match kind {
            OFPGBPT_WEIGHT => {
                if raw.len() != 8 {
                    return Err(invalid_length(raw.len()));
                }
                ensure_zero_padding(raw, 6, 8)?;
                Ok(Self::Weight(read_u16(raw, 4)?))
            }
            OFPGBPT_WATCH_PORT => {
                if raw.len() != 8 {
                    return Err(invalid_length(raw.len()));
                }
                Ok(Self::WatchPort(read_u32(raw, 4)?))
            }
            OFPGBPT_WATCH_GROUP => {
                if raw.len() != 8 {
                    return Err(invalid_length(raw.len()));
                }
                Ok(Self::WatchGroup(read_u32(raw, 4)?))
            }
            OFPGBPT_EXPERIMENTER => {
                if raw.len() < 12 {
                    return Err(invalid_length(raw.len()));
                }
                Ok(Self::Experimenter {
                    experimenter: read_u32(raw, 4)?,
                    exp_type: read_u32(raw, 8)?,
                    data: raw.get(12..).unwrap_or_default().to_vec(),
                })
            }
            _ => Ok(Self::Raw {
                kind,
                data: raw.get(4..).unwrap_or_default().to_vec(),
            }),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        match self {
            Self::Weight(weight) => {
                out.extend_from_slice(&OFPGBPT_WEIGHT.to_be_bytes());
                out.extend_from_slice(&8u16.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&[0u8; 2]);
            }
            Self::WatchPort(port) => {
                out.extend_from_slice(&OFPGBPT_WATCH_PORT.to_be_bytes());
                out.extend_from_slice(&8u16.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::WatchGroup(group) => {
                out.extend_from_slice(&OFPGBPT_WATCH_GROUP.to_be_bytes());
                out.extend_from_slice(&8u16.to_be_bytes());
                out.extend_from_slice(&group.to_be_bytes());
            }
            Self::Experimenter {
                experimenter,
                exp_type,
                data,
            } => {
                let len = 12 + data.len();
                out.extend_from_slice(&OFPGBPT_EXPERIMENTER.to_be_bytes());
                out.extend_from_slice(&checked_u16_len(len)?.to_be_bytes());
                out.extend_from_slice(&experimenter.to_be_bytes());
                out.extend_from_slice(&exp_type.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::Raw { kind, data } => {
                let len = 4 + data.len();
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&checked_u16_len(len)?.to_be_bytes());
                out.extend_from_slice(data);
            }
        }
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        Ok(())
    }
}

fn parse_bucket_properties(body: &[u8]) -> Result<Vec<BucketProperty>> {
    parse_property_entries(body, allow_any_property_type)?
        .into_iter()
        .map(|(kind, raw)| BucketProperty::parse(kind, &raw))
        .collect()
}

/// One group-level property of an `ofp_group_mod` (spec 7.3.4.3).
/// The spec defines no standard types yet, so in practice this is an
/// experimenter or raw property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupProperty {
    /// A vendor property.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload, uninterpreted.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// round-trips.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl GroupProperty {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        if kind == OFPGPT_EXPERIMENTER {
            if raw.len() < 12 {
                return Err(invalid_length(raw.len()));
            }
            return Ok(Self::Experimenter {
                experimenter: read_u32(raw, 4)?,
                exp_type: read_u32(raw, 8)?,
                data: raw.get(12..).unwrap_or_default().to_vec(),
            });
        }
        Ok(Self::Raw {
            kind,
            data: raw.get(4..).unwrap_or_default().to_vec(),
        })
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        match self {
            Self::Experimenter {
                experimenter,
                exp_type,
                data,
            } => {
                let len = 12 + data.len();
                out.extend_from_slice(&OFPGPT_EXPERIMENTER.to_be_bytes());
                out.extend_from_slice(&checked_u16_len(len)?.to_be_bytes());
                out.extend_from_slice(&experimenter.to_be_bytes());
                out.extend_from_slice(&exp_type.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::Raw { kind, data } => {
                let len = 4 + data.len();
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&checked_u16_len(len)?.to_be_bytes());
                out.extend_from_slice(data);
            }
        }
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        Ok(())
    }
}

fn parse_group_properties(body: &[u8]) -> Result<Vec<GroupProperty>> {
    parse_property_entries(body, allow_any_property_type)?
        .into_iter()
        .map(|(kind, raw)| GroupProperty::parse(kind, &raw))
        .collect()
}

/// One bucket of a group (`ofp_bucket`, spec 7.3.4.3): a list of
/// actions plus the properties that decide when it is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// Identifier within the group; `OFPG_BUCKET_ALL` addresses every
    /// bucket in a bucket-targeted group-mod command.
    pub bucket_id: u32,
    /// Actions applied to a packet sent through this bucket.
    pub actions: Vec<Action>,
    /// Weight and watch-port/watch-group properties.
    pub properties: Vec<BucketProperty>,
}

impl Bucket {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&[0u8; 2]);
        let mut actions_buf = Vec::new();
        for action in &self.actions {
            action.encode(&mut actions_buf)?;
        }
        let action_array_len = checked_u16_len(actions_buf.len())?;
        out.extend_from_slice(&action_array_len.to_be_bytes());
        out.extend_from_slice(&self.bucket_id.to_be_bytes());
        out.extend_from_slice(&actions_buf);
        for property in &self.properties {
            property.encode(out)?;
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start..start + 2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 8 {
            return Err(OfError::ShortBuffer);
        }
        let action_array_len = usize::from(read_u16(raw, 2)?);
        if 8 + action_array_len > raw.len() {
            return Err(OfError::ShortBuffer);
        }
        let actions = parse_actions(
            raw.get(8..8 + action_array_len)
                .ok_or(OfError::ShortBuffer)?,
        )?;
        let properties =
            parse_bucket_properties(raw.get(8 + action_array_len..).unwrap_or_default())?;
        Ok(Self {
            bucket_id: read_u32(raw, 4)?,
            actions,
            properties,
        })
    }
}

fn parse_buckets(body: &[u8]) -> Result<Vec<Bucket>> {
    let mut buckets = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        if body.len() - offset < 8 {
            return Err(OfError::ShortBuffer);
        }
        let len = usize::from(read_u16(body, offset)?);
        if len < 8 || !len.is_multiple_of(8) {
            return Err(invalid_length(len));
        }
        if offset + len > body.len() {
            return Err(OfError::ShortBuffer);
        }
        let raw = body.get(offset..offset + len).ok_or(OfError::ShortBuffer)?;
        buckets.push(Bucket::parse(raw)?);
        offset += len;
    }
    Ok(buckets)
}

/// One band of a meter (`ofp_meter_band_*`, spec 7.3.4.4): what to do
/// with traffic that exceeds its rate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeterBand {
    /// `OFPMBT_DROP`: discard traffic above `rate`.
    Drop {
        /// Rate above which the band applies, in the unit the meter's
        /// `OFPMF_KBPS`/`OFPMF_PKTPS` flag selects.
        rate: u32,
        /// Burst tolerance, in the same unit. Only meaningful when the
        /// meter sets `OFPMF_BURST`.
        burst_size: u32,
    },
    /// `OFPMBT_DSCP_REMARK`: increase the drop precedence of traffic
    /// above `rate` instead of dropping it.
    DscpRemark {
        /// Rate above which the band applies; unit per the meter's flags.
        rate: u32,
        /// Burst tolerance, in the same unit.
        burst_size: u32,
        /// How many drop-precedence levels to add.
        prec_level: u8,
    },
    /// `OFPMBT_EXPERIMENTER`: a vendor band.
    Experimenter {
        /// Rate above which the band applies; unit per the meter's flags.
        rate: u32,
        /// Burst tolerance, in the same unit.
        burst_size: u32,
        /// The vendor's experimenter id.
        experimenter: u32,
    },
    /// A band type this crate does not model, kept verbatim.
    Unknown {
        /// `OFPMBT_*` type from the wire.
        band_type: u16,
        /// Rate above which the band applies.
        rate: u32,
        /// Burst tolerance.
        burst_size: u32,
        /// Body bytes following the fixed band header.
        data: Vec<u8>,
    },
}

impl MeterBand {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Drop { rate, burst_size } => {
                out.extend_from_slice(&OFPMBT_DROP.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&rate.to_be_bytes());
                out.extend_from_slice(&burst_size.to_be_bytes());
                out.extend_from_slice(&[0u8; 4]);
            }
            Self::DscpRemark {
                rate,
                burst_size,
                prec_level,
            } => {
                out.extend_from_slice(&OFPMBT_DSCP_REMARK.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&rate.to_be_bytes());
                out.extend_from_slice(&burst_size.to_be_bytes());
                out.push(*prec_level);
                out.extend_from_slice(&[0u8; 3]);
            }
            Self::Experimenter {
                rate,
                burst_size,
                experimenter,
            } => {
                out.extend_from_slice(&OFPMBT_EXPERIMENTER.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&rate.to_be_bytes());
                out.extend_from_slice(&burst_size.to_be_bytes());
                out.extend_from_slice(&experimenter.to_be_bytes());
            }
            Self::Unknown {
                band_type,
                rate,
                burst_size,
                data,
            } => {
                let len = 12 + data.len();
                out.extend_from_slice(&band_type.to_be_bytes());
                out.extend_from_slice(&checked_u16_len(len)?.to_be_bytes());
                out.extend_from_slice(&rate.to_be_bytes());
                out.extend_from_slice(&burst_size.to_be_bytes());
                out.extend_from_slice(data);
                while !out.len().is_multiple_of(8) {
                    out.push(0);
                }
            }
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 12 {
            return Err(OfError::ShortBuffer);
        }
        let band_type = read_u16(raw, 0)?;
        let rate = read_u32(raw, 4)?;
        let burst_size = read_u32(raw, 8)?;
        match band_type {
            OFPMBT_DROP => {
                if raw.len() != 16 {
                    return Err(invalid_length(raw.len()));
                }
                ensure_zero_padding(raw, 12, 16)?;
                Ok(Self::Drop { rate, burst_size })
            }
            OFPMBT_DSCP_REMARK => {
                if raw.len() != 16 {
                    return Err(invalid_length(raw.len()));
                }
                ensure_zero_padding(raw, 13, 16)?;
                Ok(Self::DscpRemark {
                    rate,
                    burst_size,
                    prec_level: *raw.get(12).ok_or(OfError::ShortBuffer)?,
                })
            }
            OFPMBT_EXPERIMENTER => {
                if raw.len() < 16 {
                    return Err(invalid_length(raw.len()));
                }
                Ok(Self::Experimenter {
                    rate,
                    burst_size,
                    experimenter: read_u32(raw, 12)?,
                })
            }
            _ => Ok(Self::Unknown {
                band_type,
                rate,
                burst_size,
                data: raw.get(12..).unwrap_or_default().to_vec(),
            }),
        }
    }
}

fn parse_meter_bands(body: &[u8]) -> Result<Vec<MeterBand>> {
    let mut bands = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        if body.len() - offset < 4 {
            return Err(OfError::ShortBuffer);
        }
        let len = usize::from(read_u16(body, offset + 2)?);
        if len < 12 || !len.is_multiple_of(8) {
            return Err(invalid_length(len));
        }
        if offset + len > body.len() {
            return Err(OfError::ShortBuffer);
        }
        let raw = body.get(offset..offset + len).ok_or(OfError::ShortBuffer)?;
        bands.push(MeterBand::parse(raw)?);
        offset += len;
    }
    Ok(bands)
}

/// One `ofp_async_config_prop_header`-framed property of an
/// `OFPT_SET_ASYNC`/`OFPT_GET_ASYNC_REPLY` (spec 7.3.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Property {
    /// An `OFPACPT_*` reason mask: which reasons of one message kind this
    /// connection wants.
    ReasonMask {
        /// The `OFPACPT_*` property type, which names both the message
        /// kind and the role (master/equal or slave) it applies to.
        kind: u16,
        /// Bitmap of that message's reason codes to enable.
        mask: u32,
    },
    /// A vendor async-config property.
    Experimenter {
        /// The `OFPACPT_EXPERIMENTER_*` property type.
        kind: u16,
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// round-trips.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl Property {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        match kind {
            OFPACPT_EXPERIMENTER_SLAVE | OFPACPT_EXPERIMENTER_MASTER => {
                if raw.len() < 12 {
                    return Err(invalid_length(raw.len()));
                }
                Ok(Self::Experimenter {
                    kind,
                    experimenter: read_u32(raw, 4)?,
                    exp_type: read_u32(raw, 8)?,
                    data: raw.get(12..).unwrap_or_default().to_vec(),
                })
            }
            _ => {
                if raw.len() == 8 {
                    Ok(Self::ReasonMask {
                        kind,
                        mask: read_u32(raw, 4)?,
                    })
                } else {
                    Ok(Self::Raw {
                        kind,
                        data: raw.get(4..).unwrap_or_default().to_vec(),
                    })
                }
            }
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        match self {
            Self::ReasonMask { kind, mask } => {
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&8u16.to_be_bytes());
                out.extend_from_slice(&mask.to_be_bytes());
            }
            Self::Experimenter {
                kind,
                experimenter,
                exp_type,
                data,
            } => {
                let len = 12 + data.len();
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&checked_u16_len(len)?.to_be_bytes());
                out.extend_from_slice(&experimenter.to_be_bytes());
                out.extend_from_slice(&exp_type.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::Raw { kind, data } => {
                let len = 4 + data.len();
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(&checked_u16_len(len)?.to_be_bytes());
                out.extend_from_slice(data);
            }
        }
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        Ok(())
    }
}

/// An `OFPT_MULTIPART_REQUEST` or `OFPT_MULTIPART_REPLY` with its body
/// still raw (spec 7.3.5).
///
/// A reply larger than one frame arrives as several of these sharing an
/// xid, each but the last flagged `OFPMPF_REPLY_MORE`;
/// [`crate::client::Connection::multipart_request`] reassembles them
/// before decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartMessage {
    /// Transaction id; every part of one reply sequence repeats it.
    pub xid: u32,
    /// The `OFPMP_*` subtype being requested or answered.
    pub kind: u16,
    /// `OFPMPF_*` flags. `OFPMPF_REPLY_MORE` on a reply means further
    /// parts follow.
    pub flags: u16,
    /// The raw subtype body. Decode it with [`Self::typed_request_body`]
    /// or [`Self::typed_reply_body`].
    pub body: Vec<u8>,
}

impl MultipartMessage {
    /// A multipart request of subtype `kind` carrying a raw body.
    #[must_use]
    pub const fn request(xid: u32, kind: u16, flags: u16, body: Vec<u8>) -> Self {
        Self {
            xid,
            kind,
            flags,
            body,
        }
    }

    /// A multipart reply of subtype `kind` carrying a raw body.
    #[must_use]
    pub const fn reply(xid: u32, kind: u16, flags: u16, body: Vec<u8>) -> Self {
        Self::request(xid, kind, flags, body)
    }

    pub(crate) fn encode_request(&self) -> Result<Vec<u8>> {
        self.encode(OFPT_MULTIPART_REQUEST)
    }

    pub(crate) fn encode_reply(&self) -> Result<Vec<u8>> {
        self.encode(OFPT_MULTIPART_REPLY)
    }

    fn encode(&self, msg_type: u8) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(8 + self.body.len());
        body.extend_from_slice(&self.kind.to_be_bytes());
        body.extend_from_slice(&self.flags.to_be_bytes());
        body.extend_from_slice(&[0u8; 4]);
        body.extend_from_slice(&self.body);
        encode_message(msg_type, self.xid, &body)
    }

    pub(crate) fn parse(frame: &[u8], expected_type: u8) -> Result<Self> {
        let (header, body) = body_from_frame(frame, expected_type, 16)?;
        validate_multipart_kind(read_u16(body, 0)?)?;
        ensure_zero_padding(body, 4, 8)?;
        Ok(Self {
            xid: header.xid,
            kind: read_u16(body, 0)?,
            flags: read_u16(body, 2)?,
            body: body.get(8..).unwrap_or_default().to_vec(),
        })
    }
}

/// An `OFPT_ROLE_REQUEST` or `OFPT_ROLE_REPLY` (`ofp_role_request`,
/// spec 7.3.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleRequest {
    /// Transaction id.
    pub xid: u32,
    /// The `OFPCR_ROLE_*` role being claimed, or `OFPCR_ROLE_NOCHANGE`
    /// to query the current one.
    pub role: u32,
    /// This controller's short id (1.5), or `OFPCID_UNDEFINED`.
    pub short_id: u16,
    /// Monotonically increasing generation id. A request carrying one
    /// older than the switch has already accepted is rejected as
    /// `OFPRRFC_STALE`.
    pub generation_id: u64,
}

impl RoleRequest {
    pub(crate) fn encode_request(&self) -> Result<Vec<u8>> {
        self.encode(OFPT_ROLE_REQUEST)
    }

    pub(crate) fn encode_reply(&self) -> Result<Vec<u8>> {
        self.encode(OFPT_ROLE_REPLY)
    }

    fn encode(&self, msg_type: u8) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(16);
        body.extend_from_slice(&self.role.to_be_bytes());
        body.extend_from_slice(&self.short_id.to_be_bytes());
        body.extend_from_slice(&[0u8; 2]);
        body.extend_from_slice(&self.generation_id.to_be_bytes());
        encode_message(msg_type, self.xid, &body)
    }

    pub(crate) fn parse(frame: &[u8], expected_type: u8) -> Result<Self> {
        let (header, body) = body_from_frame(frame, expected_type, 24)?;
        validate_role(read_u32(body, 0)?)?;
        ensure_zero_padding(body, 6, 8)?;
        Ok(Self {
            xid: header.xid,
            role: read_u32(body, 0)?,
            short_id: read_u16(body, 4)?,
            generation_id: read_u64(body, 8)?,
        })
    }
}

/// An `OFPT_SET_ASYNC` or `OFPT_GET_ASYNC_REPLY` (spec 7.3.10):
/// which asynchronous messages this connection receives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncConfig {
    /// Transaction id.
    pub xid: u32,
    /// The `OFPACPT_*` properties describing the mask.
    pub properties: Vec<Property>,
}

impl AsyncConfig {
    pub(crate) fn encode_get_request(xid: u32) -> Result<Vec<u8>> {
        encode_message(OFPT_GET_ASYNC_REQUEST, xid, &[])
    }

    pub(crate) fn encode_get_reply(&self) -> Result<Vec<u8>> {
        encode_message(
            OFPT_GET_ASYNC_REPLY,
            self.xid,
            &encode_properties(&self.properties)?,
        )
    }

    pub(crate) fn encode_set(&self) -> Result<Vec<u8>> {
        encode_message(
            OFPT_SET_ASYNC,
            self.xid,
            &encode_properties(&self.properties)?,
        )
    }

    pub(crate) fn parse(frame: &[u8], expected_type: u8) -> Result<Self> {
        let (header, body) = body_from_frame(frame, expected_type, 8)?;
        Ok(Self {
            xid: header.xid,
            properties: parse_properties(body, validate_async_property_type)?,
        })
    }
}

/// The async-configuration properties this crate sends by default.
///
/// See [`crate::client::Connection::enable_all_async_events`] for the
/// everything-on variant.
#[must_use]
pub fn default_async_properties() -> Vec<Property> {
    vec![
        Property::ReasonMask {
            kind: OFPACPT_PACKET_IN_SLAVE,
            mask: 0,
        },
        Property::ReasonMask {
            kind: OFPACPT_PACKET_IN_MASTER,
            mask: (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5),
        },
        Property::ReasonMask {
            kind: OFPACPT_PORT_STATUS_SLAVE,
            mask: (1 << OFPPR_ADD) | (1 << OFPPR_DELETE) | (1 << OFPPR_MODIFY),
        },
        Property::ReasonMask {
            kind: OFPACPT_PORT_STATUS_MASTER,
            mask: (1 << OFPPR_ADD) | (1 << OFPPR_DELETE) | (1 << OFPPR_MODIFY),
        },
        Property::ReasonMask {
            kind: OFPACPT_FLOW_REMOVED_SLAVE,
            mask: 0,
        },
        Property::ReasonMask {
            kind: OFPACPT_FLOW_REMOVED_MASTER,
            mask: (1 << OFPRR_IDLE_TIMEOUT)
                | (1 << OFPRR_HARD_TIMEOUT)
                | (1 << OFPRR_DELETE)
                | (1 << OFPRR_GROUP_DELETE)
                | (1 << OFPRR_METER_DELETE)
                | (1 << OFPRR_EVICTION),
        },
        Property::ReasonMask {
            kind: OFPACPT_ROLE_STATUS_SLAVE,
            mask: 0,
        },
        Property::ReasonMask {
            kind: OFPACPT_ROLE_STATUS_MASTER,
            mask: 0,
        },
        Property::ReasonMask {
            kind: OFPACPT_TABLE_STATUS_SLAVE,
            mask: 0,
        },
        Property::ReasonMask {
            kind: OFPACPT_TABLE_STATUS_MASTER,
            mask: 0,
        },
        Property::ReasonMask {
            kind: OFPACPT_REQUESTFORWARD_SLAVE,
            mask: 0,
        },
        Property::ReasonMask {
            kind: OFPACPT_REQUESTFORWARD_MASTER,
            mask: 0,
        },
        Property::ReasonMask {
            kind: OFPACPT_FLOW_STATS_SLAVE,
            mask: 0,
        },
        Property::ReasonMask {
            kind: OFPACPT_FLOW_STATS_MASTER,
            mask: 0,
        },
        Property::ReasonMask {
            kind: OFPACPT_CONT_STATUS_SLAVE,
            mask: (1 << OFPCSR_CHANNEL_STATUS)
                | (1 << OFPCSR_ROLE)
                | (1 << OFPCSR_CONTROLLER_ADDED)
                | (1 << OFPCSR_CONTROLLER_REMOVED)
                | (1 << OFPCSR_SHORT_ID)
                | (1 << OFPCSR_EXPERIMENTER),
        },
        Property::ReasonMask {
            kind: OFPACPT_CONT_STATUS_MASTER,
            mask: (1 << OFPCSR_CHANNEL_STATUS)
                | (1 << OFPCSR_ROLE)
                | (1 << OFPCSR_CONTROLLER_ADDED)
                | (1 << OFPCSR_CONTROLLER_REMOVED)
                | (1 << OFPCSR_SHORT_ID)
                | (1 << OFPCSR_EXPERIMENTER),
        },
    ]
}

/// An `OFPT_TABLE_MOD` (`ofp_table_mod`, spec 7.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableMod {
    /// Transaction id.
    pub xid: u32,
    /// Table to configure, or `OFPTT_ALL` for every table.
    pub table_id: u8,
    /// Bitmap of `OFPTC_*` table configuration bits.
    pub config: u32,
    /// Eviction and vacancy properties.
    pub properties: Vec<TableModProperty>,
}

impl TableMod {
    /// # Errors
    ///
    /// Returns an error if the encoded message length overflows a `u16`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(8 + self.properties.len());
        body.push(self.table_id);
        body.extend_from_slice(&[0u8; 3]);
        body.extend_from_slice(&self.config.to_be_bytes());
        body.extend_from_slice(&encode_typed_properties(
            &self.properties,
            TableModProperty::encode,
        )?);
        encode_message(OFPT_TABLE_MOD, self.xid, &body)
    }

    pub(crate) fn parse(frame: &[u8]) -> Result<Self> {
        let (header, body) = body_from_frame(frame, OFPT_TABLE_MOD, 16)?;
        ensure_zero_padding(body, 1, 4)?;
        Ok(Self {
            xid: header.xid,
            table_id: *body.first().ok_or(OfError::ShortBuffer)?,
            config: read_u32(body, 4)?,
            properties: parse_typed_properties(
                body.get(8..).unwrap_or_default(),
                TableModProperty::parse,
            )?,
        })
    }
}

/// An `OFPT_PORT_MOD` (`ofp_port_mod`, spec 7.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMod {
    /// Transaction id.
    pub xid: u32,
    /// Port to configure.
    pub port_no: u32,
    /// The port's hardware address, which the switch checks against its
    /// own as a guard against configuring the wrong port.
    pub hw_addr: [u8; 6],
    /// Bitmap of `OFPPC_*` bits to set.
    pub config: u32,
    /// Which `config` bits to change; zero bits are left alone.
    pub mask: u32,
    /// Ethernet and optical properties to apply.
    pub properties: Vec<PortModProperty>,
}

impl PortMod {
    /// # Errors
    ///
    /// Returns an error if the encoded message length overflows a `u16`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(24 + self.properties.len());
        body.extend_from_slice(&self.port_no.to_be_bytes());
        body.extend_from_slice(&[0u8; 4]);
        body.extend_from_slice(&self.hw_addr);
        body.extend_from_slice(&[0u8; 2]);
        body.extend_from_slice(&self.config.to_be_bytes());
        body.extend_from_slice(&self.mask.to_be_bytes());
        body.extend_from_slice(&encode_typed_properties(
            &self.properties,
            PortModProperty::encode,
        )?);
        encode_message(OFPT_PORT_MOD, self.xid, &body)
    }

    pub(crate) fn parse(frame: &[u8]) -> Result<Self> {
        let (header, body) = body_from_frame(frame, OFPT_PORT_MOD, 32)?;
        ensure_zero_padding(body, 4, 8)?;
        ensure_zero_padding(body, 14, 16)?;
        let head: &[u8; 14] = body.first_chunk::<14>().ok_or(OfError::ShortBuffer)?;
        let mut hw_addr = [0u8; 6];
        hw_addr.copy_from_slice(&head[8..14]);
        Ok(Self {
            xid: header.xid,
            port_no: read_u32(body, 0)?,
            hw_addr,
            config: read_u32(body, 16)?,
            mask: read_u32(body, 20)?,
            properties: parse_typed_properties(
                body.get(24..).unwrap_or_default(),
                PortModProperty::parse,
            )?,
        })
    }
}

/// An `OFPT_GROUP_MOD` (`ofp_group_mod`, spec 7.3.4.2).
///
/// See `examples/12_group_mod.rs` for a `SELECT` group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMod {
    /// Transaction id.
    pub xid: u32,
    /// The `OFPGC_*` command: add, modify, delete, or one of the 1.5
    /// bucket-level commands.
    pub command: u16,
    /// The `OFPGT_*` group type: all, select, indirect, or fast-failover.
    pub group_type: u8,
    /// Group to operate on, or `OFPG_ALL` on a delete.
    pub group_id: u32,
    /// For the bucket-level commands, which bucket to act on;
    /// `OFPG_BUCKET_ALL` for all of them. Ignored by the others.
    pub command_bucket_id: u32,
    /// The group's buckets.
    pub buckets: Vec<Bucket>,
    /// Group-level properties.
    pub properties: Vec<GroupProperty>,
}

impl GroupMod {
    /// Build an `OFPGC_ADD` with the spec-mandated
    /// `command_bucket_id` (see [`Self::encode`]).
    #[must_use]
    pub const fn add(xid: u32, group_type: u8, group_id: u32, buckets: Vec<Bucket>) -> Self {
        Self {
            xid,
            command: OFPGC_ADD,
            group_type,
            group_id,
            command_bucket_id: OFPG_BUCKET_ALL,
            buckets,
            properties: Vec::new(),
        }
    }

    /// Build an `OFPGC_DELETE` for `group_id` (or `OFPG_ALL`).
    #[must_use]
    pub const fn delete(xid: u32, group_id: u32) -> Self {
        Self {
            xid,
            command: OFPGC_DELETE,
            group_type: OFPGT_ALL,
            group_id,
            command_bucket_id: OFPG_BUCKET_ALL,
            buckets: Vec::new(),
            properties: Vec::new(),
        }
    }

    /// # Errors
    ///
    /// Returns an error if a bucket fails to encode, the encoded message
    /// length overflows a `u16`, or `command_bucket_id` violates spec
    /// 7.3.4.3: `OFPGC_ADD`, `OFPGC_MODIFY` and `OFPGC_DELETE` do not use
    /// the `command_bucket_id` field, and for those commands it must be
    /// set to `OFPG_BUCKET_ALL`. Real switches enforce this -- OVS
    /// rejects a zero here with `OFPGMFC_BAD_BUCKET`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if matches!(self.command, OFPGC_ADD | OFPGC_MODIFY | OFPGC_DELETE)
            && self.command_bucket_id != OFPG_BUCKET_ALL
        {
            return Err(OfError::InvalidValue {
                field: "group_mod command_bucket_id",
                value: u64::from(self.command_bucket_id),
            });
        }
        let mut buckets_buf = Vec::new();
        for bucket in &self.buckets {
            bucket.encode(&mut buckets_buf)?;
        }
        let mut properties_buf = Vec::new();
        for property in &self.properties {
            property.encode(&mut properties_buf)?;
        }
        let bucket_array_len = checked_u16_len(buckets_buf.len())?;
        let mut body = Vec::with_capacity(16 + buckets_buf.len() + properties_buf.len());
        body.extend_from_slice(&self.command.to_be_bytes());
        body.push(self.group_type);
        body.push(0);
        body.extend_from_slice(&self.group_id.to_be_bytes());
        body.extend_from_slice(&bucket_array_len.to_be_bytes());
        body.extend_from_slice(&[0u8; 2]);
        body.extend_from_slice(&self.command_bucket_id.to_be_bytes());
        body.extend_from_slice(&buckets_buf);
        body.extend_from_slice(&properties_buf);
        encode_message(OFPT_GROUP_MOD, self.xid, &body)
    }

    pub(crate) fn parse(frame: &[u8]) -> Result<Self> {
        let (header, body) = body_from_frame(frame, OFPT_GROUP_MOD, 24)?;
        validate_group_command(read_u16(body, 0)?)?;
        ensure_zero_padding(body, 3, 4)?;
        ensure_zero_padding(body, 10, 12)?;
        let bucket_array_len = usize::from(read_u16(body, 8)?);
        if 16 + bucket_array_len > body.len() {
            return Err(OfError::ShortBuffer);
        }
        let buckets = parse_buckets(
            body.get(16..16 + bucket_array_len)
                .ok_or(OfError::ShortBuffer)?,
        )?;
        let properties =
            parse_group_properties(body.get(16 + bucket_array_len..).unwrap_or_default())?;
        let head: &[u8; 3] = body.first_chunk::<3>().ok_or(OfError::ShortBuffer)?;
        Ok(Self {
            xid: header.xid,
            command: read_u16(body, 0)?,
            group_type: head[2],
            group_id: read_u32(body, 4)?,
            command_bucket_id: read_u32(body, 12)?,
            buckets,
            properties,
        })
    }
}

/// An `OFPT_METER_MOD` (`ofp_meter_mod`, spec 7.3.4.4).
///
/// See `examples/15_meter_mod.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterMod {
    /// Transaction id.
    pub xid: u32,
    /// The `OFPMC_*` command: add, modify or delete.
    pub command: u16,
    /// Bitmap of `OFPMF_*`. Must name exactly one rate unit
    /// (`OFPMF_KBPS` or `OFPMF_PKTPS`); zero is rejected with
    /// `OFPMMFC_BAD_FLAGS`.
    pub flags: u16,
    /// Meter to operate on, or a reserved `OFPM_*` id.
    pub meter_id: u32,
    /// The meter's bands, each with its own rate.
    pub bands: Vec<MeterBand>,
}

impl MeterMod {
    /// # Errors
    ///
    /// Returns an error if a band fails to encode or the encoded message
    /// length overflows a `u16`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bands_buf = Vec::new();
        for band in &self.bands {
            band.encode(&mut bands_buf)?;
        }
        let mut body = Vec::with_capacity(8 + bands_buf.len());
        body.extend_from_slice(&self.command.to_be_bytes());
        body.extend_from_slice(&self.flags.to_be_bytes());
        body.extend_from_slice(&self.meter_id.to_be_bytes());
        body.extend_from_slice(&bands_buf);
        encode_message(OFPT_METER_MOD, self.xid, &body)
    }

    pub(crate) fn parse(frame: &[u8]) -> Result<Self> {
        let (header, body) = body_from_frame(frame, OFPT_METER_MOD, 16)?;
        validate_meter_command(read_u16(body, 0)?)?;
        Ok(Self {
            xid: header.xid,
            command: read_u16(body, 0)?,
            flags: read_u16(body, 2)?,
            meter_id: read_u32(body, 4)?,
            bands: parse_meter_bands(body.get(8..).unwrap_or_default())?,
        })
    }
}

/// An `OFPT_BUNDLE_CONTROL` message (`ofp_bundle_ctrl_msg`, spec
/// 7.3.9): opens, closes, commits or discards a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleMessage {
    /// Transaction id.
    pub xid: u32,
    /// Controller-chosen bundle identifier.
    pub bundle_id: u32,
    /// The `OFPBCT_*` operation: open, close, commit or discard, and
    /// their reply forms.
    pub ctrl_type: u16,
    /// Bitmap of `OFPBF_*`, e.g. `OFPBF_ATOMIC` and `OFPBF_ORDERED`.
    pub flags: u16,
    /// Bundle properties, e.g. a scheduled commit time.
    pub properties: Vec<BundleProperty>,
}

impl BundleMessage {
    /// # Errors
    ///
    /// Returns an error if the encoded message length overflows a `u16`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(8 + self.properties.len());
        body.extend_from_slice(&self.bundle_id.to_be_bytes());
        body.extend_from_slice(&self.ctrl_type.to_be_bytes());
        body.extend_from_slice(&self.flags.to_be_bytes());
        body.extend_from_slice(&encode_typed_properties(
            &self.properties,
            BundleProperty::encode,
        )?);
        encode_message(OFPT_BUNDLE_CONTROL, self.xid, &body)
    }

    pub(crate) fn parse(frame: &[u8]) -> Result<Self> {
        let (header, body) = body_from_frame(frame, OFPT_BUNDLE_CONTROL, 16)?;
        validate_bundle_type(read_u16(body, 4)?)?;
        Ok(Self {
            xid: header.xid,
            bundle_id: read_u32(body, 0)?,
            ctrl_type: read_u16(body, 4)?,
            flags: read_u16(body, 6)?,
            properties: parse_typed_properties(
                body.get(8..).unwrap_or_default(),
                BundleProperty::parse,
            )?,
        })
    }
}

/// An `OFPT_BUNDLE_ADD_MESSAGE` (`ofp_bundle_add_msg`, spec 7.3.9):
/// one message appended to an open bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleAddMessage {
    /// Transaction id, which must match the bundled message's own xid --
    /// a mismatch is rejected with `OFPBFC_MSG_BAD_XID`.
    pub xid: u32,
    /// The bundle to append to.
    pub bundle_id: u32,
    /// Bitmap of `OFPBF_*`.
    pub flags: u16,
    /// The complete encoded message being bundled, header included. Its
    /// xid must equal the bundle-add message's own.
    pub message: Vec<u8>,
    /// Bundle properties, e.g. a scheduled commit time.
    pub properties: Vec<BundleProperty>,
}

impl BundleAddMessage {
    /// # Errors
    ///
    /// Returns an error if the encoded message length overflows a `u16`,
    /// or if the nested message's xid differs from this bundle-add's own
    /// xid. The spec requires them to be identical ("the xid of the
    /// bundle add message must be the same"), and OVS enforces it with
    /// `OFPBFC_MSG_BAD_XID`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.message.len() >= OFP_HEADER_LEN {
            let inner = Header::parse(&self.message)?;
            if inner.xid != self.xid {
                return Err(OfError::InvalidValue {
                    field: "bundle_add nested message xid",
                    value: u64::from(inner.xid),
                });
            }
        }
        let mut body = Vec::with_capacity(16 + self.message.len() + self.properties.len());
        body.extend_from_slice(&self.bundle_id.to_be_bytes());
        body.extend_from_slice(&[0u8; 2]);
        body.extend_from_slice(&self.flags.to_be_bytes());
        body.extend_from_slice(&self.message);
        let pad = (8 - (self.message.len() % 8)) % 8;
        body.extend_from_slice(&vec![0u8; pad]);
        body.extend_from_slice(&encode_typed_properties(
            &self.properties,
            BundleProperty::encode,
        )?);
        encode_message(OFPT_BUNDLE_ADD_MESSAGE, self.xid, &body)
    }

    pub(crate) fn parse(frame: &[u8]) -> Result<Self> {
        let (header, body) = body_from_frame(frame, OFPT_BUNDLE_ADD_MESSAGE, 24)?;
        ensure_zero_padding(body, 4, 6)?;
        let nested = Header::parse(body.get(8..).ok_or(OfError::ShortBuffer)?)?;
        let nested_len = nested.length as usize;
        let nested_pad = nested_len.div_ceil(8) * 8;
        if body.len() < 8 + nested_pad {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(body, 8 + nested_len, 8 + nested_pad)?;
        Ok(Self {
            xid: header.xid,
            bundle_id: read_u32(body, 0)?,
            flags: read_u16(body, 6)?,
            message: body
                .get(8..8 + nested_len)
                .ok_or(OfError::ShortBuffer)?
                .to_vec(),
            properties: parse_typed_properties(
                body.get(8 + nested_pad..).unwrap_or_default(),
                BundleProperty::parse,
            )?,
        })
    }
}

/// An `OFPT_TABLE_STATUS` (`ofp_table_status`, spec 7.4.5): a table's
/// vacancy crossed a configured threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableStatus {
    /// Transaction id chosen by the switch.
    pub xid: u32,
    /// The `OFPTR_*` reason: vacancy-down or vacancy-up.
    pub reason: u8,
    /// The `ofp_table_desc` for the table whose vacancy changed.
    pub table: TableDescEntry,
}

/// An `OFPT_CONTROLLER_STATUS` (`ofp_controller_status`, spec 7.4.6):
/// the state of a controller connection changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerStatus {
    /// Transaction id chosen by the switch.
    pub xid: u32,
    /// Length of the `ofp_controller_status` body, properties included.
    pub length: u16,
    /// Short id of the controller this status is about.
    pub short_id: u16,
    /// That controller's `OFPCR_ROLE_*` role.
    pub role: u32,
    /// The `OFPCSR_*` reason the status changed.
    pub reason: u8,
    /// `OFPCT_STATUS_UP` or `OFPCT_STATUS_DOWN`.
    pub channel_status: u8,
    /// Properties, of which the connection URI is mandatory.
    pub properties: Vec<ControllerStatusProperty>,
}

/// `ofp_flow_removed` (spec 7.4.2).
///
/// 1.5 moved the per-flow counters 1.3 carried inline here (duration,
/// packet and byte counts) into the trailing `ofp_stats` OXS list, so
/// they live in [`Self::stats`] as [`oxs::Tlv::Duration`],
/// [`oxs::Tlv::PacketCount`] and [`oxs::Tlv::ByteCount`] rather than as
/// their own fields.
/// An `OFPT_FLOW_REMOVED` (`ofp_flow_removed`, spec 7.4.2): a flow
/// entry was removed.
///
/// Only sent for entries installed with `OFPFF_SEND_FLOW_REM`. Note the
/// 1.5 shape -- duration and the packet/byte counters live in
/// [`Self::stats`], not in fixed fields as in 1.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRemoved {
    /// Transaction id chosen by the switch.
    pub xid: u32,
    /// The table the entry lived in.
    pub table_id: u8,
    /// The `OFPRR_*` reason: idle or hard timeout, delete, eviction, or
    /// the removal of a group or meter it referenced.
    pub reason: u8,
    /// The removed entry's priority.
    pub priority: u16,
    /// The entry's idle timeout, in seconds.
    pub idle_timeout: u16,
    /// The entry's hard timeout, in seconds.
    pub hard_timeout: u16,
    /// The entry's cookie.
    pub cookie: u64,
    /// The removed entry's raw `ofp_match` OXM bytes; decode with
    /// [`crate::protocol::oxm::parse_oxm_list`].
    pub of_match: Vec<u8>,
    /// Duration and the packet/byte counters, as an OXS list. In 1.3
    /// these were fixed fields; 1.5 moved them here.
    pub stats: Vec<oxs::Tlv>,
}

/// An `OFPT_PORT_STATUS` (`ofp_port_status`, spec 7.4.3): a port was
/// added, removed, or changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortStatus {
    /// Transaction id chosen by the switch.
    pub xid: u32,
    /// The `OFPPR_*` reason: add, delete or modify.
    pub reason: u8,
    /// The port's full description after the change.
    pub desc: PortDescEntry,
}

/// An `OFPT_ROLE_STATUS` (`ofp_role_status`, spec 7.4.4): the switch
/// changed this connection's role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleStatus {
    /// Transaction id chosen by the switch.
    pub xid: u32,
    /// This connection's new `OFPCR_ROLE_*` role.
    pub role: u32,
    /// The `OFPCRR_*` reason: another controller took master, a config
    /// change, or an experimenter reason.
    pub reason: u8,
    /// Generation id at the time of the change.
    pub generation_id: u64,
    /// Any role properties the switch attached.
    pub properties: Vec<Property>,
}

/// An `OFPT_REQUESTFORWARD` (`ofp_requestforward_header`, spec 7.4.7):
/// the switch forwards another controller's group- or meter-mod here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestForward {
    /// Transaction id chosen by the switch.
    pub xid: u32,
    /// The complete group- or meter-mod another controller sent, header
    /// included.
    pub request: Vec<u8>,
}

impl FlowRemoved {
    /// Encode this `ofp_flow_removed`. Switch-side counterpart of
    /// `parse_flow_removed`.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message length overflows a `u16`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.push(self.table_id);
        body.push(self.reason);
        body.extend_from_slice(&self.priority.to_be_bytes());
        body.extend_from_slice(&self.idle_timeout.to_be_bytes());
        body.extend_from_slice(&self.hard_timeout.to_be_bytes());
        body.extend_from_slice(&self.cookie.to_be_bytes());
        encode_embedded_match(&mut body, &self.of_match)?;
        encode_embedded_stats(&mut body, &self.stats)?;
        encode_message(OFPT_FLOW_REMOVED, self.xid, &body)
    }
}

impl PortStatus {
    /// Encode this `ofp_port_status`. Switch-side counterpart of
    /// `parse_port_status`.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message length overflows a `u16`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.push(self.reason);
        body.extend_from_slice(&[0u8; 7]);
        self.desc.encode(&mut body)?;
        encode_message(OFPT_PORT_STATUS, self.xid, &body)
    }
}

impl RoleStatus {
    /// Encode this `ofp_role_status`. Switch-side counterpart of
    /// `parse_role_status`.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message length overflows a `u16`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.role.to_be_bytes());
        body.push(self.reason);
        body.extend_from_slice(&[0u8; 3]);
        body.extend_from_slice(&self.generation_id.to_be_bytes());
        body.extend_from_slice(&encode_properties(&self.properties)?);
        encode_message(OFPT_ROLE_STATUS, self.xid, &body)
    }
}

impl RequestForward {
    /// Encode this `ofp_requestforward_header`, whose body is the
    /// forwarded request message verbatim. Switch-side counterpart of
    /// `parse_request_forward`.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message length overflows a `u16`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_message(OFPT_REQUESTFORWARD, self.xid, &self.request)
    }
}

impl ControllerStatus {
    /// Encode this `ofp_controller_status`. Switch-side counterpart of
    /// `parse_controller_status`.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message length overflows a `u16`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0u8; 2]); // length, back-filled below
        body.extend_from_slice(&self.short_id.to_be_bytes());
        body.extend_from_slice(&self.role.to_be_bytes());
        body.push(self.reason);
        body.push(self.channel_status);
        body.extend_from_slice(&[0u8; 6]);
        body.extend_from_slice(&encode_typed_properties(
            &self.properties,
            ControllerStatusProperty::encode,
        )?);
        let len = checked_u16_len(body.len())?;
        if let Some(dst) = body.get_mut(0..2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        encode_message(OFPT_CONTROLLER_STATUS, self.xid, &body)
    }
}

pub(crate) fn parse_flow_removed(frame: &[u8]) -> Result<FlowRemoved> {
    // ofp_flow_removed body: table_id(1)@0, reason(1)@1, priority(2)@2,
    // idle_timeout(2)@4, hard_timeout(2)@6, cookie(8)@8, match@16,
    // then ofp_stats. 24 body bytes + an 8-byte empty match = 32.
    let (header, body) = body_from_frame(frame, OFPT_FLOW_REMOVED, 32)?;
    let head: &[u8; 2] = body.first_chunk::<2>().ok_or(OfError::ShortBuffer)?;
    let reason = head[1];
    if !matches!(
        reason,
        OFPRR_IDLE_TIMEOUT
            | OFPRR_HARD_TIMEOUT
            | OFPRR_DELETE
            | OFPRR_GROUP_DELETE
            | OFPRR_METER_DELETE
            | OFPRR_EVICTION
    ) {
        return Err(OfError::InvalidValue {
            field: "flow_removed_reason",
            value: u64::from(reason),
        });
    }
    let (of_match, match_padded) = parse_embedded_match(body, 16)?;
    let (stats, stats_padded) = parse_embedded_stats(body, 16 + match_padded)?;
    if 16 + match_padded + stats_padded != body.len() {
        return Err(invalid_length(body.len()));
    }
    Ok(FlowRemoved {
        xid: header.xid,
        table_id: head[0],
        reason,
        priority: read_u16(body, 2)?,
        idle_timeout: read_u16(body, 4)?,
        hard_timeout: read_u16(body, 6)?,
        cookie: read_u64(body, 8)?,
        of_match,
        stats,
    })
}

pub(crate) fn parse_port_status(frame: &[u8]) -> Result<PortStatus> {
    let (header, body) = body_from_frame(frame, OFPT_PORT_STATUS, 56)?;
    let reason = *body.first().ok_or(OfError::ShortBuffer)?;
    if !matches!(reason, OFPPR_ADD | OFPPR_DELETE | OFPPR_MODIFY) {
        return Err(OfError::InvalidValue {
            field: "port_status_reason",
            value: u64::from(reason),
        });
    }
    ensure_zero_padding(body, 1, 8)?;
    Ok(PortStatus {
        xid: header.xid,
        reason,
        desc: PortDescEntry::parse(body.get(8..).unwrap_or_default())?,
    })
}

pub(crate) fn parse_role_status(frame: &[u8]) -> Result<RoleStatus> {
    let (header, body) = body_from_frame(frame, OFPT_ROLE_STATUS, 24)?;
    let role = read_u32(body, 0)?;
    validate_role(role)?;
    let reason = *body.get(4).ok_or(OfError::ShortBuffer)?;
    if !matches!(
        reason,
        OFPCRR_MASTER_REQUEST | OFPCRR_CONFIG | OFPCRR_EXPERIMENTER
    ) {
        return Err(OfError::InvalidValue {
            field: "role_status_reason",
            value: u64::from(reason),
        });
    }
    ensure_zero_padding(body, 5, 8)?;
    Ok(RoleStatus {
        xid: header.xid,
        role,
        reason,
        generation_id: read_u64(body, 8)?,
        properties: parse_properties(body.get(16..).ok_or(OfError::ShortBuffer)?, |_| Ok(()))?,
    })
}

pub(crate) fn parse_table_status(frame: &[u8]) -> Result<TableStatus> {
    let (header, body) = body_from_frame(frame, OFPT_TABLE_STATUS, 24)?;
    let reason = *body.first().ok_or(OfError::ShortBuffer)?;
    if !matches!(reason, OFPTR_VACANCY_DOWN | OFPTR_VACANCY_UP) {
        return Err(OfError::InvalidValue {
            field: "table_status_reason",
            value: u64::from(reason),
        });
    }
    ensure_zero_padding(body, 1, 8)?;
    Ok(TableStatus {
        xid: header.xid,
        reason,
        table: TableDescEntry::parse(body.get(8..).unwrap_or_default())?,
    })
}

pub(crate) fn parse_request_forward(frame: &[u8]) -> Result<RequestForward> {
    let (header, body) = body_from_frame(frame, OFPT_REQUESTFORWARD, 16)?;
    let request = Header::parse(body)?;
    let request_len = request.length as usize;
    if body.len() != request_len {
        return Err(OfError::ShortBuffer);
    }
    Ok(RequestForward {
        xid: header.xid,
        request: body
            .get(..request_len)
            .ok_or(OfError::ShortBuffer)?
            .to_vec(),
    })
}

pub(crate) fn parse_controller_status(frame: &[u8]) -> Result<ControllerStatus> {
    let (header, body) = body_from_frame(frame, OFPT_CONTROLLER_STATUS, 24)?;
    let length = usize::from(read_u16(body, 0)?);
    if length < 16 || length > body.len() {
        return Err(invalid_length(length));
    }
    let role = read_u32(body, 4)?;
    validate_role(role)?;
    let head: &[u8; 10] = body.first_chunk::<10>().ok_or(OfError::ShortBuffer)?;
    let reason = head[8];
    let channel_status = head[9];
    if !matches!(
        reason,
        OFPCSR_REQUEST
            | OFPCSR_CHANNEL_STATUS
            | OFPCSR_ROLE
            | OFPCSR_CONTROLLER_ADDED
            | OFPCSR_CONTROLLER_REMOVED
            | OFPCSR_SHORT_ID
            | OFPCSR_EXPERIMENTER
    ) {
        return Err(OfError::InvalidValue {
            field: "controller_status_reason",
            value: u64::from(reason),
        });
    }
    if !matches!(channel_status, OFPCT_STATUS_UP | OFPCT_STATUS_DOWN) {
        return Err(OfError::InvalidValue {
            field: "controller_channel_status",
            value: u64::from(channel_status),
        });
    }
    ensure_zero_padding(body, 10, 16)?;
    Ok(ControllerStatus {
        xid: header.xid,
        length: checked_u16_len(length)?,
        short_id: read_u16(body, 2)?,
        role,
        reason,
        channel_status,
        properties: parse_typed_properties(
            body.get(16..length).ok_or(OfError::ShortBuffer)?,
            ControllerStatusProperty::parse,
        )?,
    })
}

pub(crate) fn encode_get_async_request(xid: u32) -> Result<Vec<u8>> {
    AsyncConfig::encode_get_request(xid)
}

pub(crate) fn encode_get_async_reply(xid: u32, properties: &[u8]) -> Result<Vec<u8>> {
    encode_message(OFPT_GET_ASYNC_REPLY, xid, properties)
}

pub(crate) fn encode_set_async(xid: u32, properties: &[Property]) -> Result<Vec<u8>> {
    AsyncConfig {
        xid,
        properties: properties.to_vec(),
    }
    .encode_set()
}

pub(crate) fn encode_get_async_reply_properties(
    xid: u32,
    properties: &[Property],
) -> Result<Vec<u8>> {
    AsyncConfig {
        xid,
        properties: properties.to_vec(),
    }
    .encode_get_reply()
}

pub(crate) fn encode_role_request(
    xid: u32,
    role: u32,
    short_id: u16,
    generation_id: u64,
) -> Result<Vec<u8>> {
    RoleRequest {
        xid,
        role,
        short_id,
        generation_id,
    }
    .encode_request()
}

pub(crate) fn encode_role_reply(
    xid: u32,
    role: u32,
    short_id: u16,
    generation_id: u64,
) -> Result<Vec<u8>> {
    RoleRequest {
        xid,
        role,
        short_id,
        generation_id,
    }
    .encode_reply()
}

pub(crate) fn encode_multipart_request(
    xid: u32,
    kind: u16,
    flags: u16,
    body: &[u8],
) -> Result<Vec<u8>> {
    MultipartMessage::request(xid, kind, flags, body.to_vec()).encode_request()
}

pub(crate) fn encode_multipart_reply(
    xid: u32,
    kind: u16,
    flags: u16,
    body: &[u8],
) -> Result<Vec<u8>> {
    MultipartMessage::reply(xid, kind, flags, body.to_vec()).encode_reply()
}

pub(crate) fn encode_table_mod(
    xid: u32,
    table_id: u8,
    config: u32,
    properties: &[TableModProperty],
) -> Result<Vec<u8>> {
    TableMod {
        xid,
        table_id,
        config,
        properties: properties.to_vec(),
    }
    .encode()
}

pub(crate) fn encode_port_mod(
    xid: u32,
    port_no: u32,
    hw_addr: [u8; 6],
    config: u32,
    mask: u32,
    properties: &[PortModProperty],
) -> Result<Vec<u8>> {
    PortMod {
        xid,
        port_no,
        hw_addr,
        config,
        mask,
        properties: properties.to_vec(),
    }
    .encode()
}

pub(crate) fn encode_meter_mod(
    xid: u32,
    command: u16,
    flags: u16,
    meter_id: u32,
    bands: &[MeterBand],
) -> Result<Vec<u8>> {
    MeterMod {
        xid,
        command,
        flags,
        meter_id,
        bands: bands.to_vec(),
    }
    .encode()
}

pub(crate) fn encode_bundle_add_message(
    xid: u32,
    bundle_id: u32,
    flags: u16,
    message: &[u8],
    properties: &[BundleProperty],
) -> Result<Vec<u8>> {
    BundleAddMessage {
        xid,
        bundle_id,
        flags,
        message: message.to_vec(),
        properties: properties.to_vec(),
    }
    .encode()
}

impl TableStatus {
    /// # Errors
    ///
    /// Returns an error if the encoded message length overflows a `u16`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.push(self.reason);
        body.extend_from_slice(&[0u8; 7]);
        self.table.encode(&mut body)?;
        encode_message(OFPT_TABLE_STATUS, self.xid, &body)
    }
}

pub(crate) fn encode_table_status(status: &TableStatus) -> Result<Vec<u8>> {
    status.encode()
}

pub(crate) fn encode_controller_status(status: &ControllerStatus) -> Result<Vec<u8>> {
    status.encode()
}

/// Encode an `ofp_experimenter_msg` (spec 7.5.4).
///
/// # Errors
///
/// Returns an error if the encoded message length overflows a `u16`.
pub fn encode_experimenter(
    xid: u32,
    experimenter: u32,
    exp_type: u32,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(8 + data.len());
    body.extend_from_slice(&experimenter.to_be_bytes());
    body.extend_from_slice(&exp_type.to_be_bytes());
    body.extend_from_slice(data);
    encode_message(OFPT_EXPERIMENTER, xid, &body)
}

pub(crate) fn parse_multipart_request(frame: &[u8]) -> Result<MultipartMessage> {
    MultipartMessage::parse(frame, OFPT_MULTIPART_REQUEST)
}

pub(crate) fn parse_multipart_reply(frame: &[u8]) -> Result<MultipartMessage> {
    MultipartMessage::parse(frame, OFPT_MULTIPART_REPLY)
}

pub(crate) fn parse_role_request(frame: &[u8]) -> Result<RoleRequest> {
    RoleRequest::parse(frame, OFPT_ROLE_REQUEST)
}

pub(crate) fn parse_role_reply(frame: &[u8]) -> Result<RoleRequest> {
    RoleRequest::parse(frame, OFPT_ROLE_REPLY)
}

pub(crate) fn parse_async_config_get_reply(frame: &[u8]) -> Result<AsyncConfig> {
    AsyncConfig::parse(frame, OFPT_GET_ASYNC_REPLY)
}

pub(crate) fn parse_async_config_set(frame: &[u8]) -> Result<AsyncConfig> {
    AsyncConfig::parse(frame, OFPT_SET_ASYNC)
}

pub(crate) fn parse_table_mod(frame: &[u8]) -> Result<TableMod> {
    TableMod::parse(frame)
}

pub(crate) fn parse_port_mod(frame: &[u8]) -> Result<PortMod> {
    PortMod::parse(frame)
}

pub(crate) fn parse_group_mod(frame: &[u8]) -> Result<GroupMod> {
    GroupMod::parse(frame)
}

pub(crate) fn parse_meter_mod(frame: &[u8]) -> Result<MeterMod> {
    MeterMod::parse(frame)
}

pub(crate) fn parse_bundle_message(frame: &[u8]) -> Result<BundleMessage> {
    BundleMessage::parse(frame)
}

pub(crate) fn parse_bundle_add_message(frame: &[u8]) -> Result<BundleAddMessage> {
    BundleAddMessage::parse(frame)
}

pub(crate) fn parse_async_flow_removed(frame: &[u8]) -> Result<FlowRemoved> {
    parse_flow_removed(frame)
}

pub(crate) fn parse_async_port_status(frame: &[u8]) -> Result<PortStatus> {
    parse_port_status(frame)
}

pub(crate) fn parse_async_role_status(frame: &[u8]) -> Result<RoleStatus> {
    parse_role_status(frame)
}

pub(crate) fn parse_async_table_status(frame: &[u8]) -> Result<TableStatus> {
    parse_table_status(frame)
}

pub(crate) fn parse_async_request_forward(frame: &[u8]) -> Result<RequestForward> {
    parse_request_forward(frame)
}

pub(crate) fn parse_async_controller_status(frame: &[u8]) -> Result<ControllerStatus> {
    parse_controller_status(frame)
}

fn write_fixed_str(out: &mut Vec<u8>, value: &str, len: usize) {
    let bytes = value.as_bytes();
    let take = bytes.len().min(len.saturating_sub(1));
    out.extend_from_slice(bytes.get(..take).unwrap_or_default());
    out.resize(out.len() + (len - take), 0);
}

fn read_fixed_str(buf: &[u8], offset: usize, len: usize) -> Result<String> {
    let raw = buf.get(offset..offset + len).ok_or(OfError::ShortBuffer)?;
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    let text = raw.get(..end).unwrap_or_default();
    Ok(String::from_utf8_lossy(text).into_owned())
}

fn parse_embedded_match(body: &[u8], offset: usize) -> Result<(Vec<u8>, usize)> {
    let match_len = usize::from(read_u16(body, offset + 2)?);
    if match_len < 4 {
        return Err(invalid_length(match_len));
    }
    let match_padded = padded_len(match_len);
    if body.len() < offset + match_padded {
        return Err(OfError::ShortBuffer);
    }
    ensure_zero_padding(body, offset + match_len, offset + match_padded)?;
    let oxm_bytes = body
        .get(offset + 4..offset + match_len)
        .ok_or(OfError::ShortBuffer)?
        .to_vec();
    crate::protocol::oxm::parse_oxm_list(&oxm_bytes)?;
    Ok((oxm_bytes, match_padded))
}

fn encode_embedded_match(out: &mut Vec<u8>, oxm_bytes: &[u8]) -> Result<()> {
    crate::protocol::ofmatch::Match::new(vec![oxm_bytes.to_vec()]).encode(out)
}

fn parse_embedded_stats(body: &[u8], offset: usize) -> Result<(Vec<oxs::Tlv>, usize)> {
    oxs::parse_stats(body, offset)
}

fn encode_embedded_stats(out: &mut Vec<u8>, stats: &[oxs::Tlv]) -> Result<()> {
    oxs::encode_stats(out, stats)
}

const DESC_STR_LEN: usize = 256;
const SERIAL_NUM_LEN: usize = 32;
const OFP_MAX_TABLE_NAME_LEN: usize = 32;
const OFP_MAX_PORT_NAME_LEN: usize = 16;
const OFP_ETH_ALEN: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Body of the reply to an `OFPMP_DESC` request (`ofp_desc`): the
/// switch's self-description, all fixed-length NUL-padded strings.
pub struct Desc {
    /// Manufacturer description.
    pub mfr_desc: String,
    /// Hardware description.
    pub hw_desc: String,
    /// Software description.
    pub sw_desc: String,
    /// Serial number.
    pub serial_num: String,
    /// Human-readable datapath description.
    pub dp_desc: String,
}

impl Desc {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1056);
        write_fixed_str(&mut out, &self.mfr_desc, DESC_STR_LEN);
        write_fixed_str(&mut out, &self.hw_desc, DESC_STR_LEN);
        write_fixed_str(&mut out, &self.sw_desc, DESC_STR_LEN);
        write_fixed_str(&mut out, &self.serial_num, SERIAL_NUM_LEN);
        write_fixed_str(&mut out, &self.dp_desc, DESC_STR_LEN);
        out
    }

    fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < 1056 {
            return Err(OfError::ShortBuffer);
        }
        Ok(Self {
            mfr_desc: read_fixed_str(body, 0, DESC_STR_LEN)?,
            hw_desc: read_fixed_str(body, DESC_STR_LEN, DESC_STR_LEN)?,
            sw_desc: read_fixed_str(body, DESC_STR_LEN * 2, DESC_STR_LEN)?,
            serial_num: read_fixed_str(body, DESC_STR_LEN * 3, SERIAL_NUM_LEN)?,
            dp_desc: read_fixed_str(body, DESC_STR_LEN * 3 + SERIAL_NUM_LEN, DESC_STR_LEN)?,
        })
    }
}

/// Shared shape of `ofp_flow_stats_request` / `ofp_aggregate_stats_request`,
/// used as the request body for `OFPMP_FLOW_DESC`, `OFPMP_FLOW_STATS`, and
/// `OFPMP_AGGREGATE_STATS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStatsRequest {
    /// Table to query, or `OFPTT_ALL` for every table.
    pub table_id: u8,
    /// Only report entries with this output port; `OFPP_ANY` for all.
    pub out_port: u32,
    /// Only report entries with this output group; `OFPG_ANY` for all.
    pub out_group: u32,
    /// Cookie to match against, subject to `cookie_mask`.
    pub cookie: u64,
    /// Which `cookie` bits must match. Zero matches every entry.
    pub cookie_mask: u64,
    /// Raw `ofp_match` OXM bytes selecting the entries to report; empty
    /// matches all of them.
    pub of_match: Vec<u8>,
}

impl FlowStatsRequest {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(40);
        out.push(self.table_id);
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&self.out_port.to_be_bytes());
        out.extend_from_slice(&self.out_group.to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&self.cookie.to_be_bytes());
        out.extend_from_slice(&self.cookie_mask.to_be_bytes());
        encode_embedded_match(&mut out, &self.of_match)?;
        Ok(out)
    }

    fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < 40 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(body, 1, 4)?;
        ensure_zero_padding(body, 12, 16)?;
        let head: &[u8; 1] = body.first_chunk::<1>().ok_or(OfError::ShortBuffer)?;
        let (of_match, _) = parse_embedded_match(body, 32)?;
        Ok(Self {
            table_id: head[0],
            out_port: read_u32(body, 4)?,
            out_group: read_u32(body, 8)?,
            cookie: read_u64(body, 16)?,
            cookie_mask: read_u64(body, 24)?,
            of_match,
        })
    }
}

/// Body of the reply to an `OFPMP_FLOW_DESC` request: `ofp_flow_desc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDesc {
    /// The table this entry lives in.
    pub table_id: u8,
    /// The entry's priority.
    pub priority: u16,
    /// Idle timeout in seconds; 0 is permanent.
    pub idle_timeout: u16,
    /// Hard timeout in seconds; 0 is permanent.
    pub hard_timeout: u16,
    /// Bitmap of `OFPFF_*` the entry was installed with.
    pub flags: u16,
    /// Eviction importance.
    pub importance: u16,
    /// The entry's cookie.
    pub cookie: u64,
    /// Raw `ofp_match` OXM bytes; decode with
    /// [`crate::protocol::oxm::parse_oxm_list`].
    pub of_match: Vec<u8>,
    /// Duration and counters, as an OXS list.
    pub stats: Vec<oxs::Tlv>,
    /// The entry's instructions.
    pub instructions: Vec<Instruction>,
}

impl FlowDesc {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&[0u8; 2]);
        out.push(self.table_id);
        out.push(0);
        out.extend_from_slice(&self.priority.to_be_bytes());
        out.extend_from_slice(&self.idle_timeout.to_be_bytes());
        out.extend_from_slice(&self.hard_timeout.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.importance.to_be_bytes());
        out.extend_from_slice(&self.cookie.to_be_bytes());
        encode_embedded_match(out, &self.of_match)?;
        encode_embedded_stats(out, &self.stats)?;
        for instruction in &self.instructions {
            instruction.encode(out)?;
        }
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start..start + 2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 24 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(raw, 2, 4)?;
        ensure_zero_padding(raw, 5, 6)?;
        let head: &[u8; 5] = raw.first_chunk::<5>().ok_or(OfError::ShortBuffer)?;
        let (of_match, match_padded) = parse_embedded_match(raw, 24)?;
        let stats_offset = 24 + match_padded;
        let (stats, stats_padded) = parse_embedded_stats(raw, stats_offset)?;
        Ok(Self {
            table_id: head[4],
            priority: read_u16(raw, 6)?,
            idle_timeout: read_u16(raw, 8)?,
            hard_timeout: read_u16(raw, 10)?,
            flags: read_u16(raw, 12)?,
            importance: read_u16(raw, 14)?,
            cookie: read_u64(raw, 16)?,
            of_match,
            stats,
            instructions: parse_instructions(
                raw.get(stats_offset + stats_padded..)
                    .ok_or(OfError::ShortBuffer)?,
            )?,
        })
    }
}

/// Body of the reply to an `OFPMP_FLOW_STATS` request: `ofp_flow_stats`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStatsEntry {
    /// The table this entry lives in.
    pub table_id: u8,
    /// The `OFPFSR_*` reason this entry is being reported.
    pub reason: u8,
    /// The entry's priority.
    pub priority: u16,
    /// Raw `ofp_match` OXM bytes.
    pub of_match: Vec<u8>,
    /// Duration and counters, as an OXS list.
    pub stats: Vec<oxs::Tlv>,
}

impl FlowStatsEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&[0u8; 2]);
        out.push(self.table_id);
        out.push(self.reason);
        out.extend_from_slice(&self.priority.to_be_bytes());
        encode_embedded_match(out, &self.of_match)?;
        encode_embedded_stats(out, &self.stats)?;
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start..start + 2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 8 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(raw, 2, 4)?;
        let head: &[u8; 6] = raw.first_chunk::<6>().ok_or(OfError::ShortBuffer)?;
        let (of_match, match_padded) = parse_embedded_match(raw, 8)?;
        let (stats, stats_padded) = parse_embedded_stats(raw, 8 + match_padded)?;
        if 8 + match_padded + stats_padded != raw.len() {
            return Err(invalid_length(raw.len()));
        }
        Ok(Self {
            table_id: head[4],
            reason: head[5],
            priority: read_u16(raw, 6)?,
            of_match,
            stats,
        })
    }
}

fn parse_length_prefixed_entries<T>(
    body: &[u8],
    min_len: usize,
    parse_one: impl Fn(&[u8]) -> Result<T>,
) -> Result<Vec<T>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        if body.len() - offset < min_len {
            return Err(OfError::ShortBuffer);
        }
        let len = usize::from(read_u16(body, offset)?);
        if len < min_len || !len.is_multiple_of(8) {
            return Err(invalid_length(len));
        }
        if offset + len > body.len() {
            return Err(OfError::ShortBuffer);
        }
        let raw = body.get(offset..offset + len).ok_or(OfError::ShortBuffer)?;
        entries.push(parse_one(raw)?);
        offset += len;
    }
    Ok(entries)
}

/// Body of the (single-struct) reply to an `OFPMP_AGGREGATE_STATS`
/// request: a bare `ofp_stats`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateStatsReply {
    /// The aggregated counters, as an OXS list -- packet count, byte
    /// count and flow count.
    pub stats: Vec<oxs::Tlv>,
}

/// Body for `ofp_multipart_request` of types `OFPMP_PORT_STATS` and
/// `OFPMP_PORT_DESC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMultipartRequest {
    /// Port to report on, or `OFPP_ANY` for every port.
    pub port_no: u32,
}

impl PortMultipartRequest {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.port_no.to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out
    }

    fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < 8 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(body, 4, 8)?;
        Ok(Self {
            port_no: read_u32(body, 0)?,
        })
    }
}

/// Body for `ofp_multipart_request` of types `OFPMP_QUEUE_STATS` and
/// `OFPMP_QUEUE_DESC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueMultipartRequest {
    /// Port to report on, or `OFPP_ANY` for every port.
    pub port_no: u32,
    /// Queue to report on, or `OFPQ_ALL` for every queue.
    pub queue_id: u32,
}

impl QueueMultipartRequest {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.port_no.to_be_bytes());
        out.extend_from_slice(&self.queue_id.to_be_bytes());
        out
    }

    fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < 8 {
            return Err(OfError::ShortBuffer);
        }
        Ok(Self {
            port_no: read_u32(body, 0)?,
            queue_id: read_u32(body, 4)?,
        })
    }
}

/// Body for `ofp_multipart_request` of types `OFPMP_GROUP_STATS` and
/// `OFPMP_GROUP_DESC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMultipartRequest {
    /// Group to report on, or `OFPG_ALL` for every group.
    pub group_id: u32,
}

impl GroupMultipartRequest {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.group_id.to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out
    }

    fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < 8 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(body, 4, 8)?;
        Ok(Self {
            group_id: read_u32(body, 0)?,
        })
    }
}

/// Body for `ofp_multipart_request` of types `OFPMP_METER_STATS` and
/// `OFPMP_METER_DESC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterMultipartRequest {
    /// Meter to report on, or `OFPM_ALL` for every meter.
    pub meter_id: u32,
}

impl MeterMultipartRequest {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.meter_id.to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out
    }

    fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < 8 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(body, 4, 8)?;
        Ok(Self {
            meter_id: read_u32(body, 0)?,
        })
    }
}

/// Body of reply to `OFPMP_TABLE_STATS` request: a fixed-size (24-byte)
/// `ofp_table_stats` entry, repeated once per table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableStatsEntry {
    /// The table these counters belong to.
    pub table_id: u8,
    /// Flow entries currently installed in it.
    pub active_count: u32,
    /// Packets looked up in this table.
    pub lookup_count: u64,
    /// Packets that matched an entry here.
    pub matched_count: u64,
}

impl TableStatsEntry {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.table_id);
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&self.active_count.to_be_bytes());
        out.extend_from_slice(&self.lookup_count.to_be_bytes());
        out.extend_from_slice(&self.matched_count.to_be_bytes());
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        ensure_zero_padding(raw, 1, 4)?;
        let head: &[u8; 1] = raw.first_chunk::<1>().ok_or(OfError::ShortBuffer)?;
        Ok(Self {
            table_id: head[0],
            active_count: read_u32(raw, 4)?,
            lookup_count: read_u64(raw, 8)?,
            matched_count: read_u64(raw, 16)?,
        })
    }
}

fn parse_fixed_entries<T>(
    body: &[u8],
    entry_len: usize,
    parse_one: impl Fn(&[u8]) -> Result<T>,
) -> Result<Vec<T>> {
    if !body.len().is_multiple_of(entry_len) {
        return Err(invalid_length(body.len()));
    }
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        let raw = body
            .get(offset..offset + entry_len)
            .ok_or(OfError::ShortBuffer)?;
        entries.push(parse_one(raw)?);
        offset += entry_len;
    }
    Ok(entries)
}

/// Body of reply to `OFPMP_PORT_STATS` request: `ofp_port_stats`, including the trailing
/// `PortStatsProperty` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortStatsEntry {
    /// The port these counters belong to.
    pub port_no: u32,
    /// Whole seconds this port has been up.
    pub duration_sec: u32,
    /// Nanoseconds beyond `duration_sec`.
    pub duration_nsec: u32,
    /// Packets received.
    pub rx_packets: u64,
    /// Packets transmitted.
    pub tx_packets: u64,
    /// Bytes received.
    pub rx_bytes: u64,
    /// Bytes transmitted.
    pub tx_bytes: u64,
    /// Packets dropped on receive.
    pub rx_dropped: u64,
    /// Packets dropped on transmit.
    pub tx_dropped: u64,
    /// Receive errors, of which the Ethernet property breaks out the
    /// specific kinds.
    pub rx_errors: u64,
    /// Transmit errors.
    pub tx_errors: u64,
    /// Ethernet and optical per-port statistics.
    pub properties: Vec<PortStatsProperty>,
}

impl PortStatsEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&self.port_no.to_be_bytes());
        out.extend_from_slice(&self.duration_sec.to_be_bytes());
        out.extend_from_slice(&self.duration_nsec.to_be_bytes());
        for value in [
            self.rx_packets,
            self.tx_packets,
            self.rx_bytes,
            self.tx_bytes,
            self.rx_dropped,
            self.tx_dropped,
            self.rx_errors,
            self.tx_errors,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out.extend_from_slice(&encode_typed_properties(
            &self.properties,
            PortStatsProperty::encode,
        )?);
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start..start + 2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 80 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(raw, 2, 4)?;
        Ok(Self {
            port_no: read_u32(raw, 4)?,
            duration_sec: read_u32(raw, 8)?,
            duration_nsec: read_u32(raw, 12)?,
            rx_packets: read_u64(raw, 16)?,
            tx_packets: read_u64(raw, 24)?,
            rx_bytes: read_u64(raw, 32)?,
            tx_bytes: read_u64(raw, 40)?,
            rx_dropped: read_u64(raw, 48)?,
            tx_dropped: read_u64(raw, 56)?,
            rx_errors: read_u64(raw, 64)?,
            tx_errors: read_u64(raw, 72)?,
            properties: parse_typed_properties(
                raw.get(80..).unwrap_or_default(),
                PortStatsProperty::parse,
            )?,
        })
    }
}

/// Body of reply to `OFPMP_QUEUE_STATS` request: `ofp_queue_stats`. The
/// trailing queue-statistics properties are kept raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueStatsEntry {
    /// The port this queue belongs to.
    pub port_no: u32,
    /// The queue these counters belong to.
    pub queue_id: u32,
    /// Bytes transmitted from this queue.
    pub tx_bytes: u64,
    /// Packets transmitted from this queue.
    pub tx_packets: u64,
    /// Packets dropped for queue overrun.
    pub tx_errors: u64,
    /// Whole seconds this queue has been installed.
    pub duration_sec: u32,
    /// Nanoseconds beyond `duration_sec`.
    pub duration_nsec: u32,
    /// Queue-specific statistics properties.
    pub properties: Vec<QueueStatsProperty>,
}

impl QueueStatsEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&[0u8; 6]);
        out.extend_from_slice(&self.port_no.to_be_bytes());
        out.extend_from_slice(&self.queue_id.to_be_bytes());
        out.extend_from_slice(&self.tx_bytes.to_be_bytes());
        out.extend_from_slice(&self.tx_packets.to_be_bytes());
        out.extend_from_slice(&self.tx_errors.to_be_bytes());
        out.extend_from_slice(&self.duration_sec.to_be_bytes());
        out.extend_from_slice(&self.duration_nsec.to_be_bytes());
        out.extend_from_slice(&encode_typed_properties(
            &self.properties,
            QueueStatsProperty::encode,
        )?);
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start..start + 2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 48 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(raw, 2, 8)?;
        Ok(Self {
            port_no: read_u32(raw, 8)?,
            queue_id: read_u32(raw, 12)?,
            tx_bytes: read_u64(raw, 16)?,
            tx_packets: read_u64(raw, 24)?,
            tx_errors: read_u64(raw, 32)?,
            duration_sec: read_u32(raw, 40)?,
            duration_nsec: read_u32(raw, 44)?,
            properties: parse_typed_properties(
                raw.get(48..).unwrap_or_default(),
                QueueStatsProperty::parse,
            )?,
        })
    }
}

/// One bucket's counters inside an `OFPMP_GROUP_STATS` reply
/// (`ofp_bucket_counter`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketCounter {
    /// Packets processed by this bucket.
    pub packet_count: u64,
    /// Bytes processed by this bucket.
    pub byte_count: u64,
}

fn parse_bucket_counters(body: &[u8]) -> Result<Vec<BucketCounter>> {
    parse_fixed_entries(body, 16, |raw| {
        Ok(BucketCounter {
            packet_count: read_u64(raw, 0)?,
            byte_count: read_u64(raw, 8)?,
        })
    })
}

/// Body of reply to `OFPMP_GROUP_STATS` request: `ofp_group_stats`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupStatsEntry {
    /// The group these counters belong to.
    pub group_id: u32,
    /// How many flow entries or groups reference this group.
    pub ref_count: u32,
    /// Packets processed by the group.
    pub packet_count: u64,
    /// Bytes processed by the group.
    pub byte_count: u64,
    /// Whole seconds the group has been installed.
    pub duration_sec: u32,
    /// Nanoseconds beyond `duration_sec`.
    pub duration_nsec: u32,
    /// Per-bucket counters, in bucket order.
    pub bucket_stats: Vec<BucketCounter>,
}

impl GroupStatsEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&self.group_id.to_be_bytes());
        out.extend_from_slice(&self.ref_count.to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&self.packet_count.to_be_bytes());
        out.extend_from_slice(&self.byte_count.to_be_bytes());
        out.extend_from_slice(&self.duration_sec.to_be_bytes());
        out.extend_from_slice(&self.duration_nsec.to_be_bytes());
        for counter in &self.bucket_stats {
            out.extend_from_slice(&counter.packet_count.to_be_bytes());
            out.extend_from_slice(&counter.byte_count.to_be_bytes());
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start..start + 2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 40 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(raw, 2, 4)?;
        ensure_zero_padding(raw, 12, 16)?;
        Ok(Self {
            group_id: read_u32(raw, 4)?,
            ref_count: read_u32(raw, 8)?,
            packet_count: read_u64(raw, 16)?,
            byte_count: read_u64(raw, 24)?,
            duration_sec: read_u32(raw, 32)?,
            duration_nsec: read_u32(raw, 36)?,
            bucket_stats: parse_bucket_counters(raw.get(40..).unwrap_or_default())?,
        })
    }
}

/// Body of reply to `OFPMP_GROUP_DESC` request: `ofp_group_desc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupDescEntry {
    /// The `OFPGT_*` group type.
    pub group_type: u8,
    /// The group's id.
    pub group_id: u32,
    /// Its buckets, in order.
    pub buckets: Vec<Bucket>,
    /// Group-level properties.
    pub properties: Vec<GroupProperty>,
}

impl GroupDescEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&[0u8; 2]);
        out.push(self.group_type);
        out.push(0);
        out.extend_from_slice(&self.group_id.to_be_bytes());
        let mut buckets_buf = Vec::new();
        for bucket in &self.buckets {
            bucket.encode(&mut buckets_buf)?;
        }
        let bucket_array_len = checked_u16_len(buckets_buf.len())?;
        out.extend_from_slice(&bucket_array_len.to_be_bytes());
        out.extend_from_slice(&[0u8; 6]);
        out.extend_from_slice(&buckets_buf);
        for property in &self.properties {
            property.encode(out)?;
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start..start + 2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 16 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(raw, 3, 4)?;
        ensure_zero_padding(raw, 10, 16)?;
        let bucket_array_len = usize::from(read_u16(raw, 8)?);
        if 16 + bucket_array_len > raw.len() {
            return Err(OfError::ShortBuffer);
        }
        let buckets = parse_buckets(
            raw.get(16..16 + bucket_array_len)
                .ok_or(OfError::ShortBuffer)?,
        )?;
        let properties =
            parse_group_properties(raw.get(16 + bucket_array_len..).unwrap_or_default())?;
        let head: &[u8; 3] = raw.first_chunk::<3>().ok_or(OfError::ShortBuffer)?;
        Ok(Self {
            group_type: head[2],
            group_id: read_u32(raw, 4)?,
            buckets,
            properties,
        })
    }
}

/// Body of reply to `OFPMP_GROUP_FEATURES` request: `ofp_group_features`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupFeatures {
    /// Bitmap of the `OFPGT_*` group types supported.
    pub types: u32,
    /// Bitmap of `OFPGFC_*` capabilities.
    pub capabilities: u32,
    /// Maximum number of groups of each `OFPGT_*` type, indexed by type.
    pub max_groups: [u32; 4],
    /// Bitmap of `OFPAT_*` actions supported by each group type, indexed
    /// by type.
    pub actions: [u32; 4],
}

impl GroupFeatures {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(&self.types.to_be_bytes());
        out.extend_from_slice(&self.capabilities.to_be_bytes());
        for value in self.max_groups {
            out.extend_from_slice(&value.to_be_bytes());
        }
        for value in self.actions {
            out.extend_from_slice(&value.to_be_bytes());
        }
        out
    }

    fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < 40 {
            return Err(OfError::ShortBuffer);
        }
        let mut max_groups = [0u32; 4];
        let mut actions = [0u32; 4];
        for (i, slot) in max_groups.iter_mut().enumerate() {
            *slot = read_u32(body, 8 + i * 4)?;
        }
        for (i, slot) in actions.iter_mut().enumerate() {
            *slot = read_u32(body, 24 + i * 4)?;
        }
        Ok(Self {
            types: read_u32(body, 0)?,
            capabilities: read_u32(body, 4)?,
            max_groups,
            actions,
        })
    }
}

/// One band's counters inside an `OFPMP_METER_STATS` reply
/// (`ofp_meter_band_stats`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterBandStats {
    /// Packets this band acted on.
    pub packet_band_count: u64,
    /// Bytes this band acted on.
    pub byte_band_count: u64,
}

fn parse_meter_band_stats(body: &[u8]) -> Result<Vec<MeterBandStats>> {
    parse_fixed_entries(body, 16, |raw| {
        Ok(MeterBandStats {
            packet_band_count: read_u64(raw, 0)?,
            byte_band_count: read_u64(raw, 8)?,
        })
    })
}

/// Body of reply to `OFPMP_METER_STATS` request: `ofp_meter_stats`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterStatsEntry {
    /// The meter these counters belong to.
    pub meter_id: u32,
    /// How many flow entries reference this meter.
    pub ref_count: u32,
    /// Packets metered.
    pub packet_in_count: u64,
    /// Bytes metered.
    pub byte_in_count: u64,
    /// Whole seconds the meter has been installed.
    pub duration_sec: u32,
    /// Nanoseconds beyond `duration_sec`.
    pub duration_nsec: u32,
    /// Per-band counters, in band order.
    pub band_stats: Vec<MeterBandStats>,
}

impl MeterStatsEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&self.meter_id.to_be_bytes());
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&[0u8; 6]);
        out.extend_from_slice(&self.ref_count.to_be_bytes());
        out.extend_from_slice(&self.packet_in_count.to_be_bytes());
        out.extend_from_slice(&self.byte_in_count.to_be_bytes());
        out.extend_from_slice(&self.duration_sec.to_be_bytes());
        out.extend_from_slice(&self.duration_nsec.to_be_bytes());
        for band in &self.band_stats {
            out.extend_from_slice(&band.packet_band_count.to_be_bytes());
            out.extend_from_slice(&band.byte_band_count.to_be_bytes());
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start + 4..start + 6) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 40 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(raw, 6, 12)?;
        Ok(Self {
            meter_id: read_u32(raw, 0)?,
            ref_count: read_u32(raw, 12)?,
            packet_in_count: read_u64(raw, 16)?,
            byte_in_count: read_u64(raw, 24)?,
            duration_sec: read_u32(raw, 32)?,
            duration_nsec: read_u32(raw, 36)?,
            band_stats: parse_meter_band_stats(raw.get(40..).unwrap_or_default())?,
        })
    }
}

fn parse_meter_stats_entries(body: &[u8]) -> Result<Vec<MeterStatsEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        if body.len() - offset < 6 {
            return Err(OfError::ShortBuffer);
        }
        let len = usize::from(read_u16(body, offset + 4)?);
        if len < 40 || !len.is_multiple_of(8) {
            return Err(invalid_length(len));
        }
        if offset + len > body.len() {
            return Err(OfError::ShortBuffer);
        }
        let raw = body.get(offset..offset + len).ok_or(OfError::ShortBuffer)?;
        entries.push(MeterStatsEntry::parse(raw)?);
        offset += len;
    }
    Ok(entries)
}

/// Body of reply to `OFPMP_METER_DESC` request: `ofp_meter_desc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterDescEntry {
    /// Bitmap of `OFPMF_*` the meter was created with.
    pub flags: u16,
    /// The meter's id.
    pub meter_id: u32,
    /// Its bands, in order.
    pub bands: Vec<MeterBand>,
}

impl MeterDescEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.meter_id.to_be_bytes());
        for band in &self.bands {
            band.encode(out)?;
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start..start + 2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 8 {
            return Err(OfError::ShortBuffer);
        }
        Ok(Self {
            flags: read_u16(raw, 2)?,
            meter_id: read_u32(raw, 4)?,
            bands: parse_meter_bands(raw.get(8..).unwrap_or_default())?,
        })
    }
}

/// Body of reply to `OFPMP_METER_FEATURES` request: `ofp_meter_features`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterFeatures {
    /// Maximum number of meters the switch supports.
    pub max_meter: u32,
    /// Bitmap of the `OFPMBT_*` band types supported.
    pub band_types: u32,
    /// Bitmap of `OFPMF_*` flags supported.
    pub capabilities: u32,
    /// Maximum bands per meter.
    pub max_bands: u8,
    /// Maximum colour value supported.
    pub max_color: u8,
    /// Bitmap of `OFPMFF_*` meter features (1.5).
    pub features: u32,
}

impl MeterFeatures {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        out.extend_from_slice(&self.max_meter.to_be_bytes());
        out.extend_from_slice(&self.band_types.to_be_bytes());
        out.extend_from_slice(&self.capabilities.to_be_bytes());
        out.push(self.max_bands);
        out.push(self.max_color);
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&self.features.to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out
    }

    /// 1.5 grew `ofp_meter_features` from 16 to 24 bytes by appending
    /// `features` and a 4-byte pad. Open vSwitch still replies with the
    /// 16-byte pre-1.5 body even on an OF 1.5 connection (confirmed
    /// against OVS 3.x), so both lengths are accepted; the short form
    /// reports `features: 0`.
    fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < 16 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(body, 14, 16)?;
        let features = if body.len() >= 24 {
            ensure_zero_padding(body, 20, 24)?;
            read_u32(body, 16)?
        } else {
            0
        };
        let head: &[u8; 14] = body.first_chunk::<14>().ok_or(OfError::ShortBuffer)?;
        Ok(Self {
            max_meter: read_u32(body, 0)?,
            band_types: read_u32(body, 4)?,
            capabilities: read_u32(body, 8)?,
            max_bands: head[12],
            max_color: head[13],
            features,
        })
    }
}

/// One `ofp_instruction_id` or `ofp_action_id` inside a table-feature
/// property list: a 4-byte type/length header, plus, for the
/// experimenter forms, whatever the extra length carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeId {
    /// The `OFPAT_*` or `OFPIT_*` type this id names.
    pub kind: u16,
    /// The experimenter id and subtype, for an experimenter type; empty
    /// otherwise.
    pub data: Vec<u8>,
}

impl TypeId {
    fn parse_list(body: &[u8]) -> Result<Vec<Self>> {
        let mut ids = Vec::new();
        let mut offset = 0;
        while offset < body.len() {
            if body.len() - offset < 4 {
                return Err(OfError::ShortBuffer);
            }
            let kind = read_u16(body, offset)?;
            let len = usize::from(read_u16(body, offset + 2)?);
            if len < 4 || offset + len > body.len() {
                return Err(invalid_length(len));
            }
            ids.push(Self {
                kind,
                data: body
                    .get(offset + 4..offset + len)
                    .ok_or(OfError::ShortBuffer)?
                    .to_vec(),
            });
            offset += len;
        }
        Ok(ids)
    }

    fn encode_list(ids: &[Self], out: &mut Vec<u8>) -> Result<()> {
        for id in ids {
            out.extend_from_slice(&id.kind.to_be_bytes());
            out.extend_from_slice(&checked_u16_len(4 + id.data.len())?.to_be_bytes());
            out.extend_from_slice(&id.data);
        }
        Ok(())
    }
}

/// One OXM/OXS id in a table-feature property list: a bare TLV header
/// with no value, plus the experimenter id when the class is
/// `OFPXMC_EXPERIMENTER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OxmId {
    /// The 4-byte OXM header: class, field, `has_mask` and length, with
    /// no value following it.
    pub header: u32,
    /// The experimenter id, present only for an experimenter-class id.
    pub experimenter: Option<u32>,
}

impl OxmId {
    fn parse_list(body: &[u8]) -> Result<Vec<Self>> {
        let mut ids = Vec::new();
        let mut offset = 0;
        while offset < body.len() {
            if body.len() - offset < 4 {
                return Err(OfError::ShortBuffer);
            }
            let header = read_u32(body, offset)?;
            offset += 4;
            let experimenter =
                if u16::try_from(header >> 16).unwrap_or_default() == OFPXMC_EXPERIMENTER {
                    let value = read_u32(body, offset)?;
                    offset += 4;
                    Some(value)
                } else {
                    None
                };
            ids.push(Self {
                header,
                experimenter,
            });
        }
        Ok(ids)
    }

    fn encode_list(ids: &[Self], out: &mut Vec<u8>) {
        for id in ids {
            out.extend_from_slice(&id.header.to_be_bytes());
            if let Some(experimenter) = id.experimenter {
                out.extend_from_slice(&experimenter.to_be_bytes());
            }
        }
    }
}

/// One `ofp_table_feature_prop_header`-framed property of an
/// `ofp_table_features` entry (spec 7.3.5.18.1).
///
/// The `kind` each variant carries is the property's own `OFPTFPT_*`
/// type, which is what distinguishes an entry from its `_MISS`
/// counterpart (and, for tables, `OFPTFPT_TABLE_SYNC_FROM`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableFeatureProperty {
    /// `OFPTFPT_INSTRUCTIONS`, `OFPTFPT_INSTRUCTIONS_MISS`.
    Instructions {
        /// Which of those two property types this is.
        kind: u16,
        /// The supported instruction types.
        ids: Vec<TypeId>,
    },
    /// `OFPTFPT_NEXT_TABLES`, `OFPTFPT_NEXT_TABLES_MISS`,
    /// `OFPTFPT_TABLE_SYNC_FROM`.
    NextTables {
        /// Which of those property types this is.
        kind: u16,
        /// Table ids reachable from this table.
        table_ids: Vec<u8>,
    },
    /// `OFPTFPT_WRITE_ACTIONS`, `OFPTFPT_APPLY_ACTIONS` and their
    /// `_MISS` counterparts.
    Actions {
        /// Which of those property types this is.
        kind: u16,
        /// The supported action types.
        ids: Vec<TypeId>,
    },
    /// `OFPTFPT_MATCH`, `OFPTFPT_WILDCARDS`, the `SETFIELD`/`COPYFIELD`
    /// families and their `_MISS` counterparts.
    Oxm {
        /// Which of those property types this is.
        kind: u16,
        /// The supported OXM field ids.
        oxm_ids: Vec<OxmId>,
    },
    /// `OFPTFPT_PACKET_TYPES`.
    PacketTypes(Vec<u32>),
    /// `OFPTFPT_EXPERIMENTER`, `OFPTFPT_EXPERIMENTER_MISS`.
    Experimenter {
        /// Which of those two property types this is.
        kind: u16,
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// survives a decode/encode round trip.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl TableFeatureProperty {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        let body = raw.get(4..).unwrap_or_default();
        Ok(match kind {
            OFPTFPT_INSTRUCTIONS | OFPTFPT_INSTRUCTIONS_MISS => Self::Instructions {
                kind,
                ids: TypeId::parse_list(body)?,
            },
            OFPTFPT_NEXT_TABLES | OFPTFPT_NEXT_TABLES_MISS | OFPTFPT_TABLE_SYNC_FROM => {
                Self::NextTables {
                    kind,
                    table_ids: body.to_vec(),
                }
            }
            OFPTFPT_WRITE_ACTIONS
            | OFPTFPT_WRITE_ACTIONS_MISS
            | OFPTFPT_APPLY_ACTIONS
            | OFPTFPT_APPLY_ACTIONS_MISS => Self::Actions {
                kind,
                ids: TypeId::parse_list(body)?,
            },
            OFPTFPT_MATCH
            | OFPTFPT_WILDCARDS
            | OFPTFPT_WRITE_SETFIELD
            | OFPTFPT_WRITE_SETFIELD_MISS
            | OFPTFPT_APPLY_SETFIELD
            | OFPTFPT_APPLY_SETFIELD_MISS
            | OFPTFPT_WRITE_COPYFIELD
            | OFPTFPT_WRITE_COPYFIELD_MISS
            | OFPTFPT_APPLY_COPYFIELD
            | OFPTFPT_APPLY_COPYFIELD_MISS => Self::Oxm {
                kind,
                oxm_ids: OxmId::parse_list(body)?,
            },
            OFPTFPT_PACKET_TYPES => {
                if !body.len().is_multiple_of(4) {
                    return Err(invalid_length(raw.len()));
                }
                Self::PacketTypes(
                    body.as_chunks::<4>()
                        .0
                        .iter()
                        .map(|chunk| u32::from_be_bytes(*chunk))
                        .collect(),
                )
            }
            OFPTFPT_EXPERIMENTER | OFPTFPT_EXPERIMENTER_MISS => {
                if raw.len() < 12 {
                    return Err(invalid_length(raw.len()));
                }
                Self::Experimenter {
                    kind,
                    experimenter: read_u32(raw, 4)?,
                    exp_type: read_u32(raw, 8)?,
                    data: raw.get(12..).unwrap_or_default().to_vec(),
                }
            }
            _ => Self::Raw {
                kind,
                data: body.to_vec(),
            },
        })
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        let kind = match self {
            Self::Instructions { kind, .. }
            | Self::Actions { kind, .. }
            | Self::NextTables { kind, .. }
            | Self::Oxm { kind, .. }
            | Self::Experimenter { kind, .. }
            | Self::Raw { kind, .. } => *kind,
            Self::PacketTypes(_) => OFPTFPT_PACKET_TYPES,
        };
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&[0u8; 2]);
        match self {
            Self::Instructions { ids, .. } | Self::Actions { ids, .. } => {
                TypeId::encode_list(ids, out)?;
            }
            Self::NextTables { table_ids, .. } => out.extend_from_slice(table_ids),
            Self::Oxm { oxm_ids, .. } => OxmId::encode_list(oxm_ids, out),
            Self::PacketTypes(values) => {
                for value in values {
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }
            Self::Experimenter {
                experimenter,
                exp_type,
                data,
                ..
            } => {
                out.extend_from_slice(&experimenter.to_be_bytes());
                out.extend_from_slice(&exp_type.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::Raw { data, .. } => out.extend_from_slice(data),
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start + 2..start + 4) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        Ok(())
    }
}

/// Body of a reply to an `OFPMP_TABLE_FEATURES` request:
/// `ofp_table_features`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableFeaturesEntry {
    /// The table being described or configured.
    pub table_id: u8,
    /// The `OFPTFC_*` command (1.5): replace, modify or disable.
    pub command: u8,
    /// Bitmap of `OFPTFF_*` table features.
    pub features: u32,
    /// Human-readable table name.
    pub name: String,
    /// Which metadata bits the table can match on.
    pub metadata_match: u64,
    /// Which metadata bits the table can write.
    pub metadata_write: u64,
    /// Bitmap of `OFPTC_*` configuration bits the table supports.
    pub capabilities: u32,
    /// Maximum flow entries the table holds.
    pub max_entries: u32,
    /// The table's feature properties: supported instructions, actions,
    /// match fields and next tables.
    pub properties: Vec<TableFeatureProperty>,
}

impl TableFeaturesEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&[0u8; 2]);
        out.push(self.table_id);
        out.push(self.command);
        out.extend_from_slice(&self.features.to_be_bytes());
        write_fixed_str(out, &self.name, OFP_MAX_TABLE_NAME_LEN);
        out.extend_from_slice(&self.metadata_match.to_be_bytes());
        out.extend_from_slice(&self.metadata_write.to_be_bytes());
        out.extend_from_slice(&self.capabilities.to_be_bytes());
        out.extend_from_slice(&self.max_entries.to_be_bytes());
        for property in &self.properties {
            property.encode(out)?;
        }
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start..start + 2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 64 {
            return Err(OfError::ShortBuffer);
        }
        let head: &[u8; 4] = raw.first_chunk::<4>().ok_or(OfError::ShortBuffer)?;
        Ok(Self {
            table_id: head[2],
            command: head[3],
            features: read_u32(raw, 4)?,
            name: read_fixed_str(raw, 8, OFP_MAX_TABLE_NAME_LEN)?,
            metadata_match: read_u64(raw, 40)?,
            metadata_write: read_u64(raw, 48)?,
            capabilities: read_u32(raw, 56)?,
            max_entries: read_u32(raw, 60)?,
            properties: parse_property_entries(
                raw.get(64..).unwrap_or_default(),
                allow_any_property_type,
            )?
            .into_iter()
            .map(|(kind, entry)| TableFeatureProperty::parse(kind, &entry))
            .collect::<Result<Vec<_>>>()?,
        })
    }
}

/// One `ofp_port_desc_prop_header`-framed property of an `ofp_port` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortProperty {
    /// `OFPPDPT_ETHERNET`: the port's Ethernet features, each a bitmap of
    /// `OFPPF_*`.
    Ethernet {
        /// Features currently in use.
        curr: u32,
        /// Features being advertised by this port.
        advertised: u32,
        /// Features the port supports.
        supported: u32,
        /// Features advertised by the peer.
        peer: u32,
        /// Current bitrate, in kbps.
        curr_speed: u32,
        /// Maximum bitrate, in kbps.
        max_speed: u32,
    },
    /// `OFPPDPT_OPTICAL`: the port's optical capabilities.
    Optical {
        /// Bitmap of `OFPOPF_*` optical features.
        supported: u32,
        /// Lowest transmit frequency or wavelength.
        tx_min_freq_lmda: u32,
        /// Highest transmit frequency or wavelength.
        tx_max_freq_lmda: u32,
        /// Transmit channel spacing.
        tx_grid_freq_lmda: u32,
        /// Lowest receive frequency or wavelength.
        rx_min_freq_lmda: u32,
        /// Highest receive frequency or wavelength.
        rx_max_freq_lmda: u32,
        /// Receive channel spacing.
        rx_grid_freq_lmda: u32,
        /// Minimum transmit power.
        tx_pwr_min: u16,
        /// Maximum transmit power.
        tx_pwr_max: u16,
    },
    /// `OFPPDPT_PIPELINE_INPUT`: the packet types this port can inject
    /// into the pipeline, as encoded `OFPHTN_*` header-type ids.
    PipelineInput(Vec<u8>),
    /// `OFPPDPT_PIPELINE_OUTPUT`: the packet types this port accepts out
    /// of the pipeline.
    PipelineOutput(Vec<u8>),
    /// `OFPPDPT_RECIRCULATE`: the ports this one can recirculate to.
    Recirculate(Vec<u32>),
    /// A vendor property.
    Experimenter {
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload, uninterpreted.
        data: Vec<u8>,
    },
    /// A property type this crate does not model, kept verbatim so it
    /// round-trips.
    Raw {
        /// The property type from the wire.
        kind: u16,
        /// Body bytes following the 4-byte property header.
        data: Vec<u8>,
    },
}

impl PortProperty {
    fn parse(kind: u16, raw: &[u8]) -> Result<Self> {
        match kind {
            OFPPDPT_ETHERNET => {
                if raw.len() != 32 {
                    return Err(invalid_length(raw.len()));
                }
                ensure_zero_padding(raw, 4, 8)?;
                Ok(Self::Ethernet {
                    curr: read_u32(raw, 8)?,
                    advertised: read_u32(raw, 12)?,
                    supported: read_u32(raw, 16)?,
                    peer: read_u32(raw, 20)?,
                    curr_speed: read_u32(raw, 24)?,
                    max_speed: read_u32(raw, 28)?,
                })
            }
            OFPPDPT_OPTICAL => {
                if raw.len() != 40 {
                    return Err(invalid_length(raw.len()));
                }
                ensure_zero_padding(raw, 4, 8)?;
                Ok(Self::Optical {
                    supported: read_u32(raw, 8)?,
                    tx_min_freq_lmda: read_u32(raw, 12)?,
                    tx_max_freq_lmda: read_u32(raw, 16)?,
                    tx_grid_freq_lmda: read_u32(raw, 20)?,
                    rx_min_freq_lmda: read_u32(raw, 24)?,
                    rx_max_freq_lmda: read_u32(raw, 28)?,
                    rx_grid_freq_lmda: read_u32(raw, 32)?,
                    tx_pwr_min: read_u16(raw, 36)?,
                    tx_pwr_max: read_u16(raw, 38)?,
                })
            }
            OFPPDPT_PIPELINE_INPUT => Ok(Self::PipelineInput(
                raw.get(4..).unwrap_or_default().to_vec(),
            )),
            OFPPDPT_PIPELINE_OUTPUT => Ok(Self::PipelineOutput(
                raw.get(4..).unwrap_or_default().to_vec(),
            )),
            OFPPDPT_RECIRCULATE => {
                let port_nos = raw.get(4..).unwrap_or_default();
                if !port_nos.len().is_multiple_of(4) {
                    return Err(invalid_length(raw.len()));
                }
                let mut ports = Vec::with_capacity(port_nos.len() / 4);
                let mut offset = 0;
                while offset < port_nos.len() {
                    ports.push(read_u32(port_nos, offset)?);
                    offset += 4;
                }
                Ok(Self::Recirculate(ports))
            }
            OFPPDPT_EXPERIMENTER => {
                if raw.len() < 12 {
                    return Err(invalid_length(raw.len()));
                }
                Ok(Self::Experimenter {
                    experimenter: read_u32(raw, 4)?,
                    exp_type: read_u32(raw, 8)?,
                    data: raw.get(12..).unwrap_or_default().to_vec(),
                })
            }
            _ => Ok(Self::Raw {
                kind,
                data: raw.get(4..).unwrap_or_default().to_vec(),
            }),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        match self {
            Self::Ethernet {
                curr,
                advertised,
                supported,
                peer,
                curr_speed,
                max_speed,
            } => {
                out.extend_from_slice(&OFPPDPT_ETHERNET.to_be_bytes());
                out.extend_from_slice(&32u16.to_be_bytes());
                out.extend_from_slice(&[0u8; 4]);
                for value in [curr, advertised, supported, peer, curr_speed, max_speed] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
            }
            Self::Optical {
                supported,
                tx_min_freq_lmda,
                tx_max_freq_lmda,
                tx_grid_freq_lmda,
                rx_min_freq_lmda,
                rx_max_freq_lmda,
                rx_grid_freq_lmda,
                tx_pwr_min,
                tx_pwr_max,
            } => {
                out.extend_from_slice(&OFPPDPT_OPTICAL.to_be_bytes());
                out.extend_from_slice(&40u16.to_be_bytes());
                out.extend_from_slice(&[0u8; 4]);
                for value in [
                    supported,
                    tx_min_freq_lmda,
                    tx_max_freq_lmda,
                    tx_grid_freq_lmda,
                    rx_min_freq_lmda,
                    rx_max_freq_lmda,
                    rx_grid_freq_lmda,
                ] {
                    out.extend_from_slice(&value.to_be_bytes());
                }
                out.extend_from_slice(&tx_pwr_min.to_be_bytes());
                out.extend_from_slice(&tx_pwr_max.to_be_bytes());
            }
            Self::PipelineInput(data) => {
                encode_property_header(out, OFPPDPT_PIPELINE_INPUT, data)?;
            }
            Self::PipelineOutput(data) => {
                encode_property_header(out, OFPPDPT_PIPELINE_OUTPUT, data)?;
            }
            Self::Recirculate(ports) => {
                let len = 4 + ports.len() * 4;
                out.extend_from_slice(&OFPPDPT_RECIRCULATE.to_be_bytes());
                out.extend_from_slice(&checked_u16_len(len)?.to_be_bytes());
                for port in ports {
                    out.extend_from_slice(&port.to_be_bytes());
                }
            }
            Self::Experimenter {
                experimenter,
                exp_type,
                data,
            } => {
                let len = 12 + data.len();
                out.extend_from_slice(&OFPPDPT_EXPERIMENTER.to_be_bytes());
                out.extend_from_slice(&checked_u16_len(len)?.to_be_bytes());
                out.extend_from_slice(&experimenter.to_be_bytes());
                out.extend_from_slice(&exp_type.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::Raw { kind, data } => {
                encode_property_header(out, *kind, data)?;
            }
        }
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        Ok(())
    }
}

fn encode_property_header(out: &mut Vec<u8>, kind: u16, data: &[u8]) -> Result<()> {
    let len = 4 + data.len();
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&checked_u16_len(len)?.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn parse_port_properties(body: &[u8]) -> Result<Vec<PortProperty>> {
    parse_property_entries(body, allow_any_property_type)?
        .into_iter()
        .map(|(kind, raw)| PortProperty::parse(kind, &raw))
        .collect()
}

/// Body of reply to `OFPMP_PORT_DESC` request: `ofp_port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortDescEntry {
    /// The port number.
    pub port_no: u32,
    /// The port's hardware address.
    pub hw_addr: [u8; 6],
    /// Human-readable port name.
    pub name: String,
    /// Bitmap of `OFPPC_*` administrative configuration bits.
    pub config: u32,
    /// Bitmap of `OFPPS_*` observed state bits, e.g. `OFPPS_LINK_DOWN`.
    pub state: u32,
    /// Ethernet, optical and pipeline properties.
    pub properties: Vec<PortProperty>,
}

impl PortDescEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&self.port_no.to_be_bytes());
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&self.hw_addr);
        out.extend_from_slice(&[0u8; 2]);
        write_fixed_str(out, &self.name, OFP_MAX_PORT_NAME_LEN);
        out.extend_from_slice(&self.config.to_be_bytes());
        out.extend_from_slice(&self.state.to_be_bytes());
        for property in &self.properties {
            property.encode(out)?;
        }
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start + 4..start + 6) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 40 {
            return Err(OfError::ShortBuffer);
        }
        let head: &[u8; 14] = raw.first_chunk::<14>().ok_or(OfError::ShortBuffer)?;
        let mut hw_addr = [0u8; OFP_ETH_ALEN];
        hw_addr.copy_from_slice(&head[8..14]);
        Ok(Self {
            port_no: read_u32(raw, 0)?,
            hw_addr,
            name: read_fixed_str(raw, 16, OFP_MAX_PORT_NAME_LEN)?,
            config: read_u32(raw, 32)?,
            state: read_u32(raw, 36)?,
            properties: parse_port_properties(raw.get(40..).unwrap_or_default())?,
        })
    }
}

fn parse_port_desc_entries(body: &[u8]) -> Result<Vec<PortDescEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        if body.len() - offset < 6 {
            return Err(OfError::ShortBuffer);
        }
        let len = usize::from(read_u16(body, offset + 4)?);
        if len < 40 || !len.is_multiple_of(8) {
            return Err(invalid_length(len));
        }
        if offset + len > body.len() {
            return Err(OfError::ShortBuffer);
        }
        let raw = body.get(offset..offset + len).ok_or(OfError::ShortBuffer)?;
        entries.push(PortDescEntry::parse(raw)?);
        offset += len;
    }
    Ok(entries)
}

/// Body of reply to `OFPMP_TABLE_DESC` request: `ofp_table_desc`. The
/// trailing table-mod property list is kept raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDescEntry {
    /// The table being described.
    pub table_id: u8,
    /// Bitmap of `OFPTC_*` configuration bits currently set.
    pub config: u32,
    /// Its eviction and vacancy properties.
    pub properties: Vec<TableModProperty>,
}

impl TableDescEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&[0u8; 2]);
        out.push(self.table_id);
        out.push(0);
        out.extend_from_slice(&self.config.to_be_bytes());
        out.extend_from_slice(&encode_typed_properties(
            &self.properties,
            TableModProperty::encode,
        )?);
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start..start + 2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 8 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(raw, 3, 4)?;
        let head: &[u8; 3] = raw.first_chunk::<3>().ok_or(OfError::ShortBuffer)?;
        Ok(Self {
            table_id: head[2],
            config: read_u32(raw, 4)?,
            properties: parse_typed_properties(
                raw.get(8..).unwrap_or_default(),
                TableModProperty::parse,
            )?,
        })
    }
}

/// Body of reply to `OFPMP_QUEUE_DESC` request: `ofp_queue_desc`. The
/// trailing queue-description property list is kept raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueDescEntry {
    /// The port this queue is on.
    pub port_no: u32,
    /// The queue's id.
    pub queue_id: u32,
    /// Its rate-limit and other properties.
    pub properties: Vec<QueueDescProperty>,
}

impl QueueDescEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&self.port_no.to_be_bytes());
        out.extend_from_slice(&self.queue_id.to_be_bytes());
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&[0u8; 6]);
        out.extend_from_slice(&encode_typed_properties(
            &self.properties,
            QueueDescProperty::encode,
        )?);
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start + 8..start + 10) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 16 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(raw, 10, 16)?;
        Ok(Self {
            port_no: read_u32(raw, 0)?,
            queue_id: read_u32(raw, 4)?,
            properties: parse_typed_properties(
                raw.get(16..).unwrap_or_default(),
                QueueDescProperty::parse,
            )?,
        })
    }
}

fn parse_queue_desc_entries(body: &[u8]) -> Result<Vec<QueueDescEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        if body.len() - offset < 10 {
            return Err(OfError::ShortBuffer);
        }
        let len = usize::from(read_u16(body, offset + 8)?);
        if len < 16 || !len.is_multiple_of(8) {
            return Err(invalid_length(len));
        }
        if offset + len > body.len() {
            return Err(OfError::ShortBuffer);
        }
        let raw = body.get(offset..offset + len).ok_or(OfError::ShortBuffer)?;
        entries.push(QueueDescEntry::parse(raw)?);
        offset += len;
    }
    Ok(entries)
}

/// Body for an `OFPMP_FLOW_MONITOR` request: `ofp_flow_monitor_request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowMonitorRequest {
    /// Controller-chosen monitor id.
    pub monitor_id: u32,
    /// Only monitor entries with this output port; `OFPP_ANY` for all.
    pub out_port: u32,
    /// Only monitor entries with this output group; `OFPG_ANY` for all.
    pub out_group: u32,
    /// Bitmap of `OFPFMF_*`: which changes to report, and how much
    /// detail each update carries.
    pub flags: u16,
    /// Table to monitor, or `OFPTT_ALL`.
    pub table_id: u8,
    /// The `OFPFMC_*` command: add, modify or delete this monitor.
    pub command: u8,
    /// Raw `ofp_match` OXM bytes selecting the entries to monitor.
    pub of_match: Vec<u8>,
}

impl FlowMonitorRequest {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(24);
        out.extend_from_slice(&self.monitor_id.to_be_bytes());
        out.extend_from_slice(&self.out_port.to_be_bytes());
        out.extend_from_slice(&self.out_group.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.push(self.table_id);
        out.push(self.command);
        encode_embedded_match(&mut out, &self.of_match)?;
        Ok(out)
    }

    fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < 16 {
            return Err(OfError::ShortBuffer);
        }
        let head: &[u8; 16] = body.first_chunk::<16>().ok_or(OfError::ShortBuffer)?;
        let (of_match, _) = parse_embedded_match(body, 16)?;
        Ok(Self {
            monitor_id: read_u32(body, 0)?,
            out_port: read_u32(body, 4)?,
            out_group: read_u32(body, 8)?,
            flags: read_u16(body, 12)?,
            table_id: head[14],
            command: head[15],
            of_match,
        })
    }
}

/// One `ofp_flow_update_header`-framed entry of an `OFPMP_FLOW_MONITOR`
/// reply (spec 7.3.5.19.2).
///
/// The `event` field selects which of the spec's three payload shapes
/// follows the common header, so each is a variant here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowMonitorUpdate {
    /// `OFPFME_INITIAL`/`_ADDED`/`_REMOVED`/`_MODIFIED`:
    /// `ofp_flow_update_full`.
    Full {
        /// The `OFPFME_*` event: initial, added, removed, or modified.
        event: u16,
        /// The table the entry lives in.
        table_id: u8,
        /// An `OFPRR_*` removal reason for `OFPFME_REMOVED`, else zero.
        reason: u8,
        /// The entry's idle timeout, in seconds.
        idle_timeout: u16,
        /// The entry's hard timeout, in seconds.
        hard_timeout: u16,
        /// The entry's priority.
        priority: u16,
        /// The entry's cookie.
        cookie: u64,
        /// Raw `ofp_match` OXM bytes.
        of_match: Vec<u8>,
        /// Empty unless the monitor asked for `OFPFMF_INSTRUCTIONS`, and
        /// always empty for `OFPFME_REMOVED`.
        instructions: Vec<Instruction>,
    },
    /// `OFPFME_ABBREV`: `ofp_flow_update_abbrev`.
    Abbrev {
        /// The xid of the controller request that caused the change.
        xid: u32,
    },
    /// `OFPFME_PAUSED`/`_RESUMED`: `ofp_flow_update_paused`.
    Paused {
        /// `OFPFME_PAUSED` or `OFPFME_RESUMED`.
        event: u16,
    },
    /// An event type this crate does not model, kept verbatim so it
    /// survives a decode/encode round trip.
    Raw {
        /// The `OFPFME_*` event from the wire.
        event: u16,
        /// Body bytes following the update header.
        data: Vec<u8>,
    },
}

impl FlowMonitorUpdate {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&[0u8; 2]);
        match self {
            Self::Full {
                event,
                table_id,
                reason,
                idle_timeout,
                hard_timeout,
                priority,
                cookie,
                of_match,
                instructions,
            } => {
                out.extend_from_slice(&event.to_be_bytes());
                out.push(*table_id);
                out.push(*reason);
                out.extend_from_slice(&idle_timeout.to_be_bytes());
                out.extend_from_slice(&hard_timeout.to_be_bytes());
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&[0u8; 4]);
                out.extend_from_slice(&cookie.to_be_bytes());
                encode_embedded_match(out, of_match)?;
                for instruction in instructions {
                    instruction.encode(out)?;
                }
            }
            Self::Abbrev { xid } => {
                out.extend_from_slice(&OFPFME_ABBREV.to_be_bytes());
                out.extend_from_slice(&xid.to_be_bytes());
            }
            Self::Paused { event } => {
                out.extend_from_slice(&event.to_be_bytes());
                out.extend_from_slice(&[0u8; 4]);
            }
            Self::Raw { event, data } => {
                out.extend_from_slice(&event.to_be_bytes());
                out.extend_from_slice(data);
            }
        }
        while !(out.len() - start).is_multiple_of(8) {
            out.push(0);
        }
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start..start + 2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 4 {
            return Err(OfError::ShortBuffer);
        }
        let event = read_u16(raw, 2)?;
        match event {
            OFPFME_INITIAL | OFPFME_ADDED | OFPFME_REMOVED | OFPFME_MODIFIED => {
                if raw.len() < 32 {
                    return Err(invalid_length(raw.len()));
                }
                // zeros[4] sits between priority and cookie.
                ensure_zero_padding(raw, 12, 16)?;
                let head: &[u8; 6] = raw.first_chunk::<6>().ok_or(OfError::ShortBuffer)?;
                let (of_match, match_padded) = parse_embedded_match(raw, 24)?;
                Ok(Self::Full {
                    event,
                    table_id: head[4],
                    reason: head[5],
                    idle_timeout: read_u16(raw, 6)?,
                    hard_timeout: read_u16(raw, 8)?,
                    priority: read_u16(raw, 10)?,
                    cookie: read_u64(raw, 16)?,
                    of_match,
                    instructions: parse_instructions(
                        raw.get(24 + match_padded..).ok_or(OfError::ShortBuffer)?,
                    )?,
                })
            }
            OFPFME_ABBREV => {
                if raw.len() < 8 {
                    return Err(invalid_length(raw.len()));
                }
                Ok(Self::Abbrev {
                    xid: read_u32(raw, 4)?,
                })
            }
            OFPFME_PAUSED | OFPFME_RESUMED => {
                if raw.len() < 8 {
                    return Err(invalid_length(raw.len()));
                }
                ensure_zero_padding(raw, 4, 8)?;
                Ok(Self::Paused { event })
            }
            _ => Ok(Self::Raw {
                event,
                data: raw.get(4..).unwrap_or_default().to_vec(),
            }),
        }
    }
}

/// One entry of an `OFPMP_CONTROLLER_STATUS` reply: `ofp_controller_status`,
/// as embedded in a multipart body (no enclosing message header/xid).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerStatusEntry {
    /// Short id of the controller described.
    pub short_id: u16,
    /// Its `OFPCR_ROLE_*` role.
    pub role: u32,
    /// The `OFPCSR_*` reason for its last status change.
    pub reason: u8,
    /// `OFPCT_STATUS_UP` or `OFPCT_STATUS_DOWN`.
    pub channel_status: u8,
    /// Properties, including the mandatory connection URI.
    pub properties: Vec<ControllerStatusProperty>,
}

impl ControllerStatusEntry {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&self.short_id.to_be_bytes());
        out.extend_from_slice(&self.role.to_be_bytes());
        out.push(self.reason);
        out.push(self.channel_status);
        out.extend_from_slice(&[0u8; 6]);
        out.extend_from_slice(&encode_typed_properties(
            &self.properties,
            ControllerStatusProperty::encode,
        )?);
        let len = checked_u16_len(out.len() - start)?;
        if let Some(dst) = out.get_mut(start..start + 2) {
            dst.copy_from_slice(&len.to_be_bytes());
        }
        Ok(())
    }

    fn parse(raw: &[u8]) -> Result<Self> {
        let length = usize::from(read_u16(raw, 0)?);
        if length < 16 || length > raw.len() {
            return Err(invalid_length(length));
        }
        let role = read_u32(raw, 4)?;
        validate_role(role)?;
        ensure_zero_padding(raw, 10, 16)?;
        let head: &[u8; 10] = raw.first_chunk::<10>().ok_or(OfError::ShortBuffer)?;
        Ok(Self {
            short_id: read_u16(raw, 2)?,
            role,
            reason: head[8],
            channel_status: head[9],
            properties: parse_typed_properties(
                raw.get(16..length).ok_or(OfError::ShortBuffer)?,
                ControllerStatusProperty::parse,
            )?,
        })
    }
}

fn parse_controller_status_entries(body: &[u8]) -> Result<Vec<ControllerStatusEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        if body.len() - offset < 2 {
            return Err(OfError::ShortBuffer);
        }
        let len = usize::from(read_u16(body, offset)?);
        if len < 16 || !len.is_multiple_of(8) {
            return Err(invalid_length(len));
        }
        if offset + len > body.len() {
            return Err(OfError::ShortBuffer);
        }
        let raw = body.get(offset..offset + len).ok_or(OfError::ShortBuffer)?;
        entries.push(ControllerStatusEntry::parse(raw)?);
        offset += len;
    }
    Ok(entries)
}

/// Body for an `OFPMP_BUNDLE_FEATURES` request: `ofp_bundle_features_request`.
/// The bundle-features property list (e.g. the timestamp/schedule-tolerance
/// property) is kept raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFeaturesRequest {
    /// Bitmap of `OFPBF_*` asking which bundle features to report on.
    pub feature_request_flags: u32,
    /// Scheduling properties the controller wants described.
    pub properties: Vec<BundleFeaturesProperty>,
}

impl BundleFeaturesRequest {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(8 + self.properties.len());
        out.extend_from_slice(&self.feature_request_flags.to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&encode_typed_properties(
            &self.properties,
            BundleFeaturesProperty::encode,
        )?);
        Ok(out)
    }

    fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < 8 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(body, 4, 8)?;
        Ok(Self {
            feature_request_flags: read_u32(body, 0)?,
            properties: parse_typed_properties(
                body.get(8..).unwrap_or_default(),
                BundleFeaturesProperty::parse,
            )?,
        })
    }
}

/// Body of reply to `OFPMP_BUNDLE_FEATURES` request: `ofp_bundle_features`.
/// The bundle-features property list is kept raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFeaturesReply {
    /// Bitmap of `OFPBF_*` the switch supports -- atomic and ordered
    /// commits, and the scheduling variants.
    pub capabilities: u16,
    /// Scheduling accuracy and limits.
    pub properties: Vec<BundleFeaturesProperty>,
}

impl BundleFeaturesReply {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(8 + self.properties.len());
        out.extend_from_slice(&self.capabilities.to_be_bytes());
        out.extend_from_slice(&[0u8; 6]);
        out.extend_from_slice(&encode_typed_properties(
            &self.properties,
            BundleFeaturesProperty::encode,
        )?);
        Ok(out)
    }

    fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < 8 {
            return Err(OfError::ShortBuffer);
        }
        ensure_zero_padding(body, 2, 8)?;
        Ok(Self {
            capabilities: read_u16(body, 0)?,
            properties: parse_typed_properties(
                body.get(8..).unwrap_or_default(),
                BundleFeaturesProperty::parse,
            )?,
        })
    }
}

/// Typed request-side body of a `MultipartMessage`, decoded per `OFPMP_*`
/// kind. See `MultipartMessage::typed_request_body`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartRequestBody {
    /// A request whose body is empty: `OFPMP_DESC`,
    /// `OFPMP_TABLE_STATS`, `OFPMP_GROUP_FEATURES`,
    /// `OFPMP_METER_FEATURES`, `OFPMP_TABLE_DESC` and
    /// `OFPMP_CONTROLLER_STATUS`.
    Empty,
    /// Body of `OFPMP_FLOW_DESC`, `OFPMP_FLOW_STATS` and
    /// `OFPMP_AGGREGATE_STATS`.
    FlowStats(FlowStatsRequest),
    /// Body of `OFPMP_PORT_STATS` and `OFPMP_PORT_DESC`.
    Port(PortMultipartRequest),
    /// Body of `OFPMP_QUEUE_STATS` and `OFPMP_QUEUE_DESC`.
    Queue(QueueMultipartRequest),
    /// Body of `OFPMP_GROUP_STATS` and `OFPMP_GROUP_DESC`.
    Group(GroupMultipartRequest),
    /// Body of `OFPMP_METER_STATS` and `OFPMP_METER_DESC`.
    Meter(MeterMultipartRequest),
    /// Body of `OFPMP_FLOW_MONITOR`.
    FlowMonitor(FlowMonitorRequest),
    /// Body of `OFPMP_BUNDLE_FEATURES`.
    BundleFeatures(BundleFeaturesRequest),
    /// The `ofp_table_features` array the controller wants to set, in the
    /// same typed form the reply uses.
    TableFeatures(Vec<TableFeaturesEntry>),
    /// Body of `OFPMP_EXPERIMENTER`, kept raw: it is by definition
    /// vendor-defined.
    Experimenter(Vec<u8>),
}

impl MultipartRequestBody {
    fn encode(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Empty => Vec::new(),
            Self::FlowStats(body) => body.encode()?,
            Self::Port(body) => body.encode(),
            Self::Queue(body) => body.encode(),
            Self::Group(body) => body.encode(),
            Self::Meter(body) => body.encode(),
            Self::FlowMonitor(body) => body.encode()?,
            Self::BundleFeatures(body) => body.encode()?,
            Self::TableFeatures(entries) => encode_each(entries, TableFeaturesEntry::encode)?,
            Self::Experimenter(raw) => raw.clone(),
        })
    }

    fn parse(kind: u16, body: &[u8]) -> Result<Self> {
        if body.len() > usize::from(u16::MAX) {
            return Err(invalid_length(body.len()));
        }
        match kind {
            OFPMP_DESC
            | OFPMP_TABLE_STATS
            | OFPMP_GROUP_FEATURES
            | OFPMP_METER_FEATURES
            | OFPMP_TABLE_DESC
            | OFPMP_CONTROLLER_STATUS => Ok(Self::Empty),
            OFPMP_FLOW_DESC | OFPMP_FLOW_STATS | OFPMP_AGGREGATE_STATS => {
                Ok(Self::FlowStats(FlowStatsRequest::parse(body)?))
            }
            OFPMP_PORT_STATS | OFPMP_PORT_DESC => {
                Ok(Self::Port(PortMultipartRequest::parse(body)?))
            }
            OFPMP_QUEUE_STATS | OFPMP_QUEUE_DESC => {
                Ok(Self::Queue(QueueMultipartRequest::parse(body)?))
            }
            OFPMP_GROUP_STATS | OFPMP_GROUP_DESC => {
                Ok(Self::Group(GroupMultipartRequest::parse(body)?))
            }
            OFPMP_METER_STATS | OFPMP_METER_DESC => {
                Ok(Self::Meter(MeterMultipartRequest::parse(body)?))
            }
            OFPMP_FLOW_MONITOR => Ok(Self::FlowMonitor(FlowMonitorRequest::parse(body)?)),
            OFPMP_BUNDLE_FEATURES => Ok(Self::BundleFeatures(BundleFeaturesRequest::parse(body)?)),
            OFPMP_TABLE_FEATURES => Ok(Self::TableFeatures(parse_length_prefixed_entries(
                body,
                64,
                TableFeaturesEntry::parse,
            )?)),
            OFPMP_EXPERIMENTER => Ok(Self::Experimenter(body.to_vec())),
            other => Err(OfError::InvalidValue {
                field: "multipart_type",
                value: u64::from(other),
            }),
        }
    }
}

/// Typed reply-side body of a `MultipartMessage`, decoded per `OFPMP_*`
/// kind. See `MultipartMessage::typed_reply_body`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartReplyBody {
    /// `OFPMP_DESC`: the switch's self-description.
    Desc(Desc),
    /// `OFPMP_FLOW_DESC`: one entry per matching flow, with its instructions.
    FlowDesc(Vec<FlowDesc>),
    /// `OFPMP_FLOW_STATS`: per-flow counters. Newer than
    /// `OFPMP_FLOW_DESC` and not universally supported (OVS has none).
    FlowStats(Vec<FlowStatsEntry>),
    /// `OFPMP_AGGREGATE_STATS`: counters summed over matching flows.
    Aggregate(AggregateStatsReply),
    /// `OFPMP_TABLE_STATS`: per-table counters.
    TableStats(Vec<TableStatsEntry>),
    /// `OFPMP_PORT_STATS`: per-port counters.
    PortStats(Vec<PortStatsEntry>),
    /// `OFPMP_QUEUE_STATS`: per-queue counters.
    QueueStats(Vec<QueueStatsEntry>),
    /// `OFPMP_GROUP_STATS`: per-group counters.
    GroupStats(Vec<GroupStatsEntry>),
    /// `OFPMP_GROUP_DESC`: each group's type and buckets.
    GroupDesc(Vec<GroupDescEntry>),
    /// `OFPMP_GROUP_FEATURES`: what the switch's group support can do.
    GroupFeatures(GroupFeatures),
    /// `OFPMP_METER_STATS`: per-meter counters.
    MeterStats(Vec<MeterStatsEntry>),
    /// `OFPMP_METER_DESC`: each meter's flags and bands.
    MeterDesc(Vec<MeterDescEntry>),
    /// `OFPMP_METER_FEATURES`: what the switch's meter support can do.
    MeterFeatures(MeterFeatures),
    /// `OFPMP_TABLE_FEATURES`: each table's capabilities and the
    /// instructions, actions and match fields it supports.
    TableFeatures(Vec<TableFeaturesEntry>),
    /// `OFPMP_PORT_DESC`: each port's address, config and features.
    PortDesc(Vec<PortDescEntry>),
    /// `OFPMP_TABLE_DESC`: each table's current configuration.
    TableDesc(Vec<TableDescEntry>),
    /// `OFPMP_QUEUE_DESC`: each queue's properties.
    QueueDesc(Vec<QueueDescEntry>),
    /// `OFPMP_FLOW_MONITOR`: flow-table change events.
    FlowMonitor(Vec<FlowMonitorUpdate>),
    /// `OFPMP_CONTROLLER_STATUS`: the state of every controller connection.
    ControllerStatus(Vec<ControllerStatusEntry>),
    /// `OFPMP_BUNDLE_FEATURES`: which bundle capabilities the switch has.
    BundleFeatures(BundleFeaturesReply),
    /// `OFPMP_EXPERIMENTER`, kept raw: it is by definition vendor-defined.
    Experimenter(Vec<u8>),
}

impl MultipartReplyBody {
    #[allow(clippy::too_many_lines)]
    fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Desc(body) => Ok(body.encode()),
            Self::FlowDesc(entries) => encode_each(entries, FlowDesc::encode),
            Self::FlowStats(entries) => encode_each(entries, FlowStatsEntry::encode),
            Self::Aggregate(body) => {
                let mut out = Vec::new();
                encode_embedded_stats(&mut out, &body.stats)?;
                Ok(out)
            }
            Self::TableStats(entries) => encode_each(entries, |entry, out| {
                TableStatsEntry::encode(entry, out);
                Ok(())
            }),
            Self::PortStats(entries) => encode_each(entries, PortStatsEntry::encode),
            Self::QueueStats(entries) => encode_each(entries, QueueStatsEntry::encode),
            Self::GroupStats(entries) => encode_each(entries, GroupStatsEntry::encode),
            Self::GroupDesc(entries) => encode_each(entries, GroupDescEntry::encode),
            Self::GroupFeatures(body) => Ok(body.encode()),
            Self::MeterStats(entries) => encode_each(entries, MeterStatsEntry::encode),
            Self::MeterDesc(entries) => encode_each(entries, MeterDescEntry::encode),
            Self::MeterFeatures(body) => Ok(body.encode()),
            Self::TableFeatures(entries) => encode_each(entries, TableFeaturesEntry::encode),
            Self::PortDesc(entries) => encode_each(entries, PortDescEntry::encode),
            Self::TableDesc(entries) => encode_each(entries, TableDescEntry::encode),
            Self::QueueDesc(entries) => encode_each(entries, QueueDescEntry::encode),
            Self::FlowMonitor(entries) => encode_each(entries, FlowMonitorUpdate::encode),
            Self::ControllerStatus(entries) => encode_each(entries, ControllerStatusEntry::encode),
            Self::BundleFeatures(body) => body.encode(),
            Self::Experimenter(raw) => Ok(raw.clone()),
        }
    }

    fn parse(kind: u16, body: &[u8]) -> Result<Self> {
        if body.len() > usize::from(u16::MAX) {
            return Err(invalid_length(body.len()));
        }
        match kind {
            OFPMP_DESC => Ok(Self::Desc(Desc::parse(body)?)),
            OFPMP_FLOW_DESC => Ok(Self::FlowDesc(parse_length_prefixed_entries(
                body,
                // 24 fixed + an 8-byte empty match + an 8-byte empty ofp_stats.
                40,
                FlowDesc::parse,
            )?)),
            OFPMP_FLOW_STATS => Ok(Self::FlowStats(parse_length_prefixed_entries(
                body,
                // 8 fixed + an 8-byte empty match + an 8-byte empty ofp_stats.
                24,
                FlowStatsEntry::parse,
            )?)),
            OFPMP_AGGREGATE_STATS => Ok(Self::Aggregate(AggregateStatsReply {
                stats: parse_embedded_stats(body, 0)?.0,
            })),
            OFPMP_TABLE_STATS => Ok(Self::TableStats(parse_fixed_entries(
                body,
                24,
                TableStatsEntry::parse,
            )?)),
            OFPMP_PORT_STATS => Ok(Self::PortStats(parse_length_prefixed_entries(
                body,
                80,
                PortStatsEntry::parse,
            )?)),
            OFPMP_QUEUE_STATS => Ok(Self::QueueStats(parse_length_prefixed_entries(
                body,
                48,
                QueueStatsEntry::parse,
            )?)),
            OFPMP_GROUP_STATS => Ok(Self::GroupStats(parse_length_prefixed_entries(
                body,
                40,
                GroupStatsEntry::parse,
            )?)),
            OFPMP_GROUP_DESC => Ok(Self::GroupDesc(parse_length_prefixed_entries(
                body,
                16,
                GroupDescEntry::parse,
            )?)),
            OFPMP_GROUP_FEATURES => Ok(Self::GroupFeatures(GroupFeatures::parse(body)?)),
            OFPMP_METER_STATS => Ok(Self::MeterStats(parse_meter_stats_entries(body)?)),
            OFPMP_METER_DESC => Ok(Self::MeterDesc(parse_length_prefixed_entries(
                body,
                8,
                MeterDescEntry::parse,
            )?)),
            OFPMP_METER_FEATURES => Ok(Self::MeterFeatures(MeterFeatures::parse(body)?)),
            OFPMP_TABLE_FEATURES => Ok(Self::TableFeatures(parse_length_prefixed_entries(
                body,
                64,
                TableFeaturesEntry::parse,
            )?)),
            OFPMP_PORT_DESC => Ok(Self::PortDesc(parse_port_desc_entries(body)?)),
            OFPMP_TABLE_DESC => Ok(Self::TableDesc(parse_length_prefixed_entries(
                body,
                8,
                TableDescEntry::parse,
            )?)),
            OFPMP_QUEUE_DESC => Ok(Self::QueueDesc(parse_queue_desc_entries(body)?)),
            OFPMP_FLOW_MONITOR => Ok(Self::FlowMonitor(parse_length_prefixed_entries(
                body,
                4,
                FlowMonitorUpdate::parse,
            )?)),
            OFPMP_CONTROLLER_STATUS => Ok(Self::ControllerStatus(parse_controller_status_entries(
                body,
            )?)),
            OFPMP_BUNDLE_FEATURES => Ok(Self::BundleFeatures(BundleFeaturesReply::parse(body)?)),
            OFPMP_EXPERIMENTER => Ok(Self::Experimenter(body.to_vec())),
            other => Err(OfError::InvalidValue {
                field: "multipart_type",
                value: u64::from(other),
            }),
        }
    }
}

fn encode_each<T>(
    entries: &[T],
    encode_one: impl Fn(&T, &mut Vec<u8>) -> Result<()>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for entry in entries {
        encode_one(entry, &mut out)?;
    }
    Ok(out)
}

impl MultipartMessage {
    /// Build a multipart request message from a typed body.
    /// Build a multipart request message from a typed body.
    ///
    /// # Errors
    ///
    /// Returns an error if any entry in `body` fails to encode (e.g. a
    /// length that overflows a `u16`).
    pub fn from_request_body(
        xid: u32,
        kind: u16,
        flags: u16,
        body: &MultipartRequestBody,
    ) -> Result<Self> {
        Ok(Self::request(xid, kind, flags, body.encode()?))
    }

    /// Build a multipart reply message from a typed body.
    ///
    /// # Errors
    ///
    /// Returns an error if any entry in `body` fails to encode (e.g. a
    /// length that overflows a `u16`).
    pub fn from_reply_body(
        xid: u32,
        kind: u16,
        flags: u16,
        body: &MultipartReplyBody,
    ) -> Result<Self> {
        Ok(Self::reply(xid, kind, flags, body.encode()?))
    }

    /// Decode this message's body as a typed multipart *request* body.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is malformed for `self.kind`, or if
    /// `self.kind` is not a recognized `OFPMP_*` constant.
    pub fn typed_request_body(&self) -> Result<MultipartRequestBody> {
        MultipartRequestBody::parse(self.kind, &self.body)
    }

    /// Decode this message's body as a typed multipart *reply* body.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is malformed for `self.kind`, or if
    /// `self.kind` is not a recognized `OFPMP_*` constant.
    pub fn typed_reply_body(&self) -> Result<MultipartReplyBody> {
        MultipartReplyBody::parse(self.kind, &self.body)
    }
}
