//! `OFPT_ERROR` (`ofp_error_msg`, §7.5.4): typed error types and codes.
//!
//! [`ErrorMessage`] is the wire message, with `error_type`/`code` as raw
//! numbers; [`ErrorMessage::kind`] turns that pair into the typed
//! [`ErrorType`], which covers all 18 `OFPET_*` families. A type or code
//! this crate does not know decodes as an `Unknown` variant rather than
//! failing, since a peer may use codes newer than this crate.

use crate::protocol::bytes::{checked_u16_len, read_u16};
use crate::protocol::constants::{OFPT_ERROR, OFP_HEADER_LEN, OFP_VERSION_1_5};
use crate::protocol::error::{OfError, Result};
use crate::protocol::header::Header;

#[derive(Debug, Clone, PartialEq, Eq)]
/// An `OFPT_ERROR` message: the peer rejected something you sent.
///
/// ```
/// use openflow::protocol::error_msg::{BadMatchCode, ErrorMessage, ErrorType};
///
/// let msg = ErrorMessage::new(7, 4, 9, Vec::new()); // OFPET_BAD_MATCH / BAD_PREREQ
/// assert_eq!(msg.kind(), ErrorType::BadMatch(BadMatchCode::BadPrereq));
/// ```
pub struct ErrorMessage {
    /// Transaction id of the message that was rejected -- match it against
    /// the xid you sent to find the culprit.
    pub xid: u32,
    /// Raw `OFPET_*` type. Decode with [`Self::kind`].
    pub error_type: u16,
    /// Raw code, whose meaning depends on `error_type`.
    pub code: u16,
    /// As much of the offending message as the peer chose to return,
    /// starting with its header. For `OFPET_EXPERIMENTER` this instead
    /// begins with the experimenter id -- see [`Self::experimenter_id`].
    pub data: Vec<u8>,
}

impl ErrorMessage {
    /// An error message from a raw type/code pair.
    #[must_use]
    pub const fn new(xid: u32, error_type: u16, code: u16, data: Vec<u8>) -> Self {
        Self {
            xid,
            error_type,
            code,
            data,
        }
    }

    /// Encode this error as an `OFPT_ERROR` frame.
    /// # Errors
    ///
    /// Returns an error if the payload does not fit in the header's `u16`
    /// length field.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let length = OFP_HEADER_LEN + 4 + self.data.len();
        let length = checked_u16_len(length)?;
        let mut out = Vec::with_capacity(usize::from(length));
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_ERROR,
            length,
            xid: self.xid,
        }
        .encode(&mut out);
        out.extend_from_slice(&self.error_type.to_be_bytes());
        out.extend_from_slice(&self.code.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    pub(crate) fn parse(frame: &[u8]) -> Result<Self> {
        let header = Header::parse(frame)?;
        if header.msg_type != OFPT_ERROR {
            return Err(OfError::UnknownMessageType(header.msg_type));
        }
        let msg_len = header.length as usize;
        if frame.len() < msg_len {
            return Err(OfError::ShortBuffer);
        }
        if msg_len < OFP_HEADER_LEN + 4 {
            return Err(OfError::InvalidLength(header.length));
        }
        Ok(Self {
            xid: header.xid,
            error_type: read_u16(frame, 8)?,
            code: read_u16(frame, 10)?,
            data: frame.get(12..msg_len).ok_or(OfError::ShortBuffer)?.to_vec(),
        })
    }

    /// The typed form of this error's `error_type`/`code` pair.
    #[must_use]
    pub const fn kind(&self) -> ErrorType {
        ErrorType::parse(self.error_type, self.code)
    }

    /// For `OFPET_EXPERIMENTER` errors (`ofp_error_experimenter_msg`), the experimenter ID
    /// occupying `data`'s first 4 bytes (wire layout: `type`, `exp_code`, `experimenter`,
    /// `data`). `None` for every other error type.
    #[must_use]
    pub fn experimenter_id(&self) -> Option<u32> {
        if self.error_type != crate::protocol::constants::OFPET_EXPERIMENTER {
            return None;
        }
        Some(u32::from_be_bytes(self.data.get(0..4)?.try_into().ok()?))
    }

    /// The experimenter-defined payload following [`Self::experimenter_id`]. `None` for every
    /// non-`OFPET_EXPERIMENTER` error type.
    #[must_use]
    pub fn experimenter_data(&self) -> Option<&[u8]> {
        if self.error_type != crate::protocol::constants::OFPET_EXPERIMENTER {
            return None;
        }
        self.data.get(4..)
    }

    /// Build an error message from a typed [`ErrorType`].
    #[must_use]
    pub const fn from_kind(xid: u32, kind: ErrorType, data: Vec<u8>) -> Self {
        let (error_type, code) = kind.as_wire();
        Self::new(xid, error_type, code, data)
    }
}

/// Encode an `OFPT_ERROR` frame.
///
/// Low-level form of [`crate::protocol::codec::Encoder::error`].
///
/// # Errors
///
/// Returns an error if the encoded frame exceeds the wire length limit.
pub fn encode_error(xid: u32, error_type: u16, code: u16, data: &[u8]) -> Result<Vec<u8>> {
    ErrorMessage::new(xid, error_type, code, data.to_vec()).encode()
}

pub(crate) fn parse_error(frame: &[u8]) -> Result<ErrorMessage> {
    ErrorMessage::parse(frame)
}
macro_rules! error_code_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $konst:ident),+ $(,)? }) => {
        $(#[$meta])*
        ///
        /// Each variant is one code of that error type; see the linked
        /// constant for what the switch means by it.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $(
                #[doc = concat!("[`", stringify!($konst), "`](crate::protocol::constants::", stringify!($konst), ").")]
                $variant,
            )+
            /// A code this crate does not know, kept as its raw value so
            /// it round-trips.
            Unknown(u16),
        }

        impl $name {
            const fn from_code(code: u16) -> Self {
                match code {
                    $(crate::protocol::constants::$konst => Self::$variant,)+
                    other => Self::Unknown(other),
                }
            }

            const fn code(self) -> u16 {
                match self {
                    $(Self::$variant => crate::protocol::constants::$konst,)+
                    Self::Unknown(other) => other,
                }
            }
        }
    };
}

error_code_enum!(
/// Codes for `OFPET_HELLO_FAILED`: version negotiation failed.
HelloFailedCode {
    Incompatible = OFPHFC_INCOMPATIBLE,
    Eperm = OFPHFC_EPERM,
});

error_code_enum!(
/// Codes for `OFPET_BAD_REQUEST`: the request itself was malformed or not permitted.
BadRequestCode {
    BadVersion = OFPBRC_BAD_VERSION,
    BadType = OFPBRC_BAD_TYPE,
    BadMultipart = OFPBRC_BAD_MULTIPART,
    BadExperimenter = OFPBRC_BAD_EXPERIMENTER,
    BadExpType = OFPBRC_BAD_EXP_TYPE,
    Eperm = OFPBRC_EPERM,
    BadLen = OFPBRC_BAD_LEN,
    BufferEmpty = OFPBRC_BUFFER_EMPTY,
    BufferUnknown = OFPBRC_BUFFER_UNKNOWN,
    BadTableId = OFPBRC_BAD_TABLE_ID,
    IsSlave = OFPBRC_IS_SLAVE,
    BadPort = OFPBRC_BAD_PORT,
    BadPacket = OFPBRC_BAD_PACKET,
    MultipartBufferOverflow = OFPBRC_MULTIPART_BUFFER_OVERFLOW,
    MultipartRequestTimeout = OFPBRC_MULTIPART_REQUEST_TIMEOUT,
    MultipartReplyTimeout = OFPBRC_MULTIPART_REPLY_TIMEOUT,
    MultipartBadSched = OFPBRC_MULTIPART_BAD_SCHED,
    PipelineFieldsOnly = OFPBRC_PIPELINE_FIELDS_ONLY,
    UnknownFailure = OFPBRC_UNKNOWN,
});

error_code_enum!(
/// Codes for `OFPET_BAD_ACTION`: an action in the message was rejected.
BadActionCode {
    BadType = OFPBAC_BAD_TYPE,
    BadLen = OFPBAC_BAD_LEN,
    BadExperimenter = OFPBAC_BAD_EXPERIMENTER,
    BadExpType = OFPBAC_BAD_EXP_TYPE,
    BadOutPort = OFPBAC_BAD_OUT_PORT,
    BadArgument = OFPBAC_BAD_ARGUMENT,
    Eperm = OFPBAC_EPERM,
    TooMany = OFPBAC_TOO_MANY,
    BadQueue = OFPBAC_BAD_QUEUE,
    BadOutGroup = OFPBAC_BAD_OUT_GROUP,
    MatchInconsistent = OFPBAC_MATCH_INCONSISTENT,
    UnsupportedOrder = OFPBAC_UNSUPPORTED_ORDER,
    BadTag = OFPBAC_BAD_TAG,
    BadSetType = OFPBAC_BAD_SET_TYPE,
    BadSetLen = OFPBAC_BAD_SET_LEN,
    BadSetArgument = OFPBAC_BAD_SET_ARGUMENT,
    BadSetMask = OFPBAC_BAD_SET_MASK,
    BadMeter = OFPBAC_BAD_METER,
});

error_code_enum!(
/// Codes for `OFPET_BAD_INSTRUCTION`: an instruction was rejected.
BadInstructionCode {
    UnknownInst = OFPBIC_UNKNOWN_INST,
    UnsupInst = OFPBIC_UNSUP_INST,
    BadTableId = OFPBIC_BAD_TABLE_ID,
    UnsupMetadata = OFPBIC_UNSUP_METADATA,
    UnsupMetadataMask = OFPBIC_UNSUP_METADATA_MASK,
    BadExperimenter = OFPBIC_BAD_EXPERIMENTER,
    BadExpType = OFPBIC_BAD_EXP_TYPE,
    BadLen = OFPBIC_BAD_LEN,
    Eperm = OFPBIC_EPERM,
    DupInst = OFPBIC_DUP_INST,
});

error_code_enum!(
/// Codes for `OFPET_BAD_MATCH`: the match was rejected -- a bad field,
/// a missing prerequisite, or a duplicate.
BadMatchCode {
    BadType = OFPBMC_BAD_TYPE,
    BadLen = OFPBMC_BAD_LEN,
    BadTag = OFPBMC_BAD_TAG,
    BadDlAddrMask = OFPBMC_BAD_DL_ADDR_MASK,
    BadNwAddrMask = OFPBMC_BAD_NW_ADDR_MASK,
    BadWildcards = OFPBMC_BAD_WILDCARDS,
    BadField = OFPBMC_BAD_FIELD,
    BadValue = OFPBMC_BAD_VALUE,
    BadMask = OFPBMC_BAD_MASK,
    BadPrereq = OFPBMC_BAD_PREREQ,
    DupField = OFPBMC_DUP_FIELD,
    Eperm = OFPBMC_EPERM,
});

error_code_enum!(
/// Codes for `OFPET_FLOW_MOD_FAILED`: the flow entry could not be installed.
FlowModFailedCode {
    UnknownFailure = OFPFMFC_UNKNOWN,
    TableFull = OFPFMFC_TABLE_FULL,
    BadTableId = OFPFMFC_BAD_TABLE_ID,
    Overlap = OFPFMFC_OVERLAP,
    Eperm = OFPFMFC_EPERM,
    BadTimeout = OFPFMFC_BAD_TIMEOUT,
    BadCommand = OFPFMFC_BAD_COMMAND,
    BadFlags = OFPFMFC_BAD_FLAGS,
    CantSync = OFPFMFC_CANT_SYNC,
    BadPriority = OFPFMFC_BAD_PRIORITY,
    IsSync = OFPFMFC_IS_SYNC,
});

error_code_enum!(
/// Codes for `OFPET_GROUP_MOD_FAILED`: the group could not be installed.
GroupModFailedCode {
    GroupExists = OFPGMFC_GROUP_EXISTS,
    InvalidGroup = OFPGMFC_INVALID_GROUP,
    WeightUnsupported = OFPGMFC_WEIGHT_UNSUPPORTED,
    OutOfGroups = OFPGMFC_OUT_OF_GROUPS,
    OutOfBuckets = OFPGMFC_OUT_OF_BUCKETS,
    ChainingUnsupported = OFPGMFC_CHAINING_UNSUPPORTED,
    WatchUnsupported = OFPGMFC_WATCH_UNSUPPORTED,
    Loop = OFPGMFC_LOOP,
    UnknownGroup = OFPGMFC_UNKNOWN_GROUP,
    ChainedGroup = OFPGMFC_CHAINED_GROUP,
    BadType = OFPGMFC_BAD_TYPE,
    BadCommand = OFPGMFC_BAD_COMMAND,
    BadBucket = OFPGMFC_BAD_BUCKET,
    BadWatch = OFPGMFC_BAD_WATCH,
    Eperm = OFPGMFC_EPERM,
    UnknownBucket = OFPGMFC_UNKNOWN_BUCKET,
    BucketExists = OFPGMFC_BUCKET_EXISTS,
});

error_code_enum!(
/// Codes for `OFPET_PORT_MOD_FAILED`: the port modification was rejected.
PortModFailedCode {
    BadPort = OFPPMFC_BAD_PORT,
    BadHwAddr = OFPPMFC_BAD_HW_ADDR,
    BadConfig = OFPPMFC_BAD_CONFIG,
    BadAdvertise = OFPPMFC_BAD_ADVERTISE,
    Eperm = OFPPMFC_EPERM,
});

error_code_enum!(
/// Codes for `OFPET_TABLE_MOD_FAILED`: the table modification was rejected.
TableModFailedCode {
    BadTable = OFPTMFC_BAD_TABLE,
    BadConfig = OFPTMFC_BAD_CONFIG,
    Eperm = OFPTMFC_EPERM,
});

error_code_enum!(
/// Codes for `OFPET_QUEUE_OP_FAILED`: a queue operation was rejected.
QueueOpFailedCode {
    BadPort = OFPQOFC_BAD_PORT,
    BadQueue = OFPQOFC_BAD_QUEUE,
    Eperm = OFPQOFC_EPERM,
});

error_code_enum!(
/// Codes for `OFPET_SWITCH_CONFIG_FAILED`: `OFPT_SET_CONFIG` was rejected.
SwitchConfigFailedCode {
    BadFlags = OFPSCFC_BAD_FLAGS,
    BadLen = OFPSCFC_BAD_LEN,
    Eperm = OFPSCFC_EPERM,
});

error_code_enum!(
/// Codes for `OFPET_ROLE_REQUEST_FAILED`: the role request was rejected,
/// commonly a stale generation id.
RoleRequestFailedCode {
    Stale = OFPRRFC_STALE,
    Unsup = OFPRRFC_UNSUP,
    BadRole = OFPRRFC_BAD_ROLE,
    IdUnsup = OFPRRFC_ID_UNSUP,
    IdInUse = OFPRRFC_ID_IN_USE,
});

error_code_enum!(
/// Codes for `OFPET_METER_MOD_FAILED`: the meter could not be installed.
MeterModFailedCode {
    UnknownFailure = OFPMMFC_UNKNOWN,
    MeterExists = OFPMMFC_METER_EXISTS,
    InvalidMeter = OFPMMFC_INVALID_METER,
    UnknownMeter = OFPMMFC_UNKNOWN_METER,
    BadCommand = OFPMMFC_BAD_COMMAND,
    BadFlags = OFPMMFC_BAD_FLAGS,
    BadRate = OFPMMFC_BAD_RATE,
    BadBurst = OFPMMFC_BAD_BURST,
    BadBand = OFPMMFC_BAD_BAND,
    BadBandValue = OFPMMFC_BAD_BAND_VALUE,
    OutOfMeters = OFPMMFC_OUT_OF_METERS,
    OutOfBands = OFPMMFC_OUT_OF_BANDS,
});

error_code_enum!(
/// Codes for `OFPET_TABLE_FEATURES_FAILED`: a table-features request was rejected.
TableFeaturesFailedCode {
    BadTable = OFPTFFC_BAD_TABLE,
    BadMetadata = OFPTFFC_BAD_METADATA,
    Eperm = OFPTFFC_EPERM,
    BadCapa = OFPTFFC_BAD_CAPA,
    BadMaxEnt = OFPTFFC_BAD_MAX_ENT,
    BadFeatures = OFPTFFC_BAD_FEATURES,
    BadCommand = OFPTFFC_BAD_COMMAND,
    TooMany = OFPTFFC_TOO_MANY,
});

error_code_enum!(
/// Codes for `OFPET_BAD_PROPERTY`: a property in the message was rejected.
BadPropertyCode {
    BadType = OFPBPC_BAD_TYPE,
    BadLen = OFPBPC_BAD_LEN,
    BadValue = OFPBPC_BAD_VALUE,
    TooMany = OFPBPC_TOO_MANY,
    DupType = OFPBPC_DUP_TYPE,
    BadExperimenter = OFPBPC_BAD_EXPERIMENTER,
    BadExpType = OFPBPC_BAD_EXP_TYPE,
    BadExpValue = OFPBPC_BAD_EXP_VALUE,
    Eperm = OFPBPC_EPERM,
});

error_code_enum!(
/// Codes for `OFPET_ASYNC_CONFIG_FAILED`: `OFPT_SET_ASYNC` was rejected,
/// typically because a reason bit is not defined on this switch.
AsyncConfigFailedCode {
    Invalid = OFPACFC_INVALID,
    Unsupported = OFPACFC_UNSUPPORTED,
    Eperm = OFPACFC_EPERM,
});

error_code_enum!(
/// Codes for `OFPET_FLOW_MONITOR_FAILED`: a flow monitor request was rejected.
FlowMonitorFailedCode {
    UnknownFailure = OFPMOFC_UNKNOWN,
    MonitorExists = OFPMOFC_MONITOR_EXISTS,
    InvalidMonitor = OFPMOFC_INVALID_MONITOR,
    UnknownMonitor = OFPMOFC_UNKNOWN_MONITOR,
    BadCommand = OFPMOFC_BAD_COMMAND,
    BadFlags = OFPMOFC_BAD_FLAGS,
    BadTableId = OFPMOFC_BAD_TABLE_ID,
    BadOut = OFPMOFC_BAD_OUT,
});

error_code_enum!(
/// Codes for `OFPET_BUNDLE_FAILED`: a bundle operation was rejected.
BundleFailedCode {
    UnknownFailure = OFPBFC_UNKNOWN,
    Eperm = OFPBFC_EPERM,
    BadId = OFPBFC_BAD_ID,
    BundleExist = OFPBFC_BUNDLE_EXIST,
    BundleClosed = OFPBFC_BUNDLE_CLOSED,
    OutOfBundles = OFPBFC_OUT_OF_BUNDLES,
    BadType = OFPBFC_BAD_TYPE,
    BadFlags = OFPBFC_BAD_FLAGS,
    MsgBadLen = OFPBFC_MSG_BAD_LEN,
    MsgBadXid = OFPBFC_MSG_BAD_XID,
    MsgUnsup = OFPBFC_MSG_UNSUP,
    MsgConflict = OFPBFC_MSG_CONFLICT,
    MsgTooMany = OFPBFC_MSG_TOO_MANY,
    MsgFailed = OFPBFC_MSG_FAILED,
    Timeout = OFPBFC_TIMEOUT,
    BundleInProgress = OFPBFC_BUNDLE_IN_PROGRESS,
    SchedNotSupported = OFPBFC_SCHED_NOT_SUPPORTED,
    SchedFuture = OFPBFC_SCHED_FUTURE,
    SchedPast = OFPBFC_SCHED_PAST,
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A typed `OFPT_ERROR` type/code pair.
///
/// Get one from [`ErrorMessage::kind`]; go back to the wire pair with
/// [`ErrorType::as_wire`].
pub enum ErrorType {
    /// `OFPET_HELLO_FAILED`.
    HelloFailed(HelloFailedCode),
    /// `OFPET_BAD_REQUEST`.
    BadRequest(BadRequestCode),
    /// `OFPET_BAD_ACTION`.
    BadAction(BadActionCode),
    /// `OFPET_BAD_INSTRUCTION`.
    BadInstruction(BadInstructionCode),
    /// `OFPET_BAD_MATCH`.
    BadMatch(BadMatchCode),
    /// `OFPET_FLOW_MOD_FAILED`.
    FlowModFailed(FlowModFailedCode),
    /// `OFPET_GROUP_MOD_FAILED`.
    GroupModFailed(GroupModFailedCode),
    /// `OFPET_PORT_MOD_FAILED`.
    PortModFailed(PortModFailedCode),
    /// `OFPET_TABLE_MOD_FAILED`.
    TableModFailed(TableModFailedCode),
    /// `OFPET_QUEUE_OP_FAILED`.
    QueueOpFailed(QueueOpFailedCode),
    /// `OFPET_SWITCH_CONFIG_FAILED`.
    SwitchConfigFailed(SwitchConfigFailedCode),
    /// `OFPET_ROLE_REQUEST_FAILED`.
    RoleRequestFailed(RoleRequestFailedCode),
    /// `OFPET_METER_MOD_FAILED`.
    MeterModFailed(MeterModFailedCode),
    /// `OFPET_TABLE_FEATURES_FAILED`.
    TableFeaturesFailed(TableFeaturesFailedCode),
    /// `OFPET_BAD_PROPERTY`.
    BadProperty(BadPropertyCode),
    /// `OFPET_ASYNC_CONFIG_FAILED`.
    AsyncConfigFailed(AsyncConfigFailedCode),
    /// `OFPET_FLOW_MONITOR_FAILED`.
    FlowMonitorFailed(FlowMonitorFailedCode),
    /// `OFPET_BUNDLE_FAILED`.
    BundleFailed(BundleFailedCode),
    /// `OFPET_EXPERIMENTER`, carrying the vendor's own code.
    Experimenter(u16),
    /// An error type this crate does not know, kept verbatim.
    Unknown {
        /// The raw `OFPET_*` value.
        error_type: u16,
        /// The raw code.
        code: u16,
    },
}

impl ErrorType {
    /// Interpret a raw `error_type`/`code` pair.
    ///
    /// Never fails: an unrecognized pair becomes [`ErrorType::Unknown`].
    #[must_use]
    pub const fn parse(error_type: u16, code: u16) -> Self {
        match error_type {
            crate::protocol::constants::OFPET_HELLO_FAILED => {
                Self::HelloFailed(HelloFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_BAD_REQUEST => {
                Self::BadRequest(BadRequestCode::from_code(code))
            }
            crate::protocol::constants::OFPET_BAD_ACTION => {
                Self::BadAction(BadActionCode::from_code(code))
            }
            crate::protocol::constants::OFPET_BAD_INSTRUCTION => {
                Self::BadInstruction(BadInstructionCode::from_code(code))
            }
            crate::protocol::constants::OFPET_BAD_MATCH => {
                Self::BadMatch(BadMatchCode::from_code(code))
            }
            crate::protocol::constants::OFPET_FLOW_MOD_FAILED => {
                Self::FlowModFailed(FlowModFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_GROUP_MOD_FAILED => {
                Self::GroupModFailed(GroupModFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_PORT_MOD_FAILED => {
                Self::PortModFailed(PortModFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_TABLE_MOD_FAILED => {
                Self::TableModFailed(TableModFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_QUEUE_OP_FAILED => {
                Self::QueueOpFailed(QueueOpFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_SWITCH_CONFIG_FAILED => {
                Self::SwitchConfigFailed(SwitchConfigFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_ROLE_REQUEST_FAILED => {
                Self::RoleRequestFailed(RoleRequestFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_METER_MOD_FAILED => {
                Self::MeterModFailed(MeterModFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_TABLE_FEATURES_FAILED => {
                Self::TableFeaturesFailed(TableFeaturesFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_BAD_PROPERTY => {
                Self::BadProperty(BadPropertyCode::from_code(code))
            }
            crate::protocol::constants::OFPET_ASYNC_CONFIG_FAILED => {
                Self::AsyncConfigFailed(AsyncConfigFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_FLOW_MONITOR_FAILED => {
                Self::FlowMonitorFailed(FlowMonitorFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_BUNDLE_FAILED => {
                Self::BundleFailed(BundleFailedCode::from_code(code))
            }
            crate::protocol::constants::OFPET_EXPERIMENTER => Self::Experimenter(code),
            other => Self::Unknown {
                error_type: other,
                code,
            },
        }
    }

    /// The raw `(error_type, code)` pair this represents.
    #[must_use]
    pub const fn as_wire(self) -> (u16, u16) {
        match self {
            Self::HelloFailed(c) => (crate::protocol::constants::OFPET_HELLO_FAILED, c.code()),
            Self::BadRequest(c) => (crate::protocol::constants::OFPET_BAD_REQUEST, c.code()),
            Self::BadAction(c) => (crate::protocol::constants::OFPET_BAD_ACTION, c.code()),
            Self::BadInstruction(c) => {
                (crate::protocol::constants::OFPET_BAD_INSTRUCTION, c.code())
            }
            Self::BadMatch(c) => (crate::protocol::constants::OFPET_BAD_MATCH, c.code()),
            Self::FlowModFailed(c) => (crate::protocol::constants::OFPET_FLOW_MOD_FAILED, c.code()),
            Self::GroupModFailed(c) => {
                (crate::protocol::constants::OFPET_GROUP_MOD_FAILED, c.code())
            }
            Self::PortModFailed(c) => (crate::protocol::constants::OFPET_PORT_MOD_FAILED, c.code()),
            Self::TableModFailed(c) => {
                (crate::protocol::constants::OFPET_TABLE_MOD_FAILED, c.code())
            }
            Self::QueueOpFailed(c) => (crate::protocol::constants::OFPET_QUEUE_OP_FAILED, c.code()),
            Self::SwitchConfigFailed(c) => (
                crate::protocol::constants::OFPET_SWITCH_CONFIG_FAILED,
                c.code(),
            ),
            Self::RoleRequestFailed(c) => (
                crate::protocol::constants::OFPET_ROLE_REQUEST_FAILED,
                c.code(),
            ),
            Self::MeterModFailed(c) => {
                (crate::protocol::constants::OFPET_METER_MOD_FAILED, c.code())
            }
            Self::TableFeaturesFailed(c) => (
                crate::protocol::constants::OFPET_TABLE_FEATURES_FAILED,
                c.code(),
            ),
            Self::BadProperty(c) => (crate::protocol::constants::OFPET_BAD_PROPERTY, c.code()),
            Self::AsyncConfigFailed(c) => (
                crate::protocol::constants::OFPET_ASYNC_CONFIG_FAILED,
                c.code(),
            ),
            Self::FlowMonitorFailed(c) => (
                crate::protocol::constants::OFPET_FLOW_MONITOR_FAILED,
                c.code(),
            ),
            Self::BundleFailed(c) => (crate::protocol::constants::OFPET_BUNDLE_FAILED, c.code()),
            Self::Experimenter(code) => (crate::protocol::constants::OFPET_EXPERIMENTER, code),
            Self::Unknown { error_type, code } => (error_type, code),
        }
    }
}
