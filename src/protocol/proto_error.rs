//! [`OfError`], the error type every parser in [`crate::protocol`]
//! returns, along with the encoders that validate lengths (the rest
//! return their frame directly).
//!
//! Re-exported as `crate::protocol::error`.

use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
/// Something went wrong encoding or decoding an `OpenFlow` message.
///
/// Most variants are decode-side: they describe a peer's frame that does
/// not match the 1.5.1 wire format. Note that an unrecognized *value*
/// (an unknown property type, action type, or error code) is not an error
/// -- those decode losslessly into an `Unknown`/`Raw` variant so they
/// round-trip. These are structural failures instead.
pub enum OfError {
    /// The buffer ended before a field the layout requires.
    ShortBuffer,
    /// A non-Hello message whose header version is not `OpenFlow` 1.5,
    /// or a Hello whose advertised versions do not include 1.5.
    UnsupportedVersion(u8),
    /// A header or embedded length field that cannot be valid (under 8
    /// bytes, past the end of the frame, or disagreeing with the frame).
    InvalidLength(u16),
    /// A frame is valid in the `OpenFlow` wire format but exceeds the limit
    /// configured for the transport reader.
    FrameTooLarge {
        /// Length advertised by the frame header.
        length: u16,
        /// Maximum frame length accepted by the reader.
        max: usize,
    },
    /// An asynchronous operation exceeded its requested deadline.
    Timeout,
    /// An `OFPT_*` type this crate does not implement.
    UnknownMessageType(u8),
    /// An OXM/OXS TLV whose length disagrees with its field id.
    InvalidOxmLength,
    /// A field carrying a value the spec does not define.
    InvalidValue {
        /// Name of the offending field.
        field: &'static str,
        /// The value that was rejected.
        value: u64,
    },
    /// The same field appeared twice in one OXM match or OXS stats list
    /// (`OFPBMC_DUP_FIELD`, §7.5.4.5).
    DuplicateOxmField {
        /// `OFPXMC_*` class of the repeated field.
        class: u16,
        /// `OFPXMT_OFB_*` id of the repeated field.
        field: u8,
    },
    /// An OXM field id that is not defined in its class.
    UnknownOxmField {
        /// `OFPXMC_*` class of the field.
        class: u16,
        /// The unrecognized field id.
        field: u8,
    },
    /// An OXM field whose prerequisite is absent -- an `IPV4_SRC` with no
    /// `ETH_TYPE`, say (§7.2.3.6).
    MissingOxmPrerequisite {
        /// The field whose prerequisite is missing.
        field: u8,
    },
    /// The underlying stream failed.
    Io(std::io::Error),
}

impl Display for OfError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShortBuffer => write!(f, "short buffer"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported OpenFlow version: {version:#x}")
            }
            Self::InvalidLength(length) => write!(f, "invalid message length: {length}"),
            Self::FrameTooLarge { length, max } => {
                write!(
                    f,
                    "OpenFlow frame is too large: {length} bytes (maximum {max})"
                )
            }
            Self::Timeout => write!(f, "OpenFlow operation timed out"),
            Self::UnknownMessageType(msg_type) => write!(f, "unknown message type: {msg_type}"),
            Self::InvalidOxmLength => write!(f, "invalid OXM length"),
            Self::InvalidValue { field, value } => {
                write!(f, "invalid value for {field}: {value}")
            }
            Self::DuplicateOxmField { class, field } => {
                write!(f, "duplicate OXM field: class={class:#x} field={field}")
            }
            Self::UnknownOxmField { class, field } => {
                write!(f, "unknown OXM field: class={class:#x} field={field}")
            }
            Self::MissingOxmPrerequisite { field } => {
                write!(f, "missing OXM prerequisite for field {field}")
            }
            Self::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl Error for OfError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for OfError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// `Result` with this module's [`OfError`] as the error type.
pub type Result<T> = std::result::Result<T, OfError>;
