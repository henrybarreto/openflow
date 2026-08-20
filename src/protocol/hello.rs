//! `OFPT_HELLO` and version negotiation (§6.3.3, §7.5.1).
//!
//! Both peers send a Hello on connect. This crate advertises only
//! `OpenFlow` 1.5 in its `OFPHET_VERSIONBITMAP`; use
//! [`is_version_compatible`] on what the peer sent to decide whether the
//! connection can proceed.

use crate::protocol::bytes::{checked_u16_len, read_u16};
use crate::protocol::constants::{
    OFPHET_VERSIONBITMAP, OFPT_HELLO, OFP_HEADER_LEN, OFP_VERSION_1_5,
};
use crate::protocol::error::{OfError, Result};
use crate::protocol::header::Header;

#[derive(Debug, Clone, PartialEq, Eq)]
/// A decoded `OFPT_HELLO`.
pub struct Hello {
    /// Transaction id.
    pub xid: u32,
    /// The `version` field of the peer's `OpenFlow` header.
    pub version: u8,
    /// The `OFPHET_VERSIONBITMAP` element, if the peer sent one.
    pub version_bitmap: Option<Vec<u32>>,
}

impl Hello {
    /// A Hello announcing `OpenFlow` 1.5, with no bitmap recorded yet.
    #[must_use]
    pub const fn new(xid: u32) -> Self {
        Self {
            xid,
            version: OFP_VERSION_1_5,
            version_bitmap: None,
        }
    }

    /// Encode a Hello carrying an `OFPHET_VERSIONBITMAP` element that
    /// advertises only `OpenFlow` 1.5 (the only version this crate speaks).
    ///
    /// The bitmap is built from the crate's own version, not from
    /// [`Self::version`] or [`Self::version_bitmap`], which record what a
    /// *peer* sent.
    /// # Errors
    ///
    /// Returns an error if the version bitmap cannot fit in the Hello length
    /// fields.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bitmap = vec![0u32; (OFP_VERSION_1_5 as usize / 32) + 1];
        if let Some(word) = bitmap.get_mut(OFP_VERSION_1_5 as usize / 32) {
            *word |= 1 << (OFP_VERSION_1_5 % 32);
        }

        let elem_len = 4 + bitmap.len() * 4;
        let padded_elem_len = elem_len.div_ceil(8) * 8;
        let length = OFP_HEADER_LEN + padded_elem_len;
        let length = checked_u16_len(length)?;
        let elem_len = checked_u16_len(elem_len)?;

        let mut out = Vec::with_capacity(usize::from(length));
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_HELLO,
            length,
            xid: self.xid,
        }
        .encode(&mut out);

        out.extend_from_slice(&OFPHET_VERSIONBITMAP.to_be_bytes());
        out.extend_from_slice(&elem_len.to_be_bytes());
        for word in &bitmap {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out.resize(usize::from(length), 0);
        Ok(out)
    }

    /// Parse a Hello message, extracting the `OFPHET_VERSIONBITMAP` element
    /// if present. Unknown element types are ignored, per spec.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short or an element's declared
    /// length is inconsistent with the message length.
    pub fn parse(frame: &[u8]) -> Result<Self> {
        let header = Header::parse(frame)?;
        if header.msg_type != OFPT_HELLO {
            return Err(OfError::UnknownMessageType(header.msg_type));
        }
        let msg_len = header.length as usize;
        if frame.len() < msg_len {
            return Err(OfError::ShortBuffer);
        }
        if !msg_len.is_multiple_of(8) {
            return Err(OfError::InvalidLength(header.length));
        }

        let mut offset = OFP_HEADER_LEN;
        let mut version_bitmap = None;
        while offset + 4 <= msg_len {
            let elem_type = read_u16(frame, offset)?;
            let elem_len = usize::from(read_u16(frame, offset + 2)?);
            if elem_len < 4 {
                return Err(OfError::InvalidLength(header.length));
            }
            let elem_end = offset + elem_len;
            if elem_end > msg_len {
                return Err(OfError::ShortBuffer);
            }
            let padded_elem_end = elem_end.div_ceil(8) * 8;
            if padded_elem_end > msg_len {
                return Err(OfError::ShortBuffer);
            }
            let _ = frame
                .get(elem_end..padded_elem_end)
                .ok_or(OfError::ShortBuffer)?;

            if elem_type == OFPHET_VERSIONBITMAP {
                let data = frame
                    .get(offset + 4..elem_end)
                    .ok_or(OfError::ShortBuffer)?;
                if data.len() % 4 != 0 {
                    return Err(OfError::InvalidLength(header.length));
                }
                version_bitmap = Some(
                    data.as_chunks::<4>()
                        .0
                        .iter()
                        .map(|chunk| u32::from_be_bytes(*chunk))
                        .collect(),
                );
            }

            offset = padded_elem_end;
        }

        Ok(Self {
            xid: header.xid,
            version: header.version,
            version_bitmap,
        })
    }
}

/// Encode this crate's Hello frame.
///
/// Low-level form of [`crate::protocol::codec::Encoder::hello`].
///
/// # Errors
///
/// Returns an error if the encoded frame exceeds the wire length limit.
pub fn encode_frame(xid: u32) -> Result<Vec<u8>> {
    Hello::new(xid).encode()
}

/// Whether `version`/`version_bitmap` (as received from a peer's Hello) are
/// compatible with this crate, which only ever speaks `OpenFlow` 1.5.
///
/// Implements the negotiation rule from spec 6.3.3: if the peer sent a
/// version bitmap, the negotiated version is the highest version common to
/// both bitmaps (ours only contains 1.5, so this reduces to "does the
/// peer's bitmap include 1.5"); otherwise it's `min(sent, received)` header
/// version, which is 1.5-compatible only if the peer's header version is
/// at least 1.5.
#[must_use]
pub fn is_version_compatible(version: u8, version_bitmap: Option<&[u32]>) -> bool {
    version_bitmap.map_or(version >= OFP_VERSION_1_5, |bitmap| {
        bitmap_has_version(bitmap, OFP_VERSION_1_5)
    })
}

fn bitmap_has_version(bitmap: &[u32], version: u8) -> bool {
    let idx = version as usize / 32;
    let bit = version as usize % 32;
    bitmap.get(idx).is_some_and(|word| word & (1 << bit) != 0)
}
