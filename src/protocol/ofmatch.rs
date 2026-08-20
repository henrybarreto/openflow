//! [`Match`], the `OFPMT_OXM` match structure a flow entry keys on
//! (`ofp_match`, §7.2.3).
//!
//! Build the TLVs it holds with the [`crate::protocol::oxm`] helpers.

use crate::protocol::bytes::checked_u16_len;
use crate::protocol::constants::OFPMT_OXM;
use crate::protocol::error::{OfError, Result};

/// Zero-pad `out` up to the next 8-byte boundary.
///
/// `OpenFlow` aligns most variable-length structures to 8 bytes; this is
/// the shared helper for that. It pads the *whole* buffer, so the
/// structure being padded must itself have started 8-aligned.
pub fn pad_to_8(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
}

/// An `OFPMT_OXM` match: the list of OXM TLVs a flow entry matches on,
/// in wire order.
///
/// Each entry is one already-encoded TLV, built by an [`oxm`] helper --
/// `oxm::eth_type`, `oxm::ipv4_dst`, ... -- or by [`oxm::field`] /
/// [`oxm::masked_field`] for a field with no dedicated helper.
///
/// ```
/// use openflow::protocol::constants::{ETH_TYPE_IPV4, OFPXMT_OFB_TCP_DST};
/// use openflow::protocol::ofmatch::Match;
/// use openflow::protocol::oxm;
///
/// // eth_type=IPv4, ip_proto=TCP, tcp_dst=80, ipv4_src in 10.0.0.0/24
/// let m = Match::new(vec![
///     oxm::eth_type(ETH_TYPE_IPV4),
///     oxm::ip_proto(6),
///     oxm::field(OFPXMT_OFB_TCP_DST, &80u16.to_be_bytes()).unwrap(),
///     oxm::ipv4_src_masked([10, 0, 0, 0], [255, 255, 255, 0]),
/// ]);
/// assert_eq!(m.oxms.len(), 4);
/// ```
///
/// Order the TLVs so each field's prerequisites come first: `ipv4_src`
/// needs `eth_type(IPv4)` ahead of it, `tcp_dst` needs that *and*
/// `ip_proto(6)`. A switch answers a missing one with
/// `OFPET_BAD_MATCH`/`OFPBMC_BAD_PREREQ`, and no field may appear twice.
/// (`PACKET_TYPE`, for non-Ethernet pipelines, must be the very first
/// TLV.)
///
/// [`oxm`]: crate::protocol::oxm
/// [`oxm::field`]: crate::protocol::oxm::field
/// [`oxm::masked_field`]: crate::protocol::oxm::masked_field
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// The match's OXM TLVs, each already encoded, in wire order.
    pub oxms: Vec<Vec<u8>>,
}

impl Match {
    /// A wildcard match -- no OXM TLVs, so it matches every packet.
    ///
    /// Pair it with priority 0 for a table-miss entry. In a
    /// [`crate::protocol::rule::Rule::delete`] it selects the whole
    /// table, subject to that rule's cookie mask.
    ///
    /// ```
    /// use openflow::protocol::ofmatch::Match;
    ///
    /// assert!(Match::any().oxms.is_empty());
    /// ```
    pub const fn any() -> Self {
        Self { oxms: Vec::new() }
    }

    /// A match over the given OXM TLVs, in the order supplied.
    ///
    /// ```
    /// use openflow::protocol::constants::ETH_TYPE_ARP;
    /// use openflow::protocol::ofmatch::Match;
    /// use openflow::protocol::oxm;
    ///
    /// let mut buf = Vec::new();
    /// Match::new(vec![oxm::eth_type(ETH_TYPE_ARP)]).encode(&mut buf).unwrap();
    /// assert_eq!(buf.len() % 8, 0); // encode() pads to an 8-byte boundary
    /// ```
    pub const fn new(oxms: Vec<Vec<u8>>) -> Self {
        Self { oxms }
    }

    /// Append the encoded `ofp_match` to `out`, padded to 8 bytes.
    ///
    /// `out` must already be 8-aligned (debug-asserted), since the padding
    /// is computed from the whole buffer's length.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded match length overflows its wire `u16`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut encoded = Vec::new();
        // `pad_to_8` pads to the whole buffer's length, so it only pads
        // this match correctly when the match itself starts 8-aligned.
        debug_assert!(out.len().is_multiple_of(8), "match must start 8-aligned");

        encoded.extend_from_slice(&OFPMT_OXM.to_be_bytes());
        encoded.extend_from_slice(&0u16.to_be_bytes());

        for oxm in &self.oxms {
            encoded.extend_from_slice(oxm);
        }

        let actual_len = checked_u16_len(encoded.len())?;
        let len_bytes = actual_len.to_be_bytes();
        encoded
            .get_mut(2..4)
            .ok_or(OfError::ShortBuffer)?
            .copy_from_slice(&len_bytes);

        pad_to_8(&mut encoded);
        out.extend_from_slice(&encoded);
        Ok(())
    }
}
