//! OXM (`OpenFlow` eXtensible Match) fields: the TLVs a
//! [`crate::protocol::ofmatch::Match`] is built from, and the value an
//! `OFPAT_SET_FIELD` action carries (§7.2.3).
//!
//! The builders here return one encoded TLV each. Fields with no
//! dedicated builder go through [`field`] / [`masked_field`] with an
//! `OFPXMT_OFB_*` constant. Decoding is [`parse_oxm_list`], which also
//! enforces the spec's prerequisite and no-duplicates rules.
//!
//! ```
//! use openflow::protocol::constants::ETH_TYPE_IPV4;
//! use openflow::protocol::oxm;
//!
//! // ipv4_src requires an eth_type(IPv4) ahead of it.
//! let tlvs = oxm::parse_oxm_list(
//!     &[oxm::eth_type(ETH_TYPE_IPV4), oxm::ipv4_src([10, 0, 0, 1])].concat(),
//! )?;
//! assert_eq!(tlvs.len(), 2);
//! # Ok::<(), openflow::protocol::error::OfError>(())
//! ```

use crate::protocol::bytes::{read_u16, read_u32};
use crate::protocol::constants::{
    OFPXMC_EXPERIMENTER, OFPXMC_OPENFLOW_BASIC, OFPXMT_OFB_ACTSET_OUTPUT, OFPXMT_OFB_ARP_OP,
    OFPXMT_OFB_ARP_SHA, OFPXMT_OFB_ARP_SPA, OFPXMT_OFB_ARP_THA, OFPXMT_OFB_ARP_TPA,
    OFPXMT_OFB_ETH_DST, OFPXMT_OFB_ETH_SRC, OFPXMT_OFB_ETH_TYPE, OFPXMT_OFB_ICMPV4_CODE,
    OFPXMT_OFB_ICMPV4_TYPE, OFPXMT_OFB_ICMPV6_CODE, OFPXMT_OFB_ICMPV6_TYPE, OFPXMT_OFB_IN_PHY_PORT,
    OFPXMT_OFB_IN_PORT, OFPXMT_OFB_IPV4_DST, OFPXMT_OFB_IPV4_SRC, OFPXMT_OFB_IPV6_DST,
    OFPXMT_OFB_IPV6_EXTHDR, OFPXMT_OFB_IPV6_FLABEL, OFPXMT_OFB_IPV6_ND_SLL,
    OFPXMT_OFB_IPV6_ND_TARGET, OFPXMT_OFB_IPV6_ND_TLL, OFPXMT_OFB_IPV6_SRC, OFPXMT_OFB_IP_DSCP,
    OFPXMT_OFB_IP_ECN, OFPXMT_OFB_IP_PROTO, OFPXMT_OFB_METADATA, OFPXMT_OFB_MPLS_BOS,
    OFPXMT_OFB_MPLS_LABEL, OFPXMT_OFB_MPLS_TC, OFPXMT_OFB_PACKET_TYPE, OFPXMT_OFB_PBB_ISID,
    OFPXMT_OFB_PBB_UCA, OFPXMT_OFB_SCTP_DST, OFPXMT_OFB_SCTP_SRC, OFPXMT_OFB_TCP_DST,
    OFPXMT_OFB_TCP_FLAGS, OFPXMT_OFB_TCP_SRC, OFPXMT_OFB_TUNNEL_ID, OFPXMT_OFB_UDP_DST,
    OFPXMT_OFB_UDP_SRC, OFPXMT_OFB_VLAN_PCP, OFPXMT_OFB_VLAN_VID,
};
use crate::protocol::error::{OfError, Result};

/// Builds an OXM TLV header. The field id is 7 bits wide (bits 9..15), so
/// a caller passing >= 128 would otherwise bleed into the class.
const fn oxm_header(class: u16, field: u8, has_mask: bool, len: u8) -> u32 {
    ((class as u32) << 16)
        | (((field & 0x7f) as u32) << 9)
        | ((has_mask as u32) << 8)
        | (len as u32)
}

fn push_oxm(out: &mut Vec<u8>, field: u8, has_mask: bool, value: &[u8]) {
    // All current callers of this helper use fixed-size typed fields. The
    // arbitrary-size public builders use `push_oxm_checked` below.
    let len = u8::try_from(value.len()).unwrap_or_default();
    let h = oxm_header(OFPXMC_OPENFLOW_BASIC, field, has_mask, len);

    out.extend_from_slice(&h.to_be_bytes());
    out.extend_from_slice(value);
}

fn push_masked_oxm(out: &mut Vec<u8>, field: u8, value: &[u8], mask: &[u8]) {
    let mut buf = Vec::with_capacity(value.len() * 2);
    buf.extend_from_slice(value);
    buf.extend_from_slice(mask);
    let len = u8::try_from(value.len() * 2).unwrap_or_default();
    let h = oxm_header(OFPXMC_OPENFLOW_BASIC, field, true, len);

    out.extend_from_slice(&h.to_be_bytes());
    out.extend_from_slice(&buf);
}

fn push_oxm_checked(out: &mut Vec<u8>, field: u8, has_mask: bool, value: &[u8]) -> Result<()> {
    let len = u8::try_from(value.len()).map_err(|_| OfError::InvalidOxmLength)?;
    let h = oxm_header(OFPXMC_OPENFLOW_BASIC, field, has_mask, len);
    out.extend_from_slice(&h.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn push_masked_oxm_checked(out: &mut Vec<u8>, field: u8, value: &[u8], mask: &[u8]) -> Result<()> {
    if value.len() != mask.len() {
        return Err(OfError::InvalidOxmLength);
    }
    let len = value
        .len()
        .checked_mul(2)
        .and_then(|len| u8::try_from(len).ok())
        .ok_or(OfError::InvalidOxmLength)?;
    let h = oxm_header(OFPXMC_OPENFLOW_BASIC, field, true, len);
    out.extend_from_slice(&h.to_be_bytes());
    out.extend_from_slice(value);
    out.extend_from_slice(mask);
    Ok(())
}

fn push_oxm_id(out: &mut Vec<u8>, field: u8, len: u8) {
    let h = oxm_header(OFPXMC_OPENFLOW_BASIC, field, false, len);
    out.extend_from_slice(&h.to_be_bytes());
}

/// Encode a bare OXM *id* (header only, no value).
///
/// Used where the wire wants field ids rather than field values -- an
/// `OFPAT_COPY_FIELD` action's `oxm_ids`, or a table-features property.
#[must_use]
pub fn field_id(field: u8, len: u8) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm_id(&mut out, field, len);
    out
}

/// `OXM_OF_IN_PORT`: the ingress port. No prerequisite.
#[must_use]
pub fn in_port(port: u32) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_IN_PORT, false, &port.to_be_bytes());
    out
}

/// `OXM_OF_ETH_DST`: destination MAC. No prerequisite.
#[must_use]
pub fn eth_dst(mac: [u8; 6]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_ETH_DST, false, &mac);
    out
}

/// `OXM_OF_ETH_SRC`: source MAC. No prerequisite.
#[must_use]
pub fn eth_src(mac: [u8; 6]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_ETH_SRC, false, &mac);
    out
}

/// `OXM_OF_ETH_TYPE`: the `EtherType`. No prerequisite itself, but
/// most other fields require it -- see [`ETH_TYPE_IPV4`].
///
/// [`ETH_TYPE_IPV4`]: crate::protocol::constants::ETH_TYPE_IPV4
#[must_use]
pub fn eth_type(eth_type: u16) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(
        &mut out,
        OFPXMT_OFB_ETH_TYPE,
        false,
        &eth_type.to_be_bytes(),
    );
    out
}

/// `OXM_OF_IPV4_SRC`: source IPv4 address. Requires `eth_type(ETH_TYPE_IPV4)`.
#[must_use]
pub fn ipv4_src(ip: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_IPV4_SRC, false, &ip);
    out
}

/// `OXM_OF_IPV4_SRC` with a mask, for prefix matching. Requires `eth_type(ETH_TYPE_IPV4)`.
#[must_use]
pub fn ipv4_src_masked(ip: [u8; 4], mask: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    push_masked_oxm(&mut out, OFPXMT_OFB_IPV4_SRC, &ip, &mask);
    out
}

/// `OXM_OF_IPV4_DST`: destination IPv4 address. Requires `eth_type(ETH_TYPE_IPV4)`.
#[must_use]
pub fn ipv4_dst(ip: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_IPV4_DST, false, &ip);
    out
}

/// `OXM_OF_IPV4_DST` with a mask, for prefix matching. Requires `eth_type(ETH_TYPE_IPV4)`.
#[must_use]
pub fn ipv4_dst_masked(ip: [u8; 4], mask: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    push_masked_oxm(&mut out, OFPXMT_OFB_IPV4_DST, &ip, &mask);
    out
}

/// `OXM_OF_ICMPV4_TYPE`. Requires `eth_type(ETH_TYPE_IPV4)` and `ip_proto(1)`.
#[must_use]
pub fn icmpv4_type(icmp_type: u8) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_ICMPV4_TYPE, false, &[icmp_type]);
    out
}

/// `OXM_OF_ICMPV4_CODE`. Requires `eth_type(ETH_TYPE_IPV4)` and `ip_proto(1)`.
#[must_use]
pub fn icmpv4_code(code: u8) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_ICMPV4_CODE, false, &[code]);
    out
}

/// `OXM_OF_ICMPV6_TYPE`. Requires `eth_type(ETH_TYPE_IPV6)` and `ip_proto(58)`.
#[must_use]
pub fn icmpv6_type(icmp_type: u8) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_ICMPV6_TYPE, false, &[icmp_type]);
    out
}

/// `OXM_OF_ICMPV6_CODE`. Requires `eth_type(ETH_TYPE_IPV6)` and `ip_proto(58)`.
#[must_use]
pub fn icmpv6_code(code: u8) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_ICMPV6_CODE, false, &[code]);
    out
}

/// `OXM_OF_IPV6_SRC`: source IPv6 address. Requires `eth_type(ETH_TYPE_IPV6)`.
#[must_use]
pub fn ipv6_src(ip: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_IPV6_SRC, false, &ip);
    out
}

/// `OXM_OF_IPV6_DST`: destination IPv6 address. Requires `eth_type(ETH_TYPE_IPV6)`.
#[must_use]
pub fn ipv6_dst(ip: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_IPV6_DST, false, &ip);
    out
}

/// `OXM_OF_IPV6_ND_TARGET`: the target address of a neighbour
/// solicitation or advertisement.
///
/// Requires the `ICMPv6` neighbour-discovery prerequisites:
/// `eth_type(ETH_TYPE_IPV6)`, `ip_proto(58)`, and the matching
/// `icmpv6_type`.
#[must_use]
pub fn ipv6_nd_target(ip: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_IPV6_ND_TARGET, false, &ip);
    out
}

/// `OXM_OF_IPV6_ND_SLL`: source link-layer address in a neighbour
/// solicitation.
///
/// Requires the `ICMPv6` neighbour-discovery prerequisites:
/// `eth_type(ETH_TYPE_IPV6)`, `ip_proto(58)`, and the matching
/// `icmpv6_type`.
#[must_use]
pub fn ipv6_nd_sll(mac: [u8; 6]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_IPV6_ND_SLL, false, &mac);
    out
}

/// `OXM_OF_IPV6_ND_TLL`: target link-layer address in a neighbour
/// advertisement.
///
/// Requires the `ICMPv6` neighbour-discovery prerequisites:
/// `eth_type(ETH_TYPE_IPV6)`, `ip_proto(58)`, and the matching
/// `icmpv6_type`.
#[must_use]
pub fn ipv6_nd_tll(mac: [u8; 6]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_IPV6_ND_TLL, false, &mac);
    out
}

/// `OXM_OF_IP_PROTO`: the IPv4 protocol or IPv6 next-header value
/// (6 TCP, 17 UDP, 1 `ICMPv4`, 58 `ICMPv6`). Requires an `eth_type` of
/// IPv4 or IPv6.
#[must_use]
pub fn ip_proto(proto: u8) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_IP_PROTO, false, &[proto]);
    out
}

/// `OXM_OF_ARP_OP`: ARP opcode. Requires `eth_type(ETH_TYPE_ARP)`.
#[must_use]
pub fn arp_op(op: u16) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_ARP_OP, false, &op.to_be_bytes());
    out
}

/// `OXM_OF_ARP_SPA`: ARP sender protocol address. Requires `eth_type(ETH_TYPE_ARP)`.
#[must_use]
pub fn arp_spa(ip: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_ARP_SPA, false, &ip);
    out
}

/// `OXM_OF_ARP_TPA`: ARP target protocol address. Requires `eth_type(ETH_TYPE_ARP)`.
#[must_use]
pub fn arp_tpa(ip: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_ARP_TPA, false, &ip);
    out
}

/// `OXM_OF_ARP_SHA`: ARP sender hardware address. Requires `eth_type(ETH_TYPE_ARP)`.
#[must_use]
pub fn arp_sha(mac: [u8; 6]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_ARP_SHA, false, &mac);
    out
}

/// `OXM_OF_ARP_THA`: ARP target hardware address. Requires `eth_type(ETH_TYPE_ARP)`.
#[must_use]
pub fn arp_tha(mac: [u8; 6]) -> Vec<u8> {
    let mut out = Vec::new();
    push_oxm(&mut out, OFPXMT_OFB_ARP_THA, false, &mac);
    out
}

/// Encode the source and destination OXM ids for an
/// `OFPAT_COPY_FIELD` action, in that order.
#[must_use]
pub fn copy_field_ids(src_field: u8, src_len: u8, dst_field: u8, dst_len: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    push_oxm_id(&mut out, src_field, src_len);
    push_oxm_id(&mut out, dst_field, dst_len);
    out
}

pub(crate) fn field_id_width(id: &[u8]) -> Result<usize> {
    let header = id.first_chunk::<4>().ok_or(OfError::ShortBuffer)?;
    let class = read_u16(id, 0)?;
    let field_and_mask = *header.get(2).ok_or(OfError::ShortBuffer)?;
    let field = field_and_mask >> 1;
    let has_mask = field_and_mask & 1 != 0;
    let width = usize::from(*header.get(3).ok_or(OfError::ShortBuffer)?);

    if has_mask || width == 0 {
        return Err(OfError::InvalidOxmLength);
    }
    if class == OFPXMC_OPENFLOW_BASIC && basic_field_size(field).map(usize::from) != Some(width) {
        return Err(OfError::InvalidOxmLength);
    }
    Ok(width)
}

/// Encode an arbitrary OpenFlow-basic OXM field by numeric id.
///
/// # Errors
///
/// Returns an error if `value` cannot fit in the wire's 8-bit OXM length.
pub fn field(field: u8, value: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    push_oxm_checked(&mut out, field, false, value)?;
    Ok(out)
}

/// Encode an arbitrary maskable OpenFlow-basic OXM field by numeric id.
///
/// # Errors
///
/// Returns an error if the value and mask lengths differ or their combined
/// length cannot fit in the wire's 8-bit OXM length.
pub fn masked_field(field: u8, value: &[u8], mask: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    push_masked_oxm_checked(&mut out, field, value, mask)?;
    Ok(out)
}

/// Pushes a plain (non-experimenter) OXM TLV in the Nicira extended
/// match class (`OFPXMC_NXM_1`).
///
/// `ct_state`/`ct_zone` predate `OpenFlow`'s generic experimenter-OXM
/// mechanism, so OVS only recognizes them under Nicira's own registered
/// class -- not under the generic
/// `OFPXMC_EXPERIMENTER`-plus-embedded-vendor-id form that every
/// experimenter *action* in this crate uses, which OVS rejects with
/// `OFPBMC_BAD_FIELD`. Not verified against a real bridge in this
/// session; see [`crate::protocol::nicira`] for what to re-check first.
fn push_nxm1_oxm(out: &mut Vec<u8>, field: u8, has_mask: bool, value: &[u8]) {
    let len = u8::try_from(value.len()).unwrap_or_default();
    let h = oxm_header(
        crate::protocol::constants::OFPXMC_NXM_1,
        field,
        has_mask,
        len,
    );
    out.extend_from_slice(&h.to_be_bytes());
    out.extend_from_slice(value);
}

/// Matches the Nicira `ct_state` bitmask exactly.
///
/// See [`ct_state_masked`] to match only a subset of bits, ignoring the
/// rest.
pub fn ct_state(bits: u32) -> Vec<u8> {
    let mut out = Vec::new();
    push_nxm1_oxm(
        &mut out,
        crate::protocol::constants::NXM_NX_CT_STATE,
        false,
        &bits.to_be_bytes(),
    );
    out
}

/// Matches the Nicira `ct_state` bits set in `mask`, ignoring the rest.
///
/// E.g. `ct_state_masked(NX_CS_TRK | NX_CS_RPL, NX_CS_TRK | NX_CS_RPL)`
/// for "tracked and reply-direction, regardless of
/// new/established/invalid."
pub fn ct_state_masked(bits: u32, mask: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut value = bits.to_be_bytes().to_vec();
    value.extend_from_slice(&mask.to_be_bytes());
    push_nxm1_oxm(
        &mut out,
        crate::protocol::constants::NXM_NX_CT_STATE,
        true,
        &value,
    );
    out
}

/// Matches the Nicira `ct_zone` field -- see [`ct_state`]'s doc comment
/// for the shared encoding convention.
pub fn ct_zone(zone: u16) -> Vec<u8> {
    let mut out = Vec::new();
    push_nxm1_oxm(
        &mut out,
        crate::protocol::constants::NXM_NX_CT_ZONE,
        false,
        &zone.to_be_bytes(),
    );
    out
}

/// Encodes decoded [`Tlv`]s back to their wire form -- the inverse of
/// [`parse_oxm_list`].
///
/// A `Tlv` that came off the wire round-trips byte for byte.
///
/// # Errors
///
/// Returns an error if a value or mask cannot be represented by the 8-bit OXM
/// length field, or if a mask does not have the same size as its value.
pub fn encode_tlv_list(tlvs: &[Tlv]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for tlv in tlvs {
        let (class, field, experimenter, value, mask) = match tlv {
            Tlv::Basic { field, value, mask } => (OFPXMC_OPENFLOW_BASIC, *field, None, value, mask),
            Tlv::Experimenter {
                field,
                experimenter,
                value,
                mask,
            } => (
                OFPXMC_EXPERIMENTER,
                *field,
                Some(*experimenter),
                value,
                mask,
            ),
            Tlv::Other {
                class,
                field,
                value,
                mask,
            } => (*class, *field, None, value, mask),
        };
        if mask.as_ref().is_some_and(|mask| mask.len() != value.len()) {
            return Err(OfError::InvalidOxmLength);
        }
        let payload_len =
            experimenter.map_or(0, |_| 4) + value.len() + mask.as_ref().map_or(0, Vec::len);
        let len = u8::try_from(payload_len).map_err(|_| OfError::InvalidOxmLength)?;
        out.extend_from_slice(&oxm_header(class, field, mask.is_some(), len).to_be_bytes());
        if let Some(experimenter) = experimenter {
            out.extend_from_slice(&experimenter.to_be_bytes());
        }
        out.extend_from_slice(value);
        if let Some(mask) = mask {
            out.extend_from_slice(mask);
        }
    }
    Ok(out)
}

/// Unmasked wire size, in bytes, of an `OFPXMC_OPENFLOW_BASIC` field.
///
/// Returns `None` for field ids the spec does not define.
const fn basic_field_size(field: u8) -> Option<u8> {
    Some(match field {
        OFPXMT_OFB_VLAN_PCP
        | OFPXMT_OFB_IP_DSCP
        | OFPXMT_OFB_IP_ECN
        | OFPXMT_OFB_IP_PROTO
        | OFPXMT_OFB_ICMPV4_TYPE
        | OFPXMT_OFB_ICMPV4_CODE
        | OFPXMT_OFB_ICMPV6_TYPE
        | OFPXMT_OFB_ICMPV6_CODE
        | OFPXMT_OFB_MPLS_TC
        | OFPXMT_OFB_MPLS_BOS
        | OFPXMT_OFB_PBB_UCA => 1,
        OFPXMT_OFB_ETH_TYPE
        | OFPXMT_OFB_VLAN_VID
        | OFPXMT_OFB_TCP_SRC
        | OFPXMT_OFB_TCP_DST
        | OFPXMT_OFB_TCP_FLAGS
        | OFPXMT_OFB_UDP_SRC
        | OFPXMT_OFB_UDP_DST
        | OFPXMT_OFB_SCTP_SRC
        | OFPXMT_OFB_SCTP_DST
        | OFPXMT_OFB_ARP_OP
        | OFPXMT_OFB_IPV6_EXTHDR => 2,
        OFPXMT_OFB_PBB_ISID => 3,
        OFPXMT_OFB_IN_PORT
        | OFPXMT_OFB_IN_PHY_PORT
        | OFPXMT_OFB_IPV4_SRC
        | OFPXMT_OFB_IPV4_DST
        | OFPXMT_OFB_ARP_SPA
        | OFPXMT_OFB_ARP_TPA
        | OFPXMT_OFB_IPV6_FLABEL
        | OFPXMT_OFB_MPLS_LABEL
        | OFPXMT_OFB_ACTSET_OUTPUT
        | OFPXMT_OFB_PACKET_TYPE => 4,
        OFPXMT_OFB_ETH_DST
        | OFPXMT_OFB_ETH_SRC
        | OFPXMT_OFB_ARP_SHA
        | OFPXMT_OFB_ARP_THA
        | OFPXMT_OFB_IPV6_ND_SLL
        | OFPXMT_OFB_IPV6_ND_TLL => 6,
        OFPXMT_OFB_METADATA | OFPXMT_OFB_TUNNEL_ID => 8,
        OFPXMT_OFB_IPV6_SRC | OFPXMT_OFB_IPV6_DST | OFPXMT_OFB_IPV6_ND_TARGET => 16,
        _ => return None,
    })
}

/// Whether the spec permits an `OFPXMC_OPENFLOW_BASIC` field to carry a mask.
const fn basic_field_is_maskable(field: u8) -> bool {
    matches!(
        field,
        OFPXMT_OFB_METADATA
            | OFPXMT_OFB_ETH_DST
            | OFPXMT_OFB_ETH_SRC
            | OFPXMT_OFB_VLAN_VID
            | OFPXMT_OFB_IPV4_SRC
            | OFPXMT_OFB_IPV4_DST
            | OFPXMT_OFB_TCP_FLAGS
            | OFPXMT_OFB_ARP_SPA
            | OFPXMT_OFB_ARP_TPA
            | OFPXMT_OFB_IPV6_SRC
            | OFPXMT_OFB_IPV6_DST
            | OFPXMT_OFB_IPV6_FLABEL
            | OFPXMT_OFB_PBB_ISID
            | OFPXMT_OFB_TUNNEL_ID
            | OFPXMT_OFB_IPV6_EXTHDR
    )
}

/// A single decoded OXM TLV entry from a match or set-field body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tlv {
    /// An `OFPXMC_OPENFLOW_BASIC` field -- one of the 44 the spec defines.
    Basic {
        /// `OFPXMT_OFB_*` field id.
        field: u8,
        /// Big-endian field value.
        value: Vec<u8>,
        /// Mask, when the TLV had `has_mask` set. Only 15 basic fields
        /// are maskable.
        mask: Option<Vec<u8>>,
    },
    /// An `OFPXMC_EXPERIMENTER`-class field. Its semantics are
    /// vendor-defined, so the value is kept uninterpreted.
    Experimenter {
        /// Field id within the vendor's own space.
        field: u8,
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Big-endian field value.
        value: Vec<u8>,
        /// Mask, when the TLV had `has_mask` set.
        mask: Option<Vec<u8>>,
    },
    /// Any other class -- notably `OFPXMC_NXM_1`, where Open vSwitch's
    /// `ct_state`/`ct_zone` live. Kept verbatim so it round-trips.
    Other {
        /// `OFPXMC_*` class.
        class: u16,
        /// Field id within that class.
        field: u8,
        /// Big-endian field value.
        value: Vec<u8>,
        /// Mask, when the TLV had `has_mask` set.
        mask: Option<Vec<u8>>,
    },
}

impl Tlv {
    /// Whether this is the given `OFPXMC_OPENFLOW_BASIC` field.
    #[must_use]
    pub const fn is_basic_field(&self, field: u8) -> bool {
        matches!(self, Self::Basic { field: actual, .. } if *actual == field)
    }

    /// Whether two OXM TLVs address the same class and field id.
    #[must_use]
    pub const fn is_same_field(&self, other: &Self) -> bool {
        self.class() == other.class() && self.field_id() == other.field_id()
    }

    /// Whether this field carries an `OpenFlow` match mask.
    #[must_use]
    pub const fn has_mask(&self) -> bool {
        match self {
            Self::Basic { mask, .. }
            | Self::Experimenter { mask, .. }
            | Self::Other { mask, .. } => mask.is_some(),
        }
    }

    /// Whether this flow-entry field matches an unmasked packet field.
    ///
    /// The two fields must identify the same OXM class and field. An entry
    /// mask compares only its set bits; a packet field carrying a mask never
    /// represents an observed packet and is therefore rejected.
    #[must_use]
    pub fn matches_packet_field(&self, packet_field: &Self) -> bool {
        let (entry_value, entry_mask) = self.value_and_mask();
        let (packet_value, packet_mask) = packet_field.value_and_mask();
        self.class() == packet_field.class()
            && self.field_id() == packet_field.field_id()
            && entry_value.len() == packet_value.len()
            && packet_mask.is_none()
            && entry_mask.map_or_else(
                || entry_value == packet_value,
                |mask| {
                    mask.len() == entry_value.len()
                        && entry_value
                            .iter()
                            .zip(packet_value)
                            .zip(mask)
                            .all(|((expected, actual), mask)| expected & mask == actual & mask)
                },
            )
    }

    /// Whether this installed flow field is selected by `filter`.
    ///
    /// A non-strict flow-mod filter selects a more-specific entry when every
    /// bit it constrains is also constrained by the entry and has the same
    /// value. This is distinct from packet matching: both operands may carry
    /// masks here.
    #[must_use]
    pub fn is_selected_by_filter(&self, filter: &Self) -> bool {
        let (entry_value, entry_mask) = self.value_and_mask();
        let (filter_value, filter_mask) = filter.value_and_mask();
        self.class() == filter.class()
            && self.field_id() == filter.field_id()
            && entry_value.len() == filter_value.len()
            && entry_value
                .iter()
                .zip(filter_value)
                .zip(
                    entry_mask
                        .into_iter()
                        .flatten()
                        .copied()
                        .chain(std::iter::repeat(0xff))
                        .zip(
                            filter_mask
                                .into_iter()
                                .flatten()
                                .copied()
                                .chain(std::iter::repeat(0xff)),
                        ),
                )
                .all(|((entry, filter_value), (entry_mask, filter_mask))| {
                    filter_mask & !entry_mask == 0
                        && *entry & filter_mask == *filter_value & filter_mask
                })
    }

    /// Whether two constraints on this field can match the same value.
    ///
    /// Different fields are independent here and therefore overlap. For the
    /// same field, the intersection is empty only when both masks constrain a
    /// bit to different values.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        if !self.is_same_field(other) {
            return true;
        }
        let (left_value, left_mask) = self.value_and_mask();
        let (right_value, right_mask) = other.value_and_mask();
        if left_value.len() != right_value.len() {
            return false;
        }
        let left_masks = left_mask
            .into_iter()
            .flatten()
            .copied()
            .chain(std::iter::repeat(0xff));
        let right_masks = right_mask
            .into_iter()
            .flatten()
            .copied()
            .chain(std::iter::repeat(0xff));
        left_value
            .iter()
            .zip(right_value)
            .zip(left_masks.zip(right_masks))
            .all(|((left, right), (left_mask, right_mask))| {
                (left ^ right) & left_mask & right_mask == 0
            })
    }

    const fn class(&self) -> u16 {
        match self {
            Self::Basic { .. } => OFPXMC_OPENFLOW_BASIC,
            Self::Experimenter { .. } => OFPXMC_EXPERIMENTER,
            Self::Other { class, .. } => *class,
        }
    }

    const fn field_id(&self) -> u8 {
        match self {
            Self::Basic { field, .. }
            | Self::Experimenter { field, .. }
            | Self::Other { field, .. } => *field,
        }
    }

    fn basic_value(&self) -> Option<&[u8]> {
        match self {
            Self::Basic { value, .. } => Some(value),
            _ => None,
        }
    }

    /// Return the value of a basic field, if this is one.
    #[must_use]
    pub fn basic_field_value(&self) -> Option<&[u8]> {
        self.basic_value()
    }

    fn value_and_mask(&self) -> (&[u8], Option<&[u8]>) {
        match self {
            Self::Basic { value, mask, .. }
            | Self::Experimenter { value, mask, .. }
            | Self::Other { value, mask, .. } => (value, mask.as_deref()),
        }
    }
}

/// Splits a masked OXM payload into its value and mask halves.
///
/// Used for the classes whose per-field lengths this crate doesn't model
/// (experimenter and any other non-basic class): the spec's only rule
/// there is that a masked TLV carries value and mask back to back, in
/// equal halves.
fn split_masked(payload: &[u8], has_mask: bool) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    if has_mask {
        if !payload.len().is_multiple_of(2) {
            return Err(OfError::InvalidOxmLength);
        }
        let half = payload.len() / 2;
        Ok((
            payload.get(..half).unwrap_or_default().to_vec(),
            Some(payload.get(half..).unwrap_or_default().to_vec()),
        ))
    } else {
        Ok((payload.to_vec(), None))
    }
}

/// Parse a sequence of OXM TLVs, such as a flow match body or a `SET_FIELD`
/// action payload.
///
/// # Errors
///
/// Returns an error if the buffer is truncated, a field's declared length is
/// inconsistent with the spec, an `OFPXMC_OPENFLOW_BASIC` field id is
/// unrecognized, or the same `(class, field)` pair appears more than once.
pub fn parse_oxm_list(buf: &[u8]) -> Result<Vec<Tlv>> {
    let tlvs = parse_oxm_list_unchecked(buf)?;
    validate_prerequisites(&tlvs)?;
    Ok(tlvs)
}

/// Parses OXM TLVs like [`parse_oxm_list`], minus the prerequisite check.
///
/// The skipped check is the spec's required-field chain (e.g. `ipv4_src`
/// normally requiring `eth_type=0x0800` earlier in the same list). Use
/// this for decoding a single field in isolation, such as one
/// `SET_FIELD` action's payload, where that surrounding context was
/// never part of the list in the first place and the source is already a
/// real, previously valid flow (so re-deriving the packet-type context
/// isn't needed to trust the field's own value).
///
/// # Errors
///
/// Returns an error under the same malformed-buffer/unrecognized-field/
/// duplicate-field conditions as [`parse_oxm_list`], just not for a
/// missing prerequisite.
pub fn parse_oxm_list_unchecked(buf: &[u8]) -> Result<Vec<Tlv>> {
    let mut tlvs = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut offset = 0;
    while offset < buf.len() {
        if buf.len() - offset < 4 {
            return Err(OfError::ShortBuffer);
        }
        let class = read_u16(buf, offset)?;
        let field_and_mask = *buf.get(offset + 2).ok_or(OfError::ShortBuffer)?;
        let field = field_and_mask >> 1;
        let has_mask = field_and_mask & 1 != 0;
        let length = usize::from(*buf.get(offset + 3).ok_or(OfError::ShortBuffer)?);
        // "Each OXM TLV is 5 to 259 (inclusive) bytes long" (spec 7.2.3.1):
        // a 4-byte header plus at least one byte of value.
        if length == 0 {
            return Err(OfError::InvalidOxmLength);
        }
        if offset + 4 + length > buf.len() {
            return Err(OfError::ShortBuffer);
        }
        let payload = buf
            .get(offset + 4..offset + 4 + length)
            .ok_or(OfError::ShortBuffer)?;

        if !seen.insert((class, field)) {
            return Err(OfError::DuplicateOxmField { class, field });
        }

        let tlv = match class {
            OFPXMC_OPENFLOW_BASIC => {
                let size = usize::from(
                    basic_field_size(field).ok_or(OfError::UnknownOxmField { class, field })?,
                );
                let expected = if has_mask { size * 2 } else { size };
                if length != expected || (has_mask && !basic_field_is_maskable(field)) {
                    return Err(OfError::InvalidOxmLength);
                }
                Tlv::Basic {
                    field,
                    value: payload.get(..size).unwrap_or_default().to_vec(),
                    mask: has_mask.then(|| payload.get(size..).unwrap_or_default().to_vec()),
                }
            }
            OFPXMC_EXPERIMENTER => {
                if length < 4 {
                    return Err(OfError::InvalidOxmLength);
                }
                let experimenter = read_u32(payload, 0)?;
                let rest = payload.get(4..).unwrap_or_default();
                let (value, mask) = split_masked(rest, has_mask)?;
                Tlv::Experimenter {
                    field,
                    experimenter,
                    value,
                    mask,
                }
            }
            _ => {
                let (value, mask) = split_masked(payload, has_mask)?;
                Tlv::Other {
                    class,
                    field,
                    value,
                    mask,
                }
            }
        };
        tlvs.push(tlv);
        offset += 4 + length;
    }
    Ok(tlvs)
}

fn basic_value(tlvs: &[Tlv], field: u8) -> Option<&[u8]> {
    tlvs.iter()
        .find(|tlv| tlv.class() == OFPXMC_OPENFLOW_BASIC && tlv.field_id() == field)
        .and_then(Tlv::basic_value)
}

fn eth_type_is(tlvs: &[Tlv], expected: u16) -> bool {
    basic_value(tlvs, OFPXMT_OFB_ETH_TYPE).is_some_and(|v| v == expected.to_be_bytes())
}

fn ip_proto_is(tlvs: &[Tlv], expected: u8) -> bool {
    basic_value(tlvs, OFPXMT_OFB_IP_PROTO).is_some_and(|v| v == [expected])
}

fn icmpv6_type_is(tlvs: &[Tlv], expected: u8) -> bool {
    basic_value(tlvs, OFPXMT_OFB_ICMPV6_TYPE).is_some_and(|v| v == [expected])
}

/// Whether the list carries `PACKET_TYPE` with the given
/// (namespace, `ns_type`) pair -- the 1.5 alternative to an `ETH_TYPE`
/// prerequisite for a non-Ethernet pipeline.
fn packet_type_is(tlvs: &[Tlv], ns: u16, ns_type: u16) -> bool {
    basic_value(tlvs, OFPXMT_OFB_PACKET_TYPE).is_some_and(|v| {
        let mut want = [0u8; 4];
        want[..2].copy_from_slice(&ns.to_be_bytes());
        want[2..].copy_from_slice(&ns_type.to_be_bytes());
        v == want
    })
}

/// Prerequisite check for the required-field chains in the spec's header
/// match field definitions (7.2.3.8).
///
/// Each IP-family prerequisite has two accepted forms — the classic
/// `ETH_TYPE` one for an Ethernet pipeline, and the `PACKET_TYPE` one
/// (spec 7.2.3.9) for a pipeline whose packets have no Ethernet header —
/// and either satisfies it.
fn validate_prerequisites(tlvs: &[Tlv]) -> Result<()> {
    const ETH_TYPE_IPV4: u16 = 0x0800;
    const ETH_TYPE_IPV6: u16 = 0x86dd;
    const ETH_TYPE_ARP: u16 = 0x0806;
    const ETH_TYPE_MPLS_UNICAST: u16 = 0x8847;
    const ETH_TYPE_MPLS_MULTICAST: u16 = 0x8848;
    const ETH_TYPE_PBB: u16 = 0x88e7;
    /// `OFPHTN_ETHERTYPE`, the namespace `PACKET_TYPE` uses for IP.
    const PT_NS_ETHERTYPE: u16 = 1;
    const IP_PROTO_TCP: u8 = 6;
    const IP_PROTO_UDP: u8 = 17;
    const IP_PROTO_SCTP: u8 = 132;
    const IP_PROTO_ICMPV4: u8 = 1;
    const IP_PROTO_ICMPV6: u8 = 58;
    const ICMPV6_NEIGHBOR_SOLICIT: u8 = 135;
    const ICMPV6_NEIGHBOR_ADVERT: u8 = 136;

    // "The Packet Type Match Field must appear as the first OXM TLV."
    if let Some(position) = tlvs.iter().position(|tlv| {
        tlv.class() == OFPXMC_OPENFLOW_BASIC && tlv.field_id() == OFPXMT_OFB_PACKET_TYPE
    }) {
        if position != 0 {
            return Err(OfError::MissingOxmPrerequisite {
                field: OFPXMT_OFB_PACKET_TYPE,
            });
        }
    }

    let is_ipv4 =
        eth_type_is(tlvs, ETH_TYPE_IPV4) || packet_type_is(tlvs, PT_NS_ETHERTYPE, ETH_TYPE_IPV4);
    let is_ipv6 =
        eth_type_is(tlvs, ETH_TYPE_IPV6) || packet_type_is(tlvs, PT_NS_ETHERTYPE, ETH_TYPE_IPV6);
    let is_ip = is_ipv4 || is_ipv6;

    for tlv in tlvs {
        if tlv.class() != OFPXMC_OPENFLOW_BASIC {
            continue;
        }
        let field = tlv.field_id();
        let satisfied = match field {
            OFPXMT_OFB_IP_DSCP | OFPXMT_OFB_IP_ECN | OFPXMT_OFB_IP_PROTO => is_ip,
            OFPXMT_OFB_IPV4_SRC | OFPXMT_OFB_IPV4_DST => is_ipv4,
            OFPXMT_OFB_ARP_OP | OFPXMT_OFB_ARP_SPA | OFPXMT_OFB_ARP_TPA | OFPXMT_OFB_ARP_SHA
            | OFPXMT_OFB_ARP_THA => eth_type_is(tlvs, ETH_TYPE_ARP),
            OFPXMT_OFB_TCP_SRC | OFPXMT_OFB_TCP_DST | OFPXMT_OFB_TCP_FLAGS => {
                is_ip && ip_proto_is(tlvs, IP_PROTO_TCP)
            }
            OFPXMT_OFB_UDP_SRC | OFPXMT_OFB_UDP_DST => is_ip && ip_proto_is(tlvs, IP_PROTO_UDP),
            OFPXMT_OFB_SCTP_SRC | OFPXMT_OFB_SCTP_DST => is_ip && ip_proto_is(tlvs, IP_PROTO_SCTP),
            OFPXMT_OFB_ICMPV4_TYPE | OFPXMT_OFB_ICMPV4_CODE => {
                is_ipv4 && ip_proto_is(tlvs, IP_PROTO_ICMPV4)
            }
            OFPXMT_OFB_ICMPV6_TYPE | OFPXMT_OFB_ICMPV6_CODE => {
                is_ipv6 && ip_proto_is(tlvs, IP_PROTO_ICMPV6)
            }
            OFPXMT_OFB_IPV6_SRC
            | OFPXMT_OFB_IPV6_DST
            | OFPXMT_OFB_IPV6_FLABEL
            | OFPXMT_OFB_IPV6_EXTHDR => is_ipv6,
            OFPXMT_OFB_IPV6_ND_TARGET => {
                is_ipv6
                    && ip_proto_is(tlvs, IP_PROTO_ICMPV6)
                    && (icmpv6_type_is(tlvs, ICMPV6_NEIGHBOR_SOLICIT)
                        || icmpv6_type_is(tlvs, ICMPV6_NEIGHBOR_ADVERT))
            }
            OFPXMT_OFB_IPV6_ND_SLL => {
                is_ipv6
                    && ip_proto_is(tlvs, IP_PROTO_ICMPV6)
                    && icmpv6_type_is(tlvs, ICMPV6_NEIGHBOR_SOLICIT)
            }
            OFPXMT_OFB_IPV6_ND_TLL => {
                is_ipv6
                    && ip_proto_is(tlvs, IP_PROTO_ICMPV6)
                    && icmpv6_type_is(tlvs, ICMPV6_NEIGHBOR_ADVERT)
            }
            OFPXMT_OFB_MPLS_LABEL | OFPXMT_OFB_MPLS_TC | OFPXMT_OFB_MPLS_BOS => {
                eth_type_is(tlvs, ETH_TYPE_MPLS_UNICAST)
                    || eth_type_is(tlvs, ETH_TYPE_MPLS_MULTICAST)
            }
            OFPXMT_OFB_PBB_ISID | OFPXMT_OFB_PBB_UCA => eth_type_is(tlvs, ETH_TYPE_PBB),
            OFPXMT_OFB_VLAN_PCP => basic_value(tlvs, OFPXMT_OFB_VLAN_VID).is_some(),
            _ => true,
        };
        if !satisfied {
            return Err(OfError::MissingOxmPrerequisite { field });
        }
    }
    Ok(())
}
