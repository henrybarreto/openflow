//! Nicira/OVS connection-tracking extension.
//!
//! The `NXAST_CT` action (and its nested `NXAST_NAT` sub-action), both
//! carried as `OFPAT_EXPERIMENTER` actions under the Nicira experimenter
//! id. Mainline `OpenFlow` 1.5 has no notion of connection tracking at
//! all -- this is entirely an Open vSwitch extension, documented
//! informally (`ovs-fields(7)`, `ovs-actions(7)`, and the
//! `nicira-ext.h`/`ofp-actions.c` sources) rather than in the spec
//! itself.
//!
//! Every numeric constant and struct layout below was reconstructed from
//! OVS's own sources rather than a specification, but all of it is now
//! **verified against a real Open vSwitch bridge**: see
//! `nicira_conntrack_actions_and_match_fields_are_accepted_by_ovs` in
//! `tests/ovs_integration.rs`, which installs a committing `ct()` with a
//! nested `nat()`, a recirculating `ct()`, and a
//! `ct_state`/`ct_zone` match, and reads all three back. OVS accepts the
//! bytes, which pins down the vendor id, both action subtypes, both
//! struct layouts and the two `NXM_NX_*` field numbers.
//!
//! Match-side fields (`ct_state`, `ct_zone`) travel under Nicira's own
//! registered OXM class `OFPXMC_NXM_1`, *not* under
//! `OFPXMC_EXPERIMENTER` -- they predate `OpenFlow`'s generic
//! experimenter-OXM mechanism, and OVS rejects the generic form with
//! `OFPBMC_BAD_FIELD`. They need no new decode support:
//! [`crate::protocol::oxm::parse_oxm_list`] decodes any unmodelled class
//! generically as [`crate::protocol::oxm::Tlv::Other`]. Encoders live in
//! [`crate::protocol::oxm::ct_state`] and friends.

use crate::protocol::action::{parse_actions, Action};
use crate::protocol::bytes::{read_u16, read_u32};
use crate::protocol::constants::{
    NXAST_CT, NXAST_NAT, NX_CT_F_COMMIT, NX_NAT_F_DST, NX_NAT_F_SRC, NX_NAT_RANGE_IPV4_MIN,
    NX_VENDOR_ID,
};
use crate::protocol::error::{OfError, Result};
use std::net::Ipv4Addr;

/// Builds an `NXAST_CT` action.
///
/// Commits (or just looks up) a packet's connection-tracking entry in
/// `zone`, then runs `nested` against it -- the only way `nat()` can
/// ever apply, since `NXAST_NAT` is only meaningful inside a `ct()`'s
/// own private action list, never as a top-level flow action.
///
/// `recirc_table`, if given, resubmits the packet there after `ct()`
/// runs (`NXCT_RECIRC_NONE` otherwise, meaning "keep evaluating the rest
/// of the current table's actions instead").
///
/// # Wire layout (verified against real OVS)
///
/// `struct nx_action_conntrack` (`nicira-ext.h`): a 16-byte body —
/// `subtype:u16, flags:u16, zone_src:u32, zone_imm:u16, recirc_table:u8,
/// pad:[u8;3], alg:u16` — appended after the generic experimenter
/// header (`type/len/vendor`, handled by [`Action::Experimenter`]'s own
/// encoding), followed directly by `nested`'s own encoded bytes with no
/// separate length prefix (the whole action's outer `len` covers it).
/// `zone_src` is always `0` here (a literal zone, never a field
/// reference), so the following union member is read as `zone_imm`.
///
/// # Errors
///
/// Returns an error if encoding any of `nested` fails.
pub fn ct(commit: bool, zone: u16, recirc_table: Option<u8>, nested: &[Action]) -> Result<Action> {
    let mut data = Vec::new();
    data.extend_from_slice(&NXAST_CT.to_be_bytes());
    let flags: u16 = if commit { NX_CT_F_COMMIT } else { 0 };
    data.extend_from_slice(&flags.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes()); // zone_src: literal, not a field
    data.extend_from_slice(&zone.to_be_bytes()); // zone_imm
    data.push(recirc_table.unwrap_or(crate::protocol::constants::NX_CT_RECIRC_NONE));
    data.extend_from_slice(&[0u8; 3]);
    data.extend_from_slice(&0u16.to_be_bytes()); // alg: none needed here
    for action in nested {
        action.encode(&mut data)?;
    }
    Ok(Action::Experimenter {
        experimenter: NX_VENDOR_ID,
        data,
    })
}

/// Decoded form of an [`ct`] action, for round-trip tests and for a
/// caller that received one over the wire (e.g. a future decompile
/// path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ct {
    /// Whether `NX_CT_F_COMMIT` was set, committing the connection to the
    /// tracker rather than only looking it up.
    pub commit: bool,
    /// The conntrack zone this action operates in.
    pub zone: u16,
    /// Table to resubmit the packet to after tracking, or
    /// `NXCT_RECIRC_NONE` for no recirculation.
    pub recirc_table: u8,
    /// The action list run against the tracked packet -- where a
    /// [`nat_src`]/[`nat_dst`] can appear.
    pub nested: Vec<Action>,
}

/// Decodes an `NXAST_CT` action's body (an [`Action::Experimenter`]'s
/// `data`, with `experimenter == NX_VENDOR_ID`).
///
/// # Errors
///
/// Returns [`OfError::ShortBuffer`] if `data` is truncated, or
/// [`OfError::InvalidValue`] if its subtype isn't `NXAST_CT`.
pub fn parse_ct(data: &[u8]) -> Result<Ct> {
    if data.len() < 16 {
        return Err(OfError::ShortBuffer);
    }
    let subtype = read_u16(data, 0)?;
    if subtype != NXAST_CT {
        return Err(OfError::InvalidValue {
            field: "nx_action subtype",
            value: u64::from(subtype),
        });
    }
    let flags = read_u16(data, 2)?;
    let zone = read_u16(data, 8)?;
    let recirc_table = *data.get(10).ok_or(OfError::ShortBuffer)?;
    let nested = parse_actions(data.get(16..).ok_or(OfError::ShortBuffer)?)?;
    Ok(Ct {
        commit: flags & NX_CT_F_COMMIT != 0,
        zone,
        recirc_table,
        nested,
    })
}

/// Builds an `NXAST_NAT` action rewriting the source address to `addr`
/// once its enclosing [`ct`] commits. Only meaningful nested inside a
/// `ct()`'s own action list (see [`ct`]).
pub fn nat_src(addr: Ipv4Addr) -> Action {
    Action::Experimenter {
        experimenter: NX_VENDOR_ID,
        data: nat_body(NX_NAT_F_SRC, Some(addr)),
    }
}

/// Builds an `NXAST_NAT` action rewriting the destination address to
/// `addr` once its enclosing [`ct`] commits. Only meaningful nested
/// inside a `ct()`'s own action list (see [`ct`]).
pub fn nat_dst(addr: Ipv4Addr) -> Action {
    Action::Experimenter {
        experimenter: NX_VENDOR_ID,
        data: nat_body(NX_NAT_F_DST, Some(addr)),
    }
}

/// Builds a bare `NXAST_NAT` action.
///
/// No flags, no address range, meaning "apply whatever address this
/// connection's tracker already recorded" -- the return-path
/// counterpart of a `commit`+[`nat_src`]/[`nat_dst`] flow, since
/// conntrack itself already knows the reverse mapping.
pub fn nat_bare() -> Action {
    Action::Experimenter {
        experimenter: NX_VENDOR_ID,
        data: nat_body(0, None),
    }
}

fn nat_body(flags: u16, ipv4_min: Option<Ipv4Addr>) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&NXAST_NAT.to_be_bytes());
    data.extend_from_slice(&[0u8; 2]); // pad
    data.extend_from_slice(&flags.to_be_bytes());
    let range_present: u16 = if ipv4_min.is_some() {
        NX_NAT_RANGE_IPV4_MIN
    } else {
        0
    };
    data.extend_from_slice(&range_present.to_be_bytes());
    if let Some(addr) = ipv4_min {
        data.extend_from_slice(&addr.octets());
    }
    data
}

/// Decoded form of a [`nat_src`]/[`nat_dst`]/[`nat_bare`] action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nat {
    /// Whether `NX_NAT_F_SRC` was set (source NAT).
    pub src: bool,
    /// Whether `NX_NAT_F_DST` was set (destination NAT).
    pub dst: bool,
    /// The `NX_NAT_RANGE_IPV4_MIN` address, if the action carried one.
    pub ipv4_min: Option<Ipv4Addr>,
}

/// Decodes an `NXAST_NAT` action's body (an [`Action::Experimenter`]'s
/// `data`, with `experimenter == NX_VENDOR_ID`).
///
/// # Errors
///
/// Returns [`OfError::ShortBuffer`] if `data` is truncated, or
/// [`OfError::InvalidValue`] if its subtype isn't `NXAST_NAT`.
pub fn parse_nat(data: &[u8]) -> Result<Nat> {
    if data.len() < 8 {
        return Err(OfError::ShortBuffer);
    }
    let subtype = read_u16(data, 0)?;
    if subtype != NXAST_NAT {
        return Err(OfError::InvalidValue {
            field: "nx_action subtype",
            value: u64::from(subtype),
        });
    }
    let flags = read_u16(data, 4)?;
    let range_present = read_u16(data, 6)?;
    let ipv4_min = if range_present & NX_NAT_RANGE_IPV4_MIN != 0 {
        Some(Ipv4Addr::from(read_u32(data, 8)?))
    } else {
        None
    };
    Ok(Nat {
        src: flags & NX_NAT_F_SRC != 0,
        dst: flags & NX_NAT_F_DST != 0,
        ipv4_min,
    })
}

#[cfg(all(test, not(clippy)))]
mod tests {
    use super::{ct, nat_bare, nat_src, parse_ct, parse_nat};
    use crate::protocol::action::{parse_actions, Action};
    use crate::protocol::constants::NX_VENDOR_ID;

    #[test]
    fn ct_with_nested_nat_src_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let nat = nat_src("203.0.113.10".parse()?);
        let action = ct(true, 7, None, std::slice::from_ref(&nat))?;

        let mut bytes = Vec::new();
        action.encode(&mut bytes)?;
        let decoded = parse_actions(&bytes)?;
        assert_eq!(decoded.len(), 1);
        let Action::Experimenter { experimenter, data } = &decoded[0] else {
            panic!("expected an experimenter action, got {:?}", decoded[0]);
        };
        assert_eq!(*experimenter, NX_VENDOR_ID);

        let parsed = parse_ct(data)?;
        assert!(parsed.commit);
        assert_eq!(parsed.zone, 7);
        assert_eq!(parsed.recirc_table, 0xff);
        assert_eq!(parsed.nested.len(), 1);

        let Action::Experimenter { data: nat_data, .. } = &parsed.nested[0] else {
            panic!("expected a nested experimenter action");
        };
        let parsed_nat = parse_nat(nat_data)?;
        assert!(parsed_nat.src);
        assert!(!parsed_nat.dst);
        assert_eq!(parsed_nat.ipv4_min, Some("203.0.113.10".parse()?));
        Ok(())
    }

    #[test]
    fn ct_with_recirc_table_and_bare_nat_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let nat = nat_bare();
        let action = ct(false, 3, Some(30), std::slice::from_ref(&nat))?;

        let mut bytes = Vec::new();
        action.encode(&mut bytes)?;
        let decoded = parse_actions(&bytes)?;
        let Action::Experimenter { data, .. } = &decoded[0] else {
            panic!("expected an experimenter action");
        };
        let parsed = parse_ct(data)?;
        assert!(!parsed.commit);
        assert_eq!(parsed.zone, 3);
        assert_eq!(parsed.recirc_table, 30);

        let Action::Experimenter { data: nat_data, .. } = &parsed.nested[0] else {
            panic!("expected a nested experimenter action");
        };
        let parsed_nat = parse_nat(nat_data)?;
        assert!(!parsed_nat.src);
        assert!(!parsed_nat.dst);
        assert_eq!(parsed_nat.ipv4_min, None);
        Ok(())
    }
}
