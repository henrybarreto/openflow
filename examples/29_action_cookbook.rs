//! Every action type, with what it does to a packet — a reference sheet.
//! Needs no switch.
//!
//! Actions never appear on their own: they are carried by an
//! [`Instruction`], usually `apply_actions` (run now) or `write_actions`
//! (defer to the action set). See `30_pipeline_instructions` for that
//! distinction. Every action here is round-tripped through the encoder
//! and parser, so a wrong recipe fails the example.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example 29_action_cookbook
//! ```

use openflow::protocol::action::{parse_actions, Action};
use openflow::protocol::constants::{
    ETH_TYPE_IPV4, OFPP_ALL, OFPP_CONTROLLER, OFPP_FLOOD, OFPP_IN_PORT, OFPP_NORMAL,
    OFPXMT_OFB_ETH_DST, OFPXMT_OFB_ETH_SRC, OFPXMT_OFB_TCP_DST,
};
use openflow::protocol::oxm;
use tracing::info;

const ETH_TYPE_VLAN: u16 = 0x8100;
const ETH_TYPE_MPLS: u16 = 0x8847;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let recipes: Vec<(&str, Action)> = vec![
        // --- output ----------------------------------------------------
        ("send out port 2", Action::output(2)),
        ("send back where it came from", Action::output(OFPP_IN_PORT)),
        (
            "flood: every port except the ingress and any blocked by STP",
            Action::output(OFPP_FLOOD),
        ),
        ("every port except the ingress", Action::output(OFPP_ALL)),
        (
            "hand to the switch's normal L2/L3 pipeline",
            Action::output(OFPP_NORMAL),
        ),
        (
            "punt the whole packet to the controller",
            Action::output_controller_no_buffer(),
        ),
        (
            "punt only the first 128 bytes",
            Action::Output {
                port: OFPP_CONTROLLER,
                max_len: 128,
            },
        ),
        // --- rewrite a header field ------------------------------------
        // set_field takes one encoded OXM TLV: any oxm:: builder works.
        (
            "rewrite destination IP (NAT-style)",
            Action::SetField(oxm::ipv4_dst([10, 0, 0, 8])),
        ),
        (
            "rewrite destination MAC (routing next-hop)",
            Action::SetField(oxm::eth_dst([0x00, 0x0c, 0x29, 0x01, 0x02, 0x03])),
        ),
        (
            "rewrite TCP destination port",
            Action::SetField(oxm::field(OFPXMT_OFB_TCP_DST, &8080u16.to_be_bytes())?),
        ),
        // --- copy one field into another -------------------------------
        (
            "copy 48 bits of eth_src into eth_dst (reflect)",
            Action::CopyField {
                n_bits: 48,
                src_offset: 0,
                dst_offset: 0,
                oxm_ids: oxm::copy_field_ids(OFPXMT_OFB_ETH_SRC, 6, OFPXMT_OFB_ETH_DST, 6),
            },
        ),
        // --- tags ------------------------------------------------------
        // Push then set: a pushed tag starts with a default value, so a
        // real "add VLAN 100" is PushVlan followed by a SetField.
        ("push a VLAN tag", Action::PushVlan(ETH_TYPE_VLAN)),
        ("pop the outermost VLAN tag", Action::PopVlan),
        ("push an MPLS shim", Action::PushMpls(ETH_TYPE_MPLS)),
        (
            "pop MPLS, revealing an IPv4 packet",
            Action::PopMpls(ETH_TYPE_IPV4),
        ),
        ("push a PBB service tag", Action::PushPbb(0x88e7)),
        ("pop the PBB tag", Action::PopPbb),
        // --- TTL -------------------------------------------------------
        ("decrement IP TTL (what a router does)", Action::DecNwTtl),
        ("set IP TTL to 64", Action::SetNwTtl(64)),
        ("decrement MPLS TTL", Action::DecMplsTtl),
        ("set MPLS TTL to 32", Action::SetMplsTtl(32)),
        (
            "copy TTL outward, into a newly pushed header",
            Action::CopyTtlOut,
        ),
        ("copy TTL inward, before popping", Action::CopyTtlIn),
        // --- QoS and indirection ---------------------------------------
        (
            "queue this on egress queue 3 (set before the output action)",
            Action::SetQueue(3),
        ),
        ("rate-limit through meter 1", Action::Meter(1)),
        (
            "process through group 1 (ECMP, flooding, failover)",
            Action::Group(1),
        ),
        // --- vendor ----------------------------------------------------
        (
            "a vendor action (see 36_conntrack for a real one)",
            Action::Experimenter {
                experimenter: 0x0000_2320, // Nicira
                data: vec![0, 0, 0, 0],
            },
        ),
    ];

    for (label, action) in &recipes {
        let mut encoded = Vec::new();
        action.encode(&mut encoded)?;

        // Decode it back and re-encode: proves the recipe is well-formed
        // on the wire. Compare the *bytes*, not the values — a decoded
        // `CopyField` keeps the action's trailing padding inside
        // `oxm_ids`, so it is byte-identical without being `==`.
        let decoded = parse_actions(&encoded)?;
        let mut reencoded = Vec::new();
        for action in &decoded {
            action.encode(&mut reencoded)?;
        }
        if reencoded != encoded {
            return Err(format!("{label}: did not round-trip: {decoded:?}").into());
        }

        info!("{label}: {} byte(s) on the wire", encoded.len());
    }

    info!("{} actions, all round-tripped", recipes.len());
    Ok(())
}
