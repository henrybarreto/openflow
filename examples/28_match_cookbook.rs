//! Every match shape in one place, with its prerequisites — a reference
//! sheet rather than a program. Needs no switch.
//!
//! The one rule that catches everyone: a field that only exists inside
//! another protocol requires that protocol to be matched first.
//! `ipv4_src` needs `eth_type(IPv4)` ahead of it; `tcp_dst` needs that
//! *and* `ip_proto(6)`. Get it wrong and the switch answers
//! `OFPET_BAD_MATCH`/`OFPBMC_BAD_PREREQ`. Each entry below is run through
//! `oxm::parse_oxm_list`, which enforces exactly those rules, so this
//! example fails loudly if any recipe here is wrong.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example 28_match_cookbook
//! ```

use openflow::protocol::constants::{
    ETH_TYPE_ARP, ETH_TYPE_IPV4, OFPXMT_OFB_MPLS_LABEL, OFPXMT_OFB_TCP_DST, OFPXMT_OFB_TUNNEL_ID,
    OFPXMT_OFB_UDP_DST, OFPXMT_OFB_VLAN_VID,
};
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use tracing::info;

/// `EtherType`s the crate has no constant for.
const ETH_TYPE_IPV6: u16 = 0x86dd;
const ETH_TYPE_MPLS: u16 = 0x8847;

/// IP protocol numbers.
const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const IP_PROTO_ICMPV6: u8 = 58;

/// `OFPVID_PRESENT`: set in a VLAN id to mean "tagged". Matching VLAN 100
/// means matching `OFPVID_PRESENT | 100`.
const OFPVID_PRESENT: u16 = 0x1000;

type Recipe = (&'static str, Vec<Vec<u8>>);

/// The recipes themselves: a label and the OXM TLVs it is made of.
fn recipes() -> Result<Vec<Recipe>, Box<dyn std::error::Error>> {
    Ok(vec![
        // --- no prerequisites ------------------------------------------
        ("everything (table-miss; use priority 0)", vec![]),
        ("ingress port 3", vec![oxm::in_port(3)]),
        (
            "destination MAC",
            vec![oxm::eth_dst([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])],
        ),
        (
            "source MAC",
            vec![oxm::eth_src([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])],
        ),
        ("all IPv4", vec![oxm::eth_type(ETH_TYPE_IPV4)]),
        // --- masked: match a prefix, not an exact value ----------------
        (
            "IPv4 source in 10.0.0.0/8",
            vec![
                oxm::eth_type(ETH_TYPE_IPV4),
                oxm::ipv4_src_masked([10, 0, 0, 0], [255, 0, 0, 0]),
            ],
        ),
        (
            "IPv4 destination in 192.168.1.0/24",
            vec![
                oxm::eth_type(ETH_TYPE_IPV4),
                oxm::ipv4_dst_masked([192, 168, 1, 0], [255, 255, 255, 0]),
            ],
        ),
        // --- L4: needs eth_type *and* ip_proto -------------------------
        (
            "HTTP (TCP port 80)",
            vec![
                oxm::eth_type(ETH_TYPE_IPV4),
                oxm::ip_proto(IP_PROTO_TCP),
                oxm::field(OFPXMT_OFB_TCP_DST, &80u16.to_be_bytes())?,
            ],
        ),
        (
            "DNS (UDP port 53)",
            vec![
                oxm::eth_type(ETH_TYPE_IPV4),
                oxm::ip_proto(IP_PROTO_UDP),
                oxm::field(OFPXMT_OFB_UDP_DST, &53u16.to_be_bytes())?,
            ],
        ),
        (
            "ICMP echo request",
            vec![
                oxm::eth_type(ETH_TYPE_IPV4),
                oxm::ip_proto(IP_PROTO_ICMP),
                oxm::icmpv4_type(8),
                oxm::icmpv4_code(0),
            ],
        ),
        // --- ARP: its own EtherType ------------------------------------
        (
            "ARP requests for 10.0.0.1",
            vec![
                oxm::eth_type(ETH_TYPE_ARP),
                oxm::arp_op(1),
                oxm::arp_tpa([10, 0, 0, 1]),
            ],
        ),
        // --- IPv6 and neighbour discovery ------------------------------
        (
            "IPv6 to 2001:db8::1",
            vec![
                oxm::eth_type(ETH_TYPE_IPV6),
                oxm::ipv6_dst([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            ],
        ),
        (
            "IPv6 neighbour solicitation (ICMPv6 type 135)",
            vec![
                oxm::eth_type(ETH_TYPE_IPV6),
                oxm::ip_proto(IP_PROTO_ICMPV6),
                oxm::icmpv6_type(135),
                oxm::ipv6_nd_target([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            ],
        ),
        // --- tags and tunnels ------------------------------------------
        (
            "VLAN 100 (OFPVID_PRESENT must be set)",
            vec![oxm::field(
                OFPXMT_OFB_VLAN_VID,
                &(OFPVID_PRESENT | 0x0064).to_be_bytes(),
            )?],
        ),
        (
            "MPLS label 500",
            vec![
                oxm::eth_type(ETH_TYPE_MPLS),
                oxm::field(OFPXMT_OFB_MPLS_LABEL, &500u32.to_be_bytes())?,
            ],
        ),
        (
            "tunnel id 0x2a (VXLAN VNI and friends)",
            vec![oxm::field(OFPXMT_OFB_TUNNEL_ID, &42u64.to_be_bytes())?],
        ),
    ])
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    for (label, oxms) in recipes()? {
        let of_match = Match::new(oxms.clone());

        // The same validation a switch performs: unknown fields, bad
        // lengths, duplicates and missing prerequisites all fail here.
        let flat: Vec<u8> = oxms.concat();
        oxm::parse_oxm_list(&flat)
            .map_err(|err| format!("{label}: this recipe is invalid: {err}"))?;

        let mut encoded = Vec::new();
        of_match.encode(&mut encoded)?;
        info!(
            "{label}: {} field(s), {} encoded byte(s)",
            of_match.oxms.len(),
            encoded.len()
        );
    }

    info!("every recipe satisfies the spec's prerequisite rules");
    Ok(())
}
