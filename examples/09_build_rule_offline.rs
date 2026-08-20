//! Build a richer flow-mod entirely offline — no switch connection needed —
//! to show how matches, actions, and instructions compose.
//!
//! The rule below matches TCP port-80 traffic over IPv4 and rewrites the
//! destination address before forwarding it on, all in one table:
//!
//! - match: `eth_type=IPv4, ip_proto=TCP, tcp_dst=80`
//! - `apply-actions`: `set_field(ipv4_dst=10.0.0.8)`
//! - `goto-table`: `1`
//!
//! `oxm::field` builds an OXM TLV for any field id/value pair the typed
//! helpers (`oxm::eth_type`, `oxm::ipv4_dst`, ...) don't cover directly —
//! here that's `tcp_dst`, since there's no dedicated helper for it yet.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example 09_build_rule_offline
//! ```

use openflow::protocol::action::Action;
use openflow::protocol::constants::{ETH_TYPE_IPV4, OFPXMT_OFB_TCP_DST};
use openflow::protocol::instruction::Instruction;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::rule::Rule;
use tracing::info;

const TCP_PROTO: u8 = 6;
const HTTP_PORT: u16 = 80;
const NAT_TARGET: [u8; 4] = [10, 0, 0, 8];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let of_match = Match::new(vec![
        oxm::eth_type(ETH_TYPE_IPV4),
        oxm::ip_proto(TCP_PROTO),
        oxm::field(OFPXMT_OFB_TCP_DST, &HTTP_PORT.to_be_bytes())?,
    ]);

    let instructions = vec![
        Instruction::apply_actions(vec![Action::SetField(oxm::ipv4_dst(NAT_TARGET))]),
        Instruction::GotoTable(1),
    ];

    let rule = Rule::add(1, 0, 300, of_match, instructions);
    let frame = rule.encode()?;
    let preview = frame.get(..frame.len().min(16)).unwrap_or_default();

    info!(
        "encoded flow-mod: {} bytes, first 16: {:02x?}",
        frame.len(),
        preview
    );
    Ok(())
}
