//! Stateful firewalling with Open vSwitch's connection-tracking
//! extension: `ct()` and `nat()` actions, and `ct_state` / `ct_zone`
//! match fields.
//!
//! **This is not standard `OpenFlow`.** Mainline 1.5 has no notion of
//! connection tracking; these ride as Nicira experimenter actions and
//! under Nicira's own OXM class, and only Open vSwitch understands them.
//! Any other switch will answer `OFPET_BAD_ACTION` or `OFPBMC_BAD_FIELD`.
//!
//! The classic use is "allow replies to connections we started": send
//! packets through `ct()` to learn their state, then match `ct_state` to
//! tell a new connection from an established one.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 36_conntrack
//! ```

use openflow::client::{Connection, Error};
use openflow::protocol::action::Action;
use openflow::protocol::constants::{ETH_TYPE_IPV4, NX_CS_NEW, NX_CS_RPL, NX_CS_TRK};
use openflow::protocol::error_msg::ErrorType;
use openflow::protocol::instruction::Instruction;
use openflow::protocol::nicira;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::rule::Rule;
use tracing::info;

const ZONE: u16 = 1;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    // 1. Commit outbound connections to the tracker, source-NATing them.
    // `nat()` is only meaningful nested inside a `ct()` — it is never a
    // top-level action.
    let nat = nicira::nat_src("203.0.113.5".parse()?);
    let commit = nicira::ct(true, ZONE, None, std::slice::from_ref(&nat))?;
    let outbound = Rule::add(
        0,
        0,
        900,
        Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4), oxm::in_port(1)]),
        vec![Instruction::apply_actions(vec![commit, Action::output(2)])],
    );
    match client.add_flow(outbound).await {
        Ok(()) => info!("committing ct() with nested nat() installed"),
        Err(Error::Remote {
            error_type, code, ..
        }) => {
            info!(
                "this switch does not support the Nicira conntrack extension: {:?}",
                ErrorType::parse(error_type, code)
            );
            info!("(expected on anything that is not Open vSwitch)");
            return Ok(());
        }
        Err(other) => return Err(other.into()),
    }

    // 2. Allow the replies. `ct_state` is a bitmask, so it is always
    // matched masked: the value says which bits must be set, the mask
    // says which bits are examined at all.
    //
    // `+trk` is the gate bit — an untracked packet has no other ct_state
    // bit meaningfully set, so always require it alongside whatever else
    // you match. This crate defines the three bits it verified against
    // OVS (`NX_CS_NEW`, `NX_CS_RPL`, `NX_CS_TRK`); for any other bit from
    // `ovs-fields(7)`, pass the raw value to `oxm::ct_state_masked`.
    let reply_direction = NX_CS_TRK | NX_CS_RPL;
    let allow_replies = Rule::add(
        0,
        0,
        901,
        Match::new(vec![
            oxm::eth_type(ETH_TYPE_IPV4),
            oxm::ct_state_masked(reply_direction, reply_direction),
            oxm::ct_zone(ZONE),
        ]),
        vec![Instruction::apply_actions(vec![Action::output(1)])],
    );
    client.add_flow(allow_replies).await?;
    info!("reply traffic (ct_state=+trk+rpl) allowed back");

    // 3. Punt genuinely new inbound connections to the controller to
    // decide about: tracked and new, but *not* a reply — hence the wider
    // mask than value.
    let new_inbound = Rule::add(
        0,
        0,
        902,
        Match::new(vec![
            oxm::eth_type(ETH_TYPE_IPV4),
            oxm::ct_state_masked(NX_CS_TRK | NX_CS_NEW, NX_CS_TRK | NX_CS_NEW | NX_CS_RPL),
            oxm::ct_zone(ZONE),
        ]),
        vec![Instruction::apply_actions(vec![
            Action::output_controller_no_buffer(),
        ])],
    );
    client.add_flow(new_inbound).await?;
    info!("new inbound connections (ct_state=+trk+new) punted to the controller");

    // 4. A recirculating ct(): instead of continuing the current action
    // list, resubmit the packet to another table once tracking is known.
    let recirculate = nicira::ct(false, ZONE, Some(1), &[])?;
    let lookup = Rule::add(
        0,
        0,
        800,
        Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]),
        vec![Instruction::apply_actions(vec![recirculate])],
    );
    client.add_flow(lookup).await?;
    info!("recirculating ct() installed: tracking happens, then table 1 decides");

    Ok(())
}
