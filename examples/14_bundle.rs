//! Install two flow-mods atomically using an `OpenFlow` bundle: open a
//! bundle, add both flow-mods to it unapplied, then commit — the switch
//! applies every message in the bundle together, or none of it.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 14_bundle
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::{ETH_TYPE_ARP, ETH_TYPE_IPV4};
use openflow::protocol::instruction::Instruction;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::rule::Rule;
use tracing::info;

const BUNDLE_ID: u32 = 1;
const TABLE_ID: u8 = 0;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

fn forward_rule(priority: u16, eth_type: u16, out_port: u32) -> Rule {
    Rule::add(
        0,
        TABLE_ID,
        priority,
        Match::new(vec![oxm::eth_type(eth_type)]),
        vec![Instruction::apply_actions(vec![Action::output(out_port)])],
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    client.bundle_open(BUNDLE_ID, 0).await?;

    for (priority, eth_type, out_port) in [(200, ETH_TYPE_ARP, 1), (100, ETH_TYPE_IPV4, 2)] {
        client
            .bundle_add_flow_mod(BUNDLE_ID, 0, forward_rule(priority, eth_type, out_port))
            .await?;
    }

    client.bundle_commit(BUNDLE_ID, 0).await?;

    info!("bundle {BUNDLE_ID} committed: 2 flow-mods applied atomically");

    Ok(())
}
