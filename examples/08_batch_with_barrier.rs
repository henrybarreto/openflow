//! Send several flow-mods back to back and only synchronize once, with a
//! single trailing barrier.
//!
//! `Connection::add_flow` is convenient for a single rule because it sends
//! a flow-mod and immediately waits for the matching barrier reply. When
//! installing a batch, waiting after every single flow-mod is wasted
//! round-trips: it's cheaper to fire off `send_flow_mod` repeatedly and
//! call `send_barrier` once at the end, which still guarantees the switch
//! has applied every one of them before this function returns.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 08_batch_with_barrier
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::{ETH_TYPE_ARP, ETH_TYPE_IPV4};
use openflow::protocol::instruction::Instruction;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::rule::Rule;
use tracing::info;

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

    let rules = vec![
        forward_rule(200, ETH_TYPE_ARP, 1),
        forward_rule(100, ETH_TYPE_IPV4, 2),
    ];
    let installed = rules.len();

    for rule in rules {
        client.send_flow_mod(rule).await?;
    }
    client.send_barrier().await?;

    info!("{installed} flow(s) installed and confirmed by a single barrier reply");

    Ok(())
}
