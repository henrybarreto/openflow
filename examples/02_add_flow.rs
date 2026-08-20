//! Install a flow rule that forwards IPv4 traffic out a fixed port.
//!
//! Builds an `OpenFlow` match on `eth_type == IPv4`, an `apply-actions`
//! instruction that outputs to port 2, and installs it with
//! `Connection::add_flow`, which sends the flow-mod and then blocks on a
//! barrier reply so the rule is guaranteed installed before the example
//! exits.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 02_add_flow
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::ETH_TYPE_IPV4;
use openflow::protocol::instruction::Instruction;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::rule::Rule;
use tracing::info;

const OUT_PORT: u32 = 2;
const TABLE_ID: u8 = 0;
const PRIORITY: u16 = 100;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    let of_match = Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]);
    let instructions = vec![Instruction::apply_actions(vec![Action::output(OUT_PORT)])];

    // `xid` is filled in by `Connection::send_flow_mod`; the value passed to
    // `Rule::add` here is irrelevant.
    let flow = Rule::add(0, TABLE_ID, PRIORITY, of_match, instructions);

    client.add_flow(flow).await?;
    info!("installed flow: eth_type=IPv4 -> output(port={OUT_PORT})");

    Ok(())
}
