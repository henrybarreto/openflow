//! Install a `SELECT` group (equal-weight ECMP-style load balancing across
//! two output ports) and a flow that forwards IPv4 traffic through it.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 12_group_mod
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::ETH_TYPE_IPV4;
use openflow::protocol::control::{Bucket, BucketProperty, GroupMod};
use openflow::protocol::instruction::Instruction;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::rule::Rule;
use tracing::info;

const GROUP_TYPE_SELECT: u8 = 1;
const GROUP_ID: u32 = 1;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

fn bucket(bucket_id: u32, out_port: u32) -> Bucket {
    Bucket {
        bucket_id,
        actions: vec![Action::output(out_port)],
        properties: vec![BucketProperty::Weight(1)],
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    let group_mod = GroupMod::add(
        0,
        GROUP_TYPE_SELECT,
        GROUP_ID,
        vec![bucket(1, 2), bucket(2, 3)],
    );
    client.add_group(group_mod).await?;
    info!("installed select group {GROUP_ID} balancing across ports 2 and 3");

    let of_match = Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]);
    let instructions = vec![Instruction::apply_actions(vec![Action::Group(GROUP_ID)])];
    let flow = Rule::add(0, 0, 100, of_match, instructions);
    client.add_flow(flow).await?;
    info!("installed flow: eth_type=IPv4 -> group({GROUP_ID})");

    Ok(())
}
