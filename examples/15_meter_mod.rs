//! Rate-limit traffic with a meter: install a 1 Mbit/s drop meter, then a
//! flow that sends IPv4 traffic through it before forwarding.
//!
//! Note `OpenFlow` 1.5 applies a meter with the `OFPAT_METER` *action*
//! (`Action::Meter`), not the 1.3-era `OFPIT_METER` instruction.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 15_meter_mod
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::{ETH_TYPE_IPV4, OFPMC_ADD, OFPMF_KBPS};
use openflow::protocol::control::MeterBand;
use openflow::protocol::instruction::Instruction;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::rule::Rule;
use tracing::info;

const METER_ID: u32 = 1;
const RATE_KBPS: u32 = 1000;
const BURST_KB: u32 = 100;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    // `flags` must name a rate unit; 0 is rejected with OFPMMFC_BAD_FLAGS.
    let bands = [MeterBand::Drop {
        rate: RATE_KBPS,
        burst_size: BURST_KB,
    }];
    client
        .send_meter_mod(OFPMC_ADD, OFPMF_KBPS, METER_ID, &bands)
        .await?;
    // Barrier so a rejected meter surfaces here, not on the next message.
    client.send_barrier().await?;
    info!("installed meter {METER_ID}: drop above {RATE_KBPS} kbps");

    let of_match = Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]);
    let instructions = vec![Instruction::apply_actions(vec![
        Action::Meter(METER_ID),
        Action::output(1),
    ])];
    client
        .add_flow(Rule::add(0, 0, 100, of_match, instructions))
        .await?;
    info!("installed flow: eth_type=IPv4 -> meter({METER_ID}) -> port 1");

    Ok(())
}
