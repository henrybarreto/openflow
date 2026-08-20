//! Craft a raw Ethernet frame and inject it into the switch's pipeline with
//! a `PacketOut`, as if it had just arrived on a port.
//!
//! The frame body itself is built by hand: a 14-byte Ethernet header followed
//! by a payload, which is all a switch needs to look at `eth_type` and act on
//! it.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 13_packet_out
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::{ETH_TYPE_IPV4, OFPP_FLOOD, OFP_NO_BUFFER};
use tracing::info;

const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const BROADCAST_MAC: [u8; 6] = [0xff; 6];

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

fn ethernet_frame() -> Vec<u8> {
    let mut frame = Vec::with_capacity(18);
    frame.extend_from_slice(&BROADCAST_MAC);
    frame.extend_from_slice(&SRC_MAC);
    frame.extend_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(b"example-payload");
    frame
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    // `in_port` has to name a real port: `OFPP_FLOOD` means "every port but
    // the one this arrived on", so with no `in_port` the switch has nothing
    // to exclude and rejects the packet-out outright.
    client
        .send_packet_out(
            OFP_NO_BUFFER,
            Some(1),
            vec![Action::output(OFPP_FLOOD)],
            &ethernet_frame(),
        )
        .await?;
    client.send_barrier().await?;

    info!("injected a synthetic broadcast frame (as if arrived on port 1) and flooded it out every other port");

    Ok(())
}
