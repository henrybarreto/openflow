//! Connect to a switch and perform the `OpenFlow` handshake.
//!
//! The switch here is anything speaking `OpenFlow` 1.5 that accepts an
//! incoming TCP connection on `OFPORT_ADDR` — for example an Open vSwitch
//! bridge configured as a passive listener:
//!
//! ```sh
//! ovs-vsctl set-controller br0 ptcp:6653:0.0.0.0
//! ```
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 01_handshake
//! ```

use openflow::client::Connection;
use tracing::info;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    info!("connecting to switch at {addr}");

    let client = Connection::connect_tcp(&addr).await?;

    if let Some(features) = client.features() {
        info!(
            "handshake complete: datapath_id={:016x} n_tables={} n_buffers={} auxiliary_id={}",
            features.datapath_id, features.n_tables, features.n_buffers, features.auxiliary_id
        );
    } else {
        info!("handshake complete, but no features reply was recorded");
    }

    Ok(())
}
