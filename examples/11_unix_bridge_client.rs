//! Connect to a local Open vSwitch bridge over its Unix management socket
//! instead of TCP.
//!
//! `Connection::connect_bridge` is a shortcut for
//! `Connection::connect_unix("/run/openvswitch/<bridge>.mgmt")`, which is
//! the path Open vSwitch exposes for direct, same-host management access.
//! Reading that socket typically requires belonging to the `openvswitch`
//! group (or root).
//!
//! Run with:
//!
//! ```sh
//! OFBRIDGE=br0 cargo run --example 11_unix_bridge_client
//! ```

use openflow::client::Connection;
use tracing::info;

fn bridge_name() -> String {
    std::env::var("OFBRIDGE").unwrap_or_else(|_| "br0".to_owned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let bridge = bridge_name();
    let client = Connection::connect_bridge(&bridge).await?;
    info!("handshake complete over the Unix management socket for bridge {bridge:?}");

    if let Some(features) = client.features() {
        info!(
            "datapath_id={:016x} n_tables={}",
            features.datapath_id, features.n_tables
        );
    }

    Ok(())
}
