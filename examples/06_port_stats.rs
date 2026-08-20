//! Query per-port counters via an `OFPMP_PORT_STATS` multipart request.
//!
//! `PortMultipartRequest { port_no: OFPP_ANY }` asks for every port in one
//! shot; pass a specific port number instead to scope the request to a
//! single interface.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 06_port_stats
//! ```

use openflow::client::Connection;
use openflow::protocol::constants::{OFPMP_PORT_STATS, OFPP_ANY};
use openflow::protocol::control::{MultipartReplyBody, MultipartRequestBody, PortMultipartRequest};
use tracing::info;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    let request = MultipartRequestBody::Port(PortMultipartRequest { port_no: OFPP_ANY });
    let reply = client.multipart_request(OFPMP_PORT_STATS, &request).await?;
    let MultipartReplyBody::PortStats(entries) = reply else {
        info!("switch replied with an unexpected multipart body: {reply:?}");
        return Ok(());
    };

    for entry in &entries {
        info!(
            "port={} rx_packets={} tx_packets={} rx_bytes={} tx_bytes={} rx_errors={} tx_errors={}",
            entry.port_no,
            entry.rx_packets,
            entry.tx_packets,
            entry.rx_bytes,
            entry.tx_bytes,
            entry.rx_errors,
            entry.tx_errors,
        );
    }

    Ok(())
}
