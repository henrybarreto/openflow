//! List the switch's egress queues with `OFPMP_QUEUE_DESC` and read their
//! counters with `OFPMP_QUEUE_STATS`.
//!
//! Queues are configured out of band (`ovs-vsctl set port ... qos=...`),
//! not through `OpenFlow` — a controller can only inspect them and steer
//! traffic into one with `Action::SetQueue`. A bridge with no `QoS`
//! configured reports no queues, which is a valid empty reply, not an
//! error.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 21_queue_inspect
//! ```

use openflow::client::Connection;
use openflow::protocol::constants::{OFPMP_QUEUE_DESC, OFPMP_QUEUE_STATS, OFPP_ANY, OFPQ_ALL};
use openflow::protocol::control::{
    MultipartReplyBody, MultipartRequestBody, QueueMultipartRequest,
};
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

    // Both wildcards at once: every queue on every port.
    let request = MultipartRequestBody::Queue(QueueMultipartRequest {
        port_no: OFPP_ANY,
        queue_id: OFPQ_ALL,
    });

    let reply = client.multipart_request(OFPMP_QUEUE_DESC, &request).await?;
    if let MultipartReplyBody::QueueDesc(entries) = reply {
        if entries.is_empty() {
            info!("no queues configured on this bridge");
        }
        for entry in &entries {
            info!(
                "port {} queue {} properties={:?}",
                entry.port_no, entry.queue_id, entry.properties
            );
        }
    }

    let reply = client
        .multipart_request(OFPMP_QUEUE_STATS, &request)
        .await?;
    if let MultipartReplyBody::QueueStats(entries) = reply {
        for entry in &entries {
            info!(
                "port {} queue {}: {} packets, {} bytes, {} errors, up {}s",
                entry.port_no,
                entry.queue_id,
                entry.tx_packets,
                entry.tx_bytes,
                entry.tx_errors,
                entry.duration_sec,
            );
        }
    }

    Ok(())
}
