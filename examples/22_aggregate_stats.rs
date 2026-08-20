//! Sum counters across many flows at once with `OFPMP_AGGREGATE_STATS`,
//! and set an explicit deadline with `multipart_request_with_timeout`.
//!
//! Aggregate stats answers "how much traffic matched this *set* of flows"
//! in one message, instead of listing every entry and adding them up. The
//! reply is an OXS list, the same extensible-stat encoding
//! `OFPT_FLOW_REMOVED` uses.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 22_aggregate_stats
//! ```

use std::time::Duration;

use openflow::client::Connection;
use openflow::protocol::constants::{
    ETH_TYPE_IPV4, OFPG_ANY, OFPMP_AGGREGATE_STATS, OFPP_ANY, OFPTT_ALL,
};
use openflow::protocol::control::{FlowStatsRequest, MultipartReplyBody, MultipartRequestBody};
use openflow::protocol::oxm;
use openflow::protocol::oxs;
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

    // Everything: every table, any output port or group, any cookie, and
    // an empty match.
    let all = MultipartRequestBody::FlowStats(FlowStatsRequest {
        table_id: OFPTT_ALL,
        out_port: OFPP_ANY,
        out_group: OFPG_ANY,
        cookie: 0,
        cookie_mask: 0,
        of_match: Vec::new(),
    });

    // `multipart_request` uses a 30s default; this form sets its own.
    let reply = client
        .multipart_request_with_timeout(OFPMP_AGGREGATE_STATS, &all, Duration::from_secs(5))
        .await?;
    report("all flows", &reply);

    // Narrowing the request narrows the sum. Note the match is a flat OXM
    // TLV list here, not an `ofp_match` — the same shape `Match::new`
    // takes, flattened.
    let ipv4_only = MultipartRequestBody::FlowStats(FlowStatsRequest {
        table_id: 0,
        out_port: OFPP_ANY,
        out_group: OFPG_ANY,
        cookie: 0,
        cookie_mask: 0,
        of_match: oxm::eth_type(ETH_TYPE_IPV4),
    });
    let reply = client
        .multipart_request(OFPMP_AGGREGATE_STATS, &ipv4_only)
        .await?;
    report("IPv4 flows in table 0", &reply);

    Ok(())
}

fn report(label: &str, reply: &MultipartReplyBody) {
    let MultipartReplyBody::Aggregate(aggregate) = reply else {
        info!("{label}: unexpected multipart body: {reply:?}");
        return;
    };

    // The counters are OXS TLVs; a switch sends only the ones it keeps.
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let mut flows = 0u32;
    for stat in &aggregate.stats {
        match stat {
            oxs::Tlv::PacketCount(count) => packets = *count,
            oxs::Tlv::ByteCount(count) => bytes = *count,
            oxs::Tlv::FlowCount(count) => flows = *count,
            other => info!("{label}: additional stat {other:?}"),
        }
    }
    info!("{label}: {flows} flow(s), {packets} packet(s), {bytes} byte(s)");
}
