//! Install a flow, then read it back via an `OFPMP_FLOW_DESC` multipart
//! request.
//!
//! `OFPMP_FLOW_DESC` (multipart type 1) is the widely-implemented
//! `OpenFlow` 1.5 way to list installed flow entries — the newer
//! `OFPMP_FLOW_STATS` (type 17) that carries live counters alongside the
//! entry is a later addition many switches, including Open vSwitch, don't
//! implement yet.
//!
//! `Connection::multipart_request` sends the request and reassembles the
//! reply across as many `OFPMPF_REPLY_MORE`-flagged messages as the switch
//! sends back, up to a 30s default timeout.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 05_flow_stats
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::{
    ETH_TYPE_IPV4, OFPG_ANY, OFPMP_FLOW_DESC, OFPP_ANY, OFPTT_ALL,
};
use openflow::protocol::control::{FlowStatsRequest, MultipartReplyBody, MultipartRequestBody};
use openflow::protocol::instruction::Instruction;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::rule::Rule;
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

    let of_match = Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]);
    let instructions = vec![Instruction::apply_actions(vec![Action::output(2)])];
    client
        .add_flow(Rule::add(0, 0, 100, of_match, instructions))
        .await?;

    // `of_match` here is the raw OXM TLV list only (no `ofp_match` header,
    // no padding) — the same shape `Match::new` takes, flattened. An empty
    // list matches every flow, mirroring `Match::any()`.
    let request = MultipartRequestBody::FlowStats(FlowStatsRequest {
        table_id: OFPTT_ALL,
        out_port: OFPP_ANY,
        out_group: OFPG_ANY,
        cookie: 0,
        cookie_mask: 0,
        of_match: Vec::new(),
    });

    let reply = client.multipart_request(OFPMP_FLOW_DESC, &request).await?;
    let MultipartReplyBody::FlowDesc(entries) = reply else {
        info!("switch replied with an unexpected multipart body: {reply:?}");
        return Ok(());
    };

    info!("{} flow(s) installed", entries.len());
    for entry in &entries {
        info!(
            "table={} priority={} cookie=0x{:016x} idle_timeout={} match_len={}",
            entry.table_id,
            entry.priority,
            entry.cookie,
            entry.idle_timeout,
            entry.of_match.len(),
        );
    }

    Ok(())
}
