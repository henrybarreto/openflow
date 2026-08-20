//! Abandon a bundle with `OFPBCT_DISCARD_REQUEST`: stage flow-mods, then
//! throw them away without applying any of them.
//!
//! The counterpart to `14_bundle`'s commit. Discard is what makes a
//! bundle a transaction rather than a batch — a controller that decides
//! mid-way it cannot finish leaves the switch exactly as it found it.
//!
//! The flow table is listed before, during and after to prove the point:
//! messages added to an open bundle have *no* effect until commit.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 34_bundle_discard
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::{
    ETH_TYPE_ARP, ETH_TYPE_IPV4, OFPG_ANY, OFPMP_FLOW_DESC, OFPP_ANY, OFPTT_ALL,
};
use openflow::protocol::control::{FlowStatsRequest, MultipartReplyBody, MultipartRequestBody};
use openflow::protocol::instruction::Instruction;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::rule::Rule;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

const BUNDLE_ID: u32 = 77;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

async fn flow_count<S>(client: &mut Connection<S>) -> Result<usize, Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = MultipartRequestBody::FlowStats(FlowStatsRequest {
        table_id: OFPTT_ALL,
        out_port: OFPP_ANY,
        out_group: OFPG_ANY,
        cookie: 0,
        cookie_mask: 0,
        of_match: Vec::new(),
    });
    match client.multipart_request(OFPMP_FLOW_DESC, &request).await? {
        MultipartReplyBody::FlowDesc(entries) => Ok(entries.len()),
        other => Err(format!("unexpected multipart body: {other:?}").into()),
    }
}

fn forward(priority: u16, eth_type: u16, out_port: u32) -> Rule {
    Rule::add(
        0,
        0,
        priority,
        Match::new(vec![oxm::eth_type(eth_type)]),
        vec![Instruction::apply_actions(vec![Action::output(out_port)])],
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    let before = flow_count(&mut client).await?;
    info!("{before} flow(s) before the bundle");

    client.bundle_open(BUNDLE_ID, 0).await?;
    for (priority, eth_type, port) in [(200, ETH_TYPE_ARP, 1), (100, ETH_TYPE_IPV4, 2)] {
        client
            .bundle_add_flow_mod(BUNDLE_ID, 0, forward(priority, eth_type, port))
            .await?;
    }
    info!("staged 2 flow-mods in bundle {BUNDLE_ID}");

    // Still nothing installed: a bundle's messages are held, not applied.
    let staged = flow_count(&mut client).await?;
    info!("{staged} flow(s) while the bundle is open (unchanged)");

    // Throw the whole thing away. `bundle_commit` here would have
    // installed both instead.
    client.bundle_discard(BUNDLE_ID, 0).await?;
    let after = flow_count(&mut client).await?;
    info!("{after} flow(s) after discarding the bundle");

    if before == after {
        info!("nothing was applied — the bundle rolled back cleanly");
    } else {
        info!("unexpected: the flow table changed across a discarded bundle");
    }

    // The bundle id is free again once discarded, so the same id can open
    // a fresh bundle immediately.
    client.bundle_open(BUNDLE_ID, 0).await?;
    client.bundle_discard(BUNDLE_ID, 0).await?;
    info!("bundle {BUNDLE_ID} reopened and discarded again");

    Ok(())
}
