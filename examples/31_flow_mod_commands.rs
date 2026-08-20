//! The flow-mod commands beyond `OFPFC_ADD`: modify, modify-strict,
//! delete and delete-strict — and what "strict" changes.
//!
//! `Rule::add` and `Rule::delete` are constructors for the two common
//! cases; every other command is the same struct with a different
//! `command` field.
//!
//! **Strict vs non-strict** is the thing to remember: a non-strict
//! modify or delete treats its match as a *filter* and hits every entry
//! the filter covers, ignoring priority. A strict one requires the match
//! **and the priority** to be exactly equal, so it hits at most one
//! entry. Use strict whenever you mean a specific flow.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 31_flow_mod_commands
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::{
    ETH_TYPE_IPV4, OFPFC_DELETE_STRICT, OFPFC_MODIFY_STRICT, OFPG_ANY, OFPMP_FLOW_DESC, OFPP_ANY,
    OFPTT_ALL,
};
use openflow::protocol::control::{FlowStatsRequest, MultipartReplyBody, MultipartRequestBody};
use openflow::protocol::instruction::Instruction;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::rule::Rule;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

fn ipv4() -> Match {
    Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)])
}

/// List what is installed, so each step's effect is visible.
async fn show<S>(client: &mut Connection<S>, label: &str) -> Result<(), Box<dyn std::error::Error>>
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
    let reply = client.multipart_request(OFPMP_FLOW_DESC, &request).await?;
    if let MultipartReplyBody::FlowDesc(entries) = reply {
        info!("{label}: {} flow(s)", entries.len());
        for entry in &entries {
            info!(
                "    priority={} cookie={:#x} instructions={}",
                entry.priority,
                entry.cookie,
                entry.instructions.len()
            );
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    // Two entries with the same match but different priorities — the
    // setup that makes strict-vs-non-strict visible.
    client
        .add_flow(Rule::add(0, 0, 700, ipv4(), Vec::new()).with_cookie(0x1111))
        .await?;
    client
        .add_flow(Rule::add(0, 0, 701, ipv4(), Vec::new()).with_cookie(0x2222))
        .await?;
    show(&mut client, "after two adds").await?;

    // OFPFC_MODIFY_STRICT: same match *and* priority 700, so only the
    // first entry gets the new instructions. A plain OFPFC_MODIFY here
    // would have rewritten both.
    //
    // Note a modify replaces the instructions but keeps the entry's
    // counters and timers — unlike a delete-then-add.
    let mut modify = Rule::add(
        0,
        0,
        700,
        ipv4(),
        vec![Instruction::apply_actions(vec![
            Action::output_controller_no_buffer(),
        ])],
    );
    modify.command = OFPFC_MODIFY_STRICT;
    modify.cookie = 0x3333;
    client.send_flow_mod(modify).await?;
    client.send_barrier().await?;
    show(&mut client, "after modify-strict of priority 700").await?;

    // OFPFC_DELETE_STRICT: removes priority 700 and leaves 701 alone.
    // `Rule::delete` defaults cookie_mask to u64::MAX, which would
    // restrict this to cookie 0 — clear it to delete regardless.
    let mut delete = Rule::delete(0, 0, ipv4());
    delete.command = OFPFC_DELETE_STRICT;
    delete.priority = 700;
    delete.cookie = 0;
    delete.cookie_mask = 0;
    client.send_flow_mod(delete).await?;
    client.send_barrier().await?;
    show(&mut client, "after delete-strict of priority 700").await?;

    // Non-strict delete with the same match ignores priority and takes
    // the rest. `delete_flows(None)` is the shorthand for "everything".
    client.delete_flows(None).await?;
    show(&mut client, "after deleting everything").await?;

    Ok(())
}
