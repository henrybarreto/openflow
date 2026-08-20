//! Subscribe to flow-table changes with `OFPMP_FLOW_MONITOR`: instead of
//! polling flow stats, ask the switch to push an update whenever a
//! matching entry is added, modified or removed.
//!
//! Not every switch implements this. A clean `OFPET_BAD_REQUEST` or
//! `OFPET_FLOW_MONITOR_FAILED` rejection is the documented outcome on
//! those, so this example treats it as a result to report rather than a
//! crash — the pattern to copy whenever you use an optional subtype.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 23_flow_monitor
//! ```

use openflow::client::{Connection, Error};
use openflow::protocol::action::Action;
use openflow::protocol::constants::{
    ETH_TYPE_IPV4, OFPFMC_ADD, OFPFMF_ADD, OFPFMF_INSTRUCTIONS, OFPFMF_REMOVED, OFPG_ANY,
    OFPMP_FLOW_MONITOR, OFPP_ANY, OFPTT_ALL,
};
use openflow::protocol::control::{
    FlowMonitorRequest, FlowMonitorUpdate, MultipartReplyBody, MultipartRequestBody,
};
use openflow::protocol::error_msg::ErrorType;
use openflow::protocol::instruction::Instruction;
use openflow::protocol::message::Message;
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

    // Watch every table for adds and removals, and ask for each entry's
    // instructions in the update.
    let request = MultipartRequestBody::FlowMonitor(FlowMonitorRequest {
        monitor_id: 1,
        out_port: OFPP_ANY,
        out_group: OFPG_ANY,
        flags: OFPFMF_ADD | OFPFMF_REMOVED | OFPFMF_INSTRUCTIONS,
        table_id: OFPTT_ALL,
        command: OFPFMC_ADD,
        of_match: Vec::new(),
    });

    // The reply to the request itself carries the *initial* state.
    match client.multipart_request(OFPMP_FLOW_MONITOR, &request).await {
        Ok(MultipartReplyBody::FlowMonitor(updates)) => {
            info!("monitor installed; {} initial update(s)", updates.len());
            for update in &updates {
                describe(update);
            }
        }
        Ok(other) => {
            info!("unexpected multipart body: {other:?}");
            return Ok(());
        }
        Err(Error::Remote {
            error_type, code, ..
        }) => {
            // Expected on switches without flow-monitor support.
            info!(
                "this switch does not support OFPMP_FLOW_MONITOR: {:?}",
                ErrorType::parse(error_type, code)
            );
            return Ok(());
        }
        Err(other) => return Err(other.into()),
    }

    // Changing the table now produces pushed updates on the same
    // connection, arriving as further multipart replies.
    let flow = Rule::add(
        0,
        0,
        200,
        Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]),
        vec![Instruction::apply_actions(vec![Action::output(1)])],
    );
    client.add_flow(flow).await?;
    info!("installed a flow; watching for pushed updates (Ctrl-C to stop)");

    loop {
        let Message::MultipartReply(message) = client.recv_message().await? else {
            continue;
        };
        match message.typed_reply_body()? {
            MultipartReplyBody::FlowMonitor(updates) => updates.iter().for_each(describe),
            other => info!("other multipart reply: {other:?}"),
        }
    }
}

fn describe(update: &FlowMonitorUpdate) {
    match update {
        FlowMonitorUpdate::Full {
            event,
            table_id,
            priority,
            cookie,
            instructions,
            ..
        } => info!(
            "event={event} table={table_id} priority={priority} cookie={cookie:#x} \
             instructions={}",
            instructions.len()
        ),
        // The switch abbreviates changes this controller made itself.
        FlowMonitorUpdate::Abbrev { xid } => info!("our own change, xid={xid}"),
        FlowMonitorUpdate::Paused { event } => {
            info!("monitor paused/resumed (event={event}) — the switch fell behind");
        }
        FlowMonitorUpdate::Raw { event, .. } => info!("unmodelled event {event}"),
    }
}
