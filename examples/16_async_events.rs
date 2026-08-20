//! Subscribe to asynchronous switch events and print them as they arrive.
//!
//! A fresh connection does *not* reliably get `FLOW_REMOVED` or
//! `PORT_STATUS` until it asks: `enable_all_async_events` sends the
//! `OFPT_SET_ASYNC` that turns them on. To see one immediately, this also
//! installs a table-miss flow with a 10 s idle timeout and
//! `OFPFF_SEND_FLOW_REM`, so the switch reports its expiry.
//!
//! Runs until Ctrl-C. Try `ovs-vsctl add-port`/`del-port` on the bridge
//! while it runs to see `PORT_STATUS` events.
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 16_async_events
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::{OFPFF_SEND_FLOW_REM, OFPP_CONTROLLER};
use openflow::protocol::instruction::Instruction;
use openflow::protocol::message::Message;
use openflow::protocol::ofmatch::Match;
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

    client.enable_all_async_events().await?;
    info!("async config now: {:?}", client.get_async().await?);

    let mut flow = Rule::add(
        0,
        0,
        0,
        Match::new(vec![]),
        vec![Instruction::apply_actions(vec![Action::output(
            OFPP_CONTROLLER,
        )])],
    );
    flow.idle_timeout = 10;
    flow.flags = OFPFF_SEND_FLOW_REM;
    client.add_flow(flow).await?;
    info!("table-miss flow installed; expires 10 s after the last match");

    loop {
        match client.recv_message().await? {
            Message::PacketIn(p) => info!(
                "packet-in: reason={} table={} in_port={:?} {} bytes",
                p.reason,
                p.table_id,
                p.in_port(),
                p.data.len()
            ),
            Message::FlowRemoved(f) => info!(
                "flow-removed: reason={} table={} priority={} cookie={:#x}",
                f.reason, f.table_id, f.priority, f.cookie
            ),
            Message::PortStatus(s) => {
                info!("port-status: reason={} port={}", s.reason, s.desc.port_no);
            }
            Message::Error(e) => info!("error from switch: {e:?}"),
            other => info!("other message: {other:?}"),
        }
    }
}
