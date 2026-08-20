//! Read and write the two pieces of per-connection configuration:
//! `OFPT_SET_CONFIG`/`OFPT_GET_CONFIG_REQUEST` (fragment handling and how
//! much of a packet arrives with a packet-in), and `OFPT_SET_ASYNC`
//! (which asynchronous events this connection receives).
//!
//! `16_async_events` turns *everything* on with
//! `enable_all_async_events`; this one builds a narrow mask by hand,
//! which is what a real controller wants — asking only for the events it
//! handles keeps the switch from spending bandwidth on the rest.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 27_switch_config
//! ```

use openflow::client::Connection;
use openflow::protocol::codec::Encoder;
use openflow::protocol::constants::{
    OFPACPT_FLOW_REMOVED_MASTER, OFPACPT_PACKET_IN_MASTER, OFPACPT_PORT_STATUS_MASTER,
    OFPCML_NO_BUFFER, OFPPR_ADD, OFPPR_DELETE, OFPPR_MODIFY, OFPRR_HARD_TIMEOUT,
    OFPRR_IDLE_TIMEOUT, OFPR_TABLE_MISS,
};
use openflow::protocol::control::Property;
use openflow::protocol::message::Message;
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

    // --- switch config -------------------------------------------------
    // There is no Connection helper for config, so this goes through
    // send_raw with an Encoder frame.
    //
    // `OFPCML_NO_BUFFER` means "send the whole packet, buffer nothing" —
    // simpler to work with, at the cost of bandwidth. A byte count like
    // 128 buffers the packet on the switch and sends only its head, which
    // you then release by echoing the buffer_id in a packet-out.
    client
        .send_raw(&Encoder::set_config(1, 0, OFPCML_NO_BUFFER))
        .await?;
    client.send_barrier().await?; // surfaces a rejection here, not later

    client.send_raw(&Encoder::get_config_request(2)).await?;
    loop {
        match client.recv_message().await? {
            Message::GetConfigReply(config) => {
                info!(
                    "config: flags={:#x} miss_send_len={}",
                    config.flags, config.miss_send_len
                );
                break;
            }
            Message::EchoRequest { xid, payload } => {
                let reply = Encoder::echo_reply(xid, &payload)?;
                client.send_raw(&reply).await?;
            }
            other => info!("ignoring {other:?} while waiting for the config reply"),
        }
    }

    // --- async config --------------------------------------------------
    // Each property names one message kind *and* the role it applies to.
    // The mask is a bitmap over that message's reason codes, so this asks
    // for table-miss packet-ins only, both timeout reasons for
    // flow-removed, and every port-status reason.
    let properties = vec![
        Property::ReasonMask {
            kind: OFPACPT_PACKET_IN_MASTER,
            mask: 1 << OFPR_TABLE_MISS,
        },
        Property::ReasonMask {
            kind: OFPACPT_FLOW_REMOVED_MASTER,
            mask: (1 << OFPRR_IDLE_TIMEOUT) | (1 << OFPRR_HARD_TIMEOUT),
        },
        Property::ReasonMask {
            kind: OFPACPT_PORT_STATUS_MASTER,
            mask: (1 << OFPPR_ADD) | (1 << OFPPR_DELETE) | (1 << OFPPR_MODIFY),
        },
    ];

    // set_async waits on a barrier, so an unsupported reason bit surfaces
    // here as OFPET_ASYNC_CONFIG_FAILED rather than silently doing nothing.
    client.set_async(&properties).await?;
    info!("narrow async mask applied");

    // Read it back to see what the switch actually stored — it may report
    // more properties than were set, including the slave-role ones.
    for property in client.get_async().await? {
        info!("async property: {property:?}");
    }

    Ok(())
}
