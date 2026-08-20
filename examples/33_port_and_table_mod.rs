//! Change a port's administrative state with `OFPT_PORT_MOD`, watch the
//! `OFPT_PORT_STATUS` it produces, and configure a table with
//! `OFPT_TABLE_MOD`.
//!
//! Two details worth copying:
//!
//! - A port-mod carries `config` **and** `mask`: only the bits set in the
//!   mask are changed, so you can bring a port down without disturbing
//!   its other settings. It also carries the port's `hw_addr`, which the
//!   switch checks — a mismatch means you are configuring the wrong port,
//!   so read the address from `OFPMP_PORT_DESC` rather than guessing.
//! - Async events must be enabled first, or the `PORT_STATUS` that your
//!   own change triggers never arrives.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 OFPORT_NAME=p1 cargo run --example 33_port_and_table_mod
//! ```

use std::time::Duration;

use openflow::client::Connection;
use openflow::protocol::codec::Encoder;
use openflow::protocol::constants::{
    OFPMP_PORT_DESC, OFPPC_PORT_DOWN, OFPPR_MODIFY, OFPP_ANY, OFPTMPEF_IMPORTANCE,
};
use openflow::protocol::control::{
    MultipartReplyBody, MultipartRequestBody, PortMultipartRequest, TableModProperty,
};
use openflow::protocol::message::Message;
use tracing::info;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

/// Which port to toggle. Defaults to the first non-reserved port found.
fn port_name() -> Option<String> {
    std::env::var("OFPORT_NAME").ok()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    // Without this the PORT_STATUS below never shows up.
    client.enable_all_async_events().await?;

    // --- table-mod ------------------------------------------------------
    // Let table 0 evict its own entries when full, preferring to keep the
    // ones with higher `Rule::importance`. There is no Connection helper,
    // so this goes out through send_raw.
    let properties = [TableModProperty::Eviction {
        flags: OFPTMPEF_IMPORTANCE,
    }];
    client
        .send_raw(&Encoder::table_mod(1, 0, 0, &properties)?)
        .await?;
    client.send_barrier().await?;
    info!("table 0 configured for importance-based eviction");

    // --- port-mod -------------------------------------------------------
    // Find a real port, and take its hardware address with it.
    let request = MultipartRequestBody::Port(PortMultipartRequest { port_no: OFPP_ANY });
    let reply = client.multipart_request(OFPMP_PORT_DESC, &request).await?;
    let MultipartReplyBody::PortDesc(ports) = reply else {
        info!("unexpected multipart body: {reply:?}");
        return Ok(());
    };

    let wanted = port_name();
    let Some(port) = ports
        .iter()
        // Reserved port numbers (>= OFPP_MAX) are not real ports.
        .filter(|p| p.port_no < 0xffff_ff00)
        .find(|p| wanted.as_ref().is_none_or(|name| *name == p.name))
    else {
        info!("no usable port found; set OFPORT_NAME to one from 17_port_inventory");
        return Ok(());
    };
    info!("using port {} ({:?})", port.port_no, port.name);

    // Bring it administratively down: config bit set, mask says "this bit
    // only".
    client
        .send_raw(&Encoder::port_mod(
            2,
            port.port_no,
            port.hw_addr,
            OFPPC_PORT_DOWN,
            OFPPC_PORT_DOWN,
            &[],
        )?)
        .await?;

    // The switch reports the change back as an OFPPR_MODIFY.
    match tokio::time::timeout(Duration::from_secs(5), client.recv_message()).await {
        Ok(Ok(Message::PortStatus(status))) => info!(
            "port-status: reason={} port={} config={:#x} state={:#x}{}",
            status.reason,
            status.desc.port_no,
            status.desc.config,
            status.desc.state,
            if status.reason == OFPPR_MODIFY {
                " (modify)"
            } else {
                ""
            },
        ),
        Ok(Ok(other)) => info!("first message back was {other:?}"),
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => info!("no port-status arrived within 5s"),
    }

    // Put it back: same mask, config bit cleared.
    client
        .send_raw(&Encoder::port_mod(
            3,
            port.port_no,
            port.hw_addr,
            0,
            OFPPC_PORT_DOWN,
            &[],
        )?)
        .await?;
    client.send_barrier().await?;
    info!("port {} restored", port.port_no);

    Ok(())
}
