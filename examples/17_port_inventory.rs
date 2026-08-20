//! List every port on the switch with `OFPMP_PORT_DESC` — number, MAC,
//! name, admin config and link state.
//!
//! This is the 1.5 way to enumerate ports: unlike 1.0, the features reply
//! carries no port list, so a controller that needs port numbers must ask
//! for them. See `06_port_stats` for the per-port counters.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 17_port_inventory
//! ```

use openflow::client::Connection;
use openflow::protocol::constants::{
    OFPMP_PORT_DESC, OFPPC_NO_FWD, OFPPC_NO_RECV, OFPPC_PORT_DOWN, OFPPS_LINK_DOWN, OFPP_ANY,
};
use openflow::protocol::control::{
    MultipartReplyBody, MultipartRequestBody, PortMultipartRequest, PortProperty,
};
use tracing::info;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

fn mac(addr: [u8; 6]) -> String {
    addr.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// `config` is what the controller asked for; `state` is what the link is
/// actually doing.
fn flags(config: u32, state: u32) -> String {
    let mut out = Vec::new();
    if config & OFPPC_PORT_DOWN != 0 {
        out.push("admin-down");
    }
    if config & OFPPC_NO_RECV != 0 {
        out.push("no-recv");
    }
    if config & OFPPC_NO_FWD != 0 {
        out.push("no-fwd");
    }
    if state & OFPPS_LINK_DOWN != 0 {
        out.push("link-down");
    }
    if out.is_empty() {
        "up".to_owned()
    } else {
        out.join(",")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    // `OFPP_ANY` asks for every port; a real port number asks for one.
    let request = MultipartRequestBody::Port(PortMultipartRequest { port_no: OFPP_ANY });
    let reply = client.multipart_request(OFPMP_PORT_DESC, &request).await?;
    let MultipartReplyBody::PortDesc(ports) = reply else {
        info!("switch replied with an unexpected multipart body: {reply:?}");
        return Ok(());
    };

    info!("{} port(s)", ports.len());
    for port in &ports {
        info!(
            "port={} name={:?} hw_addr={} [{}]",
            port.port_no,
            port.name,
            mac(port.hw_addr),
            flags(port.config, port.state),
        );

        // Speeds and supported media live in the port's properties, not in
        // the fixed part of `ofp_port`.
        for property in &port.properties {
            match property {
                PortProperty::Ethernet {
                    curr_speed,
                    max_speed,
                    ..
                } => info!("    ethernet: curr={curr_speed} kbps max={max_speed} kbps"),
                PortProperty::Optical { supported, .. } => {
                    info!("    optical: supported={supported:#x}");
                }
                other => info!("    {other:?}"),
            }
        }
    }

    Ok(())
}
