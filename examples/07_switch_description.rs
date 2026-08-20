//! Query the switch's self-reported description via an `OFPMP_DESC`
//! multipart request (manufacturer, hardware/software version, serial
//! number, and a free-form datapath description).
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 07_switch_description
//! ```

use openflow::client::Connection;
use openflow::protocol::constants::OFPMP_DESC;
use openflow::protocol::control::{MultipartReplyBody, MultipartRequestBody};
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

    let reply = client
        .multipart_request(OFPMP_DESC, &MultipartRequestBody::Empty)
        .await?;
    let MultipartReplyBody::Desc(desc) = reply else {
        info!("switch replied with an unexpected multipart body: {reply:?}");
        return Ok(());
    };

    info!(
        "mfr={:?} hw={:?} sw={:?} serial={:?} dp_desc={:?}",
        desc.mfr_desc, desc.hw_desc, desc.sw_desc, desc.serial_num, desc.dp_desc
    );

    Ok(())
}
