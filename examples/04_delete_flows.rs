//! Remove flows from a switch, either all of them or a cookie-tagged subset.
//!
//! `Connection::delete_flows` sends an `OFPFC_DELETE` flow-mod matching
//! every table (`OFPTT_ALL`) and every output port/group (`OFPP_ANY`/
//! `OFPG_ANY`), then waits on a barrier. Passing `Some(cookie)` restricts
//! the deletion to flows tagged with that exact cookie via a full
//! (`u64::MAX`) cookie mask; passing `None` deletes unconditionally.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 04_delete_flows
//! # or, to only remove flows tagged with a specific cookie:
//! OFPORT_ADDR=127.0.0.1:6653 OFCOOKIE=0xdeadbeef cargo run --example 04_delete_flows
//! ```

use openflow::client::Connection;
use tracing::info;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

fn cookie_filter() -> Option<u64> {
    let raw = std::env::var("OFCOOKIE").ok()?;
    let trimmed = raw.trim_start_matches("0x");
    u64::from_str_radix(trimmed, 16).ok()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    let cookie = cookie_filter();
    client.delete_flows(cookie).await?;

    if let Some(cookie) = cookie {
        info!("deleted flows tagged with cookie=0x{cookie:016x}");
    } else {
        info!("deleted all flows on the switch");
    }

    Ok(())
}
