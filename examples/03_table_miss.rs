//! Install the classic "table-miss" rule: send anything unmatched by any
//! other flow to the controller.
//!
//! `Rule::table_miss_to_controller` builds a priority-0, empty-match
//! flow-mod whose only instruction is `apply-actions(output(CONTROLLER,
//! no_buffer))`. It is what `controller::server` installs automatically
//! right after the handshake; this example does the same thing from a
//! plain client.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 03_table_miss
//! ```

use openflow::client::Connection;
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

    client.add_flow(Rule::table_miss_to_controller(0)).await?;
    info!("table-miss rule installed: unmatched packets now go to the controller");

    Ok(())
}
