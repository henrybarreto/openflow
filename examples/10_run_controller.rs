//! Run this crate's bundled controller: accept switch connections, learn
//! MAC addresses, and forward or flood accordingly.
//!
//! This is the same accept loop `src/main.rs` runs, exposed here as a
//! standalone example so it can be pointed at a real switch. Point an Open
//! vSwitch bridge at it:
//!
//! ```sh
//! ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
//! ```
//!
//! Run with:
//!
//! ```sh
//! OFLISTEN=0.0.0.0:6653 cargo run --example 10_run_controller
//! ```

fn listen_addr() -> String {
    std::env::var("OFLISTEN").unwrap_or_else(|_| "0.0.0.0:6653".to_owned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = listen_addr();
    openflow::controller::server::run(&addr).await?;

    Ok(())
}
