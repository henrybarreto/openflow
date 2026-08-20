//! Controller binary. The protocol and controller code lives in the
//! library crate; this only parses arguments and starts the server.
//!
//! Declaring the modules again here (rather than using the library)
//! would compile a second copy of the whole crate, doubling build time
//! and running every unit test twice.

use clap::Parser;

use openflow::protocol::error::Result;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:6653")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    openflow::controller::server::run(&args.listen).await
}
