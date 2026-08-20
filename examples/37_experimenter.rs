//! Vendor extensions: `OFPT_EXPERIMENTER` messages and
//! `OFPMP_EXPERIMENTER` multipart bodies.
//!
//! The spec reserves these for whatever a vendor wants; their contents
//! are by definition not something this crate can interpret, so it
//! carries them as raw bytes in both directions. Sending one to a switch
//! that does not know the vendor id is *supposed* to fail cleanly, and
//! this example shows exactly that: a rejection arrives, and the
//! connection keeps working.
//!
//! For a vendor extension that a real switch does implement, see
//! `36_conntrack`, which uses Nicira's experimenter id for connection
//! tracking.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 37_experimenter
//! ```

use openflow::client::{Connection, Error};
use openflow::protocol::codec::Encoder;
use openflow::protocol::constants::{NX_VENDOR_ID, OFPMP_EXPERIMENTER};
use openflow::protocol::control::MultipartRequestBody;
use openflow::protocol::error_msg::ErrorType;
use openflow::protocol::message::Message;
use tracing::info;

/// An experimenter id no vendor owns, so every switch refuses it.
const UNKNOWN_VENDOR: u32 = 0x00ff_ffff;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    // --- an experimenter *message* -------------------------------------
    // Layout: experimenter id, vendor-defined subtype, then whatever the
    // vendor says. There is no Connection helper, so send_raw it is.
    let frame = Encoder::experimenter(1, UNKNOWN_VENDOR, 1, b"hello")?;
    info!("sending a {}-byte experimenter message", frame.len());
    client.send_raw(&frame).await?;

    // The switch answers with an error rather than ignoring it.
    match client.recv_message().await? {
        Message::Error(err) => info!(
            "switch refused the experimenter message: {:?} (xid {} matches ours)",
            err.kind(),
            err.xid
        ),
        other => info!("switch answered with {other:?}"),
    }

    // --- an experimenter *multipart* -----------------------------------
    // Same idea on the statistics channel. The body starts with the
    // experimenter id and subtype; the rest is the vendor's business.
    let mut body = Vec::new();
    body.extend_from_slice(&UNKNOWN_VENDOR.to_be_bytes());
    body.extend_from_slice(&1u32.to_be_bytes()); // exp_type
    body.extend_from_slice(b"query");

    match client
        .multipart_request(
            OFPMP_EXPERIMENTER,
            &MultipartRequestBody::Experimenter(body),
        )
        .await
    {
        Ok(reply) => info!("switch answered: {reply:?}"),
        Err(Error::Remote {
            error_type, code, ..
        }) => info!(
            "switch refused the experimenter multipart: {:?}",
            ErrorType::parse(error_type, code)
        ),
        Err(other) => return Err(other.into()),
    }

    // Both rejections are per-message; the session is untouched.
    client.send_barrier().await?;
    info!("connection still healthy");

    // Real vendor ids are what make these useful. Open vSwitch's is
    // Nicira's, which 36_conntrack builds real actions on top of.
    info!("(Nicira's experimenter id is {NX_VENDOR_ID:#010x} — see 36_conntrack)");

    Ok(())
}
