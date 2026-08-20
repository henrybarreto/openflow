//! Read a switch's rejection properly: catch `Error::Remote` and turn the
//! raw `error_type`/`code` pair into a typed [`ErrorType`].
//!
//! This is the example to read first when something you send is refused.
//! Every `OFPT_ERROR` names both *what* was wrong and *which* message
//! caused it — the error's `xid` matches the xid of the offending
//! message, and its `data` holds that message's first bytes.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 25_error_handling
//! ```

use openflow::client::{Connection, Error};
use openflow::protocol::constants::{OFPMP_EXPERIMENTER, OFPTT_ALL};
use openflow::protocol::control::MultipartRequestBody;
use openflow::protocol::error_msg::{ErrorType, FlowModFailedCode};
use openflow::protocol::ofmatch::Match;
use openflow::protocol::rule::Rule;
use tracing::info;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

/// Print a `Connection` error the way an application should: typed if the
/// switch sent an `OFPT_ERROR`, otherwise as a local failure.
fn report(context: &str, err: &Error) {
    match err {
        Error::Remote {
            error_type,
            code,
            data,
        } => {
            let kind = ErrorType::parse(*error_type, *code);
            info!("{context}: switch refused it — {kind:?}");
            info!(
                "    raw type={error_type} code={code}, {} byte(s) of the offending message \
                 returned",
                data.len()
            );

            // Matching on the typed form is how an application decides
            // what to do about it.
            match kind {
                ErrorType::FlowModFailed(FlowModFailedCode::TableFull) => {
                    info!("    -> the table is full; evict something or use another table");
                }
                ErrorType::FlowModFailed(FlowModFailedCode::BadTableId) => {
                    info!("    -> that table id does not exist on this switch");
                }
                ErrorType::BadMatch(code) => {
                    info!("    -> the match was wrong ({code:?}); check OXM prerequisites");
                }
                other => info!("    -> unhandled: {other:?}"),
            }
        }
        Error::MultipartTimeout => info!("{context}: the switch never finished replying"),
        Error::UnexpectedMessage { expected, got } => {
            info!("{context}: wanted {expected}, got {got}");
        }
        other => info!("{context}: local failure: {other}"),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    // 1. An invalid table id. `OFPTT_ALL` is a delete-only wildcard, so
    // it is never a legal target for an add — the portable way to
    // provoke OFPFMFC_BAD_TABLE_ID.
    let bad_table = Rule::add(0, OFPTT_ALL, 1, Match::any(), Vec::new());
    match client.add_flow(bad_table).await {
        Ok(()) => info!("unexpectedly accepted a flow-mod for OFPTT_ALL"),
        Err(err) => report("flow-mod with table_id=OFPTT_ALL", &err),
    }

    // 2. An unknown vendor id. Experimenter messages are refused by any
    // switch that does not know the vendor.
    let mut body = Vec::new();
    body.extend_from_slice(&0x00ff_ffffu32.to_be_bytes()); // bogus experimenter
    body.extend_from_slice(&1u32.to_be_bytes()); // exp_type
    match client
        .multipart_request(
            OFPMP_EXPERIMENTER,
            &MultipartRequestBody::Experimenter(body),
        )
        .await
    {
        Ok(reply) => info!("unexpectedly accepted: {reply:?}"),
        Err(err) => report("experimenter multipart with an unknown vendor", &err),
    }

    // An `OFPT_ERROR` is a rejection of one message, not a broken
    // connection: the switch keeps talking.
    client.send_barrier().await?;
    info!("connection still healthy after two rejections");

    Ok(())
}
