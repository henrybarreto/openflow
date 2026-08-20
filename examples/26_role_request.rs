//! Claim a controller role with `OFPT_ROLE_REQUEST`: query the current
//! one, then become master.
//!
//! There is no `Connection` helper for roles, so this is also the example
//! of the escape hatch — `send_raw` with an [`Encoder`] frame, then
//! `recv_message` to wait for the reply. Two traps show up here:
//!
//! - `generation_id` must never go backwards. A switch answers a stale
//!   one with `OFPET_ROLE_REQUEST_FAILED`/`OFPRRFC_STALE`.
//! - **Other messages arrive while you wait.** An `OFPT_ECHO_REQUEST` that
//!   goes unanswered makes the switch drop the connection, so the wait
//!   loop must handle it rather than only looking for the reply.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 26_role_request
//! ```

use openflow::client::Connection;
use openflow::protocol::codec::Encoder;
use openflow::protocol::constants::{
    OFPCR_ROLE_EQUAL, OFPCR_ROLE_MASTER, OFPCR_ROLE_NOCHANGE, OFPCR_ROLE_SLAVE,
};
use openflow::protocol::control::RoleRequest;
use openflow::protocol::message::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

const fn role_name(role: u32) -> &'static str {
    match role {
        OFPCR_ROLE_EQUAL => "equal",
        OFPCR_ROLE_MASTER => "master",
        OFPCR_ROLE_SLAVE => "slave",
        OFPCR_ROLE_NOCHANGE => "nochange",
        _ => "unknown",
    }
}

/// Wait for the role reply, answering anything else that arrives first.
///
/// Keeping the echo answer in the loop is what stops the switch from
/// tearing the connection down mid-wait.
async fn await_role_reply<S>(
    client: &mut Connection<S>,
) -> Result<RoleRequest, Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match client.recv_message().await? {
            Message::RoleReply(reply) => return Ok(reply),
            Message::EchoRequest { xid, payload } => {
                let reply = Encoder::echo_reply(xid, &payload)?;
                client.send_raw(&reply).await?;
            }
            other => info!("ignoring {other:?} while waiting for the role reply"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    // OFPCR_ROLE_NOCHANGE queries without changing anything. A fresh
    // connection is always "equal".
    client
        .send_raw(&Encoder::role_request(1, OFPCR_ROLE_NOCHANGE, 0, 0)?)
        .await?;
    let current = await_role_reply(&mut client).await?;
    info!(
        "current role: {} (generation_id={})",
        role_name(current.role),
        current.generation_id
    );

    // Becoming master demotes every other master to slave, so the switch
    // uses generation_id to reject requests that raced.
    let generation_id = current.generation_id.wrapping_add(1);
    client
        .send_raw(&Encoder::role_request(
            2,
            OFPCR_ROLE_MASTER,
            0,
            generation_id,
        )?)
        .await?;
    let promoted = await_role_reply(&mut client).await?;
    info!(
        "now {} (generation_id={})",
        role_name(promoted.role),
        promoted.generation_id
    );

    // A slave connection is read-only: the switch answers any flow-mod
    // from it with OFPET_BAD_REQUEST/OFPBRC_IS_SLAVE.
    client
        .send_raw(&Encoder::role_request(
            3,
            OFPCR_ROLE_SLAVE,
            0,
            generation_id.wrapping_add(1),
        )?)
        .await?;
    let demoted = await_role_reply(&mut client).await?;
    info!("stepped down to {}", role_name(demoted.role));

    Ok(())
}
