//! A real multi-table pipeline, showing what each instruction type does
//! and the one distinction that trips people up: **apply-actions runs
//! now, write-actions defers to the action set.**
//!
//! The pipeline built here:
//!
//! - **table 0** classify: tag IPv4 traffic in metadata, then `goto` 1
//! - **table 1** police: rate-limit, stage an output in the action set
//! - **table 2** override: clear the action set for one exception
//!
//! Encodes offline and prints the frames; if `OFPORT_ADDR` points at a
//! switch it installs them too.
//!
//! ```sh
//! cargo run --example 30_pipeline_instructions                       # offline
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 30_pipeline_instructions
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::{ETH_TYPE_IPV4, OFPXMT_OFB_METADATA, OFPXMT_OFB_TCP_DST};
use openflow::protocol::instruction::Instruction;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::rule::Rule;
use tracing::info;

const IP_PROTO_TCP: u8 = 6;

/// Bit we set in metadata to mean "this is IPv4 traffic we classified".
const CLASSIFIED_IPV4: u64 = 0x1;

fn build_pipeline() -> Result<Vec<(&'static str, Rule)>, Box<dyn std::error::Error>> {
    // --- table 0: classify -----------------------------------------
    // WriteMetadata carries a value forward to the next table. The mask
    // says which bits to touch, so several tables can each own a slice
    // of the same 64-bit field without clobbering each other.
    let classify = Rule::add(
        0,
        0,
        100,
        Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]),
        vec![
            Instruction::WriteMetadata {
                metadata: CLASSIFIED_IPV4,
                metadata_mask: 0xf, // only the low nibble is ours
            },
            // GotoTable must name a *higher* table than the current one;
            // the pipeline only ever moves forward.
            Instruction::GotoTable(1),
        ],
    );

    // --- table 1: police -------------------------------------------
    // Two instructions on one entry, and they behave differently:
    //
    //   ApplyActions  runs immediately, in the order listed, before the
    //                 packet moves on. Metering has to happen here.
    //   WriteActions  merges into the *action set*, which the switch
    //                 executes only when the pipeline ends. At most one
    //                 output survives in the set, and the set runs in the
    //                 spec's fixed order regardless of listing order.
    let police = Rule::add(
        0,
        1,
        100,
        // Match on what table 0 wrote. Metadata is maskable.
        Match::new(vec![oxm::masked_field(
            OFPXMT_OFB_METADATA,
            &CLASSIFIED_IPV4.to_be_bytes(),
            &0xfu64.to_be_bytes(),
        )?]),
        vec![
            Instruction::apply_actions(vec![Action::Meter(1), Action::DecNwTtl]),
            Instruction::WriteActions(vec![Action::output(2)]),
            Instruction::GotoTable(2),
        ],
    );

    // --- table 2: override -----------------------------------------
    // ClearActions empties the action set staged by table 1, so this
    // packet is dropped instead of forwarded — the standard way to make
    // a late exception to an earlier decision.
    let exception = Rule::add(
        0,
        2,
        200,
        Match::new(vec![
            oxm::eth_type(ETH_TYPE_IPV4),
            oxm::ip_proto(IP_PROTO_TCP),
            oxm::field(OFPXMT_OFB_TCP_DST, &23u16.to_be_bytes())?, // telnet
        ]),
        vec![Instruction::ClearActions],
    );

    // Everything else in table 2 just runs the staged action set: an
    // entry with no instructions at all ends the pipeline.
    let fallthrough = Rule::add(0, 2, 0, Match::any(), Vec::new());

    Ok(vec![
        ("table 0: classify IPv4, tag metadata, goto 1", classify),
        ("table 1: meter + dec TTL now, stage output, goto 2", police),
        ("table 2: drop telnet by clearing the action set", exception),
        ("table 2: everything else runs the action set", fallthrough),
    ])
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let pipeline = build_pipeline()?;
    for (label, rule) in &pipeline {
        info!("{label} — {} byte(s) encoded", rule.encode()?.len());
    }

    let Ok(addr) = std::env::var("OFPORT_ADDR") else {
        info!("set OFPORT_ADDR to install this pipeline on a real switch");
        return Ok(());
    };

    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");
    for (label, rule) in pipeline {
        client.add_flow(rule).await?;
        info!("installed: {label}");
    }

    Ok(())
}
