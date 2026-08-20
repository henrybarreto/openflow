//! Inspect the switch's flow tables three ways: `OFPMP_TABLE_STATS`
//! (counters), `OFPMP_TABLE_DESC` (current configuration) and
//! `OFPMP_TABLE_FEATURES` (what each table can do).
//!
//! Table features is the one that answers "will this switch accept my
//! flow?" — it lists the instructions, actions and match fields each
//! table supports, so a controller can adapt instead of guessing.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 18_table_inventory
//! ```

use openflow::client::Connection;
use openflow::protocol::constants::{OFPMP_TABLE_DESC, OFPMP_TABLE_FEATURES, OFPMP_TABLE_STATS};
use openflow::protocol::control::{MultipartReplyBody, MultipartRequestBody, TableFeatureProperty};
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

    if let Some(features) = client.features() {
        info!(
            "datapath 0x{:016x} has {} table(s)",
            features.datapath_id, features.n_tables
        );
    }

    // 1. Counters. Both these subtypes take an empty request body.
    let reply = client
        .multipart_request(OFPMP_TABLE_STATS, &MultipartRequestBody::Empty)
        .await?;
    if let MultipartReplyBody::TableStats(entries) = reply {
        for entry in entries
            .iter()
            .filter(|e| e.lookup_count > 0 || e.active_count > 0)
        {
            info!(
                "table {}: {} active, {} lookups, {} matched",
                entry.table_id, entry.active_count, entry.lookup_count, entry.matched_count
            );
        }
        info!("(tables with no traffic and no flows omitted)");
    }

    // 2. Current configuration: eviction and vacancy settings.
    let reply = client
        .multipart_request(OFPMP_TABLE_DESC, &MultipartRequestBody::Empty)
        .await?;
    if let MultipartReplyBody::TableDesc(entries) = reply {
        for entry in entries.iter().filter(|e| !e.properties.is_empty()) {
            info!(
                "table {} config={:#x} properties={:?}",
                entry.table_id, entry.config, entry.properties
            );
        }
    }

    // 3. Capabilities. An *empty* TableFeatures body means "tell me what
    // you have"; a non-empty one would try to *set* the table features.
    let reply = client
        .multipart_request(
            OFPMP_TABLE_FEATURES,
            &MultipartRequestBody::TableFeatures(Vec::new()),
        )
        .await?;
    let MultipartReplyBody::TableFeatures(entries) = reply else {
        info!("switch replied with an unexpected multipart body: {reply:?}");
        return Ok(());
    };

    for entry in entries.iter().take(2) {
        info!(
            "table {} {:?}: max_entries={} metadata_match={:#x}",
            entry.table_id, entry.name, entry.max_entries, entry.metadata_match
        );
        for property in &entry.properties {
            match property {
                TableFeatureProperty::Instructions { ids, .. } => {
                    info!("    supports {} instruction type(s)", ids.len());
                }
                TableFeatureProperty::Actions { ids, .. } => {
                    info!("    supports {} action type(s)", ids.len());
                }
                TableFeatureProperty::Oxm { oxm_ids, .. } => {
                    info!("    supports {} match field(s)", oxm_ids.len());
                }
                TableFeatureProperty::NextTables { table_ids, .. } => {
                    info!("    can goto {} table(s)", table_ids.len());
                }
                _ => {}
            }
        }
    }
    info!("({} table(s) total, first 2 shown)", entries.len());

    Ok(())
}
