//! Read back the switch's groups: `OFPMP_GROUP_DESC` (type and buckets),
//! `OFPMP_GROUP_STATS` (per-group and per-bucket counters) and
//! `OFPMP_GROUP_FEATURES` (which group types and actions are supported).
//!
//! Installs the same `SELECT` group as `12_group_mod` first, so there is
//! something to read, then deletes it again.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 19_group_inspect
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::{
    OFPGC_DELETE, OFPG_ALL, OFPMP_GROUP_DESC, OFPMP_GROUP_FEATURES, OFPMP_GROUP_STATS,
};
use openflow::protocol::control::{
    Bucket, BucketProperty, GroupMod, GroupMultipartRequest, MultipartReplyBody,
    MultipartRequestBody,
};
use tracing::info;

const GROUP_TYPE_SELECT: u8 = 1;
const GROUP_ID: u32 = 42;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

const fn group_type_name(group_type: u8) -> &'static str {
    match group_type {
        0 => "all",
        1 => "select",
        2 => "indirect",
        3 => "fast-failover",
        _ => "unknown",
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    // What can this switch's group support actually do?
    let reply = client
        .multipart_request(OFPMP_GROUP_FEATURES, &MultipartRequestBody::Empty)
        .await?;
    if let MultipartReplyBody::GroupFeatures(features) = reply {
        info!(
            "group features: types={:#x} capabilities={:#x} max_groups={:?}",
            features.types, features.capabilities, features.max_groups
        );
    }

    let buckets = vec![
        Bucket {
            bucket_id: 1,
            actions: vec![Action::output(2)],
            properties: vec![BucketProperty::Weight(1)],
        },
        Bucket {
            bucket_id: 2,
            actions: vec![Action::output(3)],
            properties: vec![BucketProperty::Weight(1)],
        },
    ];
    client
        .add_group(GroupMod::add(0, GROUP_TYPE_SELECT, GROUP_ID, buckets))
        .await?;
    info!("installed group {GROUP_ID}");

    // `OFPG_ALL` reads every group; a real group id reads just that one.
    let request = MultipartRequestBody::Group(GroupMultipartRequest { group_id: OFPG_ALL });

    let reply = client.multipart_request(OFPMP_GROUP_DESC, &request).await?;
    if let MultipartReplyBody::GroupDesc(entries) = reply {
        for entry in &entries {
            info!(
                "group {} type={} with {} bucket(s)",
                entry.group_id,
                group_type_name(entry.group_type),
                entry.buckets.len()
            );
            for bucket in &entry.buckets {
                info!(
                    "    bucket {} actions={:?} properties={:?}",
                    bucket.bucket_id, bucket.actions, bucket.properties
                );
            }
        }
    }

    let reply = client
        .multipart_request(OFPMP_GROUP_STATS, &request)
        .await?;
    if let MultipartReplyBody::GroupStats(entries) = reply {
        for entry in &entries {
            info!(
                "group {} ref_count={} packets={} bytes={} up {}s",
                entry.group_id,
                entry.ref_count,
                entry.packet_count,
                entry.byte_count,
                entry.duration_sec,
            );
            for (index, bucket) in entry.bucket_stats.iter().enumerate() {
                info!(
                    "    bucket {index}: {} packets, {} bytes",
                    bucket.packet_count, bucket.byte_count
                );
            }
        }
    }

    // Clean up. A delete needs only the command and the group id.
    let mut delete = GroupMod::add(0, GROUP_TYPE_SELECT, GROUP_ID, Vec::new());
    delete.command = OFPGC_DELETE;
    client.send_group_mod(delete).await?;
    client.send_barrier().await?;
    info!("deleted group {GROUP_ID}");

    Ok(())
}
