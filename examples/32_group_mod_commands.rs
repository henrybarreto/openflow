//! The group-mod commands beyond `OFPGC_ADD`: modify a whole group, and
//! edit one bucket at a time with `OFPGC_INSERT_BUCKET` /
//! `OFPGC_REMOVE_BUCKET`.
//!
//! `command_bucket_id` is the field that only matters here. The two
//! bucket commands use it to say *where* — a real bucket id, or one of
//! the sentinels `OFPG_BUCKET_FIRST` / `OFPG_BUCKET_LAST` /
//! `OFPG_BUCKET_ALL`. Every other command ignores it.
//!
//! Editing a bucket beats rewriting the group: a modify replaces the
//! whole bucket list, which momentarily disturbs traffic through the
//! group, while an insert or remove leaves the others alone.
//!
//! Run with:
//!
//! ```sh
//! OFPORT_ADDR=127.0.0.1:6653 cargo run --example 32_group_mod_commands
//! ```

use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::{
    OFPGC_INSERT_BUCKET, OFPGC_MODIFY, OFPGC_REMOVE_BUCKET, OFPGT_ALL, OFPG_ALL, OFPG_BUCKET_LAST,
    OFPMP_GROUP_DESC,
};
use openflow::protocol::control::{
    Bucket, GroupMod, GroupMultipartRequest, MultipartReplyBody, MultipartRequestBody,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

const GROUP_ID: u32 = 8;

fn switch_addr() -> String {
    std::env::var("OFPORT_ADDR").unwrap_or_else(|_| "127.0.0.1:6653".to_owned())
}

/// An `OFPGT_ALL` group floods to every bucket, so a bucket per port.
fn bucket(bucket_id: u32, port: u32) -> Bucket {
    Bucket {
        bucket_id,
        actions: vec![Action::output(port)],
        properties: Vec::new(),
    }
}

async fn show<S>(client: &mut Connection<S>, label: &str) -> Result<(), Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = MultipartRequestBody::Group(GroupMultipartRequest { group_id: OFPG_ALL });
    let reply = client.multipart_request(OFPMP_GROUP_DESC, &request).await?;
    if let MultipartReplyBody::GroupDesc(entries) = reply {
        for entry in entries.iter().filter(|e| e.group_id == GROUP_ID) {
            info!(
                "{label}: group {} has {} bucket(s)",
                entry.group_id,
                entry.buckets.len()
            );
            for b in &entry.buckets {
                info!("    bucket {} -> {:?}", b.bucket_id, b.actions);
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr = switch_addr();
    let mut client = Connection::connect_tcp(&addr).await?;
    info!("handshake complete with {addr}");

    // ADD, via the constructor + the barrier-waiting helper.
    client
        .add_group(GroupMod::add(0, OFPGT_ALL, GROUP_ID, vec![bucket(0, 1)]))
        .await?;
    show(&mut client, "after add").await?;

    // MODIFY replaces the entire bucket list. The group id must already
    // exist, or the switch answers OFPGMFC_UNKNOWN_GROUP.
    let mut modify = GroupMod::add(0, OFPGT_ALL, GROUP_ID, vec![bucket(0, 1), bucket(1, 2)]);
    modify.command = OFPGC_MODIFY;
    client.send_group_mod(modify).await?;
    client.send_barrier().await?;
    show(&mut client, "after modify (whole list replaced)").await?;

    // INSERT_BUCKET adds one bucket without touching the others.
    // OFPG_BUCKET_LAST appends; a real bucket id inserts before it.
    let insert = GroupMod {
        xid: 0,
        command: OFPGC_INSERT_BUCKET,
        group_type: OFPGT_ALL,
        group_id: GROUP_ID,
        command_bucket_id: OFPG_BUCKET_LAST,
        buckets: vec![bucket(2, 3)],
        properties: Vec::new(),
    };
    client.send_group_mod(insert).await?;
    client.send_barrier().await?;
    show(&mut client, "after insert-bucket").await?;

    // REMOVE_BUCKET carries no buckets — command_bucket_id says which to
    // drop. OFPG_BUCKET_ALL would empty the group.
    let remove = GroupMod {
        xid: 0,
        command: OFPGC_REMOVE_BUCKET,
        group_type: OFPGT_ALL,
        group_id: GROUP_ID,
        command_bucket_id: OFPG_BUCKET_LAST,
        buckets: Vec::new(),
        properties: Vec::new(),
    };
    client.send_group_mod(remove).await?;
    client.send_barrier().await?;
    show(&mut client, "after remove-bucket").await?;

    client.send_group_mod(GroupMod::delete(0, GROUP_ID)).await?;
    client.send_barrier().await?;
    info!("deleted group {GROUP_ID}");

    Ok(())
}
